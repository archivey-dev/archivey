"""Remote benchmark axis: range requests and bytes fetched over fsspec.

Run::

    uv run --extra all python -m benchmarks.remote
    uv run --extra all python -m benchmarks.remote --update-baselines
    uv run --extra all python -m benchmarks.remote --json-out remote.json

This is stage 1 of the fsspec change (``openspec/changes/fsspec-integration``, design
§"Benchmark: requests and bytes fetched"). It measures what reading an archive costs
when every read is a network request, before archivey knows anything about fsspec, so
that the fetch planner of stage 2 lands as a reviewed diff of
``benchmarks/baselines/remote.json``.

``CountingFileSystem`` is an fsspec file system over local files. It records every
range fetch, every ``info``/``size`` call and every ``ls``, needs no network, and is
deterministic, so its counts are exact on every host. archivey reads a caller's
open fsspec file as a plain file object, and an ``OpenFile`` by range; the modes:

- ``nocache``: ``fs.open(path, cache_type="none")``: one request per read call.
- ``default``: ``fs.open(path)``: fsspec's own default cache (``readahead``, 5 MiB
  blocks), which fetches far more than it needs on a small read.
- ``planner``: the unentered ``OpenFile``, which archivey reads by range through its
  own fetch planner (stage 2), with the planner's constants set small through its
  private seam (16 KiB minimum fetch, 128 KiB maximum fetch and pool) and
  ``max_read_through`` at 16 KiB, so the small fixtures cross every planner rule.

Operations: list; read the first, a middle and the last member; ``extract_all()``;
``stream_members()`` under ``streaming=True``; and, on the formats that open members
independently, eight threads reading eight members (``threads``) and sixteen member
streams open at once (``many_streams``), the cases that pin the planner's window rules.
Threads that share one caller-opened file race for its position and its cache, so
both the requests and the bytes fetched of ``threads`` move from run to run, on TAR as on
ZIP: the case is reported and not gated.

Recorded per case: ``range_requests``, ``metadata_requests``, ``bytes_fetched``, and
``archive_size`` for scale. ``overfetch`` is ``bytes_fetched / archive_size``: the
design's ``bytes_needed`` (the least an operation could read) needs per-format span
arithmetic and comes with the planner. A modelled time (30 ms per request plus
50 MB/s) is printed beside each case so a change that trades requests for bytes can be
judged; it is not gated.

The gate (``check_against_baseline``, run by ``tests/test_remote_benchmark.py``):
``range_requests`` equal to the baseline, ``bytes_fetched`` at most the baseline, on
the formats whose bytes depend only on the stdlib's ZIP and TAR writers
(``GATED_FORMATS``). The fixtures are seeded random members (``REMOTE_SCALES``), not
the ~100:1 comparison corpus of ``benchmarks/fixtures.py``, which would fit most
archives in one small fetch.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import random
import shutil
import sys
import tarfile
import tempfile
import threading
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from fsspec.core import OpenFile
from fsspec.spec import AbstractBufferedFile, AbstractFileSystem

from archivey import ArchiveyConfig, open_archive
from archivey.internal.remote import PlannerConstants, planner_constants

BASELINES_DIR = Path(__file__).resolve().parent / "baselines"
REMOTE_BASELINE = BASELINES_DIR / "remote.json"

# Modelled link for the informational time column: a typical object-store round trip
# and a modest download rate. Not gated.
MODEL_LATENCY_S = 0.030
MODEL_BANDWIDTH_BPS = 50_000_000


@dataclass
class RequestLog:
    """What one ``CountingFileSystem`` saw. Thread-safe: members may be read in
    parallel."""

    ranges: list[tuple[str, int, int]] = field(default_factory=list)
    metadata: list[tuple[str, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_range(self, path: str, start: int, end: int) -> None:
        with self._lock:
            self.ranges.append((path, start, end))

    def record_metadata(self, call: str, path: str) -> None:
        with self._lock:
            self.metadata.append((call, path))

    @property
    def bytes_fetched(self) -> int:
        return sum(end - start for _, start, end in self.ranges)


class CountingFile(AbstractBufferedFile):
    """A buffered fsspec file whose every fetch is one recorded range request."""

    def _fetch_range(self, start: int, end: int) -> bytes:
        fs: CountingFileSystem = self.fs
        end = min(end, self.size)
        if end <= start:
            return b""
        fs.log.record_range(self.path, start, end)
        with Path(self.path).open("rb") as handle:
            handle.seek(start)
            return handle.read(end - start)


class CountingFileSystem(AbstractFileSystem):
    """Read-only fsspec file system over local paths that counts what it is asked.

    Not cached by fsspec's instance cache: each case gets a fresh log.
    """

    protocol = "counting"
    cachable = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.log = RequestLog()

    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        path = self._strip_protocol(path)
        self.log.record_metadata("info", path)
        p = Path(path)
        return {
            "name": path,
            "size": p.stat().st_size,
            "type": "directory" if p.is_dir() else "file",
        }

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[Any]:
        path = self._strip_protocol(path)
        self.log.record_metadata("ls", path)
        entries = [
            {"name": str(c), "size": c.stat().st_size, "type": "file"}
            for c in sorted(Path(path).iterdir())
            if c.is_file()
        ]
        return entries if detail else [e["name"] for e in entries]

    def cat_file(
        self, path: str, start: int | None = None, end: int | None = None, **kwargs: Any
    ) -> bytes:
        path = self._strip_protocol(path)
        data = Path(path).read_bytes()
        size = len(data)
        lo = 0 if start is None else (start if start >= 0 else max(size + start, 0))
        hi = size if end is None else (end if end >= 0 else max(size + end, 0))
        hi = min(hi, size)
        if hi > lo:
            self.log.record_range(path, lo, hi)
        return data[lo:hi]

    def _open(
        self,
        path: str,
        mode: str = "rb",
        block_size: int | str | None = "default",
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CountingFile:
        if mode != "rb":
            raise NotImplementedError("CountingFileSystem is read-only")
        # The size comes from one info() call at open, as an HTTP HEAD or a stat would.
        size = self.info(path)["size"]
        return CountingFile(
            self,
            path,
            mode=mode,
            block_size=block_size,
            autocommit=autocommit,
            cache_options=cache_options,
            size=size,
            **kwargs,
        )


@dataclass
class RemoteCaseResult:
    case: str
    format: str
    operation: str
    cache: str
    range_requests: int
    metadata_requests: int
    bytes_fetched: int
    archive_size: int

    @property
    def overfetch(self) -> float:
        return self.bytes_fetched / self.archive_size if self.archive_size else 0.0

    @property
    def modelled_s(self) -> float:
        return (
            self.range_requests * MODEL_LATENCY_S
            + self.bytes_fetched / MODEL_BANDWIDTH_BPS
        )


# The first two are how a caller opens an fsspec file and passes it as a stream:
# archivey reads it through the caller's object and cache. ``planner`` passes the
# unentered ``OpenFile`` instead, which archivey reads by range through its own fetch
# planner (``archivey.internal.remote``), with the planner's constants set small
# (``PLANNER_TEST_CONSTANTS``, design D2) so the small fixtures cross every rule.
CACHE_MODES: dict[str, dict[str, Any]] = {
    "nocache": {"cache_type": "none"},
    "default": {},
    "planner": {},
}
PLANNER_MODE = "planner"

PLANNER_TEST_CONSTANTS = PlannerConstants(
    min_fetch=16 * 1024, max_fetch=128 * 1024, pool_bytes=128 * 1024
)
PLANNER_TEST_CONFIG = ArchiveyConfig(max_read_through=16 * 1024)


def _members_with_data(reader: Any) -> list[Any]:
    return [m for m in reader.members() if m.is_file]


def _op_list(reader: Any, _dest: Path) -> None:
    reader.members()


def _read_one(index: Callable[[int], int]) -> Callable[[Any, Path], None]:
    def op(reader: Any, _dest: Path) -> None:
        members = _members_with_data(reader)
        with reader.open(members[index(len(members))]) as stream:
            stream.read()

    return op


def _op_extract_all(reader: Any, dest: Path) -> None:
    reader.extract_all(dest)


def _op_stream_members(reader: Any, _dest: Path) -> None:
    for _member, stream in reader.stream_members():
        if stream is not None:
            stream.read()


THREADED_READERS = 8
OPEN_STREAMS = 16


def _op_threads(reader: Any, _dest: Path) -> None:
    """Eight threads, each reading one of eight members spread over the archive.

    Every thread opens its stream before any reads, so all eight runs are active at
    once (design D2 rule 4, the shrinking fetch). The bytes each thread reads are
    deterministic; the order of the requests is not, so the requests and the bytes
    fetched both move a little from run to run, on TAR as on ZIP. The case is
    reported and not gated (``UNGATED_OPERATIONS``).
    """
    members = _members_with_data(reader)
    step = max(len(members) // THREADED_READERS, 1)
    chosen = members[::step][:THREADED_READERS]
    streams: list[Any] = []
    try:
        streams.extend(reader.open(m) for m in chosen)
        barrier = threading.Barrier(len(streams))
        errors: list[BaseException] = []

        def work(stream: Any) -> None:
            try:
                barrier.wait()
                while stream.read(4096):
                    pass
            except BaseException as exc:  # noqa: BLE001  # re-raised below, after every join
                errors.append(exc)
                barrier.abort()

        threads = [threading.Thread(target=work, args=(s,)) for s in streams]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if errors:
            raise errors[0]
    finally:
        for s in streams:
            s.close()


def _op_many_streams(reader: Any, _dest: Path) -> None:
    """Sixteen member streams open at once, read round-robin in small steps.

    Twice the window count under the planner's test constants (design D2 rule 4, the
    unbuffered reads past the window limit). One thread: the order is deterministic.
    """
    members = _members_with_data(reader)[:OPEN_STREAMS]
    streams = [reader.open(m) for m in members]
    try:
        live = list(streams)
        while live:
            live = [s for s in live if s.read(4096)]
    finally:
        for s in streams:
            s.close()


# operation name -> (open_archive keywords, callable)
OPERATIONS: dict[str, tuple[dict[str, Any], Callable[[Any, Path], None]]] = {
    "list": ({}, _op_list),
    "read_first": ({}, _read_one(lambda n: 0)),
    "read_middle": ({}, _read_one(lambda n: n // 2)),
    "read_last": ({}, _read_one(lambda n: n - 1)),
    "extract_all": ({}, _op_extract_all),
    "stream_members": ({"streaming": True}, _op_stream_members),
    "threads": ({"concurrent_operations": True}, _op_threads),
    "many_streams": ({"concurrent_operations": True}, _op_many_streams),
}

# Operations that need several member streams open at once: only the formats that
# open members independently run them (a solid or compressed-TAR stream cannot).
MULTI_STREAM_OPERATIONS = frozenset({"threads", "many_streams"})
MULTI_STREAM_FORMATS = frozenset({"zip_stored", "zip_deflate", "tar"})


@dataclass(frozen=True)
class RemoteScale:
    members: int
    min_member_size: int
    max_member_size: int


# The comparison corpus in benchmarks/fixtures.py compresses ~100:1 (a .tar.gz of
# 128 KiB is 1.5 KiB), so over a network almost every case would be one small fetch.
# These members are seeded random bytes: a member's stored span is about its size, so
# the counts show where each read goes. Their sizes vary, seeded, so that the gaps a
# TAR listing hops over fall on both sides of a fixed read-through distance.
REMOTE_SCALES: dict[str, RemoteScale] = {
    "ci": RemoteScale(members=32, min_member_size=4 * 1024, max_member_size=32 * 1024),
    "realistic": RemoteScale(
        members=64, min_member_size=64 * 1024, max_member_size=448 * 1024
    ),
}

# Formats whose bytes depend only on this file and the stdlib's ZIP/TAR writers. The
# compressed ones also depend on the zlib or liblzma build (zlib-ng writes other
# bytes), so their counts are reported but not gated.
GATED_FORMATS = frozenset({"zip_stored", "tar"})

# Threads sharing one caller-opened fsspec file race for its position and its cache, so
# their requests and bytes fetched change from run to run, on TAR as on ZIP: reported,
# not gated.
UNGATED_OPERATIONS = frozenset({"threads"})


def is_gated(fmt: str, operation: str) -> bool:
    return fmt in GATED_FORMATS and operation not in UNGATED_OPERATIONS


def baseline_applies(baseline: dict[str, Any]) -> bool:
    """Whether this interpreter reads in the steps the baseline was measured with.

    Without the planner, archivey reads a caller's file through buffers of
    ``io.DEFAULT_BUFFER_SIZE`` (8 KiB, 128 KiB from Python 3.14), so the request
    counts differ by version. The gate runs where the size matches the baseline's.
    """
    return baseline.get("io_default_buffer_size") == io.DEFAULT_BUFFER_SIZE


_FIXED_DATE = (2020, 1, 1, 0, 0, 0)
_FIXED_MTIME = 1_577_836_800


def _member_payloads(scale: RemoteScale) -> list[tuple[str, bytes]]:
    rng = random.Random(20261026)
    return [
        (
            f"m{i:03d}.bin",
            rng.randbytes(rng.randint(scale.min_member_size, scale.max_member_size)),
        )
        for i in range(scale.members)
    ]


def _build_zip(path: Path, members: list[tuple[str, bytes]], method: int) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=_FIXED_DATE)
            info.compress_type = method
            zf.writestr(info, data)


def _build_tar(path: Path, members: list[tuple[str, bytes]], *, gz: bool) -> None:
    with path.open("wb") as raw:
        out: Any = gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) if gz else raw
        with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tf:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = _FIXED_MTIME
                tf.addfile(info, io.BytesIO(data))
        if gz:
            out.close()


def _build_7z_solid(path: Path, members: list[tuple[str, bytes]]) -> bool:
    try:
        import py7zr
    except ImportError:
        return False
    with py7zr.SevenZipFile(path, "w", filters=[{"id": py7zr.FILTER_LZMA2}]) as sz:
        for name, data in members:
            sz.writestr(data, name)
    return True


def _fixture_paths(root: Path, scale: str) -> dict[str, Path]:
    members = _member_payloads(REMOTE_SCALES[scale])
    paths = {
        "zip_stored": root / "stored.zip",
        "zip_deflate": root / "deflate.zip",
        "tar": root / "plain.tar",
        "tar_gz": root / "plain.tar.gz",
    }
    _build_zip(paths["zip_stored"], members, zipfile.ZIP_STORED)
    _build_zip(paths["zip_deflate"], members, zipfile.ZIP_DEFLATED)
    _build_tar(paths["tar"], members, gz=False)
    _build_tar(paths["tar_gz"], members, gz=True)
    if _build_7z_solid(root / "solid.7z", members):
        paths["7z_solid"] = root / "solid.7z"
    return paths


def run_case(
    fmt: str, path: Path, operation: str, cache: str, work: Path
) -> RemoteCaseResult:
    open_kwargs, op = OPERATIONS[operation]
    fs = CountingFileSystem()
    dest = work / f"{fmt}-{operation}-{cache}"
    if cache == PLANNER_MODE:
        with (
            planner_constants(PLANNER_TEST_CONSTANTS),
            open_archive(
                OpenFile(fs, str(path), mode="rb"),
                config=PLANNER_TEST_CONFIG,
                **open_kwargs,
            ) as reader,
        ):
            op(reader, dest)
    else:
        with (
            fs.open(str(path), "rb", **CACHE_MODES[cache]) as remote,
            open_archive(remote, **open_kwargs) as reader,
        ):
            op(reader, dest)
    shutil.rmtree(dest, ignore_errors=True)
    return RemoteCaseResult(
        case=f"{fmt}_{operation}_{cache}",
        format=fmt,
        operation=operation,
        cache=cache,
        range_requests=len(fs.log.ranges),
        metadata_requests=len(fs.log.metadata),
        bytes_fetched=fs.log.bytes_fetched,
        archive_size=path.stat().st_size,
    )


def run_cases(scale: str = "ci") -> list[RemoteCaseResult]:
    results: list[RemoteCaseResult] = []
    with tempfile.TemporaryDirectory(prefix="archivey-remote-") as work_dir:
        work = Path(work_dir)
        fixtures = work / "fixtures"
        fixtures.mkdir()
        for fmt, path in _fixture_paths(fixtures, scale).items():
            for operation in OPERATIONS:
                if (
                    operation in MULTI_STREAM_OPERATIONS
                    and fmt not in MULTI_STREAM_FORMATS
                ):
                    continue
                for cache in CACHE_MODES:
                    results.append(run_case(fmt, path, operation, cache, work))
    return results


def check_against_baseline(
    results: list[RemoteCaseResult], baseline: dict[str, Any]
) -> list[str]:
    """Failures: a request count that moved, or more bytes fetched than the baseline.

    A case missing from either side fails too, so a dropped fixture cannot shrink the
    gate quietly.
    """
    failures: list[str] = []
    base_cases: dict[str, Any] = baseline.get("cases", {})
    seen = set()
    for r in results:
        if not is_gated(r.format, r.operation):
            continue
        seen.add(r.case)
        base = base_cases.get(r.case)
        if base is None:
            failures.append(f"{r.case}: not in the baseline (run --update-baselines)")
            continue
        if r.range_requests != base["range_requests"]:
            failures.append(
                f"{r.case}: {r.range_requests} range requests, baseline "
                f"{base['range_requests']}"
            )
        if r.bytes_fetched > base["bytes_fetched"]:
            failures.append(
                f"{r.case}: fetched {r.bytes_fetched} bytes, baseline "
                f"{base['bytes_fetched']}"
            )
    failures.extend(
        f"{name}: in the baseline but not measured"
        for name in sorted(
            n
            for n, b in base_cases.items()
            if is_gated(b["format"], b["operation"]) and n not in seen
        )
    )
    return failures


def to_payload(results: list[RemoteCaseResult]) -> dict[str, Any]:
    return {
        "io_default_buffer_size": io.DEFAULT_BUFFER_SIZE,
        "model": {
            "latency_s": MODEL_LATENCY_S,
            "bandwidth_bytes_per_s": MODEL_BANDWIDTH_BPS,
        },
        "cases": {
            r.case: {k: v for k, v in asdict(r).items() if k not in {"case"}}
            | {
                "overfetch": round(r.overfetch, 3),
                "gated": is_gated(r.format, r.operation),
            }
            for r in results
        },
    }


def format_report(results: list[RemoteCaseResult]) -> str:
    header = (
        f"{'case':<34} {'requests':>8} {'meta':>5} {'fetched':>10} "
        f"{'overfetch':>9} {'modelled':>9}"
    )
    lines = [header, "-" * len(header)]
    lines.extend(
        f"{r.case:<34} {r.range_requests:>8} {r.metadata_requests:>5} "
        f"{r.bytes_fetched:>10} {r.overfetch:>8.2f}x {r.modelled_s:>8.3f}s"
        for r in results
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scale", default="ci", choices=sorted(REMOTE_SCALES))
    parser.add_argument("--update-baselines", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if args.update_baselines and args.scale != "ci":
        print("--update-baselines writes the ci-scale baseline only", file=sys.stderr)
        return 2

    results = run_cases(scale=args.scale)
    print(format_report(results))
    payload = to_payload(results)
    if args.json_out:
        args.json_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if args.update_baselines:
        REMOTE_BASELINE.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print(f"wrote {REMOTE_BASELINE}")
        return 0
    if args.scale != "ci":
        return 0
    baseline = (
        json.loads(REMOTE_BASELINE.read_text()) if REMOTE_BASELINE.exists() else {}
    )
    if not baseline_applies(baseline):
        print(
            f"baseline measured with io.DEFAULT_BUFFER_SIZE="
            f"{baseline.get('io_default_buffer_size')}, this Python has "
            f"{io.DEFAULT_BUFFER_SIZE}: not gated"
        )
        return 0
    failures = check_against_baseline(results, baseline)
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
