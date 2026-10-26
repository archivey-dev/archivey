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
deterministic, so its counts are exact on every host. Today archivey sees a caller's
fsspec file as a plain file object; the cases open it the two ways a caller would:

- ``nocache``: ``fs.open(path, cache_type="none")``: one request per read call.
- ``default``: ``fs.open(path)``: fsspec's own default cache (``readahead``, 5 MiB
  blocks), which fetches far more than it needs on a small read.

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

from fsspec.spec import AbstractBufferedFile, AbstractFileSystem

from archivey import open_archive

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


# Each cache mode is how a caller would open the fsspec file today.
CACHE_MODES: dict[str, dict[str, Any]] = {
    "nocache": {"cache_type": "none"},
    "default": {},
}


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


# operation name -> (streaming=, callable)
OPERATIONS: dict[str, tuple[bool, Callable[[Any, Path], None]]] = {
    "list": (False, _op_list),
    "read_first": (False, _read_one(lambda n: 0)),
    "read_middle": (False, _read_one(lambda n: n // 2)),
    "read_last": (False, _read_one(lambda n: n - 1)),
    "extract_all": (False, _op_extract_all),
    "stream_members": (True, _op_stream_members),
}


@dataclass(frozen=True)
class RemoteScale:
    members: int
    member_size: int


# The comparison corpus in benchmarks/fixtures.py compresses ~100:1 (a .tar.gz of
# 128 KiB is 1.5 KiB), so over a network almost every case would be one small fetch.
# These members are seeded random bytes: a member's stored span is about its size, so
# the counts show where each read goes.
REMOTE_SCALES: dict[str, RemoteScale] = {
    "ci": RemoteScale(members=32, member_size=16 * 1024),
    "realistic": RemoteScale(members=64, member_size=256 * 1024),
}

# Formats whose bytes depend only on this file and the stdlib's ZIP/TAR writers. The
# compressed ones also depend on the zlib or liblzma build (zlib-ng writes other
# bytes), so their counts are reported but not gated.
GATED_FORMATS = frozenset({"zip_stored", "tar"})


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
        (f"m{i:03d}.bin", rng.randbytes(scale.member_size))
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
    streaming, op = OPERATIONS[operation]
    fs = CountingFileSystem()
    dest = work / f"{fmt}-{operation}-{cache}"
    with (
        fs.open(str(path), "rb", **CACHE_MODES[cache]) as remote,
        open_archive(remote, streaming=streaming) as reader,
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
        if r.format not in GATED_FORMATS:
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
            if b["format"] in GATED_FORMATS and n not in seen
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
            | {"overfetch": round(r.overfetch, 3), "gated": r.format in GATED_FORMATS}
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
