"""fsspec ``OpenFile`` sources and the remote fetch planner (``archivey.internal.remote``).

The planner tests drive a :class:`RangeSource` over a recording file system, so each
rule of ``fsspec-integration`` design D2 is checked on the exact ranges fetched,
independent of any format. The source tests then open real archives from
``memory://``: the same listings and bytes as a ``BytesIO`` of the same data, the
refused ``OpenFile`` fields, and the facts the source settles at open.
"""

from __future__ import annotations

import dataclasses
import io
import random
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")

from fsspec.core import OpenFile  # noqa: E402

from archivey import (  # noqa: E402
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyUsageError,
    CorruptionError,
    DiagnosticCode,
    DiagnosticPolicy,
    DiagnosticRaisedError,
    ReadError,
    SourceChangedError,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.internal.remote import (  # noqa: E402
    PlannerConstants,
    RangeSource,
    WindowPool,
    planner_constants,
)
from tests.sample_archives import (  # noqa: E402
    corpus_archive_path,
    skip_unless_runnable,
)
from tests.test_short_read_sources import (  # noqa: E402
    _CORPUS_CASES,
    _FIXTURE_ARCHIVES,
    FIXTURE_PASSWORD,
    _probe,
)

KIB = 1024
SMALL = PlannerConstants(min_fetch=16 * KIB, max_fetch=128 * KIB, pool_bytes=128 * KIB)


class RecordingFS:
    """The two calls the planner makes, over one in-memory object, recorded."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.fetches: list[tuple[int, int]] = []
        self._lock = threading.Lock()

    def size(self, path: str) -> int:
        return len(self.data)

    def cat_file(self, path: str, start: int, end: int) -> bytes:
        with self._lock:
            self.fetches.append((start, end))
        return self.data[start:end]


def _source(
    data: bytes,
    *,
    constants: PlannerConstants = SMALL,
    gap: int = 1,
    pool: WindowPool | None = None,
) -> tuple[RangeSource, RecordingFS]:
    # A gap of 1, not 0: ``max_read_through=0`` turns the minimum fetch and the
    # doubling off, and these tests are about them.
    fs = RecordingFS(data)
    pool = WindowPool(constants) if pool is None else pool
    return RangeSource(fs, "obj", size=len(data), pool=pool, max_read_through=gap), fs


DATA = bytes(range(256)) * 4096  # 1 MiB


# --- the planner, rule by rule -----------------------------------------------------------


def test_first_two_fetches_are_min_then_doubling():
    src, fs = _source(DATA)
    out = b""
    for _ in range(6):
        out += src.read(16 * KIB)
    assert out == DATA[: 96 * KIB]
    # Fetches 1 and 2 take the minimum; from the third, 32K, 64K, then the 128K cap.
    assert [e - s for s, e in fs.fetches] == [16 * KIB, 16 * KIB, 32 * KIB, 64 * KIB]


def test_doubling_stops_at_max_fetch():
    src, fs = _source(DATA)
    out = bytearray()
    while chunk := src.read(16 * KIB):
        out += chunk
    assert out == DATA
    assert max(e - s for s, e in fs.fetches) == SMALL.max_fetch
    assert sum(e - s for s, e in fs.fetches) == len(DATA)


def test_a_read_inside_a_window_fetches_nothing():
    src, fs = _source(DATA)
    src.seek(1000)
    assert src.read(100) == DATA[1000:1100]
    src.seek(1050)
    assert src.read(50) == DATA[1050:1100]
    src.seek(5000)
    assert src.read(10) == DATA[5000:5010]
    assert fs.fetches == [(1000, 1000 + 16 * KIB)]


def test_short_forward_gap_is_read_through():
    src, fs = _source(DATA, gap=8 * KIB)
    src.read(100)
    src.seek(16 * KIB + 4 * KIB)  # 4 KiB past the window's end
    assert src.read(100) == DATA[20 * KIB : 20 * KIB + 100]
    # The second fetch starts where the first ended: the gap is fetched, not skipped.
    assert fs.fetches == [(0, 16 * KIB), (16 * KIB, 32 * KIB)]


def test_long_forward_gap_and_backward_jump_start_new_runs():
    src, fs = _source(DATA, gap=8 * KIB)
    src.read(100)
    src.seek(100 * KIB)
    src.read(100)
    src.seek(50 * KIB)
    src.read(100)
    assert fs.fetches == [
        (0, 16 * KIB),
        (100 * KIB, 116 * KIB),
        (50 * KIB, 66 * KIB),
    ]


def test_zero_read_through_fetches_only_what_each_read_needs():
    src, fs = _source(DATA, gap=0)
    assert src.read(100) == DATA[:100]
    src.seek(16 * KIB + 1)
    assert src.read(10) == DATA[16 * KIB + 1 : 16 * KIB + 11]
    for _ in range(4):
        src.read(50)
    # No minimum fetch and no doubling: each fetch is exactly its read.
    assert fs.fetches == [
        (0, 100),
        (16 * KIB + 1, 16 * KIB + 11),
        *[(16 * KIB + 11 + 50 * i, 16 * KIB + 61 + 50 * i) for i in range(4)],
    ]


def test_a_read_longer_than_the_max_fetch_is_not_kept():
    src, fs = _source(DATA)
    assert src.read(512 * KIB) == DATA[: 512 * KIB]
    assert fs.fetches == [(0, 512 * KIB)]
    assert src.pool.held_bytes == 0
    # The run goes on from where the read ended.
    assert src.read(10) == DATA[512 * KIB : 512 * KIB + 10]
    assert fs.fetches[-1][0] == 512 * KIB


def test_reads_stop_at_the_size():
    src, fs = _source(DATA[:1000])
    assert src.read(5000) == DATA[:1000]
    assert src.read(10) == b""
    assert fs.fetches == [(0, 1000)]


def test_close_drops_the_windows():
    src, _ = _source(DATA)
    src.read(100)
    assert src.pool.held_bytes > 0
    src.close()
    assert src.pool.held_bytes == 0
    with pytest.raises(ValueError):
        src.read(1)


def test_pool_bound_holds_and_streams_past_the_window_limit_read_unbuffered():
    """Sixteen interleaved runs, twice the pool's window count at the minimum fetch."""
    pool = WindowPool(SMALL)
    src, fs = _source(DATA, pool=pool)
    starts = [i * 64 * KIB for i in range(16)]
    positions = list(starts)
    for _ in range(4):
        for i in range(16):
            src.seek(positions[i])
            assert src.read(1024) == DATA[positions[i] : positions[i] + 1024]
            positions[i] += 1024
            assert pool.held_bytes <= SMALL.pool_bytes
    assert pool.run_count <= SMALL.window_limit
    # The first eight runs each fetched one window; the other eight fetched exactly
    # each read.
    unbuffered = [(s, e) for s, e in fs.fetches if e - s == 1024]
    assert len(unbuffered) == 8 * 4


def test_fetch_shrinks_when_more_runs_than_the_pool_holds_at_max_fetch():
    constants = PlannerConstants(
        min_fetch=16 * KIB, max_fetch=128 * KIB, pool_bytes=256 * KIB
    )
    pool = WindowPool(constants)
    src, fs = _source(DATA, constants=constants, pool=pool)
    positions = [i * 128 * KIB for i in range(8)]
    for _ in range(8):
        for i in range(8):
            src.seek(positions[i])
            assert src.read(4 * KIB) == DATA[positions[i] : positions[i] + 4 * KIB]
            positions[i] += 4 * KIB
    # Eight runs over 256 KiB: no fetch above 32 KiB.
    assert max(e - s for s, e in fs.fetches) <= constants.pool_bytes // 8
    assert pool.held_bytes <= constants.pool_bytes


def test_a_run_started_after_the_pool_filled_still_gets_a_window():
    """An exactly full pool below the window limit trims the other windows, so a new
    run is buffered, not one request per read."""
    constants = PlannerConstants(
        min_fetch=16 * KIB, max_fetch=128 * KIB, pool_bytes=256 * KIB
    )
    pool = WindowPool(constants)
    src, fs = _source(DATA, constants=constants, pool=pool)
    positions = [0, 512 * KIB]
    while pool.held_bytes < constants.pool_bytes:
        for i in range(2):
            src.seek(positions[i])
            src.read(16 * KIB)
            positions[i] += 16 * KIB
    assert pool.held_bytes == constants.pool_bytes
    before = len(fs.fetches)
    third = 900 * KIB
    for step in range(6):
        src.seek(third + step * KIB)
        assert src.read(KIB) == DATA[third + step * KIB : third + (step + 1) * KIB]
    assert pool.run_count == 3
    assert len(fs.fetches) - before == 1
    assert pool.held_bytes <= constants.pool_bytes


class RangeIgnoringFS(RecordingFS):
    """Answers every range request with the whole object, as an HTTP server that
    ignores ``Range`` does."""

    def cat_file(self, path: str, start: int, end: int) -> bytes:
        super().cat_file(path, start, end)
        return self.data


@pytest.mark.parametrize("read", [10, 6000])
def test_a_file_system_that_ignores_ranges_is_refused(read: int):
    constants = PlannerConstants(min_fetch=1024, max_fetch=4096, pool_bytes=8192)
    fs = RangeIgnoringFS(DATA)
    pool = WindowPool(constants)
    src = RangeSource(fs, "obj", size=len(DATA), pool=pool, max_read_through=0)
    src.seek(100)
    with pytest.raises(OSError, match="does not honour range requests"):
        src.read(read)
    assert pool.held_bytes == 0


def test_an_idle_run_gives_its_window_to_a_new_one():
    pool = WindowPool(SMALL)
    src, _ = _source(DATA, pool=pool)
    for i in range(SMALL.window_limit):
        src.seek(i * 64 * KIB)
        src.read(10)
    assert pool.run_count == SMALL.window_limit
    # Reads on one run until the others are stale.
    for _ in range(SMALL.stale_reads + 1):
        src.seek(0)
        src.read(10)
    src.seek(900 * KIB)
    src.read(10)
    assert pool.run_count == 2


def test_volumes_share_one_pool():
    pool = WindowPool(SMALL)
    a, _ = _source(DATA, pool=pool)
    b, _ = _source(DATA, pool=pool)
    a.read(10)
    b.read(10)
    assert pool.run_count == 2
    a.close()
    assert pool.run_count == 1


# --- OpenFile sources --------------------------------------------------------------------


@pytest.fixture
def memfs() -> Any:
    fs = fsspec.filesystem("memory")
    yield fs
    fs.store.clear()
    fs.pseudo_dirs.clear()
    fs.pseudo_dirs.append("")


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


MEMBERS = {f"d/m{i:02d}.bin": bytes([i]) * (3000 * i + 7) for i in range(20)}


def test_open_archive_reads_an_open_file(memfs):
    memfs.pipe("/t/a.zip", _zip_bytes(MEMBERS))
    of = fsspec.open("memory://t/a.zip")
    with open_archive(of) as reader:
        got = {m.name: reader.read(m) for m in reader.members() if m.is_file}
        assert got == MEMBERS
        detected = detect_format(fsspec.open("memory://t/a.zip"))
        # Equal but for the diagnostics, whose occurrence ids differ by run.
        assert dataclasses.replace(
            reader.format_info, diagnostics=None
        ) == dataclasses.replace(detected, diagnostics=None)
        assert reader.format_info.diagnostics.counts == detected.diagnostics.counts


def test_concurrent_threads_read_their_members(memfs):
    memfs.pipe("/t/a.zip", _zip_bytes(MEMBERS))
    out: dict[str, bytes] = {}
    with (
        planner_constants(SMALL),
        open_archive(
            fsspec.open("memory://t/a.zip"), concurrent_operations=True
        ) as reader,
    ):
        members = [m for m in reader.members() if m.is_file]

        def work(m: Any) -> None:
            out[m.name] = reader.read(m)

        threads = [threading.Thread(target=work, args=(m,)) for m in members]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert out == MEMBERS


def test_open_stream_reads_an_open_file(memfs):
    import gzip

    payload = b"hello remote " * 1000
    memfs.pipe("/t/a.gz", gzip.compress(payload))
    with open_stream(fsspec.open("memory://t/a.gz")) as stream:
        assert stream.read() == payload


def test_a_volume_list_of_open_files(memfs):
    data = _zip_bytes(MEMBERS)
    third = len(data) // 3
    parts = [data[:third], data[third : 2 * third], data[2 * third :]]
    for i, part in enumerate(parts, 1):
        memfs.pipe(f"/t/v.zip.{i:03d}", part)
    sources = [fsspec.open(f"memory://t/v.zip.{i:03d}") for i in (1, 2, 3)]
    with open_archive(sources) as reader:
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == (
            MEMBERS
        )


def test_the_name_is_the_path(memfs):
    memfs.pipe("/d/data.zip", _zip_bytes(MEMBERS))
    with open_archive(fsspec.open("memory://d/data.zip")) as reader:
        assert reader.format_info.format == ArchiveFormat.ZIP
    # Detection's name-keyed checks see the path: a magic-less zlib stream is
    # recognised by its extension alone.
    import zlib

    memfs.pipe("/d/data.zz", zlib.compress(b"x" * 1000))
    info = detect_format(fsspec.open("memory://d/data.zz"))
    assert info.format == ArchiveFormat.ZLIB


def test_mode_other_than_rb_is_refused(memfs):
    memfs.pipe("/t/a.zip", _zip_bytes(MEMBERS))
    with pytest.raises(ArchiveyUsageError, match="mode='rt'") as info:
        open_archive(fsspec.open("memory://t/a.zip", mode="rt"))
    assert isinstance(info.value, ValueError)


def test_resolved_compression_is_refused_before_any_read(memfs):
    memfs.pipe("/t/x.zip.gz", b"not read")
    of = fsspec.open("memory://t/x.zip.gz", compression="infer")
    with pytest.raises(ArchiveyUsageError, match="compression='gzip'"):
        open_archive(of)
    with pytest.raises(ArchiveyUsageError, match="compression='gzip'"):
        detect_format(of)


def test_ignored_open_file_without_compression_reads_the_gzip(memfs):
    import gzip

    memfs.pipe("/t/x.zip.gz", gzip.compress(b"payload"))
    with open_archive(fsspec.open("memory://t/x.zip.gz")) as reader:
        (member,) = reader.members()
        assert reader.read(member) == b"payload"


def test_a_url_string_stays_a_local_path(memfs):
    # The object exists on memory://, so only a local-path open can fail. The OS
    # decides how: FileNotFoundError on POSIX, EINVAL for the ':' on Windows.
    memfs.pipe("/t/a.zip", _zip_bytes(MEMBERS))
    with pytest.raises(OSError):
        open_archive("memory://t/a.zip")


def test_an_already_open_fsspec_file_is_read_as_a_stream(memfs):
    memfs.pipe("/t/a.zip", _zip_bytes(MEMBERS))
    with memfs.open("/t/a.zip", "rb") as f:
        with open_archive(f) as reader:
            names = {m.name for m in reader.members() if m.is_file}
            assert names == set(MEMBERS)
        assert not f.closed


def test_reads_stop_at_the_size_seen_at_open(memfs):
    data = _zip_bytes(MEMBERS)
    memfs.pipe("/t/a.zip", data)
    with open_archive(fsspec.open("memory://t/a.zip")) as reader:
        memfs.pipe("/t/a.zip", data + b"\0" * 100_000)
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == (
            MEMBERS
        )


def test_import_archivey_does_not_import_fsspec(tmp_path: Path):
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes({"x": b"y"}))
    code = (
        "import sys, archivey\n"
        f"with archivey.open_archive({str(path)!r}) as r: r.members()\n"
        "assert 'fsspec' not in sys.modules, 'fsspec imported'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


@pytest.mark.parametrize(
    "value", [-1, True, 1.5, None, "1"], ids=["neg", "bool", "float", "none", "str"]
)
def test_max_read_through_is_checked(value: object):
    with pytest.raises(ArchiveyUsageError, match="max_read_through"):
        ArchiveyConfig(max_read_through=value)  # type: ignore[arg-type]


def test_max_read_through_reaches_the_planner(memfs):
    memfs.pipe("/t/a.zip", _zip_bytes(MEMBERS))
    with open_archive(
        fsspec.open("memory://t/a.zip"), config=ArchiveyConfig(max_read_through=0)
    ) as reader:
        source = reader._source
        assert source is not None
        ranged = source._reader
        assert isinstance(ranged, RangeSource)
        assert ranged.max_read_through == 0


# --- the corpus through the planner ------------------------------------------------------


_NAME = "/src/archive"


class _NamedBytesIO(io.BytesIO):
    """The baseline: a ``BytesIO`` named as the ``OpenFile`` is, since a single-file
    archive names its member after its source."""

    name = _NAME


def _open_file(memfs: Any, data: bytes) -> OpenFile:
    memfs.pipe(_NAME, data)
    return fsspec.open(f"memory://{_NAME}")


@pytest.mark.parametrize(("entry", "key"), _CORPUS_CASES)
def test_corpus_archive_reads_the_same_through_the_planner(
    entry: Any, key: str, tmp_path: Path, memfs: Any
) -> None:
    """Task 2.4: identical listings and bytes to a ``BytesIO`` of the same data, with
    the planner's constants small so every archive crosses windows."""
    skip_unless_runnable(entry, key)
    data = corpus_archive_path(entry, key, tmp_path).read_bytes()
    baseline = _probe(_NamedBytesIO(data), entry.passwords)
    with planner_constants(SMALL):
        assert _probe(_open_file(memfs, data), entry.passwords) == baseline


@pytest.mark.parametrize(
    "path", _FIXTURE_ARCHIVES, ids=[p.name for p in _FIXTURE_ARCHIVES]
)
def test_committed_fixture_reads_the_same_through_the_planner(
    path: Path, memfs: Any
) -> None:
    data = path.read_bytes()
    try:
        baseline = _probe(_NamedBytesIO(data), (FIXTURE_PASSWORD,))
    except Exception as exc:  # noqa: BLE001 - mirrors the short-read sweep's skip
        pytest.skip(f"fixture does not open standalone from a BytesIO: {exc}")
    with planner_constants(SMALL):
        assert _probe(_open_file(memfs, data), (FIXTURE_PASSWORD,)) == baseline


# --- a changed object (design D7, tier 3) ------------------------------------------------


def test_a_shorter_object_raises_source_changed(memfs):
    data = _zip_bytes(MEMBERS)
    memfs.pipe("/t/a.zip", data)
    # No read-through, so the listing leaves the members' bytes unfetched.
    config = ArchiveyConfig(max_read_through=0)
    with open_archive(fsspec.open("memory://t/a.zip"), config=config) as reader:
        members = [m for m in reader.members() if m.is_file]
        memfs.pipe("/t/a.zip", data[: len(data) // 2])
        with pytest.raises(SourceChangedError) as info:
            for member in members:
                reader.read(member)
    assert isinstance(info.value, ReadError)
    assert not isinstance(info.value, CorruptionError)


def test_a_longer_object_is_not_detected(memfs):
    """What tier 3 cannot see (design D7): every fetch lies inside the size read at
    open, and a longer replacement returns those ranges in full. Pinned so the docs
    cannot drift back to "a change of length raises"."""
    data = _zip_bytes({"a.bin": b"a" * 400_000})
    memfs.pipe("/t/a.zip", data)
    config = ArchiveyConfig(max_read_through=0)
    with open_archive(fsspec.open("memory://t/a.zip"), config=config) as reader:
        (member,) = [m for m in reader.members() if m.is_file]
        memfs.pipe("/t/a.zip", b"B" * (2 * len(data)))
        with pytest.raises(CorruptionError) as info:
            reader.read(member)
    assert not isinstance(info.value, SourceChangedError)


def test_a_planner_fetch_of_another_length_raises():
    src, fs = _source(DATA)
    fs.data = DATA[:100]
    with pytest.raises(SourceChangedError, match="changed while it was read"):
        src.read(10)


def _volume_bytes(data: bytes, parts: int) -> list[bytes]:
    step = -(-len(data) // parts)
    return [data[i : i + step] for i in range(0, len(data), step)]


@pytest.mark.parametrize("how", ["detected", "format", "volumes"])
def test_undetectable_change_is_recorded_at_open(memfs, how: str):
    data = _zip_bytes(MEMBERS)
    if how == "volumes":
        names = []
        for n, part in enumerate(_volume_bytes(data, 3), start=1):
            memfs.pipe(f"/t/v.zip.{n:03d}", part)
            names.append(f"memory://t/v.zip.{n:03d}")
        source: Any = [fsspec.open(name) for name in names]
    else:
        memfs.pipe("/t/a.zip", data)
        source = fsspec.open("memory://t/a.zip")
    kwargs: dict[str, Any] = {"format": ArchiveFormat.ZIP} if how == "format" else {}
    with open_archive(
        source,
        config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        **kwargs,
    ) as reader:
        assert (
            reader.diagnostics.counts.get(DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE)
            == 1
        )
        (diag,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE
        ]
        assert diag.context.kind == "source_change"
        assert diag.context.protocol == "memory"
    if how == "detected":
        info = detect_format(fsspec.open("memory://t/a.zip"))
        assert (
            info.diagnostics.counts.get(DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE) == 1
        )


def test_open_stream_with_format_records_it_and_pedantic_refuses(memfs):
    import gzip

    memfs.pipe("/t/a.gz", gzip.compress(b"payload"))
    seen: list[Any] = []
    with open_stream(
        fsspec.open("memory://t/a.gz"),
        format=ArchiveFormat.GZ,
        config=ArchiveyConfig(on_diagnostic=seen.append),
    ) as s:
        assert s.read() == b"payload"
    assert [d.code for d in seen] == [DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE]
    # The leak oracle checks the source this refusal opened is closed.
    with pytest.raises(DiagnosticRaisedError):
        open_stream(
            fsspec.open("memory://t/a.gz"),
            format=ArchiveFormat.GZ,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.PEDANTIC),
        )


def test_a_local_source_records_no_source_change(tmp_path: Path):
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes(MEMBERS))
    with open_archive(path) as reader:
        assert (
            DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE not in reader.diagnostics.counts
        )


# --- backend range hints (design D2 rule 3) ----------------------------------------------


def test_a_hint_fetches_its_span_in_one_request_from_its_start():
    src, fs = _source(DATA)
    src.will_read(1000, 60_000)
    src.seek(50_000)  # a backend may read the span's end first
    assert src.read(100) == DATA[50_000:50_100]
    src.seek(1000)
    assert src.read(100) == DATA[1000:1100]
    assert fs.fetches == [(1000, 60_000)]


def test_a_hint_inside_a_window_fetches_nothing():
    src, fs = _source(DATA)
    src.read(10)
    src.will_read(100, 200)
    assert src.pending_hint is None
    src.seek(150)
    src.read(10)
    assert fs.fetches == [(0, 16 * KIB)]


def test_a_hint_past_the_max_fetch_keeps_the_part_that_ends_with_the_read():
    src, fs = _source(DATA)
    src.will_read(0, 400 * KIB)
    src.seek(300 * KIB)
    assert src.read(10) == DATA[300 * KIB : 300 * KIB + 10]
    ((start, end),) = fs.fetches
    assert end - start <= SMALL.max_fetch
    assert start <= 300 * KIB < 300 * KIB + 10 <= end


def test_a_hint_past_a_runs_window_starts_its_own_run():
    # The read at 20 KiB continues the first run, but its hint starts past that run's
    # window: the hinted span gets a run of its own, and the first window stays for
    # whichever stream is still reading it.
    src, fs = _source(DATA, gap=8 * KIB)
    assert src.read(10) == DATA[:10]
    src.will_read(20 * KIB, 30 * KIB)
    src.seek(20 * KIB)
    assert src.read(100) == DATA[20 * KIB : 20 * KIB + 100]
    src.seek(100)
    assert src.read(100) == DATA[100:200]
    first, second = fs.fetches
    assert first == (0, 16 * KIB)
    assert second[0] == 20 * KIB


def test_a_hint_never_changes_the_bytes():
    src, _ = _source(DATA)
    for start in range(0, len(DATA), 37 * KIB):
        src.will_read(start, start + 50 * KIB)
        src.seek(start + 7)
        assert src.read(3000) == DATA[start + 7 : start + 3007]


def test_a_local_source_ignores_hints(tmp_path: Path):
    from archivey.internal.source import ArchiveSource

    path = tmp_path / "x"
    path.write_bytes(b"abc")
    with ArchiveSource.for_path(path) as source:
        source.will_read(0, 3)  # no remote source: nothing happens
        assert source.read() == b"abc"


def test_zip_lists_in_two_requests_and_reads_a_member_in_one_more():
    """The spec ceiling: the detection head, then the tail with the whole directory."""
    data = _zip_bytes(MEMBERS)
    fs = RecordingFS(data)
    with open_archive(OpenFile(fs, "/a.zip", mode="rb")) as reader:
        members = [m for m in reader.members() if m.is_file]
        assert len(fs.fetches) <= 2
        assert (
            reader.read(members[len(members) // 2])
            == MEMBERS[members[len(members) // 2].name]
        )
        assert len(fs.fetches) <= 3


def _py7zr_bytes(members: dict[str, bytes], tmp_path: Path, **kwargs: Any) -> bytes:
    py7zr = pytest.importorskip("py7zr")
    path = tmp_path / "a.7z"
    with py7zr.SevenZipFile(path, "w", **kwargs) as archive:
        for name, data in members.items():
            archive.writestr(data, name)
    return path.read_bytes()


def test_7z_with_an_encoded_header_lists_in_two_requests(tmp_path: Path):
    """py7zr, like 7-Zip, writes an encoded header: a short record after a packed
    header stream. The next-header hint fetches both with the detection head's
    follow-up, so the listing is the spec's 2 requests."""
    rng = random.Random(7)
    members = {f"m{i}.bin": rng.randbytes(40_000) for i in range(12)}
    data = _py7zr_bytes(members, tmp_path)
    fs = RecordingFS(data)
    with (
        planner_constants(SMALL),
        open_archive(OpenFile(fs, "/a.7z", mode="rb")) as reader,
    ):
        assert len([m for m in reader.members() if m.is_file]) == 12
    assert len(fs.fetches) <= 2


def test_7z_hints_the_folder_pack_stream_before_a_member_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The pack-stream hint names the folder's pack span in source offsets: from 32
    (right after the signature header on a plain py7zr archive) for the pack size.
    Red with the hint call removed, or its origin off by one."""
    py7zr = pytest.importorskip("py7zr")
    rng = random.Random(8)
    payload = rng.randbytes(300_000)
    data = _py7zr_bytes(
        {"big.bin": payload}, tmp_path, filters=[{"id": py7zr.FILTER_COPY}]
    )
    hints: list[tuple[int, int]] = []
    original = RangeSource.will_read

    def spy(self: RangeSource, start: int, end: int) -> None:
        hints.append((start, end))
        original(self, start, end)

    monkeypatch.setattr(RangeSource, "will_read", spy)
    fs = RecordingFS(data)
    with open_archive(OpenFile(fs, "/a.7z", mode="rb")) as reader:
        (member,) = [m for m in reader.members() if m.is_file]
        listed = list(hints)
        assert reader.read(member) == payload
    assert hints[len(listed) :] == [(32, 32 + 300_000)]


def _iso_bytes(members: dict[str, bytes]) -> bytes:
    pycdlib = pytest.importorskip("pycdlib")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    for name, data in members.items():
        iso.add_fp(io.BytesIO(data), len(data), f"/{name.upper()};1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def test_iso_reads_a_member_within_the_max_fetch_in_one_request():
    """The spec ceiling: list + 1. The ISO reader hints the member's extent through
    ``ReaderSource.will_read``, so the read is one fetch from the extent's start rather
    than a ramp from the minimum fetch. Red with the hint call removed (3 fetches)."""
    rng = random.Random(9)
    # The default constants: under SMALL the cap shrinks with the listing's windows.
    payload = rng.randbytes(400_000)
    data = _iso_bytes({"a.bin": rng.randbytes(50_000), "b.bin": payload})
    fs = RecordingFS(data)
    with open_archive(OpenFile(fs, "/a.iso", mode="rb")) as reader:
        member = reader.get("B.BIN")
        listed = len(fs.fetches)
        # Small reads, as a consumer streaming the member does: without the hint the
        # first one starts a run at the minimum fetch, which then doubles.
        with reader.open(member) as stream:
            assert b"".join(iter(lambda: stream.read(4096), b"")) == payload
    extent = data.index(payload[:64])
    assert fs.fetches[listed:] == [(extent, extent + len(payload))]


def test_a_plugin_hint_reaches_the_range_source(monkeypatch: pytest.MonkeyPatch):
    """``ReaderSource.will_read`` passes the plugin's offsets on unchanged."""
    rng = random.Random(10)
    payload = rng.randbytes(20_000)
    data = _iso_bytes({"b.bin": payload})
    hints: list[tuple[int, int]] = []
    original = RangeSource.will_read

    def spy(self: RangeSource, start: int, end: int) -> None:
        hints.append((start, end))
        original(self, start, end)

    monkeypatch.setattr(RangeSource, "will_read", spy)
    with open_archive(OpenFile(RecordingFS(data), "/a.iso", mode="rb")) as reader:
        assert reader.read(reader.get("B.BIN")) == payload
    extent = data.index(payload[:64])
    assert hints == [(extent, extent + len(payload))]
