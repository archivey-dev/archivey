"""fsspec ``OpenFile`` sources and the remote fetch planner (``archivey.internal.remote``).

The planner tests drive a :class:`RangeSource` over a recording file system, so each
rule of ``fsspec-integration`` design D2 is checked on the exact ranges fetched,
independent of any format. The source tests then open real archives from
``memory://``: the same listings and bytes as a ``BytesIO`` of the same data, the
refused ``OpenFile`` fields, and the facts the source settles at open.
"""

from __future__ import annotations

import bz2
import dataclasses
import gzip
import io
import logging
import lzma
import random
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, cast

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
from archivey.internal.source import seeks_to_end_are_cheap  # noqa: E402
from archivey.internal.volumes import ConcatenatedFile  # noqa: E402
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


@pytest.mark.parametrize(
    ("suffix", "compress"),
    [(".gz", "gzip"), (".bz2", "bz2"), (".xz", "lzma")],
)
def test_a_compressed_open_file_reads_the_archive_inside(
    memfs, caplog, suffix, compress
):
    import importlib

    module = importlib.import_module(compress)
    memfs.pipe(f"/t/x.zip{suffix}", module.compress(_zip_bytes(MEMBERS)))
    of = fsspec.open(f"memory://t/x.zip{suffix}", compression="infer")
    with caplog.at_level(logging.WARNING, logger="archivey.streams"):
        assert detect_format(of).format == ArchiveFormat.ZIP
        with open_archive(of) as reader:
            files = {m.name: reader.read(m) for m in reader.members() if m.is_file}
            assert files == MEMBERS
    warnings = [r for r in caplog.records if "compression=" in r.getMessage()]
    assert len(warnings) == 2
    assert "compression=None" in warnings[0].getMessage()


@pytest.mark.parametrize("how", ["read", "refused", "detected"])
def test_a_compressed_open_file_closes_the_file_under_its_decoder(
    memfs, monkeypatch, how: str
):
    """archivey opens fsspec's file and its decompressor, so it closes both: a
    decompressor handed a file object leaves it open. The caller's ``OpenFile`` is not
    entered, so its own ``close()`` cannot close a stream archivey is reading."""
    import gzip

    from archivey import FormatDetectionError

    memfs.pipe("/t/x.zip.gz", gzip.compress(_zip_bytes(MEMBERS)))
    memfs.pipe("/t/y.txt.gz", gzip.compress(b"no archive"))
    opened: list[io.BytesIO] = []
    real_open = type(memfs).open

    def spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        # A file of its own: the memory file system hands out the object it stores,
        # whose close() does nothing, so it could not tell a close.
        f = io.BytesIO(real_open(self, *args, **kwargs).getvalue())
        opened.append(f)
        return f

    monkeypatch.setattr(type(memfs), "open", spy)
    if how == "read":
        of = fsspec.open("memory://t/x.zip.gz", compression="infer")
        with open_archive(of) as reader:
            assert {m.name for m in reader.members() if m.is_file} == set(MEMBERS)
            assert opened
            assert not any(f.closed for f in opened)
    elif how == "refused":
        of = fsspec.open("memory://t/y.txt.gz", compression="infer")
        with pytest.raises(FormatDetectionError):
            open_archive(of)
    else:
        of = fsspec.open("memory://t/x.zip.gz", compression="infer")
        assert detect_format(of).format == ArchiveFormat.ZIP
    assert opened
    assert all(f.closed for f in opened)
    assert of.fobjects == []


def test_a_compressed_open_file_records_that_no_change_is_checked(memfs):
    import gzip

    memfs.pipe("/t/x.zip.gz", gzip.compress(_zip_bytes(MEMBERS)))
    of = fsspec.open("memory://t/x.zip.gz", compression="gzip")
    with open_archive(of) as reader:
        (diag,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE
        ]
    assert diag.context.protocol == "memory"
    assert "compression='gzip'" in diag.context.reason
    assert "compression='gzip'" in diag.message
    info = detect_format(of)
    assert info.diagnostics.counts.get(DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE) == 1


def test_a_compressed_open_file_holding_no_archive_names_fsspec_decoding(memfs):
    import gzip

    from archivey import FormatDetectionError, open_stream

    memfs.pipe("/t/y.txt.gz", gzip.compress(b"hello"))
    of = fsspec.open("memory://t/y.txt.gz", compression="infer")
    with pytest.raises(
        ArchiveyUsageError, match=r"compression='gzip'.*compression=None"
    ):
        open_stream(of)
    for call in (open_archive, detect_format):
        with pytest.raises(FormatDetectionError) as info:
            call(of)
        notes = getattr(info.value, "__notes__", [])
        assert any("compression='gzip'" in note for note in notes), notes
    # Without compression=, archivey decodes the gzip itself.
    with open_stream(fsspec.open("memory://t/y.txt.gz")) as stream:
        assert stream.read() == b"hello"


def test_a_compressed_open_file_in_a_volume_list_is_refused(memfs):
    memfs.pipe("/t/a.001", b"not read")
    memfs.pipe("/t/a.002", b"not read")
    parts = [
        fsspec.open("memory://t/a.001", compression="gzip"),
        fsspec.open("memory://t/a.002"),
    ]
    with pytest.raises(ArchiveyUsageError, match="compression='gzip'"):
        open_archive(parts)


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


def test_a_change_stays_seen_by_every_later_read():
    """A handler that takes the first ``SourceChangedError`` for damage cannot make the
    source read on: each later read raises again, a read a window still holds too."""
    src, fs = _source(DATA)
    assert src.read(10) == DATA[:10]  # leaves a window over the start
    fs.data = DATA[:100]
    src.seek(500_000)
    with pytest.raises(SourceChangedError):
        src.read(10)
    fs.data = DATA
    src.seek(0)
    with pytest.raises(SourceChangedError, match="changed while it was read"):
        src.read(10)


def _cut_on_fetch(monkeypatch: pytest.MonkeyPatch, memfs: Any, past: int) -> dict:
    """The first fetch that starts at or past ``past`` while ``armed["on"]`` finds the
    object cut to the bytes before it, and the original is back for every later fetch:
    the object was replaced by a shorter one and then replaced again. So only that one
    fetch can see the change, and a handler that swallows it leaves later reads with
    nothing to raise on."""
    real = type(memfs).cat_file
    armed = {"on": True}

    def cat_file(self: Any, path: str, start: Any = None, end: Any = None, **kw: Any):
        if armed["on"] and start is not None and start >= past:
            armed["on"] = False
            whole = real(self, path)
            self.pipe(path, whole[:start])
            try:
                return real(self, path, start=start, end=end, **kw)
            finally:
                self.pipe(path, whole)
        return real(self, path, start=start, end=end, **kw)

    monkeypatch.setattr(type(memfs), "cat_file", cat_file)
    return armed


def _stored_tar_gz(payload: bytes, tail: int = 0) -> bytes:
    import gzip
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("a")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    # Level 0: the deflate is stored, so offsets in the gzip follow the TAR's.
    return gzip.compress(buf.getvalue() + b"\0" * tail, 0)


def test_a_change_during_detection_raises_rather_than_another_format(
    memfs, monkeypatch
):
    """The gzip inner-container probe reads past the first fetch, and the change it
    meets must not make the answer GZ instead of TAR_GZ."""
    memfs.pipe("/t/x.tar.gz", _stored_tar_gz(random.randbytes(200_000)))
    _cut_on_fetch(monkeypatch, memfs, past=1)
    with pytest.raises(SourceChangedError):
        detect_format(
            fsspec.open("memory://t/x.tar.gz"),
            config=ArchiveyConfig(max_read_through=0),
        )


def test_a_change_while_a_single_compressed_file_opens_raises(memfs, monkeypatch):
    """A lone ``.gz``: the change meets detection's inner-container probe, and the
    open must raise it rather than go on as if the gzip held no archive."""
    import gzip

    memfs.pipe("/t/x.bin.gz", gzip.compress(random.randbytes(200_000), 0))
    _cut_on_fetch(monkeypatch, memfs, past=1)
    with pytest.raises(SourceChangedError) as info:
        open_archive(
            fsspec.open("memory://t/x.bin.gz"),
            config=ArchiveyConfig(max_read_through=0),
        )
    # Named as every other open error is, though detection raised it.
    assert info.value.archive_name == "/t/x.bin.gz"


def test_a_change_swallowed_while_the_reader_is_built_is_stamped(memfs, monkeypatch):
    """A backend that takes the change for damage while it is built: the error that
    ends the open names the archive and the format, as the open's other errors do."""
    from archivey.internal.base_reader import BaseArchiveReader

    data = _zip_bytes(MEMBERS)
    memfs.pipe("/t/a.zip", data)

    def swallowing_validate(self: Any) -> None:
        # In place of the reader's own check, which would list the members and end
        # with the change at the walk's end instead.
        armed["on"] = True
        source = self._source
        source.seek(0)
        try:
            source.read(len(data))
        except SourceChangedError:
            pass  # a handler built for damage

    monkeypatch.setattr(BaseArchiveReader, "_validate_at_open", swallowing_validate)
    armed = _cut_on_fetch(monkeypatch, memfs, past=1)
    armed["on"] = False
    with pytest.raises(SourceChangedError) as info:
        open_archive(
            fsspec.open("memory://t/a.zip"),
            format=ArchiveFormat.ZIP,
            config=ArchiveyConfig(max_read_through=0),
        )
    assert info.value.archive_name == "/t/a.zip"
    assert info.value.source_format == ArchiveFormat.ZIP


@pytest.mark.parametrize(
    "policy", [DiagnosticPolicy(), DiagnosticPolicy.STRICT], ids=["default", "strict"]
)
def test_a_change_during_the_tar_end_scan_raises(memfs, monkeypatch, policy):
    """The scan past the TAR end-of-archive marker takes a ``ReadError`` from the codec
    for a tail that fails to decode, and reports ``DIGEST_UNVERIFIABLE``; a change of
    the object is not that, and the pass ends with it. Under ``STRICT`` that report
    raises inside the handler, and the change still wins."""
    payload = random.randbytes(200_000)
    memfs.pipe("/t/x.tar.gz", _stored_tar_gz(payload, tail=3 * 2**20))
    config = ArchiveyConfig(diagnostic_policy=policy, max_read_through=0)
    armed = _cut_on_fetch(monkeypatch, memfs, past=400_000)
    armed["on"] = False
    with open_archive(fsspec.open("memory://t/x.tar.gz"), config=config) as reader:
        armed["on"] = True
        with pytest.raises(SourceChangedError):
            for member, stream in reader.stream_members():
                assert member.name == "a"
                assert stream is not None
                assert stream.read() == payload


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


# --- tail reads (design D1) -------------------------------------------------------------


def _udif_after_bzip2() -> bytes:
    """A bzip2 stream with a UDIF ``koly`` block at the end: an image whose first
    block is bzip2. The ``koly`` block is past the detection prefix."""
    koly = b"koly" + (4).to_bytes(4, "big") + (512).to_bytes(4, "big")
    payload = random.Random(44).randbytes(200_000)
    return bz2.compress(payload) + koly + bytes(512 - len(koly))


_TAIL_CASES = {
    "f.xz": lzma.compress(b"hello" * 1000),
    "f.gz": gzip.compress(b"x" * 100_000),
    "img.dmg": _udif_after_bzip2(),
}


def _listing(source: Any) -> list[tuple[str, int | None, dict]]:
    with open_archive(source) as reader:
        return [(m.name, m.size, dict(m.extra)) for m in reader.members()]


@pytest.mark.parametrize("name", sorted(_TAIL_CASES))
def test_a_remote_archive_detects_as_a_local_one(
    name: str, tmp_path: Path, memfs: Any
) -> None:
    """The tail reads run on a remote source: the UDIF ``koly`` block outranks the
    bzip2 hit, as from a path. Red when a range source declines the tail."""
    data = _TAIL_CASES[name]
    path = tmp_path / name
    path.write_bytes(data)
    memfs.pipe(f"/t/{name}", data)
    local = detect_format(path)
    remote = detect_format(fsspec.open(f"memory://t/{name}"))
    assert remote.format == local.format
    assert remote.unavailable_tiers == local.unavailable_tiers
    if name == "img.dmg":
        assert remote.format == ArchiveFormat.DMG


@pytest.mark.parametrize("name", ["f.gz", "f.xz"])
def test_a_remote_single_file_lists_as_a_local_one(
    name: str, tmp_path: Path, memfs: Any
) -> None:
    """The ``.xz`` index gives ``size`` and the gzip trailer gives ``gzip.isize``
    from an ``OpenFile`` too. Red when a range source declines the tail."""
    data = _TAIL_CASES[name]
    path = tmp_path / name
    path.write_bytes(data)
    memfs.pipe(f"/t/{name}", data)
    local = _listing(path)
    assert _listing(fsspec.open(f"memory://t/{name}")) == local
    (entry,) = local
    if name == "f.xz":
        assert entry[1] == 5000
    else:
        assert entry[2] == {"gzip.isize": 100_000}


@pytest.mark.parametrize(
    ("name", "requests"),
    [
        # The head, then the 512-byte koly block: one request for the tail.
        ("img.dmg", 2),
        # Detection's head holds the whole file: the tail reads cost nothing more.
        ("f.gz", 1),
        ("f.xz", 1),
    ],
)
def test_tail_reads_cost_one_request_each(name: str, requests: int) -> None:
    """The ruling's price: a tail read is one range request, never a walk."""
    data = _TAIL_CASES[name]
    fs = RecordingFS(data)
    source = OpenFile(fs, f"/{name}", mode="rb")
    if name == "img.dmg":
        detect_format(source)
    else:
        _listing(source)
    assert len(fs.fetches) == requests


def test_a_large_remote_xz_reads_its_index_from_the_tail() -> None:
    """A ``.xz`` past the detection head: the stream footer and the index are read
    from the tail, so ``size`` is known without decoding it. The tail is one
    request (the minimum fetch, ending at the end) beside the two the head takes
    with or without it."""
    payload = random.Random(45).randbytes(300_000)
    data = lzma.compress(payload, preset=0)
    fs = RecordingFS(data)
    config = ArchiveyConfig(max_read_through=16 * KIB)
    with (
        planner_constants(SMALL),
        open_archive(OpenFile(fs, "/big.xz", mode="rb"), config=config) as reader,
    ):
        (member,) = reader.members()
    assert member.size == len(payload)
    assert fs.fetches == [
        (0, 16 * KIB),
        (len(data) - 16 * KIB, len(data)),
        (16 * KIB, 64 * KIB),
    ]


def test_a_new_run_at_the_end_keeps_the_minimum_fetch() -> None:
    """A tail read that steps backward (a footer, then the index before it) is one
    request: the first window ends at the end and holds the minimum fetch. Red when
    the window starts at the read and holds only the bytes to the end."""
    source, fs = _source(DATA)
    source.seek(len(DATA) - 12)
    assert source.read(12) == DATA[-12:]
    source.seek(len(DATA) - 5000)
    assert source.read(100) == DATA[-5000:-4900]
    assert fs.fetches == [(len(DATA) - 16 * KIB, len(DATA))]


def test_a_range_source_resumes_at_any_offset() -> None:
    source, _ = _source(DATA)
    assert source.nearest_resume_offset(12_345) == 12_345
    assert seeks_to_end_are_cheap(cast("BinaryIO", source))


def test_a_joined_set_of_range_sources_asks_the_volume_that_holds_the_target() -> None:
    pool = WindowPool(SMALL)
    first, _ = _source(DATA[:1000], pool=pool)
    second, _ = _source(DATA[1000:5000], pool=pool)
    joined = ConcatenatedFile([cast("BinaryIO", first), cast("BinaryIO", second)])
    assert joined.seek_is_expensive
    assert joined.nearest_resume_offset(3000) == 3000
    assert joined.nearest_resume_offset(5000) == 5000
    assert seeks_to_end_are_cheap(cast("BinaryIO", joined))
