"""Unit tests for opt-in benchmark measurement counters."""

from __future__ import annotations

import gzip
import io
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from archivey import open_archive
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.measurement import ByteCounter, SeekCounter, enable_measurement
from archivey.internal.streams.counting import (
    CountingReader,
    OutputCountingStream,
    SeekCountingStream,
)
from tests.conftest import requires, requires_binary

_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
_RAR_BASIC_CONTENTS = {
    "file1.txt": b"Hello, world!",
    "empty_file.txt": b"",
    "subdir/file2.txt": b"Hello, universe!",
    "implicit_subdir/file3.txt": b"Hello there!",
}

# Controlled fixtures: tight bound (harness uses ×2 slack for arbitrary corpora).
_SOLID_DECODE_FACTOR = 1.1


def test_counting_reader_still_counts_input_bytes() -> None:
    inner = io.BytesIO(b"abcdefgh")
    wrapped = CountingReader(inner)
    assert wrapped.read(3) == b"abc"
    assert wrapped.bytes_read == 3
    buf = bytearray(4)
    assert wrapped.readinto(buf) == 4
    assert wrapped.bytes_read == 7


def test_output_counting_stream_feeds_shared_counter() -> None:
    counter = ByteCounter()
    wrapped = OutputCountingStream(io.BytesIO(b"hello-world"), counter)
    assert wrapped.read(5) == b"hello"
    assert counter.total == 5
    assert wrapped.read() == b"-world"
    assert counter.total == 11


def test_output_counting_stream_forwards_resume_offset() -> None:
    class _Inner(io.BytesIO):
        def nearest_resume_offset(self, target: int) -> int:
            return 12

    wrapped = OutputCountingStream(_Inner(b"x"), ByteCounter())
    assert wrapped.nearest_resume_offset(100) == 12
    assert (
        OutputCountingStream(io.BytesIO(b"x"), ByteCounter()).nearest_resume_offset(0)
        is None
    )


class _RefusingReadinto(io.RawIOBase):
    """A minimal file-like: ``read`` only, so the inherited ``readinto`` raises."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        return self._data.read(n)


class _NonBlocking(io.RawIOBase):
    """A non-blocking source with nothing available: ``read``/``readinto`` give None."""

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> None:
        return None

    def readinto(self, b: object, /) -> None:
        return None


def _wrap_counting(which: str, inner: io.RawIOBase) -> tuple[Any, Callable[[], int]]:
    """Return ``(wrapper, count)`` for one of the two byte-counting wrappers."""
    if which == "CountingReader":
        reader = CountingReader(inner)  # type: ignore[arg-type]
        return reader, lambda: reader.bytes_read
    counter = ByteCounter()
    return OutputCountingStream(inner, counter), lambda: counter.total  # type: ignore[arg-type]


_COUNTING_WRAPPERS = ["CountingReader", "OutputCountingStream"]


@pytest.mark.parametrize("which", _COUNTING_WRAPPERS)
def test_counting_readinto_falls_back_when_inner_refuses(which: str) -> None:
    """An inner that advertises ``readinto`` and refuses it falls back to ``read``."""
    wrapped, count = _wrap_counting(which, _RefusingReadinto(b"0123456789"))
    buf = bytearray(4)
    assert wrapped.readinto(buf) == 4
    assert bytes(buf) == b"0123"
    assert count() == 4


def test_counting_reader_under_buffered_reader_counts_a_refusing_inner() -> None:
    """The production composition: ``BufferedReader`` drives ``raw.readinto``."""
    reader = CountingReader(_RefusingReadinto(b"0123456789"))
    assert io.BufferedReader(reader).read(4) == b"0123"  # type: ignore[arg-type]
    assert reader.bytes_read == 10  # one buffered fill pulls the whole source


@pytest.mark.parametrize("which", _COUNTING_WRAPPERS)
def test_counting_wrappers_refuse_a_non_blocking_inner(which: str) -> None:
    """``None`` from the inner is "no data yet", never EOF: refuse it by name."""
    wrapped, _ = _wrap_counting(which, _NonBlocking())
    with pytest.raises(BlockingIOError, match="non-blocking"):
        wrapped.readinto(bytearray(4))
    with pytest.raises(BlockingIOError, match="non-blocking"):
        wrapped.read(4)


def test_seek_counting_stream_records_seeks_only() -> None:
    counter = SeekCounter()
    inner = io.BytesIO(b"0123456789")
    wrapped = SeekCountingStream(inner, counter)
    assert wrapped.read(2) == b"01"
    assert counter.count == 0
    wrapped.seek(5)
    assert counter.count == 1
    wrapped.seek(0)
    assert counter.count == 2
    assert wrapped.read(2) == b"01"


def test_seek_counting_stream_is_transparent_to_source_byte_size() -> None:
    from archivey.internal.streams.streamtools import source_byte_size

    counter = SeekCounter()
    wrapped = SeekCountingStream(io.BytesIO(b"0123456789"), counter)
    assert source_byte_size(wrapped) == 10
    assert counter.count == 0


def test_output_counting_stream_does_not_advertise_size() -> None:
    # Do not teach source_byte_size to unwrap every DelegatingStream: this
    # wrapper sits on decompressors whose SEEK_END is not cheap. Inner must
    # *have* a cheap size, or the assertion cannot fail for that reason.
    from archivey.internal.streams.streamtools import source_byte_size

    class _Sized(io.BytesIO):
        size = 11

    wrapped = OutputCountingStream(_Sized(b"hello-world"), ByteCounter())
    assert source_byte_size(wrapped) is None


def test_measurement_off_leaves_counters_at_zero(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"payload-aaa")
        zf.writestr("b.txt", b"payload-bbb")
    with open_archive(path) as reader:
        assert isinstance(reader, BaseArchiveReader)
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        assert reader.bytes_decompressed == 0
        assert reader.source_seek_count == 0


def test_measurement_on_counts_zip_decompressed_bytes(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    payload_a = b"payload-aaa"
    payload_b = b"payload-bbb"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", payload_a)
        zf.writestr("b.txt", payload_b)
    with enable_measurement(), open_archive(path) as reader:
        assert isinstance(reader, BaseArchiveReader)
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        assert reader.bytes_decompressed == len(payload_a) + len(payload_b)
        assert reader.source_seek_count > 0


@pytest.mark.parametrize("shape", ["path", "stream"])
def test_single_file_open_counts_metadata_probe_seeks(
    tmp_path: Path, shape: str
) -> None:
    """The metadata probes seek the source at open, and those seeks are counted.

    For a .gz: the header peek seeks to 0 (1), the ``gzip.isize`` trailer peek seeks
    back from the end (1), and the open-time validation decode repositions the shared
    source for the ISIZE tail read (1) and for its first data read (1). The
    compressed-size probe makes none: a path and a ``BytesIO`` have a cheap size, so
    it does not seek to the end.
    """
    path = tmp_path / "a.gz"
    path.write_bytes(gzip.compress(b"payload" * 100))
    source = path if shape == "path" else io.BytesIO(path.read_bytes())
    with enable_measurement(), open_archive(source) as reader:
        assert isinstance(reader, BaseArchiveReader)
        assert reader.source_seek_count == 4


def _build_solid_7z(tmp_path: Path) -> tuple[Path, int]:
    py7zr = pytest.importorskip("py7zr")
    files = {f"f{i}.bin": (b"x" * 4096) + bytes([i]) for i in range(8)}
    source = tmp_path / "src"
    source.mkdir()
    for name, data in files.items():
        (source / name).write_bytes(data)
    archive = tmp_path / "solid.7z"
    with py7zr.SevenZipFile(archive, "w", filters=[{"id": py7zr.FILTER_LZMA2}]) as zf:
        for name in sorted(files):
            zf.write(source / name, arcname=name)
    return archive, sum(len(v) for v in files.values())


def _committed_solid_rar(name: str) -> tuple[Path, int]:
    path = _RAR_FIXTURES / name
    if not path.is_file():
        pytest.skip(f"missing vendored fixture {name}")
    return path, sum(len(v) for v in _RAR_BASIC_CONTENTS.values())


@pytest.mark.parametrize(
    ("fmt", "fixture_name"),
    [
        pytest.param("7z", None, id="7z"),
        pytest.param(
            "rar",
            "basic_solid__.rar",
            id="rar5",
            marks=requires_binary("unrar"),
        ),
        pytest.param(
            "rar",
            "basic_solid__rar4.rar",
            id="rar4",
            marks=requires_binary("unrar"),
        ),
    ],
)
def test_solid_sequential_decodes_once(
    fmt: str, fixture_name: str | None, tmp_path: Path
) -> None:
    """Decode-once on sequential solid sweep is a correctness property per backend.

    Kept here (not only in the benchmark harness) so it runs across the full
    py/os/install matrix. Bound is tight (×1.1) on controlled fixtures.
    """
    if fmt == "7z":
        archive, unpacked = _build_solid_7z(tmp_path)
    else:
        assert fixture_name is not None
        archive, unpacked = _committed_solid_rar(fixture_name)

    with enable_measurement(), open_archive(archive) as reader:
        assert isinstance(reader, BaseArchiveReader)
        assert reader.info.is_solid is True
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        sequential = reader.bytes_decompressed
        assert sequential <= int(unpacked * _SOLID_DECODE_FACTOR)

    with enable_measurement(), open_archive(archive) as reader:
        assert isinstance(reader, BaseArchiveReader)
        names = [m.name for m in reader.members() if m.is_file]
        if fmt == "7z":
            # Folder-level counting: each random open re-decodes the solid block.
            for name in reversed(names):
                reader.read(name)
            assert reader.bytes_decompressed > sequential
        else:
            # RAR named ``unrar p <member>`` only counts that member's *output*
            # bytes (not internal solid rewind), so reverse-all equals sequential.
            # Prove each open is still counted by re-reading a non-empty member.
            non_empty = [
                m.name for m in reader.members() if m.is_file and (m.size or 0) > 0
            ]
            assert non_empty
            target = non_empty[-1]
            reader.read(target)
            mid = reader.bytes_decompressed
            reader.read(target)
            assert reader.bytes_decompressed > mid


@requires("py7zr")
def test_solid_selective_stream_decodes_only_needed(tmp_path: Path) -> None:
    """Unselected solid members must not be decompressed (archive-reading laziness).

    Regression for the perf-review H1 trap: eager solid positioning at yield time
    made ``stream_members`` / selective extract of one early member decode ~the
    whole folder. Bound is prefix+member with a tiny EOF-probe slack.
    """
    files = {f"m{i:03d}.bin": bytes([i]) * 4096 for i in range(8)}
    source = tmp_path / "src"
    source.mkdir()
    for name, data in files.items():
        (source / name).write_bytes(data)
    archive = tmp_path / "solid.7z"
    py7zr = pytest.importorskip("py7zr")
    with py7zr.SevenZipFile(archive, "w", filters=[{"id": py7zr.FILTER_LZMA2}]) as zf:
        for name in sorted(files):
            zf.write(source / name, arcname=name)

    first = "m000.bin"
    needed = len(files[first])
    with enable_measurement(), open_archive(archive) as reader:
        assert isinstance(reader, BaseArchiveReader)
        assert reader.info.is_solid is True
        pairs = [
            (member, stream.read() if stream is not None else None)
            for member, stream in reader.stream_members(members=[first])
        ]
        assert len(pairs) == 1
        member, data = pairs[0]
        assert member.name == first
        assert data == files[first]
        # Whole folder is 32 KiB; a regression that positions every member lands ~28–32 KiB.
        assert reader.bytes_decompressed <= needed + 64

    with enable_measurement(), open_archive(archive) as reader:
        assert isinstance(reader, BaseArchiveReader)
        dest = tmp_path / "out"
        report = reader.extract_all(dest, members=[first])
        assert len(report.results) == 1
        assert (dest / first).read_bytes() == files[first]
        assert reader.bytes_decompressed <= needed + 64
