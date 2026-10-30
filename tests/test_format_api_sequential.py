"""The plugin API's sequential shape: a format read in one forward pass.

The test format, TOYS, is defined here with ``archivey.formats`` and the root API only:
each member is a header (magic, type, name, data length, CRC-32), then its data, padded
to four bytes; a header of type ``E`` ends the archive. Symlinks store their target as
their data, as CPIO's do. Each test registers it on a registry restored afterwards
(``toys`` fixture).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import random
import struct
import threading
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO, ClassVar

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveReader,
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    ExtractionLimits,
    MemberType,
    PluginContainer,
    ResourceLimitError,
    StreamFormat,
    TruncatedError,
    detect_format,
    format_availability,
    open_archive,
)
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.diagnostics import DiagnosticCode
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberDigest,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
    register_format,
)
from archivey.internal.format_adapter import registration_scope
from archivey.internal.measurement import enable_measurement
from archivey.internal.streams.streamtools import ReadAheadStream
from tests.streams_util import CountingBytesIO, NonSeekableBytesIO

_MAGIC = b"TS"
_HEADER = struct.Struct("<2scHII")  # magic, type, name length, data length, CRC-32
_TYPES = {b"F": MemberType.FILE, b"D": MemberType.DIRECTORY, b"L": MemberType.SYMLINK}
_CODES = {kind: code for code, kind in _TYPES.items()}


class ToysContainer(PluginContainer):
    TOYS = "toys"
    BAD_SIZE = "toys-bad-size"
    SUM16 = "toys-sum16"
    NO_DIGEST = "toys-no-digest"
    CLOSING = "toys-closing"
    RPMISH = "toys-rpmish"
    DECODED = "toys-decoded"
    PEEKING = "toys-peeking"
    SIZED_EMPTY_DIRECTORY = "toys-sized-empty-directory"


TOYS = ArchiveFormat(ToysContainer.TOYS, StreamFormat.UNCOMPRESSED)


def _pad(n: int) -> int:
    return -n % 4


def build_toys(
    entries: list[tuple[str, MemberType, bytes]],
    *,
    crcs: dict[int, int] | None = None,
    end: bool = True,
) -> bytes:
    """A TOYS archive; ``crcs`` overrides what a header stores, and ``end=False``
    leaves the end header out."""
    out = bytearray()
    for i, (name, kind, payload) in enumerate(entries):
        raw = name.encode()
        crc = (crcs or {}).get(i, zlib.crc32(payload))
        out += _HEADER.pack(_MAGIC, _CODES[kind], len(raw), len(payload), crc) + raw
        out += payload + bytes(_pad(len(payload)))
    if end:
        out += _HEADER.pack(_MAGIC, b"E", 0, 0, 0)
    return bytes(out)


class ToysReader(SequentialReader):
    link_target_in_data = True

    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        while True:
            at = stream.offset
            magic, code, name_len, length, crc = stream.read_struct(_HEADER)
            if magic != _MAGIC:
                raise CorruptionError(f"no TOYS header at offset {at}")
            if code == b"E":
                return
            kind = _TYPES.get(code)
            if kind is None:
                raise CorruptionError(f"unknown TOYS member type {code!r} at {at}")
            raw = stream.read_exact(name_len)
            member = ArchiveMember(
                type=kind, name=self._context.decode_name(raw), raw_name=raw
            )
            digests = (
                (MemberDigest("crc32", crc.to_bytes(4, "big")),)
                if kind is MemberType.FILE
                else ()
            )
            yield MemberSpan(member, length, digests)
            stream.skip(_pad(length))


class ToysHandler(SequentialFormatHandler):
    format = TOYS
    extensions = (".toys",)
    magic = (Magic(0, _MAGIC),)
    uses_encoding = True

    def open_sequential(self, context: ReaderContext) -> ToysReader:
        return ToysReader(context)


@pytest.fixture
def toys() -> Iterator[ArchiveFormat]:
    with registration_scope():
        register_format(ToysHandler)
        yield TOYS


_ENTRIES: list[tuple[str, MemberType, bytes]] = [
    ("docs", MemberType.DIRECTORY, b""),
    ("docs/a.txt", MemberType.FILE, b"alpha\n"),
    ("link", MemberType.SYMLINK, b"docs/a.txt"),
    ("b.bin", MemberType.FILE, bytes(range(256)) * 400),
    ("empty", MemberType.FILE, b""),
]
_DATA = {name: data for name, kind, data in _ENTRIES if kind is MemberType.FILE}


def _write(tmp_path: Path, data: bytes, name: str = "t.toys") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_random_access_from_a_file(toys: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toys(_ENTRIES))
    with open_archive(path) as reader:
        assert reader.format == toys
        assert [m.name for m in reader.members()] == [
            "docs/",
            "docs/a.txt",
            "link",
            "b.bin",
            "empty",
        ]
        link = reader.get("link")
        assert link is not None
        assert link.link_target == "docs/a.txt"
        # Out of archive order: each member is read where the walk found it.
        assert reader.read("b.bin") == _DATA["b.bin"]
        with reader.open("docs/a.txt") as stream:
            assert stream.read() == b"alpha\n"
            assert stream.verified is archivey.Verification.CONTENT
        assert reader.read("link") == b"alpha\n"
        member = reader.get("docs/a.txt")
        assert member is not None
        assert member.hashes == {
            archivey.HashAlgorithm.CRC32: zlib.crc32(b"alpha\n").to_bytes(4, "big")
        }
        cost = reader.info.cost
        assert cost.listing_cost is ListingCost.REQUIRES_SCANNING
        assert cost.access_cost is AccessCost.DIRECT
        assert cost.stream_capability is StreamCapability.SEEKABLE


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_stream_members(toys: ArchiveFormat, tmp_path: Path, pipe: bool) -> None:
    data = build_toys(_ENTRIES)
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with open_archive(source, streaming=True) as reader:
        seen = {
            m.name: (s.read() if s is not None else m.link_target)
            for m, s in reader.stream_members()
        }
        assert reader.info.cost.stream_capability is (
            StreamCapability.FORWARD_ONLY if pipe else StreamCapability.SEEKABLE
        )
    assert seen == {
        "docs/": None,
        "docs/a.txt": b"alpha\n",
        "link": "docs/a.txt",
        "b.bin": _DATA["b.bin"],
        "empty": b"",
    }


def test_a_member_left_part_read_is_skipped(toys: ArchiveFormat) -> None:
    source = NonSeekableBytesIO(build_toys(_ENTRIES))
    with open_archive(source, streaming=True) as reader:
        got = {}
        for member, stream in reader.stream_members():
            if stream is not None:
                got[member.name] = stream.read(3)
    assert got == {"docs/a.txt": b"alp", "b.bin": b"\x00\x01\x02", "empty": b""}


def test_a_stream_kept_past_its_member_is_refused(toys: ArchiveFormat) -> None:
    source = NonSeekableBytesIO(build_toys(_ENTRIES))
    with open_archive(source, streaming=True) as reader:
        it = reader.stream_members()
        kept = None
        for member, stream in it:
            if member.name == "b.bin":
                kept = stream
                break
        assert kept is not None
        next(it)
        with pytest.raises((ArchiveyUsageError, ValueError)):
            kept.read(1)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_extract_all(toys: ArchiveFormat, tmp_path: Path, pipe: bool) -> None:
    data = build_toys(_ENTRIES)
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    dest = tmp_path / "out"
    with open_archive(source, streaming=pipe) as reader:
        reader.extract_all(dest)
    assert (dest / "docs" / "a.txt").read_bytes() == b"alpha\n"
    assert (dest / "b.bin").read_bytes() == _DATA["b.bin"]
    # Extraction writes the target with the platform separator.
    assert os.readlink(dest / "link") == os.path.join("docs", "a.txt")


def test_detection_and_availability(toys: ArchiveFormat, tmp_path: Path) -> None:
    info = detect_format(io.BytesIO(build_toys(_ENTRIES)))
    assert info.format == toys
    assert info.from_plugin
    availability = format_availability("toys")
    assert availability.required_source is StreamCapability.FORWARD_ONLY


def test_random_access_needs_a_seekable_source(toys: ArchiveFormat) -> None:
    with pytest.raises(archivey.StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(build_toys(_ENTRIES)), format="toys")


def test_a_wrong_crc_raises(toys: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toys(_ENTRIES, crcs={1: 0}))
    with open_archive(path) as reader, pytest.raises(CorruptionError):
        reader.read("docs/a.txt")
    with (
        open_archive(NonSeekableBytesIO(path.read_bytes()), streaming=True) as reader,
        pytest.raises(CorruptionError),
    ):
        for _, stream in reader.stream_members():
            if stream is not None:
                stream.read()


def test_not_an_archive_fails_at_open(toys: ArchiveFormat, tmp_path: Path) -> None:
    with pytest.raises(CorruptionError, match="no TOYS header"):
        open_archive(_write(tmp_path, b"XX" + bytes(30)), format="toys")
    with pytest.raises(TruncatedError):
        open_archive(_write(tmp_path, b"TS"), format="toys")


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_cut_member_keeps_the_members_before_it(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = build_toys(_ENTRIES)
    cut = data[: data.index(b"b.bin") + 5 + 1000]
    source = NonSeekableBytesIO(cut) if pipe else _write(tmp_path, cut)
    with open_archive(source, streaming=pipe) as reader:
        names = []
        with pytest.raises(TruncatedError):
            for member, stream in reader.stream_members():
                names.append(member.name)
                if stream is not None:
                    stream.read()
    assert names == ["docs/", "docs/a.txt", "link", "b.bin"]


class _NoDigestReader(ToysReader):
    """TOYS with no digests: a member's data is read with no verifier above it."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        for span in super().walk(stream):
            yield MemberSpan(span.member, span.data_length)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_cut_member_with_no_digest_raises_at_the_cut(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    """With no digest there is no verifier to compare the bytes read with the size:
    the member's data window (``_SpanWindow``) raises at the cut itself. A sized read returns the bytes
    before the cut and the next read raises (ADR 0014); a read with no size raises.

    Fails when the window returns a short read as a clean end."""
    fmt = _variant(_NoDigestReader, ToysContainer.NO_DIGEST)
    data = build_toys(_ENTRIES)
    cut = data[: data.index(b"b.bin") + 5 + 1000]

    def first_bin(reader: ArchiveReader) -> tuple[Iterator[object], BinaryIO]:
        it = iter(reader.stream_members())
        for member, stream in it:
            if member.name == "b.bin":
                assert stream is not None
                return it, stream
        raise AssertionError("b.bin not reached")

    def source() -> BinaryIO | Path:
        return NonSeekableBytesIO(cut) if pipe else _write(tmp_path, cut)

    with open_archive(source(), format=fmt, streaming=pipe) as reader:
        _it, stream = first_bin(reader)
        assert stream.read(4096) == _DATA["b.bin"][:1000]
        with pytest.raises(TruncatedError, match="truncated inside a member's data"):
            stream.read(4096)
    with open_archive(source(), format=fmt, streaming=pipe) as reader:
        _it, stream = first_bin(reader)
        with pytest.raises(TruncatedError, match="truncated inside a member's data"):
            stream.read()


def test_a_cut_member_read_after_the_walk_left_it_raises_at_the_cut(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    """The view a pass's stream falls back to once the walk has moved on (the
    handoff's ``reopen``) raises at a cut itself, as the window does: with no digest
    there is no verifier above it.

    Fails when the fallback is a plain view, which returns a short read as a clean
    end."""
    fmt = _variant(_NoDigestReader, ToysContainer.NO_DIGEST)
    data = build_toys(_ENTRIES)
    path = _write(tmp_path, data[: data.index(b"b.bin") + 5 + 1000])

    def detached_bin(reader: ArchiveReader) -> tuple[Iterator[object], BinaryIO]:
        # The pass is kept: closing it would close the stream it handed out.
        it = iter(reader.stream_members())
        for member, stream in it:
            if member.name == "b.bin":
                assert stream is not None
                # A first read opens the stream through the walk. The listing then
                # walks on past b.bin, which detaches the stream from the walk; the
                # walk stops at the cut.
                assert stream.read(10) == _DATA["b.bin"][:10]
                with pytest.raises(TruncatedError):
                    reader.members()
                return it, stream
        raise AssertionError("b.bin not reached")

    with open_archive(path, format=fmt, concurrent_operations=True) as reader:
        _it, stream = detached_bin(reader)
        assert stream.read(4096) == _DATA["b.bin"][10:1000]
        with pytest.raises(TruncatedError, match="truncated inside a member's data"):
            stream.read(4096)
    with open_archive(path, format=fmt, concurrent_operations=True) as reader:
        _it, stream = detached_bin(reader)
        with pytest.raises(TruncatedError, match="truncated inside a member's data"):
            stream.read()


def test_a_missing_end_header_is_truncation(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, build_toys(_ENTRIES, end=False))
    with open_archive(path) as reader, pytest.raises(TruncatedError):
        reader.members()


def test_a_long_link_target_is_reported(toys: ArchiveFormat, tmp_path: Path) -> None:
    entries = [("long", MemberType.SYMLINK, b"x" * 5000), *_ENTRIES[1:2]]
    path = _write(tmp_path, build_toys(entries))
    with open_archive(path) as reader:
        long = reader.get("long")
        assert long is not None
        assert long.link_target is None
        assert reader.read("docs/a.txt") == b"alpha\n"
        counts = reader.diagnostics.counts
    assert counts[DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE] == 1


def test_concurrent_reads(toys: ArchiveFormat, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toys(_ENTRIES))
    results: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=True) as reader:

        def read(name: str) -> None:
            results[name] = reader.read(name)

        threads = [
            threading.Thread(target=read, args=(name,))
            for name in ("b.bin", "docs/a.txt") * 4
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert results == {"b.bin": _DATA["b.bin"], "docs/a.txt": b"alpha\n"}


def _variant(reader: type[ToysReader], container: ToysContainer) -> ArchiveFormat:
    """Register a TOYS reader that changes what it yields, as its own format."""
    fmt = ArchiveFormat(container, StreamFormat.UNCOMPRESSED)

    class Variant(SequentialFormatHandler):
        format = fmt

        def open_sequential(self, context: ReaderContext) -> ToysReader:
            return reader(context)

    register_format(Variant)
    return fmt


class _BadSizeReader(ToysReader):
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        for span in super().walk(stream):
            if span.member.type is MemberType.FILE:
                span.member.size = span.data_length + 1
            yield span


def test_a_size_other_than_the_data_length_is_a_plugin_bug(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    fmt = _variant(_BadSizeReader, ToysContainer.BAD_SIZE)
    path = _write(tmp_path, build_toys(_ENTRIES))
    with (
        open_archive(path, format=fmt) as reader,
        pytest.raises(ValueError, match="data_length"),
    ):
        reader.members()


def test_a_size_given_to_an_empty_file_is_a_plugin_bug(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    """The size check covers a data length of 0 too: a FILE sized past its data would
    otherwise blame a sound archive as cut short."""
    fmt = _variant(_BadSizeReader, ToysContainer.BAD_SIZE)
    path = _write(tmp_path, build_toys([("empty", MemberType.FILE, b"")]))
    with (
        open_archive(path, format=fmt) as reader,
        pytest.raises(ValueError, match="data_length 0"),
    ):
        reader.members()


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_directory_with_data_is_reported(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = build_toys(
        [("d", MemberType.DIRECTORY, b"junk"), ("f", MemberType.FILE, b"ok")]
    )
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with open_archive(source, streaming=pipe) as reader:
        seen = [
            (m.name, m.type, m.size, s.read() if s is not None else None)
            for m, s in reader.stream_members()
        ]
        counts = reader.diagnostics.counts
    assert seen == [
        ("d/", MemberType.DIRECTORY, 4, b"junk"),
        ("f", MemberType.FILE, 2, b"ok"),
    ]
    assert counts[archivey.DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED] == 1


class _SizedEmptyDirectoryReader(ToysReader):
    """Lists every directory with a size of 5 and no stored data."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        for span in super().walk(stream):
            if span.member.type is MemberType.DIRECTORY:
                span.member.size = 5
            yield span


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_directory_listing_a_size_it_does_not_store_raises_on_read(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    # The data window ends at the stored length (0); the listed size is what the
    # read is checked against, in a pass as in open().
    fmt = _variant(_SizedEmptyDirectoryReader, ToysContainer.SIZED_EMPTY_DIRECTORY)
    data = build_toys([("d", MemberType.DIRECTORY, b"")])
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with open_archive(source, format=fmt, streaming=pipe) as reader:
        for member, stream in reader.stream_members():
            assert member.size == 5
            assert stream is not None
            with pytest.raises(TruncatedError):
                stream.read()
    if not pipe:
        with (
            open_archive(source, format=fmt) as reader,
            pytest.raises(TruncatedError),
        ):
            reader.read("d/")


class _ClosingReader(ToysReader):
    """Records its close() and when the walk's cleanup ran, against it."""

    events: ClassVar[list[str]] = []

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        try:
            yield from super().walk(stream)
        finally:
            self.events.append("walk done")

    def close(self) -> None:
        self.events.append("close")


def test_a_failed_open_closes_the_reader(toys: ArchiveFormat, tmp_path: Path) -> None:
    fmt = _variant(_ClosingReader, ToysContainer.CLOSING)
    _ClosingReader.events = []
    with pytest.raises(CorruptionError, match="no TOYS header"):
        open_archive(_write(tmp_path, b"XX" + bytes(30)), format=fmt)
    assert _ClosingReader.events == ["walk done", "close"]


def test_an_unlisted_walk_ends_before_close(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    """A walk taken at open and never listed runs its cleanup before close()."""
    fmt = _variant(_ClosingReader, ToysContainer.CLOSING)
    _ClosingReader.events = []
    with open_archive(_write(tmp_path, build_toys(_ENTRIES)), format=fmt):
        pass
    assert _ClosingReader.events == ["walk done", "close"]


def test_a_listing_stopped_by_a_limit_walks_again(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    """A second listing starts a new walk from the start, and stops the same way."""
    config = archivey.ArchiveyConfig(
        listing_limits=archivey.ListingLimits(max_members=3)
    )
    path = _write(tmp_path, build_toys(_ENTRIES))
    messages = []
    with open_archive(path, config=config) as reader:
        for _ in range(2):
            with pytest.raises(archivey.ResourceLimitError) as raised:
                reader.members()
            messages.append(str(raised.value))
    assert messages[0] == messages[1]


class _Sum16:
    def __init__(self) -> None:
        self._total = 0

    def update(self, data: bytes, /) -> None:
        self._total = (self._total + sum(data)) & 0xFFFF

    def digest(self) -> bytes:
        return self._total.to_bytes(2, "big")


class _SumReader(ToysReader):
    """Stores a 16-bit byte sum of zero for every member."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        for span in super().walk(stream):
            yield span._replace(digests=(MemberDigest("sum16", b"\x00\x00", _Sum16),))


def test_a_plugin_digest_is_checked(toys: ArchiveFormat, tmp_path: Path) -> None:
    fmt = _variant(_SumReader, ToysContainer.SUM16)
    path = _write(tmp_path, build_toys(_ENTRIES))
    with open_archive(path, format=fmt) as reader:
        assert reader.read("empty") == b""
        with pytest.raises(CorruptionError, match="sum16"):
            reader.read("docs/a.txt")


def test_an_os_pipe(toys: ArchiveFormat, tmp_path: Path) -> None:
    data = build_toys(_ENTRIES)
    read_fd, write_fd = os.pipe()

    def write() -> None:
        with open(write_fd, "wb") as out:
            out.write(data)

    writer = threading.Thread(target=write)
    writer.start()
    dest = tmp_path / "out"
    try:
        with (
            open(read_fd, "rb", buffering=0) as pipe,
            open_archive(pipe, streaming=True) as reader,
        ):
            assert reader.format == toys
            reader.extract_all(dest)
    finally:
        writer.join()
    assert (dest / "b.bin").read_bytes() == _DATA["b.bin"]


# --- Outer compression: a sequential format inside a single-file compression stream ---

_TOYS_GZ = ArchiveFormat(ToysContainer.TOYS, StreamFormat.GZIP)


def _gz(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


@pytest.mark.parametrize(
    ("stream", "compress"),
    [
        (StreamFormat.GZIP, _gz),
        (StreamFormat.BZIP2, bz2.compress),
        (StreamFormat.XZ, lzma.compress),
    ],
    ids=["gz", "bz2", "xz"],
)
def test_detected_inside_a_compression_stream(
    toys: ArchiveFormat, stream: StreamFormat, compress: Callable[[bytes], bytes]
) -> None:
    data = compress(build_toys(_ENTRIES))
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat(ToysContainer.TOYS, stream)
    assert info.detected_by == "content_probe"
    assert info.from_plugin
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.read("b.bin") == _DATA["b.bin"]


def test_compressed_extensions_and_spellings(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    # Nothing in these bytes is a signal: the extension names the pair.
    path = _write(tmp_path, b"no signal here", "t.toys.gz")
    info = detect_format(path)
    assert (info.format, info.detected_by) == (_TOYS_GZ, "extension")
    assert format_availability("toys.gz").format == _TOYS_GZ
    assert format_availability("TOYS_GZIP").format == _TOYS_GZ
    assert format_availability(_TOYS_GZ).required_source is (
        StreamCapability.FORWARD_ONLY
    )
    data = _gz(build_toys(_ENTRIES))
    with open_archive(io.BytesIO(data), format="toys.gz") as reader:
        assert reader.format == _TOYS_GZ
    # open_stream peels the compression layer, as for a compressed tar.
    with archivey.open_stream(io.BytesIO(data), format=_TOYS_GZ) as stream:
        assert stream.read() == build_toys(_ENTRIES)


def test_compressed_bytes_that_are_not_the_format_stay_a_compressed_file(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, _gz(b"plain text\n" * 100), "t.toys.gz")
    info = detect_format(path)
    assert info.format == ArchiveFormat.GZ
    # A deferred inner determination, as for a .tar.gz, not a conflict.
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT not in info.diagnostics.counts


def test_random_access_inside_a_compression_stream(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, _gz(build_toys(_ENTRIES)), "t.toys.gz")
    with open_archive(path) as reader:
        assert reader.format == _TOYS_GZ
        assert [m.name for m in reader.members()] == [
            "docs/",
            "docs/a.txt",
            "link",
            "b.bin",
            "empty",
        ]
        assert reader.get("link").link_target == "docs/a.txt"  # type: ignore[union-attr]
        # Out of archive order: going back decodes again from the start.
        assert reader.read("b.bin") == _DATA["b.bin"]
        with reader.open("docs/a.txt") as stream:
            assert stream.read() == b"alpha\n"
            assert stream.verified is archivey.Verification.CONTENT
        info = reader.info
        assert info.is_solid
        assert info.cost.listing_cost is ListingCost.REQUIRES_DECOMPRESSION
        assert info.cost.access_cost is AccessCost.SOLID
        assert info.cost.solid_block_count == 1


# Members that do not compress, so decoding the archive twice reads its bytes twice.
_INCOMPRESSIBLE = [
    ("docs", MemberType.DIRECTORY, b""),
    ("one.bin", MemberType.FILE, random.Random(1).randbytes(300_000)),
    ("two.bin", MemberType.FILE, random.Random(2).randbytes(300_000)),
    ("three.bin", MemberType.FILE, random.Random(3).randbytes(300_000)),
]


def _one_pass_archive(shape: str) -> bytes:
    if shape == "gzip":
        return _gz(build_toys(_INCOMPRESSIBLE))
    # Part-way: the first member stored, the rest in a gzip stream the walk opens.
    name = StreamFormat.GZIP.value.encode()
    return (
        build_toys(_INCOMPRESSIBLE[:2], end=False)
        + _HEADER.pack(_MAGIC, b"Z", len(name), 0, 0)
        + name
        + _gz(build_toys(_INCOMPRESSIBLE[2:]))
    )


@pytest.mark.parametrize("shape", ["gzip", "part-way"])
@pytest.mark.parametrize("call", ["extract_all", "stream_members"])
def test_random_access_pass_decodes_once(
    toys: ArchiveFormat, rpmish: ArchiveFormat, tmp_path: Path, shape: str, call: str
) -> None:
    """A random-access pass over a compressed archive reads the member data through
    the walk, so the archive is read once, not once for the headers and again for
    the data."""
    data = _one_pass_archive(shape)
    source = CountingBytesIO(data)
    fmt = _TOYS_GZ if shape == "gzip" else rpmish
    with open_archive(source, format=fmt) as reader:  # type: ignore[arg-type]
        if call == "extract_all":
            reader.extract_all(tmp_path / "out")
            got = {
                name: (tmp_path / "out" / name).read_bytes()
                for name, kind, _ in _INCOMPRESSIBLE
                if kind is MemberType.FILE
            }
        else:
            got = {m.name: s.read() for m, s in reader.stream_members() if s}
        # The pass listed the archive as it went.
        assert [m.name for m in reader.members()] == [
            "docs/",
            "one.bin",
            "two.bin",
            "three.bin",
        ]
    assert got == {n: d for n, k, d in _INCOMPRESSIBLE if k is MemberType.FILE}
    assert source.bytes_read < len(data) * 1.2, (source.bytes_read, len(data))


@pytest.mark.parametrize("mode", ["plain", "gzip", "pipe"])
def test_extract_past_a_listing_limit_writes_the_members_before_it(
    toys: ArchiveFormat, tmp_path: Path, mode: str
) -> None:
    """The pass registers each member with the limits enforced: the members before the
    one that crosses a limit are written, then ``ResourceLimitError`` is raised, in
    either access mode (DR-5; the safe-extraction damaged-listing matrix)."""
    data = build_toys(_INCOMPRESSIBLE)
    if mode == "gzip":
        data = _gz(data)
    config = archivey.ArchiveyConfig(
        listing_limits=archivey.ListingLimits(max_members=3)
    )
    source = (
        NonSeekableBytesIO(data)
        if mode == "pipe"
        else _write(tmp_path, data, "t.toys.gz" if mode == "gzip" else "t.toys")
    )
    dest = tmp_path / "out"
    with (
        open_archive(source, config=config, streaming=mode == "pipe") as reader,
        pytest.raises(archivey.ResourceLimitError),
    ):
        reader.extract_all(dest)
    assert (dest / "one.bin").read_bytes() == _INCOMPRESSIBLE[1][2]
    assert (dest / "two.bin").read_bytes() == _INCOMPRESSIBLE[2][2]
    assert not (dest / "three.bin").exists()


@pytest.mark.parametrize("shape", ["gzip", "part-way"])
def test_random_access_pass_member_survives_the_walk_moving_on(
    toys: ArchiveFormat, rpmish: ArchiveFormat, shape: str
) -> None:
    """A member the pass is reading through the walk reads on from a view of its own
    when another call moves the walk on."""
    fmt = _TOYS_GZ if shape == "gzip" else rpmish
    with open_archive(
        io.BytesIO(_one_pass_archive(shape)), format=fmt, concurrent_operations=True
    ) as reader:
        for member, stream in reader.stream_members():
            if member.name != "two.bin":
                continue
            assert stream is not None
            head = stream.read(1000)
            # Walks to the end of the archive, past this member.
            assert len(reader.members()) == 4
            assert head + stream.read() == _INCOMPRESSIBLE[2][2]
            break


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_stream_members_inside_a_compression_stream(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = _gz(build_toys(_ENTRIES))
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data, "t.toys.gz")
    with open_archive(source, streaming=True) as reader:
        assert reader.format == _TOYS_GZ
        seen = {
            m.name: (s.read() if s is not None else m.link_target)
            for m, s in reader.stream_members()
        }
    assert seen["b.bin"] == _DATA["b.bin"]
    assert seen["link"] == "docs/a.txt"


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_extract_all_inside_a_compression_stream(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = _gz(build_toys(_ENTRIES))
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data, "t.toys.gz")
    dest = tmp_path / "out"
    with open_archive(source, streaming=pipe) as reader:
        reader.extract_all(dest)
    assert (dest / "b.bin").read_bytes() == _DATA["b.bin"]
    assert os.readlink(dest / "link") == os.path.join("docs", "a.txt")


def test_an_os_pipe_inside_a_compression_stream(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    data = _gz(build_toys(_ENTRIES))
    read_fd, write_fd = os.pipe()

    def write() -> None:
        with open(write_fd, "wb") as out:
            out.write(data)

    writer = threading.Thread(target=write)
    writer.start()
    dest = tmp_path / "out"
    try:
        with (
            open(read_fd, "rb", buffering=0) as pipe,
            open_archive(pipe, streaming=True) as reader,
        ):
            assert reader.format == _TOYS_GZ
            reader.extract_all(dest)
    finally:
        writer.join()
    assert (dest / "b.bin").read_bytes() == _DATA["b.bin"]


def test_concurrent_reads_inside_a_compression_stream(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, _gz(build_toys(_ENTRIES)), "t.toys.gz")
    results: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=True) as reader:

        def read(name: str) -> None:
            results[name] = reader.read(name)

        threads = [
            threading.Thread(target=read, args=(name,))
            for name in ("b.bin", "docs/a.txt") * 4
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert results == {"b.bin": _DATA["b.bin"], "docs/a.txt": b"alpha\n"}


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_cut_compression_stream_keeps_the_members_before_it(
    toys: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = _gz(build_toys(_ENTRIES))
    cut = data[: len(data) // 2]
    source = NonSeekableBytesIO(cut) if pipe else _write(tmp_path, cut, "t.toys.gz")
    names = []
    with (
        open_archive(source, streaming=pipe) as reader,
        pytest.raises(TruncatedError),
    ):
        for member, stream in reader.stream_members():
            names.append(member.name)
            if stream is not None:
                stream.read()
    assert names[:3] == ["docs/", "docs/a.txt", "link"]


def test_bytes_after_the_compression_stream_are_reported(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, _gz(build_toys(_ENTRIES)) + b"junk", "t.toys.gz")
    with open_archive(path, streaming=True) as reader:
        for _, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        counts = reader.diagnostics.counts
    assert counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


def test_a_sequential_magic_must_end_within_512_bytes() -> None:
    class Late(ToysHandler):
        format = ArchiveFormat(ToysContainer.CLOSING, StreamFormat.UNCOMPRESSED)
        extensions = (".late",)
        magic = (Magic(510, b"LATE"),)

    with (
        registration_scope(),
        pytest.raises(ArchiveyUsageError, match="within the first 512 bytes"),
    ):
        register_format(Late)


def test_a_compressed_extension_another_format_claims_is_refused() -> None:
    class Gzipped(ToysHandler):
        format = ArchiveFormat(ToysContainer.CLOSING, StreamFormat.UNCOMPRESSED)
        extensions = (".toys.gz",)

    with registration_scope():
        register_format(Gzipped)
        # TOYS would add ".toys.gz" for its gzip pair.
        with pytest.raises(ArchiveyUsageError, match=r"'\.toys\.gz' is already"):
            register_format(ToysHandler)


# --- ForwardStream.decompress: compression that starts part-way (an RPM payload) ---


class _RpmishReader(ToysReader):
    """TOYS with one more header type: ``Z``, whose name is a ``StreamFormat`` value.
    Everything after it is that compression stream, holding more TOYS headers."""

    def archive_info(self) -> ReaderArchiveInfo:
        # The walk decompresses part-way, so the archive says it is solid up front.
        return ReaderArchiveInfo(is_solid=True)

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        while True:
            at = stream.offset
            magic, code, name_len, length, crc = stream.read_struct(_HEADER)
            if magic != _MAGIC:
                raise CorruptionError(f"no TOYS header at offset {at}")
            if code == b"E":
                return
            raw = stream.read_exact(name_len)
            if code == b"Z":
                stream = stream.decompress(StreamFormat(raw.decode()))
                continue
            member = ArchiveMember(
                type=_TYPES[code], name=self._context.decode_name(raw), raw_name=raw
            )
            yield MemberSpan(
                member,
                length,
                (MemberDigest("crc32", crc.to_bytes(4, "big")),)
                if code == b"F"
                else (),
            )
            stream.skip(_pad(length))


def build_rpmish(
    stream: StreamFormat = StreamFormat.GZIP,
    compress: Callable[[bytes], bytes] = lambda data: gzip.compress(data, mtime=0),
    *,
    after: bytes = b"",
) -> bytes:
    """Two members stored as they are, then a ``Z`` header and the rest compressed."""
    head = build_toys(_ENTRIES[:2], end=False)
    name = stream.value.encode()
    switch = _HEADER.pack(_MAGIC, b"Z", len(name), 0, 0) + name
    return head + switch + compress(build_toys(_ENTRIES[2:])) + after


@pytest.fixture
def rpmish() -> Iterator[ArchiveFormat]:
    with registration_scope():
        yield _variant(_RpmishReader, ToysContainer.RPMISH)


_RPM_NAMES = ["docs/", "docs/a.txt", "link", "b.bin", "empty"]


@pytest.mark.parametrize(
    ("stream", "compress"),
    [
        (StreamFormat.GZIP, lambda data: gzip.compress(data, mtime=0)),
        (StreamFormat.XZ, lzma.compress),
        (StreamFormat.BZIP2, bz2.compress),
    ],
    ids=["gz", "xz", "bz2"],
)
def test_decompress_part_way_random_access(
    rpmish: ArchiveFormat,
    tmp_path: Path,
    stream: StreamFormat,
    compress: Callable[[bytes], bytes],
) -> None:
    path = _write(tmp_path, build_rpmish(stream, compress))
    with open_archive(path, format=rpmish) as reader:
        assert [m.name for m in reader.members()] == _RPM_NAMES
        assert reader.get("link").link_target == "docs/a.txt"  # type: ignore[union-attr]
        # Out of order, across the switch, and back.
        assert reader.read("b.bin") == _DATA["b.bin"]
        assert reader.read("docs/a.txt") == b"alpha\n"
        assert reader.read("empty") == b""
        with reader.open("b.bin") as member_stream:
            assert member_stream.read() == _DATA["b.bin"]
            assert member_stream.verified is archivey.Verification.CONTENT
        assert reader.info.is_solid
        assert reader.info.cost.access_cost is AccessCost.SOLID


def test_decompress_part_way_cost_is_known_at_open(
    rpmish: ArchiveFormat, tmp_path: Path
) -> None:
    """The plugin declares the archive solid, so the receipt does not change when
    the walk reaches decompress()."""
    path = _write(tmp_path, build_rpmish())
    with open_archive(path, format=rpmish) as reader:
        before = reader.info
        reader.members()
        after = reader.info
    assert before.is_solid and after.is_solid
    assert before.cost == after.cost
    assert before.cost.access_cost is AccessCost.SOLID
    assert before.cost.listing_cost is ListingCost.REQUIRES_DECOMPRESSION


def test_decompress_part_way_on_a_pipe_held_open(
    rpmish: ArchiveFormat, tmp_path: Path
) -> None:
    """The whole archive is in the pipe and its writer keeps it open: the pass ends
    without waiting for the writer, as for a TAR (the codec is fed what has
    arrived)."""
    read_fd, write_fd = os.pipe()
    os.write(write_fd, build_rpmish())
    got: dict[str, bytes] = {}

    def read() -> None:
        with (
            open(read_fd, "rb", buffering=0) as pipe,
            open_archive(pipe, streaming=True, format=rpmish) as reader,
        ):
            for member, stream in reader.stream_members():
                if stream is not None:
                    got[member.name] = stream.read()

    reader_thread = threading.Thread(target=read, daemon=True)
    reader_thread.start()
    reader_thread.join(30)
    finished = not reader_thread.is_alive()
    os.close(write_fd)
    reader_thread.join(30)
    assert finished, "the pass waited for the writer to close the pipe"
    assert got["b.bin"] == _DATA["b.bin"]


def _build_nested() -> bytes:
    """Two stored members, then gzip holding two more and an xz switch inside it."""

    def switch(stream: StreamFormat) -> bytes:
        name = stream.value.encode()
        return _HEADER.pack(_MAGIC, b"Z", len(name), 0, 0) + name

    inner = (
        build_toys(_ENTRIES[2:4], end=False)
        + switch(StreamFormat.XZ)
        + lzma.compress(build_toys(_ENTRIES[4:]))
    )
    return (
        build_toys(_ENTRIES[:2], end=False)
        + switch(StreamFormat.GZIP)
        + gzip.compress(inner, mtime=0)
    )


@pytest.mark.parametrize("mode", ["file", "stream-file", "stream-pipe", "held-pipe"])
def test_decompress_part_way_nested(
    rpmish: ArchiveFormat, tmp_path: Path, mode: str
) -> None:
    """A walk can call decompress() again on the stream decompress() returned: the
    layers stack, on a file, a pipe, and a pipe whose writer keeps it open."""
    data = _build_nested()
    got: dict[str, bytes | str | None] = {}

    def read(source: object) -> None:
        with open_archive(source, streaming=mode != "file", format=rpmish) as reader:
            if mode == "file":
                # Random access, out of order, into both layers.
                got["empty"] = reader.read("empty")
                got["b.bin"] = reader.read("b.bin")
                got["docs/a.txt"] = reader.read("docs/a.txt")
                return
            for member, stream in reader.stream_members():
                got[member.name] = (
                    stream.read() if stream is not None else member.link_target
                )

    if mode == "held-pipe":
        read_fd, write_fd = os.pipe()
        os.write(write_fd, data)

        def run() -> None:
            with open(read_fd, "rb", buffering=0) as pipe:
                read(pipe)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(30)
        finished = not thread.is_alive()
        os.close(write_fd)
        thread.join(30)
        assert finished, "the pass waited for the writer to close the pipe"
    else:
        read(
            NonSeekableBytesIO(data)
            if mode == "stream-pipe"
            else _write(tmp_path, data)
        )
    if mode != "file":
        assert list(got) == _RPM_NAMES
        assert got["link"] == "docs/a.txt"
    assert got["docs/a.txt"] == b"alpha\n"
    assert got["b.bin"] == _DATA["b.bin"]
    assert got["empty"] == b""


def test_decompress_part_way_layer_close_errors_are_all_reported(
    rpmish: ArchiveFormat, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every layer is closed when one close raises; the first error propagates and
    the later ones are notes on it, not dropped."""
    path = _write(tmp_path, _build_nested())
    close = ReadAheadStream.close

    def failing_close(self: ReadAheadStream) -> None:
        was_closed = self.closed
        close(self)
        if not was_closed:
            raise OSError("close failed")

    monkeypatch.setattr(ReadAheadStream, "close", failing_close)
    with (
        pytest.raises(OSError, match="close failed") as raised,
        open_archive(path, streaming=True, format=rpmish) as reader,
    ):
        for _ in reader.stream_members():
            pass
    assert any("closing another layer failed" in n for n in raised.value.__notes__)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decompress_part_way_ratio_guard(
    rpmish: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    """The decoded payload is under the caller's decompression-ratio guard."""
    entries = [*_ENTRIES[:2], ("bomb.bin", MemberType.FILE, bytes(8 << 20))]
    name = StreamFormat.GZIP.value.encode()
    data = (
        build_toys(entries[:2], end=False)
        + _HEADER.pack(_MAGIC, b"Z", len(name), 0, 0)
        + name
        + gzip.compress(build_toys(entries[2:]), mtime=0)
    )
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with (
        open_archive(source, streaming=pipe, format=rpmish) as reader,
        pytest.raises(ResourceLimitError, match="ratio"),
    ):
        reader.extract_all(
            tmp_path / "out",
            limits=ExtractionLimits(
                max_ratio=100.0,
                ratio_activation_threshold=1 << 20,
                # A pipe has no size: the live guard, on compressed bytes counted.
                live_ratio_activation_threshold=1 << 20,
            ),
        )


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decompress_part_way_streaming(
    rpmish: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = build_rpmish()
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with open_archive(source, streaming=True, format=rpmish) as reader:
        seen = {
            m.name: (s.read() if s is not None else m.link_target)
            for m, s in reader.stream_members()
        }
    assert list(seen) == _RPM_NAMES
    assert seen["b.bin"] == _DATA["b.bin"]
    assert seen["link"] == "docs/a.txt"


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decompress_part_way_extract_all(
    rpmish: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = build_rpmish()
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    dest = tmp_path / "out"
    with open_archive(source, streaming=pipe, format=rpmish) as reader:
        reader.extract_all(dest)
    assert (dest / "docs" / "a.txt").read_bytes() == b"alpha\n"
    assert (dest / "b.bin").read_bytes() == _DATA["b.bin"]


def test_decompress_part_way_concurrent_reads(
    rpmish: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, build_rpmish())
    results: dict[str, bytes] = {}
    with open_archive(path, format=rpmish, concurrent_operations=True) as reader:

        def read(name: str) -> None:
            results[name] = reader.read(name)

        threads = [
            threading.Thread(target=read, args=(name,))
            for name in ("b.bin", "docs/a.txt") * 4
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert results == {"b.bin": _DATA["b.bin"], "docs/a.txt": b"alpha\n"}


def test_decompress_part_way_walks_again(rpmish: ArchiveFormat, tmp_path: Path) -> None:
    """A second pass walks from the start again and reads through the layer the
    first one opened."""
    path = _write(tmp_path, build_rpmish())
    with open_archive(path, format=rpmish) as reader:
        for _ in range(2):
            got = {
                m.name: s.read() for m, s in reader.stream_members() if s is not None
            }
            assert got["b.bin"] == _DATA["b.bin"]


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decompress_part_way_cut_short(
    rpmish: ArchiveFormat, tmp_path: Path, pipe: bool
) -> None:
    data = build_rpmish()
    cut = data[: len(data) - 200]
    source = NonSeekableBytesIO(cut) if pipe else _write(tmp_path, cut)
    names = []
    with (
        open_archive(source, streaming=pipe, format=rpmish) as reader,
        pytest.raises(TruncatedError),
    ):
        for member, stream in reader.stream_members():
            names.append(member.name)
            if stream is not None:
                stream.read()
    assert names[:2] == ["docs/", "docs/a.txt"]


def test_decompress_part_way_trailing_bytes_are_reported(
    rpmish: ArchiveFormat, tmp_path: Path
) -> None:
    path = _write(tmp_path, build_rpmish(after=b"junk"))
    with open_archive(path, streaming=True, format=rpmish) as reader:
        for _, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        counts = reader.diagnostics.counts
    assert counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


def test_decompress_part_way_misuse(rpmish: ArchiveFormat, tmp_path: Path) -> None:
    seen: list[ForwardStream] = []

    class Keeps(_RpmishReader):
        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            seen.append(stream)
            yield from super().walk(stream)

    class Plain(_RpmishReader):
        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            stream.decompress(StreamFormat.UNCOMPRESSED)
            yield from ()

    path = _write(tmp_path, build_rpmish())
    keeps = _variant(Keeps, ToysContainer.SUM16)
    with open_archive(path, format=keeps) as reader:
        reader.members()
    with pytest.raises(ArchiveyUsageError, match="handed to decompress"):
        seen[0].read(1)
    plain = _variant(Plain, ToysContainer.BAD_SIZE)
    with pytest.raises(ValueError, match="compression stream format"):
        open_archive(path, format=plain)


def test_decompress_misuse_is_not_offered_to_the_plugin_translator(
    rpmish: ArchiveFormat, tmp_path: Path
) -> None:
    """A plugin whose translator maps every ValueError to corruption still gets its
    own misuse back as a plugin bug, not as a damaged archive."""

    class Plain(_RpmishReader):
        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            stream.decompress(StreamFormat.UNCOMPRESSED)
            yield from ()

        def translate_exception(self, exc: Exception) -> ArchiveyError | None:
            if isinstance(exc, ValueError):
                return CorruptionError(f"translated: {exc}")
            return None

    class Reuses(Plain):
        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            stream.read_exact(_HEADER.size)
            stream.decompress(StreamFormat.GZIP)
            stream.read(1)
            yield from ()

    path = _write(tmp_path, build_rpmish())
    with pytest.raises(ValueError, match="compression stream format"):
        open_archive(path, format=_variant(Plain, ToysContainer.BAD_SIZE))
    with pytest.raises(ArchiveyUsageError, match="handed to decompress"):
        open_archive(path, format=_variant(Reuses, ToysContainer.SUM16))


# A format whose library decodes each member itself (as LHA's or a libarchive
# wrapper's does): the reader hands each member's data over as MemberSpan.data, a
# stream that reads the walk's own stream, good until the walk moves on.
_ZHEADER = struct.Struct(
    "<2scHIqI"
)  # magic, type, name length, stored length, size, CRC


def build_decoded(
    entries: list[tuple[str, MemberType, bytes]],
    *,
    sizes: dict[int, int] | None = None,
) -> bytes:
    """Each member's data zlib-compressed; ``sizes`` overrides the listed size (-1 for
    none)."""
    out = bytearray()
    for i, (name, kind, payload) in enumerate(entries):
        raw = name.encode()
        stored = zlib.compress(payload)
        size = (sizes or {}).get(i, len(payload))
        out += _ZHEADER.pack(
            b"TZ", _CODES[kind], len(raw), len(stored), size, zlib.crc32(payload)
        )
        out += raw + stored
    out += _ZHEADER.pack(b"TZ", b"E", 0, 0, 0, 0)
    return bytes(out)


class _ZlibMemberStream(io.RawIOBase):
    """The library's decoder: reads the walk's stream as asked, and returns short
    reads, as a raw stream may."""

    def __init__(self, forward: ForwardStream, stored: int) -> None:
        self._forward = forward
        self._left = stored
        self._decoder = zlib.decompressobj()
        self._pending = b""

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        while not self._pending:
            if self._left == 0:
                self._pending = self._decoder.flush()
                if not self._pending:
                    return 0
                break
            chunk = self._forward.read(min(self._left, 1000))
            if not chunk:
                raise TruncatedError("cut short")
            self._left -= len(chunk)
            self._pending = self._decoder.decompress(chunk)
        n = min(len(buffer), len(self._pending), 777)
        buffer[:n] = self._pending[:n]
        self._pending = self._pending[n:]
        return n

    @property
    def stored_left(self) -> int:
        return self._left


class _DecodedReader(SequentialReader):
    link_target_in_data = True
    walks = 0
    checked = False
    with_digests = True

    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(is_solid=True)

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        type(self).walks += 1
        while True:
            magic, code, name_len, stored, size, crc = stream.read_struct(_ZHEADER)
            if magic != b"TZ":
                raise CorruptionError("no header")
            if code == b"E":
                return
            raw = stream.read_exact(name_len)
            kind = _TYPES[code]
            member = ArchiveMember(
                type=kind,
                name=self._context.decode_name(raw),
                raw_name=raw,
                size=None if size < 0 else size,
            )
            data = _ZlibMemberStream(stream, stored)
            digests = (
                (MemberDigest("crc32", crc.to_bytes(4, "big")),)
                if kind is MemberType.FILE and self.with_digests
                else ()
            )
            yield MemberSpan(member, 0, digests, data=data, checked=self.checked)
            # Archivey read the data to its end before asking for the next member.
            stream.skip(data.stored_left)


@pytest.fixture
def decoded() -> Iterator[tuple[ArchiveFormat, type[_DecodedReader]]]:
    class Reader(_DecodedReader):
        walks = 0

    with registration_scope():
        yield _variant(Reader, ToysContainer.DECODED), Reader  # type: ignore[arg-type]


_DecodedFixture = tuple[ArchiveFormat, type[_DecodedReader]]
_DECODED_ENTRIES: list[tuple[str, MemberType, bytes]] = [
    ("docs", MemberType.DIRECTORY, b""),
    ("docs/a.txt", MemberType.FILE, b"alpha\n"),
    ("link", MemberType.SYMLINK, b"docs/a.txt"),
    ("b.bin", MemberType.FILE, bytes(range(256)) * 400),
    ("c.bin", MemberType.FILE, random.Random(4).randbytes(50_000)),
    ("empty", MemberType.FILE, b""),
]
_DECODED_DATA = {n: d for n, k, d in _DECODED_ENTRIES if k is MemberType.FILE}


def test_decoded_random_access(decoded: _DecodedFixture, tmp_path: Path) -> None:
    fmt, reader_type = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with open_archive(path, format=fmt) as reader:
        assert [m.name for m in reader.members()] == [
            "docs/",
            "docs/a.txt",
            "link",
            "b.bin",
            "c.bin",
            "empty",
        ]
        link = reader.get("link")
        assert link is not None
        assert link.link_target == "docs/a.txt"
        assert reader_type.walks == 1
        # Out of order: each read walks again from the start.
        assert reader.read("c.bin") == _DECODED_DATA["c.bin"]
        assert reader.read("docs/a.txt") == b"alpha\n"
        assert reader_type.walks == 3
        with reader.open("b.bin") as stream:
            assert stream.read() == _DECODED_DATA["b.bin"]
            assert stream.verified is archivey.Verification.CONTENT
        # In order from there, the walk carries on.
        assert reader.read("c.bin") == _DECODED_DATA["c.bin"]
        assert reader.read("empty") == b""
        assert reader_type.walks == 3
        assert reader.read("link") == b"alpha\n"
        # The target is behind the walk: one more from the start.
        assert reader_type.walks == 4
        cost = reader.info.cost
        assert cost.access_cost is AccessCost.SOLID
        assert cost.listing_cost is ListingCost.REQUIRES_DECOMPRESSION


def test_decoded_in_order_opens_walk_once(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    fmt, reader_type = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with open_archive(path, format=fmt) as reader:
        reader.members()
        for name in ("docs/a.txt", "b.bin", "c.bin", "empty"):
            with reader.open(name) as stream:
                # Read part-way: the walk drains the rest when it moves on.
                assert stream.read(3) == _DECODED_DATA[name][:3]
        assert reader_type.walks == 2


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize("partial", [False, True], ids=["whole", "part-read"])
def test_decoded_stream_members(
    decoded: _DecodedFixture, tmp_path: Path, pipe: bool, partial: bool
) -> None:
    fmt, reader_type = decoded
    data = build_decoded(_DECODED_ENTRIES)
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with open_archive(source, format=fmt, streaming=pipe) as reader:
        seen = {
            m.name: (s.read(3) if partial else s.read())
            for m, s in reader.stream_members()
            if s is not None
        }
    expected = {n: d[:3] if partial else d for n, d in _DECODED_DATA.items()}
    assert seen == expected
    assert reader_type.walks == 1


def test_decoded_stream_kept_past_its_member_is_refused(
    decoded: _DecodedFixture,
) -> None:
    fmt, _ = decoded
    source = NonSeekableBytesIO(build_decoded(_DECODED_ENTRIES))
    with open_archive(source, format=fmt, streaming=True) as reader:
        it = reader.stream_members()
        kept = None
        for member, stream in it:
            if member.name == "b.bin":
                kept = stream
                break
        assert kept is not None
        next(it)
        with pytest.raises((ArchiveyUsageError, ValueError)):
            kept.read(1)


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decoded_extract_all(
    decoded: _DecodedFixture, tmp_path: Path, pipe: bool
) -> None:
    fmt, reader_type = decoded
    data = build_decoded(_DECODED_ENTRIES)
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    dest = tmp_path / "out"
    with open_archive(source, format=fmt, streaming=pipe) as reader:
        reader.extract_all(dest)
    for name, content in _DECODED_DATA.items():
        assert (dest / name).read_bytes() == content
    assert os.readlink(dest / "link") == os.path.join("docs", "a.txt")
    # One pass: the data is read through the listing walk.
    assert reader_type.walks == 1


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decoded_data_longer_than_its_size(
    decoded: _DecodedFixture, tmp_path: Path, pipe: bool
) -> None:
    fmt, _ = decoded
    data = build_decoded(_DECODED_ENTRIES, sizes={3: 1000})
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with (
        open_archive(source, format=fmt, streaming=pipe) as reader,
        pytest.raises(CorruptionError),
    ):
        for member, stream in reader.stream_members():
            if member.name == "b.bin":
                assert stream is not None
                stream.read()


def test_decoded_data_longer_than_its_size_unread(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    """Data left unread is drained to one byte past its listed size: a longer one
    raises when the walk moves on."""
    fmt, _ = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES, sizes={3: 1000}))
    with (
        open_archive(path, format=fmt) as reader,
        pytest.raises(CorruptionError, match="longer than its listed size"),
    ):
        reader.members()


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_decoded_data_shorter_than_its_size(
    decoded: _DecodedFixture, tmp_path: Path, pipe: bool
) -> None:
    fmt, _ = decoded
    data = build_decoded(_DECODED_ENTRIES, sizes={3: 200_000})
    source = NonSeekableBytesIO(data) if pipe else _write(tmp_path, data)
    with (
        open_archive(source, format=fmt, streaming=pipe) as reader,
        pytest.raises(TruncatedError),
    ):
        for member, stream in reader.stream_members():
            if member.name == "b.bin":
                assert stream is not None
                stream.read()


def test_decoded_data_with_no_size(decoded: _DecodedFixture, tmp_path: Path) -> None:
    fmt, _ = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES, sizes={3: -1, 4: -1}))
    with open_archive(path, format=fmt) as reader:
        member = reader.get("b.bin")
        assert member is not None
        assert member.size is None
        assert reader.read("b.bin") == _DECODED_DATA["b.bin"]
        assert reader.read("c.bin") == _DECODED_DATA["c.bin"]
    source = NonSeekableBytesIO(build_decoded(_DECODED_ENTRIES, sizes={3: -1}))
    with open_archive(source, format=fmt, streaming=True) as reader:
        got = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert got == _DECODED_DATA


def test_decoded_checked_data_counts_as_content(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    fmt, reader_type = decoded
    reader_type.with_digests = False
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with open_archive(path, format=fmt) as reader, reader.open("b.bin") as stream:
        stream.read()
        assert stream.verified is archivey.Verification.STRUCTURE
    reader_type.checked = True
    with open_archive(path, format=fmt) as reader, reader.open("b.bin") as stream:
        stream.read()
        assert stream.verified is archivey.Verification.CONTENT


def test_decoded_data_and_data_length_is_a_plugin_bug(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    fmt, reader_type = decoded
    closed: list[bool] = []

    class Both(io.BytesIO):
        def close(self) -> None:
            closed.append(True)
            super().close()

    def walk(self: _DecodedReader, stream: ForwardStream) -> Iterator[MemberSpan]:
        member = ArchiveMember(type=MemberType.FILE, name="x", size=1)
        yield MemberSpan(member, 1, data=Both(b"x"))

    reader_type.walk = walk  # type: ignore[method-assign]
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with pytest.raises(ValueError, match="both data and data_length"):
        open_archive(path, format=fmt).members()
    assert closed


def test_decoded_concurrent_reads(decoded: _DecodedFixture, tmp_path: Path) -> None:
    fmt, _ = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    results: dict[str, bytes] = {}
    with open_archive(path, format=fmt, concurrent_operations=True) as reader:

        def read(name: str) -> None:
            results[name] = reader.read(name)

        threads = [
            threading.Thread(target=read, args=(name,))
            for name in ("c.bin", "docs/a.txt", "b.bin") * 3
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert results == {n: _DECODED_DATA[n] for n in ("c.bin", "docs/a.txt", "b.bin")}


def test_decoded_pass_member_survives_the_walk_moving_on(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    """A member the pass reads through the walk reads on from a walk of its own when
    another call moves the listing walk on."""
    fmt, _ = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with open_archive(path, format=fmt, concurrent_operations=True) as reader:
        for member, stream in reader.stream_members():
            if member.name != "b.bin":
                continue
            assert stream is not None
            head = stream.read(1000)
            assert len(reader.members()) == 6
            assert head + stream.read() == _DECODED_DATA["b.bin"]
            break


def test_decoded_seekable_members(decoded: _DecodedFixture, tmp_path: Path) -> None:
    """With seekable_members=True, decoded data seeks: back by walking again."""
    fmt, reader_type = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with (
        open_archive(path, format=fmt, seekable_members=True) as reader,
        reader.open("c.bin") as stream,
    ):
        assert stream.seekable()
        expected = _DECODED_DATA["c.bin"]
        stream.seek(1000)
        assert stream.read(10) == expected[1000:1010]
        stream.seek(5)
        assert stream.read(10) == expected[5:15]
        stream.seek(0)
        assert stream.read() == expected
    # The listing, the open, and one walk from the start for each of the two seeks
    # back (seek(5) after reading to 1010, then seek(0)); the forward seek reads on.
    assert reader_type.walks == 4


def test_decoded_rewalk_must_repeat_itself(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    fmt, reader_type = decoded
    original = reader_type.walk

    def walk(self: _DecodedReader, stream: ForwardStream) -> Iterator[MemberSpan]:
        again = type(self).walks > 0
        for span in original(self, stream):
            # A second walk names the fourth member differently, as a library that
            # orders its entries another way would.
            if again and span.member.name == "b.bin":
                span.member.name = "c.bin"
            yield span

    reader_type.walk = walk  # type: ignore[method-assign]
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    with open_archive(path, format=fmt) as reader:
        reader.members()
        with pytest.raises(ValueError, match="same members in the same order"):
            reader.read("b.bin")


def test_decoded_reads_take_the_handle_lock(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    """Under concurrent_operations, the plugin's decoded streams are read one call
    at a time, as every other call into the plugin is."""
    fmt, _ = decoded
    inside = 0
    overlaps = 0
    guard = threading.Lock()
    original = _ZlibMemberStream.readinto

    def readinto(self: _ZlibMemberStream, buffer: memoryview) -> int:
        nonlocal inside, overlaps
        with guard:
            inside += 1
            if inside > 1:
                overlaps += 1
        try:
            return original(self, buffer)
        finally:
            with guard:
                inside -= 1

    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    results: dict[str, bytes] = {}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_ZlibMemberStream, "readinto", readinto)
        with open_archive(path, format=fmt, concurrent_operations=True) as reader:

            def read(name: str) -> None:
                results[name] = reader.read(name)

            threads = [
                threading.Thread(target=read, args=(name,))
                for name in ("c.bin", "b.bin", "docs/a.txt") * 3
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
    assert results == {n: _DECODED_DATA[n] for n in ("c.bin", "b.bin", "docs/a.txt")}
    assert overlaps == 0


def test_decoded_checked_without_data_is_a_plugin_bug(
    toys: ArchiveFormat, tmp_path: Path
) -> None:
    class Checked(ToysReader):
        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            for span in super().walk(stream):
                yield span._replace(checked=True)

    fmt = _variant(Checked, ToysContainer.BAD_SIZE)
    path = _write(tmp_path, build_toys(_ENTRIES))
    with (
        open_archive(path, format=fmt) as reader,
        pytest.raises(ValueError, match="checked=True and no data"),
    ):
        reader.members()


def test_decoded_bytes_are_counted_once(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    """Decoded bytes count as decompressed output whether the caller or the drain
    reads them, and only once."""
    fmt, _ = decoded
    path = _write(tmp_path, build_decoded(_DECODED_ENTRIES))
    total = sum(len(d) for d in _DECODED_DATA.values()) + len(b"docs/a.txt")
    with enable_measurement(), open_archive(path, format=fmt) as reader:
        reader.members()
        stats = reader.io_stats()
        assert stats is not None
        assert stats.bytes_decompressed == total
        assert reader.read("docs/a.txt") == b"alpha\n"
        stats = reader.io_stats()
        assert stats is not None
        assert stats.bytes_decompressed == total + len(b"alpha\n")


def test_decoded_seek_back_reports_the_walk_it_costs(
    decoded: _DecodedFixture, tmp_path: Path
) -> None:
    """A seek back on decoded data walks again through every member before it, so
    the rewind diagnostic counts their bytes, not only the member's own."""
    fmt, _ = decoded
    entries = [
        ("big.bin", MemberType.FILE, random.Random(5).randbytes(2 << 20)),
        ("small.bin", MemberType.FILE, b"s" * 1000),
    ]
    path = _write(tmp_path, build_decoded(entries))
    with (
        open_archive(path, format=fmt, seekable_members=True) as reader,
        reader.open("small.bin") as stream,
    ):
        assert stream.read(100) == b"s" * 100
        stream.seek(0)
        assert stream.read() == b"s" * 1000
        counts = reader.diagnostics.counts
    assert counts[DiagnosticCode.STREAM_REWIND_REDECOMPRESSES] == 1


def _forward(data: bytes) -> tuple[ForwardStream, list[tuple[int, int]]]:
    """A ForwardStream over ``data`` read in place, and the skips it asked for."""
    source = io.BytesIO(data)
    skips: list[tuple[int, int]] = []

    def skip(offset: int, n: int) -> None:
        assert source.tell() == offset, (source.tell(), offset)
        skips.append((offset, n))
        source.seek(n, io.SEEK_CUR)

    return ForwardStream(source.read, skip), skips


def test_forward_stream_peek() -> None:
    stream, skips = _forward(bytes(range(20)))
    assert stream.peek(4) == bytes(range(4))
    assert stream.offset == 0
    # A longer peek reads on; a shorter one serves what is kept.
    assert stream.peek(6) == bytes(range(6))
    assert stream.peek(2) == bytes(range(2))
    assert stream.read(3) == bytes(range(3))
    assert stream.offset == 3
    # A read past what was peeked carries on from the stream.
    assert stream.read(5) == bytes(range(3, 8))
    assert stream.peek(3) == bytes(range(8, 11))
    # A skip consumes the peeked bytes first, then skips the stream from where it is.
    stream.skip(5)
    assert skips == [(11, 2)]
    assert stream.offset == 13
    assert stream.peek(100) == bytes(range(13, 20))
    assert stream.read_exact(7) == bytes(range(13, 20))
    assert stream.peek(1) == b""
    with pytest.raises(ValueError, match="peek"):
        stream.peek(-1)


def test_forward_stream_peek_then_decompress_is_refused() -> None:
    def decompress(offset: int, fmt: StreamFormat) -> ForwardStream:
        raise AssertionError("not reached")

    stream = ForwardStream(io.BytesIO(b"abc").read, lambda o, n: None, decompress)
    stream.peek(1)
    with pytest.raises(ArchiveyUsageError, match="peek"):
        stream.decompress(StreamFormat.GZIP)


class _PeekingReader(ToysReader):
    """TOYS read with a look into each member's data before yielding it, and at the
    next header after it."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        for span in super().walk(stream):
            assert len(stream.peek(min(span.data_length, 9))) == min(
                span.data_length, 9
            )
            yield span
            # The padding, then the next header's magic.
            pad = _pad(span.data_length)
            assert stream.peek(pad + 2)[pad:] == _MAGIC


@pytest.mark.parametrize("mode", ["file", "pipe", "stream_members"])
def test_a_walk_that_peeks_reads_the_same(
    toys: ArchiveFormat, tmp_path: Path, mode: str
) -> None:
    fmt = _variant(_PeekingReader, ToysContainer.PEEKING)
    data = build_toys(_ENTRIES)
    if mode == "pipe":
        with open_archive(NonSeekableBytesIO(data), format=fmt, streaming=True) as r:
            got = {m.name: s.read() for m, s in r.stream_members() if s is not None}
    else:
        path = _write(tmp_path, data)
        with open_archive(path, format=fmt) as r:
            if mode == "file":
                got = {n: r.read(n) for n in _DATA}
            else:
                got = {m.name: s.read() for m, s in r.stream_members() if s}
    assert {n: got[n] for n in _DATA} == _DATA
