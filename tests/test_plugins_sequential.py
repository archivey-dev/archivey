"""The plugin API's sequential shape: a format read in one forward pass.

The test format, TOYS, is defined here with ``archivey.plugins`` and the root API only:
each member is a header (magic, type, name, data length, CRC-32), then its data, padded
to four bytes; a header of type ``E`` ends the archive. Symlinks store their target as
their data, as CPIO's do. Each test registers it on a registry restored afterwards
(``toys`` fixture).
"""

from __future__ import annotations

import io
import os
import struct
import threading
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveyUsageError,
    CorruptionError,
    MemberType,
    PluginContainer,
    StreamFormat,
    TruncatedError,
    detect_format,
    format_availability,
    open_archive,
)
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.diagnostics import DiagnosticCode
from archivey.internal.plugin_adapter import registration_scope
from archivey.plugins import (
    ForwardStream,
    Magic,
    MemberDigest,
    MemberSpan,
    PluginContext,
    SequentialFormatPlugin,
    SequentialReader,
    register_format,
)
from tests.streams_util import NonSeekableBytesIO

_MAGIC = b"TS"
_HEADER = struct.Struct("<2scHII")  # magic, type, name length, data length, CRC-32
_TYPES = {b"F": MemberType.FILE, b"D": MemberType.DIRECTORY, b"L": MemberType.SYMLINK}
_CODES = {kind: code for code, kind in _TYPES.items()}


class ToysContainer(PluginContainer):
    TOYS = "toys"
    BAD_SIZE = "toys-bad-size"
    SUM16 = "toys-sum16"


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

    def __init__(self, context: PluginContext) -> None:
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


class ToysPlugin(SequentialFormatPlugin):
    format = TOYS
    extensions = (".toys",)
    magic = (Magic(0, _MAGIC),)
    uses_encoding = True

    def open_sequential(self, context: PluginContext) -> ToysReader:
        return ToysReader(context)


@pytest.fixture
def toys() -> Iterator[ArchiveFormat]:
    with registration_scope():
        register_format(ToysPlugin)
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

    class Variant(SequentialFormatPlugin):
        format = fmt

        def open_sequential(self, context: PluginContext) -> ToysReader:
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
