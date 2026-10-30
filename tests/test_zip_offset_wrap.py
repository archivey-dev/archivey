"""ZIPs written past 4 GiB without ZIP64, as macOS Archive Utility writes them.

Such a writer stores every offset modulo 2³², the end record's directory offset too.
The archives here are laid out past 4 GiB without 4 GiB of storage: a sparse,
seekable stream holds the headers and short members at their real offsets and reads
zeros everywhere else, and the large members are stored zeros. Nothing reads them
except the two pipe tests, which stream past them.
"""

from __future__ import annotations

import io
import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, DecoderLimits
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
    OffsetWrapContext,
    SizeWrapContext,
)
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.backends.zip_parser import (
    CentralDirectoryWalk,
    ReadAt,
    find_end_record,
    local_header_at,
)
from archivey.types import ArchiveFormat

_WRAP = 1 << 32
_DOS_TIME, _DOS_DATE = 0x6000, 0x5A21
# Version made by Unix 2.1 and version needed 2.0, as macOS Archive Utility writes.
_MADE_BY = (3 << 8) | 21
_BIT3 = 0x08


@dataclass(frozen=True)
class _Zeros:
    """A member of ``size`` zero bytes the sparse stream supplies without storing."""

    size: int
    crc: int


# 2³² - 16 zero bytes, so the member after it starts past 4 GiB. Its CRC-32 is fixed
# here because computing it takes a second.
_BIG = _Zeros((1 << 32) - 16, 0xCA72F00B)


class _Sparse(io.RawIOBase):
    """A seekable stream of ``size`` bytes: ``segments`` at their offsets, zeros
    elsewhere."""

    def __init__(self, segments: Sequence[tuple[int, bytes]], size: int) -> None:
        super().__init__()
        self._segments = sorted(segments)
        self._size = size
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._size}
        self._pos = base[whence] + offset
        return self._pos

    def tell(self, /) -> int:
        return self._pos

    def readinto(self, b) -> int:  # type: ignore[override]  # test double; broad buffer type
        # Released on return: PyPy frees an unreleased view only at a later
        # collection, and until then the caller cannot resize ``b``.
        with memoryview(b) as outer, outer.cast("B") as view:
            start = self._pos
            n = max(min(len(view), self._size - start), 0)
            view[:n] = bytes(n)
            for at, data in self._segments:
                lo, hi = max(at, start), min(at + len(data), start + n)
                if lo < hi:
                    view[lo - start : hi - start] = data[lo - at : hi - at]
        self._pos += n
        return n


class _ForwardOnly(_Sparse):
    """The same bytes, read forward only, as from a pipe."""

    def seekable(self) -> bool:
        return False

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        raise io.UnsupportedOperation("seek")


@dataclass(frozen=True)
class _Layout:
    segments: list[tuple[int, bytes]]
    size: int
    #: Each member's real local header offset.
    offsets: list[int]
    cd_offset: int


def _layout(
    members: Sequence[tuple[str, bytes | _Zeros]],
    *,
    central_names: dict[str, str] | None = None,
) -> _Layout:
    """A stored ZIP of ``members`` with every stored offset taken modulo 2³².

    Every short member has a data descriptor (bit 3) and a large one has its sizes in
    the local header, as in the real archive: a pipe then skips the large member's
    data instead of searching it for a descriptor.

    ``central_names`` renames entries in the central directory only, so the local
    header at an offset names another member.
    """
    segments: list[tuple[int, bytes]] = []
    central: list[bytes] = []
    offsets: list[int] = []
    pos = 0
    for name, data in members:
        raw = name.encode()
        if isinstance(data, _Zeros):
            size, crc = data.size, data.crc
        else:
            size, crc = len(data), zlib.crc32(data)
        flags = 0 if isinstance(data, _Zeros) else _BIT3
        # A size past 4 GiB is stored modulo 2³² as well, as the writer stores it.
        stored = size % _WRAP
        local = (0, 0, 0) if flags else (crc, stored, stored)
        header = struct.pack(
            "<4s2B4HL2L2H",
            b"PK\x03\x04",
            20,
            0,
            flags,
            0,
            _DOS_TIME,
            _DOS_DATE,
            *local,
            len(raw),
            0,
        )
        offsets.append(pos)
        segments.append((pos, header + raw))
        pos += len(header) + len(raw)
        if not isinstance(data, _Zeros):
            segments.append((pos, data))
        pos += size
        if flags:
            segments.append((pos, struct.pack("<4s3L", b"PK\x07\x08", crc, size, size)))
            pos += 16
        stored_name = (central_names or {}).get(name, name).encode()
        central.append(
            struct.pack(
                "<4s4B4HL2L5H2L",
                b"PK\x01\x02",
                _MADE_BY & 0xFF,
                _MADE_BY >> 8,
                20,
                0,
                flags,
                0,
                _DOS_TIME,
                _DOS_DATE,
                crc,
                stored,
                stored,
                len(stored_name),
                0,
                0,
                0,
                0,
                0o100644 << 16,
                offsets[-1] % _WRAP,
            )
            + stored_name
        )
    directory = b"".join(central)
    cd_offset = pos
    end = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        len(central),
        len(central),
        len(directory),
        cd_offset % _WRAP,
        0,
    )
    segments.append((pos, directory + end))
    return _Layout(segments, pos + len(directory) + len(end), offsets, cd_offset)


def _open(layout: _Layout, **kwargs: object):
    return open_archive(
        _Sparse(layout.segments, layout.size),
        format=ArchiveFormat.ZIP,
        **kwargs,  # type: ignore[arg-type]
    )


def _wraps(reader) -> list[OffsetWrapContext]:
    found = [
        d.context
        for d in reader.diagnostics.retained
        if d.code is DiagnosticCode.ARCHIVE_OFFSET_WRAPPED
    ]
    assert all(isinstance(c, OffsetWrapContext) for c in found)
    return found  # type: ignore[return-value]


_PAST_4_GIB = [("big.bin", _BIG), ("b.txt", b"bee " * 8), ("c.txt", b"sea " * 5)]


def test_offsets_wrapped_past_4_gib_are_corrected() -> None:
    layout = _layout(_PAST_4_GIB)
    assert layout.offsets[1] > _WRAP
    with _open(layout) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["big.bin", "b.txt", "c.txt"]
        assert reader.read(members[1]) == b"bee " * 8
        assert reader.read(members[2]) == b"sea " * 5
        wraps = _wraps(reader)
    assert [(c.record, c.member_name, c.member_id) for c in wraps] == [
        ("local_header", "b.txt", 1),
        ("local_header", "c.txt", 2),
        ("central_directory", "", None),
    ]
    assert [(c.stored_offset, c.corrected_offset) for c in wraps] == [
        (layout.offsets[1] - _WRAP, layout.offsets[1]),
        (layout.offsets[2] - _WRAP, layout.offsets[2]),
        (layout.cd_offset - _WRAP, layout.cd_offset),
    ]


def test_extraction_of_the_members_past_4_gib(tmp_path) -> None:
    with _open(_layout(_PAST_4_GIB)) as reader:
        reader.extract_all(tmp_path, members=["b.txt", "c.txt"])
    assert (tmp_path / "b.txt").read_bytes() == b"bee " * 8
    assert (tmp_path / "c.txt").read_bytes() == b"sea " * 5


def test_strict_reads_a_wrapped_offset_and_records_it() -> None:
    # macOS writes and reads these by default, so STRICT does not refuse them.
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with _open(_layout(_PAST_4_GIB), config=config) as reader:
        members = reader.members()
        assert reader.read(members[2]) == b"sea " * 5
        assert len(_wraps(reader)) == 3


def test_only_the_directory_offset_wrapped() -> None:
    # Every member starts below 4 GiB and the last one ends past it, so only the end
    # record's offset of the directory wraps.
    layout = _layout([("a.txt", b"ay"), ("big.bin", _BIG)])
    assert layout.offsets[1] < _WRAP < layout.cd_offset
    with _open(layout) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["a.txt", "big.bin"]
        assert reader.read(members[0]) == b"ay"
        wraps = _wraps(reader)
    assert [(c.record, c.stored_offset, c.corrected_offset) for c in wraps] == [
        ("central_directory", layout.cd_offset - _WRAP, layout.cd_offset)
    ]


def test_a_header_with_another_name_keeps_the_stored_offset() -> None:
    # The directory names b.txt "x.txt", so the local header at the corrected offset
    # does not match and the stored offset stays: the member lists and its read fails
    # where the stored offset points, inside big.bin's zeros.
    layout = _layout(_PAST_4_GIB, central_names={"b.txt": "x.txt"})
    with _open(layout) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["big.bin", "x.txt", "c.txt"]
        with pytest.raises(CorruptionError, match="Bad magic number for file header"):
            reader.read(members[1])
        assert reader.read(members[2]) == b"sea " * 5
        assert [c.member_name for c in _wraps(reader)] == ["c.txt", ""]


def test_a_header_with_another_name_fails_a_pipe_at_the_directory() -> None:
    # The pass met b.txt's local header, but no directory entry points at it, and the
    # entry renamed x.txt points at no local header: the pass fails at the directory,
    # as it does for any entry without a local header.
    layout = _layout(_PAST_4_GIB, central_names={"b.txt": "x.txt"})
    source = _ForwardOnly(layout.segments, layout.size)
    with open_archive(source, format=ArchiveFormat.ZIP, streaming=True) as reader:
        with pytest.raises(CorruptionError, match="held no local header"):
            for _member, _stream in reader.stream_members():
                pass
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.ARCHIVE_UNLISTED_DATA in codes


def test_members_after_one_over_4_gib_keep_their_stored_offsets() -> None:
    # The large member's sizes are stored modulo 2³² too, so its end falls 2³² short
    # and the offset after it is not below it: out of scope, and the member after it
    # fails to read. The directory's offset is still corrected.
    huge = _Zeros((1 << 32) + (1 << 29), 0)
    layout = _layout([("a.txt", b"ay"), ("huge.bin", huge), ("c.txt", b"sea")])
    with _open(layout) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["a.txt", "huge.bin", "c.txt"]
        assert reader.read(members[0]) == b"ay"
        with pytest.raises(CorruptionError, match="Bad magic number for file header"):
            reader.read(members[2])
        wraps = _wraps(reader)
    assert [(c.record, c.corrected_offset) for c in wraps] == [
        ("central_directory", layout.cd_offset)
    ]


def test_a_directory_out_of_file_order_below_4_gib_is_not_corrected() -> None:
    # An entry whose offset falls below the previous member's end in an archive with
    # nothing past 4 GiB: the corrected offset would be past the directory, so no
    # header is read there and the stored offset stays.
    data = _small_reversed()
    reads: list[int] = []

    def read_at(offset: int, n: int) -> bytes:
        reads.append(offset)
        return data[offset : offset + n]

    end = find_end_record(read_at, len(data))
    reads.clear()
    walk = CentralDirectoryWalk(
        read_at, end, local_name_at=lambda offset: _name_at(read_at, offset)
    )
    entries = list(walk)
    assert [e.name for e in entries] == [b"b.txt", b"a.txt"]
    assert [e.offset_correction for e in entries] == [0, 0]
    assert all(offset < len(data) for offset in reads)
    assert walk.findings == []
    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader:
        assert [reader.read(m) for m in reader.members()] == [b"bee", b"ay"]
        assert _wraps(reader) == []


def _small_reversed() -> bytes:
    layout = _layout([("a.txt", b"ay"), ("b.txt", b"bee")])
    stream = _Sparse(layout.segments, layout.size)
    data = stream.read(layout.size)
    cd = layout.cd_offset
    # Swap the two 51- and 51-byte central entries (same name length).
    size = (len(data) - 22 - cd) // 2
    first, second = data[cd : cd + size], data[cd + size : cd + 2 * size]
    return data[:cd] + second + first + data[cd + 2 * size :]


def test_a_pipe_corrects_the_same_offsets() -> None:
    # The pass streams past the 4 GiB member, so this test reads 4 GiB of zeros.
    layout = _layout(_PAST_4_GIB)
    source = _ForwardOnly(layout.segments, layout.size)
    with open_archive(source, format=ArchiveFormat.ZIP, streaming=True) as reader:
        names = [
            (member.name, None if stream is None else stream.read())
            for member, stream in reader.stream_members()
            if member.name != "big.bin" or stream is None
        ]
        wraps = _wraps(reader)
    assert ("b.txt", b"bee " * 8) in names
    assert ("c.txt", b"sea " * 5) in names
    assert [(c.record, c.member_name) for c in wraps] == [
        ("local_header", "b.txt"),
        ("local_header", "c.txt"),
        ("central_directory", ""),
    ]


# -- members over 4 GiB in a macOS Archive Utility ZIP ---------------------------------
#
# Archive Utility stores sizes modulo 2³² as well. Its entries carry version made by
# Unix 2.1, a data descriptor and the old Info-ZIP ``UX`` extra field alone, and the
# reader corrects sizes only for such entries.


@dataclass(frozen=True)
class _Deflated:
    """A deflated member: its raw deflate ``stream``, decoding to ``size`` bytes."""

    stream: bytes
    size: int
    crc: int


def _zeros_deflated(size: int) -> bytes:
    """A raw deflate stream of ``size`` zero bytes, built from one compressed MiB
    repeated."""
    mib = zlib.compressobj(9, zlib.DEFLATED, -15)
    # A full flush ends byte-aligned with no history, so the piece repeats.
    piece = mib.compress(bytes(1 << 20)) + mib.flush(zlib.Z_FULL_FLUSH)
    tail = zlib.compressobj(9, zlib.DEFLATED, -15)
    last = tail.compress(bytes(size % (1 << 20))) + tail.flush()
    return piece * (size >> 20) + last


# 2³² + 2²⁹ zero bytes, stored, with its CRC-32 fixed here as ``_BIG``'s is.
_HUGE_STORED = _Zeros((1 << 32) + (1 << 29), 0xE90177C6)

# 2³² + 100 zero bytes. The CRC-32 is fixed here because computing it takes a second.
_HUGE_ZEROS_SIZE = (1 << 32) + 100
_HUGE_ZEROS_CRC = 0xA92A4CE5

_UX_CENTRAL = b"UX" + struct.pack("<H2L", 8, 0, 0)
_UX_LOCAL = b"UX" + struct.pack("<H2L2H", 12, 0, 0, 501, 20)


def _mac_layout(
    members: Sequence[tuple[str, bytes | _Zeros | _Deflated]], *, mac: bool = True
) -> _Layout:
    """A ZIP of ``members`` as macOS Archive Utility writes it, every size and offset
    stored modulo 2³²: bytes and ``_Zeros`` stored, ``_Deflated`` deflated.

    ``mac=False`` leaves out the ``UX`` extra fields, so no entry carries the writer's
    fields.
    """
    segments: list[tuple[int, bytes]] = []
    central: list[bytes] = []
    offsets: list[int] = []
    pos = 0
    local_extra = _UX_LOCAL if mac else b""
    central_extra = _UX_CENTRAL if mac else b""
    for name, data in members:
        raw = name.encode()
        if isinstance(data, _Zeros):
            method, size, crc, payload, compressed = (
                0,
                data.size,
                data.crc,
                None,
                data.size,
            )
        elif isinstance(data, _Deflated):
            method, size, crc = 8, data.size, data.crc
            payload, compressed = data.stream, len(data.stream)
        else:
            method, size, crc = 0, len(data), zlib.crc32(data)
            payload, compressed = data, len(data)
        stored_size, stored_compressed = size % _WRAP, compressed % _WRAP
        header = struct.pack(
            "<4s2B4HL2L2H",
            b"PK\x03\x04",
            20,
            0,
            _BIT3,
            method,
            _DOS_TIME,
            _DOS_DATE,
            0,
            0,
            0,
            len(raw),
            len(local_extra),
        )
        offsets.append(pos)
        segments.append((pos, header + raw + local_extra))
        pos += len(header) + len(raw) + len(local_extra)
        if payload is not None:
            segments.append((pos, payload))
        pos += compressed
        descriptor = struct.pack(
            "<4s3L", b"PK\x07\x08", crc, stored_compressed, stored_size
        )
        segments.append((pos, descriptor))
        pos += len(descriptor)
        central.append(
            struct.pack(
                "<4s4B4HL2L5H2L",
                b"PK\x01\x02",
                _MADE_BY & 0xFF,
                _MADE_BY >> 8,
                20,
                0,
                _BIT3,
                method,
                _DOS_TIME,
                _DOS_DATE,
                crc,
                stored_compressed,
                stored_size,
                len(raw),
                len(central_extra),
                0,
                0,
                0,
                0o100644 << 16,
                offsets[-1] % _WRAP,
            )
            + raw
            + central_extra
        )
    directory = b"".join(central)
    cd_offset = pos
    end = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        len(central),
        len(central),
        len(directory),
        cd_offset % _WRAP,
        0,
    )
    segments.append((pos, directory + end))
    return _Layout(segments, pos + len(directory) + len(end), offsets, cd_offset)


def _size_wraps(reader) -> list[SizeWrapContext]:
    found = [
        d.context
        for d in reader.diagnostics.retained
        if d.code is DiagnosticCode.MEMBER_SIZE_WRAPPED
    ]
    assert all(isinstance(c, SizeWrapContext) for c in found)
    return found  # type: ignore[return-value]


def _count(stream) -> int:
    total = 0
    while chunk := stream.read(1 << 20):
        total += len(chunk)
    return total


def test_a_mac_stored_member_over_4_gib_gets_its_sizes_from_the_layout() -> None:
    # The member's data runs 2³² past its stored compressed size, up to the next local
    # header, so both its sizes take 2³² and the members after it are found.
    huge = _HUGE_STORED
    layout = _mac_layout([("a.txt", b"ay"), ("huge.bin", huge), ("c.txt", b"sea")])
    with _open(layout) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["a.txt", "huge.bin", "c.txt"]
        assert (members[1].size, members[1].compressed_size) == (huge.size, huge.size)
        assert "size_mod_2_32" not in members[1].extra
        assert reader.read(members[0]) == b"ay"
        assert reader.read(members[2]) == b"sea"
        sizes = _size_wraps(reader)
        wraps = _wraps(reader)
    assert [
        (c.member_name, c.stored_compressed_size, c.compressed_size, c.stored_size)
        for c in sizes
    ] == [("huge.bin", 1 << 29, huge.size, 1 << 29)]
    assert sizes[0].size == huge.size
    assert [(c.record, c.member_name) for c in wraps] == [
        ("local_header", "c.txt"),
        ("central_directory", ""),
    ]


def test_without_the_mac_fields_a_member_over_4_gib_keeps_its_stored_sizes() -> None:
    huge = _HUGE_STORED
    layout = _mac_layout(
        [("a.txt", b"ay"), ("huge.bin", huge), ("c.txt", b"sea")], mac=False
    )
    with _open(layout) as reader:
        members = reader.members()
        assert members[1].size == 1 << 29
        assert _size_wraps(reader) == []
        with pytest.raises(CorruptionError):
            reader.read(members[2])


def test_a_padded_stream_is_not_given_a_size_past_4_gib() -> None:
    # 5 MB of deflate could decode to 2³² + 100 bytes, but empty stored blocks make a
    # valid 5 MB stream of 100 bytes: the size is unknown, not 2³² + 100, and the
    # read settles it.
    data = bytes(100)
    pad = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = b"\x00\x00\x00\xff\xff" * 1_000_000 + pad.compress(data) + pad.flush()
    member = _Deflated(stream, 100, zlib.crc32(data))
    with _open(_mac_layout([("padded.bin", member)])) as reader:
        (listed,) = reader.members()
        assert listed.size is None
        # Nothing wrapped in this small archive, and the message does not say so.
        (message,) = [
            d.message
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_SIZE_WRAPPED
        ]
        assert "unknown until a read" in message
        assert "written past 4 GiB" not in message
        assert reader.read(listed) == data
        assert listed.size == 100
        assert listed.extra["size_mod_2_32"] == 100


def test_a_mac_member_without_a_crc_still_gets_its_layout_sizes() -> None:
    # A directory entry carrying data has no CRC-32 to check, but its sizes come from
    # the layout and need none. Nothing is decoded.
    huge = _Zeros(_HUGE_STORED.size, 0)
    with _open(_mac_layout([("d/", huge), ("b.txt", b"bee")])) as reader:
        listed, after = reader.members()
        assert (listed.size, listed.compressed_size) == (huge.size, huge.size)
        assert [c.member_name for c in _size_wraps(reader)] == ["d/"]
        assert reader.read(after) == b"bee"


def test_a_stored_size_deflate_cannot_reach_is_kept() -> None:
    # 100 zero bytes deflate to a few bytes, which cannot decode to the stored million:
    # a damaged entry. The size stays as stored, nothing is reported, and the read
    # fails on it.
    data = bytes(100)
    pad = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = pad.compress(data) + pad.flush()
    member = _Deflated(stream, 1_000_000, zlib.crc32(data))
    with _open(_mac_layout([("damaged.bin", member)])) as reader:
        (listed,) = reader.members()
        assert listed.size == 1_000_000
        assert "size_mod_2_32" not in listed.extra
        assert _size_wraps(reader) == []
        with pytest.raises(TruncatedError):
            reader.read(listed)


def test_a_small_mac_member_is_untouched() -> None:
    data = b"hello " * 1000
    stream = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = _Deflated(
        stream.compress(data) + stream.flush(), len(data), zlib.crc32(data)
    )
    with _open(_mac_layout([("a.txt", deflated), ("b.txt", b"bee")])) as reader:
        members = reader.members()
        assert [m.size for m in members] == [len(data), 3]
        assert reader.read(members[0]) == data
        assert all("size_mod_2_32" not in m.extra for m in members)
        assert _size_wraps(reader) == []
        assert _wraps(reader) == []


def test_a_mac_member_size_is_unknown_until_a_read_counts_it() -> None:
    # About 4 MiB of deflate can decode to 100 or 2³² + 100 bytes, so the listing
    # cannot tell, under STRICT too. This test decodes 4 GiB of zeros.
    stream = _zeros_deflated(_HUGE_ZEROS_SIZE)
    # What the test rests on: deflate's ratio lets the stream reach 2³² + 100.
    assert 1032 * len(stream) >= _HUGE_ZEROS_SIZE
    member = _Deflated(stream, _HUGE_ZEROS_SIZE, _HUGE_ZEROS_CRC)
    # Zeros decode past max_ratio, which a read holds too.
    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy.STRICT,
        decoder_limits=DecoderLimits(max_ratio=None),
    )
    layout = _mac_layout([("zeros.bin", member), ("b.txt", b"bee")])
    with _open(layout, config=config) as reader:
        listed, after = reader.members()
        assert listed.size is None
        assert listed.member_state_final is False
        assert listed.extra["size_mod_2_32"] == 100
        assert listed.compressed_size == len(stream)
        (wrap,) = _size_wraps(reader)
        assert (wrap.member_name, wrap.stored_size, wrap.size) == (
            "zeros.bin",
            100,
            None,
        )
        with reader.open(listed) as data:
            assert _count(data) == _HUGE_ZEROS_SIZE
        assert listed.size == _HUGE_ZEROS_SIZE
        assert listed.member_state_final is True
        # The key says what the archive stored; it stays once the size is known.
        assert listed.extra["size_mod_2_32"] == 100
        assert reader.read(after) == b"bee"


def _padded_mac_member(
    data: bytes, *, stored: int | None = None, crc: int | None = None
) -> _Deflated:
    """``data`` behind 2,000,000 empty stored blocks: about 10 MB of deflate, enough
    to decode to ``stored + 2**32`` bytes, so a macOS listing cannot tell the size.
    ``stored`` and ``crc`` default to the true ones."""
    pad = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = b"\x00\x00\x00\xff\xff" * 2_000_000 + pad.compress(data) + pad.flush()
    return _Deflated(
        stream,
        len(data) if stored is None else stored,
        zlib.crc32(data) if crc is None else crc,
    )


def test_an_unknown_mac_size_is_not_final_until_a_read_fills_it() -> None:
    data = bytes(range(100))
    with _open(_mac_layout([("small.bin", _padded_mac_member(data))])) as reader:
        (listed,) = reader.members()
        assert listed.size is None
        assert listed.member_state_final is False
        assert reader.read(listed) == data
        assert listed.size == len(data)
        assert listed.member_state_final is True


def test_a_read_of_a_copy_fills_the_listed_member() -> None:
    data = bytes(range(100))
    with _open(_mac_layout([("small.bin", _padded_mac_member(data))])) as reader:
        (listed,) = reader.members()
        copy = listed.replace(name="renamed.bin")
        assert reader.read(copy) == data
        assert copy.size is None
        assert (listed.size, listed.member_state_final) == (len(data), True)
        assert reader.get("small.bin").size == len(data)


def test_an_unknown_mac_size_is_final_once_the_reader_closes() -> None:
    data = bytes(range(100))
    with _open(_mac_layout([("small.bin", _padded_mac_member(data))])) as reader:
        (listed,) = reader.members()
        assert listed.member_state_final is False
    assert listed.size is None
    assert listed.member_state_final is True


def test_a_length_the_stored_size_rules_out_is_refused() -> None:
    # The stream decodes to 101 bytes against a stored 100, padded so that the size
    # is unknown: the read checks the length modulo 2³² and refuses it.
    member = _padded_mac_member(bytes(101), stored=100)
    with _open(_mac_layout([("short.bin", member)])) as reader:
        (listed,) = reader.members()
        assert listed.size is None
        with pytest.raises(CorruptionError, match="rule out"):
            reader.read(listed)
        assert listed.size is None


def test_a_crc_mismatch_leaves_the_size_unknown() -> None:
    data = bytes(100)
    member = _padded_mac_member(data, crc=zlib.crc32(data) ^ 1)
    with _open(_mac_layout([("bad.bin", member)])) as reader:
        (listed,) = reader.members()
        assert listed.size is None
        with pytest.raises(CorruptionError):
            reader.read(listed)
        assert listed.size is None


def test_a_pipe_reads_a_mac_stored_member_over_4_gib() -> None:
    # The pass streams past the 4.5 GiB member, searching it for its descriptor.
    huge = _HUGE_STORED
    layout = _mac_layout([("a.txt", b"ay"), ("huge.bin", huge), ("c.txt", b"sea")])
    source = _ForwardOnly(layout.segments, layout.size)
    with open_archive(source, format=ArchiveFormat.ZIP, streaming=True) as reader:
        got = [
            (member, None if member.name == "huge.bin" else stream.read())
            for member, stream in reader.stream_members()
        ]
        sizes = _size_wraps(reader)
    assert [(m.name, data) for m, data in got] == [
        ("a.txt", b"ay"),
        ("huge.bin", None),
        ("c.txt", b"sea"),
    ]
    assert (got[1][0].size, got[1][0].compressed_size) == (huge.size, huge.size)
    assert [(c.member_name, c.size) for c in sizes] == [("huge.bin", huge.size)]


def test_a_pipe_keeps_the_size_it_counted() -> None:
    # The directory leaves the size unknown; the pass decoded the member to its end
    # with a matching CRC-32, so the member keeps the count, as a file read fills it in.
    data = bytes(100)
    layout = _mac_layout([("p.bin", _padded_mac_member(data))])
    source = _ForwardOnly(layout.segments, layout.size)
    with open_archive(source, format=ArchiveFormat.ZIP, streaming=True) as reader:
        ((member, read),) = [
            (member, stream.read()) for member, stream in reader.stream_members()
        ]
        # The pass is over and filled the size: nothing changes it now.
        assert member.size == 100
        assert member.member_state_final is True
    assert read == data
    assert member.extra["size_mod_2_32"] == 100


@pytest.mark.parametrize("forward_only", [True, False])
def test_a_finished_pass_settles_a_size_it_left_unknown(forward_only: bool) -> None:
    # The caller never read the member, and a streaming reader cannot read it again.
    # From a pipe the pass decodes it anyway and keeps the size it counted.
    layout = _mac_layout([("p.bin", _padded_mac_member(bytes(100)))])
    source = (
        _ForwardOnly(layout.segments, layout.size)
        if forward_only
        else _Sparse(layout.segments, layout.size)
    )
    with open_archive(source, format=ArchiveFormat.ZIP, streaming=True) as reader:
        members = [member for member, _ in reader.stream_members()]
        assert [m.size for m in members] == [100 if forward_only else None]
        assert members[0].member_state_final is True


def test_a_pass_counts_no_size_past_the_target_cap_it_left_unknown() -> None:
    # Data past the symlink target cap that nobody read is decoded only that far,
    # so the pass counts no size, and the member lists with ``None`` as from a file.
    layout = _mac_layout([("p.bin", _padded_mac_member(bytes(5000)))])
    source = _ForwardOnly(layout.segments, layout.size)
    with open_archive(source, format=ArchiveFormat.ZIP, streaming=True) as reader:
        members = [member for member, _ in reader.stream_members()]
        assert [m.size for m in members] == [None]
        assert members[0].member_state_final is True


def test_a_pipe_descriptor_may_hold_the_full_size_of_a_marked_entry() -> None:
    # A pass that decoded a deflated member past 4 GiB carries the size it counted;
    # a marked entry stores it modulo 2³². Without the fingerprint it contradicts.
    from archivey.internal.backends.zip_forward_reader import _contradicts
    from archivey.internal.backends.zip_parser import CentralEntry

    def entry(extra: bytes) -> CentralEntry:
        return CentralEntry(
            index=0,
            version_made_by=_MADE_BY,
            version_needed=20,
            flags=_BIT3,
            method=8,
            dos_time=0,
            dos_date=0,
            crc=7,
            compressed_size=50,
            file_size=100,
            header_offset=0,
            disk_start=0,
            internal_attr=0,
            external_attr=0,
            name=b"a",
            extra=extra,
            comment=b"",
        )

    counted = (7, 50, (1 << 32) + 100)
    assert not _contradicts(counted, entry(_UX_CENTRAL))
    assert _contradicts(counted, entry(b""))
    assert _contradicts((7, 50, (1 << 32) + 101), entry(_UX_CENTRAL))


def _name_at(read_at: ReadAt, offset: int) -> bytes | None:
    found = local_header_at(read_at, offset)
    return None if found is None else found[0]


@pytest.mark.parametrize("forward_only", [True, False])
def test_a_failed_pass_settles_a_size_it_left_unknown(forward_only: bool) -> None:
    # A listing limit fails the pass after it yielded the member; the pass cannot be
    # walked again, so nothing can fill the size.
    from archivey.config import ListingLimits
    from archivey.exceptions import ResourceLimitError

    layout = _mac_layout([("p.bin", _padded_mac_member(bytes(100))), ("n" * 400, b"x")])
    source = (
        _ForwardOnly(layout.segments, layout.size)
        if forward_only
        else _Sparse(layout.segments, layout.size)
    )
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=300))
    held = []
    with open_archive(
        source, format=ArchiveFormat.ZIP, streaming=True, config=config
    ) as reader:
        with pytest.raises(ResourceLimitError):
            for member, _ in reader.stream_members():
                held.append(member)
        assert [m.name for m in held] == ["p.bin"]
        assert held[0].member_state_final is True
