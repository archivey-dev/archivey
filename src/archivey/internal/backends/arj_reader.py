"""An ARJ reader (``.arj``), written against ``archivey.formats``.

An ARJ archive is a run of headers, each the bytes ``60 EA``, a 2-byte size, a *basic
header* of that size, its CRC-32, and *extended headers* (a 2-byte size, the bytes,
their CRC-32), ended by a size of 0. The first is the main header, for the archive; each
one after it is a member, its compressed bytes right after its headers. A basic header
of size 0 ends the archive. There is no index: the listing reads each header and seeks
past the member's data to the next one.

A basic header starts with a fixed part whose first byte is its own size (30 bytes in
ARJ 1, 34 with the position a split member starts at, 46 with the access and creation
times of ARJ 2.62 and later), then the name and a comment, each ended by a NUL. It holds
the host OS, flags, method, file type, a DOS time (a Unix time when the host is Unix),
the sizes, the CRC-32 of the data and the file mode.

File types: 0 binary and 1 text are files, 3 a directory, 4 a volume label and 5 a
chapter label (listed as ``OTHER``), and 6 a Unix special file, which ARJ for Unix
writes with a ``U`` extended header naming what it is: a symlink and its target, a
hard link and the earlier member it names, a FIFO or a device.

The methods are 0 (stored), 1 to 3 (LHA's static-Huffman stream with a 26 624-byte
dictionary, :mod:`~archivey.internal.streams.codecs.lzh_decoder`) and 4 (a plain LZ77,
:mod:`~archivey.internal.streams.codecs.arj_fast_decoder`). Garbled (password-protected)
members and members split across volumes are listed and refused when read. The
handbook page is ``dev-docs/formats/arj.md``.
"""

from __future__ import annotations

import io
import struct
import zlib
from collections.abc import Iterator
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    MemberTimestampContext,
)
from archivey.exceptions import CorruptionError, TruncatedError, UnsupportedFeatureError
from archivey.formats import (
    IndexedFormatHandler,
    IndexedReader,
    Magic,
    MemberData,
    MemberDigest,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.arj_fast_decoder import ArjFastDecoder
from archivey.internal.streams.codecs.lzh_decoder import LzhDecoder
from archivey.internal.timestamps import dos_to_datetime, unix32_to_datetime
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    CreateSystem,
    MemberType,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

_MAGIC = b"\x60\xea"
# unarj's HEADERSIZE_MAX: no writer makes a longer basic header.
_HEADER_MAX = 2600
_FIXED_MIN = 30
_FIXED_EXT_POS = 34
_FIXED_TIMES = 46
_FIXED = struct.Struct("<BBBBBBBBIIIIHHBB")
# The extended headers of one member: ARJ writes at most a few; the cap bounds a chain
# with no count.
_EXT_MAX_TOTAL = 1 << 20

_FLAG_GARBLED = 0x01
_FLAG_VOLUME = 0x04  # the member goes on in the next volume
_FLAG_EXTFILE = 0x08  # the member started in the previous volume

_TYPE_TEXT = 1
_TYPE_MAIN = 2
_TYPE_DIRECTORY = 3
_TYPE_VOLUME_LABEL = 4
_TYPE_CHAPTER_LABEL = 5
_TYPE_UNIX_SPECIAL = 6
_FILE_TYPES = frozenset({0, _TYPE_TEXT})

_METHOD_STORED = 0
_METHODS_LZH = frozenset({1, 2, 3})
_METHOD_FAST = 4

_OS_UNIX = 2
_OS_NEXT = 8
# The hosts whose times are Unix times, as ARJ for Unix writes them.
_UNIX_TIME_HOSTS = frozenset({_OS_UNIX, _OS_NEXT})
# Hosts that write paths with backslashes: MS-DOS, OS/2, Windows 95, Win32.
_BACKSLASH_HOSTS = frozenset({0, 5, 10, 11})
_CREATE_SYSTEMS = {
    0: CreateSystem.FAT,  # MS-DOS
    2: CreateSystem.UNIX,
    3: CreateSystem.AMIGA,
    4: CreateSystem.MACINTOSH,
    5: CreateSystem.OS2_HPFS,
    7: CreateSystem.ATARI_ST,
    8: CreateSystem.UNIX,  # NeXT
    9: CreateSystem.OPENVMS,
    10: CreateSystem.WINDOWS_NTFS,  # Windows 95
    11: CreateSystem.WINDOWS_NTFS,  # Win32
}

# The ``U`` extended header of a Unix special file: a byte with the kind in its top
# three bits and the data's length in the low five, 31 meaning a 2-byte length follows.
_UX_TAG = ord("U")
_UX_FIFO = 0
_UX_HARDLINK = 1
_UX_SYMLINK = 2
_UX_CHAR = 3
_UX_BLOCK = 4
_UX_LONG = 0x1F
_UX_SPECIAL_NAMES = {_UX_FIFO: "fifo", _UX_CHAR: "char", _UX_BLOCK: "block"}

_DATA_CHUNK = 1 << 16
_TAIL_SCAN = 1 << 16
# ARJ pads nothing after the end header; DOS tools may add an end-of-file byte.
_PADDING = b"\0\x1a"


class _Location(NamedTuple):
    offset: int
    """Where the member's stored bytes start."""
    stored: int
    method: int
    crc: int
    flags: int


class _Header:
    """One basic header and its extended headers, as stored."""

    __slots__ = (
        "accessed",
        "comment",
        "crc",
        "created",
        "end",
        "file_type",
        "flags",
        "host_os",
        "method",
        "mode",
        "modified",
        "name",
        "offset",
        "password_modifier",
        "size",
        "stored",
        "unix_special",
    )

    def __init__(self, offset: int) -> None:
        self.offset = offset
        self.host_os = 0
        self.flags = 0
        self.method = 0
        self.file_type = 0
        self.password_modifier = 0
        self.modified = 0
        self.accessed = 0
        self.created = 0
        self.stored = 0
        self.size = 0
        self.crc = 0
        self.mode = 0
        self.name = b""
        self.comment = b""
        self.unix_special: tuple[int, bytes] | None = None
        self.end = 0
        """Where the member's stored bytes start."""


class ArjReader(IndexedReader[_Location]):
    """One open ARJ archive."""

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        main = self._read_header(0)
        if main is None or main.file_type != _TYPE_MAIN:
            raise CorruptionError("the ARJ archive has no main header")
        self._main = main
        self._first_member = main.end

    # ── Headers ──────────────────────────────────────────────────────────────────────

    def _read(self, pos: int, length: int, what: str) -> bytes:
        try:
            return self._source.read_exact(pos, length)
        except TruncatedError:
            raise TruncatedError(
                f"the ARJ archive ends inside {what} at offset {pos}"
            ) from None

    def _read_header(self, offset: int) -> _Header | None:
        """The header at ``offset``, or ``None`` for the end header."""
        start = self._read(offset, 4, "a header")
        if start[:2] != _MAGIC:
            raise CorruptionError(
                f"the ARJ archive has no header at offset {offset} (expected 60 EA)"
            )
        size = int.from_bytes(start[2:], "little")
        if size == 0:
            return None
        if not _FIXED_MIN <= size <= _HEADER_MAX:
            raise CorruptionError(
                f"the ARJ header at offset {offset} has size {size}; ARJ allows "
                f"{_FIXED_MIN} to {_HEADER_MAX}"
            )
        raw = self._read(offset + 4, size + 4, "a header")
        body = raw[:size]
        if zlib.crc32(body) != int.from_bytes(raw[size:], "little"):
            raise CorruptionError(f"the ARJ header at offset {offset} fails its CRC")
        header = _Header(offset)
        first = body[0]
        if not _FIXED_MIN <= first <= size:
            raise CorruptionError(
                f"the ARJ header at offset {offset} has a fixed part of {first} bytes "
                f"in {size}"
            )
        (
            _first,
            _version,
            _min_version,
            header.host_os,
            header.flags,
            header.method,
            header.file_type,
            header.password_modifier,
            header.modified,
            header.stored,
            header.size,
            header.crc,
            _filespec,
            header.mode,
            _host_data,
            _chapter,
        ) = _FIXED.unpack_from(body)
        if first >= _FIXED_TIMES:
            header.accessed, header.created = struct.unpack_from("<II", body, 34)
        name, nul, rest = body[first:].partition(b"\0")
        if not nul:
            raise CorruptionError(
                f"the name in the ARJ header at offset {offset} has no end"
            )
        header.name = name
        header.comment = rest.partition(b"\0")[0]
        pos = offset + 4 + size + 4
        total = 0
        while True:
            length = int.from_bytes(self._read(pos, 2, "an extended header"), "little")
            pos += 2
            if length == 0:
                break
            total += length
            if total > _EXT_MAX_TOTAL:
                raise CorruptionError(
                    f"the ARJ header at offset {offset} has over {_EXT_MAX_TOTAL} "
                    "bytes of extended headers"
                )
            ext = self._read(pos, length + 4, "an extended header")
            data = ext[:length]
            if zlib.crc32(data) != int.from_bytes(ext[length:], "little"):
                raise CorruptionError(
                    f"an extended header of the ARJ header at offset {offset} fails "
                    "its CRC"
                )
            self._apply_extended(header, data)
            pos += length + 4
        header.end = pos
        if header.file_type == _TYPE_MAIN:
            header.stored = 0
        source_size = self._source.size
        if source_size is not None and header.end + header.stored > source_size:
            raise TruncatedError(
                f"the ARJ archive ends inside the data of the member at offset {offset}"
            )
        return header

    @staticmethod
    def _apply_extended(header: _Header, data: bytes) -> None:
        # A tag, a byte of flags (continued in the next volume), then the data.
        if len(data) < 3 or data[0] != _UX_TAG:
            return
        kind_byte = data[2]
        kind = kind_byte >> 5
        length = kind_byte & _UX_LONG
        body = data[3:]
        if length == _UX_LONG:
            if len(body) < 2:
                raise CorruptionError("an ARJ Unix special header is cut short")
            length = int.from_bytes(body[:2], "little")
            body = body[2:]
        if length > len(body):
            raise CorruptionError("an ARJ Unix special header is cut short")
        header.unix_special = (kind, body[:length])

    # ── Listing ──────────────────────────────────────────────────────────────────────

    @override
    def iter_members(self) -> Iterator[MemberRecord[_Location]]:
        pos = self._first_member
        while True:
            if not self._source.read_at(pos, 1):
                self._report_no_end()
                return
            header = self._read_header(pos)
            if header is None:
                self._check_end(pos + 4)
                return
            if header.file_type == _TYPE_MAIN:
                raise CorruptionError(
                    f"the ARJ archive has a second main header at offset {pos}"
                )
            member = self._member(header)
            yield MemberRecord(
                member,
                _Location(
                    header.end, header.stored, header.method, header.crc, header.flags
                ),
            )
            pos = header.end + header.stored

    def _report_no_end(self) -> None:
        self._context.report(
            DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
            "the ARJ archive has no end header after its last member",
            ArchiveEofContext(
                format="arj",
                expected_marker="end_of_archive_header",
                expected_bytes=4,
                observed_bytes=0,
                observed_kind="absent",
            ),
        )

    def _check_end(self, end: int) -> None:
        """Report data after the end header."""
        tail = self._source.read_at(end, _TAIL_SCAN)
        stripped = tail.lstrip(_PADDING)
        if stripped:
            at = len(tail) - len(stripped)
            self._context.report(
                DiagnosticCode.ARCHIVE_TRAILING_DATA,
                f"the ARJ archive has data {at} bytes after its end header",
                ArchiveEofContext(
                    format="arj",
                    expected_marker="zeros_to_eof",
                    observed_bytes=at,
                    observed_kind="nonzero",
                ),
            )

    def _member(self, header: _Header) -> ArchiveMember:
        context = self._context
        raw = header.name
        if header.host_os in _BACKSLASH_HOSTS:
            raw = raw.replace(b"\\", b"/")
        name = context.decode_name(raw)
        file_type = header.file_type
        link_target: str | None = None
        special: str | None = None
        is_file = False
        if file_type in _FILE_TYPES:
            member_type = MemberType.FILE
            is_file = True
        elif file_type == _TYPE_DIRECTORY:
            member_type = MemberType.DIRECTORY
        elif file_type == _TYPE_UNIX_SPECIAL and header.unix_special is not None:
            kind, data = header.unix_special
            if kind == _UX_SYMLINK:
                member_type = MemberType.SYMLINK
                link_target = context.decode_name(data)
            elif kind == _UX_HARDLINK:
                member_type = MemberType.HARDLINK
                link_target = context.decode_name(data)
            else:
                member_type = MemberType.OTHER
                special = _UX_SPECIAL_NAMES.get(kind)
        else:
            member_type = MemberType.OTHER
        method = header.method
        if not is_file:
            compression: tuple[CompressionMethod, ...] = ()
        elif method == _METHOD_STORED:
            compression = (CompressionMethod(CompressionAlgorithm.STORED),)
        elif method in _METHODS_LZH:
            compression = (CompressionMethod(CompressionAlgorithm.LZH),)
        elif method == _METHOD_FAST:
            compression = (CompressionMethod(CompressionAlgorithm.ARJ_FAST),)
        else:
            compression = (CompressionMethod(CompressionAlgorithm.UNKNOWN),)
        unix = header.host_os in _UNIX_TIME_HOSTS
        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=raw,
            size=header.size if is_file else None,
            compressed_size=header.stored if is_file else None,
            mode=header.mode & 0o7777 if unix else None,
            # The other hosts store DOS attributes there.
            windows_attrs=None if unix else header.mode & 0xFF,
            link_target=link_target,
            compression=compression,
            comment=context.decode_name(header.comment) if header.comment else None,
            create_system=_CREATE_SYSTEMS.get(header.host_os, CreateSystem.UNKNOWN),
            is_encrypted=bool(header.flags & _FLAG_GARBLED) and is_file,
        )
        member.extra["arj.method"] = method
        member.extra["arj.file_type"] = file_type
        if special is not None:
            member.extra["special_file_type"] = special
        for field, value in (
            ("modified", header.modified),
            ("accessed", header.accessed),
            ("created", header.created),
        ):
            if value:
                self._set_time(member, field, value, unix=unix)
        return member

    def _set_time(
        self, member: ArchiveMember, field: str, value: int, *, unix: bool
    ) -> None:
        when = unix32_to_datetime(value) if unix else dos_to_datetime(value)
        if when is None:
            text = f"0x{value:08x}"
            self._context.report(
                DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
                f"Invalid ARJ {field} time for {quoted(member.name)}: {text}",
                MemberTimestampContext(
                    member_name=member.name,
                    field=field,
                    source="unix" if unix else "dos",
                    value_repr=text,
                ),
                member=member,
            )
            return
        setattr(member, field, when)

    # ── Data ─────────────────────────────────────────────────────────────────────────

    @override
    def open_member(self, member: ArchiveMember, locator: _Location) -> MemberData:
        if locator.flags & _FLAG_GARBLED:
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} is garbled (password-protected); archivey "
                "does not decrypt ARJ members"
            )
        if locator.flags & (_FLAG_VOLUME | _FLAG_EXTFILE):
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} is split across ARJ volumes, which archivey "
                "does not join"
            )
        digests = (MemberDigest("crc32", locator.crc.to_bytes(4, "big")),)
        method = locator.method
        if method == _METHOD_STORED:
            return MemberData(
                self._source.view(locator.offset, locator.stored), digests=digests
            )
        if method not in _METHODS_LZH and method != _METHOD_FAST:
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} uses ARJ method {method}, which archivey does "
                "not read"
            )
        span = ((locator.offset, locator.offset + locator.stored),)
        stream = _ArjStream(self._source, locator, member.size or 0)
        return MemberData(stream, digests=digests, bounded=True, ranges=span)

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        main = self._main
        return ReaderArchiveInfo(
            is_solid=False,
            comment=self._context.decode_name(main.comment) if main.comment else None,
        )


class _ArjStream(io.RawIOBase):
    """One member's decoded bytes."""

    _view: BinaryIO | None = None  # close() reads it, even after a failed __init__

    def __init__(self, source: ReaderSource, locator: _Location, size: int) -> None:
        self._view = source.view(locator.offset, locator.stored)
        self._decoder: LzhDecoder | ArjFastDecoder
        if locator.method == _METHOD_FAST:
            self._decoder = ArjFastDecoder(size, self._more)
        else:
            self._decoder = LzhDecoder("arj", size, self._more)

    def _more(self) -> bytes | None:
        assert self._view is not None
        data = self._view.read(_DATA_CHUNK)
        return data or None

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        with memoryview(b) as outer, outer.cast("B") as view:
            if not len(view):
                return 0
            data = self._decoder.read(len(view))
            view[: len(data)] = data
            return len(data)

    @override
    def close(self) -> None:
        if self._view is not None:
            self._view.close()
        super().close()


class ArjHandler(IndexedFormatHandler):
    """ARJ archives: ``.arj``."""

    format = ArchiveFormat.ARJ
    extensions = (".arj",)
    # Two bytes, as for ``.Z``: the main header's size and CRC-32 then confirm it at
    # open, where anything else fails as CorruptionError.
    magic = (Magic(0, _MAGIC),)
    uses_encoding = True
    non_seekable_reason = "archivey finds each member by seeking past the one before"

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> ArjReader:
        return ArjReader(source, context)


ArjReadBackend = register_builtin_format(ArjHandler)
