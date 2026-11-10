"""An LHA reader (``.lzh``, ``.lha``), written against ``archivey.formats``.

An LHA archive is a run of members, each a header and then its compressed bytes, ended
by a zero byte. There is no index: the listing reads each header and seeks past the
member's data to the next one. Each member is compressed on its own, so a member is
read straight from where its data starts.

A header has one of four layouts, its *level*, given by byte 20:

- **Level 0** (LHarc, LHA 1): a 1-byte header size and an 8-bit sum of the header, the
  method (``-lh5-``), sizes, a DOS date, the name, the CRC-16 of the data, and, from
  LHa for UNIX, an optional Unix area (mode, uid, gid, mtime).
- **Level 1**: level 0 with an OS id after the CRC, and *extended headers* after the
  base header. Their bytes count in the stored size.
- **Level 2**: a 2-byte header size, a Unix timestamp, the OS id, then extended
  headers inside the header. OS-9/68k LHA counts its size two bytes short.
- **Level 3** (LHA for OS/2): level 2 with 4-byte sizes for the extended headers.

Extended headers carry the name (``0x01``) and the directory (``0x02``, its parts
split by ``0xFF``), a comment, a CRC-16 of the whole header (``0x00``), 64-bit sizes,
Windows times, and Unix mode, owner and mtime. A directory is a member with method
``-lhd-``; a Unix symlink is one too, with a symlink mode and ``name|target`` as its
name. A member's data is checked against its CRC-16.

The reader follows lhasa (the tool Debian ships as ``lha``) where writers disagree:
Amiga LHA's directories stored as an empty ``-lh0-`` member with no name, LHARK's own
``-lh7-`` (read as ``-lk7-``), and OS-9/68k's level-2 size. The methods decoded are
``-lh0-``, ``-lz4-`` and ``-pm0-`` (stored), ``-lh4-`` to ``-lh7-``, ``-lhx-`` and
``-lk7-`` (:mod:`~archivey.internal.streams.codecs.lzh_decoder`), and ``-lh1-``,
``-lzs-`` and ``-lz5-`` (:mod:`~archivey.internal.streams.codecs.lharc_decoder`).
PMarc's methods and any other are listed and refused when read. The handbook page is
``dev-docs/formats/lha.md``.
"""

from __future__ import annotations

import io
import stat
import struct
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
from archivey.internal.streams.codecs.lharc_decoder import DECODERS as _OLD_DECODERS
from archivey.internal.streams.codecs.lzh_decoder import (
    METHODS as _LZH_METHODS,
    LzhDecoder,
)
from archivey.internal.timestamps import (
    dos_to_datetime,
    filetime_to_datetime,
    unix32_to_datetime,
)
from archivey.internal.unix_mode import UNIX_FILE_TYPE_MASK, special_file_type
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
    from datetime import datetime

    from _typeshed import WriteableBuffer

_DIRECTORY = "-lhd-"
_STORED = frozenset({"-lh0-", "-lz4-", "-pm0-"})
# Every method an LHA tool is known to write, decoded or not: detection finds an
# archive by the method at offset 2.
_KNOWN_METHODS = (
    "-lh0-",
    "-lh1-",
    "-lh2-",
    "-lh3-",
    "-lh4-",
    "-lh5-",
    "-lh6-",
    "-lh7-",
    "-lhx-",
    "-lhd-",
    "-lzs-",
    "-lz4-",
    "-lz5-",
    "-pm0-",
    "-pm1-",
    "-pm2-",
)

_BASE = 22  # the bytes every level shares, up to the level byte and one more
_LEVEL_0_MIN = 22
_LEVEL_1_MIN = 25
_LEVEL_2_SIZE = 26
_LEVEL_3_SIZE = 32
# No writer comes near this. lhasa refuses a level-3 header over 1 MiB, and the
# same cap bounds a level-1 chain of extended headers, which lhasa reads into
# memory too (each record is at most 64 KiB, the chain has no count).
_HEADER_MAX = 1 << 20
_UNIX_AREA = 12  # level 0's Unix extended area
_OS9_AREA = 22  # level 0's OS-9 extended area
_DATA_CHUNK = 1 << 16
# How far past the end byte the reader looks for data the listing would miss.
_TAIL_SCAN = 1 << 16
# Zeros and CP/M's end-of-file byte pad an archive to a record size.
_PADDING = b"\0\x1a"

_EXT_COMMON = 0x00
_EXT_NAME = 0x01
_EXT_DIRECTORY = 0x02
_EXT_COMMENT = 0x3F
_EXT_WINDOWS_TIMES = 0x41
_EXT_SIZES = 0x42
_EXT_UNIX_MODE = 0x50
_EXT_UNIX_OWNER = 0x51
_EXT_UNIX_GROUP_NAME = 0x52
_EXT_UNIX_USER_NAME = 0x53
_EXT_UNIX_MTIME = 0x54
_EXT_OS9 = 0xCC

_OS_AMIGA = ord("A")
_OS_OS9 = ord("9")
_OS_OS9_68K = ord("K")
_OS_LHARK = ord(" ")
_OS_UNIX = ord("U")
_CREATE_SYSTEMS = {
    ord("M"): CreateSystem.FAT,
    ord("2"): CreateSystem.OS2_HPFS,
    ord("U"): CreateSystem.UNIX,
    ord("A"): CreateSystem.AMIGA,
    ord("m"): CreateSystem.MACINTOSH,
    ord("w"): CreateSystem.VFAT,
    ord("W"): CreateSystem.WINDOWS_NTFS,
    ord("C"): CreateSystem.CPM,
    ord("a"): CreateSystem.ATARI_ST,
    _OS_LHARK: CreateSystem.FAT,
}

_CRC16_TABLE: list[int] = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if _c & 1 else _c >> 1
    _CRC16_TABLE.append(_c)
del _i, _c


def crc16(data: bytes | bytearray | memoryview, crc: int = 0) -> int:
    """CRC-16/ARC (polynomial 0x8005, reflected), as LHA checks data and headers."""
    table = _CRC16_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc


class _Crc16:
    """A running CRC-16, for :class:`~archivey.formats.MemberDigest`."""

    def __init__(self) -> None:
        self._crc = 0

    def update(self, data: bytes, /) -> None:
        self._crc = crc16(data, self._crc)

    def digest(self) -> bytes:
        return self._crc.to_bytes(2, "big")


class _Location(NamedTuple):
    offset: int
    """Where the member's stored bytes start."""
    stored: int
    method: str
    crc: int


class _Header:
    """One member's header, as stored."""

    __slots__ = (
        "comment",
        "crc",
        "directory",
        "dos_time",
        "end",
        "ext_times",
        "gid",
        "group",
        "header_crc",
        "level",
        "method",
        "mode",
        "mtime",
        "name",
        "offset",
        "os9_perms",
        "os_id",
        "size",
        "stored",
        "uid",
        "user",
    )

    def __init__(self, offset: int, level: int, method: str) -> None:
        self.offset = offset
        self.level = level
        self.method = method
        self.stored = 0
        self.size = 0
        self.crc = 0
        self.os_id: int | None = None
        self.name = b""
        self.directory: bytes | None = None
        self.comment: bytes | None = None
        self.dos_time: int | None = None
        self.mtime: int | None = None
        self.ext_times: tuple[int, int, int] | None = None
        self.mode: int | None = None
        self.os9_perms: int | None = None
        self.uid: int | None = None
        self.gid: int | None = None
        self.user: bytes | None = None
        self.group: bytes | None = None
        self.header_crc: tuple[int, int] | None = None
        """Where the common header's CRC field is in the raw header, and its value."""
        self.end = 0
        """Where the member's stored bytes start."""


def _os9_mode(perms: int) -> int:
    """OS-9 permissions as a Unix mode, as lhasa reads them: OS-9 has an owner and a
    public set, and the public set stands for the group and everyone else."""
    owner = perms & 0o7  # read, write, execute: bits 0, 1, 2
    public = (perms >> 3) & 0o7

    def rwx(bits: int) -> int:
        return (bits & 1) << 2 | (bits & 2) | (bits & 4) >> 2

    mode = rwx(owner) << 6 | rwx(public) << 3 | rwx(public)
    if perms & 0x80:
        mode |= stat.S_IFDIR
    return mode


def _method(raw: bytes) -> str:
    return raw.decode("latin-1")


class LhaReader(IndexedReader[_Location]):
    """One open LHA archive."""

    # LHA has no index: listing reads each header and seeks past its member's data.
    member_list_upfront = False

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        # The first header is read at open, so a file that is not LHA fails there.
        self._first = self._read_header(0)
        if self._first is None:
            raise CorruptionError("the LHA archive has no members")

    # ── Headers ──────────────────────────────────────────────────────────────────────

    def _read(self, pos: int, length: int, what: str) -> bytes:
        try:
            return self._source.read_exact(pos, length)
        except TruncatedError:
            raise TruncatedError(
                f"the LHA archive ends inside {what} at offset {pos}"
            ) from None

    def _read_header(self, offset: int) -> _Header | None:
        """The header at ``offset``, or ``None`` at the end of the archive."""
        first = self._source.read_at(offset, 1)
        if not first or first == b"\0":
            return None
        base = self._read(offset, _BASE, "a member header")
        level = base[20]
        if level in (0, 1):
            header = self._read_level_01(offset, base, level)
        elif level == 2:
            header = self._read_level_2(offset, base)
        elif level == 3:
            header = self._read_level_3(offset, base)
        else:
            raise CorruptionError(
                f"the member header at offset {offset} has level {level}; LHA has "
                "levels 0 to 3"
            )
        end = header.end + header.stored
        size = self._source.size
        if size is not None:
            cut = end > size
        else:
            # A source whose size is not known: is the data's last byte there? That
            # is ``end > size`` asked of the source, so a cut archive is not listed
            # as whole.
            cut = end > header.end and not self._source.read_at(end - 1, 1)
        if cut:
            raise TruncatedError(
                f"the LHA archive ends inside the data of the member at offset {offset}"
            )
        if header.level == 1 and header.os_id == _OS_LHARK and header.method == "-lh7-":
            header.method = "-lk7-"
        if (
            header.os_id == _OS_AMIGA
            and header.method == "-lh0-"
            and header.size == 0
            and not header.name
        ):
            header.method = _DIRECTORY
        return header

    def _read_level_01(self, offset: int, base: bytes, level: int) -> _Header:
        length = base[0]
        if length < (_LEVEL_0_MIN if level == 0 else _LEVEL_1_MIN):
            raise CorruptionError(
                f"the level-{level} header at offset {offset} is {length} bytes long"
            )
        raw = base + self._read(offset + _BASE, length + 2 - _BASE, "a member header")
        if sum(raw[2:]) & 0xFF != raw[1]:
            raise CorruptionError(
                f"the member header at offset {offset} fails its checksum"
            )
        header = _Header(offset, level, _method(raw[2:7]))
        header.stored, header.size, header.dos_time = struct.unpack_from("<III", raw, 7)
        name_length = raw[21]
        if (_LEVEL_0_MIN if level == 0 else _LEVEL_1_MIN) + name_length > length:
            raise CorruptionError(
                f"the name in the member header at offset {offset} runs past the header"
            )
        header.name = raw[22 : 22 + name_length]
        (header.crc,) = struct.unpack_from("<H", raw, 22 + name_length)
        header.end = offset + length + 2
        if level == 0:
            area = raw[24 + name_length :]
            # LHa for UNIX: OS id, a zero, mtime, then mode, uid and gid last.
            if (
                len(area) >= _UNIX_AREA
                and area[1] == 0
                and area[0]
                in (
                    _OS_UNIX,
                    _OS_OS9_68K,
                )
            ):
                header.os_id = area[0]
                (header.mtime,) = struct.unpack_from("<I", area, 2)
                header.mode, header.uid, header.gid = struct.unpack_from(
                    "<HHH", area, len(area) - 6
                )
            elif (
                len(area) >= _OS9_AREA
                and area[0] == _OS_OS9
                and area[9] == _EXT_OS9
                and area[1:3] == area[17:19]
            ):
                # OS-9's area: the permissions, repeated in an OS-9 record.
                header.os_id = _OS_OS9
                (header.os9_perms,) = struct.unpack_from("<H", area, 1)
            return header
        header.os_id = raw[24 + name_length]
        (following,) = struct.unpack_from("<H", raw, length)
        first = following
        chain = bytearray()
        pos = header.end
        while following:
            if following < 3:
                raise CorruptionError(
                    f"an extended header of the member at offset {offset} is "
                    f"{following} bytes long"
                )
            if len(chain) + following > _HEADER_MAX:
                raise CorruptionError(
                    f"the extended headers of the member at offset {offset} pass "
                    f"{_HEADER_MAX} bytes"
                )
            record = self._read(pos, following, "an extended header")
            chain += record
            pos += following
            (following,) = struct.unpack_from("<H", record, len(record) - 2)
        # Level 1 counts the extended headers in the stored size.
        if len(chain) > header.stored:
            raise CorruptionError(
                f"the extended headers of the member at offset {offset} are longer "
                "than its stored size"
            )
        header.stored -= len(chain)
        header.end = pos
        common = self._walk_extended(header, bytes(chain), 0, 2, first)
        if common is not None:
            self._check_header_crc(header, raw + chain, length + 2 + common)
        return header

    def _read_level_2(self, offset: int, base: bytes) -> _Header:
        (length,) = struct.unpack_from("<H", base)
        if length < _LEVEL_2_SIZE:
            raise CorruptionError(
                f"the level-2 header at offset {offset} is {length} bytes long"
            )
        raw = base + self._read(offset + _BASE, length - _BASE, "a member header")
        header = _Header(offset, 2, _method(raw[2:7]))
        header.stored, header.size, header.mtime = struct.unpack_from("<III", raw, 7)
        (header.crc,) = struct.unpack_from("<H", raw, 21)
        header.os_id = raw[23]
        header.end = offset + length
        if header.os_id == _OS_OS9_68K:
            # OS-9/68k LHA writes two bytes more than its size field counts.
            raw += self._read(offset + length, 2, "a member header")
            header.end += 2
        (first,) = struct.unpack_from("<H", raw, 24)
        common = self._walk_extended(header, raw, _LEVEL_2_SIZE, 2, first)
        if common is not None:
            self._check_header_crc(header, raw, common)
        return header

    def _read_level_3(self, offset: int, base: bytes) -> _Header:
        if struct.unpack_from("<H", base)[0] != 4:
            raise CorruptionError(
                f"the level-3 header at offset {offset} does not have 4-byte fields"
            )
        raw = base + self._read(
            offset + _BASE, _LEVEL_3_SIZE - _BASE, "a member header"
        )
        (length,) = struct.unpack_from("<I", raw, 24)
        if not _LEVEL_3_SIZE <= length <= _HEADER_MAX:
            raise CorruptionError(
                f"the level-3 header at offset {offset} is {length} bytes long"
            )
        raw += self._read(
            offset + _LEVEL_3_SIZE, length - _LEVEL_3_SIZE, "a member header"
        )
        header = _Header(offset, 3, _method(raw[2:7]))
        header.stored, header.size, header.mtime = struct.unpack_from("<III", raw, 7)
        (header.crc,) = struct.unpack_from("<H", raw, 21)
        header.os_id = raw[23]
        header.end = offset + length
        (first,) = struct.unpack_from("<I", raw, 28)
        common = self._walk_extended(header, raw, _LEVEL_3_SIZE, 4, first)
        if common is not None:
            self._check_header_crc(header, raw, common)
        return header

    def _walk_extended(
        self,
        header: _Header,
        raw: bytes,
        pos: int,
        field: int,
        length: int,
    ) -> int | None:
        """Read the extended headers in ``raw`` from ``pos``. Each ends with the next
        one's length in a ``field``-byte field; ``length`` is the first one's.
        Returns where the common header's CRC is."""
        common = None
        while length:
            if length < field + 1 or pos + length > len(raw):
                raise CorruptionError(
                    f"an extended header of the member at offset {header.offset} "
                    "runs past the header"
                )
            record_end = pos + length
            kind = raw[pos]
            body = raw[pos + 1 : record_end - field]
            if kind == _EXT_COMMON and len(body) >= 2:
                common = pos + 1
                header.header_crc = (common, int.from_bytes(body[:2], "little"))
            else:
                self._apply_extended(header, kind, body)
            length = int.from_bytes(raw[record_end - field : record_end], "little")
            pos = record_end
        return common

    @staticmethod
    def _apply_extended(header: _Header, kind: int, body: bytes) -> None:
        if kind == _EXT_NAME:
            header.name = body
        elif kind == _EXT_DIRECTORY:
            header.directory = body
        elif kind == _EXT_COMMENT:
            header.comment = body
        elif kind == _EXT_SIZES and len(body) >= 16:
            header.stored, header.size = struct.unpack_from("<QQ", body)
        elif kind == _EXT_WINDOWS_TIMES and len(body) >= 24:
            header.ext_times = struct.unpack_from("<QQQ", body)
        elif kind == _EXT_UNIX_MODE and len(body) >= 2:
            (header.mode,) = struct.unpack_from("<H", body)
        elif kind == _EXT_UNIX_OWNER and len(body) >= 4:
            header.gid, header.uid = struct.unpack_from("<HH", body)
        elif kind == _EXT_UNIX_GROUP_NAME:
            header.group = body
        elif kind == _EXT_UNIX_USER_NAME:
            header.user = body
        elif kind == _EXT_UNIX_MTIME and len(body) >= 4:
            (header.mtime,) = struct.unpack_from("<I", body)
        elif kind == _EXT_OS9 and len(body) >= 12:
            (header.os9_perms,) = struct.unpack_from("<H", body, 7)

    def _check_header_crc(self, header: _Header, raw: bytes, at: int) -> None:
        stored = int.from_bytes(raw[at : at + 2], "little")
        if crc16(raw[:at] + b"\0\0" + raw[at + 2 :]) != stored:
            raise CorruptionError(
                f"the member header at offset {header.offset} fails its CRC"
            )

    # ── Listing ──────────────────────────────────────────────────────────────────────

    @override
    def iter_members(self) -> Iterator[MemberRecord[_Location]]:
        header = self._first
        end = 0
        while header is not None:
            member = self._member(header)
            yield MemberRecord(
                member, _Location(header.end, header.stored, header.method, header.crc)
            )
            end = header.end + header.stored
            header = self._read_header(end)
        self._check_end(end)

    def _check_end(self, end: int) -> None:
        """Report a missing end byte, or data after it."""
        marker = self._source.read_at(end, 1)
        if not marker:
            self._context.report(
                DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
                "the LHA archive has no end byte after its last member",
                ArchiveEofContext(
                    format="lha",
                    expected_marker="end_of_archive_byte",
                    expected_bytes=1,
                    observed_bytes=0,
                    observed_kind="absent",
                ),
            )
            return
        tail = self._source.read_at(end + 1, _TAIL_SCAN)
        stripped = tail.lstrip(_PADDING)
        if stripped:
            at = 1 + len(tail) - len(stripped)
            self._context.report(
                DiagnosticCode.ARCHIVE_TRAILING_DATA,
                f"the LHA archive has data {at} bytes after its end byte",
                ArchiveEofContext(
                    format="lha",
                    expected_marker="zeros_to_eof",
                    observed_bytes=at,
                    observed_kind="nonzero",
                ),
            )

    def _member(self, header: _Header) -> ArchiveMember:
        context = self._context
        raw = header.name
        comment = header.comment
        if header.level < 2 and b"\0" in raw:
            # Amiga LHA stores a file note after the name.
            raw, comment = raw.split(b"\0", 1)
        if header.directory:
            directory = header.directory.replace(b"\xff", b"/").rstrip(b"/")
            raw = directory + b"/" + raw if raw else directory
        raw = raw.replace(b"\xff", b"/")
        name = context.decode_name(raw).replace("\\", "/")
        method = header.method
        mode = header.mode
        if header.os_id == _OS_OS9_68K and mode is not None:
            # OS-9/68k LHA writes OS-9 permissions where Unix LHA writes a mode.
            mode = _os9_mode(mode)
        elif header.os9_perms is not None:
            mode = _os9_mode(header.os9_perms)
        file_type = (mode or 0) & UNIX_FILE_TYPE_MASK
        link_target: str | None = None
        special = None
        if method == _DIRECTORY and file_type == stat.S_IFLNK:
            member_type = MemberType.SYMLINK
            # The separator is the first bar of the directory and the name joined:
            # some archives put it in the directory record (``etc|../../`` then
            # ``etc``), and lhasa splits the joined path too.
            bars = name.count("|")
            name, bar, link_target = name.partition("|")
            if not bar:
                link_target = None
            elif raw.count(b"|") == bars:
                # The stored name is name|target; raw_name keeps the name's bytes.
                # A 0x7C can be a cp932 second byte, so the bytes are cut only when
                # every 0x7C in them decoded as a bar.
                raw = raw[: raw.index(b"|")]
        elif method == _DIRECTORY:
            member_type = MemberType.DIRECTORY
        else:
            special = special_file_type(mode) if mode is not None else None
            if special is not None and not header.size:
                member_type = MemberType.OTHER
            else:
                member_type = MemberType.FILE
        if method == _DIRECTORY:
            compression: tuple[CompressionMethod, ...] = ()
        elif method in _STORED:
            compression = (CompressionMethod(CompressionAlgorithm.STORED),)
        elif method in _LZH_METHODS or method[:3] == "-lh" or method[:3] == "-lz":
            compression = (CompressionMethod(CompressionAlgorithm.LZH),)
        else:
            compression = (CompressionMethod(CompressionAlgorithm.UNKNOWN),)
        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=raw,
            size=header.size if member_type is MemberType.FILE else None,
            compressed_size=header.stored if member_type is MemberType.FILE else None,
            mode=mode & 0o7777 if mode is not None else None,
            uid=header.uid,
            gid=header.gid,
            uname=context.decode_name(header.user) if header.user else None,
            gname=context.decode_name(header.group) if header.group else None,
            link_target=link_target,
            compression=compression,
            comment=context.decode_name(comment) if comment else None,
            create_system=(
                None
                if header.os_id is None
                else _CREATE_SYSTEMS.get(header.os_id, CreateSystem.UNKNOWN)
            ),
        )
        member.extra["lha.method"] = method
        member.extra["lha.header_level"] = header.level
        if header.os_id is not None:
            member.extra["lha.os_id"] = chr(header.os_id)
        if special is not None:
            member.extra["special_file_type"] = special
        self._set_times(member, header)
        if member_type is MemberType.SYMLINK and link_target is None:
            context.link_target_unavailable(
                member,
                reason="missing",
                message=f"LHA symlink {quoted(name)} stores no target",
                target_in_archive=False,
            )
        return member

    def _set_times(self, member: ArchiveMember, header: _Header) -> None:
        if header.mtime is not None:
            member.modified = unix32_to_datetime(header.mtime)
        elif header.dos_time:
            member.modified = dos_to_datetime(header.dos_time)
            if member.modified is None:
                self._bad_time(member, "modified", "dos", f"0x{header.dos_time:08x}")
        if header.ext_times is not None:
            created, _modified, accessed = header.ext_times
            for field, value in (("created", created), ("accessed", accessed)):
                when: datetime | None
                when, issue = filetime_to_datetime(value, member.name, field=field)
                if issue is not None:
                    self._bad_time(member, field, "ntfs", issue.value_repr)
                if when is not None:
                    setattr(member, field, when)

    def _bad_time(
        self, member: ArchiveMember, field: str, source: str, value: str
    ) -> None:
        self._context.report(
            DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
            f"Invalid LHA {field} time for {quoted(member.name)}: {value}",
            MemberTimestampContext(
                member_name=member.name, field=field, source=source, value_repr=value
            ),
            member=member,
        )

    # ── Data ─────────────────────────────────────────────────────────────────────────

    @override
    def open_member(self, member: ArchiveMember, locator: _Location) -> MemberData:
        method = locator.method
        digests = (MemberDigest("crc16", locator.crc.to_bytes(2, "big"), new=_Crc16),)
        span = ((locator.offset, locator.offset + locator.stored),)
        if method in _STORED:
            return MemberData(
                self._source.view(locator.offset, locator.stored), digests=digests
            )
        if method not in _LZH_METHODS and method not in _OLD_DECODERS:
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} uses LHA method {method}, which archivey "
                "does not read"
            )
        stream = _LzhStream(self._source, locator, member.size or 0)
        return MemberData(stream, digests=digests, bounded=True, ranges=span)

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(is_solid=False)


class _LzhStream(io.RawIOBase):
    """One member's decoded bytes."""

    _view: BinaryIO | None = None  # close() reads it, even after a failed __init__

    def __init__(self, source: ReaderSource, locator: _Location, size: int) -> None:
        self._view = source.view(locator.offset, locator.stored)
        old = _OLD_DECODERS.get(locator.method)
        self._decoder = (
            LzhDecoder(locator.method, size, self._more)
            if old is None
            else old(size, self._more)
        )

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


class LhaHandler(IndexedFormatHandler):
    """LHA archives: ``.lzh``, ``.lha``."""

    format = ArchiveFormat.LHA
    extensions = (".lzh", ".lha")
    magic = tuple(Magic(2, method.encode("ascii")) for method in _KNOWN_METHODS)
    uses_encoding = True
    non_seekable_reason = "archivey finds each member by seeking past the one before"

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> LhaReader:
        return LhaReader(source, context)


LhaReadBackend = register_builtin_format(LhaHandler)
