"""The CPIO reader: the four header variants, read in one forward pass.

On-disk layout, one member after another, then a member named ``TRAILER!!!``::

    [ header ][ name, NUL-terminated ][ pad ][ data ][ pad ]

The variants differ only in the header and the padding:

- **Binary** (``cpio -H bin``): 26 bytes of 16-bit words, in the writer's byte order,
  told apart by the magic ``0o070707``. Name and data are padded to 2 bytes.
- **odc** (``-H odc``, POSIX.1 "portable"): 76 bytes of octal ASCII fields after
  ``070707``. No padding. afio writes odc too, but switches a member to its *large*
  header (``070727``, 116 bytes of mostly hexadecimal fields, as libarchive reads it)
  as afio(1) says, for a file over 2 GB, a uid or gid over 65535, or an archive of
  more than 64K hard-linked files. That header has odc's rules otherwise, so the archive is still ``odc``.
- **newc** (``-H newc``, SVR4) and **crc** (``-H crc``): 110 bytes of hexadecimal ASCII
  fields after ``070701`` or ``070702``. Name and data are padded to 4 bytes. In crc,
  the header's ``check`` field is the 32-bit sum of the data bytes.

A symlink's target is its data. Device nodes, FIFOs and sockets are ``OTHER`` members,
as in every format archivey reads.

Hard links are files that share a device and inode number. binary and odc store the
data with every link; this reader lists the first as a ``FILE`` and the later ones as
``HARDLINK`` members to it, whose copy of the data is skipped. newc and crc store the
data with the **last** link only, the earlier ones empty. archivey's hard links name an
earlier member only, so the reader holds the empty links back until the link with the
data arrives, yields that one as the ``FILE``, then the held ones as ``HARDLINK``
members to it. The member order is then not quite the archive's. A group whose data
never arrives (all its links empty, as for an empty file) is yielded at the trailer:
the first as an empty ``FILE``, the rest as links to it.

The reader is written against ``archivey.formats`` and archivey's public names only,
as a format added from outside would be; ``register_builtin_format`` is the one
internal name it uses (``tests/test_cpio.py`` checks). Handbook page:
``dev-docs/formats/cpio.md``.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    SpecialFileDataContext,
    UnknownMemberTypeContext,
)
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberDigest,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.types import ArchiveFormat, ArchiveMember, MemberType

TRAILER = b"TRAILER!!!"
# A stored name longer than this is damage: no file system takes a path this long, and
# newc's 32-bit name size would otherwise let a header ask for 4 GiB.
MAX_NAME_BYTES = 64 * 1024
# How far past the trailer the reader looks for bytes that are not zero padding (GNU cpio
# pads the archive to a 512-byte block; TAR's check reads up to 1 MiB too).
TRAILING_SCAN = 1024 * 1024

_BINARY_LE = b"\xc7\x71"  # 0o070707 as a little-endian 16-bit word
_BINARY_BE = b"\x71\xc7"
_ODC = b"070707"
_NEWC = b"070701"
_CRC = b"070702"
_AFIO_LARGE = b"070727"


class Variant(Enum):
    """A CPIO header variant, by the name GNU cpio's ``-H`` option gives it, and
    ``bin-be`` for a binary archive in the other byte order: GNU cpio writes ``bin`` in
    the host's order, and ``-H`` has no name for the other."""

    BINARY_LE = "bin"
    BINARY_BE = "bin-be"
    ODC = "odc"
    NEWC = "newc"
    CRC = "crc"


_BINARY_FIELDS = {
    Variant.BINARY_LE: struct.Struct("<12H"),
    Variant.BINARY_BE: struct.Struct(">12H"),
}
_ODC_WIDTHS = (6, 6, 6, 6, 6, 6, 6, 11, 6, 11)  # after the magic: 70 bytes
_NEWC_FIELDS = 13  # 8 hexadecimal digits each, after the magic: 104 bytes
# afio's large header after the magic, as (offset, width, base, name), and its four
# separator bytes: 110 bytes. The 4-byte flag at offset 84 is not read, as libarchive
# does not read it: afio's -Z compresses each file and stores the compressed bytes
# and size, which a reader hands back as they are. xsize is refused when non-zero,
# since nothing says where those bytes go and the next header could not be found.
_AFIO_LARGE_SIZE = 110
_AFIO_LARGE_FIELDS = (
    (0, 8, 16, "dev"),
    (8, 16, 16, "ino"),
    (25, 6, 8, "mode"),
    (31, 8, 16, "uid"),
    (39, 8, 16, "gid"),
    (47, 8, 16, "nlink"),
    (55, 8, 16, "rdev"),
    (63, 16, 16, "mtime"),
    (80, 4, 16, "namesize"),
    (88, 4, 16, "xsize"),
    (93, 16, 16, "filesize"),
)
_AFIO_LARGE_SEPARATORS = ((24, b"m"), (79, b"n"), (92, b"s"), (109, b":"))

_S_IFMT = 0o170000
_TYPES = {
    0o100000: MemberType.FILE,
    0o040000: MemberType.DIRECTORY,
    0o120000: MemberType.SYMLINK,
}
_SPECIAL = {
    0o020000: "char_device",
    0o060000: "block_device",
    0o010000: "fifo",
    0o140000: "socket",
}


@dataclass
class Header:
    """One member header, its fields as numbers."""

    variant: Variant
    offset: int
    dev: tuple[int, int]
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    name_size: int
    file_size: int
    check: int = 0


class Sum32:
    """The crc variant's checksum: the sum of the data bytes, modulo 2**32. A
    ``Hasher`` for ``MemberDigest``."""

    def __init__(self) -> None:
        self._total = 0

    def update(self, data: bytes, /) -> None:
        self._total = (self._total + sum(data)) & 0xFFFFFFFF

    def digest(self) -> bytes:
        return self._total.to_bytes(4, "big")


@dataclass
class _LinkGroup:
    """The links of one newc file seen so far: the member that carries the data, once
    it has arrived, and the empty links held back until it does."""

    name: str | None = None
    # Each held member with the name it was stored under, for the adapter's report of
    # a normalized name (MemberSpan.stored_name).
    held: list[tuple[ArchiveMember, str]] = field(default_factory=list)


def _pad(n: int, align: int) -> int:
    return -n % align


def _number(raw: bytes, base: int, what: str, offset: int) -> int:
    try:
        text = raw.decode("ascii")
        if not text.isalnum():
            raise ValueError(text)
        return int(text, base)
    except ValueError:
        raise CorruptionError(
            f"CPIO header at offset {offset}: the {what} field {raw!r} is not a number"
        ) from None


class CpioReader(SequentialReader):
    """Walks a CPIO archive of any of the four variants."""

    link_target_in_data = True

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._variant: Variant | None = None

    def archive_info(self) -> ReaderArchiveInfo:
        variant = self._variant
        return ReaderArchiveInfo(
            format_version=None if variant is None else variant.value,
            extra={} if variant is None else {"cpio.variant": variant.value},
        )

    # The walk ---------------------------------------------------------------------

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        groups: dict[tuple[tuple[int, int], int], _LinkGroup] = {}
        held = 0
        limit = self._context.config.listing_limits.max_members
        while True:
            header = self._read_header(stream)
            raw = stream.read_exact(header.name_size)
            if raw[-1:] != b"\0":
                raise CorruptionError(
                    f"CPIO header at offset {header.offset}: the name is not "
                    "NUL-terminated"
                )
            raw = raw[:-1]
            stream.skip(self._name_pad(header))
            if raw == TRAILER:
                yield from self._flush(groups)
                self._check_end(stream)
                return
            member, stored = self._member(header, raw)
            size = header.file_size
            # A file that shares its inode with another.
            key = (header.dev, header.ino)
            if member.type is MemberType.FILE and header.nlink > 1:
                group = groups.setdefault(key, _LinkGroup())
                if group.name is not None:
                    member.type = MemberType.HARDLINK
                    member.link_target = group.name
                    member.size = None
                elif size == 0 and self._defers_link_data():
                    # newc keeps the data with the last link: hold this one back.
                    if limit is not None and held >= limit:
                        raise ResourceLimitError(
                            f"CPIO archive holds more than {limit} hard links waiting "
                            "for their data, over max_members"
                        )
                    group.held.append((member, stored))
                    held += 1
                    stream.skip(size + self._data_pad(header))
                    continue
                else:
                    group.name = member.name
            yield MemberSpan(member, size, self._digests(header, member), stored)
            stream.skip(self._data_pad(header))
            if member.type is MemberType.FILE and header.nlink > 1:
                group = groups[key]
                for link, link_stored in group.held:
                    link.type = MemberType.HARDLINK
                    link.link_target = member.name
                    link.size = None
                    yield MemberSpan(link, 0, stored_name=link_stored)
                held -= len(group.held)
                group.held.clear()

    def _flush(
        self, groups: dict[tuple[tuple[int, int], int], _LinkGroup]
    ) -> Iterator[MemberSpan]:
        """At the trailer: the links whose data never arrived, the first as an empty
        file and the rest as links to it."""
        for group in groups.values():
            if not group.held:
                continue
            (first, first_stored), *rest = group.held
            first.size = 0
            yield MemberSpan(first, 0, stored_name=first_stored)
            for link, link_stored in rest:
                link.type = MemberType.HARDLINK
                link.link_target = first.name
                link.size = None
                yield MemberSpan(link, 0, stored_name=link_stored)

    def _defers_link_data(self) -> bool:
        return self._variant in (Variant.NEWC, Variant.CRC)

    def _read_header(self, stream: ForwardStream) -> Header:
        offset = stream.offset
        magic = stream.read(2)
        if len(magic) < 2:
            if offset == 0 and not magic:
                raise TruncatedError("CPIO archive is empty")
            raise TruncatedError(
                f"CPIO archive ends at offset {offset + len(magic)} without its trailer"
            )
        if magic in (_BINARY_LE, _BINARY_BE):
            variant = Variant.BINARY_LE if magic == _BINARY_LE else Variant.BINARY_BE
            header = self._binary_header(stream, variant, offset)
        else:
            magic += stream.read_exact(4)
            if magic == _ODC:
                header = self._odc_header(stream, offset)
            elif magic == _AFIO_LARGE:
                header = self._afio_large_header(stream, offset)
            elif magic in (_NEWC, _CRC):
                variant = Variant.NEWC if magic == _NEWC else Variant.CRC
                header = self._newc_header(stream, variant, offset)
            else:
                raise CorruptionError(f"No CPIO header at offset {offset}")
        if self._variant is None:
            self._variant = header.variant
        elif header.variant is not self._variant:
            raise CorruptionError(
                f"CPIO header at offset {offset} is {header.variant.value}, in a "
                f"{self._variant.value} archive"
            )
        if header.name_size == 0 or header.name_size > MAX_NAME_BYTES:
            raise CorruptionError(
                f"CPIO header at offset {offset}: a name of {header.name_size} bytes"
            )
        return header

    def _binary_header(
        self, stream: ForwardStream, variant: Variant, offset: int
    ) -> Header:
        fields = stream.read_struct(_BINARY_FIELDS[variant])
        dev, ino, mode, uid, gid, nlink, _rdev, mtime_hi, mtime_lo = fields[:9]
        name_size, size_hi, size_lo = fields[9:]
        return Header(
            variant,
            offset,
            (dev, 0),
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime_hi << 16 | mtime_lo,
            name_size,
            size_hi << 16 | size_lo,
        )

    def _odc_header(self, stream: ForwardStream, offset: int) -> Header:
        raw = stream.read_exact(sum(_ODC_WIDTHS))
        names = ("dev", "ino", "mode", "uid", "gid", "nlink", "rdev", "mtime")
        names += ("namesize", "filesize")
        values = []
        at = 0
        for width, name in zip(_ODC_WIDTHS, names, strict=True):
            values.append(_number(raw[at : at + width], 8, name, offset))
            at += width
        dev, ino, mode, uid, gid, nlink, _rdev, mtime, name_size, size = values
        return Header(
            Variant.ODC,
            offset,
            (dev, 0),
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            name_size,
            size,
        )

    def _afio_large_header(self, stream: ForwardStream, offset: int) -> Header:
        """afio's large header: an odc member whose fields need more digits."""
        raw = stream.read_exact(_AFIO_LARGE_SIZE)
        for at, separator in _AFIO_LARGE_SEPARATORS:
            if raw[at : at + 1] != separator:
                raise CorruptionError(
                    f"CPIO header at offset {offset}: no {separator.decode()!r} "
                    f"separator in an afio large header"
                )
        values = {
            name: _number(raw[at : at + width], base, name, offset)
            for at, width, base, name in _AFIO_LARGE_FIELDS
        }
        if values["xsize"]:
            # Bytes afio may add to the header; neither libarchive nor this reader
            # knows where they go, so their member cannot be found.
            raise UnsupportedFeatureError(
                f"CPIO header at offset {offset}: an afio large header with "
                f"{values['xsize']} bytes of extra data"
            )
        return Header(
            Variant.ODC,
            offset,
            (values["dev"], 0),
            values["ino"],
            values["mode"],
            values["uid"],
            values["gid"],
            values["nlink"],
            values["mtime"],
            values["namesize"],
            values["filesize"],
        )

    def _newc_header(
        self, stream: ForwardStream, variant: Variant, offset: int
    ) -> Header:
        raw = stream.read_exact(8 * _NEWC_FIELDS)
        names = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize")
        names += ("devmajor", "devminor", "rdevmajor", "rdevminor", "namesize", "check")
        values = [
            _number(raw[i * 8 : i * 8 + 8], 16, name, offset)
            for i, name in enumerate(names)
        ]
        ino, mode, uid, gid, nlink, mtime, size, major, minor = values[:9]
        name_size, check = values[11:]
        return Header(
            variant,
            offset,
            (major, minor),
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            name_size,
            size,
            check,
        )

    def _name_pad(self, header: Header) -> int:
        if header.variant is Variant.ODC:
            return 0
        if header.variant in (Variant.NEWC, Variant.CRC):
            return _pad(110 + header.name_size, 4)
        return _pad(26 + header.name_size, 2)

    def _data_pad(self, header: Header) -> int:
        if header.variant is Variant.ODC:
            return 0
        if header.variant in (Variant.NEWC, Variant.CRC):
            return _pad(header.file_size, 4)
        return _pad(header.file_size, 2)

    # Members ------------------------------------------------------------------------

    def _member(self, header: Header, raw: bytes) -> tuple[ArchiveMember, str]:
        """The member a header describes, its name normalized (so a report names it as
        callers see it), and the name it was stored under."""
        context = self._context
        stored = context.decode_name(raw)
        kind = header.mode & _S_IFMT
        member_type = _TYPES.get(kind)
        special = _SPECIAL.get(kind)
        size = header.file_size
        if member_type is None:
            # A device, FIFO or socket is OTHER, as in every format archivey reads;
            # with data it is a FILE whose bytes are the content (DR-25).
            member_type = MemberType.FILE if size else MemberType.OTHER
        member = ArchiveMember(
            type=member_type,
            name=context.normalize_name(stored, member_type),
            raw_name=raw,
            size=size if member_type is MemberType.FILE else None,
            modified=datetime.fromtimestamp(header.mtime, UTC),
            mode=header.mode & 0o7777,
            uid=header.uid,
            gid=header.gid,
        )
        if special is not None:
            member.extra["special_file_type"] = special
            if size:
                context.report(
                    DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA,
                    f"CPIO member {member.name!r} is a {special} with {size} bytes "
                    "of data; listed as a file",
                    SpecialFileDataContext(
                        member_name=member.name, special_file_type=special, size=size
                    ),
                    member=member,
                )
        elif kind not in _TYPES:
            context.report(
                DiagnosticCode.MEMBER_TYPE_UNKNOWN,
                f"CPIO member {member.name!r} has the unknown file type {kind:#o}",
                UnknownMemberTypeContext(
                    member_name=member.name,
                    stored_type=f"{kind:#o}",
                    size=member.size,
                ),
                member=member,
            )
        return member, stored

    def _digests(
        self, header: Header, member: ArchiveMember
    ) -> tuple[MemberDigest, ...]:
        # Only a FILE's data goes through the member stream that checks digests; a
        # symlink's target is read while walking, so a digest declared for it would be
        # a check that never runs.
        if header.variant is not Variant.CRC or member.type is not MemberType.FILE:
            return ()
        return (MemberDigest("cpio-crc", header.check.to_bytes(4, "big"), Sum32),)

    def _check_end(self, stream: ForwardStream) -> None:
        """After the trailer: zero padding only, within the first MiB. A second archive
        concatenated after the first (an initramfs often is one) is reported here, not
        listed, as archivey's TAR does (``dev-docs/formats/tar.md`` §6): its members
        belong to an archive the caller did not name."""
        scanned = 0
        while scanned < TRAILING_SCAN:
            chunk = stream.read(min(64 * 1024, TRAILING_SCAN - scanned))
            if not chunk:
                return
            stripped = chunk.lstrip(b"\0")
            if stripped:
                at = scanned + len(chunk) - len(stripped)
                self._context.report(
                    DiagnosticCode.ARCHIVE_TRAILING_DATA,
                    f"CPIO archive has data {at} bytes after its trailer",
                    ArchiveEofContext(
                        format="cpio",
                        expected_marker="zeros_to_eof",
                        observed_bytes=at,
                        observed_kind="nonzero",
                    ),
                )
                return
            scanned += len(chunk)


def _binary_probe(prefix: bytes) -> bool:
    """A binary CPIO header: the two-byte magic alone is too weak a signature, so the
    header must also hold a name of the size it declares, ending in a NUL."""
    if len(prefix) < 26:
        return False
    for order, magic in (("<", _BINARY_LE), (">", _BINARY_BE)):
        if prefix[:2] != magic:
            continue
        name_size = struct.unpack_from(f"{order}H", prefix, 20)[0]
        end = 26 + name_size
        return 1 < name_size and end <= len(prefix) and prefix[end - 1] == 0
    return False


class CpioHandler(SequentialFormatHandler):
    """CPIO archives in the binary, odc, newc and crc variants: ``.cpio``."""

    format = ArchiveFormat.CPIO
    extensions = (".cpio",)
    magic = (
        Magic(0, _ODC),
        Magic(0, _NEWC),
        Magic(0, _CRC),
        # afio's large header, on an archive whose first member needs it.
        Magic(0, _AFIO_LARGE),
    )
    probe = staticmethod(_binary_probe)
    uses_encoding = True

    def open_sequential(self, context: ReaderContext) -> CpioReader:
        return CpioReader(context)


CpioReadBackend = register_builtin_format(CpioHandler)
