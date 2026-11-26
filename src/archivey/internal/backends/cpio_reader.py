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
  more than 64K hard-linked files. That header has odc's rules otherwise, so the
  archive is still ``odc``.
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
as a format added from outside would be; ``register_builtin_format`` and the
salvage search (``internal.salvage``, which has no plugin hook yet) are the internal
names it uses (``tests/test_cpio.py`` checks). With ``open_archive(salvage=True)`` the
walk searches past damage for the next header (``_search``). Handbook page:
``dev-docs/formats/cpio.md``.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    SpecialFileDataContext,
    UnknownMemberTypeContext,
)
from archivey.exceptions import (
    CorruptionError,
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
    unix_member_type,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.internal.salvage import HeaderSearch, WalkSalvage
from archivey.terminal import quoted
from archivey.types import ArchiveFormat, ArchiveInfoExtra, ArchiveMember, MemberType

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


# The ASCII magics, afio's large header among them: it is an odc member's header.
_ASCII_MAGICS = frozenset({_ODC, _AFIO_LARGE, _NEWC, _CRC})
_ODC_SIZE = 76
_NEWC_SIZE = 110
_AFIO_HEADER_SIZE = 116
# Each field of a header the salvage search checks: digits only, and afio's four
# separators where they go. afio's 4-byte flag is not read, so it is not checked;
# its xsize must be 0, since the walk refuses a header with extra bytes.
_NEWC_DIGITS = re.compile(rb"[0-9A-Fa-f]{104}\Z")
_ODC_DIGITS = re.compile(rb"[0-7]{70}\Z")
_AFIO_DIGITS = re.compile(
    rb"[0-9A-Fa-f]{24}m[0-7]{6}[0-9A-Fa-f]{48}n[0-9A-Fa-f]{4}.{4}0000s[0-9A-Fa-f]{16}:\Z",
    re.DOTALL,
)


def _fixed_size(magic: bytes) -> int:
    """The size of the ASCII header with ``magic``, before its name."""
    if magic == _ODC:
        return _ODC_SIZE
    if magic == _AFIO_LARGE:
        return _AFIO_HEADER_SIZE
    return _NEWC_SIZE


def _name_size(window: bytes, at: int, magics: frozenset[bytes]) -> int | None:
    """The name size of the ASCII header at ``at`` of ``window`` when its magic is
    one of ``magics``, every field holds digits only and the size is in range;
    ``None`` otherwise, or when the header does not fit in ``window``."""
    magic = window[at : at + 6]
    if magic not in magics:
        return None
    if magic == _ODC:
        fields = window[at + 6 : at + _ODC_SIZE]
        if not _ODC_DIGITS.match(fields):
            return None
        name_size = int(fields[53:59], 8)
    elif magic == _AFIO_LARGE:
        fields = window[at + 6 : at + _AFIO_HEADER_SIZE]
        if not _AFIO_DIGITS.match(fields):
            return None
        name_size = int(fields[80:84], 16)
    else:
        fields = window[at + 6 : at + _NEWC_SIZE]
        if not _NEWC_DIGITS.match(fields):
            return None
        name_size = int(fields[88:96], 16)
    return name_size if 1 <= name_size <= MAX_NAME_BYTES else None


def _passes(window: bytes, at: int, magics: frozenset[bytes]) -> bool:
    """Whether a header the salvage search accepts starts at ``at`` of ``window``:
    its magic is one of ``magics``, every field parses, the name size is in range
    and the name ends with its NUL there."""
    name_size = _name_size(window, at, magics)
    if name_size is None:
        return False
    end = at + _fixed_size(window[at : at + 6]) + name_size
    return end <= len(window) and window[end - 1] == 0


def _header_search(magics: frozenset[bytes], step: int) -> HeaderSearch:
    """The salvage search for the headers of ``magics``, at every ``step`` bytes."""

    def find_header(window: bytes, start: int, stop: int) -> int | None:
        at = start
        while True:
            # The ASCII magics share their first four bytes. The end bound lets a
            # match start only before ``stop``.
            i = window.find(b"0707", at, stop + 3)
            if i < 0:
                return None
            if i % step == 0 and _passes(window, i, magics):
                return i
            at = i + 1

    return HeaderSearch(find_header, step, _AFIO_HEADER_SIZE + MAX_NAME_BYTES)


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

# The magic each variant's salvage search looks for; binary has no search.
_VARIANT_MAGICS = {
    Variant.ODC: frozenset({_ODC, _AFIO_LARGE}),
    Variant.NEWC: frozenset({_NEWC}),
    Variant.CRC: frozenset({_CRC}),
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
    """The links of one newc file seen so far: the latest member that carried data,
    once one has arrived (a later empty link names it), and the empty links held back
    until one does."""

    name: str | None = None
    held: list[tuple[ArchiveMember, _Scan | None]] = field(default_factory=list)


@dataclass(frozen=True)
class _Scan:
    """How salvage reached a member past the damage, for its
    ``MEMBER_FOUND_BY_SCAN`` record, made when the member is listed."""

    offset: int
    confirmed: bool
    searched: bool

    def report(self, salvage: WalkSalvage | None, member: ArchiveMember) -> None:
        assert salvage is not None
        salvage.found(
            member,
            offset=self.offset,
            confirmed=self.confirmed,
            searched=self.searched,
        )


# What the held links are, in a limit error (ReaderContext.hold).
_HELD = "CPIO hard links waiting for their data"


def _pad(n: int, align: int) -> int:
    return -n % align


def _number(raw: bytes, base: int, what: str, offset: int) -> int:
    try:
        text = raw.decode("ascii")
        # int() would also take spaces, a sign and underscores.
        if not text.isalnum():
            raise ValueError(text)
        return int(text, base)
    except ValueError:
        raise CorruptionError(
            f"CPIO header at offset {offset}: the {what} field "
            f"{quoted(raw.decode('ascii', 'surrogateescape'))} is not a number"
        ) from None


class CpioReader(SequentialReader):
    """Walks a CPIO archive of any of the four variants."""

    # A symlink's target is its data: archivey reads it from the span while walking.
    link_target_in_data = True

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._variant: Variant | None = None

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        variant = self._variant
        extra = ArchiveInfoExtra({})
        if variant is not None:
            extra["cpio.variant"] = variant.value
        # A header variant is not a version: like TAR's, it is not in format_version.
        return ReaderArchiveInfo(extra=extra)

    # The walk ---------------------------------------------------------------------

    @override
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        groups: dict[tuple[tuple[int, int], int], _LinkGroup] = {}
        # Salvage (``open_archive(salvage=True)``): the layer's search, the first
        # damage the walk met, where the next search starts, and the origin of the
        # candidate positions (0, or a header found after a lost start).
        salvage = self._context._salvage(stream) if self._context._salvage else None
        if salvage is not None and salvage.lost_start:
            # After a lost start, the first header this walk finds names the variant
            # and the alignment of the later searches. A variant an earlier walk left
            # (one a listing limit stopped) would make the search start at offset 0
            # with that variant's step, and miss a header off it.
            self._variant = None
        damage: CorruptionError | None = None
        search_from: int | None = None
        base = 0
        while True:
            # Whether the search found this header, or the walk walked on to it.
            searched = search_from is not None
            if search_from is not None:
                assert salvage is not None and damage is not None
                hit = self._search(salvage, stream, search_from, base)
                search_from = None
                if hit is None:
                    raise salvage.ending(damage)
                header, raw, base = hit
            else:
                offset = stream.offset
                try:
                    header, raw = self._read_entry(stream)
                except CorruptionError as err:
                    if (
                        salvage is None
                        or not salvage.is_damage(err)
                        or self._search_magics(salvage) is None
                    ):
                        raise
                    # Damage: the walk searches on from the damaged header, and the
                    # pass ends in this error.
                    damage = damage or err
                    search_from = offset
                    continue
            if raw == TRAILER:
                yield from self._flush(groups, salvage)
                self._check_end(stream)
                if salvage is not None:
                    if damage is not None:
                        raise salvage.ending(damage)
                    salvage.state.finish()
                return
            member = self._member(header, raw)
            scan: _Scan | None = None
            if damage is not None:
                # Past the damage every member is one the default does not list: the
                # one the search found, and those walked on from it.
                assert salvage is not None
                if not searched and not salvage.holds(stream.offset + header.file_size):
                    # Data that runs past the layer's end, as ``_search`` refuses for
                    # a found header: not listed, since reading it would end the pass
                    # in TruncatedError. The search goes on past this header.
                    search_from = salvage.after(header.offset)
                    continue
                confirmed = self._confirmed(salvage, header, stream.offset)
                # Recorded when the member is listed: a link held for its data
                # may never be.
                scan = _Scan(header.offset, confirmed, searched)
                if not confirmed:
                    # No claim on its data: the search goes on inside it, past this
                    # header, which it must not find again.
                    search_from = salvage.after(header.offset)
            size = header.file_size
            # A file that shares its inode with another.
            key = (header.dev, header.ino)
            if member.type is MemberType.FILE and header.nlink > 1:
                group = groups.setdefault(key, _LinkGroup())
                # A conforming newc or crc writer stores the data with one link only.
                # A later name that carries data of its own anyway is read as a file
                # of its own, as GNU cpio's copy-in and 7-Zip extract it.
                own_data = size > 0 and self._defers_link_data()
                if group.name is not None and not own_data:
                    # A later link of a file already yielded. binary and odc repeat
                    # the data here, which is skipped as the span's unread bytes.
                    member.type = MemberType.HARDLINK
                    member.link_target = group.name
                    member.size = None
                elif size == 0 and self._defers_link_data():
                    # newc keeps the data with the last link: hold this one back,
                    # counted toward the listing's limits while it waits.
                    self._context.hold(member, reason=_HELD)
                    group.held.append((member, scan))
                    stream.skip(size + self._data_pad(header))
                    continue
                else:
                    # The link that is yielded as the FILE: the first one in binary
                    # and odc, the one carrying the data in newc and crc.
                    group.name = member.name
            if scan is not None:
                scan.report(salvage, member)
            yield MemberSpan(member, size, self._digests(header, member))
            if search_from is None:
                # Not after a member the walk cannot confirm: it moves back into
                # the data to search on, and the pad is not where it reads next.
                stream.skip(self._data_pad(header))
            if member.type is MemberType.FILE and header.nlink > 1:
                group = groups[key]
                for link, link_scan in group.held:
                    link.type = MemberType.HARDLINK
                    link.link_target = member.name
                    link.size = None
                    if link_scan is not None:
                        link_scan.report(salvage, link)
                    yield MemberSpan(link, 0)
                group.held.clear()

    def _read_entry(self, stream: ForwardStream) -> tuple[Header, bytes]:
        """The next header and its name, the NUL taken off, and the name's padding."""
        header = self._read_header(stream)
        raw = stream.read_exact(header.name_size)
        if raw[-1:] != b"\0":
            raise CorruptionError(
                f"CPIO header at offset {header.offset}: the name is not NUL-terminated"
            )
        stream.skip(self._name_pad(header))
        return header, raw[:-1]

    # Salvage ------------------------------------------------------------------------

    def _search_magics(self, salvage: WalkSalvage) -> frozenset[bytes] | None:
        """The magics the salvage search looks for: the variant the archive showed,
        any of the three ASCII ones after a lost start, or ``None`` for a binary
        archive, which has no search."""
        variant = self._variant
        if variant is None:
            if salvage.lost_start:
                return _ASCII_MAGICS
            # The first header failed: its magic still names the variant.
            magic = salvage.read_at(0, len(_ODC))
            if magic == _AFIO_LARGE:
                return _VARIANT_MAGICS[Variant.ODC]
            return frozenset({magic}) if magic in _ASCII_MAGICS else None
        return _VARIANT_MAGICS.get(variant)

    def _search(
        self, salvage: WalkSalvage, stream: ForwardStream, start: int, base: int
    ) -> tuple[Header, bytes, int] | None:
        """The next header the salvage search finds from ``start`` that the walk
        reads and whose data the layer holds, with the base of the later searches; the
        stream is moved to after its name. ``None`` when none is
        found."""
        # A search for any variant (a lost start) runs at every byte; the header it
        # finds sets the alignment of the later ones.
        any_variant = self._variant is None
        while True:
            magics = self._search_magics(salvage)
            assert magics is not None
            step = 1 if _ODC in magics else 4
            result = salvage.search(
                _header_search(magics, step), start=start, base=base % step
            )
            if result.found is None:
                return None
            at = result.found
            salvage.seek(at)
            # A lost start's first header sets the variant (``_read_header``); one
            # the search passes over must not narrow the searches after it.
            variant = self._variant
            try:
                header, raw = self._read_entry(stream)
            except CorruptionError as exc:
                if not salvage.is_damage(exc):
                    raise
                self._variant = variant
                start = at
                continue
            if not salvage.holds(stream.offset + header.file_size):
                self._variant = variant
                start = at
                continue
            return header, raw, at if any_variant else base

    def _confirmed(self, salvage: WalkSalvage, header: Header, data_at: int) -> bool:
        """Whether the header after a found member's data, which starts at
        ``data_at``, passes the search's check (the trailer included)."""
        after = data_at + header.file_size + self._data_pad(header)
        magics = _VARIANT_MAGICS[header.variant]
        head = salvage.read_at(after, _AFIO_HEADER_SIZE)
        name_size = _name_size(head, 0, magics)
        if name_size is None:
            return False
        fixed = _fixed_size(head[:6])
        whole = head[:fixed] + salvage.read_at(after + fixed, name_size)
        return _passes(whole, 0, magics)

    def _flush(
        self,
        groups: dict[tuple[tuple[int, int], int], _LinkGroup],
        salvage: WalkSalvage | None,
    ) -> Iterator[MemberSpan]:
        """At the trailer: the links whose data never arrived, the first as an empty
        file and the rest as links to it."""
        for group in groups.values():
            if not group.held:
                continue
            (first, first_scan), *rest = group.held
            first.size = 0
            if first_scan is not None:
                first_scan.report(salvage, first)
            yield MemberSpan(first, 0)
            for link, link_scan in rest:
                link.type = MemberType.HARDLINK
                link.link_target = first.name
                link.size = None
                if link_scan is not None:
                    link_scan.report(salvage, link)
                yield MemberSpan(link, 0)

    def _defers_link_data(self) -> bool:
        """True for newc and crc, which store a hard-linked file's data with one link
        only, normally the last."""
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

    def _member(self, header: Header, raw: bytes) -> ArchiveMember:
        """The member a header describes, named as the archive stores it."""
        context = self._context
        size = header.file_size
        # A device, FIFO or socket is OTHER, as in every format archivey reads; with
        # data it is a FILE whose bytes are the content (DR-25).
        member_type, special = unix_member_type(header.mode, has_data=size > 0)
        member = ArchiveMember(
            type=member_type,
            name=context.decode_name(raw),
            raw_name=raw,
            size=size if member_type is MemberType.FILE else None,
            mode=header.mode & 0o7777,
            uid=header.uid,
            gid=header.gid,
        )
        context.set_unix_time(member, "modified", header.mtime, source="cpio")
        if special is not None:
            member.extra["special_file_type"] = special
        if special == "unknown":
            kind = header.mode & _S_IFMT
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
        elif special is not None and size:
            context.report(
                DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA,
                f"CPIO member {member.name!r} is a {special} with {size} bytes "
                "of data; listed as a file",
                SpecialFileDataContext(
                    member_name=member.name, special_file_type=special, size=size
                ),
                member=member,
            )
        return member

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

    @override
    def open_sequential(self, context: ReaderContext) -> CpioReader:
        return CpioReader(context)


CpioReadBackend = register_builtin_format(CpioHandler, SUPPORTS_SALVAGE=True)
