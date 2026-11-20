"""A read-only ISO 9660 parser (ECMA-119, Joliet, SUSP 1.12 and RRIP 1.12), for the ISO backend.

The ISO backend lists one of up to four trees an image carries over one set of file
data: the plain ISO 9660 tree of the primary volume descriptor, the Rock Ridge names
and POSIX attributes that ride its records, the Joliet tree of a supplementary volume
descriptor, and the UDF tree (``udf.py``). This module parses the first three. It
reads the image only through the ``read_at`` the caller hands in, so every read is
bounded by the image and takes the source's lock.

Layout, from the start of the image::

    0 .. 32 767        system area (an MBR or GPT on a hybrid image; not read here)
    32 768             volume descriptors, one per 2048-byte sector: primary (1),
                       supplementary (2; Joliet when its escape sequence says UCS-2),
                       boot record (0), terminator (255); UDF recognition
                       descriptors (BEA01, NSR02, TEA01) may follow
    root record        each tree's root directory record sits in its descriptor
    directory extent   directory records, one after another; a zero length byte
                       pads to the end of the logical block

A directory record (ECMA-119 9.1) gives a child's extent, data length, date, flags
and identifier, then a System Use area. On a Rock Ridge image that area holds SUSP
entries (``PX`` mode and owner, ``NM`` name, ``SL`` link target, ``TF`` times, ``CL``
/ ``PL`` / ``RE`` for relocated deep directories, ``ZF`` for zisofs data) and may
continue in a block a ``CE`` entry names.

What is parsed, and when: the whole primary tree and the Joliet tree, at
construction, as ``udf.UdfVolume`` parses the UDF tree. The listing limits are
weighed as the trees are parsed (:class:`IsoBudget`): each directory's declared
length before it is read, and one member per record. An image over them is refused
before any member is listed, and a listing reads nothing more. Path tables are not
read to list: a reader that walks the directories needs none, as Linux's isofs and
7-Zip do not. Only a source that takes read hints reads one, to hint where the
directories are (:func:`directory_hints`).

How damage is handled:

- A read that comes back short is ``TruncatedError`` when the file ends before the
  end the image declares and the read started inside the file, and
  ``CorruptionError`` otherwise (:meth:`IsoVolume._read`).
- A directory record whose fixed fields do not hold (too short, past its directory,
  an identifier longer than the record, extent or volume sequence number that
  disagree between their little- and big-endian copies) refuses the image: nothing
  after it in the directory can be found.
- A malformed System Use entry ends that record's area, and the reason is kept on
  the record (:attr:`RockRidge.dropped`). The record lists from the entries before
  it; no other record is affected.
- Non-zero bytes in a directory block's padding are noted (:attr:`IsoVolume.padding`)
  and skipped.
- A directory tree that loops is refused.
"""

from __future__ import annotations

import struct
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from typing import NamedTuple, Protocol

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.remote import MAX_PENDING_HINTS
from archivey.types import ArchiveFormat

# ECMA-119 6.2.1 and 8.1: the volume descriptors start at sector 16 and take one
# 2048-byte sector each, whatever the logical block size.
DESCRIPTOR_SECTOR = 2048
FIRST_DESCRIPTOR = 16 * DESCRIPTOR_SECTOR
# How many sectors from sector 16 are read as descriptors. A structural bound, not a
# policy limit: real images have fewer than ten (a primary, a Joliet, a boot record,
# a terminator, and the UDF recognition descriptors), and each step is one sector.
MAX_DESCRIPTORS = 256
_DESCRIPTOR_IDENTS = frozenset(
    (b"CD001", b"CDW02", b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2")
)
_VD_BOOT = 0
_VD_PRIMARY = 1
_VD_SUPPLEMENTARY = 2
_VD_TERMINATOR = 255
# The escape sequences that make a supplementary descriptor Joliet: UCS-2 levels 1 to
# 3 (Joliet specification, 1995).
_JOLIET_ESCAPES = (b"%/@", b"%/C", b"%/E")
_BLOCK_SIZES = (512, 1024, 2048)

# ECMA-119 9.1: the fixed part of a directory record, before its identifier.
_RECORD_FIXED = 33
_ROOT_RECORD_AT = 156  # in a primary or supplementary volume descriptor
# File flags (ECMA-119 9.1.6).
FLAG_DIRECTORY = 0x02
FLAG_ASSOCIATED = 0x04
_FLAG_RECORD = 0x08
_FLAG_PROTECTION = 0x10
FLAG_MULTI_EXTENT = 0x80

# The trees a budget counts members under: the primary volume descriptor's (plain ISO
# 9660, and Rock Ridge over it) and the Joliet one.
PRIMARY_TREE = 0
JOLIET_TREE = 1

# SUSP and RRIP entry tags this parser reads, or knows to skip. A System Use area
# whose first entry is one of these carries Rock Ridge; one whose first two bytes are
# anything else is taken to carry none, as pycdlib took it, the reader this one
# replaced.
_RR_FIRST_TAGS = frozenset(
    {
        b"SP", b"RR", b"CE", b"PX", b"ER", b"ES", b"PN", b"SL", b"NM", b"CL", b"PL",
        b"TF", b"SF", b"RE", b"AL",
    }
)  # fmt: skip
# Tags whose version must be 1 (SUSP 1.12 and RRIP 1.12). ``ZF`` is not here: its
# version 2 is zisofs2, which a reader refuses by the entry, not by the area.
_VERSIONED_TAGS = _RR_FIRST_TAGS | {b"PD", b"ST"}
# The Extension Reference identifiers of RRIP 1.09/1.10 and 1.12. A tree whose records
# carry Rock Ridge-shaped bytes but no such ``ER`` entry is not read as Rock Ridge:
# the bytes are then taken as a false positive (a Mac HFS hybrid, for one).
_RRIP_IDS = (b"RRIP_1991A", b"IEEE_P1282")
# How many continuation areas one record's System Use area may chain through. Linux
# stops at 32 (``RR_MAX_CE_ENTRIES``); real writers use at most one.
MAX_CONTINUATIONS = 32
# The Yellow Book XA system use record: 14 bytes, ``XA`` at byte 6.
_XA_SIZE = 14

# Bits of a ``TF`` entry's flags (RRIP 1.12 4.1.6): the times it holds, in order,
# then the long-form flag. Bit 1 is the modification time and bit 2 the access time
# (Linux ``parse_rock_ridge_inode_internal`` reads them so).
_TF_LONG_FORM = 0x80
_TF_FIELDS = ("created", "modified", "accessed", "attribute", "backup", "expiration")


class IsoBudget(Protocol):
    """Where the parser weighs what it reads and keeps: each directory's declared
    length (before the read) and each continuation area's, and one member per
    record."""

    def add_iso_bytes(self, nbytes: int) -> None: ...

    def add_iso_member(self, tree: int) -> None: ...


class RawDate(NamedTuple):
    """A date as stored: the 7-byte directory-record form, or the 17-byte long form
    of a volume descriptor (a ``TF`` entry with its long-form flag)."""

    raw: bytes
    long: bool


class Zisofs(NamedTuple):
    """A Rock Ridge ``ZF`` or ``Z2`` entry: the file's data is zisofs-compressed."""

    tag: bytes
    version: int
    algorithm: bytes
    header_size: int
    log2_block_size: int
    # ``None`` when the entry is too short to hold the fields; it is then refused.
    uncompressed_size: int | None


@dataclass(slots=True)
class RockRidge:
    """The Rock Ridge entries of one record, its own area and continuations together.

    The first entry of each kind wins; a later one is ignored. ``name`` is ``None``
    when the record has no ``NM`` entry, and the empty string when its ``NM`` entries
    spell nothing. ``symlink`` is the ``SL`` target, or ``None`` when there is no
    ``SL`` entry or when its components end on a continuation flag.
    """

    name: bytes | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    is_symlink: bool = False
    symlink: bytes | None = None
    times: dict[str, RawDate] = field(default_factory=dict)
    child_link: int | None = None
    parent_link: int | None = None
    relocated: bool = False
    zisofs: Zisofs | None = None
    # Why the area was cut short at a malformed entry; ``None`` when it was not.
    dropped: str | None = None


@dataclass(slots=True, eq=False)
class IsoEntry:
    """One entry of a directory: a file, which may span several records (a file of
    4 GiB or more), or a directory.

    ``offset`` is the image offset of its first directory record, its identity. The
    fields after it are that record's, except ``extents``, which holds every record's
    ``(block, declared length)`` in on-disc order. A directory's ``children`` are its
    entries in on-disc order, ``.`` and ``..`` left out; ``None`` for a file, and for a
    directory the walk did not enter (one a Rock Ridge ``CL`` entry stands in for).
    """

    offset: int
    ident: bytes
    flags: int
    date: bytes
    extents: tuple[tuple[int, int], ...]
    rr: RockRidge | None
    parent: IsoEntry | None
    children: list[IsoEntry] | None = None
    # A directory whose ``..`` record carries a Rock Ridge ``PL`` entry: a deep
    # directory relocated under ``rr_moved``, listed where a ``CL`` entry points.
    parent_linked: bool = False

    @property
    def is_dir(self) -> bool:
        return bool(self.flags & FLAG_DIRECTORY)

    @property
    def is_associated(self) -> bool:
        return bool(self.flags & FLAG_ASSOCIATED)

    @property
    def extent(self) -> int:
        """The first record's extent, in logical blocks."""
        return self.extents[0][0]

    @property
    def data_length(self) -> int:
        """The declared length of the data, every record together."""
        return sum(length for _, length in self.extents)


@dataclass(slots=True)
class IsoTree:
    """The directory tree of one volume descriptor."""

    kind: int  # ``PRIMARY_TREE`` or ``JOLIET_TREE``
    root: IsoEntry
    path_table_size: int
    path_table_le: int  # the little-endian path table's first block


def _both_endian_32(data: bytes, offset: int) -> tuple[int, int]:
    """A both-byte-order 32-bit field (ECMA-119 7.3.3): the little- and big-endian
    copies, in that order."""
    return (
        int.from_bytes(data[offset : offset + 4], "little"),
        int.from_bytes(data[offset + 4 : offset + 8], "big"),
    )


def _both_endian_16(data: bytes, offset: int) -> tuple[int, int]:
    return (
        int.from_bytes(data[offset : offset + 2], "little"),
        int.from_bytes(data[offset + 2 : offset + 4], "big"),
    )


class IsoVolume:
    """The ISO 9660 trees of an image, parsed at construction.

    ``hint`` is the source's read-hint callback, with the longest gap a cluster of
    directories may span; ``None`` when the source takes no hints.
    """

    def __init__(
        self,
        read_at: Callable[[int, int], bytes],
        image_length: int,
        *,
        archive_name: str | None,
        budget: IsoBudget | None,
        hint: tuple[Callable[[int, int], None], int] | None = None,
        describe_cut: Callable[[int], str] | None = None,
    ) -> None:
        self._read_at = read_at
        self._image_length = image_length
        self._archive_name = archive_name
        self._budget = budget
        self._describe_cut = describe_cut
        # The end the image declares, once known: the descriptor being read, then the
        # primary descriptor's volume space. A short read inside it is a cut image.
        self._declared_end = 0
        # The image offset of the first non-zero byte in each directory block's
        # padding, in the order met.
        self.padding: list[int] = []
        # The end of the furthest file data the primary tree points at inside the
        # file: pycdlib took the volume to end there when its volume space size
        # said less (Office XP images do), and the trailing-data check still does.
        self.data_end = 0
        self._sp_skip = 0
        self._saw_rrip = False
        self._has_rr_entries = False

        (primary, primary_at), joliet = self._read_descriptors()
        self.block_size = int.from_bytes(primary[128:130], "little")
        self.space_size = int.from_bytes(primary[80:84], "little")
        self.volume_identifier = bytes(primary[40:72])
        # Yellow Book: "CD-XA001" at byte 1024 of the primary descriptor (byte 141 of
        # its application use field) says the records may carry XA system use.
        self._xa = primary[1024:1032] == b"CD-XA001"
        self._declared_end = max(self._declared_end, self.space_size * self.block_size)

        self.primary = self._tree(primary, primary_at, PRIMARY_TREE)
        if hint is not None:
            directory_hints(self, self.primary, *hint)
        self._walk(self.primary)
        # Rock Ridge needs both entries on some record and an ``ER`` that names RRIP.
        self.rock_ridge = self._has_rr_entries and self._saw_rrip

        self.joliet: IsoTree | None = None
        if joliet is not None:
            self.joliet = self._tree(*joliet, JOLIET_TREE)
            if hint is not None:
                directory_hints(self, self.joliet, *hint)
            self._walk(self.joliet)

    # --- errors and reads -------------------------------------------------------

    def _corrupt(self, detail: str) -> CorruptionError:
        return CorruptionError(
            f"Error reading ISO image: {detail}",
            source_format=ArchiveFormat.ISO,
            archive_name=self._archive_name,
        )

    def _cut(self, offset: int, n: int) -> bool:
        """Whether a short read of ``n`` bytes at ``offset`` is a cut image: the file
        ends before the end the image declares, and the read started inside that end.
        A read that starts past it followed a wrong pointer."""
        return self._image_length < self._declared_end and offset <= self._declared_end

    def _truncated(self, what: str) -> TruncatedError:
        declared = self._declared_end
        sizes = (
            self._describe_cut(declared)
            if self._describe_cut is not None
            else f"it declares {declared} bytes and the file holds {self._image_length}"
        )
        return TruncatedError(
            f"Error reading ISO image: the image ends before its own structures do: "
            f"{sizes} ({what} is cut short)",
            source_format=ArchiveFormat.ISO,
            archive_name=self._archive_name,
        )

    def _read(self, offset: int, n: int, what: str) -> bytes:
        """``n`` bytes at ``offset``, or an error naming ``what`` when they are not all
        there (:meth:`_cut` says which)."""
        data = self._read_at(offset, n)
        if len(data) == n:
            return data
        if self._cut(offset, n):
            raise self._truncated(what)
        raise self._corrupt(
            f"{what} at offset {offset} declares {n} bytes and the image holds "
            f"{max(0, self._image_length - offset)} from there"
        )

    # --- volume descriptors -----------------------------------------------------

    def _read_descriptors(
        self,
    ) -> tuple[tuple[bytes, int], tuple[bytes, int] | None]:
        """The primary volume descriptor, and the first Joliet one (or ``None``), each
        with its image offset.

        Sectors from 16 are read as descriptors until one is not (its type or
        identifier is not a descriptor's), as pycdlib read them: UDF recognition
        descriptors may follow the terminator. A sector cut short is a cut image.
        """
        primary: tuple[bytes, int] | None = None
        joliet: tuple[bytes, int] | None = None
        terminated = False
        for index in range(MAX_DESCRIPTORS):
            start = FIRST_DESCRIPTOR + index * DESCRIPTOR_SECTOR
            self._declared_end = max(self._declared_end, start + DESCRIPTOR_SECTOR)
            sector = self._read(start, DESCRIPTOR_SECTOR, "volume descriptor")
            kind = sector[0]
            if sector[1:6] not in _DESCRIPTOR_IDENTS or kind not in (
                _VD_BOOT,
                _VD_PRIMARY,
                _VD_SUPPLEMENTARY,
                _VD_TERMINATOR,
            ):
                break
            if sector[1:6] != b"CD001":
                continue
            if kind == _VD_PRIMARY and primary is None:
                self._check_descriptor(sector, primary=True)
                primary = (sector, start)
                # From here a cut is measured against the volume space, as a cut
                # descriptor after the primary one is still a cut image.
                self._declared_end = max(
                    self._declared_end,
                    int.from_bytes(sector[80:84], "little")
                    * int.from_bytes(sector[128:130], "little"),
                )
            elif kind == _VD_SUPPLEMENTARY and joliet is None and _is_joliet(sector):
                self._check_descriptor(sector, primary=False)
                joliet = (sector, start)
            elif kind == _VD_TERMINATOR:
                if sector[6] != 1:
                    raise self._corrupt(
                        f"its volume descriptor set terminator has version {sector[6]}"
                    )
                terminated = True
        if primary is None:
            raise self._corrupt("it has no primary volume descriptor")
        if not terminated:
            raise self._corrupt("its volume descriptor set has no terminator")
        return primary, joliet

    def _check_descriptor(self, vd: bytes, *, primary: bool) -> None:
        """Refuse a primary or Joliet descriptor whose fixed fields do not hold.

        The checks are the ones pycdlib made: the version, the zero fields, and the
        two byte orders of every both-endian field. The logical block size must be
        512, 1024 or 2048 bytes.
        """
        name = "primary" if primary else "Joliet"
        version = vd[6]
        if version != 1 and (primary or version != 2):
            raise self._corrupt(f"its {name} volume descriptor has version {version}")
        if primary and vd[7] != 0:
            raise self._corrupt("its primary volume descriptor has non-zero flags")
        if any(vd[72:80]) or vd[882] != 0:
            raise self._corrupt(
                f"its {name} volume descriptor has data in a field that must be zero"
            )
        if not primary and vd[881] not in (1, 2):
            raise self._corrupt(
                f"its {name} volume descriptor has file structure version {vd[881]}"
            )
        for label, at, width in (
            ("volume space size", 80, 4),
            ("volume set size", 120, 2),
            ("volume sequence number", 124, 2),
            ("logical block size", 128, 2),
            ("path table size", 132, 4),
        ):
            le, be = (_both_endian_32 if width == 4 else _both_endian_16)(vd, at)
            if le != be:
                raise self._corrupt(
                    f"its {name} volume descriptor's {label} reads {le} little-endian "
                    f"and {be} big-endian"
                )
        block_size = int.from_bytes(vd[128:130], "little")
        if primary and block_size not in _BLOCK_SIZES:
            raise self._corrupt(
                f"its logical block size is {block_size}; it must be 512, 1024 or 2048"
            )

    def _tree(self, vd: bytes, at: int, kind: int) -> IsoTree:
        """The tree the root directory record of the descriptor at ``at`` starts."""
        record = vd[_ROOT_RECORD_AT : _ROOT_RECORD_AT + 34]
        extent, length = self._extent_and_length(record, "root directory record")
        root = IsoEntry(
            offset=at + _ROOT_RECORD_AT,
            ident=b"\x00",
            flags=FLAG_DIRECTORY,
            date=bytes(record[18:25]),
            extents=((extent, length),),
            rr=None,
            parent=None,
        )
        return IsoTree(
            kind=kind,
            root=root,
            path_table_size=int.from_bytes(vd[132:136], "little"),
            path_table_le=int.from_bytes(vd[140:144], "little"),
        )

    def _extent_and_length(self, record: bytes, what: str) -> tuple[int, int]:
        extent, extent_be = _both_endian_32(record, 2)
        if extent != extent_be:
            raise self._corrupt(
                f"a {what}'s extent reads {extent} little-endian and {extent_be} "
                "big-endian"
            )
        # The data length is read little-endian only: images in the wild get the
        # big-endian copy wrong (pycdlib, isofs and 7-Zip all read it so).
        return extent, int.from_bytes(record[10:14], "little")

    # --- directories ------------------------------------------------------------

    def _walk(self, tree: IsoTree) -> None:
        """Parse every directory of ``tree``, breadth first, each extent once.

        A directory that names an extent already entered is refused as a loop; a
        Rock Ridge ``CL`` placeholder is not entered, as the directory it points at
        is entered where it is stored (under ``rr_moved``).
        """
        root = tree.root
        seen = {root.extent}
        queue = deque([root])
        while queue:
            directory = queue.popleft()
            children = self._read_directory(tree, directory)
            directory.children = children
            for child in children:
                if not child.is_dir:
                    continue
                if child.rr is not None and child.rr.child_link is not None:
                    continue
                if child.extent in seen:
                    raise self._corrupt(
                        f"its directory {child.ident!r} names a directory already "
                        "listed: the directory tree forms a loop"
                    )
                seen.add(child.extent)
                queue.append(child)

    def _read_directory(self, tree: IsoTree, directory: IsoEntry) -> list[IsoEntry]:
        """The entries of one directory, in on-disc order.

        Records that share an identifier are joined into one file only where the
        multi-extent flag says so: a file record with the flag continues into the
        next record when that one has the same identifier and is a file record of
        the same kind (associated file or not). Every other record is an entry of its
        own, as 7-Zip lists them.
        """
        block_size = self.block_size
        start = directory.extent * block_size
        length = directory.data_length
        # Weighed as declared, before the read: the length is the image's own claim,
        # and each directory may claim up to the rest of the image.
        if self._budget is not None:
            self._budget.add_iso_bytes(length)
        data = self._read(start, length, "directory")
        entries: list[IsoEntry] = []
        continuing: IsoEntry | None = None
        pending: list[tuple[int, int]] = []
        offset = 0
        while offset < length:
            record_length = data[offset]
            if record_length == 0:
                pad = min(block_size - offset % block_size, length - offset)
                padding = data[offset : offset + pad]
                stripped = padding.lstrip(b"\0")
                if stripped:
                    self.padding.append(start + offset + pad - len(stripped))
                offset += pad
                continue
            record = data[offset : offset + record_length]
            at = start + offset
            if len(record) < record_length:
                raise self._corrupt(
                    f"the directory record at offset {at} declares {record_length} "
                    f"bytes and its directory holds {len(record)} from there"
                )
            if record_length < _RECORD_FIXED:
                raise self._corrupt(
                    f"the directory record at offset {at} is {record_length} bytes, "
                    "shorter than its fixed fields"
                )
            if _RECORD_FIXED + record[32] > record_length:
                raise self._corrupt(
                    f"the directory record at offset {at} is {record_length} bytes "
                    f"and its identifier declares {record[32]}"
                )
            entry = self._record(tree, directory, record, start + offset)
            offset += record_length
            if entry.ident in (b"\x00", b"\x01"):
                if entry.ident == b"\x01" and entry.rr is not None:
                    directory.parent_linked = entry.rr.parent_link is not None
                continue
            if self._budget is not None:
                self._budget.add_iso_member(tree.kind)
            if tree.kind == PRIMARY_TREE:
                self._note_data_end(entry)
            if (
                continuing is not None
                and entry.ident == continuing.ident
                and not entry.is_dir
                and entry.is_associated == continuing.is_associated
            ):
                pending.append(entry.extents[0])
            else:
                if continuing is not None:
                    continuing.extents = tuple(pending)
                entries.append(entry)
                continuing, pending = entry, [entry.extents[0]]
            # The chain goes on only past a file record that carries the flag.
            if entry.is_dir or not entry.flags & FLAG_MULTI_EXTENT:
                continuing.extents = tuple(pending)
                continuing = None
        if continuing is not None:
            continuing.extents = tuple(pending)
        return entries

    def _record(
        self, tree: IsoTree, directory: IsoEntry, record: bytes, offset: int
    ) -> IsoEntry:
        """Parse one directory record (ECMA-119 9.1)."""
        extent, length = self._extent_and_length(record, "directory record")
        seqnum, seqnum_be = _both_endian_16(record, 28)
        if seqnum != seqnum_be:
            raise self._corrupt(
                f"the directory record at offset {offset} has a volume sequence "
                f"number that reads {seqnum} little-endian and {seqnum_be} big-endian"
            )
        flags = record[25]
        if record[1] and flags & (_FLAG_RECORD | _FLAG_PROTECTION):
            raise self._corrupt(
                f"the directory record at offset {offset} has an extended attribute "
                "record together with the record or protection flag"
            )
        ident_length = record[32]
        ident = bytes(record[_RECORD_FIXED : _RECORD_FIXED + ident_length])
        rr: RockRidge | None = None
        if tree.kind == PRIMARY_TREE:
            # The System Use area follows the identifier and its padding byte.
            su_start = _RECORD_FIXED + ident_length + (1 - ident_length % 2)
            rr = self._system_use(
                record[su_start:],
                ident_length,
                root_dot=directory is tree.root and ident == b"\x00",
            )
        return IsoEntry(
            offset=offset,
            ident=ident,
            flags=flags,
            date=bytes(record[18:25]),
            extents=((extent, length),),
            rr=rr,
            parent=directory,
        )

    def _note_data_end(self, entry: IsoEntry) -> None:
        if entry.is_dir or (entry.rr is not None and entry.rr.is_symlink):
            return
        block, length = entry.extents[0]
        end = block * self.block_size + length
        if length and end <= self._image_length:
            self.data_end = max(self.data_end, end)

    # --- System Use (SUSP and Rock Ridge) ---------------------------------------

    def _system_use(
        self, area: bytes, ident_length: int, *, root_dot: bool
    ) -> RockRidge | None:
        """The Rock Ridge entries of a record's System Use area, or ``None`` when it
        carries none."""
        if self._xa:
            # An XA system use record comes first, right after the identifier or
            # (Windows 98 SE) after as many bytes again as the identifier, rounded up
            # to even.
            for at in (0, ident_length + ident_length % 2):
                if len(area) >= at + _XA_SIZE and area[at + 6 : at + 8] == b"XA":
                    area = area[at + _XA_SIZE :]
                    break
        # The root's ``SP`` skip count applies to every other area, before its
        # first entry (SUSP 1.12 5.3).
        skip = 0 if root_dot else self._sp_skip
        if area[skip : skip + 2] not in _RR_FIRST_TAGS:
            return None
        self._has_rr_entries = True
        rr = RockRidge()
        names: list[bytes] = []
        components: list[tuple[int, bytes]] = []
        continuations = 0
        while True:
            next_area = self._parse_area(rr, area, skip, names, components, root_dot)
            root_dot = False
            skip = 0
            if next_area is None or rr.dropped is not None:
                break
            continuations += 1
            if continuations > MAX_CONTINUATIONS:
                rr.dropped = (
                    f"more than {MAX_CONTINUATIONS} continuation areas in a chain"
                )
                break
            continued = self._continuation(rr, *next_area)
            if continued is None:
                break
            area = continued
        if names:
            rr.name = b"".join(names)
        if components:
            rr.symlink = _symlink_target(components)
        return rr

    def _continuation(
        self, rr: RockRidge, block: int, offset: int, length: int
    ) -> bytes | None:
        """The continuation area a ``CE`` entry names, or ``None`` (and the reason on
        ``rr``) when it cannot be read: it runs past its logical block, as Linux
        refuses it (``rock_continue``), or past the end of a full-length image."""
        if offset + length > self.block_size:
            rr.dropped = (
                f"continuation area of {length} bytes at offset {offset} of block "
                f"{block} runs past the {self.block_size}-byte block"
            )
            return None
        start = block * self.block_size + offset
        if self._budget is not None:
            self._budget.add_iso_bytes(length)
        data = self._read_at(start, length)
        if len(data) < length:
            if self._cut(start, length):
                raise self._truncated("Rock Ridge continuation area")
            rr.dropped = (
                f"continuation area of {length} bytes at block {block} lies past the "
                "end of the image"
            )
            return None
        return data

    def _parse_area(
        self,
        rr: RockRidge,
        area: bytes,
        skip: int,
        names: list[bytes],
        components: list[tuple[int, bytes]],
        root_dot: bool,
    ) -> tuple[int, int, int] | None:
        """Parse one System Use area into ``rr``; the ``CE`` entry's ``(block,
        offset, length)`` when it names a continuation.

        An entry whose header does not hold (a length under 4 or past the area, a
        version other than 1) or whose body does not parse ends the area there, with
        the reason kept in ``rr.dropped``: what follows is read at an offset that
        cannot be trusted. genisoimage writes such an area for a long symlink target
        (from about 400 bytes with 1.1.11), whose ``SL`` length wraps past 255;
        ``isoinfo`` and ``xorriso`` stop at the same place. An entry of a type this
        parser does not know is skipped, as SUSP 1.12 5 says. Entries after ``ST``
        are not entries.
        """
        continuation: tuple[int, int, int] | None = None
        offset = skip
        end = len(area)
        while offset < end:
            left = end - offset
            if left < 4:
                if left != 1 or area[offset] != 0:  # one zero byte pads the area
                    rr.dropped = f"{left} stray byte(s) at the end"
                break
            tag = bytes(area[offset : offset + 2])
            length = area[offset + 2]
            version = area[offset + 3]
            if length < 4 or length > left or (version != 1 and tag in _VERSIONED_TAGS):
                rr.dropped = (
                    f"entry {tag!r} at offset {offset} has version {version} and "
                    f"length {length} with {left} byte(s) left"
                )
                break
            entry = bytes(area[offset : offset + length])
            problem = self._parse_entry(rr, tag, entry, names, components, root_dot)
            if problem is not None:
                rr.dropped = f"entry {tag!r} at offset {offset} {problem}"
                break
            if tag == b"CE" and continuation is None:
                continuation = (
                    int.from_bytes(entry[4:8], "little"),
                    int.from_bytes(entry[12:16], "little"),
                    int.from_bytes(entry[20:24], "little"),
                )
            offset += length
            if tag == b"ST":
                break
        return continuation

    def _parse_entry(
        self,
        rr: RockRidge,
        tag: bytes,
        entry: bytes,
        names: list[bytes],
        components: list[tuple[int, bytes]],
        root_dot: bool,
    ) -> str | None:
        """Read one SUSP entry into ``rr``; why it does not parse, or ``None``."""
        length = len(entry)
        if tag == b"NM":
            if length == 4:
                return None  # no flags and no name: spells nothing
            if entry[4] & 7 not in (0, 1, 2, 4):
                # More than one of CONTINUE, CURRENT and PARENT: isofs ignores the
                # entry and lists the record.
                return f"has flags {entry[4]:#x}"
            # CURRENT or PARENT with a name: the name is taken, as pycdlib took it
            # (VirtualBox Guest Additions images set CURRENT on real names).
            names.append(entry[5:])
        elif tag == b"PX":
            if length not in (36, 44):
                return f"is {length} bytes, not 36 or 44"
            fields = [_both_endian_32(entry, at) for at in range(4, length, 8)]
            if any(le != be for le, be in fields):
                return "has fields whose two byte orders disagree"
            if rr.mode is None:
                rr.mode, rr.uid, rr.gid = fields[0][0], fields[2][0], fields[3][0]
        elif tag == b"SL":
            if length < 5:
                return "is too short"
            rr.is_symlink = True
            at = 5
            while at < length:
                if at + 2 > length or at + 2 + entry[at + 1] > length:
                    return "has a component cut short"
                flags, size = entry[at], entry[at + 1]
                if flags not in (0, 1, 2, 4, 8) or (flags & 0x0E and size):
                    return f"has a component with flags {flags:#x} and length {size}"
                components.append((flags, entry[at + 2 : at + 2 + size]))
                at += 2 + size
        elif tag == b"TF":
            if length < 5:
                return "is too short"
            flags = entry[4]
            size = 17 if flags & _TF_LONG_FORM else 7
            at = 5
            for bit, name in enumerate(_TF_FIELDS + ("effective",)):
                if not flags & (1 << bit):
                    continue
                raw = entry[at : at + size]
                if len(raw) < size:
                    return "holds fewer times than its flags declare"
                if name in ("created", "modified", "accessed", "attribute"):
                    rr.times.setdefault(name, RawDate(raw, size == 17))
                at += size
        elif tag == b"CE":
            if length < 28:
                return "is too short"
        elif tag in (b"CL", b"PL"):
            if length < 12:
                return "is too short"
            block = int.from_bytes(entry[4:8], "little")
            if tag == b"CL" and rr.child_link is None:
                rr.child_link = block
            elif tag == b"PL" and rr.parent_link is None:
                rr.parent_link = block
        elif tag == b"RE":
            rr.relocated = True
        elif tag == b"SP":
            if length < 7 or entry[4:6] != b"\xbe\xef":
                return "is not a valid SUSP indicator"
            if root_dot:
                self._sp_skip = entry[6]
        elif tag == b"ER":
            if length < 8:
                return "is too short"
            if entry[8 : 8 + entry[4]] in _RRIP_IDS:
                self._saw_rrip = True
        elif tag in (b"ZF", b"Z2") and rr.zisofs is None:
            rr.zisofs = _zisofs(tag, entry)
        return None


def _is_joliet(vd: bytes) -> bool:
    """Whether a supplementary descriptor is Joliet: its escape sequences name UCS-2
    and its flags do not say they are not ISO 2375 registered."""
    return vd[7] & 1 == 0 and vd[88:91] in _JOLIET_ESCAPES


def _zisofs(tag: bytes, entry: bytes) -> Zisofs:
    """A ``ZF`` (zisofs, or zisofs2 at version 2) or ``Z2`` entry. One too short to
    hold its fields keeps no size, so the file is refused rather than read as its
    compressed bytes."""
    version = entry[3]
    if len(entry) < 16:
        return Zisofs(tag, version, b"", 0, 0, uncompressed_size=None)
    return Zisofs(
        tag=tag,
        version=version,
        algorithm=bytes(entry[4:6]),
        header_size=entry[6] * 4,
        log2_block_size=entry[7],
        # Version 1 stores it both-endian in 32 bits, zisofs2 little-endian in 64.
        uncompressed_size=int.from_bytes(
            entry[8 : 12 if version == 1 else 16], "little"
        ),
    )


def _symlink_target(components: list[tuple[int, bytes]]) -> bytes | None:
    """An ``SL`` target from its components (RRIP 1.12 4.1.3.1), every ``SL`` entry's
    together; ``None`` when the last component says it continues.

    A component flagged CONTINUE runs on into the next one; CURRENT is ``.``, PARENT
    ``..``, and ROOT starts the target again at ``/``.
    """
    parts: list[bytes] = []
    continued = False
    for flags, data in components:
        if flags & 8:  # ROOT
            parts = [b""]
            continued = False
            continue
        name = b"." if flags & 2 else b".." if flags & 4 else data
        if continued:
            parts[-1] += name
        else:
            parts.append(name)
        continued = bool(flags & 1)
    if continued:
        return None
    if parts == [b""]:
        return b"/"
    return b"/".join(parts)


def directory_hints(
    volume: IsoVolume,
    tree: IsoTree,
    hint: Callable[[int, int], None],
    max_gap: int,
) -> None:
    """Hint where a tree's directories lie, from its little-endian path table.

    The walk reads each directory in turn, back and forth across the area the
    mastering tool put them in, and a remote source would fetch that area in growing
    pieces and fetch parts of it again. The path table names every directory's first
    block, so the area is known before the walk starts: each cluster of directories
    (blocks closer than ``max_gap`` apart) becomes one hint, and the source fetches
    it in one request, up to its maximum fetch. A cluster of one directory is not
    hinted: its read costs one request either way. A hint never changes the bytes a
    read returns, so a path table that does not parse, or lies past the image, gives
    no hints and no error.
    """
    block_size = volume.block_size
    size = tree.path_table_size
    start = tree.path_table_le * block_size
    if not 0 < size <= _MAX_HINT_TABLE or start + size > volume._image_length:
        return
    table = volume._read_at(start, size)
    blocks: list[int] = []
    at = 0
    while at + 8 <= len(table):
        name_length = table[at]
        if name_length == 0:
            break
        block = int.from_bytes(table[at + 2 : at + 6], "little")
        if block > 0:
            blocks.append(block)
        at += 8 + name_length + name_length % 2
    blocks.sort()
    clusters: list[tuple[int, int, int]] = []  # (first block, last block, directories)
    for block in blocks:
        if clusters and (block - clusters[-1][1]) * block_size <= max_gap:
            first, _, count = clusters[-1]
            clusters[-1] = (first, block, count + 1)
        else:
            clusters.append((block, block, 1))
    # The clusters holding the most directories, at most as many as the source keeps.
    chosen = sorted(
        (c for c in clusters if c[2] > 1), key=lambda c: c[2], reverse=True
    )[:MAX_PENDING_HINTS]
    for first, last, _ in sorted(chosen):
        # The last directory's extent is at least one block; a longer one is read on
        # past the span as an ordinary forward read.
        hint(first * block_size, (last + 1) * block_size)


# The largest path table read for hints. A DVD's table is tens of kilobytes; one
# larger than this is not worth reading to save requests.
_MAX_HINT_TABLE = 4 * 1024 * 1024


# --- dates --------------------------------------------------------------------


def date_value(date: RawDate) -> datetime | None:
    """A stored date as a ``datetime``, or ``None`` when it is not specified or not a
    date.

    The 7-byte form (ECMA-119 9.1.5) counts years from 1900; the 17-byte form (8.4.26.1)
    spells the date in ASCII digits with hundredths of a second. Both end in an offset
    from UTC in 15-minute units. A long form whose digits are not a date reads as not
    specified, as pycdlib read it; MagicISO writes binary junk in the hundredths, which
    are then dropped. A date whose UTC form falls outside ``datetime``'s range is not a
    date.
    """
    fields = date_fields(date)
    if fields is None or not any(fields):
        return None
    raw = date.raw
    offset = struct.unpack_from("b", raw, 16 if date.long else 6)[0]
    try:
        tz = timezone(timedelta(minutes=offset * 15))
        year, month, day, hour, minute, second = fields
        hundredths = 0
        if date.long:
            digits = raw[14:16]
            hundredths = int(digits) if digits.isdigit() else 0
        else:
            year += 1900
        value = datetime(
            year, month, day, hour, minute, second, hundredths * 10_000, tzinfo=tz
        )
        # 0001-01-01 at +13:00 is a valid local time whose UTC form is before year 1.
        value.astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    return value


def date_fields(date: RawDate) -> tuple[int, int, int, int, int, int] | None:
    """The stored year-to-second fields: years since 1900 for the short form, the year
    for the long one. A long form whose digits are not a date is all zeros, as pycdlib
    read it, so it is reported as not specified rather than as invalid."""
    raw = date.raw
    if not date.long:
        if len(raw) < 7:
            return None
        return (raw[0], raw[1], raw[2], raw[3], raw[4], raw[5])
    if len(raw) < 17:
        return None
    digits = raw[:14]
    try:
        parsed = datetime.strptime(digits.decode("ascii"), "%Y%m%d%H%M%S")
    except (UnicodeDecodeError, ValueError):
        return (0, 0, 0, 0, 0, 0)
    return (
        parsed.year,
        parsed.month,
        parsed.day,
        parsed.hour,
        parsed.minute,
        parsed.second,
    )


def date_is_invalid(date: RawDate | None) -> bool:
    """Whether a stored date is present, specified, and yet not a date.

    All zeros is ISO 9660's "not specified", like ZIP's zero DOS date, and is not
    reported. Anything else :func:`date_value` returns ``None`` for (a month of 13, a
    day of 0) is a date the image stores and archivey cannot use.
    """
    if date is None or date_value(date) is not None:
        return False
    fields = date_fields(date)
    return fields is not None and any(fields)


def iter_tree(root: IsoEntry) -> Iterator[tuple[IsoEntry, IsoEntry]]:
    """``(directory, entry)`` for every entry under ``root``, depth first, each
    directory's entries in on-disc order. A directory the walk did not enter (a
    Rock Ridge ``CL`` placeholder's) has no entries."""
    stack = [root]
    while stack:
        directory = stack.pop()
        children = directory.children or ()
        for child in children:
            yield directory, child
        stack.extend(c for c in reversed(children) if c.is_dir and c.children)
