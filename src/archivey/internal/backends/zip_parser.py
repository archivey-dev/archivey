"""Native ZIP structure parser (structure only: no names decoded, no codecs, no crypto).

Layout this parser assumes::

    [ prefix? ]
    [ local file header · data · data descriptor? ] × n   # PK\\x03\\x04
    [ central directory header ] × n                      # PK\\x01\\x02
    [ ZIP64 end record · ZIP64 locator ]?                 # PK\\x06\\x06, PK\\x06\\x07
    [ end of central directory record · comment ]         # PK\\x05\\x06

Call graph: :func:`find_end_record` (from the tail, or past the directory after the
members) → :class:`CentralDirectoryWalk`
(forward over the directory, one :class:`CentralEntry` at a time) →
:func:`read_local_header` (per member, when its data is wanted).

Every read goes through a ``read_at(offset, n)`` callable, so the caller owns the
handle, its position and its lock. The parser returns stored bytes and integers; it
decodes no name or comment and emits no diagnostic. Damage raises ``CorruptionError``
or ``TruncatedError`` (an archive cut short), a valid feature archivey refuses raises
``UnsupportedFeatureError``. The caller stamps archive and member context.

The ZIP64 record checks and the stub offset (``base``) follow stdlib ``zipfile``
(3.13). The end-record search is stdlib's older window, one byte wider than 3.13's
(see ``EOCD_SEARCH_WINDOW``), so a prefixed or commented archive resolves to the record
stdlib reads whenever stdlib finds one. The walk tolerates more than stdlib does: it does not refuse
the archive for an extra field cut short or a version-needed it does not know, and it
yields every entry before a damaged one.
"""

from __future__ import annotations

import heapq
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
    raw_message_of,
)
from archivey.internal.backends.zip_aes import iter_extra_fields
from archivey.internal.backends.zip_detect import (
    LOCAL_HEADER_SIGNATURE,
    LOCAL_HEADER_SIZE,
    ZIP_MULTI_VOLUME_MSG,
)
from archivey.terminal import quoted

#: ``read_at(offset, n)``: up to ``n`` bytes from absolute ``offset``; fewer only at
#: the end of the source.
ReadAt = Callable[[int, int], bytes]

EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"
# Archive extra data record: written in front of a central directory that PKWARE
# Strong Encryption has encrypted (APPNOTE §4.3.11, §7.3).
ARCHIVE_EXTRA_DATA_SIGNATURE = b"PK\x06\x08"

EOCD_SIZE = 22
ZIP64_LOCATOR_SIZE = 20
ZIP64_EOCD_SIZE = 56
CENTRAL_HEADER_SIZE = 46
# How far before the end of the file the end-record search starts: stdlib's older
# window (3.11, early 3.12 releases), ``1 << 16`` plus the record. The comment length
# is a uint16, so this is one byte more than the format needs; 3.13 and later 3.12
# releases shrank stdlib's window to match. Keeping the wider one reads every archive
# either window reads, so one byte of junk after a maximal comment stays readable on
# every Python.
EOCD_SEARCH_WINDOW = (1 << 16) + 22
STRONG_ENCRYPTED_DIRECTORY_MSG = (
    "PKWARE Strong Encryption is not supported (only ZipCrypto and WinZip AES are); "
    "this archive's central directory appears to be encrypted with it"
)

_EOCD = struct.Struct("<4s4H2LH")
_ZIP64_LOCATOR = struct.Struct("<4sLQL")
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")
#: A central header's fixed fields up to its name, extra and comment lengths.
_CENTRAL_HEAD = "<4s4B4HL2L"
_CENTRAL_HEADER = struct.Struct(_CENTRAL_HEAD + "5H2L")
#: Where those three lengths start: ``_CENTRAL_HEADER`` fields 12 to 14.
_CENTRAL_LENGTHS_AT = struct.calcsize(_CENTRAL_HEAD)
_CENTRAL_LENGTHS = struct.Struct("<3H")
_LOCAL_HEADER = struct.Struct("<4s2B4HL2L2H")

_ZIP64_EXTRA_TAG = 0x0001
_U32_MAX = 0xFFFF_FFFF
_U64_MAX = 0xFFFF_FFFF_FFFF_FFFF
# Classic end-record disk fields use 0xFFFF to mean "see the ZIP64 record", not disk
# 65535.
_ZIP64_DISK_SENTINEL = 0xFFFF

# The directory is read forward in pieces of this size. It trades memory (one piece
# plus one entry) against the number of reads, each a seek and a read on the shared
# handle; a directory no larger than one piece is read in one read.
_WALK_CHUNK = 1 << 20

# The largest offset a seek takes (a signed 64-bit file offset). A ZIP64 field can
# declare any uint64, and seeking past this raises a raw OverflowError, so an offset
# past it is refused as corrupt before anything seeks to it. It is a structural bound,
# not a policy one: no file holds a header there. Offsets below it need no bound of
# their own, because the reader keeps every member's data before the next local header
# or the central directory (the overlap guard), and a header read past the file's end
# is cut short.
MAX_DATA_OFFSET = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class EndRecord:
    """The end of central directory record, with the ZIP64 record's values when present."""

    #: Absolute position of the classic record's signature.
    eocd_offset: int
    #: A ZIP64 end record supplied the counts, size and offset below.
    zip64: bool
    #: Total entries the record declares (16 bits in a classic record).
    entries_declared: int
    cd_size: int
    #: The directory offset as stored, before ``base``.
    cd_offset: int
    #: Added to every stored offset: the bytes in front of an archive whose writer did
    #: not adjust its offsets for them (a self-extractor stub). stdlib calls it
    #: ``concat``. 0 for an ordinary archive.
    base: int
    #: The archive comment, cut at the end of the file.
    comment: bytes
    #: The comment length the record declares; above ``len(comment)`` when the file
    #: ends first.
    comment_declared: int
    #: Bytes after the record and its declared comment, up to the end of the file. The
    #: reader reports them; the parser only counts them. Junk longer than the search
    #: window hides the record itself, as it does for stdlib.
    trailing: int
    #: Why the ZIP64 records after a locator were not used, when the classic record,
    #: none of whose fields is saturated, stood in for them; the reader reports it.
    zip64_damage: str | None = None

    @property
    def cd_start(self) -> int:
        """Absolute position of the first central directory header."""
        return self.cd_offset + self.base


NO_END_RECORD_MSG = (
    "truncated or corrupt ZIP (no end of central directory record found)"
)


def find_end_record(
    read_at: ReadAt,
    file_size: int,
    *,
    members_end: Callable[[], int | None] | None = None,
) -> EndRecord:
    """Locate and read the end record, and the ZIP64 records when there are some.

    The search is stdlib's older one: a comment-less record ending at end of file, then
    the last ``PK\\x05\\x06`` in the final 65 558 bytes. Newer stdlib's window (3.13,
    later 3.12 releases) is one byte shorter; the wider one finds the same record whenever the shorter one finds
    any. A decoy signature earlier in the file, in the comment or in the record's own
    fields therefore cannot make the two disagree.

    When the search finds none (more trailing bytes than the window holds),
    ``members_end`` is called for where the members end, which the caller knows from a
    walk over the local headers (``None`` when the walk found no end), and the record
    is found by stepping over the directory from there
    (:func:`step_over_directory`).

    Raises ``UnsupportedFeatureError`` for a record that names another disk (a spanned
    set) and for an encrypted central directory (PKWARE Strong Encryption), and
    ``CorruptionError`` when no record is found or the records contradict each other.
    A damaged ZIP64 record or locator is a ``CorruptionError`` only when the classic
    record cannot stand in for it (a saturated field, or no place for the directory's
    end); otherwise the classic values are returned, with the reason in
    ``EndRecord.zip64_damage``. The two halves are :func:`locate_end_record` and
    :func:`read_end_record`.
    """
    found, _stopped = locate_end_record(read_at, file_size, members_end=members_end)
    if found is None:
        raise CorruptionError(NO_END_RECORD_MSG)
    return read_end_record(read_at, file_size, found)


def locate_end_record(
    read_at: ReadAt,
    file_size: int,
    *,
    members_end: Callable[[], int | None] | None = None,
) -> tuple[tuple[int, bytes, bytes] | None, int | None]:
    """``(offset, record, comment)`` of the end record :func:`find_end_record`
    reads, or ``None`` when neither the search nor the step finds one; and where the
    step over the directory stopped (:func:`step_over_directory`), ``None`` when no
    step ran."""
    found = locate_classic_record(read_at, file_size)
    if found is None and members_end is not None:
        directory_at = members_end()
        if directory_at is not None:
            return step_over_directory(read_at, file_size, directory_at)
    return found, None


def read_end_record(
    read_at: ReadAt, file_size: int, found: tuple[int, bytes, bytes]
) -> EndRecord:
    """The end record :func:`locate_end_record` found, with the ZIP64 records."""
    eocd_offset, record, comment = found
    (
        _sig,
        this_disk,
        cd_start_disk,
        _entries_this_disk,
        entries_total,
        cd_size,
        cd_offset,
        comment_declared,
    ) = _EOCD.unpack(record)
    zip64_damage = None
    records_start = eocd_offset
    try:
        zip64 = _read_zip64_records(read_at, eocd_offset)
    except CorruptionError as exc:
        # A damaged ZIP64 record or locator after a classic record that needs none of
        # its fields: the classic record holds everything, as for a writer that adds
        # the ZIP64 records whether they are needed or not.
        start = (
            None
            if classic_record_saturated(record)
            else _directory_end_before_zip64(read_at, eocd_offset, cd_size)
        )
        if start is None:
            raise
        zip64, zip64_damage, records_start = None, raw_message_of(exc), start
    if zip64 is not None:
        # The ZIP64 record's disk fields replace the classic ones, as stdlib's do.
        records_start, this_disk, cd_start_disk, entries_total, cd_size, cd_offset = (
            zip64
        )
    if disk_field_is_split(this_disk) or disk_field_is_split(cd_start_disk):
        raise UnsupportedFeatureError(ZIP_MULTI_VOLUME_MSG)
    base = records_start - cd_size - cd_offset
    end = EndRecord(
        eocd_offset=eocd_offset,
        zip64=zip64 is not None,
        entries_declared=entries_total,
        cd_size=cd_size,
        cd_offset=cd_offset,
        base=base,
        comment=comment,
        comment_declared=comment_declared,
        trailing=max(file_size - (eocd_offset + EOCD_SIZE + comment_declared), 0),
        zip64_damage=zip64_damage,
    )
    if end.cd_start < 0:
        raise CorruptionError("Bad offset for central directory")
    # PKWARE Strong Encryption can encrypt the directory itself; its writer puts an
    # archive extra data record where the directory starts. Checked before the walk,
    # so the refusal does not depend on how the encrypted bytes happen to parse.
    if read_at(end.cd_start, 4) == ARCHIVE_EXTRA_DATA_SIGNATURE:
        raise UnsupportedFeatureError(STRONG_ENCRYPTED_DIRECTORY_MSG)
    return end


def locate_classic_record(
    read_at: ReadAt, file_size: int
) -> tuple[int, bytes, bytes] | None:
    """``(offset, record, comment)`` of the classic end record, or ``None``."""
    if file_size < EOCD_SIZE:
        return None
    tail = read_at(file_size - EOCD_SIZE, EOCD_SIZE)
    if (
        len(tail) == EOCD_SIZE
        and tail[:4] == EOCD_SIGNATURE
        and tail[-2:] == b"\x00\x00"
    ):
        return file_size - EOCD_SIZE, tail, b""
    window_start = max(file_size - EOCD_SEARCH_WINDOW, 0)
    window = read_at(window_start, file_size - window_start)
    idx = window.rfind(EOCD_SIGNATURE)
    if idx < 0:
        return None
    record = window[idx : idx + EOCD_SIZE]
    if len(record) != EOCD_SIZE:
        return None
    (comment_declared,) = struct.unpack_from("<H", record, 20)
    comment = window[idx + EOCD_SIZE : idx + EOCD_SIZE + comment_declared]
    return window_start + idx, record, comment


def step_over_directory(
    read_at: ReadAt, file_size: int, directory_at: int
) -> tuple[tuple[int, bytes, bytes] | None, int]:
    """``(offset, record, comment)`` of the classic end record that follows the
    directory starting at ``directory_at``, or ``None``; and where the step stopped:
    the end record's offset, or that of the bytes it could not step over.

    Steps over what may lie between the members and the end record, in the order
    APPNOTE §4.3.6 gives: the directory's headers, a ZIP64 end record and its
    locator. Each step reads a length field, so only the records' fixed parts are
    read, not searched. ``None`` when anything else comes first, a record comes out of
    that order, or the file ends before the end record. A digital signature record
    (``PK\\x05\\x05``) is not stepped over: the directory walk does not read past
    one either, wherever the end record is found.
    """
    order = (
        CENTRAL_HEADER_SIGNATURE,
        ZIP64_EOCD_SIGNATURE,
        ZIP64_LOCATOR_SIGNATURE,
        EOCD_SIGNATURE,
    )
    buffer = b""
    buffer_at = 0

    def fixed(pos: int, n: int) -> bytes:
        # The directory is read forward in pieces, not one read per header.
        nonlocal buffer, buffer_at
        if not buffer_at <= pos <= pos + n <= buffer_at + len(buffer):
            buffer_at = pos
            buffer = read_at(pos, max(n, min(_WALK_CHUNK, file_size - pos)))
        return buffer[pos - buffer_at : pos - buffer_at + n]

    pos = directory_at
    stage = 0
    while pos + 4 <= file_size:
        sig = fixed(pos, 4)
        if sig not in order or order.index(sig) < stage:
            return None, pos
        stage = order.index(sig)
        if sig == CENTRAL_HEADER_SIGNATURE:
            header = fixed(pos, CENTRAL_HEADER_SIZE)
            if len(header) != CENTRAL_HEADER_SIZE:
                return None, pos
            pos += _central_entry_size(header, 0)
        elif sig == ZIP64_EOCD_SIGNATURE:
            header = fixed(pos, 12)
            if len(header) != 12:
                return None, pos
            declared = struct.unpack_from("<Q", header, 4)[0]
            # The field is how many bytes follow these twelve. A value that does not
            # fit is the stream ending inside the record, which
            # ``missing_end_record_error`` reports. Stepping to it would seek an
            # offset the stream does not have, and a value past 2**63-1 does not
            # fit in a seek.
            if declared > file_size - pos - 12:
                return None, pos
            pos += 12 + declared
        elif sig == ZIP64_LOCATOR_SIGNATURE:
            pos += ZIP64_LOCATOR_SIZE
        else:
            record = read_at(pos, EOCD_SIZE)
            if len(record) != EOCD_SIZE:
                return None, pos
            (comment_declared,) = struct.unpack_from("<H", record, 20)
            return (pos, record, read_at(pos + EOCD_SIZE, comment_declared)), pos
    return None, pos


def read_zip64_locator(read_at: ReadAt, eocd_offset: int) -> tuple[int, int] | None:
    """``(locator_offset, record_offset)`` of the ZIP64 locator right before the
    classic record at ``eocd_offset``, or ``None`` when there is none.

    A locator naming another disk is refused as a split set, and one naming a record
    past the place right before it as corruption, before any record is read.
    """
    locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE
    if locator_offset < 0:
        return None
    locator = read_at(locator_offset, ZIP64_LOCATOR_SIZE)
    if len(locator) != ZIP64_LOCATOR_SIZE:
        return None
    sig, disk_with_record, record_offset, disks = _ZIP64_LOCATOR.unpack(locator)
    if sig != ZIP64_LOCATOR_SIGNATURE:
        return None
    if disk_with_record != 0 or disks > 1:
        raise UnsupportedFeatureError(ZIP_MULTI_VOLUME_MSG)
    adjacent = locator_offset - ZIP64_EOCD_SIZE
    if adjacent < 0 or record_offset > adjacent:
        raise CorruptionError("Corrupt ZIP64 end of central directory locator")
    return locator_offset, record_offset


def zip64_record_matches(record: bytes, record_offset: int, extensible: int) -> bool:
    """Whether ``record`` is a whole ZIP64 end record whose directory ends at the
    locator's ``record_offset`` and whose size counts ``extensible`` bytes after it."""
    if len(record) != ZIP64_EOCD_SIZE or not record.startswith(ZIP64_EOCD_SIGNATURE):
        return False
    fields = _ZIP64_EOCD.unpack(record)
    record_size, cd_size, cd_offset = fields[1], fields[8], fields[9]
    return (
        cd_offset + cd_size == record_offset
        and record_size + 12 == ZIP64_EOCD_SIZE + extensible
    )


def _read_zip64_records(
    read_at: ReadAt, eocd_offset: int
) -> tuple[int, int, int, int, int, int] | None:
    """``(record_start, this_disk, cd_disk, entries, cd_size, cd_offset)``, or ``None``.

    ``None`` when no locator sits right before the classic record. ``record_start`` is
    where the ZIP64 end record (with any extensible data) starts, the position the stub
    offset is measured from. The checks are stdlib 3.13's: the locator's record offset
    must agree with the record's own size and directory span; when it does not but a
    record sits right before the locator, prepended data moved everything and that
    record is read instead (with no extensible data). The directory-span check is
    against the locator's offset in both cases, as stdlib's is: with unadjusted offsets
    behind a stub, the stored offsets all omit the stub.
    """
    located = read_zip64_locator(read_at, eocd_offset)
    if located is None:
        return None
    locator_offset, record_offset = located
    adjacent = locator_offset - ZIP64_EOCD_SIZE
    extensible = adjacent - record_offset
    record = read_at(record_offset, ZIP64_EOCD_SIZE)
    if not record.startswith(ZIP64_EOCD_SIGNATURE) and record_offset != adjacent:
        extensible = 0
        record = read_at(adjacent, ZIP64_EOCD_SIZE)
    if len(record) != ZIP64_EOCD_SIZE or not record.startswith(ZIP64_EOCD_SIGNATURE):
        raise CorruptionError("ZIP64 end of central directory record not found")
    if not zip64_record_matches(record, record_offset, extensible):
        raise CorruptionError("Corrupt ZIP64 end of central directory record")
    (
        _sig,
        _record_size,
        _made_by,
        _needed,
        this_disk,
        cd_disk,
        _entries_this_disk,
        entries_total,
        cd_size,
        cd_offset,
    ) = _ZIP64_EOCD.unpack(record)
    return adjacent - extensible, this_disk, cd_disk, entries_total, cd_size, cd_offset


def _directory_end_before_zip64(
    read_at: ReadAt, eocd_offset: int, cd_size: int
) -> int | None:
    """Where the directory ends, before ZIP64 records that cannot be read, or ``None``
    when no place fits.

    The places a directory of ``cd_size`` bytes can end are, in turn: where the
    locator names the ZIP64 record, right before the locator where a record of no
    extensible data sits, and at the locator. The first one
    after a central header, ``cd_size`` bytes back, is taken; a directory with no
    entries takes the first.

    Called only after :func:`read_zip64_locator` has read a whole locator, signature
    checked, right before the classic record: every ``CorruptionError`` out of
    :func:`_read_zip64_records` comes after that read.
    """
    locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE
    field = read_at(locator_offset + 8, 8)
    assert len(field) == 8, "a whole ZIP64 locator was read before this"
    (record_offset,) = struct.unpack("<Q", field)
    places = (
        record_offset,
        locator_offset - ZIP64_EOCD_SIZE,
        locator_offset,
    )
    for place in places:
        if not cd_size <= place <= locator_offset:
            continue
        if not cd_size or read_at(place - cd_size, 4) == CENTRAL_HEADER_SIGNATURE:
            return place
    return None


def classic_record_saturated(record: bytes) -> bool:
    """Whether any field of the classic end ``record`` holds the ZIP64 sentinel, so its
    value is in the ZIP64 record alone."""
    fields = _EOCD.unpack(record)
    return _ZIP64_DISK_SENTINEL in fields[1:5] or _U32_MAX in fields[5:7]


def disk_field_is_split(value: int) -> bool:
    """A classic or ZIP64 end-record disk field that names another disk.

    0xFFFF in a classic field means "see the ZIP64 record", not disk 65535, so it is not
    a split; a naive ``!= 0`` check would refuse legitimate ZIP64 archives. In a ZIP64
    record the field is a uint32, so 0xFFFF is a real disk there; it is tolerated
    anyway, to keep the refusal identical to the stdlib-based reader's.
    """
    return value not in (0, _ZIP64_DISK_SENTINEL)


@dataclass(slots=True)
class CentralEntry:
    """One central directory header, with its ZIP64 extra field applied.

    Read-only by convention outside the walk, not ``frozen``: a frozen dataclass sets
    each of its fields through ``object.__setattr__``, three times the cost of
    construction, and the walk builds one per member. The walk itself corrects
    offsets and sizes and drops a comment it cannot trust before it yields the entry.
    """

    #: Position in the directory, from 0.
    index: int
    #: "Version made by": the low byte is the APPNOTE version, the high byte the host.
    version_made_by: int
    #: "Version needed to extract" as one uint16, as ``zip_detect`` reads it and bounds
    #: it at 10..99. APPNOTE gives its high byte no meaning and writers leave it zero;
    #: stdlib splits it off instead.
    version_needed: int
    flags: int
    method: int
    #: The DOS time and date words as stored (the ZipCrypto check byte under bit 3 is
    #: the time's high byte).
    dos_time: int
    dos_date: int
    crc: int
    compressed_size: int
    file_size: int
    #: Absolute position of the local header: the stored offset plus ``EndRecord.base``,
    #: and plus ``offset_correction`` and minus a wrapped ``base``'s excess when the walk
    #: corrects offsets wrapped past 4 GiB (:class:`CentralDirectoryWalk`).
    header_offset: int
    disk_start: int
    internal_attr: int
    external_attr: int
    #: The stored name bytes, never decoded here.
    name: bytes
    extra: bytes
    comment: bytes
    #: What :class:`CentralDirectoryWalk` added to the stored offset because the
    #: archive was written past 4 GiB without ZIP64 (a multiple of 2³²); 0 otherwise.
    offset_correction: int = 0
    #: The offset field as stored, when ``offset_correction`` is not 0.
    stored_offset: int = 0
    #: What :class:`CentralDirectoryWalk` added to the stored compressed size because
    #: the member's data runs a multiple of 2³² past it (macOS Archive Utility,
    #: :func:`written_by_archive_utility`); 0 otherwise.
    compressed_size_correction: int = 0

    @property
    def create_system(self) -> int:
        return self.version_made_by >> 8

    @property
    def date_time(self) -> tuple[int, int, int, int, int, int]:
        """The DOS stamp as ``(year, month, day, hour, minute, second)``, unvalidated.

        The same arithmetic as ``zipfile.ZipInfo.date_time``: no range check, so a
        damaged stamp comes back as numbers ``datetime`` may refuse.
        """
        d, t = self.dos_date, self.dos_time
        return (
            (d >> 9) + 1980,
            (d >> 5) & 0xF,
            d & 0x1F,
            t >> 11,
            (t >> 5) & 0x3F,
            (t & 0x1F) * 2,
        )


#: Where the walk found the end record and the directory disagreeing. The reader turns
#: each into a diagnostic once the members are out.
@dataclass(frozen=True, slots=True)
class EntryCountMismatch:
    declared: int
    read: int
    zip64: bool


@dataclass(frozen=True, slots=True)
class CommentCutShort:
    declared: int
    available: int


@dataclass(frozen=True, slots=True)
class DirectoryOffsetWrapped:
    """The end record stores the directory's offset modulo 2³², and the walk took the
    archive's ``base`` modulo 2³² (:class:`CentralDirectoryWalk`)."""

    #: The directory offset the end record stores.
    stored: int
    #: The offset the directory is at, without ``base``.
    corrected: int


WalkFinding = EntryCountMismatch | CommentCutShort | DirectoryOffsetWrapped

#: The amount a 32-bit offset field wraps by.
OFFSET_WRAP = 1 << 32


def local_header_at(read_at: ReadAt, offset: int) -> tuple[bytes, int] | None:
    """The stored name of the local header at absolute ``offset`` and where the data
    after it starts, or ``None`` when no whole local header starts there."""
    fixed = read_at(offset, LOCAL_HEADER_SIZE)
    if len(fixed) != LOCAL_HEADER_SIZE or fixed[:4] != LOCAL_HEADER_SIGNATURE:
        return None
    (name_len,) = struct.unpack_from("<H", fixed, LOCAL_HEADER_SIZE - 4)
    name = read_at(offset + LOCAL_HEADER_SIZE, name_len)
    if len(name) != name_len:
        return None
    return name, offset + LOCAL_HEADER_SIZE + local_header_variable_length(fixed)


#: "Version made by" of macOS Archive Utility: host 3 (Unix), APPNOTE version 2.1.
ARCHIVE_UTILITY_MADE_BY = 0x0315
#: The old Info-ZIP Unix extra field (``UX``): the only one Archive Utility writes.
_INFOZIP_OLD_UNIX_TAG = b"UX"
#: A data descriptor with its signature and 4-byte sizes, as Archive Utility writes it.
_SIGNED_DESCRIPTOR_SIZE = 16


def written_by_archive_utility(entry: CentralEntry) -> bool:
    """Whether ``entry`` looks as macOS Archive Utility (Finder's Compress, ``ditto -c
    -k``) writes every entry: version made by Unix 2.1, a data descriptor (bit 3) and
    no encryption (bit 0; that writer encrypts nothing), and one extra field, the old
    Info-ZIP ``UX`` field (``0x5855``).

    The caller also requires a classic end record: that writer never writes ZIP64.
    Anyone can copy these fields, so a match only lets a reader try the corrections
    for sizes and offsets that writer wraps modulo 2³². Each correction is still
    checked against the archive's own bytes.
    """
    extra = entry.extra
    return (
        entry.version_made_by == ARCHIVE_UTILITY_MADE_BY
        and entry.flags & 0x09 == 0x08
        and len(extra) >= 4
        and extra[:2] == _INFOZIP_OLD_UNIX_TAG
        and int.from_bytes(extra[2:4], "little") == len(extra) - 4
    )


class CentralDirectoryWalk:
    """Iterate the central directory forward, one :class:`CentralEntry` at a time.

    Reads ``end.cd_size`` bytes from the directory's start in pieces, as stdlib does in
    one read, and parses an entry only when the iteration asks for it.

    Damage raises ``CorruptionError`` after every entry before it has been yielded: a
    header without its signature, a fixed header that crosses the declared end of the
    directory, a ZIP64 extra field missing a value the header defers to it, and a
    length field that does not match the entries around it:

    - a name, extra field or comment that runs past the directory's end (stdlib cuts it
      there);
    - a name, extra field or comment that swallowed the entries after it: it holds a
      central header signature from which the headers chain exactly to the
      directory's end, and either the end record's count fits that reading or the
      first of those headers points at a local header with its name
      (``local_name_at``). Neither alone is enough: a swallow can leave the count
      agreeing with the entries that remain, and a comment can hold a whole entry
      whose offset points at another member. A signature that does not chain so is
      part of the name, and a wrong count alone is the :class:`EntryCountMismatch`
      finding;
    - a name made shorter: no header starts where the entry ends, and the local header
      at the entry's offset (``local_name_at``) holds another name. The entry is not
      yielded, so the reader lists it from that header. With no such header, or the
      same name, the entry is yielded without its comment, which a wrong length may
      have cut, and the next entry raises.

    Following a signature (:class:`_ChainFollower`) remembers every position a chain
    steps onto past its first header, so each such header is stepped over once per
    walk, and it reads past the walk's own bytes through one buffer, at most twice the
    directory. A signature that is part of a name fails at its first header and costs
    nothing past it. A signature the walk can no longer follow, once a budget is
    spent, is damage too: it cannot rule out a swallow, and it does not list a name
    that may hold other entries' bytes. The directory always ends where the end
    records start (``find_end_record`` derives its start from that), so a file cut
    inside it has lost its end record and never gets here.

    Each ``iter()`` walks again from the start. :attr:`findings` is complete once an
    iteration has ended without raising, and is reset when the next one starts.

    **Offsets past 4 GiB without ZIP64.** macOS Archive Utility (Finder's Compress,
    ``ditto -c -k``) writes a classic ZIP past 4 GiB and stores every offset modulo
    2³². With ``local_name_at`` (the stored name of the local header at an absolute
    offset, ``None`` when there is none) and a classic end record, the walk undoes
    that wrap. The members lie in directory order, so an entry whose offset falls
    below the end of an entry before it (its offset, the fixed local header and its
    compressed size; the furthest such end) gets 2³² added until it does not. The
    directory's own offset wraps the same way, and then ``base`` holds a multiple of
    2³²: the walk takes ``base`` modulo 2³² instead. Each correction is kept only when
    a local header with the entry's name starts at the corrected offset, before the
    directory (for the directory's offset, the first entry's header at its offset with
    the smaller ``base``). Otherwise the entry keeps the stored offset, as without the
    correction, and its read fails as it did. A kept correction is in
    :attr:`CentralEntry.offset_correction`, or in :attr:`findings` for the directory.
    An offset from a ZIP64 extra field is never corrected.

    **Compressed sizes past 4 GiB.** Sizes wrap too. With ``local_data_start_at``
    (where the data after the local header at an offset starts) and a directory past
    4 GiB, an entry :func:`written_by_archive_utility` describes has its compressed
    size measured from the layout. Its data and 16-byte signed data descriptor end
    where the next entry's local header starts, or the directory for the last one.
    When that end is past the stored size's by a multiple of 2³², the size takes that
    multiple (:attr:`CentralEntry.compressed_size_correction`). The walk yields such an
    entry once it has read the next one. The entry after one whose size may have
    wrapped looks for its local header at its stored offset plus each multiple of 2³²
    in turn, from the first that is not below the end of the members before it, and
    keeps the first with its name. In such an archive that is one more local header
    read per member (its fixed part, then its name), when the two callables share it
    as the reader's do. An uncompressed size that wraps is the reader's to settle:
    only a decode says what it is.
    """

    def __init__(
        self,
        read_at: ReadAt,
        end: EndRecord,
        *,
        local_name_at: Callable[[int], bytes | None] | None = None,
        local_data_start_at: Callable[[int], int | None] | None = None,
    ) -> None:
        self._read_at = read_at
        self._end = end
        # The stored name of the local header an offset in the directory points at,
        # asked for wherever a length or offset field may be wrong: a corrected
        # offset, an entry no central header follows, and the first header that a
        # signature inside an entry's fields chains to (the last two in any archive).
        self._local_name_at = local_name_at
        # Offsets wrap only without ZIP64, which stores them in full.
        self._corrects_offsets = local_name_at is not None and not end.zip64
        # Sizes can wrap only in a directory past 4 GiB.
        self._local_data_start_at = (
            local_data_start_at
            if self._corrects_offsets and end.cd_start >= OFFSET_WRAP
            else None
        )
        self.findings: list[WalkFinding] = []
        self.entries_read: int | None = None

    def __iter__(self) -> Iterator[CentralEntry]:
        start_at = self._local_data_start_at
        if start_at is None:
            yield from self._entries()
            return
        # An entry whose compressed size may have wrapped, held back until the next
        # entry's offset says where its data ends, with where its data starts.
        pending: tuple[CentralEntry, int] | None = None
        try:
            for entry in self._entries():
                if pending is not None:
                    held, held_start = pending
                    pending = None
                    self._settle_compressed_size(held, held_start, entry.header_offset)
                    yield held
                data_start = (
                    start_at(entry.header_offset)
                    if written_by_archive_utility(entry)
                    else None
                )
                if data_start is None:
                    yield entry
                else:
                    pending = (entry, data_start)
        except Exception:
            # Every entry before damage is yielded before it raises.
            if pending is not None:
                yield pending[0]
            raise
        if pending is not None:
            self._settle_compressed_size(*pending, self._end.cd_start)
            yield pending[0]

    def _settle_compressed_size(
        self, entry: CentralEntry, data_start: int, data_end: int
    ) -> None:
        """Take the multiple of 2³² that ``entry``'s compressed size lost, when its data
        and signed data descriptor run from ``data_start`` to ``data_end`` (the next
        local header, or the directory), that far past the stored size."""
        gap = data_end - _SIGNED_DESCRIPTOR_SIZE - data_start - entry.compressed_size
        if gap > 0 and not gap & _U32_MAX:
            entry.compressed_size += gap
            entry.compressed_size_correction = gap

    def _entries(self) -> Iterator[CentralEntry]:
        end = self._end
        self.findings = []
        self.entries_read = None
        start = end.cd_start
        cd_size = end.cd_size
        base = end.base
        read_at = self._read_at
        data = b""  # directory bytes from data_start, never past cd_size
        data_start = 0  # directory-relative offset of data[0]

        def ensure(pos: int, want_end: int) -> None:
            """Hold the directory bytes up to ``want_end`` (or ``cd_size``), from ``pos``."""
            nonlocal data, data_start
            have = data_start + len(data)
            if want_end <= have or have >= cd_size:
                return
            # Drop what the walk has passed, then read forward in large pieces.
            pieces = [data[pos - data_start :]]
            data_start = pos
            target = min(max(want_end, have + _WALK_CHUNK), cd_size)
            while have < target:
                piece = read_at(start + have, target - have)
                if not piece:
                    break
                pieces.append(piece)
                have += len(piece)
            data = b"".join(pieces)

        name_at_offset = self._local_name_at if self._corrects_offsets else None
        # ``base`` modulo 2³², tried once, on the first entry, when ``base`` is past it.
        wrapped_base = (
            base & _U32_MAX
            if name_at_offset is not None and base >= OFFSET_WRAP
            else None
        )
        # Where the members before this entry end at the earliest: the furthest end, so
        # an entry left uncorrected does not hide the wrap from the entries after it.
        previous_end = 0
        # Whether the entry before may hold a compressed size that wrapped, which moves
        # this one's offset by a multiple of 2³² that ``previous_end`` cannot show.
        after_wrappable = False
        pos = 0
        index = 0
        follower = _ChainFollower(read_at, end)
        while pos < cd_size:
            ensure(pos, pos + CENTRAL_HEADER_SIZE)
            off = pos - data_start
            if len(data) - off < CENTRAL_HEADER_SIZE:
                raise CorruptionError(
                    f"Truncated central directory: entry #{index} starts "
                    f"{cd_size - pos} bytes before the directory's declared end"
                )
            fields = _unpack_central(data, off, index)
            name_len, extra_len, comment_len = fields[12:15]
            name_at = pos + CENTRAL_HEADER_SIZE
            extra_at = name_at + name_len
            comment_at = extra_at + extra_len
            entry_end = comment_at + comment_len
            if entry_end > cd_size:
                # Cutting the field there would list a wrong name or field, and
                # whatever entries it swallowed would go missing (DR-1).
                if extra_at > cd_size:
                    field = "name"
                elif comment_at > cd_size:
                    field = "extra field"
                else:
                    field = "comment"
                raise CorruptionError(
                    f"ZIP central directory entry #{index}'s {field} runs "
                    f"{entry_end - cd_size} bytes past the central directory's end"
                )
            ensure(pos, entry_end)
            at = name_at - data_start
            name = data[at : at + name_len]
            at += name_len
            extra = data[at : at + extra_len]
            at += extra_len
            comment = data[at : at + comment_len]
            self._follow_signatures(
                follower,
                data,
                data_start,
                name_at - data_start,
                entry_end - data_start,
                index,
                base,
            )

            entry = _central_entry(fields, name, extra, comment, index=index, base=base)
            # An offset deferred to a ZIP64 extra field is not corrected. The first
            # entry always gets the one try at ``base``: an offset that needs ZIP64
            # puts the directory past 4 GiB, which saturates the end record's own
            # offset field, and such an end record is ZIP64 (no correction at all).
            if name_at_offset is not None:
                if fields[18] != _U32_MAX:
                    offset = entry.header_offset
                    if wrapped_base is not None:
                        shift = base - wrapped_base
                        if self._header_named(offset - shift, name):
                            base = wrapped_base
                            entry.header_offset = offset - shift
                            self.findings.append(
                                DirectoryOffsetWrapped(
                                    end.cd_offset, end.cd_offset + shift
                                )
                            )
                    elif offset < previous_end or after_wrappable:
                        # The fewest 2³² steps that reach ``previous_end``,
                        # counted rather than stepped: a ZIP64 extra field can
                        # declare a compressed size near 2⁶⁴.
                        steps = max(0, (previous_end - offset + _U32_MAX) >> 32)
                        corrected = offset + (steps << 32)
                        if after_wrappable:
                            # Then each further multiple, up to the directory.
                            while not self._header_named(corrected, name):
                                corrected += OFFSET_WRAP
                                if corrected >= end.cd_start:
                                    corrected = offset
                                    break
                        elif not self._header_named(corrected, name):
                            corrected = offset
                        if corrected != offset:
                            entry.header_offset = corrected
                            entry.offset_correction = corrected - offset
                            entry.stored_offset = fields[18]
                after_wrappable = (
                    self._local_data_start_at is not None
                    and written_by_archive_utility(entry)
                )
                member_end = (
                    entry.header_offset + LOCAL_HEADER_SIZE + entry.compressed_size
                )
                previous_end = max(previous_end, member_end)
            wrapped_base = None
            if entry_end < cd_size:
                ensure(pos, entry_end + 4)
                at = entry_end - data_start
                if data[at : at + 4] != CENTRAL_HEADER_SIGNATURE:
                    self._check_cut_name(entry)
                    # The name agrees, but a length is wrong: the comment, the
                    # entry's last field, may be cut. The extra field is checked
                    # field by field where it is read.
                    entry.comment = b""
            yield entry
            index += 1
            pos = entry_end

        self.entries_read = index
        if not _count_matches(end, index):
            self.findings.append(
                EntryCountMismatch(end.entries_declared, index, end.zip64)
            )
        if end.comment_declared > len(end.comment):
            self.findings.append(
                CommentCutShort(end.comment_declared, len(end.comment))
            )

    def _follow_signatures(
        self,
        follower: _ChainFollower,
        data: bytes,
        data_start: int,
        lo: int,
        hi: int,
        index: int,
        base: int,
    ) -> None:
        """Raise when a central header signature in ``data[lo:hi]``, entry ``index``'s
        fields, starts entries that entry swallowed (:meth:`_swallowed`)."""
        sig = CENTRAL_HEADER_SIGNATURE
        find = data.find
        starts = data.startswith
        lengths = _CENTRAL_LENGTHS.unpack_from
        held = len(data)
        last_header = held - CENTRAL_HEADER_SIZE
        cd_end = self._end.cd_size - data_start
        found = find(sig, lo, hi)
        while found >= 0:
            # Most signatures inside a field are part of it: the header they would
            # start steps to a place no header starts. That is settled here, from
            # ``data`` and without the follower, which is most of a crafted field's
            # cost.
            if found <= last_header:
                name_len, extra_len, comment_len = lengths(
                    data, found + _CENTRAL_LENGTHS_AT
                )
                step_to = (
                    found + CENTRAL_HEADER_SIZE + name_len + extra_len + comment_len
                )
                if step_to > cd_end or (
                    step_to < cd_end
                    and step_to + 4 <= held
                    and not starts(sig, step_to)
                ):
                    found = find(sig, found + 1, hi)
                    continue
            swallowed = self._swallowed(
                follower, data, data_start, found + data_start, index, base
            )
            if swallowed is None:
                raise CorruptionError(
                    f"ZIP central directory entry #{index}'s name, extra field or "
                    "comment holds a central directory header, and following the "
                    "headers such signatures chain to has already read or stepped "
                    "over more than this directory allows for, so archivey cannot "
                    "rule out that a length field swallowed the entries after it"
                )
            if swallowed:
                raise CorruptionError(
                    f"ZIP central directory entry #{index}'s name, extra field or "
                    "comment holds the central directory headers after it: a "
                    "length field swallowed them"
                )
            found = find(sig, found + 1, hi)

    def _swallowed(
        self,
        follower: _ChainFollower,
        data: bytes,
        data_start: int,
        pos: int,
        index: int,
        base: int,
    ) -> bool | None:
        """Whether the central header signature at ``pos`` (directory-relative), inside
        entry ``index``'s fields, starts entries that entry swallowed; ``None`` when the
        follower's budget runs out first.

        The headers must chain from ``pos`` exactly to the directory's end, and then
        one more thing must agree with that reading: the end record's count, or the
        local header the first of them points at, which holds its name. Either can
        fail alone: a swallow can leave the count agreeing with the entries that remain,
        and a comment can hold a whole well-formed entry whose offset points at a local
        header with another name. A count that merely disagrees is
        :class:`EntryCountMismatch`."""
        found = follower.headers_to_end(data, data_start, pos)
        if found is None:
            return None
        count, head = found
        if count < 0:
            return False
        if _count_matches(self._end, index + 1 + count):
            return True
        name_at = self._local_name_at
        if name_at is None:
            return False
        fields = _CENTRAL_HEADER.unpack(head)
        if fields[18] == _U32_MAX:  # deferred to a ZIP64 field: not checked here
            return False
        offset = fields[18] + base
        start = self._end.cd_start
        name_at_pos = pos + CENTRAL_HEADER_SIZE
        name = data[name_at_pos - data_start : name_at_pos - data_start + fields[12]]
        if len(name) < fields[12]:
            name += self._read_at(
                start + name_at_pos + len(name), fields[12] - len(name)
            )
        if not 0 <= offset <= start - LOCAL_HEADER_SIZE - len(name):
            return False
        return name_at(offset) == name

    def _check_cut_name(self, entry: CentralEntry) -> None:
        """Raise for ``entry``, which no header follows, when the local header at its
        offset holds another name: its name length was made shorter, and its name is
        cut. With no local header there, or the same name, the next entry raises."""
        name_at = self._local_name_at
        if name_at is None:
            return
        offset = entry.header_offset
        if not 0 <= offset <= self._end.cd_start - LOCAL_HEADER_SIZE:
            return
        local = name_at(offset)
        if local is not None and local != entry.name:
            # Stored bytes; the reader decodes names, so these show as UTF-8.
            local_text = quoted(local.decode("utf-8", "surrogateescape"))
            central_text = quoted(entry.name.decode("utf-8", "surrogateescape"))
            raise CorruptionError(
                f"ZIP central directory entry #{entry.index} is not followed by a "
                f"central directory header, and its local header names it {local_text} "
                f"where the directory names it {central_text}: a length field is "
                "damaged"
            )

    def _header_named(self, offset: int, name: bytes) -> bool:
        """A local header named ``name`` starts at ``offset``, before the directory."""
        name_at_offset = self._local_name_at
        assert name_at_offset is not None
        if not 0 <= offset <= self._end.cd_start - LOCAL_HEADER_SIZE - len(name):
            return False
        return name_at_offset(offset) == name


#: Positions a :class:`_ChainFollower` remembers: about 400 KiB of CPython objects,
#: under one walk piece. A ladder that every later chain lands on has one rung per
#: entry it spans, and the first chain remembers them, so a few thousand collapse
#: any ladder short of that many entries.
_MEMO_CAP = 4096


class _ChainFollower:
    """Follows the central headers that a signature inside an entry's fields chains
    to, for one walk, at a cost linear in the directory's size.

    Whether the headers from a directory position chain to the directory's end
    depends on the directory's bytes alone, so each position a chain steps onto past
    its first header is remembered with its answer, and a later chain that reaches
    one stops there. The first header, the signature itself, is not remembered:
    the walk finds each signature once. So each header past a first one is stepped
    over once per walk, and the reads this needs go through one buffer kept across
    follows.

    It holds at most ``_MEMO_CAP`` positions (about 100 bytes each in CPython), so
    memory stays fixed whatever the directory holds. The walk finds signatures in
    directory order and chains only step forward, so a position at or before the
    signature being followed is never asked for again and is forgotten; the room
    goes to the positions just ahead, which the next chains land on. Chains that
    need more than the cap ahead to collapse cost steps instead, which the step
    budget counts.

    Two budgets bound what a crafted directory can make it do, and when either runs
    out the walk cannot rule out a swallow and raises:

    - headers stepped over past a first one: as many as the directory could hold
      (``cd_size // 46``), plus a few. A signature that is part of a name fails at
      its first header and spends none of it;
    - bytes read past the walk's own: twice the directory, plus two pieces.
    """

    def __init__(self, read_at: ReadAt, end: EndRecord) -> None:
        self._read_at = read_at
        self._cd_start = end.cd_start
        self._cd_size = end.cd_size
        #: Headers from a position to the directory's end, or -1 when they do not
        #: chain to it.
        self._known: dict[int, int] = {}
        #: The remembered positions, smallest first, to forget those the walk passed.
        self._order: list[int] = []
        self._steps_left = end.cd_size // CENTRAL_HEADER_SIZE + 64
        self._bytes_left = 2 * end.cd_size + 2 * _WALK_CHUNK
        self._buffer = b""
        self._buffer_at = 0

    def header_at(self, data: bytes, data_start: int, pos: int) -> bytes | None:
        """The fixed header at directory-relative ``pos``: from the walk's ``data``,
        this follower's buffer or a read; shorter than 46 bytes when the directory
        ends first, ``None`` when the byte budget is spent."""
        end = pos + CENTRAL_HEADER_SIZE
        if end > self._cd_size:
            return b""
        if data_start <= pos and end <= data_start + len(data):
            return data[pos - data_start : end - data_start]
        at = self._buffer_at
        if not (at <= pos and end <= at + len(self._buffer)):
            if self._bytes_left <= 0:
                return None
            self._buffer = self._read_at(
                self._cd_start + pos, min(_WALK_CHUNK, self._cd_size - pos)
            )
            self._buffer_at = at = pos
            self._bytes_left -= len(self._buffer)
        return self._buffer[pos - at : end - at]

    def headers_to_end(
        self, data: bytes, data_start: int, pos: int
    ) -> tuple[int, bytes] | None:
        """How many central headers chain from ``pos`` exactly to the directory's end,
        the one at ``pos`` included (-1 when they do not), and the fixed header at
        ``pos``; ``None`` when a budget runs out first."""
        cd_size = self._cd_size
        known = self._known
        # The walk finds signatures in directory order and a chain only steps
        # forward, so no later follow reaches a position at or before this one.
        heap = self._order
        while heap and heap[0] <= pos:
            del known[heapq.heappop(heap)]
        path: list[int] = []
        first = b""
        while True:
            if pos >= cd_size:
                rest = 0 if pos == cd_size else -1
                break
            if path and pos in known:
                rest = known[pos]
                break
            head = self.header_at(data, data_start, pos)
            if head is None:
                return None
            if len(head) < CENTRAL_HEADER_SIZE or head[:4] != CENTRAL_HEADER_SIGNATURE:
                rest = -1
                break
            if path:
                self._steps_left -= 1
                if self._steps_left < 0:
                    return None
            else:
                first = head
            path.append(pos)
            pos += _central_entry_size(head, 0)
        if not path:
            return -1, first
        # Remember the positions past the first, with their own counts, up to the cap.
        total = len(path)
        room = min(total, 1 + _MEMO_CAP - len(known))
        for i in range(1, room):
            known[path[i]] = -1 if rest < 0 else total - i + rest
            heapq.heappush(heap, path[i])
        return (-1 if rest < 0 else total + rest), first


def _central_entry_size(buffer: bytes, offset: int) -> int:
    """The size of the central header at ``offset`` in ``buffer``: its fixed part
    and the name, extra field and comment its lengths declare."""
    return CENTRAL_HEADER_SIZE + sum(
        _CENTRAL_LENGTHS.unpack_from(buffer, offset + _CENTRAL_LENGTHS_AT)
    )


def _count_matches(end: EndRecord, count: int) -> bool:
    """Whether ``count`` entries are what the end record declares.

    A classic record counts in 16 bits. Old 7-Zip versions stored the low 16 bits of
    a larger count there without writing ZIP64; current 7-Zip (ZipIn.cpp) accepts that
    with a "16-bit overflow for number of files in headers" note rather than a Headers
    Error, so the comparison is modulo 65536 too.
    """
    return end.entries_declared == (count if end.zip64 else count & 0xFFFF)


#: The fixed header's fields as ``_CENTRAL_HEADER`` unpacks them: signature, made-by
#: version and host, needed version and host, flags, method, DOS time and date, CRC,
#: both sizes, the three variable lengths, disk, both attribute fields, header offset.
_CentralFields = tuple[
    bytes,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
]


def _unpack_central(buffer: bytes, offset: int, index: int) -> _CentralFields:
    """Unpack the fixed 46 bytes of central directory header ``index`` at ``offset``.

    A tuple, not an object: the walk unpacks one per member. ``CorruptionError`` when
    the signature is not there.
    """
    fields = _CENTRAL_HEADER.unpack_from(buffer, offset)
    if fields[0] != CENTRAL_HEADER_SIGNATURE:
        raise CorruptionError(
            f"Bad magic number for central directory (entry #{index})"
        )
    return fields


def _central_entry(
    fields: _CentralFields,
    name: bytes,
    extra: bytes,
    comment: bytes,
    *,
    index: int,
    base: int,
) -> CentralEntry:
    """Build the entry: apply the ZIP64 extra field, then ``base`` to the offset."""
    (
        _signature,
        made_version,
        made_system,
        needed_version,
        needed_system,
        flags,
        method,
        dos_time,
        dos_date,
        crc,
        compressed_size,
        file_size,
        _name_len,
        _extra_len,
        _comment_len,
        disk_start,
        internal_attr,
        external_attr,
        header_offset,
    ) = fields
    compressed_size, file_size, header_offset, disk_start = _apply_zip64_extra(
        extra,
        compressed_size=compressed_size,
        file_size=file_size,
        header_offset=header_offset,
        disk_start=disk_start,
        index=index,
    )
    return CentralEntry(
        index,
        (made_system << 8) | made_version,
        (needed_system << 8) | needed_version,
        flags,
        method,
        dos_time,
        dos_date,
        crc,
        compressed_size,
        file_size,
        header_offset + base,
        disk_start,
        internal_attr,
        external_attr,
        name,
        extra,
        comment,
    )


def _apply_zip64_extra(
    extra: bytes,
    *,
    compressed_size: int,
    file_size: int,
    header_offset: int,
    disk_start: int,
    index: int,
) -> tuple[int, int, int, int]:
    """The four values after the ZIP64 extra field (``0x0001``) replaces the deferred ones.

    APPNOTE 4.5.3: the field holds, in this order, only the values whose header field
    is all ones: uncompressed size, compressed size, local header offset, disk number.
    As in stdlib, every ``0x0001`` field in the blob is applied in turn: a value still
    all ones after one field (a 64-bit all-ones uncompressed size counts) is read again
    from the next. A deferred size or offset a field does not hold is
    ``CorruptionError``. The disk number is the exception: stdlib never reads it and
    nothing consumes it yet, so when no field holds it, it stays ``0xFFFF`` ("not
    known") rather than refusing an archive stdlib opens; it is read once, from the
    first field with four bytes left after the other values (its first four bytes when
    it is the only deferred value, per APPNOTE). A field elsewhere in the blob that is
    cut short is left alone: it says nothing about these four.
    """
    if not (
        file_size == _U32_MAX
        or compressed_size == _U32_MAX
        or header_offset == _U32_MAX
        or disk_start == 0xFFFF
    ):
        return compressed_size, file_size, header_offset, disk_start
    disk_deferred = disk_start == 0xFFFF
    for field in iter_extra_fields(extra):
        if field.tag != _ZIP64_EXTRA_TAG:
            continue
        data = field.data
        cursor = 0
        if file_size in (_U32_MAX, _U64_MAX):
            file_size, cursor = _zip64_value(
                data, cursor, 8, "uncompressed size", index
            )
        if compressed_size == _U32_MAX:
            compressed_size, cursor = _zip64_value(
                data, cursor, 8, "compressed size", index
            )
        if header_offset == _U32_MAX:
            header_offset, cursor = _zip64_value(
                data, cursor, 8, "local header offset", index
            )
        if disk_deferred and cursor + 4 <= len(data):
            disk_start, cursor = _zip64_value(data, cursor, 4, "disk number", index)
            disk_deferred = False
    return compressed_size, file_size, header_offset, disk_start


def _zip64_value(
    data: bytes, cursor: int, width: int, what: str, index: int
) -> tuple[int, int]:
    """The ``width``-byte value at ``cursor`` in a ZIP64 extra field, and the cursor after it."""
    if cursor + width > len(data):
        raise CorruptionError(
            f"Corrupt ZIP64 extra field in central directory entry "
            f"#{index}: {what} not found"
        )
    return int.from_bytes(data[cursor : cursor + width], "little"), cursor + width


@dataclass(frozen=True, slots=True)
class LocalHeader:
    """A local file header: the copy of the member's fields in front of its data."""

    #: One uint16, as ``CentralEntry.version_needed``.
    version_needed: int
    flags: int
    method: int
    dos_time: int
    dos_date: int
    #: 0 with general-purpose bit 3, which defers it to a data descriptor.
    crc: int
    compressed_size: int
    file_size: int
    name: bytes
    extra: bytes
    #: Absolute position of the member's first data byte.
    data_start: int


def read_local_header(
    read_at: ReadAt, header_offset: int, *, zip64_sizes: bool = False
) -> LocalHeader:
    """Parse the local header at absolute ``header_offset``.

    Reads the fixed 30 bytes, then the name and extra field. Name and extra lengths are
    uint16, so 65 535 is legal and they need no cap of their own; a negative offset
    and one past :data:`MAX_DATA_OFFSET` are refused, each with its own message. The
    caller decides what a disagreement with the central directory means, and words a
    negative offset in the archive's terms when it can (``ZipReader._local_data_region``
    names the bytes the whole archive seems to be missing). ``zip64_sizes`` is
    :func:`local_header_from`'s.
    """
    if header_offset < 0:
        raise CorruptionError(
            f"The local header would start {-header_offset} bytes before the start "
            "of the file"
        )
    if header_offset > MAX_DATA_OFFSET:
        raise CorruptionError(f"Absurd local-header offset: {header_offset}")
    fixed = read_at(header_offset, LOCAL_HEADER_SIZE)
    if len(fixed) == LOCAL_HEADER_SIZE and fixed[:4] != LOCAL_HEADER_SIGNATURE:
        raise CorruptionError("Bad magic number for file header")
    if len(fixed) != LOCAL_HEADER_SIZE:
        if fixed and not LOCAL_HEADER_SIGNATURE.startswith(fixed[:4]):
            raise CorruptionError("Bad magic number for file header")
        raise TruncatedError("Truncated local file header")
    variable_len = local_header_variable_length(fixed)
    variable = read_at(header_offset + LOCAL_HEADER_SIZE, variable_len)
    if len(variable) != variable_len:
        raise TruncatedError("Truncated local file header")
    data_start = header_offset + LOCAL_HEADER_SIZE + variable_len
    if data_start > MAX_DATA_OFFSET:
        raise CorruptionError(f"Absurd local-header data offset: {data_start}")
    return local_header_from(fixed, variable, data_start, zip64_sizes=zip64_sizes)


def local_header_variable_length(fixed: bytes) -> int:
    """How many name and extra-field bytes follow the fixed local header ``fixed``."""
    name_len, extra_len = struct.unpack_from("<HH", fixed, LOCAL_HEADER_SIZE - 4)
    return name_len + extra_len


def local_stored_sizes(fixed: bytes) -> tuple[int, int]:
    """The compressed and uncompressed sizes the fixed local header ``fixed`` stores in
    its 32-bit fields, before any ZIP64 extra field replaces them."""
    fields = _LOCAL_HEADER.unpack(fixed)
    return fields[8], fields[9]


def local_header_from(
    fixed: bytes, variable: bytes, data_start: int, *, zip64_sizes: bool = False
) -> LocalHeader:
    """The :class:`LocalHeader` for the fixed 30 bytes and the name and extra field.

    Both walks read the bytes their own way and call this. The sizes are the stored
    32-bit fields unless ``zip64_sizes``, which applies a ZIP64 extra field's sizes
    (:func:`_local_sizes`): the forward walk has no central entry to take them from.
    """
    (
        _sig,
        needed_version,
        needed_system,
        flags,
        method,
        dos_time,
        dos_date,
        crc,
        compressed_size,
        file_size,
        name_len,
        _extra_len,
    ) = _LOCAL_HEADER.unpack(fixed)
    extra = variable[name_len:]
    if zip64_sizes:
        compressed_size, file_size = _local_sizes(extra, compressed_size, file_size)
    return LocalHeader(
        version_needed=(needed_system << 8) | needed_version,
        flags=flags,
        method=method,
        dos_time=dos_time,
        dos_date=dos_date,
        crc=crc,
        compressed_size=compressed_size,
        file_size=file_size,
        name=variable[:name_len],
        extra=extra,
        data_start=data_start,
    )


def _local_sizes(extra: bytes, compressed_size: int, file_size: int) -> tuple[int, int]:
    """The two sizes after a local ZIP64 extra field replaces the deferred ones; a
    deferred size no field holds stays all ones (see :func:`local_zip64_sizes`)."""
    compressed, size = local_zip64_sizes(extra, compressed_size, file_size)
    return (
        _U32_MAX if compressed is None else compressed,
        _U32_MAX if size is None else size,
    )


def local_zip64_sizes(
    extra: bytes, compressed_size: int, file_size: int
) -> tuple[int | None, int | None]:
    """The two sizes after a local ZIP64 extra field replaces the deferred ones.

    In a local header the field holds both sizes, uncompressed first, whichever is
    deferred (APPNOTE 4.5.3). A field shorter than that holds the deferred ones in the
    central directory's order. A deferred size no field holds is ``None``: a field can
    hold all ones as a real size, so the value alone does not tell.
    """
    compressed: int | None = compressed_size
    size: int | None = file_size
    if compressed_size != _U32_MAX and file_size != _U32_MAX:
        return compressed, size
    if compressed_size == _U32_MAX:
        compressed = None
    if file_size == _U32_MAX:
        size = None
    for field in iter_extra_fields(extra):
        if field.tag != _ZIP64_EXTRA_TAG:
            continue
        data = field.data
        if len(data) >= 16:
            if file_size == _U32_MAX:
                size = int.from_bytes(data[:8], "little")
            if compressed_size == _U32_MAX:
                compressed = int.from_bytes(data[8:16], "little")
        else:
            cursor = 0
            if file_size == _U32_MAX and len(data) >= 8:
                size = int.from_bytes(data[:8], "little")
                cursor = 8
            if compressed_size == _U32_MAX and len(data) >= cursor + 8:
                compressed = int.from_bytes(data[cursor : cursor + 8], "little")
        break
    return compressed, size
