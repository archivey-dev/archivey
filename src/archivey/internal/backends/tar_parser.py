"""Native TAR header parser and header walker (structure only: no member mapping).

Reads TAR headers one at a time from a byte stream and returns small data objects;
``tar_reader.py`` maps them to members. Its tests compare it with ``tarfile`` and GNU
tar.

On-disk layout this parser assumes::

    [ 512-byte header ]  v7, POSIX ustar ("ustar\\0" "00") or old GNU ("ustar  \\0")
    [ data, padded to 512 ]          only for types that carry data
    ...
    [ zero block ] [ zero block ]    the end-of-archive marker

    Extended headers come before the member they describe, in any order:
      x / X   PAX records for the next member      g  PAX records for every later member
      L       GNU long name                        K  GNU long link name
    Each is a header block plus its data, which holds the records or the name.

Every header encoding ``tarfile`` reads is read here: base-256 numbers, the ustar
``prefix``, PAX records (per-member and global) and the four GNU sparse encodings (old
GNU ``S`` with extension blocks, PAX 0.0, 0.1 and 1.0).

The walk is a loop, not a recursion, and allocates nothing whose size comes from a
header field before the caller's budget allows it: an extended header is charged
before it is read, and a sparse map is charged by its entry count before its entries
are parsed. Strings stay ``bytes``; decoding happens in the reader, where the caller's
``encoding=`` is known.

Where GNU tar 1.35 and ``tarfile`` read a malformed archive differently, this parser
follows GNU tar, the format's official tool (design rule DR-6), unless a comment says
otherwise.
"""

from __future__ import annotations

import errno
import re
import struct
import zlib
from array import array
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import BinaryIO, cast

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.streams.decompressor_stream import _COMPRESSED_READ_SIZE_MAX
from archivey.internal.streams.streamtools import read_within_reach
from archivey.internal.streams.streamtools.base import ReadOnlyIOStream
from archivey.terminal import quoted

BLOCKSIZE = 512

# A size or offset past this is no file's size: seeking there fails (OverflowError,
# EINVAL) on every stream archivey reads from.
MAX_OFFSET = 2**63 - 1

# What a sparse map entry is charged against ``max_metadata_bytes``, which counts
# header text, not allocator bytes: 24 is the width of an entry in its fixed-width
# encoding (two 12-byte numbers in an old GNU header), whatever encoding the map came
# in. The archive-reading spec sets this weight. A SparseMap holds 16 bytes per entry.
SPARSE_ENTRY_BYTES = 24

# The most significant digits a PAX number may have: 20, the width of the largest
# ``uintmax_t``. GNU tar reads PAX numbers with ``strtoumax``, so a longer one is out of
# range, and it reads each number of a sparse 1.0 map into a buffer of this size. Two
# reasons make it structural, not a policy limit. ``int()`` refuses more than
# ``sys.int_max_str_digits`` (4300 by default) with a builtin ``ValueError``, so every
# PAX number is measured before it is converted (``_pax_decimal``, ``_map_number``).
# And the streaming 1.0 map reader would otherwise grow one buffer for as long as the
# archive lasts on a number with no newline after it.
PAX_NUMBER_DIGITS = 20

# The largest PAX ``uid`` or ``gid`` read: ``uid_t`` and ``gid_t`` are 32-bit unsigned
# on every platform GNU tar ships on, and GNU tar 1.35 reports a larger id ("out of
# range 0..4294967295") and keeps the header's.
MAX_PAX_ID = 2**32 - 1

# The read step for what the walk reads and a header sizes: an extended header, the
# data area a forward-only walk skips (``_discard``), and a link's declared data span
# it scans for zeros (``_read_zeros``). A declared size is attacker-chosen, so it is
# never one read. The skip stays at this step: on a compressed source it is bound by
# the decoder (1 MiB measured no faster listing a compressed tar of 1 MiB members), on
# an uncompressed one buffered reads are cheap, and a smaller step over-reads less at
# the end of a short archive.
READ_STEP = 64 * 1024
# The read step for member data a consumer reads through the walk (``_ForwardSlice``)
# from a stream of unknown length: still a bound on the allocation a declared size can
# cause, at 1 MiB. It matches the piece the member verifier's sized drain reads
# (``verify._SIZED_DRAIN_CHUNK``, which is this constant too), so one such piece is one
# read here; at 64 KiB it was sixteen reads and a join. A caller's larger read is still
# split.
DATA_READ_STEP = _COMPRESSED_READ_SIZE_MAX

POSIX_MAGIC = b"ustar\x00"
GNU_MAGIC = b"ustar  \x00"

# Typeflags.
SPARSE_TYPE = b"S"
LINK_TYPES = frozenset((b"1", b"2"))
PAX_MEMBER_TYPES = frozenset((b"x", b"X"))  # ``X`` is Solaris's spelling of ``x``
PAX_GLOBAL_TYPE = b"g"
LONG_NAME_TYPE = b"L"
LONG_LINK_TYPE = b"K"
EXTENDED_TYPES = PAX_MEMBER_TYPES | {PAX_GLOBAL_TYPE, LONG_NAME_TYPE, LONG_LINK_TYPE}
# Types whose size field does not announce a data area. ``tarfile`` skips no data
# after these; GNU tar skips none after a directory and fails on the others with
# "Skipping to next header". Data declared on one of them is read as the next header,
# as both tools read it. The size field of every other typeflag announces a data area,
# whatever either tool makes of the type: the regular types, ``D``, ``M``, ``V``, and
# typeflags the reader does not know (``tar_reader._KNOWN_TYPES``) all have their data
# skipped by size.
NO_DATA_TYPES = frozenset((b"1", b"2", b"3", b"4", b"5", b"6"))
# A link (``1`` or ``2``) with a size is the exception, ruled by the maintainer over GNU
# tar's reading (2026-10-17): when the block after its header is not a member header,
# the declared blocks are read as the link's data and skipped, so a zero block among
# them does not end the walk (TarWalker._place_link_data). All of this is about the
# header's own size field: a PAX size, which GNU tar 1.35 skips, gives these typeflags a
# data area (LinkData.FRAMED for a link, tar_reader._directory_has_data for ``5``; a
# device or FIFO with one is refused by the reader).

# The regular-file typeflags whose entry is a directory when its final name ends in
# "/": AREGTYPE (NUL), REGTYPE (``0``) and CONTTYPE (``7``), the three GNU tar's
# extract.c sends to ``extract_dir`` on a trailing slash. Old GNU sparse ``S`` is not
# among them: GNU tar extracts it as a file whatever its name.
_OLD_STYLE_DIRECTORY_TYPES = frozenset((b"\x00", b"0", b"7"))


class HeaderFormat(Enum):
    """Which header layout a block uses, from its magic field."""

    V7 = "v7"
    USTAR = "ustar"
    GNU = "gnu"


class NameSource(Enum):
    """Which record a member's name or link name came from."""

    HEADER = "header"  # the ustar/v7/GNU header block (with the ustar prefix)
    GNU_LONG = "gnu_long"  # a GNU ``L`` or ``K`` header
    PAX = "pax"  # a PAX ``path``/``linkpath`` or ``GNU.sparse.name`` record


class SparseFormat(Enum):
    OLD_GNU = "old_gnu"
    PAX_0_0 = "0.0"
    PAX_0_1 = "0.1"
    PAX_1_0 = "1.0"


# --------------------------------------------------------------------------- blocks


# Not frozen, as no caller writes to it: a frozen init costs a microsecond per header
# on the listing's hot path.
@dataclass(slots=True)
class HeaderBlock:
    """One decoded 512-byte header block. Strings are the stored bytes, cut at the
    first NUL; ``name`` already has the ustar ``prefix`` joined to it."""

    offset: int
    format: HeaderFormat
    name: bytes
    mode: int
    uid: int
    gid: int
    size: int
    # ``None`` when the field holds no octal digit (only NULs and blanks): no time is
    # recorded, and reading it as 1970 would be a guess (DR-1).
    mtime: int | None
    typeflag: bytes
    linkname: bytes
    uname: bytes
    gname: bytes
    # ``None`` unless the header is a ustar or GNU device (typeflag 3 or 4): no
    # other header holds a device number (see ``_DEVICE_NUMBER_TYPES``). Both are
    # also ``None`` when such a device's field is not a number, and
    # ``device_number_fault`` then says which.
    devmajor: int | None
    devminor: int | None
    # Old GNU ``S`` only: the four in-header map slots, whether extension blocks
    # follow, and the logical size.
    sparse_slots: tuple[tuple[int, int], ...] = ()
    sparse_extended: bool = False
    sparse_realsize: int = 0
    device_number_fault: str | None = None


@dataclass(frozen=True, slots=True)
class ZeroBlock:
    """A block of 512 NUL bytes: the first block of an end-of-archive marker."""

    offset: int


@dataclass(frozen=True, slots=True)
class RejectedBlock:
    """A full block that is not a valid header. ``reason`` names what failed."""

    offset: int
    reason: str


class _BadNumber(ValueError):
    pass


def _cut_nul(field: bytes) -> bytes:
    end = field.find(b"\x00")
    return field if end < 0 else field[:end]


# C ``isspace`` in the C locale, which is what GNU tar skips and stops at.
_BLANKS = rb" \t\n\v\f\r"
# An octal header field after its optional leading NUL: blanks, digits, then a NUL, a
# blank or the end of the field. The bytes after that terminator are not read.
_OCTAL_FIELD = re.compile(
    rb"[" + _BLANKS + rb"]*([0-7]*)(?:[\x00" + _BLANKS + rb"]|\Z)"
)
_HIGH_BYTES = bytes(range(0x80, 0x100))
_ZERO_BLOCK = bytes(BLOCKSIZE)


def parse_number(field: bytes) -> int:
    """A numeric header field: octal or GNU base-256.

    Octal is read the way GNU tar 1.35 reads it (``from_header``): one leading NUL is
    skipped (an old writer of unknown vintage put one there when the previous field
    overflowed), then leading blanks, then octal digits up to the first byte that is
    not one. That byte must be a NUL or a blank, or the end of the field; whatever
    follows it is ignored, as GNU tar ignores it (``tarfile`` too, after a NUL). A
    field with no digits is 0, as ``tarfile`` reads it (GNU tar reports a field of
    only blanks and reads it as -1). Base-256 is flagged by the first byte: ``0x80`` positive,
    ``0xFF`` negative (two's complement over the field).

    Every field, the checksum included, is read this way: GNU tar reads the checksum
    with the same function, and the checksum itself is what guards the header.

    The base-256 form is ``tarfile``'s: a field starting with any other byte that has
    the high bit set, ``0x81`` for one, is :class:`_BadNumber` here. GNU tar 1.35 flags
    base-256 by ``0x80`` and ``0xFF`` alone too, so any other high-bit byte is not a
    number to it either: it reports "where numeric ... value expected" and skips the
    header for a ``size``, or lists -1 for an id or a time (measured 2026-10-30).
    Refusing the header here keeps one answer for every field. No real archive loses
    anything by it: such a field would hold a value of at least 2**56 in magnitude.
    """
    if not field:
        return 0
    first = field[0]
    if first == 0x80 or first == 0xFF:
        value = int.from_bytes(field[1:], "big")
        if first == 0xFF:
            value -= 1 << (8 * (len(field) - 1))
        return value
    # The leading NUL is skipped whenever it is there (``where += !*where``), never
    # matched as the terminator of an empty number: "\0junk" is not a number.
    match = _OCTAL_FIELD.match(field, 1 if first == 0 else 0)
    if match is None:
        raise _BadNumber(field)
    digits = match.group(1)
    return int(digits, 8) if digits else 0


# Adler-32's low 16 bits are 1 plus the byte sum modulo 65521. A piece of 256 bytes
# sums to at most 255 * 256 = 65280, below the modulus, so each piece's value is the
# exact sum. It saves about 1 µs per header over ``sum()`` on CPython 3.11 and 3.12;
# re-check with benchmarks/tar_listing_baseline.py before keeping or dropping it.
_SUM_PIECE = 256


def _byte_sum(data: bytes) -> int:
    """``sum(data)``, computed in C."""
    total = 0
    for start in range(0, len(data), _SUM_PIECE):
        total += (zlib.adler32(data[start : start + _SUM_PIECE]) & 0xFFFF) - 1
    return total


def _checksum_matches(block: bytes, stored: int) -> bool:
    """Whether ``stored`` is the unsigned or the signed sum of ``block`` with its
    checksum field as spaces.

    Old Sun and other writers summed signed bytes; GNU tar and ``tarfile`` accept
    either sum.
    """
    unsigned = _byte_sum(block) - sum(block[148:156]) + 8 * 0x20
    if stored == unsigned:
        return True
    rest = block[:148] + block[156:]
    high = len(rest) - len(rest.translate(None, _HIGH_BYTES))
    return stored == unsigned - 256 * high


_FIELDS = (
    ("mode", 100, 108),
    ("uid", 108, 116),
    ("gid", 116, 124),
    ("size", 124, 136),
    ("mtime", 136, 148),
)
# The ``mtime`` field. Its bytes are checked again when it reads as 0: with no octal
# digit in it, only NULs and blanks, ``HeaderBlock.mtime`` is ``None``.
_MTIME_FIELD = slice(*_FIELDS[-1][1:])
_NO_DIGIT = b"\x00" + _BLANKS
# The five numeric fields in _FIELDS order, as raw bytes, in one C call. A test checks
# that it cuts the same bytes as _FIELDS. The device numbers are not among them: they
# are read only for a device (``_DEVICE_NUMBER_TYPES``).
_split_numbers = struct.Struct("100x8s8s8s12s12s364x").unpack
# Most numeric fields repeat across an archive (mode, ids, the device numbers, often
# the times), so a cache hit replaces the strip/translate/int. Bounded, so a hostile
# archive of distinct values costs a cache miss per field and no more memory. Measured
# per header against a plain dict lookup: the same within noise.
_cached_number = lru_cache(maxsize=4096)(parse_number)


def _field_named(block: bytes) -> str:
    """The name of the first numeric field of ``block`` that is not a number, for the
    rejection message; only called once the parse has failed."""
    for field, start, end in _FIELDS:
        try:
            parse_number(block[start:end])
        except _BadNumber:
            return field
    raise AssertionError("no field failed")  # pragma: no cover


# The typeflags whose devmajor and devminor fields GNU tar reads: character and block
# devices, in a ustar or GNU header. For any other header (a FIFO included) GNU tar
# never parses the two fields, so bytes there that are not a number are no damage.
# On a device, a field that is not a number does not reject the header either: GNU tar
# 1.35 reports it, lists the device with a garbage number and reads on. The header
# leaves both numbers out and names the fault, for the reader to report on the member.
_DEVICE_NUMBER_TYPES = (b"3", b"4")


def parse_header_block(
    block: bytes, offset: int
) -> HeaderBlock | ZeroBlock | RejectedBlock:
    """Decode one full 512-byte block.

    No exception for an outcome the walk expects: a zero block ends the walk and a
    rejected block is classified by the caller, which knows whether it came first.
    """
    assert len(block) == BLOCKSIZE
    if block == _ZERO_BLOCK:
        return ZeroBlock(offset)
    try:
        stored_sum = parse_number(block[148:156])
    except _BadNumber:
        return RejectedBlock(offset, "the checksum field is not a number")
    if not _checksum_matches(block, stored_sum):
        return RejectedBlock(offset, "bad header checksum")
    try:
        mode, uid, gid, size, mtime = map(_cached_number, _split_numbers(block))
    except _BadNumber:
        return RejectedBlock(offset, f"the {_field_named(block)} field is not a number")
    if not mtime and not block[_MTIME_FIELD].strip(_NO_DIGIT):
        mtime = None
    if size < 0:
        return RejectedBlock(offset, f"negative size {size}")
    if size > MAX_OFFSET:
        return RejectedBlock(offset, f"size {size} is past any file's size")
    typeflag = block[156:157]
    magic = block[257:265]
    name = _cut_nul(block[0:100])
    devmajor: int | None = None
    devminor: int | None = None
    device_number_fault: str | None = None
    sparse_slots: tuple[tuple[int, int], ...] = ()
    sparse_extended = False
    sparse_realsize = 0
    if magic == GNU_MAGIC:
        header_format = HeaderFormat.GNU
    elif magic[:6] == POSIX_MAGIC:
        header_format = HeaderFormat.USTAR
    else:
        header_format = HeaderFormat.V7
    if header_format is HeaderFormat.V7:
        # A v7 header ends at byte 257: uname, gname and the device numbers are
        # ustar fields, and GNU tar reads none of them from a v7 header.
        uname = gname = b""
    else:
        uname = _cut_nul(block[265:297])
        gname = _cut_nul(block[297:329])
        if typeflag in _DEVICE_NUMBER_TYPES:
            numbers: list[int] = []
            for field, start in (("devmajor", 329), ("devminor", 337)):
                try:
                    numbers.append(_cached_number(block[start : start + 8]))
                except _BadNumber:
                    device_number_fault = (
                        f"the {field} field {shown_value(block[start : start + 8])} "
                        "is not a number"
                    )
                    break
            else:
                devmajor, devminor = numbers
    if typeflag == SPARSE_TYPE and header_format is HeaderFormat.GNU:
        # The old GNU sparse slots, which only an old GNU header holds. GNU tar 1.35
        # reads an "S" under ustar or v7 magic as a regular file: in a ustar header
        # bytes 345.. are the name prefix. (tarfile reads the slots whatever the
        # magic says.)
        try:
            sparse_slots = _sparse_slots(block, 386, 4)
            sparse_realsize = parse_number(block[483:495])
        except _BadNumber:
            return RejectedBlock(
                offset,
                "an old GNU sparse field is not a number or past any file's size",
            )
        if not 0 <= sparse_realsize <= MAX_OFFSET:
            # GNU tar 1.35: "Archive value -1 is out of off_t range". Listed, it
            # would be the member's size; a negative one with an empty map read
            # as an empty file.
            return RejectedBlock(
                offset,
                f"old GNU sparse real size {sparse_realsize} is negative or past "
                "any file's size",
            )
        sparse_extended = block[482] != 0
    elif header_format is HeaderFormat.USTAR:
        # GNU tar joins the prefix for any "ustar\0" magic, whatever the version
        # bytes, and never for old GNU or v7 headers, whose bytes 345.. hold other
        # fields or nothing. (tarfile joins it for every header but GNU types.)
        prefix = _cut_nul(block[345:500])
        if prefix:
            name = prefix + b"/" + name
    return HeaderBlock(
        offset=offset,
        format=header_format,
        name=name,
        typeflag=typeflag,
        linkname=_cut_nul(block[157:257]),
        uname=uname,
        gname=gname,
        devmajor=devmajor,
        devminor=devminor,
        device_number_fault=device_number_fault,
        sparse_slots=sparse_slots,
        sparse_extended=sparse_extended,
        sparse_realsize=sparse_realsize,
        mode=mode,
        uid=uid,
        gid=gid,
        size=size,
        mtime=mtime,
    )


def starts_with_header(prefix: bytes) -> bool:
    """Whether ``prefix`` opens with a TAR header block the walk would accept.

    Detection's check for a TAR without magic: a v7 header, or one an old writer filled
    in without ``ustar``. The block must parse as :func:`parse_header_block` parses it,
    so its checksum matches the block's byte sum (the field itself counted as eight
    spaces) and every numeric field is a number. Its name must also be non-empty. A zero block is not a header: an empty TAR has no header to
    check.

    Text and binary data pass only when built to. It is the test ``tarfile.is_tarfile``
    and Commons Compress make, and GNU tar's own reading of the first block.
    """
    if len(prefix) < BLOCKSIZE:
        return False
    header = parse_header_block(prefix[:BLOCKSIZE], 0)
    return isinstance(header, HeaderBlock) and bool(header.name)


def _sparse_slots(block: bytes, start: int, count: int) -> tuple[tuple[int, int], ...]:
    """Old GNU map slots: ``count`` (offset, numbytes) pairs of 12-byte numbers.

    The list ends at the first slot whose numbytes field is empty, as GNU tar reads
    it (``oldgnu_add_sparse``); a real final entry ``(realsize, 0)`` is stored as
    digits, so it is kept.
    """
    slots = []
    for i in range(count):
        pos = start + 24 * i
        if block[pos + 12] == 0:
            break
        offset = parse_number(block[pos : pos + 12])
        length = parse_number(block[pos + 12 : pos + 24])
        # A base-256 field reaches 2**95 either side of zero. A negative entry that
        # fits is kept, for validate_sparse_map to name with its offset.
        if not all(-MAX_OFFSET - 1 <= n <= MAX_OFFSET for n in (offset, length)):
            raise _BadNumber(block[pos : pos + 24])
        slots.append((offset, length))
    return tuple(slots)


# ------------------------------------------------------------------------ PAX records


_PAX_LENGTH = re.compile(rb"([0-9]{1,20}) ")
# The keywords an empty value sets to empty, as GNU tar 1.35's decoders store any
# string. Another keyword's empty value leaves the value in force before it.
_EMPTY_VALUE_STORED = frozenset((b"linkpath", b"uname", b"gname"))
# The skipped empty values EMPTY_VALUE reports: a name, or a number GNU tar 1.35 calls
# invalid. Any other keyword is left out: GNU tar writes an empty
# SCHILY.xattr.<name> for an empty extended attribute (tar --xattrs), and a comment or
# vendor record names and frames nothing.
_EMPTY_VALUE_REPORTED = frozenset(
    (b"path", b"mtime", b"atime", b"ctime", b"uid", b"gid")
)
# The keywords whose value is a C string to GNU tar 1.35, cut at its first NUL as an
# ``L`` or ``K`` payload and a header field are. The cut comes before the empty-value
# rule, so a ``path`` that is empty after it is skipped and the value in force stays.
_C_STRING_KEYS = frozenset(
    (b"path", b"GNU.sparse.name", b"linkpath", b"uname", b"gname")
)


@dataclass(frozen=True, slots=True)
class PaxValue:
    """One PAX record's value, with whether its block declared ``hdrcharset=BINARY``
    (then a name value has no declared encoding; otherwise it is UTF-8)."""

    value: bytes
    binary: bool


@dataclass(slots=True)
class PaxRecords:
    """One PAX block's records.

    ``values`` holds the last value of each key, or the first with ``first_wins``
    (:func:`parse_pax_records`). ``sparse_offsets`` and
    ``sparse_numbytes`` hold the ``GNU.sparse.offset`` and ``GNU.sparse.numbytes``
    values in order: a PAX sparse 0.0 map is the only record order that matters.
    """

    values: dict[bytes, PaxValue]
    sparse_offsets: list[bytes]
    sparse_numbytes: list[bytes]
    # Keys set more than once in the block, apart from the sparse 0.0 map's, each
    # once (a dict, so a block of one key repeated holds one entry).
    repeated: dict[bytes, None]
    # Keys of _C_STRING_KEYS whose value held a NUL and was cut there, each once.
    nul_cut: dict[bytes, None]
    # Keys of _EMPTY_VALUE_REPORTED whose empty value was skipped and is the
    # block's last record of that key, each once.
    emptied: dict[bytes, None]


# The PAX sparse 0.0 map repeats these two keys by design.
_SPARSE_MAP_KEYS = frozenset((b"GNU.sparse.offset", b"GNU.sparse.numbytes"))
# The PAX numbers LEADING_ZERO reports: the ones that frame a member or give its listed
# size. A sparse map's offsets and lengths are left out: the walk checks that the
# chunks sum to the stored size, so a map read as octal cannot frame anything, and no
# case of tar-minefield (whose F26 is about size) covers them.
_LEADING_ZERO_KEYS = (b"size", b"GNU.sparse.size", b"GNU.sparse.realsize")
# Keys that name or frame one member, which a global header applies to every member.
_MEMBER_KEYS = (b"path", b"linkpath", b"size")


class Ambiguity(Enum):
    """Header shapes no known writer produces, on which readers disagree. The walk
    reads each as GNU tar 1.35 does; the reader reports it (``MEMBER_HEADER_AMBIGUOUS``).
    """

    # A GNU long name (or link name) read for a member whose name (or link target)
    # came from a PAX record after all: its own or a global path, its GNU.sparse.name,
    # or a linkpath. GNU tar uses the PAX record, tarfile the one that comes first.
    BOTH_FAMILIES = "both_families"
    # One field set twice for one member: two L or two K headers, a PAX key twice in
    # one block, or two x headers (field b"x"; GNU tar drops all but the last, tarfile
    # merges them). GNU tar keeps the last (the first in a global header), tarfile the
    # first L.
    REPEATED = "repeated"
    # A global header carrying path, linkpath or size: every later member gets it.
    GLOBAL_MEMBER_FIELD = "global_member_field"
    # A PAX string value holding a NUL byte: GNU tar cuts it there, tarfile does not.
    NUL_IN_VALUE = "nul_in_value"
    # A global header that drops a key an earlier global header set (one per key):
    # GNU tar replaces the global records, tarfile and POSIX merge them.
    GLOBAL_REPLACED = "global_replaced"
    # GNU long headers (L or K) and an x header in one member's chain, in either
    # order, when no PAX record overrode the long name (that is BOTH_FAMILIES). To a
    # reader that knows only PAX, an L header is a member of an unknown type, so the
    # x header's records (a size among them) apply to it, not to the member.
    MIXED_CHAIN = "mixed_chain"
    # A global header between an x or L header and the member it extends. GNU tar
    # applies the x or L header to the member; a reader can apply it to the global
    # header instead, and the member keeps its header's name.
    GLOBAL_IN_CHAIN = "global_in_chain"
    # An x header's last record of path or a number (_EMPTY_VALUE_REPORTED) with an
    # empty value, which is skipped: POSIX has it delete a field, and readers disagree
    # on which. GNU tar keeps the value in force before it (and reports an empty
    # number as invalid).
    EMPTY_VALUE = "empty_value"
    # A PAX size or sparse size (_LEADING_ZERO_KEYS) with a leading zero, such as 0777:
    # 777 to GNU tar and POSIX, 511 to a reader that takes it as octal, as the
    # header's numbers are.
    LEADING_ZERO = "leading_zero"


def _record_ambiguities(
    records: PaxRecords, found: list[tuple[Ambiguity, bytes]], *, is_global: bool
) -> None:
    """Add one PAX block's ambiguities to ``found``."""
    values = records.values
    found += [(Ambiguity.REPEATED, key) for key in records.repeated]
    found += [(Ambiguity.NUL_IN_VALUE, key) for key in records.nul_cut]
    if is_global:
        found += [
            (Ambiguity.GLOBAL_MEMBER_FIELD, key)
            for key in _MEMBER_KEYS
            if key in values
        ]
        return
    # In a global header an empty value is how POSIX unsets a global record, and a
    # global size is GLOBAL_MEMBER_FIELD already.
    found += [(Ambiguity.EMPTY_VALUE, key) for key in records.emptied]
    for key in _LEADING_ZERO_KEYS:
        number = values.get(key)
        if number is not None and len(number.value) > 1 and number.value[:1] == b"0":
            found.append((Ambiguity.LEADING_ZERO, key))


def parse_pax_records(
    data: bytes, *, binary_default: bool, first_wins: bool = False
) -> PaxRecords:
    """Parse ``"<length> <key>=<value>\\n"`` records.

    ``length`` is decimal and counts the whole record, itself and the newline
    included; it must land on the newline. Parsing stops at a NUL byte where a record
    would start, which is the block padding. ``hdrcharset`` in the same block applies
    to every name value in it (POSIX); ``binary_default`` is the global one in force.
    Raises :class:`CorruptionError` on a record that does not parse.

    A repeated key keeps one value, so a block of many records of one key holds no
    object per record: the last one, as GNU tar 1.35 applies a member's records in
    order, or the first with ``first_wins``, as it applies a global header's (it
    keeps them in a list it prepends to). An empty value is read as GNU tar reads it:
    ``linkpath``, ``uname`` and ``gname`` become empty, a ``GNU.sparse.*`` record is
    kept for the sparse checks to judge, an empty ``size`` is
    :class:`CorruptionError` (GNU tar reports it as "invalid size=", and the size
    frames the member), and any other keyword is left out, so the value in force
    before it stays (GNU tar skips an empty ``path`` and reports an empty number as
    invalid). The keywords in ``_C_STRING_KEYS`` are cut at their first NUL before
    that rule applies. ``hdrcharset`` is kept by the same rule as any key, and the one
    kept decides whether the block's names are binary.
    """
    raw: dict[bytes, bytes] = {}
    offsets: list[bytes] = []
    numbytes: list[bytes] = []
    repeated: dict[bytes, None] = {}
    nul_cut: dict[bytes, None] = {}
    emptied: dict[bytes, None] = {}
    seen: set[bytes] = set()
    pos = 0
    end = len(data)
    while pos < end and data[pos] != 0:
        match = _PAX_LENGTH.match(data, pos)
        if match is None:
            raise CorruptionError(
                f"TAR PAX header has a malformed record at byte {pos}"
            )
        length = int(match.group(1))
        record_end = pos + length
        # The shortest record is "5 x=\n".
        if length < 5 or record_end > end or data[record_end - 1] != 0x0A:
            raise CorruptionError(
                f"TAR PAX header has a record at byte {pos} whose length {length} "
                f"does not end on a newline"
            )
        key, equals, value = data[match.end() : record_end - 1].partition(b"=")
        if not key or not equals:
            raise CorruptionError(
                f"TAR PAX header has a record at byte {pos} with no key"
            )
        if key in _C_STRING_KEYS and 0 in value:
            value = _cut_nul(value)
            nul_cut[key] = None
        if key == b"GNU.sparse.offset":
            offsets.append(value)
        elif key == b"GNU.sparse.numbytes":
            numbytes.append(value)
        pos = record_end
        # Every record of a key after its first counts, an empty one too: one key
        # set twice in one header is REPEATED whichever value wins.
        if key in seen and key not in _SPARSE_MAP_KEYS:
            repeated[key] = None
        seen.add(key)
        if not value and key not in _EMPTY_VALUE_STORED:
            if key == b"size":
                raise CorruptionError(
                    f"TAR PAX header has an empty size record at byte "
                    f"{pos - length}: the size frames the member's data"
                )
            if not key.startswith(b"GNU.sparse."):
                if key in _EMPTY_VALUE_REPORTED:
                    emptied[key] = None
                continue
        # The sparse 0.0 map repeats its keys by design: not reported above, but the
        # value kept still follows first_wins like any other key.
        if key in raw and first_wins:
            continue
        # A value stored after an empty record of its key is the one in force, so the
        # empty record no longer kept an earlier value.
        emptied.pop(key, None)
        raw[key] = value
    # hdrcharset follows the block's own rule (last in x, first in g) like any key,
    # and an empty one is skipped like any other empty value.
    hdrcharset = raw.get(b"hdrcharset")
    binary = binary_default if hdrcharset is None else hdrcharset == b"BINARY"
    # Each value is replaced in place, so the dict is never held twice.
    values = cast("dict[bytes, PaxValue]", raw)
    for key, value in raw.items():
        values[key] = PaxValue(value, binary)
    return PaxRecords(values, offsets, numbytes, repeated, nul_cut, emptied)


_SHOWN_CHARACTERS = 40


def shown_value(value: bytes | str) -> str:
    """``value`` quoted for a message, cut to 40 characters with ``...`` inside the
    quotes when longer, so a cut value never reads as a complete one. A byte that is
    not printable ASCII shows as one backslash escape, as ``bytes`` repr writes it."""
    cut = len(value) > _SHOWN_CHARACTERS
    # repr of the cut bytes escapes each byte once; the b prefix is dropped.
    shown = (
        repr(value[:_SHOWN_CHARACTERS])[1:]
        if isinstance(value, bytes)
        else repr(value[:_SHOWN_CHARACTERS])
    )
    return shown[:-1] + "..." + shown[-1] if cut else shown


def _pax_decimal(text: bytes) -> int | None:
    """A PAX decimal number (ASCII digits only), or ``None`` when ``text`` is not one
    or has more than 20 significant digits, past any ``uintmax_t``.

    The digit count is checked before ``int()``, which refuses more than 4300 digits
    with a builtin ``ValueError`` (``sys.int_max_str_digits``). GNU tar reads the
    value with ``strtoumax``: leading zeros are allowed, and a longer number is out
    of range.
    """
    if not text.isdigit():
        return None
    significant = text.lstrip(b"0")
    if len(significant) > PAX_NUMBER_DIGITS:
        return None
    return int(significant) if significant else 0


def _pax_int(records: Mapping[bytes, PaxValue], key: bytes, name: str) -> int | None:
    """The PAX record ``key`` as a size or offset, or ``None`` when it is absent or
    empty. ``name`` is the member's, already quoted. A value that is not a number,
    or one past :data:`MAX_OFFSET`, is :class:`CorruptionError`."""
    entry = records.get(key)
    if entry is None or not entry.value:
        return None
    text = entry.value
    if not text.isdigit():
        raise CorruptionError(
            f"TAR PAX record {key.decode()} is not a number: {shown_value(text)}"
        )
    value = _pax_decimal(text)
    if value is None or value > MAX_OFFSET:
        raise CorruptionError(
            f"TAR PAX {key.decode()} {shown_value(text)} of {name} is past any "
            "file's size"
        )
    return value


def _sparse_major_1_or_more(major: PaxValue | None) -> bool:
    """Whether a ``GNU.sparse.major`` value is a number of 1 or more.

    Read from the digits, not through ``int()``: a value of thousands of digits is still
    a version of 1 or more, and ``int()`` refuses one past Python's digit limit."""
    if major is None:
        return False
    value = major.value
    return value.isdigit() and value.strip(b"0") != b""


# ------------------------------------------------------------------------ sparse maps


@dataclass(slots=True)
class SparseMap:
    """A sparse member's chunks: ``offsets[i]`` is where chunk ``i`` sits in the
    logical file, ``lengths[i]`` how many stored bytes it holds. Chunks are stored
    one after another in the data area, in this order."""

    offsets: array[int]
    lengths: array[int]

    def __len__(self) -> int:
        return len(self.offsets)

    @classmethod
    def from_pairs(cls, pairs: list[int]) -> SparseMap:
        assert len(pairs) % 2 == 0, "a sparse map is (offset, length) pairs"
        try:
            return cls(array("q", pairs[0::2]), array("q", pairs[1::2]))
        except OverflowError:
            # The parsers refuse such a number with a better message first.
            raise CorruptionError(
                "TAR sparse map has an entry past any file's size"
            ) from None


Charge = Callable[[int, str], None]
"""``charge(nbytes, what)``: count ``nbytes`` of retained header text against the
member's budget, raising :class:`ResourceLimitError` when it is spent. ``what`` names
the cost for the message."""


def _map_number(item: bytes, name: str, what: str) -> int:
    """One decimal number of a PAX sparse map. ``name`` is already quoted."""
    if not item.isdigit() or len(item) > PAX_NUMBER_DIGITS:
        raise CorruptionError(
            f"TAR sparse map of {name} ({what}) has a bad number: {shown_value(item)}"
        )
    value = int(item)
    if value > MAX_OFFSET:
        raise CorruptionError(
            f"TAR sparse map of {name} ({what}) has {value}, past any file's size"
        )
    return value


def _parse_map_numbers(text: bytes, name: str, *, what: str) -> list[int]:
    return [_map_number(item, name, what) for item in text.split(b",")]


def sparse_map_0_1(value: bytes, name: str, charge: Charge) -> SparseMap:
    """PAX sparse 0.1: ``GNU.sparse.map`` is ``offset,numbytes,offset,numbytes...``.

    The entry count is charged from the comma count before any number is parsed.
    """
    commas = value.count(b",")
    if commas % 2 == 0:
        raise CorruptionError(
            f"TAR sparse map of {name} (GNU.sparse.map) has an odd count of numbers"
        )
    charge(((commas + 1) // 2) * SPARSE_ENTRY_BYTES, "sparse map")
    return SparseMap.from_pairs(_parse_map_numbers(value, name, what="GNU.sparse.map"))


def sparse_map_0_0(
    offsets: list[bytes], lengths: list[bytes], name: str, charge: Charge
) -> SparseMap:
    """PAX sparse 0.0: the values of the repeated ``GNU.sparse.offset`` /
    ``GNU.sparse.numbytes`` records, in order. Charged from the record count before
    parsing."""
    if len(offsets) != len(lengths):
        raise CorruptionError(
            f"TAR sparse map of {name} (GNU.sparse.offset/numbytes) has "
            f"{len(offsets)} offsets and {len(lengths)} lengths"
        )
    charge(len(offsets) * SPARSE_ENTRY_BYTES, "sparse map")
    pairs: list[int] = []
    for offset, length in zip(offsets, lengths, strict=True):
        # One number per record: a comma is not a separator here.
        pairs.append(_map_number(offset, name, "GNU.sparse.offset"))
        pairs.append(_map_number(length, name, "GNU.sparse.numbytes"))
    return SparseMap.from_pairs(pairs)


def read_sparse_map_1_0(
    read: Callable[[int], bytes], stored_size: int, name: str, charge: Charge
) -> tuple[SparseMap, int]:
    """PAX sparse 1.0: the map is decimal lines at the start of the data area — the
    entry count, then an offset and a length per entry — padded to a whole block.

    ``read(n)`` reads the data area from its start. Returns the map and how many bytes
    of the data area it takes (whole blocks); the chunks start there. The count is
    charged before the entries are read.
    """
    buffer = bytearray()
    consumed = 0
    numbers: list[int] = []
    wanted: int | None = None

    def next_number() -> int:
        nonlocal consumed
        while True:
            newline = buffer.find(b"\n")
            if newline >= 0:
                item = bytes(buffer[:newline])
                del buffer[: newline + 1]
                return _map_number(item, name, "1.0")
            if len(buffer) > PAX_NUMBER_DIGITS:
                raise CorruptionError(
                    f"TAR sparse map of {name} (1.0) has a number longer than "
                    f"{PAX_NUMBER_DIGITS} digits"
                )
            if consumed + BLOCKSIZE > stored_size:
                raise CorruptionError(
                    f"TAR sparse map of {name} (1.0) runs past the member's data"
                )
            block = read(BLOCKSIZE)
            if len(block) < BLOCKSIZE:
                raise TruncatedError(
                    f"TAR archive is truncated inside the sparse map of {name}"
                )
            consumed += BLOCKSIZE
            buffer.extend(block)

    wanted = next_number()
    charge(wanted * SPARSE_ENTRY_BYTES, "sparse map")
    for _ in range(2 * wanted):
        numbers.append(next_number())
    return SparseMap.from_pairs(numbers), consumed


def validate_sparse_map(
    sparse: SparseMap, size: int, stored: int, name: str
) -> CorruptionError | UnsupportedFeatureError | None:
    """The error opening this sparse member must raise, or ``None``.

    ``size`` is the logical size, ``stored`` the bytes the data area holds for the
    chunks (the 1.0 map's own blocks excluded). ``name`` goes into the message as it
    is, so the caller passes it through ``quoted()``. Damage is
    :class:`CorruptionError`: a logical size that is negative or past
    :data:`MAX_OFFSET` (no caller passes a negative one today, since the header and
    PAX parsers refuse it; the check keeps a future caller from slipping one
    through), a negative entry, a chunk past the logical size, or chunks that do not
    add up to exactly the stored bytes (more would read the next header as data;
    fewer leaves bytes inside the member that nothing names, DR-3). A map whose
    chunks are out of order or overlap is valid data archivey will not serve:
    ``tarfile`` stitched such chunks into the wrong bytes, and serving them in
    logical order in a forward pass would buffer up to the logical size. It is
    :class:`UnsupportedFeatureError`, and only when the map has no damage. An empty
    entry is exempt from the order check: GNU tar ends a map with ``(realsize, 0)``
    when the file ends in a hole.
    """
    if not 0 <= size <= MAX_OFFSET:
        return CorruptionError(
            f"TAR sparse member {name} has a logical size of {size} bytes, "
            "negative or past any file's size"
        )
    total = 0
    previous_end = 0
    unordered: UnsupportedFeatureError | None = None
    for offset, length in zip(sparse.offsets, sparse.lengths, strict=True):
        if offset < 0 or length < 0:
            return CorruptionError(
                f"TAR sparse map of {name} has a negative entry "
                f"(offset {offset}, {length} bytes)"
            )
        if offset + length > size:
            return CorruptionError(
                f"TAR sparse map of {name} has a chunk at offset {offset} "
                f"({length} bytes) that ends past the member's size of {size} bytes"
            )
        if length:
            if offset < previous_end and unordered is None:
                unordered = UnsupportedFeatureError(
                    f"TAR sparse map of {name} is out of order or overlapping: a chunk "
                    f"at offset {offset} starts before the previous chunk ends at "
                    f"{previous_end}"
                )
            previous_end = max(previous_end, offset + length)
        total += length
    if total != stored:
        return CorruptionError(
            f"TAR sparse map of {name} accounts for {total} bytes of data, but the "
            f"member stores {stored}"
        )
    return unordered


# --------------------------------------------------------------------------- entries


@dataclass(slots=True)
class TarEntry:
    """One member, after its extended headers are applied.

    ``data_offset`` is where its stored bytes start in the stream and ``stored_size``
    how many there are (exact, before block padding). For a sparse member these are
    the chunks alone: an old GNU map's extension blocks and a PAX 1.0 map come before
    ``data_offset``. ``size`` is the logical size: the same as ``stored_size`` except
    for a sparse member.
    """

    header: HeaderBlock
    header_offset: int  # where the first header of the member's chain starts
    data_offset: int
    stored_size: int
    size: int
    name: bytes
    name_source: NameSource
    name_binary: bool  # a PAX name under hdrcharset=BINARY: no declared encoding
    linkname: bytes | None
    linkname_source: NameSource | None
    linkname_binary: bool
    uname: bytes
    uname_pax: PaxValue | None
    gname: bytes
    gname_pax: PaxValue | None
    uid: int
    gid: int
    # The PAX records in force: the global records, then the member's own on top.
    # Shared, read-only, between members that have none of their own.
    pax: Mapping[bytes, PaxValue]
    has_own_pax: bool
    # An AREGTYPE (NUL), REGTYPE (0) or CONTTYPE (7) entry whose final name ends in
    # "/": a directory, as GNU tar reads it (7-Zip agrees for NUL and 0). Its
    # declared size is a real data area (the typeflag carries data), which the
    # reader lists and reports.
    old_style_directory: bool
    # Set only for a member type that carries data: sparse records on a link,
    # device, FIFO or directory leave both None.
    sparse_format: SparseFormat | None = None
    sparse: SparseMap | None = None
    # Set only for a link whose size field or PAX size declares blocks that the walk
    # took as its data (see LinkData). ``size`` keeps the declared byte count;
    # ``stored_size`` is 0, since nothing delivers the bytes.
    link_data: LinkData | None = None
    # Header shapes no known writer produces in this member's chain, each once, with
    # the PAX key or name field involved (b"path" for an L header, b"linkpath" for K).
    ambiguities: tuple[tuple[Ambiguity, bytes], ...] = ()

    @property
    def typeflag(self) -> bytes:
        return self.header.typeflag

    def span(self) -> TarSpan:
        """The fields a reader needs after listing: where the data is and how to
        read it. Kept in place of the entry, which holds the parsed header, names
        and PAX records (~500 bytes a member) that the member no longer needs."""
        return TarSpan(
            self.header.typeflag,
            self.data_offset,
            self.stored_size,
            self.size,
            self.sparse,
        )

    @property
    def data_end(self) -> int:
        """Where the next header starts."""
        return self.data_offset + _round_up(self.stored_size)


@dataclass(slots=True)
class TarSpan:
    """A member's data area, as :meth:`TarEntry.span` keeps it after listing.

    The fields mean what they mean on :class:`TarEntry`.
    """

    typeflag: bytes
    data_offset: int
    stored_size: int
    size: int
    sparse: SparseMap | None


def _round_up(n: int) -> int:
    return (n + BLOCKSIZE - 1) // BLOCKSIZE * BLOCKSIZE


def carries_data(typeflag: bytes) -> bool:
    return typeflag not in NO_DATA_TYPES


# --------------------------------------------------------------------------- walker


class LinkData(Enum):
    """What the walk did with the blocks a link header's size declares."""

    # The block after the header is not a member header: the declared blocks were
    # skipped and the walk went on from their end. When they are all zeros and no
    # member header follows them, the walk then ends on their first block
    # (TarWalker._end_at_zero_span).
    SKIPPED = "skipped"
    # The block after the header is a zero block and every byte from there to the end
    # of the archive is zero, fewer bytes than the size declares: the zero block ends
    # the walk, as a trailer after a header whose blocks were never written.
    ENDS_ARCHIVE = "ends_archive"
    # A PAX ``size`` declared the blocks. GNU tar skips them whatever they hold, so
    # the walk did too, without looking at the block after the header.
    FRAMED = "framed"


class TarEndKind(Enum):
    """Why a walk stopped."""

    ZERO_BLOCK = "zero_block"  # the first block of an end-of-archive marker
    REJECTED = "rejected"  # a full block, or a chain of headers, that does not parse
    ABSENT = "absent"  # the stream ended exactly where a header should start
    SHORT = "short"  # the stream ended inside a header block


@dataclass(frozen=True, slots=True)
class TarEnd:
    """Why a walk stopped, and where. ``reason`` says why a header was rejected, or
    names the extended header that a zero block left with no member;
    ``observed_bytes`` is how much of a short block the stream held."""

    kind: TarEndKind
    offset: int
    reason: str = ""
    observed_bytes: int = 0


Budget = tuple[int, int] | None
"""``(bytes left, cap)`` of ``max_metadata_bytes`` for one member's headers, or
``None`` for no limit."""


class _Charger:
    __slots__ = ("_name", "_raw_name", "cap", "left")

    def __init__(self, budget: Budget) -> None:
        self.left, self.cap = budget if budget is not None else (-1, -1)
        self._name: str | None = "a TAR member"
        self._raw_name = b""

    @property
    def name(self) -> str:
        """The member's name, quoted for a message. Quoted on first use: most members
        never need it."""
        if self._name is None:
            self._name = quoted(self._raw_name.decode("utf-8", "surrogateescape"))
        return self._name

    def name_member(self, raw_name: bytes) -> None:
        self._raw_name = raw_name
        self._name = None

    def __call__(self, nbytes: int, what: str) -> None:
        if self.cap < 0:
            return
        if nbytes > self.left:
            raise ResourceLimitError(
                f"Listing limit reached: max_metadata_bytes={self.cap} ({what} of "
                f"{self.name} weighs {nbytes} bytes, {max(self.left, 0)} left)"
            )
        self.left -= nbytes


class TarWalker:
    """Walks the headers of one TAR byte stream, one member per :meth:`next_entry`.

    ``seekable`` walks skip a member's data with a seek; forward-only walks read
    through it in steps, so the cost is the bytes the archive holds, not the size a
    header declares. Both read the declared span of a link header whose first block
    is zero (:meth:`_place_link_data`), once and bounded the same way. The walker
    owns the stream position between calls: a caller that reads member data on a
    seekable stream may move it freely (each call seeks back), and on a forward-only
    stream reads through :meth:`open_data`, whose reads the walker counts.
    """

    def __init__(
        self, stream: BinaryIO, *, seekable: bool, end: int | None = None
    ) -> None:
        self._stream = stream
        self._seekable = seekable
        # Byte length of the archive when it is a fact (a plain file). A read is then
        # clamped to what the file holds, so one member is one read. Unknown (a
        # compressed stream, a test buffer) keeps the stepped read.
        self._end = end
        self._pos = 0  # where the next header starts, once the current data is skipped
        self._stream_pos = 0  # forward-only: bytes consumed from the stream so far
        self._global: dict[bytes, PaxValue] = {}
        self._global_view: Mapping[bytes, PaxValue] = _ReadOnly({})
        self._global_binary = False
        # The end of the last member's data area, while it is still to be checked
        # (see _check_data_present).
        self._unchecked_data_end: int | None = None
        self.end: TarEnd | None = None
        # Forward-only: a block read ahead and not yet used, with its offset: the block
        # after a link header with a size, which such a walk cannot read twice. A
        # seekable walk reads it again: a caller may move that stream between calls,
        # and the header loop reads an extended header's records from where the
        # stream stands after its block.
        self._held_block: tuple[int, bytes] | None = None
        # A link's skipped span that began with a zero block and held only zeros, as
        # (start, end), until the next header after it is read (_end_at_zero_span).
        self._zero_span: tuple[int, int] | None = None
        # What follows the zero block the walk ended on, when that block starts a
        # link's zero span the walk had already read past. Served by stream_after_end
        # in place of a seek back, which on a compressed source decodes the stream
        # again from its start.
        self._replay: _ReplayStream | None = None
        # The first error next_entry raised: the walk is over, and later calls
        # raise it again.
        self._failed: ArchiveyError | None = None

    # The stream ---------------------------------------------------------------

    def _seek(self, offset: int) -> None:
        if offset > MAX_OFFSET:
            raise CorruptionError(
                f"TAR archive asks for offset {offset}, past any file's size"
            )
        if self._seekable:
            try:
                self._stream.seek(offset)
            except (OverflowError, ValueError) as exc:
                raise CorruptionError(
                    f"TAR archive asks for offset {offset}, which the source cannot "
                    "seek to"
                ) from exc
            except OSError as exc:
                if exc.errno in _SEEK_RANGE_ERRNOS:
                    raise TruncatedError(
                        f"TAR archive is truncated: it ends before offset {offset}"
                    ) from exc
                raise
            self._stream_pos = offset
            return
        self._discard(offset - self._stream_pos)

    def _discard(self, count: int) -> None:
        assert count >= 0, "a forward-only walk never goes back"
        while count:
            want = min(count, READ_STEP)
            got = len(self._stream.read(want))
            self._stream_pos += got
            count -= got
            if got < want:
                raise TruncatedError(
                    f"TAR archive is truncated: a member's data runs to offset "
                    f"{self._stream_pos + count}, but the archive ends at "
                    f"{self._stream_pos}"
                )

    def _read(self, size: int, step: int = READ_STEP) -> bytes:
        end = self._end
        # ``end`` is a fact, so clamping cannot hide bytes the file really holds.
        # Without it a declared size is read in steps: one joined copy per member
        # larger than the step.
        remaining = None if end is None else max(0, end - self._stream_pos)
        data = read_within_reach(self._stream, size, remaining=remaining, step=step)
        self._stream_pos += len(data)
        return data

    def _read_block(self, offset: int) -> bytes:
        held = self._held_block
        if held is not None:
            self._held_block = None
            # Held only at _pos, the next header's offset, which is what the header
            # loop asks for next; any other offset would be a read back on a
            # forward-only stream.
            assert held[0] == offset, (held[0], offset)
            return held[1]
        self._seek(offset)
        return self._read(BLOCKSIZE)

    def _read_zeros(self, count: int) -> tuple[bool, int]:
        """Read up to ``count`` bytes from the current position, stopping after the
        first chunk with a non-zero byte or at the end of the stream. Return whether
        every byte read is zero, and how many bytes were read."""
        read = 0
        while read < count:
            chunk = self._read(min(count - read, READ_STEP))
            read += len(chunk)
            if chunk.count(0) != len(chunk):
                return False, read
            if not chunk:
                break
        return True, read

    def _check_data_present(self, end: int) -> None:
        """On a seekable stream, raise unless the byte before ``end`` exists.

        A seek past the end succeeds, so a member whose data area the archive cuts
        short would otherwise read as a clean end. ``tarfile`` makes the same check.
        """
        if not self._seekable:
            return
        self._seek(end - 1)
        if not self._read(1):
            raise TruncatedError(
                f"TAR archive is truncated: a member's data runs to offset {end}, "
                "past the end of the archive"
            )

    @property
    def position(self) -> int:
        """Where the next header starts (the end of the last member's data area)."""
        return self._pos

    def open_data(self, span: TarSpan) -> _ForwardSlice:
        """A forward-only stream over ``span``'s data area (``stored_size`` bytes),
        read through the walk's own stream. It is good while the walk stays at the
        data, that is until the next :meth:`next_entry`; its ``in_place()`` tells
        whether it still is."""
        return _ForwardSlice(self, span.data_offset, span.stored_size)

    def stream_after_end(self) -> BinaryIO:
        """The stream, positioned right after the zero block the walk ended on, for
        the caller's check of the rest of the end-of-archive marker and what follows
        it."""
        assert self.end is not None and self.end.kind is TarEndKind.ZERO_BLOCK
        if self._replay is not None:
            return cast(BinaryIO, self._replay)
        self._seek(self.end.offset + BLOCKSIZE)
        return self._stream

    # The walk -----------------------------------------------------------------

    def next_entry(self, budget: Budget = None) -> TarEntry | TarEnd:
        """Parse the next member's headers and return it, or the end of the walk.

        ``budget`` bounds this member's extended headers and sparse map together.
        Raises :class:`CorruptionError`, :class:`TruncatedError` or
        :class:`ResourceLimitError` for damage inside a member's headers; a block that
        is not a header at all ends the walk as a :class:`TarEnd` for the caller to
        classify. After an error, every later call raises the same error.
        """
        if self._failed is not None:
            raise self._failed
        if self.end is not None:
            return self.end
        try:
            return self._next_entry(budget)
        except ArchiveyError as exc:
            self._failed = exc
            raise

    def _next_entry(self, budget: Budget) -> TarEntry | TarEnd:
        charge = _Charger(budget)
        start = self._pos
        offset = start
        unchecked = self._unchecked_data_end
        self._unchecked_data_end = None
        zero_span = self._zero_span
        self._zero_span = None
        own: dict[bytes, PaxValue] = {}
        # This member's PAX sparse 0.0 map records, in order, from its last x header.
        sparse_offsets: list[bytes] = []
        sparse_numbytes: list[bytes] = []
        long_name: bytes | None = None
        long_link: bytes | None = None
        ambiguities: list[tuple[Ambiguity, bytes]] = []
        x_seen = False
        gnu_long_seen = False
        # Where the last x or L header of this member's chain starts, once there is
        # one: the chain must end in a member header. A global header describes no
        # member, so it starts no chain.
        extended_at: int | None = None
        while True:
            block = self._read_block(offset)
            if len(block) < BLOCKSIZE:
                if not block and offset == unchecked:
                    # Only an empty read leaves it open whether the last member's data
                    # area is whole. Checked only here, so a walk over a stream that a
                    # member read has moved on never seeks back.
                    self._check_data_present(offset)
                if extended_at is not None:
                    raise TruncatedError(
                        "TAR archive is truncated after the extended header at "
                        f"offset {extended_at}"
                    )
                if zero_span is not None and offset == zero_span[1]:
                    # The span's end is this call's first block (_place_link_data
                    # set _pos to it), so this asks "is this the span just read".
                    assert offset == start, (offset, start)
                    return self._end_at_zero_span(zero_span, block)
                kind = TarEndKind.SHORT if block else TarEndKind.ABSENT
                self.end = TarEnd(kind, offset, observed_bytes=len(block))
                return self.end
            parsed = parse_header_block(block, offset)
            if isinstance(parsed, ZeroBlock | RejectedBlock):
                if (
                    extended_at is None
                    and zero_span is not None
                    and offset == zero_span[1]
                ):
                    assert offset == start, (offset, start)
                    return self._end_at_zero_span(zero_span, block)
                if isinstance(parsed, ZeroBlock):
                    # GNU tar 1.35 lists an archive whose last x or L header comes
                    # right before the end marker cleanly; the reason names the
                    # unused header so the reader can report it.
                    reason = (
                        ""
                        if extended_at is None
                        else f"the extended header at offset {extended_at} "
                        "describes no member"
                    )
                    self.end = TarEnd(TarEndKind.ZERO_BLOCK, offset, reason=reason)
                elif extended_at is not None:
                    return self._reject(
                        offset,
                        f"the extended header at offset {extended_at} is followed "
                        f"by a block that is no header ({parsed.reason})",
                    )
                else:
                    self.end = TarEnd(TarEndKind.REJECTED, offset, reason=parsed.reason)
                return self.end
            if parsed.typeflag in EXTENDED_TYPES:
                header_at = offset
                if parsed.typeflag != PAX_GLOBAL_TYPE:
                    extended_at = offset
                elif extended_at is not None:
                    ambiguities.append((Ambiguity.GLOBAL_IN_CHAIN, b"g"))
                charge(parsed.size, "an extended header")
                data = self._read(parsed.size)
                if len(data) < parsed.size:
                    raise TruncatedError(
                        "TAR archive is truncated inside an extended header at "
                        f"offset {header_at}"
                    )
                offset += BLOCKSIZE + _round_up(parsed.size)
                if parsed.typeflag in (LONG_NAME_TYPE, LONG_LINK_TYPE):
                    gnu_long_seen = True
                if parsed.typeflag == LONG_NAME_TYPE:
                    if long_name is not None:
                        ambiguities.append((Ambiguity.REPEATED, b"path"))
                    long_name = _cut_nul(data)
                elif parsed.typeflag == LONG_LINK_TYPE:
                    if long_link is not None:
                        ambiguities.append((Ambiguity.REPEATED, b"linkpath"))
                    long_link = _cut_nul(data)
                else:
                    try:
                        records = parse_pax_records(
                            data,
                            binary_default=self._global_binary,
                            first_wins=parsed.typeflag == PAX_GLOBAL_TYPE,
                        )
                    except CorruptionError as exc:
                        # Records that do not parse make a header that does not parse,
                        # which the reader classifies like any rejected block.
                        return self._reject(header_at, str(exc))
                    is_global = parsed.typeflag == PAX_GLOBAL_TYPE
                    _record_ambiguities(records, ambiguities, is_global=is_global)
                    if is_global:
                        ambiguities += [
                            (Ambiguity.GLOBAL_REPLACED, key)
                            for key in self._global
                            if key not in records.values and key != b"hdrcharset"
                        ]
                        self._apply_global(records.values)
                    else:
                        # A later x header replaces an earlier one for the same
                        # member, as GNU tar 1.35 keeps only the last: merging them
                        # would let a dropped size frame the member differently.
                        if x_seen:
                            ambiguities.append((Ambiguity.REPEATED, b"x"))
                        x_seen = True
                        own = records.values
                        sparse_offsets = records.sparse_offsets
                        sparse_numbytes = records.sparse_numbytes
                continue
            try:
                entry = self._resolve(
                    parsed,
                    start,
                    offset,
                    own,
                    (sparse_offsets, sparse_numbytes),
                    long_name,
                    long_link,
                    charge,
                )
            except _RejectedHeader as exc:
                return self._reject(offset, exc.reason)
            # Asked of _resolve's answer, so only a long name a PAX record overrode
            # counts, and a field the typeflag does not use never does.
            if long_name is not None and entry.name_source is NameSource.PAX:
                ambiguities.append((Ambiguity.BOTH_FAMILIES, b"path"))
            if long_link is not None and entry.linkname_source is NameSource.PAX:
                ambiguities.append((Ambiguity.BOTH_FAMILIES, b"linkpath"))
            if (
                gnu_long_seen
                and x_seen
                and not any(a is Ambiguity.BOTH_FAMILIES for a, _ in ambiguities)
            ):
                ambiguities.append((Ambiguity.MIXED_CHAIN, b"x"))
            if ambiguities:
                entry.ambiguities = tuple(dict.fromkeys(ambiguities))
            self._pos = entry.data_end
            if entry.stored_size:
                self._unchecked_data_end = entry.data_end
                if entry.typeflag in LINK_TYPES:
                    # A PAX size framed the link's blocks: skipped, delivered by
                    # nothing (LinkData.FRAMED).
                    entry.link_data = LinkData.FRAMED
                    entry.stored_size = 0
            elif entry.size and entry.typeflag in LINK_TYPES:
                self._place_link_data(entry)
            return entry

    def _place_link_data(self, entry: TarEntry) -> None:
        """Decide where the next header starts after a link header with a size.

        The maintainer ruled (2026-10-17) that a link's declared blocks are skipped,
        so that a zero block among them is not read as the end-of-archive marker. GNU
        tar and ``tarfile`` skip nothing after a link and stop there; 7-Zip skips a
        symlink's blocks. A size alone does not prove the blocks are there, so the
        block right after the header decides, as for a ``DIRTYPE`` header:

        - A member header: the size names no data, and the walk reads that header
          next, as GNU tar, ``tarfile`` and bsdtar read it. Nothing is reported.
        - A short block or none: the walk reads it next, and the reader reports the
          missing end-of-archive marker.
        - Any other full block (data, or a zero block): the declared blocks are the
          link's data. The walk goes on from their end and ``link_data`` is
          :attr:`LinkData.SKIPPED`. Blocks the archive cuts short are truncation, as
          for a file's data.

        A span that begins with a zero block is read here (once, and no further than
        its end), because zeros there have a second reading: the trailer after a
        header whose blocks were never written. When every byte of it is zero, the
        walk keeps it, and if the walk then ends right at its end (no member header
        follows), :meth:`_end_at_zero_span` moves the end back to the span's first
        block, so the trailer checks see the zeros as the trailer. When the archive
        ends inside such a span, the zero block ends the walk at once and
        ``link_data`` is :attr:`LinkData.ENDS_ARCHIVE`.
        """
        start = entry.data_offset
        block = self._read_block(start)
        if len(block) < BLOCKSIZE or isinstance(
            parse_header_block(block, start), HeaderBlock
        ):
            if not self._seekable:
                self._held_block = (start, block)
            return
        end = start + _round_up(entry.size)
        entry.link_data = LinkData.SKIPPED
        self._pos = end
        self._unchecked_data_end = end
        if block.count(0) != BLOCKSIZE:
            return
        rest = end - start - BLOCKSIZE
        all_zero, read = self._read_zeros(rest)
        if not all_zero:
            return
        if read == rest:
            # Read whole, so the span needs no presence check: on a compressed source
            # that check is a seek back.
            self._unchecked_data_end = None
            self._zero_span = (start, end)
            return
        entry.link_data = LinkData.ENDS_ARCHIVE
        self._unchecked_data_end = None
        self.end = TarEnd(TarEndKind.ZERO_BLOCK, start)
        self._replay = self._replay_from(read, b"", start + BLOCKSIZE + read)

    def _end_at_zero_span(self, span: tuple[int, int], block: bytes) -> TarEnd:
        """End the walk on the first block of a link's zero span, when the block at
        the span's end, ``block``, is no member header.

        The span and what follows it are then the same bytes as a trailer (and
        whatever comes after one) behind a header whose blocks were never written, as
        GNU tar and ``tarfile`` read them, so the trailer checks run from the span's
        first block. The link stays reported (:attr:`LinkData.SKIPPED`).
        """
        start, end = span
        self.end = TarEnd(TarEndKind.ZERO_BLOCK, start)
        self._replay = self._replay_from(
            end - start - BLOCKSIZE, block, end + len(block)
        )
        return self.end

    def _replay_from(self, zeros: int, head: bytes, resume: int) -> _ReplayStream:
        """``zeros`` zero bytes and ``head``, the bytes the walk read up to
        ``resume``, then the stream from ``resume``. The stream is moved there only
        when the replay reaches it, with a forward seek: a seekable stream may have
        been moved since."""
        return _ReplayStream(zeros, head, self._stream, lambda: self._seek(resume))

    def _reject(self, offset: int, reason: str) -> TarEnd:
        self.end = TarEnd(TarEndKind.REJECTED, offset, reason=reason)
        return self.end

    def _apply_global(self, records: dict[bytes, PaxValue]) -> None:
        """Make a global header's records the ones in force.

        They replace the records of any earlier global header, as GNU tar 1.35 reads
        them (``xheader_decode_global`` empties its list first). POSIX and ``tarfile``
        merge them instead, and so did this walker; the two readings frame a member
        differently when an earlier global header set ``size`` and a later one does
        not, which would hide a member from one tool or the other (DR-6). Only
        ``hdrcharset`` carries over, archivey's reading rather than a measured one (a
        listing cannot show what GNU tar does with it): it says how to decode names,
        not what they are.
        """
        hdrcharset = records.get(b"hdrcharset")
        if hdrcharset is not None:
            self._global_binary = hdrcharset.value == b"BINARY"
        self._global = dict(records)
        self._global_view = _ReadOnly(self._global)

    def _resolve(
        self,
        header: HeaderBlock,
        start: int,
        offset: int,
        own: dict[bytes, PaxValue],
        own_sparse: tuple[list[bytes], list[bytes]],
        long_name: bytes | None,
        long_link: bytes | None,
        charge: _Charger,
    ) -> TarEntry:
        if own:
            merged: Mapping[bytes, PaxValue] = _ReadOnly({**self._global, **own})
        else:
            merged = self._global_view

        def pax(key: bytes) -> PaxValue | None:
            value = merged.get(key)
            # Only a GNU.sparse.* record, or a keyword an empty value clears, can
            # be empty here (parse_pax_records); for those this means "not set".
            return value if value is not None and value.value else None

        name, name_source, name_binary = header.name, NameSource.HEADER, False
        if long_name is not None:
            name, name_source = long_name, NameSource.GNU_LONG
        # PAX wins over a GNU long name, whichever came first, as GNU tar applies it.
        # GNU.sparse.name is the real name of a PAX sparse member (whose path is a
        # GNUSparseFile.N placeholder), so it wins over path.
        # Most archives have no PAX records at all; each lookup is skipped for them.
        has_pax = bool(merged)
        # parse_pax_records cut a name at its first NUL and skipped one empty after it.
        for key in (b"path", b"GNU.sparse.name") if has_pax else ():
            value = pax(key)
            if value is not None and value.value:
                name, name_source, name_binary = (
                    value.value,
                    NameSource.PAX,
                    value.binary,
                )
        charge.name_member(name)

        typeflag = header.typeflag
        linkname: bytes | None = None
        linkname_source: NameSource | None = None
        linkname_binary = False
        if typeflag in LINK_TYPES:
            linkname, linkname_source = header.linkname, NameSource.HEADER
            if long_link is not None:
                linkname, linkname_source = long_link, NameSource.GNU_LONG
            # An empty linkpath clears the target, as GNU tar 1.35 reads it.
            value = merged.get(b"linkpath") if has_pax else None
            if value is not None:
                linkname, linkname_source, linkname_binary = (
                    value.value,
                    NameSource.PAX,
                    value.binary,
                )

        stored_size = header.size
        pax_size = (
            _pax_int(merged, b"size", charge.name)
            if has_pax and pax(b"size") is not None
            else None
        )
        if pax_size is not None:
            stored_size = pax_size

        uid, gid = header.uid, header.gid
        for key in (b"uid", b"gid") if has_pax else ():
            value = pax(key)
            number = None if value is None else _pax_decimal(value.value)
            if number is None or number > MAX_PAX_ID:
                # A PAX id that is not a number, or is past uid_t's range, is
                # ignored and the header's kept, as GNU tar 1.35 keeps it. GNU tar
                # also reports such an id ("out of range", exit 2); archivey keeps
                # the header's value silently.
                pass
            elif key == b"uid":
                uid = number
            else:
                gid = number

        data_offset = offset + BLOCKSIZE
        size = stored_size
        sparse_format: SparseFormat | None = None
        sparse: SparseMap | None = None
        if typeflag == SPARSE_TYPE and header.format is HeaderFormat.GNU:
            sparse_format = SparseFormat.OLD_GNU
            sparse, data_offset = self._old_gnu_map(
                header, data_offset, charge.name, charge
            )
            size = header.sparse_realsize
        elif not carries_data(typeflag) or not has_pax:
            # Sparse records on a link, device, FIFO or directory describe no data
            # area: the member is not sparse. Without PAX records it has none.
            pass
        # GNU tar 1.35 reads any major version of 1 or more as 1.0, whatever the minor
        # (measured with 1.1, 1.5, 2.0 and 9.9) and whatever 0.x records came with it:
        # with a GNU.sparse.size it lists the realsize, and with a GNU.sparse.map it
        # warns about the excess map and still reads the 1.0 map. Only the member's
        # own records choose, as for 0.x below; the major may be a global default.
        elif (b"GNU.sparse.major" in own or b"GNU.sparse.realsize" in own) and (
            _sparse_major_1_or_more(merged.get(b"GNU.sparse.major"))
        ):
            sparse_format = SparseFormat.PAX_1_0
            realsize_record = merged.get(b"GNU.sparse.realsize")
            if realsize_record is not None and not realsize_record.value:
                # Present and empty is damage, as for the 0.x records below; GNU
                # tar 1.35 and tarfile both refuse it.
                raise CorruptionError(
                    f"TAR PAX record GNU.sparse.realsize of {charge.name} is empty"
                )
            realsize = _pax_int(merged, b"GNU.sparse.realsize", charge.name)
            # The map is the first blocks of the data area. It is read here, as
            # tarfile and GNU tar read it, so a bad map fails the listing as in the
            # other encodings and its entries count against this member's budget.
            self._seek(data_offset)
            sparse, used = read_sparse_map_1_0(
                self._read, stored_size, charge.name, charge
            )
            whole_size = stored_size
            data_offset += used
            stored_size -= used
            if realsize is None:
                # No realsize record: GNU tar 1.35 takes the stored size (the header
                # or a PAX `size` record, map blocks included) as the bound, extracts
                # up to the greatest chunk end, and calls the member malformed when a
                # chunk ends past that size. A realsize of 0 stays 0, and a chunk past
                # it fails as in GNU tar.
                size = max(
                    (
                        o + n
                        for o, n in zip(sparse.offsets, sparse.lengths, strict=True)
                    ),
                    default=0,
                )
                if size > whole_size:
                    raise CorruptionError(
                        f"TAR sparse map of {charge.name} has a chunk ending at "
                        f"{size}, past the member's stored size (header or PAX "
                        f"size) of {whole_size} bytes and with no GNU.sparse.realsize"
                    )
            else:
                size = realsize
        # The 0.x encodings are chosen by the presence of the records that define
        # their map, not by pax(), which drops an empty value: a sparse record whose
        # value is empty is damage, and reading the member as a plain file would serve
        # its compacted data as the content. Only the member's own records choose: a
        # map describes one member's data area, so a global sparse record makes no
        # member sparse, as GNU tar 1.35 reads it. The values still read the global
        # defaults.
        elif b"GNU.sparse.map" in own:
            sparse_format = SparseFormat.PAX_0_1
            sparse = sparse_map_0_1(
                merged[b"GNU.sparse.map"].value, charge.name, charge
            )
            size = _pax_int(merged, b"GNU.sparse.size", charge.name) or 0
        elif b"GNU.sparse.size" in own or own_sparse[0]:
            sparse_format = SparseFormat.PAX_0_0
            sparse = sparse_map_0_0(*own_sparse, charge.name, charge)
            size = _pax_int(merged, b"GNU.sparse.size", charge.name) or 0
        elif b"GNU.sparse.major" in own or b"GNU.sparse.realsize" in own:
            # GNU tar refuses a major of 0, an empty one, or one that is not a number
            # when no 0.x map came with it. A realsize with no major is refused too:
            # it declares a 1.0 member's logical size, and GNU tar fails on it. (A
            # minor alone is read as a plain file, as GNU tar reads it.) Read as a
            # plain file, the member would serve its map blocks as content.
            major = merged.get(b"GNU.sparse.major")
            version = "(none)" if major is None else shown_value(major.value)
            raise CorruptionError(
                f"TAR member {charge.name} has GNU sparse major version "
                f"{version} and no sparse map"
            )

        # The final name decides, after any PAX path or GNU long name: a regular-file
        # typeflag with a name ending in "/" is a pre-POSIX directory entry
        # (``_OLD_STYLE_DIRECTORY_TYPES`` says which typeflags count).
        old_style_directory = typeflag in _OLD_STYLE_DIRECTORY_TYPES and name.endswith(
            b"/"
        )
        if not carries_data(typeflag) and pax_size is None:
            # The size field of a link, device, FIFO or directory announces no data
            # area: the next header follows this one. A PAX size does: GNU tar 1.35
            # skips that many bytes after a directory, a link or a FIFO (measured
            # 2026-10-30), so a member stored in them is no member to it, and the walk
            # skips them too.
            stored_size = 0
        return TarEntry(
            header=header,
            header_offset=start,
            data_offset=data_offset,
            stored_size=stored_size,
            size=size,
            name=name,
            name_source=name_source,
            name_binary=name_binary,
            linkname=linkname,
            linkname_source=linkname_source,
            linkname_binary=linkname_binary,
            uname=header.uname,
            uname_pax=merged.get(b"uname") if has_pax else None,
            gname=header.gname,
            gname_pax=merged.get(b"gname") if has_pax else None,
            uid=uid,
            gid=gid,
            pax=merged,
            has_own_pax=bool(own),
            old_style_directory=old_style_directory,
            sparse_format=sparse_format,
            sparse=sparse,
        )

    def _old_gnu_map(
        self, header: HeaderBlock, data_offset: int, name: str, charge: _Charger
    ) -> tuple[SparseMap, int]:
        """Read an old GNU map: the header's slots, then 21-slot extension blocks
        while each says another follows. Each block is charged before it is kept."""
        pairs: list[int] = []
        charge(len(header.sparse_slots) * SPARSE_ENTRY_BYTES, "sparse map")
        for slot in header.sparse_slots:
            pairs.extend(slot)
        extended = header.sparse_extended
        while extended:
            block = self._read_block(data_offset)
            if len(block) < BLOCKSIZE:
                raise TruncatedError(
                    f"TAR archive is truncated inside the sparse map of {name}"
                )
            try:
                slots = _sparse_slots(block, 0, 21)
            except _BadNumber:
                # tarfile rejects the whole header here, and so does the walk.
                raise _RejectedHeader(
                    f"the sparse map of {name} has an extension block with a bad number"
                ) from None
            charge(len(slots) * SPARSE_ENTRY_BYTES, "sparse map")
            for slot in slots:
                pairs.extend(slot)
            extended = block[504] != 0
            data_offset += BLOCKSIZE
        return SparseMap.from_pairs(pairs), data_offset


# What a filesystem answers to a seek past the offsets it supports (ext4 for a
# base-256 size of 2**62): the archive is shorter than that offset, as GNU tar reports.
_SEEK_RANGE_ERRNOS = frozenset((errno.EINVAL, errno.EOVERFLOW))


class _ReplayStream:
    """``zeros`` zero bytes, then ``head``, then the rest of ``stream``: a walk's
    view of bytes it had read past, as stream_after_end serves them. The zeros are
    made as they are read, so a long span costs no memory."""

    def __init__(
        self,
        zeros: int,
        head: bytes,
        stream: BinaryIO,
        position: Callable[[], None],
    ) -> None:
        self._zeros = zeros
        self._head = head
        self._stream = stream
        # Puts the stream where the replayed bytes end, once, before its first read.
        self._position: Callable[[], None] | None = position

    def read(self, size: int = -1, /) -> bytes:
        if size < 0:
            raise ValueError("a replayed TAR tail is read in sized steps")
        # Filled across the parts, so a short read means the end, as on the stream.
        n = min(size, self._zeros)
        self._zeros -= n
        out = bytes(n)
        if len(out) < size and self._head:
            take = size - len(out)
            out += self._head[:take]
            self._head = self._head[take:]
        if len(out) < size:
            if self._position is not None:
                self._position()
                self._position = None
            out += self._stream.read(size - len(out))
        return out


class _RejectedHeader(Exception):
    """A member's headers do not parse: the walk ends as at a rejected block."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _ReadOnly(dict[bytes, PaxValue]):
    """The PAX records in force for a member, shared by members with none of their
    own. A plain ``dict`` on purpose: one is built per member with its own records,
    and a ``MappingProxyType`` would add a layer to every lookup. The ``Mapping``
    annotation on :attr:`TarEntry.pax` is what keeps callers from writing to it;
    the walker never writes to one once it is made."""

    __slots__ = ()


class _ForwardSlice(ReadOnlyIOStream):
    """Forward-only reads of one member's data area, counted by its walker."""

    def __init__(self, walker: TarWalker, start: int, length: int) -> None:
        super().__init__()
        self._walker = walker
        self._start = start
        self._length = length
        self._done = 0

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._done

    def in_place(self) -> bool:
        """Whether the walk is still where this stream reads next."""
        return self._walker._stream_pos == self._start + self._done

    def read(self, size: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed TAR member stream")
        walker = self._walker
        if not self.in_place():
            raise ValueError(
                "TAR member data is no longer readable: the walk has moved on"
            )
        left = self._length - self._done
        whole = size is None or size < 0
        want = left if whole else min(size, left)
        data = walker._read(want, DATA_READ_STEP)
        self._done += len(data)
        if whole and data and len(data) < want:
            # A read with no size asks for the whole member, so the error at the cut
            # belongs in this call and the bytes before it are not returned. The next
            # read raises a decoder's deferred error, or gets no bytes.
            self._done += len(walker._read(want - len(data), DATA_READ_STEP))
            data = b""
        if data and len(data) < want:
            # A short read is the end (ADR 0014). The bytes go to the caller now, and
            # the next read, which gets none, raises.
            return data
        if len(data) < want:
            error = TruncatedError(
                "TAR archive is truncated inside a member's data at offset "
                f"{walker._stream_pos}"
            )
            # The archive ends inside this member, so the walk ends here too, and
            # its next call raises this same error rather than a second report of
            # the same cut.
            walker._failed = error
            raise error
        return data
