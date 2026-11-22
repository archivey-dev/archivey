"""ISO 9660 backend on the v2 ABC: plain ISO 9660, Joliet, Rock Ridge and UDF, no optional package.

Image layout::

    Sector 16+ : volume descriptors (PVD at 16 * 2048 = 32768 bytes)
    Directory records form the tree; file data at extent * block_size

Namespaces — auto-select richest available (Rock Ridge > UDF > Joliet > plain) and
record the choice in ``ArchiveInfo.extra["iso.namespace"]``:

- Rock Ridge — POSIX mode/uid/gid and symlinks
- UDF — long Unicode names, permissions, owner, symlinks; read by ``udf.py``, which
  also reads a UDF-only image, one with no ISO 9660 descriptor
- Joliet / plain — those fields are ``None``; plain names are upper-case 8.3 with a
  ``;version`` suffix, and Joliet names often carry one too; both drop it

How a listing is built:

1. ``IsoReader.__init__`` parses the ISO 9660 and Joliet trees with
   ``iso9660.IsoVolume``, and the UDF tree with ``udf.UdfVolume`` when the image has
   one, both under one :class:`_ParseBudget`. It then picks the namespace. A UDF-only
   image has no ISO 9660 trees; when UDF is listed, steps 2 and 3 are
   ``udf.UdfVolume.walk`` and :meth:`IsoReader._make_udf_member`.
2. :meth:`IsoReader._walk_entries` walks that namespace's tree entry by entry and
   renders each entry's path. :meth:`IsoReader._entry_name` gives each entry's name.
   Rock Ridge takes the ``NM`` name, else the ISO 9660 identifier. Joliet takes its
   UTF-16 identifier. Plain ISO 9660 takes its identifier. A Rock Ridge or plain name
   is bytes in no declared charset: it decodes as UTF-8, else with ``encoding=``. A
   Rock Ridge name that neither decodes takes the name of the same file in the Joliet
   tree, when the two line up. Any other name keeps its bytes as
   ``surrogateescape``.
3. :meth:`IsoReader._make_member` turns each entry into an ``ArchiveMember``: mode,
   owner and times come from the Rock Ridge ``PX`` and ``TF`` entries when present, the
   modification time from the directory record's date otherwise.
4. :meth:`IsoReader._report_files_in_other_trees` reports each file held only by a
   tree archivey did not list (Joliet, plain ISO 9660 or UDF).

The directory tree lives in the header region → ``INDEXED`` listing and ``DIRECT``
random access. A non-seekable source is rejected (trailing metadata; no streaming).
Write is out of scope (``UnsupportedFeatureError``). Offsets are absolute, so the
image must start at ``tell() == 0`` — ``open_archive`` wraps mid-positioned streams
(stream-position contract). A compressed ``.iso.xz`` is a single-file compressor
wrapping the image, not mounted here.
"""

from __future__ import annotations

import io
import re
import stat
import struct
import zlib
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    Literal,
    TypeVar,
    cast,
)

from archivey.internal.overrides import override

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

from archivey.config import ListingLimits
from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    MemberHeaderRecordContext,
    MemberTimestampContext,
    NameEncodingContext,
    ReaderDisagreementContext,
    UnreadSessionContext,
    raw_name_to_base64,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    IndexedFormatHandler,
    IndexedReader,
    Magic,
    MemberData,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
)
from archivey.internal.backends.cd_sectors import (
    PROBE_SIZE,
    RAW_SECTOR_SYNC,
    USER_DATA_SIZE,
    CookedSource,
    RawSectorLayout,
    cooked_source,
    raw_sector_layout,
)
from archivey.internal.backends.cd_sessions import last_session_source
from archivey.internal.backends.cue_sheet import (
    DiscSource,
    disc_source,
    parse_cue,
    read_cue_text,
)
from archivey.internal.backends.iso9660 import (
    JOLIET_TREE,
    PRIMARY_TREE,
    IsoEntry,
    IsoVolume,
    RawDate,
    RockRidge,
    Zisofs,
    date_fields,
    date_is_invalid,
    date_value,
    iter_tree,
)
from archivey.internal.backends.udf import (
    Span,
    UdfEntry,
    UdfName,
    UdfVolume,
    ZeroRun,
    has_volume_recognition,
    udf_timestamp,
)
from archivey.internal.base_reader import special_file_has_data_report
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.listing_limits import (
    check_metadata_budget,
    metadata_limit_error,
    str_retained_bytes,
)
from archivey.internal.streams.codecs.isolated import (
    IN_PROCESS,
    Natives,
    natives_for,
)
from archivey.internal.streams.decompressor_stream import release_decoder
from archivey.internal.streams.streamtools import (
    resolve_seek,
)
from archivey.internal.timestamps import TimestampIssue
from archivey.internal.trailing_scan import MAX_TRAILING_SCAN, first_nonzero_offset
from archivey.internal.unix_mode import special_file_type
from archivey.internal.volumes import JoinedViews
from archivey.terminal import quoted
from archivey.types import (
    EXTRA_SPECIAL_FILE_TYPE,
    ArchiveFormat,
    ArchiveInfoExtra,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    MemberExtra,
    MemberType,
    SpecialFileType,
)


class _ParseBudget:
    """What the image's trees hold as they are parsed, weighed against ``ListingLimits``.

    ``iso9660.IsoVolume`` and ``udf.UdfVolume`` parse every tree of the image at open,
    before archivey lists anything, and report here as they go, so an over-limit image
    is refused early instead of after the whole tree is built.

    Members are counted per tree, because a listing shows one tree (Rock Ridge or plain
    ISO 9660 from the primary descriptor, Joliet from its supplementary one, or UDF),
    and an image with several has each file once per tree: one count for the whole
    image would halve the member cap of such an image. Within a tree the count is a
    superset of the listing: every record but ``.`` and ``..`` counts as a member,
    including the extra records of a multi-extent file and the ``rr_moved``
    scaffolding the listing hides.

    Bytes are one sum for the whole image, every tree together, held to
    ``max_metadata_bytes`` (ruled by davi, 2026-10-10; ``dev-docs/formats/iso.md``
    records the reasons and what would reopen it): every tree parsed is kept, so a
    budget per tree let one image retain it once per tree. For the ISO 9660 and
    Joliet trees the bytes are the directory records as stored, System Use areas
    included, plus each Rock Ridge continuation area every time it is read. That is
    more than the text a listing keeps.

    For the UDF tree, every File Identifier but the parent entry and deleted entries
    counts as a member, and each directory's data as stored, each File Entry's fixed
    part, extended attributes and allocation descriptors as the entry declares them
    (or the bytes its tag's CRC covers, when more), and each Indirect Entry's tag and
    CRC-covered bytes add to the image's bytes, a directory weighed before it is read.
    Each ICB is parsed and weighed once, however many names lead to it.

    Every full path of the UDF tree is weighed too, as the walk builds it, in a sum
    of its own held to ``max_metadata_bytes`` (:meth:`add_udf_path`).
    """

    def __init__(self, limits: ListingLimits) -> None:
        self._limits = limits
        # Members per tree: ``iso9660.PRIMARY_TREE``, ``JOLIET_TREE`` or ``_UDF_TREE``.
        self._members: dict[int, int] = {}
        # Bytes of every tree together: one image-wide budget (see above).
        self._bytes = 0
        # The full paths of the UDF tree, weighed apart from the bytes above.
        self._udf_path_bytes = 0

    def add_iso_bytes(self, nbytes: int) -> None:
        self._add_bytes(nbytes, f"its {_ISO_TREE_NAME}")

    def add_iso_member(self, tree: int) -> None:
        self._add_member(tree)

    def add_udf_bytes(self, nbytes: int) -> None:
        self._add_bytes(nbytes, f"its {_UDF_TREE_NAME}")

    def add_udf_member(self) -> None:
        self._add_member(_UDF_TREE)

    def add_udf_path(self, path: str, raw_path: bytes) -> None:
        """Weigh one full UDF path, text and stored bytes together, as the walk
        builds it, as the XAR reader weighs its paths.

        A sum of its own, held to ``max_metadata_bytes``: it bounds the paths
        ``UdfVolume.names`` keeps. The text is weighed by the listing's rule for a
        member's name (``str_retained_bytes``), and the stored bytes as the listing
        weighs a raw name. A listed member's name is this path normalized: a
        directory's gains a trailing ``/``, which this does not weigh, and a ``.`` or
        empty segment is dropped. So the listing of an ordinary tree weighs at least
        as much, and only a tree whose names normalization shortens can be refused
        here although its listing would fit. The walk weighs each path just after it
        builds it, so a chain of nested directories, whose paths grow with the square
        of its depth, is refused once they pass the cap."""
        self._udf_path_bytes += str_retained_bytes(path) + len(raw_path)
        max_meta = self._limits.max_metadata_bytes
        if max_meta is not None and self._udf_path_bytes > max_meta:
            raise metadata_limit_error(
                max_meta,
                f"its {_UDF_TREE_NAME} holds at least {self._udf_path_bytes} bytes "
                f"of paths before the members are made, at {quoted(path[:200])}",
            )

    def _add_member(self, tree: int) -> None:
        count = self._members.get(tree, 0) + 1
        self._members[tree] = count
        max_members = self._limits.max_members
        if max_members is not None and count > max_members:
            name = _UDF_TREE_NAME if tree == _UDF_TREE else _ISO_TREE_NAME
            raise ResourceLimitError(
                f"Listing limit reached: max_members={max_members} "
                f"({name} holds more than {max_members} records)"
            )

    def _add_bytes(self, nbytes: int, source: str) -> None:
        """Add ``nbytes`` to the image-wide sum; ``source`` says where they came from."""
        self._bytes += nbytes
        check_metadata_budget(
            self._limits,
            self._bytes,
            detail=(
                f"ISO image has {self._bytes} bytes of parsed directory metadata; "
                f"the last came from {source}"
            ),
        )


# How many files only another tree holds are reported per tree
# (``IsoReader._report_files_in_other_trees``).
_OTHER_TREE_REPORTS = 16
# What ``IsoReader._report_unlisted`` decodes a reported file's name from: a directory
# entry, or a UDF name already decoded.
_NameSource = TypeVar("_NameSource")


# The key the UDF tree is counted under in ``_ParseBudget``, beside the ISO 9660 trees'
# ``PRIMARY_TREE`` and ``JOLIET_TREE``.
_UDF_TREE = -1
# How a refusal names the tree a member or the last bytes came from: an ISO 9660 or
# Joliet tree, or the UDF tree.
_ISO_TREE_NAME = "ISO directory tree"
_UDF_TREE_NAME = "UDF directory tree"


# MBR and GPT count in 512-byte sectors, whatever the ISO's logical block size. A GPT
# lists 128 entries of 128 bytes in the usual layout; UEFI allows any entry size of 128
# times a power of two. A header whose entry array is larger than 512 KiB is not taken,
# so the array read at open is at most that, on top of the trailing scan's 1 MiB.
_PARTITION_SECTOR = 512
_MIN_GPT_ENTRY_SIZE = 128
_MAX_GPT_ARRAY = 512 * 1024
_MIN_GPT_HEADER_SIZE = 92
# An MBR entry of this type says "a GPT describes this disk" and spans the whole
# medium, often as 0xFFFFFFFF sectors; it lists no partition of its own.
_MBR_PROTECTIVE = 0xEE


def _image_end(fp: BinaryIO, *, volume_end: int, image_length: int) -> int:
    """Where an ISO image ends: its volume space or its furthest listed partition.

    A hybrid image (``xorriso -append_partition``, isohybrid) is a disk image as well
    as an ISO: its MBR, and often a GPT, sit in the system area and list partitions
    that can lie past the ISO 9660 volume space, such as an EFI system partition, with
    the GPT's backup header at the very end. Those bytes are the disk's, not
    something appended to it, so the end is the furthest of the volume space, every
    MBR partition, every GPT partition, and the GPT backup header. A GPT counts only
    when its header CRC and its entry-array CRC both match, so a damaged GPT, or
    ``EFI PART`` alone, widens nothing. An MBR has no checksum: its non-empty,
    non-protective entries are taken as written (``0x55AA`` present), as a crafted
    volume space would be. The result can pass the image's length; the caller compares
    it with ``image_length``. ``fp``'s position is not kept.
    """
    end = volume_end
    fp.seek(0)
    head = fp.read(2 * _PARTITION_SECTOR)
    if len(head) >= _PARTITION_SECTOR and head[510:512] == b"\x55\xaa":
        for slot in range(4):
            entry = head[446 + 16 * slot : 446 + 16 * (slot + 1)]
            if entry[4] in (0, _MBR_PROTECTIVE):
                continue
            first, count = struct.unpack_from("<II", entry, 8)
            end = max(end, (first + count) * _PARTITION_SECTOR)
    return max(end, _gpt_end(fp, head[_PARTITION_SECTOR:], image_length=image_length))


def _gpt_end(fp: BinaryIO, gpt: bytes, *, image_length: int) -> int:
    """The end of the furthest GPT partition or backup header; 0 when none is valid."""
    if len(gpt) < _MIN_GPT_HEADER_SIZE or gpt[:8] != b"EFI PART":
        return 0
    header_size, header_crc = struct.unpack_from("<II", gpt, 12)
    if not _MIN_GPT_HEADER_SIZE <= header_size <= len(gpt):
        return 0
    header = bytearray(gpt[:header_size])
    header[16:20] = bytes(4)
    if zlib.crc32(header) != header_crc:
        return 0
    (backup_lba,) = struct.unpack_from("<Q", gpt, 32)
    (entries_lba,) = struct.unpack_from("<Q", gpt, 72)
    entry_count, entry_size, entries_crc = struct.unpack_from("<III", gpt, 80)
    multiple, remainder = divmod(entry_size, _MIN_GPT_ENTRY_SIZE)
    if not (
        multiple > 0
        and remainder == 0
        and multiple & (multiple - 1) == 0  # 128 times a power of two
        and entry_count * entry_size <= _MAX_GPT_ARRAY
        and entries_lba * _PARTITION_SECTOR < image_length
    ):
        return 0
    fp.seek(entries_lba * _PARTITION_SECTOR)
    table = fp.read(entry_count * entry_size)
    if len(table) != entry_count * entry_size or zlib.crc32(table) != entries_crc:
        return 0
    end = (backup_lba + 1) * _PARTITION_SECTOR
    for at in range(0, len(table), entry_size):
        if table[at : at + 16] == bytes(16):
            continue  # unused entry
        _first, last = struct.unpack_from("<QQ", table, at + 32)
        end = max(end, (last + 1) * _PARTITION_SECTOR)
    return end


# Directory extents closer than this are hinted as one span. A clustering threshold:
# small enough that a span is mostly directories, large enough that a mastering tool's
# padding or a few small files between directories do not split it. A span is capped
# at the planner's maximum fetch whatever its length. The gaps are a guess, unlike the
# directories, so the threshold is also capped at ``ArchiveyConfig.max_read_through``:
# a span reads through no gap that ordinary reads would not, and ``0`` hints nothing.
_DIRECTORY_CLUSTER_GAP = 1024 * 1024


# ECMA-119: the volume descriptors start at block 16 and are one 2048-byte sector each,
# whatever the logical block size.
_DESCRIPTOR_SECTOR = 2048
_FIRST_DESCRIPTOR = 16 * _DESCRIPTOR_SECTOR
# How many descriptors are searched for the primary one on an image that has a UDF
# recognition sequence: at most 384 bytes read. Real images put it first, or after one
# boot record.
_MAX_DESCRIPTORS_SEARCHED = 64
# The first bytes of a primary volume descriptor: type 1, standard identifier
# ``CD001``, version 1.
_PVD_PREFIX = b"\x01CD001\x01"


def _has_primary_descriptor(read_at: Callable[[int, int], bytes]) -> bool:
    """Whether the volume descriptor set holds a primary volume descriptor.

    A UDF recognition descriptor (``BEA01``, ``NSR02``, ``TEA01``) does not end the
    search, since a bridge image may in principle put one first.
    """
    for index in range(_MAX_DESCRIPTORS_SEARCHED):
        head = read_at(_FIRST_DESCRIPTOR + index * _DESCRIPTOR_SECTOR, 6)
        if head[1:6] == b"CD001":
            if head[0] == 1:
                return True
            if head[0] == 255:
                return False
        elif head[1:6] not in (b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2"):
            return False
    return False


# Trailing ";1"/";42" version suffix on an ISO 9660 or Joliet file identifier. ``\Z``,
# not ``$``: ``$`` also matches before a final newline, which would drop it from the name.
_VERSION_SUFFIX = re.compile(r";([0-9]+)\Z")

# How many records under a Rock Ridge directory are searched for a file that also sits
# in the Joliet tree, to find that directory's Joliet counterpart. Bounds the cost of a
# crafted image full of directories whose names are not UTF-8.
_JOLIET_SEARCH_RECORDS = 64


def _strip_version(name: str, *, listed: bool) -> tuple[str, int | None]:
    """``name`` without its ``;N`` version, and ``N`` (``None`` without one).

    With ``listed`` (a name a member is listed under: a plain ISO 9660 identifier, or a
    Joliet one in the Joliet namespace), an empty extension's ``.`` goes too
    (``FOO.;1`` is ``FOO``), and a stem with nothing but dots in it (``;1``, ``.;1``,
    ``...;1``) is a name, not a version: it comes back unchanged with ``None``, since
    stripping it would make up an empty, ``.`` or ``..`` name the image does not store.
    Without it (a Joliet name compared with another tree), the suffix always goes and
    its version is reported, so ``;1`` becomes ``""`` with version 1. Neither such
    caller lets that empty name reach a member: ``_joliet_name`` drops it in
    ``_ascii_runs_match``, and ``_joliet_text`` only feeds extent matching.
    """
    match = _VERSION_SUFFIX.search(name)
    if match is None:
        return name, None
    stem = name[: match.start()]
    if listed:
        if not stem.strip("."):
            return name, None
        stem = stem.removesuffix(".")
    return stem, int(match.group(1))


def _iso_ident_name(entry: IsoEntry) -> bytes:
    """An entry's ISO 9660 identifier, version and empty-extension dot removed."""
    # Latin-1 maps each byte to one character, and none of 0x80-0xff is a digit.
    ident = entry.ident.decode("latin-1")
    return _strip_version(ident, listed=True)[0].encode("latin-1")


def _nm_name(entry: IsoEntry) -> bytes | None:
    """The name an entry's Rock Ridge ``NM`` entries spell, or ``None`` when it has no
    ``NM`` entries or they spell no name.

    An ``NM`` that spells nothing names nothing: joined into a path, an empty
    component would list the entry's children one directory up. The ISO 9660
    identifier stands in, as the Linux kernel's isofs falls back to it. RRIP gives an
    empty ``NM`` only to ``.`` and ``..`` (the CURRENT and PARENT flags), which the
    walk never lists, so on a listed entry it is a writer's error.
    """
    rr = entry.rr
    return None if rr is None else rr.name or None


def _rr_key(entry: IsoEntry) -> bytes:
    """The name a Rock Ridge entry lists under, as bytes: its ``NM`` name, else its
    ISO 9660 identifier."""
    nm = _nm_name(entry)
    return nm if nm is not None else _iso_ident_name(entry)


def _sorted_children(directory: IsoEntry) -> list[IsoEntry]:
    """A directory's entries in identifier order.

    ECMA-119 9.3 has a writer record a directory's entries sorted by identifier, and
    every writer seen does. Sorting here lists an image that does not in the same
    order. The sort is stable, so entries that share an identifier keep their on-disc
    order, which decides which of them is current.
    """
    children = directory.children or []
    return sorted(children, key=_ident_of)


def _ident_of(entry: IsoEntry) -> bytes:
    return entry.ident


def _byte_ascii_runs(raw: bytes) -> tuple[str, ...]:
    """The ASCII text of a byte name, split where non-ASCII bytes are."""
    return tuple(run.decode("ascii") for run in re.split(rb"[\x80-\xff]+", raw))


def _decode_joliet(ident: bytes) -> str:
    """A Joliet identifier as text; never raises.

    The identifier is UTF-16BE code units, and NTFS lets a name hold a surrogate
    without its partner, so the decode uses ``surrogatepass``: the unit stays in the
    name, as the 7z reader keeps it, and extraction decides what reaches disk. A valid
    pair still decodes as one character. An odd trailing byte is not a unit and
    becomes U+FFFD.
    """
    cut = len(ident) - len(ident) % 2
    name = ident[:cut].decode("utf-16_be", errors="surrogatepass")
    return name + "\ufffd" if cut < len(ident) else name


def _text_ascii_runs(name: str) -> tuple[str, ...]:
    """The ASCII text of a decoded name, split where non-ASCII characters are."""
    return tuple(re.split(r"[^\x00-\x7f]+", name))


def _ascii_runs_match(raw: bytes, name: str) -> bool:
    """Whether a byte name and a decoded name have the same ASCII text between the rest.

    A Rock Ridge name in a single-byte legacy encoding and the Joliet name of the same
    file differ only where the legacy bytes are: ``caf\\xe9.txt`` and ``café.txt`` both
    read ``caf``, something, ``.txt``. A Joliet name cut at 64 characters, or the name of
    some other file, does not line up.
    """
    return _byte_ascii_runs(raw) == _text_ascii_runs(name)


# zisofs: the 16-byte header at the start of a compressed file's data, then one
# little-endian 32-bit pointer per block plus one, each an offset from the start of the
# data. Block ``i`` is the zlib stream between pointers ``i`` and ``i + 1``; two equal
# pointers stand for a block of zeros. (Linux ``fs/isofs/compress.c``, ``mkzftree``.)
_ZISOFS_MAGIC = b"\x37\xe4\x53\x96\xc9\xdb\xd6\x07"
_ZISOFS_HEADER_SIZE = 16
# The block sizes the format allows: 32, 64 and 128 KiB. One block is held at a time.
_ZISOFS_LOG2_BLOCK_SIZES = range(15, 18)


def _zisofs_refusal(entry: Zisofs) -> str | None:
    """Why a zisofs entry describes data this reader does not decode, or ``None``."""
    if entry.uncompressed_size is None:
        return f"a zisofs {entry.tag.decode('ascii')} entry too short to parse"
    if entry.tag != b"ZF":
        return f"zisofs2 under the {entry.tag.decode('ascii')} tag"
    if entry.version != 1:
        return f"zisofs version {entry.version} (only version 1 is read)"
    if entry.algorithm != b"pz":
        return f"zisofs algorithm {entry.algorithm!r} (only 'pz', zlib, is read)"
    if entry.header_size != _ZISOFS_HEADER_SIZE:
        return f"a zisofs header of {entry.header_size} bytes"
    if entry.log2_block_size not in _ZISOFS_LOG2_BLOCK_SIZES:
        return f"a zisofs block size of 2**{entry.log2_block_size} bytes"
    return None


class _ZisofsStream(io.RawIOBase):
    """Seekable decoded view of one zisofs-compressed file.

    ``inner`` is the file's data as stored. Each read inflates the block it lands in,
    capped one byte past the block size, so a crafted block that inflates further is
    detected as corruption rather than cut to fit. The zlib stream must also end,
    checksum included, exactly at the next pointer, and a span longer than any deflated
    block of the block size is refused before it is read.
    """

    def __init__(
        self,
        inner: BinaryIO,
        entry: Zisofs,
        stored_size: int | None,
        natives: Natives = IN_PROCESS,
    ) -> None:
        super().__init__()
        self._inner = inner
        self._natives = natives
        self._stored_size = stored_size
        header = inner.read(_ZISOFS_HEADER_SIZE)
        if len(header) < _ZISOFS_HEADER_SIZE:
            raise TruncatedError("zisofs header is cut short")
        if header[:8] != _ZISOFS_MAGIC:
            raise CorruptionError("zisofs file does not start with the zisofs magic")
        size = int.from_bytes(header[8:12], "little")
        if (
            size != entry.uncompressed_size
            or header[12] * 4 != entry.header_size
            or header[13] != entry.log2_block_size
        ):
            raise CorruptionError(
                "zisofs header disagrees with the Rock Ridge ZF entry"
            )
        self._size = size
        self._log2 = entry.log2_block_size
        self._block_size = 1 << self._log2
        # zlib's ``compressBound``: no block of this size deflates to more, so a
        # longer span is corruption and is never read into memory.
        n = self._block_size
        self._max_packed = n + (n >> 12) + (n >> 14) + (n >> 25) + 13
        self._position = 0
        self._cached_index = -1
        self._cached = b""

    @override
    def readable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True

    @override
    def tell(self) -> int:
        return self._position

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        # A relative seek to before the start clamps to 0, as io.BytesIO and the other
        # member streams do. ArchiveStream.seek rejects a negative SEEK_SET and a bad
        # whence before they reach here.
        self._position = resolve_seek(
            offset, whence, pos=self._position, end=lambda: self._size
        )
        return self._position

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        # Views released on return: see try_readinto. Full-count (ADR 0014): archivey
        # takes a short read from its own stream as the member's end, so a read goes
        # on past a block's end until the buffer is full or the file ends.
        with memoryview(b) as outer, outer.cast("B") as view:
            filled = 0
            while filled < len(view) and self._position < self._size:
                index = self._position >> self._log2
                block = self._block(index)
                start = self._position - (index << self._log2)
                count = min(len(view) - filled, len(block) - start)
                # _block returns exactly the block's bytes (it raises otherwise) and
                # start is inside it, so each turn copies at least one byte. A short
                # count here would end the member early (ADR 0014).
                assert count > 0, (count, start, len(block))
                view[filled : filled + count] = block[start : start + count]
                self._position += count
                filled += count
            return filled

    def _block(self, index: int) -> bytes:
        if index == self._cached_index:
            return self._cached
        expected = min(self._block_size, self._size - (index << self._log2))
        self._inner.seek(_ZISOFS_HEADER_SIZE + 4 * index)
        pointers = self._inner.read(8)
        if len(pointers) < 8:
            raise TruncatedError(f"zisofs block pointer {index} is cut short")
        start = int.from_bytes(pointers[:4], "little")
        end = int.from_bytes(pointers[4:], "little")
        if (
            end < start
            or end - start > self._max_packed
            or (self._stored_size is not None and end > self._stored_size)
        ):
            raise CorruptionError(
                f"zisofs block {index} spans {start}..{end} in {self._stored_size} "
                "stored bytes"
            )
        if start == end:
            data = bytes(expected)
        else:
            self._inner.seek(start)
            packed = self._inner.read(end - start)
            if len(packed) < end - start:
                raise TruncatedError(f"zisofs block {index} is cut short")
            # One byte past the block size, so a block that inflates further is seen
            # rather than cut to fit.
            decompressor = self._natives.zlib_decompressobj()
            try:
                data = decompressor.decompress(packed, expected + 1)
                ended = decompressor.eof and not decompressor.unused_data
            except zlib.error as exc:
                raise CorruptionError(f"zisofs block {index}: {exc}") from exc
            finally:
                release_decoder(decompressor)
            if len(data) != expected:
                raise CorruptionError(
                    f"zisofs block {index} holds {len(data)} bytes, not {expected}"
                )
            # The stream has to end, checksum included, where the pointers say: a
            # block cut before its Adler-32 or followed by other bytes is not verified.
            if not ended:
                raise CorruptionError(
                    f"zisofs block {index} does not end where its pointers say"
                )
        self._cached_index, self._cached = index, data
        return data

    @override
    def close(self) -> None:
        if not self.closed:
            # ``getattr``: ``IOBase.__del__`` closes an instance whose ``__init__``
            # raised, possibly before ``_inner`` was set.
            inner = getattr(self, "_inner", None)
            try:
                if inner is not None:
                    inner.close()
            finally:
                self._cached = b""
                super().close()


class IsoReader(IndexedReader["IsoEntry | UdfEntry"]):
    """Reads an ISO 9660 image: Rock Ridge, UDF, Joliet or plain ISO 9660.

    Written against ``archivey.formats`` (``IsoHandler``): the adapter holds the handle
    lock around every call into it and around the streams it returns, and checks each
    member's size. Every read goes through the source (``read_at`` or a view), so it
    is bounded by the image and takes the source's lock.
    """

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._context = context
        self._source = source
        self._archive_name = context.archive_name
        self._format = ArchiveFormat.ISO
        encoding = context.encoding
        config = context.config
        self._encoding = encoding
        # The Joliet tree's files by extent, and by extent and the ASCII runs of their
        # name, built the first time a Rock Ridge name is not UTF-8 and ``encoding=``
        # does not decode it; and the entries whose name was taken from their Joliet
        # counterpart, by ``id()``, to report on the member. The keys are entries of
        # ``self._volume``, which the reader holds for its whole life.
        self._joliet_files: dict[int, list[IsoEntry]] | None = None
        self._joliet_files_by_runs: dict[
            tuple[int, tuple[str, ...]], list[IsoEntry]
        ] = {}
        self._joliet_named: dict[int, IsoEntry] = {}
        # Each Rock Ridge directory's children by stored name, by ``id()`` of the
        # directory, built the first time a link target is followed through it, so
        # following many targets through one wide directory stays linear.
        self._rock_ridge_children: dict[int, dict[bytes, IsoEntry]] = {}
        # The primary tree's first directory at each extent, for Rock Ridge ``CL``
        # relocation; built on the first ``CL`` entry met (``_relocation_index``).
        self._entry_at_extent: dict[int, IsoEntry] | None = None
        # The directories, by ``id()``, whose ``..`` carries ``PL`` but that no ``CL``
        # the listing reaches points at, so they list where they are stored; built on
        # the first ``PL`` entry met (``_unrelinked``).
        self._orphans: set[int] | None = None
        # The reader's own view of the source, for the trailing-data scan; closed by
        # ``_release_archive_handles``.
        self._iso_fp = source.view(0)
        # The ISO 9660 and Joliet trees (``iso9660.py``); ``None`` for a UDF-only image.
        self._volume: IsoVolume | None = None
        # The UDF tree (``udf.py``), when the image has one that parses.
        self._udf: UdfVolume | None = None
        try:
            limits = config.listing_limits
            budget = (
                None
                if limits.max_members is None and limits.max_metadata_bytes is None
                else _ParseBudget(limits)
            )
            self._image_length = self._iso_fp.seek(0, 2)
            udf_present = has_volume_recognition(source.read_at)
            # A UDF-only image (no primary volume descriptor) has no ISO 9660 tree;
            # every other image is parsed as ISO 9660, so a cut or damaged ISO 9660
            # image is refused there whether or not it also has UDF.
            if not udf_present or _has_primary_descriptor(source.read_at):
                self._volume = self._open_volume(source, budget)
                self._report_directory_padding(self._volume.padding)
            if udf_present:
                self._udf = self._open_udf(budget, required=self._volume is None)

            # The namespace, once for the image: Rock Ridge > UDF > Joliet > plain
            # ISO 9660 (davi, 2026-11-18).
            volume = self._volume
            if volume is not None and volume.rock_ridge:
                self._namespace = "rock_ridge"
            elif self._udf is not None:
                self._namespace = "udf"
            elif volume is not None and volume.joliet is not None:
                self._namespace = "joliet"
            else:
                self._namespace = "iso9660"
            self._report_trailing_data()
        except BaseException:
            # No reader is returned for anyone to close, so release the view now. The
            # source is ``open_archive``'s to close on this path.
            self._release_archive_handles()
            raise

    def _open_volume(
        self, source: ReaderSource, budget: _ParseBudget | None
    ) -> IsoVolume:
        """Parse the image's ISO 9660 and Joliet trees."""
        # A raw sector image's offsets are not the file's, so it is not hinted.
        gap = min(_DIRECTORY_CLUSTER_GAP, self._context.config.max_read_through)
        will_read = None if isinstance(source, CookedSource) else source._will_read
        describe_cut: Callable[[int], str] | None = None
        if isinstance(source, CookedSource):
            raw_size = source.raw_size
            image_length = self._image_length

            def describe_cut(declared: int) -> str:
                # The image is the raw file's user data: name the raw sectors too.
                sectors = -(-declared // USER_DATA_SIZE)
                return (
                    f"it declares {sectors} sectors and the {raw_size}-byte raw "
                    f"sector image holds {image_length // USER_DATA_SIZE} whole ones"
                )

        return IsoVolume(
            source.read_at,
            self._image_length,
            archive_name=self._archive_name,
            budget=budget,
            hint=None if will_read is None or gap == 0 else (will_read, gap),
            describe_cut=describe_cut,
        )

    def _open_udf(
        self, budget: _ParseBudget | None, *, required: bool
    ) -> UdfVolume | None:
        """Parse the image's UDF tree. A tree that uses a partition type archivey
        does not read (sparable or virtual) is ``None`` when the image has an ISO 9660
        tree to list instead, and refused when it has not. A damaged UDF tree is
        refused either way."""
        try:
            return UdfVolume(
                self._source.read_at,
                self._image_length,
                archive_name=self._archive_name,
                budget=budget,
            )
        except UnsupportedFeatureError:
            if required:
                raise
            return None

    def _report_directory_padding(self, offsets: list[int]) -> None:
        """Report each directory block whose padding is not all zeros (DR-3).

        ``ARCHIVE_TRAILING_DATA`` with ``expected_marker="directory_padding"``: a
        warning by default, refused under ``DiagnosticPolicy.STRICT``. Every tree is
        parsed, so the block may belong to a tree the listing does not use. The
        records before the padding are all read; what the padding holds is not, which
        is why the message says a record may be missing. Each offset is reported
        once.
        """
        for found in sorted(set(offsets)):
            self._context.report(
                DiagnosticCode.ARCHIVE_TRAILING_DATA,
                (
                    "ISO directory block is damaged: its padding after the last "
                    f"directory record holds a non-zero byte at offset {found}. The "
                    "records before it are listed; a record whose length byte was "
                    "damaged would be missing."
                ),
                ArchiveEofContext(
                    archive_name=self._archive_name,
                    format="iso",
                    expected_marker="directory_padding",
                    expected_bytes=0,
                    observed_bytes=found,
                    observed_kind="nonzero",
                ),
            )

    def _report_unread_session(self, start: int, stop: int) -> bool:
        """Report another ISO 9660 volume in the data sectors from ``start`` to
        ``stop`` of a raw image read from its first track; True when one is there.

        ``ARCHIVE_UNREAD_SESSION``: the sector addresses did not place a later session
        there that holds a volume (``cd_sessions``), which a session written for other
        addresses, or a later one that only starts with a volume descriptor, does not. A
        ``.cue`` sheet beside the file may still choose it, so a read of the same file
        by its path beside the sheet can list other files. The listing stays the first
        track's. Another ISO appended to the image, or a sector that starts with the
        same bytes by chance, gets the same report. A primary volume descriptor starts a
        sector with ``1``, ``CD001`` and version ``1`` (:data:`_PVD_PREFIX`), which is
        all that is checked. That trade-off is deliberate: a false match only changes
        which integrity code names bytes that are reported either way. The report stands
        for the trailing data those sectors are, which is not reported as well.
        """
        sector = -(-start // USER_DATA_SIZE)
        while sector * USER_DATA_SIZE + len(_PVD_PREFIX) <= stop:
            self._iso_fp.seek(sector * USER_DATA_SIZE)
            if self._iso_fp.read(len(_PVD_PREFIX)) == _PVD_PREFIX:
                break
            sector += 1
        else:
            return False
        self._context.report(
            DiagnosticCode.ARCHIVE_UNREAD_SESSION,
            (
                "Raw CD image holds another ISO 9660 volume descriptor at sector "
                f"{sector}, after the one listed, as a later session of a disc does. "
                "Its sector addresses do not place a readable session there, so "
                "without a .cue sheet the first track is read; a sheet beside the "
                "file may choose that session."
            ),
            UnreadSessionContext(
                archive_name=self._archive_name, format="iso", sector=sector
            ),
        )
        return True

    def _report_hidden_session(self, disc: DiscSource) -> None:
        """Report a later session the ``.cue`` sheet does not show.

        ``ARCHIVE_UNREAD_SESSION``, as for a raw image read from its first track: the
        sheet chose a track, but the sector addresses of a data track after it jump
        by a session gap the sheet does not have, and that session holds a volume
        the sheet-less reading lists (``cue_sheet._hidden_session`` runs the same
        check). The two readings differ; the listing follows the sheet."""
        if disc.hidden_session is None:
            return
        track, sector = disc.hidden_session
        self._context.report(
            DiagnosticCode.ARCHIVE_UNREAD_SESSION,
            (
                f"The .cue sheet places track {track} in the session it reads, but "
                "the track's sector addresses start a later session, with an ISO "
                f"9660 volume descriptor at address {sector}. The listing follows "
                "the sheet; read without it, the image lists that session."
            ),
            UnreadSessionContext(
                archive_name=self._archive_name, format="iso", sector=sector
            ),
        )

    def _report_trailing_data(self) -> None:
        """Report a non-zero byte after the end of the image, as DR-3 asks.

        ``ARCHIVE_TRAILING_DATA`` with ``expected_marker="zeros_to_eof"``, as after a
        TAR trailer: a warning by default, refused under ``DiagnosticPolicy.STRICT``.
        Zero padding is silent. The image ends at the furthest of its volume space and
        the partitions its MBR or GPT lists (:func:`_image_end`): a hybrid ISO, the
        layout Linux installer images use, appends an EFI partition and a GPT backup
        after the volume space, and those bytes belong to the disk image. 7-Zip warns
        on them; archivey does not. Called from the constructor, which the adapter
        calls under its handle lock.
        """
        volume = self._volume
        volume_end = 0
        if volume is not None:
            # The furthest file data inside the file counts too: an image whose
            # volume space size says less than its files use (Office XP images do)
            # ends where they do.
            volume_end = max(volume.space_size * volume.block_size, volume.data_end)
        if self._udf is not None:
            # The partitions the UDF volume declares, and its anchor at block 256. A
            # UDF volume may also keep anchors at its last blocks, which end inside
            # the partition space or the ISO 9660 volume space on every writer seen.
            volume_end = max(volume_end, self._udf.end)
        end = _image_end(
            self._iso_fp,
            volume_end=volume_end,
            image_length=self._image_length,
        )
        image_length = self._image_length
        if isinstance(self._source, DiscSource):
            self._report_hidden_session(self._source)
            # Only the rest of the chosen track: what follows it is another track
            # of the disc, which the .cue sheet accounts for.
            end, image_length = self._source.trailing_window(end, MAX_TRAILING_SCAN)
        elif isinstance(self._source, CookedSource) and end < image_length:
            # A raw image holds every track of the disc, and only the first is read.
            # What follows the data track (audio, or another track's pregap) is the
            # disc's own; only data sectors that continue the track are scanned.
            image_length = self._source.data_end(end, MAX_TRAILING_SCAN)
            if self._report_unread_session(end, image_length):
                return
        if end >= image_length:
            return
        self._iso_fp.seek(end)
        found = first_nonzero_offset(
            self._iso_fp, limit=min(MAX_TRAILING_SCAN, image_length - end)
        )
        if found is None:
            return
        self._context.report(
            DiagnosticCode.ARCHIVE_TRAILING_DATA,
            (
                "ISO image continues past its end: a non-zero byte appears "
                f"{found} bytes after the volume space and any partitions its "
                "partition table lists. The listing does not account for it (this "
                "file may hold something appended to the image)."
            ),
            ArchiveEofContext(
                archive_name=self._archive_name,
                format="iso",
                expected_marker="zeros_to_eof",
                expected_bytes=0,
                observed_bytes=found,
                observed_kind="nonzero",
            ),
        )

    # --- listing ------------------------------------------------------------------------

    def _join(self, dirpath: str, name: str) -> str:
        return "/" + name if dirpath == "/" else f"{dirpath}/{name}"

    def _split_version(self, ns_path: str) -> tuple[str, int | None]:
        """The path to show the caller, and the file version if it had one.

        The leading ``/`` is stripped. In the ``iso9660`` and ``joliet`` namespaces a
        ``;N`` suffix is the file *version*: it is removed and returned, and so is the
        ``.`` that separates an empty extension (``FOO.;1`` is ``FOO``), since the two
        are one rule in ISO 9660. Joliet inherits the version syntax, and Windows-era
        writers put ``;1`` on Joliet names too; Windows and Linux both drop it, so a
        Joliet name follows the plain rule. A Rock Ridge ``NM`` name has no version.

        ``FOO.;1`` and ``FOO;1`` both map to ``("FOO", 1)``. Level 1 requires the dotted
        spelling but writers emit both, so a directory can hold the two. Where one of them
        is the newest version, the two take the one bare name and last-entry-wins makes
        only the later one current. A superseded version is presented by its stored
        spelling (see ``_make_member``), so the two stay apart there.
        """
        rel = ns_path.lstrip("/")
        if self._namespace == "rock_ridge":
            return rel, None
        parent, sep, base = rel.rpartition("/")
        stem, version = _strip_version(base, listed=True)
        return parent + sep + stem, version

    def _version_order(self, item: tuple[str, bytes, object]) -> tuple[str, int]:
        """Sort key putting each plain-ISO name's versions in ascending order."""
        presented, version = self._split_version(item[0])
        return presented, version or 0

    def _group_versions(
        self, files: list[tuple[str, bytes, IsoEntry]]
    ) -> list[tuple[str, bytes, IsoEntry]]:
        """``files`` in record order, each name's versions together in ascending order.

        For Joliet. The versions of one name move to where its first record is, so the
        highest is listed last as in the plain namespace; every other file keeps its
        place, since a Joliet directory's record order is not the sort of its names.
        """
        first_at: dict[str, int] = {}
        keys: list[tuple[int, int]] = []
        for index, (path, _, _) in enumerate(files):
            presented, version = self._split_version(path)
            keys.append((first_at.setdefault(presented, index), version or 0))
        order = sorted(range(len(files)), key=keys.__getitem__)
        return [files[i] for i in order]

    def _decode_bytes_name(
        self, raw: bytes, *, rr_entry: IsoEntry | None = None
    ) -> str:
        """Decode a Rock Ridge or plain ISO 9660 name, or a Rock Ridge link target.

        Nothing in the image says which charset these bytes are in: a Rock Ridge name
        is whatever the writer's locale was. UTF-8 is tried first; bytes that are not
        valid UTF-8 are decoded with ``encoding=`` when the caller gave one, as TAR
        does for its names, then by the name of the Joliet counterpart of the Rock
        Ridge record ``rr_entry`` when one is given (``_joliet_name``), and with UTF-8
        and ``surrogateescape`` otherwise.

        Decoding always returns. A codec ``open_archive`` accepted can still fail on
        these bytes (``utf-32`` on a length that is not a multiple of four, or
        ``idna``, which has no ``surrogateescape``); the name then decodes as it would
        with no ``encoding=``.
        """
        decoded = self._decode_known(raw)
        if decoded is None and rr_entry is not None:
            # Only a Rock Ridge image has Rock Ridge names and link targets to fall
            # back from.
            assert self._namespace == "rock_ridge"
            decoded = self._joliet_name(rr_entry, raw)
        if decoded is None:
            decoded = raw.decode("utf-8", errors="surrogateescape")
        return decoded

    def _decode_known(self, raw: bytes) -> str | None:
        """``raw`` as UTF-8, else with ``encoding=``; ``None`` when neither applies."""
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        if self._encoding is not None:
            try:
                return raw.decode(self._encoding, errors="surrogateescape")
            except UnicodeError:
                pass
        return None

    def _joliet_name(self, entry: IsoEntry, raw: bytes) -> str | None:
        """The Joliet name of the file or directory a Rock Ridge entry describes.

        Rock Ridge names carry no charset, but most images that have them also have a
        Joliet tree, whose UTF-16 names a legacy name was converted into when the image
        was written. The two trees are separate, so the counterpart is found through
        the data: a file by its extent, a directory as the Joliet parent of a file
        found under it. The Joliet name is used only when its ASCII text lines up with
        the Rock Ridge bytes (``_ascii_runs_match``); otherwise ``None``.
        """
        if self._volume is None or self._volume.joliet is None:
            return None
        if self._joliet_files is None:
            self._index_joliet_files(self._volume.joliet.root)
        counterpart = (
            self._joliet_directory(entry)
            if entry.is_dir
            else self._joliet_file(entry, raw)
        )
        if counterpart is None:
            return None
        ident = counterpart.ident
        if len(ident) % 2:
            # A damaged Joliet name: the Rock Ridge entry escapes its own bytes
            # rather than borrow a name that ``_decode_joliet`` ends with U+FFFD.
            return None
        name, _ = _strip_version(_decode_joliet(ident), listed=False)
        if not _ascii_runs_match(raw, name):
            return None
        self._joliet_named[id(entry)] = counterpart
        return name

    def _index_joliet_files(self, root: IsoEntry) -> None:
        """Index every file of the Joliet tree.

        Every empty file of a genisoimage image shares one extent, so the files are
        also indexed by the ASCII runs of their name: finding the one a Rock Ridge name
        lines up with is then one lookup, not a match against each file at the extent.
        """
        files: dict[int, list[IsoEntry]] = {}
        by_runs = self._joliet_files_by_runs
        for _, child in iter_tree(root):
            if child.is_dir:
                continue
            files.setdefault(child.extent, []).append(child)
            runs = _text_ascii_runs(self._joliet_text(child))
            by_runs.setdefault((child.extent, runs), []).append(child)
        self._joliet_files = files

    def _joliet_file(self, entry: IsoEntry, raw: bytes) -> IsoEntry | None:
        """The one Joliet file at this entry's extent whose name lines up with ``raw``.

        Empty files and hard links share an extent, so the name has to single one out.
        """
        candidates = self._joliet_files_by_runs.get(
            (entry.extent, _byte_ascii_runs(raw)), ()
        )
        return candidates[0] if len(candidates) == 1 else None

    def _joliet_directory(self, entry: IsoEntry) -> IsoEntry | None:
        """The Joliet directory holding the same files as this Rock Ridge directory.

        Searches the first ``_JOLIET_SEARCH_RECORDS`` entries under it, breadth first,
        for a non-empty file with exactly one Joliet entry at its extent, then climbs
        that entry's Joliet parents as many levels as the file sits below ``entry``.
        """
        assert self._joliet_files is not None
        queue = [(entry, 1)]
        visited = 0
        while queue and visited < _JOLIET_SEARCH_RECORDS:
            directory, depth = queue.pop(0)
            for child, _ in self._children(directory, True):
                visited += 1
                if visited > _JOLIET_SEARCH_RECORDS:
                    break
                if child.is_dir:
                    queue.append((child, depth + 1))
                    continue
                joliet = self._joliet_files.get(child.extent, ())
                if child.data_length == 0 or len(joliet) != 1:
                    continue
                found: IsoEntry | None = joliet[0]
                for _ in range(depth):
                    found = None if found is None else found.parent
                return found if found is not None and found.is_dir else None
        return None

    @staticmethod
    def _joliet_text(entry: IsoEntry) -> str:
        """A Joliet identifier as text, without its version; never raises."""
        name = _decode_joliet(entry.ident)
        return _strip_version(name, listed=False)[0]

    def _entry_name(self, entry: IsoEntry) -> tuple[str, bytes]:
        """One entry's own name in the selected namespace, and its bytes.

        In the Rock Ridge namespace the ``NM`` name wins, and the entry's ISO 9660
        identifier stands in when there is none (:func:`_nm_name`). Either is bytes in
        no declared charset, decoded as :meth:`_decode_bytes_name` says.

        Decoding never raises: a name that is not valid in its namespace's encoding is
        rendered (surrogateescape for the byte namespaces; for Joliet's UTF-16, a lone
        surrogate kept as that unit and an odd trailing byte as U+FFFD) rather than
        costing the listing. The bytes are the name as stored for the byte namespaces,
        and the UTF-8 of the decoded name for Joliet, a lone surrogate as its three
        bytes.
        """
        if self._namespace == "rock_ridge":
            nm = _nm_name(entry)
            if nm is not None:
                return self._decode_bytes_name(nm, rr_entry=entry), nm
            ident = _iso_ident_name(entry)
            return self._decode_bytes_name(ident), ident
        if self._namespace == "joliet":
            name = _decode_joliet(entry.ident)
            return name, name.encode("utf-8", errors="surrogatepass")
        return self._decode_bytes_name(entry.ident), entry.ident

    def _children(
        self, directory: IsoEntry, use_rr: bool
    ) -> Iterator[tuple[IsoEntry, IsoEntry]]:
        """A directory's entries in identifier order, Rock Ridge relocation followed
        when ``use_rr``, each with the record its name comes from.

        ISO 9660 caps depth at eight, so a Rock Ridge writer parks each deeper
        directory under a root-level ``rr_moved`` directory (its ``..`` carries a
        ``PL`` entry) and leaves a ``CL`` placeholder, a file record, where it belongs.
        With ``use_rr`` a parked directory is skipped where it is stored
        (:meth:`_is_parked`), and a placeholder gives way to the directory it points
        at (:meth:`_relocated`) for its contents and attributes, and keeps its own
        name, as Linux's ``readdir`` names it from the placeholder's ``NM``. A
        placeholder that points at nothing is listed as the file record it is.
        """
        for child in _sorted_children(directory):
            named = child
            if use_rr and child.rr is not None:
                if self._is_parked(child):
                    continue
                if child.rr.child_link is not None:
                    child = self._relocated(child, child.rr.child_link)
            yield child, named

    def _relocated(self, placeholder: IsoEntry, extent: int) -> IsoEntry:
        """The directory a Rock Ridge ``CL`` placeholder points at, or the placeholder.

        The target is the primary tree's first directory at ``extent``, breadth
        first, leaving out placeholders and symlinks, as Linux follows a ``CL``. A
        ``CL`` that names no directory leaves the placeholder.

        The target is not re-matched by name among its parent's entries: two deep
        directories of one name (``a/.../x`` and ``b/.../x``) are both relocated
        into ``rr_moved``, so a name match would list the first ``x`` in both places
        and lose the second one's files.
        """
        return self._relocation_index().get(extent, placeholder)

    def _is_parked(self, entry: IsoEntry) -> bool:
        """Whether a directory is a relocated one, listed where a ``CL`` points at it
        rather than where it is stored: its ``..`` carries a ``PL`` entry, and a ``CL``
        entry that the listing reaches points at its extent (:meth:`_unrelinked`).

        A ``PL`` that no reachable ``CL`` points back at relinks nothing, so that
        directory is listed where it is stored rather than lost with its files.
        Linux hides an entry by its own ``RE`` entry instead, which this reader does
        not use.
        """
        if not (entry.is_dir and entry.parent_linked and entry.rr is not None):
            return False
        return id(entry) not in self._unrelinked()

    def _unrelinked(self) -> set[int]:
        """The ``PL`` directories, by ``id()``, that no ``CL`` the listing reaches
        points at.

        The primary tree is walked as :meth:`_children` lists it: a ``CL`` is followed
        to its directory and a ``PL`` directory is not entered where it is stored.
        A ``CL`` counts only once the walk reaches it, so one inside the very
        directory it would relink does not hide that directory. Each ``PL`` directory
        whose extent no reached ``CL`` points at, in the order the walk met them, is
        then listed where it is stored and walked in turn, since the ``CL`` entries
        under it may relink others. Each extent is walked once.
        """
        if self._orphans is None:
            assert self._volume is not None
            index = self._relocation_index()
            orphans: set[int] = set()
            reached: set[int] = set()
            walked: set[int] = set()
            parked: list[IsoEntry] = []

            def walk(start: IsoEntry) -> None:
                queue = [start]
                for directory in queue:
                    if directory.extent in walked:
                        continue
                    walked.add(directory.extent)
                    for child in directory.children or ():
                        rr = child.rr
                        if rr is not None and child.is_dir and child.parent_linked:
                            parked.append(child)
                        elif rr is not None and rr.child_link is not None:
                            reached.add(rr.child_link)
                            target = index.get(rr.child_link)
                            if target is not None:
                                queue.append(target)
                        elif child.is_dir and child.children is not None:
                            queue.append(child)

            walk(self._volume.primary.root)
            position = 0
            while position < len(parked):
                directory = parked[position]
                position += 1
                if directory.extent not in reached:
                    orphans.add(id(directory))
                    walk(directory)
            self._orphans = orphans
        return self._orphans

    def _relocation_index(self) -> dict[int, IsoEntry]:
        """The primary tree's first directory at each extent, breadth first, leaving
        out placeholders and symlinks, as Linux follows a ``CL``; built once."""
        if self._entry_at_extent is None:
            assert self._volume is not None
            index: dict[int, IsoEntry] = {}
            queue = [self._volume.primary.root]
            for directory in queue:
                for child in directory.children or ():
                    rr = child.rr
                    if rr is not None and (rr.child_link is not None or rr.is_symlink):
                        continue
                    if child.is_dir:
                        index.setdefault(child.extent, child)
                        if child.children is not None:
                            queue.append(child)
            self._entry_at_extent = index
        return self._entry_at_extent

    def _is_rr_moved(self, entry: IsoEntry) -> bool:
        """Whether a root-level directory is Rock Ridge's ``rr_moved`` relocation parent.

        That directory is the relocation's scaffolding, not part of the tree anyone
        archived. It is known by its contents rather than its name: every child is a
        relocated directory (:meth:`_is_parked`), the same test :meth:`_children` uses
        to hide those children from their parking place.
        """
        children = entry.children
        if not children:
            return False
        return all(self._is_parked(child) for child in children)

    def _tree_root(self) -> IsoEntry:
        volume = self._volume
        assert volume is not None
        if self._namespace == "joliet":
            assert volume.joliet is not None
            return volume.joliet.root
        return volume.primary.root

    def _walk_entries(self) -> Iterator[tuple[str, bytes, IsoEntry, bool]]:
        """Yield ``(namespace path, its bytes, entry, superseded)`` per entry.

        The path is only a rendering of the entry: a Rock Ridge name holding ``/``,
        or two entries sharing one name, lists each entry. Each directory extent is
        descended once.

        Within a directory, subdirectories come first and then files, each in
        identifier order (:func:`_sorted_children`), except that plain ISO 9660 files
        are ordered by (name, version) and the versions of one Joliet name are brought
        together (``_group_versions``). ``superseded`` is true for a plain ISO 9660 or
        Joliet file when the same directory holds a higher version of the same name.
        """
        root = self._tree_root()
        use_rr = self._namespace == "rock_ridge"
        seen_extents = {root.extent}
        stack: list[tuple[str, bytes, IsoEntry]] = [("/", b"", root)]
        while stack:
            dirpath, raw_dirpath, directory = stack.pop()
            dirs: list[tuple[str, bytes, IsoEntry]] = []
            files: list[tuple[str, bytes, IsoEntry]] = []
            for child, named in self._children(directory, use_rr):
                if (
                    use_rr
                    and dirpath == "/"
                    and child.is_dir
                    and self._is_rr_moved(child)
                ):
                    continue
                name, raw_name = self._entry_name(named)
                path = self._join(dirpath, name)
                raw_path = raw_name if dirpath == "/" else raw_dirpath + b"/" + raw_name
                (dirs if child.is_dir else files).append((path, raw_path, child))
            if self._namespace == "iso9660":
                files.sort(key=self._version_order)
            elif self._namespace == "joliet":
                files = self._group_versions(files)
            newest: dict[str, int] = {}
            for path, _, _ in files:
                presented, version = self._split_version(path)
                if version is not None:
                    newest[presented] = max(newest.get(presented, version), version)
            for path, raw_path, entry in dirs:
                yield path, raw_path, entry, False
            for path, raw_path, entry in files:
                presented, version = self._split_version(path)
                superseded = version is not None and version < newest[presented]
                yield path, raw_path, entry, superseded
            for path, raw_path, entry in reversed(dirs):
                if entry.children is None or entry.extent in seen_extents:
                    continue
                seen_extents.add(entry.extent)
                stack.append((path, raw_path, entry))

    @override
    def iter_members(self) -> Iterator[MemberRecord[IsoEntry | UdfEntry]]:
        # Listing reads nothing from the image except to follow a Rock Ridge link
        # target that is not UTF-8 (``_decode_link_target``), and that walks entries
        # already parsed too: every tree was parsed at open. ``index`` is each
        # member's position in the walk, the id registration stamps, so a diagnostic
        # raised while typing can name it. The image offset each listed non-empty
        # file's data starts at is kept, so the trees not listed can be compared with
        # the listed one.
        listed_extents: set[int] = set()
        if self._udf is not None and self._namespace == "udf":
            for index, name in enumerate(self._udf.walk()):
                udf_entry = name.entry
                extent = udf_entry.first_extent
                if (
                    not udf_entry.is_directory
                    and udf_entry.info_length
                    and extent is not None
                ):
                    listed_extents.add(extent)
                member = self._make_udf_member(name, index)
                yield MemberRecord(member, udf_entry)
        else:
            assert self._volume is not None
            block_size = self._volume.block_size
            for index, (ns_path, raw_path, entry, superseded) in enumerate(
                self._walk_entries()
            ):
                if not entry.is_dir and entry.data_length:
                    listed_extents.add(entry.extent * block_size)
                member = self._make_member(
                    ns_path, raw_path, entry, index, superseded=superseded
                )
                yield MemberRecord(member, entry)
        self._report_files_in_other_trees(listed_extents)

    # --- the image's other trees ---------------------------------------------------

    def _report_files_in_other_trees(self, listed_extents: set[int]) -> None:
        """Report a file that a tree this reader does not list holds and the listed
        tree does not: ``MEMBER_READERS_DISAGREE``, ``file_only_in_joliet``,
        ``file_only_in_iso9660`` or ``file_only_in_udf``.

        An image carries up to three name trees over one set of file data. Linux and
        xorriso read Rock Ridge, Windows and 7-Zip read UDF first and Joliet when there
        is no UDF, and a reader without Joliet support reads the plain ISO 9660 tree,
        so a file put in one tree only is seen by some readers and hidden from the
        others. archivey lists one tree (Rock Ridge, else UDF, else Joliet, else plain
        ISO 9660) and compares the others: Joliet unless it is listed, the plain tree
        when Joliet is listed or when UDF is listed and there is no Joliet (Rock Ridge
        names ride the plain records, so listing Rock Ridge covers them), and UDF
        unless it is listed. Files are matched by the image offset of the data each
        points at, not by name, since a Joliet name is cut at 64 characters and a plain
        one is 8.3. Empty files are left out: they share one extent, so they cannot be
        told apart.

        Every tree was parsed at open, within the listing budget, so this walks what
        is already in memory and reads nothing from the image. At most
        ``_OTHER_TREE_REPORTS`` files are reported per tree.
        """
        volume = self._volume
        joliet = volume is not None and volume.joliet is not None
        if self._namespace != "joliet" and joliet:
            self._report_unlisted(
                "Joliet",
                "file_only_in_joliet",
                self._entry_tree_files(JOLIET_TREE),
                self._joliet_text,
                listed_extents,
            )
        if self._namespace == "joliet" or (
            self._namespace == "udf" and volume is not None and not joliet
        ):
            self._report_unlisted(
                "ISO 9660",
                "file_only_in_iso9660",
                self._entry_tree_files(PRIMARY_TREE),
                self._plain_text,
                listed_extents,
            )
        if self._udf is not None and self._namespace != "udf":
            self._report_unlisted(
                "UDF",
                "file_only_in_udf",
                self._udf_tree_files(self._udf),
                lambda name: name,
                listed_extents,
            )

    def _report_unlisted(
        self,
        tree: str,
        shape: Literal[
            "file_only_in_joliet", "file_only_in_iso9660", "file_only_in_udf"
        ],
        files: Iterator[tuple[int | None, str, _NameSource]],
        name_of: Callable[[_NameSource], str],
        listed_extents: set[int],
    ) -> None:
        """Report the files of ``files``, ``(extent, directory path, name source)``,
        whose extent no listed file has. A name is decoded only for a file reported."""
        reported = 0
        for extent, dirpath, name_source in files:
            if extent is not None and extent in listed_extents:
                continue
            path = dirpath + name_of(name_source)
            reported += 1
            cap = (
                f" No more than {_OTHER_TREE_REPORTS} such files are reported per tree."
                if reported == _OTHER_TREE_REPORTS
                else ""
            )
            self._context.report(
                DiagnosticCode.MEMBER_READERS_DISAGREE,
                (
                    f"The image's {tree} tree holds the file {quoted(path)}, which the "
                    f"{self._namespace.replace('_', ' ')} tree archivey lists does not: "
                    f"a reader of the {tree} tree sees it, and it is not a member "
                    f"here.{cap}"
                ),
                ReaderDisagreementContext(
                    archive_name=self._archive_name,
                    member_name=path,
                    member_id=None,
                    shape=shape,
                ),
            )
            if reported == _OTHER_TREE_REPORTS:
                return

    def _entry_tree_files(
        self, tree: int
    ) -> Iterator[tuple[int | None, str, IsoEntry]]:
        """``(image offset, directory path, entry)`` of every non-empty file in the
        Joliet or plain ISO 9660 tree."""
        volume = self._volume
        assert volume is not None
        if tree == JOLIET_TREE:
            assert volume.joliet is not None
            root, name_of = volume.joliet.root, self._joliet_text
        else:
            root, name_of = volume.primary.root, self._plain_text
        block_size = volume.block_size
        stack: list[tuple[str, IsoEntry]] = [("", root)]
        while stack:
            dirpath, directory = stack.pop()
            for child in _sorted_children(directory):
                if child.is_dir:
                    if child.children is not None:
                        stack.append((f"{dirpath}{name_of(child)}/", child))
                elif child.data_length:
                    yield child.extent * block_size, dirpath, child

    @staticmethod
    def _plain_text(entry: IsoEntry) -> str:
        """A plain ISO 9660 identifier as text, without its version; never raises."""
        name = entry.ident.decode("latin-1")
        return name if entry.is_dir else _strip_version(name, listed=True)[0]

    @staticmethod
    def _udf_tree_files(udf: UdfVolume) -> Iterator[tuple[int | None, str, str]]:
        """``(image offset, directory path, name)`` of every non-empty file in the UDF
        tree. The offset is ``None`` for data held inside the File Entry, which no
        ISO 9660 record can point at."""
        for name in udf.walk():
            entry = name.entry
            if entry.is_directory or entry.is_symlink or not entry.info_length:
                continue
            dirpath, _, base = name.path.rpartition("/")
            yield entry.first_extent, f"{dirpath}/" if dirpath else "", base

    def _make_udf_member(self, name: UdfName, index: int) -> ArchiveMember:
        """The member for one name of the UDF tree.

        Type, mode, owner and times come from the File Entry: its ICB file type, its
        permissions (UDF's owner, group and other bits, which map onto POSIX's), its
        uid and gid (``None`` when UDF's "not specified" ``0xFFFFFFFF``), and its
        modification, access and attribute times, plus the creation time of an
        Extended File Entry. A device, FIFO or socket with no data is ``OTHER``, as
        under Rock Ridge.
        """
        entry = name.entry
        raw_mode = entry.mode
        special = special_file_type(raw_mode)
        if entry.is_directory:
            member_type = MemberType.DIRECTORY
        elif entry.is_symlink:
            member_type = MemberType.SYMLINK
        elif stat.S_ISREG(raw_mode) or entry.info_length:
            member_type = MemberType.FILE
        else:
            member_type = MemberType.OTHER
        extra = MemberExtra()
        if special is not None:
            extra[EXTRA_SPECIAL_FILE_TYPE] = special
        invalid: list[tuple[str, str, str]] = []

        def convert(raw: bytes | None, field: str) -> datetime | None:
            if raw is None:
                return None
            value, bad = udf_timestamp(raw)
            if bad:
                invalid.append((field, "udf", raw.hex()))
            return value

        is_file = member_type is MemberType.FILE
        member = ArchiveMember(
            type=member_type,
            name=name.path,
            raw_name=name.raw_path,
            size=entry.info_length if is_file else None,
            compressed_size=entry.info_length if is_file else None,
            modified=convert(entry.modified, "modified"),
            accessed=convert(entry.accessed, "accessed"),
            created=convert(entry.created, "created"),
            ctime=convert(entry.attribute, "ctime"),
            mode=stat.S_IMODE(raw_mode),
            uid=entry.uid,
            gid=entry.gid,
            link_target=name.link_target,
            compression=(
                (CompressionMethod(algo=CompressionAlgorithm.STORED),)
                if is_file
                else ()
            ),
            is_encrypted=False,
            extra=extra,
        )
        if special is not None and is_file:
            self._context.report(*special_file_has_data_report(member), member=member)
        self._report_invalid_dates(member, invalid, tree="UDF")
        return member

    def _make_member(
        self,
        ns_path: str,
        raw_path: bytes,
        entry: IsoEntry,
        index: int,
        *,
        superseded: bool = False,
    ) -> ArchiveMember:
        """The member for one walked entry, named as the image presents it.

        ``ns_path`` is the path :meth:`_walk_entries` rendered in the selected
        namespace (:meth:`_entry_name` says which name source wins), and ``raw_path``
        its bytes. Where each other field comes from:

        - type: a Rock Ridge symlink, else the record's directory flag, else OTHER when
          a Rock Ridge ``PX`` mode is not a regular file's and the extent is empty,
          else FILE (:meth:`_member_type`);
        - mode, uid and gid: the Rock Ridge ``PX`` entry; ``None`` without one
          (:meth:`_px`);
        - times: the Rock Ridge ``TF`` entry, with the directory record's date as the
          fallback for the modification time (:meth:`_timestamps`);
        - size and compression: the extents as declared on disc, or the size a zisofs
          ``ZF`` entry declares (:meth:`_stored_data`).

        The member's diagnostics are reported once it is built, since each names it.
        archivey normalizes the name after this returns.
        """
        rr = entry.rr
        raw_mode, uid, gid = (
            (None, None, None) if rr is None else (rr.mode, rr.uid, rr.gid)
        )
        special = special_file_type(raw_mode) if raw_mode is not None else None
        member_type = self._member_type(entry, rr, raw_mode, special)
        name, version = self._member_name(ns_path, member_type, superseded)
        extra = (
            MemberExtra({"iso.version": version})
            if version is not None
            else MemberExtra()
        )
        if special is not None:
            # Only a mode that names a special or unknown file type: a non-regular mode
            # that is a directory's (``S_IFDIR`` on a file record) still makes OTHER
            # in ``_member_type`` but recorded no special file, so it gets no key.
            extra[EXTRA_SPECIAL_FILE_TYPE] = special

        modified, accessed, created, ctime, invalid_dates = self._timestamps(entry, rr)
        mode = stat.S_IMODE(raw_mode) if raw_mode is not None else None
        link_target = self._symlink_target(member_type, entry, rr)
        size, compressed_size, compression = self._stored_data(entry, member_type)

        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=raw_path,
            size=size,
            # The stored length; for a zisofs member ``size`` is the decoded one.
            compressed_size=compressed_size,
            modified=modified,
            accessed=accessed,
            created=created,
            ctime=ctime,
            mode=mode,
            uid=uid,
            gid=gid,
            link_target=link_target,
            compression=compression,
            is_encrypted=False,
            extra=extra,
            is_current=not superseded,
        )
        self._emit_system_use_cut(member, rr, index)
        if special is not None and member.type is MemberType.FILE:
            self._context.report(*special_file_has_data_report(member), member=member)
        self._report_invalid_dates(member, invalid_dates)
        self._report_name_fallbacks(member, entry, rr, index)
        return member

    def _member_type(
        self,
        entry: IsoEntry,
        rr: RockRidge | None,
        raw_mode: int | None,
        special: SpecialFileType | None,
    ) -> MemberType:
        """The member type of an entry; ``raw_mode`` and ``special`` come from its
        Rock Ridge ``PX`` entry, when it has one."""
        if rr is not None and rr.is_symlink:
            return MemberType.SYMLINK
        if entry.is_dir:
            return MemberType.DIRECTORY
        if (
            special is not None or (raw_mode is not None and not stat.S_ISREG(raw_mode))
        ) and entry.data_length == 0:
            # A Rock Ridge PX mode names a device, FIFO or socket, and the extent is
            # empty (genisoimage and xorriso write a FIFO so): OTHER. A non-empty extent
            # under such a mode is a FILE whose bytes are the content (DR-25), with
            # ``extra["special_file_type"]`` keeping the stored type.
            return MemberType.OTHER
        return MemberType.FILE

    def _member_name(
        self, ns_path: str, member_type: MemberType, superseded: bool
    ) -> tuple[str, int | None]:
        """The member name for ``ns_path``, and its plain ISO 9660 or Joliet version."""
        # ISO 9660 / Joliet paths are POSIX-style ("/"): a backslash is a literal character.
        # ECMA-119 gives a version only to a file identifier. A directory's ``;N`` is
        # part of its name, and its children's paths keep it.
        if member_type is MemberType.DIRECTORY:
            return ns_path.lstrip("/"), None
        name, version = self._split_version(ns_path)
        if superseded:
            # An older version is presented as its stored identifier (``FOO.;1``), as
            # RAR presents a file-version history row: a distinct name to read it by,
            # matching ``raw_name``, and ``is_current=False`` so extraction skips it.
            # The newest version takes the bare name. Keeping the stored spelling also
            # keeps ``FOO.;1`` and ``FOO;1`` apart when both are superseded.
            name = ns_path.lstrip("/")
        return name, version

    def _stored_data(
        self, entry: IsoEntry, member_type: MemberType
    ) -> tuple[int | None, int | None, tuple[CompressionMethod, ...]]:
        """``(size, compressed_size, compression)`` of a member; only a file has data.

        The size is the length the records declare, every extent together, even
        where the image ends before the data does: reading such a member fails at
        the cut with ``TruncatedError``."""
        if member_type != MemberType.FILE:
            return None, None, ()
        size: int | None = entry.data_length
        compressed_size = size
        compression = (CompressionMethod(algo=CompressionAlgorithm.STORED),)
        zisofs = None if entry.rr is None else entry.rr.zisofs
        if zisofs is not None:
            # Rock Ridge transparent compression: the extent holds zisofs blocks of
            # zlib data, and the ZF entry declares the size they decode to.
            size = zisofs.uncompressed_size
            # A variant this reader refuses to decode is not reported as deflate.
            algo = (
                CompressionAlgorithm.DEFLATE
                if _zisofs_refusal(zisofs) is None
                else CompressionAlgorithm.UNKNOWN
            )
            compression = (CompressionMethod(algo=algo),)
        return size, compressed_size, compression

    def _report_invalid_dates(
        self,
        member: ArchiveMember,
        invalid_dates: list[tuple[str, str, str]],
        *,
        tree: str = "ISO 9660",
    ) -> None:
        """Report each stored date ``_timestamps`` could not read.

        The message names the member, so it is built here, not in ``_timestamps``.
        """
        for field, source, value_repr in invalid_dates:
            message = f"Invalid {tree} date for {quoted(member.name)}: {value_repr}"
            issue = TimestampIssue(
                field=field, source=source, value_repr=value_repr, message=message
            )
            self._context.report(
                DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
                issue.message,
                MemberTimestampContext(
                    member_name=member.name,
                    field=issue.field,
                    source=issue.source,
                    value_repr=issue.value_repr,
                ),
                member=member,
            )

    def _report_name_fallbacks(
        self,
        member: ArchiveMember,
        entry: IsoEntry,
        rr: RockRidge | None,
        index: int,
    ) -> None:
        """Report a member whose name did not come from where its namespace puts it.

        Three cases: a Rock Ridge name that is not UTF-8 and was taken from the Joliet
        tree; a record in a Rock Ridge image with no Rock Ridge entries at all; and a
        Rock Ridge ``NM`` entry that spells an empty name. The last two leave the
        member under its ISO 9660 name.
        """
        if id(entry) in self._joliet_named:
            self._context.report(
                DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED,
                (
                    "Rock Ridge name is not valid UTF-8; the name is taken from the "
                    f"Joliet tree: {quoted(member.name)}"
                ),
                NameEncodingContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    raw_name_base64=raw_name_to_base64(member.raw_name),
                    # No decode of the stored bytes happened: the name is another
                    # record's, and Rock Ridge declares no charset.
                    inferred_encoding="",
                    declared_encoding="",
                ),
                member=member,
            )
        if self._namespace == "rock_ridge" and rr is None:
            # The image is Rock Ridge but this record's System Use area carries none
            # (absent or damaged). The member is kept under its ISO 9660 name; what the
            # entries would have given (the long name, POSIX mode/owner, a symlink)
            # is missing, and the caller is told so.
            self._context.report(
                DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                (
                    f"Directory record {quoted(member.name)} carries no Rock Ridge "
                    "entries; the member is listed under its ISO 9660 name without "
                    "Rock Ridge name, mode, owner or link data."
                ),
                MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    record="rock_ridge",
                    reason="no Rock Ridge entries in the System Use area",
                ),
                member=member,
            )
        # An absent ``NM`` is RRIP-legal, so its fallback to the ISO 9660 name is
        # silent; an ``NM`` that is present and spells nothing is a writer's error,
        # so the same fallback is reported. A record whose ISO 9660 identifier is
        # empty too has no name left: the empty component then collapses as in any
        # format, and ``member_name_normalized`` reports that.
        if self._namespace == "rock_ridge" and rr is not None and rr.name == b"":
            fallback = (
                "the member is listed under its ISO 9660 name"
                if entry.ident
                else "its ISO 9660 identifier is empty too, so no name is left"
            )
            self._context.report(
                DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                (
                    f"The Rock Ridge NM entry of {quoted(member.name)} spells an "
                    f"empty name; {fallback}."
                ),
                MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    record="NM",
                    reason="empty alternate name",
                ),
                member=member,
            )

    def _emit_system_use_cut(
        self, member: ArchiveMember, rr: RockRidge | None, index: int
    ) -> None:
        """Report a Rock Ridge area the System Use filter cut short, if this one was.

        What followed the malformed entry is lost, so a symlink's target, which may
        have run on past it, is withheld rather than reported cut short.
        """
        reason = None if rr is None else rr.dropped
        if reason is None:
            return
        self._context.report(
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
            (
                f"The Rock Ridge entries of {quoted(member.name)} are malformed "
                f"({reason}); the member is listed from the entries before that."
            ),
            MemberHeaderRecordContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=index,
                # The entry list was cut short, so no one record is named.
                record="",
                reason=reason,
                list_truncated=True,
            ),
            member=member,
        )
        if member.type == MemberType.SYMLINK:
            self._context.link_target_unavailable(
                member,
                reason="target_record_malformed",
                message=(
                    f"The symlink target of {quoted(member.name)} may run past a "
                    "malformed Rock Ridge entry; leaving link_target unset."
                ),
                target_in_archive=True,
            )

    def _timestamps(
        self, entry: IsoEntry, rr: RockRidge | None
    ) -> tuple[
        datetime | None,
        datetime | None,
        datetime | None,
        datetime | None,
        list[tuple[str, str, str]],
    ]:
        """Return ``(modified, accessed, created, ctime, invalid)``.

        ``ctime`` is the Rock Ridge attribute-change time (POSIX ``st_ctime``). It
        never fills ``created``, which holds only a TF creation time. ``invalid``
        lists each stored date that is not a date, as ``(field, source,
        value_repr)``, for a ``MEMBER_TIMESTAMP_INVALID`` report. A TF modification
        time wins over the directory-record date, which cannot hold hundredths or the
        long form's four-digit year.
        """
        invalid: list[tuple[str, str, str]] = []

        def convert(date: RawDate | None, field: str, source: str) -> datetime | None:
            if date is None:
                return None
            value = date_value(date)
            if value is None and date_is_invalid(date):
                invalid.append((field, source, repr(date_fields(date))))
            return value

        times = {} if rr is None else rr.times
        modified = convert(times.get("modified"), "modified", "rock_ridge")
        accessed = convert(times.get("accessed"), "accessed", "rock_ridge")
        created = convert(times.get("created"), "created", "rock_ridge")
        ctime = convert(times.get("attribute"), "ctime", "rock_ridge")
        modified = modified or convert(
            RawDate(entry.date, False), "modified", "directory_record"
        )
        return modified, accessed, created, ctime, invalid

    def _symlink_target(
        self, member_type: MemberType, entry: IsoEntry, rr: RockRidge | None
    ) -> str | None:
        if member_type != MemberType.SYMLINK or rr is None or not rr.symlink:
            return None
        return self._decode_link_target(entry, rr.symlink)

    def _decode_link_target(self, entry: IsoEntry, target: bytes) -> str:
        """Decode a Rock Ridge link target so that it names what the member names name.

        A target that is not UTF-8 and that ``encoding=`` does not decode is followed
        through the image from the symlink's directory, one component at a time. A
        component that names an entry here decodes the way that entry's own name does,
        Joliet fallback included, so a link to ``caf\\xe9.txt`` reads ``café.txt`` when
        the file lists as ``café.txt``. An absolute target points outside the image and
        a component that names nothing here has no entry to ask, so both are escaped.
        """
        decoded = self._decode_known(target)
        if decoded is not None:
            return decoded
        volume = self._volume
        if target.startswith(b"/") or volume is None or volume.joliet is None:
            return target.decode("utf-8", errors="surrogateescape")
        directory: IsoEntry | None = entry.parent
        parts: list[str] = []
        for component in target.split(b"/"):
            here = self._rock_ridge_child(directory, component)
            # ``_joliet_name`` registers ``here`` for the member's diagnostic, as the
            # walk's own ``_entry_name`` does with the same entry and bytes, so which
            # of the two runs first changes nothing.
            parts.append(self._decode_bytes_name(component, rr_entry=here))
            directory = here if here is not None and here.is_dir else None
        return "/".join(parts)

    def _rock_ridge_child(
        self, directory: IsoEntry | None, component: bytes
    ) -> IsoEntry | None:
        """The entry ``component`` names from ``directory`` in the Rock Ridge tree."""
        if directory is None or component in (b"", b"."):
            return directory
        if component == b"..":
            return directory.parent
        children = self._rock_ridge_children.get(id(directory))
        if children is None:
            children = {}
            for child, named in self._children(directory, True):
                # The name the member lists under; the first of several entries
                # sharing it, as a scan finds.
                children.setdefault(_rr_key(named), child)
            self._rock_ridge_children[id(directory)] = children
        return children.get(component)

    # --- data ---------------------------------------------------------------------------

    def _data_spans(self, entry: IsoEntry) -> list[tuple[int, int]]:
        """Where a file's data is in the image: each extent's byte offset and length.

        The extents of a multi-extent file (4 GiB or more) are read in record order,
        wherever they sit: ECMA-119 does not require them to be back to back. Extents
        that overlap each other are refused as corrupt, since no writer makes them and
        they would let a small image list a file many times its size. A span past the
        end of the image is read as far as the image goes, and the spans after it are
        dropped: the joined stream would otherwise move their bytes down into the
        gap, to the wrong offsets. The stream then ends where the data stops being
        in place, and the adapter's size check makes the short read a
        ``TruncatedError`` from that offset on.
        """
        assert self._volume is not None
        block_size = self._volume.block_size
        spans = [
            (block * block_size, length) for block, length in entry.extents if length
        ]
        end = -1
        for start, length in sorted(spans):
            if start < end:
                raise CorruptionError(
                    "ISO file stored in extents that overlap each other",
                    source_format=self._format,
                    archive_name=self._archive_name,
                )
            end = start + length
        kept: list[tuple[int, int]] = []
        for start, length in spans:
            present = max(0, min(length, self._image_length - start))
            if present:
                kept.append((start, present))
            if present < length:
                break
        return kept

    @override
    def open_member(
        self, member: ArchiveMember, locator: IsoEntry | UdfEntry
    ) -> MemberData:
        if isinstance(locator, UdfEntry):
            return self._open_udf_member(locator)
        # The adapter checks the listed size on every member, so a file whose declared
        # data runs past the end of the image reads what is there, then fails at the
        # cut with TruncatedError. A zisofs file cut there fails at the block that is
        # cut, as a TruncatedError from the decoder.
        entry = locator
        zisofs = None if entry.rr is None else entry.rr.zisofs
        if zisofs is not None:
            refusal = _zisofs_refusal(zisofs)
            if refusal is not None:
                raise UnsupportedFeatureError(
                    f"ISO member {quoted(member.name)} is stored with {refusal}; "
                    "reading it is not supported",
                    source_format=self._format,
                    archive_name=self._archive_name,
                )
        # The adapter holds the handle lock here, so the zisofs header read is
        # covered, and wraps the stream in it after. The views stop at the declared
        # length and the zisofs decoder at the declared size, so neither returns a
        # byte past ``size``.
        spans = self._data_spans(entry)
        ranges = tuple((start, start + length) for start, length in spans)
        if isinstance(self._source, CookedSource):
            # The hints name bytes of the file archivey reads, which for a raw image
            # are the whole sectors holding each extent.
            ranges = tuple(self._source.raw_range(*span) for span in ranges)
        elif isinstance(self._source, DiscSource):
            # Read by its sector addresses, the opened file holds the tracks; by a
            # .cue sheet it does not (the data is in the track files), and a span
            # across two tracks has no one range.
            mapped = [self._source.file_range(*span) for span in ranges]
            ranges = tuple(r for r in mapped if r is not None)
            if len(ranges) < len(mapped):
                ranges = ()
        return MemberData(
            self._data_stream(spans, zisofs, member),
            bounded=True,
            ranges=ranges,
        )

    def _open_udf_member(self, entry: UdfEntry) -> MemberData:
        """A UDF file's data: inline in its File Entry, or its extents joined.

        Recorded extents that overlap each other are refused as corrupt, as for an
        ISO 9660 multi-extent file: no writer makes them, and they would let a small
        image list a file many times its size. An extent allocated but not recorded
        reads as zeros. An extent past the end of the image is read as far as the
        image goes and the extents after it are dropped, so the adapter's size check
        makes the short read a ``TruncatedError``.
        """
        if entry.inline is not None:
            return MemberData(io.BytesIO(entry.inline), bounded=True)
        end = -1
        for start, length in sorted(
            (span.offset, span.length)
            for span in entry.spans
            if span.offset is not None and span.length
        ):
            if start < end:
                raise CorruptionError(
                    "UDF file stored in extents that overlap each other",
                    source_format=self._format,
                    archive_name=self._archive_name,
                )
            end = start + length
        kept: list[Span] = []
        for span in entry.spans:
            if span.offset is None:
                kept.append(span)
                continue
            present = max(0, min(span.length, self._image_length - span.offset))
            if present:
                kept.append(Span(span.offset, present))
            if present < span.length:
                break
        ranges = tuple(
            (span.offset, span.offset + span.length)
            for span in kept
            if span.offset is not None
        )
        if isinstance(self._source, CookedSource):
            ranges = tuple(self._source.raw_range(*span) for span in ranges)
        elif isinstance(self._source, DiscSource):
            ranges = ()
        streams: list[BinaryIO] = []
        try:
            for span in kept:
                streams.append(
                    cast(BinaryIO, ZeroRun(span.length))
                    if span.offset is None
                    else self._source.view(span.offset, span.length)
                )
            stream: BinaryIO
            if len(streams) == 1:
                stream = streams[0]
            elif not streams:
                stream = self._source.view(0, 0)
            else:
                stream = JoinedViews(streams)
        except BaseException:
            for part in streams:
                part.close()
            raise
        return MemberData(stream, bounded=True, ranges=ranges)

    def _data_stream(
        self,
        spans: list[tuple[int, int]],
        zisofs: Zisofs | None,
        member: ArchiveMember,
    ) -> BinaryIO:
        # A view of the source per extent (``_data_spans``), joined when there are
        # several.
        stream: BinaryIO
        if len(spans) == 1:
            stream = self._source.view(*spans[0])
        elif not spans:
            stream = self._source.view(0, 0)
        else:
            views: list[BinaryIO] = []
            try:
                for start, length in spans:
                    views.append(self._source.view(start, length))
                stream = JoinedViews(views)
            except BaseException:
                for view in views:
                    view.close()
                raise
        if zisofs is None:
            return stream
        try:
            return cast(
                BinaryIO,
                _ZisofsStream(
                    stream,
                    zisofs,
                    member.compressed_size,
                    natives_for(self._context.config.process_isolation),
                ),
            )
        except BaseException:
            stream.close()
            raise

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        if self._namespace == "udf":
            assert self._udf is not None
            return ReaderArchiveInfo(
                format_version=None,
                comment=self._udf.volume_identifier or None,
                extra=ArchiveInfoExtra({"iso.namespace": self._namespace}),
            )
        assert self._volume is not None
        # The standard allows d-characters only, but writers store the -V text as it
        # was given (xorriso: UTF-8). It records no charset, as a Rock Ridge name does
        # not, so it decodes the way a byte name does: UTF-8, else encoding=, else
        # surrogateescape. The Joliet copy is not read: xorriso turns its non-ASCII
        # bytes into "_", and its 16 characters are half the primary's 32 bytes. Only
        # the space padding the standard defines is removed, and before the decode, so
        # a multi-byte encoding= never meets the padding and a label's own trailing
        # character (a no-break space, say) stays.
        volume_id = self._decode_bytes_name(self._volume.volume_identifier.rstrip(b" "))
        return ReaderArchiveInfo(
            # ISO 9660 stores no interchange level.
            format_version=None,
            comment=volume_id or None,
            extra=ArchiveInfoExtra({"iso.namespace": self._namespace}),
        )

    def _release_archive_handles(self) -> None:
        """Close what the open built: the reader's own view of the source, and a
        ``DiscSource`` the handler built for it.

        One release path for both the failure inside ``__init__`` and the ordinary
        close, so the two cannot drift. The ``ArchiveSource`` under the view is not
        this reader's to close: the adapter closes it after teardown, and
        ``open_archive`` closes it when the constructor raises.
        """
        try:
            self._iso_fp.close()
        finally:
            if isinstance(self._source, DiscSource):
                self._source.close()

    @override
    def close(self) -> None:
        self._release_archive_handles()


def raw_layout_of(source: BinaryIO) -> RawSectorLayout | None:
    """The layout of a raw CD sector image, or ``None`` if ``source`` is not one.

    ``source`` is left at the position it was handed in at.
    """
    start = source.tell()
    try:
        head = source.read(PROBE_SIZE)
    finally:
        source.seek(start)
    return raw_sector_layout(head)


def refuse_raw_sector_image(
    source: BinaryIO,
    format: ArchiveFormat,
    archive_name: str | None,
) -> None:
    """Raise ``UnsupportedFeatureError`` if ``source`` is a raw CD sector image that
    cannot be read.

    Mode 1 and Mode 2 Form 1 images are read by the built-in reader, through
    ``cd_sectors.cooked_source``. A Form 2 image holds no filesystem, and an unknown
    mode or an image too short to show its sector size is not read. (A replacement
    reader is refused every raw image, by ``open_archive`` itself.)

    Called by ``open_archive`` for a source resolved as ISO, before the backend is
    asked to open it, so the refusal names the layout rather than a structure the
    reader cannot find.
    """
    layout = raw_layout_of(source)
    if layout is None or layout.readable:
        return
    if layout.form2:
        what = (
            "Its sectors carry video or audio, not an ISO 9660 filesystem, so there is "
            "nothing here to list."
        )
    else:
        what = (
            "Reading this layout is not supported; convert it to a plain .iso first "
            "(for example with bchunk or bin2iso, using the .cue sheet if there is "
            "one)."
        )
    raise UnsupportedFeatureError(
        f"The file is a raw CD sector image ({layout.describe()}), not an ISO 9660 "
        f"image. {what}",
        source_format=format,
        archive_name=archive_name,
    )


def _cue_for(path: Path | None, raw: bool) -> Path | None:
    """The ``.cue`` sheet to read: ``path`` itself, or for a raw ``.bin`` the sheet
    beside it with the same stem that names it. ``None`` for anything else, and for a
    source with no path (a stream)."""
    if path is None:
        return None
    if path.suffix.lower() == ".cue":
        return path
    if not raw:
        return None
    try:
        siblings = [
            p
            for p in path.parent.iterdir()
            if p.suffix.lower() == ".cue" and p.stem.lower() == path.stem.lower()
        ]
    except OSError:
        return None
    for sheet in siblings:
        try:
            names = [f.name.lower() for f in parse_cue(read_cue_text(sheet))]
        except (OSError, ArchiveyError):
            continue
        if path.name.lower() in names:
            return sheet
    return None


class IsoHandler(IndexedFormatHandler):
    """ISO 9660 images (plain, Joliet, Rock Ridge and UDF), read through
    ``archivey.formats``; no optional package."""

    format = ArchiveFormat.ISO
    # A .cue sheet is text with no magic: it is found by its name, and the disc it
    # describes is read from the track files beside it (cue_sheet.py).
    extensions = (".iso", ".cue")
    # The image is addressed by absolute offsets (volume descriptors at 32 KiB), so
    # even a forward-only pass needs a seekable source.
    non_seekable_reason = (
        "its volume descriptors and directory records are at absolute offsets in "
        "the image"
    )
    # The primary volume descriptor's "CD001" magic sits at offset 32 769; detection
    # peeks the extended 32 774-byte window on demand to find it (see
    # internal/detection.py).
    magic = (
        Magic(32769, b"CD001"),
        # A UDF-only image (a Blu-ray disc, say) starts its Volume Recognition
        # Sequence with "BEA01" where an ISO 9660 image has its primary descriptor.
        Magic(32769, b"BEA01"),
        # A raw CD sector dump (a ``.bin``). Mode 1 and Mode 2 Form 1 are read through
        # ``cooked_source``; other layouts are refused by name in open_archive (see
        # refuse_raw_sector_image) rather than failing detection.
        Magic(0, RAW_SECTOR_SYNC),
    )
    uses_encoding = True  # for Rock Ridge and plain names that are not valid UTF-8

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> IsoReader:
        layout = raw_sector_layout(source.read_at(0, PROBE_SIZE))
        if layout is not None and not layout.readable:
            # open_archive refuses these first; this covers a caller that reaches
            # the handler some other way.
            raise UnsupportedFeatureError(
                f"The file is a raw CD sector image ({layout.describe()}) that "
                "cannot be read as an ISO 9660 image.",
                source_format=ArchiveFormat.ISO,
                archive_name=context.archive_name,
            )
        cue = _cue_for(source.path, layout is not None)
        if cue is not None:
            disc = disc_source(cue, context.archive_name, source._progress_reporter)
            try:
                return IsoReader(disc, context)
            except BaseException:
                disc.close()
                raise
        if layout is not None:
            # Without a sheet, the sector addresses place a later session.
            disc = last_session_source(source, layout, context.archive_name)
            if disc is not None:
                return IsoReader(disc, context)
            source = cooked_source(source, layout, context.archive_name)
        return IsoReader(source, context)


IsoReadBackend = register_builtin_format(IsoHandler)
