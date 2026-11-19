"""A read-only UDF parser (ECMA-167 and OSTA UDF 1.02 to 2.60), for the ISO backend.

UDF is the file system of DVDs and Blu-ray discs, and of Windows install images. A
"bridge" image carries it next to an ISO 9660 tree over the same file data; a UDF-only
image (most Blu-ray discs) has no ISO 9660 descriptor at all. ``pycdlib`` cannot open a
UDF-only image and reads only partitions without a metadata partition, so archivey
parses UDF itself, in pure Python, and turns ``pycdlib``'s own UDF parse off
(``iso_reader._install_pycdlib_udf_skip``).

How the tree is found, from the start of the image::

    32 768             Volume Recognition Sequence: BEA01, NSR02 or NSR03, TEA01
    block 256          Anchor Volume Descriptor Pointer (or block N-256, or N-1)
    anchor -> main     Volume Descriptor Sequence: Partition Descriptors, the
                       Logical Volume Descriptor (block size, partition maps, and
                       where the File Set Descriptor is)
    File Set           the root directory's ICB
    ICB -> File Entry  type, owner, permissions, times, and allocation descriptors
                       saying where its data is; a directory's data is a list of
                       File Identifier Descriptors, each naming a child's ICB

Supported: type 1 partition maps, the type 2 metadata partition (UDF 2.50 and later,
Blu-ray), short and long allocation descriptors, continued allocation
extents, data inline in the File Entry, unrecorded (sparse) extents read as zeros,
File Entries and Extended File Entries, ICB strategy 4 and the indirect entries of
strategy 4096. Sparable and virtual partitions (rewritable and incrementally written
discs) are refused with ``UnsupportedFeatureError``.

Every read goes through the ``read_at`` the caller hands in, so it is bounded by the
image and takes the source's lock. What the walk keeps is weighed against
``ListingLimits`` as it goes (:class:`UdfBudget`), before the bytes are read, and so
is each full path it builds.
"""

from __future__ import annotations

import bisect
import io
import stat
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Protocol

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.overrides import override
from archivey.types import ArchiveFormat

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

# ECMA-167 2/9.1: the Volume Recognition Sequence starts at byte 32 768 and holds one
# descriptor per 2048 bytes, whatever the block size.
VRS_START = 32768
_VRS_STRIDE = 2048
# How many Volume Recognition descriptors are looked at before giving up: the ISO 9660
# descriptors come first on a bridge image, and real images have fewer than ten. A
# structural bound, not a policy limit (format-iso spec): a scan guard far past what
# any writer produces, and each step is one 2048-byte read.
_VRS_MAX = 64
# Block sizes tried for the anchor at block 256 (ECMA-167 3/8.4.2.1). 2048 first:
# every optical disc and every image writer uses it.
_BLOCK_SIZES = (2048, 512, 1024, 4096)
_ANCHOR_BLOCK = 256

# Descriptor tag identifiers (ECMA-167 3/7.2.1 and 4/7.2.1).
_TAG_PVD = 1
_TAG_AVDP = 2
_TAG_VDP = 3
_TAG_PD = 5
_TAG_LVD = 6
_TAG_TD = 8
_TAG_FSD = 256
_TAG_FID = 257
_TAG_AED = 258
_TAG_IE = 259
_TAG_TE = 260
_TAG_FE = 261
_TAG_EFE = 266

# The bounds below are structural, not policy limits (format-iso spec, "Bound the
# UDF chains"): they stop a loop in a chain that the format lets point anywhere, and
# no writer comes near them, so ``ArchiveyConfig`` has no setting for them.
# How many Volume Descriptor Sequence extents (VDP chain) and descriptors are read.
# Writers record one extent of fewer than ten descriptors.
_MAX_VDS_EXTENTS = 16
_MAX_VDS_DESCRIPTORS = 256
# How many indirect entries (ICB strategy 4096) and allocation extent descriptors
# are followed for one entry before it is refused as a loop. Writers use strategy 4
# (no indirect entries) and a few continuation blocks for a very fragmented file.
_MAX_INDIRECT = 64
# How many partition maps a Logical Volume Descriptor may hold. Writers record one or
# two (a physical partition, and a metadata partition over it).
_MAX_PARTITION_MAPS = 64
# A symlink's data is read while listing; a longer one is refused as corrupt. No
# system can make one this long: PATH_MAX is 4096 bytes on Linux, and Linux's UDF
# driver refuses a symlink longer than one block.
_MAX_SYMLINK_BYTES = 64 * 1024

# What one extra span from splitting an extent over metadata runs weighs against the
# metadata budget: the size of a long allocation descriptor (ECMA-167 4/14.14.2).
_SPAN_WEIGHT = 16

# ICB file types (ECMA-167 4/14.6.6).
_FT_DIRECTORY = 4
_FT_FILE = 5
_FT_BLOCK = 6
_FT_CHAR = 7
_FT_FIFO = 9
_FT_SOCKET = 10
_FT_SYMLINK = 12
_FT_METADATA = (250, 251)

_FILE_TYPE_MODE = {
    _FT_DIRECTORY: stat.S_IFDIR,
    _FT_FILE: stat.S_IFREG,
    0: stat.S_IFREG,  # "not specified": Linux reads it as a regular file
    _FT_BLOCK: stat.S_IFBLK,
    _FT_CHAR: stat.S_IFCHR,
    _FT_FIFO: stat.S_IFIFO,
    _FT_SOCKET: stat.S_IFSOCK,
    _FT_SYMLINK: stat.S_IFLNK,
}

# File characteristics of a File Identifier Descriptor (ECMA-167 4/14.4.3).
_FID_DIRECTORY = 0x02
_FID_DELETED = 0x04
_FID_PARENT = 0x08

# Allocation descriptor kinds (ICB tag flags, low three bits) and extent types (the
# top two bits of an extent length, ECMA-167 4/14.14.1.1).
_AD_SHORT = 0
_AD_LONG = 1
_AD_EXTENDED = 2
_AD_INLINE = 3
_EXTENT_RECORDED = 0
_EXTENT_NEXT = 3

_METADATA_PARTITION = b"*UDF Metadata Partition"
_SPARABLE_PARTITION = b"*UDF Sparable Partition"
_VIRTUAL_PARTITION = b"*UDF Virtual Partition"

_ReadAt = Callable[[int, int], bytes]


class UdfBudget(Protocol):
    """Where the walk weighs what it parses: one member per name, bytes, and the full
    paths it builds."""

    def add_udf_member(self) -> None: ...

    def add_udf_bytes(self, nbytes: int) -> None: ...

    def add_udf_path(self, path: str, raw_path: bytes) -> None: ...


def has_volume_recognition(read_at: _ReadAt) -> bool:
    """Whether the image's Volume Recognition Sequence names a UDF volume: a ``BEA01``
    followed by ``NSR02`` or ``NSR03``, after any ISO 9660 descriptors."""
    extended = False
    for index in range(_VRS_MAX):
        data = read_at(VRS_START + index * _VRS_STRIDE, 6)
        ident = data[1:6]
        if ident == b"BEA01":
            extended = True
        elif ident in (b"NSR02", b"NSR03"):
            if extended:
                return True
        elif ident == b"TEA01":
            extended = False
        elif ident not in (b"CD001", b"CDW02", b"BOOT2"):
            return False
    return False


def decode_dstring(raw: bytes) -> str:
    """An OSTA CS0 name (UDF 2.1.1) as text; never raises.

    The first byte is the compression ID: 8 (or 254) means one byte per character,
    16 (or 255) UTF-16BE. A lone surrogate stays in the name, as in a Joliet name, and
    an odd trailing byte becomes U+FFFD. Any other ID is not a name UDF defines; its
    bytes are shown as Latin-1 so the member keeps a name.
    """
    if not raw:
        return ""
    kind, body = raw[0], raw[1:]
    if kind in (16, 255):
        cut = len(body) - len(body) % 2
        name = body[:cut].decode("utf-16_be", errors="surrogatepass")
        return name + "�" if cut < len(body) else name
    return body.decode("latin-1")


def _dstring_field(field: bytes) -> str:
    """A fixed-size dstring (ECMA-167 1/7.2.12): its last byte is the used length."""
    if not field:
        return ""
    used = field[-1]
    if used == 0 or used >= len(field):
        return ""
    return decode_dstring(field[:used])


def udf_timestamp(raw: bytes) -> tuple[datetime | None, bool]:
    """A UDF timestamp (ECMA-167 1/7.3) as a datetime, and whether it was invalid.

    All zeros is "not recorded" and is not invalid. A timezone of -2047 means "not
    specified"; the time is then read as UTC, as Linux does.
    """
    if len(raw) < 12 or not any(raw):
        return None, False
    (type_tz, year, month, day, hour, minute, second, centi, hundreds, micro) = (
        struct.unpack("<HhBBBBBBBB", raw)
    )
    offset = type_tz & 0x0FFF
    if offset & 0x0800:
        offset -= 0x1000
    tz = UTC if offset == -2047 else None
    try:
        if tz is None:
            tz = timezone(timedelta(minutes=offset))
        # Each sub-second field holds 0-99 (ECMA-167 1/7.3). One out of range keeps
        # the whole seconds and flags the date, as nothing is dropped silently.
        sub_second_ok = centi <= 99 and hundreds <= 99 and micro <= 99
        micros = centi * 10_000 + hundreds * 100 + micro if sub_second_ok else 0
        value = datetime(year, month, day, hour, minute, second, micros, tzinfo=tz)
        value.astimezone(UTC)
    except (ValueError, OverflowError):
        return None, True
    return value, not sub_second_ok


def _tag_checksum(data: bytes) -> int:
    return (sum(data[0:4]) + sum(data[5:16])) & 0xFF


def _crc_itu(data: bytes) -> int:
    """CRC-16/CCITT as ECMA-167 7.2.6 defines it (polynomial 0x1021, start 0)."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


class ZeroRun(io.RawIOBase):
    """``length`` zero bytes, seekable: an unrecorded extent of a file."""

    def __init__(self, length: int) -> None:
        super().__init__()
        self._length = length
        self._position = 0

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
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._position, io.SEEK_END: self._length}
        position = base[whence] + offset
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        with memoryview(b) as outer, outer.cast("B") as view:
            n = max(0, min(len(view), self._length - self._position))
            view[:n] = bytes(n)
        self._position += n
        return n


@dataclass(frozen=True, slots=True)
class Span:
    """A run of a file's data: ``length`` bytes at image offset ``offset``, or zeros
    when ``offset`` is ``None`` (an extent allocated but not recorded, or sparse)."""

    offset: int | None
    length: int


@dataclass(slots=True)
class UdfEntry:
    """One File Entry, as the listing needs it."""

    location: int  # the entry's absolute byte offset, its identity
    file_type: int
    uid: int | None
    gid: int | None
    permissions: int
    info_length: int
    modified: bytes
    accessed: bytes
    attribute: bytes
    created: bytes | None
    spans: tuple[Span, ...]
    inline: bytes | None
    partition: int

    @property
    def is_directory(self) -> bool:
        return self.file_type == _FT_DIRECTORY

    @property
    def is_symlink(self) -> bool:
        return self.file_type == _FT_SYMLINK

    @property
    def mode(self) -> int:
        """The POSIX mode: the file type's bits, and UDF's permissions for owner,
        group and others (ECMA-167 4/14.9.5: execute 1, write 2, read 4 per class, in
        the same order as POSIX). UDF keeps setuid, setgid and sticky in an extended
        attribute that is not read."""
        perms = self.permissions
        bits = (perms & 0o7) | ((perms >> 5) & 0o7) << 3 | ((perms >> 10) & 0o7) << 6
        return _FILE_TYPE_MODE.get(self.file_type, 0) | bits

    @property
    def first_extent(self) -> int | None:
        """The image offset of the first recorded byte of the data, or ``None`` when
        no extent is recorded (no data, or zeros only)."""
        for span in self.spans:
            if span.length and span.offset is not None:
                return span.offset
        return None


@dataclass(slots=True)
class UdfName:
    """One name in the tree: a File Identifier and the entry it names."""

    path: str  # the joined path, with no leading "/"
    raw_path: bytes  # the stored identifiers, compression IDs dropped, joined by "/"
    entry: UdfEntry
    link_target: str | None = None  # a symbolic link's target


@dataclass(frozen=True, slots=True)
class _Partition:
    """A partition map: a physical partition's start and length in blocks, or a
    metadata partition read through its metadata file's extents."""

    start: int
    length: int
    metadata: tuple[tuple[int, int], ...] | None = None  # (block offset, blocks)
    # The logical block each metadata run starts at, for a bisect.
    firsts: tuple[int, ...] = ()


class UdfVolume:
    """The UDF tree of an image, parsed at construction; :meth:`walk` lists it."""

    def __init__(
        self,
        read_at: _ReadAt,
        image_length: int,
        *,
        archive_name: str | None,
        budget: UdfBudget | None,
    ) -> None:
        self._read_at = read_at
        self._image_length = image_length
        self._archive_name = archive_name
        self._budget = budget
        # The end the volume declares, once known; reads before it that come back
        # short are a cut image.
        self._declared_end = 0
        self._integrity_end = 0
        self.block_size, anchor = self._find_anchor()
        self._partitions: list[_Partition] = []
        self.volume_identifier = ""
        fsd_location = self._read_volume_descriptors(anchor)
        self.end = self._volume_end(anchor)
        self._root_icb = self._read_file_set(fsd_location)
        self.root = self._read_entry(*self._root_icb)
        if not self.root.is_directory:
            raise self._corrupt("its root is not a directory")
        # The whole tree is parsed here, at open, as pycdlib parses the ISO 9660
        # trees inside ``open_fp``: the listing limits refuse an image before any
        # member is listed, and listing reads nothing more.
        self.names = list(self._walk())

    # --- errors and reads -------------------------------------------------------

    def _corrupt(self, detail: str) -> CorruptionError:
        return CorruptionError(
            f"Error reading UDF volume: {detail}",
            source_format=ArchiveFormat.ISO,
            archive_name=self._archive_name,
        )

    def _read(self, offset: int, n: int, what: str) -> bytes:
        """``n`` bytes at ``offset``, or an error naming ``what`` when they are not
        all there: ``TruncatedError`` when the image declares more than the file
        holds and the read started inside the file, ``CorruptionError`` when a
        pointer led past the end."""
        if offset < 0 or n < 0:
            raise self._corrupt(f"{what} has a negative location")
        data = self._read_at(offset, n)
        if len(data) == n:
            return data
        # A cut image: the read starts inside the file, before the volume has said
        # where it ends, or it stays inside the partitions the volume declares and
        # the file holds less than they do. A read past the declared partitions
        # followed a wrong pointer.
        declared = self._declared_end
        if (declared == 0 and offset < self._image_length) or (
            declared > self._image_length and offset + n <= declared
        ):
            raise TruncatedError(
                f"Error reading UDF volume: the image ends before its {what} does: "
                f"it needs bytes up to {offset + n} and the file holds "
                f"{self._image_length}",
                source_format=ArchiveFormat.ISO,
                archive_name=self._archive_name,
            )
        raise self._corrupt(f"{what} at offset {offset} lies past the end of the image")

    def _tagged(
        self, data: bytes, idents: tuple[int, ...], location: int | None, what: str
    ) -> int:
        """Check a descriptor tag (ECMA-167 3/7.2) and return its identifier.

        The checksum, the identifier, the recorded location (when ``location`` is
        given) and the CRC over the descriptor body must hold.
        """
        if len(data) < 16:
            raise self._corrupt(f"{what} is cut short")
        ident, _version, checksum, _r, _serial, crc, crc_len, tag_location = (
            struct.unpack_from("<HHBBHHHI", data, 0)
        )
        if _tag_checksum(data) != checksum:
            raise self._corrupt(f"{what} has a bad descriptor tag checksum")
        if ident not in idents:
            raise self._corrupt(f"{what} has descriptor tag {ident}")
        if location is not None and tag_location != location:
            raise self._corrupt(
                f"{what} records location {tag_location}, but sits at {location}"
            )
        if 16 + crc_len > len(data):
            raise self._corrupt(f"{what} declares a CRC past its end")
        if _crc_itu(data[16 : 16 + crc_len]) != crc:
            raise self._corrupt(f"{what} has a bad descriptor CRC")
        return ident

    # --- volume structure -------------------------------------------------------

    def _find_anchor(self) -> tuple[int, bytes]:
        """The block size and the Anchor Volume Descriptor Pointer.

        The anchor is at block 256; an image may keep it only at block N-256 or at
        its last block N-1 (ECMA-167 3/8.4.2.1), which is tried for 2048-byte blocks.
        """
        for size in _BLOCK_SIZES:
            data = self._read_at(_ANCHOR_BLOCK * size, size)
            if self._is_anchor(data, _ANCHOR_BLOCK):
                return size, data
        size = _BLOCK_SIZES[0]
        last = self._image_length // size - 1
        for block in (last - _ANCHOR_BLOCK, last):
            if block > _ANCHOR_BLOCK:
                data = self._read_at(block * size, size)
                if self._is_anchor(data, block):
                    return size, data
        if self._image_length < (_ANCHOR_BLOCK + 1) * size:
            raise TruncatedError(
                "Error reading UDF volume: the image ends before its anchor at block "
                f"256: the file holds {self._image_length} bytes",
                source_format=ArchiveFormat.ISO,
                archive_name=self._archive_name,
            )
        raise self._corrupt("no Anchor Volume Descriptor Pointer was found")

    def _volume_end(self, anchor: bytes) -> int:
        """Where the volume ends: the furthest of its partitions, its volume
        descriptor sequences, its integrity sequence and the anchors at block 256
        and at the image's last block or 256 blocks before it (ECMA-167 3/8.4.2.1).
        Bytes after it are not the volume's."""
        size = self.block_size
        ends = [self._declared_end, (_ANCHOR_BLOCK + 1) * size, self._integrity_end]
        for field in (16, 24):
            length, location = struct.unpack_from("<II", anchor, field)
            if length:
                ends.append(location * size + length)
        last = self._image_length // size - 1
        for block in (last - _ANCHOR_BLOCK, last):
            if block > _ANCHOR_BLOCK and self._is_anchor(
                self._read_at(block * size, size), block
            ):
                ends.append((block + 1) * size)
        return max(ends)

    def _is_anchor(self, data: bytes, block: int) -> bool:
        if len(data) < 32:
            return False
        try:
            self._tagged(data[:512], (_TAG_AVDP,), block, "the anchor")
        except CorruptionError:
            return False
        return True

    def _read_volume_descriptors(self, anchor: bytes) -> tuple[int, int, int]:
        """Parse the main Volume Descriptor Sequence (the reserve one when the main
        one does not parse), and return where the File Set Descriptor is."""
        main = struct.unpack_from("<II", anchor, 16)
        reserve = struct.unpack_from("<II", anchor, 24)
        try:
            return self._read_sequence(*main)
        except CorruptionError:
            if not reserve[0]:
                raise
            return self._read_sequence(*reserve)

    def _read_sequence(self, length: int, location: int) -> tuple[int, int, int]:
        size = self.block_size
        partitions: dict[int, tuple[int, int, int]] = {}  # number -> (seq, start, len)
        lvd: bytes | None = None
        lvd_seq = -1
        pvd_seq = -1
        seen = 0
        for _extent in range(_MAX_VDS_EXTENTS):
            next_extent: tuple[int, int] | None = None
            for block in range(location, location + length // size):
                seen += 1
                if seen > _MAX_VDS_DESCRIPTORS:
                    raise self._corrupt("its volume descriptor sequence never ends")
                data = self._read(block * size, size, "volume descriptor sequence")
                ident = struct.unpack_from("<H", data, 0)[0]
                if ident == 0:
                    return self._finish_sequence(partitions, lvd)
                ident = self._tagged(
                    data,
                    (_TAG_PVD, _TAG_VDP, _TAG_PD, _TAG_LVD, _TAG_TD, 4, 7),
                    block,
                    "a volume descriptor",
                )
                seq = struct.unpack_from("<I", data, 16)[0]
                if ident == _TAG_TD:
                    return self._finish_sequence(partitions, lvd)
                if ident == _TAG_VDP:
                    next_extent = struct.unpack_from("<II", data, 20)
                    break
                if ident == _TAG_PVD and seq > pvd_seq:
                    pvd_seq = seq
                    self.volume_identifier = _dstring_field(data[24:56])
                elif ident == _TAG_PD:
                    number = struct.unpack_from("<H", data, 22)[0]
                    start, plength = struct.unpack_from("<II", data, 188)
                    if number not in partitions or seq > partitions[number][0]:
                        partitions[number] = (seq, start, plength)
                elif ident == _TAG_LVD and seq > lvd_seq:
                    lvd_seq = seq
                    lvd = data
            if next_extent is None:
                return self._finish_sequence(partitions, lvd)
            length, location = next_extent
        raise self._corrupt("its volume descriptor pointers form a chain too long")

    def _finish_sequence(
        self, partitions: dict[int, tuple[int, int, int]], lvd: bytes | None
    ) -> tuple[int, int, int]:
        if lvd is None:
            raise self._corrupt("it has no Logical Volume Descriptor")
        size = self.block_size
        (block_size,) = struct.unpack_from("<I", lvd, 212)
        if block_size != size:
            raise self._corrupt(
                f"its logical block size {block_size} differs from the {size}-byte "
                "blocks its anchor is found by"
            )
        integrity_length, integrity_block = struct.unpack_from("<II", lvd, 432)
        if integrity_length:
            self._integrity_end = integrity_block * size + integrity_length
        lv_ident = _dstring_field(lvd[84:212])
        if lv_ident:
            self.volume_identifier = lv_ident
        for _seq, start, plength in partitions.values():
            self._declared_end = max(self._declared_end, (start + plength) * size)
        map_length, map_count = struct.unpack_from("<II", lvd, 264)
        maps = lvd[440 : 440 + map_length]
        if len(maps) < map_length or map_count > _MAX_PARTITION_MAPS:
            raise self._corrupt("its partition maps do not fit their descriptor")
        offset = 0
        metadata_maps: list[tuple[int, int, int]] = []
        for _ in range(map_count):
            if offset + 2 > len(maps):
                raise self._corrupt("its partition maps do not fit their descriptor")
            map_type, map_len = maps[offset], maps[offset + 1]
            if map_len < 6 or offset + map_len > len(maps):
                raise self._corrupt("a partition map has a bad length")
            body = maps[offset : offset + map_len]
            if map_type == 1:
                number = struct.unpack_from("<H", body, 4)[0]
                self._partitions.append(self._physical(partitions, number))
            elif map_type == 2 and map_len >= 64:
                ident = body[5:28].rstrip(b"\0")
                number = struct.unpack_from("<H", body, 38)[0]
                if ident == _METADATA_PARTITION:
                    (file_block,) = struct.unpack_from("<I", body, 40)
                    metadata_maps.append((len(self._partitions), number, file_block))
                    # A placeholder until every physical partition is known.
                    self._partitions.append(_Partition(0, 0, ()))
                elif ident in (_SPARABLE_PARTITION, _VIRTUAL_PARTITION):
                    kind = "sparable" if ident == _SPARABLE_PARTITION else "virtual"
                    raise UnsupportedFeatureError(
                        f"UDF volume uses a {kind} partition (a rewritable or "
                        "incrementally written disc); reading it is not supported",
                        source_format=ArchiveFormat.ISO,
                        archive_name=self._archive_name,
                    )
                else:
                    raise self._corrupt(
                        f"a partition map names an unknown type {ident!r}"
                    )
            else:
                raise self._corrupt(f"a partition map has type {map_type}")
            offset += map_len
        if not self._partitions:
            raise self._corrupt("it has no partition map")
        for index, number, file_block in metadata_maps:
            physical = self._physical(partitions, number)
            self._partitions[index] = self._metadata_partition(physical, file_block)
        fsd_length, fsd_block, fsd_part = struct.unpack_from("<IIH", lvd, 248)
        return fsd_length & 0x3FFFFFFF, fsd_block, fsd_part

    def _physical(
        self, partitions: dict[int, tuple[int, int, int]], number: int
    ) -> _Partition:
        try:
            _seq, start, length = partitions[number]
        except KeyError:
            raise self._corrupt(
                f"a partition map names partition {number}, which has no "
                "Partition Descriptor"
            ) from None
        return _Partition(start, length)

    def _metadata_partition(self, physical: _Partition, file_block: int) -> _Partition:
        """The metadata partition (UDF 2.50 2.2.10): its blocks are the data of the
        metadata file, an Extended File Entry in the physical partition."""
        size = self.block_size
        location = (physical.start + file_block) * size
        data = self._read(location, size, "metadata file entry")
        self._tagged(data, (_TAG_FE, _TAG_EFE), file_block, "the metadata file entry")
        entry = self._parse_entry(data, location, physical_part=physical)
        if entry.file_type not in _FT_METADATA:
            raise self._corrupt("its metadata partition's file is not a metadata file")
        runs: list[tuple[int, int]] = []
        for span in entry.spans:
            if span.offset is None or span.offset % size or span.length % size:
                raise self._corrupt("its metadata file has an extent not on a block")
            start, count = span.offset // size, span.length // size
            if runs and runs[-1][0] + runs[-1][1] == start:
                # Runs that follow each other on disc are one run: each step of
                # _extent_spans then makes one span, which is what it is charged.
                runs[-1] = (runs[-1][0], runs[-1][1] + count)
            elif count:
                runs.append((start, count))
        firsts: list[int] = []
        total = 0
        for _start, count in runs:
            firsts.append(total)
            total += count
        return _Partition(0, total, tuple(runs), tuple(firsts))

    def _block_offset(self, partition: int, block: int, what: str) -> int:
        """The image offset of logical ``block`` of partition reference ``partition``."""
        try:
            part = self._partitions[partition]
        except IndexError:
            raise self._corrupt(f"{what} names partition {partition}") from None
        if block >= part.length:
            raise self._corrupt(f"{what} lies past the end of its partition")
        if part.metadata is None:
            return (part.start + block) * self.block_size
        index = bisect.bisect_right(part.firsts, block) - 1
        start, _count = part.metadata[index]
        return (start + block - part.firsts[index]) * self.block_size

    def _extent_spans(
        self, partition: int, block: int, length: int, what: str
    ) -> list[Span]:
        """The image spans of an extent of ``length`` bytes from logical ``block``,
        split where a metadata partition's blocks are not contiguous."""
        size = self.block_size
        blocks = -(-length // size)
        if partition >= len(self._partitions):
            raise self._corrupt(f"{what} names partition {partition}")
        if block + blocks > self._partitions[partition].length:
            raise self._corrupt(f"{what} runs past the end of its partition")
        part = self._partitions[partition]
        if part.metadata is None:
            # A physical partition is contiguous: one span.
            return [Span((part.start + block) * size, length)]
        # Intersect [block, block + blocks) with the metadata runs once: the cost is
        # one bisect plus one step per run the extent covers, never one per block.
        # Runs are non-empty and never contiguous (_metadata_partition merges
        # them), so each step makes one span.
        spans: list[Span] = []
        index = bisect.bisect_right(part.firsts, block) - 1
        remaining = length
        while remaining > 0:
            run_start, run_count = part.metadata[index]
            skip = block - part.firsts[index]
            take = min(remaining, (run_count - skip) * size)
            spans.append(Span((run_start + skip) * size, take))
            remaining -= take
            block += run_count - skip
            index += 1
        if self._budget is not None and len(spans) > 1:
            # Each run covered after the first is one more span archivey keeps, as
            # if stored: weighed as a long allocation descriptor. This charges the
            # work an extent split over many metadata runs causes.
            self._budget.add_udf_bytes((len(spans) - 1) * _SPAN_WEIGHT)
        return spans

    def _read_file_set(self, location: tuple[int, int, int]) -> tuple[int, int]:
        """The root directory's ICB (partition, block), from the File Set Descriptor."""
        _length, block, partition = location
        offset = self._block_offset(partition, block, "the file set descriptor")
        data = self._read(offset, self.block_size, "file set descriptor")
        self._tagged(data, (_TAG_FSD,), block, "the file set descriptor")
        _len, root_block, root_part = struct.unpack_from("<IIH", data, 400)
        return root_part, root_block

    # --- file entries -----------------------------------------------------------

    def _read_entry(self, partition: int, block: int) -> UdfEntry:
        """Read and parse the File Entry at an ICB, following indirect entries."""
        for _ in range(_MAX_INDIRECT):
            offset = self._block_offset(partition, block, "a file entry")
            data = self._read(offset, self.block_size, "file entry")
            ident = self._tagged(
                data, (_TAG_FE, _TAG_EFE, _TAG_IE, _TAG_TE), block, "a file entry"
            )
            if ident == _TAG_IE:
                # ECMA-167 4/14.7: the next ICB of a strategy 4096 hierarchy.
                _len, block, partition = struct.unpack_from("<IIH", data, 36)
                continue
            if ident == _TAG_TE:
                raise self._corrupt("a file identifier names a terminal entry")
            return self._parse_entry(data, offset, partition=partition)
        raise self._corrupt("its indirect entries form a chain too long")

    def _parse_entry(
        self,
        data: bytes,
        location: int,
        *,
        partition: int = 0,
        physical_part: _Partition | None = None,
    ) -> UdfEntry:
        ident = struct.unpack_from("<H", data, 0)[0]
        file_type = data[16 + 11]
        flags = struct.unpack_from("<H", data, 16 + 18)[0]
        uid, gid, perms = struct.unpack_from("<III", data, 36)
        (info_length,) = struct.unpack_from("<Q", data, 56)
        created: bytes | None
        if ident == _TAG_EFE:
            accessed = data[80:92]
            modified = data[92:104]
            created = data[104:116]
            attribute = data[116:128]
            ea_length, ad_length = struct.unpack_from("<II", data, 208)
            base = 216
        else:
            accessed = data[72:84]
            modified = data[84:96]
            attribute = data[96:108]
            created = None
            ea_length, ad_length = struct.unpack_from("<II", data, 168)
            base = 176
        start = base + ea_length
        if self._budget is not None:
            # What the entry declares, not the block it sits in: a File Entry is
            # weighed as its fixed part, extended attributes and allocation
            # descriptors.
            self._budget.add_udf_bytes(start + ad_length)
        if start + ad_length > len(data) or start < base:
            raise self._corrupt(
                "a file entry declares extended attributes and allocation "
                "descriptors longer than its block"
            )
        if info_length >= 1 << 62:
            raise self._corrupt("a file entry declares an impossible length")
        area = data[start : start + ad_length]
        kind = flags & 0x7
        inline: bytes | None = None
        spans: tuple[Span, ...] = ()
        if kind == _AD_INLINE:
            if info_length > len(area):
                raise self._corrupt("a file's inline data is shorter than its length")
            inline = area[:info_length]
        else:
            spans = self._allocation(area, kind, partition, physical_part, info_length)
        return UdfEntry(
            location=location,
            file_type=file_type,
            uid=None if uid == 0xFFFFFFFF else uid,
            gid=None if gid == 0xFFFFFFFF else gid,
            permissions=perms,
            info_length=info_length,
            modified=modified,
            accessed=accessed,
            attribute=attribute,
            created=created,
            spans=spans,
            inline=inline,
            partition=partition,
        )

    def _allocation(
        self,
        area: bytes,
        kind: int,
        partition: int,
        physical_part: _Partition | None,
        info_length: int,
    ) -> tuple[Span, ...]:
        """The spans of a file's data from its allocation descriptors, following
        Allocation Extent Descriptors, cut to ``info_length``."""
        if kind == _AD_SHORT:
            ad_size = 8
        elif kind == _AD_LONG:
            ad_size = 16
        elif kind == _AD_EXTENDED:
            # UDF 2.01 2.3.10 allows only short and long descriptors; Linux refuses
            # extended ones too. Their recorded and information lengths (data that
            # is partly recorded, or compressed) are not modelled.
            raise UnsupportedFeatureError(
                "UDF file entry uses extended allocation descriptors; reading them "
                "is not supported",
                source_format=ArchiveFormat.ISO,
                archive_name=self._archive_name,
            )
        else:
            raise self._corrupt(f"a file entry has allocation descriptor kind {kind}")
        spans: list[Span] = []
        remaining = info_length
        continuations = 0
        offset = 0
        while remaining > 0:
            if offset + ad_size > len(area):
                break
            raw_length = struct.unpack_from("<I", area, offset)[0]
            extent_type = raw_length >> 30
            length = raw_length & 0x3FFFFFFF
            if kind == _AD_SHORT:
                block = struct.unpack_from("<I", area, offset + 4)[0]
                part = partition
            else:
                block, part = struct.unpack_from("<IH", area, offset + 4)
            offset += ad_size
            if length == 0:
                break
            if extent_type == _EXTENT_NEXT:
                continuations += 1
                if continuations > _MAX_INDIRECT:
                    raise self._corrupt("its allocation extents form a chain too long")
                area = self._allocation_extent(part, block, length, physical_part)
                offset = 0
                continue
            used = min(length, remaining)
            remaining -= used
            if extent_type != _EXTENT_RECORDED:
                spans.append(Span(None, used))
            elif physical_part is not None:
                start = (physical_part.start + block) * self.block_size
                if block + -(-length // self.block_size) > physical_part.length:
                    raise self._corrupt("a file's extent runs past its partition")
                spans.append(Span(start, used))
            else:
                spans.extend(self._extent_spans(part, block, used, "a file's extent"))
        if remaining > 0:
            raise self._corrupt(
                f"a file's extents hold {info_length - remaining} bytes of its "
                f"{info_length}"
            )
        return tuple(spans)

    def _allocation_extent(
        self, partition: int, block: int, length: int, physical_part: _Partition | None
    ) -> bytes:
        """The allocation descriptors an Allocation Extent Descriptor holds."""
        size = self.block_size
        if physical_part is not None:
            offset = (physical_part.start + block) * size
        else:
            offset = self._block_offset(partition, block, "an allocation extent")
        data = self._read(offset, min(length, size), "allocation extent")
        if len(data) < 24:
            raise self._corrupt("an allocation extent is too short to hold its header")
        if self._budget is not None:
            self._budget.add_udf_bytes(len(data))
        self._tagged(data, (_TAG_AED,), block, "an allocation extent")
        (ad_length,) = struct.unpack_from("<I", data, 20)
        if 24 + ad_length > len(data):
            raise self._corrupt("an allocation extent declares more than it holds")
        return data[24 : 24 + ad_length]

    # --- data -------------------------------------------------------------------

    def read_data(self, entry: UdfEntry, limit: int | None, what: str) -> bytes:
        """The data of a small entry (a directory or a symlink), read whole. A
        directory has no ``limit``: the metadata budget bounds it, and
        ``ListingLimits.UNLIMITED`` is the caller's opt-out."""
        if entry.inline is not None:
            return entry.inline
        if limit is not None and entry.info_length > limit:
            raise self._corrupt(f"a {what} is {entry.info_length} bytes long")
        if self._budget is not None:
            self._budget.add_udf_bytes(entry.info_length)
        if any(span.offset is None for span in entry.spans):
            raise self._corrupt(f"a {what} has an extent that is not recorded")
        return b"".join(
            self._read(span.offset, span.length, what)
            for span in entry.spans
            if span.offset is not None
        )

    def symlink_target(self, entry: UdfEntry) -> str:
        """A symlink's target from its path components (ECMA-167 4/14.16)."""
        data = self.read_data(entry, _MAX_SYMLINK_BYTES, "symbolic link")
        parts: list[str] = []
        absolute = False
        offset = 0
        while offset + 4 <= len(data):
            kind, length = data[offset], data[offset + 1]
            ident = data[offset + 4 : offset + 4 + length]
            if len(ident) < length:
                raise self._corrupt("a symbolic link's path component is cut short")
            offset += 4 + length
            if kind in (1, 2) and not parts:
                absolute = True  # the root, or a root the implementation names
            elif kind == 3:
                parts.append("..")
            elif kind == 4:
                parts.append(".")
            elif kind == 5:
                parts.append(decode_dstring(ident))
            else:
                raise self._corrupt(f"a symbolic link has path component type {kind}")
        target = "/".join(parts)
        return "/" + target if absolute else target

    # --- the tree ---------------------------------------------------------------

    def walk(self) -> Iterator[UdfName]:
        """Every name in the tree, as parsed at open (:meth:`_walk`)."""
        return iter(self.names)

    def _walk(self) -> Iterator[UdfName]:
        """Every name in the tree, depth first, directories before their contents.

        Each directory is entered once; a directory naming one of its ancestors (or
        any directory already entered) is refused as a loop. Deleted entries and the
        parent entry are skipped.
        """
        seen = {self.root.location}
        stack: list[tuple[str, bytes, UdfEntry]] = [("", b"", self.root)]
        while stack:
            dirpath, raw_dir, directory = stack.pop()
            children: list[tuple[str, bytes, UdfEntry]] = []
            for name, raw, entry in self._children(directory):
                path = f"{dirpath}{name}"
                raw_path = raw_dir + raw
                if self._budget is not None:
                    # Every full path is kept from open, and a chain of nested
                    # directories makes them grow with the square of the depth, far
                    # past the directory data and File Entry bytes the budget weighs
                    # as they are read: each path is weighed as it is built.
                    self._budget.add_udf_path(path, raw_path)
                if entry.is_directory:
                    if entry.location in seen:
                        raise self._corrupt(
                            f"its directory {path!r} names a directory already listed: "
                            "the directory tree forms a loop"
                        )
                    seen.add(entry.location)
                    children.append((path + "/", raw_path + b"/", entry))
                target = self.symlink_target(entry) if entry.is_symlink else None
                yield UdfName(path, raw_path, entry, target)
            stack.extend(reversed(children))

    def _children(self, directory: UdfEntry) -> Iterator[tuple[str, bytes, UdfEntry]]:
        """``(name, stored name bytes, entry)`` per File Identifier of a directory."""
        data = self.read_data(directory, None, "directory")
        offset = 0
        size = len(data)
        while offset + 38 <= size:
            if not any(data[offset : offset + 16]):
                # Zeros where a descriptor would start end the directory only when
                # nothing follows: UDF 2.01 2.3.4.4 keeps a tag off a block boundary,
                # so a writer leaves no gap, and Linux and 7-Zip refuse one.
                if any(data[offset:]):
                    raise self._corrupt(
                        "a directory has zeros where a file identifier should start"
                    )
                break
            (l_iu,) = struct.unpack_from("<H", data, offset + 36)
            l_fi = data[offset + 19]
            total = (38 + l_iu + l_fi + 3) & ~3
            descriptor = data[offset : offset + min(total, size - offset)]
            self._tagged(descriptor, (_TAG_FID,), None, "a file identifier")
            if 38 + l_iu + l_fi > len(descriptor):
                raise self._corrupt("a file identifier runs past its directory")
            characteristics = data[offset + 18]
            _len, block, part = struct.unpack_from("<IIH", data, offset + 20)
            raw = data[offset + 38 + l_iu : offset + 38 + l_iu + l_fi]
            offset += total
            if characteristics & (_FID_PARENT | _FID_DELETED):
                continue
            if self._budget is not None:
                # The directory's bytes were weighed when it was read.
                self._budget.add_udf_member()
            entry = self._read_entry(part, block)
            if bool(characteristics & _FID_DIRECTORY) != entry.is_directory:
                raise self._corrupt(
                    f"the file identifier {decode_dstring(raw)!r} and its file "
                    "entry disagree on whether it is a directory"
                )
            yield decode_dstring(raw), raw[1:], entry
