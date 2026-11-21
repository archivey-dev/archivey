"""Writes Apple disk images for the tests: UDIF (``.dmg``) around a raw disk, GPT and
APM partition maps, and HFS+ volumes.

No tool on Linux writes filled HFS+ volumes (``mkfs.hfsplus`` makes empty ones and the
userland write tools hang), and nothing writes UDIF, so both writers are here. They aim
for coverage, not size: every UDIF run codec, sparse disks of any size, signed layouts,
and HFS+ volumes with folders, files, symlinks, hard links, extended attributes,
fragmented forks and every decmpfs type, plus hooks to break each structure.
``fsck.hfsplus`` (``hfsprogs``) passes the volumes and 7-Zip reads the images
(``test_dmg_build.py`` checks both when they are installed), so the reader is not only
checked against its own reading of the formats.

Layouts from Apple TN1150 (HFS+), the UDIF structures as 7-Zip's ``DmgHandler.cpp`` reads
them, and UEFI 2.10 §5 (GPT). Field details match the ``hdiutil`` fixtures in
``tests/fixtures/external/dmg_hdiutil/``.
"""

from __future__ import annotations

import bz2
import lzma
import plistlib
import stat
import struct
import uuid
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

SECTOR = 512

# ── CRC-32 over zero bytes, without the bytes ────────────────────────────────────────

_CRC_POLY = 0xEDB88320


def _gf2_times(mat: list[int], vec: int) -> int:
    out = 0
    i = 0
    while vec:
        if vec & 1:
            out ^= mat[i]
        vec >>= 1
        i += 1
    return out


def _gf2_square(mat: list[int]) -> list[int]:
    return [_gf2_times(mat, m) for m in mat]


def crc32_zeros(crc: int, n: int) -> int:
    """``zlib.crc32(bytes(n), crc)`` in O(log n): the zero-extension operator of zlib's
    ``crc32_combine``, so a disk of 2^50 zero bytes costs nothing to checksum."""
    if n <= 0:
        return crc
    # The register is inverted before and after; zero bytes act linearly on the raw
    # register, so apply the operator for n zero bytes to it.
    reg = crc ^ 0xFFFFFFFF
    odd = [_CRC_POLY] + [1 << i for i in range(31)]  # the operator for one zero bit
    even = _gf2_square(odd)  # two zero bits
    odd = _gf2_square(even)  # four zero bits
    while True:
        even = _gf2_square(odd)  # one zero byte on the first pass, then 4, 16, ...
        if n & 1:
            reg = _gf2_times(even, reg)
        n >>= 1
        if not n:
            break
        odd = _gf2_square(even)  # 2, 8, 32, ... zero bytes
        if n & 1:
            reg = _gf2_times(odd, reg)
        n >>= 1
        if not n:
            break
    return reg ^ 0xFFFFFFFF


# ── Codecs for UDIF runs ─────────────────────────────────────────────────────────────

ZERO, RAW, IGNORE = 0, 1, 2
ADC, ZLIB, BZIP2, LZFSE, LZMA = (
    0x80000004,
    0x80000005,
    0x80000006,
    0x80000007,
    0x80000008,
)
COMMENT, END = 0x7FFFFFFE, 0xFFFFFFFF


def adc_literals(data: bytes) -> bytes:
    """Valid ADC made of literal runs only (``1LLLLLLL``, up to 128 bytes each)."""
    out = bytearray()
    for i in range(0, len(data), 128):
        chunk = data[i : i + 128]
        out.append(0x80 | (len(chunk) - 1))
        out += chunk
    return bytes(out)


def adc_one_byte_literals(data: bytes) -> bytes:
    """Valid ADC at its worst: one literal per command, twice the input size."""
    out = bytearray()
    for b in data:
        out += bytes((0x80, b))
    return bytes(out)


def lzvn_literals(data: bytes) -> bytes:
    """Valid raw LZVN made of literal-only opcodes, then the end-of-stream opcode."""
    out = bytearray()
    i = 0
    while i < len(data):
        n = min(len(data) - i, 16 + 255)
        if n >= 16:
            out += bytes((0xE0, n - 16))
        else:
            out.append(0xE0 | n)
        out += data[i : i + n]
        i += n
    return bytes(out + b"\x06" + bytes(7))


def lzfse_stored(data: bytes) -> bytes:
    """An LZFSE stream of one stored ``bvx-`` block and the end block."""
    return b"bvx-" + struct.pack("<I", len(data)) + data + b"bvx$"


def lzfse_lzvn(data: bytes) -> bytes:
    """An LZFSE stream of one ``bvxn`` block (literal-only LZVN) and the end block."""
    payload = lzvn_literals(data)
    return b"bvxn" + struct.pack("<II", len(data), len(payload)) + payload + b"bvx$"


def encode_run(kind: int, data: bytes) -> bytes:
    """The stored bytes of one run of ``kind`` holding ``data``."""
    if kind == RAW:
        return data
    if kind == ZLIB:
        return zlib.compress(data, 9)
    if kind == BZIP2:
        return bz2.compress(data, 9)
    if kind == LZMA:
        return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    if kind == ADC:
        return adc_literals(data)
    if kind == LZFSE:
        return lzfse_lzvn(data)
    if kind in (ZERO, IGNORE):
        return b""
    raise ValueError(f"no encoder for run type {kind:#x}")


# ── UDIF ─────────────────────────────────────────────────────────────────────────────

KOLY = struct.Struct(">4sIIIQQQQQII16sII128sQQ120sII128sIQ12s")
MISH = struct.Struct(">4sIQQQII24sII128sI")
RUN = struct.Struct(">IIQQQQ")
CODE_SIGNATURE_AT = 0x128  # offset u64, length u64 inside the koly block


@dataclass
class Zeros:
    """``sectors`` zero sectors, given by count alone (no bytes in memory)."""

    sectors: int


@dataclass
class Table:
    """One ``blkx`` entry: the sector range it covers and its name, as hdiutil names
    them (``disk image (Apple_HFS : 4)``)."""

    name: str
    first_sector: int
    sector_count: int
    free: bool = False  # Apple_Free: one ignore run, CRC 0, as hdiutil writes it


@dataclass
class WrittenRun:
    """Where one run went, for tests that break it: ``table`` and ``index`` say which
    descriptor, ``stored_at`` is its stored bytes' file offset."""

    table: int
    index: int
    kind: int
    sector: int  # absolute
    sectors: int
    stored_at: int
    stored_length: int


@dataclass
class Udif:
    image: bytes
    runs: list[WrittenRun]
    koly_at: int
    plist_at: int
    plist_length: int
    data_fork_at: int
    data_fork_length: int


def _segments(disk: bytes | Sequence[bytes | Zeros]) -> list[bytes | Zeros]:
    if isinstance(disk, (bytes, bytearray, memoryview)):
        disk = [bytes(disk)]
    out: list[bytes | Zeros] = []
    for seg in disk:
        if isinstance(seg, Zeros):
            out.append(seg)
        else:
            if len(seg) % SECTOR:
                raise ValueError("disk segments must be whole sectors")
            out.append(bytes(seg))
    return out


def _disk_sectors(segments: Sequence[bytes | Zeros]) -> int:
    return sum(
        s.sectors if isinstance(s, Zeros) else len(s) // SECTOR for s in segments
    )


def _slice(
    segments: Sequence[bytes | Zeros], first: int, count: int
) -> list[bytes | Zeros]:
    """The sectors ``[first, first + count)`` of the disk, as segments."""
    out: list[bytes | Zeros] = []
    pos = 0
    end = first + count
    for seg in segments:
        n = seg.sectors if isinstance(seg, Zeros) else len(seg) // SECTOR
        a, b = max(first, pos), min(end, pos + n)
        if a < b:
            if isinstance(seg, Zeros):
                out.append(Zeros(b - a))
            else:
                out.append(seg[(a - pos) * SECTOR : (b - pos) * SECTOR])
        pos += n
    return out


def write_udif(
    disk: bytes | Sequence[bytes | Zeros],
    *,
    tables: Sequence[Table] | None = None,
    codec: int = ZLIB,
    run_sectors: int = 2048,
    choose: Callable[[int, bytes], int] | None = None,
    encode: Callable[[int, bytes], bytes] = encode_run,
    data_fork_at: int = 0,
    mish_data_offset: int = 0,
    koly_at_front: bool = False,
    code_signature: bytes | None = None,
    trailing: bytes = b"",
    sector_count: int | None = None,
    patch_koly: Callable[[bytearray], None] | None = None,
    patch_mish: Callable[[int, bytearray], None] | None = None,
    patch_plist: Callable[[dict], None] | None = None,
    plist_bytes: bytes | None = None,
) -> Udif:
    """A UDIF image of ``disk``.

    ``tables`` split the disk into ``blkx`` entries (default: one entry over the whole
    disk). Each table is cut into runs of at most ``run_sectors``: an all-zero run is a
    zero-fill run, a ``Zeros`` segment always is one, and the others use ``codec``, or
    whatever ``choose(absolute_sector, bytes)`` returns. ``encode(kind, bytes)`` makes the
    stored bytes, so a test can store anything.

    Layout options: ``data_fork_at`` puts that many filler bytes before the data fork and
    ``mish_data_offset`` gives every table a non-zero data offset (both move the stored
    bytes as 7-Zip computes them); ``koly_at_front`` writes the old layout with the
    ``koly`` block at offset 0; ``code_signature`` stores a blob between the property
    list and the ``koly`` block and records it in the ``koly`` block; ``trailing`` adds
    bytes after everything. The ``patch_*`` hooks edit each structure before it is
    written, and ``plist_bytes`` replaces the property list outright.
    """
    segments = _segments(disk)
    total = _disk_sectors(segments)
    if tables is None:
        tables = [Table("whole disk (Apple_HFS : 0)", 0, total)]
    # ``data_fork`` holds the filler before the data fork (``data_fork_at``), then the
    # fork, which starts with ``mish_data_offset`` filler bytes so that every stored
    # offset, counted from the fork plus the table's data offset, stays positive.
    lead = 0 if koly_at_front else data_fork_at
    data_fork = bytearray(b"\xa5" * lead + b"\x5a" * mish_data_offset)
    runs: list[WrittenRun] = []
    blkx = []
    checksums = bytearray()
    prefix = SECTOR if koly_at_front else 0  # the koly block comes first
    for t_index, table in enumerate(tables):
        table_runs: list[tuple[int, int, int, int, int, int]] = []
        crc = 0
        base = lead + mish_data_offset  # stored offsets count from here
        if table.free:
            pieces: list[tuple[int, int, bytes | None]] = [
                (table.first_sector, table.sector_count, None)
            ]
        else:
            pieces = []
            pos = table.first_sector
            for seg in _slice(segments, table.first_sector, table.sector_count):
                if isinstance(seg, Zeros):
                    pieces.append((pos, seg.sectors, b""))
                    pos += seg.sectors
                    continue
                for off in range(0, len(seg), run_sectors * SECTOR):
                    chunk = seg[off : off + run_sectors * SECTOR]
                    pieces.append((pos, len(chunk) // SECTOR, chunk))
                    pos += len(chunk) // SECTOR
        for sector, count, chunk in pieces:
            if chunk is None:
                kind = IGNORE
                stored = b""
            elif chunk == b"" or not any(chunk):
                kind = ZERO
                stored = b""
                crc = crc32_zeros(crc, count * SECTOR)
            else:
                kind = choose(sector, chunk) if choose else codec
                if kind in (ZERO, IGNORE):
                    stored = b""
                    if kind == ZERO:
                        crc = crc32_zeros(crc, count * SECTOR)
                else:
                    stored = encode(kind, chunk)
                    crc = zlib.crc32(chunk, crc)
            offset = len(data_fork) - base
            runs.append(
                WrittenRun(
                    t_index,
                    len(table_runs),
                    kind,
                    sector,
                    count,
                    prefix + len(data_fork),
                    len(stored),
                )
            )
            table_runs.append(
                (kind, 0, sector - table.first_sector, count, offset, len(stored))
            )
            data_fork += stored
        end_offset = len(data_fork) - base
        table_runs.append((END, 0, table.sector_count, 0, end_offset, 0))
        if table.free:
            crc = 0
        checksum = struct.pack(">I", crc).ljust(128, b"\0")
        checksums += struct.pack(">I", crc)
        mish = bytearray(
            MISH.pack(
                b"mish",
                1,
                table.first_sector,
                table.sector_count,
                mish_data_offset,
                0 if table.free else run_sectors + 1,
                t_index,
                bytes(24),
                2,
                32,
                checksum,
                len(table_runs),
            )
        )
        for r in table_runs:
            mish += RUN.pack(*r)
        if patch_mish:
            patch_mish(t_index, mish)
        blkx.append(
            {
                "Attributes": "0x0050",
                "CFName": table.name,
                "Data": bytes(mish),
                "ID": str(t_index - 1),
                "Name": table.name,
            }
        )
    plist = {"resource-fork": {"blkx": blkx, "plst": [_PLST]}}
    if patch_plist:
        patch_plist(plist)
    xml = plist_bytes if plist_bytes is not None else plistlib.dumps(plist)
    data_crc = zlib.crc32(data_fork[lead:])
    fork_at = prefix + lead
    fork_len = len(data_fork) - lead
    body = bytearray(data_fork)
    plist_at = prefix + len(body)
    body += xml
    sig_at = sig_len = 0
    if code_signature is not None:
        sig_at, sig_len = prefix + len(body), len(code_signature)
        body += code_signature
    koly = bytearray(
        KOLY.pack(
            b"koly",
            4,
            512,
            1,
            0,
            fork_at,
            fork_len,
            0,
            0,
            1,
            1,
            uuid.UUID(int=0x5A).bytes,
            2,
            32,
            struct.pack(">I", data_crc).ljust(128, b"\0"),
            plist_at,
            len(xml),
            bytes(120),
            2,
            32,
            struct.pack(">I", zlib.crc32(checksums)).ljust(128, b"\0"),
            1,
            total if sector_count is None else sector_count,
            bytes(12),
        )
    )
    struct.pack_into(">QQ", koly, CODE_SIGNATURE_AT, sig_at, sig_len)
    if patch_koly:
        patch_koly(koly)
    if koly_at_front:
        image = bytes(koly) + bytes(body) + trailing
        koly_at = 0
    else:
        image = bytes(body) + bytes(koly) + trailing
        koly_at = len(body)
    return Udif(image, runs, koly_at, plist_at, len(xml), fork_at, fork_len)


# The ``plst`` entry hdiutil writes: 0x408 bytes, zero but for ``0x0001 0x0001`` at 0x204.
_PLST = {
    "Attributes": "0x0050",
    "Data": bytes(0x204) + b"\x00\x01\x00\x01" + bytes(0x408 - 0x208),
    "ID": "0",
    "Name": "",
}


# ── Partition maps ───────────────────────────────────────────────────────────────────

HFS_GUID = uuid.UUID("48465300-0000-11AA-AA11-00306543ECAC")
APFS_GUID = uuid.UUID("7C3457EF-0000-11AA-AA11-00306543ECAC")


@dataclass
class Partition:
    """A partition of ``data`` (whole sectors) with its GPT type or APM type name."""

    data: bytes | Zeros
    name: str = "disk image"
    gpt_type: uuid.UUID = HFS_GUID
    apm_type: str = "Apple_HFS"

    @property
    def sectors(self) -> int:
        if isinstance(self.data, Zeros):
            return self.data.sectors
        if len(self.data) % SECTOR:
            raise ValueError("partition data must be whole sectors")
        return len(self.data) // SECTOR


@dataclass
class Disk:
    """A partitioned disk, and the ``blkx`` tables hdiutil would write for it."""

    segments: list[bytes | Zeros]
    tables: list[Table]
    starts: list[int]  # each partition's first sector


def _guid_le(u: uuid.UUID) -> bytes:
    return u.bytes_le


def write_gpt(
    partitions: Sequence[Partition],
    *,
    first: int = 40,
    gap: int = 0,
    tail: int = 7,
    patch_header: Callable[[bytearray], None] | None = None,
    patch_entries: Callable[[bytearray], None] | None = None,
) -> Disk:
    """A GPT disk as hdiutil lays it out: protective MBR, header at sector 1, 128 entries
    of 128 bytes from sector 2, the first partition at sector ``first`` (40), ``gap``
    free sectors between partitions, ``tail`` free sectors after the last one (hdiutil
    leaves 7 on a disk of its default size, fewer on one it sizes to fit), then the
    backup entries and header."""
    starts = []
    pos = first
    for p in partitions:
        starts.append(pos)
        pos += p.sectors + gap
    last_used = pos - gap
    total = last_used + tail + 32 + 1
    entries = bytearray(128 * 128)
    for i, (p, start) in enumerate(zip(partitions, starts, strict=True)):
        e = (
            _guid_le(p.gpt_type)
            + _guid_le(uuid.UUID(int=i + 1))
            + struct.pack("<QQQ", start, start + p.sectors - 1, 0)
            + p.name.encode("utf-16-le").ljust(72, b"\0")
        )
        entries[128 * i : 128 * (i + 1)] = e
    if patch_entries:
        patch_entries(entries)
    entries_crc = zlib.crc32(entries)

    def header(mine: int, other: int, entries_at: int) -> bytes:
        h = bytearray(
            struct.pack(
                "<8sIIIIQQQQ16sQIII",
                b"EFI PART",
                0x10000,
                92,
                0,
                0,
                mine,
                other,
                34,
                total - 34,
                uuid.UUID(int=0xD15C).bytes_le,
                entries_at,
                128,
                128,
                entries_crc,
            )
        )
        struct.pack_into("<I", h, 16, zlib.crc32(h))
        if patch_header and mine == 1:
            patch_header(h)
        return bytes(h).ljust(SECTOR, b"\0")

    # The protective MBR entry; hdiutil writes FE FF FF for both CHS addresses.
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack(
        "<B3sB3sII",
        0,
        b"\xfe\xff\xff",
        0xEE,
        b"\xfe\xff\xff",
        1,
        min(total - 1, 0xFFFFFFFF),
    )
    mbr[510:512] = b"\x55\xaa"
    segments: list[bytes | Zeros] = [
        bytes(mbr),
        header(1, total - 1, 2),
        bytes(entries),
        bytes((first - 34) * SECTOR),
    ]
    tables = [
        Table("Protective Master Boot Record (MBR : 0)", 0, 1),
        Table("GPT Header (Primary GPT Header : 1)", 1, 1),
        Table("GPT Partition Data (Primary GPT Table : 2)", 2, 32),
        Table(" (Apple_Free : 3)", 34, first - 34, free=True),
    ]
    n = 4
    for i, (p, start) in enumerate(zip(partitions, starts, strict=True)):
        segments.append(p.data)
        tables.append(Table(f"{p.name} (Apple_{_kind(p)} : {n})", start, p.sectors))
        n += 1
        if gap and i + 1 < len(partitions):
            segments.append(bytes(gap * SECTOR))
            tables.append(
                Table(f" (Apple_Free : {n})", start + p.sectors, gap, free=True)
            )
            n += 1
    segments.append(bytes(tail * SECTOR))
    tables.append(Table(f" (Apple_Free : {n})", last_used, tail, free=True))
    segments.append(bytes(entries))
    tables.append(
        Table(f"GPT Partition Data (Backup GPT Table : {n + 1})", last_used + tail, 32)
    )
    segments.append(header(total - 1, 1, last_used + tail))
    tables.append(Table(f"GPT Header (Backup GPT Header : {n + 2})", total - 1, 1))
    return Disk(segments, tables, starts)


def _kind(p: Partition) -> str:
    return "APFS" if p.gpt_type == APFS_GUID else "HFS"


def write_apm(
    partitions: Sequence[Partition],
    *,
    patch_map: Callable[[int, bytearray], None] | None = None,
) -> Disk:
    """An Apple Partition Map disk: driver descriptor at sector 0, the map entries from
    sector 1 (the map's own entry first), then each partition."""
    n_entries = len(partitions) + 1
    map_sectors = max(63, n_entries)
    starts = []
    pos = 1 + map_sectors
    for p in partitions:
        starts.append(pos)
        pos += p.sectors
    total = pos
    ddm = bytearray(SECTOR)
    struct.pack_into(">2sHI", ddm, 0, b"ER", SECTOR, total)

    def entry(index: int, start: int, count: int, name: str, kind: str) -> bytearray:
        e = bytearray(SECTOR)
        struct.pack_into(
            ">2sHIII32s32sIII",
            e,
            0,
            b"PM",
            0,
            n_entries,
            start,
            count,
            name.encode("ascii").ljust(32, b"\0"),
            kind.encode("ascii").ljust(32, b"\0"),
            0,
            count,
            0x33,
        )
        if patch_map:
            patch_map(index, e)
        return e

    pmap = entry(0, 1, map_sectors, "Apple", "Apple_partition_map")
    for i, (p, start) in enumerate(zip(partitions, starts, strict=True)):
        pmap += entry(i + 1, start, p.sectors, p.name, p.apm_type)
    pmap += bytes((map_sectors - n_entries) * SECTOR)
    segments: list[bytes | Zeros] = [bytes(ddm), bytes(pmap)]
    tables = [
        Table("Driver Descriptor Map (DDM : 0)", 0, 1),
        Table("Apple (Apple_partition_map : 1)", 1, map_sectors),
    ]
    for i, (p, start) in enumerate(zip(partitions, starts, strict=True)):
        segments.append(p.data)
        tables.append(Table(f"{p.name} ({p.apm_type} : {i + 2})", start, p.sectors))
    return Disk(segments, tables, starts)


def write_bare(partition: Partition) -> Disk:
    """A disk that is one partition with no map (``hdiutil -layout NONE``)."""
    return Disk(
        [partition.data],
        [Table(f"{partition.name} ({partition.apm_type} : 0)", 0, partition.sectors)],
        [0],
    )


# ── HFS+ ─────────────────────────────────────────────────────────────────────────────

HFS_EPOCH_OFFSET = 2082844800  # seconds from 1904-01-01 to 1970-01-01
ROOT_PARENT, ROOT_FOLDER = 1, 2
EXTENTS_ID, CATALOG_ID, BAD_BLOCKS_ID, ALLOCATION_ID, STARTUP_ID, ATTRIBUTES_ID = (
    3,
    4,
    5,
    6,
    7,
    8,
)
FIRST_USER_ID = 16
FOLDER, FILE, FOLDER_THREAD, FILE_THREAD = 1, 2, 3, 4
PRIVATE_DATA = "\0\0\0\0HFS+ Private Data"
PRIVATE_DIR_DATA = ".HFS+ Private Directory Data\r"
UF_COMPRESSED = 0x20
DECMPFS_BLOCK = 0x10000


def hfs_time(unix: int) -> int:
    return (unix + HFS_EPOCH_OFFSET) & 0xFFFFFFFF


@dataclass
class Node:
    """One entry of the tree to write. ``path`` is ``/``-separated from the volume
    root, so a ``/`` in ``path`` is always a separator. To store a ``/`` in a name, pass
    the name's UTF-16BE units in ``raw_name``; the POSIX view (mount, 7-Zip) shows that
    stored ``/`` as ``:``."""

    path: str
    kind: str = "file"  # file, dir, symlink, hardlink, fifo, chardev
    data: bytes = b""
    target: str = ""  # symlink target, or the path of a hard link's first file
    mode: int | None = None
    uid: int = 501
    gid: int = 20
    mtime: int = 1_700_000_000
    xattrs: dict[str, bytes] = field(default_factory=dict)
    compression: int | None = None  # a decmpfs type: 3, 4, 7, 8, 9, 10, 11, 12
    fragment: int = 0  # write the data fork as this many separate extents
    raw_name: bytes | None = None  # the UTF-16BE name units as stored, overriding path
    resource_fork: bytes = b""
    rdev: int = 0


@dataclass
class CatalogRecord:
    """A catalog leaf record before packing: tests edit these through ``patch_catalog``
    (a parent loop, a missing thread, a bad name)."""

    parent: int
    name: bytes  # UTF-16BE
    body: bytearray

    def key(self) -> bytes:
        return (
            struct.pack(">HIH", 6 + len(self.name), self.parent, len(self.name) // 2)
            + self.name
        )


@dataclass
class Hfs:
    """A written volume and where its parts went, for tests that break it."""

    volume: bytes
    block_size: int
    cnids: dict[str, int]  # path -> CNID ("" is the root)
    forks: dict[str, list[tuple[int, int]]]  # path -> data fork extents (block, count)
    catalog_at: int  # byte offset of the catalog file's first block
    catalog_node_size: int
    catalog_leaves: list[int]  # node numbers of the catalog leaves, in order
    attributes_at: int
    extents_at: int


def _compare_name(name: bytes, case_sensitive: bool) -> tuple[int, ...]:
    units = struct.unpack(f">{len(name) // 2}H", name)
    if case_sensitive:
        return units
    # FastUnicodeCompare folds case and sorts U+0000 last (its table maps it to 0xFFFF,
    # which puts the private data folder after every other root entry). ASCII folding
    # is enough for the names tests use.
    return tuple(
        0xFFFF if u == 0 else u + 32 if 0x41 <= u <= 0x5A else u for u in units
    )


def _utf16(name: str) -> bytes:
    return name.encode("utf-16-be", "surrogatepass")


def _decmpfs(kind: int, data: bytes) -> tuple[bytes, bytes]:
    """The ``com.apple.decmpfs`` value and the resource fork for ``data`` stored as
    decmpfs ``kind``."""
    header = b"fpmc" + struct.pack("<IQ", kind, len(data))
    if kind == 3:
        return header + zlib.compress(data, 9), b""
    if kind == 9:  # stored behind the 0xCC marker; 7-Zip reads type 9 only with it
        return header + b"\xcc" + data, b""
    if kind == 7:
        return header + lzvn_literals(data), b""
    if kind == 11:
        return header + lzfse_stored(data), b""
    blocks = [data[i : i + DECMPFS_BLOCK] for i in range(0, len(data), DECMPFS_BLOCK)]

    def chunk(encoded: bytes, block: bytes, stored_marker: bytes) -> bytes:
        # A chunk that would not fit in 64 KiB is stored behind its marker byte (0xFF
        # for types 4 and 12, 0x06 for type 8), as macOS stores a chunk that does not
        # shrink; 7-Zip refuses a longer chunk. A full 64 KiB literal-only chunk always
        # takes this path.
        return encoded if len(encoded) <= DECMPFS_BLOCK else stored_marker + block

    if kind == 4:
        encoded = [chunk(zlib.compress(b, 9), b, b"\xff") for b in blocks]
        table = struct.pack("<I", len(encoded))
        off = 4 + 8 * len(encoded)
        body = bytearray()
        for e in encoded:
            table += struct.pack("<II", off, len(e))
            off += len(e)
            body += e
        payload = table + body
        rsrc_data = struct.pack(">I", len(payload)) + payload
        # A resource fork: 256-byte header, the data, then the 50-byte resource map that
        # macOS (and afsctool) writes for one 'cmpf' resource with ID 1 and no name.
        rmap = (
            bytes(24)
            + struct.pack(">HHH", 0x1C, 0x32, 0)
            + b"cmpf"
            + struct.pack(">HHhH", 0, 0x0A, 1, 0xFFFF)
            + bytes(8)
        )
        head = struct.pack(
            ">IIII", 0x100, 0x100 + len(rsrc_data), len(rsrc_data), len(rmap)
        )
        rsrc = head + bytes(0x100 - 16) + rsrc_data + rmap
        return header, rsrc
    if kind in (8, 10, 12):
        if kind == 8:
            encoded = [chunk(lzvn_literals(b), b, b"\x06") for b in blocks]
        elif kind == 12:
            encoded = [chunk(lzfse_stored(b), b, b"\xff") for b in blocks]
        else:
            # Type 10: the type 8 offset table over raw blocks, as the prototype reads
            # it. This is an unverified stand-in: no tool here reads type 10, so the
            # layout must be checked on a real file before anyone relies on it (§6.6).
            encoded = list(blocks)
        offsets = [4 * (len(encoded) + 1)]
        for e in encoded:
            offsets.append(offsets[-1] + len(e))
        return header, struct.pack(f"<{len(offsets)}I", *offsets) + b"".join(encoded)
    raise ValueError(f"no decmpfs writer for type {kind}")


class _Allocator:
    def __init__(self, first: int) -> None:
        self.next = first
        self.used: list[tuple[int, int]] = []

    def take(self, blocks: int, *, hole: bool = False) -> tuple[int, int]:
        start = self.next
        self.next += blocks
        if blocks and not hole:
            self.used.append((start, blocks))
        return start, blocks


def _fork(size: int, extents: Sequence[tuple[int, int]], block_size: int) -> bytes:
    total = sum(c for _s, c in extents)
    first8 = list(extents[:8]) + [(0, 0)] * (8 - min(8, len(extents)))
    out = struct.pack(">QII", size, block_size, total)
    for s, c in first8:
        out += struct.pack(">II", s, c)
    return out


def _btree(
    records: Sequence[tuple[bytes, bytes]],
    node_size: int,
    *,
    max_key: int,
    btree_type: int,
    compare_type: int,
    variable_index_keys: bool,
    min_nodes: int,
    block_size: int,
    patch_nodes: Callable[[list[bytearray]], None] | None = None,
) -> tuple[bytes, list[int]]:
    """A B-tree file: header node, leaves holding ``records`` (key, data) in the order
    given, and index levels above them. Returns the file and the leaf node numbers."""
    leaves: list[list[bytes]] = []
    current: list[bytes] = []
    used = 14
    for key, data in records:
        rec = key + data
        if 14 + len(rec) + 1 + 4 > node_size:
            raise ValueError(f"a B-tree record of {len(rec)} bytes does not fit a node")
        if used + len(rec) + 2 * (len(current) + 2) > node_size and current:
            leaves.append(current)
            current, used = [], 14
        current.append(rec)
        used += len(rec) + (len(rec) & 1)
    if current:
        leaves.append(current)
    # Node numbers: 0 header, then leaves, then index nodes bottom-up.
    next_node = 1
    leaf_numbers = list(range(next_node, next_node + len(leaves)))
    next_node += len(leaves)
    levels: list[tuple[list[int], list[list[bytes]]]] = [(leaf_numbers, leaves)]
    while len(levels[-1][0]) > 1:
        below_numbers, below = levels[-1]
        index_recs = []
        for number, node_recs in zip(below_numbers, below, strict=True):
            first = node_recs[0]
            (klen,) = struct.unpack_from(">H", first)
            key = first[: 2 + klen]
            if not variable_index_keys:
                key = struct.pack(">H", max_key) + key[2:].ljust(max_key, b"\0")
            index_recs.append(key + struct.pack(">I", number))
        nodes: list[list[bytes]] = []
        current, used = [], 14
        for rec in index_recs:
            if used + len(rec) + 2 * (len(current) + 2) > node_size and current:
                nodes.append(current)
                current, used = [], 14
            current.append(rec)
            used += len(rec) + (len(rec) & 1)
        nodes.append(current)
        numbers = list(range(next_node, next_node + len(nodes)))
        next_node += len(nodes)
        levels.append((numbers, nodes))
    total_nodes = max(next_node, min_nodes)
    per_block = max(1, block_size // node_size)  # the file fills whole blocks
    total_nodes = -(-total_nodes // per_block) * per_block
    buf = [bytearray(node_size) for _ in range(total_nodes)]
    for height, (numbers, nodes) in enumerate(levels, start=1):
        kind = -1 if height == 1 else 0
        for i, (number, recs) in enumerate(zip(numbers, nodes, strict=True)):
            flink = numbers[i + 1] if i + 1 < len(numbers) else 0
            blink = numbers[i - 1] if i else 0
            _pack_node(buf[number], flink, blink, kind, height, recs)
    depth = len(levels) if records else 0
    root = levels[-1][0][0] if records else 0
    header = struct.pack(
        ">HIIIIHHIIHIBBI64s",
        depth,
        root,
        len(records),
        leaf_numbers[0] if records else 0,
        leaf_numbers[-1] if records else 0,
        node_size,
        max_key,
        total_nodes,
        total_nodes - next_node,
        0,
        node_size,
        btree_type,
        compare_type,
        0x2 | (0x4 if variable_index_keys else 0),  # big keys, variable index keys
        bytes(64),
    )
    map_size = node_size - 14 - len(header) - 128 - 8
    bitmap = bytearray(map_size)
    for n in range(next_node):
        bitmap[n // 8] |= 0x80 >> (n % 8)
    _pack_node(buf[0], 0, 0, 1, 0, [header, bytes(128), bytes(bitmap)])
    if patch_nodes:
        patch_nodes(buf)
    return b"".join(buf), leaf_numbers if records else []


def _pack_node(
    node: bytearray,
    flink: int,
    blink: int,
    kind: int,
    height: int,
    recs: Sequence[bytes],
) -> None:
    struct.pack_into(">IIbBHH", node, 0, flink, blink, kind, height, len(recs), 0)
    pos = 14
    offsets = []
    for r in recs:
        offsets.append(pos)
        node[pos : pos + len(r)] = r
        pos += len(r)
        pos += pos & 1
    offsets.append(pos)
    size = len(node)
    for i, off in enumerate(offsets):
        struct.pack_into(">H", node, size - 2 * (i + 1), off)


JOURNAL_STATES = ("clean", "pending", "need-init", "external")
JOURNAL_SIZE = 512 * 1024
_JHDR_SIZE = 512  # the journal header's sector
_BLHDR_SIZE = 4096  # one block list header
_BLHDR_CHECKSUM_SIZE = 32  # header + binfo[0], BLHDR_CHECKSUM_SIZE in hfs_journal.c


def _journal_checksum(data: bytes) -> int:
    """``calc_checksum`` of Apple's ``vfs_journal.c``, on a 32-bit int."""
    cksum = 0
    for b in data:
        cksum = ((cksum << 8) ^ (cksum + b)) & 0xFFFFFFFF
    return ~cksum & 0xFFFFFFFF


def _write_journal(
    volume: bytearray, state: str, *, info_at: int, journal_at: int
) -> None:
    """The journal info block (big-endian, TN1150) and the journal header (written
    little-endian, as on an Intel Mac; ``endian`` says which)."""
    flags = {"clean": 1, "pending": 1, "need-init": 1 | 4, "external": 2}[state]
    struct.pack_into(
        ">I32sQQ", volume, info_at, flags, bytes(32), journal_at, JOURNAL_SIZE
    )
    start = end = _JHDR_SIZE
    if state == "pending":
        # One transaction of one block list header that lists no blocks.
        end = start + _BLHDR_SIZE
        blhdr = bytearray(_BLHDR_SIZE)
        struct.pack_into("<HHII", blhdr, 0, _BLHDR_SIZE // 16 - 1, 1, _BLHDR_SIZE, 0)
        struct.pack_into(
            "<I", blhdr, 8, _journal_checksum(bytes(blhdr[:_BLHDR_CHECKSUM_SIZE]))
        )
        volume[journal_at + start : journal_at + end] = blhdr
    header = bytearray(
        struct.pack(
            "<IIQQQIII",
            0x4A4E4C78,  # "JNLx"
            0x12345678,
            start,
            end,
            JOURNAL_SIZE,
            _BLHDR_SIZE,
            0,
            _JHDR_SIZE,
        )
    )
    struct.pack_into("<I", header, 36, _journal_checksum(bytes(header)))
    volume[journal_at : journal_at + len(header)] = header


def write_hfsplus(
    nodes: Sequence[Node],
    *,
    name: str = "Test",
    block_size: int = 4096,
    hfsx: bool = False,
    case_sensitive: bool | None = None,
    node_size: int = 4096,
    spare_blocks: int = 16,
    journal: str | None = None,
    dirty: bool = False,
    patch_catalog: Callable[[list[CatalogRecord]], None] | None = None,
    patch_catalog_nodes: Callable[[list[bytearray]], None] | None = None,
    patch_header: Callable[[bytearray], None] | None = None,
    patch_volume: Callable[[bytearray, Hfs], None] | None = None,
    attributes_in_fork: Sequence[str] = (),
) -> Hfs:
    """An HFS+ (or with ``hfsx``, HFSX) volume holding ``nodes``.

    Folders that a path needs are made on the way. A ``hardlink`` node names its first
    file in ``target``; that file's data moves to ``iNode<n>`` in the private folder and
    both paths become links to it, as macOS writes them. A ``compression`` writes the file
    through decmpfs with that type. ``fragment`` splits the data fork into that many
    extents (more than 8 go to the extents overflow file). Extended attributes are inline
    records, or fork records for the names in ``attributes_in_fork``.

    The hooks break things: ``patch_catalog`` edits the leaf records before they are
    sorted and packed, ``patch_catalog_nodes`` edits the packed nodes (a leaf loop, bad
    record offsets), ``patch_header`` the volume header, and ``patch_volume`` the whole
    volume once it is laid out.

    ``journal`` writes a journaled volume, with ``.journal_info_block`` and ``.journal``
    in the root as macOS makes them, in one of the states of design §6.1: ``"clean"``
    (an empty journal), ``"pending"`` (transactions not yet replayed), ``"need-init"``
    or ``"external"`` (the journal info flags say so).
    """
    if journal not in (None, *JOURNAL_STATES):
        raise ValueError(f"journal must be one of {JOURNAL_STATES}")
    if journal:
        nodes = [
            *nodes,
            Node(".journal_info_block", data=bytes(block_size)),
            Node(".journal", data=bytes(JOURNAL_SIZE)),
        ]
    if case_sensitive is None:
        case_sensitive = hfsx
    now = hfs_time(1_700_000_000)
    cnids: dict[str, int] = {"": ROOT_FOLDER}
    kinds: dict[str, str] = {"": "dir"}
    order: list[Node] = []
    next_id = FIRST_USER_ID
    by_path = {n.path.strip("/"): n for n in nodes}

    def ensure_dir(path: str) -> None:
        nonlocal next_id
        if path in cnids:
            return
        parent = path.rpartition("/")[0]
        ensure_dir(parent)
        cnids[path] = next_id
        kinds[path] = "dir"
        next_id += 1
        order.append(by_path.get(path) or Node(path, kind="dir"))

    links: dict[str, list[str]] = {}  # first file path -> link paths
    for n in nodes:
        p = n.path.strip("/")
        if n.kind == "hardlink":
            links.setdefault(n.target.strip("/"), []).append(p)
    has_links = bool(links)
    private_id = 0
    if has_links:
        private_id = next_id
        next_id += 1
    for n in nodes:
        p = n.path.strip("/")
        if p in cnids:
            continue
        ensure_dir(p.rpartition("/")[0])
        if n.kind == "dir":
            ensure_dir(p)
            continue
        cnids[p] = next_id
        kinds[p] = n.kind
        next_id += 1
        order.append(n)

    # The first 1536 bytes (boot blocks, volume header) and the last 1024 (alternate
    # header, reserved) are allocated blocks of their own.
    head_blocks = -(-1536 // block_size)
    tail_blocks = -(-1024 // block_size)
    alloc = _Allocator(head_blocks)
    # Data forks first, so the B-trees know every extent.
    forks: dict[str, list[tuple[int, int]]] = {}
    rsrc_forks: dict[str, list[tuple[int, int]]] = {}
    contents: list[tuple[int, bytes]] = []  # (block, bytes)
    overflow: list[
        tuple[int, int, int, list[tuple[int, int]]]
    ] = []  # cnid, fork, start
    xattrs: dict[int, dict[str, bytes]] = {}
    file_bodies: dict[str, tuple[bytes, bytes, int]] = {}  # path -> data, rsrc, flags

    def place(
        path: str, cnid: int, data: bytes, fork_type: int, pieces: int
    ) -> list[tuple[int, int]]:
        blocks = -(-len(data) // block_size)
        if not blocks:
            return []
        pieces = max(1, min(pieces or 1, blocks))
        extents = []
        per = blocks // pieces
        done = 0
        for i in range(pieces):
            count = per if i + 1 < pieces else blocks - done
            start, _ = alloc.take(count)
            if pieces > 1:
                alloc.take(1, hole=True)  # a free block, so the extents cannot merge
            extents.append((start, count))
            contents.append(
                (start, data[done * block_size : (done + count) * block_size])
            )
            done += count
        if len(extents) > 8:
            rest = extents[8:]
            start_block = sum(c for _s, c in extents[:8])
            for i in range(0, len(rest), 8):
                group = rest[i : i + 8]
                overflow.append((cnid, fork_type, start_block, group))
                start_block += sum(c for _s, c in group)
        return extents

    for n in order:
        p = n.path.strip("/")
        if kinds[p] in ("dir",):
            if n.xattrs:
                xattrs[cnids[p]] = dict(n.xattrs)
            continue
        data, rsrc = n.data, n.resource_fork
        flags = 0
        ex = dict(n.xattrs)
        if n.kind == "symlink":
            data = n.target.encode("utf-8", "surrogateescape")
        elif n.kind == "hardlink":
            data = b""
        if n.compression is not None and n.kind == "file":
            value, rsrc = _decmpfs(n.compression, data)
            ex["com.apple.decmpfs"] = value
            data = b""
            flags |= UF_COMPRESSED
        file_bodies[p] = (data, rsrc, flags)
        target_cnid = cnids[p]
        forks[p] = place(p, target_cnid, data, 0, n.fragment)
        rsrc_forks[p] = place(p, target_cnid, rsrc, 0xFF, 0)
        if ex:
            xattrs[target_cnid] = ex

    # Attribute fork values (``attributes_in_fork``) need blocks too.
    attr_fork_extents: dict[tuple[int, str], tuple[int, list[tuple[int, int]]]] = {}
    for cnid, ex in xattrs.items():
        for xname, value in ex.items():
            if xname in attributes_in_fork:
                start, count = alloc.take(-(-len(value) // block_size))
                contents.append((start, value))
                attr_fork_extents[(cnid, xname)] = (len(value), [(start, count)])

    # ── catalog records ──
    records: list[CatalogRecord] = []
    counts = {"files": 0, "folders": 0}
    children: dict[int, int] = {}

    def parent_of(path: str) -> int:
        return cnids[path.rpartition("/")[0]]

    def bsd(
        n: Node | None, default_mode: int, special: int = 0, owner_flags: int = 0
    ) -> bytes:
        mode = default_mode if n is None or n.mode is None else n.mode
        uid = 501 if n is None else n.uid
        gid = 20 if n is None else n.gid
        return struct.pack(">IIBBHI", uid, gid, 0, owner_flags, mode, special)

    def folder_record(
        cnid: int, n: Node | None, valence: int, finder: bytes = bytes(16)
    ) -> bytearray:
        t = hfs_time(n.mtime) if n else now
        # HFSX keeps each folder's count of direct subfolders (kHFSHasFolderCountMask
        # and the field TN1150 calls reserved2); fsck_hfs requires it there.
        flags, folder_count = (0x0010, subfolders.get(cnid, 0)) if hfsx else (0, 0)
        return bytearray(
            struct.pack(">hHII5I", FOLDER, flags, valence, cnid, t, t, t, t, 0)
            + bsd(n, stat.S_IFDIR | 0o755)
            + finder
            + bytes(16)
            + struct.pack(">II", 0, folder_count)
        )

    def file_record(
        cnid: int,
        n: Node | None,
        *,
        mode: int,
        ftype: bytes = b"\0\0\0\0",
        creator: bytes = b"\0\0\0\0",
        special: int = 0,
        flags: int = 0x0002,
        owner_flags: int = 0,
        data_fork: bytes = bytes(80),
        rsrc_fork: bytes = bytes(80),
        finder_flags: int = 0,
        first_link: int = 0,
        prev_link: int = 0,
        next_link: int = 0,
    ) -> bytearray:
        # The link chain reuses fields: the inode's first link ID is reserved1, and a
        # link's previous and next link IDs take its owner and group IDs, as the hdiutil
        # fixtures store them and fsck.hfsplus checks them.
        t = hfs_time(n.mtime) if n else now
        owner = bsd(n, mode, special, owner_flags)
        if ftype == b"hlnk":
            owner = struct.pack(">II", prev_link, next_link) + owner[8:]
        return bytearray(
            struct.pack(">hHII5I", FILE, flags, first_link, cnid, t, t, t, t, 0)
            + owner
            + ftype
            + creator
            + struct.pack(">HIH", finder_flags, 0, 0)
            + bytes(16)
            + struct.pack(">II", 0, 0)
            + data_fork
            + rsrc_fork
        )

    def thread(kind: int, parent: int, name: bytes) -> bytearray:
        return bytearray(struct.pack(">hhIH", kind, 0, parent, len(name) // 2) + name)

    def name_of(path: str, n: Node | None) -> bytes:
        if n is not None and n.raw_name is not None:
            return n.raw_name
        return _utf16(path.rpartition("/")[2])

    subfolders: dict[int, int] = {}
    for path, cnid in cnids.items():
        if path:
            children[parent_of(path)] = children.get(parent_of(path), 0) + 1
            if kinds[path] == "dir":
                subfolders[parent_of(path)] = subfolders.get(parent_of(path), 0) + 1
    if has_links:
        children[ROOT_FOLDER] = children.get(ROOT_FOLDER, 0) + 1
        subfolders[ROOT_FOLDER] = subfolders.get(ROOT_FOLDER, 0) + 1
        children[private_id] = len(links)

    root_name = _utf16(name)
    records.append(
        CatalogRecord(
            ROOT_PARENT,
            root_name,
            folder_record(ROOT_FOLDER, None, children.get(ROOT_FOLDER, 0)),
        )
    )
    records.append(
        CatalogRecord(ROOT_FOLDER, b"", thread(FOLDER_THREAD, ROOT_PARENT, root_name))
    )
    if has_links:
        pname = _utf16(PRIVATE_DATA)
        invisible = struct.pack(
            ">IIHhhH", 0, 0, 0x5000, 0, 0, 0
        )  # kIsInvisible | kNameLocked
        records.append(
            CatalogRecord(
                ROOT_FOLDER,
                pname,
                folder_record(private_id, None, children[private_id], invisible),
            )
        )
        records.append(
            CatalogRecord(private_id, b"", thread(FOLDER_THREAD, ROOT_FOLDER, pname))
        )
        counts["folders"] += 1

    link_ids = {lp: cnids[lp] for paths in links.values() for lp in paths}
    # The first file's own path also becomes a link, with a fresh CNID.
    for first in links:
        link_ids[first] = next_id
        next_id += 1

    for n in order:
        p = n.path.strip("/")
        cnid = cnids[p]
        nm = name_of(p, n)
        parent = parent_of(p)
        if kinds[p] == "dir":
            records.append(
                CatalogRecord(parent, nm, folder_record(cnid, n, children.get(cnid, 0)))
            )
            records.append(CatalogRecord(cnid, b"", thread(FOLDER_THREAD, parent, nm)))
            counts["folders"] += 1
            continue
        data, rsrc, owner_flags = file_bodies[p]
        data_fork = _fork(len(data), forks[p], block_size)
        rsrc_fork = _fork(len(rsrc), rsrc_forks[p], block_size)
        if p in links:  # the inode: data in the private folder, the path a link
            group = [p, *links[p]]
            ids = [link_ids[x] for x in group]
            inode_name = _utf16(f"iNode{cnid}")
            records.append(
                CatalogRecord(
                    private_id,
                    inode_name,
                    file_record(
                        cnid,
                        n,
                        mode=n.mode or (stat.S_IFREG | 0o644),
                        special=len(group),
                        flags=0x0002 | 0x0020,
                        owner_flags=owner_flags,
                        data_fork=data_fork,
                        rsrc_fork=rsrc_fork,
                        first_link=ids[0],
                    ),
                )
            )
            records.append(
                CatalogRecord(cnid, b"", thread(FILE_THREAD, private_id, inode_name))
            )
            counts["files"] += 1
            for i, lp in enumerate(group):
                lid = ids[i]
                prev_id = ids[i - 1] if i else 0
                next_link = ids[i + 1] if i + 1 < len(group) else 0
                ln = by_path.get(lp) or n
                lname = name_of(lp, ln)
                lparent = parent_of(lp)
                records.append(
                    CatalogRecord(
                        lparent,
                        lname,
                        file_record(
                            lid,
                            ln,
                            mode=stat.S_IFREG | 0o444,
                            ftype=b"hlnk",
                            creator=b"hfs+",
                            special=cnid,
                            flags=0x0002 | 0x0020,
                            finder_flags=0x0100,  # kHasBeenInited
                            prev_link=prev_id,
                            next_link=next_link,
                        ),
                    )
                )
                records.append(
                    CatalogRecord(lid, b"", thread(FILE_THREAD, lparent, lname))
                )
                counts["files"] += 1
            continue
        if n.kind == "hardlink":
            continue  # written with its first file above
        mode = n.mode
        ftype = creator = b"\0\0\0\0"
        special = 0
        if n.kind == "symlink":
            mode = mode or (stat.S_IFLNK | 0o755)
            ftype, creator = b"slnk", b"rhap"
        elif n.kind == "fifo":
            mode = mode or (stat.S_IFIFO | 0o644)
        elif n.kind == "chardev":
            mode = mode or (stat.S_IFCHR | 0o644)
            special = n.rdev
        else:
            mode = mode or (stat.S_IFREG | 0o644)
        records.append(
            CatalogRecord(
                parent,
                nm,
                file_record(
                    cnid,
                    n,
                    mode=mode,
                    ftype=ftype,
                    creator=creator,
                    special=special,
                    owner_flags=owner_flags,
                    data_fork=data_fork,
                    rsrc_fork=rsrc_fork,
                ),
            )
        )
        records.append(CatalogRecord(cnid, b"", thread(FILE_THREAD, parent, nm)))
        counts["files"] += 1

    for r in records:  # kHFSHasAttributesMask on every record that has an attribute
        (rtype,) = struct.unpack_from(">h", r.body)
        if rtype in (FOLDER, FILE) and struct.unpack_from(">I", r.body, 8)[0] in xattrs:
            struct.pack_into(
                ">H", r.body, 2, struct.unpack_from(">H", r.body, 2)[0] | 0x0004
            )
    if patch_catalog:
        patch_catalog(records)
    records.sort(key=lambda r: (r.parent, _compare_name(r.name, case_sensitive)))
    cat_pairs = []
    for r in records:
        key = r.key()
        body = bytes(r.body)
        cat_pairs.append((key + (b"\0" if len(key) & 1 else b""), body))
    catalog, leaves = _btree(
        cat_pairs,
        node_size,
        max_key=516,
        btree_type=0,
        compare_type=0xBC if case_sensitive else 0xCF,
        variable_index_keys=True,
        min_nodes=8,
        block_size=block_size,
        patch_nodes=patch_catalog_nodes,
    )

    # ── extents overflow ──
    # HFSPlusExtentKey order (TN1150): fileID, then forkType, then startBlock.
    ext_pairs = []
    for cnid, fork_type, start_block, group in sorted(overflow):
        key = struct.pack(">HBBII", 10, fork_type, 0, cnid, start_block)
        body = b"".join(struct.pack(">II", s, c) for s, c in group).ljust(64, b"\0")
        ext_pairs.append((key, body))
    extents_file, _ = _btree(
        ext_pairs,
        node_size,
        max_key=10,
        btree_type=0,
        compare_type=0,
        variable_index_keys=False,
        min_nodes=8,
        block_size=block_size,
    )

    # ── attributes ──
    attr_pairs = []
    for cnid in sorted(xattrs):
        for xname in sorted(xattrs[cnid], key=lambda s: _utf16(s)):
            value = xattrs[cnid][xname]
            uname = _utf16(xname)
            key = (
                struct.pack(">HHIIH", 12 + len(uname), 0, cnid, 0, len(uname) // 2)
                + uname
            )
            if (cnid, xname) in attr_fork_extents:
                size, ext = attr_fork_extents[(cnid, xname)]
                body = struct.pack(">II", 0x20, 0) + _fork(size, ext, block_size)
            else:
                body = struct.pack(">IIII", 0x10, 0, 0, len(value)) + value
                body += b"\0" * (len(body) & 1)
            attr_pairs.append((key, body))
    attributes_file, _ = _btree(
        attr_pairs,
        node_size,
        max_key=266,
        btree_type=0,
        compare_type=0,
        variable_index_keys=True,
        min_nodes=8,
        block_size=block_size,
    )

    # ── lay out the special files after the data ──
    def place_file(data: bytes) -> tuple[int, int]:
        blocks = -(-len(data) // block_size)
        start, _ = alloc.take(blocks)
        contents.append((start, data))
        return start, blocks

    ext_start, ext_blocks = place_file(extents_file)
    cat_start, cat_blocks = place_file(catalog)
    attr_start, attr_blocks = place_file(attributes_file)
    data_end = alloc.next
    total_blocks = data_end + spare_blocks
    bitmap_bytes = -(-total_blocks // 8)
    bitmap_blocks = -(-bitmap_bytes // block_size)
    alloc_start, _ = alloc.take(bitmap_blocks)
    total_blocks = max(total_blocks, alloc.next + tail_blocks + 1)
    bitmap_bytes = -(-total_blocks // 8)
    if -(-bitmap_bytes // block_size) != bitmap_blocks:
        raise AssertionError("bitmap outgrew its blocks")
    # Blocks used: the head (boot + header), every extent, the tail (alternate header).
    bitmap = bytearray(bitmap_blocks * block_size)
    used = [(0, head_blocks), *alloc.used, (total_blocks - tail_blocks, tail_blocks)]
    used_count = 0
    for start, count in used:
        for b in range(start, start + count):
            bitmap[b // 8] |= 0x80 >> (b % 8)
            used_count += 1
    contents.append((alloc_start, bytes(bitmap)))

    volume = bytearray(total_blocks * block_size)
    for start, data in contents:
        volume[start * block_size : start * block_size + len(data)] = data

    attributes = 0x00000100  # kHFSVolumeUnmountedMask
    if dirty:
        attributes &= ~0x100
    journal_info_block = 0
    if journal:
        attributes |= 0x2000  # kHFSVolumeJournaledMask
        journal_info_block = forks[".journal_info_block"][0][0]
        _write_journal(
            volume,
            journal,
            info_at=journal_info_block * block_size,
            journal_at=forks[".journal"][0][0] * block_size,
        )
    vh = bytearray(512)
    struct.pack_into(
        ">2sHIII4IIIIIIIIIIIQ",
        vh,
        0,
        b"HX" if hfsx else b"H+",
        5 if hfsx else 4,
        attributes,
        0x4846534A if journal else 0x31302E30,  # "HFSJ" or "10.0"
        journal_info_block,
        now,
        now,
        0,
        now,
        counts["files"],
        counts["folders"],
        block_size,
        total_blocks,
        total_blocks - used_count,
        data_end,
        65536,
        65536,
        next_id,
        1,
        1,
    )
    vh[112:192] = _fork(len(bitmap), [(alloc_start, bitmap_blocks)], block_size)
    vh[192:272] = _fork(len(extents_file), [(ext_start, ext_blocks)], block_size)
    vh[272:352] = _fork(len(catalog), [(cat_start, cat_blocks)], block_size)
    vh[352:432] = _fork(len(attributes_file), [(attr_start, attr_blocks)], block_size)
    if patch_header:
        patch_header(vh)
    volume[1024:1536] = vh
    volume[len(volume) - 1024 : len(volume) - 512] = vh
    hfs = Hfs(
        b"",
        block_size,
        cnids,
        forks,
        cat_start * block_size,
        node_size,
        leaves,
        attr_start * block_size,
        ext_start * block_size,
    )
    if patch_volume:
        patch_volume(volume, hfs)
    hfs.volume = bytes(volume)
    return hfs


def dmg_of(
    nodes: Sequence[Node],
    *,
    layout: str = "gpt",
    codec: int = ZLIB,
    hfs_options: Mapping[str, Any] | None = None,
    **udif_options: Any,
) -> bytes:
    """A whole ``.dmg``: an HFS+ volume of ``nodes`` in a GPT (or ``apm``, or ``none``)
    disk in a UDIF image."""
    hfs = write_hfsplus(nodes, **(hfs_options or {}))
    volume = hfs.volume + bytes(-len(hfs.volume) % SECTOR)
    part = Partition(volume)
    if layout == "gpt":
        disk = write_gpt([part])
    elif layout == "apm":
        disk = write_apm([part])
    else:
        disk = write_bare(part)
    return write_udif(
        disk.segments, tables=disk.tables, codec=codec, **udif_options
    ).image
