"""Build small UDF images for the ISO tests, from scratch.

No writer the suite can run makes a UDF-only image with files in it, a metadata
partition (UDF 2.50, as on Blu-ray), Extended File Entries, unrecorded extents,
continued allocation extents or strategy-4096 indirect entries: ``pycdlib`` writes UDF
2.60 bridge images with File Entries and short allocation descriptors only, and
``mkudffs`` writes empty file systems. This module lays those shapes out by hand, by
ECMA-167 and the OSTA UDF specification, with 2048-byte blocks.

Layout of an image::

    16-18       BEA01, NSR03, TEA01 (or after an ISO 9660 set, never here)
    32-35       main Volume Descriptor Sequence: PVD, PD, LVD, TD
    48-51       reserve sequence, a copy
    256         Anchor Volume Descriptor Pointer
    300...      the partition; with ``metadata=True`` its block 0 holds the metadata
                file's Extended File Entry and the metadata partition's blocks follow;
                file data from partition block 64
    last block  a second anchor
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime

BLOCK = 2048
_PARTITION_START = 300
_MAIN_VDS = 32
_RESERVE_VDS = 48
_ANCHOR = 256
# The partition block file data starts at; metadata comes before it.
_DATA_BASE = 64


def _crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def tag(ident: int, location: int, body: bytes) -> bytes:
    """A descriptor: its 16-byte tag (checksum and CRC filled in), then ``body``."""
    head = bytearray(
        struct.pack("<HHBBHHHI", ident, 3, 0, 0, 1, _crc(body), len(body), location)
    )
    head[4] = (sum(head[0:4]) + sum(head[5:16])) & 0xFF
    return bytes(head) + body


def retag(descriptor: bytes | bytearray) -> bytes:
    """``descriptor`` with its tag's checksum and CRC recomputed after an edit."""
    ident, _v, _c, _r, _s, _crc_value, crc_len, location = struct.unpack_from(
        "<HHBBHHHI", descriptor, 0
    )
    del ident, location
    data = bytearray(descriptor)
    struct.pack_into("<H", data, 8, _crc(bytes(data[16 : 16 + crc_len])))
    data[4] = (sum(data[0:4]) + sum(data[5:16])) & 0xFF
    return bytes(data)


def dstring(name: str) -> bytes:
    """An OSTA CS0 name: compression ID 8 when every character fits a byte, else 16."""
    if all(ord(char) < 256 for char in name):
        return b"\x08" + name.encode("latin-1")
    return b"\x10" + name.encode("utf-16-be", errors="surrogatepass")


def _dstring_field(text: str, size: int) -> bytes:
    raw = dstring(text) if text else b""
    return raw.ljust(size - 1, b"\0") + bytes([len(raw)])


def timestamp(value: datetime) -> bytes:
    """A UDF timestamp in UTC (type 1, offset 0)."""
    value = value.astimezone(UTC)
    return struct.pack(
        "<HhBBBBBBBB",
        1 << 12,
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond // 10_000,
        (value.microsecond // 100) % 100,
        value.microsecond % 100,
    )


WHEN = datetime(2024, 5, 6, 7, 8, 9, 120_000, tzinfo=UTC)


@dataclass
class Node:
    """One file, directory or symlink of the tree to build."""

    name: str
    data: bytes = b""
    file_type: int = 5  # 4 directory, 5 file, 12 symlink, 9 FIFO, ...
    children: list[Node] = field(default_factory=list)
    target: str | None = None  # for a symlink
    permissions: int = 0x14A5  # r-x for owner, group, other in UDF's layout
    uid: int = 1000
    gid: int = 100
    inline: bool = False  # data inside the File Entry
    sparse: int = 0  # bytes of unrecorded extent after the data
    split: bool = False  # continue the allocation descriptors in an extent
    indirect: bool = False  # an Indirect Entry at the ICB names the File Entry
    times: bytes | None = None  # every time field of the entry


def directory(name: str, *children: Node) -> Node:
    return Node(name, file_type=4, children=list(children))


def symlink_data(target: str) -> bytes:
    """A symlink's path components (ECMA-167 4/14.16)."""
    out = b""
    parts = target.split("/")
    if target.startswith("/"):
        out += struct.pack("<BBH", 2, 0, 0)
        parts = parts[1:]
    for part in parts:
        if part == "..":
            out += struct.pack("<BBH", 3, 0, 0)
        elif part == ".":
            out += struct.pack("<BBH", 4, 0, 0)
        elif part:
            raw = dstring(part)
            out += struct.pack("<BBH", 5, len(raw), 0) + raw
    return out


class _Image:
    def __init__(self, *, extended: bool, metadata: bool, long_ad: bool) -> None:
        self.extended = extended
        self.metadata = metadata
        self.long_ad = long_ad or metadata
        # Physical partition blocks (partition reference 0) and, with a metadata
        # partition, metadata blocks (reference 1), each a dict block -> bytes.
        self.physical: dict[int, bytes] = {}
        self.meta: dict[int, bytes] = {}
        self.next_physical = 1 if metadata else 0
        # File data goes after every metadata block, so cutting an image inside
        # file data leaves the tree whole.
        self.next_data = _DATA_BASE
        self.next_meta = 0
        self.meta_ref = 1 if metadata else 0

    def alloc_meta(self, count: int = 1) -> int:
        if self.metadata:
            block = self.next_meta
            self.next_meta += count
        else:
            block = self.next_physical
            self.next_physical += count
        return block

    def alloc_data(self, nbytes: int) -> int:
        block = self.next_data
        self.next_data += max(1, -(-nbytes // BLOCK))
        return block

    def put_meta(self, block: int, data: bytes) -> None:
        for index in range(0, max(len(data), 1), BLOCK):
            target = self.meta if self.metadata else self.physical
            target[block + index // BLOCK] = data[index : index + BLOCK]

    def put_data(self, block: int, data: bytes) -> None:
        for index in range(0, len(data), BLOCK):
            self.physical[block + index // BLOCK] = data[index : index + BLOCK]

    # --- descriptors --------------------------------------------------------

    def ad(self, length: int, block: int, partref: int, extent_type: int = 0) -> bytes:
        raw = (extent_type << 30) | length
        if self.long_ad:
            return struct.pack("<IIH6x", raw, block, partref)
        return struct.pack("<II", raw, block)

    def file_entry(
        self,
        node: Node,
        location: int,
        info_length: int,
        ads: bytes,
        *,
        file_type: int | None = None,
        inline: bool = False,
    ) -> bytes:
        kind = 3 if inline else (1 if self.long_ad else 0)
        icb = struct.pack(
            "<IHHHBBIHH",
            0,
            4,
            0,
            1,
            0,
            node.file_type if file_type is None else file_type,
            0,
            0,
            kind,
        )
        when = node.times if node.times is not None else timestamp(WHEN)
        common = struct.pack("<III", node.uid, node.gid, node.permissions)
        common += struct.pack("<HBBI", 1, 0, 0, 0)
        common += struct.pack("<Q", info_length)
        if self.extended:
            body = icb + common
            body += struct.pack("<QQ", info_length, -(-info_length // BLOCK))
            body += when * 4  # access, modification, creation, attribute
            body += struct.pack("<II", 1, 0)  # checkpoint, reserved
            body += bytes(16) + bytes(16)  # extended attribute ICB, stream ICB
            body += bytes(32) + struct.pack("<Q", 0)  # implementation ID, unique ID
            body += struct.pack("<II", 0, len(ads)) + ads
            return tag(266, location, body)
        body = icb + common
        body += struct.pack("<Q", -(-info_length // BLOCK))
        body += when * 3  # access, modification, attribute
        body += struct.pack("<I", 1) + bytes(16) + bytes(32) + struct.pack("<Q", 0)
        body += struct.pack("<II", 0, len(ads)) + ads
        return tag(261, location, body)

    def fid(self, name: bytes, block: int, partref: int, characteristics: int) -> bytes:
        body = struct.pack("<HBB", 1, characteristics, len(name))
        body += struct.pack("<IIH6x", BLOCK, block, partref)
        body += struct.pack("<H", 0) + name
        total = 16 + len(body)
        body += bytes((-total) % 4)
        return tag(257, 0, body)

    # --- the tree -----------------------------------------------------------

    def write(self, node: Node, parent_icb: int | None) -> int:
        """Lay ``node`` out; return its ICB block in the metadata space."""
        icb = self.alloc_meta()
        entry_block = self.alloc_meta() if node.indirect else icb
        if node.file_type == 4:
            data = self.fid(
                b"", parent_icb if parent_icb is not None else icb, self.meta_ref, 0x0A
            )
            for child in node.children:
                child_icb = self.write(child, icb)
                characteristics = 0x02 if child.file_type == 4 else 0
                data += self.fid(
                    dstring(child.name), child_icb, self.meta_ref, characteristics
                )
            dir_block = self.alloc_meta(-(-len(data) // BLOCK))
            self.put_meta(dir_block, data)
            ads = self.ad(len(data), dir_block, self.meta_ref)
            entry = self.file_entry(node, entry_block, len(data), ads)
        else:
            payload = (
                symlink_data(node.target or "") if node.file_type == 12 else node.data
            )
            if node.inline:
                entry = self.file_entry(
                    node, entry_block, len(payload), payload, inline=True
                )
            else:
                ads = b""
                if payload:
                    block = self.alloc_data(len(payload))
                    self.put_data(block, payload)
                    if node.split and len(payload) > BLOCK:
                        first = self.ad(BLOCK, block, 0)
                        rest = self.ad(len(payload) - BLOCK, block + 1, 0)
                        aed_block = self.alloc_meta()
                        aed = tag(
                            258, aed_block, struct.pack("<II", 0, len(rest)) + rest
                        )
                        self.put_meta(aed_block, aed)
                        ads = first + self.ad(len(aed), aed_block, self.meta_ref, 3)
                    else:
                        ads = self.ad(len(payload), block, 0)
                if node.sparse:
                    ads += self.ad(node.sparse, 0, 0, 1)
                entry = self.file_entry(
                    node, entry_block, len(payload) + node.sparse, ads
                )
        self.put_meta(entry_block, entry)
        if node.indirect:
            body = struct.pack("<IHHHBBIHH", 0, 4096, 0, 1, 0, 3, 0, 0, 0)
            body += struct.pack("<IIH6x", BLOCK, entry_block, self.meta_ref)
            self.put_meta(icb, tag(259, icb, body))
        return icb


def build_udf(
    root: Node,
    *,
    extended: bool = False,
    metadata: bool = False,
    long_ad: bool = False,
    label: str = "UDFTEST",
    revision: int = 0x0250,
    map_ident: bytes = b"*UDF Metadata Partition",
    split_metadata_file: bool = False,
) -> bytes:
    """A UDF-only image holding the tree under ``root`` (a directory node).

    ``extended`` writes Extended File Entries, ``metadata`` a metadata partition
    (whose map names ``map_ident``), ``long_ad`` long allocation descriptors.
    ``split_metadata_file`` records the metadata file as one extent per block.
    """
    image = _Image(extended=extended or metadata, metadata=metadata, long_ad=long_ad)
    fsd_block = image.alloc_meta()
    root_icb = image.write(root, None)
    fsd = bytearray(480)
    fsd[0:12] = timestamp(WHEN)
    struct.pack_into("<HH", fsd, 12, 3, 3)
    fsd[96:224] = _dstring_field(label, 128)
    struct.pack_into("<IIH", fsd, 384, BLOCK, root_icb, image.meta_ref)
    image.put_meta(fsd_block, tag(256, fsd_block, bytes(fsd)))

    meta_blocks = image.next_meta
    if metadata:
        # The metadata partition's blocks follow the metadata file's entry, back to
        # back, from physical block 1.
        start = image.next_physical
        image.next_physical += meta_blocks
        assert image.next_physical <= _DATA_BASE
        for block, data in image.meta.items():
            image.physical[start + block] = data
        meta_node = Node("", permissions=0, uid=0xFFFFFFFF, gid=0xFFFFFFFF)
        if split_metadata_file:
            # One short AD per block, back to back on disc.
            ads = b"".join(
                struct.pack("<II", BLOCK, start + index) for index in range(meta_blocks)
            )
        else:
            ads = struct.pack("<II", meta_blocks * BLOCK, start)
        image.long_ad = False
        entry = image.file_entry(meta_node, 0, meta_blocks * BLOCK, ads, file_type=250)
        image.physical[0] = entry
    assert image.next_physical <= _DATA_BASE
    length = image.next_data + 16

    out = bytearray((_PARTITION_START + length + 1) * BLOCK)
    for index, ident in enumerate(
        (b"BEA01", b"NSR03" if revision >= 0x200 else b"NSR02", b"TEA01")
    ):
        offset = (16 + index) * BLOCK
        out[offset : offset + 7] = b"\0" + ident + b"\x01"

    def descriptors(first: int) -> None:
        pvd = bytearray(496)
        struct.pack_into("<II", pvd, 0, 1, 0)
        pvd[8:40] = _dstring_field(label, 32)
        pd = bytearray(496)
        struct.pack_into("<IHH", pd, 0, 1, 1, 0)
        pd[8:40] = b"\0+NSR03".ljust(32, b"\0")
        struct.pack_into("<III", pd, 168, 1, _PARTITION_START, length)
        maps = struct.pack("<BBHH", 1, 6, 1, 0)
        if metadata:
            regid = (
                b"\0"
                + map_ident.ljust(23, b"\0")
                + struct.pack("<H", revision)
                + bytes(6)
            )
            maps += struct.pack("<BBH", 2, 64, 0) + regid
            maps += struct.pack(
                "<HHIIIIHB5x", 1, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 32, 1, 0
            )
        lvd = bytearray(424)
        struct.pack_into("<I", lvd, 0, 1)
        lvd[68:196] = _dstring_field(label, 128)
        struct.pack_into("<I", lvd, 196, BLOCK)
        struct.pack_into("<IIH", lvd, 232, BLOCK, fsd_block, image.meta_ref)
        struct.pack_into("<II", lvd, 248, len(maps), 2 if metadata else 1)
        blocks = (
            tag(1, first, bytes(pvd)),
            tag(5, first + 1, bytes(pd)),
            tag(6, first + 2, bytes(lvd) + maps),
            tag(8, first + 3, bytes(496)),
        )
        for index, data in enumerate(blocks):
            offset = (first + index) * BLOCK
            out[offset : offset + len(data)] = data

    descriptors(_MAIN_VDS)
    descriptors(_RESERVE_VDS)
    anchor_body = struct.pack("<IIII", 16 * BLOCK, _MAIN_VDS, 16 * BLOCK, _RESERVE_VDS)
    anchor_body += bytes(480)
    last = len(out) // BLOCK - 1
    for block in (_ANCHOR, last):
        data = tag(2, block, anchor_body)
        out[block * BLOCK : block * BLOCK + len(data)] = data
    for block, data in image.physical.items():
        offset = (_PARTITION_START + block) * BLOCK
        out[offset : offset + len(data)] = data
    return bytes(out)
