"""HFS+ and HFSX volumes, read as the Mac mounts them (Apple TN1150, "HFS Plus Volume
Format").

This module parses; it makes no ``ArchiveMember``. :class:`HfsVolume` reads the volume
header and the journal state when the image opens (design §6.1 of
``openspec/changes/dmg-reader``), and everything else at the first listing:

- the B-trees (:class:`_BTree`): a header node, then index and leaf nodes of
  ``nodeSize`` bytes in the tree's fork. The walk follows the leaf chain from
  ``firstLeafNode`` and refuses a node reached twice;
- the catalog: one record per folder and file, keyed by (parent id, name), plus thread
  records. :func:`read_catalog` walks it once for the folders, the hard-link inodes and
  the hidden folders, and :func:`catalog_entries` again to yield each entry;
- the attributes B-tree: extended attributes by (file id, name), among them
  ``com.apple.decmpfs``, the header of a transparently compressed file;
- the extents overflow B-tree: a fork's extents past the eight its record holds, looked
  up when the fork is read.

Every offset and count is checked before it is used: extents inside the volume, node
numbers inside the tree, record offsets inside the node, names inside their key. A
fork is read in pieces through its extents, never as a whole.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Callable, Iterator
from typing import NamedTuple

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import ReaderContext, ReaderSource
from archivey.internal.streams.codecs.lzfse_decoder import (
    lzfse_decompress,
    lzvn_decompress,
)
from archivey.types import CompressionAlgorithm, StreamFormat

# Seconds from the HFS epoch (1904-01-01 UTC) to the Unix epoch.
HFS_EPOCH_OFFSET = 2_082_844_800

_VOLUME_HEADER_AT = 1024
_VOLUME_HEADER = struct.Struct(">2sHIIIIIIIIIIIIIIIIII8s32s")
_FORK = struct.Struct(">QII64s")
_NODE = struct.Struct(">IIbBHH")
_BTREE_HEADER = struct.Struct(">HIIIIHHIIHIBBI")
_JOURNAL_INFO = struct.Struct(">I32sQQ")
_JOURNAL_HEADER = struct.Struct("<IIQQQIII")
_JOURNAL_MAGIC = 0x4A4E4C78  # "JNLx"
_JOURNAL_ENDIAN = 0x12345678
_JOURNALED = 0x2000  # kHFSVolumeJournaledBit
_JOURNAL_IN_FS = 0x1
_JOURNAL_ON_OTHER_DEVICE = 0x2
_JOURNAL_NEED_INIT = 0x4

_ROOT_PARENT = 1
ROOT_FOLDER = 2
_EXTENTS_FILE = 3
_CATALOG_FILE = 4
_ATTRIBUTES_FILE = 8

_FOLDER, _FILE, _FOLDER_THREAD, _FILE_THREAD = 1, 2, 3, 4
_FOLDER_RECORD = 88
_FILE_RECORD = 248
_LEAF, _INDEX, _HEADER = -1, 0, 1
DATA_FORK, RESOURCE_FORK = 0x00, 0xFF

PRIVATE_DATA = "\0\0\0\0HFS+ Private Data"
PRIVATE_DIRECTORY_DATA = ".HFS+ Private Directory Data\r"
JOURNAL_FILES = (".journal", ".journal_info_block")
UF_COMPRESSED = 0x20
DECMPFS = "com.apple.decmpfs"
DECMPFS_CHUNK = 0x10000
# A symlink's target is its data fork; longer than PATH_MAX is damage.
SYMLINK_MAX = 1024
# Extended attribute values up to this are listed in ``extra``; longer ones by name.
XATTR_VALUE_MAX = 1024
# decmpfs headers and inline data are kept for the read; a value is at most one chunk
# and the header, so this bounds what one attribute can keep.
_DECMPFS_KEEP = DECMPFS_CHUNK + 64
# What one kept extent costs in memory: a (start, count) tuple of two ints, and its
# slots in the list and in the final tuple.
_EXTENT_CHARGE = 96
# The memory one kept folder thread holds besides its name: a dict slot, its int key,
# a (parent, name) tuple, the parent int and the bytes object (about 207 bytes measured
# with tracemalloc on CPython 3.12 for an empty name).
_THREAD_CHARGE = 208
# The block a fork read gathers at a time through the extents.
READ_PIECE = 1 << 20

_S_IFMT = 0o170000
_S_IFREG = 0o100000
_S_IFDIR = 0o040000
_S_IFLNK = 0o120000
_SPECIAL = {
    0o010000: "fifo",
    0o020000: "char_device",
    0o060000: "block_device",
    0o140000: "socket",
}


class Fork(NamedTuple):
    """A fork record: its size, its blocks, and the first eight extents."""

    size: int
    total_blocks: int
    extents: tuple[tuple[int, int], ...]  # (start block, block count), empty dropped


def parse_fork(raw: bytes, at: int = 0) -> Fork:
    size, _, total, packed = _FORK.unpack_from(raw, at)
    extents = struct.unpack(">16I", packed)
    return Fork(
        size,
        total,
        tuple((extents[i], extents[i + 1]) for i in range(0, 16, 2) if extents[i + 1]),
    )


def hfs_time(value: int) -> int | None:
    """A catalog date (seconds since 1904, UTC) as Unix seconds; ``None`` for 0."""
    return value - HFS_EPOCH_OFFSET if value else None


class VolumeHeader(NamedTuple):
    signature: bytes  # b"H+" or b"HX"
    attributes: int
    journal_info_block: int
    block_size: int
    total_blocks: int
    extents: Fork
    catalog: Fork
    attributes_file: Fork


def read_volume_header(source: ReaderSource) -> VolumeHeader:
    """The volume header at offset 1024, checked against the partition's length."""
    raw = source.read_exact(_VOLUME_HEADER_AT, 512)
    signature = raw[:2]
    if signature == b"BD":
        raise UnsupportedFeatureError(
            "HFS (standard) volumes, and HFS+ volumes inside an HFS wrapper, are not "
            "supported"
        )
    fields = _VOLUME_HEADER.unpack_from(raw)
    version = fields[1]
    if (signature, version) not in ((b"H+", 4), (b"HX", 5)):
        raise CorruptionError(
            f"no HFS+ volume header (signature {signature!r}, version {version})"
        )
    attributes, journal_info_block = fields[2], fields[4]
    block_size, total_blocks = fields[11], fields[12]
    if block_size < 512 or block_size > 1 << 16 or block_size & (block_size - 1):
        raise CorruptionError(f"the HFS+ block size {block_size} is not valid")
    partition = source.size or 0
    if total_blocks * block_size > partition:
        raise CorruptionError(
            f"the HFS+ volume declares {total_blocks} blocks of {block_size} bytes, "
            f"more than its {partition}-byte partition"
        )
    return VolumeHeader(
        signature,
        attributes,
        journal_info_block,
        block_size,
        total_blocks,
        parse_fork(raw, 192),
        parse_fork(raw, 272),
        parse_fork(raw, 352),
    )


def check_journal(source: ReaderSource, header: VolumeHeader) -> tuple[int, int] | None:
    """Refuse a journal with pending transactions or on another device (TN1150: such a
    volume must be replayed before it is read). Returns the blocks of the journal and
    of the journal info block, which the listing hides, or ``None`` when the volume is
    not journaled."""
    if not header.attributes & _JOURNALED:
        return None
    bs = header.block_size
    info_at = header.journal_info_block * bs
    if header.journal_info_block >= header.total_blocks:
        raise CorruptionError(
            f"the HFS+ journal info block {header.journal_info_block} is past the "
            f"volume's {header.total_blocks} blocks"
        )
    flags, _, offset, size = _JOURNAL_INFO.unpack(
        source.read_exact(info_at, _JOURNAL_INFO.size)
    )
    journal_blocks = (offset // bs, header.journal_info_block)
    if flags & _JOURNAL_NEED_INIT:
        return journal_blocks  # an empty journal: nothing to replay
    if flags & _JOURNAL_ON_OTHER_DEVICE or not flags & _JOURNAL_IN_FS:
        raise UnsupportedFeatureError(
            "HFS+ volumes with an external journal are not supported: whether it holds "
            "changes not yet written to the volume cannot be checked"
        )
    if offset + max(size, _JOURNAL_HEADER.size) > header.total_blocks * bs:
        raise CorruptionError(
            f"the HFS+ journal ({size} bytes at offset {offset}) is past the volume"
        )
    raw = source.read_exact(offset, _JOURNAL_HEADER.size)
    fields = _JOURNAL_HEADER.unpack(raw)
    if fields[0] != _JOURNAL_MAGIC or fields[1] != _JOURNAL_ENDIAN:
        swapped = struct.unpack(">IIQQQIII", raw)
        if swapped[0] != _JOURNAL_MAGIC or swapped[1] != _JOURNAL_ENDIAN:
            raise CorruptionError(
                f"the HFS+ journal header at volume offset {offset} has no JNLx magic"
            )
        fields = swapped
    start, end = fields[2], fields[3]
    if start != end:
        raise UnsupportedFeatureError(
            "HFS+ volumes with an unreplayed journal are not supported: the journal "
            "holds changes not yet written to the volume"
        )
    return journal_blocks


# ── Forks ────────────────────────────────────────────────────────────────────────────


class _ExtentLookup:
    """Extents past a fork record's eight, from the extents overflow B-tree."""

    def __init__(self, volume: HfsVolume) -> None:
        self._volume = volume
        self._tree: _BTree | None = None

    def find(
        self, cnid: int, fork_type: int, start_block: int
    ) -> list[tuple[int, int]]:
        """The extents of the overflow record keyed (``cnid``, ``fork_type``,
        ``start_block``), or ``CorruptionError`` when there is none."""
        if self._tree is None:
            header = self._volume.header
            if not header.extents.size:
                raise CorruptionError(
                    f"file {cnid} needs extents past its record, and the volume has no "
                    "extents overflow file"
                )
            self._tree = _BTree(self._volume, _EXTENTS_FILE, header.extents, "extents")
        target = (cnid, fork_type, start_block)
        record = self._tree.search(lambda key: _extent_key(key) <= target)
        if record is not None:
            key, data = record
            if _extent_key(key) == target and len(data) >= 64:
                extents = struct.unpack_from(">16I", data)
                return [
                    (extents[i], extents[i + 1])
                    for i in range(0, 16, 2)
                    if extents[i + 1]
                ]
        raise CorruptionError(
            f"the extents overflow file has no extents for file {cnid} from block "
            f"{start_block}"
        )


def _extent_key(key: bytes) -> tuple[int, int, int]:
    """An extents overflow key: (file id, fork type, start block), compared in that
    order (Apple's ``CompareExtentKeysPlus``)."""
    if len(key) < 12:
        raise CorruptionError("an extents overflow key is shorter than 12 bytes")
    fork_type, _, cnid, start = struct.unpack_from(">BBII", key, 2)
    return cnid, fork_type, start


class HfsVolume:
    """One HFS+ or HFSX volume: the header and journal state at open, the trees on
    demand."""

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self.source = source
        self.context = context
        self.header = header = read_volume_header(source)
        self.hfsx = header.signature == b"HX"
        self.journal_blocks = check_journal(source, header)
        self._overflow = _ExtentLookup(self)
        self._name: str | None = None

    # Forks.

    def extents(self, cnid: int, fork_type: int, fork: Fork) -> list[tuple[int, int]]:
        """Every extent of a fork, the overflow ones included, each checked to lie
        inside the volume, and together covering the fork's size."""
        bs = self.header.block_size
        total = self.header.total_blocks
        extents = list(fork.extents)
        have = sum(count for _, count in extents)
        if cnid == _EXTENTS_FILE and have < fork.total_blocks:
            # TN1150: the extents overflow file has no overflow extents of its own.
            # Looking them up would build its B-tree again, and recurse.
            raise CorruptionError(
                f"the extents overflow file's eight extents hold {have} blocks, less "
                f"than its {fork.total_blocks}"
            )
        while have < fork.total_blocks:
            more = self._overflow.find(cnid, fork_type, have)
            if not more:
                break
            extents += more
            have += sum(count for _, count in more)
            if len(extents) > fork.total_blocks:
                raise CorruptionError(
                    f"file {cnid} has more extents than its {fork.total_blocks} blocks"
                )
        for start, count in extents:
            if start + count > total:
                raise CorruptionError(
                    f"an extent of file {cnid} (blocks {start} to {start + count}) is "
                    f"past the volume's {total} blocks"
                )
        if have * bs < fork.size:
            raise CorruptionError(
                f"the extents of file {cnid} hold {have * bs} bytes, less than its "
                f"{fork.size}"
            )
        return extents

    def fork_reader(
        self, cnid: int, fork_type: int, fork: Fork
    ) -> Callable[[int, int], bytes]:
        """``read(offset, n)`` over the fork's first ``fork.size`` bytes: exactly
        ``n`` bytes, or ``TruncatedError`` past the fork's end."""
        extents = self.extents(cnid, fork_type, fork)
        bs = self.header.block_size
        # Each extent's first byte in the fork, for a bisect-free walk.
        starts: list[int] = []
        pos = 0
        for _, count in extents:
            starts.append(pos)
            pos += count * bs
        source = self.source
        size = fork.size

        def read(offset: int, n: int) -> bytes:
            if offset + n > size:
                raise TruncatedError(
                    f"file {cnid} ends at byte {size}, before byte {offset + n}"
                )
            parts: list[bytes] = []
            want = n
            at = offset
            for (start, count), first in zip(extents, starts):
                length = count * bs
                if at >= first + length:
                    continue
                if want <= 0:
                    break
                within = at - first
                take = min(want, length - within)
                parts.append(source.read_exact(start * bs + within, take))
                at += take
                want -= take
            return b"".join(parts)

        return read

    # The catalog.

    def catalog(self) -> _BTree:
        return _BTree(self, _CATALOG_FILE, self.header.catalog, "catalog")

    def volume_name(self) -> str:
        """The volume's name: the key of the root folder's record, the first record of
        the catalog (parent id 1)."""
        if self._name is None:
            name = ""
            for key, data in self.catalog().leaf_records(limit=1):
                parent, raw = _catalog_key(key)
                if parent == _ROOT_PARENT and data[:2] == b"\x00\x01":
                    name = _decode_name(raw)
            self._name = name
        return self._name


class _BTree:
    """One B-tree of the volume, read node by node from its fork."""

    def __init__(self, volume: HfsVolume, cnid: int, fork: Fork, name: str) -> None:
        self._name = name
        self._read = volume.fork_reader(cnid, DATA_FORK, fork)
        head = self._read(0, min(512, fork.size))
        if len(head) < _NODE.size + _BTREE_HEADER.size:
            raise CorruptionError(f"the HFS+ {name} B-tree is too short for its header")
        _, _, kind, _, _, _ = _NODE.unpack_from(head)
        if kind != _HEADER:
            raise CorruptionError(f"the HFS+ {name} B-tree has no header node")
        (depth, root, _, first_leaf, _, node_size, _, total_nodes, _, _, _, _,
         compare, _) = _BTREE_HEADER.unpack_from(head, _NODE.size)  # fmt: skip
        if not 512 <= node_size <= 32768 or node_size & (node_size - 1):
            raise CorruptionError(f"the HFS+ {name} B-tree's node size {node_size}")
        if total_nodes * node_size > fork.size:
            raise CorruptionError(
                f"the HFS+ {name} B-tree declares {total_nodes} nodes of {node_size} "
                f"bytes, more than its {fork.size}-byte file"
            )
        self.depth = depth
        self.root = root
        self.first_leaf = first_leaf
        self.node_size = node_size
        self.total_nodes = total_nodes
        self.compare = compare

    def node(self, number: int) -> tuple[int, int, int, list[tuple[bytes, bytes]]]:
        """Node ``number``: (forward link, kind, height, records as (key, data))."""
        if not 0 < number < self.total_nodes:
            raise CorruptionError(
                f"the HFS+ {self._name} B-tree links to node {number}, outside its "
                f"{self.total_nodes} nodes"
            )
        size = self.node_size
        buf = self._read(number * size, size)
        flink, _, kind, height, count, _ = _NODE.unpack_from(buf)
        if _NODE.size + 2 * (count + 1) > size:
            raise CorruptionError(
                f"node {number} of the HFS+ {self._name} B-tree declares {count} records"
            )
        offsets = struct.unpack_from(f">{count + 1}H", buf, size - 2 * (count + 1))[
            ::-1
        ]
        limit = size - 2 * (count + 1)
        records = []
        for i in range(count):
            start, end = offsets[i], offsets[i + 1]
            if not _NODE.size <= start < end <= limit:
                raise CorruptionError(
                    f"node {number} of the HFS+ {self._name} B-tree has record offsets "
                    "out of order or outside the node"
                )
            record = buf[start:end]
            if len(record) < 2:
                raise CorruptionError(
                    f"a record in node {number} of the HFS+ {self._name} B-tree is "
                    "shorter than its key length"
                )
            (key_length,) = struct.unpack_from(">H", record)
            if kind == _INDEX or kind == _LEAF:
                if 2 + key_length > len(record):
                    raise CorruptionError(
                        f"a key in node {number} of the HFS+ {self._name} B-tree runs "
                        "past its record"
                    )
                split = 2 + key_length
                # Index and leaf records start their data on an even byte.
                data_at = split + (split & 1)
                records.append((record[:split], record[data_at:]))
            else:
                records.append((b"", record))
        return flink, kind, height, records

    def leaf_records(self, limit: int | None = None) -> Iterator[tuple[bytes, bytes]]:
        """Every leaf record, in key order, following the leaf chain. A node reached
        twice, or one that is not a leaf, raises ``CorruptionError``."""
        seen: set[int] = set()
        number = self.first_leaf
        yielded = 0
        while number:
            if number in seen:
                raise CorruptionError(
                    f"the HFS+ {self._name} B-tree's leaf chain reaches node {number} "
                    "twice"
                )
            seen.add(number)
            flink, kind, height, records = self.node(number)
            if kind != _LEAF or height != 1:
                raise CorruptionError(
                    f"the HFS+ {self._name} B-tree's leaf chain reaches node {number}, "
                    f"which is not a leaf (kind {kind}, height {height})"
                )
            for record in records:
                yield record
                yielded += 1
                if limit is not None and yielded >= limit:
                    return
            number = flink

    def search(
        self, at_or_before: Callable[[bytes], bool]
    ) -> tuple[bytes, bytes] | None:
        """The last leaf record whose key ``at_or_before`` accepts (keys accepted form
        a prefix of the key order), found down the index from the root."""
        number = self.root
        seen: set[int] = set()
        while number:
            if number in seen or len(seen) > 64:
                raise CorruptionError(f"the HFS+ {self._name} B-tree's index loops")
            seen.add(number)
            _, kind, _, records = self.node(number)
            chosen = None
            for key, data in records:
                if not at_or_before(key):
                    break
                chosen = (key, data)
            if kind == _LEAF:
                return chosen
            if kind != _INDEX:
                raise CorruptionError(
                    f"the HFS+ {self._name} B-tree's index reaches node {number} of "
                    f"kind {kind}"
                )
            if chosen is None or len(chosen[1]) < 4:
                return None
            (number,) = struct.unpack_from(">I", chosen[1])
        return None


# ── Catalog records ──────────────────────────────────────────────────────────────────


def _catalog_key(key: bytes) -> tuple[int, bytes]:
    """A catalog key's (parent id, name as stored UTF-16BE)."""
    if len(key) < 8:
        raise CorruptionError("an HFS+ catalog key is shorter than 8 bytes")
    parent, length = struct.unpack_from(">IH", key, 2)
    if length > 255 or 8 + 2 * length > len(key):
        raise CorruptionError(
            f"an HFS+ catalog key's name of {length} units runs past the key"
        )
    return parent, key[8 : 8 + 2 * length]


def _decode_name(raw: bytes) -> str:
    """A stored name, as the Mac shows it in a path: UTF-16BE, a lone surrogate kept
    as that unit (as for a Joliet or UDF name), ``/`` as ``:``."""
    return raw.decode("utf-16-be", errors="surrogatepass").replace("/", ":")


class Entry(NamedTuple):
    """A catalog record that becomes a member, before its path is joined."""

    cnid: int
    parent: int
    name: str
    record: bytes  # the folder or file record


def is_folder(entry: Entry) -> bool:
    return entry.record[:2] == b"\x00\x01"


class FileInfo(NamedTuple):
    """What a file or folder record says of its owner, mode, times and Finder type."""

    uid: int
    gid: int
    owner_flags: int
    mode: int
    special: int
    created: int | None
    modified: int | None
    file_type: bytes
    creator: bytes


def file_info(record: bytes) -> FileInfo:
    created, modified = struct.unpack_from(">II", record, 12)
    uid, gid, _, owner_flags, mode, special = struct.unpack_from(">IIBBHI", record, 32)
    return FileInfo(
        uid,
        gid,
        owner_flags,
        mode,
        special,
        hfs_time(created),
        hfs_time(modified),
        record[48:52],
        record[52:56],
    )


def data_fork(record: bytes) -> Fork:
    return parse_fork(record, 88)


def resource_fork(record: bytes) -> Fork:
    return parse_fork(record, 168)


# What a file record is, by the precedence of design §6.4.
FILE_LINK = "file_link"
DIRECTORY_LINK = "directory_link"
SYMLINK = "symlink"
REGULAR = "file"
SPECIAL = "special"


def file_kind(info: FileInfo) -> tuple[str, str | None]:
    """A file record's kind, and for a special file its name for
    ``extra["special_file_type"]``. Hard-link markers come first, whatever the mode
    says; then a non-zero BSD mode; with mode 0, the Finder type and creator."""
    if info.file_type == b"hlnk" and info.creator == b"hfs+":
        return FILE_LINK, None
    if info.file_type == b"fdrp" and info.creator == b"MACS":
        return DIRECTORY_LINK, None
    kind = info.mode & _S_IFMT
    if info.mode:
        if kind == _S_IFLNK:
            return SYMLINK, None
        if kind in _SPECIAL:
            return SPECIAL, _SPECIAL[kind]
        if kind in (_S_IFREG, 0):
            return REGULAR, None
        if kind == _S_IFDIR:
            # A file record with a directory mode: the record decides.
            return REGULAR, None
        return SPECIAL, "unknown"
    if info.file_type == b"slnk" and info.creator == b"rhap":
        return SYMLINK, None
    return REGULAR, None


def finder_symlink_disagrees(info: FileInfo) -> bool:
    """Whether the BSD mode and the Finder ``slnk``/``rhap`` tags disagree on a
    symlink (both set, one says symlink and the other does not)."""
    finder = info.file_type == b"slnk" and info.creator == b"rhap"
    mode_link = info.mode & _S_IFMT == _S_IFLNK
    return bool(info.mode) and finder != mode_link


class Catalog(NamedTuple):
    """What the first pass over the catalog keeps."""

    folders: dict[int, tuple[int, str]]  # folder id: (parent id, name)
    inodes: dict[int, Entry]  # link id: the iNode file in the private folder
    hidden: frozenset[int]  # folder ids whose contents are not listed
    # The folders whose thread record is missing, unreadable, or names another parent
    # or name, by folder id. Paths come from the folder records; a thread only
    # cross-checks them.
    bad_threads: tuple[int, ...] = ()


def read_catalog(
    volume: HfsVolume,
    charge: Callable[[int, str], None],
) -> tuple[Catalog, ArchiveyError | None]:
    """The first pass: every folder's parent and name, the hard-link inodes, and the
    hidden folders. A damaged node stops the pass; what it found is returned with the
    error, so the listing can yield the members before the damage."""
    folders: dict[int, tuple[int, str]] = {}
    private_files: int | None = None
    hidden: set[int] = set()
    inode_records: list[Entry] = []
    failure: ArchiveyError | None = None
    threads: dict[int, tuple[int, bytes] | None] = {}
    try:
        for key, data in volume.catalog().leaf_records():
            if data[:2] == b"\x00\x03":
                # A folder thread: keyed by the folder's id with an empty name, it
                # holds the folder's parent id and name (TN1150 "Catalog File").
                cnid, _ = _catalog_key(key)
                if cnid in threads:
                    continue
                thread = _thread_record(data)
                charge(
                    _THREAD_CHARGE + (len(thread[1]) if thread else 0),
                    "the HFS+ folder threads",
                )
                threads[cnid] = thread
                continue
            if data[:2] != b"\x00\x01" and data[:2] != b"\x00\x02":
                continue  # file threads; pass 2 refuses an unknown type
            parent, raw = _catalog_key(key)
            if data[:2] == b"\x00\x01":
                if len(data) < _FOLDER_RECORD:
                    raise CorruptionError("an HFS+ folder record is short")
                (cnid,) = struct.unpack_from(">I", data, 8)
                name = _decode_name(raw)
                charge(len(raw) + 64, "the HFS+ folder names")
                folders[cnid] = (parent, name)
                if parent == ROOT_FOLDER and name == PRIVATE_DATA:
                    private_files = cnid
                    hidden.add(cnid)
                elif parent == ROOT_FOLDER and name == PRIVATE_DIRECTORY_DATA:
                    hidden.add(cnid)
            elif private_files is not None and parent == private_files:
                inode_records.append(_file_entry(parent, raw, data))
                charge(len(data) + len(raw), "the HFS+ hard-link inodes")
    except ArchiveyError as exc:
        failure = exc
    # A private folder found after its inodes' records (it sorts by its parent, the
    # root, which comes first, so only a damaged catalog does this): its inodes are
    # read again in the second pass's order, so a link may find none.
    inodes: dict[int, Entry] = {}
    for entry in inode_records:
        if entry.name.startswith("iNode"):
            try:
                inodes[int(entry.name[5:])] = entry
            except ValueError:
                pass
    bad_threads: tuple[int, ...] = ()
    # A pass stopped by a damaged node has not read the later threads, so every later
    # folder would look like it had none: the cross-check runs on a whole pass only.
    if failure is None:
        bad_threads = tuple(
            cnid
            for cnid, (parent, name) in folders.items()
            if (thread := threads.get(cnid)) is None
            or thread[0] != parent
            or _decode_name(thread[1]) != name
        )
    return Catalog(folders, inodes, frozenset(hidden), bad_threads), failure


def _thread_record(data: bytes) -> tuple[int, bytes] | None:
    """A thread record's (parent id, name as stored UTF-16BE), or ``None`` when it is
    too short for its name: it then disagrees, as a missing one does, and the listing,
    which does not need it, goes on."""
    if len(data) < 10:
        return None
    parent, length = struct.unpack_from(">IH", data, 4)
    if length > 255 or 10 + 2 * length > len(data):
        return None
    return parent, data[10 : 10 + 2 * length]


def _file_entry(parent: int, raw_name: bytes, data: bytes) -> Entry:
    if len(data) < _FILE_RECORD:
        raise CorruptionError("an HFS+ file record is short")
    (cnid,) = struct.unpack_from(">I", data, 8)
    return Entry(cnid, parent, _decode_name(raw_name), data[:_FILE_RECORD])


def catalog_entries(volume: HfsVolume) -> Iterator[Entry]:
    """The second pass: every folder and file record, in catalog order."""
    for key, data in volume.catalog().leaf_records():
        kind = data[:2]
        if kind == b"\x00\x01":
            if len(data) < _FOLDER_RECORD:
                raise CorruptionError("an HFS+ folder record is short")
            parent, raw = _catalog_key(key)
            (cnid,) = struct.unpack_from(">I", data, 8)
            yield Entry(cnid, parent, _decode_name(raw), data[:_FOLDER_RECORD])
        elif kind == b"\x00\x02":
            parent, raw = _catalog_key(key)
            yield _file_entry(parent, raw, data)
        elif kind not in (b"\x00\x03", b"\x00\x04"):
            (record_type,) = struct.unpack_from(">h", data) if len(data) >= 2 else (0,)
            raise CorruptionError(f"unknown HFS+ catalog record type {record_type}")


def folder_path(
    folders: dict[int, tuple[int, str]],
    cache: dict[int, str | None],
    cnid: int,
    looped: set[int],
    charge: Callable[[int, str], None],
) -> str | None:
    """The path of folder ``cnid`` below the root (``""`` for the root), or ``None``
    when its chain does not reach the root: a folder the first pass did not find, or a
    chain that comes back to a folder. For a loop, the folder's cnid goes in ``looped``,
    so the walk lists the other members and raises at its end. ``seen`` ends a loop and
    the cache keeps the whole walk linear in the number of folders. Each path the cache
    keeps is charged to ``max_metadata_bytes``: the paths of a chain grow with the
    square of its depth, and the folders inside a hidden folder never become members,
    so no member name is charged for them."""
    if cnid in cache:
        return cache[cnid]
    chain: list[int] = []
    seen: set[int] = set()
    at = cnid
    while at not in cache:
        if at in seen:
            for each in chain:
                cache[each] = None
            looped.add(cnid)
            return None
        seen.add(at)
        found = folders.get(at)
        if found is None:
            for each in chain:
                cache[each] = None
            cache[at] = None
            return None
        chain.append(at)
        at = found[0]
    base = cache[at]
    for each in reversed(chain):
        if base is None:
            cache[each] = None
            continue
        name = folders[each][1]
        base = f"{base}/{name}" if base else name
        charge(len(base) + 32, "the HFS+ folder paths")
        cache[each] = base
    return cache[cnid]


# ── Extended attributes ──────────────────────────────────────────────────────────────


class Attribute(NamedTuple):
    """One extended attribute: an inline value, or a fork that holds it."""

    value: bytes | None  # inline (kept up to XATTR_VALUE_MAX, decmpfs whole)
    size: int
    fork: Fork | None


def read_attributes(
    volume: HfsVolume,
    charge: Callable[[int, str], None],
) -> tuple[dict[int, dict[str, Attribute]], set[int], ArchiveyError | None]:
    """Every extended attribute, by file id and name; the file ids with a record that
    did not parse (reported on their members); and the error that stopped the walk,
    if one did."""
    found: dict[int, dict[str, Attribute]] = {}
    bad: set[int] = set()
    fork = volume.header.attributes_file
    if not fork.size:
        return found, bad, None
    # The extents of a fork attribute with extent records (0x30), and their block
    # count, gathered in a list so that N records take linear time.
    grown: dict[tuple[int, str], tuple[list[tuple[int, int]], int]] = {}
    failure: ArchiveyError | None = None
    try:
        tree = _BTree(volume, _ATTRIBUTES_FILE, fork, "attributes")
        for key, data in tree.leaf_records():
            if len(key) < 14:
                raise CorruptionError("an HFS+ attribute key is shorter than 14 bytes")
            cnid, _, length = struct.unpack_from(">IIH", key, 4)
            if 14 + 2 * length > len(key):
                bad.add(cnid)
                continue
            name = key[14 : 14 + 2 * length].decode("utf-16-be", "surrogatepass")
            if len(data) < 4:
                bad.add(cnid)
                continue
            (record_type,) = struct.unpack_from(">I", data)
            attrs = found.setdefault(cnid, {})
            if record_type == 0x10:
                if len(data) < 16:
                    bad.add(cnid)
                    continue
                (size,) = struct.unpack_from(">I", data, 12)
                if 16 + size > len(data):
                    bad.add(cnid)
                    continue
                keep = _DECMPFS_KEEP if name == DECMPFS else XATTR_VALUE_MAX
                value = data[16 : 16 + size] if size <= keep else None
                charge(
                    2 * length + (len(value) if value else 0) + 32, "HFS+ attributes"
                )
                attrs[name] = Attribute(value, size, None)
                grown.pop((cnid, name), None)
            elif record_type == 0x20:
                if len(data) < 8 + _FORK.size:
                    bad.add(cnid)
                    continue
                attr_fork = parse_fork(data, 8)
                charge(2 * length + 128, "HFS+ attributes")
                attrs[name] = Attribute(None, attr_fork.size, attr_fork)
                grown.pop((cnid, name), None)
            elif record_type == 0x30:
                # More extents of an attribute's fork: kept with it, in key order.
                existing = attrs.get(name)
                if existing is None or existing.fork is None or len(data) < 8 + 64:
                    bad.add(cnid)
                    continue
                more = struct.unpack_from(">16I", data, 8)
                added = [(more[i], more[i + 1]) for i in range(0, 16, 2) if more[i + 1]]
                charge(_EXTENT_CHARGE * len(added), "HFS+ attributes")
                kept = grown.get((cnid, name))
                if kept is None:
                    extents = list(existing.fork.extents)
                    blocks = sum(count for _, count in extents)
                else:
                    extents, blocks = kept
                extents += added
                blocks += sum(count for _, count in added)
                if blocks > existing.fork.total_blocks:
                    # More blocks than the fork has: the attribute is damaged and
                    # dropped, so its later extent records find nothing to grow.
                    bad.add(cnid)
                    del attrs[name]
                    grown.pop((cnid, name), None)
                    continue
                grown[(cnid, name)] = (extents, blocks)
            else:
                bad.add(cnid)
    except ArchiveyError as exc:
        failure = exc
    for (cnid, name), (extents, _) in grown.items():
        attribute = found[cnid][name]
        if attribute.fork is not None:
            found[cnid][name] = attribute._replace(
                fork=attribute.fork._replace(extents=tuple(extents))
            )
    return found, bad, failure


def attribute_value(volume: HfsVolume, cnid: int, attribute: Attribute) -> bytes:
    """An attribute's whole value: inline, or read from its fork."""
    if attribute.value is not None and attribute.fork is None:
        return attribute.value
    fork = attribute.fork
    if fork is None:
        raise CorruptionError(f"the attribute of file {cnid} was not kept")
    if fork.size > _DECMPFS_KEEP:
        raise CorruptionError(
            f"an attribute of file {cnid} is {fork.size} bytes, more than archivey "
            "reads"
        )
    have = sum(count for _, count in fork.extents)
    if have * volume.header.block_size < fork.size:
        raise CorruptionError(f"an attribute fork of file {cnid} is missing extents")
    bs = volume.header.block_size
    parts = []
    left = fork.size
    for start, count in fork.extents:
        if start + count > volume.header.total_blocks:
            raise CorruptionError(
                f"an attribute extent of file {cnid} is past the volume"
            )
        take = min(left, count * bs)
        parts.append(volume.source.read_exact(start * bs, take))
        left -= take
        if not left:
            break
    return b"".join(parts)


# ── Transparent compression (decmpfs) ────────────────────────────────────────────────


class Decmpfs(NamedTuple):
    kind: int
    size: int
    inline: bytes  # the attribute's bytes after its 16-byte header


def parse_decmpfs(value: bytes) -> Decmpfs:
    if len(value) < 16 or value[:4] != b"fpmc":
        raise CorruptionError("the com.apple.decmpfs attribute has no fpmc header")
    kind, size = struct.unpack_from("<IQ", value, 4)
    return Decmpfs(kind, size, value[16:])


_INLINE = (1, 3, 7, 9, 11)
_IN_RESOURCE_FORK = (4, 8, 10, 12)
_LZVN_KINDS = (7, 8)
_LZFSE_KINDS = (11, 12)


def decmpfs_reader(
    volume: HfsVolume,
    context: ReaderContext,
    cnid: int,
    header: Decmpfs,
    rsrc: Fork,
) -> Callable[[int], bytes]:
    """``read_block(i)`` for a ``block_stream`` of 64 KiB chunks over the decoded
    file. Every length is checked before it is used."""
    kind, size = header.kind, header.size
    if kind not in _INLINE and kind not in _IN_RESOURCE_FORK:
        raise UnsupportedFeatureError(
            f"HFS+ transparent compression type {kind} is not supported"
        )
    method = (
        CompressionAlgorithm.LZVN
        if kind in _LZVN_KINDS
        else CompressionAlgorithm.LZFSE
        if kind in _LZFSE_KINDS
        else None
    )
    if method is not None:
        refusal = context.config.formats._codec_refusal(method)
        if refusal is not None:
            raise UnsupportedFeatureError(f"{refusal}.")
    chunks = -(-size // DECMPFS_CHUNK)

    def expected(index: int) -> int:
        return min(DECMPFS_CHUNK, size - index * DECMPFS_CHUNK)

    if kind in _INLINE:
        if size > DECMPFS_CHUNK:
            raise CorruptionError(
                f"file {cnid} declares {size} bytes of inline compressed data, more "
                "than one 64 KiB chunk"
            )

        def inline_block(index: int) -> bytes:
            return _decode_chunk(context, kind, header.inline, size, cnid)

        return inline_block
    if not rsrc.size:
        raise CorruptionError(
            f"file {cnid} is compressed in its resource fork, which is empty"
        )
    read = volume.fork_reader(cnid, RESOURCE_FORK, rsrc)
    fork_size = rsrc.size
    if kind == 4:
        if fork_size < 260:
            raise CorruptionError(f"the resource fork of file {cnid} is too short")
        (data_at,) = struct.unpack(">I", read(0, 4))
        base = data_at + 4
        if base + 4 > fork_size:
            raise CorruptionError(f"the resource fork of file {cnid} has no data")
        (count,) = struct.unpack("<I", read(base, 4))
        if count != chunks:
            raise CorruptionError(
                f"the compressed file {cnid} has {count} chunks, not the {chunks} its "
                f"{size} bytes need"
            )
        if base + 4 + 8 * count > fork_size:
            raise CorruptionError(f"the chunk table of file {cnid} runs past its fork")

        def chunk_range(index: int) -> tuple[int, int]:
            offset, length = struct.unpack("<II", read(base + 4 + 8 * index, 8))
            return base + offset, length

    else:
        if 4 * (chunks + 1) > fork_size:
            raise CorruptionError(f"the chunk table of file {cnid} runs past its fork")

        def chunk_range(index: int) -> tuple[int, int]:
            start, end = struct.unpack("<II", read(4 * index, 8))
            if end < start:
                raise CorruptionError(
                    f"chunk {index} of file {cnid} ends before it starts"
                )
            return start, end - start

    def fork_block(index: int) -> bytes:
        start, length = chunk_range(index)
        if start + length > fork_size or length > 2 * DECMPFS_CHUNK:
            raise CorruptionError(
                f"chunk {index} of the compressed file {cnid} ({length} bytes at "
                f"{start}) is outside its resource fork"
            )
        return _decode_chunk(context, kind, read(start, length), expected(index), cnid)

    return fork_block


def _decode_chunk(
    context: ReaderContext,
    kind: int,
    data: bytes,
    want: int,
    cnid: int,
) -> bytes:
    """One decmpfs chunk, which must decode to exactly ``want`` bytes."""
    try:
        if kind == 1:
            out = data
        elif kind == 10:
            # Each chunk is its raw block behind a 0xCC byte. The macOS kernel reads
            # that layout and refuses a chunk without the byte (EINVAL), as the macOS
            # check against hdiutil found (tasks.md §M).
            if data[:1] != b"\xcc":
                raise CorruptionError(
                    f"a type 10 chunk of the compressed file {cnid} does not start "
                    "with the 0xCC byte macOS requires"
                )
            out = data[1:]
        elif kind == 9:
            # 7-Zip (``HfsHandler.cpp``) reads type 9 only after a 0xCC byte and
            # refuses it without; no macOS sample shows what Apple writes or accepts
            # (design §6.6). Without the marker the file is not known to be damaged,
            # only not read the way 7-Zip reads it.
            if data[:1] != b"\xcc":
                raise UnsupportedFeatureError(
                    f"the compressed file {cnid} stores type 9 data without the 0xCC "
                    "byte 7-Zip reads it after; archivey does not read it"
                )
            out = data[1:]
        elif kind in (3, 4):
            if data[:1] and data[0] & 0x0F == 0x0F:
                out = data[1:]
            else:
                with context.decompress(io.BytesIO(data), StreamFormat.ZLIB) as stream:
                    out = stream.read(want + 1)
                    while len(out) <= want and (
                        more := stream.read(want + 1 - len(out))
                    ):
                        out += more
        # The LZVN and LZFSE decoders refuse any output past ``want`` themselves, and
        # their message names ``want``.
        elif kind in _LZVN_KINDS:
            out = data[1:] if data[:1] == b"\x06" else lzvn_decompress(data, want)
        else:
            out = data[1:] if data[:1] == b"\xff" else lzfse_decompress(data, want)
    except (CorruptionError, TruncatedError) as exc:
        raise CorruptionError(f"the compressed data of file {cnid}: {exc}") from None
    if len(out) != want:
        raise CorruptionError(
            f"a compressed chunk of file {cnid} (type {kind}) decodes to "
            f"{'more than ' + str(want) if len(out) > want else len(out)} bytes, not "
            f"{want}"
        )
    return out
