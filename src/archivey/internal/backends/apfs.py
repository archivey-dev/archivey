"""APFS containers and volumes, read as the Mac mounts them (Apple, *Apple File System
Reference*, 2020).

This module parses; it makes no ``ArchiveMember``, as :mod:`.hfsplus` makes none.
:class:`ApfsContainer` checks block 0 when the image opens (design §7 of
``openspec/changes/dmg-reader``) and reads the rest at the first listing (§6A):

- the checkpoint: the newest container superblock in the checkpoint descriptor ring
  whose checkpoint is complete (every checkpoint-map block valid);
- the object maps: a B-tree from (object id, transaction id) to a block, one for the
  container (it maps the volume superblocks) and one per volume (it maps the
  filesystem tree's nodes);
- each volume's filesystem tree (:meth:`ApfsVolume.walk`): inodes, directory records,
  extended attributes and file extents, kept in memory and charged.

Every object carries a Fletcher-64 checksum, checked on every read (D7). A node that
fails it, or any other check, is skipped: the walk records the key range its verified
parent gave it (:class:`Damage`) and goes on with its siblings. A later lookup that
lands in such a range raises ``CorruptionError`` instead of reporting the record as
absent, so a hole in a file never reads as zeros when its extents may be in a lost node.

Every offset and count is checked before it is used: blocks inside the container,
records inside their node, extended fields inside their value. A file is read in pieces
through its extents, never whole.
"""

from __future__ import annotations

import bisect
import itertools
import struct
from array import array
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from typing import NamedTuple

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import ReaderContext, ReaderSource
from archivey.terminal import quoted

_OBJECT = struct.Struct("<QQQII")  # checksum, oid, xid, type, subtype
_NODE = struct.Struct("<HHIHH")  # flags, level, keys, table offset, table length
_NODE_AT = 32
_NODE_DATA = 56
_INFO = struct.Struct("<IIIIIIQQ")  # flags, node size, key size, value size, ...
_OMAP_VALUE = struct.Struct("<IIQ")  # flags, size, physical address
_INODE = struct.Struct("<QQQQQQQiIIIIIHHQ")
_XFIELD = struct.Struct("<BBH")
_EXTENT = struct.Struct("<QQQ")  # length and flags, physical block, crypto id
_DREC = struct.Struct("<QQH")  # file id, date added, flags

NX_MAGIC = b"NXSB"
_APSB_MAGIC = b"APSB"

_TYPE_MASK = 0xFFFF
_PHYSICAL = 0x40000000
_T_NX = 0x1
_T_BTREE = 0x2
_T_BTREE_NODE = 0x3
_T_OMAP = 0xB
_T_CHECKPOINT_MAP = 0xC
_T_FS = 0xD

_ROOT, _LEAF, _FIXED = 0x1, 0x2, 0x4
_CHECKPOINT_MAP_LAST = 0x1
_OMAP_DELETED = 0x1
_OMAP_ENCRYPTED = 0x4

# Container incompatible features.
_NX_VERSION1 = 0x1
_NX_FUSION = 0x100
# Volume flags and incompatible features.
_FS_UNENCRYPTED = 0x1
_CASE_INSENSITIVE = 0x1
_NORMALIZATION_INSENSITIVE = 0x8
_SEALED = 0x20

# Filesystem record types (the top four bits of a key's first word).
INODE, XATTR, SIBLING_LINK, DSTREAM_ID, EXTENT, DIR_REC = 3, 4, 5, 6, 8, 9
_OID_MASK = (1 << 60) - 1
_INO_EXT_DSTREAM = 8
_XATTR_STREAM, _XATTR_EMBEDDED = 0x1, 0x2

ROOT_DIRECTORY = 2
# Directories no path from the root reaches: the parent of the root and private
# directories, and the private directory, which holds the volume's own files.
UNREACHED_DIRECTORIES = frozenset((1, 3))
UF_COMPRESSED = 0x20
SYMLINK_XATTR = "com.apple.fs.symlink"
DECMPFS_XATTR = "com.apple.decmpfs"
RESOURCE_FORK_XATTR = "com.apple.ResourceFork"

MIN_BLOCK_SIZE = 4096
MAX_BLOCK_SIZE = 65536
# The checkpoint scan reads and decodes at most SCAN_BUDGET bytes (the open budget's
# size, counted on its own). The ring cap is structural: SCAN_BUDGET already bounds the
# work, so the cap only refuses an absurd header before any read.
MAX_DESC_BLOCKS = 65536
SCAN_BUDGET = 64 << 20
# Structural: real nodes hold about 100 entries or more, so 10 levels already
# address more than 2^64 blocks; 32 leaves room, and refuses a corrupt level field
# before the walk descends.
MAX_DEPTH = 32
# The block a file read gathers at a time through its extents.
READ_PIECE = 1 << 20
# The format's NX_MAX_FILE_SYSTEMS: the superblock's volume array has this many slots.
_MAX_VOLUMES = 100
# A filesystem node's records cost about this much each beyond their bytes.
_RECORD_COST = 64
# What one damaged range holds beyond its reason's text (the tuple, its bounds and
# the index's entry for it), measured on CPython 3.11.
_DAMAGE_COST = 200
# A data stream with more extents and damaged ranges than this has its check kept
# (``stream_reader``). One kept check holds at most _VIEW_COST bytes, and
# _VIEW_RANGE_COST more per damaged range it bounds (the range itself is charged
# already); measured on CPython 3.11.
_KEPT_VIEW_MIN = 16
_VIEW_COST = 256
_VIEW_RANGE_COST = 64


def fletcher64(block: bytes) -> int:
    """APFS's object checksum: Fletcher-64 over the block's 32-bit words after the
    first 8 bytes (which hold the checksum)."""
    n = (len(block) - 8) // 4
    words = struct.unpack_from(f"<{n}I", block, 8)
    m = 0xFFFFFFFF
    s1 = sum(words)
    # sum1 after each word, summed: each word counts once per word from it on.
    s2 = n * s1 - sum(i * w for i, w in enumerate(words))
    s1 %= m
    s2 %= m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return (c2 << 32) | c1


def seal(block: bytearray) -> None:
    """Write ``block``'s Fletcher-64 into its first 8 bytes."""
    struct.pack_into("<Q", block, 0, fletcher64(bytes(block)))


class Damage(NamedTuple):
    """A node the walk skipped: the range of order keys its parent gave it (``None``
    for no bound), and its block."""

    low: tuple[int, ...] | None
    high: tuple[int, ...] | None
    address: int
    reason: str


_BELOW: tuple[int, ...] = ()
_ABOVE: tuple[float, ...] = (float("inf"),)


class DamageIndex:
    """The damaged ranges of one tree, with lookups in logarithmic time: the ranges
    are merged into disjoint intervals sorted by key, so the intervals that meet a
    query are one run found by bisection. A range's bounds count as inside it."""

    def __init__(self, charge: Callable[[int], None] | None = None) -> None:
        # Each range is counted as it is added, so a node full of entries that name
        # a missing child stops at the metadata cap instead of after the walk.
        self._charge = charge
        self._items: list[Damage] = []
        # (low, high, the first range merged in), disjoint and in key order.
        self._merged: list[tuple[tuple[float, ...], tuple[float, ...], Damage]] | None
        self._merged = None

    def append(self, item: Damage) -> None:
        if self._charge is not None:
            self._charge(_DAMAGE_COST + len(item.reason))
        self._items.append(item)
        self._merged = None

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, index: int) -> Damage:
        return self._items[index]

    def _intervals(self) -> list[tuple[tuple[float, ...], tuple[float, ...], Damage]]:
        if self._merged is None:
            merged: list[tuple[tuple[float, ...], tuple[float, ...], Damage]] = []
            spans = sorted(
                (
                    _BELOW if each.low is None else each.low,
                    _ABOVE if each.high is None else each.high,
                    i,
                )
                for i, each in enumerate(self._items)
            )
            for low, high, i in spans:
                if merged and low <= merged[-1][1]:
                    last = merged[-1]
                    merged[-1] = (last[0], max(last[1], high), last[2])
                else:
                    merged.append((low, high, self._items[i]))
            self._merged = merged
        return self._merged

    def meeting(
        self, low: tuple[float, ...], high: tuple[float, ...]
    ) -> Iterator[Damage]:
        """The merged ranges that meet the key range [``low``, ``high``], in key
        order, each with its merged bounds (``None`` for no bound) and the address
        and reason of the first range merged into it."""
        merged = self._intervals()
        i = bisect.bisect_left(merged, low, key=lambda m: m[1])
        while i < len(merged) and merged[i][0] <= high:
            start, end, first = merged[i]
            yield Damage(
                None if start == _BELOW else tuple(int(k) for k in start),
                None if end == _ABOVE else tuple(int(k) for k in end),
                first.address,
                first.reason,
            )
            i += 1

    def holding(self, prefix: tuple[int, ...]) -> Iterator[Damage]:
        """The merged ranges that may hold a key starting with ``prefix``."""
        return self.meeting(prefix, (*prefix, float("inf")))

    def first_holding(self, prefix: tuple[int, ...]) -> Damage | None:
        return next(self.holding(prefix), None)


# ── Objects and B-trees ──────────────────────────────────────────────────────────────


class _Blocks:
    """The container's blocks, each checked against the block count before it is
    read."""

    def __init__(self, source: ReaderSource, block_size: int, block_count: int) -> None:
        self.source = source
        self.size = block_size
        self.count = block_count

    def read(self, address: int) -> bytes:
        if not 0 < address < self.count:
            raise CorruptionError(
                f"an APFS object at block {address} is outside the container's "
                f"{self.count} blocks"
            )
        try:
            return self.source.read_exact(address * self.size, self.size)
        except TruncatedError:
            raise TruncatedError(
                f"the APFS container's block {address} is past the end of its partition"
            ) from None

    def object(
        self, address: int, kinds: tuple[int, ...], *, oid: int | None, max_xid: int
    ) -> bytes:
        """The object at ``address``: its checksum good, its type one of ``kinds``,
        its own id ``oid`` (a physical object's is its address), and written no later
        than ``max_xid``."""
        block = self.read(address)
        checksum, own, xid, kind, _ = _OBJECT.unpack_from(block)
        if fletcher64(block) != checksum:
            raise CorruptionError(
                f"the APFS object at block {address} fails its checksum"
            )
        if kind & _TYPE_MASK not in kinds:
            raise CorruptionError(
                f"the APFS object at block {address} is of type "
                f"0x{kind & _TYPE_MASK:x}, not the one expected there"
            )
        want = address if oid is None else oid
        if own != want:
            raise CorruptionError(
                f"the APFS object at block {address} is object {own}, not {want}"
            )
        if xid > max_xid:
            raise CorruptionError(
                f"the APFS object at block {address} was written by transaction {xid}, "
                f"after the checkpoint's {max_xid}"
            )
        return block


class _Node(NamedTuple):
    leaf: bool
    level: int
    records: list[tuple[bytes, bytes]]
    info: tuple[int, ...] | None  # the root's btree_info_t


def _parse_node(
    block: bytes, block_size: int, info: tuple[int, ...] | None, root: bool
) -> _Node:
    """A B-tree node's records as (key, value) bytes, every one checked to lie inside
    the node."""
    flags, level, count, toc_at, toc_length = _NODE.unpack_from(block, _NODE_AT)
    if bool(flags & _ROOT) != root:
        raise CorruptionError(
            "an APFS B-tree node is marked root where it is not, or the reverse"
        )
    leaf = bool(flags & _LEAF)
    if leaf != (level == 0) or level > MAX_DEPTH:
        raise CorruptionError(
            f"an APFS B-tree node has level {level} and leaf flag {leaf}"
        )
    if root:
        info = _INFO.unpack_from(block, block_size - _INFO.size)
        if info[1] != block_size:
            raise CorruptionError(
                f"an APFS B-tree's nodes are {info[1]} bytes, not the container's "
                f"{block_size}-byte blocks"
            )
    if info is None:
        raise CorruptionError("an APFS B-tree node is read without its tree's root")
    fixed = bool(flags & _FIXED)
    toc = _NODE_DATA + toc_at
    keys_at = toc + toc_length
    values_end = block_size - (_INFO.size if root else 0)
    entry = 4 if fixed else 8
    if count * entry > toc_length or keys_at > values_end:
        raise CorruptionError(
            f"an APFS B-tree node declares {count} records, more than its table holds"
        )
    records = []
    for i in range(count):
        if fixed:
            key_at, value_at = struct.unpack_from("<HH", block, toc + 4 * i)
            key_length = info[2]
            value_length = info[3] if leaf else 8
        else:
            key_at, key_length, value_at, value_length = struct.unpack_from(
                "<HHHH", block, toc + 8 * i
            )
        k0 = keys_at + key_at
        v0 = values_end - value_at
        if not (
            k0 + key_length <= values_end and keys_at <= v0 <= values_end - value_length
        ):
            raise CorruptionError("an APFS B-tree record lies outside its node")
        records.append((block[k0 : k0 + key_length], block[v0 : v0 + value_length]))
    return _Node(leaf, level, records, info)


class _Leaf(NamedTuple):
    """A leaf's records, with the key range its parent gave it and its block: the
    ``Damage`` to record when a record in it does not parse."""

    records: list[tuple[bytes, bytes]]
    low: tuple[int, ...] | None
    high: tuple[int, ...] | None
    address: int

    def damage(self, reason: str) -> Damage:
        return Damage(self.low, self.high, self.address, reason)


def _walk(
    blocks: _Blocks,
    root: int,
    *,
    subtype: str,
    max_xid: int,
    order: Callable[[bytes], tuple[int, ...]],
    resolve: Callable[[int], int] | None,
    damage: DamageIndex,
    seen: set[int],
) -> Iterator[_Leaf]:
    """The leaves of a B-tree, in key order. ``root`` is the root node's address, or
    its virtual id when ``resolve`` maps ids to addresses (a filesystem tree). A node
    that cannot be used is added to ``damage`` with the key range its parent gave it,
    and the walk goes on."""
    # (node id or address, low bound, high bound, the level the parent expects)
    stack: list[
        tuple[int, tuple[int, ...] | None, tuple[int, ...] | None, int | None]
    ] = [(root, None, None, None)]
    info: tuple[int, ...] | None = None
    while stack:
        ident, low, high, level = stack.pop()
        address = ident
        try:
            if resolve is not None:
                address = resolve(ident)
            if address in seen:
                raise CorruptionError(
                    f"the APFS {subtype} tree reaches the node at block {address} twice"
                )
            seen.add(address)
            block = blocks.object(
                address,
                (_T_BTREE,) if level is None else (_T_BTREE_NODE,),
                oid=ident if resolve is not None else None,
                max_xid=max_xid,
            )
            node = _parse_node(block, blocks.size, info, level is None)
            if level is not None and node.level != level:
                raise CorruptionError(
                    f"the APFS {subtype} tree's node at block {address} is at level "
                    f"{node.level}, not {level}"
                )
            if level is None:
                info = node.info
            keys = [order(key) for key, _ in node.records]
            if any(b < a for a, b in itertools.pairwise(keys)) or (
                keys
                and (
                    (low is not None and keys[0] < low)
                    or (high is not None and keys[-1] > high)
                )
            ):
                raise CorruptionError(
                    f"the APFS {subtype} tree's node at block {address} holds keys out "
                    "of order"
                )
        except (CorruptionError, TruncatedError) as exc:
            damage.append(Damage(low, high, address, str(exc)))
            continue
        if node.leaf:
            yield _Leaf(node.records, low, high, address)
            continue
        children = []
        for i, (_key, value) in enumerate(node.records):
            if len(value) < 8:
                damage.append(Damage(keys[i], high, address, "short index value"))
                break
            (child,) = struct.unpack_from("<Q", value)
            upper = keys[i + 1] if i + 1 < len(keys) else high
            children.append((child, keys[i], upper, node.level - 1))
        stack.extend(reversed(children))


# ── Object maps ──────────────────────────────────────────────────────────────────────


def _omap_order(key: bytes) -> tuple[int, ...]:
    if len(key) < 16:
        raise CorruptionError("an APFS object map key is shorter than 16 bytes")
    return struct.unpack_from("<QQ", key)


class _Omap:
    """An object map, read whole: each object id's newest entry at or before the
    checkpoint's transaction, tombstones included."""

    def __init__(
        self,
        blocks: _Blocks,
        address: int,
        max_xid: int,
        what: str,
        charge: Callable[[int, str], None],
    ) -> None:
        self.what = what
        self.max_xid = max_xid
        self.damage = DamageIndex(lambda n: charge(n, what))
        # oid -> (xid, flags, address)
        self.entries: dict[int, tuple[int, int, int]] = {}
        try:
            head = blocks.object(address, (_T_OMAP,), oid=None, max_xid=max_xid)
        except (CorruptionError, TruncatedError) as exc:
            self.damage.append(Damage(None, None, address, str(exc)))
            return
        (tree,) = struct.unpack_from("<Q", head, 48)
        for leaf in _walk(
            blocks,
            tree,
            subtype="object map",
            max_xid=max_xid,
            order=_omap_order,
            resolve=None,
            damage=self.damage,
            seen=set(),
        ):
            charge(len(leaf.records) * _RECORD_COST, what)
            # A leaf is all or nothing: a value that does not parse drops the leaf.
            found: list[tuple[int, int, int, int]] = []
            for key, value in leaf.records:
                oid, xid = struct.unpack_from("<QQ", key)
                if xid > max_xid:
                    continue
                if len(value) < _OMAP_VALUE.size:
                    self.damage.append(leaf.damage("a value shorter than 16 bytes"))
                    break
                flags, _, where = _OMAP_VALUE.unpack_from(value)
                found.append((oid, xid, flags, where))
            else:
                for oid, xid, flags, where in found:
                    best = self.entries.get(oid)
                    if best is None or best[0] < xid:
                        self.entries[oid] = (xid, flags, where)

    def lookup(self, oid: int) -> tuple[int, int] | None:
        """``(address, flags)`` of object ``oid``, or ``None`` when the map has no
        live entry for it. ``CorruptionError`` when an entry newer than the one found
        may be in a damaged node."""
        found = self.entries.get(oid)
        after = found[0] + 1 if found is not None else 0
        for each in self.damage.meeting((oid, after), (oid, self.max_xid)):
            raise CorruptionError(
                f"APFS object {oid} is mapped by a damaged node of {self.what} (block "
                f"{each.address}: {each.reason})"
            )
        if found is None or found[1] & _OMAP_DELETED:
            return None
        return found[2], found[1]

    def address(self, oid: int) -> int:
        found = self.lookup(oid)
        if found is None:
            raise CorruptionError(f"{self.what} has no entry for object {oid}")
        return found[0]


# ── The container ────────────────────────────────────────────────────────────────────


class _Superblock(NamedTuple):
    block_size: int
    block_count: int
    incompatible: int
    desc_blocks: int
    desc_base: int
    desc_index: int
    desc_length: int
    omap: int
    volumes: tuple[int, ...]
    xid: int


def _superblock(block: bytes) -> _Superblock:
    (block_size,) = struct.unpack_from("<I", block, 36)
    (block_count,) = struct.unpack_from("<Q", block, 40)
    (incompatible,) = struct.unpack_from("<Q", block, 64)
    desc_blocks, _, desc_base = struct.unpack_from("<IIQ", block, 104)
    desc_index, desc_length = struct.unpack_from("<II", block, 136)
    (omap,) = struct.unpack_from("<Q", block, 160)
    volumes = tuple(v for v in struct.unpack_from(f"<{_MAX_VOLUMES}Q", block, 184) if v)
    (xid,) = struct.unpack_from("<Q", block, 16)
    return _Superblock(
        block_size,
        block_count,
        incompatible,
        desc_blocks,
        desc_base,
        desc_index,
        desc_length,
        omap,
        volumes,
        xid,
    )


def _refuse_container(incompatible: int) -> None:
    if incompatible & _NX_FUSION:
        raise UnsupportedFeatureError("APFS Fusion containers are not supported")
    if incompatible & _NX_VERSION1:
        raise UnsupportedFeatureError(
            "APFS containers in the prerelease version 1 layout are not supported"
        )


class RefusedVolume(NamedTuple):
    name: str
    reason: str


class ApfsContainer:
    """One APFS container: block 0 checked at open, the checkpoint and volumes read by
    :meth:`load` at the first listing."""

    def __init__(
        self,
        source: ReaderSource,
        context: ReaderContext,
        report: Callable[[str, str, int], None],
    ) -> None:
        self.source = source
        self.context = context
        self._report = report
        head = source.read_exact(0, MIN_BLOCK_SIZE)
        if head[32:36] != NX_MAGIC:
            raise CorruptionError("no APFS container superblock (NXSB) at block 0")
        (block_size,) = struct.unpack_from("<I", head, 36)
        if not MIN_BLOCK_SIZE <= block_size <= MAX_BLOCK_SIZE or block_size & (
            block_size - 1
        ):
            raise CorruptionError(f"the APFS block size {block_size} is not valid")
        if block_size > MIN_BLOCK_SIZE:
            head = source.read_exact(0, block_size)
        checksum, _, _, kind, _ = _OBJECT.unpack_from(head)
        if fletcher64(head) != checksum or kind & _TYPE_MASK != _T_NX:
            raise CorruptionError("the APFS container superblock at block 0 is damaged")
        first = _superblock(head)
        _refuse_container(first.incompatible)
        partition = source.size or 0
        if first.block_count * block_size > partition:
            raise CorruptionError(
                f"the APFS container declares {first.block_count} blocks of "
                f"{block_size} bytes, more than its {partition}-byte partition"
            )
        if first.desc_blocks & 0x80000000:
            raise UnsupportedFeatureError(
                "APFS containers whose checkpoint area is not contiguous are not "
                "supported"
            )
        if not 0 < first.desc_blocks <= MAX_DESC_BLOCKS:
            raise CorruptionError(
                f"the APFS checkpoint area declares {first.desc_blocks} blocks"
            )
        if (
            first.desc_base + first.desc_blocks > first.block_count
            or not first.desc_base
        ):
            raise CorruptionError("the APFS checkpoint area is outside the container")
        self._first = first
        self._blocks = _Blocks(source, block_size, first.block_count)

    @property
    def block_size(self) -> int:
        return self._blocks.size

    def _checkpoint(self) -> _Superblock:
        """The newest container superblock in the descriptor ring whose checkpoint is
        complete (design §6A.2)."""
        first = self._first
        ring = first.desc_blocks
        # Per ring index: (type, xid, checksum good, checkpoint-map flags).
        seen: list[tuple[int, int, bool, int]] = []
        candidates: list[tuple[int, int, bytes]] = []  # (xid, index, block)
        for index in range(ring):
            try:
                block = self._blocks.read(first.desc_base + index)
            except (CorruptionError, TruncatedError):
                seen.append((0, 0, False, 0))
                continue
            checksum, _, xid, kind, _ = _OBJECT.unpack_from(block)
            good = fletcher64(block) == checksum
            kind &= _TYPE_MASK
            (flags,) = struct.unpack_from("<I", block, 32)
            seen.append((kind, xid, good, flags))
            if good and kind == _T_NX and block[32:36] == NX_MAGIC:
                candidates.append((xid, index, block))
        candidates.sort(reverse=True)
        for xid, index, block in candidates:
            found = _superblock(block)
            problem = self._incomplete(found, index, seen)
            if problem is None:
                return found
            self._report(
                "apfs_checkpoint",
                (
                    f"The APFS checkpoint of transaction {xid} is incomplete ({problem}); "
                    "an older one is looked for."
                ),
                (first.desc_base + index) * self._blocks.size,
            )
        raise CorruptionError("the APFS container has no complete checkpoint")

    def _incomplete(
        self, found: _Superblock, index: int, seen: list[tuple[int, int, bool, int]]
    ) -> str | None:
        first = self._first
        ring = first.desc_blocks
        if (found.block_size, found.desc_blocks, found.desc_base) != (
            self._blocks.size,
            ring,
            first.desc_base,
        ):
            return "its geometry differs from block 0's"
        if not found.desc_index < ring or not 2 <= found.desc_length <= ring:
            return "its descriptor span is outside the ring"
        if (found.desc_index + found.desc_length - 1) % ring != index:
            return "its descriptor span does not end at the superblock"
        for step in range(found.desc_length - 1):
            kind, xid, good, flags = seen[(found.desc_index + step) % ring]
            if not good or kind != _T_CHECKPOINT_MAP or xid != found.xid:
                return f"checkpoint-map block {step + 1} is missing or damaged"
            last = step == found.desc_length - 2
            if bool(flags & _CHECKPOINT_MAP_LAST) != last:
                return "its checkpoint-map blocks are not marked in order"
        if found.block_count != first.block_count:
            return "its block count differs from block 0's"
        return None

    def load(
        self,
        budget: Callable[[], AbstractContextManager[object]],
        charge: Callable[[int, str], None],
    ) -> tuple[list[ApfsVolume], list[RefusedVolume], list[str]]:
        """The volumes: those archivey reads, those it refuses (encrypted, sealed),
        and the problems that lost others (each becomes the listing's error)."""
        with budget():
            nx = self._checkpoint()
        _refuse_container(nx.incompatible)
        omap = _Omap(
            self._blocks, nx.omap, nx.xid, "the APFS container's object map", charge
        )
        volumes: list[ApfsVolume] = []
        refused: list[RefusedVolume] = []
        lost: list[str] = []
        for oid in nx.volumes:
            try:
                found = omap.lookup(oid)
                if found is None:
                    raise CorruptionError(
                        f"the APFS container's object map has no entry for volume {oid}"
                    )
                address, flags = found
                block = self._blocks.object(address, (_T_FS,), oid=oid, max_xid=nx.xid)
                if block[32:36] != _APSB_MAGIC:
                    raise CorruptionError(f"APFS volume {oid} has no APSB magic")
                volume = ApfsVolume(self, block, oid, nx.xid, charge)
                reason = volume.refusal(flags)
                if reason is not None:
                    refused.append(RefusedVolume(volume.name, reason))
                    continue
                volume.load_omap()
                volumes.append(volume)
            except (CorruptionError, TruncatedError) as exc:
                lost.append(str(exc))
        return volumes, refused, lost


# ── Volumes and the filesystem tree ──────────────────────────────────────────────────


def _fs_order(key: bytes) -> tuple[int, ...]:
    """The part of a filesystem key that orders it here: object id, record type, and
    a file extent's offset. Names are left out: the hashed-name order compares hashes
    that may collide, and nothing here needs an order finer than this."""
    if len(key) < 8:
        raise CorruptionError("an APFS filesystem key is shorter than 8 bytes")
    (word,) = struct.unpack_from("<Q", key)
    kind = word >> 60
    if kind == EXTENT:
        if len(key) < 16:
            raise CorruptionError("an APFS file extent key is shorter than 16 bytes")
        return (word & _OID_MASK, kind, struct.unpack_from("<Q", key, 8)[0])
    return (word & _OID_MASK, kind, 0)


class Inode(NamedTuple):
    parent: int
    stream: int  # the data stream's id
    created: int  # ns since 1970, UTC
    modified: int
    nlink: int
    bsd_flags: int
    uid: int
    gid: int
    mode: int
    size: int  # the data stream's size; 0 without one


class Xattr(NamedTuple):
    """An extended attribute: its bytes when embedded, else its stream and size."""

    value: bytes | None
    stream: int
    size: int


class Child(NamedTuple):
    name: bytes  # as stored, without its trailing NUL
    file_id: int
    kind: int  # DT_* type


def _xfields(blob: bytes) -> Iterator[tuple[int, bytes]]:
    """An inode's extended fields as (type, value), every one inside ``blob``."""
    if len(blob) < 4:
        return
    count, used = struct.unpack_from("<HH", blob)
    data_at = 4 + 4 * count
    if data_at + used > len(blob):
        raise CorruptionError("an APFS inode's extended fields run past its record")
    at = data_at
    for i in range(count):
        kind, _, size = _XFIELD.unpack_from(blob, 4 + 4 * i)
        if at + size > data_at + used:
            raise CorruptionError("an APFS inode's extended field runs past its record")
        yield kind, blob[at : at + size]
        at += (size + 7) & ~7


def _name(raw: bytes) -> bytes:
    return raw[:-1] if raw.endswith(b"\0") else raw


class FsTree:
    """What a volume's filesystem tree holds, as the walk found it."""

    def __init__(self, charge: Callable[[int], None] | None = None) -> None:
        self.inodes: dict[int, Inode] = {}
        self.children: dict[int, list[Child]] = {}
        self.xattrs: dict[int, dict[str, Xattr]] = {}
        # Per data stream: logical offset, length, block, flattened, in key order.
        self.extents: dict[int, array[int]] = {}
        self.encrypted_streams: set[int] = set()
        # Per inode: how many sibling-link records (one per hard-link name) it has.
        self.siblings: dict[int, int] = {}
        self.damage = DamageIndex(charge)
        # Per data stream: its checked extents, for a stream costly to check
        # (``stream_reader``). A kept check stays true for the life of the tree:
        # ``extents`` and ``damage`` are complete once ``ApfsVolume.walk`` returns,
        # and nothing adds to them after it.
        self.stream_views: dict[int, _StreamView] = {}
        self._charge = charge

    def keep_view(self, stream: int, view: _StreamView) -> None:
        if self._charge is not None:
            self._charge(_VIEW_COST + _VIEW_RANGE_COST * len(view.lows))
        self.stream_views[stream] = view

    def damaged(self, oid: int, kind: int) -> Damage | None:
        """The damaged range that may hold a record (``oid``, ``kind``), if any."""
        return self.damage.first_holding((oid, kind))


class ApfsVolume:
    """One volume of a container: its superblock and object map, and the walk of its
    filesystem tree."""

    def __init__(
        self,
        container: ApfsContainer,
        block: bytes,
        oid: int,
        xid: int,
        charge: Callable[[int, str], None],
    ) -> None:
        self.container = container
        self.oid = oid
        self.xid = xid
        self._charge = charge
        (self.incompatible,) = struct.unpack_from("<Q", block, 56)
        (self.fs_flags,) = struct.unpack_from("<Q", block, 264)
        (root_type,) = struct.unpack_from("<I", block, 116)
        self._omap_address, self._root = struct.unpack_from("<QQ", block, 128)
        self._root_virtual = not root_type & _PHYSICAL
        self.raw_name = block[704:960].split(b"\0", 1)[0]
        self.name = container.context.decode_name(self.raw_name)
        self.hashed = bool(
            self.incompatible & (_CASE_INSENSITIVE | _NORMALIZATION_INSENSITIVE)
        )
        self._omap: _Omap | None = None

    def refusal(self, omap_flags: int) -> str | None:
        if not self.fs_flags & _FS_UNENCRYPTED or omap_flags & _OMAP_ENCRYPTED:
            return "an encrypted APFS volume"
        if self.incompatible & _SEALED:
            return "a sealed APFS volume"
        return None

    def load_omap(self) -> None:
        blocks = self.container._blocks
        self._omap = _Omap(
            blocks,
            self._omap_address,
            self.xid,
            f"the object map of APFS volume {quoted(self.name)}",
            self._charge,
        )

    def _resolve(self, oid: int) -> int:
        assert self._omap is not None
        found = self._omap.lookup(oid)
        if found is None:
            raise CorruptionError(
                f"the object map of APFS volume {quoted(self.name)} has no entry for node {oid}"
            )
        if found[1] & _OMAP_ENCRYPTED:
            # The volume was read as not encrypted, so this mapping contradicts it:
            # damage to the node it leads to, as any bad mapping is, and not a
            # refusal of the whole archive.
            raise CorruptionError(
                f"the object map of APFS volume {quoted(self.name)} marks node {oid} "
                "encrypted, but the volume is not encrypted"
            )
        return found[0]

    def walk(self) -> FsTree:
        """Every record of the live filesystem tree, in key order. A damaged node is
        skipped and its range recorded in ``FsTree.damage``."""
        blocks = self.container._blocks
        charge = self._charge
        what = f"the APFS volume {quoted(self.name)}"
        tree = FsTree(lambda n: charge(n, what))
        for leaf in _walk(
            blocks,
            self._root,
            subtype="filesystem",
            max_xid=self.xid,
            order=_fs_order,
            resolve=self._resolve if self._root_virtual else None,
            damage=tree.damage,
            seen=set(),
        ):
            records = leaf.records
            charge(
                sum(len(k) + len(v) for k, v in records) + _RECORD_COST * len(records),
                what,
            )
            try:
                self._add(tree, records)
            except (CorruptionError, TruncatedError) as exc:
                tree.damage.append(leaf.damage(str(exc)))
        return tree

    def _add(self, tree: FsTree, records: list[tuple[bytes, bytes]]) -> None:
        """One leaf's records into ``tree``. A record that does not parse is damage
        in a node whose checksum passed: the leaf is all or nothing, so it is parsed
        in full before anything is kept, and the error leaves ``tree`` as it was."""
        inodes: list[tuple[int, Inode]] = []
        children: list[tuple[int, Child]] = []
        xattrs: list[tuple[int, str, Xattr]] = []
        extents: list[tuple[int, int, int, int, int]] = []
        siblings: list[int] = []
        for key, value in records:
            (word,) = struct.unpack_from("<Q", key)
            oid, kind = word & _OID_MASK, word >> 60
            if kind == INODE:
                inodes.append((oid, _inode(value)))
            elif kind == DIR_REC:
                children.append((oid, self._child(key, value)))
            elif kind == XATTR:
                name, attr = _xattr(key, value)
                xattrs.append((oid, self.container.context.decode_name(name), attr))
            elif kind == SIBLING_LINK:
                siblings.append(oid)
            elif kind == EXTENT:
                if len(value) < _EXTENT.size:
                    raise CorruptionError("an APFS file extent value is too short")
                (logical,) = struct.unpack_from("<Q", key, 8)
                flags_length, block, crypto = _EXTENT.unpack_from(value)
                extents.append(
                    (oid, logical, flags_length & ((1 << 56) - 1), block, crypto)
                )
        for oid, inode in inodes:
            tree.inodes[oid] = inode
        for oid, child in children:
            tree.children.setdefault(oid, []).append(child)
        for oid, name, attr in xattrs:
            tree.xattrs.setdefault(oid, {})[name] = attr
        for oid in siblings:
            tree.siblings[oid] = tree.siblings.get(oid, 0) + 1
        for oid, logical, length, block, crypto in extents:
            if crypto:
                tree.encrypted_streams.add(oid)
            tree.extents.setdefault(oid, array("Q")).extend((logical, length, block))

    def _child(self, key: bytes, value: bytes) -> Child:
        if self.hashed:
            if len(key) < 12:
                raise CorruptionError("an APFS directory key is too short")
            (length_and_hash,) = struct.unpack_from("<I", key, 8)
            length, at = length_and_hash & 0x3FF, 12
        else:
            if len(key) < 10:
                raise CorruptionError("an APFS directory key is too short")
            (length,) = struct.unpack_from("<H", key, 8)
            at = 10
        if at + length > len(key) or not length:
            raise CorruptionError("an APFS directory key's name runs past the key")
        if len(value) < _DREC.size:
            raise CorruptionError("an APFS directory record is too short")
        file_id, _, flags = _DREC.unpack_from(value)
        return Child(_name(key[at : at + length]), file_id, flags & 0xF)


def _inode(value: bytes) -> Inode:
    if len(value) < _INODE.size:
        raise CorruptionError("an APFS inode record is too short")
    (parent, stream, created, modified, _, _, _, nlink, _, _, bsd_flags, uid, gid,
     mode, _, _) = _INODE.unpack_from(value)  # fmt: skip
    size = 0
    for kind, field in _xfields(value[_INODE.size :]):
        if kind == _INO_EXT_DSTREAM:
            if len(field) < 8:
                raise CorruptionError("an APFS data stream field is too short")
            (size,) = struct.unpack_from("<Q", field)
    return Inode(
        parent, stream, created, modified, nlink, bsd_flags, uid, gid, mode, size
    )


def _xattr(key: bytes, value: bytes) -> tuple[bytes, Xattr]:
    if len(key) < 10:
        raise CorruptionError("an APFS extended attribute key is too short")
    (length,) = struct.unpack_from("<H", key, 8)
    if 10 + length > len(key) or len(value) < 4:
        raise CorruptionError("an APFS extended attribute record is too short")
    name = _name(key[10 : 10 + length])
    flags, data_length = struct.unpack_from("<HH", value)
    data = value[4 : 4 + data_length]
    if len(data) != data_length:
        raise CorruptionError("an APFS extended attribute's data runs past its record")
    if flags & _XATTR_EMBEDDED:
        return name, Xattr(data, 0, data_length)
    if flags & _XATTR_STREAM:
        if data_length < 16:
            raise CorruptionError(
                "an APFS extended attribute's stream record is too short"
            )
        stream, size = struct.unpack_from("<QQ", data)
        return name, Xattr(None, stream, size)
    raise CorruptionError(f"an APFS extended attribute has flags 0x{flags:x}")


# ── Data streams ─────────────────────────────────────────────────────────────────────


class _StreamView(NamedTuple):
    """What checking a data stream's extents found; nothing in it depends on the size
    read or on the name of the file."""

    # The first bad extent: ("overlap", its start, 0) or ("past", its first block,
    # its end block); None when every extent is good.
    fault: tuple[str, int, int] | None
    # A read to a size above this meets a hole or a zero extent.
    sparse_from: int
    # The damaged ranges that may hold the stream's extent keys, in key order (the
    # index's merged ranges are disjoint, so their lowest offsets ascend): those
    # lowest offsets, and the running maximum of their highest offsets.
    lows: tuple[int, ...]
    peaks: tuple[float, ...]


def _offsets(each: Damage, prefix: tuple[int, int]) -> tuple[int, float]:
    """The lowest and highest offsets of the extent keys of stream ``prefix`` that the
    damaged range ``each`` may hold."""
    low = each.low[2] if each.low is not None and each.low[:2] == prefix else 0
    high = (
        each.high[2]
        if each.high is not None and each.high[:2] == prefix
        else float("inf")
    )
    return low, high


def _check_stream(
    flat: array[int], damage: DamageIndex, stream: int, bs: int, count: int
) -> _StreamView:
    """Check the extents ``flat`` of ``stream`` (in key order) once, and gather the
    damaged ranges that may hold more of them."""
    fault: tuple[str, int, int] | None = None
    sparse_from: int | None = None
    pos = 0
    for i in range(0, len(flat), 3):
        start, length, address = flat[i], flat[i + 1], flat[i + 2]
        if start < pos:
            fault = ("overlap", start, 0)
            break
        if start > pos and sparse_from is None:
            sparse_from = pos
        if address == 0:
            if sparse_from is None or start < sparse_from:
                sparse_from = start
        elif address + -(-length // bs) > count:
            fault = ("past", address, address + -(-length // bs))
            break
        pos = start + length
    lows: list[int] = []
    peaks: list[float] = []
    prefix = (stream, EXTENT)
    peak = float("-inf")
    for each in damage.holding(prefix):
        low, high = _offsets(each, prefix)
        peak = max(peak, high)
        lows.append(low)
        peaks.append(peak)
    sparse_from = pos if sparse_from is None else min(sparse_from, pos)
    return _StreamView(fault, sparse_from, tuple(lows), tuple(peaks))


def stream_view(volume: ApfsVolume, tree: FsTree, stream: int) -> _StreamView:
    """The check of data stream ``stream``'s extents: kept on ``tree``, and charged,
    when it is costly (``stream_reader``). Only the charge raises
    (``ResourceLimitError``); a bad extent is recorded in the view, for the read."""
    view = tree.stream_views.get(stream)
    if view is None:
        blocks = volume.container._blocks
        flat = tree.extents.get(stream, array("Q"))
        view = _check_stream(flat, tree.damage, stream, blocks.size, blocks.count)
        if len(flat) // 3 + len(view.lows) > _KEPT_VIEW_MIN:
            tree.keep_view(stream, view)
    return view


def stream_reader(
    volume: ApfsVolume, tree: FsTree, stream: int, size: int, what: str
) -> tuple[Callable[[int, int], bytes], bool]:
    """``read(offset, n)`` over the first ``size`` bytes of data stream ``stream``:
    exactly ``n`` bytes, or ``TruncatedError`` past ``size``; and whether the stream
    has holes. Holes read as zeros, except where a damaged node may hold the extent
    that fills them (``CorruptionError``). The extents are checked here, so a bad
    extent fails the read that opens the stream.

    Inodes may share a stream, and each one opens it: a stream whose check costs more
    than ``_KEPT_VIEW_MIN`` extents and damaged ranges is checked once and its
    :class:`_StreamView` kept on ``tree`` and charged, so the calls together cost
    what the stream holds and not that times the inodes."""
    blocks = volume.container._blocks
    bs = blocks.size
    if stream in tree.encrypted_streams:
        raise CorruptionError(
            f"{what} has an extent with an encryption id on an unencrypted volume"
        )
    flat = tree.extents.get(stream, array("Q"))
    view = stream_view(volume, tree, stream)
    if view.fault is not None:
        kind, first, last = view.fault
        if kind == "overlap":
            raise CorruptionError(f"{what} has overlapping extents at byte {first}")
        raise CorruptionError(
            f"an extent of {what} (blocks {first} to {last}) "
            f"is past the container's {blocks.count} blocks"
        )
    sparse = view.sparse_from < size
    lows, peaks = view.lows, view.peaks
    extents = range(len(flat) // 3)

    def start_of(i: int) -> int:
        return flat[3 * i]

    def hole(at: int, stop: int) -> None:
        """Serve zeros over [``at``, ``stop``), unless an extent the records cannot
        show may start between the last known extent before ``at`` and ``stop``."""
        index = bisect.bisect_right(extents, at, key=start_of) - 1
        before = flat[3 * index] if index >= 0 else -1
        # The ranges that start below ``stop`` are the first ``below`` (they are in
        # key order), and the first range whose high end is past ``before`` is where
        # ``peaks`` first passes it: a scan of every range finds the same one.
        below = bisect.bisect_left(lows, stop)
        first = bisect.bisect_right(peaks, before)
        if first < below:
            # The view kept the bounds only; the range is found again, the same
            # one since the tree's damage does not change after the walk.
            prefix = (stream, EXTENT)
            each = next(itertools.islice(tree.damage.holding(prefix), first, None))
            assert _offsets(each, prefix)[0] == lows[first]
            raise CorruptionError(
                f"the extents of {what} from byte {at} are in a damaged node of "
                f"the filesystem tree (block {each.address}: {each.reason})"
            )

    source = volume.container.source

    def read(offset: int, n: int) -> bytes:
        if offset + n > size:
            raise TruncatedError(
                f"{what} ends at byte {size}, before byte {offset + n}"
            )
        parts: list[bytes] = []
        at = offset
        end = offset + n
        index = max(0, bisect.bisect_right(extents, at, key=start_of) - 1)
        while at < end:
            if index < len(extents):
                start, length, address = flat[3 * index : 3 * index + 3]
                if start <= at < start + length:
                    take = min(end, start + length) - at
                    if address:
                        parts.append(source.read_exact(address * bs + at - start, take))
                    else:
                        parts.append(bytes(take))
                    at += take
                    index += 1
                    continue
                if start + length <= at:
                    index += 1
                    continue
            following = flat[3 * index] if index < len(extents) else end
            take = min(end, following) - at
            hole(at, at + take)
            parts.append(bytes(take))
            at += take
        return b"".join(parts)

    return read, sparse


def xattr_value(
    volume: ApfsVolume, tree: FsTree, attr: Xattr, limit: int, what: str
) -> bytes:
    """An extended attribute's bytes, embedded or from its stream; at most ``limit``
    bytes are read, a longer one is ``CorruptionError``."""
    if attr.value is not None:
        return attr.value
    if attr.size > limit:
        raise CorruptionError(f"{what} is {attr.size} bytes, more than archivey reads")
    read, _ = stream_reader(volume, tree, attr.stream, attr.size, what)
    return read(0, attr.size)


def read_pieces(size: int, read: Callable[[int, int], bytes]) -> Callable[[int], bytes]:
    """``read_block(i)`` for a ``block_stream`` of ``READ_PIECE`` blocks."""

    def read_piece(index: int) -> bytes:
        return read(index * READ_PIECE, min(READ_PIECE, size - index * READ_PIECE))

    return read_piece
