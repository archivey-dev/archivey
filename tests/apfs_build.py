"""Writes APFS containers for the tests (DMG plan Part E, design §9.2).

No tool on Linux writes filled APFS containers (``mkapfs`` from apfsprogs makes empty
ones), so this writer is here. It writes what the reader needs and the structures
macOS writes around them: block 0 and a checkpoint (one checkpoint-map block and the
container superblock in the descriptor ring), the container object map, one or more
volumes, each with its superblock, object map and filesystem tree (an index root over
leaves, or one root leaf), and file data. Every object gets its Fletcher-64.

The filesystem tree holds inodes, directory records (plain or hashed keys), extended
attributes (embedded, or as streams), data-stream records and file extents, for files,
directories, symlinks, hard links (several directory records naming one inode), clones
(two inodes whose extents share blocks), sparse files (holes, and extents with block 0)
and decmpfs files (the attribute, and the resource fork as a stream attribute).

Hooks break it: ``split_before`` decides which records start a new leaf, so a test
knows which records a damaged leaf held; ``omap_leaf_entries`` splits the volume's
object map the same way; ``newer_checkpoint`` writes a newer checkpoint that is
damaged or incomplete; ``patch`` edits the laid-out container. :func:`reseal` puts a
good checksum back on an edited object.

Layouts from Apple's *Apple File System Reference* (2020); field values follow the
``hdiutil`` fixtures in ``tests/fixtures/external/dmg_hdiutil/``.
"""

from __future__ import annotations

import stat
import struct
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from tests.dmg_build import Node, _decmpfs

BLOCK = 4096
NX_OID, FIRST_VIRTUAL = 1, 1026
ROOT_PARENT, ROOT_DIR, PRIVATE_DIR, FIRST_INODE = 1, 2, 3, 16
DESC_BLOCKS = 8

T_NX, T_BTREE, T_BTREE_NODE, T_OMAP, T_CHECKPOINT_MAP, T_FS, T_FSTREE = (
    0x1,
    0x2,
    0x3,
    0xB,
    0xC,
    0xD,
    0xE,
)
PHYSICAL, EPHEMERAL = 0x40000000, 0x80000000
INODE, XATTR, SIBLING_LINK, DSTREAM_ID, EXTENT, DIR_REC = 3, 4, 5, 6, 8, 9
INO_EXT_NAME, INO_EXT_DSTREAM = 4, 8
XATTR_STREAM, XATTR_EMBEDDED = 1, 2
EMBEDDED_MAX = 3804  # XATTR_MAX_EMBEDDED_SIZE
UF_COMPRESSED = 0x20
_DT = {"file": 8, "dir": 4, "symlink": 10, "fifo": 1, "chardev": 2}
_MODE = {
    "file": stat.S_IFREG | 0o644,
    "dir": stat.S_IFDIR | 0o755,
    "symlink": stat.S_IFLNK | 0o755,
    "fifo": stat.S_IFIFO | 0o644,
    "chardev": stat.S_IFCHR | 0o644,
}


def fletcher64(block: bytes) -> int:
    n = (len(block) - 8) // 4
    words = struct.unpack_from(f"<{n}I", block, 8)
    m = 0xFFFFFFFF
    s1 = s2 = 0
    for w in words:
        s1 = (s1 + w) % m
        s2 = (s2 + s1) % m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return (c2 << 32) | c1


def reseal(container: bytearray, address: int, block_size: int = BLOCK) -> None:
    """Put a good Fletcher-64 back on the object at block ``address``."""
    at = address * block_size
    block = bytes(container[at : at + block_size])
    struct.pack_into("<Q", container, at, fletcher64(block))


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc


def name_hash(name: bytes) -> int:
    """The 22-bit hash of a hashed directory key: CRC-32C of the NFD, case-folded name
    as UTF-32LE, complemented."""
    text = unicodedata.normalize(
        "NFD", name.decode("utf-8", "surrogateescape").casefold()
    )
    return (~_crc32c(text.encode("utf-32-le", "surrogatepass"))) & 0x3FFFFF


@dataclass
class Apfs:
    """A written container and where its parts went, for tests that break it."""

    container: bytes
    block_size: int
    inodes: dict[str, int]  # path -> inode id ("" is the root)
    streams: dict[str, int]  # path -> data stream id
    data_blocks: dict[str, list[int]]  # path -> the blocks its extents use
    fs_leaves: list[int]  # first volume: the filesystem tree's leaf blocks, in order
    fs_root: int
    omap_leaves: list[int]  # first volume: its object map's leaf blocks
    volume_superblocks: list[int]
    checkpoint_superblock: int  # the ring block of the superblock read
    container_omap: int


@dataclass
class _Record:
    oid: int
    kind: int
    secondary: tuple[object, ...]
    key: bytes
    value: bytes
    path: str = ""

    def order(self) -> tuple[object, ...]:
        return (self.oid, self.kind, *self.secondary)


@dataclass
class _Layout:
    blocks: dict[int, bytes] = field(default_factory=dict)
    next: int = 1 + DESC_BLOCKS

    def take(self, count: int = 1) -> int:
        start = self.next
        self.next += count
        return start


def _object(body: bytearray, oid: int, xid: int, kind: int, subtype: int = 0) -> bytes:
    struct.pack_into("<QQII", body, 8, oid, xid, kind, subtype)
    struct.pack_into("<Q", body, 0, fletcher64(bytes(body)))
    return bytes(body)


def _node(
    records: Sequence[tuple[bytes, bytes]],
    *,
    oid: int,
    xid: int,
    kind: int,
    subtype: int,
    level: int,
    root: bool,
    fixed: tuple[int, int] | None,
    info: tuple[int, int, int, int, int, int] | None = None,
    key_count: int | None = None,
    block_size: int = BLOCK,
) -> bytes:
    """One B-tree node. ``info`` (flags, key size, value size, longest key, longest
    value, node count) is the root's ``btree_info_t``; keys counted from the records."""
    body = bytearray(block_size)
    entry = 4 if fixed else 8
    toc_length = entry * len(records)
    keys_at = 56 + toc_length
    values_end = block_size - (40 if root else 0)
    key_pos = 0
    value_pos = 0
    for i, (key, value) in enumerate(records):
        body[keys_at + key_pos : keys_at + key_pos + len(key)] = key
        value_pos += len(value)
        body[values_end - value_pos : values_end - value_pos + len(value)] = value
        if fixed:
            struct.pack_into("<HH", body, 56 + 4 * i, key_pos, value_pos)
        else:
            struct.pack_into(
                "<HHHH", body, 56 + 8 * i, key_pos, len(key), value_pos, len(value)
            )
        key_pos += len(key)
    if keys_at + key_pos > values_end - value_pos:
        raise ValueError("records do not fit in one node")
    flags = (0x1 if root else 0) | (0x2 if level == 0 else 0) | (0x4 if fixed else 0)
    struct.pack_into(
        "<HHIHHHH",
        body,
        32,
        flags,
        level,
        len(records),
        0,
        toc_length,
        key_pos,
        values_end - value_pos - keys_at - key_pos,
    )
    struct.pack_into("<HHHH", body, 48, 0xFFFF, 0, 0xFFFF, 0)
    if root:
        assert info is not None
        bt_flags, key_size, value_size, longest_key, longest_value, nodes = info
        struct.pack_into(
            "<IIIIIIQQ",
            body,
            block_size - 40,
            bt_flags,
            block_size,
            key_size,
            value_size,
            longest_key,
            longest_value,
            len(records) if key_count is None else key_count,
            nodes,
        )
    return _object(body, oid, xid, kind, subtype)


def _capacity(block_size: int, root: bool) -> int:
    return block_size - 56 - (40 if root else 0)


def _inode_value(
    parent: int,
    stream: int,
    ns: int,
    nlink: int,
    bsd_flags: int,
    uid: int,
    gid: int,
    mode: int,
    size: int | None,
    name: bytes,
    uncompressed: int | None = None,
) -> bytes:
    head = struct.pack(
        "<QQQQQQQiIIIIIHHQ",
        parent,
        stream,
        ns,
        ns,
        ns,
        ns,
        0 if uncompressed is None else 0x40000,  # INODE_HAS_UNCOMPRESSED_SIZE
        nlink,
        0,
        0,
        bsd_flags,
        uid,
        gid,
        mode,
        0,
        uncompressed or 0,
    )
    fields: list[tuple[int, bytes]] = [(INO_EXT_NAME, name + b"\0")]
    if size is not None:
        fields.append(
            (
                INO_EXT_DSTREAM,
                struct.pack("<QQQQQ", size, -(-size // BLOCK) * BLOCK, 0, size, 0),
            )
        )
    data = b""
    headers = b""
    for kind, value in fields:
        headers += struct.pack("<BBH", kind, 0, len(value))
        data += value + bytes(-len(value) % 8)
    return head + struct.pack("<HH", len(fields), len(data)) + headers + data


def write_apfs(
    nodes: Sequence[Node],
    *,
    name: str = "Test",
    hashed: bool = True,
    more_volumes: Sequence[tuple[str, Sequence[Node]]] = (),
    holes: dict[str, Sequence[tuple[int, int]]] | None = None,
    zero_extents: dict[str, Sequence[tuple[int, int]]] | None = None,
    clones: dict[str, str] | None = None,
    split_before: Sequence[tuple[str, int] | tuple[str, int, int]] = (),
    leaf_records: int | None = None,
    omap_leaf_entries: int | None = None,
    newer_checkpoint: str | None = None,
    volume_flags: int = 0x1,
    volume_incompatible: int | None = None,
    container_incompatible: int = 0x2,
    spare_blocks: int = 8,
    patch_records: Callable[[list[_Record]], None] | None = None,
    patch: Callable[[bytearray, Apfs], None] | None = None,
) -> Apfs:
    """An APFS container whose first volume, ``name``, holds ``nodes``.

    Folders that a path needs are made on the way. ``hardlink`` nodes add a directory
    record for their ``target``'s inode. ``holes`` leaves byte ranges of a file with no
    extent, ``zero_extents`` writes an extent with block 0 there (both ranges must be
    whole blocks of zeros in the data). ``clones`` maps a path to another file whose
    data it shares: its own inode and stream, extents on the same blocks.
    ``compression`` writes a decmpfs file: the attribute embedded, the resource fork as
    a stream attribute. ``hashed`` writes hashed directory keys (a case-insensitive
    volume, as ``hdiutil`` makes them).

    ``split_before`` lists (path, record type) pairs: the first record of that type for
    that path's inode (for type 8, its stream; for type 9, the record naming it) starts
    a new leaf. A third item, for type 8, names the extent's logical offset instead.
    ``leaf_records`` caps the records per leaf. ``newer_checkpoint`` adds a checkpoint
    with a higher transaction after the real one: ``"bad-checksum"`` (its superblock
    fails its checksum) or ``"missing-map"`` (its superblock is good and its
    checkpoint-map block is not there).
    """
    holes = dict(holes or {})
    zero_extents = dict(zero_extents or {})
    clones = dict(clones or {})
    xid = 4
    layout = _Layout()
    data_runs: list[tuple[int, bytes]] = []
    oid_counter = [FIRST_VIRTUAL]

    def new_oid() -> int:
        oid_counter[0] += 1
        return oid_counter[0] - 1

    volume_specs = [(name, nodes), *more_volumes]
    volume_oids = [new_oid() for _ in volume_specs]
    superblocks: list[int] = []
    first_leaves: list[int] = []
    first_omap: list[int] = []
    first_root = 0
    inodes_map: dict[str, int] = {}
    streams_map: dict[str, int] = {}
    data_blocks: dict[str, list[int]] = {}

    def write_volume(vi: int, vname: str, vnodes: Sequence[Node]) -> None:
        nonlocal first_leaves, first_omap, first_root, inodes_map, streams_map
        records: list[_Record] = []
        inode_ids: dict[str, int] = {"": ROOT_DIR}
        kinds: dict[str, str] = {"": "dir"}
        next_inode = [FIRST_INODE]
        by_path = {n.path.strip("/"): n for n in vnodes}
        order: list[str] = []
        links: dict[str, list[str]] = {}

        def ensure_dir(path: str) -> None:
            if path in inode_ids:
                return
            parent = path.rpartition("/")[0]
            ensure_dir(parent)
            inode_ids[path] = next_inode[0]
            next_inode[0] += 1
            kinds[path] = "dir"
            order.append(path)

        for n in vnodes:
            path = n.path.strip("/")
            ensure_dir(path.rpartition("/")[0])
            if n.kind == "hardlink":
                links.setdefault(n.target, []).append(path)
                order.append(path)
                kinds[path] = "hardlink"
                continue
            if n.kind == "dir":
                ensure_dir(path)
                continue
            inode_ids[path] = next_inode[0]
            next_inode[0] += 1
            kinds[path] = n.kind
            order.append(path)
        for path in order:
            if kinds[path] == "hardlink":
                target = by_path[path].target
                inode_ids[path] = inode_ids[target]

        def key_head(oid: int, kind: int) -> bytes:
            return struct.pack("<Q", oid | kind << 60)

        def drec_key(parent: int, raw: bytes) -> tuple[bytes, tuple[object, ...]]:
            stored = raw + b"\0"
            if hashed:
                packed = name_hash(raw) << 10 | len(stored)
                return (
                    key_head(parent, DIR_REC) + struct.pack("<I", packed) + stored,
                    (packed, stored),
                )
            return (
                key_head(parent, DIR_REC) + struct.pack("<H", len(stored)) + stored,
                (stored,),
            )

        def add_xattr(
            oid: int, xname: str, value: bytes, path: str, *, stream: bool
        ) -> None:
            raw = xname.encode() + b"\0"
            key = key_head(oid, XATTR) + struct.pack("<H", len(raw)) + raw
            if not stream and len(value) <= EMBEDDED_MAX:
                body = struct.pack("<HH", XATTR_EMBEDDED, len(value)) + value
            else:
                # Streams take ids from the inode numbers, below the volume's next
                # object id, as macOS numbers them (7-Zip checks it).
                sid = next_inode[0]
                next_inode[0] += 1
                place(sid, value, path=path + f"#{xname}")
                dstream = struct.pack(
                    "<QQQQQ",
                    len(value),
                    -(-len(value) // BLOCK) * BLOCK,
                    0,
                    len(value),
                    0,
                )
                inner = struct.pack("<Q", sid) + dstream
                body = struct.pack("<HH", XATTR_STREAM, len(inner)) + inner
            records.append(_Record(oid, XATTR, (raw,), key, body, path))

        def extent(
            stream: int, logical: int, length: int, block: int, path: str
        ) -> None:
            records.append(
                _Record(
                    stream,
                    EXTENT,
                    (logical,),
                    key_head(stream, EXTENT) + struct.pack("<Q", logical),
                    struct.pack("<QQQ", length, block, 0),
                    path,
                )
            )

        def place(
            stream: int,
            data: bytes,
            *,
            path: str,
            fragment: int = 0,
            gaps: Sequence[tuple[int, int]] = (),
            zeros: Sequence[tuple[int, int]] = (),
        ) -> list[int]:
            """Write ``data``'s extents for ``stream`` and return the blocks used."""
            used: list[int] = []
            skip = [(a, a + n) for a, n in gaps]
            nulls = [(a, a + n) for a, n in zeros]
            size = len(data)
            total = -(-size // BLOCK)
            pieces = max(1, fragment)
            per = max(1, -(-total // pieces))
            b = 0
            while b < total:
                lo = b * BLOCK
                if any(a <= lo < e for a, e in skip):
                    b += 1
                    continue
                zero = next(((a, e) for a, e in nulls if a <= lo < e), None)
                if zero is not None:
                    count = (zero[1] - lo) // BLOCK
                    extent(stream, lo, count * BLOCK, 0, path)
                    b += count
                    continue
                count = 1
                while (
                    b + count < total
                    and count < per
                    and not any(a <= (b + count) * BLOCK < e for a, e in skip + nulls)
                ):
                    count += 1
                start = layout.take(count)
                if fragment:
                    layout.take(1)  # a gap between fragments on disk
                chunk = data[lo : lo + count * BLOCK]
                data_runs.append((start, chunk))
                used.extend(range(start, start + count))
                extent(stream, lo, count * BLOCK, start, path)
                b += count
            return used

        ns = 1_700_000_000 * 10**9
        root_inode = _inode_value(
            ROOT_PARENT, ROOT_DIR, ns, 1, 0, 501, 20, _MODE["dir"], None, b"root"
        )
        records.append(
            _Record(ROOT_DIR, INODE, (), key_head(ROOT_DIR, INODE), root_inode, "")
        )
        private = _inode_value(
            ROOT_PARENT, PRIVATE_DIR, ns, 1, 0, 0, 0, _MODE["dir"], None, b"private-dir"
        )
        records.append(
            _Record(PRIVATE_DIR, INODE, (), key_head(PRIVATE_DIR, INODE), private, "")
        )
        for parent, raw, fid in (
            (ROOT_PARENT, b"root", ROOT_DIR),
            (ROOT_PARENT, b"private-dir", PRIVATE_DIR),
        ):
            key, sec = drec_key(parent, raw)
            records.append(
                _Record(parent, DIR_REC, sec, key, struct.pack("<QQH", fid, ns, 4), "")
            )

        streams: dict[str, int] = {}
        for path in [p for p in order if kinds[p] != "hardlink"]:
            n = by_path.get(path)
            kind = kinds[path]
            oid = inode_ids[path]
            parent_path = path.rpartition("/")[0]
            parent = inode_ids[parent_path]
            raw_name = path.rpartition("/")[2].encode("utf-8", "surrogateescape")
            if n is not None and n.raw_name is not None:
                raw_name = n.raw_name
            mtime = (n.mtime if n is not None else 1_700_000_000) * 10**9
            mode = n.mode if n is not None and n.mode is not None else _MODE[kind]
            uid = n.uid if n is not None else 501
            gid = n.gid if n is not None else 20
            nlink = 1 + len(links.get(path, ()))
            bsd = 0
            size: int | None = None
            uncompressed: int | None = None
            stream = oid
            if kind == "file" and n is not None:
                data = n.data
                if n.compression is not None:
                    bsd = UF_COMPRESSED
                    uncompressed = len(data)
                    value, rsrc = _decmpfs(n.compression, data)
                    add_xattr(oid, "com.apple.decmpfs", value, path, stream=False)
                    if rsrc:
                        add_xattr(
                            oid, "com.apple.ResourceFork", rsrc, path, stream=True
                        )
                else:
                    size = len(data)
                    if path in clones:
                        src = clones[path]
                        stream = oid
                        for rec in [
                            r
                            for r in records
                            if r.kind == EXTENT and r.oid == streams[src]
                        ]:
                            (logical,) = rec.secondary
                            length, block, _ = struct.unpack("<QQQ", rec.value)
                            extent(stream, logical, length, block, path)  # type: ignore[arg-type]
                        data_blocks[path] = data_blocks.get(src, [])
                    elif data:
                        data_blocks[path] = place(
                            stream,
                            data,
                            path=path,
                            fragment=n.fragment,
                            gaps=holes.get(path, ()),
                            zeros=zero_extents.get(path, ()),
                        )
                    if data:
                        records.append(
                            _Record(
                                stream,
                                DSTREAM_ID,
                                (),
                                key_head(stream, DSTREAM_ID),
                                struct.pack("<I", 1),
                                path,
                            )
                        )
                    streams[path] = stream
                if n.resource_fork:
                    add_xattr(
                        oid,
                        "com.apple.ResourceFork",
                        n.resource_fork,
                        path,
                        stream=True,
                    )
            if kind == "symlink" and n is not None:
                add_xattr(
                    oid,
                    "com.apple.fs.symlink",
                    n.target.encode() + b"\0",
                    path,
                    stream=False,
                )
            if n is not None:
                for xname, xvalue in n.xattrs.items():
                    add_xattr(oid, xname, xvalue, path, stream=False)
            value = _inode_value(
                parent,
                stream,
                mtime,
                nlink,
                bsd,
                uid,
                gid,
                mode,
                size,
                raw_name,
                uncompressed,
            )
            records.append(_Record(oid, INODE, (), key_head(oid, INODE), value, path))
            if nlink > 1:
                # One sibling link per name of a hard-linked file, as macOS writes
                # them: its own id, then the name's parent and the name.
                for link_path in [path, *links[path]]:
                    sibling = next_inode[0]
                    next_inode[0] += 1
                    raw = link_path.rpartition("/")[2].encode() + b"\0"
                    records.append(
                        _Record(
                            oid,
                            SIBLING_LINK,
                            (sibling,),
                            key_head(oid, SIBLING_LINK) + struct.pack("<Q", sibling),
                            struct.pack(
                                "<QH", inode_ids[link_path.rpartition("/")[0]], len(raw)
                            )
                            + raw,
                            path,
                        )
                    )
            key, sec = drec_key(parent, raw_name)
            records.append(
                _Record(
                    parent,
                    DIR_REC,
                    sec,
                    key,
                    struct.pack("<QQH", oid, mtime, _DT[kind]),
                    path,
                )
            )
            for link in links.get(path, ()):
                lparent = inode_ids[link.rpartition("/")[0]]
                key, sec = drec_key(lparent, link.rpartition("/")[2].encode())
                records.append(
                    _Record(
                        lparent,
                        DIR_REC,
                        sec,
                        key,
                        struct.pack("<QQH", oid, mtime, _DT[kind]),
                        link,
                    )
                )
        if patch_records:
            patch_records(records)
        records.sort(key=_Record.order)

        # ── the filesystem tree: leaves, then an index root over them if needed ──
        breaks = set()
        for spath, skind, *at in split_before:
            target_ids = {inode_ids[spath], streams.get(spath, inode_ids[spath])}
            for i, rec in enumerate(records):
                if (
                    rec.kind == skind
                    and (
                        rec.oid in target_ids if skind != DIR_REC else rec.path == spath
                    )
                    and (not at or rec.secondary == (at[0],))
                ):
                    breaks.add(i)
                    break
        leaves: list[list[_Record]] = [[]]
        used = 0
        cap = _capacity(BLOCK, False)
        for i, rec in enumerate(records):
            cost = 8 + len(rec.key) + len(rec.value)
            full = used + cost > cap or (
                leaf_records is not None and len(leaves[-1]) >= leaf_records
            )
            if leaves[-1] and (i in breaks or full):
                leaves.append([])
                used = 0
            leaves[-1].append(rec)
            used += cost
        single = len(leaves) == 1 and sum(
            8 + len(r.key) + len(r.value) for r in leaves[0]
        ) <= _capacity(BLOCK, True)
        fs_map: list[tuple[int, int]] = []  # (virtual oid, address)
        longest_key = max(len(r.key) for r in records)
        longest_value = max(len(r.value) for r in records)
        if single:
            root_oid = new_oid()
            root_at = layout.take()
            layout.blocks[root_at] = _node(
                [(r.key, r.value) for r in leaves[0]],
                oid=root_oid,
                xid=xid,
                kind=T_BTREE,
                subtype=T_FSTREE,
                level=0,
                root=True,
                fixed=None,
                info=(0x42, 0, 0, longest_key, longest_value, 1),
            )
            fs_map.append((root_oid, root_at))
            leaf_blocks = [root_at]
        else:
            leaf_blocks = []
            index: list[tuple[bytes, bytes]] = []
            for leaf in leaves:
                leaf_oid = new_oid()
                at = layout.take()
                layout.blocks[at] = _node(
                    [(r.key, r.value) for r in leaf],
                    oid=leaf_oid,
                    xid=xid,
                    kind=T_BTREE_NODE,
                    subtype=T_FSTREE,
                    level=0,
                    root=False,
                    fixed=None,
                )
                fs_map.append((leaf_oid, at))
                leaf_blocks.append(at)
                index.append((leaf[0].key, struct.pack("<Q", leaf_oid)))
            root_oid = new_oid()
            root_at = layout.take()
            layout.blocks[root_at] = _node(
                index,
                oid=root_oid,
                xid=xid,
                kind=T_BTREE,
                subtype=T_FSTREE,
                level=1,
                root=True,
                fixed=None,
                info=(0x42, 0, 0, longest_key, longest_value, len(leaves) + 1),
                key_count=len(records),
            )
            fs_map.append((root_oid, root_at))

        # ── the volume's object map ──
        omap_records = sorted(
            (struct.pack("<QQ", oid, xid), struct.pack("<IIQ", 0, BLOCK, at))
            for oid, at in fs_map
        )
        omap_obj = layout.take()
        omap_root, omap_leaf_blocks = _omap_tree(
            layout, omap_records, xid, omap_leaf_entries
        )
        omap_body = bytearray(BLOCK)
        struct.pack_into(
            "<IIIIQ",
            omap_body,
            32,
            0,
            0,
            PHYSICAL | T_BTREE,
            PHYSICAL | T_BTREE,
            omap_root,
        )
        layout.blocks[omap_obj] = _object(omap_body, omap_obj, xid, PHYSICAL | T_OMAP)

        # ── the volume superblock ──
        apsb_at = layout.take()
        sb = bytearray(BLOCK)
        sb[32:36] = b"APSB"
        incompat = (
            volume_incompatible
            if volume_incompatible is not None
            else (0x1 if hashed else 0)
        )
        struct.pack_into("<IQQQ", sb, 36, vi, 0, 0, incompat)
        struct.pack_into(
            "<III", sb, 116, T_BTREE, PHYSICAL | T_BTREE, PHYSICAL | T_BTREE
        )
        struct.pack_into("<QQ", sb, 128, omap_obj, root_oid)
        struct.pack_into("<Q", sb, 176, next_inode[0])
        struct.pack_into("<Q", sb, 264, volume_flags)
        raw_vname = vname.encode()
        sb[704 : 704 + len(raw_vname)] = raw_vname
        layout.blocks[apsb_at] = _object(sb, volume_oids[vi], xid, T_FS)
        superblocks.append(apsb_at)
        if vi == 0:
            first_leaves = leaf_blocks
            first_omap = omap_leaf_blocks
            first_root = root_at
            inodes_map = dict(inode_ids)
            streams_map = dict(streams)

    for vi, (vname, vnodes) in enumerate(volume_specs):
        write_volume(vi, vname, vnodes)

    # ── the container object map ──
    nx_records = sorted(
        (struct.pack("<QQ", oid, xid), struct.pack("<IIQ", 0, BLOCK, at))
        for oid, at in zip(volume_oids, superblocks)
    )
    nx_omap_obj = layout.take()
    nx_omap_root, _ = _omap_tree(layout, nx_records, xid, None)
    body = bytearray(BLOCK)
    struct.pack_into(
        "<IIIIQ", body, 32, 0, 0, PHYSICAL | T_BTREE, PHYSICAL | T_BTREE, nx_omap_root
    )
    layout.blocks[nx_omap_obj] = _object(body, nx_omap_obj, xid, PHYSICAL | T_OMAP)

    for start, chunk in data_runs:
        for i in range(-(-len(chunk) // BLOCK)):
            piece = chunk[i * BLOCK : (i + 1) * BLOCK]
            layout.blocks[start + i] = piece + bytes(BLOCK - len(piece))
    block_count = layout.next + spare_blocks

    def superblock(sb_xid: int, desc_index: int) -> bytearray:
        nx = bytearray(BLOCK)
        nx[32:36] = b"NXSB"
        struct.pack_into("<IQ", nx, 36, BLOCK, block_count)
        struct.pack_into("<QQQ", nx, 48, 0, 0, container_incompatible)
        struct.pack_into("<QQ", nx, 88, oid_counter[0], sb_xid + 1)
        struct.pack_into("<IIQQ", nx, 104, DESC_BLOCKS, 0, 1, 0)
        struct.pack_into(
            "<IIIIII", nx, 128, (desc_index + 2) % DESC_BLOCKS, 0, desc_index, 2, 0, 0
        )
        struct.pack_into("<Q", nx, 160, nx_omap_obj)
        struct.pack_into("<I", nx, 180, 100)
        for i, oid in enumerate(volume_oids):
            struct.pack_into("<Q", nx, 184 + 8 * i, oid)
        return nx

    def checkpoint_map(cp_xid: int, at: int) -> bytes:
        cpm = bytearray(BLOCK)
        struct.pack_into("<II", cpm, 32, 1, 0)
        return _object(cpm, at, cp_xid, PHYSICAL | T_CHECKPOINT_MAP)

    # The checkpoint read: ring indexes 0 (map) and 1 (superblock).
    layout.blocks[1] = checkpoint_map(xid, 1)
    nx = superblock(xid, 0)
    nx_block = _object(nx, NX_OID, xid, EPHEMERAL | T_NX)
    layout.blocks[2] = nx_block
    layout.blocks[0] = nx_block
    if newer_checkpoint is not None:
        newer = superblock(xid + 1, 2)
        if newer_checkpoint == "bad-checksum":
            block = bytearray(_object(newer, NX_OID, xid + 1, EPHEMERAL | T_NX))
            block[200] ^= 0xFF
            layout.blocks[1 + 3] = bytes(block)
            layout.blocks[1 + 2] = checkpoint_map(xid + 1, 1 + 2)
        elif newer_checkpoint == "missing-map":
            layout.blocks[1 + 3] = _object(newer, NX_OID, xid + 1, EPHEMERAL | T_NX)
        else:
            raise ValueError(newer_checkpoint)

    container = bytearray(block_count * BLOCK)
    for at, block in layout.blocks.items():
        container[at * BLOCK : at * BLOCK + len(block)] = block
    info = Apfs(
        b"",
        BLOCK,
        inodes_map,
        streams_map,
        data_blocks,
        first_leaves,
        first_root,
        first_omap,
        superblocks,
        2,
        nx_omap_obj,
    )
    if patch:
        patch(container, info)
    info.container = bytes(container)
    return info


def _omap_tree(
    layout: _Layout,
    records: list[tuple[bytes, bytes]],
    xid: int,
    per_leaf: int | None,
) -> tuple[int, list[int]]:
    """An object map's B-tree: one root leaf, or leaves of ``per_leaf`` entries under
    an index root. Returns the root's block and the leaf blocks."""
    if per_leaf is None or len(records) <= per_leaf:
        at = layout.take()
        layout.blocks[at] = _node(
            records,
            oid=at,
            xid=xid,
            kind=PHYSICAL | T_BTREE,
            subtype=T_OMAP,
            level=0,
            root=True,
            fixed=(16, 16),
            info=(0x12, 16, 16, 16, 16, 1),
        )
        return at, [at]
    leaves = []
    index = []
    for i in range(0, len(records), per_leaf):
        chunk = records[i : i + per_leaf]
        at = layout.take()
        layout.blocks[at] = _node(
            chunk,
            oid=at,
            xid=xid,
            kind=PHYSICAL | T_BTREE_NODE,
            subtype=T_OMAP,
            level=0,
            root=False,
            fixed=(16, 16),
        )
        leaves.append(at)
        index.append((chunk[0][0], struct.pack("<Q", at)))
    root = layout.take()
    layout.blocks[root] = _node(
        index,
        oid=root,
        xid=xid,
        kind=PHYSICAL | T_BTREE,
        subtype=T_OMAP,
        level=1,
        root=True,
        fixed=(16, 16),
        info=(0x12, 16, 16, 16, 16, len(leaves) + 1),
        key_count=len(records),
    )
    return root, leaves


def apfs_dmg(
    container: bytes,
    *,
    layout: str = "gpt",
    codec: int | None = None,
    **udif_options: object,
) -> bytes:
    """A whole ``.dmg``: an APFS container in a GPT (or ``apm``, or ``none``) disk in a
    UDIF image."""
    from tests import dmg_build as d

    part = d.Partition(
        container, name="disk image", gpt_type=d.APFS_GUID, apm_type="Apple_APFS"
    )
    if layout == "gpt":
        disk = d.write_gpt([part])
    elif layout == "apm":
        disk = d.write_apm([part])
    else:
        disk = d.write_bare(part)
    if codec is not None:
        udif_options["codec"] = codec
    return d.write_udif(disk.segments, tables=disk.tables, **udif_options).image  # type: ignore[arg-type]
