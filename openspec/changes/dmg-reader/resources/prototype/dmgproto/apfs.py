"""APFS read-only prototype (Apple File System Reference), unencrypted, unsealed, no snapshots."""

from __future__ import annotations

import operator
import struct
from dataclasses import dataclass, field

from .hfsplus import decmpfs

OBJ_HDR = struct.Struct("<QQQII")
NX_MAGIC, APSB_MAGIC = b"NXSB", b"APSB"
T_NX, T_BTREE, T_BTREE_NODE, T_OMAP, T_FS = 0x1, 0x2, 0x3, 0xB, 0xD
BTNODE_ROOT, BTNODE_LEAF, BTNODE_FIXED = 1, 2, 4
J_INODE, J_XATTR, J_SIBLING, J_DSTREAM_ID, J_EXTENT, J_DIR_REC = 3, 4, 5, 6, 8, 9
INO_EXT_DSTREAM = 8
XATTR_STREAM, XATTR_EMBEDDED = 1, 2
ROOT_DIR = 2
UF_COMPRESSED = 0x20
FS_UNENCRYPTED = 1
INCOMPAT_CASE_INSENSITIVE, INCOMPAT_NORM_INSENSITIVE, INCOMPAT_SEALED = 0x1, 0x8, 0x20
MAX_NODES = 1 << 22
MAX_DEPTH = 32


class ApfsError(Exception):
    pass


def fletcher64(block: bytes) -> int:
    n = (len(block) - 8) // 4
    words = struct.unpack_from(f"<{n}I", block, 8)
    m = 0xFFFFFFFF
    s1 = sum(words) % m
    s2 = sum(map(operator.mul, words, range(n, 0, -1))) % m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return (c2 << 32) | c1


@dataclass
class Inode:
    oid: int
    parent: int
    private_id: int
    mtime_ns: int
    ctime_ns: int
    nlink: int
    bsd_flags: int
    uid: int
    gid: int
    mode: int
    size: int
    xattrs: dict = field(default_factory=dict)


@dataclass
class Entry:
    path: str
    kind: str
    inode: Inode | None
    link_to: str | None = None


class Apfs:
    def __init__(self, view, verify_checksums: bool = True) -> None:
        self.v = view
        self.verify = verify_checksums
        self.bs = 4096
        b0 = view.read_at(0, 4096)
        if b0[32:36] != NX_MAGIC:
            raise ApfsError("no NXSB")
        (self.bs,) = struct.unpack_from("<I", b0, 36)
        if self.bs < 4096 or self.bs > 65536 or self.bs & (self.bs - 1):
            raise ApfsError("bad block size")
        self.nx = self._latest_superblock(b0)
        nx = self.nx
        (self.block_count,) = struct.unpack_from("<Q", nx, 40)
        (incompat,) = struct.unpack_from("<Q", nx, 64)
        if incompat & 0x100:
            raise ApfsError("Fusion container")
        (omap_oid,) = struct.unpack_from("<Q", nx, 160)
        (self.xid,) = struct.unpack_from("<Q", nx, 16)
        self.nx_omap = self._load_omap(omap_oid, self.xid)
        fs_oids = [o for o in struct.unpack_from("<100Q", nx, 184) if o]
        if not fs_oids:
            raise ApfsError("container holds no volume")
        self.volumes = []
        for vo in fs_oids:
            if vo not in self.nx_omap:
                raise ApfsError("volume superblock not in object map")
            sb = self._obj(self.nx_omap[vo], T_FS)
            if sb[32:36] != APSB_MAGIC:
                raise ApfsError("bad APSB")
            self.volumes.append(sb)
        if len(self.volumes) > 1:
            pass  # prototype reads the first; question for the report
        sb = self.volumes[0]
        (self.vol_incompat,) = struct.unpack_from("<Q", sb, 56)
        (fs_flags,) = struct.unpack_from("<Q", sb, 264)
        self.encrypted = not fs_flags & FS_UNENCRYPTED
        if self.encrypted:
            raise ApfsError("encrypted APFS volume")
        if self.vol_incompat & INCOMPAT_SEALED:
            raise ApfsError("sealed volume")
        self.hashed_names = bool(self.vol_incompat & (INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORM_INSENSITIVE))
        self.volname = sb[704:960].split(b"\0", 1)[0].decode("utf-8", "replace")
        vol_omap_oid, root_tree_oid = struct.unpack_from("<QQ", sb, 128)
        self.vol_omap = self._load_omap(vol_omap_oid, self.xid)
        if root_tree_oid not in self.vol_omap:
            raise ApfsError("root tree not in volume object map")
        self.root_tree = self.vol_omap[root_tree_oid]
        self.nodes_read = 0

    # --- objects ---------------------------------------------------------------------------
    def _block(self, paddr: int) -> bytes:
        if paddr <= 0 or paddr >= self.block_count if hasattr(self, "block_count") else False:
            raise ApfsError("block address out of range")
        b = self.v.read_at(paddr * self.bs, self.bs)
        if len(b) != self.bs:
            raise ApfsError("truncated block")
        return b

    def _obj(self, paddr: int, want_type: int | None = None) -> bytes:
        b = self._block(paddr)
        ck, oid, xid, otype, _sub = OBJ_HDR.unpack_from(b)
        if self.verify and fletcher64(b) != ck:
            raise ApfsError(f"checksum mismatch in block {paddr}")
        if want_type is not None and otype & 0xFFFF != want_type:
            raise ApfsError(f"block {paddr} is type {otype & 0xFFFF:#x}, expected {want_type:#x}")
        return b

    def _latest_superblock(self, b0: bytes) -> bytes:
        desc_blocks, _data_blocks, desc_base = struct.unpack_from("<IIQ", b0, 104)
        best = b0 if fletcher64(b0) == struct.unpack_from("<Q", b0)[0] else None
        if desc_blocks & 0x80000000:
            raise ApfsError("non-contiguous checkpoint area")
        if desc_blocks > 1 << 16:
            raise ApfsError("checkpoint area too large")
        for i in range(desc_blocks):
            b = self.v.read_at((desc_base + i) * self.bs, self.bs)
            if len(b) != self.bs or b[32:36] != NX_MAGIC:
                continue
            ck, _oid, xid, otype, _ = OBJ_HDR.unpack_from(b)
            if otype & 0xFFFF != T_NX or fletcher64(b) != ck:
                continue
            if best is None or xid > struct.unpack_from("<Q", best, 16)[0]:
                best = b
        if best is None:
            raise ApfsError("no valid container superblock")
        return best

    # --- b-trees ---------------------------------------------------------------------------
    def _iter_tree(self, root_paddr: int, translate=None, depth: int = 0, info=None, seen=None):
        """Yield (key bytes, value bytes) of every leaf record, in order."""
        if seen is None:
            seen = set()
        if root_paddr in seen or len(seen) > MAX_NODES or depth > MAX_DEPTH:
            raise ApfsError("b-tree loops or is too deep")
        seen.add(root_paddr)
        b = self._obj(root_paddr)
        self.nodes_read = getattr(self, "nodes_read", 0) + 1
        if b[24:28] and (struct.unpack_from("<I", b, 24)[0] & 0xFFFF) not in (T_BTREE, T_BTREE_NODE):
            raise ApfsError("not a b-tree node")
        flags, level, nkeys, toff, tlen = struct.unpack_from("<HHIHH", b, 32)
        if flags & BTNODE_ROOT:
            info = struct.unpack_from("<IIII", b, self.bs - 40)  # flags, node_size, key_size, val_size
        if info is None:
            raise ApfsError("b-tree info missing")
        toc = 56 + toff
        kstart = toc + tlen
        vend = self.bs - (40 if flags & BTNODE_ROOT else 0)
        fixed = bool(flags & BTNODE_FIXED)
        leaf = bool(flags & BTNODE_LEAF)
        if (8 if not fixed else 4) * nkeys > tlen:
            raise ApfsError("table of contents too small")
        for i in range(nkeys):
            if fixed:
                ko, vo = struct.unpack_from("<HH", b, toc + 4 * i)
                kl = info[2]
                vl = info[3] if leaf else 8
            else:
                ko, kl, vo, vl = struct.unpack_from("<HHHH", b, toc + 8 * i)
            k0 = kstart + ko
            v0 = vend - vo
            if not (kstart <= k0 and k0 + kl <= vend and kstart <= v0 and v0 + vl <= vend):
                raise ApfsError("record outside node")
            key = b[k0:k0 + kl]
            val = b[v0:v0 + vl]
            if leaf:
                yield key, val
            else:
                (child,) = struct.unpack_from("<Q", val)
                if translate is not None:
                    if child not in translate:
                        raise ApfsError("child node not in object map")
                    child = translate[child]
                yield from self._iter_tree(child, translate, depth + 1, info, seen)

    def _load_omap(self, omap_paddr: int, max_xid: int) -> dict[int, int]:
        om = self._obj(omap_paddr, T_OMAP)
        (tree,) = struct.unpack_from("<Q", om, 48)
        best: dict[int, tuple[int, int]] = {}
        for k, v in self._iter_tree(tree):
            oid, xid = struct.unpack_from("<QQ", k)
            flags, _size, paddr = struct.unpack_from("<IIQ", v)
            if xid > max_xid or flags & 1:  # OMAP_VAL_DELETED
                continue
            if flags & 4:
                raise ApfsError("encrypted object map entry")
            if oid not in best or best[oid][0] < xid:
                best[oid] = (xid, paddr)
        return {o: p for o, (_x, p) in best.items()}

    # --- file system tree ------------------------------------------------------------------
    def entries(self) -> list[Entry]:
        inodes: dict[int, Inode] = {}
        children: dict[int, list[tuple[str, int, int]]] = {}
        self.extents: dict[int, list[tuple[int, int, int]]] = {}
        dstream_sizes: dict[int, int] = {}
        for k, v in self._iter_tree(self.root_tree, self.vol_omap):
            (oat,) = struct.unpack_from("<Q", k)
            oid, typ = oat & 0x0FFFFFFFFFFFFFFF, oat >> 60
            if typ == J_INODE:
                (parent, private_id, _cr, mtime, ctime, _at, _if, nlink, _pc, _wg, bsd, uid, gid, mode, _p,
                 usize) = struct.unpack_from("<QQQQQQQiIIIIIHHQ", v)
                ino = Inode(oid, parent, private_id, mtime, ctime, nlink, bsd, uid, gid, mode, 0)
                ino.size = self._dstream_size(v[92:])
                inodes[oid] = ino
            elif typ == J_DIR_REC:
                if self.hashed_names:
                    (lh,) = struct.unpack_from("<I", k, 8)
                    nlen = lh & 0x3FF
                    name = k[12:12 + nlen]
                else:
                    (nlen,) = struct.unpack_from("<H", k, 8)
                    name = k[10:10 + nlen]
                name = name.rstrip(b"\0").decode("utf-8", "surrogateescape")
                file_id, _added, flags = struct.unpack_from("<QQH", v)
                children.setdefault(oid, []).append((name, file_id, flags & 0xF))
            elif typ == J_EXTENT:
                (logical,) = struct.unpack_from("<Q", k, 8)
                lf, pb, crypto = struct.unpack_from("<QQQ", v)
                self.extents.setdefault(oid, []).append((logical, lf & 0x00FFFFFFFFFFFFFF, pb))
            elif typ == J_XATTR:
                (nlen,) = struct.unpack_from("<H", k, 8)
                name = k[10:10 + nlen].rstrip(b"\0").decode("utf-8", "surrogateescape")
                flags, dlen = struct.unpack_from("<HH", v)
                data = v[4:4 + dlen]
                self._pending_xattrs = getattr(self, "_pending_xattrs", [])
                self._pending_xattrs.append((oid, name, flags, data))
        for oid, name, flags, data in getattr(self, "_pending_xattrs", []):
            ino = inodes.get(oid)
            if ino is None:
                continue
            if flags & XATTR_EMBEDDED:
                ino.xattrs[name] = data
            elif flags & XATTR_STREAM:
                xoid, size = struct.unpack_from("<QQ", data)
                ino.xattrs[name] = ("stream", xoid, size)
        for lst in self.extents.values():
            lst.sort()
        self.inodes = inodes
        out: list[Entry] = []
        first_path: dict[int, str] = {}
        seen_dirs = {ROOT_DIR}
        stack = [(ROOT_DIR, "")]
        while stack:
            d, prefix = stack.pop()
            for name, fid, dtype in sorted(children.get(d, [])):
                path = prefix + name
                ino = inodes.get(fid)
                if ino is None:
                    raise ApfsError(f"directory entry {path!r} names a missing inode")
                fmt = ino.mode & 0o170000
                if fmt == 0o040000:
                    if fid in seen_dirs:
                        raise ApfsError("directory reached twice")
                    seen_dirs.add(fid)
                    out.append(Entry(path, "dir", ino))
                    stack.append((fid, path + "/"))
                elif fid in first_path:
                    out.append(Entry(path, "hardlink", ino, first_path[fid]))
                elif fmt == 0o120000:
                    out.append(Entry(path, "symlink", ino))
                elif fmt == 0o100000:
                    first_path[fid] = path
                    out.append(Entry(path, "file", ino))
                else:
                    out.append(Entry(path, "other", ino))
        return out

    @staticmethod
    def _dstream_size(x: bytes) -> int:
        if len(x) < 4:
            return 0
        n, used = struct.unpack_from("<HH", x)
        hdr = 4 + 4 * n
        off = hdr
        for i in range(n):
            t, _f, size = struct.unpack_from("<BBH", x, 4 + 4 * i)
            if t == INO_EXT_DSTREAM:
                return struct.unpack_from("<Q", x, off)[0]
            off += (size + 7) & ~7
        return 0

    def read_stream(self, dstream_oid: int, size: int) -> bytes:
        out = bytearray()
        for logical, length, pb in self.extents.get(dstream_oid, []):
            if logical != len(out):
                if logical < len(out):
                    raise ApfsError("overlapping extents")
                out += bytes(logical - len(out))  # hole between extents
            if pb == 0:
                out += bytes(length)
            else:
                if pb + (length + self.bs - 1) // self.bs > self.block_count:
                    raise ApfsError("extent past end of container")
                chunk = self.v.read_at(pb * self.bs, length)
                if len(chunk) != length:
                    raise ApfsError("truncated extent")
                out += chunk
            if len(out) >= size:
                break
        if len(out) < size:
            out += bytes(size - len(out))  # sparse tail
        return bytes(out[:size])

    def xattr_bytes(self, ino: Inode, name: str) -> bytes | None:
        x = ino.xattrs.get(name)
        if isinstance(x, tuple):
            return self.read_stream(x[1], x[2])
        return x

    def symlink_target(self, e: Entry) -> str:
        t = self.xattr_bytes(e.inode, "com.apple.fs.symlink")
        if t is None:
            raise ApfsError("symlink without target")
        return t.rstrip(b"\0").decode("utf-8", "surrogateescape")

    def file_bytes(self, e: Entry) -> bytes:
        ino = e.inode
        if ino.bsd_flags & UF_COMPRESSED:
            hdr = self.xattr_bytes(ino, "com.apple.decmpfs")
            if hdr is None or hdr[:4] != b"fpmc":
                raise ApfsError("compressed file without decmpfs header")
            ctype, usize = struct.unpack_from("<IQ", hdr, 4)
            return decmpfs(ctype, usize, hdr[16:], lambda: self.xattr_bytes(ino, "com.apple.ResourceFork") or b"")
        return self.read_stream(ino.private_id, ino.size)
