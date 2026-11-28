"""HFS+ / HFSX read-only prototype (Apple TN1150), over any object with read_at(off, n)."""

from __future__ import annotations

import stat
import struct
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from . import lzfse

HFS_EPOCH = datetime(1904, 1, 1, tzinfo=UTC)
FORK = struct.Struct(">QII64s")
NODE_DESC = struct.Struct(">IIbBHH")
HEADER_REC = struct.Struct(">HIIIIHHII")
ROOT_PARENT, ROOT_FOLDER, EXTENTS_ID, CATALOG_ID, ALLOC_ID, STARTUP_ID, ATTR_ID = 1, 2, 3, 4, 6, 7, 8
FOLDER, FILE, FOLDER_THREAD, FILE_THREAD = 1, 2, 3, 4
UF_COMPRESSED = 0x20
PRIVATE_FILES = "\0\0\0\0HFS+ Private Data"
PRIVATE_DIRS = ".HFS+ Private Directory Data\r"


class HfsError(Exception):
    pass


def hfs_time(v: int) -> datetime | None:
    return HFS_EPOCH + timedelta(seconds=v) if v else None


@dataclass
class Fork:
    size: int
    total_blocks: int
    extents: list[tuple[int, int]]


def parse_fork(b: bytes) -> Fork:
    size, _clump, total, ext = FORK.unpack(b)
    extents = [struct.unpack_from(">II", ext, 8 * i) for i in range(8)]
    return Fork(size, total, [e for e in extents if e[1]])


@dataclass
class Entry:
    cnid: int
    parent: int
    name: str
    kind: str  # dir, file, symlink, hardlink, other
    mode: int
    uid: int
    gid: int
    mtime: datetime | None
    ctime: datetime | None
    size: int = 0
    data: Fork | None = None
    rsrc: Fork | None = None
    compressed: bool = False
    link_inode: int = 0  # for hlnk: iNode number
    file_type: bytes = b""
    path: str = ""
    link_target: str | None = None
    extra: dict = field(default_factory=dict)


class HfsPlus:
    def __init__(self, view) -> None:
        self.v = view
        vh = view.read_at(1024, 512)
        if len(vh) < 512:
            raise HfsError("truncated volume header")
        sig = vh[:2]
        if sig == b"BD":
            raise HfsError("HFS (standard) or HFS wrapper volume: not supported in prototype")
        if sig not in (b"H+", b"HX"):
            raise HfsError("not HFS+")
        self.hfsx = sig == b"HX"
        self.version, self.attributes = struct.unpack_from(">HI", vh, 2)
        self.block_size, self.total_blocks = struct.unpack_from(">II", vh, 40)
        if self.block_size < 512 or self.block_size & (self.block_size - 1) or self.block_size > 1 << 20:
            raise HfsError("bad block size")
        self.file_count, self.folder_count = struct.unpack_from(">II", vh, 32)
        self.create_date, self.modify_date = struct.unpack_from(">II", vh, 16)
        self.extents_fork = parse_fork(vh[192:272])
        self.catalog_fork = parse_fork(vh[272:352])
        self.attributes_fork = parse_fork(vh[352:432])
        self.journaled = bool(self.attributes & 0x2000)
        self.overflow: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
        if self.extents_fork.size:
            self._load_overflow()
        self.xattrs: dict[int, dict[str, bytes | Fork]] = {}
        if self.attributes_fork.size:
            self._load_xattrs()

    # --- forks -----------------------------------------------------------------------------
    def fork_extents(self, cnid: int, fork_type: int, fork: Fork) -> list[tuple[int, int]]:
        ext = list(fork.extents)
        have = sum(c for _, c in ext)
        if have < fork.total_blocks:
            for start_block, s, c in sorted(self.overflow.get((cnid, fork_type), [])):
                if start_block != have:
                    continue
                ext.append((s, c))
                have += c
        if have < fork.total_blocks:
            raise HfsError(f"fork of {cnid} missing extents ({have}/{fork.total_blocks} blocks)")
        for s, c in ext:
            if s + c > self.total_blocks:
                raise HfsError("extent past end of volume")
        return ext

    def read_fork(self, cnid: int, fork_type: int, fork: Fork, offset: int = 0, n: int | None = None) -> bytes:
        if n is None:
            n = fork.size - offset
        n = max(0, min(n, fork.size - offset))
        if fork.size > fork.total_blocks * self.block_size:
            raise HfsError("fork size larger than its blocks")
        out = bytearray()
        pos = 0
        bs = self.block_size
        for s, c in self.fork_extents(cnid, fork_type, fork):
            ext_len = c * bs
            if pos + ext_len > offset and len(out) < n:
                rel = max(0, offset - pos)
                take = min(ext_len - rel, n - len(out))
                chunk = self.v.read_at(s * bs + rel, take)
                if len(chunk) != take:
                    raise HfsError("volume truncated")
                out += chunk
            pos += ext_len
            if len(out) >= n:
                break
        return bytes(out)

    # --- b-trees ---------------------------------------------------------------------------
    def _btree_leaves(self, cnid: int, fork: Fork):
        ext = self.fork_extents(cnid, 0, fork)

        def read(off: int, n: int) -> bytes:
            return self.read_fork(cnid, 0, fork, off, n)

        head = read(0, 512)
        fl, bl, kind, height, nrec, _ = NODE_DESC.unpack_from(head)
        if kind != 1:
            raise HfsError("b-tree header node missing")
        depth, root, leaf_recs, first_leaf, last_leaf, node_size, max_key, total_nodes, free = HEADER_REC.unpack_from(head, 14)
        if node_size < 512 or node_size & (node_size - 1) or node_size > 32768:
            raise HfsError("bad node size")
        if total_nodes * node_size > fork.size:
            raise HfsError("b-tree larger than its fork")
        seen = set()
        node = first_leaf
        while node:
            if node in seen or node >= total_nodes:
                raise HfsError("b-tree leaf chain loops or leaves the tree")
            seen.add(node)
            buf = read(node * node_size, node_size)
            fl, bl, kind, height, nrec, _ = NODE_DESC.unpack_from(buf)
            if kind != -1:
                raise HfsError("leaf chain reached a non-leaf node")
            if 14 + 2 * nrec > node_size:
                raise HfsError("too many records")
            offs = [struct.unpack_from(">H", buf, node_size - 2 * (i + 1))[0] for i in range(nrec + 1)]
            for i in range(nrec):
                a, b = offs[i], offs[i + 1]
                if not (14 <= a < b <= node_size - 2 * (nrec + 1)):
                    raise HfsError("record offsets out of order")
                yield buf[a:b]
            node = fl

    def _load_overflow(self) -> None:
        # extents overflow tree leaves can't themselves be in overflow (TN1150)
        fork = self.extents_fork
        saved = self.overflow
        for rec in self._btree_leaves(EXTENTS_ID, fork):
            klen, ftype, _pad, cnid, start = struct.unpack_from(">HBBII", rec)
            ext = [struct.unpack_from(">II", rec, 2 + klen + 8 * i) for i in range(8)]
            lst = saved.setdefault((cnid, ftype), [])
            blk = start
            for s, c in ext:
                if c:
                    lst.append((blk, s, c))
                    blk += c
        # flatten to (start_block_in_fork, start, count) consecutive
        for k, lst in saved.items():
            saved[k] = lst

    def _load_xattrs(self) -> None:
        for rec in self._btree_leaves(ATTR_ID, self.attributes_fork):
            klen, _pad, cnid, start, nlen = struct.unpack_from(">HHIIH", rec)
            name = rec[14:14 + 2 * nlen].decode("utf-16-be", "surrogatepass")
            d = 2 + klen
            (rtype,) = struct.unpack_from(">I", rec, d)
            if rtype == 0x10:
                (size,) = struct.unpack_from(">I", rec, d + 12)
                self.xattrs.setdefault(cnid, {})[name] = rec[d + 16:d + 16 + size]
            elif rtype == 0x20:
                self.xattrs.setdefault(cnid, {})[name] = parse_fork(rec[d + 8:d + 88])
            # 0x30 overflow extents for attribute forks: ignored in prototype

    def xattr(self, cnid: int, name: str) -> bytes | None:
        v = self.xattrs.get(cnid, {}).get(name)
        if isinstance(v, Fork):
            if len(v.extents) and sum(c for _, c in v.extents) >= v.total_blocks:
                out = bytearray()
                for s, c in v.extents:
                    out += self.v.read_at(s * self.block_size, c * self.block_size)
                return bytes(out[: v.size])
            raise HfsError("attribute fork with overflow extents")
        return v

    # --- catalog ---------------------------------------------------------------------------
    def entries(self) -> list[Entry]:
        out: list[Entry] = []
        threads: dict[int, tuple[int, str]] = {}
        for rec in self._btree_leaves(CATALOG_ID, self.catalog_fork):
            klen, parent, nlen = struct.unpack_from(">HIH", rec)
            if 6 + 2 * nlen > klen:
                raise HfsError("catalog key name longer than key")
            name = rec[8:8 + 2 * nlen].decode("utf-16-be", "surrogatepass").replace("/", ":")
            d = 2 + klen
            d += d & 1
            (rtype,) = struct.unpack_from(">h", rec, d)
            r = rec[d:]
            if rtype in (FOLDER_THREAD, FILE_THREAD):
                p, n = struct.unpack_from(">IH", r, 4)
                threads[0] = (p, "")  # unused
                continue
            if rtype not in (FOLDER, FILE):
                raise HfsError(f"unknown catalog record type {rtype}")
            if rtype == FOLDER:
                if len(r) < 88:
                    raise HfsError("short folder record")
                (cnid,) = struct.unpack_from(">I", r, 8)
            else:
                if len(r) < 248:
                    raise HfsError("short file record")
                (cnid,) = struct.unpack_from(">I", r, 8)
            create, cmod = struct.unpack_from(">II", r, 12)
            uid, gid, admin_flags, owner_flags, mode, special = struct.unpack_from(">IIBBHI", r, 32)
            ftype, creator = r[48:52], r[52:56]
            if rtype == FOLDER:
                e = Entry(cnid, parent, name, "dir", mode, uid, gid, hfs_time(cmod), hfs_time(create))
            else:
                e = Entry(cnid, parent, name, "file", mode, uid, gid, hfs_time(cmod), hfs_time(create))
                e.data = parse_fork(r[88:168])
                e.rsrc = parse_fork(r[168:248])
                e.size = e.data.size
                e.file_type = ftype
                e.compressed = bool(owner_flags & UF_COMPRESSED)
                if ftype == b"hlnk" and creator == b"hfs+":
                    e.kind = "hardlink"
                    e.link_inode = special
                elif stat.S_ISLNK(mode) or (ftype == b"slnk" and creator == b"rhap"):
                    e.kind = "symlink"
                elif mode and not stat.S_ISREG(mode):
                    e.kind = "other"
            out.append(e)
        return out

    # --- file data -------------------------------------------------------------------------
    def file_bytes(self, e: Entry) -> bytes:
        if e.compressed:
            return self._decmpfs(e)
        return self.read_fork(e.cnid, 0, e.data)

    def _decmpfs(self, e: Entry) -> bytes:
        hdr = self.xattr(e.cnid, "com.apple.decmpfs")
        if hdr is None or len(hdr) < 16 or hdr[:4] != b"fpmc":
            raise HfsError(f"compressed file {e.name!r} without decmpfs header")
        ctype, usize = struct.unpack_from("<IQ", hdr, 4)
        return decmpfs(ctype, usize, hdr[16:], lambda: self.read_fork(e.cnid, 0xFF, e.rsrc))


MAX_DECMPFS_BLOCK = 0x10000


def decmpfs(ctype: int, usize: int, inline: bytes, rsrc) -> bytes:
    if ctype in (1, 9):  # uncompressed in xattr ... 9 is the documented one
        return inline[:usize]
    if ctype == 3:  # zlib in xattr
        if inline[:1] and inline[0] & 0x0F == 0x0F:
            return inline[1:1 + usize]
        return zlib.decompressobj().decompress(inline, usize)
    if ctype == 7:  # LZVN in xattr
        if inline[:1] == b"\x06":
            return inline[1:1 + usize]
        out = bytearray()
        lzfse.lzvn_decode(inline, out, usize)
        return bytes(out)
    if ctype == 11:  # LZFSE in xattr
        if inline[:1] == b"\xff":
            return inline[1:1 + usize]
        return lzfse.decompress(inline, usize)
    if ctype == 4:  # zlib in resource fork (resource map layout)
        rf = rsrc()
        (data_off,) = struct.unpack_from(">I", rf, 0)
        base = data_off + 4
        (count,) = struct.unpack_from("<I", rf, base)
        out = bytearray()
        for i in range(count):
            off, size = struct.unpack_from("<II", rf, base + 4 + 8 * i)
            blk = rf[base + off:base + off + size]
            want = min(MAX_DECMPFS_BLOCK, usize - len(out))
            if blk[:1] and blk[0] & 0x0F == 0x0F:
                out += blk[1:1 + want]
            else:
                out += zlib.decompressobj().decompress(blk, want)
        if len(out) != usize:
            raise HfsError("decmpfs zlib size mismatch")
        return bytes(out)
    if ctype in (8, 12, 10):  # LZVN / LZFSE / raw in resource fork: offset table
        rf = rsrc()
        nblocks = (usize + MAX_DECMPFS_BLOCK - 1) // MAX_DECMPFS_BLOCK
        offs = struct.unpack_from(f"<{nblocks + 1}I", rf, 0)
        out = bytearray()
        for i in range(nblocks):
            blk = rf[offs[i]:offs[i + 1]]
            want = min(MAX_DECMPFS_BLOCK, usize - len(out))
            if ctype == 10 or (ctype == 8 and blk[:1] == b"\x06") or (ctype == 12 and blk[:1] == b"\xff"):
                out += blk[1:1 + want] if ctype != 10 else blk[:want]
            elif ctype == 8:
                part = bytearray()
                lzfse.lzvn_decode(blk, part, want)
                out += part
            else:
                out += lzfse.decompress(blk, want)
        if len(out) != usize:
            raise HfsError("decmpfs size mismatch")
        return bytes(out)
    raise HfsError(f"decmpfs type {ctype} not supported")


def build_paths(entries: list[Entry], root_cnid: int = ROOT_FOLDER):
    """Resolve parent chains to paths; drop the private folders; resolve hard links."""
    dirs = {e.cnid: e for e in entries if e.kind == "dir"}
    private_files = next((e.cnid for e in entries if e.parent == root_cnid and e.name == PRIVATE_FILES), None)
    private_dirs = next((e.cnid for e in entries if e.parent == root_cnid and e.name == PRIVATE_DIRS), None)
    inodes = {}
    if private_files is not None:
        for e in entries:
            if e.parent == private_files and e.name.startswith("iNode"):
                try:
                    inodes[int(e.name[5:])] = e
                except ValueError:
                    pass
    cache: dict[int, str | None] = {root_cnid: ""}

    def dir_path(cnid: int, depth: int = 0) -> str | None:
        if cnid in cache:
            return cache[cnid]
        if depth > 4096 or cnid not in dirs:
            return None
        d = dirs[cnid]
        pp = dir_path(d.parent, depth + 1)
        p = None if pp is None else (pp + "/" + d.name if pp else d.name)
        cache[cnid] = p
        return p

    result = []
    for e in entries:
        if e.cnid == root_cnid:
            continue
        if e.parent in (private_files, private_dirs) or e.cnid in (private_files, private_dirs):
            continue
        pp = dir_path(e.parent)
        if pp is None:
            continue  # orphan (or the root's own record)
        e.path = pp + "/" + e.name if pp else e.name
        result.append(e)
    return result, inodes
