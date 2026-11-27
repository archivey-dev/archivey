"""Glue: UDIF image -> partition -> filesystem -> manifest {path: (kind, sha256|target, size)}."""

from __future__ import annotations

import hashlib
import os
import time

from . import hfsplus, udif

HFS_NAMES = ("Apple_HFS", "Apple_HFSX")
APFS_NAMES = ("Apple_APFS",)


def pick_partition(img: udif.UdifImage):
    for p in img.partitions:
        if any(n in p.name for n in HFS_NAMES):
            return "hfs", p
        if any(n in p.name for n in APFS_NAMES):
            return "apfs", p
    # whole-disk partition image (imageVariant 2) or unnamed: probe
    p = max(img.partitions, key=lambda p: p.sector_count)
    return "probe", p


def open_fs(path: str):
    f = open(path, "rb")
    img = udif.UdifImage(f, os.path.getsize(path))
    kind, part = pick_partition(img)
    view = udif.DiskView(img, part.first_sector * 512, part.sector_count * 512)
    if kind == "probe":
        if view.read_at(1024, 2) in (b"H+", b"HX"):
            kind = "hfs"
        elif view.read_at(32, 4) == b"NXSB":
            kind = "apfs"
        else:
            raise udif.DmgError(f"no known filesystem in {part.name!r}")
    if kind == "hfs":
        return img, kind, hfsplus.HfsPlus(view)
    from . import apfs
    return img, kind, apfs.Apfs(view)


def manifest(path: str, with_data: bool = True):
    img, kind, fs = open_fs(path)
    t0 = time.time()
    res: dict[str, tuple] = {}
    if kind == "hfs":
        entries, inodes = hfsplus.build_paths(fs.entries())
        t_list = time.time() - t0
        for e in entries:
            if e.kind == "dir":
                res[e.path] = ("dir",)
            elif e.kind == "symlink":
                res[e.path] = ("symlink", fs.file_bytes(e).decode("utf-8", "surrogateescape"))
            elif e.kind == "hardlink":
                target = inodes.get(e.link_inode)
                if target is None:
                    res[e.path] = ("broken-hardlink",)
                else:
                    data = fs.file_bytes(target) if with_data else b""
                    res[e.path] = ("file", hashlib.sha256(data).hexdigest(), len(data))
            elif e.kind == "file":
                data = fs.file_bytes(e) if with_data else b""
                res[e.path] = ("file", hashlib.sha256(data).hexdigest(), len(data))
            else:
                res[e.path] = ("other",)
    else:
        entries = fs.entries()
        t_list = time.time() - t0
        for e in entries:
            if e.kind == "dir":
                res[e.path] = ("dir",)
            elif e.kind == "symlink":
                res[e.path] = ("symlink", fs.symlink_target(e))
            elif e.kind == "file":
                data = fs.file_bytes(e) if with_data else b""
                res[e.path] = ("file", hashlib.sha256(data).hexdigest(), len(data))
            else:
                res[e.path] = ("other",)
    return kind, res, t_list, time.time() - t0, img
