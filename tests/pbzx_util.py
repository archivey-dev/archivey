"""Writes pbzx streams and odc CPIO archives for the tests, as Apple's ``pkgbuild`` and
``xip`` lay out a ``.pkg`` ``Payload`` and a ``.xip`` ``Content``."""

from __future__ import annotations

import lzma
import struct

APPLE_CHUNK = 1 << 24


def make_pbzx(
    data: bytes,
    *,
    chunk: int = 1 << 16,
    store: bool | None = None,
    header: int | None = None,
) -> bytes:
    """``data`` as a pbzx stream of ``chunk``-byte chunks. Each chunk is xz unless xz
    does not shrink it (``store=None``), or always stored or always xz."""
    out = bytearray(b"pbzx" + struct.pack(">Q", chunk if header is None else header))
    for start in range(0, len(data), chunk):
        piece = data[start : start + chunk]
        packed = lzma.compress(piece)
        stored = len(packed) >= len(piece) if store is None else store
        body = piece if stored else packed
        out += struct.pack(">QQ", len(piece), len(body)) + body
    return bytes(out)


def odc_cpio(
    entries: list[tuple[str, bytes | None]],
    *,
    links: dict[str, str] | None = None,
    modes: dict[str, int] | None = None,
) -> bytes:
    """An odc CPIO (``070707``) of ``(name, data)``; ``None`` data makes a directory.
    ``links`` maps a name to the earlier name it is a hard link to: both get one inode
    and a link count of 2. ``modes`` sets a name's mode."""
    links = links or {}
    modes = modes or {}
    inodes: dict[str, int] = {}
    out = bytearray()
    for ino, (name, data) in enumerate([*entries, ("TRAILER!!!", b"")], start=1):
        raw = name.encode() + b"\0"
        if data is None:
            mode, data = 0o40755, b""
        elif name == "TRAILER!!!":
            mode = 0
        else:
            mode = 0o100644
        mode = modes.get(name, mode)
        linked = name in links or name in links.values()
        inode = inodes.setdefault(links.get(name, name), ino)
        fields = (0, inode, mode, 0, 0, 2 if linked else 1, 0, 1_700_000_000)
        out += b"070707%06o%06o%06o%06o%06o%06o%06o%011o" % fields
        out += b"%06o%011o" % (len(raw), len(data)) + raw + data
    return bytes(out)
