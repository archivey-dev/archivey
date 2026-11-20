"""A minimal plain ISO 9660 image written without any package, for tests that must run
on a core-only install (no pycdlib)."""

from __future__ import annotations

import struct

_BLOCK = 2048


def _both16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _record(ident: bytes, extent: int, length: int, *, is_dir: bool) -> bytes:
    date = bytes([126, 11, 20, 12, 0, 0, 0])  # 2026-11-20 12:00:00 UTC
    body = (
        b"\x00"
        + _both32(extent)
        + _both32(length)
        + date
        + bytes([2 if is_dir else 0, 0, 0])
        + _both16(1)
        + bytes([len(ident)])
        + ident
    )
    if len(ident) % 2 == 0:
        body += b"\x00"
    return bytes([len(body) + 1]) + body


def minimal_iso(name: bytes = b"HELLO.TXT;1", data: bytes = b"hello\n") -> bytes:
    """One file ``name`` holding ``data`` in the root of a plain ISO 9660 image."""
    root_at, file_at = 20, 21
    blocks = file_at + max(1, -(-len(data) // _BLOCK))
    root = (
        _record(b"\x00", root_at, _BLOCK, is_dir=True)
        + _record(b"\x01", root_at, _BLOCK, is_dir=True)
        + _record(name, file_at, len(data), is_dir=False)
    )
    path_table_le = bytes([1, 0]) + struct.pack("<I", root_at) + struct.pack("<H", 1)
    path_table_be = bytes([1, 0]) + struct.pack(">I", root_at) + struct.pack(">H", 1)
    path_table_le += b"\x00\x00"
    path_table_be += b"\x00\x00"
    blank_date = b"0" * 16 + b"\x00"
    pvd = (
        b"\x01CD001\x01\x00"
        + b" " * 32
        + b"MINIMAL".ljust(32)
        + bytes(8)
        + _both32(blocks)
        + bytes(32)
        + _both16(1)
        + _both16(1)
        + _both16(_BLOCK)
        + _both32(len(path_table_le))
        + struct.pack("<I", 18)
        + bytes(4)
        + struct.pack(">I", 19)
        + bytes(4)
        + _record(b"\x00", root_at, _BLOCK, is_dir=True)
        + b" " * 128 * 4
        + b" " * 37 * 3
        + blank_date * 4
        + b"\x01\x00"
    )
    terminator = b"\xffCD001\x01"
    image = bytearray(blocks * _BLOCK)
    for block, content in (
        (16, pvd),
        (17, terminator),
        (18, path_table_le),
        (19, path_table_be),
        (root_at, root),
        (file_at, data),
    ):
        image[block * _BLOCK : block * _BLOCK + len(content)] = content
    return bytes(image)
