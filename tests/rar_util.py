"""Helpers for tests that edit RAR archives by hand."""

from __future__ import annotations

import struct
import zlib

from archivey.internal.backends.rar_parser import load_vint


def flag_size_unknown(
    data: bytes, *, placeholder: bool = False, only: int | None = None
) -> bytes:
    """``data`` with the "size unknown" file flag (``0x08``) set on every RAR5 FILE
    header, or only on the one at index ``only``, and each header CRC redone.
    ``placeholder`` also writes 127 over the first flagged member's size, a two-byte
    vint (rar pads it), so the header keeps its length."""
    out = bytearray(data)
    pos = 8  # past the RAR5 signature
    file_index = -1
    while pos < len(out):
        size, body_at = load_vint(out, pos + 4)
        block_type, q = load_vint(out, body_at)
        flags, q = load_vint(out, q)
        if flags & 0x0001:  # extra area
            _, q = load_vint(out, q)
        data_size = 0
        if flags & 0x0002:  # data area
            data_size, q = load_vint(out, q)
        if block_type == 2:
            file_index += 1
        if block_type == 2 and only in (None, file_index):
            # FILE; its one-byte file flags are at q
            out[q] |= 0x08
            if placeholder:
                assert out[q + 2] == 0x00  # a padded two-byte size vint
                out[q + 1 : q + 3] = b"\xff\x00"
                placeholder = False
            crc = zlib.crc32(out[pos + 4 : body_at + size]) & 0xFFFFFFFF
            out[pos : pos + 4] = crc.to_bytes(4, "little")
        if block_type == 5:  # end of archive
            break
        pos = body_at + size + data_size
    return bytes(out)


def _rar3_block(block_type: int, flags: int, body: bytes) -> bytes:
    """A RAR 1.5-4 block header: CRC16, type, flags, size, then ``body``."""
    head = bytes([block_type]) + struct.pack("<HH", flags, 7 + len(body)) + body
    return struct.pack("<H", zlib.crc32(head) & 0xFFFF) + head


def write_rar29_stored(files: list[tuple[str, bytes]]) -> bytes:
    """A RAR 2.9 archive of ``files`` (name, data), stored (``-m0``), nonsolid.

    ``rar`` 7.00 no longer writes RAR 1.5-4 archives, so tests that need one with
    many members write it here: a MAIN header, one FILE header per member
    (``LONG_BLOCK`` set, a DOS time of 2020-01-01, Unix host, mode 0644), and the
    end block ``rar`` writes. ``unrar t`` tests the result OK.
    """
    out = bytearray(b"Rar!\x1a\x07\x00")
    out += _rar3_block(0x73, 0x0000, b"\0" * 6)
    dos_time = ((2020 - 1980) << 25) | (1 << 21) | (1 << 16)
    for name, data in files:
        raw = name.encode("utf-8")
        body = struct.pack(
            "<LLBLLBBHL",
            len(data),
            len(data),
            3,  # Unix
            zlib.crc32(data) & 0xFFFFFFFF,
            dos_time,
            29,
            0x30,  # stored
            len(raw),
            0o100644,
        )
        out += _rar3_block(0x74, 0x8000, body + raw)
        out += data
    out += _rar3_block(0x7B, 0x4000, b"")
    return bytes(out)
