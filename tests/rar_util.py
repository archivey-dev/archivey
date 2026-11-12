"""Helpers for tests that edit RAR archives by hand."""

from __future__ import annotations

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
