"""A minimal ``.lzo`` (lzop) writer for tests: every block stored, not compressed.

lzop stores a block as is when LZO1X does not make it shorter, so a file of stored
blocks is one ``lzop -d`` reads. With ``python-lzo`` installed, ``compress=True``
writes LZO1X blocks too.
"""

from __future__ import annotations

import struct
import zlib

MAGIC = b"\x89LZO\x00\r\n\x1a\n"
_F_ADLER32_D = 0x1
_F_ADLER32_C = 0x2
_F_H_EXTRA_FIELD = 0x40


def make_lzop(
    data: bytes,
    *,
    name: bytes = b"",
    block_size: int = 256 * 1024,
    compress: bool = False,
    mtime: int = 0,
    extra: bytes | None = None,
) -> bytes:
    """``data`` as one lzop file: version 0x1040 header, Adler-32 checksums, and the
    header's extra field when ``extra`` is given."""
    flags = _F_ADLER32_D | (_F_ADLER32_C if compress else 0)
    if extra is not None:
        flags |= _F_H_EXTRA_FIELD
    header = struct.pack(">HHHBBI", 0x1040, 0x20A0, 0x0940, 1, 5, flags)
    header += struct.pack(">III", 0o100644, mtime & 0xFFFFFFFF, mtime >> 32)
    header += bytes([len(name)]) + name
    out = bytearray(MAGIC + header + struct.pack(">I", zlib.adler32(header)))
    if extra is not None:
        # The length, the field, and an Adler-32 of both (lzop's read_header).
        field = struct.pack(">I", len(extra)) + extra
        out += field + struct.pack(">I", zlib.adler32(field))
    for at in range(0, len(data), block_size):
        block = data[at : at + block_size]
        packed = block
        if compress:
            import lzo  # optional: only the tests that ask for it need it

            candidate = lzo.compress(block, 1, False)
            if len(candidate) < len(block):
                packed = candidate
        out += struct.pack(">II", len(block), len(packed))
        out += struct.pack(">I", zlib.adler32(block))
        if packed is not block:
            out += struct.pack(">I", zlib.adler32(packed))
        out += packed
    return bytes(out + b"\x00\x00\x00\x00")
