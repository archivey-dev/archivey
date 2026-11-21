"""Rust codecs with standard-library-shaped interfaces.

- Hashes like :mod:`hashlib`: :class:`Crc16Arc`, and :func:`crc16_arc` like
  :func:`zlib.crc32`.
- :mod:`archivey_codecs.lzw`: Unix ``compress`` (``.Z``), a decompressor like
  :class:`lzma.LZMADecompressor`.
- :mod:`archivey_codecs.lzx`: LZX as Microsoft cabinets store it, a decompressor like
  :class:`lzma.LZMADecompressor`.
- :mod:`archivey_codecs.lzo1x`: one-shot LZO1X blocks of a known output size.
- :mod:`archivey_codecs.zipcrypto`: traditional PKWARE ZIP encryption.
- :mod:`archivey_codecs.bcj2`: 7-Zip's four-stream BCJ2 x86 filter.
- :mod:`archivey_codecs.filters`: the ARM64 and RISC-V branch-conversion filters.

Every error is a :class:`CodecError`, a :class:`ValueError`. :data:`KERNELS` gives
each kernel's revision, raised whenever its output, errors or saved state change.
"""

from types import MappingProxyType

from archivey_codecs import _codecs, bcj2, filters, lzo1x, lzw, lzx, zipcrypto
from archivey_codecs._codecs import (
    CodecError,
    CorruptDataError,
    Crc16Arc,
    TruncatedDataError,
    UnsupportedDataError,
    crc16_arc,
)

# Read-only: archivey decides from this table whether to use a kernel.
KERNELS = MappingProxyType(dict(_codecs.KERNELS))

__all__ = [
    "KERNELS",
    "CodecError",
    "CorruptDataError",
    "Crc16Arc",
    "TruncatedDataError",
    "UnsupportedDataError",
    "bcj2",
    "crc16_arc",
    "filters",
    "lzo1x",
    "lzw",
    "lzx",
    "zipcrypto",
]
