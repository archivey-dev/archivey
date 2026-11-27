"""Native (Rust) speedups for archivey: decoders with standard-library-shaped interfaces.

- :func:`crc16_arc`: CRC-16/ARC, like :func:`zlib.crc32`.
- :mod:`archivey_speedups.lzw`: Unix ``compress`` (``.Z``), a decompressor like
  :class:`lzma.LZMADecompressor`.
- :mod:`archivey_speedups.lzx`: LZX as Microsoft cabinets store it, a decompressor like
  :class:`lzma.LZMADecompressor`.
- :mod:`archivey_speedups.lzo1x`: one-shot LZO1X blocks of a known output size.
- :mod:`archivey_speedups.lzfse` and :mod:`archivey_speedups.lzvn`: Apple's LZFSE streams
  and raw LZVN (DMG images, HFS+ compressed files), one-shot to a known output size.
- :mod:`archivey_speedups.zipcrypto`: traditional PKWARE ZIP encryption.
- :mod:`archivey_speedups.bcj2`: 7-Zip's four-stream BCJ2 x86 filter.
- :mod:`archivey_speedups.filters`: the ARM64 and RISC-V branch-conversion filters.

Every error is a :class:`CodecError`, a :class:`ValueError`. :data:`KERNELS` gives
each kernel's revision, raised whenever its output, errors or saved state change.
"""

from types import MappingProxyType

from archivey_speedups import (
    _speedups,
    bcj2,
    filters,
    lzfse,
    lzo1x,
    lzvn,
    lzw,
    lzx,
    zipcrypto,
)
from archivey_speedups._speedups import (
    CodecError,
    CorruptDataError,
    TruncatedDataError,
    UnsupportedDataError,
    crc16_arc,
)

# Read-only: archivey decides from this table whether to use a kernel.
KERNELS = MappingProxyType(dict(_speedups.KERNELS))

__all__ = [
    "KERNELS",
    "CodecError",
    "CorruptDataError",
    "TruncatedDataError",
    "UnsupportedDataError",
    "bcj2",
    "crc16_arc",
    "filters",
    "lzfse",
    "lzo1x",
    "lzvn",
    "lzw",
    "lzx",
    "zipcrypto",
]
