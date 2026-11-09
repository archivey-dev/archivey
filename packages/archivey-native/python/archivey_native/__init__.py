"""Optional Rust kernels for archivey (prototype).

archivey imports this package only through ``archivey.internal.native``, which checks
:data:`ABI_VERSION` and falls back to the pure-Python decoders when the package is
missing, too old or too new. Nothing here is public API.
"""

from archivey_native._native import (
    ABI_VERSION,
    CorruptData,
    LzwState,
    LzxDecoder,
    TruncatedData,
    UnsupportedData,
    ZipCryptoKeys,
    arm64_decode,
    lzo1x_decompress,
    riscv_decode,
)

__all__ = [
    "ABI_VERSION",
    "CorruptData",
    "LzwState",
    "LzxDecoder",
    "TruncatedData",
    "UnsupportedData",
    "ZipCryptoKeys",
    "arm64_decode",
    "lzo1x_decompress",
    "riscv_decode",
]
