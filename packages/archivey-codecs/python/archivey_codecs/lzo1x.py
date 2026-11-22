"""LZO1X blocks, decoded whole to a size the container records (lzop, SquashFS)."""

from archivey_codecs._codecs import lzo1x_decompress as decompress

__all__ = ["decompress"]
