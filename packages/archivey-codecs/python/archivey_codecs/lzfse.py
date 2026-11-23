"""LZFSE streams, decoded whole to a size the container records (DMG runs, HFS+
compressed files)."""

from archivey_codecs._codecs import lzfse_decompress as decompress

__all__ = ["decompress"]
