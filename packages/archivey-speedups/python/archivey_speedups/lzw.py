"""Unix ``compress`` (``.Z``): LZW with the :class:`lzma.LZMADecompressor` interface,
plus ``flush()``, since the format has no end marker."""

from archivey_speedups._speedups import LzwDecompressor as Decompressor

__all__ = ["Decompressor"]
