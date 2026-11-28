"""LZX as Microsoft cabinets store it, with the :class:`lzma.LZMADecompressor`
interface, plus ``flush()`` for the end of the input and the cabinet folder's output
size, which sets where the last frame ends."""

from archivey_speedups._speedups import LzxDecompressor as Decompressor

__all__ = ["Decompressor"]
