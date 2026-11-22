"""7-Zip's BCJ2 x86 filter: four input streams decode to one output of a declared
size, read with ``read(max_length)``."""

from archivey_codecs._codecs import Bcj2Decompressor as Decompressor

__all__ = ["Decompressor"]
