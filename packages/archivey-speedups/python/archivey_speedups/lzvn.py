"""Raw LZVN, as HFS+ compressed files store it, decoded whole to a size the container
records."""

from archivey_speedups._speedups import lzvn_decompress as decompress

__all__ = ["decompress"]
