"""SquashFS for archivey, as a format plugin.

Register it once, then open SquashFS images like any other archive::

    from archivey.formats import register_format
    from archivey_squashfs import SquashfsHandler

    register_format(SquashfsHandler)
"""

from __future__ import annotations

from archivey import ArchiveFormat, PluginContainer, StreamFormat
from archivey.formats import FormatHandler, Magic, ReaderContext, ReaderSource
from archivey_squashfs.reader import MAGIC, SquashfsReader

__all__ = ["SQUASHFS", "SquashfsContainer", "SquashfsHandler", "SquashfsReader"]


class SquashfsContainer(PluginContainer):
    SQUASHFS = "squashfs"


SQUASHFS = ArchiveFormat(SquashfsContainer.SQUASHFS, StreamFormat.UNCOMPRESSED)


class SquashfsHandler(FormatHandler):
    """SquashFS 4.0 images: ``.squashfs``, ``.sqfs`` and snap packages."""

    format = SQUASHFS
    extensions = (".squashfs", ".sqfs", ".snap")
    magic = (Magic(0, MAGIC),)
    uses_encoding = True

    def open(self, source: ReaderSource, context: ReaderContext) -> SquashfsReader:
        return SquashfsReader(source, context)
