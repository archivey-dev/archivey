"""Unix ar archives for archivey, as a format plugin read in one forward pass.

Register it once, then open ar archives (static libraries, ``.deb`` packages' outer
layer) like any other, from a pipe too::

    from archivey.formats import register_format
    from archivey_ar import ArHandler

    register_format(ArHandler)
"""

from __future__ import annotations

from archivey import ArchiveFormat, PluginContainer, StreamFormat
from archivey.formats import Magic, ReaderContext, SequentialFormatHandler
from archivey_ar.reader import ArReader

__all__ = ["AR", "ArContainer", "ArHandler", "ArReader"]


class ArContainer(PluginContainer):
    AR = "ar"


AR = ArchiveFormat(ArContainer.AR, StreamFormat.UNCOMPRESSED)


class ArHandler(SequentialFormatHandler):
    """ar archives in the GNU (System V) and BSD dialects: ``.a``, ``.ar``, ``.lib``."""

    format = AR
    extensions = (".a", ".ar", ".lib")
    # A thin archive is claimed too, so that opening one says why it cannot be read.
    magic = (Magic(0, b"!<arch>\n"), Magic(0, b"!<thin>\n"))
    uses_encoding = True

    def open_sequential(self, context: ReaderContext) -> ArReader:
        return ArReader(context)
