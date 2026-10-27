"""SquashFS for archivey, as a format plugin.

Register it once, then open SquashFS images like any other archive::

    from archivey.plugins import register_format
    from archivey_squashfs import SquashfsPlugin

    register_format(SquashfsPlugin)
"""

from __future__ import annotations

from archivey import ArchiveFormat, PluginContainer, StreamFormat
from archivey.plugins import FormatPlugin, Magic, PluginContext, PluginSource
from archivey_squashfs.reader import MAGIC, SquashfsReader

__all__ = ["SQUASHFS", "SquashfsContainer", "SquashfsPlugin", "SquashfsReader"]


class SquashfsContainer(PluginContainer):
    SQUASHFS = "squashfs"


SQUASHFS = ArchiveFormat(SquashfsContainer.SQUASHFS, StreamFormat.UNCOMPRESSED)


class SquashfsPlugin(FormatPlugin):
    """SquashFS 4.0 images: ``.squashfs``, ``.sqfs`` and snap packages."""

    format = SQUASHFS
    extensions = (".squashfs", ".sqfs", ".snap")
    magic = (Magic(0, MAGIC),)
    uses_encoding = True

    def open(self, source: PluginSource, context: PluginContext) -> SquashfsReader:
        return SquashfsReader(source, context)
