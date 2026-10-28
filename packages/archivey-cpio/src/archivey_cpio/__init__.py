"""CPIO for archivey, as a format plugin read in one forward pass.

Register it once, then open CPIO archives like any other, from a pipe too::

    from archivey.plugins import register_format
    from archivey_cpio import CpioPlugin

    register_format(CpioPlugin)
"""

from __future__ import annotations

import struct

from archivey import ArchiveFormat, PluginContainer, StreamFormat
from archivey.plugins import Magic, PluginContext, SequentialFormatPlugin
from archivey_cpio.reader import CpioReader, Sum32, Variant

__all__ = ["CPIO", "CpioContainer", "CpioPlugin", "CpioReader", "Sum32", "Variant"]


class CpioContainer(PluginContainer):
    CPIO = "cpio"


CPIO = ArchiveFormat(CpioContainer.CPIO, StreamFormat.UNCOMPRESSED)


def _binary_probe(prefix: bytes) -> bool:
    """A binary CPIO header: the two-byte magic alone is too weak a signature, so the
    header must also hold a name of the size it declares, ending in a NUL."""
    if len(prefix) < 26:
        return False
    for order, magic in (("<", b"\xc7\x71"), (">", b"\x71\xc7")):
        if prefix[:2] != magic:
            continue
        name_size = struct.unpack_from(f"{order}H", prefix, 20)[0]
        end = 26 + name_size
        return 1 < name_size and end <= len(prefix) and prefix[end - 1] == 0
    return False


class CpioPlugin(SequentialFormatPlugin):
    """CPIO archives in the binary, odc, newc and crc variants: ``.cpio``."""

    format = CPIO
    extensions = (".cpio",)
    magic = (
        Magic(0, b"070707"),
        Magic(0, b"070701"),
        Magic(0, b"070702"),
        # afio's large header, on an archive whose first member needs it.
        Magic(0, b"070727"),
    )
    probe = staticmethod(_binary_probe)
    uses_encoding = True

    def open_sequential(self, context: PluginContext) -> CpioReader:
        return CpioReader(context)
