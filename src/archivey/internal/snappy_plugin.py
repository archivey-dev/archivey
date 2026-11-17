"""Experimental Snappy framed (``.sz``) support, as a codec plugin a caller registers.

Nothing registers it by default::

    from archivey.formats import register_codec
    from archivey.internal.snappy_plugin import snappy_handler

    register_codec(snappy_handler())  # or "cramjam" / "compress-utils"

archivey then reads ``.sz`` files and ``.tar.sz`` through the ordinary plugin-codec
path. The framing, sizes and CRCs are checked by
:mod:`archivey.internal.streams.codecs.snappy_framed`; only the raw block decode comes
from the named backend. The backend runs in this process, with no decoder child.
"""

from __future__ import annotations

from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.formats import CodecCall, CodecHandler, Magic
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.snappy_framed import (
    AUTO_ORDER,
    STREAM_IDENTIFIER,
    SnappyFormatError,
    SnappyFramedDecompressor,
    crc32c_function,
    resolve_backend,
)
from archivey.types import PluginStream


class SnappyStream(PluginStream):
    SZ = "sz"


def snappy_handler(backend: str = "auto", crc: str = "auto") -> type[CodecHandler]:
    """A ``CodecHandler`` class for Snappy framed streams whose raw blocks ``backend``
    decodes: a key of ``BACKENDS``, or ``"auto"`` for the first installed one in
    ``AUTO_ORDER`` (chosen when this is called). ``crc`` picks the CRC-32C
    implementation
    (``"auto"``, ``"python"``, ``"google-crc32c"`` or ``"crc32c"``)."""
    chosen = resolve_backend(backend)
    auto = backend == "auto"

    class SnappyHandler(CodecHandler):
        stream_format = SnappyStream.SZ
        magic = (Magic(0, STREAM_IDENTIFIER),)
        # A repeated stream identifier is a chunk of the same stream, so the
        # decompressor reads concatenated streams itself, to the end of the input.
        concatenated = False
        checks_content = True
        requires = (chosen.module,)
        install_hint = (
            "pip install " + " or ".join(reversed(AUTO_ORDER))
            if auto
            else f"pip install {chosen.package}"
        )

        @override
        def decompressor(self, call: CodecCall) -> SnappyFramedDecompressor:
            # A chunk is at most 64 KiB decoded and about 76 KiB compressed, whatever
            # the input declares, so there is nothing in ``call.limits`` to check.
            del call
            return SnappyFramedDecompressor(chosen.load(), crc32c_function(crc))

        @override
        def translate_exception(self, exc: Exception) -> ArchiveyError | None:
            if isinstance(exc, SnappyFormatError):
                return CorruptionError(f"Error reading Snappy stream: {exc}")
            return None

    SnappyHandler.__name__ = SnappyHandler.__qualname__ = (
        f"SnappyHandler[{chosen.name}]"
    )
    return SnappyHandler
