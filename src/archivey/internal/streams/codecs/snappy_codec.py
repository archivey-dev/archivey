"""Snappy: the ``.sz`` files of Snappy's framing format.

The chunks are parsed and checked in Python (``snappy_framed``); a raw block is decoded
by ``compress-utils`` or ``cramjam`` when installed, else in Python, and the CRC-32C by
``google-crc32c`` or ``crc32c``, else in Python. None of them is required. Under
``ProcessIsolation.NATIVE_DECODERS`` the packages run in a child process.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.internal.config import StreamConfig
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import Codec, CodecParams, StreamCodec
from archivey.internal.streams.codecs.snappy_framed import (
    STREAM_IDENTIFIER,
    SnappyFormatError,
    SnappyFramedDecompressor,
    chunk_decoder,
)
from archivey.types import ArchiveFormat, MagicSignature, StreamFormat

if TYPE_CHECKING:
    from archivey.formats import Decompressor


class SnappyCodec(StreamCodec):
    """Snappy framed streams: one :class:`SnappyFramedDecompressor` per file."""

    codec = Codec.SNAPPY
    stream_format = StreamFormat.SNAPPY
    magic = (MagicSignature(0, STREAM_IDENTIFIER, ArchiveFormat.SNAPPY),)
    # Every chunk carries a CRC-32C of its decoded data, checked before it is returned.
    checks_content = True
    # A repeated stream identifier is a chunk of the same stream, so the decompressor
    # reads concatenated streams itself, to the end of the input.
    concatenated = False

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        # A chunk is at most 64 KiB decoded and about 76 KiB compressed, whatever the
        # input declares, so there is no declared size to check against the limits.
        del params
        excluded, natives, usage = (
            config.excluded_libraries,
            config.natives,
            config.usage,
        )
        return SnappyFramedDecompressor(chunk_decoder(excluded, natives, usage))

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, SnappyFormatError):
            return CorruptionError(f"Error reading Snappy stream: {exc}")
        return None
