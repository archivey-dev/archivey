"""Unix ``compress`` (``.Z``, LZW)."""

from __future__ import annotations

from typing import BinaryIO

from archivey.exceptions import ArchiveyError
from archivey.internal.config import StreamConfig
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.unix_compress_decoder import (
    UnixCompressDecompressorStream,
)
from archivey.types import (
    ArchiveFormat,
    MagicSignature,
    StreamFormat,
)


class UnixCompressCodec(StreamCodec):
    codec = Codec.UNIX_COMPRESS
    stream_format = StreamFormat.UNIX_COMPRESS
    magic = (MagicSignature(0, b"\x1f\x9d", ArchiveFormat.Z),)

    @override
    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        # Native LZW over DecompressorStream: forward decode works on non-seekable
        # sources; CLEAR boundaries become SeekPoints when config.seekable is true.
        return UnixCompressDecompressorStream(
            source, collector=config.collector, seekable=config.seekable
        )

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        # Native LZW raises CorruptionError / UnsupportedFeatureError / TruncatedError
        # directly (like xz/lzip). No third-party exception remapping.
        return None
