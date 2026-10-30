"""LZO: the ``.lzo`` file format ``lzop`` writes, and raw LZO1X as a member method."""

from __future__ import annotations

import stat
from typing import BinaryIO

from archivey.exceptions import ArchiveyError, CorruptionError, UnsupportedFeatureError
from archivey.internal.config import StreamConfig
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    MetadataContext,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import (
    FramedDecompressorStream,
    stream_magic,
)
from archivey.internal.streams.codecs.isolated import natives_for
from archivey.internal.streams.codecs.lzo_decoder import (
    LZOP_MAGIC,
    Lzo1xDecoder,
    LzopDecompressor,
    lzo1x_decompressor,
    parse_lzop_header,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream
from archivey.internal.timestamps import unix32_to_datetime
from archivey.types import ArchiveFormat, ArchiveMember, MagicSignature, StreamFormat

# The longest header lzop writes: the fixed fields, a 255-byte name and the checksum.
_HEADER_PEEK = 512


class LzopCodec(StreamCodec):
    """The ``.lzo`` file format: one lzop file, or several back to back.

    A one-stream decompressor (:class:`LzopDecompressor`) over :class:`FramedDecoder`,
    the shape of bzip2, zstd and LZ4 and of a codec added with ``register_codec``.
    """

    codec = Codec.LZOP
    stream_format = StreamFormat.LZOP
    magic = (MagicSignature(0, LZOP_MAGIC, ArchiveFormat.LZOP),)

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        decode_block = lzo1x_decompressor(
            config.excluded_libraries, natives_for(config.process_isolation)
        )
        return FramedDecompressorStream(
            source,
            lambda: LzopDecompressor(decode_block),
            codec_name="lzop",
            # ``lzop -d`` reads a further file after the first's end block.
            magic=stream_magic(tuple(bytes([b]) for b in LZOP_MAGIC)),
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        # The decompressor raises CorruptionError / UnsupportedFeatureError itself.
        return self._eof_truncation(exc, "lzop")

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """The stored name, mtime and mode from the first file's header.

        A damaged header is left to the read, which raises for it.
        """
        try:
            header = parse_lzop_header(ctx.peek_header(_HEADER_PEEK))
        except (CorruptionError, UnsupportedFeatureError):
            return
        if header is None:
            return
        if header.name:
            member.raw_name = header.name
            member.extra["lzop.original_filename"] = header.name.decode(
                "utf-8", "surrogateescape"
            )
        if 0 < header.mtime < 2**32:
            member.modified = unix32_to_datetime(header.mtime)
        if header.mode and stat.S_ISREG(header.mode):
            member.mode = stat.S_IMODE(header.mode)


class Lzo1xCodec(StreamCodec):
    """Raw LZO1X with no header, as SquashFS stores a block. Container-only.

    Needs ``params.unpack_size``: LZO1X does not store its decoded length, and the
    data must decode to exactly that many bytes.
    """

    codec = Codec.LZO

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        size = params.unpack_size
        if size is None:
            raise UnsupportedFeatureError(
                "raw LZO1X data cannot be read without its decoded size"
            )
        decode_block = lzo1x_decompressor(
            config.excluded_libraries, natives_for(config.process_isolation)
        )
        return DecompressorStream(
            source,
            make_decoder=lambda _p, _i: Lzo1xDecoder(decode_block, size),
            codec_name="lzo",
            collector=config.collector,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        return None
