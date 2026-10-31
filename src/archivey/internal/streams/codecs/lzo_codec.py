"""LZO: the ``.lzo`` file format ``lzop`` writes, and raw LZO1X as a member method."""

from __future__ import annotations

import stat
from collections.abc import Callable
from typing import TYPE_CHECKING, BinaryIO

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.config import StreamConfig, check_decoder_memory
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    MetadataContext,
    StreamCodec,
)
from archivey.internal.streams.codecs.lzo_decoder import (
    LZOP_BLOCK_SIZE,
    LZOP_MAGIC,
    Lzo1xDecoder,
    LzopDecompressor,
    lzo1x_decompressor,
    parse_lzop_header,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream
from archivey.internal.timestamps import unix_to_datetime
from archivey.types import ArchiveFormat, ArchiveMember, MagicSignature, StreamFormat

if TYPE_CHECKING:
    from archivey.formats import Decompressor

# lzop's F_CS_MASK and F_CS_LATIN1.
_F_CS_MASK = 0x00F00000
_F_CS_LATIN1 = 0x00100000
# The longest header lzop writes: the fixed fields, a 255-byte name and the checksum.
_HEADER_PEEK = 512


def _block_check(config: StreamConfig) -> Callable[[int], None]:
    """What refuses an lzop block's declared size before it is decoded whole, and the
    header extra field's before it is read.

    A read checks it against ``DecoderLimits.max_decoder_memory``, as other codecs
    check a declared dictionary or window. A detection probe reads a few hundred bytes
    (``probe_read_bound``) and decodes uncapped (``codecs/base.py``), so it allows the
    block size lzop writes, 256 KiB, and a block over that is "can't tell".
    """
    bound = config.probe_read_bound
    if bound is not None:
        ceiling = max(bound, LZOP_BLOCK_SIZE)

        def check_probe(size: int) -> None:
            if size > ceiling:
                raise ResourceLimitError(
                    f"an lzop block or extra field declares {size} bytes, over the {ceiling} a "
                    "detection probe decodes"
                )

        return check_probe
    limits, usage = config.decoder_limits, config.usage

    def check(size: int) -> None:
        check_decoder_memory(
            size, limits=limits, what="an lzop block or extra field", usage=usage
        )

    return check


class LzopCodec(StreamCodec):
    """The ``.lzo`` file format: one lzop file, or several back to back.

    A one-stream decompressor (:class:`LzopDecompressor`) over :class:`FramedDecoder`,
    the shape of bzip2, zstd and LZ4 and of a codec added with ``register_codec``.
    """

    codec = Codec.LZOP
    stream_format = StreamFormat.LZOP
    magic = (MagicSignature(0, LZOP_MAGIC, ArchiveFormat.LZOP),)

    # The default stream_start reads a further file after the first's end block, as
    # ``lzop -d`` does.
    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        return LzopDecompressor(
            lzo1x_decompressor(config.excluded_libraries, config.natives),
            _block_check(config),
        )

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        # The decompressor raises CorruptionError / UnsupportedFeatureError itself.
        return self._eof_truncation(exc, "lzop")

    @override
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
            # lzop's flags name the name's character set (F_CS_MASK). lzop itself
            # never sets them, so the name is in whatever encoding the system that
            # wrote it used: UTF-8 is read as UTF-8, and other bytes are kept as
            # surrogates. A file that says Latin-1 is read as Latin-1.
            encoding = (
                "latin-1" if header.flags & _F_CS_MASK == _F_CS_LATIN1 else "utf-8"
            )
            member.extra["lzop.original_filename"] = header.name.decode(
                encoding, "surrogateescape"
            )
        # 0 is what lzop writes for standard input. lzop 0x0940 and later store 64 bits.
        if header.mtime > 0:
            modified = unix_to_datetime(header.mtime)
            if modified is not None:
                member.modified = modified
        if header.mode and stat.S_ISREG(header.mode):
            member.mode = stat.S_IMODE(header.mode)


class Lzo1xCodec(StreamCodec):
    """Raw LZO1X with no header, as SquashFS stores a block. Container-only.

    Needs ``params.unpack_size``: LZO1X does not store its decoded length, and the
    data may decode to at most that many bytes. A SquashFS block passes its block
    size, which a file's last block decodes to less than.
    """

    codec = Codec.LZO

    @override
    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        size = params.unpack_size
        if size is None:
            raise UnsupportedFeatureError(
                "raw LZO1X data cannot be read without its decoded size"
            )
        check_decoder_memory(
            size,
            limits=config.decoder_limits,
            what="a raw LZO1X block's size",
            usage=config.usage,
        )
        decode_block = lzo1x_decompressor(config.excluded_libraries, config.natives)
        return DecompressorStream(
            source,
            make_decoder=lambda _p, _i: Lzo1xDecoder(decode_block, size),
            codec_name="lzo",
            collector=config.collector,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        return None
