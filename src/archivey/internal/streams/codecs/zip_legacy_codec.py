"""Shrink (ZIP method 1) and Implode (ZIP method 6), the DOS-era ZIP methods."""

from __future__ import annotations

from typing import BinaryIO

from archivey.exceptions import ArchiveyError, UnsupportedFeatureError
from archivey.internal.config import StreamConfig
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.zip_legacy_decoder import (
    ImplodeDecoder,
    ShrinkDecoder,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream


class ShrinkCodec(StreamCodec):
    """Shrink: container-only (no stream format), pure Python, forward-only.

    ``params.unpack_size`` is where the data ends; without it the data ends with the
    input, which a source that runs on past it (``params.input_runs_on``) cannot give.
    """

    codec = Codec.SHRINK

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        size = params.unpack_size
        if size is None and params.input_runs_on:
            raise UnsupportedFeatureError(
                "Shrink data has no end marker: it cannot be read without its size "
                "from a source that goes on after it"
            )
        return DecompressorStream(
            source,
            make_decoder=lambda _p, _i: ShrinkDecoder(size),
            codec_name="shrink",
            collector=config.collector,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        # The decoder raises CorruptionError / TruncatedError itself.
        return None


class ImplodeCodec(StreamCodec):
    """Implode: container-only, pure Python, forward-only.

    Needs ``params.unpack_size`` (the data has no end marker), and the two settings ZIP
    keeps in general-purpose bits 1 and 2: ``implode_large_window`` (an 8 KiB window,
    else 4 KiB) and ``implode_literal_tree`` (three trees, else two).
    """

    codec = Codec.IMPLODE

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        size = params.unpack_size
        if size is None:
            raise UnsupportedFeatureError(
                "Implode data has no end marker: it cannot be read without its size"
            )
        large = params.implode_large_window
        literal = params.implode_literal_tree
        return DecompressorStream(
            source,
            make_decoder=lambda _p, _i: ImplodeDecoder(
                size, large_window=large, literal_tree=literal
            ),
            codec_name="implode",
            collector=config.collector,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        return None
