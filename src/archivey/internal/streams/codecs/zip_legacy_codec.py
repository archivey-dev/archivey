"""Shrink (ZIP method 1) and Implode (ZIP method 6), the DOS-era ZIP methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from archivey.exceptions import UnsupportedFeatureError
from archivey.internal.config import StreamConfig
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import Codec, CodecParams, StreamCodec
from archivey.internal.streams.codecs.zip_legacy_decoder import (
    ImplodeDecompressor,
    ShrinkDecompressor,
)

if TYPE_CHECKING:
    from archivey.formats import Decompressor


class ShrinkCodec(StreamCodec):
    """Shrink: container-only (no stream format), pure Python, forward-only.

    ``params.unpack_size`` is where the data ends; without it the data ends with the
    input, which a source that runs on past it (``params.input_runs_on``) cannot give.
    """

    codec = Codec.SHRINK

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        if params.unpack_size is None and params.input_runs_on:
            raise UnsupportedFeatureError(
                "Shrink data has no end marker: it cannot be read without its size "
                "from a source that goes on after it"
            )
        return ShrinkDecompressor(params.unpack_size)


class ImplodeCodec(StreamCodec):
    """Implode: container-only, pure Python, forward-only.

    Needs ``params.unpack_size`` (the data has no end marker), and the two settings ZIP
    keeps in general-purpose bits 1 and 2: ``implode_large_window`` (an 8 KiB window,
    else 4 KiB) and ``implode_literal_tree`` (three trees, else two).
    """

    codec = Codec.IMPLODE

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        if params.unpack_size is None:
            raise UnsupportedFeatureError(
                "Implode data has no end marker: it cannot be read without its size"
            )
        return ImplodeDecompressor(
            params.unpack_size,
            large_window=params.implode_large_window,
            literal_tree=params.implode_literal_tree,
        )
