"""Shrink (ZIP method 1) and Implode (ZIP method 6), the DOS-era ZIP methods."""

from __future__ import annotations

from archivey.exceptions import UnsupportedFeatureError
from archivey.formats import CodecCall, Decompressor
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import Codec
from archivey.internal.streams.codecs.handler_codec import (
    BuiltinCodecHandler,
    builtin_codec,
    params_of,
)
from archivey.internal.streams.codecs.zip_legacy_decoder import (
    ImplodeDecompressor,
    ShrinkDecompressor,
)


class ShrinkHandler(BuiltinCodecHandler):
    """Shrink: container-only (no stream format), pure Python, forward-only.

    ``call.size`` is where the data ends; without it the data ends with the input,
    which a source that runs on past it (``params.input_runs_on``) cannot give.
    """

    codec = Codec.SHRINK

    @override
    def decompressor(self, call: CodecCall) -> Decompressor:
        if call.size is None and params_of(call).input_runs_on:
            raise UnsupportedFeatureError(
                "Shrink data has no end marker: it cannot be read without its size "
                "from a source that goes on after it"
            )
        return ShrinkDecompressor(call.size)


class ImplodeHandler(BuiltinCodecHandler):
    """Implode: container-only, pure Python, forward-only.

    Needs ``call.size`` (the data has no end marker), and the two settings ZIP keeps in
    general-purpose bits 1 and 2: ``implode_large_window`` (an 8 KiB window, else
    4 KiB) and ``implode_literal_tree`` (three trees, else two).
    """

    codec = Codec.IMPLODE

    @override
    def decompressor(self, call: CodecCall) -> Decompressor:
        if call.size is None:
            raise UnsupportedFeatureError(
                "Implode data has no end marker: it cannot be read without its size"
            )
        params = params_of(call)
        return ImplodeDecompressor(
            call.size,
            large_window=params.implode_large_window,
            literal_tree=params.implode_literal_tree,
        )


ShrinkCodec = builtin_codec(ShrinkHandler)
ImplodeCodec = builtin_codec(ImplodeHandler)
