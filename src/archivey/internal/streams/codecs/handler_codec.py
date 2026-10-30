"""A built-in codec written as a :class:`~archivey.formats.CodecHandler`.

A built-in handler uses the public hooks a plugin codec has (``magic``,
``decompressor(call)``, ``translate_exception``) and adds the ones only archivey's own
codecs have for now: process isolation, a seek index over further streams, an
accelerator that decodes another way, a config-dependent translator. Each of those is
a ``_``-prefixed method here with a default that does nothing, so a built-in codec
overrides only what it uses. :func:`builtin_codec` makes the registry entry.
"""

from __future__ import annotations

import functools
from typing import BinaryIO, ClassVar

from archivey.exceptions import ArchiveyError
from archivey.formats import CodecCall, CodecHandler, Decompressor
from archivey.internal.config import StreamConfig
from archivey.internal.excluded_libraries import NO_EXCLUSIONS
from archivey.internal.streams.archive_stream import (
    ExceptionTranslator,
    RewindWarning,
)
from archivey.internal.streams.codecs.base import (
    CodecId,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import (
    FramedDecompressorStream,
    StreamIndex,
    StreamStart,
    stream_magic,
)
from archivey.types import (
    MagicSignature,
    MissingComponent,
    OptionalLibrary,
)


def _never(data: bytes) -> bool:
    """The :data:`StreamStart` of a container coder that is one stream."""
    del data
    return False


def call_for(params: CodecParams, config: StreamConfig) -> CodecCall:
    """The :class:`CodecCall` for one open with ``params`` and ``config``."""
    return CodecCall(
        size=params.unpack_size,
        properties=params.properties,
        limits=config.decoder_limits,
        probe_bound=config.probe_read_bound,
    )


class BuiltinCodecHandler(CodecHandler):
    """A built-in codec: the public :class:`CodecHandler` hooks, and the private ones
    below. Never registered with ``register_codec``; :func:`builtin_codec` adds it."""

    codec: ClassVar[CodecId]
    # The full ``MagicSignature`` rows, which name the format they detect.
    signatures: ClassVar[tuple[MagicSignature, ...]] = ()
    requirement: ClassVar[MissingComponent | None] = None
    # Install advice added to the error for a missing ``requirement``.
    missing_note: ClassVar[str] = ""

    def _decompressor(self, call: CodecCall, config: StreamConfig) -> Decompressor:
        """The decompressor for one stream, under ``config``'s process isolation.
        Default: :meth:`decompressor`, in this process."""
        del config
        return self.decompressor(call)

    def _stream_start(self, params: CodecParams) -> StreamStart:
        """How a further stream starts. Default: one of ``signatures`` at offset 0, or
        none for a container coder that is one stream."""
        starts = [m.magic for m in self.signatures if m.offset == 0]
        if params.single_stream or not self.concatenated or not starts:
            return _never
        return stream_magic(*(tuple(bytes([b]) for b in data) for data in starts))

    def _stream_index(self, config: StreamConfig) -> StreamIndex | None:
        """Further streams as seek points, when ``config`` asks for seeking. Default:
        none."""
        del config
        return None

    def _open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO | None:
        """Decode another way than :meth:`_decompressor` (an accelerator), or ``None``
        to decode with it. Default: ``None``."""
        del source, params, config
        return None

    def _check_accelerator(self, source: CodecSource, config: StreamConfig) -> None:
        """:meth:`StreamCodec.check_accelerator`. Default: no accelerator."""
        del source, config

    def _translator(self, config: StreamConfig) -> ExceptionTranslator:
        """The translator for the decode ``config`` chooses, which maps an
        ``EOFError`` itself. Default: :meth:`translate_exception`, then an
        ``EOFError`` as truncation."""
        del config
        return self.translate_exception

    def _rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        """:meth:`StreamCodec.rewind_warning`. Default: the codec's name."""
        del config
        return RewindWarning(self.codec.value, suggest_install=False)

    def _magic_behind_prefix(self, prefix: bytes) -> bool:
        """:meth:`StreamCodec.magic_behind_prefix`. Default: no prefix."""
        del prefix
        return False

    def _backend_present(self) -> bool:
        """Whether the decoder's optional package imports. Default: it has none."""
        return True

    def _excluded_by(self, excluded: frozenset[OptionalLibrary]) -> bool:
        """Whether ``excluded`` turns the decoder's package off."""
        return self.requirement is not None and self.requirement.name in excluded

    def _requirement_under(
        self, excluded: frozenset[OptionalLibrary]
    ) -> MissingComponent | None:
        """:meth:`StreamCodec.requirement_under`. ``None`` means the default."""
        del excluded
        return None


class BuiltinHandlerCodec(StreamCodec):
    """The registry entry for a :class:`BuiltinCodecHandler`."""

    handler: BuiltinCodecHandler

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        handler = self.handler
        excluded = config.excluded_libraries
        if not self.available(excluded):
            raise self._missing(
                f"{self.codec.value} streams",
                note=handler.missing_note,
                excluded=excluded,
            )
        stream = handler._open(source, params, config)
        if stream is not None:
            return stream
        call = call_for(params, config)
        return FramedDecompressorStream(
            source,
            functools.partial(handler._decompressor, call, config),
            codec_name=self.codec.value,
            magic=handler._stream_start(params),
            index=handler._stream_index(config),
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def check_accelerator(self, source: CodecSource, config: StreamConfig) -> None:
        self.handler._check_accelerator(source, config)

    def translate(self, exc: Exception) -> ArchiveyError | None:
        translated = self.handler.translate_exception(exc)
        if translated is not None:
            return translated
        return self._eof_truncation(exc, self.codec.value)

    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        if type(self.handler)._translator is BuiltinCodecHandler._translator:
            return self.translate
        # A handler's own translator decides everything, an ``EOFError`` too: one
        # from the caller's source must reach the caller unchanged.
        return self.handler._translator(config)

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return self.handler._rewind_warning(config)

    def magic_behind_prefix(self, prefix: bytes) -> bool:
        return self.handler._magic_behind_prefix(prefix)

    def _backend_present(self) -> bool:
        return self.handler._backend_present()

    def excluded_by(self, excluded: frozenset[OptionalLibrary]) -> bool:
        return self.handler._excluded_by(excluded)

    def requirement_under(
        self, excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS
    ) -> MissingComponent | None:
        own = self.handler._requirement_under(excluded)
        return own if own is not None else super().requirement_under(excluded)


def builtin_codec(handler: type[BuiltinCodecHandler]) -> type[StreamCodec]:
    """The registry entry's class for ``handler``."""
    return type(
        f"{handler.__name__}Codec",
        (BuiltinHandlerCodec,),
        {
            "handler": handler(),
            "codec": handler.codec,
            "stream_format": handler.stream_format,
            "magic": handler.signatures,
            "requirement": handler.requirement,
            "extension_aliases": tuple(handler.extension_aliases),
            "checks_content": bool(handler.checks_content),
        },
    )


__all__ = ["BuiltinCodecHandler", "BuiltinHandlerCodec", "builtin_codec", "call_for"]
