"""A built-in codec written as a :class:`~archivey.formats.CodecHandler`.

A built-in codec is a handler like a plugin's: ``stream_format``, ``magic``,
``decompressor(call)`` and ``translate_exception`` mean the same. Two things differ.

- Its ``call`` is a :class:`BuiltinCall`, which also carries the stream config and the
  container's parameters. A built-in reads its private settings there: process
  isolation, accelerators, whether the caller asked for seeking.
- It may override the ``_``-prefixed hooks of :class:`BuiltinCodecHandler`, for what a
  plugin codec cannot do yet: an accelerator, a seek index over further streams,
  detection past a structural prefix. Each defaults to doing nothing.

:func:`builtin_codec` makes the registry entry.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, BinaryIO, ClassVar

from archivey.config import ProcessIsolation
from archivey.exceptions import ArchiveyError
from archivey.formats import CodecCall, CodecHandler
from archivey.internal.config import DEFAULT_STREAM_CONFIG, StreamConfig
from archivey.internal.excluded_libraries import NO_EXCLUSIONS, as_excluded
from archivey.internal.streams.archive_stream import (
    ExceptionTranslator,
    RewindWarning,
)
from archivey.internal.streams.codecs.base import (
    CodecId,
    CodecParams,
    CodecSource,
    MetadataContext,
    ProbeChargeDecode,
    ProbeReadAt,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import (
    FramedDecompressorStream,
    StreamIndex,
    StreamStart,
    stream_magic,
)
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    ContainerFormat,
    MagicSignature,
    MissingComponent,
    OptionalLibrary,
)

_DEFAULT_PARAMS = CodecParams()


@dataclass(frozen=True)
class BuiltinCall(CodecCall):
    """The :class:`CodecCall` a built-in codec is given: the public fields, and what
    only archivey's own codecs read."""

    config: StreamConfig = DEFAULT_STREAM_CONFIG
    params: CodecParams = _DEFAULT_PARAMS


def builtin_call(params: CodecParams, config: StreamConfig) -> BuiltinCall:
    """The call for one open with ``params`` and ``config``."""
    return BuiltinCall(
        size=params.unpack_size,
        properties=params.properties,
        limits=config.decoder_limits,
        probe_bound=config.probe_read_bound,
        config=config,
        params=params,
    )


def config_of(call: CodecCall) -> StreamConfig:
    """The stream config of a built-in codec's ``call``."""
    assert isinstance(call, BuiltinCall), "a built-in codec is given a BuiltinCall"
    return call.config


def _never(data: bytes) -> bool:
    """The :data:`StreamStart` of a container coder that is one stream."""
    del data
    return False


class BuiltinCodecHandler(CodecHandler):
    """A built-in codec. Never registered with ``register_codec``;
    :func:`builtin_codec` adds it.

    The hooks that take a ``call`` run for each open. The ones that take a ``config``
    run before it (detection, the translator, the rewind warning), when there is no
    call yet.
    """

    codec: ClassVar[CodecId]
    # The name diagnostics and messages give the stream, when not ``codec.value``.
    codec_name: ClassVar[str | None] = None
    # The optional package the decoder needs, and its install advice; ``None`` for
    # the standard library. A codec with one overrides :meth:`_library`.
    requirement: ClassVar[MissingComponent | None] = None
    # More install advice for the error a missing ``requirement`` raises.
    missing_note: ClassVar[str] = ""

    def _library(self) -> OptionalLibrary | str | None:
        """The package the decoder uses, or ``None`` when it is absent. Only called
        when there is a ``requirement``."""
        raise NotImplementedError

    def _open(self, source: CodecSource, call: BuiltinCall) -> BinaryIO | None:
        """A stream that decodes another way than :meth:`decompressor` (an
        accelerator), or ``None`` to decode with it."""
        del source, call
        return None

    def _stream_start(self, call: BuiltinCall) -> StreamStart:
        """How a further stream starts: one of ``magic`` at offset 0, or nothing for a
        coder that is one stream. Override for a check stricter than ``magic``."""
        starts = [m.data for m in self.magic if m.offset == 0]
        if call.params.single_stream or not self.concatenated or not starts:
            return _never
        return stream_magic(*(tuple(bytes([b]) for b in data) for data in starts))

    def _stream_index(self, call: BuiltinCall) -> StreamIndex | None:
        """Further streams as seek points. Default: none."""
        del call
        return None

    def _check_accelerator(self, source: CodecSource, config: StreamConfig) -> None:
        """:meth:`StreamCodec.check_accelerator`. Default: no accelerator."""
        del source, config

    def _translator(self, config: StreamConfig) -> ExceptionTranslator:
        """The translator for the decode ``config`` chooses (an accelerator's, or one
        that needs the limits). Default: :meth:`translate_exception`."""
        del config
        return self.translate_exception

    def _rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        """:meth:`StreamCodec.rewind_warning`. Default: the codec's name."""
        del config
        return RewindWarning(self.codec.value, suggest_install=False)

    def _magic_behind_prefix(self, prefix: bytes) -> bool:
        """:meth:`StreamCodec.magic_behind_prefix`. Read only when overridden."""
        raise NotImplementedError

    def _content_probe(
        self,
        entry: StreamCodec,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """:meth:`StreamCodec.content_probe`, for a probe that decodes a sample
        (through ``entry``, the registry entry) or reads past the prefix. Read only
        when overridden."""
        raise NotImplementedError

    def _extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """:meth:`StreamCodec.extract_metadata`. Default: none."""
        del ctx, member


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
        call = builtin_call(params, config)
        stream = handler._open(source, call)
        if stream is not None:
            return stream
        return FramedDecompressorStream(
            source,
            lambda: handler.decompressor(call),
            codec_name=handler.codec_name or self.codec.value,
            magic=handler._stream_start(call),
            index=handler._stream_index(call),
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def check_accelerator(self, source: CodecSource, config: StreamConfig) -> None:
        self.handler._check_accelerator(source, config)

    def translate(self, exc: Exception) -> ArchiveyError | None:
        return self.handler.translate_exception(exc)

    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        return self.handler._translator(config)

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return self.handler._rewind_warning(config)

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        self.handler._extract_metadata(ctx, member)

    def _backend_present(self) -> bool:
        return self.requirement is None or self.handler._library() is not None

    def _excludable(self) -> OptionalLibrary | str | None:
        """The package ``exclude_libraries`` turns off: the one in use, which
        ``requirement`` (zstd's backport) may not name, or ``requirement``'s when none
        is installed. An excluded package that is absent is reported as excluded,
        not as one to install."""
        if self.requirement is None:
            return None
        return self.handler._library() or self.requirement.name

    def excluded_by(self, excluded: frozenset[OptionalLibrary]) -> bool:
        library = self._excludable()
        return library is not None and library in excluded

    def requirement_under(
        self, excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS
    ) -> MissingComponent | None:
        requirement = self.requirement
        if requirement is None or not self.excluded_by(excluded):
            return requirement
        library = self._excludable()
        assert library is not None
        return as_excluded(dataclasses.replace(requirement, name=library))


def builtin_codec(handler: type[BuiltinCodecHandler]) -> type[StreamCodec]:
    """The registry entry's class for ``handler``."""
    fmt = ArchiveFormat(ContainerFormat.RAW_STREAM, handler.stream_format)
    instance = handler()
    # Only what the handler overrides: the detector skips a codec whose
    # ``magic_behind_prefix`` or ``content_probe`` is the base's.
    hooks: dict[str, Any] = {}
    if handler._magic_behind_prefix is not BuiltinCodecHandler._magic_behind_prefix:
        hooks["magic_behind_prefix"] = lambda self, prefix: (
            self.handler._magic_behind_prefix(prefix)
        )
    if handler._content_probe is not BuiltinCodecHandler._content_probe:
        hooks["content_probe"] = lambda self, prefix, **kwargs: (
            self.handler._content_probe(self, prefix, **kwargs)
        )
    return type(
        f"{handler.__name__}Codec",
        (BuiltinHandlerCodec,),
        {
            **hooks,
            "handler": instance,
            "codec": handler.codec,
            "stream_format": handler.stream_format,
            "magic": tuple(
                MagicSignature(m.offset, m.data, fmt) for m in handler.magic
            ),
            "requirement": handler.requirement,
            "extension_aliases": tuple(handler.extension_aliases),
            "checks_content": bool(handler.checks_content),
        },
    )


__all__ = [
    "BuiltinCall",
    "BuiltinCodecHandler",
    "BuiltinHandlerCodec",
    "builtin_call",
    "builtin_codec",
    "config_of",
]
