"""A built-in codec written as a :class:`~archivey.formats.CodecHandler`.

A built-in codec is a handler like a plugin's: ``stream_format``, ``magic``,
``extension_aliases``, ``concatenated``, ``checks_content`` and ``decompressor(call)``
mean the same. These differ:

- Its ``call`` is a :class:`BuiltinCall`, which also carries the stream config and the
  container's parameters. A built-in reads its private settings there: process
  isolation, accelerators, whether the caller asked for seeking.
- It may override the ``_``-prefixed hooks of :class:`BuiltinCodecHandler`, for what a
  plugin codec cannot do yet: an accelerator, a seek index over further streams,
  detection past a structural prefix. Each defaults to doing nothing.
- Its dependency is ``requirement`` and ``missing_note``, and its probe is
  ``_content_probe``, not a plugin's ``requires``, ``install_hint`` and ``probe``:
  :func:`builtin_codec` refuses a handler that sets those.
- Its ``translate_exception`` maps an ``EOFError`` itself
  (``StreamCodec._eof_truncation``); the entry adds no fallback, as the plugin adapter
  does, because an accelerator's translator must leave an ``EOFError`` from the
  caller's own source alone.

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
    never_starts,
    offset0_start,
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


def params_of(call: CodecCall) -> CodecParams:
    """The container's parameters in a built-in codec's ``call``."""
    assert isinstance(call, BuiltinCall), "a built-in codec is given a BuiltinCall"
    return call.params


class BuiltinCodecHandler(CodecHandler):
    """A built-in codec. Never registered with ``register_codec``;
    :func:`builtin_codec` adds it.

    The hooks that take a ``call`` run for each open. The ones that take a ``config``
    run before it (detection, the translator, the rewind warning), when there is no
    call yet.
    """

    codec: ClassVar[CodecId]
    # The name diagnostics and messages give the stream (:attr:`stream_name`), when
    # not ``codec.value``.
    codec_name: ClassVar[str | None] = None
    # The optional package the decoder needs, and its install advice; ``None`` for
    # the standard library. A codec with one overrides :meth:`_library`.
    requirement: ClassVar[MissingComponent | None] = None
    # More install advice for the error a missing ``requirement`` raises.
    missing_note: ClassVar[str] = ""

    @property
    def stream_name(self) -> str:
        """The stream's name in messages and diagnostics."""
        return self.codec_name or self.codec.value

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
        if call.params.single_stream:
            return never_starts
        return offset0_start(self.magic, self.concatenated)

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
        return RewindWarning(self.stream_name, suggest_install=False)

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
                f"{handler.stream_name} streams",
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
            codec_name=handler.stream_name,
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


def _magic_behind_prefix(self: BuiltinHandlerCodec, prefix: bytes) -> bool:
    return self.handler._magic_behind_prefix(prefix)


def _content_probe(
    self: BuiltinHandlerCodec,
    prefix: bytes,
    *,
    source_length: int | None = None,
    read_at: ProbeReadAt | None = None,
    charge_decode: ProbeChargeDecode | None = None,
    isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
) -> bool:
    return self.handler._content_probe(
        self,
        prefix,
        source_length=source_length,
        read_at=read_at,
        charge_decode=charge_decode,
        isolation=isolation,
    )


def builtin_codec(handler: type[BuiltinCodecHandler]) -> type[StreamCodec]:
    """The registry entry's class for ``handler``, named like the module's alias for
    it (``Bzip2Handler`` gives ``Bzip2Codec``).

    A container-only codec (Shrink, Implode) leaves ``stream_format`` unset, and has no
    ``magic``.
    """
    for field in ("requires", "install_hint", "probe"):
        assert getattr(handler, field) == getattr(CodecHandler, field), (
            f"{handler.__name__}.{field} is a plugin's; a built-in uses "
            "requirement, missing_note and _content_probe"
        )
    stream_format = getattr(handler, "stream_format", None)
    magic: tuple[MagicSignature, ...] = ()
    if stream_format is not None:
        fmt = ArchiveFormat(ContainerFormat.RAW_STREAM, stream_format)
        magic = tuple(MagicSignature(m.offset, m.data, fmt) for m in handler.magic)
    else:
        assert not handler.magic, "a container-only codec has no magic"
    name = handler.__name__.removesuffix("Handler") + "Codec"
    attrs: dict[str, Any] = {
        "__module__": handler.__module__,
        "__qualname__": name,
        "handler": handler(),
        "codec": handler.codec,
        "stream_format": stream_format,
        "magic": magic,
        "requirement": handler.requirement,
        "extension_aliases": tuple(handler.extension_aliases),
        "checks_content": bool(handler.checks_content),
    }
    # Only what the handler overrides: the detector skips a codec whose
    # ``magic_behind_prefix`` or ``content_probe`` is the base's.
    if handler._magic_behind_prefix is not BuiltinCodecHandler._magic_behind_prefix:
        attrs["magic_behind_prefix"] = _magic_behind_prefix
    if handler._content_probe is not BuiltinCodecHandler._content_probe:
        attrs["content_probe"] = _content_probe
    return type(name, (BuiltinHandlerCodec,), attrs)


__all__ = [
    "BuiltinCall",
    "BuiltinCodecHandler",
    "BuiltinHandlerCodec",
    "builtin_call",
    "builtin_codec",
    "config_of",
    "params_of",
]
