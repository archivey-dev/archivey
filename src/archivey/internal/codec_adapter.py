"""A :class:`~archivey.formats.CodecHandler` as a :class:`StreamCodec`: what
``register_codec`` adds to the codec registry.

The handler's decompressor has the standard library's one-stream interface, so the
codec decodes through :class:`FramedDecoder`, the adapter bzip2, zstd and LZ4 use: it
gives the handler the same rules for padding, further streams and trailing data as
those codecs have.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, BinaryIO

from archivey.config import ProcessIsolation
from archivey.exceptions import ArchiveyError, ArchiveyUsageError
from archivey.internal.config import StreamConfig
from archivey.internal.excluded_libraries import (
    NO_EXCLUSIONS,
    as_excluded,
    is_excluded_module,
)
from archivey.internal.format_adapter import prefix_probe
from archivey.internal.format_args import add_plugin_spellings, plugin_spelling_clash
from archivey.internal.registry import _optional, get_registry
from archivey.internal.streams.archive_stream import RewindWarning
from archivey.internal.streams.codecs.base import (
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import (
    FramedDecompressorStream,
    StreamStart,
    stream_magic,
)
from archivey.internal.streams.codecs.registry import add_stream_codec, stream_codecs
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    MagicSignature,
    MissingComponent,
    OptionalLibrary,
    PluginStream,
    StreamFormat,
)

if TYPE_CHECKING:
    from archivey.formats import CodecCall, CodecHandler


def _never(data: bytes) -> bool:
    """The :data:`StreamStart` of a codec that reads one stream: nothing starts another."""
    del data
    return False


class HandlerCodec(StreamCodec):
    """The base of the codec class :func:`codec_class` builds for each handler."""

    handler: CodecHandler
    # How a further stream starts (``CodecHandler.concatenated``).
    # A static method: a plain function here would be bound, and called with the codec.
    starts: StreamStart = staticmethod(_never)

    def requirement_under(
        self, excluded: frozenset[OptionalLibrary]
    ) -> MissingComponent | None:
        """The first module in ``requires`` that ``excluded`` turns off or that does
        not import, else the first one, so a codec that needs any reports one."""
        requires = self.handler.requires
        if not requires:
            return None
        name = next(
            (
                n
                for n in requires
                if is_excluded_module(n, excluded) or _optional(n) is None
            ),
            requires[0],
        )
        hint = self.handler.install_hint or f"install {name}"
        component = MissingComponent(name, hint, (str(self.handler.stream_format),))
        return (
            as_excluded(component) if is_excluded_module(name, excluded) else component
        )

    def _backend_present(self) -> bool:
        return all(_optional(name) is not None for name in self.handler.requires)

    def excluded_by(self, excluded: frozenset[OptionalLibrary]) -> bool:
        return any(is_excluded_module(n, excluded) for n in self.handler.requires)

    def available(self, excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS) -> bool:
        return not self.excluded_by(excluded) and self._backend_present()

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        if not self.available(config.excluded_libraries):
            raise self._missing(
                f"{self.handler.stream_format.value} streams",
                excluded=config.excluded_libraries,
            )
        call = codec_call(params, config)
        return FramedDecompressorStream(
            source,
            functools.partial(self.handler.decompressor, call),
            codec_name=self.handler.stream_format.value,
            magic=self.starts,
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        translated = self.handler.translate_exception(exc)
        if translated is not None:
            return translated
        return self._eof_truncation(exc, self.handler.stream_format.value)

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return RewindWarning(self.handler.stream_format.value, suggest_install=False)


def codec_call(params: CodecParams, config: StreamConfig) -> CodecCall:
    """The :class:`CodecCall` a handler's decoder is given for ``params`` and
    ``config``."""
    # Imported here: archivey.formats imports this module's neighbours.
    from archivey.formats import CodecCall

    return CodecCall(
        size=params.unpack_size,
        properties=params.properties,
        limits=config.decoder_limits,
        probe_bound=config.probe_read_bound,
    )


def _content_probe(probe: Callable[[bytes], bool]) -> Callable[..., bool]:
    """A handler's ``probe(prefix)`` as :meth:`StreamCodec.content_probe`.

    A format plugin's probe wrapper (``format_adapter.prefix_probe``) does the work:
    the probe gets the peeked prefix only, and one that raises is no match, logged.
    """
    check = prefix_probe(probe)

    def content_probe(
        self: StreamCodec,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: object = None,
        charge_decode: object = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        del self, source_length, read_at, charge_decode, isolation
        return check(prefix)

    return content_probe


def codec_class(handler: type[CodecHandler]) -> type[HandlerCodec]:
    """The :class:`StreamCodec` subclass that decodes with ``handler``."""
    stream_format = handler.stream_format
    fmt = ArchiveFormat(ContainerFormat.RAW_STREAM, stream_format)
    attrs: dict[str, Any] = {
        "handler": handler(),
        "codec": stream_format,
        "stream_format": stream_format,
        "magic": tuple(MagicSignature(m.offset, m.data, fmt) for m in handler.magic),
        "extension_aliases": tuple(handler.extension_aliases),
        "checks_content": bool(handler.checks_content),
    }
    starts = [m.data for m in handler.magic if m.offset == 0]
    if handler.concatenated and starts:
        attrs["starts"] = staticmethod(
            stream_magic(*(tuple(bytes([b]) for b in data) for data in starts))
        )
    if handler.probe is not None:
        attrs["content_probe"] = _content_probe(handler.probe)
    return type(f"{handler.__name__}Codec", (HandlerCodec,), attrs)


def _check_handler(handler: type[CodecHandler]) -> PluginStream:
    # Imported here: archivey.formats imports this module's neighbours.
    from archivey.formats import CodecHandler

    if not (isinstance(handler, type) and issubclass(handler, CodecHandler)):
        raise ArchiveyUsageError(
            f"register_codec() takes a CodecHandler subclass, got {handler!r}"
        )
    name = handler.__name__
    stream = getattr(handler, "stream_format", None)
    if not isinstance(stream, PluginStream):
        raise ArchiveyUsageError(
            f"{name}.stream_format must be a PluginStream member, got {stream!r}"
        )
    if stream.value in {s.value for s in StreamFormat}:
        raise ArchiveyUsageError(
            f"{name}: stream value {stream.value!r} is a built-in format's"
        )
    for codec in stream_codecs():
        other = codec.stream_format
        if other is not None and other.value == stream.value:
            raise ArchiveyUsageError(
                f"{name}: stream value {stream.value!r} is already used by "
                f"{type(other).__name__}.{other.name}"
            )
    registry = get_registry()
    raw = ArchiveFormat(ContainerFormat.RAW_STREAM, stream)
    pairs = [
        ArchiveFormat(base.container, stream) for base in registry.stream_pair_bases()
    ]
    for each in (raw, *(p for p in pairs if not _builtin(p))):
        clash = plugin_spelling_clash(each)
        if clash is not None:
            spelling, owner = clash
            raise ArchiveyUsageError(
                f"{name}: format= spelling {spelling!r} already names "
                f"{owner.display_name}; choose a stream value and member name no "
                "format uses"
            )
    extensions = [f".{stream.value}", *handler.extension_aliases]
    for ext in extensions:
        if not ext.startswith(".") or len(ext) < 2 or any(c in ext[1:] for c in "./\\"):
            raise ArchiveyUsageError(
                f"{name}: extension {ext!r} must be a dot followed by at least one "
                "character, with no further dot or path separator"
            )
    claimed = {ext.lower(): owner for ext, owner in registry.extension_map().items()}
    for base_ext in ("", *registry.stream_pair_extensions()):
        for ext in extensions:
            owner = claimed.get(f"{base_ext}{ext}".lower())
            if owner is not None:
                raise ArchiveyUsageError(
                    f"{name}: extension {base_ext + ext!r} is already claimed by "
                    f"{owner.display_name}"
                )
    for magic in handler.magic:
        if magic.offset < 0 or not magic.data:
            raise ArchiveyUsageError(
                f"{name}: magic {magic!r} needs a non-negative offset and at least "
                "one byte"
            )
    if handler.probe is not None and not callable(handler.probe):
        raise ArchiveyUsageError(f"{name}.probe must be callable or None")
    if isinstance(handler.requires, str):
        raise ArchiveyUsageError(f"{name}.requires must be a tuple of module names")
    return stream


def _builtin(fmt: ArchiveFormat) -> bool:
    """Whether ``fmt``'s container is built in, whose pairs take no plugin spelling."""
    return isinstance(fmt.container, ContainerFormat)


def register_plugin_codec(handler: type[CodecHandler]) -> None:
    """Add ``handler``'s codec to the registry (``register_codec``)."""
    stream = _check_handler(handler)
    add_stream_codec(codec_class(handler)())
    registry = get_registry()
    registry.codecs_changed()
    add_plugin_spellings(ArchiveFormat(ContainerFormat.RAW_STREAM, stream))
    for base in registry.stream_pair_bases():
        pair = ArchiveFormat(base.container, stream)
        if not _builtin(pair):
            add_plugin_spellings(pair)


__all__ = ["HandlerCodec", "codec_class", "register_plugin_codec"]
