"""The codec registry: every openable codec, lookups by id and stream format, and
:func:`open_codec_stream` / :func:`open_codec_raw` / :func:`resolve_codec`.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, BinaryIO

from archivey.exceptions import ArchiveyError
from archivey.internal.config import (
    DEFAULT_STREAM_CONFIG,
    StreamConfig,
)
from archivey.internal.dataclass_copy import copy_with
from archivey.internal.excluded_libraries import NO_EXCLUSIONS
from archivey.internal.streams.archive_stream import (
    ArchiveStreamImpl,
    ExceptionTranslator,
    RewindWarning,
    raise_translated,
)
from archivey.internal.streams.codecs.base import (
    _DEFAULT_PARAMS,
    AnyStreamFormat,
    Codec,
    CodecId,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.brotli_codec import BrotliCodec
from archivey.internal.streams.codecs.bzip2_codec import Bzip2Codec
from archivey.internal.streams.codecs.deflate64_codec import Deflate64Codec
from archivey.internal.streams.codecs.gzip_codec import GzipCodec
from archivey.internal.streams.codecs.lz4_codec import Lz4Codec
from archivey.internal.streams.codecs.lzma_codec import (
    LzipCodec,
    Lzma2Codec,
    LzmaAloneCodec,
    LzmaCodec,
    XzCodec,
)
from archivey.internal.streams.codecs.ppmd_codec import PpmdCodec
from archivey.internal.streams.codecs.stored_codec import StoredCodec
from archivey.internal.streams.codecs.unix_compress_codec import UnixCompressCodec
from archivey.internal.streams.codecs.zip_legacy_codec import ImplodeCodec, ShrinkCodec
from archivey.internal.streams.codecs.zlib_codec import (
    DeflateCodec,
    ZlibCodec,
)
from archivey.internal.streams.codecs.zstd_codec import ZstdCodec
from archivey.internal.streams.streamtools import (
    fix_stream_start_position,
    is_seekable,
    source_byte_size,
)
from archivey.types import (
    MissingComponent,
    OptionalLibrary,
)

if TYPE_CHECKING:
    from archivey.internal.diagnostics_collector import DiagnosticCollector


# Single source of truth for *openable* codecs. Detection, the single-file reader, and
# the backend registry read them through the functions below, at call time, so a codec
# added later by :func:`add_stream_codec` (``archivey.formats.register_codec``) reaches
# every one of them. Filter-only ``Codec`` enum members (DELTA / BCJ_*) are
# intentionally absent — they compose into raw LZMA via ``LZMA_FILTER_IDS``, not
# standalone ``StreamCodec.open``.
_STREAM_CODECS: list[StreamCodec] = [
    StoredCodec(),
    GzipCodec(),
    Bzip2Codec(),
    XzCodec(),
    LzipCodec(),
    LzmaAloneCodec(),
    LzmaCodec(),
    Lzma2Codec(),
    DeflateCodec(),
    ZlibCodec(),
    ZstdCodec(),
    Lz4Codec(),
    BrotliCodec(),
    UnixCompressCodec(),
    PpmdCodec(),
    Deflate64Codec(),
    ShrinkCodec(),
    ImplodeCodec(),
]

_BY_CODEC: dict[CodecId, StreamCodec] = {c.codec: c for c in _STREAM_CODECS}
_BY_STREAM_FORMAT: dict[AnyStreamFormat, StreamCodec] = {
    c.stream_format: c for c in _STREAM_CODECS if c.stream_format is not None
}


def stream_codecs() -> tuple[StreamCodec, ...]:
    """Every openable codec, built-in ones first, then registered ones in order."""
    return tuple(_STREAM_CODECS)


def single_file_codecs() -> tuple[StreamCodec, ...]:
    """The codecs presented as standalone single-file formats (a subset of
    :func:`stream_codecs`): each one is also read around a TAR or a sequential
    format (``.tar.gz``, ``.cpio.gz``)."""
    return tuple(c for c in _STREAM_CODECS if c.single_file_format is not None)


def single_file_codec(stream_format: object) -> StreamCodec | None:
    """The single-file codec for ``stream_format``, or ``None`` when no codec decodes
    it as a standalone stream (``UNCOMPRESSED`` included)."""
    sc = _BY_STREAM_FORMAT.get(stream_format)  # type: ignore[call-overload]
    return sc if sc is not None and sc.single_file_format is not None else None


def add_stream_codec(sc: StreamCodec) -> None:
    """Add ``sc`` after every codec there already is. The caller has checked that its
    ``codec`` and ``stream_format`` are new."""
    assert sc.codec not in _BY_CODEC, sc.codec
    assert sc.stream_format is None or sc.stream_format not in _BY_STREAM_FORMAT
    _STREAM_CODECS.append(sc)
    _BY_CODEC[sc.codec] = sc
    if sc.stream_format is not None:
        _BY_STREAM_FORMAT[sc.stream_format] = sc


def save_codec_state() -> Callable[[], None]:
    """Save what :func:`add_stream_codec` writes; the result restores it (tests)."""
    codecs = list(_STREAM_CODECS)
    by_codec = dict(_BY_CODEC)
    by_format = dict(_BY_STREAM_FORMAT)

    def restore() -> None:
        _STREAM_CODECS[:] = codecs
        _BY_CODEC.clear()
        _BY_CODEC.update(by_codec)
        _BY_STREAM_FORMAT.clear()
        _BY_STREAM_FORMAT.update(by_format)

    return restore


def stream_codec(codec: CodecId) -> StreamCodec:
    """The codec object for ``codec`` (raises ``KeyError`` for a filter-only codec)."""
    return _BY_CODEC[codec]


def stream_codec_for_format(stream_format: AnyStreamFormat) -> StreamCodec:
    """The codec object that decodes a single-file/TAR ``StreamFormat``."""
    return _BY_STREAM_FORMAT[stream_format]


def codec_for_stream_format(stream_format: AnyStreamFormat) -> CodecId:
    """Map a single-file/TAR ``StreamFormat`` to its codec."""
    return _BY_STREAM_FORMAT[stream_format].codec


def codec_requirement(
    codec: CodecId, excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS
) -> MissingComponent | None:
    """The optional-dependency requirement declared by ``codec``, if any, as a call
    with ``excluded`` reports it (:meth:`StreamCodec.requirement_under`)."""
    sc = _BY_CODEC.get(codec)
    return sc.requirement_under(excluded) if sc is not None else None


def is_codec_available(
    codec: CodecId, excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS
) -> bool:
    """Whether ``codec``'s decompression backend is importable right now, and
    ``excluded`` (a call's ``FormatPolicy.exclude_libraries``) does not turn it off.

    A codec with no ``requirement`` is stdlib-backed and always available; an optional codec
    reports on its backing package's live sentinel. Used by the registry to compute a
    format's tri-state support compositionally over the codecs it can use. Reads the
    sentinels live, so it reflects test monkeypatching.
    """
    sc = _BY_CODEC.get(codec)
    return sc is None or sc.available(excluded)


@dataclass(frozen=True)
class CodecBackend:
    """A resolved codec backend: its open function (config-bound) and its translator.

    Returned by :func:`resolve_codec` so callers can obtain (and reuse) the backend
    without opening a stream — the "backend dispatch is separable from opening" contract.
    Reuse it only within the scope of ``config.collector``: a backend resolved with a
    reader's collector reports every stream it opens into that reader.
    """

    codec: CodecId
    config: StreamConfig
    translate: ExceptionTranslator
    rewind_warning: RewindWarning | None
    _open: Callable[[CodecSource, CodecParams, StreamConfig], BinaryIO] = field(
        repr=False
    )
    # The codec's ``StreamCodec.checks_content``.
    checks_content: bool = False

    def open(
        self, source: CodecSource, params: CodecParams = _DEFAULT_PARAMS
    ) -> BinaryIO:
        return self._open(source, params, self.config)


def resolve_codec(
    codec: CodecId, config: StreamConfig = DEFAULT_STREAM_CONFIG
) -> CodecBackend:
    """Resolve ``codec`` to its backend (open function + translator) without opening anything.

    The translator must match the *active* backend: when an accelerator
    (``rapidgzip`` / ``indexed_bzip2``) is the chosen backend, its exception taxonomy
    differs from stdlib's, so the codec's :meth:`StreamCodec.translator` selects the right one.
    The ``rewind_warning`` is likewise config-dependent (an active accelerator gives indexed
    random access, so it carries none); it is attached to the ``ArchiveStream`` by
    :func:`open_codec_stream`.

    Raises ``KeyError`` for a filter-only codec (Delta/BCJ), which is composed into a raw
    LZMA chain rather than opened standalone.
    """
    sc = _BY_CODEC[codec]
    return CodecBackend(
        codec=codec,
        config=config,
        translate=sc.translator(config),
        rewind_warning=sc.rewind_warning(config),
        _open=sc.open,
        checks_content=sc.checks_content,
    )


def open_codec_stream(
    codec: CodecId,
    source: CodecSource,
    *,
    config: StreamConfig = DEFAULT_STREAM_CONFIG,
    params: CodecParams = _DEFAULT_PARAMS,
    stamp: Callable[[ArchiveyError], None] | None = None,
    collector: DiagnosticCollector | None = None,
    seekable: bool | None = None,
    on_close: Callable[[], None] | None = None,
    repeat_verdict: bool = True,
) -> ArchiveStreamImpl:
    """Open a decompressing stream for ``codec`` with exceptions translated/stamped.

    The returned stream wraps the backend so corrupt/truncated/non-seekable errors surface
    as ``ArchiveyError`` subclasses (never raw codec exceptions).

    ``config.seekable`` gates native index construction and accelerator ``AUTO``
    resolution; for the DEFLATE family, ``AUTO`` also takes a large sequential read
    (``_sequential_read_pays`` in ``rapidgzip_select.py``).
    The ArchiveStream seekability hint is separate: pass ``seekable=False`` to force a
    forward-only public handle (as :func:`~archivey.open_stream` does by default). When
    ``seekable`` is omitted the handle stays seekable so format backends that need
    positioning on an outer codec stream (compressed TAR) keep working — member-stream
    seekability is enforced by the reader wrapper instead.

    ``on_close`` runs when the returned stream closes, after its inner: how a caller that
    built something for this stream alone (``open_stream``'s source) ties it to the
    stream's lifetime.

    ``collector`` goes to the returned stream and, through ``config.collector``, to the
    codec's own decompressor, which is where a degraded seek index is reported. A
    ``config`` that already carries a collector keeps it when ``collector`` is omitted.
    A stored stream source is the exception: its codec emits nothing, so ``collector``
    reaches only the returned stream and ``config`` is passed on unchanged.

    ``repeat_verdict=False`` makes the stream raise each error as the decoder raises
    it, and not repeat the first one after a seek (``ArchiveStreamImpl._fail``). It is for
    a stream that only a reader's own views read. A read seeks the shared handle when it
    is not already there. Some reads still seek, and one seek is enough to mark the
    stream rewound.
    """
    source, config, backend = _prepared_backend(codec, source, config, collector)
    # Default True: internal/format callers may need to seek the codec stream even when
    # ``config.seekable`` is False (no accelerator/index). Public ``open_stream`` passes
    # the caller's ``seekable=`` explicitly.
    stream_seekable = True if seekable is None else seekable
    return ArchiveStreamImpl(
        lambda: backend.open(source, params),
        translate=backend.translate,
        stamp=stamp,
        lazy=False,
        seekable=stream_seekable,
        rewind_warning=backend.rewind_warning if stream_seekable else None,
        collector=collector if collector is not None else config.collector,
        on_close=on_close,
        repeat_verdict=repeat_verdict,
        checks_content=backend.checks_content,
    )


@dataclass(frozen=True, slots=True)
class OpenedCodec:
    """A codec stream opened without an :class:`ArchiveStream` around it.

    ``translate`` and ``rewind_warning`` are what :func:`open_codec_stream` would have
    put on that stream. The caller builds its own stream around ``stream`` with them.
    """

    stream: BinaryIO
    translate: ExceptionTranslator
    rewind_warning: RewindWarning | None


def open_codec_raw(
    codec: CodecId,
    source: CodecSource,
    *,
    config: StreamConfig = DEFAULT_STREAM_CONFIG,
    params: CodecParams = _DEFAULT_PARAMS,
    collector: DiagnosticCollector | None = None,
) -> OpenedCodec:
    """Open ``codec`` over ``source`` now, for a caller that wraps the result itself.

    :func:`open_codec_stream` returns an :class:`ArchiveStream`. A member backend wraps
    that in its member stream, which then collapses the codec stream away on open. A
    caller that would only do that (a ZIP member) calls this instead and passes
    ``translate`` and ``rewind_warning`` to its own stream: one stream object per
    member, not two. An open failure raises what :func:`open_codec_stream` raises for
    it. ``rewind_warning`` is the codec's, whatever the seek demand: the caller drops it
    for a stream that cannot seek, as :func:`open_codec_stream` does for
    ``seekable=False``.
    """
    source, config, backend = _prepared_backend(codec, source, config, collector)
    try:
        stream = backend.open(source, params)
    except Exception as e:  # noqa: BLE001 - re-raised via the translator
        raise_translated(e, backend.translate)
    return OpenedCodec(
        stream=stream,
        translate=backend.translate,
        rewind_warning=backend.rewind_warning,
    )


def _prepared_backend(
    codec: CodecId,
    source: CodecSource,
    config: StreamConfig,
    collector: DiagnosticCollector | None,
) -> tuple[CodecSource, StreamConfig, CodecBackend]:
    """The source, decoder config and backend that both openers above use."""
    is_stream = not isinstance(source, (str, os.PathLike))
    if is_stream:
        # A seekable stream positioned mid-file gets a clean tell()==0 origin (a
        # SlicingStream view), because codec backends address the source with absolute
        # offsets — the seekable XZ/lzip index, stdlib gzip's rewind — and would
        # otherwise read the wrong bytes. Streams at position 0 pass through unchanged
        # (see the stream-position contract in ``format-detection``). Expected to be a
        # no-op for every caller today: ``open_stream`` rebases its source first, and the
        # readers hand in views that start at 0. It stays for a direct caller that does
        # not.
        source = fix_stream_start_position(source)
    # A stored stream decodes nothing, so the config work below would build values
    # nothing reads: ``StoredCodec`` opens its source as is, and its translator and
    # rewind warning ignore the config. ZIP opens one per member, so it is skipped
    # (the collector still reaches the stream below). A path source still runs it.
    if not (is_stream and codec is Codec.STORED):
        config = _decoder_config(codec, source, config, collector)
    return source, config, resolve_codec(codec, config)


def _decoder_config(
    codec: CodecId,
    source: CodecSource,
    config: StreamConfig,
    collector: DiagnosticCollector | None,
) -> StreamConfig:
    """``config`` as :func:`open_codec_stream`'s decoder sees it.

    Carries ``collector``, drops seek demand that a stream source cannot meet, notes
    whether the source can seek, fills the known input size, then lets the codec adjust
    it.
    """
    # One copy for all four adjustments, and none when nothing changes: a ZIP reader
    # opens a codec per member, and each copy of this dataclass is a few microseconds.
    changes: dict[str, Any] = {}
    if collector is not None and config.collector is not collector:
        changes["collector"] = collector
    # ``ZipReader._member_config`` fills ``source_seekable`` and clears ``seekable`` by
    # these two rules before it gets here, so a ZIP member's config is copied once: a
    # change to either rule belongs there too.
    source_seekable = isinstance(source, (str, os.PathLike)) or is_seekable(source)
    if config.seekable and not source_seekable:
        # Seek demand on a source that cannot seek cannot be met, and it would make
        # accelerator AUTO pick a decoder that fails at open when it asks the
        # source for ``tell``. A compressed TAR opened ``streaming=True`` with
        # ``seekable_members=True`` over a forward-only stream arrives here so.
        changes["seekable"] = False
    if source_seekable != config.source_seekable:
        # Lets accelerator AUTO consider a sequential read (``_rapidgzip_wanted``).
        changes["source_seekable"] = source_seekable
    # Fill the AUTO size gate when the caller did not already supply a known length
    # (path ``stat``, ``SlicingStream.size``, ``BytesIO``, …). Unknown stays ``None``.
    if config.compressed_input_size is None:
        size = source_byte_size(source)
        if size is not None:
            changes["compressed_input_size"] = size
    if changes:
        config = copy_with(config, **changes)
    # Fill before resolve_codec so the translator and rewind_warning agree with open.
    return _BY_CODEC[codec].prepare_config(source, config)
