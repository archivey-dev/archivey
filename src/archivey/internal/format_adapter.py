"""The adapter between ``archivey.formats`` and the internal reader machinery.

A :class:`~archivey.formats.FormatHandler` (a plugin's, or a built-in format written
against the public API, such as ar or CPIO) becomes a reader in three steps:

1. **Registration.** :func:`register_plugin` (``archivey.formats.register_format``)
   checks the handler (:func:`_check_plugin`) and builds one :class:`ReadBackend`
   subclass for it (:func:`_backend_class`), whose class attributes carry the
   handler's format, extensions, magic and probe. It registers that class after the
   built-in backends, so a built-in signal always wins detection.
   :func:`register_builtin_format` builds the same class for a built-in format and
   registers it among the built-in backends. A ``FormatPolicy(replace=…)`` entry gets
   its class from :func:`replacement_backend`, which is never registered.
2. **Selection.** Detection names the format from the registered classes' magic,
   extensions and probes. ``open_archive`` (and ``ReaderContext.open_nested``) then
   get the class from ``registry.BackendRegistry.reader_for_format``, which returns
   the :func:`replacement_backend` class when the call's policy replaces the format.
3. **Opening.** :meth:`_PluginBackend.open_read` builds the adapter for the handler's
   shape. A format reader does not subclass :class:`BaseArchiveReader`: two adapter
   subclasses serve every one. :class:`IndexedReaderAdapter` implements the abstract
   reader methods by calling an :class:`~archivey.formats.IndexedReader`, and
   :class:`SequentialReaderAdapter` by walking a
   :class:`~archivey.formats.SequentialReader`. The walk, the passes, link handling,
   verification and extraction stay internal, and the handler reaches archivey's
   services (codecs, diagnostics, limits) through the
   :class:`~archivey.formats.ReaderContext` the adapter builds.

The file holds, in order: the shared adapter base, the indexed adapter,
the sequential adapter with the walk helpers it uses, then the backend class and the
registration functions. ``codec_adapter`` does the same for a
:class:`~archivey.formats.CodecHandler`.
"""

from __future__ import annotations

import functools
import io
import logging
import lzma
import threading
import weakref
from collections.abc import Callable, Generator, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, nullcontext, suppress
from dataclasses import fields, replace
from typing import Any, BinaryIO, ClassVar, NoReturn, TypeVar, cast

from archivey.config import ArchiveyConfig, DecoderLimits, ProcessIsolation
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticContext,
    validate_code_context,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
    _UsageTypeError,
    _UsageValueError,
    exception_detail,
)
from archivey.formats import (
    FormatHandler,
    FormatReader,
    ForwardStream,
    Hasher,
    IndexedFormatHandler,
    IndexedReader,
    MemberData,
    MemberDigest,
    MemberRecord,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal import format_args
from archivey.internal.base_reader import (
    MAX_LINK_TARGET_BYTES,
    BaseArchiveReader,
    ReadBackend,
    reject_start_offset,
)
from archivey.internal.bomb_tracker import DecodeRatioGuard, ReadRatioTally
from archivey.internal.config import stream_config_from_archivey
from archivey.internal.dataclass_copy import copy_with
from archivey.internal.detection import INNER_CONTAINER_PROBE_BYTES
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.format_args import (
    add_plugin_spellings,
    add_sequential_container,
    plugin_spelling_clash,
)
from archivey.internal.logs import detection as detection_logger
from archivey.internal.naming import emit_member_name_normalized, normalize_member_name
from archivey.internal.open_site import OpenSite
from archivey.internal.overrides import override
from archivey.internal.password import _PasswordCandidates
from archivey.internal.pe_resources import ProgramResources
from archivey.internal.registry import ContentProbe, get_registry
from archivey.internal.remote import MAX_PENDING_HINTS
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import MemberStreamParts, RewindWarning
from archivey.internal.streams.blocks import BlockStream
from archivey.internal.streams.codecs import (
    AnyStreamFormat,
    Codec,
    CodecId,
    CodecParams,
    codec_for_stream_format,
    decode_lzma_filter_properties,
    open_codec_stream,
    single_file_codec,
    single_file_codecs,
)
from archivey.internal.streams.codecs.registry import save_codec_state
from archivey.internal.streams.decompressor_stream import StreamChecksumError
from archivey.internal.streams.read_hints import mark_read_span, read_span_hint
from archivey.internal.streams.respawn import RespawnStream
from archivey.internal.streams.streamtools import (
    FullCountStream,
    LockedStream,
    OneReadEachStream,
    ReadAheadStream,
    ReadOnlyIOStream,
    SharedSource,
    SlicingStream,
    check_read_size,
    ensure_bufferedio,
    is_seekable,
    read_arrived,
    source_byte_size,
)
from archivey.internal.streams.streamtools.binaryio import (
    ReadableStream,
    read_blocking,
    read_within_reach,
)
from archivey.internal.streams.verification import (
    SpanningCheckError,
    ask_verification_proofs,
    drop_spanning_ceiling,
    mark_spanning_checksum,
    raise_member_level,
)
from archivey.internal.streams.verify import CustomDigests, hasher_factory
from archivey.internal.walk_handoff import MemberDataView
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    CompressionAlgorithm,
    ContainerFormat,
    HashAlgorithm,
    MagicSignature,
    MemberStreams,
    MemberType,
    PluginContainer,
    PluginStream,
    StreamFormat,
    Verification,
)


def _bounded(stream: object, size: int | None) -> bool:
    """Whether ``stream`` cannot return more than ``size`` bytes, so the overrun probe
    is not needed: a view or a block stream no longer than the member, which is what
    ``MemberData.bounded`` would say."""
    if size is None or not isinstance(stream, (SlicingStream, BlockStream)):
        return False
    length = stream.size
    return length is not None and length <= size


# Cached by type: the ABC ``issubclass`` and the module-name check otherwise run on
# every member open (about 190-250 ns, against 70 cached). A process meets few stream
# types; past 64 the oldest is evicted and costs the plain check again.
@functools.lru_cache(maxsize=64)
def _type_reads_full(cls: type) -> bool:
    return issubclass(cls, io.BufferedIOBase) or cls.__module__.startswith("archivey.")


def _reads_full(stream: object) -> bool:
    """Whether ``stream.read(n)`` returns ``n`` bytes unless it ends, so a plugin's
    member stream needs no :class:`FullCountStream` in front of it.

    A buffered stream does. So does every stream archivey made, a
    ``ReaderSource.view()`` or a ``ReaderContext.decompress()`` result: the stream layer
    keeps that rule, and a short read from one is its end. Anything else may be an
    ``io.RawIOBase`` that stops a read early (at a block boundary, say), and the
    wrapper's cost when it does not is one call per read and no copy.
    """
    return _type_reads_full(type(stream))


# How many archives deep ``ReaderContext.open_nested`` reads. The formats that nest
# go one level (a ``.deb``'s tars) or two (a ``.pkg``'s XAR payload); the bound turns
# a walk that keeps naming its own format into an archivey error before Python's
# recursion limit does, since each level holds a reader and a few generator frames.
MAX_NESTED_DEPTH = 8

# The walk steps ``ReaderContext.hold()`` tells apart (``_PluginAdapter._walk_step``).
_LISTING = "listing"
_REWALK = "rewalk"


class _PluginAdapter(BaseArchiveReader):
    """What the adapters of both reader shapes share: the context, errors, digests,
    archive info and close."""

    _reader: FormatReader

    def __init__(
        self,
        plugin: FormatHandler,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
    ) -> None:
        # Until ``plugin.open()`` returns there is no reader, and only the plugin
        # translates errors (``_translate_exception``).
        self._reader_open = False
        super().__init__(
            format,
            streaming,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
        self._source = source
        self._plugin = plugin
        # The caller's ``encoding=``, for a nested reader (``_open_nested``).
        self._encoding = encoding
        # Iterators ReaderContext.open_nested() returned, closed with the archive at the
        # latest.
        self._nested_iterators: weakref.WeakSet[Iterator[MemberSpan]] = (
            weakref.WeakSet()
        )
        # The plugin may hold a handle of its own (a library over ``source.path``), so
        # under CONCURRENT every call into it, and every read of a stream it returned,
        # takes one lock (``_handle_guard``). The exception is ``translate_exception``,
        # which ``base_reader`` runs outside the lock. The views of ``ReaderSource``
        # need none, but archivey cannot tell which kind of reader it was given. A
        # random-access pass's stored member data read through the walk takes
        # ``_walk_lock`` instead (``_open_member_in_walk``): it reads archivey's own
        # walk stream, not the plugin, and the walk is the only other reader of that
        # stream. Decoded member data (``MemberSpan.data``) is the plugin's stream, so
        # it takes this lock too.
        if MemberStreams.CONCURRENT in member_streams:
            self._handle_lock = threading.Lock()
        # Views over a seekable source, when the reader shape uses them.
        self._shared: SharedSource | None = None
        # The member decoder config, as ZIP builds its own: the compressed bytes a
        # plugin hands ``decompress`` are the codec's whole input, so a byte after the
        # codec's end of stream is damage.
        self._decoder_config = replace(
            stream_config_from_archivey(
                self._config,
                streaming=streaming,
                seekable=MemberStreams.SEEKABLE in member_streams,
                usage=self._usage,
            ),
            refuse_input_after_end=True,
        )
        # The walk position of the member being listed: the id registration will
        # stamp on it, for a report made before it is yielded.
        self._walk_index = 0
        # Which walk is taking a step, for ``ReaderContext.hold()`` (``_hold``):
        # ``_LISTING`` charges the listing, ``_REWALK`` (a walk started over to reach
        # member data) charges nothing, and ``None`` (no step) is a plugin bug.
        self._walk_step: str | None = None
        # Reports on a member being listed, held until it is yielded and named
        # (``_send_held_reports``), by the member's id(): each sends one, naming the
        # member as it is named when called, with the member id it is given.
        self._held_reports: dict[int, list[Callable[[int | None], None]]] = {}
        context = ReaderContext(
            encoding=encoding,
            archive_name=archive_name,
            config=config,
            decompress=self._decompress,
            report=self._report,
            link_target_unavailable=self._link_target_unavailable,
            hold=self._hold,
            charge_metadata=self._charge_metadata,
            open_nested=self._open_nested,
            usage=self._usage,
        )
        context._spanning_check = self._new_spanning_check
        context._decompress_coder = self._decompress_coder
        self._reader = self._open_reader(context)
        self._reader_open = True

    def _open_reader(self, context: ReaderContext) -> FormatReader:
        """Call the plugin's ``open``, and check what it returned."""
        raise NotImplementedError

    def _new_spanning_check(self, key: object) -> SpanningCheck:
        """``ReaderContext._spanning_check()``: a check over several members' data
        that the reader runs itself, named ``key``."""
        return SpanningCheck(self, key)

    def _wrong_reader(self, reader: object, method: str, noun: str) -> NoReturn:
        # Every interface check raises through ``_plugin_bug()``, wherever it runs.
        raise _plugin_bug(
            TypeError(
                f"{type(self._plugin).__name__}.{method}() returned "
                f"{type(reader).__name__}, not {noun}"
            )
        )

    def _refuse_codec_off_by_policy(self, method: object) -> None:
        """Refuse a codec ``config.formats`` turns off, before its code runs."""
        if not isinstance(method, (StreamFormat, PluginStream, CompressionAlgorithm)):
            return
        refusal = self._config.formats._codec_refusal(method)
        if refusal is not None:
            raise UnsupportedFeatureError(
                refusal, source_format=self._format, archive_name=self._archive_name
            )

    def _decompress_coder(
        self, data: BinaryIO, stream_format: StreamFormat, size: int | None
    ) -> BinaryIO:
        """``ReaderContext._decompress_coder``: ``stream_format`` data that is a
        container coder's whole data, decoded as a member's method is: bzip2 and LZMA
        Alone end at their first stream, and a byte after the end is refused."""
        return self._decompress(data, stream_format, size, None, whole_file=False)

    def _decompress(
        self,
        data: BinaryIO,
        method: CompressionAlgorithm | AnyStreamFormat,
        size: int | None,
        properties: bytes | None,
        *,
        whole_file: bool = True,
    ) -> BinaryIO:
        """``ReaderContext.decompress``: ``data`` through archivey's codec layer.

        ``whole_file=False`` (``_decompress_coder``) keeps the member decoder
        config's ``refuse_input_after_end`` for a stream format too."""
        self._refuse_codec_off_by_policy(method)
        is_stream = isinstance(method, (StreamFormat, PluginStream))
        codec: CodecId | None
        if is_stream:
            try:
                codec = codec_for_stream_format(method)
            except KeyError:
                codec = None
        else:
            codec = _PLUGIN_CODECS.get(method)
        if codec is None:
            raise UnsupportedFeatureError(
                f"ReaderContext.decompress() does not decode {method.name}",
                source_format=self._format,
                archive_name=self._archive_name,
            )
        params = self._codec_params(
            codec, method, size, properties, is_stream=is_stream and whole_file
        )
        # Per call, as ZIP fills them per member (``_member_decoder_config``): the
        # output size, and the input size while ``data`` is at its start. The
        # accelerators choose by them, and rapidgzip's length check needs the first.
        changes: dict[str, Any] = {"expected_decompressed_size": size}
        if is_stream and whole_file:
            # A whole stream reads as a file of its format does: bytes after its end
            # are reported (``ARCHIVE_TRAILING_DATA``), not refused. Most stream
            # codecs have no refusal; the report is what they all share.
            changes["refuse_input_after_end"] = False
            changes["report_trailing_data"] = True
        if not is_seekable(data) or data.tell() == 0:
            input_size = source_byte_size(data)
            if input_size is not None:
                changes["compressed_input_size"] = input_size
        decoded = open_codec_stream(
            codec,
            data,
            config=copy_with(self._decoder_config, **changes),
            params=params,
            collector=self._diagnostics_collector,
        )
        # A decoder over a view reads the view's span.
        hint = read_span_hint(data)
        if hint is not None:
            mark_read_span(decoded, hint)
        return decoded

    def _codec_params(
        self,
        codec: CodecId,
        method: CompressionAlgorithm | AnyStreamFormat,
        size: int | None,
        properties: bytes | None,
        *,
        is_stream: bool,
    ) -> CodecParams:
        """The codec parameters for one ``decompress`` call: what ``codec`` needs
        beyond the bytes, read from the call's ``size`` and ``properties``.
        ``is_stream`` says ``method`` is a stream format read as a whole file
        (``decompress``), not a member's method or a container coder's data
        (``_decompress_coder``)."""
        # A bzip2 member is one stream, as in ZIP and 7z: a further stream after its
        # end is refused. So is LZMA Alone, which has no further streams of its own,
        # in a container coder (``_decompress_coder``, a XAR member). Zstd and LZ4 data
        # may be several frames, read together (RFC 8878, the LZ4 frame format), and xz
        # several streams with their padding, as a ZIP xz member may. A stream format
        # read as a file (``decompress``) is read as a file of that format is, so a
        # ``.bz2`` stream may hold several, as bzip2 itself decodes them.
        params = CodecParams(
            single_stream=not is_stream and codec in (Codec.BZIP2, Codec.LZMA_ALONE)
        )
        if isinstance(method, PluginStream):
            # A registered codec parses its own properties (``CodecCall``).
            params = CodecParams(unpack_size=size, properties=properties)
        if codec is Codec.LZMA or codec is Codec.LZMA2:
            want = 5 if codec is Codec.LZMA else 1
            if properties is None or len(properties) != want:
                raise CorruptionError(
                    f"{method.name} needs {want} bytes of properties, got "
                    f"{'none' if properties is None else len(properties)}",
                    source_format=self._format,
                    archive_name=self._archive_name,
                )
            what = f"{self._format.display_name} {method.name} member"
            filter_id = lzma.FILTER_LZMA1 if codec is Codec.LZMA else lzma.FILTER_LZMA2
            # Its own params, with no ``single_stream``: raw LZMA needs none.
            params = CodecParams(
                filters=[
                    decode_lzma_filter_properties(filter_id, properties, what=what)
                ],
                # Raw LZMA1 may have no end marker: it stops at the stored size.
                unpack_size=size if codec is Codec.LZMA else None,
            )
        if codec is Codec.LZO:
            if size is None:
                raise UnsupportedFeatureError(
                    "ReaderContext.decompress() needs size= for LZO: raw LZO1X does "
                    "not store its decoded length",
                    source_format=self._format,
                    archive_name=self._archive_name,
                )
            params = CodecParams(unpack_size=size)
        return params

    def _member_id(self, member: ArchiveMember | None) -> int | None:
        """The id a report on ``member`` carries: its registered id once listed,
        else the walk position it is about to be listed at."""
        if member is None:
            return None
        return member._member_id if member._member_id is not None else self._walk_index

    def _report(
        self,
        code: DiagnosticCode,
        message: str,
        details: DiagnosticContext,
        member: ArchiveMember | None,
    ) -> None:
        """``ReaderContext.report``: one diagnostic, with the archive and member filled
        in."""
        if code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE:
            raise ArchiveyUsageError(
                "report SYMLINK_TARGET_UNAVAILABLE with "
                "ReaderContext.link_target_unavailable()"
            )
        try:
            validate_code_context(code, details)
        except ValueError as exc:
            raise ArchiveyUsageError(f"ReaderContext.report(): {exc}") from None
        if member is None:
            self._send_report(code, message, details, None, None)
        elif self._walk_step == _REWALK:
            # A walk started over yields fresh members under their stored names:
            # report on the one the listing named.
            name = normalize_member_name(
                member.name, member.type, backslash_is_separator=False
            )
            listed = self._listed_named(name)
            member_id = listed[0]._member_id if len(listed) == 1 else None
            self._send_report(code, message, _named(details, name), member, member_id)
        elif not self._hold_report(
            member,
            lambda member_id: self._send_report(
                code, message, _named(details, member.name), member, member_id
            ),
        ):
            self._send_report(code, message, details, member, self._member_id(member))

    def _hold_report(
        self, member: ArchiveMember, send: Callable[[int | None], None]
    ) -> bool:
        """Hold ``send`` until ``member`` is yielded, if the listing has not yielded
        it yet: until then it is not named as callers see it. ``send`` takes the
        member's id, ``None`` for a member never yielded."""
        if member._member_id is not None or self._walk_step != _LISTING:
            return False
        self._held_reports.setdefault(id(member), []).append(send)
        return True

    def _send_report(
        self,
        code: DiagnosticCode,
        message: str,
        details: DiagnosticContext,
        member: ArchiveMember | None,
        member_id: int | None,
    ) -> None:
        """Emit one diagnostic, filling in the archive name and member id where the
        plugin left them ``None``."""
        fill: dict[str, object] = {}
        if getattr(details, "archive_name", "") is None:
            fill["archive_name"] = self._archive_name
        if getattr(details, "member_id", "") is None and member_id is not None:
            fill["member_id"] = member_id
        self._diagnostics_collector.emit(
            code=code,
            message=message,
            context=_with_fields(details, fill),
            member=member,
            attach_to_member=member is not None,
        )

    def _send_held_reports(self, member: ArchiveMember) -> None:
        """Send the reports held for ``member`` (``_hold_report``), now that archivey
        has named it and the walk is at it."""
        sends = self._held_reports.pop(id(member), ())
        if sends:
            member_id = self._member_id(member)
            for send in sends:
                send(member_id)

    def _send_unyielded_reports(self, *, may_raise: bool) -> None:
        """Send the reports held for members the walk never yielded, under the names
        the reader gave them and with no member id: archivey listed no such member.

        A report the caller's policy raises on raises only when ``may_raise`` (the
        walk ended normally). On a walk closed part-way, or ended by an error, the
        report is still recorded, but its raise is dropped: it would replace the
        error, or be lost in a generator's close."""
        with self._diagnostics_collector.deferring_raises() as first_held:
            while self._held_reports:
                _key, sends = self._held_reports.popitem()
                for send in sends:
                    send(None)
        held = first_held()
        if may_raise and held is not None:
            raise held

    def _name_member(self, member: ArchiveMember, index: int) -> None:
        """Give a listed member the names callers see, and send what was reported on
        it before: the name normalized, and a hard link's target the same way, since
        a link names another member by its listed name."""
        presented = member.name
        member.name = normalize_member_name(
            presented, member.type, backslash_is_separator=False
        )
        if member.type is MemberType.HARDLINK and member.link_target:
            member.link_target = normalize_member_name(
                member.link_target, MemberType.FILE, backslash_is_separator=False
            )
        self._send_held_reports(member)
        self._report_listed(member, presented, index)

    @override
    def _iter_members(self) -> Iterator[ArchiveMember]:
        ended = False
        try:
            yield from self._walk_members()
            ended = True
        except StreamChecksumError:
            # The codec reported its checksum failing (gzip, zlib, lzip, zstd, LZ4):
            # it stays the ceiling of the members it covers, which verify_all()
            # returns. An xz or bzip2 check failure reads as damage, handled below.
            self._spanning_check_ran("codec")
            raise
        except SpanningCheckError:
            # A check the reader ran failed (``SpanningCheck.failed``), which records
            # the members it covers itself.
            raise
        except ArchiveyError as e:
            # Damage ended the walk before the outer codec's end, so its checksum
            # cannot run. Damage does not lower ``verifiable``: the members only that
            # checksum covers are failures of verify_all() instead.
            self._note_spanning_unreachable("codec", self._listed, e)
            raise
        finally:
            # Members held and never yielded stop counting with the walk that held
            # them, however it ends: at its end, on damage, or closed part-way.
            self._listing_tracker.release_held()
            self._send_unyielded_reports(may_raise=ended)

    def _walk_members(self) -> Iterator[ArchiveMember]:
        """The listing walk of the reader's shape (``_iter_members``)."""
        raise NotImplementedError

    def _close_steps(
        self, steps: Iterator[object], guard: AbstractContextManager[object]
    ) -> None:
        """Close the plugin's walk when the listing stops before its end: closed
        part-way, or ended by an error. Closing archivey's own generator does not
        close it on every interpreter (PyPy's collector does, later), so its
        ``finally`` blocks would run after the archive closed. An error from it is
        dropped: on a walk an error ended, that error stands; on one the caller
        stopped, nothing is raised or reported, as when the collector closed it."""
        close = getattr(steps, "close", None)
        if close is not None:
            with suppress(Exception), guard:
                close()

    def _walk_next(self, steps: Iterator[object], step: str = _LISTING) -> object:
        """The next step of a walk, or ``_END`` once it ends: the listing's, during
        which a ``hold()`` is charged, or with ``step=_REWALK`` a data walk's, during
        which it is not."""
        self._walk_step = step
        try:
            return next(steps, _END)
        finally:
            self._walk_step = None

    def _hold(self, member: ArchiveMember, reason: str | None) -> None:
        """``ReaderContext.hold()``: charge a held member to the listing's limits.
        A walk started over to reach member data was listed already: no charge."""
        step = self._walk_step
        if step is None:
            raise ArchiveyUsageError(
                "ReaderContext.hold() counts a member only while walk() or "
                "iter_members() is listing it"
            )
        if step == _REWALK:
            return
        if not isinstance(member, ArchiveMember):
            raise TypeError(
                f"ReaderContext.hold() takes an ArchiveMember, not "
                f"{type(member).__name__}"
            )
        try:
            self._listing_tracker.hold_member(
                member, reason or "members held back by the reader"
            )
        except ValueError:
            raise ArchiveyUsageError(
                f"ReaderContext.hold(): {quoted(member.name)} is held already"
            ) from None

    def _charge_metadata(self, nbytes: int, what: str) -> None:
        """``ReaderContext.charge_metadata()``: charge the listing for what the walk
        keeps. A walk started over to reach member data was charged already."""
        step = self._walk_step
        if step is None:
            raise ArchiveyUsageError(
                "ReaderContext.charge_metadata() counts bytes only while walk() or "
                "iter_members() is listing"
            )
        if step == _REWALK:
            return
        if not isinstance(nbytes, int) or isinstance(nbytes, bool) or nbytes < 0:
            raise ArchiveyUsageError(
                "ReaderContext.charge_metadata() takes a size of 0 or more, got "
                f"{nbytes!r}"
            )
        self._listing_tracker.charge_walk(nbytes, what)

    def _open_nested(self, data: BinaryIO, fmt: ArchiveFormat) -> Iterator[MemberSpan]:
        """``ReaderContext.open_nested()``: archivey's reader for ``fmt`` over
        ``data``, working for this reader."""
        if self._walk_step is None:
            raise ArchiveyUsageError(
                "ReaderContext.open_nested() reads an inner archive only while walk() "
                "is listing"
            )
        if not isinstance(fmt, ArchiveFormat):
            raise TypeError(
                f"ReaderContext.open_nested() takes an ArchiveFormat, not "
                f"{type(fmt).__name__}"
            )
        registry = get_registry()
        policy = self._config.formats
        refusal = policy._nested_refusal(fmt)
        if refusal is not None:
            raise UnsupportedFeatureError(refusal, source_format=fmt)
        backend_cls = registry.reader_for_format(
            fmt,
            replacement=policy._replacement_for(fmt),
            excluded=policy._libraries_off,
        )
        if not backend_cls.SUPPORTS_STREAMING_NON_SEEKABLE:
            raise UnsupportedFeatureError(
                f"{fmt.display_name} cannot be read inside another archive: it needs "
                "a seekable source",
                source_format=fmt,
            )
        if self._nested_depth >= MAX_NESTED_DEPTH:
            raise UnsupportedFeatureError(
                f"{fmt.display_name} archive nested more than {MAX_NESTED_DEPTH} "
                "archives deep",
                source_format=fmt,
            )
        spans = self._nested_spans(backend_cls, data, fmt, first=self._walk_index)
        self._nested_iterators.add(spans)
        return spans

    def _nested_spans(
        self,
        backend_cls: type[ReadBackend],
        data: BinaryIO,
        fmt: ArchiveFormat,
        *,
        first: int,
    ) -> Iterator[MemberSpan]:
        """The spans of the inner archive ``data``: its members, numbered from
        ``first`` in what it reports, and their decoded data."""
        collector = self._diagnostics_collector
        with collector.member_ids_from(first):
            reader = backend_cls().open_read(
                ArchiveSource.for_stream(data),
                format=fmt,
                streaming=True,
                passwords=None,
                encoding=self._encoding,
                archive_name=self._archive_name,
                config=self._config,
                collector=collector,
            )
        try:
            pairs = iter(reader.stream_members())
            while True:
                with collector.member_ids_from(first):
                    pair = next(pairs, None)
                if pair is None:
                    return
                member, stream = pair
                outer = _outer_copy(member)
                yield MemberSpan(
                    outer,
                    data=None
                    if stream is None
                    else _NestedData(
                        cast(BinaryIO, stream), collector, first, member, outer
                    ),
                )
        finally:
            with collector.member_ids_from(first):
                reader.close()

    def _link_target_unavailable(
        self,
        member: ArchiveMember,
        reason: str,
        message: str,
        target_in_archive: bool,
    ) -> None:
        """``ReaderContext.link_target_unavailable``: clear the member's link target
        and report why, held like any report until the member is named."""
        member.link_target = None

        def send(member_id: int | None) -> None:
            self._emit_link_target_unavailable(
                member,
                reason=reason,
                message=message,
                target_in_archive=target_in_archive,
                member_id=member_id,
            )

        if not self._hold_report(member, send):
            send(self._member_id(member))

    @override
    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        # A plugin that broke the interface is a plugin bug, not a fault in the
        # archive: not offered to the plugin's translator, which may map every
        # ValueError to corruption. Every interface check raises through
        # ``_plugin_bug()``, wherever it runs.
        if isinstance(exc, ArchiveyUsageError) or getattr(exc, _PLUGIN_BUG, False):
            return None
        translated = (
            self._reader.translate_exception(exc) if self._reader_open else None
        )
        return (
            translated
            if translated is not None
            else self._plugin.translate_exception(exc)
        )

    def _member_digests(
        self, member: ArchiveMember, digests: tuple[MemberDigest, ...], method: str
    ) -> tuple[dict[HashAlgorithm, bytes], CustomDigests]:
        """The digests to check: the member's listed ``hashes`` and ``digests``, which
        the plugin's ``method`` returned with the member's data.

        A digest archivey computes itself joins the listed ones, and is published on
        ``member.hashes`` as a built-in format publishes a CRC-32 it reads from a local
        header. When the listing already holds that name with another value, the
        archive stores two values for one checksum (an index and a local header that
        disagree): both are checked, so a read that reaches the end raises for
        whichever does not match, instead of one silently replacing the other. Any
        other digest is computed with the plugin's hasher.
        """
        expected = dict(member.hashes)
        listed = {str(key).lower(): (key, value) for key, value in expected.items()}
        custom: dict[str, tuple[bytes, Callable[[], Hasher]]] = {}
        published: dict[HashAlgorithm, bytes] = {}
        seen: set[str] = set()
        for digest in digests:
            key = digest.name.lower()
            if key in seen:
                self._refuse_digest(
                    digest, method, "which another digest of the member uses"
                )
            seen.add(key)
            algorithm = _ALGORITHMS.get(key)
            if algorithm is not None:
                # Every HashAlgorithm has a hasher of archivey's own (CRC-32, BLAKE2sp).
                built_in = hasher_factory(algorithm)
                assert built_in is not None
                factory = built_in
            elif digest.new is not None:
                factory = digest.new
            else:
                self._refuse_digest(
                    digest, method, "which archivey does not compute, with no hasher"
                )
            if key in listed:
                listed_key, prior = listed[key]
                if hasher_factory(key) is None:
                    # A listed name archivey has no hasher of its own for: the
                    # listed value is checked with the plugin's hasher too. One
                    # archivey can hash (hashlib's ``sha1``) keeps archivey's.
                    del expected[listed_key]
                    custom[key] = (prior, factory)
                if prior != digest.expected:
                    custom[f"{key} from {method}()"] = (digest.expected, factory)
            elif algorithm is not None:
                expected[algorithm] = published[algorithm] = digest.expected
            else:
                custom[key] = (digest.expected, factory)
        if published:
            member.hashes = {**member.hashes, **published}
        return expected, custom

    def _refuse_digest(
        self, digest: MemberDigest, method: str, reason: str
    ) -> NoReturn:
        raise _plugin_bug(
            ValueError(
                f"{type(self._reader).__name__}.{method}() returned a digest "
                f"named {digest.name!r}, {reason}"
            )
        )

    @override
    def _get_archive_info(self) -> ArchiveInfo:
        with self._translated_errors(), self._handle_guard():
            info = self._reader.archive_info()
        cost = self._cost(info)
        # A plugin's keys are its own, namespaced by its format (``"zoo.method"``), so
        # they are not in the inventory of built-in keys and are copied in as data. A
        # built-in format-API reader's keys (``"cpio.variant"``) are in that inventory.
        extra = ArchiveInfoExtra()
        extra.update(info.extra)
        return ArchiveInfo(
            format=self._format,
            format_version=info.format_version,
            is_solid=self._is_solid(info),
            member_count=None,
            comment=info.comment,
            is_encrypted=False,
            is_multivolume=False,
            cost=cost,
            extra=extra,
        )

    def _cost(self, info: ReaderArchiveInfo) -> CostReceipt:
        raise NotImplementedError

    def _is_solid(self, info: ReaderArchiveInfo) -> bool:
        # One compression stream around a sequential format makes it solid, as for a
        # compressed TAR.
        return info.is_solid or self._format.stream is not StreamFormat.UNCOMPRESSED

    def _report_listed(self, member: ArchiveMember, presented: str, index: int) -> None:
        """The reports archivey makes on every member a plugin lists, whatever its
        shape: a name normalization, and a directory that declares data."""
        emit_member_name_normalized(
            self._diagnostics_collector,
            member=member,
            presented_name=presented,
            archive_name=self._archive_name,
            member_id=index,
        )
        if member.type is MemberType.DIRECTORY and member.size:
            # No format gives a directory content: the bytes are delivered by a read and
            # dropped by extraction, as for a built-in format (data model, DR-3).
            self._emit_directory_data_ignored(member, index)

    @override
    def _close_archive(self) -> None:
        try:
            for spans in list(self._nested_iterators):
                cast(Generator[MemberSpan, None, None], spans).close()
            with self._translated_errors(), self._handle_guard():
                self._reader.close()
        finally:
            if self._shared is not None:
                self._shared.close()


class IndexedReaderAdapter(_PluginAdapter):
    """Serves an :class:`~archivey.formats.IndexedReader` through the internal reader
    contract."""

    # The archive's region inside the source, ``[_origin, _region_end)``: set only for
    # a built-in format that ships behind a self-extracting stub (``SFX_MAGIC``), from
    # detection's ``payload_offset`` and ``payload_end`` (``ReadBackend.open_read``).
    # The reader sees the region as its whole source.
    def __init__(
        self, *args: Any, region: tuple[int, int | None] = (0, None), **kwargs: Any
    ) -> None:
        self._origin, self._region_end = region
        super().__init__(*args, **kwargs)

    @override
    def _will_read(self, start: int, end: int) -> None:
        # The reader's offsets count from the region's start.
        super()._will_read(self._origin + start, self._origin + end)

    @override
    def _open_reader(self, context: ReaderContext) -> IndexedReader[Any]:
        source = self._source
        assert source is not None
        region: BinaryIO = source
        if self._origin or self._region_end is not None:
            end = self._region_end
            region = SlicingStream(
                source,
                start=self._origin,
                length=None if end is None else max(0, end - self._origin),
            )
        self._shared = shared = SharedSource(
            region, wrap_handle=self._seek_handle_wrapper()
        )
        plugin_source = ReaderSource(
            self._marked_view, shared.size, source.path, shared.read_at
        )
        plugin = self._plugin
        assert isinstance(plugin, IndexedFormatHandler)
        with self._translated_errors(), self._handle_guard():
            reader = plugin.open(plugin_source, context)
        if not isinstance(reader, IndexedReader):
            self._wrong_reader(reader, "open", "an IndexedReader")
        self._indexed = reader
        self._MEMBER_LIST_UPFRONT = reader.member_list_upfront
        return reader

    def _marked_view(self, start: int, length: int | None) -> BinaryIO:
        """``ReaderSource.view``: a view of the shared source, marked with its span
        for the range hint archivey gives when the view is read as a member's data."""
        shared = self._shared
        assert shared is not None
        view = shared.view(start, length)
        size = view.size
        if size:
            mark_read_span(
                view, functools.partial(self._will_read, start, start + size)
            )
        return view

    @override
    def _cost(self, info: ReaderArchiveInfo) -> CostReceipt:
        return CostReceipt(
            listing_cost=(
                ListingCost.INDEXED
                if self._indexed.member_list_upfront
                else ListingCost.REQUIRES_SCANNING
            ),
            access_cost=AccessCost.SOLID if info.is_solid else AccessCost.DIRECT,
            stream_capability=StreamCapability.SEEKABLE,
            solid_block_count=None,
        )

    @override
    def _walk_members(self) -> Iterator[ArchiveMember]:
        # One boundary and one guard for the whole walk: both are reusable, and
        # building them per member is a measurable part of listing a large archive.
        boundary = self._translated_errors()
        guard = self._handle_guard()
        tracker = self._listing_tracker
        tracker.release_held()
        with boundary, guard:
            # A plain function (not a generator) lists, and may hold, in this call.
            self._walk_step = _LISTING
            try:
                records = iter(self._indexed.iter_members())
            finally:
                self._walk_step = None
        try:
            yield from self._walk_records(records, boundary, guard)
        except BaseException:
            self._close_steps(records, guard)
            raise

    def _walk_records(
        self,
        records: Iterator[object],
        boundary: AbstractContextManager[object],
        guard: AbstractContextManager[object],
    ) -> Iterator[ArchiveMember]:
        """The members of the plugin's ``iter_members()`` steps, typed and named."""
        index = 0
        tracker = self._listing_tracker
        while True:
            self._walk_index = index
            with boundary, guard:
                record = self._walk_next(records)
            if record is _END:
                return
            if not isinstance(record, MemberRecord):
                raise _plugin_bug(
                    TypeError(
                        f"{type(self._reader).__name__}.iter_members() yielded "
                        f"{type(record).__name__}, not a MemberRecord"
                    )
                )
            member = record.member
            if not isinstance(member, ArchiveMember):
                raise _plugin_bug(
                    TypeError(
                        f"{type(self._reader).__name__}.iter_members() yielded "
                        f"{type(member).__name__}, not an ArchiveMember"
                    )
                )
            # A held member is counted as listed from here on, not twice.
            tracker.release_member(member)
            member._raw = record.locator
            self._name_member(member, index)
            index += 1
            yield member

    def _plugin_member_data(self, member: ArchiveMember) -> tuple[MemberData, BinaryIO]:
        """Call the plugin's ``open_member``: its data, and its stream as archivey reads
        it, full-count and under the handle lock."""
        with self._translated_errors(member.name), self._handle_guard():
            data = self._indexed.open_member(member, member._raw)
        if not isinstance(data, MemberData):
            raise _plugin_bug(
                TypeError(
                    f"{type(self._reader).__name__}.open_member() returned "
                    f"{type(data).__name__}, not MemberData"
                )
            )
        if data.ranges:
            self._hint_ranges(data)
        else:
            # A view, or a decoder over one, says its span itself.
            hint = read_span_hint(data.stream)
            if hint is not None:
                hint()
        stream = cast(BinaryIO, data.stream)
        if not data.bounded and _bounded(stream, member.size):
            data = data._replace(bounded=True)
        if not _reads_full(stream):
            stream = FullCountStream(stream)
        if self._handle_lock is not None:
            stream = LockedStream(stream, self._handle_lock)
        return data, stream

    def _hint_ranges(self, data: MemberData) -> None:
        """Pass ``MemberData.ranges`` to the source, as the planner's hints. The first
        ``MAX_PENDING_HINTS`` are kept: the planner holds no more at once."""
        ranges = data.ranges
        if not ranges:
            return
        if not isinstance(ranges, tuple) or not all(
            isinstance(r, tuple)
            and len(r) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in r)
            for r in ranges
        ):
            with suppress(Exception):
                data.stream.close()
            raise _plugin_bug(
                TypeError(
                    f"{type(self._reader).__name__}.open_member() returned "
                    f"MemberData.ranges={ranges!r}, not a tuple of (start, end) ints"
                )
            )
        for start, end in ranges[:MAX_PENDING_HINTS]:
            self._will_read(start, end)

    @override
    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        data, stream = self._plugin_member_data(member)
        # Until the parts take the stream over, a raise here (a refused digest name,
        # a hasher factory that fails) leaves archivey owing it a close.
        try:
            expected, custom_digests = (
                self._member_digests(member, data.digests, "open_member")
                if data.digests
                else (member.hashes, None)
            )
            rewind: RewindWarning | None = None
            if self._seek_declared() and not is_seekable(stream):
                # The caller asked for seekable members and the plugin's stream reads
                # forward only: a forward seek reads through, and a backward one
                # opens the member again from the start (``open_member`` once more).
                # With no listed size, a seek from the end reads through to find it.
                stream = RespawnStream(
                    lambda: self._plugin_member_data(member)[1],
                    stream,
                    size=member.size,
                    what=f"{self._format.display_name} member data",
                )
                rewind = RewindWarning(
                    codec_name=self._format.display_name, suggest_install=False
                )
            return self._member_parts(
                stream,
                member.name,
                size=member.size,
                # A listed size is enforced, so a short stream raises TruncatedError
                # and a long one CorruptionError. A file listed with no size is read
                # to the end of its stream, and only its digests are checked.
                expected_size=member.size,
                expected_hashes=expected or None,
                verify_member=member,
                fill_size=member.size is None,
                checks_content=data.checked,
                bounded=data.bounded,
                custom_digests=custom_digests or None,
                rewind_warning=rewind,
            )
        except BaseException:
            stream.close()
            raise


_PUBLIC_MEMBER_FIELDS = tuple(
    f.name for f in fields(ArchiveMember) if not f.name.startswith("_")
)


def _outer_copy(member: ArchiveMember) -> ArchiveMember:
    """A nested reader's member as the outer listing takes it: its public fields
    and what was reported on it so far. The inner reader keeps its own object, whose
    internal state it reads again (TAR's span, at the end of its walk)."""
    copy = ArchiveMember(
        **{
            name: getattr(member, name)
            for name in _PUBLIC_MEMBER_FIELDS
            if name != "link_target_member"
        }
    )
    copy.extra = type(member.extra)(member.extra)
    copy.hashes = dict(member.hashes)
    copy._diagnostics = member._diagnostics
    # The inner listing settled the target (an empty one it reported): the outer
    # listing does not look for it in the data, nor report it again.
    copy._link_target_resolved = member._link_target_resolved
    return copy


class SpanningCheck:
    """A check over the data of several members that a built-in reader runs itself,
    such as a makeself payload's MD5, which covers every file of the TAR in it.

    The reader calls :meth:`cover` on each member the check covers before yielding
    it, and :meth:`passed` or :meth:`failed` once the check ran. Until it passes, a
    covered file's ``verifiable`` is ``CHECKSUM``, as for a ``.tar.gz`` trailer; a
    pass raises every covered file to ``CHECKSUM``, read or not, and a failure makes
    each one a failure of ``verify_all()``. A walk that stops before the check runs
    leaves the covered files as failures too (``_note_spanning_unreachable``).
    """

    __slots__ = ("_adapter", "_covers", "_key")

    def __init__(self, adapter: _PluginAdapter, key: object) -> None:
        self._adapter = adapter
        self._key = key
        self._covers: list[ArchiveMember] = []

    def cover(self, member: ArchiveMember) -> None:
        """Count ``member`` as covered, if it is a file: other members have no data."""
        if member.is_file:
            mark_spanning_checksum(member)
            self._covers.append(member)

    def passed(self) -> None:
        """The check matched: every covered file is checked."""
        self._adapter._spanning_check_ran(self._key)
        for member in self._covers:
            raise_member_level(member, Verification.CHECKSUM, Verification.CHECKSUM)

    def failed(self, message: str) -> SpanningCheckError:
        """The check did not match. Returns the error for the reader to raise; every
        later ``verify_all()`` returns each covered file with it."""
        error = SpanningCheckError(message, covers=tuple(self._covers))
        error.archive_name = self._adapter._archive_name
        # Kept until a later walk passes the check: a read of a covered member that
        # stops before the payload's end does not run it again.
        self._adapter._spanning_unreachable[self._key] = error
        return error


class _NestedData(io.RawIOBase):
    """An inner member's data (``ReaderContext.open_nested``): what the inner reader
    reports while it is read names the member as the outer listing numbers it."""

    # What close() reads, set before __init__ runs.
    _stream: BinaryIO | None = None

    def __init__(
        self,
        stream: BinaryIO,
        collector: DiagnosticCollector,
        first: int,
        inner: ArchiveMember,
        outer: ArchiveMember,
    ) -> None:
        self._stream = stream
        self._collector = collector
        self._first = first
        # What the inner reader attaches to its member while the data is read is
        # attached to the member the caller holds too.
        self._inner = inner
        self._outer = outer
        self._seen = len(inner._diagnostics)

    def _pass_on_diagnostics(self) -> None:
        attached = self._inner._diagnostics
        if len(attached) > self._seen:
            outer = self._outer
            new = outer._diagnostics + attached[self._seen :]
            object.__setattr__(outer, "_diagnostics", new)
            self._seen = len(attached)

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, buffer: Any) -> int:
        stream = self._stream
        assert stream is not None
        try:
            with self._collector.member_ids_from(self._first):
                data = stream.read(len(buffer))
        finally:
            self._pass_on_diagnostics()
        buffer[: len(data)] = data
        return len(data)

    @override
    def close(self) -> None:
        if not self.closed:
            try:
                stream = self._stream
                if stream is not None:
                    with self._collector.member_ids_from(self._first):
                        stream.close()
                    self._pass_on_diagnostics()
            finally:
                super().close()


class _Walk:
    """One walk of the archive: the layer it reads now (the archive's, or the last
    stream it decompressed), and, in random access, the buffered views it opened, one
    per layer. The listing walk is one; a walk started to reach a member's decoded
    data again (``_DataWalk``) is another, with views of its own."""

    __slots__ = ("layer", "views")

    def __init__(self) -> None:
        self.layer: _Layer | None = None
        self.views: list[BinaryIO] = []

    def close(self) -> None:
        views, self.views = self.views, []
        for view in reversed(views):
            view.close()


class _Layer:
    """One stream a walk reads: the archive's bytes, or the decoded bytes of a
    compression stream the walk started with ``ForwardStream.decompress``.

    ``forward`` is the walk's stream over it. ``stream`` is what ``forward`` reads: the
    streaming buffer, or a random-access walk's own view. ``shared`` (random access
    only) gives member data views of it, at the offsets ``forward`` counts.
    """

    __slots__ = ("forward", "shared", "stream")

    def __init__(self, stream: BinaryIO, shared: SharedSource | None) -> None:
        self.stream = stream
        self.shared = shared
        self.forward: ForwardStream


class _Span:
    """Where a sequential member's data is, on its ``_raw``: ``length`` bytes from
    ``offset`` of its layer's stream, with the digests its header stored; or, for a
    member the reader decodes itself (``MemberSpan.data``), that stream (``decoded``)."""

    __slots__ = ("custom", "decoded", "expected", "layer", "length", "offset")

    def __init__(
        self,
        layer: _Layer,
        offset: int,
        length: int,
        expected: Mapping[HashAlgorithm, bytes] | None,
        custom: CustomDigests | None,
        decoded: _Decoded | None = None,
    ) -> None:
        self.layer = layer
        self.offset = offset
        self.length = length
        self.expected = expected
        self.custom = custom
        self.decoded = decoded


def _named(details: DiagnosticContext, name: str) -> DiagnosticContext:
    """``details`` naming its member ``name``, when it names a member."""
    if getattr(details, "member_name", None) is None:
        return details
    return _with_fields(details, {"member_name": name})


def _with_fields(
    details: DiagnosticContext, fields: Mapping[str, object]
) -> DiagnosticContext:
    """``details`` with ``fields`` replaced: only fields the caller checked
    ``details`` has (``getattr``). ``DiagnosticContext`` is a union of dataclasses,
    some without those fields, so ``replace`` is called on it as ``Any``."""
    if not fields:
        return details
    return cast(DiagnosticContext, replace(cast(Any, details), **fields))


def _listed_name(span: MemberSpan) -> str:
    """The name archivey lists a span's member by: the same in the listing walk
    (``_name_member``) and in every walk started over."""
    member = span.member
    return normalize_member_name(member.name, member.type, backslash_is_separator=False)


def _full_count(data: BinaryIO | io.RawIOBase) -> BinaryIO:
    """``data`` as archivey reads a reader's stream: full-count."""
    stream = cast(BinaryIO, data)
    return stream if _reads_full(stream) else FullCountStream(stream)


def _read_up_to(decoded: _Decoded, n: int) -> bytes:
    """Up to ``n`` bytes of ``decoded``, fewer only at its end."""
    chunks: list[bytes] = []
    left = n
    while left and (chunk := decoded.read(left)):
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


class _Decoded:
    """A member's decoded data as the reader handed it over (``MemberSpan.data``):
    good until the walk that yielded it moves on, when :meth:`finish` reads what is
    left of it and closes it. ``index`` is the member's place in the walk, where a
    walk started over finds it again; ``size`` (the listed one) and ``name`` are the
    member's, for the drain."""

    __slots__ = (
        "checked",
        "consumed",
        "done",
        "index",
        "name",
        "prefix",
        "size",
        "stream",
    )

    def __init__(
        self,
        stream: BinaryIO,
        checked: bool,
        index: int,
        size: int | None,
        name: str,
    ) -> None:
        self.stream = stream
        self.checked = checked
        self.index = index
        self.size = size
        self.name = name
        # Bytes read so far, by the caller or the drain.
        self.consumed = 0
        # The decoded bytes of the members before it in the listing walk: what a walk
        # started over decodes to reach it.
        self.prefix = 0
        self.done = False

    def read(self, n: int) -> bytes:
        if self.done:
            raise ArchiveyUsageError(
                "member data is no longer readable: the pass has moved on"
            )
        data = self.stream.read(n)
        self.consumed += len(data)
        return data

    def finish(self) -> None:
        """Read what the caller left, so the reader's library is past it, and close
        the stream. A listed ``size`` caps the read at one byte past it: data longer
        than that raises ``CorruptionError``."""
        if self.done:
            return
        size = self.size
        try:
            while True:
                want = _SKIP_BY_READING
                if size is not None:
                    want = min(want, size + 1 - self.consumed)
                    if want <= 0:
                        break
                if not self.read(want):
                    break
            if size is not None and self.consumed > size:
                raise CorruptionError(
                    f"the decoded data of {quoted(self.name)} is longer than its listed "
                    f"size of {size} bytes"
                )
        finally:
            self.close()

    def close(self) -> None:
        self.done = True
        self.stream.close()


# A forward skip up to this many bytes reads them through the walk's buffer; a longer
# one seeks, when the stream can.
_SKIP_BY_READING = 64 * 1024
# The walk's read buffer: headers are small reads.
_WALK_BUFFER = 64 * 1024


class _BlockingReads:
    """A ``read`` that refuses a non-blocking stream's ``None`` (``read_blocking``),
    as the inner of ``read_within_reach``."""

    __slots__ = ("read",)

    def __init__(self, read: Callable[[int], bytes]) -> None:
        self.read = read


# What one read of header bytes may ask the walk's stream for at a time. A header read
# larger than this is served in steps of it, so a size field that lies costs at most
# one step more than the bytes the stream really has (``tar_parser.READ_STEP`` is the
# same size).
_HEADER_READ_STEP = 64 * 1024


class _ForwardInput(ReadOnlyIOStream):
    """A compression stream that starts part-way through a streaming walk: the rest of
    the walk's buffer, read forward. Each read takes what the buffer holds or one
    read of what has arrived, never a full count, so a codec fed from it does not wait
    on a pipe whose writer keeps it open (TAR's rule)."""

    def __init__(self, stream: BinaryIO) -> None:
        super().__init__()
        # The walk's buffer: archivey's ReadAheadStream (over a codec, or a parent
        # layer) or a BufferedReader over the source's arrived view.
        self._stream = stream

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        n = check_read_size(n)
        if n == 0:
            return b""
        n = n if n > 0 else _WALK_BUFFER
        stream = self._stream
        if isinstance(stream, ReadAheadStream):
            return stream.read_arrived(n)
        return read_arrived(stream, n)


class _SpanWindow(ReadOnlyIOStream):
    """A streaming pass's member data: the next bytes of the walk's own stream, good
    while the walk is at them. The walk's stream ends early only where the archive
    does, so a read that ends before the span keeps the full-count rule (ADR 0014),
    as :class:`MemberDataView` does for a view: a sized read returns the bytes before
    the cut and the next read raises ``TruncatedError``, and a read with no size
    raises. For a member the walk sizes the span is its whole data, so no read goes
    past it and the member needs no size check of its own; a directory that lists a
    size it does not store is checked above the window (``_span_parts``). ``what``
    names the archive in the error."""

    def __init__(self, forward: ForwardStream, span: _Span, what: str) -> None:
        super().__init__()
        self._forward = forward
        self._span = span
        self._what = what
        self._done = 0

    @override
    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._done

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed member stream")
        n = check_read_size(n)
        span = self._span
        if self._forward.offset != span.offset + self._done:
            raise ArchiveyUsageError(
                "member data is no longer readable: the pass has moved on"
            )
        whole = n < 0
        left = span.length - self._done
        want = left if whole else min(n, left)
        if want <= 0:
            return b""
        if not whole:
            data = self._forward.read(want)
            self._done += len(data)
            if not data:
                raise self._cut()
            return data
        # A read with no size goes on after a short read, so that an error the walk's
        # stream holds for its next read (a ratio guard's refusal, after the bytes
        # before it) comes out as itself; only a stream that has ended is a cut.
        chunks: list[bytes] = []
        while left > 0:
            chunk = self._forward.read(left)
            if not chunk:
                raise self._cut()
            chunks.append(chunk)
            self._done += len(chunk)
            left -= len(chunk)
        return b"".join(chunks)

    def _cut(self) -> TruncatedError:
        return TruncatedError(
            f"{self._what} is truncated inside a member's data at offset "
            f"{self._span.offset + self._done}"
        )


class _DecodedWindow(ReadOnlyIOStream):
    """A member's decoded data read through the walk that yielded it: good while the
    walk is at it, as :class:`_SpanWindow` is. Closing it leaves the data to the
    walk, which drains and closes it when it moves on."""

    def __init__(self, decoded: _Decoded) -> None:
        super().__init__()
        self._decoded = decoded
        self._done = 0

    @override
    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._done

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed member stream")
        n = check_read_size(n)
        if n >= 0:
            data = self._decoded.read(n)
            self._done += len(data)
            return data
        chunks = []
        while chunk := self._decoded.read(_SKIP_BY_READING):
            chunks.append(chunk)
        data = b"".join(chunks)
        self._done += len(data)
        return data


class _DataWalk:
    """A walk started over to reach a member's decoded data again (random access):
    its views, the reader's walk, the next member's index and the data it handed out
    last, which the next step drains."""

    __slots__ = ("current", "next_index", "spans", "walk")

    def __init__(self, walk: _Walk, spans: Iterator[MemberSpan]) -> None:
        self.walk = walk
        self.spans = spans
        self.next_index = 0
        self.current: _Decoded | None = None

    def close(self) -> None:
        try:
            if self.current is not None:
                self.current.close()
        finally:
            try:
                close = getattr(self.spans, "close", None)
                if close is not None:
                    close()
            finally:
                self.walk.close()


class _DataWalkStream(ReadOnlyIOStream):
    """A member's decoded data reached by a walk of its own. Closing it hands the
    walk back to the adapter, so a member opened next, further on, carries on from
    here instead of walking from the start again."""

    def __init__(
        self, adapter: SequentialReaderAdapter, walk: _DataWalk, decoded: _Decoded
    ) -> None:
        # Assigned before the base __init__: close() reads them.
        self._adapter: SequentialReaderAdapter | None = adapter
        self._walk = walk
        self._window = _DecodedWindow(decoded)
        super().__init__()

    @override
    def tell(self) -> int:
        return self._window.tell()

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed member stream")
        return self._window.read(n)

    @override
    def close(self) -> None:
        adapter, self._adapter = self._adapter, None
        if adapter is not None:
            self._window.close()
            adapter._return_data_walk(self._walk)
        super().close()


class SequentialReaderAdapter(_PluginAdapter):
    """Serves a :class:`~archivey.formats.SequentialReader`: its walk is the member
    walk, and member data is a window of the walk's stream (a streaming pass) or a
    view of the source at the offset the walk recorded (random access)."""

    _MEMBER_LIST_UPFRONT = False

    @override
    def _open_reader(self, context: ReaderContext) -> SequentialReader:
        plugin = self._plugin
        assert isinstance(plugin, SequentialFormatHandler)
        source = self._source
        assert source is not None
        # Streaming: the buffer the walk reads through, made here, so closed here.
        self._owned_stream: BinaryIO | None = None
        # The listing walk: the layer it reads now and its own views (``_new_walk``).
        self._listing_walk = _Walk()
        # The layer of the member a streaming pass yielded last.
        self._forward: ForwardStream | None = None
        # The decoded data (``MemberSpan.data``) of the member the listing walk
        # yielded last, until the walk moves on.
        self._listing_decoded: _Decoded | None = None
        # Random access: an idle walk started over to reach decoded data, kept so a
        # member opened next, further on, carries on from it (``_decoded_by_walk``).
        self._data_walk_lock = threading.Lock()
        self._idle_data_walk: _DataWalk | None = None
        # Streams ``ForwardStream.decompress`` opened, closed with the reader. Random
        # access keeps each layer's codec and views by where it starts, so a walk
        # started over reads through the ones it opened before.
        self._layer_streams: list[BinaryIO] = []
        self._layer_sources: dict[
            tuple[int, int, StreamFormat | PluginStream], SharedSource
        ] = {}
        # What the walk decodes on the reader's behalf, held to
        # ``decoder_limits.max_ratio`` while listing too (``_ratio_guarded``): the
        # layers' decoded bytes, each layer by its number, and the members' decoded
        # data (``MemberSpan.data``), each by its place in the walk. A walk started
        # over decodes the same bytes again and adds nothing.
        self._layer_ratio_tally = ReadRatioTally()
        self._layer_count = 0
        self._decoded_ratio_tally = ReadRatioTally()
        # A compressed pair (``.cpio.gz``): the codec stream the walk and the member
        # data read, as TAR's (``_open_outer_codec_stream``). The walk sees decoded
        # bytes only.
        self._codec_stream: BinaryIO | None = None
        self._compressed = self._format.stream is not StreamFormat.UNCOMPRESSED
        try:
            self._open_streams(source, member_streams=self._member_streams)
        except BaseException:
            self._release_streams()
            raise
        try:
            with self._translated_errors(), self._handle_guard():
                reader = plugin.open_sequential(context)
            if not isinstance(reader, SequentialReader):
                self._wrong_reader(reader, "open_sequential", "a SequentialReader")
            self._reader = self._sequential = reader
            self._reader_open = True
            # The first step of the walk is taken now, so a file that is not one of
            # the format's archives fails to open (DR-15b), as a TAR does.
            walk = self._new_walk()
            with self._translated_errors(), self._handle_guard():
                first = self._walk_next(walk)
            self._open_walk: tuple[Iterator[MemberSpan], object] | None = (
                walk,
                first,
            )
        except BaseException:
            # The reader is closed as _close_archive closes it: reader, then streams.
            # A failing close() must not replace the error being raised.
            try:
                if self._reader_open:
                    self._reader_open = False
                    with suppress(Exception), self._handle_guard():
                        self._sequential.close()
            finally:
                self._release_streams()
                if self._shared is not None:
                    self._shared.close()
            raise
        return reader

    def _open_streams(
        self, source: ArchiveSource, *, member_streams: MemberStreams
    ) -> None:
        """Open what the walk reads: a buffer over the source (streaming) or views of
        it (random access), over the decoded bytes when the format is compressed."""
        if self._streaming:
            # The walk and the member windows read one stream, as a TAR pass does.
            self._handle_lock = self._handle_lock or threading.Lock()
        if self._compressed:
            codec = self._codec_stream = self._open_outer_codec_stream(
                source,
                self._format.stream,
                self._streaming,
                member_streams=member_streams,
            )
            if self._streaming:
                # The walk reads small headers: a buffer in front makes each one a
                # copy from memory, not a decoder call. On a source that cannot seek,
                # the codec reads what has arrived, and so does this buffer (TAR's
                # rule).
                self._owned_stream = ReadAheadStream(
                    codec, _WALK_BUFFER, fill_arrived=not source.seekable()
                )
            else:
                # Each walk buffers its own view (_new_walk), and member data is a
                # view too: a read that is not where the decoder is seeks it, which
                # decodes again from the start when it goes back (a solid archive).
                self._shared = SharedSource(codec)
            return
        if self._streaming:
            # On a pipe, the buffer fills from what has arrived, so a short archive
            # whose writer keeps the pipe open opens at once (TAR's rule).
            raw = source if source.seekable() else cast(BinaryIO, source.arrived_view())
            self._owned_stream = cast(
                BinaryIO, ensure_bufferedio(self._track_source_seeks(raw))
            )
        else:
            self._shared = SharedSource(source, wrap_handle=self._seek_handle_wrapper())

    def _new_walk(self, walk: _Walk | None = None) -> Iterator[MemberSpan]:
        """A walk from the start of the archive, over a stream of its own: the listing
        walk, or ``walk`` (random access only)."""
        if walk is None:
            # Only one listing walk runs at a time: one started over replaces the last
            # one's views, and its member's decoded data.
            decoded, self._listing_decoded = self._listing_decoded, None
            try:
                if decoded is not None:
                    decoded.close()
            finally:
                self._listing_walk.close()
            walk = self._listing_walk = _Walk()
        if self._streaming:
            stream = self._owned_stream
            assert stream is not None
            layer = _Layer(stream, None)
            # Read forward only: the source may not start at offset 0 of its handle.
            walk.layer = self._layer_forward(walk, layer, seekable=False)
        else:
            assert self._shared is not None
            walk.layer = self._random_access_layer(
                walk, self._shared, compressed=self._compressed
            )
        forward = walk.layer.forward
        with self._translated_errors(), self._handle_guard():
            # A walk() that is not a generator steps, and may hold, in this call.
            self._walk_step = _LISTING if walk is self._listing_walk else _REWALK
            try:
                return iter(self._sequential.walk(forward))
            finally:
                self._walk_step = None

    def _random_access_layer(
        self, walk: _Walk, shared: SharedSource, *, compressed: bool
    ) -> _Layer:
        """A layer over ``shared`` with a view of its own for ``walk``."""
        # A plain file: a read larger than the buffer rewinds the prefetched tail and
        # returns the file's own bytes. A codec keeps the join, since rewinding it
        # would decode the tail again; and a skip reads through it, which is what a
        # seek of the decoder would do, and finds where the data ends.
        view = ReadAheadStream(
            shared.view(0, None), _WALK_BUFFER, rewind_oversize=not compressed
        )
        walk.views.append(view)
        return self._layer_forward(walk, _Layer(view, shared), seekable=not compressed)

    def _layer_forward(self, walk: _Walk, layer: _Layer, *, seekable: bool) -> _Layer:
        """Give ``layer`` the walk's ``ForwardStream`` over its stream."""
        stream = layer.stream
        size = layer.shared.size if layer.shared is not None else None

        def skip(offset: int, n: int) -> None:
            end = offset + n
            if seekable and n > _SKIP_BY_READING and (size is None or end <= size):
                if size is not None:
                    stream.seek(end)
                    return
                # A size not known: a seek past the end would not fail, and the next
                # header would read as the end of the archive. Read the last byte
                # skipped; when it is not there, read through from ``offset`` to
                # raise at the cut.
                stream.seek(end - 1)
                if read_blocking(stream, 1):
                    return
                stream.seek(offset)
            left = n
            while left:
                chunk = read_blocking(stream, min(left, _SKIP_BY_READING))
                if not chunk:
                    raise TruncatedError(
                        f"the archive ends at offset {end - left}, inside the {n} "
                        f"bytes from offset {offset}"
                    )
                left -= len(chunk)

        # Each step refuses a ``None`` read, as ``skip`` does: ``read_within_reach`` takes
        # its inner's results as bytes.
        refusing = cast(
            "ReadableStream", _BlockingReads(functools.partial(read_blocking, stream))
        )

        def read(n: int) -> bytes:
            # A walk reads header bytes a size field of the archive asked for, so the
            # read must not allocate what the field says before the stream shows it
            # has the bytes (threat model, "Allocations sized by a header field").
            # A plain file of known size clamps the read to what is left, as ``skip``
            # trusts that size: no step copies, so a large honest table (an ar ``//``
            # member) costs one buffer, not the steps and their join.
            remaining = size - stream.tell() if seekable and size is not None else None
            return read_within_reach(
                refusing, n, remaining=remaining, step=_HEADER_READ_STEP
            )

        layer.forward = ForwardStream(
            read,
            skip,
            functools.partial(self._decompress_layer, walk, layer),
        )
        return layer

    def _decompress_layer(
        self,
        walk: _Walk,
        parent: _Layer,
        offset: int,
        stream_format: StreamFormat | PluginStream,
    ) -> ForwardStream:
        """``ForwardStream.decompress``: a layer over the decoded bytes of the
        compression stream that starts at ``offset`` of ``parent``, which becomes the
        layer ``walk`` reads."""
        stream_codec = single_file_codec(stream_format)
        codec = stream_codec.codec if stream_codec is not None else None
        if codec is None:
            raise _plugin_bug(
                ValueError(
                    f"ForwardStream.decompress() takes a compression stream format, "
                    f"got {stream_format!r}"
                )
            )
        self._refuse_codec_off_by_policy(stream_format)
        # The member decoder's config (same limits), except that the stream runs to
        # the end of the archive, as a .gz file's does: bytes after its end are
        # reported, as bytes after an archive's end are, not refused. The decoded
        # bytes are held to the ratio below (``_ratio_guarded``), since listing
        # decodes all of them.
        config = replace(
            self._decoder_config,
            refuse_input_after_end=False,
            report_trailing_data=True,
            # The container's members are read through this stream, several small
            # ones to one read: a failing call that lost its bytes would take whole
            # members with it. So it recovers them whatever the caller set.
            recover_partial_data=True,
        )
        if self._streaming:
            # The parent is done (the ForwardStream that called this refuses reads
            # now), so the codec reads its buffer straight on, one read of what has
            # arrived each time: outermost, so the codec puts no full-count buffer in
            # front of it (as _codec_input does for an outer stream).
            raw = _ForwardInput(parent.stream)
            decoded = open_codec_stream(
                codec,
                OneReadEachStream(self._wrap_compressed_input(raw)),
                config=config,
                stamp=self._stamp_error_context,
                collector=self._diagnostics_collector,
            )
            self._layer_streams.append(decoded)
            decoded = self._guarded_layer(decoded)
            assert self._source is not None
            buffered = ReadAheadStream(
                decoded, _WALK_BUFFER, fill_arrived=not self._source.seekable()
            )
            self._layer_streams.append(buffered)
            layer = self._layer_forward(walk, _Layer(buffered, None), seekable=False)
        else:
            assert parent.shared is not None
            # The parent's source is held for the reader's life (``self._shared``, or
            # this table), so its id cannot be reused while the key is in use.
            key = (id(parent.shared), offset, stream_format)
            shared = self._layer_sources.get(key)
            if shared is None:
                view = parent.shared.view(offset, None)
                self._layer_streams.append(view)
                decoded = open_codec_stream(
                    codec,
                    self._wrap_compressed_input(view),
                    config=config,
                    stamp=self._stamp_error_context,
                    collector=self._diagnostics_collector,
                    # Read only through views, as a compressed TAR's codec is.
                    repeat_verdict=False,
                )
                self._layer_streams.append(decoded)
                shared = self._layer_sources[key] = SharedSource(
                    self._guarded_layer(decoded)
                )
            layer = self._random_access_layer(walk, shared, compressed=True)
        walk.layer = layer
        return layer.forward

    def _guarded_layer(self, decoded: BinaryIO) -> BinaryIO:
        """A ``decompress()`` layer's decoded stream, held to the ratio with the
        walk's other layers (a layer opened inside another adds to its count)."""
        self._layer_count += 1
        return self._ratio_guarded(decoded, self._layer_ratio_tally, self._layer_count)

    def _ratio_guarded(
        self, stream: BinaryIO, tally: ReadRatioTally, key: int
    ) -> BinaryIO:
        """``stream``, bytes the walk decodes, held to ``decoder_limits.max_ratio`` of
        the archive's size in every use, listing included, as
        ``_open_outer_codec_stream`` holds an outer compression stream (an
        ``extract_all`` call's ratio governing its own decodes). Its bytes count
        toward ``tally`` as ``key``'s."""
        limits = self._ratio_limits()
        if limits.max_ratio is None:
            return stream
        return DecodeRatioGuard(
            stream,
            limits=limits,
            static_size=self._trusted_source_size(),
            consumed=self._live_consumed(),
            tally=tally,
            key=key,
            run_limits=self._run_ratio_limits,
        )

    @override
    def _walk_members(self) -> Iterator[ArchiveMember]:
        boundary = self._translated_errors()
        guard = self._handle_guard()
        tracker = self._listing_tracker
        if self._open_walk is not None:
            walk, span = self._open_walk
            self._open_walk = None
        else:
            # The holds of a walk abandoned part-way go with it.
            tracker.release_held()
            walk = self._new_walk()
            self._walk_index = 0
            with boundary, guard:
                span = self._walk_next(walk)
        try:
            yield from self._walk_spans(walk, span, boundary, guard)
        except BaseException:
            self._close_steps(walk, guard)
            raise

    def _walk_spans(
        self,
        walk: Iterator[object],
        span: object,
        boundary: AbstractContextManager[object],
        guard: AbstractContextManager[object],
    ) -> Iterator[ArchiveMember]:
        """The members of the plugin's ``walk()`` steps, from ``span`` on."""
        index = 0
        # Decoded bytes of the members walked so far (``_Decoded.prefix``).
        prefix = 0
        while span is not _END:
            self._walk_index = index
            # The layer the walk read this span's header from: a decompress() in the
            # step that yielded it moved the walk onto a new one.
            layer = self._listing_walk.layer
            assert layer is not None
            forward = self._forward = layer.forward
            member = self._take_span(span, layer, index)
            record = member._raw
            assert isinstance(record, _Span)
            decoded = self._listing_decoded = record.decoded
            if decoded is not None:
                decoded.prefix = prefix
            try:
                yield member
            except BaseException:
                # The walk is abandoned here (the generator closed): the data the
                # reader handed over is not read on.
                if decoded is not None:
                    self._listing_decoded = None
                    with suppress(Exception), guard:
                        decoded.close()
                raise
            index += 1
            self._walk_index = index
            if decoded is not None:
                self._listing_decoded = None
                with self._translated_errors(member.name), guard:
                    decoded.finish()
                prefix += decoded.consumed
                with boundary, guard:
                    span = self._walk_next(walk)
                continue
            with boundary, guard:
                left = record.offset + record.length - forward.offset
                # A read through the member's window or the link target's stops at
                # the data's end, so the walk is never past it.
                assert left >= 0, (record.offset, record.length, forward.offset)
                if left:
                    forward.skip(left)
                span = self._walk_next(walk)
        self._raise_members_the_codec_checked()

    def _raise_members_the_codec_checked(self) -> None:
        """Raise every listed file to ``CHECKSUM`` once the walk ends at the end of an
        outer codec whose whole-stream checksum matched (a ``.cpio.gz`` trailer).

        That checksum covers every decoded byte, so a member whose data is a slice of
        those bytes is checked, read or not. Data a reader decodes itself
        (``MemberSpan.data``) or a layer it starts with ``ForwardStream.decompress``
        is decoded again from those bytes, so it is left to its own reads. A walk
        cut short raises nothing. When the walk ended without that proof because a
        frame has no check, the members marked as covered fall to what their own
        reads reach (``drop_spanning_ceiling``). When the codec has a check and the
        walk did not reach it, most likely because the archive ends early, that is
        treated as damage: they keep the ceiling and are failures of every later
        ``verify_all()`` (``_note_spanning_unreachable``).
        """
        codec = self._codec_stream
        if codec is None:
            return
        proofs = ask_verification_proofs(codec)
        if not (proofs.ended and proofs.content):
            if proofs.frame_unchecked or not proofs.content_possible:
                # A frame with no check: no read of this archive can check every
                # byte, so the members marked as covered fall to what their own
                # reads reach. That is the format, not damage.
                for member in self._listed:
                    drop_spanning_ceiling(member, Verification.LENGTH)
            else:
                # The check exists but this walk did not reach it, most likely
                # because the archive ends early. Treated as damage: the ceiling
                # stays and the covered members are failures of verify_all().
                self._note_spanning_unreachable("codec", self._listed, None)
            return
        self._spanning_check_ran("codec")
        for member in self._listed:
            if self._codec_covers(member):
                raise_member_level(member, Verification.CHECKSUM, Verification.CHECKSUM)

    def _codec_covers(self, member: ArchiveMember) -> bool:
        """Whether ``member``'s data is a slice of the outer codec's decoded bytes,
        which that codec's whole-stream checksum covers."""
        record = member._raw
        outer = self._owned_stream if self._streaming else self._shared
        return (
            member.is_file
            and self._member_data_is_stream_bytes(member)
            and isinstance(record, _Span)
            and (record.layer.stream if self._streaming else record.layer.shared)
            is outer
        )

    def _take_span(self, span: object, layer: _Layer, index: int) -> ArchiveMember:
        """The member a span describes, checked, named and placed."""
        data = span.data if isinstance(span, MemberSpan) else None
        try:
            member = self._take_span_checked(span, layer, index)
        except BaseException:
            # Archivey owns the decoded data once yielded: a refused span closes it.
            if data is not None:
                with suppress(Exception), self._handle_guard():
                    data.close()
            raise
        codec = self._codec_stream
        if (
            codec is not None
            and self._codec_covers(member)
            and ask_verification_proofs(codec).content_possible
        ):
            # A walk to the end runs the codec's checksum over this member's bytes
            # (``_raise_members_the_codec_checked``).
            mark_spanning_checksum(member)
        return member

    def _take_span_checked(
        self, span: object, layer: _Layer, index: int
    ) -> ArchiveMember:
        """Check a span the plugin's walk yielded against the interface, then name
        its member and record where its data is (``member._raw``)."""
        name = type(self._reader).__name__
        if not isinstance(span, MemberSpan):
            raise _plugin_bug(
                TypeError(
                    f"{name}.walk() yielded {type(span).__name__}, not a MemberSpan"
                )
            )
        member = span.member
        if not isinstance(member, ArchiveMember):
            raise _plugin_bug(
                TypeError(
                    f"{name}.walk() yielded {type(member).__name__}, not an ArchiveMember"
                )
            )
        # A held member is counted as listed from here on, not twice.
        self._listing_tracker.release_member(member)
        length = span.data_length
        if not isinstance(length, int) or length < 0:
            raise _plugin_bug(
                ValueError(
                    f"{name}.walk() yielded {member.name!r} with data_length {length!r}, "
                    "not a whole number of bytes"
                )
            )
        data = span.data
        if data is not None and length:
            raise _plugin_bug(
                ValueError(
                    f"{name}.walk() yielded {member.name!r} with both data and "
                    f"data_length {length}: decoded data has no stored bytes to skip"
                )
            )
        if data is None and span.checked:
            raise _plugin_bug(
                ValueError(
                    f"{name}.walk() yielded {member.name!r} with checked=True and no "
                    "data: stored bytes are checked against the span's digests"
                )
            )
        # A directory's data is its declared size too: it stays a DIRECTORY, a read
        # delivers the bytes and the listing reports them (_report_listed). Decoded
        # data has no stored length to check the size against: its size is the one
        # listed, enforced when read.
        sized = data is None and (
            member.type is MemberType.FILE
            or (member.type is MemberType.DIRECTORY and length)
        )
        if sized:
            if member.size is None:
                member.size = length
            elif member.size != length:
                raise _plugin_bug(
                    ValueError(
                        f"{name}.walk() yielded {member.name!r} with size {member.size} "
                        f"and data_length {length}: a member's data is stored as it is"
                    )
                )
        self._name_member(member, index)
        expected: dict[HashAlgorithm, bytes] | None = None
        custom: CustomDigests | None = None
        if span.digests:
            expected, custom = self._member_digests(member, span.digests, "walk")
        decoded: _Decoded | None = None
        if data is not None:
            stream = self._decoded_stream(data, index)
            decoded = _Decoded(stream, span.checked, index, member.size, member.name)
        forward = layer.forward
        record = _Span(layer, forward.offset, length, expected, custom or None, decoded)
        member._raw = record
        if (
            member.type is MemberType.SYMLINK
            and self._sequential.link_target_in_data
            and member.link_target is None
            and not member._link_target_resolved
        ):
            self._read_link_target(member, decoded, forward, length, index)
        return member

    def _read_link_target(
        self,
        member: ArchiveMember,
        decoded: _Decoded | None,
        forward: ForwardStream,
        length: int,
        index: int,
    ) -> None:
        """Set a symlink's target from its data, for a format that stores it there
        (``SequentialReader.link_target_in_data``), or report it too long."""
        if decoded is not None:
            with self._translated_errors(member.name), self._handle_guard():
                target = _read_up_to(decoded, MAX_LINK_TARGET_BYTES + 1)
            if len(target) > MAX_LINK_TARGET_BYTES:
                self._emit_link_target_too_long(member, member_id=index)
            else:
                member.link_target = target.decode("utf-8", errors="surrogateescape")
        elif length > MAX_LINK_TARGET_BYTES:
            self._emit_link_target_too_long(member, member_id=index)
        else:
            with self._translated_errors(member.name), self._handle_guard():
                target = forward.read_exact(length)
            member.link_target = target.decode("utf-8", errors="surrogateescape")

    @override
    def _pass_reads_through_walk(self) -> bool:
        """A random-access pass reads through the walk until it ends, so a
        compressed archive (``.cpio.gz``, or one a walk decompresses part-way) is
        decoded once for the headers and the data, not once for each."""
        return True

    @override
    def _member_data_is_stream_bytes(self, member: ArchiveMember) -> bool:
        # A span's ``data_length`` bytes are stored as they are (CPIO, ar). A member
        # the reader decodes itself (``MemberSpan.data``) is compressed on its own.
        record = member._raw
        return isinstance(record, _Span) and record.decoded is None

    @override
    def _open_member_in_walk(self, member: ArchiveMember) -> MemberStreamParts:
        record = member._raw
        assert isinstance(record, _Span), "a sequential member is missing its span"
        decoded = record.decoded
        if decoded is not None:
            with self._walk_lock:
                # The window reads the plugin's stream, so under CONCURRENT it takes
                # the handle lock as every call into the plugin does (walk steps take
                # it inside _walk_lock, in the same order).
                window = (
                    self._plugin_locked(_DecodedWindow(decoded))
                    if self._decoded_in_place(decoded)
                    else None
                )
                stream = self._walk_handoff_locked(
                    window,
                    functools.partial(self._decoded_by_walk, decoded),
                )
            return self._decoded_parts(member, record, decoded, stream)
        shared = record.layer.shared
        assert shared is not None

        def reopen(start: int) -> BinaryIO:
            return self._span_view(record, start)

        # Stored data: _walk_lock, not _handle_guard: the window reads the walk's own
        # stream (not the plugin's, as decoded data above does), which
        # only the walk also reads, and every walk step runs under _walk_lock; the
        # walk detaches this stream before it moves (_before_pull_locked). The views
        # it falls back to are serialized by the SharedSource.
        with self._walk_lock:
            forward = record.layer.forward
            # The walk is at the data's start only while it is on the member's
            # layer: a decompress() in the step after it moved the walk on.
            in_place = (
                self._listing_walk.layer is not None
                and forward is self._listing_walk.layer.forward
                and forward.offset == record.offset
            )
            stream = self._walk_handoff_locked(
                _SpanWindow(forward, record, self._archive_what) if in_place else None,
                reopen,
            )
        return self._span_parts(member, record, stream)

    @override
    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        record = member._raw
        assert isinstance(record, _Span), "a sequential member is missing its span"
        stream: BinaryIO
        decoded = record.decoded
        if decoded is not None:
            rewind: RewindWarning | None = None
            if not self._streaming:
                stream = self._decoded_by_walk(decoded, 0)
                if self._seek_declared():
                    # The caller asked for seekable members: a forward seek reads
                    # through, and a backward one walks again to the member.
                    stream = RespawnStream(
                        lambda: self._decoded_by_walk(decoded, 0),
                        stream,
                        size=member.size,
                        what=f"{self._format.display_name} member data",
                    )
                    rewind = RewindWarning(
                        codec_name=self._format.display_name,
                        suggest_install=False,
                        # A seek back decodes the members before this one again too.
                        min_redecode_bytes=decoded.prefix,
                    )
            elif self._decoded_in_place(decoded):
                assert self._handle_lock is not None
                stream = LockedStream(_DecodedWindow(decoded), self._handle_lock)
            else:
                raise ArchiveyUsageError(
                    f"the data of {quoted(member.name)} is no longer readable: the "
                    "pass has moved on"
                )
            return self._decoded_parts(member, record, decoded, stream, rewind)
        if self._streaming:
            forward = self._forward
            if forward is not record.layer.forward or forward.offset != record.offset:
                raise ArchiveyUsageError(
                    f"the data of {quoted(member.name)} is no longer readable: the "
                    "pass has moved on"
                )
            stream = _SpanWindow(forward, record, self._archive_what)
            assert self._handle_lock is not None
            stream = LockedStream(stream, self._handle_lock)
        else:
            shared = record.layer.shared
            assert shared is not None
            # ``open()``: a plain view, and the listed size checked above it (a
            # MemberDataView here measured slower than the size check).
            stream = shared.view(record.offset, record.length)
            return self._span_parts(member, record, stream, check_size=True)
        return self._span_parts(member, record, stream)

    @functools.cached_property
    def _archive_what(self) -> str:
        # Built once: it is read on every member open, and the format never changes.
        return f"{self._format.display_name} archive"

    def _span_view(self, record: _Span, start: int) -> BinaryIO:
        """``record``'s data from ``start`` for a pass the walk has left: a view that
        raises ``TruncatedError`` at a cut (:class:`MemberDataView`), as the window it
        takes over from does."""
        shared = record.layer.shared
        assert shared is not None
        view = shared.view(record.offset, record.length)
        if start:
            view.seek(start)
        return MemberDataView(
            view, record.offset, record.length, what=self._archive_what
        )

    def _decoded_in_place(self, decoded: _Decoded) -> bool:
        """Whether the listing walk is at the start of ``decoded``: it is the data of
        the member the walk yielded last, and nothing has read it yet."""
        return (
            decoded is self._listing_decoded
            and not decoded.done
            and decoded.consumed == 0
        )

    def _decoded_by_walk(self, decoded: _Decoded, start: int) -> BinaryIO:
        """``decoded``'s data from ``start``, reached by a walk of its own (random
        access): the idle one, when it is not past the member yet, or one from the
        start of the archive. The members before it are read past, as the listing
        walk does: their decoded data drained, their stored data skipped."""
        with self._data_walk_lock:
            data_walk, self._idle_data_walk = self._idle_data_walk, None
        if data_walk is not None and data_walk.next_index > decoded.index:
            self._close_data_walk(data_walk)
            data_walk = None
        try:
            if data_walk is not None:
                current, data_walk.current = data_walk.current, None
                try:
                    if current is not None:
                        with (
                            self._translated_errors(current.name),
                            self._handle_guard(),
                        ):
                            current.finish()
                except ArchiveyError:
                    # Safe to drop: the listing walk drained this member the same
                    # way and would have failed on it, so a member that raises here
                    # was never listed. This open starts over.
                    self._close_data_walk(data_walk)
                    data_walk = None
            if data_walk is None:
                walk = _Walk()
                data_walk = _DataWalk(walk, self._new_walk(walk))
            target = self._walk_to_decoded(data_walk, decoded)
            data_walk.current = target
            data_walk.next_index = decoded.index + 1
            if start:
                # Data that ends before ``start`` is short: the reader of the
                # handed-off stream finds it so (TruncatedError).
                with self._translated_errors(decoded.name), self._handle_guard():
                    _read_up_to(target, start)
            return self._plugin_locked(_DataWalkStream(self, data_walk, target))
        except BaseException:
            if data_walk is not None:
                self._close_data_walk(data_walk)
            raise

    def _walk_to_decoded(self, data_walk: _DataWalk, decoded: _Decoded) -> _Decoded:
        """Step ``data_walk`` to the member ``decoded`` describes and return its data
        as this walk's reader hands it over."""
        walk = data_walk.walk
        # A step reads a header no member is named by yet, as the listing walk's do.
        boundary = self._translated_errors()
        guard = self._handle_guard()
        index = data_walk.next_index
        while True:
            with boundary, guard:
                span = self._walk_next(data_walk.spans, _REWALK)
            if span is _END:
                raise CorruptionError(
                    f"walking the archive again ended before {quoted(decoded.name)}"
                )
            if not isinstance(span, MemberSpan):
                raise _plugin_bug(
                    TypeError(
                        f"{type(self._reader).__name__}.walk() yielded "
                        f"{type(span).__name__}, not a MemberSpan"
                    )
                )
            if not isinstance(span.member, ArchiveMember):
                raise _plugin_bug(
                    TypeError(
                        f"{type(self._reader).__name__}.walk() yielded "
                        f"{type(span.member).__name__}, not an ArchiveMember"
                    )
                )
            data = span.data
            if index == decoded.index:
                try:
                    self._check_rewalked(span, decoded)
                    if data is None:
                        raise CorruptionError(
                            f"walking the archive again found no decoded data for "
                            f"{quoted(decoded.name)}"
                        )
                except BaseException:
                    if data is not None:
                        with suppress(Exception), guard:
                            data.close()
                    raise
                return _Decoded(
                    self._decoded_stream(data, index),
                    span.checked,
                    index,
                    decoded.size,
                    decoded.name,
                )
            # A member on the way, read past under the name it is listed by.
            name = _listed_name(span)
            with self._translated_errors(name), guard:
                if data is not None:
                    _Decoded(
                        self._decoded_stream(data, index),
                        span.checked,
                        index,
                        span.member.size,
                        name,
                    ).finish()
                elif span.data_length:
                    layer = walk.layer
                    assert layer is not None
                    layer.forward.skip(span.data_length)
            index += 1

    def _decoded_stream(self, data: BinaryIO | io.RawIOBase, index: int) -> BinaryIO:
        """A reader's decoded data as archivey reads it: full-count, counted as
        decompressed output, the drain's bytes too (``_decoded_parts`` does not count
        them again), and held to the ratio, the drain too, as the data of the member
        at ``index`` of the walk."""
        return self._ratio_guarded(
            self._track_decompressed(_full_count(data)),
            self._decoded_ratio_tally,
            index,
        )

    def _check_rewalked(self, span: MemberSpan, decoded: _Decoded) -> None:
        """Refuse a walk started over that does not yield, at the member's place, the
        member the listing walk did: ``walk()`` must repeat itself."""
        found = _listed_name(span)
        if found != decoded.name:
            raise _plugin_bug(
                ValueError(
                    f"{type(self._reader).__name__}.walk() yielded {found!r} as member "
                    f"{decoded.index} when walked again, not {decoded.name!r}: a walk must "
                    "yield the same members in the same order each time"
                )
            )

    def _plugin_locked(self, stream: BinaryIO) -> BinaryIO:
        """``stream``, which reads the plugin's, under the handle lock when one is
        set (CONCURRENT)."""
        if self._handle_lock is None:
            return stream
        return LockedStream(stream, self._handle_lock)

    def _return_data_walk(self, data_walk: _DataWalk) -> None:
        """Keep ``data_walk``, whose stream closed, for the next open, unless one is
        kept already. Called from that stream's close, which holds the handle lock
        when one is set (``_plugin_locked``)."""
        with self._data_walk_lock:
            if self._idle_data_walk is None and self._reader_open:
                self._idle_data_walk = data_walk
                return
        self._close_data_walk(data_walk, guard=False)

    def _close_data_walk(self, data_walk: _DataWalk, *, guard: bool = True) -> None:
        """Close ``data_walk``; ``guard=False`` when the caller holds the handle lock
        (the reader's close)."""
        with suppress(Exception), self._handle_guard() if guard else nullcontext():
            data_walk.close()

    def _decoded_parts(
        self,
        member: ArchiveMember,
        record: _Span,
        decoded: _Decoded,
        stream: BinaryIO,
        rewind: RewindWarning | None = None,
    ) -> MemberStreamParts:
        """``member``'s parts over ``stream``, its decoded data."""
        expected = record.expected if record.expected is not None else member.hashes
        return self._member_parts(
            stream,
            member.name,
            size=member.size,
            # A listed size is enforced, so a short stream raises TruncatedError and
            # a long one CorruptionError. A member listed with no size is read to the
            # end of its stream, and only its digests are checked.
            expected_size=member.size,
            expected_hashes=expected or None,
            verify_member=member,
            fill_size=member.size is None,
            checks_content=decoded.checked,
            custom_digests=record.custom,
            rewind_warning=rewind,
            # Counted where it is decoded (``_decoded_stream``), drain included.
            track_output=False,
        )

    def _span_parts(
        self,
        member: ArchiveMember,
        record: _Span,
        stream: BinaryIO,
        *,
        check_size: bool = False,
    ) -> MemberStreamParts:
        """``member``'s parts over ``stream``, its data window or view.

        A pass's window (:class:`_SpanWindow`, or the :class:`MemberDataView` a
        handoff falls back to) raises ``TruncatedError`` at a cut itself, so with no
        digest the member gets no verifier to read through, when its listed size is
        its data length. The walk makes them equal for a file and for a directory
        that stores data: it refuses a span whose listed size differs and fills an
        unset size from it (:meth:`_take_span_checked`). A directory that lists a
        size and stores nothing also gets a stream (``pass_has_data``), and its size
        is checked above the window, as it is for a plain view (``check_size``,
        ``open()``), which ends short at a cut."""
        expected = record.expected if record.expected is not None else member.hashes
        return self._member_parts(
            stream,
            member.name,
            size=member.size,
            expected_size=(
                member.size if check_size or member.size != record.length else None
            ),
            expected_hashes=expected or None,
            verify_member=member,
            # A window and a view both stop at the data's end.
            bounded=True,
            custom_digests=record.custom,
        )

    @override
    def _cost(self, info: ReaderArchiveInfo) -> CostReceipt:
        assert self._source is not None
        capability = (
            StreamCapability.SEEKABLE
            if self._source.seekable()
            else StreamCapability.FORWARD_ONLY
        )
        if self._compressed:
            # One compression stream over all members, as a compressed TAR. A walk
            # that decompresses part-way is not known to until it gets there, so its
            # plugin says so up front with ``ReaderArchiveInfo.is_solid``.
            return CostReceipt(
                listing_cost=ListingCost.REQUIRES_DECOMPRESSION,
                access_cost=AccessCost.SOLID,
                stream_capability=capability,
                solid_block_count=1,
            )
        # A sequential plugin declares is_solid when its members share one decode
        # (compression that starts part-way), so the later headers sit inside it.
        return CostReceipt(
            listing_cost=(
                ListingCost.REQUIRES_DECOMPRESSION
                if info.is_solid
                else ListingCost.REQUIRES_SCANNING
            ),
            access_cost=AccessCost.SOLID if info.is_solid else AccessCost.DIRECT,
            stream_capability=capability,
            solid_block_count=None,
        )

    def _release_streams(self) -> None:
        """Close the streams this adapter made. Safe to call more than once."""
        try:
            with self._data_walk_lock:
                idle, self._idle_data_walk = self._idle_data_walk, None
            if idle is not None:
                self._close_data_walk(idle, guard=False)
            decoded, self._listing_decoded = self._listing_decoded, None
            if decoded is not None:
                with suppress(Exception):
                    decoded.close()
            self._listing_walk.close()
        finally:
            try:
                if self._owned_stream is not None:
                    owned, self._owned_stream = self._owned_stream, None
                    owned.close()
            finally:
                try:
                    # Innermost first: a layer reads the one it was opened over.
                    streams, self._layer_streams = self._layer_streams, []
                    self._layer_sources.clear()
                    # Every stream is closed even when one close raises. The first
                    # error propagates and each later one is added to it as a note:
                    # ExitStack would keep only the last, with no __context__.
                    first: Exception | None = None
                    for stream in reversed(streams):
                        try:
                            stream.close()
                        except Exception as err:  # noqa: BLE001 — re-raised after the rest close
                            if first is None:
                                first = err
                            else:
                                first.add_note(
                                    "closing another layer failed: "
                                    + exception_detail(err, with_type=True)
                                )
                    if first is not None:
                        raise first
                finally:
                    if self._codec_stream is not None:
                        codec, self._codec_stream = self._codec_stream, None
                        codec.close()

    @override
    def _close_archive(self) -> None:
        # A walk taken at open and never listed is still suspended in the plugin's
        # walk(): finish it first, so its own cleanup runs before close() and over an
        # open stream, not later in the collector. It never ran in _iter_members, so
        # the reports its first step held are sent here, as for a walk stopped
        # part-way: recorded, never raised.
        try:
            if self._open_walk is not None:
                close = getattr(self._open_walk[0], "close", None)
                self._open_walk = None
                try:
                    if close is not None:
                        with self._translated_errors(), self._handle_guard():
                            close()
                finally:
                    self._send_unyielded_reports(may_raise=False)
        finally:
            try:
                super()._close_archive()
            finally:
                with self._handle_guard():
                    self._release_streams()


# Set on an error that reports a plugin breaking the interface, so the plugin's own
# ``translate_exception`` is not offered it (``_PluginAdapter._translate_exception``).
_PLUGIN_BUG = "_archivey_plugin_bug"

# What ``next()`` returns at the end of a plugin's iterator, where ``None`` would hide a
# ``None`` the plugin yields: that one reaches the type checks and is reported.
_END = object()

_ErrorT = TypeVar("_ErrorT", bound=Exception)


def _plugin_bug(error: _ErrorT) -> _ErrorT:
    """``error``, marked as a plugin breaking the interface (:data:`_PLUGIN_BUG`).

    Every interface check raises through this, so a check that runs inside an error
    boundary is not reported as a fault in the archive by a plugin's broad
    ``translate_exception``, and one that runs outside a boundary today stays right if
    a later change moves it inside one.
    """
    setattr(error, _PLUGIN_BUG, True)
    return error


# The ``MemberDigest`` names archivey computes itself, with its own hasher.
_ALGORITHMS = {str(algorithm): algorithm for algorithm in HashAlgorithm}

# The methods ``ReaderContext.decompress`` decodes. PPMd, the branch filters and RAR
# need parameters or framing a plain method name cannot carry.
_PLUGIN_CODECS: dict[CompressionAlgorithm, Codec] = {
    CompressionAlgorithm.STORED: Codec.STORED,
    CompressionAlgorithm.DEFLATE: Codec.DEFLATE,
    CompressionAlgorithm.DEFLATE64: Codec.DEFLATE64,
    CompressionAlgorithm.BZIP2: Codec.BZIP2,
    CompressionAlgorithm.ZSTD: Codec.ZSTD,
    CompressionAlgorithm.LZ4: Codec.LZ4,
    CompressionAlgorithm.BROTLI: Codec.BROTLI,
    CompressionAlgorithm.LZMA: Codec.LZMA,
    CompressionAlgorithm.LZMA2: Codec.LZMA2,
    CompressionAlgorithm.XZ: Codec.XZ,
    CompressionAlgorithm.LZO: Codec.LZO,
}


class _PluginBackend(ReadBackend):
    """Base of the backend class :func:`register_plugin` builds for each plugin."""

    PLUGIN: ClassVar[type[FormatHandler]]

    @override
    def open_read(
        self,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        passwords: _PasswordCandidates | None,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
        start_offset: int = 0,
        end_offset: int | None = None,
        program_resources: ProgramResources | None = None,
    ) -> _PluginAdapter:
        common = (
            self.PLUGIN(),
            source,
            format,
            streaming,
            encoding if self.USES_ENCODING else None,
            archive_name,
            config,
        )
        options: dict[str, Any] = {
            "collector": collector,
            "member_streams": member_streams,
            "open_site": open_site,
        }
        if issubclass(self.PLUGIN, SequentialFormatHandler):
            reject_start_offset(
                start_offset, format, archive_name, end_offset, program_resources
            )
            return SequentialReaderAdapter(*common, **options)
        # Only a built-in format that declares SFX magic is handed a region, which its
        # reader reads as the whole source (``IndexedReaderAdapter``).
        if not self.SFX_MAGIC:
            reject_start_offset(
                start_offset, format, archive_name, end_offset, program_resources
            )
        return IndexedReaderAdapter(
            *common, region=(start_offset, end_offset), **options
        )


def prefix_probe(probe: object) -> ContentProbe:
    """Adapt a plugin's ``probe(prefix)`` to the registry's probe shape.

    The plugin gets the peeked prefix only: no ``read_at`` and no decode allowance, so
    it cannot make detection read more of an untrusted source.
    """
    assert callable(probe)
    # Per registration, so the probe need not be hashable and nothing outlives it.
    warned = False

    def content_probe(
        prefix: bytes,
        /,
        *,
        source_length: int | None = None,
        read_at: Callable[[int, int], bytes | None] | None = None,
        charge_decode: Callable[[int], bool] | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
        decoder_limits: DecoderLimits = DecoderLimits(),
    ) -> bool:
        nonlocal warned
        # A probe that raises (a struct.unpack past a short prefix, say) is no match:
        # one plugin must not change how unrelated input fails to be detected. Out of
        # memory and OS errors are not the probe's parsing, and propagate as everywhere.
        try:
            return bool(probe(prefix))
        except (MemoryError, OSError):
            raise
        except Exception:  # noqa: BLE001 — any parsing error is a plugin bug, logged
            # WARNING the first time, so its author sees the bug; DEBUG after that, so
            # a bad plugin does not flood every detection.
            detection_logger.log(
                logging.DEBUG if warned else logging.WARNING,
                "plugin probe %r raised; taken as no match",
                probe,
                exc_info=True,
            )
            warned = True
            return False

    return content_probe


def _check_plugin(plugin: type[FormatHandler]) -> ArchiveFormat:
    """Refuse a handler ``register_format`` cannot take, before anything is
    registered; return its format.

    The handler must be one of the two shapes, with a new :class:`PluginContainer`
    and an ``UNCOMPRESSED`` stream. Its ``format=`` spellings and extensions (with a
    sequential format's compressed pairs) must be new, so registering it never
    changes what an existing spelling or extension means.
    """
    if not (
        isinstance(plugin, type)
        and issubclass(plugin, (IndexedFormatHandler, SequentialFormatHandler))
    ):
        raise ArchiveyUsageError(
            "register_format() takes an IndexedFormatHandler or a "
            f"SequentialFormatHandler subclass, got {plugin!r}"
        )
    fmt = getattr(plugin, "format", None)
    if not isinstance(fmt, ArchiveFormat):
        raise ArchiveyUsageError(
            f"{plugin.__name__}.format must be an ArchiveFormat, got {fmt!r}"
        )
    if not isinstance(fmt.container, PluginContainer):
        raise ArchiveyUsageError(
            f"{plugin.__name__}.format must use a PluginContainer member as its "
            f"container, got {fmt.container!r}"
        )
    sequential = issubclass(plugin, SequentialFormatHandler)
    if fmt.stream != StreamFormat.UNCOMPRESSED:
        raise ArchiveyUsageError(
            f"{plugin.__name__}.format must have an UNCOMPRESSED stream: "
            + (
                "archivey adds the compressed forms of a sequential format itself"
                if sequential
                else "an indexed format inside a compression stream is not supported"
            )
        )
    registry = get_registry()
    if registry.registered_reader(fmt) is not None:
        raise ArchiveyUsageError(f"Format {fmt.display_name} is already registered")
    value = fmt.container.value
    if value in {c.value for c in ContainerFormat}:
        raise ArchiveyUsageError(
            f"{plugin.__name__}: container value {value!r} is a built-in format's"
        )
    for other in registry.list_known_formats():
        if isinstance(other.container, PluginContainer) and (
            other.container.value == value
        ):
            raise ArchiveyUsageError(
                f"{plugin.__name__}: container value {value!r} is already used by "
                f"{other.display_name}"
            )
    for each in (fmt, *(compressed_formats(fmt) if sequential else ())):
        clash = plugin_spelling_clash(each)
        if clash is not None:
            spelling, owner = clash
            raise ArchiveyUsageError(
                f"{plugin.__name__}: format= spelling {spelling!r} already names "
                f"{owner.display_name}; choose a container value and member name no "
                "format uses"
            )
    for ext in plugin.extensions:
        if not ext.startswith(".") or len(ext) < 2:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: extension {ext!r} must be a dot followed by at "
                "least one character"
            )
    claimed = {ext.lower(): owner for ext, owner in registry.extension_map().items()}
    for ext in _extensions(plugin, fmt, sequential=sequential):
        owner = claimed.get(ext.lower())
        if owner is not None:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: extension {ext!r} is already claimed by "
                f"{owner.display_name}"
            )
    for magic in plugin.magic:
        if magic.offset < 0 or not magic.data:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: magic {magic!r} needs a non-negative offset "
                "and at least one byte"
            )
        end = magic.offset + len(magic.data)
        if sequential and end > INNER_CONTAINER_PROBE_BYTES:
            # Detection finds a sequential format inside a compression stream by this
            # magic, in the bytes it already decodes for TAR's: one that ends later
            # would make it decode more.
            raise ArchiveyUsageError(
                f"{plugin.__name__}: magic {magic!r} ends at byte {end}; a sequential "
                f"format's magic must end within the first {INNER_CONTAINER_PROBE_BYTES} "
                "bytes"
            )
    if plugin.probe is not None and not callable(plugin.probe):
        raise ArchiveyUsageError(f"{plugin.__name__}.probe must be callable or None")
    check_requires(plugin.__name__, plugin.requires)
    return fmt


def check_requires(name: str, requires: object) -> None:
    """Refuse a handler's ``requires`` given as one string, which would be read as one
    module per character. Shared by ``register_format`` and ``register_codec``."""
    if isinstance(requires, str):
        raise ArchiveyUsageError(f"{name}.requires must be a tuple of module names")


def compressed_formats(fmt: ArchiveFormat) -> tuple[ArchiveFormat, ...]:
    """``fmt`` inside each single-file compression stream archivey decodes now, as
    ``TAR_GZ`` is TAR inside gzip."""
    return tuple(
        ArchiveFormat(fmt.container, codec.stream_format)
        for codec in single_file_codecs()
        if codec.stream_format is not None
    )


def _extensions(
    plugin: type[FormatHandler], fmt: ArchiveFormat, *, sequential: bool
) -> dict[str, ArchiveFormat]:
    """The plugin's extensions, and for a sequential format each one followed by a
    compression stream's (``.cpio`` gives ``.cpio.gz``, ``.cpio.xz``, …)."""
    extensions = dict.fromkeys(plugin.extensions, fmt)
    if sequential:
        for codec in single_file_codecs():
            if codec.stream_format is None:
                continue
            pair = ArchiveFormat(fmt.container, codec.stream_format)
            for ext in plugin.extensions:
                for codec_ext in codec.extensions:
                    extensions[f"{ext}{codec_ext}"] = pair
    return extensions


# The built-in containers a plugin can replace (``FormatPolicy(replace=)``): the ones an
# indexed plugin can read. TAR, ar, CPIO and RAW_STREAM read in one pass, DIRECTORY is
# not a file, and DMG is recognised only to be refused.
REPLACEABLE_CONTAINERS = frozenset(
    {
        ContainerFormat.ZIP,
        ContainerFormat.SEVEN_Z,
        ContainerFormat.RAR,
        ContainerFormat.ISO,
        ContainerFormat.SQUASHFS,
        ContainerFormat.XAR,
        ContainerFormat.CAB,
        ContainerFormat.LHA,
        ContainerFormat.ARJ,
    }
)


def check_replacement(container: object, plugin: object) -> None:
    """Refuse a ``FormatPolicy(replace={container: plugin})`` entry that cannot be used.

    Run when the policy is built, so a bad plugin fails before any open.
    """
    call = "FormatPolicy(replace=…)"
    if not isinstance(container, ContainerFormat):
        raise _UsageTypeError(
            f"{call} takes ContainerFormat keys, got {container!r} "
            f"({type(container).__name__})."
        )
    if container not in REPLACEABLE_CONTAINERS:
        names = ", ".join(
            sorted(f"ContainerFormat.{c.name}" for c in REPLACEABLE_CONTAINERS)
        )
        raise _UsageValueError(
            f"{call} cannot replace ContainerFormat.{container.name}; it takes {names}."
        )
    if isinstance(plugin, type) and issubclass(plugin, SequentialFormatHandler):
        raise _UsageValueError(
            f"{call}: {plugin.__name__} is a SequentialFormatHandler; a replacement "
            "reads an indexed container and subclasses IndexedFormatHandler."
        )
    if not (isinstance(plugin, type) and issubclass(plugin, IndexedFormatHandler)):
        raise _UsageTypeError(
            f"{call} takes an IndexedFormatHandler subclass for ContainerFormat."
            f"{container.name}, got {plugin!r}."
        )
    name = plugin.__name__
    expected = ArchiveFormat(container, StreamFormat.UNCOMPRESSED)
    fmt = getattr(plugin, "format", None)
    if fmt != expected:
        raise _UsageValueError(
            f"{call}: {name}.format must be {expected!r} to replace "
            f"ContainerFormat.{container.name}, got {fmt!r}."
        )
    if plugin.extensions or plugin.magic or plugin.probe is not None:
        raise _UsageValueError(
            f"{call}: {name} declares extensions, magic or a probe. A replacement is "
            "found by the built-in detection and declares none."
        )


@functools.cache
def replacement_backend(plugin: type[FormatHandler]) -> type[ReadBackend]:
    """The backend that reads a built-in container with ``plugin``, built once per
    plugin class. It is not registered, so detection never sees it."""
    return _backend_class(plugin, plugin.format, {})


def _backend_class(
    plugin: type[FormatHandler], fmt: ArchiveFormat, overrides: Mapping[str, object]
) -> type[_PluginBackend]:
    """The :class:`ReadBackend` subclass that reads ``fmt`` with ``plugin``.

    It translates the handler's public declarations into the class attributes the
    registry and detection read (``FORMATS``, ``EXTENSIONS``, ``MAGIC``,
    ``CONTENT_PROBES``, ...), and its ``open_read`` builds the adapter. ``overrides``
    sets attributes a plugin cannot declare (:func:`register_builtin_format`).
    """
    probe = plugin.probe
    sequential = issubclass(plugin, SequentialFormatHandler)
    magic = tuple(MagicSignature(m.offset, m.data, fmt) for m in plugin.magic)
    attrs: dict[str, object] = {
        "PLUGIN": plugin,
        "FORMATS": (fmt,),
        # A sequential format reads through every single-file compression stream;
        # the registry makes those pairs, so a codec registered later has one too.
        "STREAM_PAIRS": sequential,
        "PAIR_EXTENSIONS": tuple(plugin.extensions) if sequential else (),
        "EXTENSIONS": dict.fromkeys(plugin.extensions, fmt),
        "MAGIC": magic,
        "INNER_MAGIC": magic if sequential else (),
        "CONTENT_PROBES": (((fmt, prefix_probe(probe)),) if probe is not None else ()),
        "USES_ENCODING": bool(plugin.uses_encoding),
        # A sequential format reads a pipe in a streaming pass, so it has no reason
        # to refuse one.
        "SUPPORTS_STREAMING_NON_SEEKABLE": sequential,
        **(
            {}
            if sequential
            else {
                # Not sequential, so indexed: ``_check_plugin`` and
                # ``check_replacement`` admit no other shape.
                "NON_SEEKABLE_REASON": cast(
                    "type[IndexedFormatHandler]", plugin
                ).non_seekable_reason
                or "its reader needs random access to the archive"
            }
        ),
        "INSTALL_HINT": plugin.install_hint,
        "REQUIRED_MODULES": tuple(plugin.requires),
        **overrides,
    }
    return type(f"{plugin.__name__}Backend", (_PluginBackend,), attrs)


def register_plugin(plugin: type[FormatHandler]) -> None:
    """Build the backend class for ``plugin`` and register it (``register_format``)."""
    fmt = _check_plugin(plugin)
    backend = _backend_class(plugin, fmt, {})
    get_registry().register_plugin_backend(backend)
    for each in (fmt, *(compressed_formats(fmt) if backend.STREAM_PAIRS else ())):
        add_plugin_spellings(each)


def registered_plugins() -> tuple[type[FormatHandler], ...]:
    """The plugins :func:`register_plugin` registered, in registration order."""
    backends = get_registry().plugin_backends()
    return tuple(cast("type[_PluginBackend]", cls).PLUGIN for cls in backends)


def register_builtin_format(
    plugin: type[FormatHandler], **overrides: object
) -> type[ReadBackend]:
    """Register a built-in format whose reader is written against ``archivey.formats``.

    The format keeps its built-in container, extensions, magic and place among the
    built-in backends, so detection does not change and ``FormatInfo.from_plugin`` is
    false. A sequential format's compressed pairs are spelled as a plugin's are
    (``"ar.gz"``). ``overrides`` sets backend attributes a plugin cannot declare
    (``OPTIONAL_DEPENDENCY``, ``INSTALL_HINT``). Returns the backend class.
    """
    backend = _backend_class(plugin, plugin.format, overrides)
    get_registry().register_reader(backend)
    if issubclass(plugin, SequentialFormatHandler):
        container = plugin.format.container
        assert isinstance(container, ContainerFormat), (
            "a built-in has a named container"
        )
        add_sequential_container(container)
        # Its compressed pairs (``ar.gz``) have no named constant.
        format_args.PAIR_SPELLED_CONTAINERS.add(container)
        for each in compressed_formats(plugin.format):
            add_plugin_spellings(each)
    return backend


@contextmanager
def registration_scope() -> Generator[None]:
    """Undo, on exit, every :func:`register_plugin` and ``register_codec`` made
    inside it.

    ``register_format`` is permanent by design, so this is for tests. It restores each
    table :func:`register_plugin` writes; a table that function comes to write is saved
    here too, next to the others.
    """
    registry = get_registry()
    restore_registry = registry.save_plugin_state()
    restore_codecs = save_codec_state()
    spellings = dict(format_args._plugin_spellings)
    try:
        yield
    finally:
        restore_registry()
        restore_codecs()
        registry.codecs_changed()
        format_args._plugin_spellings.clear()
        format_args._plugin_spellings.update(spellings)
