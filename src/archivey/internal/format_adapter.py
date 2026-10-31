"""The adapter between ``archivey.formats`` and the internal reader machinery.

A format reader does not subclass :class:`BaseArchiveReader`. Two subclasses serve every
one, built-in or plugin: :class:`IndexedReaderAdapter` implements the four abstract methods by calling an
:class:`~archivey.formats.IndexedReader`, and :class:`SequentialReaderAdapter` by
walking a :class:`~archivey.formats.SequentialReader`, so the walk, the passes, link
handling and extraction stay internal (the ``plugin-api`` OpenSpec change, design §1
and §2a).

:func:`register_plugin` builds one :class:`ReadBackend` subclass per plugin and
registers it after the built-in backends, so a built-in signal always wins (§4).
:func:`register_builtin_format` builds one for a built-in format, registered with the
other built-in backends.
"""

from __future__ import annotations

import functools
import io
import logging
import lzma
import threading
from collections.abc import Callable, Generator, Iterator, Mapping
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import replace
from typing import Any, BinaryIO, ClassVar, NoReturn, cast

from archivey.config import ArchiveyConfig, ProcessIsolation
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
    IndexedReader,
    MemberData,
    MemberDigest,
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
from archivey.internal.registry import ContentProbe, get_registry
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
from archivey.internal.streams.streamtools.binaryio import read_blocking
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
        context = ReaderContext(
            encoding=encoding,
            archive_name=archive_name,
            config=config,
            decompress=self._decompress,
            report=self._report,
            link_target_unavailable=self._link_target_unavailable,
        )
        self._reader = self._open_reader(context)
        self._reader_open = True

    def _open_reader(self, context: ReaderContext) -> FormatReader:
        """Call the plugin's ``open``, and check what it returned."""
        raise NotImplementedError

    def _wrong_reader(self, reader: object, method: str, noun: str) -> NoReturn:
        # Each check that the plugin kept to the interface sits outside the error
        # boundary, so a plugin's broad ``translate_exception`` cannot report a plugin
        # bug as a fault in the archive.
        raise TypeError(
            f"{type(self._plugin).__name__}.{method}() returned "
            f"{type(reader).__name__}, not {noun}"
        )

    def _decompress(
        self,
        data: BinaryIO,
        method: CompressionAlgorithm | AnyStreamFormat,
        size: int | None,
        properties: bytes | None,
    ) -> BinaryIO:
        """``ReaderContext.decompress``: ``data`` through archivey's codec layer."""
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
        # Only a bzip2 member is one stream, as in ZIP and 7z: a further stream after
        # its end is refused. Zstd and LZ4 data may be several frames, read together
        # (RFC 8878, the LZ4 frame format), and the other codecs read no flag. A
        # stream format is read as a file of that format is, so a ``.bz2`` stream may
        # hold several, as bzip2 itself decodes them.
        params = CodecParams(single_stream=codec is Codec.BZIP2 and not is_stream)
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
        # Per call, as ZIP fills them per member (``_member_decoder_config``): the
        # output size, and the input size while ``data`` is at its start. The
        # accelerators choose by them, and rapidgzip's length check needs the first.
        changes: dict[str, Any] = {"expected_decompressed_size": size}
        if is_stream:
            # A whole stream reads as a file of its format does: bytes after its end
            # are reported (``ARCHIVE_TRAILING_DATA``), not refused. Most stream
            # codecs have no refusal; the report is what they all share.
            changes["refuse_input_after_end"] = False
            changes["report_trailing_data"] = True
        if not is_seekable(data) or data.tell() == 0:
            input_size = source_byte_size(data)
            if input_size is not None:
                changes["compressed_input_size"] = input_size
        return open_codec_stream(
            codec,
            data,
            config=copy_with(self._decoder_config, **changes),
            params=params,
            collector=self._diagnostics_collector,
        )

    def _member_id(self, member: ArchiveMember | None) -> int | None:
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
        fill: dict[str, object] = {}
        if getattr(details, "archive_name", "") is None:
            fill["archive_name"] = self._archive_name
        if getattr(details, "member_id", "") is None and member is not None:
            fill["member_id"] = self._member_id(member)
        self._diagnostics_collector.emit(
            code=code,
            message=message,
            context=replace(details, **fill) if fill else details,  # type: ignore[type-var]
            member=member,
            attach_to_member=member is not None,
        )

    def _link_target_unavailable(
        self,
        member: ArchiveMember,
        reason: str,
        message: str,
        target_in_archive: bool,
    ) -> None:
        member.link_target = None
        self._emit_link_target_unavailable(
            member,
            reason=reason,
            message=message,
            target_in_archive=target_in_archive,
            member_id=self._member_id(member),
        )

    @override
    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        # A plugin that broke the interface is a plugin bug, not a fault in the
        # archive: not offered to the plugin's translator, which may map every
        # ValueError to corruption. These are raised from inside the walk, so the
        # boundary cannot sit outside them as it does for _wrong_reader's checks.
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
        raise ValueError(
            f"{type(self._reader).__name__}.{method}() returned a digest "
            f"named {digest.name!r}, {reason}"
        )

    @override
    def _get_archive_info(self) -> ArchiveInfo:
        with self._translated_errors(), self._handle_guard():
            info = self._reader.archive_info()
        cost = self._cost(info)
        # A plugin's keys are its own, namespaced by its format (``"lha.method"``), so
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
            with self._translated_errors(), self._handle_guard():
                self._reader.close()
        finally:
            if self._shared is not None:
                self._shared.close()


class IndexedReaderAdapter(_PluginAdapter):
    """Serves an :class:`~archivey.formats.IndexedReader` through the internal reader
    contract."""

    @override
    def _open_reader(self, context: ReaderContext) -> IndexedReader[Any]:
        source = self._source
        assert source is not None
        self._shared = shared = SharedSource(
            source, wrap_handle=self._seek_handle_wrapper()
        )
        plugin_source = ReaderSource(
            shared.view, shared.size, source.path, shared.read_at
        )
        with self._translated_errors(), self._handle_guard():
            reader = self._plugin.open(plugin_source, context)
        if not isinstance(reader, IndexedReader):
            self._wrong_reader(reader, "open", "an IndexedReader")
        self._indexed = reader
        self._MEMBER_LIST_UPFRONT = reader.member_list_upfront
        return reader

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
    def _iter_members(self) -> Iterator[ArchiveMember]:
        # One boundary and one guard for the whole walk: both are reusable, and
        # building them per member is a measurable part of listing a large archive.
        boundary = self._translated_errors()
        guard = self._handle_guard()
        with boundary, guard:
            records = iter(self._indexed.iter_members())
        index = 0
        while True:
            self._walk_index = index
            with boundary, guard:
                record = next(records, None)
            if record is None:
                return
            member = record.member
            if not isinstance(member, ArchiveMember):
                raise TypeError(
                    f"{type(self._reader).__name__}.iter_members() yielded "
                    f"{type(member).__name__}, not an ArchiveMember"
                )
            # A reader that reports while listing normalizes the name itself, and
            # hands over the one it started from.
            presented = (
                record.stored_name if record.stored_name is not None else member.name
            )
            member.name = normalize_member_name(
                presented, member.type, backslash_is_separator=False
            )
            member._raw = record.locator
            self._report_listed(member, presented, index)
            index += 1
            yield member

    def _plugin_member_data(self, member: ArchiveMember) -> tuple[MemberData, BinaryIO]:
        """Call the plugin's ``open_member``: its data, and its stream as archivey reads
        it, full-count and under the handle lock."""
        with self._translated_errors(member.name), self._handle_guard():
            data = self._indexed.open_member(member, member._raw)
        if not isinstance(data, MemberData):
            raise TypeError(
                f"{type(self._reader).__name__}.open_member() returned "
                f"{type(data).__name__}, not MemberData"
            )
        stream = cast(BinaryIO, data.stream)
        if not data.bounded and _bounded(stream, member.size):
            data = data._replace(bounded=True)
        if not _reads_full(stream):
            stream = FullCountStream(stream)
        if self._handle_lock is not None:
            stream = LockedStream(stream, self._handle_lock)
        return data, stream

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


class _Walk:
    """One walk of the archive: the layer it reads now (the archive's, or the last
    stream it decompressed), and, in random access, the buffered views it opened, one
    per layer. The listing walk is one; a walk started to reach a member's decoded
    data again (``_DataWalks``) is another, with views of its own."""

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


def _span_names(span: MemberSpan) -> tuple[str, str]:
    """The name a span's member was presented by, and the one archivey lists it by:
    the same in the listing walk and in every walk started over."""
    member = span.member
    presented = span.stored_name if span.stored_name is not None else member.name
    return presented, normalize_member_name(
        presented, member.type, backslash_is_separator=False
    )


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
        data = self._forward.read(want)
        self._done += len(data)
        if len(data) < want and (whole or not data):
            raise TruncatedError(
                f"{self._what} is truncated inside a member's data at offset "
                f"{span.offset + self._done}"
            )
        return data


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
                first = next(walk, None)
            self._open_walk: tuple[Iterator[MemberSpan], MemberSpan | None] | None = (
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
            return iter(self._sequential.walk(forward))

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
                stream.seek(end)
                return
            left = n
            while left:
                chunk = read_blocking(stream, min(left, _SKIP_BY_READING))
                if not chunk:
                    raise TruncatedError(
                        f"the archive ends at offset {end - left}, inside the {n} "
                        f"bytes from offset {offset}"
                    )
                left -= len(chunk)

        layer.forward = ForwardStream(
            functools.partial(read_blocking, stream),
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
            error = ValueError(
                f"ForwardStream.decompress() takes a compression stream format, got "
                f"{stream_format!r}"
            )
            setattr(error, _PLUGIN_BUG, True)
            raise error
        # The member decoder's config (same limits, same ratio guard), except that the
        # stream runs to the end of the archive, as a .gz file's does: bytes after its
        # end are reported, as bytes after an archive's end are, not refused.
        config = replace(
            self._decoder_config,
            refuse_input_after_end=False,
            report_trailing_data=True,
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
                shared = self._layer_sources[key] = SharedSource(decoded)
            layer = self._random_access_layer(walk, shared, compressed=True)
        walk.layer = layer
        return layer.forward

    @override
    def _iter_members(self) -> Iterator[ArchiveMember]:
        boundary = self._translated_errors()
        guard = self._handle_guard()
        if self._open_walk is not None:
            walk, span = self._open_walk
            self._open_walk = None
        else:
            walk = self._new_walk()
            self._walk_index = 0
            with boundary, guard:
                span = next(walk, None)
        index = 0
        # Decoded bytes of the members walked so far (``_Decoded.prefix``).
        prefix = 0
        while span is not None:
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
                    span = next(walk, None)
                continue
            with boundary, guard:
                left = record.offset + record.length - forward.offset
                # A read through the member's window or the link target's stops at
                # the data's end, so the walk is never past it.
                assert left >= 0, (record.offset, record.length, forward.offset)
                if left:
                    forward.skip(left)
                span = next(walk, None)

    def _take_span(self, span: object, layer: _Layer, index: int) -> ArchiveMember:
        """The member a span describes, checked, named and placed."""
        data = span.data if isinstance(span, MemberSpan) else None
        try:
            return self._take_span_checked(span, layer, index)
        except BaseException:
            # Archivey owns the decoded data once yielded: a refused span closes it.
            if data is not None:
                with suppress(Exception), self._handle_guard():
                    data.close()
            raise

    def _take_span_checked(
        self, span: object, layer: _Layer, index: int
    ) -> ArchiveMember:
        name = type(self._reader).__name__
        if not isinstance(span, MemberSpan):
            raise TypeError(
                f"{name}.walk() yielded {type(span).__name__}, not a MemberSpan"
            )
        member = span.member
        if not isinstance(member, ArchiveMember):
            raise TypeError(
                f"{name}.walk() yielded {type(member).__name__}, not an ArchiveMember"
            )
        length = span.data_length
        if not isinstance(length, int) or length < 0:
            raise ValueError(
                f"{name}.walk() yielded {member.name!r} with data_length {length!r}, "
                "not a whole number of bytes"
            )
        data = span.data
        if data is not None and length:
            raise ValueError(
                f"{name}.walk() yielded {member.name!r} with both data and "
                f"data_length {length}: decoded data has no stored bytes to skip"
            )
        if data is None and span.checked:
            raise ValueError(
                f"{name}.walk() yielded {member.name!r} with checked=True and no "
                "data: stored bytes are checked against the span's digests"
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
                raise ValueError(
                    f"{name}.walk() yielded {member.name!r} with size {member.size} "
                    f"and data_length {length}: a member's data is stored as it is"
                )
        presented, member.name = _span_names(span)
        expected: dict[HashAlgorithm, bytes] | None = None
        custom: CustomDigests | None = None
        if span.digests:
            expected, custom = self._member_digests(member, span.digests, "walk")
        decoded: _Decoded | None = None
        if data is not None:
            stream = self._decoded_stream(data)
            decoded = _Decoded(stream, span.checked, index, member.size, member.name)
        forward = layer.forward
        record = _Span(layer, forward.offset, length, expected, custom or None, decoded)
        member._raw = record
        self._report_listed(member, presented, index)
        if (
            member.type is MemberType.SYMLINK
            and self._sequential.link_target_in_data
            and member.link_target is None
        ):
            if decoded is not None:
                with self._translated_errors(member.name), self._handle_guard():
                    target = _read_up_to(decoded, MAX_LINK_TARGET_BYTES + 1)
                if len(target) > MAX_LINK_TARGET_BYTES:
                    self._emit_link_target_too_long(member, member_id=index)
                else:
                    member.link_target = target.decode(
                        "utf-8", errors="surrogateescape"
                    )
            elif length > MAX_LINK_TARGET_BYTES:
                self._emit_link_target_too_long(member, member_id=index)
            else:
                with self._translated_errors(member.name), self._handle_guard():
                    target = forward.read_exact(length)
                member.link_target = target.decode("utf-8", errors="surrogateescape")
        return member

    @override
    def _pass_reads_through_walk(self) -> bool:
        """A random-access pass reads through the walk until it ends, so a
        compressed archive (``.cpio.gz``, or one a walk decompresses part-way) is
        decoded once for the headers and the data, not once for each."""
        return True

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
                span = next(data_walk.spans, None)
            if not isinstance(span, MemberSpan):
                if span is not None:
                    raise TypeError(
                        f"{type(self._reader).__name__}.walk() yielded "
                        f"{type(span).__name__}, not a MemberSpan"
                    )
                raise CorruptionError(
                    f"walking the archive again ended before {quoted(decoded.name)}"
                )
            if not isinstance(span.member, ArchiveMember):
                raise TypeError(
                    f"{type(self._reader).__name__}.walk() yielded "
                    f"{type(span.member).__name__}, not an ArchiveMember"
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
                    self._decoded_stream(data),
                    span.checked,
                    index,
                    decoded.size,
                    decoded.name,
                )
            # A member on the way, read past under the name it is listed by.
            name = _span_names(span)[1]
            with self._translated_errors(name), guard:
                if data is not None:
                    _Decoded(
                        self._decoded_stream(data),
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

    def _decoded_stream(self, data: BinaryIO | io.RawIOBase) -> BinaryIO:
        """A reader's decoded data as archivey reads it: full-count, and counted as
        decompressed output, the drain's bytes too (``_decoded_parts`` does not count
        them again)."""
        return self._track_decompressed(_full_count(data))

    def _check_rewalked(self, span: MemberSpan, decoded: _Decoded) -> None:
        """Refuse a walk started over that does not yield, at the member's place, the
        member the listing walk did: ``walk()`` must repeat itself."""
        found = _span_names(span)[1]
        if found != decoded.name:
            raise ValueError(
                f"{type(self._reader).__name__}.walk() yielded {found!r} as member "
                f"{decoded.index} when walked again, not {decoded.name!r}: a walk must "
                "yield the same members in the same order each time"
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
        # open stream, not later in the collector.
        try:
            if self._open_walk is not None:
                close = getattr(self._open_walk[0], "close", None)
                self._open_walk = None
                if close is not None:
                    with self._translated_errors(), self._handle_guard():
                        close()
        finally:
            try:
                super()._close_archive()
            finally:
                with self._handle_guard():
                    self._release_streams()


# Set on an error that reports a plugin breaking the interface, so the plugin's own
# ``translate_exception`` is not offered it (``_PluginAdapter._translate_exception``).
_PLUGIN_BUG = "_archivey_plugin_bug"

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
    ) -> _PluginAdapter:
        reject_start_offset(start_offset, format, archive_name)
        adapter = (
            SequentialReaderAdapter
            if issubclass(self.PLUGIN, SequentialFormatHandler)
            else IndexedReaderAdapter
        )
        return adapter(
            self.PLUGIN(),
            source,
            format,
            streaming,
            encoding if self.USES_ENCODING else None,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
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
    if not (isinstance(plugin, type) and issubclass(plugin, FormatHandler)):
        raise ArchiveyUsageError(
            f"register_format() takes a FormatHandler subclass, got {plugin!r}"
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
    return fmt


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
# indexed plugin can read. TAR and RAW_STREAM read in one pass, DIRECTORY is not a file,
# and DMG is recognised only to be refused.
REPLACEABLE_CONTAINERS = frozenset(
    {
        ContainerFormat.ZIP,
        ContainerFormat.SEVEN_Z,
        ContainerFormat.RAR,
        ContainerFormat.ISO,
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
    if not (isinstance(plugin, type) and issubclass(plugin, FormatHandler)):
        raise _UsageTypeError(
            f"{call} takes a FormatHandler subclass for ContainerFormat."
            f"{container.name}, got {plugin!r}."
        )
    name = plugin.__name__
    if issubclass(plugin, SequentialFormatHandler):
        raise _UsageValueError(
            f"{call}: {name} is a SequentialFormatHandler; a replacement reads an "
            "indexed container and subclasses FormatHandler."
        )
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
                "NON_SEEKABLE_REASON": "its reader needs random access to the archive"
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
    (``NON_SEEKABLE_REASON``, ``OPTIONAL_DEPENDENCY``). Returns the backend class.
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
