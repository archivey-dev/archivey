"""Single-file compressor backend — one multi-format reader for every standalone codec.

A bare ``.gz`` / ``.bz2`` / ``.xz`` / ``.zst`` / ``.lz4`` / ``.lz`` (lzip) /
``.lzma`` (LZMA Alone) / ``.zz`` (zlib) / ``.br`` (brotli) / ``.Z`` (unix-compress)
stream is presented as a **one-member pseudo-archive**: exactly one ``FILE`` member
whose name is inferred by stripping the codec extension (or ``.uncompressed`` when
there is no known suffix). There is no member table — size/mtime/crc come from
per-codec :class:`~archivey.internal.streams.codecs.MetadataContext` hooks when cheap
(gzip FNAME/mtime, xz/lzip size, …); otherwise they are filled/verified on read via
the shared codec layer.

The backend is codec-agnostic; adding a standalone codec is "add codec + enum +
detection" — no new backend class (see ``format-single-file-compressors``). Basic
ZST/LZ4 read is already here; remaining seekable-index / accelerator work for those
codecs is an idea in ``dev-docs/IDEAS.md`` ("Seekable zstd through a native frame index").
"""

from __future__ import annotations

import io
import logging
import uuid
from collections.abc import Callable, Iterator
from dataclasses import replace
from typing import BinaryIO, TypeVar

from archivey.config import ArchiveyConfig
from archivey.cost import (
    AccessCost,
    CostReceipt,
    ListingCost,
    StreamCapability,
)
from archivey.diagnostics import Diagnostic, DiagnosticCode, DiagnosticContext
from archivey.exceptions import ArchiveyError, StreamNotSeekableError
from archivey.internal.base_reader import (
    BaseArchiveReader,
    ReadBackend,
    reject_start_offset,
)
from archivey.internal.config import (
    stream_config_from_archivey,
    without_accelerators,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.naming import (
    COMPRESSED_TAR_SHORT_SUFFIXES,
    infer_member_name_from_archive,
)
from archivey.internal.open_site import OpenSite
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import register_reader
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import MemberStreamParts
from archivey.internal.streams.codecs import (
    SINGLE_FILE_CODECS,
    Codec,
    MetadataContext,
    open_codec_stream,
    resolve_codec,
    stream_codec_for_format,
)
from archivey.internal.streams.codecs.lzip_decoder import peek_index_summary
from archivey.internal.streams.decompressor_stream import (
    DecompressorStream,
    IndexReport,
    PrebuiltIndex,
)
from archivey.internal.streams.streamtools import (
    SharedSource,
    SlicingStream,
    read_exact,
)
from archivey.types import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    MemberStreams,
    MemberType,
)

_T = TypeVar("_T")

# Lowercased standalone-compression extensions, for the "strip vs append .uncompressed" rule
# in member-name inference. Sourced from the codec objects. (The combined `tar.gz`/`.tgz`
# names are a format-detection concern, not single-file naming.)
_COMPRESSION_EXTS: frozenset[str] = frozenset(
    ext.lower() for c in SINGLE_FILE_CODECS for ext in c.extensions
)
_TAR_SHORT_TO_TAR: dict[str, str] = dict.fromkeys(COMPRESSED_TAR_SHORT_SUFFIXES, ".tar")


class _IndexReportRecorder(DiagnosticCollector):
    """Keeps what an index scan emits, for a member stream to emit later.

    Nothing is counted, logged or called back here: the member stream that uses the
    scan emits each report into the reader's collector instead. An emit that must
    raise (``escalate_as``) is not deferred; it goes through as usual. The replay
    passes no member and the stream module's logger, so an emit that names a member
    is refused here rather than silently losing its attachment.
    """

    def __init__(self) -> None:
        super().__init__()
        self.reports: list[IndexReport] = []

    def emit(
        self,
        *,
        code: DiagnosticCode,
        message: str,
        context: DiagnosticContext,
        member: ArchiveMember | None = None,
        attach_to_member: bool = False,
        logger: logging.Logger | None = None,
        escalate_as: type[BaseException] | None = None,
        escalate_message: str | None = None,
        escalate_kwargs: dict[str, object] | None = None,
    ) -> Diagnostic:
        if escalate_as is not None:
            return super().emit(
                code=code,
                message=message,
                context=context,
                member=member,
                attach_to_member=attach_to_member,
                logger=logger,
                escalate_as=escalate_as,
                escalate_message=escalate_message,
                escalate_kwargs=escalate_kwargs,
            )
        assert member is None and not attach_to_member, (
            "an index scan's deferred report cannot name a member"
        )
        self.reports.append(IndexReport(code, message, context))
        return Diagnostic(
            occurrence_id=uuid.uuid4().hex, code=code, message=message, context=context
        )


def _infer_member_name(archive_name: str | None) -> str:
    """Infer the single member's name from the source filename (see the spec)."""
    return infer_member_name_from_archive(
        archive_name,
        strip_suffixes=_COMPRESSION_EXTS,
        replace_suffixes=_TAR_SHORT_TO_TAR,
    )


class SingleFileReader(BaseArchiveReader):
    """Presents one standalone compressed stream as a one-member archive.

    Source shapes at open:

    - Path → reopen per ``open()`` (independent FDs; concurrent opens stay isolated)
    - Seekable stream → :class:`SharedSource` views from position 0
    - Non-seekable → one pending stream; first open consumes it

    A seekable source is validated by :meth:`_validate_at_open`, which ``open_archive``
    calls after setting format provenance: it decodes one byte, so a source that is not
    the claimed codec raises from ``open_archive`` rather than the first ``read``. A
    non-seekable source is not validated until that read.
    """

    _MEMBER_LIST_UPFRONT = True

    def __init__(
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
    ) -> None:
        # password rejection is central: open_archive checks ReadBackend.SUPPORTS_PASSWORD.
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
        self._stream_codec = stream_codec_for_format(format.stream)
        self._codec = self._stream_codec.codec
        self._seekable = source.seekable()

        # A non-seekable source cannot be randomly accessed, and an accelerator
        # (rapidgzip) would fail at *open* on it: rapidgzip needs either a seekable
        # stream or a real OS fileno, and a non-seekable source offers neither (so it
        # raises StreamNotSeekableError). Keep the codec sequential for such a source
        # regardless of the archive's streaming flag. Declared seek demand
        # (MemberStreams.SEEKABLE) also gates accelerator AUTO resolution, which for the
        # DEFLATE family also takes a large sequential read from a seekable source.
        seek_declared = MemberStreams.SEEKABLE in member_streams
        # The codec stream is the whole file, so bytes after its end are reported.
        self._codec_config = replace(
            stream_config_from_archivey(
                self._config,
                streaming=self._streaming or not self._seekable,
                seekable=seek_declared and self._seekable,
                usage=self._usage,
            ),
            report_trailing_data=True,
        )

        # Metadata probes answer a different question than member streams, so they get
        # their own config. `seekable_members` declares what the caller wants to do with
        # the *member stream*; the xz index and lzip trailer are bounded backward peeks
        # that hand nobody a stream, so reading them is decided by the source's shape.
        # Gating them on the declaration made the same .xz report size=None on a plain
        # open and 44 with the flag — a capability flag changing metadata. Accelerators
        # stay OFF: a probe reads no member data, so an accelerator's startup cost buys
        # nothing the native index does not already have.
        self._metadata_config = without_accelerators(
            stream_config_from_archivey(
                self._config,
                streaming=False,
                seekable=self._seekable,
                usage=self._usage,
            )
        )

        # The compressed-source header, read at most once and cached (only the gzip metadata
        # hook needs it; codecs without header metadata never trigger a read). See _peek_header.
        self._header_cache: bytes | None = None
        # The xz index scan made for ``member.size``, kept for the member streams when
        # they build an index (see _probe_decompressed_size). It lives as long as the
        # reader, whether or not a stream ever seeks, and holds at most MAX_SEEK_POINTS
        # points (xz.md §6).
        self._seek_index: PrebuiltIndex | None = None
        self._member = self._build_member(archive_name)

        # Concurrent/re-entrant member open (no ``_first_stream`` scratch):
        # - Path source: each open hands the path to the codec (independent FD; keeps
        #   path-only accelerator features such as the rapidgzip ISIZE truncation
        #   backstop). Concurrent opens are naturally isolated — same shape as ZIP path.
        # - Seekable stream: SharedSource.view(0) + a fresh codec per open, so interleaved
        #   opens never clobber the single shared handle position.
        # - Non-seekable: one forward pass; a second open fails loudly once consumed.
        self._shared: SharedSource | None = None
        self._pending_parts: MemberStreamParts | None = None
        if self._seekable and (source.path is None or self._measure):
            # A stream source always shares its one handle, handing out views. A path
            # source normally hands the path to the codec (independent FDs) and shares
            # only under measurement, so the source's seeks are visible.
            self._shared = SharedSource(source, wrap_handle=self._seek_handle_wrapper())
        if not self._seekable:
            # Non-seekable: validation waits for the first read (see _validate_at_open).
            self._pending_parts = self._open_codec_parts()

    def _validate_at_open(self) -> None:
        """Decode one byte, so a source that is not the claimed codec fails at open.

        Constructing a codec stream checks nothing, because every codec checks its header
        on the first read. One byte is the whole guarantee; a corrupt tail still fails on
        read. An empty result is a valid empty stream: each decoder raises on input too
        short to hold its own header. The probe stream is not cached; every
        ``_open_member`` builds a fresh one. The error names no member, since nobody asked
        for one yet.

        A non-seekable source is not probed: the read would consume a byte of the one
        pass the first ``open_member`` hands out, so it still fails on that read.

        The probe decodes with the standard library: rapidgzip runs in a child process,
        and one byte does not pay for starting one (about 30 ms) that the member read then
        starts again. An ``ON`` accelerator is still resolved here, without starting
        anything (``StreamCodec.check_accelerator``), so rapidgzip absent or no child
        process possible fails at open. ``AUTO`` is left to the read, which resolves it
        against the config the registry prepares.
        """
        if not self._seekable:
            return
        with self._member_stream(
            self._open_codec_parts(attribute_member=False, accelerated=False)
        ) as probe:
            probe.read(1)

    def _build_member(self, archive_name: str | None) -> ArchiveMember:
        member = ArchiveMember(
            type=MemberType.FILE,
            name=_infer_member_name(archive_name),
            raw_name=None,
            size=None,  # filled per-codec below where cheaply known
            compressed_size=self._probe_compressed_size(),
            modified=None,
        )
        # Per-codec metadata extraction lives on the codec object (gzip FNAME/mtime, xz/lzip
        # decompressed size); the reader stays codec-agnostic and just supplies the
        # source-reading hooks the extractor may need (the base method is a no-op).
        self._stream_codec.extract_metadata(self._metadata_context(), member)
        # A size the format does not record comes from the first clean full read
        # (``_open_codec_parts``); ``member_state_final`` waits for it.
        member._size_unread = member.size is None
        return member

    # --- metadata helpers ----------------------------------------------------------------

    def _metadata_context(self) -> MetadataContext:
        return MetadataContext(
            peek_header=self._peek_header,
            probe_decompressed_size=self._probe_decompressed_size,
            probe_lzip_index=self._probe_lzip_index,
            peek_trailer=self._peek_trailer,
        )

    def _peek_trailer(self, length: int) -> bytes | None:
        """The last ``length`` bytes of the compressed source, or ``None``.

        ``None`` for a source shorter than ``length`` and wherever
        :meth:`_try_on_seekable_source` declines: a pipe, a member stream whose seek
        may re-decode, a read that fails.
        """

        def tail(f: BinaryIO) -> bytes | None:
            # One seek. A source shorter than ``length`` raises ``ValueError`` (some
            # streams) or ``OSError`` (a file; ``_try_on_seekable_source`` catches it),
            # or clamps to 0 and reads short (``BytesIO``): every path gives ``None``.
            try:
                f.seek(-length, io.SEEK_END)
            except ValueError:
                return None
            data = f.read(length)
            return data if len(data) == length else None

        return self._try_on_seekable_source(tail)

    def _peek_header(self, length: int) -> bytes:
        """The first ``length`` bytes of the compressed source, read once and cached.

        The first call (or one needing more than is cached) reads the source a single time;
        later calls serve from the cache without re-opening or re-seeking. For a non-seekable
        source this reuses the prefix detection already buffered in the source's replay
        prefix; for a path it opens a fresh handle; for a seekable stream it reads and rewinds
        once.
        """
        if self._header_cache is None or len(self._header_cache) < length:
            self._header_cache = self._read_source_prefix(length)
        return self._header_cache[:length]

    def _on_seekable_source(self, fn: Callable[[BinaryIO], _T | None]) -> _T | None:
        """Run ``fn`` on a seekable handle over the source; restore stream position.

        Path sources get a fresh FD; a path is always seekable here, because
        ``ArchiveSource.for_path`` clears ``path`` for a FIFO, device or socket. Seekable
        streams are passed through with the caller's position restored afterward.
        Non-seekable sources return ``None`` without calling ``fn`` (never forces a decode
        pass). ``OSError`` propagates. Under measurement the handle counts its seeks.
        """
        src = self._source
        assert src is not None
        if src.path is not None:
            with open(src.path, "rb") as f:
                return fn(self._track_source_seeks(f))
        if not src.seekable():
            return None
        pos = src.tell()
        # The seek counter owns what it wraps, so under measurement it gets a non-owning
        # view: wrapping the source itself would close it when the probe drops the wrapper.
        handle = SlicingStream(src, start=0) if self._measure else src
        try:
            return fn(self._track_source_seeks(handle))
        finally:
            src.seek(pos)

    def _try_on_seekable_source(self, fn: Callable[[BinaryIO], _T | None]) -> _T | None:
        """:meth:`_on_seekable_source` for a metadata probe that reads the source's tail.

        ``OSError`` gives ``None``. So does a source whose seek may re-decode
        (``seek_is_expensive``, any member stream): the xz index and the lzip trailer sit
        at the end, and on a member that decompresses, reaching them decompresses the
        whole member, then the restore decompresses it again. The test covers member
        streams as a group, so a stored ZIP entry or a TAR member, whose seek is a slice,
        is skipped too. Those probes only fill metadata (``size``, the lzip CRC-32); the
        decoder still checks its own index and trailers on read.
        """
        src = self._source
        assert src is not None  # always set in __init__
        if src.seek_is_expensive:
            return None
        try:
            return self._on_seekable_source(fn)
        except OSError:
            return None

    def _probe_compressed_size(self) -> int | None:
        """Byte length of the compressed source, when it is cheap to learn.

        A member stream from another archive (``seek_is_expensive``) reports its
        advertised ``size`` (``ArchiveSource.size_hint``), seekable or not: that is the
        length its container's header declares, and the outer archive's
        ``seekable_members`` must not change metadata. On any other seekable source, its
        cheap size comes first: a path's ``stat``, a ``BytesIO``'s buffer, a ``size``
        attribute. Without one, one ``SEEK_END`` answers, so the same bytes report the
        same size from a path, a ``BytesIO`` or an unrecognized seekable stream. A member
        stream with no advertised length reports ``None``: a seek to its end may
        decompress the whole member. A caller's non-seekable stream reports ``None`` too,
        even when it has a ``size`` attribute. A missing path raises ``OSError`` inside
        ``_on_seekable_source``, and ``_try_on_seekable_source`` turns it into ``None``.

        What separates the pipe from the seekable caller stream is seekability, not
        trust: both carry an unchecked ``size`` claim, and the seekable one's is
        reported. On a pipe there is no ``SEEK_END`` to answer, so ``None`` is the
        answer it always had. The value is not only metadata. Two extraction ratio
        guards divide by a source length: the per-member guard by ``compressed_size``,
        and the archive-wide guard by ``BaseArchiveReader.compressed_source_size``
        (``_trusted_source_size``). Both follow this rule, so a pipe's ``size`` claim
        reaches neither, and the live byte counter stays. Nothing here checks a
        member stream's declared length, and a ``SEEK_END`` could not do better: a TAR
        member stream answers it from the same declared length. A ZIP member that holds
        fewer bytes than it declares is refused with ``TruncatedError`` only after its
        payload is decoded, so for a nested archive ``max_extracted_bytes`` is the bound
        that holds (spec ``safe-extraction``, "Archive-wide decompression ratio for
        solid containers").

        The absolute ``SEEK_END`` is the member's length, not the handle's, because the
        source reaching a reader is already normalized to begin at offset 0 — a caller
        stream handed in at its current ``tell()`` arrives here sliced (and its size hint
        is rebased with it). Worth stating: read locally, ``seek(0, SEEK_END)`` on a
        "passed through" caller stream looks like it would over-report by the start
        offset.
        """
        src = self._source
        assert src is not None  # always set in __init__
        if not src.seekable():
            # No ``SEEK_END`` here to measure the end, so only a declared length can
            # answer. A member stream's is its container's header (``seek_is_expensive``
            # is true exactly when the source borrows an ``ArchiveStream``; a joined set
            # with one is seekable and never reaches here). A caller's pipe reports
            # ``None`` even with a ``size`` attribute.
            return src.size_hint if src.seek_is_expensive else None
        if src.size_hint is not None:
            return src.size_hint
        # ``_try_on_seekable_source`` gives ``None`` for an expensive seek.
        return self._try_on_seekable_source(lambda f: f.seek(0, io.SEEK_END))

    def _read_source_prefix(self, length: int) -> bytes:
        src = self._source
        assert src is not None  # always set in __init__
        if src.path is None and not src.seekable():
            return src.peek(length)

        def read(f: BinaryIO) -> bytes:
            # open_archive normalizes the origin (a mid-positioned stream is rebased so
            # tell() == 0 at the archive's first byte), so 0 is the archive start.
            f.seek(0)
            return read_exact(f, length)

        data = self._on_seekable_source(read)
        assert data is not None  # the source is a path or seekable
        return data

    def _probe_lzip_index(self) -> tuple[int, int] | None:
        """Decompressed size + combined CRC-32 from one seekable lzip index scan.

        The source has to be seekable, and its seek has to be cheap. It does not have to
        be a path, and does not need the caller's ``seekable_members`` declaration:
        ``_try_on_seekable_source`` gives the probe a handle either way, and returns
        ``None`` for a non-seekable source or one whose seek may re-decode. Returns
        ``None`` when the index is unavailable or corrupt.
        """
        if self._codec is not Codec.LZIP:
            return None

        def probe(f: BinaryIO) -> tuple[int, int] | None:
            size = f.seek(0, io.SEEK_END)
            if size < 26:  # header(6) + trailer(20)
                return None
            try:
                return peek_index_summary(f, size)
            except ArchiveyError:
                return None

        return self._try_on_seekable_source(probe)

    def _probe_decompressed_size(self) -> int | None:
        """Decompressed size from the stream index/trailer, when cheaply available.

        Needs a seekable source whose seek is cheap. It does not have to be a path, and
        does not need the caller's ``seekable_members`` declaration:
        ``_try_on_seekable_source`` opens a fresh handle for a path, returns ``None`` for
        a source whose seek may re-decode, and restores a caller stream's position
        afterwards; ``_metadata_config`` asks the codec for its index because the
        *source* can seek. The codec is opened over a non-owning :class:`SlicingStream`
        view, so closing the probe's decompressor never closes a stream the caller owns.
        """

        # Not the reader's collector: a degraded index is not reported at open. This
        # asks a metadata question and answers size=None when the index is unreadable.
        # The member stream reports the index into the reader's collector when a caller
        # seeks; reporting here too would count one file twice, and under STRICT would
        # refuse the open for a caller who never seeks.
        #
        # When member streams build an index (``seekable_members`` on a seekable
        # source), the scan is kept for them: each one uses it in place of its own scan
        # and emits the reports recorded here. A crafted file of many tiny xz streams
        # makes the scan expensive, so it runs once. Otherwise a degraded index goes to
        # resolve_collector's throwaway (a WARNING line and nothing else).
        keep = self._codec_config.seekable
        recorder = _IndexReportRecorder() if keep else None
        config = replace(self._metadata_config, collector=recorder)

        def probe(f: BinaryIO) -> int | None:
            try:
                backend = resolve_codec(self._codec, config)
                stream = backend.open(SlicingStream(f, start=0))
            except (ArchiveyError, OSError, ValueError):
                return None
            try:
                if not isinstance(stream, DecompressorStream):
                    return None
                if recorder is None:
                    return stream.try_get_size()
                scanned = stream.scan_index()
                if scanned is None:
                    return None
                points, size = scanned
                self._seek_index = PrebuiltIndex(
                    tuple(points), size, tuple(recorder.reports)
                )
                return size
            finally:
                stream.close()

        return self._try_on_seekable_source(probe)

    # --- reader hooks --------------------------------------------------------------------

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield self._member

    def _open_codec_parts(
        self, *, attribute_member: bool = True, accelerated: bool = True
    ) -> MemberStreamParts:
        """Open a fresh decompression stream over the source, as the member's parts.

        ``attribute_member=False`` leaves ``member_name`` off errors the stream raises, for
        the open-time probe that no caller asked for. ``accelerated=False`` decodes with
        the standard library whatever ``use_rapidgzip`` / ``use_indexed_bzip2`` say.

        A seekable stream source goes through a whole-source ``SharedSource`` view so
        concurrent / re-entrant opens never clobber the shared handle's position. A path
        source is passed through as a path (the codec opens an independent handle — the
        same concurrent-open shape as ZIP path-source), except under measurement, where it
        shares one handle too so its seeks stay visible. A non-seekable source is read
        once, forward-only.
        """
        member_name = self._member.name if attribute_member else None

        def stamp(exc: ArchiveyError) -> None:
            self._stamp_error_context(exc, member_name)

        src = self._source
        assert src is not None  # always set in __init__
        codec_source: str | BinaryIO
        # _wrap_compressed_input counts the compressed bytes the codec pulls whenever the
        # source has no trusted size (``_trusted_source_size``), so the live ratio guard
        # has a denominator. A path
        # source always has a cheap ``stat`` size, so the path branch needs none.
        if self._shared is not None:
            # Whole-source view + fresh codec per open (no per-member byte range for a
            # single-file archive). The view is non-owning; the SharedSource outlives it.
            codec_source = self._wrap_compressed_input(self._shared.view(0))
        elif src.path is not None:
            codec_source = str(src.path)
        else:
            codec_source = self._codec_input(src)
        config = self._codec_config
        if not accelerated:
            # Still fail where the accelerated open would fail before decoding (ON with
            # rapidgzip absent, or no child process possible), so the error stays at open.
            try:
                self._stream_codec.check_accelerator(codec_source, config)
            except ArchiveyError as exc:
                stamp(exc)
                raise
            config = without_accelerators(config)
        if self._seek_index is not None:
            config = replace(config, seek_index=self._seek_index)
        raw = open_codec_stream(
            self._codec,
            codec_source,
            config=config,
            stamp=stamp,
            collector=self._diagnostics_collector,
        )
        # The parts carry the reader's diagnostic collector/operation id. The handle
        # that serves them collapses the codec's own ArchiveStream into itself. A
        # member with no recorded size takes the length of the first read from the
        # start to the end that skips no byte; the open-time probe is no such read.
        member = self._member
        fill = attribute_member and member.size is None
        return self._member_parts(
            raw,
            member_name,
            size=member.size,
            verify_member=member if fill else None,
            fill_size=fill,
        )

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        if self._seekable:
            # Reentrant: every open builds a fresh codec (path → independent FD; stream →
            # SharedSource view). No per-open scratch on self.
            return self._open_codec_parts()

        # Non-seekable: serve the one-shot stream opened at init; a second open fails loudly.
        if self._pending_parts is not None:
            parts = self._pending_parts
            self._pending_parts = None
            return parts
        err = StreamNotSeekableError(
            "Cannot open this member again: the source is non-seekable and its "
            "single decompression pass has already been consumed. Buffer the "
            "source to disk or a BytesIO to re-read it.",
        )
        self._stamp_error_context(err, member.name)
        raise err

    def _get_archive_info(self) -> ArchiveInfo:
        cost = CostReceipt(
            listing_cost=ListingCost.INDEXED,  # exactly one member, always
            access_cost=AccessCost.DIRECT,  # one member -> no solid-block dependency
            stream_capability=(
                StreamCapability.SEEKABLE
                if self._seekable
                else StreamCapability.FORWARD_ONLY
            ),
            solid_block_count=None,
        )
        return ArchiveInfo(
            format=self._format,
            format_version=None,
            is_solid=False,
            member_count=1,
            comment=None,
            is_encrypted=False,
            is_multivolume=False,
            cost=cost,
        )

    def _close_archive(self) -> None:
        # Close an unserved non-seekable pending stream. The SharedSource is deliberately
        # NOT closed: it owns nothing (only stream sources are wrapped, and the caller
        # owns those), and marking it closed would poison still-open member streams —
        # which are the caller's to close and, over the rapidgzip accelerator, ABORT the
        # process if their source dies underneath them (rapidgzip 0.16 raises C++
        # std::invalid_argument through terminate() when a Python-file callback raises —
        # on read, close, and the GC-time guard alike; see dev-docs/known-issues.md). Reads
        # after the *caller* closes their source surface as a typed error via the
        # ArchiveStream closed-handle mapping (stdlib codec paths).
        if self._pending_parts is not None:
            self._pending_parts.inner.close()
            self._pending_parts = None


class SingleFileBackend(ReadBackend):
    """One backend serving every standalone single-file compressor.

    Only the format list is declared here, derived from the codec objects. The detection
    tables (magic, extensions, content probes) are not duplicated onto this backend — the
    detector reads them straight from ``STREAM_CODECS`` via the registry — so adding a
    standalone codec is a single ``StreamCodec`` subclass (see ``compressed-streams`` /
    ``format-detection``).
    """

    FORMATS: tuple[ArchiveFormat, ...] = tuple(
        c.single_file_format
        for c in SINGLE_FILE_CODECS
        if c.single_file_format is not None
    )
    # A compressed stream decodes front-to-back, so streaming=True works on a
    # non-seekable source. Random access always needs a seekable source.
    SUPPORTS_STREAMING_NON_SEEKABLE = True

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
    ) -> SingleFileReader:
        reject_start_offset(start_offset, format, archive_name)
        # `format` is the resolved single-file format (from detection or the caller); its
        # stream codec is exactly what to decompress with — no re-inspection needed.
        return SingleFileReader(
            source,
            format,
            streaming,
            passwords,
            encoding,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )


register_reader(SingleFileBackend)
