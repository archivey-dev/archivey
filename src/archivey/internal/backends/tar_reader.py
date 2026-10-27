"""TAR backend on the v2 ABC, over archivey's own header parser (``tar_parser.py``).

On-disk layout::

    [ 512-byte header ][ file data, padded to 512 ]*
    [ 512 zero bytes ][ 512 zero bytes ]   # two null end-of-archive trailers

There is no central directory: listing is a header walk (``REQUIRES_SCANNING``) or a
progressive forward pass. Compressed forms (``.tar.gz`` / …) wrap the same layout in
a stream codec and behave as **solid** for random member opens.

Random-access reading (``streaming=False``) needs a seekable source (decompressing
first for a compressed tar) and opens any member on demand: a member's stream is a
view over its data area. Forward-only (``streaming=True``) walks one progressive pass,
including on a non-seekable source, via ``_iter_with_data()`` / ``stream_members()``;
a member's data is read through the walker, which skips what the consumer left.

After a full walk, :meth:`TarReader._verify_tar_eof` checks the end, from the
:class:`~archivey.internal.backends.tar_parser.TarEnd` the walk stopped on:

- A header that does not parse → ``CorruptionError``, in both access modes and
  whatever follows it.
- A missing two-block null trailer → ``ARCHIVE_EOF_MARKER_MISSING``.
- A trailer whose first block is zero and whose second is not, after at least one
  member → ``ARCHIVE_EOF_MARKER_MISSING`` (``expected_marker="second_zero_block"``).
  With no member before the zero block it is ``CorruptionError``, so a file that is
  not a tar does not open as an empty one.
- A non-zero byte within ``_MAX_TRAILING_SCAN`` bytes of a complete trailer, or of a
  damaged second trailer block → ``ARCHIVE_TRAILING_DATA``. Zero padding passes.
- A ``DIRTYPE`` header with a size as the last member, the walk stopped on a zero block
  inside the span that size declares → ``MEMBER_DIRECTORY_DATA_IGNORED`` naming the
  directory: the declared blocks, if there, were read as the marker and hid the members
  behind them, and nothing tells that from a trailer after a header whose blocks were
  never written (:meth:`TarReader._report_directory_span`). A block that is neither a
  header nor zero where the data would begin → ``CorruptionError`` naming the directory.
  A walk that stopped at or past the span's end read all of it: ordinary checks only.

A directory listed from an old-style regular-file header named ``d/`` keeps its declared
``size`` and is reported with ``MEMBER_DIRECTORY_DATA_IGNORED`` at listing; ``open()``
and ``stream_members()`` deliver the bytes, extraction creates the directory (DR-3).

A symlink or hard link header with a size is listed as a link with no ``size``. When
the block after it is not a member header, the walker skips the declared blocks (see
``TarWalker._place_link_data``) and the link is reported with
``MEMBER_LINK_DATA_IGNORED`` at listing; extraction creates the link.

These codes follow the diagnostic policy like any other: a caller who wants one to fail
sets it to ``RAISE`` (``DiagnosticPolicy.STRICT`` does so for all of them).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, nullcontext
from dataclasses import replace
from datetime import datetime
from typing import BinaryIO, Literal, cast

from archivey.config import ArchiveyConfig
from archivey.cost import (
    AccessCost,
    CostReceipt,
    ListingCost,
    StreamCapability,
)
from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    DigestContext,
    DirectoryDataContext,
    LinkDataContext,
    MemberHeaderRecordContext,
    UnknownMemberTypeContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ReadError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.tar_parser import (
    BLOCKSIZE,
    SPARSE_ENTRY_BYTES,
    Budget,
    LinkData,
    NameSource,
    PaxValue,
    TarEnd,
    TarEndKind,
    TarEntry,
    TarSpan,
    TarWalker,
    shown_value,
    validate_sparse_map,
)
from archivey.internal.base_reader import (
    BaseArchiveReader,
    ReadBackend,
    _ProgressivePassIterator,
    pass_has_data,
    reject_start_offset,
)
from archivey.internal.config import stream_config_from_archivey
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.file_copy_pass import DEFAULT_FILE_COPY_PASS, FileCopyPass
from archivey.internal.logs import (
    backends as backends_logger,
    integrity as integrity_logger,
)
from archivey.internal.naming import (
    COMPRESSED_TAR_SHORT_SUFFIXES,
    emit_member_name_normalized,
    normalize_member_name,
)
from archivey.internal.open_site import OpenSite
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import register_reader
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.streams.codecs import (
    SINGLE_FILE_CODECS,
    codec_for_stream_format,
    open_codec_stream,
)
from archivey.internal.streams.decompressor_stream import _StreamChecksumError
from archivey.internal.streams.streamtools import (
    DelegatingStream,
    LockedStream,
    ReadAheadStream,
    ReadOnlyIOStream,
    SharedView,
    SparseStream,
    check_read_size,
    ensure_bufferedio,
)
from archivey.internal.streams.streamtools.binaryio import (
    ask_resume_offset,
    read_blocking,
)
from archivey.internal.timestamps import TimestampIssue, unix_to_datetime
from archivey.internal.unix_mode import special_file_type_from_tar_typeflag
from archivey.terminal import quoted
from archivey.types import (
    EXTRA_SPECIAL_FILE_TYPE,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    ContainerFormat,
    MagicSignature,
    MemberExtra,
    MemberStreams,
    MemberType,
    StreamFormat,
    _ReadOnlyDict,
)

# Read size for the trailing-bytes scan. The tail past the trailer is unbounded (a
# concatenated archive, a padded record, arbitrary junk), so it is consumed in chunks
# rather than with one read().
_TRAILING_SCAN_CHUNK = 64 * 1024

# How far past the trailer the trailing-bytes scan looks before it stops. An effort
# bound, not a ceiling: nothing is refused when it is reached, the scan only stops
# looking. `tar` pads to 10 KiB records by default, so a concatenated archive's header
# lands within ~10 KiB of the trailer in the ordinary case; this is a hundred times
# that. Measured on a gzipped tar with an all-zero tail (the worst case, since the scan
# stops at the first non-zero byte), 1 MiB costs ~5 ms. A constant rather than a config
# field: promoting it later is backward compatible, demoting a field is not, and on
# ``ListingLimits`` a ``None`` would have to mean "scan to EOF", inverting what ``None``
# means on every other field there.
_MAX_TRAILING_SCAN = 1 * 2**20

# Stream formats that carry, or can carry, a checksum over the whole decoded stream
# or its last block, which is checked only when the stream's end is read. For these a
# trailing scan that stops at ``_MAX_TRAILING_SCAN`` leaves that checksum unchecked, and
# says so.
_STREAMS_WITH_CHECKSUM = frozenset(
    (
        StreamFormat.GZIP,
        StreamFormat.BZIP2,
        StreamFormat.XZ,
        StreamFormat.ZSTD,
        StreamFormat.LZ4,
        StreamFormat.LZIP,
        StreamFormat.ZLIB,
    )
)

# The subset whose failed check reads, to archivey, like any other decode failure: the
# bzip2 block CRC and the xz block check. For these, a tail that fails to decode in the
# trailing scan may be a failed check over members already read, and says so.
_STREAMS_WITH_UNTYPED_CHECKSUM = frozenset((StreamFormat.BZIP2, StreamFormat.XZ))

# What :meth:`TarReader._verify_tar_eof` found where the end-of-archive marker belongs:
# no block, a partial one, a non-null block after a zero block that ended at least one
# member (the marker is damaged, the listing whole), a header that does not parse (the
# listing is shortened), or a non-null block after a zero block with no member before
# it.
_EofFinding = Literal[
    "absent", "short", "damaged_second_block", "rejected_header", "no_member"
]

# Typeflags whose member is a file: regular (``0`` and the old NUL), contiguous (``7``)
# and old GNU sparse (``S``) all carry the file's data. Devices, FIFOs and GNU's
# multi-volume continuation (``M``) and volume header (``V``) list as OTHER, their data
# skipped by size. A typeflag none of these sets names is unknown (``_KNOWN_TYPES``).
_FILE_TYPES = frozenset((b"0", b"\x00", b"7", b"S"))
# The walk's read-ahead over a codec stream or a view. Fixed rather than io's default,
# which Python 3.14 raised from 8 KiB to 128 KiB: a larger read-ahead reads and decodes
# further past what the listing needs, so listing costs and source reads would differ
# by Python version.
_WALK_BUFFER = 8 * 1024

# GNU tar's incremental dumps store a directory as a ``D`` (dumpdir) entry, whose data
# lists the directory's contents at dump time. GNU tar extracts it as a directory; the
# list is skipped.
_DIRECTORY_TYPES = frozenset((b"5", b"D"))

_SYMLINK_TYPE = b"2"
_HARDLINK_TYPE = b"1"
# Character and block devices and FIFOs, which carry device numbers.
_DEVICE_TYPES = frozenset((b"3", b"4", b"6"))
# GNU's multi-volume continuation and volume header. GNU tar knows both and extracts
# neither: it skips a ``V`` and refuses an ``M`` ("continued from another volume").
_VOLUME_TYPES = frozenset((b"M", b"V"))
# Every typeflag a member header can have that archivey knows. The extended headers
# (``x``, ``X``, ``g``, ``L``, ``K``) never reach a member: the walker applies them.
_KNOWN_TYPES = (
    _FILE_TYPES
    | _DIRECTORY_TYPES
    | _DEVICE_TYPES
    | _VOLUME_TYPES
    | {_SYMLINK_TYPE, _HARDLINK_TYPE}
)


def _member_type(entry: TarEntry) -> MemberType:
    typeflag = entry.typeflag
    if typeflag in _DIRECTORY_TYPES or entry.old_style_directory:
        return MemberType.DIRECTORY
    if typeflag == _SYMLINK_TYPE:
        return MemberType.SYMLINK
    if typeflag == _HARDLINK_TYPE:
        return MemberType.HARDLINK
    if typeflag in _FILE_TYPES:
        return MemberType.FILE
    if typeflag not in _KNOWN_TYPES and entry.size:
        # An unknown typeflag that declares data: GNU tar extracts it as a regular
        # file with a warning, and 7-Zip 23.01 extracts it as one. The data area is the
        # structure (DR-25; maintainer ruling, 2026-10-17). _to_member reports it.
        return MemberType.FILE
    # Character/block devices, FIFOs, multi-volume and volume headers, and an unknown
    # typeflag with no data.
    return MemberType.OTHER


def _directory_declaring_blocks(member: ArchiveMember | None) -> TarSpan | None:
    """``member``'s span when it is a ``DIRTYPE`` header with a non-zero size, else None.

    Such a header announces blocks it has no data area for (``NO_DATA_TYPES``), so the
    walker read the next header right behind it; where the walk stopped decides what
    the size meant (:meth:`TarReader._verify_tar_eof`). An old-style ``d/`` regular-file
    header is not this case: its typeflag carries data, which is read by size.
    """
    if member is None:
        return None
    span = member._raw
    assert isinstance(span, TarSpan), "TAR member is missing its span"
    if span.typeflag != b"5" or not span.size:
        return None
    return span


def _declared_span_end(span: TarSpan) -> int:
    """The offset right after the blocks ``span``'s size field declares, were they
    there: a ``NO_DATA`` typeflag's ``data_offset`` is the block after its header and
    its ``stored_size`` is 0, so the span is measured from the declared ``size``."""
    return span.data_offset + (span.size + BLOCKSIZE - 1) // BLOCKSIZE * BLOCKSIZE


# Every compressed-tar combination the codec layer can decode: TAR composed with each
# standalone stream codec (gz/bz2/xz/zst/lz4/lzip/lzma-alone/zlib/brotli/unix-compress).
# The common ones have named ArchiveFormat constants; the rest are equal-by-value
# on-demand instances.
_TAR_COMPRESSED: tuple[ArchiveFormat, ...] = tuple(
    ArchiveFormat(ContainerFormat.TAR, codec.stream_format)
    for codec in SINGLE_FILE_CODECS
    if codec.stream_format is not None
)

# Plain TAR plus every compressed combination the codec layer can decode.
_TAR_FORMATS: tuple[ArchiveFormat, ...] = (ArchiveFormat.TAR, *_TAR_COMPRESSED)

# Canonical extensions are derived from each format (TAR -> ".tar", TAR_GZ -> ".tar.gz",
# (TAR, LZIP) -> ".tar.lz", …); only the short aliases (.tgz/.tbz/…) and `.cbt`
# (comic-book TAR) are listed by hand.
# (Built at module scope: a dict comprehension in the class body can't see class-level names.)
_TAR_EXTENSIONS: dict[str, ArchiveFormat] = {
    f".{fmt.file_extension()}": fmt for fmt in _TAR_FORMATS
}
# A codec's extension aliases have their ``.tar.`` forms too (``.tar.brotli``).
_TAR_EXTENSIONS.update(
    {
        f".tar{alias}": ArchiveFormat(ContainerFormat.TAR, codec.stream_format)
        for codec in SINGLE_FILE_CODECS
        if codec.stream_format is not None
        for alias in codec.extension_aliases
    }
)
_TAR_EXTENSIONS.update(
    {
        suffix: ArchiveFormat(ContainerFormat.TAR, stream)
        for suffix, stream in COMPRESSED_TAR_SHORT_SUFFIXES.items()
    }
)
_TAR_EXTENSIONS[".cbt"] = ArchiveFormat.TAR


# Shared across FILE/HARDLINK members — avoid per-member CompressionMethod construction.
_STORED_COMPRESSION: tuple[CompressionMethod, ...] = (
    CompressionMethod(algo=CompressionAlgorithm.STORED),
)


def _pax_text(entry: TarEntry, key: bytes) -> str | None:
    """The PAX record ``key`` in force for ``entry`` as text, or ``None`` when it is
    absent or empty (an empty value in a member's own header cancels the keyword)."""
    value = entry.pax.get(key)
    if value is None or not value.value:
        return None
    return value.value.decode("utf-8", "surrogateescape")


# A PAX time as GNU tar 1.35 reads it (``decode_timespec``): an optional minus, ASCII
# digits, then an optional point and more digits.
_PAX_TIME = re.compile(r"-?[0-9]+(?:\.[0-9]*)?")


def _pax_time(
    entry: TarEntry, key: str, name: str
) -> tuple[datetime | None, TimestampIssue | None]:
    """Parse a PAX time record (decimal Unix seconds) into a tz-aware UTC datetime.

    Covers the standard ``mtime``, ``atime`` and ``ctime`` records and libarchive's
    ``LIBARCHIVE.creationtime`` extension keyword (not a standard PAX record).

    Returns ``(None, None)`` when the record is absent, and ``(None, TimestampIssue)``
    when it is present but not a number or outside ``datetime``'s range, so a bad
    record is reported the same way as a bad header ``mtime``.

    A number is what GNU tar 1.35 accepts: an optional ``-``, ASCII digits, then
    optionally a ``.`` and more digits (``1000.`` included). Python float syntax
    beyond that (``+1``, ``1e3``, ``1_000``, blanks, ``.5``, ``inf``) is reported,
    as GNU tar reports it ("invalid mtime").
    """
    raw = _pax_text(entry, key.encode())
    if raw is None:
        return None, None
    value = (
        unix_to_datetime(float(raw)) if _PAX_TIME.fullmatch(raw) is not None else None
    )
    if value is not None:
        return value, None
    return None, _tar_time_issue(name, key, shown_value(raw), pax_record=True)


# The ArchiveMember field each TAR time fills, which is what a timestamp diagnostic
# names in every format.
_TAR_TIME_FIELDS = {
    "mtime": "modified",
    "atime": "accessed",
    "ctime": "ctime",
    "LIBARCHIVE.creationtime": "created",
}


def _tar_time_issue(
    name: str, key: str, value_repr: str, *, pax_record: bool
) -> TimestampIssue:
    """The ``MEMBER_TIMESTAMP_INVALID`` finding for one TAR time field.

    ``value_repr`` is the raw PAX record for a record, and the header's ``mtime`` for
    one that ``datetime`` cannot hold.
    """
    label = f"PAX {key}" if pax_record else key
    return TimestampIssue(
        field=_TAR_TIME_FIELDS[key],
        source="tar",
        value_repr=value_repr,
        message=f"Invalid TAR {label} for {quoted(name)}: {value_repr}",
    )


class _MemberDataView(DelegatingStream):
    """A random-access member's data area that raises at a cut, not a clean end.

    The view under it returns ``b""`` where the archive ends, which reads as the end of
    the member. Here a read that ends before ``length`` keeps the full-count rule (ADR
    0014): a sized read returns the bytes before the cut and the next read raises, and a
    read with no size raises and returns nothing. The source size is not needed.
    """

    readinto_passthrough = False

    def __init__(self, view: SharedView, data_offset: int, length: int) -> None:
        super().__init__(view)
        self._data_offset = data_offset
        self._length = length

    def read(self, n: int | None = -1, /) -> bytes:
        n = check_read_size(n)
        position = self._inner.tell()
        whole = n < 0
        want = self._length - position if whole else min(n, self._length - position)
        if want <= 0:
            return b""
        data = read_blocking(self._inner, want)
        if len(data) < want and (whole or not data):
            raise TruncatedError(
                "TAR archive is truncated inside a member's data at offset "
                f"{self._data_offset + position + len(data)}"
            )
        return data

    def nearest_resume_offset(self, target: int) -> int | None:
        # The member's offsets are the view's.
        return ask_resume_offset(self._inner, target)


class _WalkHandoffStream(ReadOnlyIOStream):
    """A pass's member data, read through the walk until the walk moves on.

    The walk's next pull calls :meth:`detach` under the walk lock. From then on the
    stream reads a view of its own from where it stopped (on a compressed tar, a
    decoder seek back), so the walk can move on for another caller while the pass is
    still reading this member. A stream detached after its last read builds no view.
    """

    def __init__(self, reader: TarReader, span: TarSpan, data: BinaryIO) -> None:
        self._data = data
        self._view: BinaryIO | None = None
        self._reader = reader
        self._span = span
        self._detached_at: int | None = None
        self._pos = 0
        super().__init__()

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._pos

    def detach(self) -> None:
        """Stop reading through the walk. Called under the walk lock."""
        if self._detached_at is None and not self.closed:
            self._detached_at = self._pos

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed TAR member stream")
        if self._detached_at is None:
            with self._reader._walk_lock:
                if self._detached_at is None:
                    data = self._data.read(n)
                    # Under the lock: a pull on another thread detaches at this
                    # position, so it must already count the bytes returned here.
                    self._pos += len(data)
                    return data
        if self._view is None:
            self._view = self._reader._independent_data(
                self._span, self._detached_at or 0
            )
        data = self._view.read(n)
        self._pos += len(data)
        return data

    def close(self) -> None:
        if self._view is not None:
            self._view.close()
        self._data.close()
        super().close()


class TarReader(BaseArchiveReader):
    """Reads a TAR archive (plain or compressed) with :class:`TarWalker`.

    A seekable source can open any member, but ``_MEMBER_LIST_UPFRONT`` is False —
    there is no central directory, so a complete list always requires a scan (or a
    finished stream pass).
    """

    # TAR has no central directory and scans lazily: the member list only exists after a
    # scan, so the report peek has nothing to return before one. (RAR scans too, but at
    # open, so its peek has a list.) Once iterated, the base serves the cached list anyway.
    _MEMBER_LIST_UPFRONT = False

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
        self._encoding = encoding
        # The codec for header and GNU name fields that are not valid UTF-8, and for
        # PAX values that are not.
        self._codec = encoding if encoding is not None else "utf-8"
        self._source = source
        self._compressed = format.stream != StreamFormat.UNCOMPRESSED
        # The one pass stream reading member data through the walk, if any; the walk
        # detaches it before its next pull (see _pull_member).
        self._walk_stream: _WalkHandoffStream | None = None
        # Streaming only: the buffer in front of the codec stream or the source, built
        # by this reader, so closed by it. Random access keeps each walk's view
        # (``_walker_view``) and each compressed member's view instead, so a reader
        # holds ``_owned_stream`` or ``_walker_view``, never both.
        self._owned_stream: BinaryIO | None = None
        # A compressed tar's codec stream, in either mode. In random access nothing
        # wraps it, so it is closed here explicitly (streaming's buffer also closes it;
        # a second close is a no-op): left to the garbage collector, a stream held by a
        # failed open's traceback kept its rapidgzip child process running.
        self._owned_codec_stream: BinaryIO | None = None
        # Random access only: the current walk's own buffered view (see _new_walker).
        self._walker_view: BinaryIO | None = None
        # The last PAX records a member without records of its own was built from,
        # and the ``extra["tar.pax_headers"]`` every such member shares
        # (:meth:`_extra_pax_headers`).
        self._shared_pax: tuple[Mapping[bytes, PaxValue], _ReadOnlyDict] | None = None
        # Shared-handle lock: CONCURRENT readers serialize every read of the shared
        # byte stream; streaming readers also take a lock (exclusive / normally
        # uncontended) so the same critical-section shape covers the walk, member
        # reads, the end check and close.
        self._handle_lock = (
            threading.Lock()
            if MemberStreams.CONCURRENT in member_streams or streaming
            else None
        )

        try:
            self._stream = self._open_byte_stream(
                source, format, streaming, member_streams=member_streams
            )
            # The first member's headers are parsed at open, so a file that is not a
            # tar fails here (DR-15b).
            self._walker = self._new_walker()
            first = self._step(self._walker)
            self._check_first(first)
            # The walk that hands out ``first`` is the open-time one; a random-access
            # walk started over after a discarded failure builds its own.
            self._open_walk: tuple[TarWalker, TarEntry | TarEnd] | None = (
                self._walker,
                first,
            )
        except ArchiveyError as exc:
            # Release before re-raising: the exception traceback keeps this frame alive
            # and would otherwise pin the owned stream until the caller drops the
            # exception (inventory/fuzz catch-and-continue loops).
            self._release_owned_stream()
            self._stamp_error_context(exc)
            raise
        except BaseException:
            self._release_owned_stream()
            raise

    def _release_owned_stream(self) -> None:
        """Close the streams this reader opened, if any. Safe to call more than once."""
        try:
            # Never both (see __init__), so the codec stream alone needs the finally.
            self._close_walker_view()
            if self._owned_stream is not None:
                owned, self._owned_stream = self._owned_stream, None
                owned.close()
        finally:
            if self._owned_codec_stream is not None:
                codec, self._owned_codec_stream = self._owned_codec_stream, None
                codec.close()

    def _close_walker_view(self) -> None:
        if self._walker_view is not None:
            view, self._walker_view = self._walker_view, None
            view.close()

    def _open_byte_stream(
        self,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        *,
        member_streams: MemberStreams,
    ) -> BinaryIO:
        """The TAR bytes: the source for a plain tar, archivey's codec stream for a
        compressed one."""
        if self._compressed:
            codec = codec_for_stream_format(format.stream)
            codec_source: str | BinaryIO
            if source.path is not None:
                # A file goes to the codec as its path, as for a bare compressed file:
                # the codec opens its own handle and may use path-only accelerators, and
                # the static ratio applies because the size is known.
                codec_source = str(source.path)
            else:
                # A stream whose size is not known is counted, so the live
                # decompression-ratio guard can see compressed bytes consumed.
                codec_source = self._codec_input(source, track_seeks=True)
            stream = open_codec_stream(
                codec,
                codec_source,
                # The codec stream is the whole file, so bytes after its end are
                # reported, as bytes after the TAR trailer are.
                config=replace(
                    stream_config_from_archivey(
                        self._config,
                        streaming=streaming,
                        seekable=MemberStreams.SEEKABLE in member_streams,
                        usage=self._usage,
                    ),
                    report_trailing_data=True,
                ),
                stamp=lambda exc: self._stamp_error_context(exc),
                collector=self._diagnostics_collector,
                # Random access reads it only through views. A read seeks the shared
                # handle when it is not already there, and one such seek is enough to
                # mark the stream rewound. A repeated verdict would drop the prefix of
                # the read that reaches the damage; each member stream repeats its own.
                repeat_verdict=streaming,
            )
            self._owned_codec_stream = stream
            if not streaming:
                # Each walk buffers its own view (_new_walker). A second buffer here
                # would fill the first one in a loop, and a loop that reaches a damaged
                # codec tail raises and drops the bytes already decoded, though the
                # walk may need none of the tail.
                return stream
            # The walker reads 512-byte blocks: a buffer in front makes each one a copy
            # from memory, not a decoder call. It reads the codec once per read, so a
            # cut member's recoverable prefix comes before its TruncatedError.
            self._owned_stream = ReadAheadStream(
                stream,
                _WALK_BUFFER,
                # On a source that cannot seek, the codec reads what has arrived
                # (_codec_input), and so does this buffer: a short tar on a pipe
                # whose writer keeps it open opens, and its members read, at once.
                fill_arrived=not source.seekable(),
            )
            return self._owned_stream
        if streaming and not source.seekable():
            # The buffer fills from what has arrived, not a full 8 KiB, so a short
            # tar on a pipe whose writer keeps it open opens at once. Its own reads
            # still gather until they are full, as the walker needs.
            view = cast("BinaryIO", source.arrived_view())
            self._owned_stream = cast(
                "BinaryIO", ensure_bufferedio(self._track_source_seeks(view))
            )
            return self._owned_stream
        stream = self._track_source_seeks(source)
        if streaming:
            # Random access buffers each walk's own view instead (_new_walker).
            self._owned_stream = cast("BinaryIO", ensure_bufferedio(stream))
            return self._owned_stream
        return stream

    @property
    def _plain_source_size(self) -> int | None:
        """The file size a plain tar's walk and member views clamp reads to.

        A plain file's length is a fact, so a member read is clamped to the bytes the
        file holds and issued once. A compressed stream's length is not: ``None``.
        """
        assert self._source is not None
        return None if self._compressed else self._source.size

    def _new_walker(self) -> TarWalker:
        """A walker from the start of the archive.

        Streaming: over the reader's one forward stream, whose only reader it is
        (member data is read through it). Random access: over a buffered view of its
        own, which repositions the shared stream under the handle lock when the
        handle is not already there, so member reads never move the walk. A pass
        reads member data through this buffer too, so on a compressed tar the
        buffer's read-ahead into a member's data never makes a member read seek
        the decoder back.
        """
        end = self._plain_source_size
        if self._streaming:
            return TarWalker(self._stream, seekable=False, end=end)
        # Plain file: a read larger than the buffer rewinds the prefetched tail and
        # returns the file's own buffer. Joining the tail on would copy the member.
        # A codec keeps the join: rewinding it would decode the tail again.
        view = ReadAheadStream(
            SharedView(self._stream, 0, lock=self._io_guard()),
            _WALK_BUFFER,
            rewind_oversize=not self._compressed,
        )
        # Only one walk runs at a time, and a pass's member streams are closed when it
        # ends, so a walk started over replaces the last one's view.
        self._close_walker_view()
        self._walker_view = view
        return TarWalker(view, seekable=True, end=end)

    def _io_guard(self) -> AbstractContextManager[object]:
        return self._handle_lock if self._handle_lock is not None else nullcontext()

    def _walk_guard(self) -> AbstractContextManager[object]:
        """Held around the walker's own reads. A streaming walker reads the shared
        stream directly; a random-access one reads through a locked view."""
        return self._handle_guard() if self._streaming else nullcontext()

    def _step(self, walker: TarWalker) -> TarEntry | TarEnd:
        with self._walk_guard():
            return walker.next_entry(self._header_budget())

    def _check_first(self, first: TarEntry | TarEnd) -> None:
        """Refuse a file whose first block is not a member header or a zero block."""
        if not isinstance(first, TarEnd):
            return
        if first.kind == TarEndKind.ABSENT:
            raise TruncatedError("TAR archive is truncated: the file is empty")
        if first.kind == TarEndKind.SHORT:
            raise TruncatedError(
                f"TAR archive is truncated: it holds {first.observed_bytes} bytes, "
                "less than one header block"
            )
        if first.kind == TarEndKind.REJECTED:
            raise CorruptionError(
                f"Not a TAR archive, or a damaged one: the header at offset "
                f"{first.offset} does not parse ({first.reason})"
            )

    def _header_budget(self) -> Budget:
        """``(bytes left, cap)`` of ``max_metadata_bytes`` for the next member's headers.

        Every walk enforces the running total, so the next member may use what the
        listing has not yet retained. Every TAR accounting path enforces the cap, so
        the total never exceeds it (only a link target read on request is weighed
        without enforcing, and a TAR link's target is in its header).
        """
        cap = self._config.listing_limits.max_metadata_bytes
        if cap is None:
            return None
        counted = self._listing_tracker.metadata_bytes
        assert counted <= cap, (counted, cap)
        return (cap - counted, cap)

    def _pull_member(self) -> ArchiveMember | None:
        """Pull as the base does, after handing off a pass's stream.

        A pass may still be reading the member the walk is at through the walk. That
        stream moves to a view of its own first (:class:`_WalkHandoffStream`), so a
        pull for another caller, such as ``members()`` from another thread under
        ``CONCURRENT``, does not cut it off. The pass's own next pull hands over a
        stream it is about to close, which costs nothing.
        """
        with self._walk_lock:
            live = self._walk_stream
            if live is not None:
                self._walk_stream = None
                live.detach()
            return super()._pull_member()

    def _register_member(
        self,
        idx: int,
        member: ArchiveMember,
    ) -> None:
        """Register as the base does, then weigh a sparse member's retained map.

        The map can hold millions of entries from a few kilobytes of compressed
        archive, and it stays on the member's span for the life of the listing.
        """
        super()._register_member(idx, member)
        span = member._raw
        if isinstance(span, TarSpan) and span.sparse is not None:
            self._listing_tracker.account_retained_bytes(
                len(span.sparse) * SPARSE_ENTRY_BYTES
            )

    def _iter_members(self) -> Iterator[ArchiveMember]:
        """The member walk, one header per pull.

        Each member is registered (and counted against the listing limits) before the
        next header is parsed, so a header bomb stops at the member that crosses a cap.
        A random-access walk started over after a discarded failure walks again from
        the start with a walker of its own.
        """
        if self._open_walk is not None:
            walker, entry = self._open_walk
            self._open_walk = None
        else:
            walker = self._new_walker()
            with self._translated_errors():
                entry = self._step(walker)
        # A pass reads the data of the member the walk is at through this walker.
        self._walker = walker
        index = 0
        last_member: ArchiveMember | None = None
        while isinstance(entry, TarEntry):
            last_member = self._to_member(entry, index)
            yield last_member
            index += 1
            with self._translated_errors():
                entry = self._step(walker)
        self._verify_tar_eof(walker, entry, last_member=last_member, member_count=index)

    def _iter_members_progressive(self) -> Iterator[ArchiveMember]:
        """Forward-only member walk. Yields bare members; the base's shared progressive
        pass stamps ids and resolves backward links."""
        return self._iter_members()

    def _iter_with_data_random_access(
        self,
    ) -> Iterator[tuple[ArchiveMember, ArchiveStream | None]]:
        """``stream_members()`` on a random-access reader, in one forward pass.

        The base's version lists every member first and then reads their data, which
        on a compressed tar decodes the stream to its end for the headers and then again
        from the start for the data. Here, when the walk has not ended yet, the walk and
        the data share one pass: the member is registered and yielded, and its data is
        read before the walk parses the next header, so every seek goes forward.
        Members are registered as they arrive, as the base's walk registers them, so
        ``members()`` afterwards serves the same list, and the pass links a hardlink to
        an earlier member only, as the streaming pass does.

        A pass over a listing that is already complete reads the members' data in
        archive order, which is one forward sweep too (after one seek back to the first
        member). The pass has its own cursor over the reader's one walk, so a pass
        abandoned early does not make the next one start part-way.
        """
        if self._walk_done:
            yield from super()._iter_with_data()
            return

        def _open_in_walk(member: ArchiveMember) -> BinaryIO:
            # The raw body, not another ArchiveStream. The lazy handle below is the
            # one wrapper; a second one was built and collapsed on every member.
            with self._translated_errors(member.name):
                return self._member_body(member, in_walk=True)

        def _open(member: ArchiveMember) -> ArchiveStream | None:
            if not pass_has_data(member):
                return None
            return self._lazy_member_stream(member, _open_in_walk, track_output=True)

        yield from self._drive_pass_streams(
            _ProgressivePassIterator(self), open_member=_open
        )

    def _list_before_extraction(self) -> None:
        """List as members arrive in the extraction's one pass, not before it.

        The base lists the whole archive before an extraction, which on a compressed
        tar decodes the stream once for the headers and again for the data. Here the
        pass the extraction runs (:meth:`_iter_with_data_random_access`) registers each
        member with the limits enforced, as every pass does, so ``ResourceLimitError``
        is raised at the member that crosses a cap, before it is written, as
        ``members()`` raises it. A listing that is already complete is the base's case.
        """
        if self._walk_done:
            super()._list_before_extraction()

    def _iter_with_data(
        self, copies: FileCopyPass = DEFAULT_FILE_COPY_PASS
    ) -> Iterator[tuple[ArchiveMember, ArchiveStream | None]]:
        if not self._streaming:
            yield from self._iter_with_data_random_access()
            return
        # Pull from the shared instance-held progressive pass so __iter__,
        # stream_members, and members_report share one cursor and finalization.
        # close_previous=False: the walk's next header leaves the previous member's
        # stream unreadable, and the walk reads through whatever it left.
        with self._translated_errors():

            def _open(member: ArchiveMember) -> ArchiveStream | None:
                if not pass_has_data(member):
                    return None
                return self._open_member_stream(member, defer_sparse_error=True)

            yield from self._drive_pass_streams(
                self._begin_forward_pass(),
                open_member=_open,
                close_previous=False,
            )

    def _verify_tar_eof(
        self,
        walker: TarWalker,
        end: TarEnd,
        *,
        last_member: ArchiveMember | None,
        member_count: int,
    ) -> None:
        """Check the end-of-archive marker from where the walk stopped.

        ``member_count`` is how many members the walk yielded and ``last_member`` the
        last of them, or None. When its header is a ``DIRTYPE`` with a size, the
        walker read the next header where its data would begin (a directory has no
        data area, so it skipped none), and a walk that ends on a zero block inside
        the span the size declares has two readings nobody can tell apart: the
        declared blocks are zeros, read as the end-of-archive marker with the members
        behind them dropped, or they were never written and the trailer follows the
        header. :meth:`_report_directory_span` says so with
        ``MEMBER_DIRECTORY_DATA_IGNORED``, the weight DR-3 gives a directory's
        declared data, and the marker checks below run unchanged. When the block
        where the data would begin does not parse, :meth:`_refuse_directory_blocks`
        names the directory in the ``CorruptionError`` the rejected header is anyway.
        A walk that stopped at or past the declared span's end (an extended-header
        chain that spans it, say) read everything the size could have hidden, so it
        gets the ordinary checks alone. The same header followed by a member header
        that parses is GNU tar's, bsdtar's and 7-Zip's clean case, listed with no size
        and no report, and never reaches this method as ``last_member``.

        A header that does not parse (a corrupt member header after the first) means
        the listing was cut short, and that escalates to ``CorruptionError`` whatever
        the diagnostic policy says. This needs no further read, so it holds in both
        access modes whatever follows the rejected header: nothing, a zero block (a
        member whose data starts with one), or more members.

        A zero block ends the members. An ``x`` or ``L`` header right before it is
        left unused, as GNU tar 1.35 lists such an archive, with no diagnostic. Only
        the *second* marker block is checked: reading two here would demand a third
        block of trailing zeros and wrongly flag a minimal ``tar -b1`` trailer. A short
        or empty read is a truncated or absent trailer, reported as
        ``ARCHIVE_EOF_MARKER_MISSING`` under the ordinary diagnostic policy.

        A non-null block there, after a zero block with members listed, means the
        end-of-archive marker itself is damaged: every member before it is listed and
        whole, as GNU tar and 7-Zip list them with a warning, so it is
        ``ARCHIVE_EOF_MARKER_MISSING`` under the ordinary policy
        (``DiagnosticPolicy.STRICT`` refuses it), and the scan past the trailer runs
        from the block after it. A zero block and then a non-null one with no member
        before them is ``CorruptionError``.
        """
        directory = _directory_declaring_blocks(last_member)
        if end.kind == TarEndKind.REJECTED:
            if directory is not None and end.offset == directory.data_offset:
                assert last_member is not None
                self._refuse_directory_blocks(last_member, directory)
            self._emit_eof_marker("rejected_header", observed_bytes=BLOCKSIZE)
            return
        if (
            directory is not None
            and end.kind == TarEndKind.ZERO_BLOCK
            and end.offset < _declared_span_end(directory)
        ):
            assert last_member is not None
            self._report_directory_span(
                last_member, directory, member_id=member_count - 1
            )
        if end.kind != TarEndKind.ZERO_BLOCK:
            self._emit_eof_marker(
                "absent" if end.kind == TarEndKind.ABSENT else "short",
                observed_bytes=end.observed_bytes,
            )
            return
        stream = walker.stream_after_end()
        with self._translated_errors(), self._walk_guard():
            chunk = stream.read(BLOCKSIZE)
        if len(chunk) == BLOCKSIZE and chunk == bytes(BLOCKSIZE):
            self._verify_nothing_but_zeros_to_eof(stream)
            return
        if len(chunk) == BLOCKSIZE:
            if member_count == 0:
                self._emit_eof_marker("no_member", observed_bytes=BLOCKSIZE)
                return
            # One zero block, then a damaged one: the marker is damaged, not the
            # listing. The scan past it still runs, because on a compressed tar it is
            # where the codec's whole-stream checksum over the members just listed is
            # usually reached.
            self._emit_eof_marker("damaged_second_block", observed_bytes=BLOCKSIZE)
            self._verify_nothing_but_zeros_to_eof(stream)
            return
        self._emit_eof_marker(
            "absent" if len(chunk) == 0 else "short", observed_bytes=len(chunk)
        )

    def _report_directory_span(
        self, member: ArchiveMember, directory: TarSpan, *, member_id: int
    ) -> None:
        """Report ``MEMBER_DIRECTORY_DATA_IGNORED`` for a ``DIRTYPE`` header with a
        size when the walk ended on a zero block inside the span that size declares.

        The bytes have two readings: the declared blocks are zeros, which the walker
        read as the end-of-archive marker (a lone block, or a complete marker when the
        span is two blocks or more), so the members behind them are not listed, as GNU
        tar lists the directory and stops ("A lone zero block", or no word at all); or
        the blocks were never written and the trailer follows the header, as a writer
        that carried ``st_size`` leaves it. Nothing in the file tells them apart, so
        the report says what the header declares and what the walk saw, and the
        directory is listed with no ``size``: the declared bytes cannot be told from
        the trailer, so ``open()`` has nothing to deliver. The code is in
        ``ARCHIVE_INTEGRITY_CODES``, so ``DiagnosticPolicy.STRICT`` refuses the
        archive, the weight DR-3 gives a directory's declared data in every format.
        The marker checks that follow report the trailer as they would after a file.
        The finding is attached to the member, as the old-style directory's is, which
        is why the walk keeps its last member and not only its last entry.
        """
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED,
            message=(
                f"Directory {quoted(member.name)} declares {directory.size} bytes of "
                "data and the archive ends on a zero block inside the span those bytes "
                "would occupy: a TAR directory entry has no data area, so if the "
                "blocks are there they were read as the end-of-archive marker and the "
                "members behind them are not listed. Extraction creates the directory; "
                "the bytes cannot be told from the trailer, so there is nothing to "
                "read."
            ),
            context=DirectoryDataContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                size=directory.size,
                compressed_size=None,
            ),
            member=member,
            attach_to_member=True,
            logger=integrity_logger,
        )

    def _refuse_directory_blocks(
        self, member: ArchiveMember, directory: TarSpan
    ) -> None:
        """Raise ``CorruptionError`` naming a ``DIRTYPE`` header with a size when the
        block where its data would begin is neither a member header nor a zero block.

        The archive is damaged there whichever reading holds, the declared blocks
        present and read as a header or absent with junk behind the directory; GNU tar
        reports "Skipping to next header" and exits 2 on both. The generic rejected
        header report would raise anyway; this one names the directory, since its
        declared size is the likeliest reason a header sits where none parses. A
        rejected block further on, past a header chain that did parse, is not this
        case and gets the generic report.
        """
        raise CorruptionError(
            f"TAR header for {quoted(member.name)} is a directory that declares "
            f"{directory.size} bytes of data, and the block where that data would "
            "begin is neither a member header nor a zero block: a directory entry has "
            "no data area, so either the declared blocks are there and were read as a "
            "header, or the archive is damaged right after the directory",
            archive_name=self._archive_name,
            member_name=member.name,
        )

    def _verify_nothing_but_zeros_to_eof(self, stream: BinaryIO) -> None:
        """Report a non-zero byte within ``_MAX_TRAILING_SCAN`` bytes of the trailer.

        Without this, a complete trailer asserted only that the two trailer blocks were
        present — 4 KiB of arbitrary appended bytes passed silently. Zeros still pass,
        deliberately: writers pad to 10 KiB records routinely, so "nothing but zeros" is
        the strongest rule that does not flag what ``tar(1)`` itself writes.

        Concatenated archives are reported here, which is the intended answer — they are
        two archives and only the first was listed.

        The scan is bounded because it is not free: on a compressed tar the tail must be
        decompressed to be inspected. Past the bound it stops looking and reports
        nothing, so a second archive further out goes unseen; the bound is an effort
        limit, not a claim that the rest is zero. Read in bounded chunks: the tail may be
        arbitrarily long and must not be materialized. On a forward-only source the
        reads go past the trailer too, so a pipe held open after the tar ends blocks
        here until more bytes or EOF arrive; ``docs/formats.md`` says so to callers.

        A tail that fails to *decode* never raises. Every member was already read
        whole, so a decode failure out here must not turn a good listing into an
        error, and it is not trailing tar data, so it is not reported as that. The one
        exception is a :class:`_StreamChecksumError`: a codec checksum that covers the
        whole decoded stream (gzip's CRC-32 and ISIZE, zlib's Adler-32, the zstd and lz4
        content checksums, lzip's CRC-32) failed, so the members already read are
        damaged, and that raises. A ``tar -b128`` record pads 64 KiB past the trailer,
        so this scan is often where the checksum is reached.

        A compressed stream that ends early (a cut gzip footer, a cut lz4 end mark and
        content checksum) is :class:`TruncatedError` here. The checksum that would
        cover the members was never reached, so on any codec that can carry one this is
        ``DIGEST_UNVERIFIABLE`` (``reason="trailing_stream_truncated"``). Junk after
        the compressed stream is reported by the codec itself, as
        ``ARCHIVE_TRAILING_DATA``.

        Any other decode failure here (a damaged deflate stream past the trailer, say)
        is ``DIGEST_UNVERIFIABLE`` (``reason="trailing_decode_failed"``) on a codec
        that can carry a checksum, not silence. It is worded as "cannot be told", not
        "never reached": the bytes that failed may be in the members' own stream, or
        in a further compressed member (``cat a.tar.gz b.gz``) whose predecessor's
        checksum was already checked, and nothing here tells the two apart. A further
        member that fills a whole scan chunk (``_TRAILING_SCAN_CHUNK``) of output
        in a read that does not fail is reported as trailing data instead; one that
        fails before that loses its output with the failing read.
        bzip2 and xz check each block, and neither reports a failed check differently
        from junk after the stream, so on those the failure may be that check itself.
        When the codec had already read to the failure during the last member's read,
        it fails there instead, as ``CorruptionError`` from that read.

        The first non-zero byte ends the scan, on every codec. Reading on to the
        stream's checksum would look more thorough, but nothing here says where the
        listed members' compressed stream ends: in a concatenated ``.tar.gz`` the
        trailing bytes are a second gzip member, whose checksum covers none of the
        listed members, while the first member's was already checked on the way in.
        So past trailing bytes the scan claims nothing about the checksum either way;
        ``ARCHIVE_TRAILING_DATA`` is the report, and ``STRICT`` refuses it.

        When the scan stops at its bound with the compressed stream not yet at its end,
        that checksum was never checked, and ``DIGEST_UNVERIFIABLE`` says so.
        """
        offset = 0
        while offset <= _MAX_TRAILING_SCAN:
            # One byte past the bound, to learn whether the stream ended there.
            want = min(_TRAILING_SCAN_CHUNK, _MAX_TRAILING_SCAN - offset) or 1
            try:
                with self._translated_errors(), self._walk_guard():
                    chunk = stream.read(want)
            except _StreamChecksumError:
                # Nothing non-zero has come out since the trailer, so the stream this
                # checksum covers holds the members already read: this is damage to
                # them, not a tail that failed to decode. (A codec's read-ahead can
                # also check a short further member whose output this read has not
                # returned yet; that is attributed to the members too.)
                raise
            except TruncatedError:
                # The compressed stream ends before its footer, so the checksum it
                # would carry over the members already read was never reached.
                self._emit_stream_checksum_unverified(
                    reason="trailing_stream_truncated"
                )
                return
            except ReadError:
                # In the members' stream or a further one: whether the checksum over
                # the members passed cannot be told.
                self._emit_stream_checksum_unverified(reason="trailing_decode_failed")
                return
            if not chunk:
                return
            if offset == _MAX_TRAILING_SCAN:
                self._emit_stream_checksum_unverified(reason="trailing_scan_limit")
                return
            stripped = chunk.lstrip(b"\x00")
            if stripped:
                self._emit_trailing_data(
                    observed_bytes=offset + (len(chunk) - len(stripped))
                )
                return
            offset += len(chunk)

    def _emit_stream_checksum_unverified(self, *, reason: str) -> None:
        """Report a compressed stream whose checksum the trailing scan could not check.

        ``reason`` is ``"trailing_scan_limit"`` when the scan stopped at its bound
        before the stream's end, ``"trailing_stream_truncated"`` when the compressed
        stream ended before its footer, and ``"trailing_decode_failed"`` when the
        tail failed to decode in another way (see
        :meth:`_verify_nothing_but_zeros_to_eof`). Only for a codec that can carry
        such a checksum; the zstd, lz4 and xz ones are optional, so the message says
        "if it carries one".
        """
        stream = self._format.stream
        if stream not in _STREAMS_WITH_CHECKSUM:
            return
        if reason == "trailing_scan_limit":
            what = (
                f"continues more than {_MAX_TRAILING_SCAN} bytes past the "
                "end-of-archive marker, and the scan stopped there: the stream's "
                "checksum, if it carries one, was not checked"
            )
        elif reason == "trailing_stream_truncated":
            what = (
                "ends before its footer, past the end-of-archive marker: the stream's "
                "checksum, if it carries one, was never reached"
            )
        elif stream in _STREAMS_WITH_UNTYPED_CHECKSUM:
            what = (
                "fails to decode past the end-of-archive marker: this codec reports a "
                "failed check the same way as junk after the stream, so whether the "
                "checksum passed cannot be told"
            )
        else:
            what = (
                "fails to decode past the end-of-archive marker: the failure may be "
                "in the stream that holds the members or in a further compressed "
                "member after it, so whether the checksum passed cannot be told"
            )
        self._diagnostics_collector.emit(
            code=DiagnosticCode.DIGEST_UNVERIFIABLE,
            message=(
                f"The {stream.value} stream around this TAR archive {what}, so damage "
                "to the members already read may go unseen."
            ),
            context=DigestContext(
                archive_name=self._archive_name,
                algorithm=f"{stream.value} stream checksum",
                reason=reason,
            ),
            logger=integrity_logger,
        )

    def _emit_trailing_data(self, *, observed_bytes: int) -> None:
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_TRAILING_DATA,
            message=(
                "TAR archive continues past its end-of-archive marker: a non-zero byte "
                f"appears {observed_bytes} bytes after the trailer. The listing does not "
                "account for it (this file may be two archives concatenated)."
            ),
            context=ArchiveEofContext(
                archive_name=self._archive_name,
                format="tar",
                expected_marker="zeros_to_eof",
                expected_bytes=0,
                observed_bytes=observed_bytes,
                observed_kind="nonzero",
            ),
            logger=backends_logger,
        )

    def _emit_eof_marker(self, end: _EofFinding, *, observed_bytes: int) -> None:
        """Report a missing or damaged two-zero-block end-of-archive marker.

        ``end`` says what was found where the marker belongs (see :data:`_EofFinding`).
        ``"rejected_header"`` and ``"no_member"`` are corruption whatever the policy:
        the first means a header that does not parse ended the walk and shortened the
        listing, the second that a file with no member is a zero block and then junk,
        which must not open as an empty tar. The other three follow the policy.
        ``"damaged_second_block"`` gets its own ``expected_marker``,
        ``"second_zero_block"``, so a caller can tell a whole listing from a
        shortened one by the context, not the message.
        """
        expected_marker = "two_zero_blocks"
        expected_bytes = 1024
        observed_kind: Literal["absent", "short", "nonzero"] = "nonzero"
        escalate_as: type[BaseException] | None = None
        if end == "damaged_second_block":
            message = (
                "TAR archive's end-of-archive marker is damaged: a zero block ends the "
                "members, but the block after it is not zero. Every member before it is "
                "listed."
            )
            expected_marker = "second_zero_block"
            expected_bytes = 512
        elif end == "rejected_header":
            message = (
                "TAR archive is corrupt: a member header that does not parse appears "
                "where the next header or the end-of-archive marker was expected, so "
                "the members after it are not listed."
            )
            escalate_as = CorruptionError
        elif end == "no_member":
            message = (
                "TAR archive is corrupt: it has no member, and the block after its "
                "first zero block is not zero. A file that is only a zero block and "
                "then other bytes is not shown to be a TAR archive, so it does not "
                "open as an empty one."
            )
            escalate_as = CorruptionError
        else:
            message = (
                "TAR archive may be truncated: missing or short end-of-archive marker "
                "block(s)."
            )
            observed_kind = end
        escalate_kwargs: dict[str, object] | None = None
        if escalate_as is not None:
            escalate_kwargs = {
                "source_format": self._format,
                "archive_name": self._archive_name,
            }
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
            message=message,
            context=ArchiveEofContext(
                archive_name=self._archive_name,
                format="tar",
                expected_marker=expected_marker,
                expected_bytes=expected_bytes,
                observed_bytes=observed_bytes,
                observed_kind=observed_kind,
            ),
            logger=backends_logger,
            escalate_as=escalate_as,
            escalate_kwargs=escalate_kwargs,
        )

    def _source_stream_capability(self) -> StreamCapability:
        assert self._source is not None
        if self._source.seekable():
            return StreamCapability.SEEKABLE
        return StreamCapability.FORWARD_ONLY

    def _extra_pax_headers(self, entry: TarEntry) -> _ReadOnlyDict:
        """``extra["tar.pax_headers"]`` for ``entry``: its PAX records, the global ones
        in force included, as text.

        A read-only copy. Members that carry only the PAX global records share one,
        as the walker shares the records: one per member cost the global records once
        for every 512-byte member header. Read-only so that sharing it is invisible: a
        change made through one member cannot show on another.
        """
        if entry.has_own_pax:
            return _ReadOnlyDict(self._pax_headers_text(entry.pax))
        shared = self._shared_pax
        if shared is None or shared[0] is not entry.pax:
            shared = self._shared_pax = (
                entry.pax,
                _ReadOnlyDict(self._pax_headers_text(entry.pax)),
            )
        return shared[1]

    def _pax_headers_text(self, records: Mapping[bytes, PaxValue]) -> dict[str, str]:
        """PAX records as text. Keys and values are UTF-8 when their bytes are valid
        UTF-8, under ``hdrcharset=BINARY`` too, as the member's name is; a value that is
        not falls back to the archive codec (``_decode_not_utf8``)."""
        text: dict[str, str] = {}
        for key, entry in records.items():
            value = entry.value
            try:
                decoded = value.decode("utf-8")
            except UnicodeDecodeError:
                decoded = self._decode_not_utf8(value)
            text[key.decode("utf-8", "surrogateescape")] = decoded
        return text

    def _decode_not_utf8(self, raw: bytes) -> str:
        """Bytes that are not valid UTF-8, decoded with the archive codec: the
        caller's ``encoding=``, else UTF-8, with undecodable bytes kept as surrogates.

        ``surrogateescape`` can escape only a byte of 0x80 or more, so a codec that
        does not read ASCII bytes as ASCII can still fail: ``utf-16`` on an odd byte
        count, ``utf-32`` on a code point out of range, ``utf-7`` on a ``+`` shift
        that ends badly; ``idna`` refuses the handler outright. Such a name decodes as
        it would with no ``encoding=``, as in ZIP, RAR and ISO.

        ``_decode_name`` also passes valid UTF-8 here, only to compare readings.
        """
        try:
            return raw.decode(self._codec, "surrogateescape")
        except UnicodeError:
            return raw.decode("utf-8", "surrogateescape")

    def _decode_name(
        self, raw: bytes, source: NameSource | None, binary: bool
    ) -> tuple[str, bool]:
        """A name, link name, user or group name as text, and whether the UTF-8
        reading was taken over the caller's ``encoding=``.

        A PAX value is UTF-8 unless its block says ``hdrcharset=BINARY``; one that is
        not valid UTF-8 falls back to the archive codec. A ustar or GNU field, or a
        ``BINARY`` PAX value, declares no encoding: it is UTF-8 when its bytes are
        valid UTF-8, else the caller's ``encoding=`` (UTF-8 with surrogateescape by
        default), the rule every format follows.
        """
        # UTF-8 is tried before the codec, ASCII included: ``encoding="cp037"`` would
        # otherwise turn the ASCII name ``abc`` into ``/ÂÄ``.
        try:
            utf8_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return self._decode_not_utf8(raw), False
        if (
            self._encoding is None
            or raw.isascii()
            or (source is NameSource.PAX and not binary)
        ):
            return utf8_text, False
        # Through the helper, not the codec: a codec that cannot decode these bytes
        # (``idna``, ``utf-16`` on an odd byte count) must not fail the listing, and
        # would not have named the member, so its fallback reading equals the UTF-8
        # one and nothing is reported, as RAR's ``_utf8_over_encoding`` does.
        return utf8_text, utf8_text != self._decode_not_utf8(raw)

    def _to_member(self, entry: TarEntry, index: int) -> ArchiveMember:
        """Type one member. ``index`` is its position in the walk, the id registration
        stamps, so the diagnostics raised here can name it before it has one."""
        member_type = _member_type(entry)
        presented, inferred = self._decode_name(
            entry.name, entry.name_source, entry.name_binary
        )
        if entry.name_source is NameSource.PAX or member_type == MemberType.DIRECTORY:
            # A PAX path is read with its trailing slashes removed, as tarfile reads
            # it; a directory's slash is its type.
            presented = presented.rstrip("/") or presented
        # TAR is a POSIX format: a backslash is a legal filename character, not a separator.
        name = normalize_member_name(
            presented, member_type, backslash_is_separator=False
        )

        link_target: str | None = None
        if entry.linkname is not None:
            link_target, _ = self._decode_name(
                entry.linkname, entry.linkname_source, entry.linkname_binary
            )

        timestamp_issues: list[TimestampIssue] = []
        modified: datetime | None
        if entry.pax and _pax_text(entry, b"mtime") is not None:
            modified, issue = _pax_time(entry, "mtime", presented)
            if issue is not None:
                timestamp_issues.append(issue)
        else:
            # A hostile out-of-range value (a base-256 mtime beyond datetime's range)
            # must not sink the whole listing, so it degrades to None and is reported.
            modified = unix_to_datetime(entry.header.mtime)
            if modified is None:
                timestamp_issues.append(
                    _tar_time_issue(
                        presented, "mtime", repr(entry.header.mtime), pax_record=False
                    )
                )

        compression = (
            _STORED_COMPRESSION
            if member_type in (MemberType.FILE, MemberType.HARDLINK)
            else ()
        )

        # The typeflag as stored: NUL or 0 for an old-style directory, so a caller can
        # tell it from a DIRTYPE one.
        extra = MemberExtra({"tar.type": entry.typeflag})
        special = special_file_type_from_tar_typeflag(entry.typeflag)
        if special is not None:
            if entry.size:
                # The typeflag is structure in TAR, so a device or FIFO header has no
                # data: GNU tar and libarchive ignore its size field and read the next
                # header where the "data" starts. An all-zero payload would then read
                # as the end-of-archive marker and every later member would vanish
                # without a word, so the header is refused as damage (DR-25).
                raise CorruptionError(
                    f"TAR header for {quoted(name)} is a {special.replace('_', ' ')} "
                    f"that declares {entry.size} bytes of data; a device or FIFO entry "
                    "has no data, and tar skips such a header as damaged",
                    archive_name=self._archive_name,
                    member_name=name,
                )
            # The cross-format key says which kind the archive recorded (DR-25).
            extra[EXTRA_SPECIAL_FILE_TYPE] = special
        if entry.pax:
            extra["tar.pax_headers"] = self._extra_pax_headers(entry)
        if entry.header.devmajor is not None and entry.header.devminor is not None:
            # Set for a ustar or GNU character or block device only: a FIFO or a v7
            # header holds no device number, and GNU tar reads none there.
            extra["tar.devmajor"] = entry.header.devmajor
            extra["tar.devminor"] = entry.header.devminor

        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=entry.name,
            # An old-style directory keeps its declared size: its regular-file
            # typeflag gives it a data area, which open() and a pass deliver (DR-3). A DIRTYPE
            # size names no data area, so it is dropped here and judged at the end
            # of the walk (_verify_tar_eof).
            size=entry.size
            if member_type == MemberType.FILE
            or (entry.old_style_directory and entry.size)
            else None,
            modified=modified,
            # The permission bits are the low twelve, which is what stat.S_IMODE
            # keeps. Masked here rather than through S_IMODE, which refuses the
            # negative or wider-than-32-bit value a GNU base-256 mode field can hold.
            mode=entry.header.mode & 0o7777,
            uid=entry.uid,
            gid=entry.gid,
            compression=compression,
            extra=extra,
            # The span alone, so _open_member needs no name/id lookup table and the
            # parsed entry (header, names, PAX records) is not kept per member.
            _raw=entry.span(),
        )
        # Skip defaulted None/False fields on the listing hot path (perf review L2).
        if entry.pax:
            accessed, issue = _pax_time(entry, "atime", presented)
            if accessed is not None:
                member.accessed = accessed
            elif issue is not None:
                timestamp_issues.append(issue)
            # PAX ``ctime`` is st_ctime (inode change), never a birth time, so it is
            # ``ctime``, never ``created``.
            ctime, issue = _pax_time(entry, "ctime", presented)
            if ctime is not None:
                member.ctime = ctime
            elif issue is not None:
                timestamp_issues.append(issue)
            # libarchive writes the source's birth time, where the OS has one, as a PAX
            # extension keyword. It is the only TAR writer known to store a birth time.
            birth, issue = _pax_time(entry, "LIBARCHIVE.creationtime", presented)
            if birth is not None:
                member.created = birth
            elif issue is not None:
                timestamp_issues.append(issue)
        uname = self._owner_name(entry.uname, entry.uname_pax)
        if uname:
            member.uname = uname
        gname = self._owner_name(entry.gname, entry.gname_pax)
        if gname:
            member.gname = gname
        if link_target is not None and member_type in (
            MemberType.SYMLINK,
            MemberType.HARDLINK,
        ):
            member.link_target = link_target
        # All four GNU encodings: the old ``S`` typeflag and PAX sparse 0.0 / 0.1 /
        # 1.0, which GNU tar writes under ``--format=pax`` with a plain ``0`` typeflag.
        if entry.sparse_format is not None:
            member.is_sparse = True
        # member.name is still ``name``: this is the callee's own early return, kept
        # here to skip the call for the common unchanged name.
        if name != presented:
            emit_member_name_normalized(
                self._diagnostics_collector,
                member=member,
                presented_name=presented,
                archive_name=self._archive_name,
                member_id=index,
            )
        for issue in timestamp_issues:
            self._emit_timestamp_invalid(member, index, issue)
        if inferred:
            # The UTF-8 reading was taken over the caller's encoding=, which ZIP and
            # RAR 1.5-4 report the same way.
            assert self._encoding is not None
            self._emit_name_encoding_inferred(
                member,
                index,
                inferred_encoding="utf-8",
                passed_over=self._encoding,
                message=(
                    f"TAR member name decoded as 'utf-8' rather than "
                    f"{self._encoding!r} (the stored bytes are valid UTF-8): "
                    f"{quoted(member.name)}"
                ),
            )
        if entry.header.device_number_fault is not None:
            # GNU tar 1.35 reports the field and lists the device with a garbage
            # number. Here the numbers are absent, never wrong, and the walk goes on.
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=(
                    f"TAR device {quoted(member.name)}: "
                    f"{entry.header.device_number_fault}; the member has no device "
                    "numbers."
                ),
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    record="device_numbers",
                    reason=entry.header.device_number_fault,
                ),
                member=member,
                attach_to_member=True,
                logger=backends_logger,
            )
        if entry.old_style_directory and entry.size:
            # GNU tar creates the directory and skips the bytes without a word (7-Zip
            # too, for NUL and 0). Say so; read() delivers them.
            self._emit_directory_data_ignored(member, index)
        if entry.link_data is not None:
            self._emit_link_data_ignored(member, index, entry)
        if entry.typeflag not in _KNOWN_TYPES:
            self._emit_member_type_unknown(member, index, entry.typeflag)
        return member

    def _emit_link_data_ignored(
        self, member: ArchiveMember, member_id: int, entry: TarEntry
    ) -> None:
        """Report ``MEMBER_LINK_DATA_IGNORED`` for a link header whose declared
        blocks the walk took as its data (:class:`LinkData`).

        A TAR link has no data area. The walker skipped the declared blocks, so a
        zero block among them did not end the listing, as the maintainer ruled
        (2026-10-17); GNU tar and ``tarfile`` stop at such a block and drop the members
        after it. The code is in ``ARCHIVE_INTEGRITY_CODES``, as
        ``MEMBER_DIRECTORY_DATA_IGNORED`` is: a warning by default, refused under
        ``DiagnosticPolicy.STRICT``. The finding is attached to the member.
        """
        kind = "Symlink" if member.type == MemberType.SYMLINK else "Hard link"
        declares = f"{kind} {quoted(member.name)} declares {entry.size} bytes of data"
        if entry.link_data is LinkData.ENDS_ARCHIVE:
            what = (
                f"{declares}, and the archive ends on zero bytes before the span those "
                "bytes would occupy ends: if the blocks are there, they are zeros cut "
                "short; if not, the zero block is the end-of-archive marker."
            )
        else:
            what = (
                f"{declares}; a TAR link entry has no data area, so the blocks are "
                "skipped. If they are all zeros and no member header follows them, "
                "they are read as the end-of-archive marker, as for a link whose "
                "blocks were never written, and the listing ends there."
            )
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_LINK_DATA_IGNORED,
            message=(
                f"{what} Extraction creates the link and does not write the bytes."
            ),
            context=LinkDataContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                size=entry.size,
            ),
            member=member,
            attach_to_member=True,
            logger=integrity_logger,
        )

    def _emit_member_type_unknown(
        self, member: ArchiveMember, member_id: int, typeflag: bytes
    ) -> None:
        """Report ``MEMBER_TYPE_UNKNOWN`` for a header whose typeflag archivey does
        not know. GNU tar warns too ("Unknown file type"); the code is advisory."""
        stored_type = typeflag.decode("latin-1")
        if member.type == MemberType.FILE:
            outcome = (
                f"it declares {member.size} bytes of data, so it is listed as a file, "
                "as GNU tar extracts it"
            )
        else:
            outcome = "it declares no data, so it is listed as OTHER and not extracted"
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_TYPE_UNKNOWN,
            message=(
                f"TAR member {quoted(member.name)} has the unknown type "
                f"{stored_type!r}: {outcome}."
            ),
            context=UnknownMemberTypeContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                stored_type=stored_type,
                size=member.size,
            ),
            member=member,
            attach_to_member=True,
            logger=backends_logger,
        )

    def _owner_name(self, header: bytes, pax: PaxValue | None) -> str:
        """``uname`` or ``gname``: a PAX record of that name overrides the header's."""
        if pax is not None:
            return self._decode_name(pax.value, NameSource.PAX, pax.binary)[0]
        return self._decode_name(header, NameSource.HEADER, False)[0]

    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        # The stream layer (streamtools) raises builtins, never archivey errors.
        # Today the one EOFError a member read can raise is a sparse member's
        # SparseStream, when the stream under it returned no bytes instead of raising
        # its own TruncatedError. The message says only what every source shares, so
        # a new one still reads as truncation and is not blamed on a sparse member.
        if isinstance(exc, EOFError):
            return TruncatedError(f"TAR member data ended early: {exc}")
        return None

    def _open_member(self, member: ArchiveMember) -> ArchiveStream:
        with self._translated_errors(member.name):
            return self._open_member_stream(member, defer_sparse_error=False)

    def _member_body(self, member: ArchiveMember, *, in_walk: bool) -> BinaryIO:
        """``member``'s bytes, before the public wrapper.

        A bad sparse map raises here. ``in_walk`` reads through the walk's own stream,
        as a streaming walk does. The pass closes the stream before the walk moves on."""
        span = member._raw
        assert isinstance(span, TarSpan), "TAR member is missing its span"
        if span.sparse is not None:
            sparse_error = validate_sparse_map(
                span.sparse, span.size, span.stored_size, quoted(member.name)
            )
            if sparse_error is not None:
                raise sparse_error
        stream: BinaryIO
        if self._streaming:
            stream = self._walker.open_data(span)
        elif in_walk:
            with self._walk_lock:
                stream = self._walk_data(span)
        else:
            stream = self._independent_data(span)
        if span.sparse is not None:
            stream = SparseStream(
                stream, span.sparse.offsets, span.sparse.lengths, span.size
            )
        if self._streaming:
            assert self._handle_lock is not None
            stream = LockedStream(stream, self._handle_lock)
        return stream

    def _independent_data(self, span: TarSpan, start: int = 0) -> BinaryIO:
        """``span``'s data area from ``start``, read independently of the walk.

        A view of its own: a read seeks the shared stream under the handle lock when
        the handle is elsewhere, so members and the walk read independently. The view
        clamps its length to the source size when it has one, so a read past the end
        of the file is not issued; _MemberDataView reports a cut member either way. A
        plain tar passes its known size rather than probing it on every open. A codec
        stream keeps the probe: its size comes from the decompressor (try_get_size),
        not from the source.
        """
        view = SharedView(
            self._stream,
            span.data_offset,
            span.stored_size,
            lock=self._io_guard(),
            source_size=self._plain_source_size,
            probe_source_size=self._compressed,
        )
        if start:
            view.seek(start)
        stream: BinaryIO = _MemberDataView(view, span.data_offset, span.stored_size)
        if self._compressed:
            # The codec stream has no buffer of its own here (_open_byte_stream), so
            # a read smaller than this would cost a decoder seek and read. The buffer
            # sits above the view and reads it at most once per read, so a cut
            # member's recoverable prefix comes before its TruncatedError.
            stream = ReadAheadStream(stream, _WALK_BUFFER)
        return stream

    def _walk_data(self, span: TarSpan) -> BinaryIO:
        """``span``'s data for a pass, through the walk when the walk is at it.

        Called under the walk lock. Reading through the walk is what lets a pass
        over a compressed tar decode it once. Only one stream reads through the walk
        at a time, and only while the walk is at the start of this member's data;
        any other open (a second pass behind the first, or one in step with it) gets
        a view of its own.
        """
        data = self._walker.open_data(span)
        live = self._walk_stream
        if not data.in_place() or (live is not None and not live.closed):
            return self._independent_data(span)
        stream = _WalkHandoffStream(self, span, data)
        self._walk_stream = stream
        return stream

    def _open_member_stream(
        self, member: ArchiveMember, *, defer_sparse_error: bool
    ) -> ArchiveStream:
        """Open ``member``'s data. A bad sparse map raises here, or with
        ``defer_sparse_error`` on the first read: a forward-only consumer that skips
        the member does not read the bad map, and the walk moves on to the next
        header by the member's stored size.

        A random-access pass does not come through here: it opens the raw body
        (see :meth:`_member_body`) and wraps it once."""
        span = member._raw
        assert isinstance(span, TarSpan), "TAR member is missing its span"
        if defer_sparse_error and span.sparse is not None:
            sparse_error = validate_sparse_map(
                span.sparse, span.size, span.stored_size, quoted(member.name)
            )
            if sparse_error is not None:

                def _refuse(
                    error: CorruptionError | UnsupportedFeatureError = sparse_error,
                ) -> BinaryIO:
                    raise error

                return self._wrap_member_stream(
                    None, member.name, open_fn=_refuse, size=member.size
                )
        return self._wrap_member_stream(
            self._member_body(member, in_walk=False),
            member.name,
            size=member.size,
        )

    def _get_archive_info(self) -> ArchiveInfo:
        stream_cap = self._source_stream_capability()
        if self._compressed:
            cost = CostReceipt(
                listing_cost=ListingCost.REQUIRES_DECOMPRESSION,
                access_cost=AccessCost.SOLID,  # one compression stream over all members
                stream_capability=stream_cap,
                solid_block_count=1,
            )
        else:
            cost = CostReceipt(
                listing_cost=ListingCost.REQUIRES_SCANNING,  # walk 512-byte headers, no index
                access_cost=AccessCost.DIRECT,  # each member is at a known, independent offset
                stream_capability=stream_cap,
                solid_block_count=None,
            )
        return ArchiveInfo(
            format=self._format,
            format_version=None,
            is_solid=self._compressed,
            member_count=None,  # no central directory: a count requires a full scan
            comment=None,
            is_encrypted=False,
            is_multivolume=False,
            cost=cost,
        )

    def _close_archive(self) -> None:
        # Close what this reader built, even when a close raises: teardown runs once.
        # The source closes with the reader, after this. Under the handle lock, so a
        # concurrent member read never runs on a stream being closed.
        with self._handle_guard():
            self._release_owned_stream()


class TarReadBackend(ReadBackend):
    """Backend factory for TAR archives (plain and compressed)."""

    FORMATS: tuple[ArchiveFormat, ...] = _TAR_FORMATS
    EXTENSIONS: Mapping[str, ArchiveFormat] = _TAR_EXTENSIONS
    # Plain tar is recognized by the POSIX/GNU "ustar" magic at offset 257. Compressed tars
    # carry only their outer codec's magic; detection's inner-TAR probe (see internal/
    # detection.py) decompresses a prefix and finds this same signature to report TAR_GZ etc.
    MAGIC: tuple[MagicSignature, ...] = (
        MagicSignature(257, b"ustar", ArchiveFormat.TAR),
    )
    # TAR is walkable front-to-back, so streaming=True works on a non-seekable source
    # (random access always needs a seekable one — that side is format-independent).
    SUPPORTS_STREAMING_NON_SEEKABLE = True
    USES_ENCODING = True  # the fallback codec for names that are not valid UTF-8

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
    ) -> TarReader:
        reject_start_offset(start_offset, format, archive_name)
        # `format` carries the concrete (TAR, <stream>) variant the detector/caller resolved;
        # the backend uses its stream to pick the codec to decompress with.
        return TarReader(
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


register_reader(TarReadBackend)
