"""Seekable decompress *engine*: one stream class, many codec strategies.

:class:`DecompressorStream` owns the buffer, position, seek-point table, and seek
algorithm. Codecs plug in through the :class:`Decoder` protocol (feed / flush /
recreate / index discovery) — not by subclassing the stream.

The decoders live next to their codec in :mod:`archivey.internal.streams.codecs`, as
``<name>_decoder.py`` (``deflate_decoder``, ``brotli_decoder``, ``ppmd_decoder``,
``xz_decoder``, ``lzip_decoder``, ``unix_compress_decoder``, …), with
``framed_decoder`` for the one-shot decompressors (bzip2, zstd, LZ4).

``codecs.StreamCodec.open`` wires those into an ``ArchiveStream``; this module is
only the shared engine underneath. One exception: above :class:`SeekPoint` sit the
DEFLATE family's shared helpers, the ``zlib.error`` translators, the truncation message
and the inflate step, used by the zlib, gzip, raw DEFLATE and resume decoders.
"""

from __future__ import annotations

import bisect
import io
import lzma
import os
import zlib
from collections.abc import Callable, Container, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from typing import (
    Any,
    BinaryIO,
    Generic,
    NoReturn,
    Protocol,
    TypeVar,
    cast,
)

from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    DiagnosticContext,
    SeekIndexContext,
)
from archivey.exceptions import (
    CorruptionError,
    ReadError,
    TruncatedError,
    UnsupportedFeatureError,
    exception_detail,
)
from archivey.internal.diagnostics_collector import (
    DiagnosticCollector,
    nothing_held,
    resolve_collector,
)
from archivey.internal.logs import streams as logger
from archivey.internal.streams.child_process import is_no_verdict
from archivey.internal.streams.native_memory import end_lzma_decoder
from archivey.internal.streams.resume import (
    ResumeReachedStreamEnd,
    hold_for_planned_seek,
    planning_seek,
)
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    ensure_bufferedio,
    resolve_seek,
)
from archivey.internal.streams.verification import (
    VerificationProofs,
    ask_verification_proofs,
)


class _StreamChecksumError(CorruptionError):
    """A whole-stream checksum failed after the stream's bytes were delivered.

    Internal: callers see a :class:`CorruptionError`. A reader that tolerates a decode
    failure past the end of its own data (the TAR end-of-archive scan) re-raises this
    one, because the checksum covers bytes it has already handed out. Raised for a
    checksum over the whole decoded stream (or a member of it): gzip CRC-32 and ISIZE,
    zlib Adler-32, the zstd and lz4 content checksums, lzip CRC-32 and data size. Not
    for a check that covers one block, and not for xz, whose integrity-check failure
    liblzma reports with the same message as any corrupt input.
    """


class DataAfterEndError(CorruptionError):
    """Input left over in a container coder's compressed data after its codec's end.

    A ZIP member or a 7z coder declares its compressed size, so no honest writer leaves
    bytes there that the codec does not read; a zero byte counts too. 7-Zip reports
    them as a data error ("There are some data after the end of the payload data", or
    "Data Error"). Raised where a stream was opened with
    ``StreamConfig.refuse_input_after_end``, and by raw LZMA, which is container-only,
    whatever it was opened with (:func:`input_after_end_error`). A class of its own so
    a check that reads one byte past a coder's declared output, and discards a decoder
    error there, can still let this one through.
    """


def gzip_corruption(exc: Exception, label: str = "gzip") -> CorruptionError:
    """The error for a ``zlib.error`` from a gzip or zlib stream.

    zlib names a failed trailer check "incorrect data check" (the gzip CRC-32 or the
    zlib Adler-32) or "incorrect length check" (gzip ISIZE); both cover the whole
    member, so they are :class:`_StreamChecksumError`. Anything else is damage to
    the deflate body itself.
    """
    text = str(exc)
    if "incorrect data check" in text or "incorrect length check" in text:
        return _StreamChecksumError(
            f"Error reading {label} stream: {exception_detail(exc)}"
        )
    return CorruptionError(f"Error reading {label} stream: {exception_detail(exc)}")


# zlib's gzip-window errors for a member header that gzip(1) refuses as unsupported,
# not as damaged: "unknown method 7 -- not supported" (CM other than 8 = deflate), and
# "has flags 0x80 -- not supported" / "is encrypted -- not supported" (a reserved FLG
# bit, which RFC 1952 says a decoder must refuse).
_GZIP_UNSUPPORTED_HEADER = ("unknown compression method", "unknown header flags set")


def input_after_end_error(name: str, output: int | None = None) -> DataAfterEndError:
    """The error for input after a codec's end, where the container refuses it.

    ``StreamConfig.refuse_input_after_end`` (DR-3). The decoders' check
    (``DecompressorStream``) and the bzip2 accelerator's end check both raise it.
    ``output`` is the stream's output before that end, when known. The bytes are
    either data the member carries after the stream or, for a codec that stops at a
    declared output size, the rest of a stream that size cuts short.
    """
    at = "" if output is None else f" after {output} bytes of output"
    return DataAfterEndError(
        f"{name} stream ends{at} before its input does: bytes are left after its end "
        "(data after the stream, or a declared size shorter than the stream)"
    )


def gzip_error(exc: Exception) -> CorruptionError | UnsupportedFeatureError:
    """The error for a ``zlib.error`` from a gzip stream.

    A member header gzip refuses as unsupported is :class:`UnsupportedFeatureError`;
    anything else is :func:`gzip_corruption`.
    """
    if any(text in str(exc) for text in _GZIP_UNSUPPORTED_HEADER):
        return UnsupportedFeatureError(
            f"Unsupported gzip member header: {exception_detail(exc)}; a damaged "
            "header reads the same way"
        )
    return gzip_corruption(exc)


def zlib_error(exc: Exception, label: str) -> CorruptionError:
    """The error for a ``zlib.error`` from a zlib (``label`` "zlib") or raw DEFLATE
    ("deflate") stream: always :func:`gzip_corruption`.

    Unlike :func:`gzip_error`, a refused header is not unsupported. zlib refuses a zlib
    header whose method is not deflate ("unknown compression method"), but RFC 1950
    defines no method other than 8, so that header is damage, not a valid feature
    archivey cannot decode (DR-4).
    """
    return gzip_corruption(exc, label)


def truncated_message(label: str) -> str:
    """The message of the :class:`TruncatedError` a decoder gives a ``label`` stream
    that ends before its end marker."""
    return f"{label} stream is truncated"


class _Inflater(Protocol):
    """``zlib.decompressobj()``'s surface, in this process or a child."""

    def decompress(self, data: bytes, max_length: int = ..., /) -> bytes: ...

    def flush(self, length: int = ..., /) -> bytes: ...

    @property
    def unconsumed_tail(self) -> bytes: ...

    @property
    def eof(self) -> bool: ...


def _inflate(
    decomp: _Inflater,
    data: bytes,
    max_length: int,
    error: Callable[[zlib.error], Exception],
) -> bytes:
    """One inflate step: ``data`` to at most ``max_length`` output bytes, the rest kept
    in ``unconsumed_tail``. A negative ``max_length`` is no limit, and so is 0 (zlib's
    reading): ``DecompressorStream`` never asks for 0 bytes. A ``zlib.error`` leaves
    as ``error`` maps it."""
    try:
        if max_length < 0:
            return decomp.decompress(data)
        return decomp.decompress(data, max_length)
    except zlib.error as exc:
        raise error(exc) from exc


def _inflate_rest(decomp: _Inflater, error: Callable[[zlib.error], Exception]) -> bytes:
    """At the end of the input: the output of what ``decomp`` still holds.

    The caller checks ``decomp.eof`` after: when it is false, the stream is truncated.
    The end is reached with ``decompress`` (with no input when nothing is left over:
    zlib may still hold output that an earlier ``max_length`` cut short), not with
    ``flush``: PyPy's ``flush`` never sets ``eof``, so a stream that ended there would
    read as truncated. On CPython that ``decompress`` drains everything zlib holds, so
    the ``flush`` after it returns nothing; it stays for a binding whose ``decompress``
    holds output back, so a truncated stream still yields every byte decoded.
    """
    out = _inflate(decomp, decomp.unconsumed_tail, -1, error)
    if decomp.eof:
        return out
    try:
        return out + decomp.flush()
    except zlib.error as exc:
        raise error(exc) from exc


@dataclass(order=True, slots=True)
class SeekPoint:
    """A point from which decompression can resume.

    Ordered by ``decompressed_offset`` only, so ``bisect`` over a ``list[SeekPoint]``
    works without a ``key=`` argument.
    """

    decompressed_offset: int
    compressed_offset: int = field(compare=False)
    # Opaque per-codec resume token. Compared by identity, and by == where a
    # codec re-emits an equal-valued token for the same offset
    # (``_resolve_same_offset_collision``). Deliberately Any: object breaks
    # the assignment of a non-None value to ``_XzBlockBounds`` in
    # ``XzDecoder.from_point``, the block it hands to ``_XzBlockResume``; one Any
    # here vs a cast there.
    state: Any = field(default=None, compare=False)
    # The point came from the file's own index (a seek table, trailers, block sizes), or
    # from a decode that resumed at such a point and counted its offsets from it. Only
    # a decode from the origin, through points like it, proves an offset; the stream
    # drops every point that has this flag when the index and the decode disagree
    # (``DecompressorStream._drop_index``). One index source is left unmarked: xz's
    # per-stream scan during a forward read (``XzDecoder._progressive_stream_points``)
    # reads block records but emits them as decoded points. That is safe because no
    # check could find those points wrong. The offset check never fires for xz: a
    # block point's state holds its own output offset, so two xz points with the same
    # state are at the same offset. The end-total check cannot disagree either:
    # liblzma verifies each stream's index against its block headers at the stream's
    # end and raises when they differ, before a decode publishes a total. And the
    # scan runs only once the decode has crossed that stream and liblzma has checked
    # its index, so a resume at one of its points that fails before any output
    # (``DecompressorStream._drop_index_at_failed_point``) is damage the decode would
    # meet too, and raising it is right.
    from_index: bool = field(default=False, compare=False)


def _is_data_verdict(exc: Exception) -> bool:
    """Whether a decoder's exception is about the bytes it was fed.

    Not a verdict: an ``OSError`` (the caller's source), a ``MemoryError``, an error
    marked by ``child_process.mark_no_verdict`` (a decoder child ended from outside,
    most often by the out-of-memory killer, or one that could not start), and a
    ``ReadError`` that is not a ``CorruptionError``. A ``ResourceLimitError`` is
    otherwise a verdict: inside a decode it is a ``DecoderLimits`` refusal of a size a
    header declared (``check_decoder_memory``), and those bytes are what the index
    pointed at.

    Every other exception counts as a verdict, on purpose. The exception here is
    mostly the backend's own (``zstd.ZstdError``, ``zlib.error``, ``lzma.LZMAError``),
    not yet translated, and its type differs by codec and by backend; this stream
    holds no translator to ask (``StreamCodec.translate``). Reading an unknown
    exception as a verdict costs at most the index: the stream reports
    ``SEEK_INDEX_DEGRADED`` with the exception's text and decodes from the start,
    where an error that is not specific to the resume raises again.
    """
    if isinstance(exc, (OSError, MemoryError)) or is_no_verdict(exc):
        return False
    return not isinstance(exc, ReadError) or isinstance(exc, CorruptionError)


def _same_state(a: object, b: object) -> bool:
    """Whether two resume states are the same: by identity for shared objects, by value
    for re-emitted XZ block bounds (progressive enrichment and ``build_index`` build
    distinct instances)."""
    return a is b or a == b


def _as_index_point(point: SeekPoint) -> SeekPoint:
    """``point``, marked as an index's claim. A new object: index points are shared."""
    if point.from_index:
        return point
    return SeekPoint(
        point.decompressed_offset, point.compressed_offset, point.state, True
    )


@dataclass
class DecodeOut:
    """Bytes produced by a decoder step, plus any absolute seek points discovered."""

    data: bytes
    points: list[SeekPoint] = field(default_factory=list)


class Decoder(Protocol):
    """Codec strategy for :class:`DecompressorStream`."""

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder: ...

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        """Decode ``chunk``, producing at most ``max_length`` output bytes when ≥ 0.

        When ``max_length`` limits output, unconsumed compressed input must be retained
        so a subsequent ``feed(b"", max_length=…)`` (while :attr:`needs_input` is false)
        can continue without the stream reading more from the source. ``max_length=-1``
        means unlimited (used by ``readall`` / flush-to-EOF).
        """
        ...

    def flush(self) -> DecodeOut:
        """Finalize at compressed EOF — the sole truncation-detection point.

        Called exactly once when the compressed source is exhausted. Implementations
        MUST arm :attr:`pending_error` with a :class:`~archivey.exceptions.TruncatedError`
        when the decode is incomplete (not :attr:`finished`, or finished alongside a
        known truncation such as unix-compress leftover bits), and MUST return any
        recoverable flush leftover rather than raising that truncation inline.
        :class:`~archivey.exceptions.CorruptionError` for trailing junk / hard
        corruption MAY still raise from ``flush``.
        """
        ...

    @property
    def finished(self) -> bool: ...

    @property
    def trailing_bytes(self) -> int | None:
        """How many of the bytes fed so far lie past the stream's end, once any do.

        ``None`` until the decoder has reached the end of its data and found a non-zero
        byte after it that starts no further stream. The count runs from that byte to
        the end of everything fed, so the stream can turn it into a source offset. A
        decoder that sets it is :attr:`finished` and ignores further input.
        """
        ...

    @property
    def input_after_end(self) -> bool:
        """True once any byte, a zero too, has been fed after the stream's end.

        Unlike :attr:`trailing_bytes` this counts zero padding, and the decoder may go
        on reading after it. A stream opened with ``refuse_input_after_end`` ends there
        and raises :class:`DataAfterEndError` once its output has been read (DR-3).
        """
        ...

    @property
    def needs_input(self) -> bool:
        """False when more output can be produced without reading new compressed bytes."""
        ...

    @property
    def drains_after_flush(self) -> bool:
        """True when ``flush`` returned output and more follows through ``feed(b"")``."""
        ...

    @property
    def pending_error(self) -> BaseException | None: ...

    def clear_pending_error(self) -> None:
        """Clear :attr:`pending_error` after the stream has raised it (or on seek reset)."""
        ...

    def close(self) -> None:
        """Release decoder-owned native resources deterministically.

        A decoder whose native object lives in a child process gives the process
        back here, so it can serve the next decoder without waiting for GC. A
        decoder holding a native worker whose lifetime is unsafe under GC (PPMd)
        uses this to reach a clean state before it is dropped. Idempotent; never
        raises.
        """
        ...

    def build_index(
        self, inner: BinaryIO, last_known: SeekPoint
    ) -> tuple[list[SeekPoint], int | None]: ...

    @property
    def index_reads_whole_source(self) -> bool:
        """True when :meth:`build_index` reads the payload front to back.

        False when the scan reads only index/trailer structures, as the xz, lzip and
        zstd scans do, even when a file of many small streams makes those structures
        large. True for the BGZF walk, which reads every byte of the compressed source.
        A size query (:meth:`DecompressorStream.try_get_size`) must be cheap, so it does
        not build an index that reads the payload: the size stays unknown until a seek
        builds the index or a read reaches the end. A seek still builds it.
        """
        ...


class BaseDecoder:
    """Default decoder behavior: empty points, no pending error, no-op index build.

    Subclasses that override :meth:`flush` own truncation detection: at compressed
    EOF, arm :attr:`pending_error` when the stream is incomplete and return any
    leftover bytes — do not raise :class:`~archivey.exceptions.TruncatedError` from
    ``flush`` itself (the stream raises it on the next empty ``read``, or from
    ``readall``).
    """

    _pending_error: BaseException | None = None
    _trailing_bytes: int | None = None
    _input_after_end = False
    # See Decoder.index_reads_whole_source. The xz, lzip and zstd scans read only
    # index/trailer structures, not the payload.
    index_reads_whole_source = False

    @property
    def pending_error(self) -> BaseException | None:
        return self._pending_error

    @property
    def trailing_bytes(self) -> int | None:
        return self._trailing_bytes

    @property
    def input_after_end(self) -> bool:
        return self._input_after_end

    def _past_end(self, data: bytes) -> bool:
        """Account for ``data``, fed after the stream's last byte; True once it is junk.

        Zeros are padding and pass, as they do after a TAR trailer: block devices, tape
        and ``dd`` pad files with them. The first non-zero byte sets
        :attr:`trailing_bytes`; the caller then stops decoding. Any byte, a zero too,
        sets :attr:`input_after_end`.
        """
        if data:
            self._input_after_end = True
        if self._trailing_bytes is None:
            rest = data.lstrip(b"\x00")
            if rest:
                self._trailing_bytes = len(rest)
        return self._trailing_bytes is not None

    def clear_pending_error(self) -> None:
        self._pending_error = None

    @property
    def needs_input(self) -> bool:
        return True

    @property
    def drains_after_flush(self) -> bool:
        """True when ``flush`` returned output and more follows through ``feed(b"")``.

        Only PPMd, which takes a truncated member's input whole at compressed EOF,
        sets it; every other decoder hands back all its remaining output from
        ``flush``.
        """
        return False

    def close(self) -> None:
        """Give back the decoder processes this decoder holds (see
        :meth:`Decoder.close`); overridden by PPMd."""
        release_decoder_children(self)

    def spoil_child(self) -> None:
        """The member failed a check above the decoder (a digest mismatch): a decoder
        whose child process must then not serve another member ends it at close. A
        no-op here; overridden by PPMd."""

    def build_index(
        self, inner: BinaryIO, last_known: SeekPoint
    ) -> tuple[list[SeekPoint], int | None]:
        del inner, last_known
        return [], None


# Compressed bytes read per fill when the decoder needs more input.
#
# Historically matched CPython gzip / ``_compression.DecompressReader``
# (``io.DEFAULT_BUFFER_SIZE`` = 8 KiB). That feed forces ~17 Python trips through
# the decode loop for a typical 256 KiB ZIP member while ``zipfile`` decompresses
# each member in one C call — the dominant residual ZIP read-all gap after the
# stream-layering work in #136/#137 (see ``review/archive/2026-07-28-performance/residual-gap.md``).
# 64 KiB reaches the measured plateau for those members; ``max_length`` still
# bounds peak *output* buffer on ``read(n)`` (the #128 / F3a contract), and ZIP
# members are additionally capped by their ``SlicingStream`` compressed extent.
_COMPRESSED_READ_SIZE = 65536
# Ceiling when a large bounded ``read(n)`` (whole-member via fused verify) asks
# for more output than the default feed — one compressed read ≈ one C inflate.
_COMPRESSED_READ_SIZE_MAX = 1 << 20
# Output budget when skipping forward during seek (unbounded skip would reintroduce
# the per-read amplification bomb on highly compressible spans).
_SEEK_OUTPUT_CHUNK = 65536


def _compressed_feed_size(max_length: int) -> int:
    """How many compressed bytes to pull for one decoder feed.

    Large bounded requests scale up toward ``max_length`` (capped) so a known-size
    whole-member read collapses to one inflate call. Small / unbounded requests
    keep the default feed; output amplification remains gated by ``max_length``.
    """
    if max_length < 0 or max_length <= _COMPRESSED_READ_SIZE:
        return _COMPRESSED_READ_SIZE
    return min(max_length, _COMPRESSED_READ_SIZE_MAX)


MakeDecoder = Callable[[SeekPoint, BinaryIO], Decoder]


# What ``_deferring_raises`` enters without a collector: nothing is ever held.
_NO_DEFERRAL: AbstractContextManager[Callable[[], Exception | None]] = nullcontext(
    nothing_held
)


# Upper bound on a stream's seek table, in entries. A seek table is an optimisation, so
# passing the cap thins the table instead of failing: points are kept at least a spacing
# apart (in decompressed bytes) chosen so the table falls to half the cap, and later
# points keep that spacing. A seek then decodes at most about one spacing plus one unit
# further than it would with every point. Nothing becomes unreadable (unless a policy
# escalates the SEEK_INDEX_DEGRADED it reports), which is why this is a structural
# constant and not a ListingLimits field. Without it the table grows with the unit count
# the file declares: an lzip member can be 26 bytes, so a table cost ~9x the file's size.
# Real files stay far below it: xz -T0 writes 24 MiB blocks and ncompress checks for a
# CLEAR every 10 kB of input, so reaching it takes a multi-GiB file even at the densest.
MAX_SEEK_POINTS = 1 << 18

# ``SeekIndexContext.error_type`` when a table was thinned; no exception is involved.
SEEK_TABLE_THINNED = "SeekTableThinned"
# ``SeekIndexContext.error_type`` (scan ``decode_check``) when the decode put a unit at
# another output offset than the index did, and the stream dropped the index.
SEEK_INDEX_CONTRADICTED = "SeekIndexContradicted"

# What each codec's seek index is read from, for the error or report that names it.
_INDEX_SOURCES = {
    "xz": "xz block index",
    "lzip": "lzip member trailers",
    "zstd": "zstd seek table",
    "gzip": "BGZF block sizes",
}


def emit_index_thinned(
    collector: DiagnosticCollector | None,
    codec_name: str,
    scan: str,
    *,
    units: str = "entries",
) -> None:
    """Report that an index scan kept a spaced subset of its ``units``."""
    resolve_collector(collector).emit(
        code=DiagnosticCode.SEEK_INDEX_DEGRADED,
        message=(
            f"{codec_name} index has more than {MAX_SEEK_POINTS} {units}; kept a "
            "spaced subset, so seeks may decode further"
        ),
        context=SeekIndexContext(
            codec=codec_name, scan=scan, error_type=SEEK_TABLE_THINNED
        ),
        logger=logger,
    )


@dataclass(frozen=True)
class IndexReport:
    """One diagnostic an index scan emitted, kept to be emitted again later.

    ``message`` is kept raw: the emit that replays it escapes it. Storing a
    :class:`Diagnostic` instead would escape it twice, because a ``Diagnostic``
    escapes its message when it is constructed.
    """

    code: DiagnosticCode
    message: str
    context: DiagnosticContext


@dataclass(frozen=True)
class PrebuiltIndex:
    """The result of a whole-source index scan, for another stream over the same bytes.

    The single-file reader scans the xz index at open to learn ``member.size``. Each
    member stream it opens takes this result as ``initial_index`` and uses it in place
    of its own scan. ``points`` and ``size`` are what :meth:`Decoder.build_index`
    returned. ``reports`` are the diagnostics the scan emitted (a thinned or unreadable
    index). The stream emits them into its own collector when it would have run the
    scan, so the caller sees each report once per stream, under its own policy, as
    before.

    Every stream that takes this index shares the same ``points`` objects, possibly
    on different threads. Nothing may mutate a point or its ``state`` in place.
    """

    points: tuple[SeekPoint, ...]
    size: int | None
    reports: tuple[IndexReport, ...] = ()


_T = TypeVar("_T")


def thinning_spacing(span: int) -> int:
    """The spacing that keeps points spread over ``span`` bytes to half the cap."""
    return max(1, -(-2 * span // MAX_SEEK_POINTS))


def spaced_subset(
    items: Sequence[_T], key: Callable[[_T], int], spacing: int
) -> list[_T]:
    """Keep the first item, then each item at least ``spacing`` past the last one kept.

    ``items`` must be in non-decreasing ``key`` order. Over a key span ``S`` at most
    ``S // spacing + 1`` items survive, whatever their count.
    """
    kept: list[_T] = []
    last = 0
    for item in items:
        k = key(item)
        if not kept or k - last >= spacing:
            kept.append(item)
            last = k
    return kept


class SpacedCollector(Generic[_T]):
    """Collect items with non-decreasing keys, thinning to stay within the cap.

    For the backward index scans, which cannot know their entry count up front: an
    lzip trailer names only the member before it, and xz streams are found one at a
    time. Keys are decompressed distances, so thinning keeps seek cost bounded.
    Memory stays at most :data:`MAX_SEEK_POINTS` items. The first item is always kept.
    """

    def __init__(self, key: Callable[[_T], int]) -> None:
        self._key = key
        self._limit = MAX_SEEK_POINTS
        self.items: list[_T] = []
        self.spacing = 0
        self.thinned = False

    def add(self, item: _T) -> None:
        k = self._key(item)
        if self.items and k - self._key(self.items[-1]) < self.spacing:
            return
        self.items.append(item)
        if len(self.items) > self._limit:
            self.thinned = True
            self.spacing = max(
                self.spacing * 2, thinning_spacing(k - self._key(self.items[0]))
            )
            self.items = spaced_subset(self.items, self._key, self.spacing)


class _IndexBlock(Protocol):
    """Fields ``build_index_backwards`` reads on a scanned block.

    Codec-specific extras (XZ ``uncompressed_size``, lzip CRC) stay on the
    concrete block type; ``include_block`` / ``to_point`` see that type via
    ``_B``, not this protocol.
    """

    @property
    def decompressed_start(self) -> int: ...

    @property
    def decompressed_end(self) -> int: ...


_B = TypeVar("_B", bound=_IndexBlock)


class _ScanFn(Protocol[_B]):
    """The backward index/trailer scan ``build_index_backwards`` calls.

    Parameter names in a callback protocol bind every implementation, so the
    first two are positional-only: a scanner may call them whatever it likes.
    This module only ever passes them positionally. A scanner that had to thin its
    entries to stay within :data:`MAX_SEEK_POINTS` calls ``on_thinned``.
    """

    def __call__(
        self,
        stream: BinaryIO,
        file_size: int,
        /,
        *,
        stop_at: int,
        start_decompressed_offset: int,
        on_thinned: Callable[[], None] | None = None,
    ) -> list[_B]: ...


def build_index_backwards(
    inner: BinaryIO,
    last_known: SeekPoint,
    scan_fn: _ScanFn[_B],
    to_point: Callable[[_B], SeekPoint],
    warning_msg: str,
    *,
    codec_name: str = "",
    collector: DiagnosticCollector | None = None,
    scan: str = "backwards_index",
    include_block: Callable[[_B], bool] | None = None,
) -> tuple[list[SeekPoint], int | None]:
    """Backward scan → seek points + total decompressed size.

    ``scan_fn`` reads only index/trailer structures (no decompression). On a
    ``CorruptionError`` (e.g. valid-but-unparseable trailing data) it emits
    ``SEEK_INDEX_DEGRADED`` and returns an empty index so the stream falls back to
    sequential decoding.

    ``include_block``, when set, filters scanned bounds before they become seek
    points (e.g. XZ zero-``uncompressed_size`` blocks that share a decompressed
    offset with the next real block and are never useful resume targets). The
    total size still comes from the last bound's ``decompressed_end``, so a scanner
    that thins its entries always keeps the last one.
    """
    file_size = inner.seek(0, io.SEEK_END)
    thinned = False

    def on_thinned() -> None:
        nonlocal thinned
        thinned = True

    try:
        bounds = scan_fn(
            inner,
            file_size,
            stop_at=last_known.compressed_offset,
            start_decompressed_offset=last_known.decompressed_offset,
            on_thinned=on_thinned,
        )
    except CorruptionError as e:
        message = warning_msg % (e,)
        resolve_collector(collector).emit(
            code=DiagnosticCode.SEEK_INDEX_DEGRADED,
            message=message,
            context=SeekIndexContext(
                codec=codec_name,
                scan=scan,
                error_type=type(e).__name__,
            ),
            logger=logger,
        )
        return [], None
    if thinned:
        emit_index_thinned(collector, codec_name, scan)
    points = [
        to_point(b)
        for b in bounds
        if b.decompressed_start > last_known.decompressed_offset
        and (include_block is None or include_block(b))
    ]
    total: int | None = bounds[-1].decompressed_end if bounds else None
    return points, total


class DecompressorStream(ReadOnlyIOStream):
    """Seekable ``BinaryIO`` over compressed bytes, driven by a :class:`Decoder`.

    Owns: output buffer, logical position, seek-point table, and the seek algorithm
    (bisect to a point → recreate decoder → skip forward). Does **not** know codec
    formats — ``make_decoder`` supplies that.

    ``seekable=False`` skips index/seek-point work (forward-only cheap path).
    ``readable``/``writable``/``write``/``readinto`` come from :class:`ReadOnlyIOStream`.

    A stream ``path`` is borrowed by default (``owns_inner=False``): the archive
    handle / ``SharedView`` stays with the caller. Pipeline stages that wrap a
    *private* inner (a later 7z ``_FilterStage`` over the previous coder's
    output, including the LZMA1 cap ``SlicingStream(owns_inner=True)``) pass
    ``owns_inner=True`` so that inner is closed with this stream. A first-stage
    BCJ (Copy+BCJ, BCJ-alone) leaves the default: the pack view is borrowed.
    ``ensure_bufferedio`` is non-closing, so ``_inner.close()`` would not reach
    that source — ``_owned_inner`` holds the object this stream is responsible
    for closing (the path we opened, or the stream we were handed with
    ``owns_inner=True``).

    A report the collector's policy escalates (``SEEK_INDEX_DEGRADED`` under
    ``STRICT``) is raised when the operation that met it has left the stream
    consistent, never from inside a decode or an index scan. ``read`` raises before it
    consumes: the bytes it decoded stay buffered and the position is unchanged, so the
    next read returns them. ``seek`` and a size query raise after they finish, with the
    position where they left it. Either way the handle stays usable.

    ``refuse_input_after_end`` marks a source that is exactly one container coder's
    compressed data (a ZIP member's, a 7z coder's declared input). Any byte the decoder is fed
    after the end of its data, a zero byte too, is then :class:`DataAfterEndError`,
    raised after the output before that end has been delivered, as for a truncation.
    ``report_trailing_data`` does not apply to such a stream.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | BinaryIO,
        *,
        make_decoder: MakeDecoder,
        collector: DiagnosticCollector | None = None,
        codec_name: str = "",
        seekable: bool = True,
        owns_inner: bool = False,
        report_trailing_data: bool = False,
        refuse_input_after_end: bool = False,
        initial_index: PrebuiltIndex | None = None,
    ) -> None:
        super().__init__()
        self._owned_inner: BinaryIO | None = None
        # Used once, in place of the decoder's index scan (see _ensure_index_built).
        self._initial_index = initial_index
        self._refuse_input_after_end = refuse_input_after_end
        # The DataAfterEndError of a ``refuse_input_after_end`` stream, raised once the
        # output before the end has been read (see _end_error), until a seek restarts.
        self._surplus: DataAfterEndError | None = None
        self._diagnostics_collector = collector
        self._codec_name = codec_name
        self._report_trailing_data = report_trailing_data
        # Reported once per stream: a seek back re-decodes to the same end.
        self._trailing_reported = False
        # Compressed bytes read from the start of the source, for the offset of
        # trailing data on a source that cannot tell() (a seek resets it).
        self._compressed_read = 0
        # Declared seek demand: without it, skip seek-point tables / index scans, but
        # still allow O(n) seeks from the origin (compressed TAR needs that for random
        # access even when MemberStreams.SEEKABLE was not declared).
        self._index_enabled = seekable
        self._seek_points: list[SeekPoint] = [SeekPoint(0, 0)]
        self._index_built = False
        self._index_build_attempted = False
        # Minimum decompressed distance between points once the table has been thinned
        # (0 until then); see _thin_seek_table.
        self._min_spacing = 0
        self._table_thinned = False
        # The table's points by compressed offset, kept while the table holds index
        # points, to find where the index and the decode disagree (_contradicts). It
        # holds only points the table holds (_note_kept), so it is bounded like the
        # table.
        self._claims: dict[int, SeekPoint] | None = None
        # The index was dropped (_drop_index): later index points are refused.
        self._index_dropped = False
        # The decoder resumed at an index point, so the offsets it counts are the
        # index's (see SeekPoint.from_index), and so is a size it reaches the end with.
        self._decode_from_index = False
        self._size_from_index = False
        # The index point the decoder resumed at, while it has given no output from it:
        # a decode that fails there drops the index (_drop_index_at_failed_point).
        self._fresh_index_point: SeekPoint | None = None
        # The index was dropped while the decoder counted from it: the operation
        # restarts it from a decoded point before it returns (_restart_at_position).
        self._restart_pending = False
        # The output offset of the decoder's next byte, whoever reads it: the size a
        # decode reaches the end with (_publish_size).
        self._decoder_pos = 0
        self._make_decoder = make_decoder
        try:
            if isinstance(path, (str, os.PathLike)):
                # The handle outlives this statement; its owner closes it.
                self._inner: BinaryIO = open(os.fspath(path), "rb")  # noqa: SIM115
                self._owned_inner = self._inner
            else:
                # typeshed keeps BufferedIOBase and BinaryIO apart; at runtime it is one.
                self._inner = cast("BinaryIO", ensure_bufferedio(path))
                if owns_inner:
                    self._owned_inner = path
            self._decoder: Decoder = make_decoder(self._seek_points[0], self._inner)
        except BaseException:
            # ``close()`` needs a decoder, and ``IOBase.__del__`` calls it on any
            # instance not marked closed, including one whose ``__init__`` raised.
            # Release what this stream already owns and mark it closed here, so the
            # finalizer has nothing left to do. A decoder constructor that raises
            # (``PpmdDecoder`` refuses PPMd7 without a pack or unpack size) or a path
            # that cannot be opened otherwise dies again there as ``AttributeError``.
            owned = self._owned_inner
            self._owned_inner = None
            try:
                if owned is not None:
                    owned.close()
            except Exception:  # noqa: BLE001, S110 - the refusal below is the error to report
                pass
            finally:
                super().close()
            raise
        self._buffer = bytearray()
        self._eof = False
        self._pos = 0
        self._size: int | None = None
        # The deferred error this stream raised at its end (see _raise_deferred), or the
        # error the decoder raised (see _decoding), until a seek restarts the decoder.
        self._spent: BaseException | None = None

    def seekable(self) -> bool:
        return self._inner.seekable()

    def add_seek_points(self, points: Sequence[SeekPoint]) -> None:
        """Merge ``points`` into the sorted index, skipping duplicates.

        Pass points in ascending ``decompressed_offset`` order; the common in-order case
        is an O(1) append, out-of-order insertions fall back to bisect. No-ops when
        index construction was not declared (no seek-point table is built), except for
        refining the origin's ``compressed_offset`` / ``state`` (unix-compress header
        commit must apply even when the table is not built).

        Once the table has been thinned (:meth:`_thin_seek_table`), a point closer than
        ``_min_spacing`` to a neighbour is dropped before the collision rules below.

        While the table holds index points (``SeekPoint.from_index``), each point is
        first checked against the others at its ``compressed_offset``
        (:meth:`_contradicts`). The same resume data at another output offset proves the
        index wrong there, so the stream drops the index (:meth:`_drop_index`).

        Same-``decompressed_offset`` collisions:
        - Origin (offset 0) may always be refined in place (unix-compress header commit),
          but never by an index point.
        - Where one side is an index point, the other a decoded one, with the same
          ``state``: the decoded point is kept. Two index points: the later
          ``compressed_offset`` is kept. Neither raises: both are valid where empty
          units lie between them (lzip), and an index that lies there is caught by the
          check above once the decode passes the next index point.
        - For other offsets, an exact duplicate is skipped; a *forward* refinement
          (same ``state``, ``compressed_offset`` moves forward) last-wins — unix-compress
          empty CLEAR segments legitimately re-emit the same decompressed offset at a
          later compressed resume point. A ``state=None`` placeholder yields to a richer
          non-``None`` resume state (XZ block bounds over a progressive stream-start).
          Divergent non-``None`` states raise :class:`CorruptionError` (never a raw
          ``AssertionError``) so hostile indexes cannot escape the ``ArchiveyError`` tree.
        """
        for point in points:
            if point.from_index and self._index_dropped:
                continue
            # Origin refinement always applies — resume must skip a committed header
            # even when seek-point indexing was not declared. Last-wins here is
            # intentional: unix-compress emits SeekPoint(0, HEADER_SIZE) to replace
            # the placeholder SeekPoint(0, 0).
            origin = self._seek_points[0]
            if (
                point.decompressed_offset == 0
                and origin.decompressed_offset == 0
                and not point.from_index
                and (
                    origin.compressed_offset != point.compressed_offset
                    or origin.state is not point.state
                )
            ):
                self._note_kept(origin, point)
                self._seek_points[0] = point
                continue
            if not self._index_enabled:
                continue
            held = self._contradicts(point)
            if held is not None:
                low, high = sorted(
                    (held.decompressed_offset, point.decompressed_offset)
                )
                self._drop_index(
                    f"Compressed offset {point.compressed_offset} starts at output "
                    f"offset {low} and also at output offset {high}."
                )
                if point.from_index:
                    continue
            if self._min_spacing and self._too_close(point):
                continue
            if point < self._seek_points[-1]:
                i = bisect.bisect_left(self._seek_points, point)
                if i < len(self._seek_points) and self._seek_points[i] == point:
                    self._resolve_same_offset_collision(i, point)
                    continue
                self._seek_points.insert(i, point)
                self._note_kept(None, point)
            elif self._seek_points[-1] == point:
                self._resolve_same_offset_collision(len(self._seek_points) - 1, point)
                continue
            else:
                self._seek_points.append(point)
                self._note_kept(None, point)
            if len(self._seek_points) > MAX_SEEK_POINTS:
                self._thin_seek_table()

    def _contradicts(self, point: SeekPoint) -> SeekPoint | None:
        """The table's point that ``point`` proves the index wrong against, if any.

        Two points with the same ``compressed_offset`` and resume ``state`` resume the
        same decode, so they must be at the same output offset. When they are not, and
        either is an index point, the index is wrong: the unit before has another size
        than it says. Only points the table still holds are compared, so after a
        thinning a point dropped from the table, or refused as too close to another,
        is no longer compared with anything.
        """
        if self._claims is None:
            return None
        held = self._claims.get(point.compressed_offset)
        if (
            held is not None
            and _same_state(held.state, point.state)
            and held.decompressed_offset != point.decompressed_offset
            and (held.from_index or point.from_index)
        ):
            return held
        return None

    def _note_kept(self, old: SeekPoint | None, new: SeekPoint) -> None:
        """Keep ``_claims`` in step with the table: ``new`` was added, in place of
        ``old`` when one is given."""
        claims = self._claims
        if claims is None:
            return
        if old is not None and claims.get(old.compressed_offset) is old:
            del claims[old.compressed_offset]
        claims[new.compressed_offset] = new

    def _drop_index(self, disagreement: str, *, lead: str | None = None) -> None:
        """Drop every index point and size, and say so: ``lead`` says what happened,
        by default that the decode contradicted the index, and ``disagreement`` how.

        The index is only an accelerator, and the file decodes: seeks go on from the
        points a decode from the origin records, and the size is the decoded one. A
        size the index gave is forgotten, so the next size query decodes to the end. A
        decoder that resumed at an index point is restarted before the operation
        returns (:meth:`_restart_at_position`).
        """
        self._claims = None
        self._index_dropped = True
        self._seek_points[:] = [p for p in self._seek_points if not p.from_index]
        self._forget_index_size()
        if self._decode_from_index:
            self._restart_pending = True
        if lead is None:
            lead = f"The {self._index_source()} and the data do not agree."
        resolve_collector(self._diagnostics_collector).emit(
            code=DiagnosticCode.SEEK_INDEX_DEGRADED,
            message=(
                f"{lead} {disagreement} The index is no longer used: seeks resume "
                "only from points found by decoding, and the size is the decoded one"
            ),
            context=SeekIndexContext(
                codec=self._codec_name,
                scan="decode_check",
                error_type=SEEK_INDEX_CONTRADICTED,
            ),
            logger=logger,
        )

    def _index_source(self) -> str:
        """What the index is, for a message, such as "zstd seek table"."""
        codec = self._codec_name or "compressed"
        return _INDEX_SOURCES.get(codec, f"{codec} seek index")

    def _forget_index_size(self) -> None:
        # _index_built is cleared too. Once the index has been tried its only reader is
        # xz's per-stream scan (the ``index_built`` closure in xz_decoder), which then
        # runs again; _ensure_index_built is gated by _index_build_attempted.
        if self._size_from_index:
            self._size = None
            self._size_from_index = False
            self._index_built = False

    def _too_close(self, point: SeekPoint) -> bool:
        """Whether ``point`` lands within ``_min_spacing`` of a neighbour in the table."""
        points = self._seek_points
        i = bisect.bisect_left(points, point)
        if i < len(points) and points[i] == point:
            return False  # same offset: the collision rules decide
        # i >= 1: the origin sits at offset 0 and point is past it.
        if point.decompressed_offset - points[i - 1].decompressed_offset < (
            self._min_spacing
        ):
            return True
        return (
            i < len(points)
            and points[i].decompressed_offset - point.decompressed_offset
            < self._min_spacing
        )

    def _thin_seek_table(self) -> None:
        """Bring a table past :data:`MAX_SEEK_POINTS` down to at most half of it.

        Points are kept at least a spacing apart, and later points keep it. Any subset
        is safe: every point resumes on its own, whatever else the table holds.
        """
        span = self._seek_points[-1].decompressed_offset
        self._min_spacing = max(self._min_spacing * 2, thinning_spacing(span))
        self._seek_points[:] = spaced_subset(
            self._seek_points, lambda p: p.decompressed_offset, self._min_spacing
        )
        if self._claims is not None:
            # The points the table dropped are no longer compared (_contradicts).
            self._claims = {p.compressed_offset: p for p in self._seek_points}
        message = (
            f"{self._codec_name} seek table passed {MAX_SEEK_POINTS} entries; kept "
            "a spaced subset, so seeks may decode further"
        )
        context = SeekIndexContext(
            codec=self._codec_name, scan="seek_table", error_type=SEEK_TABLE_THINNED
        )
        collector = resolve_collector(self._diagnostics_collector)
        if self._table_thinned:
            # Recorded once per stream; the policy still applies to every thinning.
            collector.escalate_only(
                code=DiagnosticCode.SEEK_INDEX_DEGRADED,
                message=message,
                context=context,
            )
            return
        self._table_thinned = True
        collector.emit(
            code=DiagnosticCode.SEEK_INDEX_DEGRADED,
            message=message,
            context=context,
            logger=logger,
        )

    def _resolve_same_offset_collision(self, index: int, point: SeekPoint) -> None:
        """Skip duplicates; allow forward refinement / richer-state merge; else error."""
        existing = self._seek_points[index]
        if _same_state(existing.state, point.state) and (
            existing.from_index or point.from_index
        ):
            # See add_seek_points: a decoded point beats an index one, and of two index
            # points the later one is kept.
            if existing.from_index and (
                not point.from_index
                or point.compressed_offset > existing.compressed_offset
            ):
                self._note_kept(existing, point)
                self._seek_points[index] = point
            return
        if existing.compressed_offset == point.compressed_offset and _same_state(
            existing.state, point.state
        ):
            return
        if point.compressed_offset >= existing.compressed_offset and _same_state(
            existing.state, point.state
        ):
            self._note_kept(existing, point)
            self._seek_points[index] = point
            return
        # Prefer a non-None resume state over a progressive placeholder (XZ: block
        # bounds beat a stream-start SeekPoint emitted before enrichment / after a
        # prior build_index). Same-offset with only one side carrying state is the
        # legitimate multi-stream path; keep the richer point.
        if existing.state is None and point.state is not None:
            self._note_kept(existing, point)
            self._seek_points[index] = point
            return
        if existing.state is not None and point.state is None:
            return
        # Two different resume states at one output offset (xz block records that the
        # backward index scan and a forward read's per-stream scan disagree on). Two
        # decode-discovered points cannot collide: a point is recorded only once its
        # unit has output, so they rise in both coordinates. Points without resume
        # state where one is the index's were settled above, without a raise.
        raise CorruptionError(
            f"The {self._index_source()} and the data do not agree. Output offset "
            f"{point.decompressed_offset} starts at compressed offset "
            f"{existing.compressed_offset} and also at compressed offset "
            f"{point.compressed_offset}. The file is damaged or was made to "
            f"mislead a seek. Seek points: {existing!r} and {point!r}"
        )

    def _find_best_seek_point(self, pos: int) -> SeekPoint:
        """The last seek point with ``decompressed_offset <= pos``.

        It reads the table as it stands. Every point resumes on its own (an XZ block
        point carries its stream's bounds), so a table that progressive enrichment has
        only partly filled is safe to use.
        """
        i = bisect.bisect_right(self._seek_points, SeekPoint(pos, 0)) - 1
        return self._seek_points[i]

    def _verification_proofs(self) -> VerificationProofs:
        """Only a whole-content match from the source, and doubt about its key.

        The source is compressed, so its end and length say nothing about the
        decoded bytes. A check over all of it does: the WinZip AES HMAC covers every
        ciphertext byte, and so every byte decoded from them.
        """
        below = ask_verification_proofs(self._inner)
        return VerificationProofs(
            key_in_doubt=below.key_in_doubt,
            content=below.content,
            content_possible=below.content_possible,
        )

    def nearest_resume_offset(self, target: int) -> int:
        """Decompressed offset the decoder must restart from to reach ``target``.

        The origin when no seek point lies closer, which is what makes a single-block
        ``.xz`` behave exactly like a codec with no index at all — the case
        ``STREAM_REWIND_REDECOMPRESSES`` used to be blind to, because it keyed on the
        codec's identity rather than on this.

        Deliberately reads the table **as it stands** and never calls
        ``_ensure_index_built()``: a diagnostic that built an index would change the cost
        it is reporting on. An index still being filled in reports a resume point further
        back than the finished one would, which errs toward telling the caller.

        The exception is a caller planning a seek (``ask_seek_resume_offset``): it is
        owed the resume point the seek will use, so the index a forward seek to
        ``target`` would build is built here (``_build_index_for_seek``).
        """
        if planning_seek():
            self._build_index_for_seek(target)
        return self._find_best_seek_point(target).decompressed_offset

    def _build_index_for_seek(self, target: int) -> None:
        """Build the index now when a forward seek to ``target`` would (see ``_seek``).

        A report the build escalates is held, as the seek holds it, and handed to the
        planning caller (``hold_for_planned_seek``), which raises it once its seek has
        moved, where it would have come from had the seek built the index itself.
        """
        if (
            target <= self._pos + len(self._buffer)
            or target <= self._seek_points[-1].decompressed_offset
            or not self._inner.seekable()
        ):
            return
        with self._deferring_raises() as pending:
            self._ensure_index_built()
            held = pending()
        if held is not None:
            hold_for_planned_seek(held)

    def _reset_to_seek_point(self, point: SeekPoint) -> None:
        self._inner.seek(point.compressed_offset)
        self._compressed_read = point.compressed_offset
        # Dispose the outgoing decoder deterministically before dropping it:
        # mid-member a PPMd decode can leave its native worker parked, and relying
        # on __del__/GC timing to quiesce it is exactly what close() exists to avoid
        # (no-op for every other codec). recreate() builds a fresh decoder from the
        # config, not from the old native state, so closing first is safe.
        old_decoder = self._decoder
        old_decoder.close()
        self._decoder = old_decoder.recreate(point, self._inner)
        self._decode_from_index = point.from_index
        self._fresh_index_point = point if point.from_index else None
        self._decoder_pos = point.decompressed_offset
        self._decoder.clear_pending_error()
        self._spent = None
        self._surplus = None
        self._buffer.clear()
        self._eof = False
        self._pos = point.decompressed_offset

    def _ingest_decode(self, out: DecodeOut) -> bytes:
        if out.data:
            self._fresh_index_point = None
        self._decoder_pos += len(out.data)
        if out.points:
            points = out.points
            if self._decode_from_index:
                points = [_as_index_point(p) for p in points]
            self.add_seek_points(points)
        return out.data

    def _publish_size(self, size: int) -> None:
        """Record the size a decode reached the end with (the index's, if it resumed at
        an index point).

        A size the index gave that differs is a contradiction like two points that
        disagree: it catches a lie in the last unit, which no index point follows.
        """
        if (
            self._size_from_index
            and not self._index_dropped
            and self._size is not None
            and self._size != size
        ):
            self._drop_index(
                f"The index gives the output size as {self._size}, and decoding to "
                f"the end gives {size}."
            )
        self._size = size
        self._size_from_index = self._decode_from_index

    def _restart_from_decoded_point(self) -> None:
        """Restart a decoder that counted its offsets from a dropped index point.

        It restarts at the nearest point before the position that the decode found, so
        its offsets are true again. A size it reached the end with is forgotten.
        """
        self._restart_pending = False
        self._forget_index_size()
        self._reset_to_seek_point(self._find_best_seek_point(self._pos))

    def _restart_at_position(self) -> None:
        """Restart as :meth:`_restart_from_decoded_point`, and decode back to the
        position. Undelivered output of the old decoder is dropped: its offsets were
        the index's."""
        target = self._pos
        self._restart_from_decoded_point()
        self._skip_to(target)

    def _read_decompressed_chunk(self, max_length: int = -1) -> bytes:
        if not self._decoder.needs_input:
            out = self._decoding(lambda: self._decoder.feed(b"", max_length))
            if out is None:
                return b""
            drained = self._ingest_decode(out)
            if self._ended():
                return self._end_at_trailing_data(drained)
            if drained:
                return drained
            # Decoder claimed retained input but produced nothing (e.g. a stuck
            # lzma needs_input=False under a budget). Fall through to reading more
            # compressed bytes — or EOF — so the caller cannot spin forever.
        chunk = self._inner.read(_compressed_feed_size(max_length))
        self._compressed_read += len(chunk)
        if not chunk:
            out = self._decoding(self._decoder.flush)
            if out is None:
                return b""
            leftover = self._ingest_decode(out)
            if self._ended():
                return self._end_at_trailing_data(leftover)
            if leftover and self._decoder.drains_after_flush:
                # The decoder took its input whole at compressed EOF and has more
                # output: keep pulling it through ``feed(b"")``. It reports False
                # once drained, and the next empty read calls ``flush`` again.
                return leftover
            self._eof = True
            # Incomplete EOF: decoder owns TruncatedError via pending_error (set in
            # flush). Deliver leftover now; bounded read raises on the next empty
            # read. Only publish a clean complete size when truly finished and not
            # truncated (pending_error alone is insufficient — unix-compress can be
            # finished=True with leftover-bits truncation).
            if self._decoder.pending_error is None and self._decoder.finished:
                self._publish_size(self._decoder_pos)
                self._index_built = True  # a forward scan to EOF is a complete index
            return leftover
        out = self._decoding(lambda: self._decoder.feed(chunk, max_length))
        if out is None:
            return b""
        data = self._ingest_decode(out)
        if self._ended():
            return self._end_at_trailing_data(data)
        return data

    def _decoding(self, call: Callable[[], DecodeOut]) -> DecodeOut | None:
        """Make one decoder call, keeping an error it raises as this stream's verdict.

        A decoder that raised is left in a state nothing defines, and restarting it from
        a seek point is the only defined way back. Fed again, a standard-library decoder
        may refuse every later call or repeat its first error, and neither is a verdict
        this stream can read: on CPython 3.11.17, ``bz2`` answers with ``ValueError(
        "Decompressor is unusable after a previous error")``, which
        ``BzipCodec.translate`` would report as a truncation, and ``lzma`` with
        ``LZMAError("Internal error")``. So the error goes into ``_spent``, as a deferred
        one does (:meth:`_raise_deferred`): a bounded read hands back what is already
        buffered, then raises it again, and ``readall`` raises at once, as it does for a
        deferred error. A seek restarts the decoder from a seek point, also a seek to the
        position the stream is already at.

        Every exception counts, not only a verdict on the data: an ``OSError`` from the
        caller's source raised inside a decode (xz's resume hand-off seeks the source)
        or a bug in the decoder leaves its state just as undefined, so it sticks until a
        seek too. ``ResumeReachedStreamEnd`` is not an error, and its caller replaces
        this stream.

        The one exception is a verdict on the data from a decoder that resumed at an
        index point and has given no output from it: that drops the index instead
        (:meth:`_drop_index_at_failed_point`), and the call returns ``None``, which
        hands back no output.
        """
        try:
            return call()
        except ResumeReachedStreamEnd:
            raise
        except Exception as exc:
            if self._drop_index_at_failed_point(exc):
                return None
            self._spent = exc
            raise

    def _drop_index_at_failed_point(self, exc: Exception) -> bool:
        """Drop the index when the decoder fails at an index point before any output.

        Bytes that start no unit at the offset the index gave contradict the index as
        two disagreeing points do (a zstd seek table whose sizes add up but put a frame
        start inside a frame). The index is only an accelerator: it is dropped with
        ``SEEK_INDEX_DEGRADED`` and the operation restarts the decoder from a decoded
        point (``_restart_pending``). That reaches the same place by decoding, or, when
        the data is damaged there and the index was right, raises the same error after
        decoding the prefix: this stream cannot tell the two apart.

        Only a verdict on the data counts (:func:`_is_data_verdict`). An ``OSError``
        from the source, a ``MemoryError``, a decoder child ended from outside (most
        often by the out-of-memory killer) or one that could not start, and a
        ``ReadError`` that is not a ``CorruptionError`` say nothing about the index,
        and keep the path every other error takes. A ``DecoderLimits`` refusal of a
        size the bytes at the point declare is a verdict. Returns whether it dropped
        the index.
        """
        point = self._fresh_index_point
        if point is None or self._index_dropped or not _is_data_verdict(exc):
            return False
        self._fresh_index_point = None
        self._drop_index(
            f"Decoding from its point at compressed offset {point.compressed_offset} "
            f"(output offset {point.decompressed_offset}) failed, so the index is "
            f"wrong there or the data is damaged: {exc}",
            lead=f"The {self._index_source()} may not match the data.",
        )
        return True

    def _ended(self) -> bool:
        """Whether the decoder has been fed bytes past its end that end this stream.

        For a ``refuse_input_after_end`` stream that is any byte, a zero too (every
        codec a container member uses reports it through :attr:`Decoder.input_after_end`);
        otherwise the first byte that is not zero padding (:attr:`Decoder.trailing_bytes`).
        """
        if self._refuse_input_after_end:
            return self._decoder.input_after_end
        return self._decoder.trailing_bytes is not None

    def _end_error(self) -> BaseException | None:
        """The error this stream raises at its end, once its output has been read."""
        if self._surplus is not None:
            return self._surplus
        return self._decoder.pending_error

    def _end_at_trailing_data(self, data: bytes) -> bytes:
        """End the stream where the decoder found bytes past the codec's end.

        ``data`` is this call's output, all of it before that end. Nothing further is
        read from the source: the bytes past the end are not decoded, however many
        there are. In a ``refuse_input_after_end`` stream they are
        :class:`DataAfterEndError`, raised once ``data`` and what came before it have
        been read, and no size is
        published. Otherwise the stream is complete, so its size is published, and
        the bytes are reported once per stream, as ``ARCHIVE_TRAILING_DATA``, when the
        stream is one the caller was handed (``report_trailing_data``).
        """
        if self._refuse_input_after_end:
            if not self._eof:
                self._eof = True
                self._surplus = input_after_end_error(
                    self._codec_name or "compressed",
                    self._pos + len(self._buffer) + len(data),
                )
            return data
        if not self._eof:
            self._eof = True
            self._publish_size(self._decoder_pos)
            self._index_built = True
        if self._report_trailing_data and not self._trailing_reported:
            self._trailing_reported = True
            self._report_trailing(self._trailing_data_offset())
        return data

    def _trailing_data_offset(self) -> int:
        trailing = self._decoder.trailing_bytes or 0
        end = self._compressed_read
        if self._inner.seekable():
            # A resuming decoder (xz's block hand-off) moves the source itself.
            end = self._inner.tell()
        return max(end - trailing, 0)

    def _report_trailing(self, offset: int) -> None:
        report_trailing_data(
            self._diagnostics_collector, self._codec_name or "compressed", offset
        )

    def _deferring_raises(
        self,
    ) -> AbstractContextManager[Callable[[], Exception | None]]:
        """Hold escalated reports until this operation's state is consistent.

        See the class docstring. Without a collector there is nothing to hold: the
        throwaway :func:`resolve_collector` builds runs the library default policy.
        """
        collector = self._diagnostics_collector
        if collector is None:
            return _NO_DEFERRAL
        return collector.deferring_raises()

    def readall(self) -> bytes:
        if self._spent is not None:
            # The caller asked for the whole stream, which cannot be had: raise now,
            # even with output buffered, as for a deferred error below.
            self._raise_spent()
        # Prefer join-of-chunks over staging through the shared bytearray: a whole-stream
        # read never needs the partial-read buffer, and the extend + bytes(buffer) copy
        # was a measurable share of ZIP read-all overhead (perf review H2).
        chunks: list[bytes] = []
        with self._deferring_raises() as pending:
            while True:
                if self._restart_pending:
                    # Everything this call holds came from the restarted decoder.
                    chunks.clear()
                    self._restart_at_position()
                if self._buffer:
                    chunks.append(bytes(self._buffer))
                    self._buffer.clear()
                if self._eof:
                    break
                chunk = self._read_decompressed_chunk()
                if chunk:
                    chunks.append(chunk)
            held = pending()
            if held is not None:
                # Put back what was decoded, unconsumed. A decode that finished clean
                # has already published the true total: the EOF branches publish
                # _decoder_pos, which counts every byte the decoder produced.
                self._buffer[:0] = b"".join(chunks)
                raise held
        # A read(-1)/readall() caller expects the complete stream and will not call
        # again, so a deferred pending_error (e.g. truncated .Z) must raise here —
        # unlike chunked read(n), which returns bytes now and raises on the next empty
        # read. Partial bytes from this call are dropped: the caller asked for the
        # whole stream and it is incomplete. They are released before the raise, since
        # the recorded error's traceback keeps this frame, and its locals, alive. Gate
        # _size *before* raising so a caller that catches TruncatedError cannot then
        # read a clean prefix-as-complete size.
        err = self._end_error()
        if err is not None:
            chunks.clear()
            self._raise_deferred(err)
        data = b"".join(chunks)
        if self._size is None or self._pos <= self._size:
            self._pos += len(data)
            self._publish_size(self._pos)
        return data

    def read(self, n: int = -1, /) -> bytes:
        if n == 0:
            return b""
        if n is None or n < 0:
            return self.readall()
        return self._read(n, n)

    def read_ahead(self, need: int, n: int, /) -> bytes:
        """At least ``need`` bytes, or fewer only at the end, and at most ``n``.

        Like ``read(need)``, errors included, but the feed that completes ``need``
        may give more, and up to ``n`` of it comes back too. No source read is made
        for bytes past ``need``. A buffer in front of this stream fills from it and
        does not wait for bytes nobody asked for yet: on a source that cannot seek,
        each feed is what has arrived (``BaseArchiveReader._codec_input``).
        """
        if need <= 0 or n < need:
            raise ValueError(f"read_ahead needs 0 < need <= n, got {need}, {n}")
        return self._read(need, n)

    def _read(self, need: int, n: int) -> bytes:
        """At least ``need`` bytes, or fewer only at the end, and at most ``n``."""
        if self._spent is not None and not self._buffer:
            self._raise_spent()
        with self._deferring_raises() as pending:
            if not self._buffer and not self._eof:
                # Common case: nothing buffered and one decode fills the request. Hand
                # that chunk back as is, skipping the extend / slice / delete copies
                # through ``_buffer`` (each a full copy of the output). A short or
                # over-long chunk takes the buffered loop below, unchanged. So does a
                # chunk decoded while a raise was held: returning it would leave this
                # block and drop the raise, so the chunk stays buffered, unconsumed,
                # and the raise propagates below.
                chunk = self._read_decompressed_chunk(n)
                if (
                    need <= len(chunk) <= n
                    and pending() is None
                    and not self._restart_pending
                ):
                    self._pos += len(chunk)
                    return chunk
                self._buffer.extend(chunk)
                # ``_buffer`` holds it now. A raise below keeps this frame alive on
                # its traceback, which must not pin a second copy of the bytes.
                chunk = b""
            # A decoder that raised mid-read is not fed again (see _decoding): what it
            # produced before the error is handed back, and the read after that raises.
            while True:
                if self._restart_pending:
                    self._restart_at_position()
                if len(self._buffer) >= need or self._eof or self._spent is not None:
                    break
                self._buffer.extend(
                    self._read_decompressed_chunk(n - len(self._buffer))
                )
            held = pending()
            if held is not None:
                raise held
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        self._pos += len(data)
        if not data:
            err = self._end_error()
            if err is not None:
                self._raise_deferred(err)
        return data

    def _raise_deferred(self, err: BaseException) -> NoReturn:
        """Raise the decoder's deferred end-of-stream error, and keep raising it.

        The decoder has reached the end of its input, so a later read would otherwise
        return ``b""`` and a truncated stream would read as a short, clean one. Every
        later read that has no buffered bytes raises ``err`` again, and no size is
        published. A seek restarts the decoder (:meth:`_seek`), which reaches the same
        error again at the same place.
        """
        self._decoder.clear_pending_error()
        self._surplus = None
        self._spent = err
        raise err

    def _raise_spent(self) -> NoReturn:
        """Raise the recorded error again, with this raise's traceback only.

        Re-raising the stored instance as is would append each raise's frames to one
        traceback, which grows with every retry and keeps every frame on it alive.
        The same instance is raised each time, so a caller that kept an earlier raise
        sees its traceback replaced by the latest one; the message and type do not
        change, and a bounded traceback is worth more than the first raise's frames.
        """
        assert self._spent is not None
        raise self._spent.with_traceback(None)

    def close(self) -> None:
        # Quiesce any decoder-owned native worker before dropping references, so a
        # blocked PPMd worker cannot be resumed into freed memory at GC.
        if self.closed:
            return
        try:
            self._decoder.close()
        finally:
            owned = self._owned_inner
            self._owned_inner = None
            try:
                if owned is not None:
                    owned.close()
            finally:
                super().close()

    def _ensure_index_built(self) -> None:
        if not self._index_enabled or self._index_built or self._index_build_attempted:
            return
        initial = self._initial_index
        if initial is None:
            new_points, new_size = self._scan_index()
        else:
            # The scan made elsewhere, with what it emitted emitted here, in the same
            # order a scan here would (the caller's deferring block holds a raise).
            self._initial_index = None
            new_points, new_size = initial.points, initial.size
            for report in initial.reports:
                resolve_collector(self._diagnostics_collector).emit(
                    code=report.code,
                    message=report.message,
                    context=report.context,
                    logger=logger,
                )
        self._index_build_attempted = True
        if new_points or new_size is not None:
            self._index_built = True
        if new_points:
            # Checked against what a decode already found, and against what it finds
            # later (_contradicts).
            self._claims = {p.compressed_offset: p for p in self._seek_points}
            self.add_seek_points([_as_index_point(p) for p in new_points])
        if self._index_dropped:
            self._index_built = False
        elif new_size is not None:
            self._size = new_size
            self._size_from_index = True

    def _scan_index(self) -> tuple[Sequence[SeekPoint], int | None]:
        inner_pos = self._inner.tell()
        # Always scan from the absolute origin. Using a mid-stream last_known (from
        # progressive enrichment) as the baseline renumbers later streams' decompressed
        # offsets incorrectly. A full from-origin scan is cheap (index/trailer only).
        found = self._decoder.build_index(self._inner, SeekPoint(0, 0))
        # build_index may have seeked _inner (e.g. lzip's backward trailer scan);
        # restore it so the decompressor's expected read position is still valid.
        if self._inner.tell() != inner_pos:
            self._inner.seek(inner_pos)
        return found

    def scan_index(self) -> tuple[Sequence[SeekPoint], int | None] | None:
        """Run the decoder's whole-source index scan and return it, keeping nothing.

        ``None`` when this stream builds no index (seeking not declared, or a source
        that cannot seek). For a caller that hands the result to other streams as a
        :class:`PrebuiltIndex`; the diagnostics the scan emits go to this stream's
        collector.
        """
        if not self._index_enabled or not self._inner.seekable():
            return None
        return self._scan_index()

    def try_get_size(self) -> int | None:
        """The total decompressed size if cheaply available, else ``None``.

        Cheap means no data is decoded: the size is known already (a read reached the
        end, or an index scan gave it), or the decoder's index scan gives it. A scan
        that reads the payload (the BGZF walk,
        :attr:`Decoder.index_reads_whole_source`) is not cheap, so it is not run here;
        the size is then ``None`` until a seek or a read finds it.
        """
        if self._size is not None:
            return self._size
        if not self._index_enabled or not self._inner.seekable():
            return None
        if self._decoder.index_reads_whole_source:
            return None
        with self._deferring_raises() as pending:
            self._ensure_index_built()
            held = pending()
            if held is not None:
                raise held
        return self._size

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        with self._deferring_raises() as pending:
            pos = self._seek(offset, whence)
            if self._restart_pending:
                self._restart_at_position()
            held = pending()
            if held is not None:
                raise held
        return pos

    def _end_offset(self) -> int:
        """Return the decompressed size; finding it may decode the rest of the stream."""
        self._ensure_index_built()
        if self._size is None:
            if self._spent is not None:
                # This stream already raised an error (a truncation, or the decoder's
                # own): report the same error, not the generic unknown-size one below.
                self._raise_spent()
            # Building the index didn't reveal the size; scan to EOF to find it
            # without buffering all remaining data in RAM.
            self._pos += len(self._buffer)
            self._buffer.clear()
            while True:
                if self._restart_pending:
                    # The end this decoder would reach is the index's: start over.
                    self._restart_from_decoded_point()
                if self._eof:
                    break
                data = self._read_decompressed_chunk(_SEEK_OUTPUT_CHUNK)
                self._pos += len(data)
            # Truncated streams must not publish a clean complete size; surface
            # the deferred fault instead of asserting or treating the prefix as
            # the full stream.
            err = self._end_error()
            if err is not None:
                self._raise_deferred(err)
            if self._size is None:
                raise TruncatedError(
                    "Cannot seek to end: decompressed size is unknown "
                    "(stream ended incompletely)"
                )
        return self._size

    def _seek(self, offset: int, whence: int) -> int:
        if not self._inner.seekable():
            raise io.UnsupportedOperation("seek")

        new_pos = resolve_seek(offset, whence, pos=self._pos, end=self._end_offset)
        if (
            whence != io.SEEK_END
            and new_pos > self._pos + len(self._buffer)
            and new_pos > self._seek_points[-1].decompressed_offset
        ):
            self._ensure_index_built()

        if self._spent is not None:
            # The decoder raised, at the end of a truncated input or mid-stream, so no
            # position is reachable from where it stands: restart from the nearest seek
            # point, and let the decode below reach new_pos, or the error again. The
            # size short-circuit below cannot turn this back into a clean end: a decode
            # that raised never publishes a size (readall and SEEK_END raise first), so
            # a size here came from an index scan, and a seek at or past the size the
            # index claims is at the end.
            self._reset_to_seek_point(self._find_best_seek_point(new_pos))

        if self._size is not None and new_pos >= self._size:
            self._buffer.clear()
            self._eof = True
            self._pos = new_pos
            return self._pos

        if new_pos == self._pos:
            return self._pos

        if new_pos < self._pos:
            self._reset_to_seek_point(self._find_best_seek_point(new_pos))
        elif new_pos <= self._pos + len(self._buffer):
            del self._buffer[: new_pos - self._pos]
            self._pos = new_pos
            return self._pos
        else:
            best = self._find_best_seek_point(new_pos)
            if best.decompressed_offset > self._pos:
                self._reset_to_seek_point(best)
            else:
                self._pos += len(self._buffer)
                self._buffer.clear()

        return self._skip_to(new_pos)

    def _skip_to(self, new_pos: int) -> int:
        """Decode forward from ``_pos``, with nothing buffered, to ``new_pos``."""
        assert not self._buffer
        if self._pos == new_pos:
            return self._pos

        while not self._eof:
            if self._restart_pending:
                # The index was dropped under this decode: go on from a decoded point.
                self._restart_from_decoded_point()
                continue
            decompressed = self._read_decompressed_chunk(_SEEK_OUTPUT_CHUNK)
            if self._pos + len(decompressed) >= new_pos:
                self._buffer.extend(decompressed[new_pos - self._pos :])
                self._pos = new_pos
                return self._pos
            self._pos += len(decompressed)

        self._pos = new_pos
        return self._pos

    def tell(self, /) -> int:
        return self._pos


# How far back from the end of the file the xz and lzip index scans look for the end
# of the data when the file does not end with it. The same bound as the TAR trailing
# scan: enough for any padding or appended signature seen in practice. Past it the
# index is reported unreadable (SEEK_INDEX_DEGRADED) and reads decode sequentially.
TRAILING_DATA_SEARCH = 1 << 20
# How many candidate ends those scans check before giving up the same way. Real
# appended data holds few: xz's two-byte footer magic turns up once every 64 KiB of
# random bytes, and lzip tries a few ends per run of zeros, however long the run. A tail
# crafted to be all candidates would otherwise cost a Python check per few bytes on
# every open.
TRAILING_DATA_CANDIDATES = 4096


def near_stream_magic(data: bytes, magic: bytes | Sequence[Container[int]]) -> bool:
    """Whether ``data``, the bytes after a complete stream, start like a damaged stream.

    The rule is lzip's: ``lzip`` refuses a file whose trailing data has two or three of
    the four ``LZIP`` magic bytes in place, as a "corrupt header in multimember file"
    (its ``--loose-trailing`` option turns that off). Here it is stated for a magic of
    any length: the first ``len(magic)`` bytes of ``data`` hold the magic's byte in at
    least half of the positions, and not in all of them. One rule serves every codec
    whose magic tells a further stream from appended bytes (xz, lzip, zstd, LZ4,
    bzip2), so they cannot disagree on what a damaged stream is.

    One damaged byte, or a few flipped bits in one byte, leaves a 4-byte magic three
    matches and xz's 6-byte one five, so the damage the rule exists for is always
    caught. Random appended bytes match a 4-byte magic about once in 11 000 tails,
    zstd's and LZ4's skippable-frame magic (16 values for its first byte) about once in
    1 300, and xz's magic about once in 850 000. A codec is judged against each magic
    it accepts after a stream, so its rate is the sum: about once in 1 160 tails for
    zstd (a frame or a skippable frame) and once in 1 050 for LZ4 (a frame, a legacy
    stream or a skippable frame). A tail shorter than the magic does not match:
    ``lzip`` also refuses a few bytes that begin like its magic, but a tail that short
    holds too little to tell damage from appended bytes, so it is reported as trailing
    data like any other.

    archivey has no option like lzip's ``--loose-trailing``. A file whose appended
    bytes match by chance fails to read past its last stream, with nothing a caller
    can set to get the rest of the data. Damage is not a policy choice in this
    layer: a damaged last footer also raises with no option.

    ``magic`` is the magic's bytes, or the bytes each position may hold (bzip2's
    block-size digit, zstd's skippable-frame range). A ``data`` that starts with the
    whole magic is a stream, not a near match.
    """
    if len(data) < len(magic):
        return False
    if isinstance(magic, bytes):
        matches = sum(a == b for a, b in zip(data, magic))
    else:
        matches = sum(byte in allowed for byte, allowed in zip(data, magic))
    return len(magic) <= 2 * matches < 2 * len(magic)


def damaged_stream_error(offset: int | None = None) -> CorruptionError:
    """The error for bytes after a stream that :func:`near_stream_magic` matches.

    ``offset`` is where the damaged stream starts in the source. The xz and lzip
    decoders and their index searches know it and pass it. ``FramedDecoder`` (zstd, LZ4,
    bzip2) does not: it sees only the bytes it is fed, and only the
    ``DecompressorStream`` that feeds it knows their source offset. Its error still
    names the archive, member and format, from the error context.
    """
    where = "" if offset is None else f" at offset {offset}"
    return CorruptionError(
        f"Damaged stream header{where}: the bytes after a complete stream hold at "
        "least half of the stream magic, so a further stream starts there and is damaged"
    )


def report_trailing_data(
    collector: DiagnosticCollector | None, codec_name: str, offset: int
) -> None:
    """Report non-zero bytes at compressed ``offset``, past the end of a codec's data.

    Shared by :class:`DecompressorStream` and the accelerator wrappers that find the
    same thing another way, so every path says it identically.
    """
    resolve_collector(collector).emit(
        code=DiagnosticCode.ARCHIVE_TRAILING_DATA,
        message=(
            f"The {codec_name} stream ends before the file does: bytes that are not "
            f"part of it start at compressed offset {offset}. The data was read in "
            "full; the bytes after it were not decoded (something may have been "
            "appended to the file)."
        ),
        context=ArchiveEofContext(
            format=codec_name,
            expected_marker="end_of_stream",
            expected_bytes=0,
            observed_bytes=offset,
            observed_kind="nonzero",
        ),
        logger=logger,
    )


_CODECS_PACKAGE = "archivey.internal.streams.codecs."


def release_decoder(decoder: object) -> None:
    """Give back the child process ``decoder`` holds now, and end it now when it is an
    in-process liblzma decoder (``native_memory.end_lzma_decoder``).

    For a native decoder, or a codec-layer wrapper of one, that its owner is done with
    while it goes on: CPython frees a dropped child proxy at once and its finalizer
    gives the child back then, but PyPy frees it at a later collection, and the child
    stays leased until that runs. A wrapper (the lz4 picker, the clamped Alone header)
    is looked through as :func:`release_decoder_children` does.
    """
    if getattr(type(decoder), "holds_decoder_child", False):
        cast(Any, decoder).close()
    elif type(decoder) is lzma.LZMADecompressor:
        end_lzma_decoder(decoder)
    elif type(decoder).__module__.startswith(_CODECS_PACKAGE):
        release_decoder_children(decoder)


def release_decoder_children(holder: object, depth: int = 3) -> None:
    """Give back every decoder process ``holder`` holds now, not when GC frees it.

    A decoder keeps its native object in an attribute, sometimes inside a small helper
    of its own (the xz and lzip state, the clamped Alone header, the lz4 picker), so
    this looks through the attributes of codec-layer helpers a few levels down for a
    child proxy (``holds_decoder_child``, codecs/isolated.py). An archive reader can
    sit in a reference cycle, and without this its decoders' child processes would
    stay leased until the cycle collector ran. It also ends the in-process liblzma
    decoders it finds, which matters on PyPy only (``native_memory.end_lzma_decoder``).
    """
    for value in list(getattr(holder, "__dict__", {}).values()):
        if getattr(type(value), "holds_decoder_child", False):
            value.close()
        elif type(value) is lzma.LZMADecompressor:
            end_lzma_decoder(value)
        elif (
            depth > 0
            and type(value).__module__.startswith(_CODECS_PACKAGE)
            and not isinstance(value, io.IOBase)
        ):
            release_decoder_children(value, depth - 1)


# How many wrappers ``retire_decoder_children`` looks through; a member stream has a
# handful, so this only stops a cycle.
_MAX_WRAPPERS = 16


def retire_decoder_children(stream: object) -> None:
    """Tell every decoder under ``stream`` that its member failed a check (see
    :meth:`BaseDecoder.spoil_child`), looking through the wrappers' ``_inner`` and a
    slice's ``_stream`` (a solid member's is its folder): a 7z coder chain stacks one
    decoder on another, and a solid folder's decoder serves all its members."""
    for _ in range(_MAX_WRAPPERS):
        if isinstance(stream, DecompressorStream):
            spoil = getattr(stream._decoder, "spoil_child", None)
            if spoil is not None:
                spoil()
        stream = _layer_below(stream)
        if stream is None:
            return


def _layer_below(stream: object) -> object | None:
    for name in ("_inner", "_stream"):
        below = getattr(stream, name, None)
        if below is not None:
            return below
    return None
