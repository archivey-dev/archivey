"""Decoders for gzip, zlib and raw DEFLATE on the standard library's ``zlib``."""

from __future__ import annotations

import os
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Any, BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import (
    GZIP_MAGIC,
    GZIP_WBITS,
    RAW_DEFLATE_WBITS,
)
from archivey.internal.streams.codecs.bgzf_index import build_bgzf_index
from archivey.internal.streams.codecs.deflate_resume import (
    DeflateResume,
    DeflateResumeDecoder,
)
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    Decoder,
    DecompressorStream,
    SeekPoint,
    _inflate,
    _inflate_rest,
    gzip_error,
    release_decoder,
    truncated_message,
    zlib_error,
)
from archivey.internal.streams.native_memory import UNDER_PYPY

# Output between two snapshot seek points one decode records (:class:`ZlibSnapshot`).
# A seek decodes about half of it on average: about 2 ms on a 4-core machine.
SNAPSHOT_SPACING = 1 << 20
# What one ``decompressobj.copy()`` holds: zlib's inflate state, about 7 KiB, and its
# 32 KiB window (``tracemalloc`` counts 39 KiB on zlib 1.3).
SNAPSHOT_HELD_BYTES = 40 << 10


@dataclass(frozen=True, slots=True, eq=False)
class ZlibSnapshot:
    """A :class:`SeekPoint` state: ``decompressobj.copy()`` taken between two feeds.

    It holds everything the decode carries forward, mid-block too: the window, the bit
    position, the Huffman tables, and the running checksum (gzip's CRC-32 and length,
    zlib's Adler-32; raw DEFLATE has none), so a decode resumed from it still checks a
    gzip or zlib trailer. ``decomp`` is never decoded from: each resume takes a copy of
    it (:meth:`resume`), so the point can be shared.
    The copy is taken at the start of a feed and keeps ``unconsumed_tail``, the input
    an earlier feed left undecoded, so its compressed offset is where that feed's new
    input starts, past the tail: a resumed decoder prepends the tail to what it reads
    from there, as the decoder it was copied from would have. Taking copies on those
    continuation feeds too keeps the spacing near :data:`SNAPSHOT_SPACING` when one
    read decodes to more than a feed's output. ``held_bytes`` counts the tail, which
    the copy keeps alive. A :class:`~decompressor_stream.SnapshotState`.
    """

    decomp: Any
    held_bytes: int = SNAPSHOT_HELD_BYTES
    min_gap: int = SNAPSHOT_SPACING // 2

    def resume(self) -> Any:
        return self.decomp.copy()


def _snapshot_point(decomp: Any, produced: int, fed_end: int) -> SeekPoint:
    """A snapshot seek point taken at the start of a feed: output offset ``produced``,
    compressed offset ``fed_end``, where the feed's new input starts."""
    return SeekPoint(
        produced,
        fed_end,
        ZlibSnapshot(
            decomp.copy(),
            held_bytes=SNAPSHOT_HELD_BYTES + len(decomp.unconsumed_tail),
        ),
    )


def _zlib_label(wbits: int) -> str:
    """The name of a ``wbits`` stream in messages: a positive ``wbits`` reads the zlib
    header, a negative one raw DEFLATE."""
    return "zlib" if wbits > 0 else "deflate"


class _KeepsOutputBeforeErrors(BaseDecoder):
    """Inflate steps that keep the bytes zlib decodes before an error, on a pipe.

    CPython's ``decompressobj.decompress`` drops a call's output when the call raises,
    and a pipe cannot be decoded again (``DecompressorStream._redecode_to_error``).
    Once :meth:`keep_output_before_errors` is called, each step first takes
    ``decompressobj.copy()`` (the 32 KiB window and the state). When the step raises,
    the copy decodes the same input again one output byte per call up to the error;
    those bytes are handed back, and the next call raises the error. Only a bounded
    step takes the copy: an unbounded ``read()`` raises without the prefix
    (``compressed-streams``), and replaying a whole unbounded step one byte per call
    could cost millions of calls. Only a zlib error is replayed; any other error,
    ``MemoryError`` included, raises at once. The copy costs within 1% on a 40 MB
    pipe read; a source that can seek is decoded again instead, so it never takes
    one. A decompressor in a decoder child has no ``copy()``, and keeps the stream's
    behaviour.
    """

    _decomp: Any
    _keep = False
    _raise_next: Exception | None = None

    @override
    def keep_output_before_errors(self) -> None:
        # PyPy never frees a ``decompressobj.copy()``: one per feed kept about 44 KiB
        # each (30 MiB for one 1-byte-feed pass over a 10 KB gzip). There a pipe keeps
        # the stream's behaviour, as a decompressor in a decoder child does.
        self._keep = hasattr(self._decomp, "copy") and not UNDER_PYPY

    def _raise_pending(self) -> None:
        if self._raise_next is not None:
            raise self._raise_next

    def _inflate_step(
        self, data: bytes, max_length: int, error: Callable[[zlib.error], Exception]
    ) -> bytes:
        if not self._keep or max_length <= 0:
            # ``_inflate`` reads 0 as no limit too.
            return _inflate(self._decomp, data, max_length, error)
        snapshot = self._decomp.copy()
        try:
            return _inflate(self._decomp, data, max_length, error)
        except Exception as exc:
            if not isinstance(exc.__cause__, zlib.error):
                raise
            recovered = _decode_to_error(snapshot, data, max_length)
            if not recovered:
                raise
            self._raise_next = exc
            return recovered


def _decode_to_error(decomp: Any, data: bytes, max_length: int) -> bytes:
    """The bytes ``decomp`` gives from ``data`` before it raises, one per call, at
    most ``max_length`` (positive) of them.

    Empty when the input runs out, the stream ends or ``max_length`` is reached
    first: the call that raised did not stop there, so the error was not met again
    and nothing is handed back.
    """
    got = bytearray()
    pending = data
    try:
        while len(got) < max_length:
            out = decomp.decompress(pending, 1)
            pending = decomp.unconsumed_tail
            if not out or decomp.eof:
                return b""
            got += out
    except zlib.error:
        return bytes(got)
    return b""


class ZlibDecoder(_KeepsOutputBeforeErrors):
    """Inflate a raw-deflate or zlib-wrapped stream via ``zlib.decompressobj``.

    With ``index`` (declared seek demand), a :class:`ZlibSnapshot` is a seek point
    about every :data:`SNAPSHOT_SPACING` of output, at the start of a feed, as in
    :class:`GzipDecoder` (in process only). A zlib stream's copy carries the running
    Adler-32, so a decode resumed from it still checks the trailer. ``start`` is the
    point this decoder resumes from.
    """

    def __init__(
        self,
        wbits: int = RAW_DEFLATE_WBITS,
        *,
        index: bool = False,
        start: SeekPoint | None = None,
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._wbits = wbits
        self._index = index
        self._natives = natives
        if start is not None and isinstance(start.state, ZlibSnapshot):
            self._decomp = start.state.resume()
        else:
            self._decomp = natives.zlib_decompressobj(wbits)
        self._label = _zlib_label(wbits)
        self._error = partial(zlib_error, label=self._label)
        # Source offset just past every byte fed, and output offset just past every
        # byte produced, for snapshot points; counted only on declared seek demand.
        self._fed_end = start.compressed_offset if start is not None else 0
        self._produced = start.decompressed_offset if start is not None else 0
        self._snapshots = index and hasattr(self._decomp, "copy")
        self._last_snapshot = self._produced

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        del inner
        if isinstance(point.state, DeflateResume):
            return DeflateResumeDecoder(
                point.state,
                self,
                corruption=self._error,
                truncated=truncated_message(self._label),
                natives=self._natives,
            )
        return ZlibDecoder(
            self._wbits, index=self._index, start=point, natives=self._natives
        )

    @override
    def close(self) -> None:
        # An in-process ``zlib`` object holds no decoder process and needs no ending,
        # so the attribute walk of ``BaseDecoder.close`` would find nothing (its
        # docstring allows the skip); ZIP closes one decoder per member.
        if self._natives.isolated:
            super().close()

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        self._raise_pending()
        if self._decomp.eof:
            # Past the end; the stream stops reading once these hold a non-zero byte.
            self._past_end(chunk)
            return DecodeOut(b"")
        # unconsumed_tail holds input not yet consumed under a prior max_length cap;
        # prepend it exactly once (mirrors gzip._GzipReader).
        tail = self._decomp.unconsumed_tail
        data = tail + chunk
        if not data:
            return DecodeOut(b"")
        points: list[SeekPoint] = []
        if self._snapshots and self._produced - self._last_snapshot >= SNAPSHOT_SPACING:
            self._last_snapshot = self._produced
            points.append(_snapshot_point(self._decomp, self._produced, self._fed_end))
        self._fed_end += len(chunk)
        out = self._inflate_step(data, max_length, self._error)
        self._produced += len(out)
        if self._raise_next is None and self._decomp.eof:
            self._past_end(self._decomp.unused_data)
        return DecodeOut(out, points)

    def flush(self) -> DecodeOut:
        self._raise_pending()
        leftover = _inflate_rest(self._decomp, self._error)
        if not self._decomp.eof:
            self._pending_error = TruncatedError(truncated_message(self._label))
        return DecodeOut(leftover)

    @property
    def finished(self) -> bool:
        return self._decomp.eof

    @property
    @override
    def needs_input(self) -> bool:
        return self._raise_next is None and not self._decomp.unconsumed_tail


class GzipDecoder(_KeepsOutputBeforeErrors):
    """gzip-window inflate with multi-member chaining.

    Uses ``wbits=16+MAX_WBITS`` so zlib validates CRC/ISIZE. Right after a member,
    ``1f 8b`` starts a new ``decompressobj`` and the data goes on. NUL bytes there are
    padding only when nothing but NULs follows them to the end of the input, as GNU
    ``gzip`` reads them (tape and block padding). Anything else (junk, a partial magic
    at true EOF, or any byte after NULs, a further member too) ends the data there and
    sets :attr:`trailing_bytes`, counted from the first non-NUL byte, which the stream
    reports.

    Python's ``gzip`` differs on two of these: ``GzipFile`` raises on junk, and it
    skips NULs before a further member and reads that member. GNU ``gzip`` and 7-Zip
    stop at the NULs, and rapidgzip raises there ("Invalid gzip/zlib wrapper"). Archivey
    stops at the NULs too, as GNU ``gzip`` does; ``dev-docs/formats/gzip.md`` §6 says
    why.

    Cross-``feed`` NUL runs and a lone trailing ``1f`` are retained until the next
    byte (or ``flush``) resolves them.

    Mid-member ``max_length`` remainder stays in ``decompressobj.unconsumed_tail``
    (same as :class:`ZlibDecoder`); ``_retained`` is only for post-member bytes.

    With ``index`` (declared seek demand), every member after the first that has output
    is a seek point, recorded when the decode reaches it, and :meth:`build_index` walks
    a BGZF or mgzip file's members without decoding (:mod:`.bgzf_index`). Inside a
    member, a :class:`ZlibSnapshot` is a seek point about every
    :data:`SNAPSHOT_SPACING` of output, at the start of a feed (in process only: a
    decompressor in a decoder child has no ``copy()``). ``start`` is the point this
    decoder resumes from.
    """

    # The BGZF walk reads the whole file (the mgzip walk jumps, but runs only after the
    # first header says mgzip), so a size query does not run it.
    index_reads_whole_source = True

    def __init__(
        self,
        *,
        index: bool = False,
        collector: DiagnosticCollector | None = None,
        start: SeekPoint | None = None,
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._natives = natives
        self._index = index
        self._collector = collector
        # Source offset just past every byte fed, and output offset just past every
        # byte produced: the bytes a feed holds are always the last ones fed. Every
        # reassignment of ``data`` in ``feed`` must keep it a suffix: ``_retained`` or
        # ``unconsumed_tail`` plus the chunk, ``_resolve_between`` dropping padding
        # from the front, and ``unused_data`` at a member's end (zlib leaves the same
        # bytes in ``unconsumed_tail`` there). One that broke it would give seek
        # points the wrong source offset, which serves wrong bytes rather than raising.
        self._fed_end = start.compressed_offset if start is not None else 0
        self._produced = start.decompressed_offset if start is not None else 0
        # The current member's start, recorded once the member has output: an empty
        # member (BGZF's end marker) shares its offset with whatever follows.
        self._pending_point: SeekPoint | None = None
        if start is not None and isinstance(start.state, ZlibSnapshot):
            self._decomp = start.state.resume()
        else:
            self._decomp = natives.zlib_decompressobj(GZIP_WBITS)
        # Snapshot seek points (ZlibSnapshot): only on declared seek demand, and only
        # where ``copy()`` exists. The output offset of the last one, or of the start.
        self._snapshots = index and hasattr(self._decomp, "copy")
        self._last_snapshot = self._produced
        # Post-member bytes not yet resolved (NUL padding / next magic / junk).
        # Never store unconsumed_tail here — that lives on the decompressobj.
        self._retained = b""
        self._between_members = False
        # Between members, NUL bytes have been skipped: only more NULs may follow.
        self._padded = False
        self._finished = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        del inner
        if isinstance(point.state, DeflateResume):
            return DeflateResumeDecoder(
                point.state,
                self,
                corruption=gzip_error,
                truncated=truncated_message("gzip"),
                natives=self._natives,
            )
        return GzipDecoder(
            index=self._index,
            collector=self._collector,
            start=point,
            natives=self._natives,
        )

    def _arm_trailing_junk(self, data: bytes) -> None:
        """End the data at ``data``: bytes after a member that start no further member.

        ``data`` has its NUL padding stripped already and runs to the end of what has
        been fed; the stream reports it from :attr:`trailing_bytes`.
        """
        self._past_end(data)
        self._retained = b""
        self._between_members = False
        self._finished = True

    def _resolve_between(self, data: bytes) -> bytes:
        """Strip NULs; start next member, retain partial magic, arm junk, or wait."""
        rest = data.lstrip(b"\x00")
        self._padded = self._padded or len(rest) < len(data)
        data = rest
        if not data:
            self._between_members = True
            self._retained = b""
            return b""
        if self._padded:
            # A byte after NUL padding: the data ended at the padding.
            self._arm_trailing_junk(data)
            return b""
        if data.startswith(GZIP_MAGIC):
            release_decoder(self._decomp)
            self._decomp = self._natives.zlib_decompressobj(GZIP_WBITS)
            self._between_members = False
            self._retained = b""
            return data
        if data == b"\x1f":
            self._between_members = True
            self._retained = data
            return b""
        self._arm_trailing_junk(data)
        return b""

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        self._raise_pending()
        if self._finished or self._pending_error is not None:
            return DecodeOut(b"")

        points: list[SeekPoint] = []
        if self._between_members:
            data = self._retained + chunk
            self._retained = b""
        else:
            tail = self._decomp.unconsumed_tail
            data = tail + chunk
            if data and self._snapshot_due():
                self._last_snapshot = self._produced
                points.append(
                    _snapshot_point(self._decomp, self._produced, self._fed_end)
                )
        self._fed_end += len(chunk)

        # Output pieces, joined once at the end: one ``decompress`` call is the common
        # case, and ``b"".join`` hands a lone piece back without copying it.
        output: list[bytes] = []
        produced_total = 0
        while True:
            if self._pending_error is not None or self._finished:
                break
            if max_length >= 0 and produced_total >= max_length:
                if self._between_members and data:
                    self._retained = data
                break

            if self._between_members:
                data = self._resolve_between(data)
                if self._pending_error is not None or self._finished:
                    break
                if self._retained or not data:
                    # Partial magic retained, or only NULs/empty — need more input.
                    break
                if self._index:
                    # ``data`` starts a further member.
                    self._pending_point = SeekPoint(
                        self._produced + produced_total, self._fed_end - len(data)
                    )
                continue

            if not data:
                break

            limit = max_length - produced_total if max_length >= 0 else -1
            if limit == 0:
                break
            # Corrupt deflate body (bad CRC/data check inside a member) raises
            # CorruptionError here so a raw GzipDecompressorStream does not leak
            # zlib.error (GzipCodec.translate maps it too, but the decoder must stand
            # on its own). A failed CRC-32/ISIZE check is a StreamChecksumError.
            produced = self._inflate_step(data, limit, gzip_error)
            if produced:
                if self._pending_point is not None:
                    points.append(self._pending_point)
                    self._pending_point = None
                output.append(produced)
                produced_total += len(produced)
            if self._raise_next is not None:
                break

            if self._decomp.eof:
                data = self._decomp.unused_data
                self._between_members = True
                continue

            # More compressed input remains under a max_length cap — leave it in
            # unconsumed_tail for the next feed (do not copy into _retained).
            data = self._decomp.unconsumed_tail
            if data and produced and (max_length < 0 or produced_total < max_length):
                continue
            break

        self._produced += produced_total
        return DecodeOut(b"".join(output), points)

    def _snapshot_due(self) -> bool:
        """Whether a feed inside a member starts with a snapshot seek point
        (:class:`ZlibSnapshot`). Never before a member's first output, which is the
        member's own point."""
        return (
            self._snapshots
            and self._pending_point is None
            and self._produced - self._last_snapshot >= SNAPSHOT_SPACING
        )

    def flush(self) -> DecodeOut:
        self._raise_pending()
        if self._finished:
            return DecodeOut(b"")
        # Drain mid-member unconsumed_tail / continue member chaining with no new input.
        # With no max_length, feed consumes all of its input and runs _resolve_between
        # on every byte after a member, so what is left at the end of the input is one
        # of three cases.
        out = self.feed(b"").data
        if self._pending_error is not None or self._finished:
            return DecodeOut(out)
        if not self._between_members:
            # Inside a member, with all of its input fed: the member is cut. zlib can
            # still hold output back, which _inflate_rest returns, but it cannot end the
            # member: while output is held, the 8-byte trailer is still unconsumed input,
            # so a member that gets here never reached its trailer.
            out += _inflate_rest(self._decomp, gzip_error)
            self._pending_error = TruncatedError(truncated_message("gzip"))
        elif self._retained:
            # A lone 1f that _resolve_between kept for a magic that never came.
            self._arm_trailing_junk(self._retained)
        else:
            # After a member, nothing but NUL padding.
            self._finished = True
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    @override
    def needs_input(self) -> bool:
        if self._raise_next is not None:
            return False
        if self._pending_error is not None or self._finished:
            return True
        if self._decomp.unconsumed_tail:
            return False
        # Full next-member prefix retained — drain without reading more.
        return not self._retained.startswith(GZIP_MAGIC)

    @override
    def build_index(
        self, inner: BinaryIO, last_known: SeekPoint
    ) -> tuple[list[SeekPoint], int | None]:
        del last_known  # the walk always starts at the first member
        if not self._index:
            return [], None
        return build_bgzf_index(inner, self._collector)


def ZlibDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    wbits: int = RAW_DEFLATE_WBITS,
    *,
    collector: DiagnosticCollector | None = None,
    report_trailing_data: bool = False,
    refuse_input_after_end: bool = False,
    index: bool = False,
    file_index: bool = True,
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Inflate a raw-deflate or zlib-wrapped stream.

    A backward seek decodes from the start, unless ``index`` (declared seek demand)
    makes zlib snapshots seek points (:class:`ZlibDecoder`).
    """
    return DecompressorStream(
        path,
        make_decoder=lambda point, _i: ZlibDecoder(
            wbits, index=index, start=point, natives=natives
        ),
        collector=collector,
        codec_name=_zlib_label(wbits),
        report_trailing_data=report_trailing_data,
        refuse_input_after_end=refuse_input_after_end,
        file_index=file_index,
    )


def GzipDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    collector: DiagnosticCollector | None = None,
    report_trailing_data: bool = False,
    index: bool = False,
    file_index: bool = True,
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Inflate a gzip stream with multi-member chaining.

    A backward seek decodes from the start, unless ``index`` (declared seek demand)
    makes member starts and a BGZF or mgzip file's members seek points (:class:`GzipDecoder`).
    """
    return DecompressorStream(
        path,
        make_decoder=lambda point, _i: GzipDecoder(
            index=index, collector=collector, start=point, natives=natives
        ),
        collector=collector,
        codec_name="gzip",
        report_trailing_data=report_trailing_data,
        file_index=file_index,
    )
