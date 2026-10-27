"""Decoders for gzip, zlib and raw DEFLATE on the standard library's ``zlib``."""

from __future__ import annotations

import os
from functools import partial
from typing import BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.diagnostics_collector import DiagnosticCollector
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


def _zlib_label(wbits: int) -> str:
    """The name of a ``wbits`` stream in messages: a positive ``wbits`` reads the zlib
    header, a negative one raw DEFLATE."""
    return "zlib" if wbits > 0 else "deflate"


class ZlibDecoder(BaseDecoder):
    """Inflate a raw-deflate or zlib-wrapped stream via ``zlib.decompressobj``."""

    def __init__(
        self, wbits: int = RAW_DEFLATE_WBITS, *, natives: Natives = IN_PROCESS
    ) -> None:
        self._wbits = wbits
        self._natives = natives
        self._decomp = natives.zlib_decompressobj(wbits)
        self._label = _zlib_label(wbits)
        self._error = partial(zlib_error, label=self._label)

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
        return ZlibDecoder(self._wbits, natives=self._natives)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        if self._decomp.eof:
            # Past the end; the stream stops reading once these hold a non-zero byte.
            self._past_end(chunk)
            return DecodeOut(b"")
        # unconsumed_tail holds input not yet consumed under a prior max_length cap;
        # prepend it exactly once (mirrors gzip._GzipReader).
        data = self._decomp.unconsumed_tail + chunk
        if not data:
            return DecodeOut(b"")
        out = _inflate(self._decomp, data, max_length, self._error)
        if self._decomp.eof:
            self._past_end(self._decomp.unused_data)
        return DecodeOut(out)

    def flush(self) -> DecodeOut:
        leftover = _inflate_rest(self._decomp, self._error)
        if not self._decomp.eof:
            self._pending_error = TruncatedError(truncated_message(self._label))
        return DecodeOut(leftover)

    @property
    def finished(self) -> bool:
        return self._decomp.eof

    @property
    def needs_input(self) -> bool:
        return not self._decomp.unconsumed_tail


class GzipDecoder(BaseDecoder):
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
    a BGZF file's members without decoding (:mod:`.bgzf_index`). ``start`` is the point
    this decoder resumes from.
    """

    # The BGZF walk reads the whole file, so a size query does not run it.
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
        self._decomp = natives.zlib_decompressobj(GZIP_WBITS)
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
        if self._finished or self._pending_error is not None:
            return DecodeOut(b"")

        if self._between_members:
            data = self._retained + chunk
            self._retained = b""
        else:
            data = self._decomp.unconsumed_tail + chunk
        self._fed_end += len(chunk)

        # Output pieces, joined once at the end: one ``decompress`` call is the common
        # case, and ``b"".join`` hands a lone piece back without copying it.
        output: list[bytes] = []
        points: list[SeekPoint] = []
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
            # on its own). A failed CRC-32/ISIZE check is a _StreamChecksumError.
            produced = _inflate(self._decomp, data, limit, gzip_error)
            if produced:
                if self._pending_point is not None:
                    points.append(self._pending_point)
                    self._pending_point = None
                output.append(produced)
                produced_total += len(produced)

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

    def flush(self) -> DecodeOut:
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
    def needs_input(self) -> bool:
        if self._pending_error is not None or self._finished:
            return True
        if self._decomp.unconsumed_tail:
            return False
        # Full next-member prefix retained — drain without reading more.
        return not self._retained.startswith(GZIP_MAGIC)

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
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Inflate a raw-deflate or zlib-wrapped stream (forward-only)."""
    return DecompressorStream(
        path,
        make_decoder=lambda _p, _i: ZlibDecoder(wbits, natives=natives),
        collector=collector,
        codec_name=_zlib_label(wbits),
        report_trailing_data=report_trailing_data,
        refuse_input_after_end=refuse_input_after_end,
    )


def GzipDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    collector: DiagnosticCollector | None = None,
    report_trailing_data: bool = False,
    index: bool = False,
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Inflate a gzip stream with multi-member chaining.

    A backward seek decodes from the start, unless ``index`` (declared seek demand)
    makes member starts and a BGZF file's members seek points (:class:`GzipDecoder`).
    """
    return DecompressorStream(
        path,
        make_decoder=lambda point, _i: GzipDecoder(
            index=index, collector=collector, start=point, natives=natives
        ),
        collector=collector,
        codec_name="gzip",
        report_trailing_data=report_trailing_data,
    )
