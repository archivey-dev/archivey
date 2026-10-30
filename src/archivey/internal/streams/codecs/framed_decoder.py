"""The decoder for a codec whose library decodes one stream at a time
(:class:`archivey.formats.Decompressor`): bzip2, zstd, LZ4, LZMA Alone, Shrink,
Implode and every plugin codec. It ends a stream at its end mark, or where the input
ends for one with none (``end_input()``), and tells a following stream from trailing
data by its start (:data:`StreamStart`).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.bzip2_resume import (
    Bzip2Resume,
    Bzip2ResumeDecoder,
)
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    Decoder,
    DecompressorStream,
    SeekPoint,
    damaged_stream_error,
    near_stream_magic,
    release_decoder,
)

if TYPE_CHECKING:
    from archivey.formats import Decompressor


# A stream's magic, as the bytes each position may hold; a codec lists one per kind of
# stream that may follow the first (zstd: a frame or a skippable frame).
StreamMagic = tuple[tuple[frozenset[int], ...], ...]
# Given the bytes after a stream: True when they start another, None when more bytes are
# needed to tell, False when they do not. It may also refuse the stream by raising, as
# the LZMA Alone check does for a dictionary over ``max_decoder_memory`` and a magic
# check does for a damaged magic, so its result must not be cached or its call skipped.
StreamStart = Callable[[bytes], bool | None]

# The most output one ``FramedDecoder.flush`` call drains from a decompressor that held
# some back until the end of its input; the stream calls ``flush`` again for the rest.
_FLUSH_DRAIN_CHUNK = 65536


def stream_magic(*alternatives: tuple[bytes | range, ...]) -> StreamStart:
    """A :data:`StreamStart` matching any of ``alternatives``, per-position bytes or ranges."""
    return MagicStart(
        tuple(
            tuple(frozenset(position) for position in alternative)
            for alternative in alternatives
        )
    )


def never_starts(data: bytes) -> bool:
    """The :data:`StreamStart` of a codec that reads one stream: nothing starts another."""
    del data
    return False


def offset0_start(
    magic: Iterable[tuple[int, bytes]], concatenated: bool
) -> StreamStart:
    """How a further stream starts for a codec that declares ``magic`` as
    ``(offset, data)`` pairs: one of its offset-0 magics, or nothing when it is not
    ``concatenated`` or has none. Plugin and built-in codecs share this rule."""
    starts = [data for offset, data in magic if offset == 0]
    if not concatenated or not starts:
        return never_starts
    return stream_magic(*(tuple(bytes([b]) for b in data) for data in starts))


@dataclass(frozen=True)
class StreamIndex:
    """How a codec's further streams become seek points (zstd frames).

    Every stream after the first starts with a fresh decompressor, so its start is a
    point a seek can resume from. ``resumes_at`` is given the bytes that start such a
    stream and says whether to record its start (zstd: not a skippable frame, which
    holds no output). ``build`` reads a whole-file index without decoding (the zstd
    seek table), as :meth:`Decoder.build_index` does.
    """

    resumes_at: Callable[[bytes], bool]
    build: Callable[[BinaryIO, SeekPoint], tuple[list[SeekPoint], int | None]]


class MagicStart:
    """The :data:`StreamStart` that :func:`stream_magic` makes: a check of ``magic``.

    :class:`FramedDecoder` also asks it whether bytes that begin inside a short run of
    zeros are a damaged stream (:meth:`damaged`), since a damaged byte can be a zero.
    """

    def __init__(self, magic: StreamMagic) -> None:
        self.magic = magic
        # The longest alternative. A run of this many zeros is padding, not the start
        # of a damaged magic.
        self.width = max((len(alternative) for alternative in magic), default=0)

    def __call__(self, data: bytes) -> bool | None:
        return _magic_state(data, self.magic)

    def damaged(self, data: bytes) -> bool:
        """Whether ``data`` starts like a damaged stream (:func:`near_stream_magic`)."""
        return any(near_stream_magic(data, alternative) for alternative in self.magic)


def _magic_state(data: bytes, magic: StreamMagic) -> bool | None:
    """True when ``data`` starts a stream, False when it does not, None when the bytes
    so far cannot tell.

    ``None`` comes for a ``data`` that is a prefix of a magic, and also for any
    ``data`` shorter than an alternative that it does not start: such bytes cannot
    start that stream, but bytes that start like a damaged stream
    (:func:`near_stream_magic`) raise :class:`CorruptionError`, and that test needs a
    whole magic. So a short ``data`` is waited on; at the end of the source it is
    trailing data (``flush``).
    """
    for alternative in magic:
        seen = min(len(data), len(alternative))
        if all(data[i] in alternative[i] for i in range(seen)):
            return True if seen == len(alternative) else None
    undecided = False
    for alternative in magic:
        if len(data) < len(alternative):
            undecided = True
            continue
        if near_stream_magic(data, alternative):
            raise damaged_stream_error()
    return None if undecided else False


class FramedDecoder(BaseDecoder):
    """Decode a codec whose library decompressor stops at the end of one stream.

    ``bz2``, ``lzma`` (Alone), ``zstd`` and ``lz4.frame`` each have a one-stream
    decompressor with ``decompress(data, max_length)``, ``eof``, ``unused_data`` and
    ``needs_input``. Their file readers decide on their own what may follow a stream,
    and disagree: ``bz2.open`` ignores anything that does not decode, zstd and lz4
    raise on it. This adapter decides it the same way for all of them. Bytes that start
    ``magic`` right after a stream begin another stream (a concatenated file); bytes
    there that hold at least half of the magic, but not all, are a damaged stream and
    raise :class:`CorruptionError` (:func:`near_stream_magic`). Zeros that run to the
    end of the input are padding. Anything else ends the data and sets
    :attr:`trailing_bytes`. That includes any byte after zeros, a further stream's
    magic too: the first non-zero byte after them is where the trailing bytes start.
    One exception: a run of zeros shorter than the magic is judged with the bytes after
    it as the start of a damaged stream, since the damaged byte can be a zero.
    With an ``index`` (:class:`StreamIndex`), each further stream's start is a seek
    point, and ``start`` is the point this decoder resumes from.
    Each codec's own tool stops at zeros between streams too: ``bzip2``, ``zstd``,
    ``lz4`` and ``xz --format=lzma``, and 7-Zip for bzip2 and LZMA Alone. ``zstd``,
    ``lz4`` and ``xz --format=lzma`` also refuse zeros at the end of the file, which
    archivey accepts on purpose, as for every codec (``dev-docs/formats/single-file.md``
    §6). A codec with no magic (LZMA Alone) passes a :data:`StreamStart` check of the
    header instead, which may raise to refuse the next stream. ``zero_padding=False``
    hands zeros to that check too (raw LZMA, where 7-Zip refuses any byte after the end
    marker).

    The first stream is handed to the library as it comes, so a file that is not this
    codec at all fails with the library's own error. An empty source, or one that ends
    inside a stream, is truncated. A decompressor with an ``end_input()`` is told where the
    input ends, which lets a stream with no end mark (legacy LZ4, Shrink with no size)
    end there. Output it held back until then comes from ``decompress(b"",
    max_length)``, called again until it sets ``eof``; asking for input instead, or
    producing nothing, leaves the stream truncated.
    """

    def __init__(
        self,
        new_decompressor: Callable[[], Decompressor],
        *,
        magic: StreamStart,
        zero_padding: bool = True,
        index: StreamIndex | None = None,
        start: SeekPoint | None = None,
    ) -> None:
        self._new = new_decompressor
        self._magic = magic
        self._index = index
        # Source offset just past every byte fed, and output offset just past every
        # byte produced: the bytes a feed holds are always the last ones fed, so a
        # further stream's start is at ``_fed_end`` minus what is left of them. Every
        # reassignment of ``data`` in ``feed`` must keep it a suffix: ``_held`` plus
        # the chunk, ``_next_stream`` dropping zeros from the front, and
        # ``unused_data`` at a stream's end. One that broke it would give seek points
        # the wrong source offset, which serves wrong bytes rather than raising.
        self._fed_end = start.compressed_offset if start is not None else 0
        self._produced = start.decompressed_offset if start is not None else 0
        # The current stream's start, recorded once the stream has output: a stream
        # with none shares its offset with the next one, and the point is the next's,
        # as in an index that lists both.
        self._pending_point: SeekPoint | None = None
        # The magic-based codecs only (not LZMA Alone): they also judge a short run of
        # zeros as the start of a damaged magic.
        self._magic_start = magic if isinstance(magic, MagicStart) else None
        self._zero_padding = zero_padding
        self._decomp = new_decompressor()
        self._fed = False
        # Past a stream's end, looking for the next one.
        self._between = False
        # Past a stream's end, zeros have been skipped; no stream follows them.
        self._padded = False
        # Input not yet handed on: kept when an output budget ran out, or bytes after a
        # stream, fewer than a magic, waiting for the rest (``_need_more``).
        self._held = b""
        self._need_more = False
        self._done = False
        # The last ``feed``'s output budget, which bounds the output ``flush`` drains.
        self._max_length = -1
        # Set once a decompressor with an ``end_input()`` has been told the input ended;
        # ``_draining`` while its held-back output is still coming (``flush``).
        self._told_end = False
        self._draining = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        del inner
        if isinstance(point.state, Bzip2Resume):
            # Only the bzip2 takeover adds such a point (``bzip2_resume``), so
            # ``_new`` builds a bz2 decompressor.
            return Bzip2ResumeDecoder(point.state, self, self._new)
        return FramedDecoder(
            self._new,
            magic=self._magic,
            zero_padding=self._zero_padding,
            index=self._index,
            start=point,
        )

    def _next_stream(self, data: bytes) -> bytes:
        """Resolve ``data`` past a stream's end: the next stream's input, or ``b""``.

        A further stream continues the output only where ``magic`` accepts it; a
        container coder that is one stream (``CodecParams.single_stream``) accepts
        none, so a further stream there is input after the end, like any other byte
        that starts no stream.
        """
        rest = data.lstrip(b"\x00") if self._zero_padding else data
        if len(rest) < len(data):
            # Zero padding is input after a stream's end, which a
            # ``refuse_input_after_end`` stream refuses (``input_after_end``).
            self._input_after_end = True
            self._padded = True
        width = self._magic_start.width if self._magic_start is not None else 0
        # A run of ``width`` zeros or more is padding whatever its length, so no more
        # than ``width`` of them are kept: the decision then does not depend on where
        # the source's chunks end.
        zeros = len(data) - len(rest)
        data = data[max(0, zeros - width) :]
        if not rest:
            self._held = data
            self._need_more = bool(data)
            return b""
        if self._padded:
            # After zeros no stream is read. Only a run shorter than the magic is still
            # judged, as a damaged magic's first bytes, which needs a magic's length.
            if 0 < zeros < width and len(data) < width:
                self._held = data
                self._need_more = True
                return b""
            self._judge_zero_run(data, zeros)
            self._past_end(rest)
            self._done = True
            return b""
        state = self._magic(rest)
        if state is None:
            self._held = data
            self._need_more = True
            return b""
        if state:
            release_decoder(self._decomp)
            self._decomp = self._new()
            self._between = False
            return rest
        self._past_end(rest)
        self._done = True
        return b""

    def _judge_zero_run(self, data: bytes, zeros: int) -> None:
        """Raise when ``data``, past a stream's end, starts with ``zeros`` zeros that
        begin a damaged stream.

        A damaged first byte can be a zero, which the padding strip takes for padding.
        So a run shorter than the magic is also judged as its start. ``_next_stream``
        and ``flush`` both ask, so the end of the input judges the bytes as the middle
        of the file does.
        """
        magic = self._magic_start
        if magic is not None and 0 < zeros < magic.width and magic.damaged(data):
            raise damaged_stream_error()

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        if self._done:
            return DecodeOut(b"")
        data = self._held + chunk
        self._held = b""
        self._need_more = False
        self._max_length = max_length
        self._fed = self._fed or bool(data)
        self._fed_end += len(chunk)
        output = bytearray()
        points: list[SeekPoint] = []
        while True:
            if max_length >= 0 and len(output) >= max_length:
                self._held = data
                break
            if self._between:
                data = self._next_stream(data)
                if self._between or self._done:
                    break
                if self._index is not None and self._index.resumes_at(data):
                    self._pending_point = SeekPoint(
                        self._produced + len(output), self._fed_end - len(data)
                    )
            limit = max_length - len(output) if max_length >= 0 else -1
            produced = self._decomp.decompress(data, limit)
            if produced and self._pending_point is not None:
                points.append(self._pending_point)
                self._pending_point = None
            output.extend(produced)
            data = b""
            if self._decomp.eof:
                # lz4 reports no leftover as None rather than b"".
                data = self._decomp.unused_data or b""
                self._between = True
                continue
            if self._decomp.needs_input or not produced:
                break
        self._produced += len(output)
        return DecodeOut(bytes(output), points)

    def flush(self) -> DecodeOut:
        if self._done:
            return DecodeOut(b"")
        if self._between:
            # The file ends inside the bytes held after this stream. A short run of
            # zeros and the bytes after it can still be a magic wide, and a damaged
            # stream (as in ``_next_stream``). The width counts from the first zero:
            # ``\x00Zh9`` is a bzip2 magic wide and raises. Fewer bytes than that,
            # zeros included, are too short to tell, so they are what follows this
            # one. ``_held`` keeps at most ``width`` zeros (``_next_stream``), so the
            # capped count decides ``zeros < width`` exactly as the uncapped one does.
            held = self._held
            if self._zero_padding:
                self._judge_zero_run(held, len(held) - len(held.lstrip(b"\x00")))
            self._past_end(held)
            self._held = b""
            self._done = True
            return DecodeOut(b"")
        if not self._told_end:
            self._end_input()
        output = self._drain() if self._told_end else b""
        self._draining = False
        if self._decomp.eof:
            # A stream with no end mark ended with its input, so no stream follows
            # it: any byte it did not use is after its end.
            self._past_end(self._decomp.unused_data or b"")
            self._done = True
        elif output and not self._decomp.needs_input:
            # More held-back output follows: the stream calls ``flush`` again.
            self._draining = True
        elif self._pending_error is None:
            self._pending_error = TruncatedError(
                "File is truncated" if self._fed else "File is empty"
            )
        self._produced += len(output)
        return DecodeOut(output)

    def _end_input(self) -> None:
        """Tell the decompressor, when it has an ``end_input()``, that the input ended.

        ``end_input()`` returns nothing: output it held back until the end comes from
        ``decompress(b"", max_length)`` (``_drain``), bounded like any other. Its error
        is the decoder's pending error.
        """
        end_input = getattr(self._decomp, "end_input", None)
        if end_input is None:
            return
        self._told_end = True
        try:
            if end_input():
                raise TypeError("a decompressor's end_input() returns no output")
        except Exception as exc:  # noqa: BLE001 - the codec's error, raised later
            self._pending_error = exc

    def _drain(self) -> bytes:
        """The next piece of the output a decompressor held back until the end of its
        input, at most ``_FLUSH_DRAIN_CHUNK`` bytes and the last ``feed``'s budget."""
        if self._pending_error is not None or self._decomp.eof:
            return b""
        limit = _FLUSH_DRAIN_CHUNK
        if self._max_length > 0:
            limit = min(limit, self._max_length)
        return self._decomp.decompress(b"", limit)

    @property
    @override
    def drains_after_flush(self) -> bool:
        return self._draining

    @property
    def finished(self) -> bool:
        return self._done

    @property
    @override
    def needs_input(self) -> bool:
        if self._done or self._draining:
            return True
        if self._held:
            return self._need_more
        return self._between or self._decomp.needs_input

    @override
    def build_index(
        self, inner: BinaryIO, last_known: SeekPoint
    ) -> tuple[list[SeekPoint], int | None]:
        if self._index is None:
            return [], None
        return self._index.build(inner, last_known)


def FramedDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    new_decompressor: Callable[[], Decompressor],
    *,
    codec_name: str,
    magic: StreamStart,
    zero_padding: bool = True,
    index: StreamIndex | None = None,
    collector: DiagnosticCollector | None = None,
    report_trailing_data: bool = False,
    refuse_input_after_end: bool = False,
) -> DecompressorStream:
    """Decode a one-stream library decompressor's codec.

    Forward-only with an O(n) rewind, unless ``index`` makes its streams seek points.
    """
    return DecompressorStream(
        path,
        make_decoder=lambda point, _i: FramedDecoder(
            new_decompressor,
            magic=magic,
            zero_padding=zero_padding,
            index=index,
            start=point,
        ),
        collector=collector,
        codec_name=codec_name,
        report_trailing_data=report_trailing_data,
        refuse_input_after_end=refuse_input_after_end,
    )
