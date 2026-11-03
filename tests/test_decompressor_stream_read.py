"""``DecompressorStream.read(n)`` returns exactly ``n`` bytes until the end.

``read(n)`` hands a decoder's chunk straight back when nothing is buffered and the
chunk is exactly ``n`` bytes, and routes every other shape through its buffer. These
cases pin the contract across both routes: a decoder that returns what was asked, one
that returns less, and one that ignores ``max_length`` and returns more.
"""

from __future__ import annotations

import gzip
import io
import os
import zlib
from pathlib import Path
from typing import BinaryIO

import pytest

import archivey
from archivey import ArchiveyConfig
from archivey.diagnostics import DiagnosticPolicy
from archivey.exceptions import DiagnosticRaisedError
from archivey.internal.config import StreamConfig
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.codecs.base import CodecParams
from archivey.internal.streams.codecs.bzip2_codec import Bzip2Codec
from archivey.internal.streams.codecs.deflate_decoder import ZlibDecoder
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    SeekPoint,
)
from tests.conftest import assert_raised_again

_DATA = bytes(range(256)) * 97  # 24_832 bytes, not a multiple of any read size below


class _ScalingDecoder(BaseDecoder):
    """Emits each input byte ``factor`` times; honours ``max_length`` unless told not to.

    Output that ``max_length`` holds back waits in ``_pending`` for the next ``feed``,
    as zlib's ``unconsumed_tail`` does.
    """

    def __init__(self, factor: int, *, honour_max_length: bool) -> None:
        self._factor = factor
        self._honour = honour_max_length
        self._pending = b""
        self._done = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _ScalingDecoder:
        del point, inner
        return _ScalingDecoder(self._factor, honour_max_length=self._honour)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        out = self._pending + b"".join(bytes([b]) * self._factor for b in chunk)
        if self._honour and 0 <= max_length < len(out):
            self._pending = out[max_length:]
            return DecodeOut(out[:max_length])
        self._pending = b""
        return DecodeOut(out)

    def flush(self) -> DecodeOut:
        self._done = True
        out, self._pending = self._pending, b""
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return self._done

    @property
    def needs_input(self) -> bool:
        return not self._pending


def _stream(factor: int, *, honour_max_length: bool) -> DecompressorStream:
    return DecompressorStream(
        io.BytesIO(_DATA[::factor] if factor > 1 else _DATA),
        make_decoder=lambda point, inner: _ScalingDecoder(
            factor, honour_max_length=honour_max_length
        ),
    )


@pytest.mark.parametrize("honour_max_length", [True, False])
@pytest.mark.parametrize("factor", [1, 3])
@pytest.mark.parametrize("n", [1, 7, 4096, 65536, 1 << 20])
def test_read_n_is_full_count_until_eof(
    n: int, factor: int, honour_max_length: bool
) -> None:
    source = _DATA[::factor] if factor > 1 else _DATA
    expected = b"".join(bytes([b]) * factor for b in source)
    with _stream(factor, honour_max_length=honour_max_length) as stream:
        pieces: list[bytes] = []
        delivered = 0  # re-summing every piece here would make the n=1 rows quadratic
        while True:
            piece = stream.read(n)
            if not piece:
                break
            pieces.append(piece)
            delivered += len(piece)
            assert stream.tell() == delivered
        assert b"".join(pieces) == expected
        # Every piece but the last is exactly n bytes.
        assert all(len(p) == n for p in pieces[:-1])
        assert 0 < len(pieces[-1]) <= n
        assert stream.read(n) == b""


def test_read_n_after_partial_read_keeps_the_buffered_tail() -> None:
    """A read that leaves bytes buffered must hand them out before decoding more."""
    with _stream(1, honour_max_length=False) as stream:
        first = stream.read(10)  # the decoder returned far more; the rest is buffered
        second = stream.read(20)
        rest = stream.read()
    assert first + second + rest == _DATA
    assert (len(first), len(second)) == (10, 20)


class _TrailingAtFillDecoder(_ScalingDecoder):
    """A pass-through decoder that finds trailing data in the feed that fills a read.

    The first feed returns exactly ``max_length`` bytes and, in the same call, flags
    bytes past the stream's end, so the stream reports ``ARCHIVE_TRAILING_DATA``
    while that chunk is in hand.
    """

    def __init__(self) -> None:
        super().__init__(1, honour_max_length=True)

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _TrailingAtFillDecoder:
        del point, inner
        return _TrailingAtFillDecoder()

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        out = super().feed(chunk, max_length)
        self._pending = b""
        self._trailing_bytes = 1
        self._done = True
        return out


def _strict_collector() -> DiagnosticCollector:
    return DiagnosticCollector(policy=DiagnosticPolicy.STRICT)


def test_a_raise_held_while_decoding_a_full_chunk_propagates_and_keeps_the_bytes() -> (
    None
):
    """A read whose one decode fills ``n`` but also holds a raise must raise, and the
    bytes it decoded must come back on the next read, not be dropped with the raise."""
    n = 4096
    with DecompressorStream(
        io.BytesIO(_DATA),
        make_decoder=lambda point, inner: _TrailingAtFillDecoder(),
        collector=_strict_collector(),
        report_trailing_data=True,
    ) as stream:
        with pytest.raises(DiagnosticRaisedError):
            stream.read(n)
        assert stream.read(n) == _DATA[:n]
        assert stream.read(n) == b""


def _largest_library_local(exc: BaseException) -> int:
    """The largest ``bytes``/``bytearray`` local on the non-test frames of ``exc``."""
    biggest = 0
    tb = exc.__traceback__
    while tb is not None:
        if "tests" not in Path(tb.tb_frame.f_code.co_filename).parts:
            for value in list(tb.tb_frame.f_locals.values()):
                if isinstance(value, (bytes, bytearray)):
                    biggest = max(biggest, len(value))
        tb = tb.tb_next
    return biggest


def test_a_raise_after_a_short_chunk_does_not_keep_the_chunk_alive() -> None:
    """The raise's traceback keeps ``read``'s frame alive; the chunk it buffered must
    not stay bound there as a second copy of the bytes."""
    payload = os.urandom(200_000)
    blob = gzip.compress(payload) + b"appended signature\n"
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with archivey.open_stream(io.BytesIO(blob), config=config) as stream:
        with pytest.raises(DiagnosticRaisedError) as caught:
            # One request larger than the payload: the decode comes back short.
            stream.read(len(payload) + 100_000)
        assert _largest_library_local(caught.value) < 4096


def test_a_decoder_error_is_raised_again_after_a_seek_to_the_same_place() -> None:
    # The real library: the decoder raised at offset 0, so seek(0) moves nothing; it
    # must still restart the decoder rather than feed the spent one. Whether a spent
    # bz2 decoder raises ValueError or repeats its OSError depends on the CPython build,
    # so the fake decoder below is the check that does not.
    stream = Bzip2Codec().open_framed(
        io.BytesIO(b"not bzip2"), CodecParams(), StreamConfig(seekable=True)
    )
    with pytest.raises(OSError, match="Invalid data stream"):
        stream.read(10)
    for _ in range(2):
        assert stream.seek(0) == 0
        with pytest.raises(OSError, match="Invalid data stream"):
            stream.read(10)
    with pytest.raises(OSError, match="Invalid data stream"):
        stream.read(10)  # and without a seek, the verdict stays


class _FailsOnFeed(BaseDecoder):
    """Emits the first 100 bytes of each chunk before feed number ``fails_on``, raises
    on that one, then is spent.

    Once it has raised it answers every call with ``ValueError``, as ``bz2`` does on
    some CPython builds.
    """

    def __init__(self, fails_on: int) -> None:
        self._fails_on = fails_on
        self._feeds = 0
        self._raised = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _FailsOnFeed:
        del point, inner
        return _FailsOnFeed(self._fails_on)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        if self._raised:
            raise ValueError("Decompressor is unusable after a previous error")
        self._feeds += 1
        if self._feeds == self._fails_on:
            self._raised = True
            raise OSError("Invalid data stream")
        return DecodeOut(chunk[:100])

    def flush(self) -> DecodeOut:
        return self.feed(b"")

    @property
    def finished(self) -> bool:
        return False

    @property
    def needs_input(self) -> bool:
        return True


class _BigThenFails(_FailsOnFeed):
    """Emits 1 MiB on its first feed, then raises on the second."""

    def __init__(self) -> None:
        super().__init__(2)

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _BigThenFails:
        del point, inner
        return _BigThenFails()

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        out = super().feed(chunk, max_length)
        return DecodeOut(bytes(1 << 20)) if self._feeds == 1 else out


def test_a_decoder_error_after_a_short_chunk_does_not_keep_the_chunk_alive() -> None:
    """As above, for a decoder error on the decode after a short chunk: the raise's
    frames hold no second copy, and the chunk comes back on the next read."""
    stream = DecompressorStream(
        io.BytesIO(_DATA), make_decoder=lambda point, inner: _BigThenFails()
    )
    with pytest.raises(OSError, match="Invalid data stream") as caught:
        stream.read(4 << 20)
    assert _largest_library_local(caught.value) < 4096
    assert stream.read(4 << 20) == bytes(1 << 20)


def test_a_spent_decoder_is_restarted_by_a_seek_to_the_same_place() -> None:
    # The decoder raises on its first feed, so the stream is still at 0 and seek(0)
    # moves nothing. It must restart the decoder anyway: the spent one would answer
    # with ValueError, which the assertion does not accept.
    stream = DecompressorStream(
        io.BytesIO(_DATA), make_decoder=lambda point, inner: _FailsOnFeed(1)
    )
    with pytest.raises(OSError, match="Invalid data stream"):
        stream.read(10)
    for _ in range(2):
        assert stream.seek(0) == 0
        with pytest.raises(OSError, match="Invalid data stream"):
            stream.read(10)


def test_a_decoder_error_after_output_hands_back_the_buffer_then_raises() -> None:
    # The read that reaches the error raises with the first chunk's output buffered.
    # Later reads hand that output back, then raise the same error; none of them
    # feeds the spent decoder, whose ValueError would replace the verdict.
    stream = DecompressorStream(
        io.BytesIO(_DATA), make_decoder=lambda point, inner: _FailsOnFeed(2)
    )
    with pytest.raises(OSError, match="Invalid data stream") as first:
        stream.read(len(_DATA))
    got = stream.read(len(_DATA))
    assert got
    assert got == _DATA[: len(got)]
    for _ in range(2):
        with pytest.raises(OSError) as again:
            stream.read(len(_DATA))
        assert_raised_again(again.value, first.value)
    # A seek restarts the decoder, which hands back its first chunk again.
    assert stream.seek(0) == 0
    assert stream.read(len(got)) == got


class _FlushLeavesEof:
    """A ``zlib`` decompressor whose ``flush`` returns the rest but leaves ``eof``
    as it was, as PyPy's does. Everything else is the real decompressor."""

    def __init__(self, inner: zlib._Decompress) -> None:
        self._inner = inner
        self._eof_after_flush: bool | None = None

    def decompress(self, data: bytes, max_length: int = 0) -> bytes:
        return self._inner.decompress(data, max_length)

    def flush(self, *args: int) -> bytes:
        before = self._inner.eof
        out = self._inner.flush(*args)
        self._eof_after_flush = before
        return out

    @property
    def eof(self) -> bool:
        if self._eof_after_flush is not None:
            return self._eof_after_flush
        return self._inner.eof

    @property
    def unconsumed_tail(self) -> bytes:
        return self._inner.unconsumed_tail

    @property
    def unused_data(self) -> bytes:
        return self._inner.unused_data


def _flush_leaves_eof_decoder(point: SeekPoint, inner: BinaryIO) -> ZlibDecoder:
    del point, inner
    decoder = ZlibDecoder(-15)
    decoder._decomp = _FlushLeavesEof(decoder._decomp)  # type: ignore[assignment]
    return decoder


def test_a_complete_deflate_stream_ends_without_flush_setting_eof() -> None:
    """Output a ``max_length`` cut held back is drained at the end of the input, and the
    stream counts as complete even where ``flush`` never sets ``eof`` (PyPy).

    Small reads keep zlib's output cut short when the input runs out, so the end is
    reached only through ``_inflate_rest``.
    """
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    payload = b"\0" * 300_000
    data = compressor.compress(payload) + compressor.flush()
    with DecompressorStream(
        io.BytesIO(data), make_decoder=_flush_leaves_eof_decoder
    ) as stream:
        pieces: list[bytes] = []
        while piece := stream.read(255):
            pieces.append(piece)
        assert b"".join(pieces) == payload
        assert stream._decoder.finished
        assert stream._decoder.pending_error is None
