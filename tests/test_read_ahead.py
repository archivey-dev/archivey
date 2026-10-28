"""``read_ahead(need, n)`` and the buffer that fills through it.

A reader's buffer over a codec stream on a pipe asks for the bytes its caller needs,
and takes the rest of the decoder's last feed up to its own size. The contract:
at least ``need`` bytes, or fewer only at the end, and at most ``n``; no source read
for bytes past ``need``; and errors as ``read(need)`` raises them. These tests pin it
on ``DecompressorStream``, ``ArchiveStream`` and ``ReadAheadStream(fill_arrived=True)``
with a source that hands over one scripted chunk per read.
"""

from __future__ import annotations

import io
import zlib
from collections.abc import Callable
from typing import BinaryIO

import pytest

from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.internal.hashing import crc32_digest
from archivey.internal.streams.archive_stream import ArchiveStreamImpl
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    SeekPoint,
)
from archivey.internal.streams.streamtools import ReadAheadStream
from archivey.internal.streams.streamtools.binaryio import OneReadEachStream
from archivey.types import HashAlgorithm
from tests.streams_util import QueuedChunks


class _PassThrough(BaseDecoder):
    """Hands each input byte back as is, holding back what ``max_length`` cuts off."""

    def __init__(self) -> None:
        self._pending = b""
        self._done = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _PassThrough:
        del point, inner
        return _PassThrough()

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        out = self._pending + chunk
        if 0 <= max_length < len(out):
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


class _FailsOnFeed(BaseDecoder):
    """Hands back each chunk until feed number ``fails_on``, which raises."""

    def __init__(self, fails_on: int) -> None:
        self._fails_on = fails_on
        self._feeds = 0

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _FailsOnFeed:
        del point, inner
        return _FailsOnFeed(self._fails_on)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        del max_length
        self._feeds += 1
        if self._feeds >= self._fails_on:
            raise OSError("Invalid data stream")
        return DecodeOut(chunk)

    def flush(self) -> DecodeOut:
        return self.feed(b"")

    @property
    def finished(self) -> bool:
        return False

    @property
    def needs_input(self) -> bool:
        return True


_CHUNKS = (b"a" * 100, b"b" * 100, b"c" * 100)
_DATA = b"".join(_CHUNKS)


def _decoded(
    *chunks: bytes, decoder: BaseDecoder | None = None
) -> tuple[DecompressorStream, QueuedChunks]:
    """A codec stream over ``chunks``, fed one source read each, as on a pipe."""
    source = QueuedChunks(*chunks)
    made = decoder if decoder is not None else _PassThrough()
    stream = DecompressorStream(
        OneReadEachStream(source),  # type: ignore[arg-type]
        make_decoder=lambda point, inner: made.recreate(point, inner),
    )
    return stream, source


def test_the_feed_that_completes_need_comes_back_whole() -> None:
    stream, source = _decoded(*_CHUNKS)
    assert stream.read_ahead(3, 1000) == _CHUNKS[0]
    assert source.calls == 1, "a read was made for bytes past need"
    assert stream.tell() == 100


def test_need_across_feeds_reads_only_the_feeds_it_needs() -> None:
    stream, source = _decoded(*_CHUNKS)
    assert stream.read_ahead(150, 1000) == _DATA[:200]
    assert source.calls == 2


def test_no_more_than_n_comes_back_and_the_rest_stays_buffered() -> None:
    stream, source = _decoded(*_CHUNKS)
    assert stream.read_ahead(150, 170) == _DATA[:170]
    assert source.calls == 2
    assert stream.read(30) == _DATA[170:200]
    assert source.calls == 2
    assert stream.tell() == 200


def test_need_equal_to_n_is_read_need() -> None:
    stream, _ = _decoded(*_CHUNKS)
    assert stream.read_ahead(150, 150) == _DATA[:150]
    assert stream.read_ahead(150, 150) == _DATA[150:]
    assert stream.read_ahead(1, 1) == b""


def test_a_short_return_only_at_the_end() -> None:
    stream, _ = _decoded(b"x" * 40)
    assert stream.read_ahead(50, 100) == b"x" * 40
    assert stream.read_ahead(50, 100) == b""


@pytest.mark.parametrize(("need", "n"), [(1, 1), (0, 5), (-1, 5), (6, 5)])
def test_need_must_be_positive_and_at_most_n(need: int, n: int) -> None:
    stream, source = _decoded(*_CHUNKS)
    if need > 0 and n >= need:
        assert stream.read_ahead(need, n) == b"a"
        return
    with pytest.raises(ValueError, match="read_ahead"):
        stream.read_ahead(need, n)
    assert source.calls == 0


def _drain(read: Callable[[int], bytes], size: int) -> tuple[list[bytes], list[str]]:
    """Read until the stream raises twice in a row; the pieces and the errors in order.

    A read that meets the error with bytes still buffered raises first, and the next
    reads hand those bytes back, then raise again.
    """
    pieces: list[bytes] = []
    errors: list[str] = []
    for _ in range(1000):
        try:
            piece = read(size)
        except Exception as err:  # noqa: BLE001 - the error is what is compared
            if pieces and not pieces[-1]:
                return pieces, errors
            errors.append(f"{type(err).__name__}: {err}")
            pieces.append(b"")
            continue
        assert piece, "the stream ended without the error"
        pieces.append(piece)
    raise AssertionError("no error")


@pytest.mark.parametrize("need", [1, 50, 100, 150, 250])
@pytest.mark.parametrize("extra", [0, 1, 1000])
def test_errors_come_as_read_need_raises_them(need: int, extra: int) -> None:
    """The same bytes and the same error as ``read(need)``. A piece is ``need`` to
    ``need + extra`` bytes, except the last one before the error."""
    reference, _ = _decoded(*_CHUNKS, decoder=_FailsOnFeed(3))
    want, want_errors = _drain(reference.read, need)
    stream, _ = _decoded(*_CHUNKS, decoder=_FailsOnFeed(3))
    got, errors = _drain(lambda size: stream.read_ahead(size, size + extra), need)
    assert b"".join(got) == b"".join(want) == _DATA[:200]
    assert set(errors) == set(want_errors) == {"OSError: Invalid data stream"}
    full = [len(piece) for piece in got[: got.index(b"")]]
    assert all(need <= size <= need + extra for size in full[:-1])


# --- ArchiveStream -------------------------------------------------------------------


def _translate(err: Exception) -> ArchiveyError | None:
    return CorruptionError(str(err)) if isinstance(err, OSError) else None


def test_archive_stream_passes_read_ahead_to_its_codec_stream() -> None:
    inner, source = _decoded(*_CHUNKS)
    stream = ArchiveStreamImpl(lambda: inner, translate=_translate)
    assert stream.read_ahead(3, 1000) == _CHUNKS[0]
    assert source.calls == 1


class _NoReadAhead(io.BytesIO):
    """An inner that must not be asked to read ahead."""

    def read_ahead(self, need: int, n: int, /) -> bytes:
        raise AssertionError("read_ahead went past the verifier")


def test_archive_stream_with_a_verifier_reads_through_it() -> None:
    """Bytes from ``read_ahead`` would skip the digest check, so a stream with a
    verifier reads ``n`` through it, and the mismatch is raised."""
    bad = crc32_digest(zlib.crc32(_DATA) ^ 1)
    stream = ArchiveStreamImpl(
        lambda: _NoReadAhead(_DATA),
        translate=_translate,
        expected_hashes={HashAlgorithm.CRC32: bad},
    )
    got, errors = _drain(lambda size: stream.read_ahead(size, 250), 3)
    assert b"".join(got) == _DATA[: len(b"".join(got))]
    assert errors and "crc32" in errors[0]


def test_archive_stream_repeats_its_verdict_without_asking_the_codec() -> None:
    inner, source = _decoded(*_CHUNKS, decoder=_FailsOnFeed(3))
    stream = ArchiveStreamImpl(lambda: inner, translate=_translate)
    assert stream.read_ahead(200, 1000) == _DATA[:200]
    with pytest.raises(CorruptionError) as first:
        stream.read_ahead(1, 1000)
    calls = source.calls
    with pytest.raises(CorruptionError) as again:
        stream.read_ahead(1, 1000)
    assert again.value is first.value
    assert source.calls == calls


# --- ReadAheadStream(fill_arrived=True) ----------------------------------------------


def test_the_buffer_does_not_wait_to_fill() -> None:
    inner, source = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    assert buffer.read(5) == _DATA[:5]
    assert source.calls == 1
    assert buffer.tell() == 5
    # The rest of the feed is buffered: these read no more of the source.
    assert buffer.read(95) == _DATA[5:100]
    assert source.calls == 1
    assert buffer.tell() == 100


def test_without_fill_arrived_the_buffer_reads_to_its_size() -> None:
    """The contrast: a full-count fill reads every chunk to get 8 KiB."""
    inner, source = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192)  # type: ignore[arg-type]
    assert buffer.read(5) == _DATA[:5]
    assert source.calls == len(_CHUNKS) + 1


def test_seeks_and_tell_inside_the_surplus() -> None:
    inner, source = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    assert buffer.read(10) == _DATA[:10]
    assert buffer.seek(2) == 2
    assert buffer.tell() == 2
    assert buffer.read(3) == _DATA[2:5]
    assert buffer.seek(50, io.SEEK_CUR) == 55
    assert buffer.read(45) == _DATA[55:100]
    assert source.calls == 1
    assert buffer.read(150) == _DATA[100:250]
    assert buffer.tell() == 250
    assert buffer.read() == _DATA[250:]


# --- ReadAheadStream.read_arrived -----------------------------------------------------


def test_read_arrived_takes_the_buffered_bytes_first() -> None:
    inner, source = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    assert buffer.read(5) == _DATA[:5]
    assert buffer.read_arrived(10) == _DATA[5:15]
    # Fewer buffered bytes than asked for: those, without reading the source.
    assert buffer.read_arrived(1000) == _DATA[15:100]
    assert source.calls == 1
    assert buffer.tell() == 100


def test_read_arrived_with_fill_arrived_is_one_feed() -> None:
    inner, source = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    assert buffer.read_arrived(1000) == _CHUNKS[0]
    assert source.calls == 1
    assert buffer.read_arrived(1000) == _CHUNKS[1]
    assert source.calls == 2
    assert buffer.tell() == 200


def test_read_arrived_without_fill_arrived_is_a_read() -> None:
    """The fallback: a full-count fill, as ``read(n)``."""
    inner, source = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192)  # type: ignore[arg-type]
    assert buffer.read_arrived(150) == _DATA[:150]
    assert source.calls == len(_CHUNKS) + 1
    assert buffer.read_arrived(1000) == _DATA[150:]
    assert buffer.read_arrived(1000) == b""


def test_read_arrived_raises_a_held_error() -> None:
    inner, _ = _decoded(*_CHUNKS, decoder=_FailsOnFeed(3))
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    assert buffer.read(150) == _DATA[:150]
    # The fill fails with bytes still buffered: they come back, the error is held.
    assert buffer.read(100) == _DATA[150:200]
    with pytest.raises((OSError, ArchiveyError)):
        buffer.read_arrived(10)


def test_read_arrived_refuses_misuse() -> None:
    inner, _ = _decoded(*_CHUNKS)
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive"):
        buffer.read_arrived(0)
    buffer.close()
    with pytest.raises(ValueError, match="closed"):
        buffer.read_arrived(1)


@pytest.mark.parametrize("size", [1, 7, 150, 1000])
def test_the_buffer_gives_the_prefix_then_the_error(size: int) -> None:
    inner, _ = _decoded(*_CHUNKS, decoder=_FailsOnFeed(3))
    buffer = ReadAheadStream(inner, 8192, fill_arrived=True)  # type: ignore[arg-type]
    got, errors = _drain(buffer.read, size)
    assert b"".join(got) == _DATA[:200]
    assert set(errors) == {"OSError: Invalid data stream"}
