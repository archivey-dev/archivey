"""``ReadAheadStream``: a read buffer that reads its full-count inner once per read."""

from __future__ import annotations

import io
from random import Random

import pytest

from archivey.internal.streams.streamtools import ReadAheadStream


class _DeferredCut(io.RawIOBase):
    """Full-count bytes that end in a deferred error, as a cut decoder's do.

    A read that reaches the end returns the bytes left, short; the read after it raises.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self.reads: list[int] = []

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        assert whence == io.SEEK_SET
        self._pos = offset
        return offset

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1, /) -> bytes:
        self.reads.append(n)
        if self._pos >= len(self._data):
            raise EOFError("cut")
        end = len(self._data) if n < 0 else self._pos + n
        data = self._data[self._pos : end]
        self._pos += len(data)
        return data


def _drain(stream: ReadAheadStream, size: int) -> bytes:
    out = bytearray()
    with pytest.raises(EOFError):
        while block := stream.read(size):
            out += block
    return bytes(out)


@pytest.mark.parametrize("size", [1, 7, 100, 1000, 5000])
def test_the_prefix_comes_before_a_deferred_error(size: int) -> None:
    data = Random(0).randbytes(2500)
    assert _drain(ReadAheadStream(_DeferredCut(data), 1024), size) == data


def test_the_inner_is_read_once_per_read() -> None:
    inner = _DeferredCut(bytes(2500))
    stream = ReadAheadStream(inner, 1024)
    assert len(stream.read(10)) == 10
    assert inner.reads == [1024]
    assert len(stream.read(1020)) == 1020  # 1014 buffered, 6 from one fill
    assert inner.reads == [1024, 1024]
    assert len(stream.read(3000)) == 1470  # 1018 buffered, then the short end
    assert inner.reads == [1024, 1024, 1982]


def test_buffered_bytes_come_before_an_error_from_the_fill() -> None:
    """A fill that raises with bytes still buffered returns them; the error waits for
    the next read."""
    stream = ReadAheadStream(_DeferredCut(bytes(1024)), 1024)
    assert len(stream.read(1000)) == 1000
    assert len(stream.read(100)) == 24
    with pytest.raises(EOFError):
        stream.read(100)


def test_read_all_returns_the_buffer_and_the_rest() -> None:
    data = Random(1).randbytes(3000)
    stream = ReadAheadStream(io.BytesIO(data), 1024)
    assert stream.read(5) == data[:5]
    assert stream.read() == data[5:]
    assert stream.read() == b""


def test_seek_and_tell_count_the_bytes_still_buffered() -> None:
    data = Random(2).randbytes(3000)
    stream = ReadAheadStream(io.BytesIO(data), 1024)
    assert stream.read(10) == data[:10]
    assert stream.tell() == 10
    assert stream.seek(5, io.SEEK_CUR) == 15
    assert stream.read(10) == data[15:25]
    assert stream.seek(-10, io.SEEK_END) == 2990
    assert stream.read() == data[2990:]
    assert stream.seek(1) == 1
    assert stream.tell() == 1
    assert stream.read(3) == data[1:4]


def test_a_seek_drops_a_held_error() -> None:
    stream = ReadAheadStream(_DeferredCut(bytes(1024)), 1024)
    stream.read(1000)
    assert len(stream.read(100)) == 24  # the error is held
    assert stream.seek(0) == 0
    assert stream.read(4) == bytes(4)


def test_a_seek_inside_the_buffer_does_not_move_the_inner() -> None:
    data = Random(3).randbytes(2048)
    inner = _DeferredCut(data)
    stream = ReadAheadStream(inner, 1024)
    assert stream.read(10) == data[:10]
    assert stream.seek(500) == 500
    assert stream.read(10) == data[500:510]
    assert stream.seek(-510, io.SEEK_CUR) == 0
    assert stream.read(4) == data[:4]
    assert inner.reads == [1024]
    assert inner.tell() == 1024


def test_close_closes_the_inner() -> None:
    inner = io.BytesIO(b"abc")
    stream = ReadAheadStream(inner, 1024)
    stream.close()
    assert inner.closed
    with pytest.raises(ValueError, match="closed"):
        stream.read(1)


class _SizedReads(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.sizes: list[int] = []

    def read(self, n: int = -1, /) -> bytes:
        self.sizes.append(n)
        return super().read(n)


class _RaisesOnRead(io.BytesIO):
    """Raises ``OSError`` from the read that starts at ``at``.

    ``consume`` bytes are taken first, so the position after the raise is ahead of
    where the read began.
    """

    def __init__(self, data: bytes, *, at: int, consume: int = 0) -> None:
        super().__init__(data)
        self._at = at
        self._consume = consume
        self._raised = False

    def read(self, n: int = -1, /) -> bytes:
        if not self._raised and self.tell() >= self._at:
            self._raised = True
            if self._consume:
                super().read(self._consume)
            raise OSError("cut")
        return super().read(n)


class _RestoreSeekFails(_RaisesOnRead):
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if whence == io.SEEK_SET:
            raise OSError("no absolute")
        return super().seek(offset, whence)


def test_rewind_oversize_does_not_repeat_bytes_after_a_failed_read() -> None:
    """A failed oversize read returns the prefetched tail and leaves the inner past it.

    The rewind has already given that tail back to the inner. Returning it without
    moving forward makes the read after the stashed error deliver the same bytes.
    """
    data = bytes(range(32))
    stream = ReadAheadStream(_RaisesOnRead(data, at=3), 8, rewind_oversize=True)
    assert stream.read(3) == data[:3]
    assert stream.read(100) == data[3:8]
    assert stream.tell() == 8
    with pytest.raises(OSError, match="cut"):
        stream.read(1)
    assert stream.read(4) == data[8:12]


def test_rewind_oversize_restore_uses_the_position_from_before_the_read() -> None:
    """Bytes the failed read already took do not shift where the tail ends.

    The restore is an absolute seek to the position from just after the rewind,
    plus the tail. Seeking forward by the tail from wherever the failed read
    stopped would skip past the tail.
    """
    data = bytes(range(32))
    stream = ReadAheadStream(
        _RaisesOnRead(data, at=3, consume=2), 8, rewind_oversize=True
    )
    assert stream.read(3) == data[:3]
    assert stream.read(100) == data[3:8]
    assert stream.tell() == 8
    with pytest.raises(OSError, match="cut"):
        stream.read(1)
    assert stream.read(4) == data[8:12]


def test_rewind_oversize_reraises_when_the_position_cannot_be_restored() -> None:
    """A restore that fails does not hand back bytes the inner still holds."""
    data = bytes(range(32))
    stream = ReadAheadStream(_RestoreSeekFails(data, at=3), 8, rewind_oversize=True)
    assert stream.read(3) == data[:3]
    with pytest.raises(OSError, match="cut"):
        stream.read(100)


def test_rewind_oversize_reads_the_request_once() -> None:
    """A large read rewinds the prefetched tail and returns one inner read.

    Joining the tail to a second read would copy the whole request. The bytes
    are the same either way.
    """
    data = bytes(range(256)) * 8
    inner = _SizedReads(data)
    stream = ReadAheadStream(inner, 8, rewind_oversize=True)
    assert stream.read(3) == data[:3]
    inner.sizes.clear()
    assert stream.read(100) == data[3:103]
    assert inner.sizes == [100]
    assert stream.read() == data[103:]
    plain = ReadAheadStream(io.BytesIO(data), 8)
    assert plain.read(3) + plain.read(100) + plain.read() == data


def test_skip_buffered_moves_only_inside_the_buffer() -> None:
    inner = io.BytesIO(bytes(range(100)))
    stream = ReadAheadStream(inner, 16)
    assert stream.read(4) == bytes(range(4))
    assert stream.skip_buffered(10)
    assert stream.tell() == 14
    assert not stream.skip_buffered(3)  # two bytes left in the buffer
    assert stream.read(2) == bytes([14, 15])
