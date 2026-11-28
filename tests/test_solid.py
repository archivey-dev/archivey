"""Contract for :class:`SolidBlockReader` — the sequential solid-block demux.

This primitive backs 7z solid-folder iteration and is intended for RAR's ``unrar p``
pipe too, so its lazy-skip / no-drain-on-close behaviour is pinned here directly rather
than only through the 7z reader.
"""

from __future__ import annotations

import io

import pytest

from archivey.internal.streams.streamtools import SolidBlockReader, skip_forward


class _CountingBlock(io.BytesIO):
    """A BytesIO that records how many bytes were read and whether it was closed."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.bytes_read = 0
        self.was_closed = False

    def read(self, n: int = -1, /) -> bytes:
        data = super().read(n)
        self.bytes_read += len(data)
        return data

    def close(self) -> None:
        self.was_closed = True
        super().close()


def test_consecutive_members_read_in_order() -> None:
    block = _CountingBlock(b"AAAABBBBBCC")
    reader = SolidBlockReader(block)
    assert reader.open_member(0, 4).read() == b"AAAA"
    assert reader.open_member(4, 5).read() == b"BBBBB"
    assert reader.open_member(9, 2).read() == b"CC"


def test_partial_read_then_next_member_lazily_skips_tail() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    first = reader.open_member(0, 4)
    assert first.read(1) == b"A"  # only one byte consumed from the first member
    # Opening the next member skips the first member's unread tail (the lazy drain).
    assert reader.open_member(4, 4).read() == b"BBBB"


def test_close_does_not_drain_the_block() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    reader.open_member(0, 4).read(1)  # read a single byte, leave the rest
    reader.close()
    # Only the one requested byte was ever read; close discards the block without draining.
    assert block.bytes_read == 1
    assert block.was_closed is True


def test_out_of_order_open_raises() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    reader.open_member(4, 4).read()
    with pytest.raises(ValueError, match="in order"):
        reader.open_member(0, 4)


def test_gap_between_members_is_skipped() -> None:
    block = _CountingBlock(b"AA__BB")  # bytes 2..4 belong to no member
    reader = SolidBlockReader(block)
    assert reader.open_member(0, 2).read() == b"AA"
    assert reader.open_member(4, 2).read() == b"BB"


def test_truncated_block_raises_eof_on_skip() -> None:
    block = _CountingBlock(b"AAAA")  # only 4 bytes, second member starts past the end
    reader = SolidBlockReader(block)
    reader.open_member(0, 4).read(1)
    with pytest.raises(EOFError):
        reader.open_member(8, 2)  # skip of 7 bytes over a 3-byte remainder
    # The failed skip consumed the remainder; _pos must not stay at the pre-skip value.
    assert reader._pos == 4


def test_failed_skip_advances_position_by_what_was_consumed() -> None:
    """A skip that hits EOF must still credit bytes discarded, or later offsets are wrong."""
    block = _CountingBlock(b"AAAABBBB")  # 8 bytes
    reader = SolidBlockReader(block)
    with pytest.raises(EOFError):
        reader.open_member(100, 4)
    assert reader._pos == 8
    # With a correct _pos, a later open behind the consumed range is rejected as
    # out of order rather than skipping from a stale origin of 0.
    with pytest.raises(ValueError, match="in order"):
        reader.open_member(0, 4)


def test_failed_lazy_skip_advances_position_by_what_was_consumed() -> None:
    """The lazy path has the same skip/_pos pair; a failed first-read must not desync it."""
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    member = reader.open_member(100, 4, lazy=True)
    with pytest.raises(EOFError):
        member.read()
    assert reader._pos == 8


class _RaiseAfterPrefix:
    """Yields ``prefix``, then raises — a 7z/unrar decode error mid-skip."""

    def __init__(self, prefix: bytes, exc: BaseException) -> None:
        self._prefix = prefix
        self._off = 0
        self._exc = exc

    def read(self, n: int = -1, /) -> bytes:
        if self._off >= len(self._prefix):
            raise self._exc
        if n < 0:
            n = len(self._prefix) - self._off
        out = self._prefix[self._off : self._off + n]
        self._off += len(out)
        return out

    def close(self) -> None:
        return


def test_failed_skip_credits_bytes_when_read_raises() -> None:
    """A raising read() mid-skip must still credit bytes already pulled, not only EOF."""
    block = _RaiseAfterPrefix(b"AAAA", OSError("decode failed"))
    reader = SolidBlockReader(block, close_block=False)
    with pytest.raises(OSError, match="decode failed"):
        reader.open_member(10, 2)
    assert reader._pos == 4
    with pytest.raises(ValueError, match="in order"):
        reader.open_member(0, 2)


def test_close_block_false_leaves_block_open() -> None:
    block = _CountingBlock(b"AAAA")
    reader = SolidBlockReader(block, close_block=False)
    reader.open_member(0, 4).read()
    reader.close()
    assert block.was_closed is False


def test_lazy_open_member_defers_skip_until_read() -> None:
    from archivey.internal.streams.streamtools.solid import _MemberSlice

    block = _CountingBlock(b"AAAABBBBCCCC")
    reader = SolidBlockReader(block)
    first = reader.open_member(0, 4, lazy=True)
    second = reader.open_member(4, 4, lazy=True)
    # Same type as eager; no extra wrapper layer.
    assert isinstance(first, _MemberSlice)
    assert isinstance(second, _MemberSlice)
    # Claiming lazy handles must not touch the block.
    assert block.bytes_read == 0
    first.close()  # unread — free
    assert block.bytes_read == 0
    assert second.read() == b"BBBB"
    # Skipped the first member's range only when the second was actually read.
    assert block.bytes_read == 8


def test_lazy_open_member_out_of_order_still_rejected_at_claim() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    reader.open_member(4, 4).read()
    with pytest.raises(ValueError, match="in order"):
        reader.open_member(0, 4, lazy=True)


def test_lazy_then_read_after_later_member_raises() -> None:
    """A pending slice whose offset was passed by another open cannot be read later."""
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    early = reader.open_member(0, 4, lazy=True)
    assert reader.open_member(4, 4).read() == b"BBBB"
    with pytest.raises(ValueError, match="in order"):
        early.read()


def test_lazy_same_offset_does_not_steal_later_member() -> None:
    """A lazy zero-size member at the successor's offset must not claim the live slice."""
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    reader.open_member(0, 4).read()
    empty = reader.open_member(4, 0, lazy=True)
    later = reader.open_member(4, 4)
    with pytest.raises(ValueError, match="superseded"):
        empty.read()
    assert later.read() == b"BBBB"


def test_skip_forward_helper_raises_on_short_stream() -> None:
    stream = io.BytesIO(b"1234")
    skip_forward(stream, 4)
    assert stream.read() == b""
    stream.seek(0)
    with pytest.raises(EOFError):
        skip_forward(stream, 5)


def test_skip_forward_credits_each_chunk() -> None:
    from archivey.internal.streams.streamtools.solid import _SKIP_CHUNK

    calls: list[int] = []
    stream = io.BytesIO(b"x" * (2 * _SKIP_CHUNK + 5))
    skip_forward(stream, 2 * _SKIP_CHUNK + 5, on_chunk=calls.append)
    assert calls == [_SKIP_CHUNK, _SKIP_CHUNK, 5]


def test_skip_forward_credits_partial_skip_before_eof() -> None:
    from archivey.internal.streams.streamtools.solid import _SKIP_CHUNK

    calls: list[int] = []
    stream = io.BytesIO(b"x" * (_SKIP_CHUNK + 3))
    with pytest.raises(EOFError):
        skip_forward(stream, 2 * _SKIP_CHUNK, on_chunk=calls.append)
    assert calls == [_SKIP_CHUNK, 3]


def test_read_on_closed_lazy_member_raises_without_advancing() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    member = reader.open_member(4, 4, lazy=True)
    member.close()
    with pytest.raises(ValueError, match="closed file"):
        member.read(4)
    # A closed pending slice must not skip the block on its own behalf.
    assert block.bytes_read == 0


def test_read_on_closed_member_raises() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    member = reader.open_member(0, 4)
    member.close()
    with pytest.raises(ValueError, match="closed file"):
        member.read(4)
    # Close is not a drain; a closed unread member must not pull bytes.
    assert block.bytes_read == 0


def test_closed_slice_cannot_read_the_next_member() -> None:
    """Close A, open B: A.read() must raise, not return B's bytes (and starve B)."""
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    first = reader.open_member(0, 4)
    first.close()
    second = reader.open_member(4, 4)
    with pytest.raises(ValueError, match="closed file"):
        first.read(4)
    assert second.read() == b"BBBB"


def test_superseded_slice_cannot_read_the_next_member() -> None:
    """An still-open slice that a later open_member replaced must not consume B."""
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    first = reader.open_member(0, 4)
    second = reader.open_member(4, 4)
    with pytest.raises(ValueError, match="superseded"):
        first.read(4)
    assert second.read() == b"BBBB"


def test_tell_on_superseded_slice_raises() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    first = reader.open_member(0, 4)
    first.read(2)
    reader.open_member(4, 4)
    with pytest.raises(ValueError, match="superseded"):
        first.tell()


def test_eager_read_after_reader_close_says_reader_closed() -> None:
    """close() clears _current; that is not a later open_member()."""
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    member = reader.open_member(0, 4)
    reader.close()
    with pytest.raises(ValueError, match="SolidBlockReader is closed"):
        member.read(4)


def test_lazy_read_after_reader_close_says_reader_closed() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    member = reader.open_member(0, 4, lazy=True)
    reader.close()
    with pytest.raises(ValueError, match="SolidBlockReader is closed"):
        member.read(4)


def test_tell_after_reader_close_says_reader_closed() -> None:
    block = _CountingBlock(b"AAAABBBB")
    reader = SolidBlockReader(block)
    member = reader.open_member(0, 4)
    member.read(1)
    reader.close()
    with pytest.raises(ValueError, match="SolidBlockReader is closed"):
        member.tell()


class _StallsAfter(io.RawIOBase):
    """A non-blocking raw stream: hands out ``data``, then has nothing ready."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes | None:
        if not self._data:
            return None
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


def test_skip_forward_reports_a_stall_as_blocking_not_eof() -> None:
    calls: list[int] = []
    with pytest.raises(BlockingIOError):
        skip_forward(_StallsAfter(b"abc"), 5, on_chunk=calls.append)  # type: ignore[arg-type]  # RawIOBase double
    assert calls == [3]


class _OverReads(io.RawIOBase):
    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        return b"x" * (n + 1)


def test_skip_forward_refuses_a_read_longer_than_asked() -> None:
    with pytest.raises(ValueError, match="returned"):
        skip_forward(_OverReads(), 4)  # type: ignore[arg-type]  # RawIOBase double
