"""A sparse file's logical bytes over its stored bytes, holes as zeros.

A sparse file is stored as its data chunks only, one after another, plus a map that
says where each chunk sits in the logical file. :class:`SparseStream` serves the
logical file: a read inside a chunk reads the stored bytes, a read inside a hole
returns zeros without touching the inner stream.

The map must already be validated by the caller: non-negative, in order, not
overlapping, inside ``size``, and summing to the stored bytes. For TAR,
``validate_sparse_map`` in the native TAR parser checks exactly these. This module
does not check them again, because what an invalid map means (damage, or a valid map
it cannot serve) is the format's decision, not this stream's.

The zeros of a hole are output the archive chooses, and this stream neither counts nor
caps them: the output limits (``max_extracted_bytes``, ``max_ratio``) must count above
it, where the logical bytes are.

Stored data that ends early follows the member-stream truncation rule (ADR 0014): a
sized ``read(n)`` returns the logical bytes before the cut, holes included, short, and
the next read raises; a ``read()`` with no size raises and returns nothing. The error
is the inner stream's own when it raises one, so a format reader can name where its
archive ends. An inner that returns ``b""`` instead gets a builtin :class:`EOFError`
from this stream, which the format reader translates, as for
:func:`~archivey.internal.streams.streamtools.solid.skip_forward`.

Seeking follows ``io.BytesIO``: any non-negative target is accepted, a read past the
end returns ``b""``. Over a forward-only inner the stream is forward-only too: reading
never needs to go back in the inner, because chunks are in logical order, but a
backward seek would.
"""

from __future__ import annotations

import io
from bisect import bisect_right
from collections.abc import Sequence
from typing import BinaryIO

from archivey.internal.overrides import override
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    check_read_size,
    resolve_seek,
)
from archivey.internal.streams.streamtools.solid import skip_forward


class SparseStream(DelegatingStream):
    """The logical bytes of a sparse file of ``size`` bytes.

    ``offsets[i]`` is where chunk ``i`` starts in the logical file and ``lengths[i]``
    how long it is; chunk ``i`` is stored right after chunk ``i - 1`` in ``inner``.
    The first chunk starts where ``inner`` is positioned when this stream is made.
    Owns ``inner``, as every :class:`DelegatingStream` does.
    """

    # read() transforms the inner's bytes, so readinto must go through it.
    readinto_passthrough = False

    def __init__(
        self,
        inner: BinaryIO,
        offsets: Sequence[int],
        lengths: Sequence[int],
        size: int,
    ) -> None:
        super().__init__(inner)
        # A zero-length chunk's end equals its start. Keeping it can make a
        # fragment ask the inner stream for zero bytes. Dropping it keeps the
        # ends increasing, so adding one to the index matches the search.
        chunks = [(o, n) for o, n in zip(offsets, lengths, strict=True) if n]
        self._starts = [o for o, _ in chunks]
        self._ends = [o + n for o, n in chunks]
        # Where each chunk starts in the inner stream.
        self._stored: list[int] = []
        total = 0
        for _, n in chunks:
            self._stored.append(total)
            total += n
        self._size = size
        self._pos = 0
        # The next chunk when _pos is in a hole, or len(self._starts) when _pos
        # is past the last chunk. A seek to a new position sets it. read() adds
        # one at a chunk's end.
        self._chunk_index = self._chunk_index_at(0)
        # Where the first chunk starts in the inner stream, and how far past it the
        # inner stream is now.
        self._base = inner.tell() if self._seekable else 0
        self._inner_pos = 0
        # The inner's error at a cut, held back by a sized read that had bytes to
        # return first; the next read raises it.
        self._pending: Exception | None = None

    def _raise_if_closed(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed file.")

    @override
    def tell(self) -> int:
        self._raise_if_closed()
        return self._pos

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self._raise_if_closed()
        target = resolve_seek(offset, whence, pos=self._pos, end=lambda: self._size)
        if not self._seekable and target < self._pos:
            raise io.UnsupportedOperation(
                "backward seek on a forward-only sparse stream"
            )
        if target == self._pos:
            return target
        # The next read starts somewhere else and meets the cut again if it reaches it.
        self._pending = None
        self._pos = target
        self._chunk_index = self._chunk_index_at(target)
        return target

    def _chunk_index_at(self, pos: int) -> int:
        # Position 0 needs no search. Starts are non-negative and empty chunks
        # are dropped, so no chunk ends at or before 0. The index is 0.
        if pos == 0:
            return 0
        # Ends increase. The first end strictly after pos is the chunk that
        # contains pos, or the next chunk when pos is in a hole. An end equal to
        # pos belongs to a chunk the position has already left.
        return bisect_right(self._ends, pos)

    @override
    def read(self, n: int = -1, /) -> bytes:
        self._raise_if_closed()
        n = check_read_size(n)
        if self._pending is not None:
            error, self._pending = self._pending, None
            raise error
        left = self._size - self._pos
        if left <= 0:
            return b""
        whole = n < 0
        want = left if whole else min(n, left)
        parts: list[bytes] = []
        while want:
            try:
                part, cut = self._read_some(want)
            except Exception as exc:
                # The inner raised, as at a cut on a chunk's first byte, where the
                # inner read gets nothing. A sized read that already holds bytes,
                # holes included, returns them first (ADR 0014) and raises this same
                # error on the next read. The position is still at the failed chunk.
                # Nothing is converted here, only delayed by one read.
                if whole or not parts:
                    raise
                self._pending = exc
                break
            parts.append(part)
            want -= len(part)
            if cut and not whole:
                # A short read is the end (ADR 0014): the bytes before the cut go to
                # the caller now, and the next read, which gets none, raises. A read
                # with no size goes on to that raise and returns nothing, as a
                # plain member's does.
                break
        return b"".join(parts)

    def _read_some(self, want: int) -> tuple[bytes, bool]:
        """Up to ``want`` bytes from one chunk or one hole, advancing the position,
        and whether the stored data ended inside the chunk."""
        i = self._chunk_index
        if i == len(self._starts):
            return self._read_hole(want, self._size), False
        start = self._starts[i]
        if self._pos < start:
            return self._read_hole(want, start), False
        end = self._ends[i]
        pos = self._pos
        assert pos < end, "chunk index points past the chunk"
        count = min(want, end - pos)
        data = self._read_stored(self._stored[i] + pos - start, count)
        self._pos = pos + len(data)
        if self._pos == end:
            self._chunk_index = i + 1
        return data, len(data) < count

    def _read_hole(self, want: int, boundary: int) -> bytes:
        count = min(want, boundary - self._pos)
        self._pos += count
        # Built whole: ``read`` already bounds ``want``, and a read that is one hole
        # returns this object without a join copying it.
        return bytes(count)

    def _read_stored(self, at: int, count: int) -> bytes:
        inner = self._inner
        if at != self._inner_pos:
            if self._seekable:
                inner.seek(self._base + at)
                self._inner_pos = at
            else:
                # Chunks are in logical order, so a forward-only inner only ever skips
                # forward: the reader moved past a chunk's start by a seek. Counted as
                # it goes, so a skip that raises leaves the position true.
                skip_forward(inner, at - self._inner_pos, on_chunk=self._advance_inner)
        # A full-count inner (ADR 0014): a short read is its end, and the caller gets
        # the bytes before it. An inner that returns nothing at its end, rather than
        # raising its own error, gets this one.
        data = inner.read(count)
        self._inner_pos += len(data)
        if not data:
            raise EOFError(
                f"the stored sparse data ended: none of the {count} bytes read "
                "from a chunk are there"
            )
        return data

    def _advance_inner(self, count: int) -> None:
        self._inner_pos += count
