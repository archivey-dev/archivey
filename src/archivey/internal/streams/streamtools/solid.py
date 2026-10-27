"""Demultiplex one forward-only decoded stream into consecutive member sub-streams.

A *solid block* — a 7z folder, or a RAR ``unrar p`` pipe — decodes to a single
forward-only (often non-seekable) byte stream whose members occupy consecutive,
known-size ranges. :class:`SolidBlockReader` owns that stream and hands out one member
sub-stream at a time, skipping forward **lazily**: the gap before a member is consumed
only when the *next* member is opened, so closing a never-advanced member costs nothing.
Closing the reader closes the block without draining.

Not the same as :class:`~archivey.internal.streams.streamtools.shared.SharedSource`
(independent seekable views) or :class:`~archivey.internal.streams.streamtools.locked.LockedStream`
(lock around seek+read on one handle). This class is deliberately forward-only.

``open_member(..., lazy=True)`` defers open/skip until the first read — so an
iterator that yields then closes an unselected member pays nothing.

A block that ends early is reported in two ways. A block that ends before a member's
start makes the skip to that member (:func:`skip_forward`, on ``open_member`` or a lazy
slice's first read) raise a plain :class:`EOFError` for the caller to translate. A block
that ends inside a member raises nothing: the member's ``read`` returns the bytes that
are there and then ``b""``. The caller must compare the bytes read with the member's
size (the ``ArchiveStream`` verifier does this when it has an ``expected_size``).

The closed / superseded / same-offset guards on :class:`_MemberSlice` are
defence-in-depth for this primitive's own contract. Current backends serialize
member access via ``_drive_pass_streams(close_previous=True)``, so no public
``open_archive`` path holds two live slices at once.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO, Self

from archivey.internal.streams.streamtools.base import ReadOnlyIOStream

_SKIP_CHUNK = 1 << 20  # 1 MiB


def skip_forward(
    stream: BinaryIO,
    count: int,
    *,
    on_chunk: Callable[[int], None] | None = None,
) -> None:
    """Read and discard exactly ``count`` bytes from a forward-only ``stream``.

    ``on_chunk`` is called with the length of each chunk as soon as it is read, so a
    caller tracking the stream position stays correct when a later ``read`` raises
    partway through the skip (a 7z folder decode error, a dying ``unrar`` pipe).

    Raises :class:`EOFError` if the stream ends before ``count`` bytes are consumed.
    """
    remaining = count
    while remaining > 0:
        chunk = stream.read(min(remaining, _SKIP_CHUNK))
        if not chunk:
            raise EOFError("stream ended before the requested position")
        remaining -= len(chunk)
        if on_chunk is not None:
            on_chunk(len(chunk))


class _MemberSlice(ReadOnlyIOStream):
    """One member's forward-only view over its owning reader's block stream.

    Non-owning: closing a member slice never closes the shared block — the
    :class:`SolidBlockReader` owns that. Reads are bounded to the member's declared size
    and flow through the reader so it always knows the block's position.

    When constructed with ``pending=True`` (``open_member(..., lazy=True)``), the
    skip-to-``offset`` runs on first read rather than at construction. Closing a
    slice never advances or drains the block — pending *and* already-positioned
    unread closes are free. The gap before the next member is consumed by the
    next ``open_member`` (or a pending slice's first read).
    """

    def __init__(
        self,
        reader: SolidBlockReader,
        offset: int,
        size: int,
        *,
        pending: bool = False,
    ) -> None:
        super().__init__()
        self._reader = reader
        self._offset = offset
        self._size = size
        self._remaining = size
        self._pending = pending
        self._seq = reader._stamp()

    def _ensure_positioned(self) -> None:
        # Only read() calls this, after its own closed check.
        if not self._pending:
            return
        self._reader._advance_to(self)
        self._pending = False

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        self._ensure_positioned()
        # close() clears _current without marking slices closed. Check that
        # before the superseded test, or eager read() claims a later open_member()
        # that never happened. Lazy already raises here via _ensure_positioned.
        if self._reader._closed:
            raise ValueError("SolidBlockReader is closed")
        if self._reader._current is not self:
            raise ValueError("solid member superseded by a later open_member()")
        if self._remaining <= 0:
            return b""
        if n < 0 or n > self._remaining:
            n = self._remaining
        data = self._reader._consume(n)
        self._remaining -= len(data)
        return data

    @property
    def _stream(self) -> BinaryIO:
        """The decoded block this member is a range of (shared with its other
        members), under the name a slice gives its source: what a check on this
        member's bytes reports back to (``retire_decoder_children``)."""
        return self._reader._block

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._reader._closed:
            raise ValueError("SolidBlockReader is closed")
        if self._pending:
            return 0
        if self._reader._current is not self:
            raise ValueError("solid member superseded by a later open_member()")
        return self._size - self._remaining


class SolidBlockReader:
    """Hand out consecutive member sub-streams over one forward-only decoded block.

    ``open_member(offset, size)`` returns a forward-only stream for the member occupying
    ``[offset, offset + size)`` of the decoded block. Members must be opened in
    non-decreasing ``offset`` order; the reader skips forward from its current position to
    ``offset`` lazily, at open time, so a partially-read (or unread) member costs nothing
    until the next one is requested. Only one member is active at a time.

    Pass ``lazy=True`` to defer that open until the first read on the returned handle.
    ``open_member`` still rejects an ``offset`` behind the current position immediately,
    before any read. Closing a lazy
    handle without reading never skip-decodes. Eager and lazy both return the same
    :class:`_MemberSlice` type — no extra wrapper layer.

    Closed / superseded / same-offset guards on the returned handle are
    defence-in-depth for this primitive. Current backends serialize member access via
    ``_drive_pass_streams(close_previous=True)``, so no public path holds two live
    slices at once.
    """

    def __init__(self, block: BinaryIO, *, close_block: bool = True) -> None:
        self._block = block
        self._close_block = close_block
        self._pos = 0  # bytes consumed from the block so far
        self._current: _MemberSlice | None = None
        self._closed = False
        self._seq = 0

    def _stamp(self) -> int:
        self._seq += 1
        return self._seq

    def _check_can_open_at(self, offset: int) -> None:
        """Raise ``ValueError`` unless a member at ``offset`` can still be opened.

        That needs the reader to be open and ``offset`` not to be behind the bytes
        already consumed: the block is forward-only, so earlier data is gone.
        """
        if self._closed:
            raise ValueError("SolidBlockReader is closed")
        if offset < self._pos:
            raise ValueError(
                f"solid members must be opened in order: offset {offset} < "
                f"position {self._pos}"
            )

    def _advance_to(self, member: _MemberSlice) -> None:
        """Position the block at ``member`` and make it current.

        Shared by eager ``open_member`` and a pending slice's first read.
        ``_pos`` is credited per skipped chunk, so a ``read`` that raises mid-skip
        leaves it matching the bytes already pulled from the block.
        """
        self._check_can_open_at(member._offset)
        current = self._current
        # Offsets alone cannot order two slices at the same offset (a zero-size
        # member sharing its successor's start). A strictly newer claim wins.
        if current is not None and current is not member and current._seq > member._seq:
            raise ValueError("solid member superseded by a later open_member()")
        self._current = None
        skip_forward(self._block, member._offset - self._pos, on_chunk=self._credit)
        self._current = member

    def open_member(self, offset: int, size: int, *, lazy: bool = False) -> BinaryIO:
        if lazy:
            self._check_can_open_at(offset)
            return _MemberSlice(self, offset, size, pending=True)
        slice_ = _MemberSlice(self, offset, size, pending=False)
        self._advance_to(slice_)
        return slice_

    def _credit(self, n: int) -> None:
        self._pos += n

    def _consume(self, n: int) -> bytes:
        data = self._block.read(n)
        self._pos += len(data)
        return data

    def close(self) -> None:
        # No draining: whatever is left in the block is discarded with it.
        if self._closed:
            return
        self._closed = True
        self._current = None
        if self._close_block:
            self._block.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
