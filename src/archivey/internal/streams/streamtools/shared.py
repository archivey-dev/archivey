"""``SharedSource`` — concurrent-safe byte-range views over one underlying source.

A source (an OS file handle or a seekable ``BinaryIO``) has exactly one file position.
Two consumers that each ``seek``+``read`` the same handle will clobber each other's
offset — even on a single thread. :class:`SharedSource` mints independent, seekable,
**non-owning** views over ``[start, start+length)``; each view keeps its own ``_pos``,
and a read seeks the underlying to that absolute position under a shared lock when
the handle is not already there, so the seek+read pair stays atomic.

Views are :class:`~archivey.internal.streams.streamtools.slice.SharedView` instances
(a :class:`~archivey.internal.streams.streamtools.slice.SlicingStream` subclass) with
the source lock engaged — the same bound/tell logic, plus a locked seek when the
handle is not already at the view's offset.

This is the streamtools analogue of stdlib ``zipfile._SharedFile``. It is deliberately
archivey-dependency-free: it raises stdlib-shaped errors (``ValueError`` / ``OSError`` /
``io.UnsupportedOperation``), never ``archivey.exceptions``.

**Views are unbuffered.** A ``read`` is one locked read of the shared handle, and a
seek when the handle is elsewhere — cheap (an in-memory offset move on a regular
file / ``BytesIO``), and the current consumers (codec streams, which buffer
internally) already read in large chunks. A consumer that issues many tiny reads
should wrap its view in a buffer itself; buffering inside the primitive would
double-copy for everyone else. Over a view of a decoder that defers its error,
that buffer is :class:`~archivey.internal.streams.streamtools.readahead.ReadAheadStream`,
not ``io.BufferedReader``, which asks again after a short fill and so drops the prefix.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import BinaryIO, Self

from archivey.exceptions import TruncatedError
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    ask_resume_offset,
    check_read_size,
    is_seekable,
    read_blocking,
    read_exact,
    source_byte_size,
)
from archivey.internal.streams.streamtools.slice import (
    SharedView,
    _already_at,
    _clamp_slice_length,
)


class SharedSource:
    """Factory for locked, per-view-position slices over one seekable source.

    Construct from an already-open seekable ``BinaryIO``. The factory never takes
    ownership of it: closing the factory stops new views and closes nothing, and whoever
    handed the source in closes it. That is one rule for every caller rather than one
    per source shape; a reader hands in its archive source, which knows what it opened.

    ``wrap_handle`` (optional) is applied once to the underlying file handle it was
    handed. Production readers use it to install a seek counter when measurement is
    enabled, and identity otherwise.
    """

    def __init__(
        self,
        source: BinaryIO,
        *,
        wrap_handle: Callable[[BinaryIO], BinaryIO] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._closed = False

        if not is_seekable(source):
            raise ValueError("SharedSource requires a seekable BinaryIO source")
        self._handle: BinaryIO = source
        # Frozen at construction: the source is assumed not to grow.
        self._size: int | None = source_byte_size(source)

        if wrap_handle is not None:
            self._handle = wrap_handle(self._handle)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def size(self) -> int | None:
        """Cheap total byte size of the source, when knowable."""
        return self._size

    def view(self, start: int, length: int | None = None) -> SharedView:
        """Mint a non-owning seekable view over ``[start, start+length)``.

        ``length is None`` means "to the end of the source". When ``_size`` is
        already known, over-long ``length`` is clamped here (and an omitted one
        frozen to the remaining bytes) so a ``wrap_handle`` that hid cheap size
        from ``source_byte_size`` still yields a short view. That pre-clamp is
        kept so ``view()`` without a length stays a bounded drain, matching main
        (the constructor could leave ``length`` untouched once ``source_size`` is
        a separate argument; that would be a behaviour change on every SharedSource
        view). The constructed :class:`SharedView` is told ``source_size`` so it
        does not re-probe the handle. Past-EOF (``start >= size``) is the empty-view
        case of the same clamp. Negative ``start``/``length`` remain hard errors.
        """
        self._raise_if_closed()
        if start < 0:
            raise ValueError(f"view start must be non-negative, got {start}")
        if length is not None and length < 0:
            raise ValueError(f"view length must be non-negative, got {length}")

        length = _clamp_slice_length(start, length, self._size)

        return SharedView(
            self._handle,
            start=start,
            length=length,
            lock=self._lock,
            check_open=self._raise_if_closed,
            source_size=self._size,
            probe_source_size=False,
        )

    def read_at(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes from ``offset``; fewer only at the end of the source.

        One locked seek and read of the shared handle, with no view built: for a
        parser's many small reads at offsets, where a view per read costs several
        times the read. The seek is skipped when the handle is already there, as a
        view's is.
        """
        self._raise_if_closed()
        if offset < 0 or n < 0:
            raise ValueError(f"offset {offset} or length {n} is negative")
        if self._size is not None:
            n = max(0, min(n, self._size - offset))
        if n == 0:
            return b""
        with self._lock:
            self._raise_if_closed()
            if not _already_at(self._handle, offset):
                self._handle.seek(offset)
            return read_exact(self._handle, n)

    def close(self) -> None:
        """Mark closed; the source it was built over stays open, as its owner's."""
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed file.")


class MemberDataView(DelegatingStream):
    """A random-access member's data area that raises at a cut, not a clean end.

    The view under it returns ``b""`` where the archive ends, which reads as the end of
    the member. Here a read that ends before ``length`` keeps the full-count rule (ADR
    0014): a sized read returns the bytes before the cut and the next read raises, and a
    read with no size raises and returns nothing. The source size is not needed.
    ``what`` names the archive in the error ("TAR archive").
    """

    readinto_passthrough = False

    def __init__(
        self, view: SharedView, data_offset: int, length: int, *, what: str
    ) -> None:
        super().__init__(view)
        self._data_offset = data_offset
        self._length = length
        self._what = what

    def read(self, n: int | None = -1, /) -> bytes:
        n = check_read_size(n)
        position = self._inner.tell()
        whole = n < 0
        want = self._length - position if whole else min(n, self._length - position)
        if want <= 0:
            return b""
        data = read_blocking(self._inner, want)
        if len(data) < want and (whole or not data):
            raise TruncatedError(
                f"{self._what} is truncated inside a member's data at offset "
                f"{self._data_offset + position + len(data)}"
            )
        return data

    def nearest_resume_offset(self, target: int) -> int | None:
        # The member's offsets are the view's.
        return ask_resume_offset(self._inner, target)
