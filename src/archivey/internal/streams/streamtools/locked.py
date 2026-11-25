"""Lock-wrapping stream for library-owned shared handles.

:class:`LockedStream` holds ``lock`` across **every** read/seek/tell on ``inner``
(a reader whose members share one handle under ``MemberStreams.CONCURRENT``:
seek-then-read must be atomic). Archivey
buffering/error wrappers sit *outside* this layer.

For independent logical positions over one file, prefer
:class:`~archivey.internal.streams.streamtools.shared.SharedSource` instead of
``LockedStream`` (ZIP-style re-seek-under-lock views).
"""

from __future__ import annotations

import contextlib
import io
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, BinaryIO

from archivey.internal.overrides import override
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    readinto_via_read,
    try_readinto,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer


class HandleLock:
    """A reader's shared-handle lock: a non-reentrant lock that knows its holder.

    A close that comes while this thread holds the lock (the collector freeing a
    dropped stream inside a call that reads through the handle, where every layer of
    that stream is finalized on its own) cannot wait for it. :meth:`defer` keeps
    such a close, and the release that frees the lock runs it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner: int | None = None
        self._deferred: list[Callable[[], None]] = []

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        acquired = self._lock.acquire(blocking, timeout)
        if acquired:
            self._owner = threading.get_ident()
        return acquired

    def release(self) -> None:
        # The holder's batch, taken while it still holds the lock: a thread that
        # takes the lock after this release starts its own list. Nothing deferred
        # (every plain read) keeps no reference to the list, which the next holder
        # may fill, and allocates none.
        batch: list[Callable[[], None]] | tuple[()] = self._deferred
        if batch:
            self._deferred = []
        else:
            batch = ()
        self._owner = None
        self._lock.release()
        for close in batch:
            # Outside the lock: each close takes it again. A collector's close: a
            # failure belongs to no call the caller made.
            with contextlib.suppress(Exception):
                close()

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def held_by_current_thread(self) -> bool:
        return self._owner == threading.get_ident()

    def defer(self, close: Callable[[], None]) -> None:
        """Keep ``close`` for the release of the lock this thread holds."""
        self._deferred.append(close)


class LockedStream(DelegatingStream):
    """Hold ``lock`` across each shared-handle operation on ``inner``.

    Used by TAR/ISO under ``MemberStreams.CONCURRENT`` so library seek-then-read
    sequences on a shared fileobj cannot interleave. Archivey buffering/error wrappers
    sit *outside* this layer.
    """

    def __init__(
        self, inner: BinaryIO, lock: HandleLock | threading.Lock | threading.RLock
    ) -> None:
        super().__init__(inner)
        self._lock = lock

    @override
    def read(self, n: int = -1, /) -> bytes:
        with self._lock:
            return self._inner.read(n)

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        # Stay under the lock for both the native and fallback path.
        # super().readinto() would call self.read() on fallback, and
        # LockedStream.read re-acquires this (non-reentrant) lock.
        with self._lock:
            n = try_readinto(self._inner, b)
            if n is not None:
                return n
            return readinto_via_read(self._inner, b)

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if not self.seekable():
            raise io.UnsupportedOperation("seek")
        with self._lock:
            return self._inner.seek(offset, whence)

    @override
    def tell(self, /) -> int:
        with self._lock:
            return self._inner.tell()

    @override
    def close(self) -> None:
        if self.closed:
            return
        lock = self._lock
        if isinstance(lock, HandleLock) and lock.held_by_current_thread():
            # Only the collector closes a stream here (a caller's close inside a
            # call of the reader is refused before it reaches this layer): it runs
            # once this thread lets the lock go.
            lock.defer(self.close)
            return
        with lock:
            super().close()
