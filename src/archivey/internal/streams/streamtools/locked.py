"""Lock-wrapping stream for library-owned shared handles.

:class:`LockedStream` holds ``lock`` across **every** read/seek/tell on ``inner``
(TAR/ISO under ``MemberStreams.CONCURRENT``: seek-then-read must be atomic). Archivey
buffering/error wrappers sit *outside* this layer.

For independent logical positions over one file, prefer
:class:`~archivey.internal.streams.streamtools.shared.SharedSource` instead of
``LockedStream`` (ZIP-style re-seek-under-lock views).
"""

from __future__ import annotations

import io
import threading
from typing import TYPE_CHECKING, BinaryIO

from archivey.internal.overrides import override
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    readinto_via_read,
    try_readinto,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer


class LockedStream(DelegatingStream):
    """Hold ``lock`` across each shared-handle operation on ``inner``.

    Used by TAR/ISO under ``MemberStreams.CONCURRENT`` so library seek-then-read
    sequences on a shared fileobj cannot interleave. Archivey buffering/error wrappers
    sit *outside* this layer.
    """

    def __init__(self, inner: BinaryIO, lock: threading.Lock | threading.RLock) -> None:
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
        with self._lock:
            super().close()
