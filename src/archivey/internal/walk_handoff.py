"""A random-access pass's member data, read through the member walk until it moves on.

A pass over a solid archive (a compressed TAR, a compressed sequential format) reads
each member's data through the walk's own stream, so the archive is decoded once. When
the walk moves on before the pass has read the member to its end, the stream reads a
view of its own from where it stopped instead (``BaseArchiveReader._walk_handoff``).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import BinaryIO

from archivey.internal.streams.streamtools import ReadOnlyIOStream


class WalkHandoffStream(ReadOnlyIOStream):
    """A pass's member data, read through the walk until the walk moves on.

    The walk's next pull calls :meth:`detach` under the walk lock
    (``BaseArchiveReader._before_pull_locked``). From then on the stream reads
    ``reopen(position)``, a view of its own from where it stopped (on a codec stream, a
    decoder seek back), so the walk can move on for another caller while the pass is
    still reading this member. A stream detached after its last read builds no view.
    """

    def __init__(
        self,
        data: BinaryIO,
        reopen: Callable[[int], BinaryIO],
        walk_lock: threading.RLock,
    ) -> None:
        # Assigned before the base __init__: close() reads them.
        self._data = data
        self._view: BinaryIO | None = None
        self._reopen = reopen
        self._walk_lock = walk_lock
        self._detached_at: int | None = None
        self._pos = 0
        super().__init__()

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._pos

    def detach(self) -> None:
        """Stop reading through the walk. Called under the walk lock."""
        if self._detached_at is None and not self.closed:
            self._detached_at = self._pos

    def read(self, n: int | None = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed member stream")
        if n is None:
            n = -1
        if self._detached_at is None:
            with self._walk_lock:
                if self._detached_at is None:
                    data = self._data.read(n)
                    # Under the lock: a pull on another thread detaches at this
                    # position, so it must already count the bytes returned here.
                    self._pos += len(data)
                    return data
        if self._view is None:
            self._view = self._reopen(self._detached_at or 0)
        data = self._view.read(n)
        self._pos += len(data)
        return data

    def close(self) -> None:
        if self._view is not None:
            self._view.close()
        self._data.close()
        super().close()
