"""A random-access pass's member data, read through the member walk until it moves on.

A random-access pass of a backend whose listing is a scan of the data (TAR, a sequential
format) reads each member's data through the walk's own stream. On a solid archive (a
compressed one) that is where it pays: the archive is decoded once, not twice. When
the walk moves on before the pass has read the member to its end, the stream reads a
view of its own from where it stopped instead (``BaseArchiveReader._walk_handoff_locked``).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.streams.decompressor_stream import _COMPRESSED_READ_SIZE_MAX
from archivey.internal.streams.streamtools import (
    DelegatingStream,
    ReadOnlyIOStream,
    SharedView,
    check_read_size,
)
from archivey.internal.streams.streamtools.binaryio import (
    ask_resume_offset,
    read_blocking,
)

# The most a member data read asks of the stream under it at once. The size a read
# wants comes from a header, which may claim far more than the archive holds, and a
# read of ``n`` bytes from a file or a buffered stream allocates ``n`` up front. It
# matches the piece the member verifier's sized drain reads (``verify._SIZED_DRAIN_CHUNK``),
# so one such piece is one read here.
MEMBER_READ_STEP = _COMPRESSED_READ_SIZE_MAX


def read_stepped(read: Callable[[int], bytes], want: int) -> bytes:
    """Up to ``want`` bytes from the full-count ``read``, fewer only at its end, asked
    for at most :data:`MEMBER_READ_STEP` at a time."""
    if want <= MEMBER_READ_STEP:
        return read(want)
    chunks = []
    while want:
        chunk = read(min(want, MEMBER_READ_STEP))
        if not chunk:
            break
        chunks.append(chunk)
        want -= len(chunk)
    return b"".join(chunks)


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


class MemberDataView(DelegatingStream):
    """A random-access member's data area that raises at a cut, not a clean end.

    TAR's own opens use it, and so does a handoff's view once the walk has moved on
    (TAR's and the sequential adapter's ``reopen``).

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
        inner = self._inner
        data = read_stepped(lambda size: read_blocking(inner, size), want)
        if len(data) < want and (whole or not data):
            raise TruncatedError(
                f"{self._what} is truncated inside a member's data at offset "
                f"{self._data_offset + position + len(data)}"
            )
        return data

    def nearest_resume_offset(self, target: int) -> int | None:
        # The member's offsets are the view's.
        return ask_resume_offset(self._inner, target)
