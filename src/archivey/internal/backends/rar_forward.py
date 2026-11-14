"""A non-seekable source as the RAR header walk sees it, read front to back.

The walk (``rar_parser``) asks a source for ``tell``, ``read`` and ``seek``. Over a
pipe, :class:`ForwardSource` serves each of them without holding the archive:

- a seek forward reads and drops the bytes in between;
- a seek back lands in the bytes it still holds: the last :data:`KEEP_BYTES` read.
  The walk's seeks back are short: the signature check (8 bytes), the trailing scan
  after the end block (up to 1 MiB, ``trailing_scan``), and a header read again for a
  synthetic archive (:meth:`ForwardSource.read_at`; a RAR5 header is at most 2 MiB);
- a seek to the end is known only once the source has ended there.

Anything else raises ``io.UnsupportedOperation``, so a seek the walk was not expected to
make fails loudly rather than reading the wrong bytes.
"""

from __future__ import annotations

import io
from typing import BinaryIO

#: The bytes before the read position kept for a seek back.
KEEP_BYTES = 4 << 20
_SKIP_CHUNK = 1 << 20


class ForwardSource(io.RawIOBase):
    """``inner``, read once from its current position, which is offset ``start``."""

    def __init__(
        self, inner: BinaryIO, *, start: int = 0, keep: int = KEEP_BYTES
    ) -> None:
        super().__init__()
        self._inner = inner
        self._keep = keep
        # The bytes held run from ``_held_at`` to ``_frontier``: the end of what has
        # been read from ``inner``.
        self._held = bytearray()
        self._held_at = start
        self._frontier = start
        self._pos = start
        # Where ``inner`` ended, once a read found nothing more.
        self._end: int | None = None

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def _pull(self, n: int) -> bytes:
        """Up to ``n`` new bytes from ``inner``, held; ``b""`` at its end."""
        if self._end is not None:
            return b""
        chunk = self._inner.read(n)
        if not chunk:
            self._end = self._frontier
            return b""
        self._held += chunk
        self._frontier += len(chunk)
        self._trim()
        return chunk

    def _trim(self) -> None:
        drop = self._pos - self._keep - self._held_at
        if drop > 0:
            drop = min(drop, len(self._held))
            del self._held[:drop]
            self._held_at += drop

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            parts = []
            while chunk := self.read(_SKIP_CHUNK):
                parts.append(chunk)
            return b"".join(parts)
        if size == 0 or self._pos > self._frontier:
            return b""
        out = bytearray()
        if self._pos < self._frontier:
            at = self._pos - self._held_at
            out += self._held[at : at + size]
        while len(out) < size:
            chunk = self._pull(size - len(out))
            if not chunk:
                break
            out += chunk
        self._pos += len(out)
        self._trim()
        return bytes(out)

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        memoryview(buffer).cast("B")[: len(data)] = data
        return len(data)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            offset += self._pos
        elif whence == io.SEEK_END:
            if self._end is None:
                raise io.UnsupportedOperation(
                    "a forward RAR source knows its end only once it has reached it"
                )
            offset += self._end
        elif whence != io.SEEK_SET:
            raise ValueError(f"invalid whence: {whence}")
        if offset < self._held_at:
            raise io.UnsupportedOperation(
                f"a forward RAR source cannot seek back to {offset}: it holds bytes "
                f"from {self._held_at} on"
            )
        while self._frontier < offset and self._end is None:
            self._pull(min(_SKIP_CHUNK, offset - self._frontier))
            # Keep only what a seek back from ``offset`` can need.
            self._pos = min(offset, self._frontier)
            self._trim()
        self._pos = offset
        self._trim()
        return offset

    def read_at(self, offset: int, size: int) -> bytes:
        """``size`` bytes at ``offset``, which must lie in what is held; the read
        position does not move. Reads forward from ``inner`` when the span runs
        past what has been read."""
        if offset < self._held_at:
            raise io.UnsupportedOperation(
                f"a forward RAR source no longer holds offset {offset}"
            )
        while self._frontier < offset + size and self._end is None:
            if not self._pull(offset + size - self._frontier):
                break
        at = offset - self._held_at
        return bytes(self._held[at : at + size])

    def holds(self, offset: int, size: int) -> bool:
        """Whether the source has the ``size`` bytes at ``offset``, read ahead to
        find out. A span longer than :data:`KEEP_BYTES` counts as held: its read
        finds the cut."""
        if size > self._keep:
            return True
        self.read_at(offset, size)
        return self._frontier >= offset + size


class ForwardSpan:
    """The next ``size`` bytes of a :class:`ForwardSource`, read once in order."""

    def __init__(self, source: ForwardSource, start: int, size: int) -> None:
        self._source = source
        self._next = start
        self._end = start + size
        self.closed = False

    def read(self, n: int = -1) -> bytes:
        left = self._end - self._next
        if left <= 0 or self.closed:
            return b""
        n = left if n < 0 else min(n, left)
        source = self._source
        if source.tell() != self._next:
            source.seek(self._next)
        data = source.read(n)
        self._next += len(data)
        return data

    def close(self) -> None:
        self.closed = True
