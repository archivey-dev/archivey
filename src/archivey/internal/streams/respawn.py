"""``RespawnStream``: a seekable view over a member stream that reads forward only.

A forward seek reads and drops the bytes it skips; a backward seek closes the inner
stream and opens a fresh one from the start. The RAR backend uses it over an ``unrar``
or ``unar`` pipe, and the plugin adapter over a plugin's member stream that cannot
seek.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    resolve_seek,
    skip_forward,
)

__all__ = ["RespawnStream"]

_SKIP_CHUNK = 1 << 16


class RespawnStream(ReadOnlyIOStream):
    """Seekable view of a member stream that can only be read forward.

    Used for a one-member decompressor pipe (``unrar p`` or ``unar``) and for a
    plugin's member stream that cannot seek. A backward seek cannot reposition the
    inner stream. Close it and ``spawn`` a fresh one on the next ``read()`` that
    needs bytes; skip to the logical offset then. Forward seeks do not read the
    inner stream until a later ``read()`` needs those bytes. Past-end seeks leave
    the inner stream where it is: a read with ``pos > size`` is empty, and a read at
    ``pos == size`` still reaches the inner stream so fused verify's one-byte
    overrun probe can see trailing output — that boundary read is clamped to one
    byte.

    ``_pos`` is the logical offset. ``_inner_pos`` is the inner stream's progress
    clamped to ``_size``: the overrun probe's extra byte advances ``_pos`` but not
    ``_inner_pos``, so a no-op ``SEEK_CUR`` after it does not count as a backward
    seek and force a respawn, which for RAR means killing and restarting the
    process. Re-probing after seeking back to ``_size`` is then not byte-exact;
    that path is unreachable while the first probe raises ``CorruptionError`` on
    any trailing byte (``verify.py`` ``_conclude``). Respawn is keyed on the inner
    stream's progress, so ``seek(0, SEEK_END); seek(0)`` before any read costs
    nothing.

    ``spawn`` must return a stream that owns what it opened, so close/respawn
    releases it: for RAR, the process (``_UnrarOwnedStream``,
    ``_bounded_member_pipe`` wrapping one, or a ``UnarOutputStream``); for a
    plugin, the stream its ``open_member`` returned.

    ``what`` names the producer in the ``TruncatedError`` raised when it ends before
    ``size`` (``"unrar output"``).

    ``size=None`` is a member whose length is not known up front (a plugin member
    listed with no size). The stream learns it when the inner stream first ends: on a
    read or forward seek that reaches the end, or on a ``SEEK_END``, which reads
    through to the end to find it. Until then a read is not clamped, and an early end
    cannot be told from the real one. Once learned, it behaves as a known ``size``:
    a later spawn that ends sooner raises ``TruncatedError``.

    Same restart-on-rewind shape as ``DecompressorStream`` /
    ``Decoder.recreate`` with a one-point index at origin. It does not use
    that engine: ``Decoder`` is a push interface fed compressed bytes, while
    this stream pulls plaintext from a producer it cannot feed. ``AesDecryptStream``
    is a different shape — O(1) CBC restart, no replay — and does not count
    toward extracting a shared restart-and-replay base.
    """

    def __init__(
        self,
        spawn: Callable[[], BinaryIO],
        inner: BinaryIO,
        *,
        size: int | None,
        what: str,
    ) -> None:
        super().__init__()
        self._what = what
        self._spawn = spawn
        self._inner: BinaryIO | None = inner
        self._size = size
        self._pos = 0
        self._inner_pos = 0

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._pos

    def _close_inner(self) -> None:
        inner = self._inner
        self._inner = None
        # A replacement process always starts at byte 0. Reset even if close
        # raises, so a later read cannot label those bytes with the old offset.
        self._inner_pos = 0
        if inner is not None:
            inner.close()

    def _ensure(self) -> BinaryIO:
        if self._inner is None:
            self._inner = self._spawn()
        return self._inner

    def _inner_needed(self, logical: int) -> int:
        return logical if self._size is None else min(logical, self._size)

    def _advance(self, count: int) -> None:
        self._inner_pos += count

    def _end(self) -> int:
        """The member's length; with no size known yet, read through to the end."""
        if self._size is None:
            inner = self._ensure()
            while chunk := inner.read(_SKIP_CHUNK):
                self._inner_pos += len(chunk)
            self._size = self._inner_pos
        return self._size

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        target = resolve_seek(offset, whence, pos=self._pos, end=self._end)
        needed = self._inner_needed(target)
        if needed < self._inner_pos:
            # Close first; set the logical cursor only if close succeeds, so a
            # failed seek leaves tell() unchanged (Python IO). Spawn is lazy —
            # _sync_inner calls _ensure on the next read. Spawning here would
            # start a process that close-without-read would kill.
            self._close_inner()
        self._pos = target
        return self._pos

    def nearest_resume_offset(self, target: int) -> int:
        """Where the output restarts to reach ``target``: the live inner stream's
        position when ``target`` is at or past it, else 0 (a fresh spawn). A member's verifier asks
        this to see that reaching a forward target decodes the skipped bytes anyway."""
        if self._inner is not None and self._inner_needed(target) >= self._inner_pos:
            return self._inner_pos
        return 0

    def _sync_inner(self) -> BinaryIO:
        inner = self._ensure()
        want = self._inner_needed(self._pos)
        if want > self._inner_pos:
            try:
                skip_forward(inner, want - self._inner_pos, on_chunk=self._advance)
            except EOFError as exc:
                if self._size is None:
                    # A forward seek past the end of a member of unknown length:
                    # the end is found, and the read there returns nothing.
                    self._size = self._inner_pos
                    return inner
                raise TruncatedError(
                    f"{self._what} ended after {self._inner_pos} of {self._size} bytes"
                ) from exc
            self._inner_pos = want
        return inner

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._size is not None and self._pos > self._size:
            return b""
        inner = self._sync_inner()
        if self._size is None:
            data = inner.read(n)
            self._pos += len(data)
            self._inner_pos += len(data)
            # An empty read, or a read of everything, has reached the end.
            if n < 0 or (not data and n != 0):
                self._size = self._inner_pos
            return data
        if self._pos > self._size:  # the forward seek above found the end
            return b""
        if self._pos < self._size:
            remaining = self._size - self._pos
            if n < 0 or n > remaining:
                n = remaining
        else:
            # At declared size the overrun probe must reach the inner stream, but only
            # for one byte — read(-1) here would pull the rest of a corrupt
            # member into memory.
            n = 1 if n < 0 else min(n, 1)
        data = inner.read(n)
        self._pos += len(data)
        # Overrun probe at pos == size can return one extra byte. Count it in
        # _pos (so pos > size reads are empty) but not as inner progress past
        # _size, or the next seek including SEEK_CUR would respawn.
        self._inner_pos = min(self._inner_pos + len(data), self._size)
        return data

    def close(self) -> None:
        if self.closed:
            return
        close_error: BaseException | None = None
        try:
            self._close_inner()
        except BaseException as exc:  # noqa: BLE001 - mark closed even if inner.close fails
            close_error = exc
        super().close()
        if close_error is not None:
            raise close_error
