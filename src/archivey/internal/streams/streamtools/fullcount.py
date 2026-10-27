"""``FullCountStream`` — full-count reads over a stream that may return short, unbuffered."""

from __future__ import annotations

from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import read_blocking, read_exact


class FullCountStream(DelegatingStream):
    """``inner``, with ``read(n)`` returning ``n`` bytes unless the stream ends.

    For an inner whose short read is not its end, as ``io.RawIOBase`` allows: a short
    return is followed by more reads for the bytes still missing (:func:`read_exact`).
    Unlike ``io.BufferedReader`` it reads nothing ahead, so each ``read(n)`` takes
    exactly ``n`` bytes from ``inner`` and copies only when a read was short.

    Owns ``inner``, as every :class:`DelegatingStream` does; ``seek`` and ``tell``
    forward to it.
    """

    # ``readinto`` goes through ``read``, which is where the re-asking happens.
    readinto_passthrough = False

    def read(self, n: int = -1, /) -> bytes:
        if n is None or n < 0:
            return read_blocking(self._inner)
        return read_exact(self._inner, n)
