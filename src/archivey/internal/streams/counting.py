"""Pass-through stream wrappers that count bytes or seeks.

Used for:

- *Compressed input pressure* (:class:`CountingReader`) — how many compressed bytes a
  decompressor has pulled from a source whose total size is not knowable (live
  decompression-ratio guard in ``safe-extraction``).
- *Decompressed output volume* (:class:`OutputCountingStream`) — bytes leaving a
  decode stage, for the benchmark solid-block invariant.
- *Source seek storms* (:class:`SeekCountingStream`) — ``seek`` calls on the
  archive-facing handle, for the benchmark seek axis.
- *A shared budget* (:class:`BudgetDrawStream`) — bytes leaving a decode stage, drawn
  from an :class:`~archivey.Budget` several readers share. Installed only when the
  reader's config holds one.

Measurement wrappers share a :class:`~archivey.internal.measurement.ByteCounter` /
:class:`~archivey.internal.measurement.SeekCounter` so multiple layers can feed one
archive-level total. They are installed only when measurement is enabled.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO, cast

from archivey.internal.overrides import override
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    read_blocking,
    readinto_via_read,
    try_readinto,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

    from archivey.config import Budget
    from archivey.internal.measurement import ByteCounter, SeekCounter
    from archivey.internal.streams.streamtools.readahead import _ReadsAhead


class CountingReader(DelegatingStream):
    """Wrap ``inner`` and count the total number of bytes returned by reads.

    Both read paths keep the count current: ``read`` counts what it returns and ``readinto``
    counts what it fills, so the zero-copy ``readinto`` fast path stays fast (no intermediate
    ``bytes`` object) instead of being routed through ``read``. The count reflects bytes
    *pulled from the source*; with a decompressor reading fixed-size chunks it overshoots the
    strictly-decoded amount by at most one read, which is negligible against the output of a
    real decompression bomb.

    It sets no ``forwards_verification``: it wraps a compressed archive input, and a raw
    source has no check of its own to forward.
    """

    def __init__(self, inner: BinaryIO) -> None:
        super().__init__(inner)
        self._bytes_read = 0

    @property
    def bytes_read(self) -> int:
        return self._bytes_read

    @override
    def read(self, n: int = -1, /) -> bytes:
        data = read_blocking(self._inner, n)
        self._bytes_read += len(data)
        return data

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        n = try_readinto(self._inner, b)
        if n is None:
            # No usable inner readinto (missing, or advertised and refused): fill from
            # self.read(), which already counts, so nothing is added here. Calling it
            # directly rather than through super() keeps the inner from being probed a
            # second time.
            return readinto_via_read(self, b)
        self._bytes_read += n
        return n


class OutputCountingStream(DelegatingStream):
    """Wrap a decoded (or stored) stream and add every delivered byte to ``counter``.

    Used for the benchmark ``bytes_decompressed`` axis. Unlike :class:`CountingReader`,
    this feeds a shared :class:`~archivey.internal.measurement.ByteCounter` so folder-level
    and member-level wrappers can share one archive total when needed.
    """

    # Counts bytes and changes none of them: the verification level looks through.
    forwards_verification = True

    def __init__(self, inner: BinaryIO, counter: ByteCounter) -> None:
        super().__init__(inner)
        self._counter = counter

    @override
    def read(self, n: int = -1, /) -> bytes:
        data = read_blocking(self._inner, n)
        self._counter.add(len(data))
        return data

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        n = try_readinto(self._inner, b)
        if n is None:
            # Same fallback as CountingReader: self.read() already counts.
            return readinto_via_read(self, b)
        self._counter.add(n)
        return n

    def nearest_resume_offset(self, target: int) -> int | None:
        # Measurement wrapper around decoded output; preserve the inner's offset space.
        return ask_resume_offset(self._inner, target)


class SeekCountingStream(DelegatingStream):
    """Wrap a source stream and count every ``seek`` call on ``counter``.

    ``read`` / ``readinto`` are pass-through (no byte counting). Installed only when
    measurement is on so the non-measure path pays nothing.

    ``peel_for_source_size`` is True: this wrapper sits on archive-facing handles
    and does not change their cheap size, so ``source_byte_size`` looks through it
    the same way with measurement on or off. Do not copy this onto
    :class:`OutputCountingStream` — that one sits on decompressors.
    """

    peel_for_source_size = True

    def __init__(self, inner: BinaryIO, counter: SeekCounter) -> None:
        super().__init__(inner)
        self._counter = counter

    @override
    def seek(self, offset: int, whence: int = 0, /) -> int:
        self._counter.record()
        return self._inner.seek(offset, whence)


# The largest read a budgeted read-to-the-end asks of the decoder at once, so a
# decoder that sizes a buffer by the count it is asked for is never asked for the
# whole room of a large budget.
_BUDGET_STEP = 1 << 24


class BudgetDrawStream(DelegatingStream):
    """Wrap a decoded (or stored) stream and draw every delivered byte from a shared
    :class:`~archivey.Budget`, as :class:`OutputCountingStream` counts them.

    A read that could cross the limit asks the decoder for at most one byte past
    what is left, so the read that crosses it decodes one byte more than the budget
    allows, not the rest of the member; ``read_ahead`` is capped the same way. That
    holds per read: readers on other threads size their reads against the same room,
    so each can overshoot by one read. A forward seek past the furthest offset the
    stream has reached draws the gap: a decoder serves it by decoding the bytes it
    skips. A seek the budget cannot cover is refused before the decoder moves, and
    draws nothing; a seek to an end the stream cannot size reads to it, drawn as a
    read is.
    """

    # Changes no bytes and no positions: verification and resume offsets are the
    # inner's, as for ``OutputCountingStream``.
    forwards_verification = True

    def __init__(self, inner: BinaryIO, budget: Budget) -> None:
        super().__init__(inner)
        self._budget = budget
        self._pos = 0
        self._reach = 0  # the furthest offset reached, by a read or a seek

    def _advance(self, n: int) -> None:
        self._pos += n
        self._reach = max(self._reach, self._pos)

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        budget = self._budget
        budget._check_bytes_left()
        room = budget._bytes_room()
        if n is None:
            n = -1
        if room is None or 0 <= n <= room:
            data = read_blocking(self._inner, n)
            self._advance(len(data))
            budget._draw_bytes(len(data))
            return data
        if n >= 0:
            # Full count: a short return is the end, as from the decoder itself.
            data = read_blocking(self._inner, room + 1)
            self._advance(len(data))
            budget._draw_bytes(len(data))  # raises if it took the last byte and one
            return data
        parts: list[bytes] = []
        while True:
            room = budget._bytes_room()
            step = _BUDGET_STEP if room is None else min(_BUDGET_STEP, room + 1)
            # A decoder's error raises here and drops what earlier steps returned,
            # as one ``read()`` of the whole member would have raised.
            data = read_blocking(self._inner, step)
            if not data:
                return b"".join(parts)
            self._advance(len(data))
            budget._draw_bytes(len(data))
            parts.append(data)

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        return readinto_via_read(self, b)

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        budget = self._budget
        room = budget._bytes_room()
        if whence == io.SEEK_SET:
            target: int | None = offset
        elif whence == io.SEEK_CUR:
            target = self._pos + offset
        else:
            size = self.try_get_size()
            target = None if size is None else size + offset
            if target is None and room is not None:
                # The end is not known without decoding to it: read there from the
                # furthest offset reached, each step drawn, so the budget stops the
                # decode where it runs out, as it does a read.
                self._inner.seek(self._reach)
                self._pos = self._reach
                while self.read(_BUDGET_STEP):
                    pass
        if target is not None and room is not None and target - self._reach > room:
            # Refused before the decoder decodes the gap. Nothing was decoded, so
            # nothing is drawn: the room stays for other reads.
            budget._refuse_bytes(target - self._reach)
        self._pos = self._inner.seek(offset, whence)
        if self._pos > self._reach:
            gap = self._pos - self._reach
            self._reach = self._pos
            budget._draw_bytes(gap)
        return self._pos

    def read_ahead(self, need: int, n: int, /) -> bytes:
        """The decoder's ``read_ahead``, drawn and capped like a read: at most one
        byte past the room, even when ``need`` is more, so that byte's draw raises
        rather than the decoder filling the whole ``need``."""
        cap = self._budget._read_cap(n)
        data = cast("_ReadsAhead", self._inner).read_ahead(min(need, cap), cap)
        self._advance(len(data))
        self._budget._draw_bytes(len(data))
        return data

    def try_get_size(self) -> int | None:
        """The inner stream's cheap size, as ``ArchiveStreamImpl.size`` asks it."""
        inner = self._inner
        try_get_size = getattr(inner, "try_get_size", None)
        if callable(try_get_size):
            result = try_get_size()
            return result if isinstance(result, int) else None
        size = getattr(inner, "size", None)
        return size if isinstance(size, int) and not isinstance(size, bool) else None

    def nearest_resume_offset(self, target: int) -> int | None:
        return ask_resume_offset(self._inner, target)
