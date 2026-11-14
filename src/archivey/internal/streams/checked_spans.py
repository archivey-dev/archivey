"""The decoded ranges of a compressed stream whose every byte passed a block or frame
check, so a reader can raise the members they cover to ``CHECKSUM`` as soon as the
check passes, rather than when a decode from the start reaches the stream's end.

A codec whose decoder hands out only checked bytes (bzip2 one block at a time, bzip3)
says so with ``checks_every_byte``; ``DecompressorStream`` then adds each call's output
to its :class:`CheckedSpans`. A decoder that hands out bytes before their check runs
reports the ranges whose check has passed since instead (``DecodeOut.checked``: xz
blocks), and the stream adds those. A compressed TAR reader asks for the spans added
since it last asked (:meth:`CheckedSpans.take_new`) and raises each listed member whose
data lies inside the spans (``TarReader._refresh_member_levels``).

What a block check proves: every byte of the member came out of a block whose stored CRC
matched it. It does not prove the blocks are in the order the writer put them, or that
none is missing; the stream's whole-stream check (bzip2's combined CRC, xz's index)
proves that, at the end. The ``CHECKSUM`` level says "every byte passed a checksum
stored with the data", which a block CRC is.
"""

from __future__ import annotations

import bisect
import io
import threading
from collections.abc import Callable

from archivey.internal.streams.verification import MAX_WRAPPER_DEPTH

# The most disjoint spans kept: a stream read in many separate places (random access
# over a huge archive) drops the one nearest its start. Dropping a span only loses a
# proof.
MAX_SPANS = 4096


class CheckedSpans:
    """Disjoint, sorted ``[start, end)`` ranges of decoded offsets, merged as they
    grow, and the ranges added since :meth:`take_new` last ran."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._new: list[tuple[int, int]] = []
        self._lock = threading.Lock()

    def add(self, start: int, end: int) -> None:
        """Record that every byte of ``[start, end)`` passed its check."""
        if end <= start:
            return
        with self._lock:
            new = self._new
            if new and new[-1][1] == start:
                new[-1] = (new[-1][0], end)
            else:
                new.append((start, end))
            starts, ends = self._starts, self._ends
            # The spans that touch or overlap [start, end) merge with it.
            lo = bisect.bisect_left(ends, start)
            hi = bisect.bisect_right(starts, end)
            if lo < hi:
                start = min(start, starts[lo])
                end = max(end, ends[hi - 1])
            starts[lo:hi] = [start]
            ends[lo:hi] = [end]
            if len(starts) > MAX_SPANS:
                del starts[0], ends[0]

    def covers(self, start: int, end: int) -> bool:
        """Whether every byte of ``[start, end)`` lies in one checked span."""
        with self._lock:
            i = bisect.bisect_right(self._starts, start) - 1
            return i >= 0 and self._ends[i] >= end

    def take_new(self) -> list[tuple[int, int]]:
        """The ranges added since the last call, merged where they touch."""
        with self._lock:
            new, self._new = self._new, []
        return new


def find_checked_spans(stream: object) -> CheckedSpans | None:
    """The :class:`CheckedSpans` of the decoder stream under ``stream``, following
    ``_inner`` and a ``BufferedReader``'s raw stream; ``None`` when there is none.

    Only for a stack whose layers keep the decoded offsets (the codec stream of a
    compressed TAR): a layer that moved them would make the spans name other bytes.
    """
    for _ in range(MAX_WRAPPER_DEPTH):
        if stream is None:
            return None
        spans = getattr(stream, "checked_spans", None)
        if isinstance(spans, CheckedSpans):
            return spans
        if isinstance(stream, io.BufferedReader):
            stream = stream.raw
        else:
            stream = getattr(stream, "_inner", None)
    return None


# The refresh a reader gives its member streams, to run before they read the member's
# level (``ArchiveStream._level_refresh``).
LevelRefresh = Callable[[], None]
