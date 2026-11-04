"""The ranges of each 7z folder's decoded output that some read hashed in order.

A 7z folder's unpack digest (its CRC-32) is the only check of a member that has no CRC
of its own. A decode of the whole folder in order runs it (``_FolderChecks``), but a
``seekable_members=True`` read of each member in turn starts its own decode at that
member, and on a stored folder the seek decodes nothing before it. Each such read still
hashes the bytes it returns, so the reader keeps those hashes here, per folder, and
joins neighbours with :func:`crc32_combine`. When one range covers the whole folder,
its CRC is the folder's, and the check runs without another decode.

Memory stays bounded whatever the reads: a new range that touches no stored range must
be at least :data:`FOLDER_RANGE_MIN_BYTES` long, or start at the folder's first byte, or
end at its last, so a folder holds at most ``size / FOLDER_RANGE_MIN_BYTES + 2``. Across
the reader, :data:`FOLDER_RANGE_CAP` stops the count; a range past it is dropped, and
``verify_all()`` reads that folder again, as it does for any folder whose CRC has not run.
"""

from __future__ import annotations

import threading
from bisect import bisect_left
from dataclasses import dataclass

from archivey.internal.hashing import crc32_combine

# A stored range smaller than this that touches no other range and neither end of its
# folder is not kept: a read of a small member in the middle of a folder, with nothing
# read next to it yet. 64 KiB keeps at most one entry (about 100 bytes) per 64 KiB of
# folder, and a gap this small is cheap for ``verify_all()`` to read again.
FOLDER_RANGE_MIN_BYTES = 64 * 1024

# The most ranges one reader keeps, over all its folders: about 400 KiB at most. A
# range past it is dropped and its folder falls back to the ``verify_all()`` read.
FOLDER_RANGE_CAP = 4096


@dataclass(frozen=True)
class RecordResult:
    """What :meth:`FolderRanges.record` did with a range.

    ``kept``: the range's bytes are now in a stored range (added, joined to a
    neighbour, or already covered). ``start`` and ``crc``: when ``kept``, the stored
    range that holds the recorded range starts at ``start``, and ``crc`` is the CRC
    from there to the recorded range's end; a recorder that continues past that end
    continues this CRC. ``complete``: the CRC of the whole folder, when this record
    made one range cover it.
    """

    kept: bool
    start: int = 0
    crc: int = 0
    complete: int | None = None


_DROPPED = RecordResult(kept=False)


class FolderRanges:
    """Per reader, each folder's disjoint ``(start, end, crc)`` ranges, by start.

    Shared by every decode of a folder in one reader, so one lock guards it. The lock is
    held for list work and :func:`crc32_combine` only, never across I/O or a callback.
    Every decode of a folder in one reader uses the folder's one password
    (``SevenZipReader._folder_passwords``), so ranges from different decodes hash the
    same bytes.
    """

    def __init__(
        self, *, min_bytes: int = FOLDER_RANGE_MIN_BYTES, cap: int = FOLDER_RANGE_CAP
    ) -> None:
        self._lock = threading.Lock()
        self._ranges: dict[int, list[tuple[int, int, int]]] = {}
        self._count = 0
        self._min_bytes = min_bytes
        self._cap = cap

    def count(self) -> int:
        """The number of ranges kept, over every folder."""
        return self._count

    def ranges(self, folder: int) -> list[tuple[int, int, int]]:
        """A copy of ``folder``'s ranges, by start."""
        with self._lock:
            return list(self._ranges.get(folder, ()))

    def starts_at(self, folder: int, pos: int) -> bool:
        """Whether one of ``folder``'s ranges starts at ``pos``."""
        with self._lock:
            stored = self._ranges.get(folder)
            if not stored:
                return False
            i = bisect_left(stored, pos, key=_start)
            return i < len(stored) and stored[i][0] == pos

    def ending_at(self, folder: int, pos: int) -> tuple[int, int] | None:
        """``(start, crc)`` of ``folder``'s range that ends at ``pos``, if one does."""
        with self._lock:
            stored = self._ranges.get(folder)
            if not stored:
                return None
            i = bisect_left(stored, pos, key=_end)
            if i < len(stored) and stored[i][1] == pos:
                return stored[i][0], stored[i][2]
            return None

    def record(
        self, folder: int, start: int, end: int, crc: int, size: int
    ) -> RecordResult:
        """Add ``[start, end)`` of ``folder``, whose bytes hash to ``crc``.

        A stored range the new one contains is replaced by it, and one that ends where
        the new one starts, or starts where it ends, is joined to it. A new range that
        overlaps a stored one only in part is dropped: its CRC cannot be split at the
        stored range's edge, and the stored range already holds those bytes.
        """
        if not 0 <= start < end <= size:
            return _DROPPED
        with self._lock:
            stored = self._ranges.setdefault(folder, [])
            # ``lo``: the first stored range that ends after ``start``; ``hi``: the
            # first that starts at or after ``end``. Ranges are disjoint and sorted, so
            # both orders agree.
            lo = bisect_left(stored, start + 1, key=_end)
            hi = bisect_left(stored, end, key=_start)
            inside = stored[lo:hi]
            if inside:
                first, last = inside[0], inside[-1]
                if first[0] <= start and first[1] >= end:
                    # Already covered: the stored range holds these bytes. The
                    # recorder keeps its own start, as the stored CRC up to ``end``
                    # is not known.
                    return RecordResult(kept=True, start=start, crc=crc)
                if first[0] < start or last[1] > end:
                    return _DROPPED
            left = stored[lo - 1] if lo > 0 and stored[lo - 1][1] == start else None
            right = stored[hi] if hi < len(stored) and stored[hi][0] == end else None
            added = 1 - len(inside) - (left is not None) - (right is not None)
            if added > 0:
                if self._count + added > self._cap:
                    return _DROPPED
                if end - start < self._min_bytes and start != 0 and end != size:
                    return _DROPPED
            new_start, new_crc = start, crc
            if left is not None:
                new_start = left[0]
                new_crc = crc32_combine(left[2], crc, end - start)
            joined_crc = new_crc
            new_end = end
            if right is not None:
                new_end = right[1]
                joined_crc = crc32_combine(new_crc, right[2], right[1] - right[0])
            first_i = lo - (left is not None)
            last_i = hi + (right is not None)
            stored[first_i:last_i] = [(new_start, new_end, joined_crc)]
            self._count += added
            complete = joined_crc if new_start == 0 and new_end == size else None
            return RecordResult(
                kept=True, start=new_start, crc=new_crc, complete=complete
            )

    def settle(self, folder: int, size: int, crc: int | None) -> None:
        """A decode from the folder's start reached its end with CRC ``crc``.

        ``None`` (it did not match the folder's): forget ``folder``'s ranges, so a later
        set of reads can cover it again and raise the mismatch again. Otherwise keep
        one range over the whole folder: a later record of it is already covered.
        """
        with self._lock:
            stored = self._ranges.pop(folder, [])
            self._count -= len(stored)
            if crc is not None and size > 0:
                self._ranges[folder] = [(0, size, crc)]
                self._count += 1


def _start(entry: tuple[int, int, int]) -> int:
    return entry[0]


def _end(entry: tuple[int, int, int]) -> int:
    return entry[1]
