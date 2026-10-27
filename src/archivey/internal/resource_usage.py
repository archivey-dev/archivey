"""How close one reader came to each reader-lifetime limit: a private record.

Internal on purpose. ``scripts/scan_archives.py`` and ``archivey extract --dry-run``
read it to tune the defaults from a real corpus; it becomes public, if at all, once
such a scan shows which numbers are useful (a public name would be kept under the
deprecate-first policy).

What it holds, and where each number comes from:

- ``decoder_memory``: the largest allocation the archive *declared* that archivey checks
  itself (:func:`~archivey.internal.config.check_decoder_memory`), and what declared
  it. Noted before the comparison, so a refused declaration is recorded at its true
  size. xz, LZMA Alone and zstd hand the cap to liblzma / libzstd, which read the
  declaration themselves, and are not counted.
- ``key_derivation_rounds``: the rounds the reader's
  :class:`~archivey.internal.config.KeyDerivationBudget` spent (7z AES, RAR).
- ``spool_bytes``: the most the reader's :class:`~archivey.internal.spool.SpoolBudget`
  held charged at once (RAR from a stream).
- ``listed_members`` and ``listing_metadata_bytes``: the reader's listing tracker.

The extraction counters (bytes, entries, ratios) are not here: the
:class:`~archivey.ExtractionReport`'s results already carry them. A counter that
refuses stops at the cap, so a scan that wants the true value turns the counting
limits off; the decoder-memory peak is exact either way.

A detection probe builds its own stream config, without a recorder, so a size a
content probe checks is never counted as the archive's.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from archivey.internal.config import KeyDerivationBudget
    from archivey.internal.listing_limits import ListingLimitTracker
    from archivey.internal.spool import SpoolBudget


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    """A snapshot of :class:`ResourceUsageRecorder`.

    The decoder memory and spool numbers are peaks and the key-derivation rounds a
    total. The listing numbers are the tracker's current totals: a failed walk that is
    retried resets them, so they count the last walk.
    """

    decoder_memory: int = 0
    decoder_memory_what: str = ""
    key_derivation_rounds: int = 0
    spool_bytes: int = 0
    listed_members: int = 0
    listing_metadata_bytes: int = 0


class ResourceUsageRecorder:
    """The mutable record one reader keeps; :meth:`snapshot` freezes it.

    The reader makes one at construction. ``note_decoder_memory`` is called from codec
    threads, so it takes a lock. The budgets and the listing tracker keep their own
    totals; the recorder holds a reference and reads them at snapshot time.
    """

    __slots__ = (
        "_decoder_memory",
        "_decoder_memory_what",
        "_kdf_budgets",
        "_listing",
        "_lock",
        "_spool",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._decoder_memory = 0
        self._decoder_memory_what = ""
        self._kdf_budgets: list[KeyDerivationBudget] = []
        self._spool: SpoolBudget | None = None
        self._listing: ListingLimitTracker | None = None

    def note_decoder_memory(self, declared: int, what: str) -> None:
        """Keep ``declared`` if it is the largest declaration so far."""
        with self._lock:
            if declared > self._decoder_memory:
                self._decoder_memory = declared
                self._decoder_memory_what = what

    def watch_key_derivation(self, budget: KeyDerivationBudget) -> None:
        self._kdf_budgets.append(budget)

    def watch_spool(self, spool: SpoolBudget) -> None:
        self._spool = spool

    def watch_listing(self, tracker: ListingLimitTracker) -> None:
        self._listing = tracker

    def snapshot(self) -> ResourceUsage:
        with self._lock:
            memory, what = self._decoder_memory, self._decoder_memory_what
        listing = self._listing
        return ResourceUsage(
            decoder_memory=memory,
            decoder_memory_what=what,
            key_derivation_rounds=sum(b.spent for b in self._kdf_budgets),
            spool_bytes=self._spool.peak if self._spool is not None else 0,
            listed_members=listing.member_count if listing is not None else 0,
            listing_metadata_bytes=listing.metadata_bytes if listing is not None else 0,
        )
