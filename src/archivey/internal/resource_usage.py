"""How close one reader came to each reader-lifetime limit: a private record.

Internal on purpose. ``scripts/investigations/scan_archives.py`` and ``archivey extract
--dry-run`` read it to tune the defaults from a real corpus; it becomes public, if at
all, once such a scan shows which numbers are useful (a public name would be kept under
the deprecate-first policy).

What it holds, and where each number comes from:

- ``decoder_memory``: the largest allocation the archive *declared* that archivey checks
  itself (:func:`~archivey.internal.config.check_decoder_memory`), and what declared
  it. Noted before the comparison, so a refused declaration is recorded at its true
  size. xz, LZMA Alone and zstd hand the cap to liblzma / libzstd, which read the
  declaration themselves; archivey notes it from the same header (an xz stream's
  first block, the ``.lzma`` header, each zstd frame), since an archive read inside
  this one gets the cap less this number (``_PluginAdapter._nested_config``).
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

The recorder also keeps the public list of backends the reader ran
(:attr:`archivey.ArchiveReader.backends_used`): it already reaches every codec through
``StreamConfig.usage``. A detection probe's decodes are not in it, for the same reason.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

from archivey.types import BackendKindStr, BackendUse

if TYPE_CHECKING:
    from archivey.internal.config import KeyDerivationBudget
    from archivey.internal.listing_limits import ListingLimitTracker
    from archivey.internal.spool import SpoolBudget


def handler_name(handler: object) -> str:
    """How :attr:`~archivey.ArchiveReader.backends_used` names a format or codec
    handler: ``"archivey"`` for one archivey ships (CAB and XAR read through the plugin
    adapter too), else its class as ``module.QualName``."""
    cls = handler if isinstance(handler, type) else type(handler)
    if cls.__module__ == "archivey" or cls.__module__.startswith("archivey."):
        return "archivey"
    return f"{cls.__module__}.{cls.__qualname__}"


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    """A snapshot of :class:`ResourceUsageRecorder`.

    The decoder memory and spool numbers are peaks and the key-derivation rounds a
    total. The listing numbers are the tracker's current totals: a failed walk that is
    retried resets them, so they count the last walk. They include the members a
    plugin reader holds back (``ReaderContext.hold()``) while it holds them; a hold
    not yielded is released when the walk ends, however it ends, so a stopped walk
    counts the members it listed.
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
        "_backends",
        "_backends_also_to",
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
        # Insertion-ordered: the order each backend was first used.
        self._backends: dict[BackendUse, None] = {}
        # The outer reader's recorder, for a reader a plugin opened through
        # ``ReaderContext.open_nested``: what the inner archive ran is the outer's too.
        self._backends_also_to: ResourceUsageRecorder | None = None

    def note_decoder_memory(self, declared: int, what: str) -> None:
        """Keep ``declared`` if it is the largest declaration so far."""
        with self._lock:
            if declared > self._decoder_memory:
                self._decoder_memory = declared
                self._decoder_memory_what = what

    def note_backend(
        self,
        kind: BackendKindStr,
        name: str,
        used_for: str,
        path: str | None = None,
    ) -> None:
        """Record that the reader ran ``name`` for ``used_for``; a repeat is a no-op."""
        use = BackendUse(kind, name, used_for, path)
        with self._lock:
            self._backends.setdefault(use, None)
            outer = self._backends_also_to
        if outer is not None:
            outer.note_backend(kind, name, used_for, path)

    def report_backends_to(self, outer: ResourceUsageRecorder) -> None:
        """Record every backend this reader has run, and every later one, in ``outer``
        too: a nested reader's backends are its outer reader's."""
        with self._lock:
            self._backends_also_to = outer
            so_far = tuple(self._backends)
        for use in so_far:
            outer.note_backend(use.kind, use.name, use.used_for, use.path)

    def backends(self) -> tuple[BackendUse, ...]:
        """Every backend recorded, in the order each was first used."""
        with self._lock:
            return tuple(self._backends)

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
