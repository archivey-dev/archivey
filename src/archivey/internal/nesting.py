"""Which reader a reader being built reads inside (``ReaderContext.open_nested``).

The readers of one nest of archives share their limits' budgets (maintainer ruling,
2026-11-08: "charge across the nesting"). A reader learns the reader it reads inside
while it is built, on the building thread, the way it learns its depth from
:attr:`DiagnosticCollector.nesting_depth
<archivey.internal.diagnostics_collector.DiagnosticCollector.nesting_depth>`:

- its listing tracker charges what it keeps beyond its members to the outermost
  tracker (:class:`~archivey.internal.listing_limits.ListingLimitTracker`);
- its ratio guards divide by the outermost archive's compressed bytes
  (``BaseArchiveReader._trusted_source_size`` and ``_live_consumed``);
- its ``max_decoder_memory`` is what the outer levels left
  (``_PluginAdapter._nested_config``).
"""

from __future__ import annotations

import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from archivey.internal.base_reader import BaseArchiveReader

_local = threading.local()


@contextmanager
def reading_inside(outer: BaseArchiveReader) -> Generator[None]:
    """Build readers inside ``outer`` on this thread while the block runs."""
    before = getattr(_local, "outer", None)
    _local.outer = outer
    try:
        yield
    finally:
        _local.outer = before


def enclosing_reader() -> BaseArchiveReader | None:
    """The reader a reader built now reads inside, or ``None`` at the top."""
    return getattr(_local, "outer", None)
