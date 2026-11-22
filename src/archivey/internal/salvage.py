"""Salvage mode (``open_archive(salvage=True)``): the per-reader state and the
forward header search every salvaging format shares.

Where damage stops a format's member walk, a reader in salvage mode searches forward
for the next header that passes the format's own checks, lists the member it finds
there, and walks on. This module owns the parts that do not depend on the format:

- :func:`requesting_salvage` / :func:`take_salvage_request` carry the caller's flag
  from the opener to the reader the opener builds, as :mod:`~archivey.internal.nesting`
  carries ``parent=``, so no backend's ``open_read`` takes another argument.
- :class:`SalvageState`, one per reader: whether the reader salvages, its
  :class:`~archivey.SalvageLimits`, the search budget and the position each layer's
  search has reached, and the ``ARCHIVE_REGION_SKIPPED`` records with their cap.
- :func:`search_forward`, the search itself. A format gives it a
  :class:`HeaderSearch`: a ``find_header(window, start)`` function that is pure on
  bytes, the step between candidate positions, and the longest header it needs.

The search reads the layer in windows, examines each candidate position at most
once per layer (its position only moves forward), and counts what it examines
against ``SalvageLimits.max_search_bytes``. Salvage is add-only: a format starts a
search only where its normal walk stopped on damage, so every member the default
lists comes first and unchanged.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from archivey.diagnostics import (
    DiagnosticCode,
    RegionSkippedContext,
    SalvageUnavailableContext,
)
from archivey.internal.logs import backends as logger

if TYPE_CHECKING:
    from archivey.config import SalvageLimits
    from archivey.internal.diagnostics_collector import DiagnosticCollector

# Bytes one window of the search holds beyond the overlap. 1 MiB keeps a read large
# enough to be cheap on a file and on a range-request source, and small enough to hold.
WINDOW_SIZE = 1 << 20

# The layer name of the archive's own bytes, as opposed to a codec's decoded stream.
ARCHIVE_LAYER = "archive"

_local = threading.local()


@dataclass(frozen=True)
class SalvageRequest:
    """What the opener of a reader says about salvage: whether the caller asked for
    it, and whether the backend that builds the reader has a salvage search
    (``ReadBackend.SUPPORTS_SALVAGE``)."""

    requested: bool = False
    supported: bool = False


_NO_REQUEST = SalvageRequest()


@contextmanager
def requesting_salvage(requested: bool, *, supported: bool) -> Generator[None]:
    """Let the next reader built on this thread take this salvage request.

    ``open_archive`` wraps the backend's ``open_read`` in it with the caller's
    ``salvage=``, and ``ReaderContext.open_nested`` wraps the inner reader's build
    with the outer reader's request, so an archive archivey opens inside another
    salvages when the outer one was asked to. The first reader built in the block
    takes the request (:func:`take_salvage_request`); one a password provider or a
    diagnostic callback opens later in the same open does not.
    """
    before = getattr(_local, "request", _NO_REQUEST)
    _local.request = SalvageRequest(requested=requested, supported=supported)
    try:
        yield
    finally:
        _local.request = before


def take_salvage_request() -> SalvageRequest:
    """The salvage request of the reader built now, consumed so no later reader
    takes it. A reader built outside :func:`requesting_salvage` gets no request."""
    request: SalvageRequest = getattr(_local, "request", _NO_REQUEST)
    _local.request = _NO_REQUEST
    return request


@dataclass(frozen=True)
class HeaderSearch:
    """What a format gives :func:`search_forward`.

    ``find_header(window, start)`` returns the index in ``window`` of the first
    candidate position at or after ``start`` where a header passes the format's own
    checks, or ``None``. It is pure on the bytes it is given. ``window[0]`` is always
    at a candidate position, so the candidate positions are ``start``,
    ``start + step``, ``start + 2 * step`` and so on; a ``find_header`` that returns
    any other index is a bug, and the search raises ``AssertionError``. A header that
    does not fit in the window does not pass: the search shows it again, whole, in
    the next window, unless the layer ends first.

    ``step`` is the distance between candidate positions: 512 for TAR, 4 or 1 for
    CPIO, 2 for ar. Candidate positions are counted from the ``base`` given to
    :func:`search_forward`, such as the archive's start.

    ``max_header_size`` is the most bytes ``find_header`` reads from a candidate
    position to decide, at least ``step``. The windows overlap by one byte less, so a
    header that straddles a window's end is found once, in the window where it fits.
    """

    find_header: Callable[[bytes, int], int | None]
    step: int
    max_header_size: int

    def __post_init__(self) -> None:
        # A header at least as long as the step keeps every window's next position
        # inside the bytes already read, so the reads stay contiguous.
        if not 1 <= self.step <= self.max_header_size:
            raise AssertionError(
                f"HeaderSearch needs 1 <= step <= max_header_size, got "
                f"step={self.step} and max_header_size={self.max_header_size}"
            )


@dataclass(frozen=True)
class SearchResult:
    """How one :func:`search_forward` ended.

    ``found`` is where the header found starts in the layer, or ``None``. With
    ``None``, ``limit_reached`` says why: ``False`` when no header passes before the
    layer's end, ``True`` when ``SalvageLimits.max_search_bytes`` stopped the search.
    Once the limit is reached, every later search of the reader returns at once with
    ``limit_reached=True``, and the format lists nothing more.
    """

    found: int | None
    limit_reached: bool = False


class SalvageState:
    """One reader's salvage mode: whether it salvages, its limits, the search budget,
    each layer's search position and the ``ARCHIVE_REGION_SKIPPED`` records.

    ``requested`` is whether the reader was opened with ``salvage=True``; ``enabled``
    is whether it salvages, which also needs its backend to have a salvage search.
    A reader asks ``enabled`` before it searches, and reads ``limits`` for the caps.

    A format calls :func:`search_forward` with this state, and :meth:`finish` when its
    walk ends, which records the ``report_limit`` record if any range went
    unreported. A walk started over after a failure calls :meth:`restart` first, so
    it searches again from zero, as the first walk did.
    """

    def __init__(
        self,
        *,
        requested: bool,
        enabled: bool,
        limits: SalvageLimits,
        collector: DiagnosticCollector,
        archive_name: str | None,
        format_name: str,
    ) -> None:
        self.requested = requested
        self.enabled = enabled
        self.limits = limits
        self._collector = collector
        self._archive_name = archive_name
        self._format_name = format_name
        self.restart()

    def restart(self) -> None:
        """Forget every search, for a walk that starts over from the archive's start."""
        # Bytes the searches have examined, all layers together.
        self.searched_bytes = 0
        # Set once max_search_bytes stops a search; every later search stops at once.
        self.limit_reached = False
        # Per layer, the first candidate position no search has examined yet.
        self._positions: dict[str, int] = {}
        # ARCHIVE_REGION_SKIPPED records made, and the ranges past the cap: their
        # count and where the first of them starts.
        self._reported_regions = 0
        self._unreported_regions = 0
        self._first_unreported: tuple[str, int] | None = None
        self._finished = False

    def position(self, layer: str = ARCHIVE_LAYER) -> int:
        """The first position in ``layer`` that no search has examined yet (``0``
        when none has searched it)."""
        return self._positions.get(layer, 0)

    def remaining_bytes(self) -> int | None:
        """Bytes the searches may still examine, or ``None`` for no cap."""
        cap = self.limits.max_search_bytes
        return None if cap is None else max(0, cap - self.searched_bytes)

    def _examined(self, layer: str, start: int, stop: int) -> None:
        """Count the bytes from ``start`` to ``stop`` as examined, and move the
        layer's position to ``stop``."""
        self.searched_bytes += stop - start
        self._positions[layer] = stop

    def record_region(
        self,
        *,
        layer: str,
        offset: int,
        length: int | None,
        reason: Literal["no_header", "search_limit"],
    ) -> None:
        """Record one ``ARCHIVE_REGION_SKIPPED``, within ``max_reported_regions``.

        A ``"no_header"`` range past the cap is counted for :meth:`finish` instead.
        The ``"search_limit"`` record is made whatever the count: it is the one that
        says why the listing stops.
        """
        if (
            reason == "no_header"
            and self._reported_regions >= self.limits.max_reported_regions
        ):
            if self._first_unreported is None:
                self._first_unreported = (layer, offset)
            self._unreported_regions += 1
            return
        if reason == "no_header":
            self._reported_regions += 1
            what = "no header passes the format's checks in it"
            span = f"{length} bytes at offset {offset}"
        else:
            what = (
                "SalvageLimits.max_search_bytes "
                f"({self.limits.max_search_bytes}) stopped the search there; "
                "nothing after it is listed"
            )
            span = f"the bytes from offset {offset}"
        self._emit(
            RegionSkippedContext(
                archive_name=self._archive_name,
                format=self._format_name,
                layer=layer,
                offset=offset,
                length=length,
                reason=reason,
            ),
            f"Salvage skipped {span}{_in_layer(layer)} of the {self._format_name} "
            f"archive: {what}.",
        )

    def finish(self) -> None:
        """Record the ``report_limit`` record when ranges went past
        ``max_reported_regions``. Once per walk; later calls do nothing."""
        if self._finished:
            return
        self._finished = True
        if self._first_unreported is None:
            return
        layer, offset = self._first_unreported
        count = self._unreported_regions
        ranges = "range" if count == 1 else "ranges"
        self._emit(
            RegionSkippedContext(
                archive_name=self._archive_name,
                format=self._format_name,
                layer=layer,
                offset=offset,
                length=None,
                reason="report_limit",
            ),
            f"Salvage skipped {count} more {ranges} of the {self._format_name} "
            f"archive, from offset {offset}{_in_layer(layer)}, that are not reported "
            f"one by one: SalvageLimits.max_reported_regions is "
            f"{self.limits.max_reported_regions}.",
        )

    def _emit(self, context: RegionSkippedContext, message: str) -> None:
        self._collector.emit(
            code=DiagnosticCode.ARCHIVE_REGION_SKIPPED,
            message=message,
            context=context,
            logger=logger,
        )


def _in_layer(layer: str) -> str:
    return "" if layer == ARCHIVE_LAYER else f" of its {layer} stream"


def emit_salvage_unavailable(
    collector: DiagnosticCollector, *, archive_name: str | None, format_name: str
) -> None:
    """Record ``SALVAGE_UNAVAILABLE`` for a reader asked to salvage whose format has
    no salvage search."""
    collector.emit(
        code=DiagnosticCode.SALVAGE_UNAVAILABLE,
        message=(
            f"salvage=True has no effect on {format_name}: archivey has no salvage "
            "search for this format, so the archive is read as it is without it."
        ),
        context=SalvageUnavailableContext(
            archive_name=archive_name, format=format_name
        ),
        logger=logger,
    )


def search_forward(
    state: SalvageState,
    read_at: Callable[[int, int], bytes],
    search: HeaderSearch,
    *,
    start: int,
    end: int | None = None,
    base: int = 0,
    layer: str = ARCHIVE_LAYER,
    window_size: int = WINDOW_SIZE,
) -> SearchResult:
    """Search ``layer`` forward from ``start`` for the next header that passes.

    ``read_at(offset, size)`` returns the layer's bytes from ``offset``: ``size`` of
    them, or fewer only where the layer ends. Within one call the search reads
    forward, each read starting where the one before ended, so a decoded stream can
    serve it without seeking back. ``end``, when known, is where the layer ends; the
    search reads nothing at or past it.

    The candidate positions are ``base + k * search.step``. The search starts at the
    first one at or after ``start``, or at the first one this layer's earlier
    searches have not examined, whichever is later: no position is examined twice in
    a layer. Each position examined counts ``search.step`` bytes (fewer at the
    layer's end) against ``SalvageLimits.max_search_bytes``.

    It records ``ARCHIVE_REGION_SKIPPED`` for the range it stepped over: up to the
    header it found, or to the layer's end, or, when the limit stops it, one
    ``"search_limit"`` record with no length. A format that lists the found member
    and finds it unconfirmed searches again from the next candidate position after
    it; one that walks on from the member searches again only at the next damage.
    """
    if not state.enabled:
        raise AssertionError("search_forward called on a reader that does not salvage")
    if start < base:
        raise AssertionError(f"search start {start} is before the base {base}")
    if state.limit_reached:
        return SearchResult(found=None, limit_reached=True)
    step = search.step
    region_start = max(start, state.position(layer))
    # The first candidate position at or after region_start.
    pos = base + -(-(region_start - base) // step) * step
    if end is not None and pos >= end:
        # No candidate position is left before the end: nothing to examine.
        state._examined(layer, end, end)
        _record_no_header(state, layer, region_start, end)
        return SearchResult(found=None)

    span = window_size + search.max_header_size - 1
    # The bytes read so far, from ``pos``; ``buf_end`` is the layer offset after them.
    buf = b""
    buf_end = pos
    at_end = False
    while True:
        want = span - len(buf)
        if end is not None:
            want = min(want, end - buf_end)
        if want > 0 and not at_end:
            chunk = read_at(buf_end, want)
            buf += chunk
            buf_end += len(chunk)
            if len(chunk) < want or (end is not None and buf_end >= end):
                at_end = True
        elif end is not None and buf_end >= end:
            at_end = True

        if at_end:
            # Every position before the layer's end is examined; a header that does
            # not fit there fails find_header's own check.
            last_fit = buf_end - 1
        else:
            last_fit = buf_end - search.max_header_size
        last = last_fit
        remaining = state.remaining_bytes()
        budget_bound = False
        # A position costs ``step`` bytes, or what is left of the layer at its end,
        # so the rest of a layer that has ended costs what is left of it.
        if remaining is not None and not (at_end and buf_end - pos <= remaining):
            last_affordable = pos + (remaining // step - 1) * step
            if last_affordable < last:
                last = last_affordable
                budget_bound = True

        if last >= pos:
            found = search.find_header(buf, 0)
            if found is not None:
                if found < 0 or found % step:
                    raise AssertionError(
                        f"find_header returned {found}, which is not a candidate "
                        f"position (a multiple of {step} at or after 0)"
                    )
                if pos + found <= last:
                    header_at = pos + found
                    after = header_at + step
                    state._examined(
                        layer, pos, min(after, buf_end) if at_end else after
                    )
                    if header_at > region_start:
                        state.record_region(
                            layer=layer,
                            offset=region_start,
                            length=header_at - region_start,
                            reason="no_header",
                        )
                    return SearchResult(found=header_at)
            # The last candidate position examined, then the first one after it.
            examined_last = pos + (last - pos) // step * step
            next_pos = examined_last + step
            if at_end and not budget_bound:
                next_pos = min(next_pos, buf_end)
            state._examined(layer, pos, next_pos)
            buf = buf[next_pos - pos :]
            pos = next_pos

        if at_end and pos >= buf_end and not budget_bound:
            _record_no_header(state, layer, region_start, buf_end)
            return SearchResult(found=None)
        if budget_bound:
            state.limit_reached = True
            state.record_region(
                layer=layer, offset=region_start, length=None, reason="search_limit"
            )
            return SearchResult(found=None, limit_reached=True)


def _record_no_header(
    state: SalvageState, layer: str, region_start: int, layer_end: int
) -> None:
    if layer_end > region_start:
        state.record_region(
            layer=layer,
            offset=region_start,
            length=layer_end - region_start,
            reason="no_header",
        )
