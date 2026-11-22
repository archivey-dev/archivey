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
from archivey.internal.overrides import override

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
    it, whether the backend that builds the reader has a salvage search
    (``ReadBackend.SUPPORTS_SALVAGE``), whether the archive's start may be lost, and
    whether the reader reads again what an earlier reader of the same archive
    reported. ``lost_start`` is set when the format came from ``format=`` or the
    source name's extension, not from the archive's own bytes (design decision 9).
    ``repeat`` marks an inner archive built again by a walk started over to reach
    member data: a repeat reader salvages as the first one did, and records none of
    the salvage codes, since the first one recorded them."""

    requested: bool = False
    supported: bool = False
    lost_start: bool = False
    repeat: bool = False


_NO_REQUEST = SalvageRequest()


@contextmanager
def requesting_salvage(
    requested: bool,
    *,
    supported: bool,
    lost_start: bool = False,
    repeat: bool = False,
) -> Generator[None]:
    """Let the next reader built on this thread take this salvage request.

    ``open_archive`` wraps the backend's ``open_read`` in it with the caller's
    ``salvage=``, and ``ReaderContext.open_nested`` wraps the inner reader's build
    with the outer reader's request, so an archive archivey opens inside another
    salvages when the outer one was asked to. The first reader built in the block
    takes the request (:func:`take_salvage_request`); one a password provider or a
    diagnostic callback opens later in the same open does not. ``lost_start`` is
    :attr:`SalvageRequest.lost_start`; it counts only with ``requested``. ``repeat``
    marks a reader that reads again what an earlier one reported
    (:class:`SalvageRequest`).
    """
    before = getattr(_local, "request", _NO_REQUEST)
    _local.request = SalvageRequest(
        requested=requested,
        supported=supported,
        lost_start=requested and lost_start,
        repeat=repeat,
    )
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

    ``find_header(window, start, stop)`` returns the index in ``window`` of the first
    candidate position at or after ``start`` and before ``stop`` where a header
    passes the format's own checks, or ``None``. It is pure on the bytes it is given.
    ``window[0]`` is always at a candidate position, so the candidate positions are
    ``start``, ``start + step``, ``start + 2 * step`` and so on, up to ``stop``; a
    ``find_header`` that returns any other index is a bug, and the search raises
    ``AssertionError``. It examines no candidate position at or after ``stop``: the
    search gives those to a later window, or the budget does not pay for them. The
    window holds ``max_header_size - 1`` bytes past ``stop`` where the layer has
    them, so each candidate before ``stop`` can be checked whole. A header that does
    not fit in the window does not pass: the layer ends inside it.

    ``step`` is the distance between candidate positions: 512 for TAR, 4 or 1 for
    CPIO, 2 for ar. Candidate positions are counted from the ``base`` given to
    :func:`search_forward`, such as the archive's start.

    ``max_header_size`` is the most bytes ``find_header`` reads from a candidate
    position to decide, at least ``step``. The windows overlap by one byte less, so a
    header that straddles a window's end is found once, in the window where it fits.
    """

    find_header: Callable[[bytes, int, int], int | None]
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
    ``lost_start`` says the format came from ``format=`` or the name's extension, so
    the archive's first header may be lost: a salvage reader whose first header
    does not parse searches for one from the start (design decision 9).

    A format calls :func:`search_forward` with this state, and :meth:`finish` when its
    walk ends, which records the ``report_limit`` record if any range went
    unreported. The budget, the records and the layer positions are the listing
    walk's: only that walk charges and records. A listing walk started over after a
    failure calls :meth:`restart` first. Any other walk from the start, such as one
    a random-access reader runs to reach a member's data, possibly while the listing
    walk runs, searches with a :class:`QuietSalvageState` of its own, so it leaves
    this state as it is.
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
        lost_start: bool = False,
    ) -> None:
        self.requested = requested
        self.enabled = enabled
        self.lost_start = enabled and lost_start
        self.limits = limits
        self._collector = collector
        self._archive_name = archive_name
        self._format_name = format_name
        self.restart()

    def restart(self) -> None:
        """Forget every search, for a listing walk that starts over from the
        archive's start after a failure: the walk then searches, charges the budget
        and records again from zero, as the first listing walk did.

        A walk that starts over only to reach a member's data, beside a listing that
        stays, does not call this: it searches with a :class:`QuietSalvageState` of
        its own, which finds the same members, charges nothing to this state and
        records nothing."""
        # Bytes the searches have examined, all layers together.
        self.searched_bytes = 0
        # Set once max_search_bytes stops a search; every later search stops at once.
        self.limit_reached = False
        # Per layer, and per volume of a set, the first candidate position no
        # search has examined yet.
        self._positions: dict[tuple[str, int | None], int] = {}
        # ARCHIVE_REGION_SKIPPED records made, and the ranges past the cap: their
        # count and where the first of them starts.
        self._reported_regions = 0
        self._unreported_regions = 0
        self._first_unreported: tuple[str, int, int | None] | None = None
        self._finished = False

    def position(
        self, layer: str = ARCHIVE_LAYER, volume_index: int | None = None
    ) -> int:
        """The first position in ``layer`` that no search has examined yet (``0``
        when none has searched it). In a multi-volume set each volume is its own
        offset space, so ``volume_index`` names which one."""
        return self._positions.get((layer, volume_index), 0)

    def remaining_bytes(self) -> int | None:
        """Bytes the searches may still examine, or ``None`` for no cap."""
        cap = self.limits.max_search_bytes
        return None if cap is None else max(0, cap - self.searched_bytes)

    def _examined(
        self, layer: str, start: int, stop: int, volume_index: int | None = None
    ) -> None:
        """Count the bytes from ``start`` to ``stop`` as examined, and move the
        layer's position to ``stop``. The position never moves back: a byte behind it
        was examined already, and examining it again would count it twice."""
        before = self.position(layer, volume_index)
        if stop < before or stop < start:
            raise AssertionError(
                f"the {layer} search position would move back, from {before} to {stop}"
            )
        self.searched_bytes += stop - start
        self._positions[layer, volume_index] = stop

    def record_region(
        self,
        *,
        layer: str,
        offset: int,
        length: int | None,
        volume_index: int | None = None,
    ) -> None:
        """Record one ``ARCHIVE_REGION_SKIPPED`` with ``reason="no_header"``, within
        ``max_reported_regions``. A range past the cap is counted for :meth:`finish`
        instead."""
        if self._reported_regions >= self.limits.max_reported_regions:
            if self._first_unreported is None:
                self._first_unreported = (layer, offset, volume_index)
            self._unreported_regions += 1
            return
        self._reported_regions += 1
        self._emit(
            RegionSkippedContext(
                archive_name=self._archive_name,
                format=self._format_name,
                layer=layer,
                offset=offset,
                length=length,
                reason="no_header",
                volume_index=volume_index,
            ),
            f"Salvage skipped {length} {'byte' if length == 1 else 'bytes'} at offset "
            f"{offset}{_in_layer(layer, volume_index)} of the {self._format_name} "
            "archive: no header passes the format's checks in it.",
        )

    def record_search_limit(
        self,
        *,
        layer: str,
        started_at: int,
        examined_from: int,
        stopped_at: int,
        volume_index: int | None = None,
    ) -> None:
        """Record the ``ARCHIVE_REGION_SKIPPED`` with ``reason="search_limit"`` for a
        search that started at ``started_at`` and that ``max_search_bytes`` stopped at
        ``stopped_at``, having examined the bytes from ``examined_from``. It is made
        whatever the count of records, as ``report_limit`` is: it says why the listing
        stops."""
        if stopped_at > examined_from:
            stop = f"stopped at offset {stopped_at}, after the bytes it examined"
        else:
            stop = "stopped before examining a byte"
        searched = "" if layer == ARCHIVE_LAYER else f"the {layer} stream of "
        self._emit(
            RegionSkippedContext(
                archive_name=self._archive_name,
                format=self._format_name,
                layer=layer,
                offset=started_at,
                length=None,
                reason="search_limit",
                volume_index=volume_index,
            ),
            f"Salvage stopped searching {searched}the {self._format_name} "
            f"archive: SalvageLimits.max_search_bytes "
            f"({self.limits.max_search_bytes}) ran out. The search started at offset "
            f"{started_at}{_in_volume(volume_index)} and {stop}; nothing after it is "
            "listed.",
        )

    def finish(self) -> None:
        """Record the ``report_limit`` record when ranges went past
        ``max_reported_regions``. Once per walk; later calls do nothing."""
        if self._finished:
            return
        self._finished = True
        if self._first_unreported is None:
            return
        layer, offset, volume_index = self._first_unreported
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
                volume_index=volume_index,
            ),
            f"Salvage skipped {count} more {ranges} of the {self._format_name} "
            f"archive, from offset {offset}{_in_layer(layer, volume_index)}, that are "
            f"not reported one by one: SalvageLimits.max_reported_regions is "
            f"{self.limits.max_reported_regions}.",
        )

    def _emit(self, context: RegionSkippedContext, message: str) -> None:
        self._collector.emit(
            code=DiagnosticCode.ARCHIVE_REGION_SKIPPED,
            message=message,
            context=context,
            logger=logger,
        )


def _in_layer(layer: str, volume_index: int | None = None) -> str:
    stream = "" if layer == ARCHIVE_LAYER else f" of its {layer} stream"
    return stream + _in_volume(volume_index)


def _in_volume(volume_index: int | None) -> str:
    return "" if volume_index is None else f" in volume {volume_index + 1}"


# ``SalvageUnavailableContext.reason``.
SalvageUnavailableReason = Literal["no_salvage_search", "forward_only_reader"]

_UNAVAILABLE_CAUSES: dict[SalvageUnavailableReason, str] = {
    "no_salvage_search": "archivey has no salvage search for this format",
    "forward_only_reader": (
        "this format's salvage search cannot run on an archive inside another one, "
        "which archivey reads forward only"
    ),
}


def emit_salvage_unavailable(
    collector: DiagnosticCollector,
    *,
    archive_name: str | None,
    format_name: str,
    reason: SalvageUnavailableReason = "no_salvage_search",
) -> None:
    """Record ``SALVAGE_UNAVAILABLE`` for a reader asked to salvage whose format's
    search cannot run: ``"no_salvage_search"`` when the format has none,
    ``"forward_only_reader"`` when it cannot run on this forward-only reader."""
    collector.emit(
        code=DiagnosticCode.SALVAGE_UNAVAILABLE,
        message=(
            f"salvage=True has no effect on {format_name}: "
            f"{_UNAVAILABLE_CAUSES[reason]}, so the archive is read as it is "
            "without it."
        ),
        context=SalvageUnavailableContext(
            archive_name=archive_name, format=format_name, reason=reason
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
    volume_index: int | None = None,
    accept: Callable[[int], bool] | None = None,
) -> SearchResult:
    """Search ``layer`` forward from ``start`` for the next header that passes.

    ``read_at(offset, size)`` returns the layer's bytes from ``offset``: ``size`` of
    them, or fewer only where the layer ends. Within one call the search reads
    forward, each read starting where the one before ended, so a decoded stream can
    serve it without seeking back. ``end``, when known, is where the layer ends; the
    search reads nothing at or past it, and an ``end`` before ``start`` or before the
    layer's search position is a bug (``AssertionError``). Under a budget the search
    reads no further than the last header the budget lets it reach (one byte more
    when ``end`` is not known and the budget pays for every byte read, to see
    whether the layer ends there), and with no budget left it reads nothing.

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

    ``volume_index`` names the volume of a multi-volume set the layer is in: each
    volume has its own positions, and the records name it. ``accept(offset)``, when
    given, is asked about each header found: ``False`` passes it over without ending
    the range, so one record covers the bytes on both sides of it, as for a copy of
    a header that is not a member (the search counts the position examined and goes
    on from the next one).
    """
    if not state.enabled:
        raise AssertionError("search_forward called on a reader that does not salvage")
    if start < base:
        raise AssertionError(f"search start {start} is before the base {base}")
    if end is not None and (end < start or end < state.position(layer, volume_index)):
        raise AssertionError(
            f"search end {end} is before the start {start} or before the "
            f"{layer} search position {state.position(layer, volume_index)}"
        )
    if state.limit_reached:
        return SearchResult(found=None, limit_reached=True)
    step = search.step
    region_start = max(start, state.position(layer, volume_index))
    if end is not None and region_start >= end:
        # An empty range: nothing to examine or record, and the position stays.
        return SearchResult(found=None)
    # The first candidate position at or after region_start.
    pos = base + -(-(region_start - base) // step) * step
    if end is not None and pos >= end:
        # No candidate position is left before the end: nothing to examine.
        state._examined(layer, end, end, volume_index)
        _record_no_header(state, layer, region_start, end, volume_index)
        return SearchResult(found=None)
    examined_from = pos
    remaining = state.remaining_bytes()
    if remaining == 0:
        # Stop before reading: a read could only fetch bytes nobody may examine.
        state.limit_reached = True
        state.record_search_limit(
            layer=layer,
            started_at=region_start,
            examined_from=pos,
            stopped_at=pos,
            volume_index=volume_index,
        )
        return SearchResult(found=None, limit_reached=True)
    if end is None and pos > region_start:
        # The bytes before the first candidate position are not examined, but only
        # a read shows whether the layer has them: a layer that ends among them
        # skips only what it holds.
        gap = read_at(region_start, pos - region_start)
        if len(gap) < pos - region_start:
            layer_end = region_start + len(gap)
            state._examined(layer, layer_end, layer_end, volume_index)
            _record_no_header(state, layer, region_start, layer_end, volume_index)
            return SearchResult(found=None)
    # With a budget, no read goes past the last header the budget lets the search
    # reach: the bytes it may examine, plus the rest of a header that starts there.
    read_limit = (
        None if remaining is None else pos + remaining + search.max_header_size - 1
    )

    span = window_size + search.max_header_size - 1
    # The bytes read so far, from ``pos``; ``buf_end`` is the layer offset after them.
    buf = b""
    buf_end = pos
    at_end = False
    while True:
        want = span - len(buf)
        if end is not None:
            want = min(want, end - buf_end)
        if read_limit is not None:
            want = min(want, read_limit - buf_end)
        if want > 0 and not at_end:
            chunk = read_at(buf_end, want)
            buf += chunk
            buf_end += len(chunk)
            if len(chunk) < want or (end is not None and buf_end >= end):
                at_end = True
        elif end is not None and buf_end >= end:
            at_end = True

        remaining = state.remaining_bytes()
        last, budget_bound = _last_position(
            pos, buf_end, at_end, remaining, step, search.max_header_size
        )
        if (
            budget_bound
            and end is None
            and not at_end
            and remaining is not None
            and buf_end - pos <= remaining
        ):
            # The budget pays for every byte read, and with no ``end`` only a read
            # shows whether the layer ends here. If it does, the budget is no limit.
            probe = read_at(buf_end, 1)
            if probe:
                buf += probe
                buf_end += len(probe)
            else:
                at_end = True
            last, budget_bound = _last_position(
                pos, buf_end, at_end, remaining, step, search.max_header_size
            )

        if last >= pos:
            # The candidate positions this window may examine are those before
            # ``stop``; the window keeps the bytes a header at the last one needs.
            stop = last - pos + 1
            window = buf[: stop - 1 + search.max_header_size]
            found = search.find_header(window, 0, stop)
            while found is not None:
                if found < 0 or found % step or found >= stop:
                    raise AssertionError(
                        f"find_header returned {found}, which is not a candidate "
                        f"position (a multiple of {step} at or after 0 and before "
                        f"{stop})"
                    )
                header_at = pos + found
                if accept is not None and not accept(header_at):
                    # Passed over inside the same range: look on from the next
                    # position in the bytes already read.
                    found = search.find_header(window, found + step, stop)
                    continue
                after = header_at + step
                state._examined(
                    layer, pos, min(after, buf_end) if at_end else after, volume_index
                )
                if header_at > region_start:
                    state.record_region(
                        layer=layer,
                        offset=region_start,
                        length=header_at - region_start,
                        volume_index=volume_index,
                    )
                return SearchResult(found=header_at)
            # The last candidate position examined, then the first one after it.
            examined_last = pos + (last - pos) // step * step
            next_pos = examined_last + step
            if at_end and not budget_bound:
                next_pos = min(next_pos, buf_end)
            state._examined(layer, pos, next_pos, volume_index)
            buf = buf[next_pos - pos :]
            pos = next_pos

        if at_end and pos >= buf_end and not budget_bound:
            _record_no_header(state, layer, region_start, buf_end, volume_index)
            return SearchResult(found=None)
        if budget_bound:
            state.limit_reached = True
            state.record_search_limit(
                layer=layer,
                started_at=region_start,
                examined_from=examined_from,
                stopped_at=pos,
                volume_index=volume_index,
            )
            return SearchResult(found=None, limit_reached=True)


def _last_position(
    pos: int,
    buf_end: int,
    at_end: bool,
    remaining: int | None,
    step: int,
    max_header_size: int,
) -> tuple[int, bool]:
    """The last position this window may examine, and whether the budget set it."""
    # At the layer's end every position before it is examined; a header that does
    # not fit there fails find_header's own check.
    last = buf_end - 1 if at_end else buf_end - max_header_size
    # A position costs ``step`` bytes, or what is left of the layer at its end, so
    # the rest of a layer that has ended costs what is left of it.
    if remaining is None or (at_end and buf_end - pos <= remaining):
        return last, False
    last_affordable = pos + (remaining // step - 1) * step
    # Below ``pos`` when the budget cannot pay for one more position.
    if last_affordable < last or last_affordable < pos:
        return min(last, last_affordable), True
    return last, False


def _record_no_header(
    state: SalvageState,
    layer: str,
    region_start: int,
    layer_end: int,
    volume_index: int | None = None,
) -> None:
    if layer_end > region_start:
        state.record_region(
            layer=layer,
            offset=region_start,
            length=layer_end - region_start,
            volume_index=volume_index,
        )


class QuietSalvageState(SalvageState):
    """The salvage state of a walk started over to reach member data: it searches as
    the listing walk did, so it finds the same members, and records nothing, since
    the listing walk recorded it all."""

    @override
    def _emit(self, context: RegionSkippedContext, message: str) -> None:
        pass
