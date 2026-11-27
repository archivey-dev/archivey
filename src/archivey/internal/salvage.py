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
  :class:`HeaderSearch`: a ``find_header(window, start, stop)`` function that is pure
  on bytes and examines only candidate starts before ``stop``, the step between
  candidate positions, and the longest header it needs.

The search reads the layer in windows, examines each candidate position at most
once per layer (its position only moves forward), and counts what it examines
against ``SalvageLimits.max_search_bytes``. Salvage is add-only: a format starts a
search only where its normal walk stopped on damage, so every member the default
lists comes first and unchanged.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from archivey.diagnostics import (
    DiagnosticCode,
    RegionSkippedContext,
    SalvageScanContext,
    SalvageUnavailableContext,
)
from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.internal.bomb_tracker import AlwaysStopResourceLimitError
from archivey.internal.logs import backends as logger
from archivey.internal.overrides import override
from archivey.internal.streams.callers_source import from_source_callback
from archivey.terminal import escape_control_chars

if TYPE_CHECKING:
    from archivey.config import SalvageLimits
    from archivey.formats import ForwardStream, ReaderContext
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.types import ArchiveMember

# Bytes one window of the search holds beyond the overlap. 1 MiB keeps a read large
# enough to be cheap on a file and on a range-request source, and small enough to hold.
WINDOW_SIZE = 1 << 20
# The first window of each search call; each later one doubles, up to WINDOW_SIZE. A
# walk that lists a found member it cannot confirm searches again just after it, and
# the next header is often close: a search that started with a full window would
# read, and on a decoded layer decode and charge, a megabyte for each such restart.
FIRST_WINDOW_SIZE = 4 << 10

# The layer name of the archive's own bytes, as opposed to a codec's decoded stream.
ARCHIVE_LAYER = "archive"

_local = threading.local()


@dataclass(frozen=True)
class SalvageRequest:
    """What the opener of a reader says about salvage: whether the caller asked for
    it, whether the backend that builds the reader has a salvage search
    (``ReadBackend.SUPPORTS_SALVAGE``), and whether the reader reads again what an
    earlier reader of the same archive reported (``repeat``): an inner archive
    built again by a walk started over to reach member data. A repeat reader
    salvages as the first one did, and records none of the salvage codes, since
    the first one recorded them."""

    requested: bool = False
    supported: bool = False
    repeat: bool = False
    # The archive's start is not confirmed by its bytes (detection did not find the
    # format there): the reader treats a first header that fails at offset 0 as
    # damage at 0 and searches from 0. Set by the lost-start opener.
    lost_start: bool = False


_NO_REQUEST = SalvageRequest()


@contextmanager
def requesting_salvage(
    requested: bool,
    *,
    supported: bool,
    repeat: bool = False,
    lost_start: bool = False,
) -> Generator[None]:
    """Let the next reader built on this thread take this salvage request.

    ``open_archive`` wraps the backend's ``open_read`` in it with the caller's
    ``salvage=``, and ``ReaderContext.open_nested`` wraps the inner reader's build
    with the outer reader's request, so an archive archivey opens inside another
    salvages when the outer one was asked to. The first reader built in the block
    takes the request (:func:`take_salvage_request`); one a password provider or a
    diagnostic callback opens later in the same open does not. ``repeat`` marks a
    reader that reads again what an earlier one reported (:class:`SalvageRequest`).
    """
    before = getattr(_local, "request", _NO_REQUEST)
    _local.request = SalvageRequest(
        requested=requested,
        supported=supported,
        repeat=repeat,
        lost_start=requested and lost_start,
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

    A format calls :func:`search_forward` with this state, and :meth:`finish` when its
    walk ends, which records the ``report_limit`` record if any range went
    unreported. The budget, the records and the layer positions are the listing
    walk's: only that walk charges and records. A listing walk started over after a
    failure calls :meth:`restart` first. Any other walk from the start, such as one
    a random-access reader runs to reach a member's data, possibly while the listing
    walk runs, searches with a :class:`QuietSalvageState` of its own, so it leaves
    this state as it is.

    ``repeat`` is ``True`` on a :class:`QuietSalvageState`: a reader built with one
    reads again what an earlier reader reported, and so does every reader it opens
    inside itself (``SalvageRequest.repeat``).
    """

    repeat = False

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
        # Whether the reader starts with a search from offset 0 when its first
        # header fails there (``SalvageRequest.lost_start``).
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
        layer's position to ``stop``. The position never moves back: a byte behind it
        was examined already, and examining it again would count it twice."""
        if stop < self.position(layer) or stop < start:
            raise AssertionError(
                f"the {layer} search position would move back, from "
                f"{self.position(layer)} to {stop}"
            )
        self.searched_bytes += stop - start
        self._positions[layer] = stop

    def record_region(
        self,
        *,
        layer: str,
        offset: int,
        length: int | None,
    ) -> None:
        """Record one ``ARCHIVE_REGION_SKIPPED`` with ``reason="no_header"``, within
        ``max_reported_regions``. A range past the cap is counted for :meth:`finish`
        instead."""
        if self._reported_regions >= self.limits.max_reported_regions:
            if self._first_unreported is None:
                self._first_unreported = (layer, offset)
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
            ),
            f"Salvage skipped {length} {'byte' if length == 1 else 'bytes'} at offset "
            f"{offset}{_in_layer(layer)} of "
            f"the {self._format_name} archive: no header passes the format's checks "
            "in it.",
        )

    def record_search_limit(
        self, *, layer: str, started_at: int, examined_from: int, stopped_at: int
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
            ),
            f"Salvage stopped searching {searched}the {self._format_name} "
            f"archive: SalvageLimits.max_search_bytes "
            f"({self.limits.max_search_bytes}) ran out. The search started at offset "
            f"{started_at} and {stop}; nothing after it is listed.",
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
    first_window_size: int = FIRST_WINDOW_SIZE,
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

    The first window holds ``first_window_size`` bytes (``window_size`` when that is
    smaller), and each later one twice the one before, up to ``window_size``: a call
    reads about twice the bytes up to the header it finds, plus one header, not a
    full window, so a search started again just after a header costs what it reads.

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
    if end is not None and (end < start or end < state.position(layer)):
        raise AssertionError(
            f"search end {end} is before the start {start} or before the "
            f"{layer} search position {state.position(layer)}"
        )
    if state.limit_reached:
        return SearchResult(found=None, limit_reached=True)
    step = search.step
    region_start = max(start, state.position(layer))
    if end is not None and region_start >= end:
        # An empty range: nothing to examine or record, and the position stays.
        return SearchResult(found=None)
    # The first candidate position at or after region_start.
    pos = base + -(-(region_start - base) // step) * step
    if end is not None and pos >= end:
        # No candidate position is left before the end: nothing to examine.
        state._examined(layer, end, end)
        _record_no_header(state, layer, region_start, end)
        return SearchResult(found=None)
    examined_from = pos
    remaining = state.remaining_bytes()
    if remaining == 0:
        # Stop before reading: a read could only fetch bytes nobody may examine.
        state.limit_reached = True
        state.record_search_limit(
            layer=layer, started_at=region_start, examined_from=pos, stopped_at=pos
        )
        return SearchResult(found=None, limit_reached=True)
    if end is None and pos > region_start:
        # The bytes before the first candidate position are not examined, but only
        # a read shows whether the layer has them: a layer that ends among them
        # skips only what it holds.
        gap = read_at(region_start, pos - region_start)
        if len(gap) < pos - region_start:
            layer_end = region_start + len(gap)
            state._examined(layer, layer_end, layer_end)
            _record_no_header(state, layer, region_start, layer_end)
            return SearchResult(found=None)
    # With a budget, no read goes past the last header the budget lets the search
    # reach: the bytes it may examine, plus the rest of a header that starts there.
    read_limit = (
        None if remaining is None else pos + remaining + search.max_header_size - 1
    )

    window = min(first_window_size, window_size)
    span = window + search.max_header_size - 1
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
            examined = buf[: stop - 1 + search.max_header_size]
            found = search.find_header(examined, 0, stop)
            if found is not None:
                if found < 0 or found % step or found >= stop:
                    raise AssertionError(
                        f"find_header returned {found}, which is not a candidate "
                        f"position (a multiple of {step} at or after 0 and before "
                        f"{stop})"
                    )
                header_at = pos + found
                after = header_at + step
                state._examined(layer, pos, min(after, buf_end) if at_end else after)
                if header_at > region_start:
                    state.record_region(
                        layer=layer,
                        offset=region_start,
                        length=header_at - region_start,
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
            if window < window_size:
                window = min(window * 2, window_size)
                span = window + search.max_header_size - 1

        if at_end and pos >= buf_end and not budget_bound:
            # The layer ends here, so no later search of it has anything to examine,
            # even when this one examined no candidate position.
            state._examined(layer, buf_end, buf_end)
            _record_no_header(state, layer, region_start, buf_end)
            return SearchResult(found=None)
        if budget_bound:
            state.limit_reached = True
            state.record_search_limit(
                layer=layer,
                started_at=region_start,
                examined_from=examined_from,
                stopped_at=pos,
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
    state: SalvageState, layer: str, region_start: int, layer_end: int
) -> None:
    if layer_end > region_start:
        state.record_region(
            layer=layer,
            offset=region_start,
            length=layer_end - region_start,
        )


def noting_search_limit(state: SalvageState, error: ArchiveyError) -> ArchiveyError:
    """The damage error that ends a salvage pass: ``error`` itself, or, when
    ``SalvageLimits.max_search_bytes`` stopped a search, a copy of it whose message
    says so."""
    if not state.limit_reached:
        return error
    noted = copy.copy(error)
    raw = (
        f"{error.raw_message}; salvage stopped there: SalvageLimits.max_search_bytes "
        f"({state.limits.max_search_bytes}) stopped the search"
    )
    noted.raw_message = raw
    noted.message = escape_control_chars(raw)
    noted.args = (noted.message, *error.args[1:])
    return noted


class QuietSalvageState(SalvageState):
    """The salvage state of a walk started over to reach member data: it searches as
    the listing walk did, so it finds the same members, and records nothing, since
    the listing walk recorded it all."""

    repeat = True

    @override
    def _emit(self, context: RegionSkippedContext, message: str) -> None:
        pass


# The step of a probe that reads forward through a decoded layer (``WalkSalvage``).
_PROBE_STEP = 1 << 20


class WalkSalvage:
    """What a sequential reader's walk uses to search past damage in the layer it
    reads: built by archivey for each layer a random-access walk reads, and handed
    out by ``ReaderContext._salvage(stream)`` (``None`` when the reader does not
    salvage, or reads the layer forward only).

    ``read_at`` and :meth:`search` read the layer through views of their own and do
    not move the walk's stream; :meth:`seek` moves it, back as well as forward, to a
    header the search found. :meth:`found` records ``MEMBER_FOUND_BY_SCAN`` for a
    member about to be yielded. When the walk ends, :meth:`ending` gives the error
    to raise, after :meth:`SalvageState.finish`.
    """

    def __init__(
        self,
        *,
        state: SalvageState,
        layer: str,
        size: int | None,
        read_at: Callable[[int, int], bytes],
        open_reader: Callable[
            [int], tuple[Callable[[int, int], bytes], Callable[[], None]]
        ],
        seek: Callable[[int], None],
        position: Callable[[], int],
        report_found: Callable[[ArchiveMember, SalvageScanContext, str], None] | None,
        format_name: str,
    ) -> None:
        self.state = state
        self.layer = layer
        self.size = size
        self._read_at = read_at
        self._open_reader = open_reader
        self.seek = seek
        self._position = position
        # On a layer of unknown size: how far the probes have read, and the layer's
        # end once one reached it (``read_at``).
        self._held_to = 0
        self._end: int | None = None
        # The member about to be yielded is one the walk could not confirm, so it
        # moves back into its data after it (``moves_back``).
        self._moves_back = False
        self._report_found = report_found
        self._format_name = format_name

    @property
    def lost_start(self) -> bool:
        """The reader was asked to find its first header by a search from 0."""
        return self.state.lost_start

    def search(
        self, search: HeaderSearch, *, start: int, base: int = 0
    ) -> SearchResult:
        """:func:`search_forward` over this layer from ``start``. A start past the
        layer's end (a header's sizes that point past it) has nothing left to
        search: the search starts at the end."""
        self._moves_back = False
        if self.size is not None:
            start = min(start, self.size)
        read, close = self._open_reader(start)
        try:
            return search_forward(
                self.state,
                read,
                search,
                start=start,
                end=self.size,
                base=base,
                layer=self.layer,
            )
        finally:
            close()

    def moves_back(self) -> bool:
        """Whether the walk moves back into the data of the member it yielded last,
        to search on, so the skip past that data can wait (``_skip_data`` in the
        adapter). Asked once per member: it answers ``False`` again after."""
        moves_back, self._moves_back = self._moves_back, False
        return moves_back

    def after(self, header: int) -> int:
        """Where a search starts that must not find the header at ``header`` again
        (a member past the damage that nothing confirms): the search rounds it up to
        the next candidate position."""
        return header + 1

    def read_at(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes of the layer from ``offset``, for a check of a header
        the search did not read: the next one, or the first one's magic.

        On a decoded layer of unknown size, a probe past the bytes known to be there
        reads forward to ``offset`` rather than seeking there. A decoder that has not
        reached its end takes a seek to any offset, and the decoded-bytes budget would
        charge the whole gap, up to an offset a damaged size field gave, without
        decoding it. The walk keeps how far its probes have read (``_held_to``) and,
        once one reaches it, the layer's end (``_end``): a later probe reads forward
        only past ``_held_to``, a probe behind it reads its bytes where they are, and
        a probe at or past ``_end`` reads nothing. So the walk's probes together read
        forward through the layer at most once, however many headers the search finds.

        A probe the decoding limits refuse (the ratio limit, or the listing's budget)
        reads as nothing: the candidate fails its check, and the pass ends in the first
        damage, not in the limit. So does a probe past damage in a decoded layer (a
        codec stream cut or corrupt before ``offset``): the layer ends there for the
        probes. An exception ``on_source_read`` raised is not damage and propagates.
        """
        if self.size is not None:
            return self._read_at_refused_as_nothing(offset, n)
        if n <= 0 or (self._end is not None and offset >= self._end):
            return b""
        start = max(self._position(), self._held_to)
        if offset <= start:
            data = self._read_at_refused_as_nothing(offset, n)
        else:
            data = self._read_forward(start, offset, n)
        if data:
            self._held_to = max(self._held_to, offset + len(data))
        else:
            # The layer ends at ``offset`` or before, or the limits refuse a read
            # there: a later probe there reads nothing either, without a read.
            self._end = offset if self._end is None else min(self._end, offset)
        return data

    def _read_at_refused_as_nothing(self, offset: int, n: int) -> bytes:
        try:
            return self._read_at(offset, n)
        except AlwaysStopResourceLimitError:
            return b""
        except CorruptionError as exc:
            # A decoded layer damaged before ``offset`` (a codec stream cut or
            # corrupt there): the probe reads nothing, as at the layer's end. The
            # walk's own read reaches that damage, if anything does.
            if not self.is_damage(exc):
                raise
            return b""

    def _read_forward(self, start: int, offset: int, n: int) -> bytes:
        """``read_at`` past ``start``, the furthest offset known to be there: read
        forward from it, noting how far the layer goes."""
        at = start
        read, close = self._open_reader(start)
        try:
            while at < offset:
                got = len(read(at, min(offset - at, _PROBE_STEP)))
                if not got:
                    return b""
                at += got
                self._held_to = max(self._held_to, at)
            return read(offset, n)
        except AlwaysStopResourceLimitError:
            return b""
        except CorruptionError as exc:
            # The decoded layer is damaged past ``at``: it ends there for the
            # probes, so a later one does not decode up to the damage again.
            if not self.is_damage(exc):
                raise
            self._end = at if self._end is None else min(self._end, at)
            return b""
        finally:
            close()

    def holds(self, end: int) -> bool:
        """Whether the layer has bytes up to ``end``: a member past the damage whose
        data runs past the layer's end is not listed, since reading it would stop the
        pass. On a decoded layer of unknown size, ``end`` within what the probes have
        read is held without a read, and a probe the limits refuse is not held."""
        if self.size is not None:
            return end <= self.size
        if end <= max(self._held_to, self._position()):
            return True
        return len(self.read_at(end - 1, 1)) == 1

    def found(
        self,
        member: ArchiveMember,
        *,
        offset: int,
        confirmed: bool,
        unchecked: tuple[str, ...] = ("position",),
        searched: bool = True,
        held: bool = False,
    ) -> None:
        """Record ``MEMBER_FOUND_BY_SCAN`` for ``member``, before it is yielded:
        found by the search (``searched``), walked on to after a member the search
        found, or (``held``) a hard link the walk read whole before the damage and
        held for data that no link before the damage carried (``"held_link"``)."""
        if not held:
            # A held link has no data to move back into.
            self._moves_back = not confirmed
        if self._report_found is None:
            return
        if held:
            where = (
                "as a hard link: the walk read its header whole before the damage, "
                "but its data never came with a later link before the damage"
            )
        elif searched:
            where = "by a header search"
        else:
            where = "by walking on from a member a header search found"
        if held:
            # Size 0, read whole by the normal walk: no sizes of its own to check.
            how = (
                "the header after it passes too"
                if confirmed
                else "the header after it is the damage"
            )
        elif confirmed:
            how = "the header after its data passes too"
        else:
            how = "nothing after it confirms it, so its sizes are unchecked"
        self._report_found(
            member,
            SalvageScanContext(
                member_name=member.name,
                format=self._format_name,
                method="held_link" if held else "header_search",
                offset=offset,
                confirmed=confirmed,
                unchecked=unchecked,
            ),
            f"Salvage found {self._format_name} member {member.name!r} {where}, "
            f"at offset {offset}{_in_layer(self.layer)}; {how}.",
        )

    @staticmethod
    def is_damage(error: BaseException) -> bool:
        """Whether ``error``, a ``CorruptionError`` the walk caught, is damage the
        search may go past. An exception ``ArchiveyConfig.on_source_read`` raised is
        the caller's own, whatever its type: the walk raises it unchanged."""
        return not from_source_callback(error)

    def ending(self, error: ArchiveyError) -> ArchiveyError:
        """Finish the walk's salvage records and give the damage error to raise."""
        self.state.finish()
        return noting_search_limit(self.state, error)


def walk_salvage(context: ReaderContext, stream: ForwardStream) -> WalkSalvage | None:
    """The salvage search of the layer ``stream`` reads, or ``None`` when the caller did
    not ask for salvage. A reader's walk calls this once, before its first header.

    It is the one place a reader reaches the context's salvage hook, so that readers
    bound for a plugin package read no private attribute of ``ReaderContext``. Plugins
    get salvage later through a hook of their own (openspec/changes/salvage-mode,
    design decision 4)."""
    search = context._salvage
    return search(stream) if search is not None else None
