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

import copy
import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from archivey.diagnostics import (
    DiagnosticCode,
    RegionSkippedContext,
    SalvageScanContext,
    SalvageUnavailableContext,
)
from archivey.exceptions import ArchiveyError, ResourceLimitError
from archivey.internal.logs import backends as logger
from archivey.internal.overrides import override
from archivey.terminal import escape_control_chars

if TYPE_CHECKING:
    from archivey.config import SalvageLimits
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.types import ArchiveMember

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
    # The archive's start is not confirmed by its bytes (detection did not find the
    # format there): the reader treats a first header that fails at offset 0 as
    # damage at 0 and searches from 0. Set by the lost-start opener.
    lost_start: bool = False


_NO_REQUEST = SalvageRequest()


@contextmanager
def requesting_salvage(
    requested: bool, *, supported: bool, lost_start: bool = False
) -> Generator[None]:
    """Let the next reader built on this thread take this salvage request.

    ``open_archive`` wraps the backend's ``open_read`` in it with the caller's
    ``salvage=``, and ``ReaderContext.open_nested`` wraps the inner reader's build
    with the outer reader's request, so an archive archivey opens inside another
    salvages when the outer one was asked to. The first reader built in the block
    takes the request (:func:`take_salvage_request`); one a password provider or a
    diagnostic callback opens later in the same open does not.
    """
    before = getattr(_local, "request", _NO_REQUEST)
    _local.request = SalvageRequest(
        requested=requested,
        supported=supported,
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
            f"Salvage skipped {length} bytes at offset {offset}{_in_layer(layer)} of "
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


def emit_salvage_unavailable(
    collector: DiagnosticCollector,
    *,
    archive_name: str | None,
    format_name: str,
    forward_only: bool = False,
) -> None:
    """Record ``SALVAGE_UNAVAILABLE`` for a reader asked to salvage whose format has
    no salvage search, or, with ``forward_only``, whose search needs to move back in
    a layer this reader reads forward only (an archive inside another one)."""
    why = (
        "this reader reads its archive forward only, inside another archive, and the "
        "search needs to go back"
        if forward_only
        else "archivey has no salvage search for this format"
    )
    collector.emit(
        code=DiagnosticCode.SALVAGE_UNAVAILABLE,
        message=(
            f"salvage=True has no effect on {format_name}: {why}, so the archive is "
            "read as it is without it."
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
    search reads nothing at or past it, and an ``end`` before ``start`` or before the
    layer's search position is a bug (``AssertionError``). Under a budget the search
    reads no further than the last header the budget lets it reach (one byte more
    when ``end`` is not known, to see the layer's end), and with no budget left it
    reads nothing.

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
    # With a budget, no read goes past the last header the budget lets the search
    # reach: the bytes it may examine, plus the rest of a header that starts there.
    # With no ``end``, one byte more: only a short read shows the layer ends there,
    # and a budget that pays for every byte left is then no limit.
    read_limit = (
        None
        if remaining is None
        else pos + remaining + search.max_header_size - (0 if end is None else 1)
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
            # Below ``pos`` when the budget cannot pay for one more position.
            if last_affordable < last or last_affordable < pos:
                last = min(last, last_affordable)
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
            state.record_search_limit(
                layer=layer,
                started_at=region_start,
                examined_from=examined_from,
                stopped_at=pos,
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

    @override
    def _emit(self, context: RegionSkippedContext, message: str) -> None:
        pass


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
        report_found: Callable[[ArchiveMember, SalvageScanContext, str], None] | None,
        format_name: str,
    ) -> None:
        self.state = state
        self.layer = layer
        self.size = size
        self._read_at = read_at
        self._open_reader = open_reader
        self.seek = seek
        self._report_found = report_found
        self._format_name = format_name

    @property
    def lost_start(self) -> bool:
        """The reader was asked to find its first header by a search from 0."""
        return self.state.lost_start

    def search(
        self, search: HeaderSearch, *, start: int, base: int = 0
    ) -> SearchResult:
        """:func:`search_forward` over this layer from ``start``."""
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

    def after(self, header: int) -> int:
        """Where a search starts that must not find the header at ``header`` again
        (a member past the damage that nothing confirms): the search rounds it up to
        the next candidate position."""
        return header + 1

    def read_at(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes of the layer from ``offset``, for a check of a header
        the search did not read: the next one, or the first one's magic.

        A probe the decoding limits refuse (a decoded layer read past what the
        archive's size allows, at an offset a damaged size field gave) reads as
        nothing: the candidate fails its check, and the pass ends in the first
        damage, not in the limit.
        """
        try:
            return self._read_at(offset, n)
        except ResourceLimitError:
            return b""

    def holds(self, end: int) -> bool:
        """Whether the layer has bytes up to ``end``: a found member whose data runs
        past the layer's end is not listed, since reading it would stop the pass. On
        a decoded layer of unknown size, a probe the limits refuse is not held."""
        if self.size is not None:
            return end <= self.size
        return end <= 0 or len(self.read_at(end - 1, 1)) == 1

    def found(
        self,
        member: ArchiveMember,
        *,
        offset: int,
        confirmed: bool,
        unchecked: tuple[str, ...] = ("position",),
        searched: bool = True,
    ) -> None:
        """Record ``MEMBER_FOUND_BY_SCAN`` for ``member``, before it is yielded:
        found by the search (``searched``), or walked on to after a member the search
        found."""
        if self._report_found is None:
            return
        where = (
            "by a header search"
            if searched
            else "walking on after a member a header search found"
        )
        how = (
            "the header after its data passes too"
            if confirmed
            else "nothing after it confirms it, so its sizes are unchecked"
        )
        self._report_found(
            member,
            SalvageScanContext(
                member_name=member.name,
                format=self._format_name,
                offset=offset,
                confirmed=confirmed,
                unchecked=unchecked,
            ),
            f"Salvage found {self._format_name} member {member.name!r} {where}, "
            f"at offset {offset}{_in_layer(self.layer)}; {how}.",
        )

    def ending(self, error: ArchiveyError) -> ArchiveyError:
        """Finish the walk's salvage records and give the damage error to raise."""
        self.state.finish()
        return noting_search_limit(self.state, error)
