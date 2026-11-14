"""The nest a reader belongs to: an archive's reader and every reader opened inside it.

A reader joins a nest two ways, both learned while it is built, on the building
thread:

- **Format nesting** (``ReaderContext.open_nested``), under :func:`reading_inside`.
  The levels run at once and every inner byte also passes through the outer reader,
  so the inner reader shares more than the totals (maintainer ruling, 2026-11-08:
  "charge across the nesting"):

  - its listing tracker charges what it keeps beyond its members to the outermost
    tracker (:class:`~archivey.internal.listing_limits.ListingLimitTracker`);
  - its ratio guards divide by the outermost archive's compressed bytes
    (``BaseArchiveReader._trusted_source_size`` and ``_live_consumed``);
  - its ``max_decoder_memory`` is what the outer levels left
    (``_PluginAdapter._nested_config``).

- **Caller nesting** (``open_archive(..., parent=reader)``), under :func:`joining`.
  The reader keeps every limit it would have on its own.

Either way the reader draws from the nest's :class:`NestAccount`, which the outermost
reader creates and which holds three totals for the whole nest: decoded bytes
(``DecoderLimits.max_nest_decoded_bytes``), members (``ListingLimits.max_members``),
and the nest ratio (``DecoderLimits.max_ratio`` times the outermost archive's size).
Each reader draws through a :class:`NestDraws` of its own, whose caps are the stricter
of the outermost reader's config and its own: a child can tighten a nest total, never
loosen it.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig
    from archivey.internal.base_reader import BaseArchiveReader

# How many archives deep a nest may go below its outermost archive, both kinds of
# nesting counted: nine archives in a chain, the outermost included. The formats that
# nest go one level (a ``.deb``'s tars) or two (a ``.pkg``'s XAR payload); the bound
# turns a walk that keeps naming its own format into an archivey error before
# Python's recursion limit does, since each level holds a reader and a few generator
# frames.
MAX_NESTED_DEPTH = 8

_local = threading.local()


@contextmanager
def reading_inside(outer: BaseArchiveReader) -> Generator[None]:
    """Build readers inside ``outer`` on this thread while the block runs
    (``ReaderContext.open_nested``)."""
    before = getattr(_local, "outer", None)
    _local.outer = outer
    try:
        yield
    finally:
        _local.outer = before


def enclosing_reader() -> BaseArchiveReader | None:
    """The reader a reader built now reads inside (``open_nested``), or ``None``."""
    return getattr(_local, "outer", None)


@contextmanager
def joining(parent: BaseArchiveReader | None) -> Generator[None]:
    """Let the next reader built on this thread join ``parent``'s nest
    (``open_archive(parent=)``).

    The first reader built in the block takes the link (:func:`take_joining_parent`),
    so a reader that a password provider or an ``on_diagnostic`` callback opens later
    in the same open stays outside the nest. ``open_archive`` wraps only the backend's
    ``open_read`` in it and checks afterwards that the reader it returns took the link.
    """
    before = getattr(_local, "parent", None)
    _local.parent = parent
    try:
        yield
    finally:
        _local.parent = before


def take_joining_parent() -> BaseArchiveReader | None:
    """The parent a reader built now joins, consumed so no later reader takes it."""
    parent = getattr(_local, "parent", None)
    _local.parent = None
    return parent


def _stricter(a: int | None, b: int | None) -> int | None:
    """The tighter of two caps, ``None`` meaning no cap."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _stricter_ratio(a: float | None, b: float | None) -> float | None:
    """The tighter of two ratio caps, ``None`` meaning no cap."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _nest_error(message: str) -> Exception:
    """The error a nest total raises: a ``ResourceLimitError`` that stops an
    extraction, as the archive-wide ratio does, rather than failing one member."""
    # Imported here: ``bomb_tracker`` imports the config's limits.
    from archivey.internal.bomb_tracker import AlwaysStopResourceLimitError

    return AlwaysStopResourceLimitError(message)


class NestAccount:
    """The totals one nest shares, owned by its outermost reader.

    It counts every decoded byte, every member, and the nest ratio's sum, from every
    reader of the nest on every thread, closed readers included: it outlives the
    readers that hold it. Its caps live on each reader's :class:`NestDraws`.
    """

    __slots__ = (
        "_ask_root_size",
        "_decoded_bytes",
        "_lock",
        "_members",
        "_ratio_readers",
        "_ratio_sum",
        "_root_size",
    )

    def __init__(self, root_size: Callable[[], int | None]) -> None:
        self._lock = threading.Lock()
        self._decoded_bytes = 0
        self._members = 0
        self._ratio_sum = 0
        # How many readers have added to the ratio sum. One alone is never judged:
        # its own ratio rules hold the same bytes against the same size.
        self._ratio_readers = 0
        self._ask_root_size = root_size
        self._root_size: int | None = None

    @property
    def decoded_bytes(self) -> int:
        """Bytes decoded so far by every reader of the nest."""
        return self._decoded_bytes

    @property
    def members(self) -> int:
        """Members listed so far by the readers of the nest that draw them."""
        return self._members

    @property
    def ratio_sum(self) -> int:
        """The nest ratio's sum: each reader's one-pass high-water mark, added up."""
        return self._ratio_sum

    def root_size(self) -> int | None:
        """The outermost archive's trusted size, asked once it is known."""
        if self._root_size is None:
            self._root_size = self._ask_root_size()
        return self._root_size


class NestDraws:
    """One reader's draws on its nest's :class:`NestAccount`, under caps that are the
    stricter of the outermost reader's config and this reader's own.

    Answers the calls :class:`~archivey.internal.streams.counting.BudgetDrawStream`
    and the direct draw sites make: decoded bytes against ``max_nest_decoded_bytes``,
    members against ``max_members``, and this reader's part of the nest ratio.

    A read that could cross the byte cap asks the decoder for at most one byte past
    what is left, so the read that crosses it decodes one byte more than the cap. That
    holds per read, a buffer's read-ahead over a source that cannot seek included;
    readers on other threads size their reads against the same room, so each can
    overshoot by one read.
    """

    __slots__ = (
        "_account",
        "_floor",
        "_mark",
        "_max_decoded_bytes",
        "_max_members",
        "_max_ratio",
    )

    def __init__(
        self,
        account: NestAccount,
        *,
        root: ArchiveyConfig,
        own: ArchiveyConfig,
        judges_ratio: bool,
    ) -> None:
        self._account = account
        self._max_decoded_bytes = _stricter(
            root.decoder_limits.max_nest_decoded_bytes,
            own.decoder_limits.max_nest_decoded_bytes,
        )
        self._max_members = _stricter(
            root.listing_limits.max_members, own.listing_limits.max_members
        )
        # ``None`` for a reader that adds nothing to the nest ratio: one
        # ``open_nested`` builds, whose bytes are in its outer reader's number.
        self._max_ratio = (
            _stricter_ratio(root.decoder_limits.max_ratio, own.decoder_limits.max_ratio)
            if judges_ratio
            else None
        )
        # A lower floor judges sooner: the stricter of the two, as for the caps.
        self._floor = min(
            root.decoder_limits.ratio_activation_threshold,
            own.decoder_limits.ratio_activation_threshold,
        )
        self._mark = 0  # this reader's one-pass high-water mark

    @property
    def account(self) -> NestAccount:
        return self._account

    @property
    def max_decoded_bytes(self) -> int | None:
        return self._max_decoded_bytes

    @property
    def max_members(self) -> int | None:
        return self._max_members

    @property
    def max_ratio(self) -> float | None:
        """The nest ratio cap this reader's growth is judged against, or ``None``."""
        return self._max_ratio

    # --- Decoded bytes --------------------------------------------------------------

    def _bytes_room(self) -> int | None:
        """Bytes left before the cap (``None``: no cap). Read without the lock: it
        only sizes a read, and ``_draw_bytes`` judges."""
        cap = self._max_decoded_bytes
        if cap is None:
            return None
        return max(0, cap - self._account._decoded_bytes)

    def _check_bytes_left(self) -> None:
        """Raise if the nest has already decoded past the cap, so a read after the
        one that crossed it decodes nothing."""
        cap = self._max_decoded_bytes
        if cap is not None and self._account._decoded_bytes > cap:
            self._draw_bytes(0, force=True)

    def _read_cap(self, want: int) -> int:
        """How many of ``want`` bytes to decode next: all of them while there is room,
        else one past what is left, so the draw of that read raises. Raises at once if
        the nest is already spent."""
        self._check_bytes_left()
        room = self._bytes_room()
        return want if room is None else min(want, room + 1)

    def _draw_bytes(self, n: int, *, force: bool = False) -> None:
        """Count ``n`` decoded bytes; raise once the total passes the cap. The bytes
        stay counted: they were decoded. ``force`` judges the total even for none."""
        if n <= 0 and not force:
            return
        account = self._account
        with account._lock:
            account._decoded_bytes += n
            total = account._decoded_bytes
        cap = self._max_decoded_bytes
        if cap is not None and total > cap:
            raise _nest_error(
                f"Nest limit reached: max_nest_decoded_bytes={cap} (the archives of "
                f"this nest have decoded {total} bytes)"
            )

    def _refuse_bytes(self, n: int, what: str) -> None:
        """Raise for ``n`` bytes ``what`` would decode that do not fit, drawing none:
        a step refused before its decoder moves decoded nothing."""
        raise _nest_error(
            f"Nest limit reached: max_nest_decoded_bytes={self._max_decoded_bytes} "
            f"(the archives of this nest have decoded {self._account._decoded_bytes} "
            f"bytes; {what} would decode {n} more)"
        )

    def _draw_whole(self, n: int, what: str) -> None:
        """Draw ``n`` bytes ``what`` decodes in one step that cannot stop part way,
        before it runs: refused, drawing nothing, when they do not fit."""
        self._check_bytes_left()
        room = self._bytes_room()
        if room is not None and n > room:
            self._refuse_bytes(n, what)
        self._draw_bytes(n)

    # --- Members --------------------------------------------------------------------

    def _draw_members(self, n: int) -> None:
        """Count ``n`` listed members; raise, counting none, past the cap."""
        account = self._account
        cap = self._max_members
        with account._lock:
            total = account._members + n
            if cap is not None and total > cap:
                raise _nest_error(
                    f"Nest limit reached: max_members={cap} (the archives of this "
                    f"nest would list {total} members)"
                )
            account._members = total

    # --- The nest ratio -------------------------------------------------------------

    def report_pass(self, decoded: int) -> None:
        """Record that this reader has decoded ``decoded`` bytes of its archive in one
        pass; add the growth of its high-water mark to the nest ratio's sum and judge
        it. A reader that adds nothing to the nest ratio ignores the call."""
        cap = self._max_ratio
        if cap is None or decoded <= self._mark:
            return
        account = self._account
        with account._lock:
            if decoded <= self._mark:
                return
            if self._mark == 0:
                account._ratio_readers += 1
            account._ratio_sum += decoded - self._mark
            self._mark = decoded
            total = account._ratio_sum
            readers = account._ratio_readers
        if readers < 2 or total <= self._floor:
            return
        size = account.root_size()
        if size is None or size <= 0:
            return
        if total / size > cap:
            raise _nest_error(
                f"Nest decompression ratio {total / size:.0f}:1 exceeds limit "
                f"max_ratio={cap:.0f}:1 (the archives of this nest have decoded "
                f"{total} bytes in one pass each, from an outermost archive of "
                f"{size} bytes)"
            )
