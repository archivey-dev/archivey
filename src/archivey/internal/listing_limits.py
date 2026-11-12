"""Retained metadata-byte accounting for :class:`~archivey.config.ListingLimits`.

A listing bomb is an archive whose member list, not its data, costs too much memory:
millions of members, or huge names, comments or extra fields. Each reader owns one
:class:`ListingLimitTracker` and charges every member to it as the listing registers
it, so ``max_members`` and ``max_metadata_bytes`` refuse the archive while it is being
listed. Parsers that keep metadata before members exist (7z, RAR, ISO) weigh it with
:func:`text_bytes` and :func:`check_metadata_budget` by the same rules.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping

from archivey.config import Budget, ListingLimits
from archivey.exceptions import ResourceLimitError
from archivey.internal.bomb_tracker import AlwaysStopResourceLimitError
from archivey.types import ArchiveMember


def _str_retained_bytes(value: str) -> int:
    """Cheap upper bound on UTF-8 size for listing bomb accounting.

    ``max_metadata_bytes`` is a safety cap, not a precise allocator — encoding
    every field on the open+list hot path is wasted work. UTF-8 is at most 4
    bytes per Unicode code point, so ``4 * len(s)`` never under-counts a
    Unicode name bomb; ASCII uses ``len(s)`` (exact, the common case).
    """
    n = len(value)
    return n if value.isascii() else n * 4


def _retained_bytes(value: object) -> int:
    """Retained size of a ``str``/``bytes`` value; anything else weighs nothing."""
    if isinstance(value, str):
        return _str_retained_bytes(value)
    if isinstance(value, bytes):
        return len(value)
    return 0


def text_bytes(value: str | bytes | None) -> int:
    """Retained weight of one stored text field, by the rule :class:`ListingLimitTracker`
    uses for member fields: ``bytes`` by length, ``str`` per :func:`_str_retained_bytes`.

    For a parser that weighs what it keeps before members are registered (7z, RAR).
    """
    return _retained_bytes(value)


# What one entry of a nested dict keyed by a number retains beyond its value's bytes:
# the key object, the dict slot and the value's object header. Measured 69 bytes for
# a ZIP extra field with one byte of data (CPython 3.11, int key over 256).
NUMBERED_ENTRY_BYTES = 72


def _extra_bytes(extra: Mapping[str, object]) -> int:
    """Sum retained ``str``/``bytes`` lengths in ``extra`` (one-level nested dicts).

    Values count at both levels; keys count only inside a nested dict. A top-level
    key is a format-defined literal (``zip.compress_type``, ``tar.type``) that no
    archive sizes, so charging it would only tighten the cap by a per-format toll.
    A nested key is archive text: TAR copies every PAX record into
    ``extra["tar.pax_headers"]``, where the keyword is as attacker-sized as the value.
    A nested key that is not text (a ZIP extra field's tag in
    ``extra["zip.extra_fields"]``) weighs ``NUMBERED_ENTRY_BYTES``: the archive sets
    how many entries there are, and an empty value would otherwise weigh nothing.
    """
    total = 0
    for value in extra.values():
        if type(value) is int:
            # The common value (``zip.compress_type``, ``tar.type``): weighs nothing.
            continue
        if isinstance(value, dict):
            for nested_key, nested in value.items():
                key_bytes = (
                    _retained_bytes(nested_key)
                    if isinstance(nested_key, (str, bytes))
                    else NUMBERED_ENTRY_BYTES
                )
                total += key_bytes + _retained_bytes(nested)
        else:
            total += _retained_bytes(value)
    return total


def member_metadata_bytes(member: ArchiveMember) -> int:
    """Retained metadata weight for one member (listing bomb accounting)."""
    # Hot path for every listing: most optional string fields are None, and the
    # ``_str_retained_bytes`` rule is inlined for the name.
    name = member.name
    total = len(name) if name.isascii() else len(name) * 4
    raw_name = member.raw_name
    if raw_name is not None:
        total += len(raw_name)
    comment = member.comment
    if comment is not None:
        total += _str_retained_bytes(comment)
    link_target = member.link_target
    if link_target is not None:
        total += _str_retained_bytes(link_target)
    uname = member.uname
    if uname is not None:
        total += _str_retained_bytes(uname)
    gname = member.gname
    if gname is not None:
        total += _str_retained_bytes(gname)
    extra = member.extra
    if extra:
        total += _extra_bytes(extra)
    return total


def archive_comment_bytes(comment: str | None) -> int:
    if comment is None:
        return 0
    return _str_retained_bytes(comment)


class ListingLimitTracker:
    """Accumulate member count + retained metadata; optionally raise when caps are crossed."""

    def __init__(self, limits: ListingLimits, *, budget: Budget | None = None) -> None:
        self._limits = limits
        # The shared pool members are also drawn from, and how many this reader has
        # drawn: a listing walked again after ``reset`` draws only past that.
        self._budget = budget
        self._budget_members = 0
        self.member_count = 0
        self.metadata_bytes = 0
        self._archive_comment_counted = False
        # Members a reader holds back before yielding them (``hold_member``): what
        # each was charged, by identity, until ``release_member`` takes it off.
        self._held: dict[int, tuple[ArchiveMember, int]] = {}
        self._held_bytes = 0
        # What a reader keeps while it walks, beyond its members (``charge_walk``),
        # taken off when the walk ends.
        self._walk_bytes = 0

    def reset(self) -> None:
        self.member_count = 0
        self.metadata_bytes = 0
        self._archive_comment_counted = False
        self._held = {}
        self._held_bytes = 0
        self._walk_bytes = 0

    def charge_walk(self, nbytes: int, what: str) -> None:
        """Charge ``nbytes`` a reader keeps while it walks (a name table, a header)
        to ``max_metadata_bytes``, with the members, and refuse them before the
        reader allocates them. ``what`` names them, for the refusal. The charge
        stays until :meth:`release_held`, at the walk's end."""
        next_bytes = self.metadata_bytes + nbytes
        max_meta = self._limits.max_metadata_bytes
        if max_meta is not None and next_bytes > max_meta:
            raise metadata_limit_error(
                max_meta,
                f"retained {next_bytes} bytes, {nbytes} of them for {what}",
            )
        self.metadata_bytes = next_bytes
        self._walk_bytes += nbytes

    def account_archive_comment(self, comment: str | None) -> None:
        """Charge the archive's comment to ``max_metadata_bytes``, once per listing."""
        if self._archive_comment_counted:
            return
        self._archive_comment_counted = True
        added = archive_comment_bytes(comment)
        if added <= 0:
            return
        self._add_bytes(added, enforce=True)

    def account_member(self, member: ArchiveMember) -> None:
        """Count one registered member and its metadata, refusing it past either cap."""
        # Called once per member of every listing, so the checks are inlined; each
        # raise still goes through the shared helpers.
        next_count = self.member_count + 1
        next_bytes = self.metadata_bytes + member_metadata_bytes(member)
        limits = self._limits
        max_members = limits.max_members
        if max_members is not None and next_count > max_members:
            self._check_members(next_count)
        max_meta = limits.max_metadata_bytes
        if max_meta is not None and next_bytes > max_meta:
            self._check_metadata(next_bytes)
        if self._budget is not None:
            self._draw_budget_members(next_count)
        # Raises before storing, so a refused member changes neither total.
        self.metadata_bytes = next_bytes
        self.member_count = next_count

    def _draw_budget_members(self, next_count: int) -> None:
        """Draw the shared budget up to ``next_count`` members, past what this reader
        has drawn already; the budget refuses, counting none, past its cap."""
        budget = self._budget
        if budget is not None and next_count > self._budget_members:
            budget._draw_members(next_count - self._budget_members)
            self._budget_members = next_count

    def hold_member(self, member: ArchiveMember, reason: str) -> None:
        """Charge a member a reader holds back before yielding it, as one member and
        its metadata.

        ``reason`` says what the held members wait for, for the refusal. The charge
        stays until :meth:`release_member`, called when the member is yielded and
        counted by :meth:`account_member`, so a held member is counted once.
        """
        key = id(member)
        if key in self._held:
            raise ValueError(f"member {member.name!r} is already held")
        nbytes = member_metadata_bytes(member)
        held = len(self._held) + 1
        held_bytes = self._held_bytes + nbytes
        next_count = self.member_count + 1
        next_bytes = self.metadata_bytes + nbytes
        limits = self._limits
        max_members = limits.max_members
        if max_members is not None and next_count > max_members:
            raise ResourceLimitError(
                f"Listing limit reached: max_members={max_members} (counted "
                f"{next_count} members, {held} of them {reason})"
            )
        max_meta = limits.max_metadata_bytes
        if max_meta is not None and next_bytes > max_meta:
            raise metadata_limit_error(
                max_meta,
                f"retained {next_bytes} bytes, {held_bytes} of them for {held} "
                f"{reason}",
            )
        # Drawn as account_member draws, before the reader keeps it: the high-water
        # mark means the register after the release does not draw it again.
        self._draw_budget_members(next_count)
        self._held[key] = (member, nbytes)
        self._held_bytes = held_bytes
        self.member_count = next_count
        self.metadata_bytes = next_bytes

    def release_member(self, member: ArchiveMember) -> None:
        """Take off what :meth:`hold_member` charged for ``member``, if it is held."""
        if not self._held:
            return
        entry = self._held.pop(id(member), None)
        if entry is not None:
            self._uncharge(entry[1])

    def release_held(self) -> None:
        """Take off every charge still held, and what the walk kept beyond its
        members (:meth:`charge_walk`): the walk that held them has ended."""
        held, self._held = self._held, {}
        for _, nbytes in held.values():
            self._uncharge(nbytes)
        self.metadata_bytes -= self._walk_bytes
        self._walk_bytes = 0

    def _uncharge(self, nbytes: int) -> None:
        self._held_bytes -= nbytes
        self.member_count -= 1
        self.metadata_bytes -= nbytes

    def account_link_target(self, target: str, *, enforce: bool = True) -> None:
        """Add a link target that was resolved after its member was registered.

        ZIP, 7z and RAR4 keep a symlink's target in the member's data, which is read
        only once every member is registered, so :meth:`account_member` saw ``None``
        for it. Weighing it here is what makes ``max_metadata_bytes`` hold for the
        ``link_target`` field the spec names.
        """
        self._add_bytes(_str_retained_bytes(target), enforce=enforce)

    def account_retained_bytes(self, nbytes: int, *, enforce: bool = True) -> None:
        """Add metadata a backend retains for a member outside its public fields.

        TAR keeps a sparse member's map on the ``TarInfo`` it reads the data through,
        where :func:`member_metadata_bytes` cannot see it.
        """
        self._add_bytes(nbytes, enforce=enforce)

    def _add_bytes(self, nbytes: int, *, enforce: bool) -> None:
        """Add ``nbytes``; ``enforce=False`` records them without refusing, for a
        caller that weighs metadata outside a listing call."""
        next_bytes = self.metadata_bytes + nbytes
        if enforce:
            self._check_metadata(next_bytes)
        self.metadata_bytes = next_bytes

    def assert_within_limits(self) -> None:
        """Re-check accumulated totals (e.g. when returning a previously built cache)."""
        self._check_members(self.member_count)
        self._check_metadata(self.metadata_bytes)

    def _check_members(self, count: int) -> None:
        max_members = self._limits.max_members
        if max_members is not None and count > max_members:
            raise ResourceLimitError(
                f"Listing limit reached: max_members={max_members} "
                f"(registered {count} members)"
            )

    def _check_metadata(self, nbytes: int) -> None:
        check_metadata_budget(self._limits, nbytes, detail=f"retained {nbytes} bytes")


def check_metadata_budget(limits: ListingLimits, nbytes: int, *, detail: str) -> None:
    """Raise :class:`ResourceLimitError` if ``nbytes`` exceeds ``max_metadata_bytes``.

    ``None`` disables the check. ``detail`` names what was weighed; it goes in the
    parentheses after the limit, so every refusal of this limit reads the same way.
    """
    check_metadata_bytes(limits.max_metadata_bytes, nbytes, detail=detail)


def check_metadata_bytes(max_meta: int | None, nbytes: int, *, detail: str) -> None:
    """Same check, for a caller that holds the ``max_metadata_bytes`` value rather
    than a ``ListingLimits``."""
    if max_meta is not None and nbytes > max_meta:
        raise metadata_limit_error(max_meta, detail)


def metadata_limit_error(max_meta: int, detail: str) -> ResourceLimitError:
    """The refusal of ``max_metadata_bytes``, for a caller on a hot path that compares
    itself and builds ``detail`` only once the limit is crossed."""
    return ResourceLimitError(
        f"Listing limit reached: max_metadata_bytes={max_meta} ({detail})"
    )


class ListingDecodeCount:
    """The bytes one listing pass decodes, held to ``ListingLimits.max_decoded_bytes``.

    Counts only while listing work runs on the thread that does it (:meth:`enter` /
    :meth:`leave`, around ``BaseArchiveReader._pull_members_locked`` and
    ``BaseArchiveReader._listing_work``: a walk step, the steps taken at open, the
    listing's link targets), so the bytes a caller reads from a member, between steps
    or on another thread, do not count. :meth:`start_pass` starts the count over for
    each later walk. Draws come through :class:`StageDraws`, from the decode stages
    that also draw a :class:`~archivey.Budget`.
    """

    __slots__ = ("_cap", "_drawn", "_started", "_thread")

    def __init__(self, cap: int) -> None:
        self._cap = cap
        self._drawn = 0
        self._started = False
        self._thread: int | None = None

    @property
    def drawn(self) -> int:
        return self._drawn

    def start_pass(self) -> None:
        """A walk starts. The first one keeps what opening the archive decoded (a 7z
        header): that is part of the first listing. A walk started over counts from
        zero."""
        if self._started:
            self._drawn = 0
        self._started = True

    def enter(self) -> int | None:
        """Count on this thread until :meth:`leave`; returns what to pass to it."""
        previous = self._thread
        self._thread = threading.get_ident()
        return previous

    def leave(self, previous: int | None) -> None:
        self._thread = previous

    def _active(self) -> bool:
        return self._thread is not None and self._thread == threading.get_ident()

    def room(self) -> int | None:
        """Bytes left in this pass, or ``None`` when no listing work runs on this thread."""
        if not self._active():
            return None
        return max(0, self._cap - self._drawn)

    def check_left(self) -> None:
        if self._active() and self._drawn > self._cap:
            raise self._error(0)

    def draw(self, n: int) -> None:
        if n <= 0 or not self._active():
            return
        self._drawn += n
        if self._drawn > self._cap:
            raise self._error(0)

    def refuse(self, n: int, what: str) -> None:
        raise self._error(n, what)

    def _error(self, n: int, what: str = "") -> AlwaysStopResourceLimitError:
        detail = f"listing this archive has decoded {self._drawn} bytes" + (
            f"; {what} would decode {n} more" if what else ""
        )
        # Archive-wide like the Budget's: nothing that skips one member's failure
        # (``OnError.CONTINUE``, the forward ZIP's drain) may go on decoding past it.
        return AlwaysStopResourceLimitError(
            f"Listing limit reached: max_decoded_bytes={self._cap} ({detail})"
        )


class StageDraws:
    """A decode stage's draws: the config's :class:`~archivey.Budget` and the listing
    pass's :class:`ListingDecodeCount`, either of which may be absent. Answers the
    calls :class:`~archivey.internal.streams.counting.BudgetDrawStream` and the direct
    draw sites make of a budget, as the tighter of the two."""

    __slots__ = ("_budget", "_listing")

    def __init__(self, budget: Budget | None, listing: ListingDecodeCount) -> None:
        self._budget = budget
        self._listing = listing

    @staticmethod
    def of(
        budget: Budget | None, listing: ListingDecodeCount | None
    ) -> Budget | StageDraws | None:
        """What a decode stage draws from: ``None`` for nothing, the budget alone when
        there is no listing cap."""
        if listing is None:
            return budget
        return StageDraws(budget, listing)

    def _bytes_room(self) -> int | None:
        listing = self._listing.room()
        budget = self._budget._bytes_room() if self._budget is not None else None
        if listing is None:
            return budget
        return listing if budget is None else min(listing, budget)

    def _check_bytes_left(self) -> None:
        if self._budget is not None:
            self._budget._check_bytes_left()
        self._listing.check_left()

    def _read_cap(self, want: int) -> int:
        self._check_bytes_left()
        room = self._bytes_room()
        return want if room is None else min(want, room + 1)

    def _draw_bytes(self, n: int) -> None:
        if self._budget is not None:
            self._budget._draw_bytes(n)
        self._listing.draw(n)

    def _refuse_bytes(self, n: int, what: str) -> None:
        budget = self._budget
        if budget is not None:
            room = budget._bytes_room()
            if room is not None and n > room:
                budget._refuse_bytes(n, what)
        self._listing.refuse(n, what)

    def _draw_whole(self, n: int, what: str) -> None:
        self._check_bytes_left()
        room = self._bytes_room()
        if room is not None and n > room:
            self._refuse_bytes(n, what)
        self._draw_bytes(n)
