"""Member selection normalization shared by streaming and extraction."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from archivey.diagnostics import DiagnosticCode, SelectorUnmatchedContext
from archivey.exceptions import _UsageTypeError
from archivey.internal.arg_checks import describe_value
from archivey.terminal import quoted
from archivey.types import ArchiveMember

if TYPE_CHECKING:
    from archivey.internal.diagnostics_collector import DiagnosticCollector


class CollectionSelector:
    """The predicate that the collection form of ``members=`` normalizes to.

    It also records which entries matched a member, so that the pass that ran it can
    report each entry that matched nothing (``MEMBER_SELECTOR_UNMATCHED``). It is not
    iterable, so ``normalize_member_selector`` passes it through as a predicate.
    """

    __slots__ = (
        "_directory_spellings",
        "_entries",
        "_identities",
        "_matched",
        "_names",
        "_record",
    )

    def __init__(
        self, entries: list[str | ArchiveMember], *, record: bool = True
    ) -> None:
        self._entries = entries
        # False for a selector nothing will report on (the extraction coordinator's
        # own identity selectors), so it skips the per-member bookkeeping.
        self._record = record
        # member name -> indexes of the str entries that select that name.
        self._names: dict[str, list[int]] = {}
        # (_archive_id, member_id) -> indexes of the ArchiveMember entries with that id.
        self._identities: dict[tuple[str, int], list[int]] = {}
        self._matched: set[int] = set()
        # Entries that name a directory without its trailing "/", seen on the way past
        # ("dir" when the archive holds "dir/"), so the report can name the fix.
        self._directory_spellings: set[str] = set()
        for index, entry in enumerate(entries):
            if isinstance(entry, str):
                self._names.setdefault(entry, []).append(index)
            # Match by (_archive_id, member_id) identity. A member that carries no ids
            # (never registered by a reader, for example built by hand) cannot
            # correspond to any real member, so it matches nothing and is reported
            # as unmatched.
            elif entry._archive_id is not None and entry._member_id is not None:
                identity = (entry._archive_id, entry._member_id)
                self._identities.setdefault(identity, []).append(index)

    def __call__(self, member: ArchiveMember) -> bool:
        name = member.name
        if self._record and name.endswith("/") and name[:-1] in self._names:
            self._directory_spellings.add(name[:-1])
        by_name = self._names.get(name)
        by_identity = None
        if member._archive_id is not None and member._member_id is not None:
            by_identity = self._identities.get((member._archive_id, member._member_id))
        if by_name is None and by_identity is None:
            return False
        if self._record:
            if by_name is not None:
                self._matched.update(by_name)
            if by_identity is not None:
                self._matched.update(by_identity)
        return True

    def would_select(self, member: ArchiveMember, names: Iterable[str]) -> bool:
        """Whether a member under any of ``names`` (or ``member`` by identity) is
        selected, recording nothing: for a member whose name can still change."""
        if (
            member._archive_id is not None
            and member._member_id is not None
            and (member._archive_id, member._member_id) in self._identities
        ):
            return True
        return any(name in self._names for name in names)

    def unmatched(self) -> list[str | ArchiveMember]:
        """The entries that no member has matched so far, in the caller's order.

        An entry that the caller repeated is listed once: a name by its text, a member
        by its identity. Two hand-built members with no identity are two entries.
        """
        seen_names: set[str] = set()
        seen_identities: set[tuple[str, int]] = set()
        result: list[str | ArchiveMember] = []
        for index, entry in enumerate(self._entries):
            if index in self._matched:
                continue
            if isinstance(entry, str):
                if entry in seen_names:
                    continue
                seen_names.add(entry)
            elif entry._archive_id is not None and entry._member_id is not None:
                identity = (entry._archive_id, entry._member_id)
                if identity in seen_identities:
                    continue
                seen_identities.add(identity)
            result.append(entry)
        return result

    def report_unmatched(
        self, collector: DiagnosticCollector, archive_name: str | None
    ) -> None:
        """Emit one ``MEMBER_SELECTOR_UNMATCHED`` per entry that matched nothing.

        Call it only when every member has been offered to the selector. Before that,
        an entry that has not matched yet can still match a later member.
        """
        for entry in self.unmatched():
            if isinstance(entry, str):
                context = SelectorUnmatchedContext(
                    archive_name=archive_name, entry=entry, entry_kind="name"
                )
                message = f"members= entry {quoted(entry)} matched no member."
                if entry in self._directory_spellings:
                    message = (
                        f"members= entry {quoted(entry)} matched no member; the "
                        f"archive holds {quoted(entry + '/')} (a directory's name ends "
                        f"in '/')."
                    )
            else:
                context = SelectorUnmatchedContext(
                    archive_name=archive_name, entry=entry.name, entry_kind="member"
                )
                message = (
                    f"members= entry for member {quoted(entry.name)} matched no "
                    f"member: a member entry matches only the same member of this "
                    f"reader."
                )
            collector.emit(
                code=DiagnosticCode.MEMBER_SELECTOR_UNMATCHED,
                message=message,
                context=context,
            )


def normalize_member_selector(
    members: Iterable[str | ArchiveMember] | Callable[[ArchiveMember], bool] | None,
) -> Callable[[ArchiveMember], bool] | None:
    """Normalize an iterable or predicate selector to a predicate.

    An iterable is read exactly once, so a generator works. Call this once per public
    call and pass the result on: a second call on the caller's argument would find a
    one-shot iterable empty.

    A ``str`` entry matches every member with exactly that name, so a directory is
    selected as ``"dir/"``, not ``"dir"``. An ``ArchiveMember`` entry matches by
    identity. The collection form returns a :class:`CollectionSelector`, which also
    records the entries that matched nothing.

    A selector that is both callable and iterable is read as an iterable.
    ``Iterable`` is not final, so the two arms of the parameter's type can
    overlap; the tie is decided here rather than falling out of the order of
    the checks.
    """
    if members is None:
        return None
    if isinstance(members, (str, bytes)):
        # A str is an iterable of one-character strings, so `members="notes.txt"`
        # selected the set {"n", "o", "t", "e", "s", ".", "x"} — no member matched,
        # and the call reported a clean extraction of nothing. Refused rather than
        # wrapped: guessing that a string meant [string] would make the plural
        # parameter accept a singular, and the caller is one bracket from correct.
        # bytes gets no list-wrapping advice: Pass [b'notes.txt'] is itself a
        # usage error (names are str). The str branch is the common slip.
        if isinstance(members, bytes):
            raise _UsageTypeError(
                f"members= takes names (str) or ArchiveMembers, but got "
                f"{describe_value(members)}."
            )
        raise _UsageTypeError(
            f"members= takes a collection of names or members, but got "
            f"{describe_value(members)}. Pass [{members!r}] to select one member."
        )
    if not isinstance(members, Iterable):
        # Everything below is the collection arm, so only the predicate is left here.
        # Testing the collection first is what decides the tie: an object that is both
        # callable and iterable is read as a collection, which is the more
        # defensible reading of a parameter named ``members``. The precedence was
        # never an explicit decision before; it is one now.
        #
        # It is also what lets both checkers narrow this arm with no ``cast``.
        # ``callable()`` cannot drop the collection arm, because ``Iterable`` is not
        # final and a subclass may define ``__call__`` — ty intersects the two instead
        # and the intersection returns ``object``. A negative ``isinstance`` does drop
        # it, so the value that reaches the return below is already a predicate.
        if not callable(members):
            raise _UsageTypeError(
                f"members= takes a collection of names or members, a predicate, or "
                f"None, but got {describe_value(members)}."
            )
        return members
    entries: list[str | ArchiveMember] = []
    for entry in members:
        if isinstance(entry, (str, ArchiveMember)):
            entries.append(entry)
        else:
            # Anything else used to land in ``names``, where it could never equal a
            # member name, so the entry was dropped and the call still reported
            # success. A selector that silently selects nothing is the one outcome
            # a caller cannot distinguish from an archive that has nothing.
            raise _UsageTypeError(
                f"members= takes names (str) or ArchiveMembers, but one entry was "
                f"{describe_value(entry)}."
            )
    return CollectionSelector(entries)
