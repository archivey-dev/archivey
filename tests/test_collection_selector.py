"""The collection form of ``members=``: what it selects and what it reports unmatched.

These drive :class:`CollectionSelector` directly with hand-built members, so the
identity rule (both ids set) and the report's wording and context are pinned without
an archive.
"""

from __future__ import annotations

from archivey.diagnostics import Diagnostic, DiagnosticCode, SelectorUnmatchedContext
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.selection import CollectionSelector
from archivey.types import ArchiveMember, MemberType


def _member(
    name: str, *, archive_id: str | None = None, member_id: int | None = None
) -> ArchiveMember:
    member = ArchiveMember(type=MemberType.FILE, name=name)
    member._archive_id = archive_id
    member._member_id = member_id
    return member


def _report(selector: CollectionSelector, archive_name: str | None) -> list[Diagnostic]:
    seen: list[Diagnostic] = []
    selector.report_unmatched(
        DiagnosticCollector(on_diagnostic=seen.append), archive_name
    )
    assert all(d.code is DiagnosticCode.MEMBER_SELECTOR_UNMATCHED for d in seen)
    return seen


def test_a_member_with_no_ids_is_selected_only_by_name() -> None:
    selector = CollectionSelector(["x"])
    assert not selector(_member("y"))
    assert selector(_member("x"))


def test_a_member_entry_matched_by_identity_is_not_reported() -> None:
    entry = _member("a", archive_id="arc", member_id=3)
    other = _member("b", archive_id="arc", member_id=4)
    selector = CollectionSelector([entry, other])
    # A different name, the same identity: a member renamed on the way.
    assert selector(_member("renamed", archive_id="arc", member_id=3))
    assert selector.unmatched() == [other]


def test_unmatched_lists_each_entry_once_in_the_callers_order() -> None:
    first = _member("a", archive_id="arc", member_id=1)
    second = _member("b", archive_id="arc", member_id=2)
    selector = CollectionSelector(["n", "n", first, second, first, "m"])
    assert selector.unmatched() == ["n", first, second, "m"]


def test_members_missing_one_id_are_separate_entries() -> None:
    # A member with only one of its ids has no identity, so two of them are two
    # entries even when the id they have is the same.
    one = _member("a", archive_id="arc")
    two = _member("b", archive_id="arc")
    selector = CollectionSelector([one, two])
    assert not selector(_member("c", archive_id="arc"))
    assert selector.unmatched() == [one, two]


def test_the_report_names_the_archive_and_the_entry_kind() -> None:
    selector = CollectionSelector(["n", _member("m", archive_id="arc", member_id=1)])
    reports = _report(selector, "a.zip")
    contexts = [d.context for d in reports]
    assert all(isinstance(c, SelectorUnmatchedContext) for c in contexts)
    assert [
        (c.archive_name, c.entry, c.entry_kind)
        for c in contexts
        if isinstance(c, SelectorUnmatchedContext)
    ] == [("a.zip", "n", "name"), ("a.zip", "m", "member")]


def test_the_directory_hint_needs_the_name_plus_a_slash() -> None:
    # "dir/" in the archive names the fix for an entry "dir"; "dirt" does not.
    selector = CollectionSelector(["dir", "di"])
    assert not selector(_member("dir/"))
    assert not selector(_member("dit"))
    messages = [d.message for d in _report(selector, None)]
    hint = (
        "members= entry 'dir' matched no member; the archive holds 'dir/' "
        "(a directory's name ends in '/')."
    )
    assert messages == [hint, "members= entry 'di' matched no member."]
