"""Edges of the name policy that a mutation sweep found unpinned: which segment a
check reaches, which message a refusal carries, and when two names share a key."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from archivey import ExtractionPolicy, FilterRejectionError
from archivey.internal.filters import (
    SYMLINK_ESCAPES,
    SYMLINK_LOOPS,
    apply_name_policy,
    collision_key,
    link_resolution_problem,
)
from archivey.types import ArchiveMember, MemberType


def _member(
    name: str, *, type: MemberType = MemberType.FILE, link_target: str | None = None
) -> ArchiveMember:
    return ArchiveMember(type=type, name=name, link_target=link_target)


def test_a_reserved_name_after_an_empty_segment_is_refused() -> None:
    """Link targets are not normalized, so ``x//CON`` reaches the segment check with
    an empty segment before the device name."""
    member = _member("l", type=MemberType.SYMLINK, link_target="x//CON")
    with pytest.raises(FilterRejectionError, match="reserved device name") as caught:
        apply_name_policy(member, ExtractionPolicy.STANDARD)
    assert caught.value.link_target == "x//CON"


@pytest.mark.parametrize(
    ("member", "message"),
    [
        (_member("in\u202ev"), "in member name"),
        (_member("a/CON"), "device name in path"),
        (_member("a/b:c"), "Colon in path segment"),
        (_member("a/. ./b"), "entirely dots/spaces"),
        (
            _member("l", type=MemberType.SYMLINK, link_target="t\u202ex"),
            "in link target of 'l'",
        ),
    ],
    ids=["bidi", "reserved", "colon", "dots", "bidi-in-target"],
)
def test_a_refusal_names_the_member_it_refuses(
    member: ArchiveMember, message: str
) -> None:
    for policy in (ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD):
        with pytest.raises(FilterRejectionError, match=message) as caught:
            apply_name_policy(member, policy)
        assert caught.value.member_name == member.name


@pytest.mark.parametrize(
    ("code", "what"),
    [
        (0xDC80, "bytes that are not UTF-8"),
        (0xDCFF, "bytes that are not UTF-8"),
        (0xDC7F, "a lone surrogate"),
        (0xDD00, "a lone surrogate"),
        (0xDFFF, "a lone surrogate"),
    ],
    ids=lambda value: hex(value) if isinstance(value, int) else None,
)
def test_strict_names_an_escaped_byte_and_a_lone_surrogate_apart(
    code: int, what: str
) -> None:
    """``surrogateescape`` spells a byte 0x80-0xFF as U+DC80-U+DCFF: only that range
    is an undecodable byte, every other surrogate is a lone one."""
    with pytest.raises(FilterRejectionError, match=f"Name holds {what}\\."):
        apply_name_policy(_member("a" + chr(code)), ExtractionPolicy.STRICT)


@pytest.mark.parametrize(
    "policy",
    [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD, ExtractionPolicy.TRUSTED],
)
def test_a_trailing_separator_does_not_change_the_collision_key(
    policy: ExtractionPolicy,
) -> None:
    assert collision_key("a/", policy) == collision_key("a", policy) == "a"
    assert collision_key("d\\a/", policy) == collision_key("d/a", policy)


def test_a_segment_ending_in_a_space_shares_a_key_without_it() -> None:
    """Win32 trims a trailing space or dot on every segment, not only the last."""
    standard = ExtractionPolicy.STANDARD
    assert collision_key("a /b", standard) == collision_key("a/b", standard)
    assert collision_key("a./b", standard) == collision_key("a/b", standard)
    assert collision_key("a /b", ExtractionPolicy.TRUSTED) == "a /b"


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
def test_a_link_problem_names_a_loop_apart_from_an_escape(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "out"
    root.mkdir()
    (root / "a").symlink_to("b")
    (root / "b").symlink_to("a")
    (root / "out").symlink_to("../secret")

    assert link_resolution_problem(root / "a", root) == SYMLINK_LOOPS
    assert link_resolution_problem(root / "out", root) == SYMLINK_ESCAPES
    assert link_resolution_problem(root / "file", root) is None
