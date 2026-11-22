"""``Placements``: which result of an extraction run owns each file it wrote.

Two names of one directory entry are what a case-insensitive filesystem makes of a
case variant. A hard link gives two names of one file on any filesystem, so the tests
that ask the filesystem use one to stand for that, where ``os.lstat`` reports inodes.
The tests of the bookkeeping alone use ``PureWindowsPath``, whose equality folds case
as ``WindowsPath``'s does, and run everywhere.
"""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
from typing import cast

import pytest

from archivey.internal.placements import Placements

posix_inodes = pytest.mark.skipif(
    os.name == "nt", reason="hard links stand in for case aliases; inodes on POSIX"
)


def _file(path: Path, data: bytes = b"x") -> Path:
    path.write_bytes(data)
    return path


@posix_inodes
def test_owner_is_none_with_nothing_claimed(tmp_path: Path) -> None:
    assert Placements().owner(_file(tmp_path / "a"), "a", occupied=True) is None


@posix_inodes
def test_the_file_at_a_name_decides_over_the_key(tmp_path: Path) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    os.link(tmp_path / "A", tmp_path / "a")
    # ``a`` is another name of the file ``A`` claimed: its owner, whatever its key.
    assert placements.owner(tmp_path / "a", "a", occupied=True) is first
    # A name with no entry falls back to the key.
    assert placements.owner(tmp_path / "b", "A", occupied=False) is first


@posix_inodes
def test_a_landing_retires_the_claim_it_replaced(tmp_path: Path) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    os.link(tmp_path / "A", tmp_path / "a")
    owner = placements.owner(tmp_path / "a", "a", occupied=True)
    assert owner is first
    second = placements.land(tmp_path / "a", "a", tmp_path / "a", 1, replaced=owner)
    assert placements.at_key("A") is None
    assert not placements.is_live(first)
    # Both names reach the entry ``a`` now owns.
    assert placements.owner(tmp_path / "A", "A", occupied=True) is second
    assert placements.owner(tmp_path / "a", "a", occupied=True) is second


@posix_inodes
def test_a_released_claim_is_not_found_by_identity(tmp_path: Path) -> None:
    placements = Placements()
    path = _file(tmp_path / "A")
    claim = placements.claim(path, "A", path, 0)
    assert placements.by_identity(path) is claim
    assert placements.release(path, "A")
    assert placements.by_identity(path) is None
    assert not placements.release(path, "A")


@posix_inodes
def test_a_landing_on_its_own_name_keeps_one_claim(tmp_path: Path) -> None:
    placements = Placements()
    path = _file(tmp_path / "A")
    first = placements.claim(path, "A", path, 0)
    second = placements.land(path, "A", path, 1, replaced=first)
    assert placements.at_key("A") is second
    assert placements.at_path(path, "A") is second


@posix_inodes
def test_the_key_decides_between_hard_links_of_one_file(tmp_path: Path) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    os.link(tmp_path / "A", tmp_path / "b")
    link = placements.claim(tmp_path / "b", "b", tmp_path / "b", 1)
    # One inode, two claims: each name's own key answers for it.
    assert placements.owner(tmp_path / "A", "A", occupied=True) is first
    assert placements.owner(tmp_path / "b", "b", occupied=True) is link
    # A name no key reaches finds the claim of the name it folds to, else the latest.
    os.link(tmp_path / "A", tmp_path / "a")
    os.link(tmp_path / "A", tmp_path / "c")
    assert placements.owner(tmp_path / "a", "a", occupied=True) is first
    assert placements.owner(tmp_path / "c", "c", occupied=True) is link


def _win(path: str) -> Path:
    return cast(Path, PureWindowsPath(path))


def test_a_landing_retires_a_case_variant_whose_path_compares_equal() -> None:
    # Under TRUSTED, ``A`` and ``a`` have keys of their own, and ``WindowsPath``
    # equality says they are one path: the claims, not the paths, are compared.
    placements = Placements()
    upper, lower = _win("C:/o/A"), _win("C:/o/a")
    first = placements.claim(upper, "A", upper, 0)
    second = placements.land(lower, "a", lower, 1, replaced=first)
    assert placements.at_key("A") is None
    assert not placements.is_live(first)
    assert placements.at_key("a") is second
    assert placements.claimed_key(upper) == "A"
    assert placements.claimed_key(lower) == "a"


def test_a_release_matches_the_path_as_spelled() -> None:
    placements = Placements()
    upper, lower = _win("C:/o/A"), _win("C:/o/a")
    claim = placements.claim(upper, "A", upper, 0)
    assert placements.at_path(lower, "A") is None
    assert not placements.release(lower, "A")
    assert placements.at_path(upper, "A") is claim
    assert placements.release(upper, placements.claimed_key(upper) or "")
    assert not placements
