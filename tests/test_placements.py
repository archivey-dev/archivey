"""``Placements``: which result of an extraction run owns each file it wrote.

Two names of one directory entry are what a case-insensitive filesystem makes of a
case variant. A hard link gives two names of one file on any filesystem, so these
tests use one to stand for that, where ``os.lstat`` reports inodes.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from archivey.internal.placements import Placements

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="hard links stand in for case aliases; inodes on POSIX"
)


def _file(path: Path, data: bytes = b"x") -> Path:
    path.write_bytes(data)
    return path


def test_owner_is_none_with_nothing_claimed(tmp_path: Path) -> None:
    assert Placements().owner(_file(tmp_path / "a"), "a", occupied=True) is None


def test_the_file_at_a_name_decides_over_the_key(tmp_path: Path) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    os.link(tmp_path / "A", tmp_path / "a")
    # ``a`` is another name of the file ``A`` claimed: its owner, whatever its key.
    assert placements.owner(tmp_path / "a", "a", occupied=True) is first
    # A name with no entry falls back to the key.
    assert placements.owner(tmp_path / "b", "A", occupied=False) is first


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


def test_a_stale_claim_never_answers_for_the_file_there_now(tmp_path: Path) -> None:
    # ``A`` was claimed, then the entry at ``A`` came to hold ``b``'s file: a
    # sequence of case-variant writes ends this way. Its own key still holds
    # ``A``'s claim, but the file decides.
    placements = Placements()
    placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    later = placements.claim(_file(tmp_path / "b", b"y"), "b", tmp_path / "b", 1)
    os.unlink(tmp_path / "A")
    os.link(tmp_path / "b", tmp_path / "A")
    assert placements.owner(tmp_path / "A", "A", occupied=True) is later


def test_a_released_claim_is_not_found_by_identity(tmp_path: Path) -> None:
    placements = Placements()
    path = _file(tmp_path / "A")
    claim = placements.claim(path, "A", path, 0)
    assert placements.by_identity(path) is claim
    assert placements.release(path, "A")
    assert placements.by_identity(path) is None
    assert not placements.release(path, "A")


def test_a_landing_on_its_own_name_keeps_one_claim(tmp_path: Path) -> None:
    placements = Placements()
    path = _file(tmp_path / "A")
    first = placements.claim(path, "A", path, 0)
    second = placements.land(path, "A", path, 1, replaced=first)
    assert placements.at_key("A") is second
    assert placements.at_path(path, "A") is second
