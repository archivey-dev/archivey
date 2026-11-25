"""``Placements``: which result of an extraction run owns each file it wrote.

Two names of one directory entry are what a case-insensitive filesystem makes of a
case variant. A hard link gives two names of one file on any filesystem, so the tests
that ask the filesystem use one to stand for that, where ``os.lstat`` reports inodes.
The tests of the bookkeeping alone use ``PureWindowsPath``, whose equality folds case
as ``WindowsPath``'s does, and run everywhere.
"""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path, PureWindowsPath
from typing import cast

import pytest

from archivey.internal import placements as placements_module
from archivey.internal.placements import Placements

posix_inodes = pytest.mark.skipif(
    os.name == "nt", reason="hard links stand in for case aliases; inodes on POSIX"
)


def _file(path: Path, data: bytes = b"x") -> Path:
    path.write_bytes(data)
    return path


def _alias(
    existing: Path, alias: Path, stand_in: pytest.MonkeyPatch | None = None
) -> None:
    """Make ``alias`` a second name of ``existing``. A case- or normalization-
    insensitive filesystem (macOS) has made it one already.

    With ``stand_in``, a hard link made here is the test's one stand-in for a short
    name or a case variant, which adds no link to its file: the file's entry count
    leaves it out. Where the filesystem made the alias, nothing is patched."""
    if os.path.lexists(alias):
        return
    os.link(existing, alias)
    if stand_in is not None:
        stand_in.setattr(placements_module, "_entry_count", lambda st: st.st_nlink - 1)


@posix_inodes
def test_owner_is_none_with_nothing_claimed(tmp_path: Path) -> None:
    assert Placements().owner(_file(tmp_path / "a"), "a", occupied=True) is None


@posix_inodes
def test_a_name_no_key_reaches_finds_the_claim_of_its_file(tmp_path: Path) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    _alias(tmp_path / "A", tmp_path / "a")
    # ``a`` is another name of the file ``A`` claimed: its owner, whatever its key.
    assert placements.owner(tmp_path / "a", "a", occupied=True) is first
    # A name with no entry falls back to the key.
    assert placements.owner(tmp_path / "b", "A", occupied=False) is first


@posix_inodes
def test_a_landing_retires_the_claim_it_replaced(tmp_path: Path) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    _alias(tmp_path / "A", tmp_path / "a")
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
    _alias(tmp_path / "A", tmp_path / "b")
    link = placements.claim(tmp_path / "b", "b", tmp_path / "b", 1)
    # One inode, two claims: each name's own key answers for it.
    assert placements.owner(tmp_path / "A", "A", occupied=True) is first
    assert placements.owner(tmp_path / "b", "b", occupied=True) is link
    # A name no key reaches finds the claim of the name it folds to.
    _alias(tmp_path / "A", tmp_path / "a")
    assert placements.owner(tmp_path / "a", "a", occupied=True) is first
    # A name that folds to neither (an 8.3 short name stands for one of the two)
    # cannot tell which entry it reaches: no claim answers for it.
    _alias(tmp_path / "A", tmp_path / "c")
    assert placements.owner(tmp_path / "c", "c", occupied=True) is None


@posix_inodes
def test_a_name_that_folds_to_no_claim_finds_its_file_s_only_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    placements = Placements()
    only = placements.claim(_file(tmp_path / "LongFileName"), "L", tmp_path / "L", 0)
    # ``LONGFI~1`` names the one entry the file has a claim for.
    _alias(tmp_path / "LongFileName", tmp_path / "LONGFI~1", monkeypatch)
    assert placements.owner(tmp_path / "LONGFI~1", "LONGFI~1", occupied=True) is only


@posix_inodes
def test_a_retired_claim_leaves_the_identity_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    placements = Placements()
    first = placements.claim(_file(tmp_path / "A"), "A", tmp_path / "A", 0)
    _alias(tmp_path / "A", tmp_path / "b")
    link = placements.claim(tmp_path / "b", "b", tmp_path / "b", 1)
    _alias(tmp_path / "A", tmp_path / "c", monkeypatch)
    assert placements.owner(tmp_path / "c", "c", occupied=True) is None
    # With ``A``'s claim retired, ``b``'s is the file's only one, but ``A`` is still
    # one of its entries, which ``c`` may name: no answer.
    assert placements.retire(first)
    assert placements.owner(tmp_path / "c", "c", occupied=True) is None
    # With ``A`` gone, ``c`` can only name ``b``'s entry.
    os.unlink(tmp_path / "A")
    assert placements.owner(tmp_path / "c", "c", occupied=True) is link
    assert (
        sum(
            len(spellings)
            for entries in placements._by_id.values()
            for spellings in entries.values()
        )
        == 1
    )


@posix_inodes
def test_an_unclaimed_hard_link_does_not_take_its_file_s_only_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A hard link ``a`` to ``src`` whose claim was taken back stays on disk; ``A``, a
    # case variant of it, reaches ``a``'s entry, not ``src``'s. The macOS link parity
    # soak wrote a member over ``src`` before the file's entry count was checked.
    placements = Placements()
    placements.claim(_file(tmp_path / "src"), "src", tmp_path / "src", 0)
    os.link(tmp_path / "src", tmp_path / "a")
    _alias(tmp_path / "a", tmp_path / "A", monkeypatch)
    assert placements.owner(tmp_path / "A", "a", occupied=True) is None


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


@posix_inodes
def test_a_hard_link_elsewhere_with_the_same_name_is_another_entry(
    tmp_path: Path,
) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "e").mkdir()
    placements = Placements()
    here = placements.claim(_file(tmp_path / "d" / "A"), "d/A", tmp_path / "d/A", 0)
    _alias(tmp_path / "d" / "A", tmp_path / "e" / "a")
    placements.claim(tmp_path / "e" / "a", "e/a", tmp_path / "e/a", 1)
    # ``d/a`` stands for the entry ``d/A`` (a case alias): ``e/a`` has its name, but
    # in another directory.
    _alias(tmp_path / "d" / "A", tmp_path / "d" / "a")
    assert placements.owner(tmp_path / "d" / "a", "d/a", occupied=True) is here


@posix_inodes
def test_a_name_folds_unicode_normalization_too(tmp_path: Path) -> None:
    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", "café")
    placements = Placements()
    first = placements.claim(_file(tmp_path / nfc), nfc, tmp_path / nfc, 0)
    _alias(tmp_path / nfc, tmp_path / "b")
    placements.claim(tmp_path / "b", "b", tmp_path / "b", 1)
    # On APFS the NFD spelling is the entry the NFC one names.
    _alias(tmp_path / nfc, tmp_path / nfd)
    assert placements.owner(tmp_path / nfd, nfd, occupied=True) is first


@posix_inodes
def test_hard_links_whose_names_fold_together_keep_their_own_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Under TRUSTED on a case-sensitive filesystem, ``A`` and ``a`` are two
    # entries; here they are hard links of one file.
    _file(tmp_path / "A")
    if os.path.lexists(tmp_path / "a"):
        pytest.skip("needs a case-sensitive filesystem")
    placements = Placements()
    upper = placements.claim(tmp_path / "A", "A", tmp_path / "A", 0)
    os.link(tmp_path / "A", tmp_path / "a")
    lower = placements.claim(tmp_path / "a", "a", tmp_path / "a", 1)
    _alias(tmp_path / "A", tmp_path / "c", monkeypatch)
    assert placements.owner(tmp_path / "A", "", occupied=True) is upper
    assert placements.owner(tmp_path / "a", "", occupied=True) is lower
    # Two live claims: a name of neither has no answer.
    assert placements.owner(tmp_path / "c", "c", occupied=True) is None
    os.unlink(tmp_path / "a")
    assert placements.release(tmp_path / "a", "a")
    # ``A``'s claim is still indexed, and now the file's only one.
    assert placements.by_identity(tmp_path / "c") is upper
    assert placements.owner(tmp_path / "c", "c", occupied=True) is upper
