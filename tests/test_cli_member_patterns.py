"""CLI member patterns: ``match_glob(..., with_contents=True)``, plus Windows ``\\``."""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import MemberPass, open_archive
from archivey.cli.exit_codes import EXIT_FAIL, EXIT_OK, EXIT_USAGE
from archivey.cli.filters import MemberSelection
from archivey.cli.main import main
from archivey.exceptions import ReadError
from archivey.internal.base_reader import BaseArchiveReader
from archivey.paths import match_glob
from archivey.types import ArchiveMember
from tests.test_extraction_damaged_listing import _rar_cut


def _tar(path: Path, entries: list[tuple[str, bytes | None]]) -> Path:
    """Write a TAR of ``(name, content)``; ``None`` content is a directory. A
    ``.tar.gz`` path gets a gzip-compressed TAR, which has no member index."""
    mode = "w:gz" if path.name.endswith(".tar.gz") else "w"
    with tarfile.open(path, mode) as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return path


_TREE: list[tuple[str, bytes | None]] = [
    ("docs", None),
    ("docs/a.txt", b"a"),
    ("docs/sub", None),
    ("docs/sub/b.txt", b"b"),
    ("docs.txt", b"not the dir"),
    ("src/main.py", b"code"),
]


def _members(tmp_path: Path) -> list[ArchiveMember]:
    with open_archive(_tar(tmp_path / "t.tar", _TREE)) as ar:
        return ar.members()


def _selected(
    members: list[ArchiveMember],
    includes: list[str],
    excludes: list[str] | None = None,
    *,
    windows: bool = False,
) -> list[str]:
    pred = MemberSelection(includes, excludes, backslash_is_separator=windows).predicate
    assert pred is not None
    return [m.name for m in members if pred(m)]


def test_cli_patterns_match_like_match_glob_with_contents(tmp_path: Path) -> None:
    """``*`` stays inside one folder; a pattern matching a folder selects the folder and
    everything under it, as ``tar`` does, but not the sibling file ``docs.txt``."""
    members = _members(tmp_path)
    contents = ["docs/", "docs/a.txt", "docs/sub/", "docs/sub/b.txt"]
    assert _selected(members, ["docs"]) == contents
    assert _selected(members, ["docs/"]) == contents
    assert _selected(members, ["docs/**"]) == contents
    assert _selected(members, ["*.txt"]) == ["docs.txt"]
    assert _selected(members, ["**/*.txt"]) == [
        "docs/a.txt",
        "docs/sub/b.txt",
        "docs.txt",
    ]
    for pattern in ["docs", "docs/**", "*.txt", "**/*.txt", "src", "*/"]:
        predicate = match_glob(pattern, with_contents=True)
        assert _selected(members, [pattern]) == [
            m.name for m in members if predicate(m)
        ]


def test_a_directory_pattern_does_not_select_a_file_of_that_name(
    tmp_path: Path,
) -> None:
    members = _members(tmp_path)
    assert _selected(members, ["docs.txt/"]) == []
    assert _selected(members, ["docs.txt"]) == ["docs.txt"]


def test_a_nested_directory_and_a_wildcard_still_work(tmp_path: Path) -> None:
    members = _members(tmp_path)
    assert _selected(members, ["docs/sub"]) == ["docs/sub/", "docs/sub/b.txt"]
    assert _selected(members, ["*.py"]) == []
    assert _selected(members, ["**/*.py"]) == ["src/main.py"]
    # A directory stored only through its files (no "src/" entry) is still selected.
    assert _selected(members, ["src"]) == ["src/main.py"]


def test_exclude_matches_the_same_way(tmp_path: Path) -> None:
    members = _members(tmp_path)
    assert _selected(members, ["docs"], ["docs/sub"]) == ["docs/", "docs/a.txt"]


def test_a_backslash_is_a_separator_only_on_windows(tmp_path: Path) -> None:
    members = _members(tmp_path)
    assert _selected(members, ["docs\\sub"], windows=True) == [
        "docs/sub/",
        "docs/sub/b.txt",
    ]
    # Elsewhere a backslash is a literal character a TAR member name can contain.
    assert _selected(members, ["docs\\sub"], windows=False) == []


def test_unmatched_patterns_use_the_same_rule(tmp_path: Path) -> None:
    selection = MemberSelection(
        ["docs", "src", "docs.txt/", "missing", "docs"],
        None,
        backslash_is_separator=False,
    )
    for member in _members(tmp_path):
        selection(member)
    assert selection.unmatched_includes() == ["docs.txt/", "missing"]


@pytest.mark.parametrize(
    ("pattern", "reason", "unrelated"),
    [
        ("a//b", "has an empty component", "[...]"),
        ("[z-a]", "has a malformed [...] set: bad character range z-a", "'/'"),
    ],
)
def test_an_invalid_pattern_is_a_usage_error(
    pattern: str,
    reason: str,
    unrelated: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The message carries match_glob's own reason, so it names only what is wrong.
    archive = _tar(tmp_path / "t.tar", _TREE)
    assert main(["list", str(archive), pattern]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert f"archivey: invalid member pattern: {pattern!r} {reason}" in err
    assert unrelated not in err
    assert "position" not in err


@pytest.mark.parametrize("pattern", ["docs", "docs/", "docs/**"])
def test_extract_a_directory_by_name(
    pattern: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _tar(tmp_path / "t.tar", _TREE)
    dest = tmp_path / "out"
    assert main(["x", str(archive), "-d", str(dest), pattern]) == EXIT_OK
    assert (dest / "docs" / "sub" / "b.txt").read_bytes() == b"b"
    assert not (dest / "docs.txt").exists()
    assert "pattern matched no members" not in capsys.readouterr().err


def test_list_a_directory_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _tar(tmp_path / "t.tar", _TREE)
    assert main(["list", str(archive), "docs/sub"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "docs/sub/b.txt" in out
    assert "docs/a.txt" not in out


def test_extract_with_only_a_missing_directory_pattern_still_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _tar(tmp_path / "t.tar", _TREE)
    dest = tmp_path / "out"
    assert main(["x", str(archive), "-d", str(dest), "nothere/"]) == EXIT_FAIL
    assert "pattern matched no members: 'nothere/'" in capsys.readouterr().err


def test_a_matching_pattern_wins_over_the_dash_d_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``out`` names a local folder and a directory in the archive: it is a pattern.

    The ``-d`` hint is for a pattern that matched nothing; this one matched.
    """
    archive = _tar(
        tmp_path / "t.tar", [("out", None), ("out/a.txt", b"a"), ("top.txt", b"t")]
    )
    work = tmp_path / "work"
    (work / "out").mkdir(parents=True)
    monkeypatch.chdir(work)
    assert main(["x", str(archive), "out"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "did you mean -d" not in err
    assert (work / "out" / "a.txt").read_bytes() == b"a"
    assert not (work / "top.txt").exists()


# --- One pass, and an empty selection fails the same way -------------------------

# Larger than the 1 MiB rewind that the library reports, so a second pass over the
# compressed TAR shows on stderr. The report is an INFO record, which reaches stderr
# only under ``-v``, so the test passes it. Zeros, so the file stays small.
_BIG = b"\0" * (2 * 1024 * 1024)


@pytest.mark.parametrize("verb", ["t", "x"])
def test_a_pattern_on_a_compressed_tar_reads_it_once(
    verb: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A TAR inside gzip has no member index. Finding unmatched patterns must not cost
    a scan of its own, which then has to seek back and decompress everything again."""
    archive = _tar(
        tmp_path / "t.tar.gz", [("a.txt", b"a"), ("big.bin", _BIG), ("z.txt", b"z")]
    )
    dest = tmp_path / "out"
    args = [verb, "-v", str(archive), "a.txt", "missing"]
    if verb == "x":
        args += ["-d", str(dest)]
    assert main(args) == EXIT_OK
    err = capsys.readouterr().err
    assert "Backward seek" not in err
    assert "warning: pattern matched no members: 'missing'" in err
    if verb == "x":
        assert sorted(p.name for p in dest.iterdir()) == ["a.txt"]


_EMPTY_SELECTIONS = {
    "every include match excluded": (
        ["docs"],
        ["docs"],
        (
            "warning: no members selected: --exclude removed every member the "
            "patterns matched"
        ),
    ),
    "exclude only": (
        [],
        ["*"],
        "warning: no members selected: --exclude removed every member",
    ),
    "include misses": (
        ["missing"],
        [],
        "warning: pattern matched no members: 'missing'",
    ),
}


def _zip(path: Path, entries: list[tuple[str, bytes | None]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries:
            if content is None:
                archive.writestr(name + "/", b"")
            else:
                archive.writestr(name, content)
    return path


@pytest.mark.parametrize("case", sorted(_EMPTY_SELECTIONS))
@pytest.mark.parametrize("kind", ["zip", "tar.gz"])
@pytest.mark.parametrize("verb", ["t", "x"])
def test_patterns_that_select_nothing_fail_with_a_message(
    verb: str,
    kind: str,
    case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exit 1 and a warning, whatever emptied the selection, with an index (ZIP) or
    without one (TAR inside gzip). ``extract`` leaves nothing on disk, not even the
    directory it would have extracted into."""
    includes, excludes, message = _EMPTY_SELECTIONS[case]
    make = _zip if kind == "zip" else _tar
    archive = make(tmp_path / f"a.{kind}", [("docs", None), ("docs/a.txt", b"a")])
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    args = [verb, str(archive), *includes]
    for pattern in excludes:
        args += ["--exclude", pattern]
    assert main(args) == EXIT_FAIL
    err = capsys.readouterr().err
    assert message in err
    assert "OK," not in err
    assert "extracted" not in err
    # A dest named with -d is not left behind either, nor the parents made for it.
    if verb == "x":
        assert main([*args, "-d", "made/for/it"]) == EXIT_FAIL
    assert list(work.iterdir()) == []


def test_list_warns_when_patterns_select_nothing_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _tar(tmp_path / "t.tar", _TREE)
    assert main(["list", str(archive), "docs", "--exclude", "docs"]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        "warning: no members selected: --exclude removed every member the "
        "patterns matched" in captured.err
    )


@pytest.mark.parametrize("verb", ["t", "x"])
def test_exclude_on_an_empty_archive_is_not_an_empty_selection(
    verb: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With no members, ``--exclude`` removed nothing: the run is as without it.

    (A TAR with no members has nothing to detect it by, so this uses a ZIP.)"""
    archive = _zip(tmp_path / "empty.zip", [])
    args = [verb, str(archive), "--exclude", "*"]
    if verb == "x":
        args += ["-d", str(tmp_path / "out")]
    assert main(args) == EXIT_OK
    assert "no members selected" not in capsys.readouterr().err


def _chmod_denies_reads(path: Path) -> bool:
    """Whether ``chmod 000`` stops this process reading ``path`` (not as root, not on
    Windows)."""
    try:
        path.read_bytes()
    except PermissionError:
        return True
    return False


@pytest.mark.parametrize("verb", ["t", "x"])
def test_an_unmatched_pattern_is_reported_after_a_member_fails(
    verb: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A member that fails does not end the pass: every member was still offered to
    the patterns, so the unmatched one is reported. A directory has no index, and its
    pass goes on past a file it cannot open."""
    tree = tmp_path / "tree"
    tree.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (tree / name).write_bytes(name.encode())
    unreadable = tree / "b.txt"
    unreadable.chmod(0)
    try:
        if not _chmod_denies_reads(unreadable):
            pytest.skip("chmod 000 does not deny reads here")
        args = [verb, str(tree), "*.txt", "nosuch"]
        if verb == "x":
            args += ["-d", str(tmp_path / "out")]
        assert main(args) == EXIT_FAIL
        err = capsys.readouterr().err
        assert "1 failed" in err
        assert "warning: pattern matched no members: 'nosuch'" in err
    finally:
        unreadable.chmod(0o644)


_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("verb", ["t", "x"])
def test_a_damaged_index_does_not_settle_the_patterns(
    verb: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A free member list that ends in damage holds only the members before it. A
    pattern naming a later member is not known to match nothing, so it is not
    reported as such; the run's own pass reaches the damage and reports it."""
    archive = tmp_path / "tinyvol_cut.part1.rar"
    archive.write_bytes((_FIXTURES / "rar" / "tinyvol_cut.part1.rar").read_bytes())
    monkeypatch.chdir(tmp_path)
    args = [verb, archive.name, "c.txt"]
    if verb == "x":
        args += ["-d", "out"]
    assert main(args) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "pattern matched no members" not in err
    assert "volume 2" in err


def test_the_dash_d_hint_skips_a_directory_the_run_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With no index, ``extract`` creates ``-d out`` before the patterns are judged.
    It removes that directory before the warning, so the hint does not point at it;
    a directory that was already there is the operator's and gets the hint."""
    archive = _tar(tmp_path / "t.tar.gz", [("docs", None), ("docs/a.txt", b"a")])
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    args = ["x", str(archive), "out", "-d", "out"]
    assert main(args) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "warning: pattern matched no members: 'out'" in err
    assert "did you mean" not in err
    assert list(work.iterdir()) == []

    (work / "out").mkdir()
    assert main(args) == EXIT_FAIL
    assert "(did you mean -d out?)" in capsys.readouterr().err


def _cut_rar(tmp_path: Path, *, file_index: int) -> Path:
    """``basic_nonsolid__.rar`` cut inside the header of its ``file_index``-th FILE
    block: the listing is the files before the cut, then a truncation error."""
    archive = tmp_path / "cut.rar"
    archive.write_bytes(
        _rar_cut("basic_nonsolid__.rar", rar4=False, file_index=file_index)
    )
    return archive


def test_a_damaged_index_still_counts_the_untested_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A listing that ends in damage does not settle the patterns, but its members
    are still the totals. When the pass dies after the first of the three listed
    files, the summary reports the one it never reached."""
    archive = _cut_rar(tmp_path, file_index=3)
    original = BaseArchiveReader.stream_members

    def _dies_after_first(
        self: BaseArchiveReader, *args: object, **kwargs: object
    ) -> MemberPass:
        def _gen() -> Iterator[object]:
            members = original(self, *args, **kwargs)  # type: ignore[arg-type]
            yield next(members)
            raise ReadError("simulated stream failure")

        return MemberPass(_gen())  # type: ignore[arg-type]

    monkeypatch.setattr(BaseArchiveReader, "stream_members", _dies_after_first)
    assert main(["t", str(archive)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "1 OK, 1 failed, 1 not tested" in err


def test_extract_aborted_on_a_damaged_index_claims_no_unmatched_pattern(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The pass reaches the damage and aborts, so the patterns are never judged: the
    command exits 1 with the listing error and no "matched no members" claim. The
    spec lets the aborted run leave the ``-d`` directory it created; nothing is
    written into it."""
    archive = _cut_rar(tmp_path, file_index=2)
    monkeypatch.chdir(tmp_path)
    assert main(["x", archive.name, "nosuch", "-d", "out"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "pattern matched no members" not in err
    assert "truncated" in err
    assert "extraction stopped" in err
    out = tmp_path / "out"
    assert not out.exists() or list(out.iterdir()) == []


def test_list_on_a_damaged_index_claims_no_unmatched_pattern(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``list`` has no pass after its listing. A pattern may name a member after the
    damage, so ``list`` gives no pattern warning and prints the listing error."""
    archive = _cut_rar(tmp_path, file_index=2)
    assert main(["list", str(archive), "nosuch"]) == EXIT_FAIL
    captured = capsys.readouterr()
    assert "pattern matched no members" not in captured.err
    assert "truncated" in captured.err
    assert captured.out == ""
