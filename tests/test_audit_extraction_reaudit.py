"""Reproducers from the 2026-09-30 extraction re-audit.

The 2026-09 security audit's extraction pass was its narrowest
(``review/archive/2026-09-29-extraction-audit/SUMMARY.md``), so extraction was audited
again: ``internal/extraction.py``, ``internal/filters.py``, link handling, and the CLI
``extract`` / ``test`` paths. Numbering continues the audit's E1-E4.

Each test asserts the promised behaviour. The one still open is
``xfail(strict=True)`` with the defect in ``reason``: a fix makes the test XPASS, which
fails CI until the marker is removed. The rest are regression tests for the fixes.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
from pathlib import Path
from typing import Any

import pytest

import archivey
from archivey import ExtractionStatus
from archivey.cli.main import main
from tests.conftest import requires_unrar_cli
from tests.extract_util import open_and_extract

posix_links = pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")


def _build_tar(path: Path, entries: list[tuple]) -> Path:
    """Write a TAR of ``(name, kind, payload[, TarInfo attributes])`` entries.

    ``kind`` is ``file`` (payload is the content), ``sym`` / ``hard`` (payload is the
    link name) or ``dir``.
    """
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        for name, kind, payload, *rest in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if kind == "dir" else 0o644
            for key, value in (rest[0] if rest else {}).items():
                setattr(info, key, value)
            if kind == "file":
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
                continue
            info.type = {
                "sym": tarfile.SYMTYPE,
                "hard": tarfile.LNKTYPE,
                "dir": tarfile.DIRTYPE,
            }[kind]
            if kind in ("sym", "hard"):
                info.linkname = payload
            tf.addfile(info)
    return path


def _links_escaping(root: Path) -> list[str]:
    """Every symlink under ``root`` that resolves outside it."""
    real_root = root.resolve()
    escaping = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                resolved = path.resolve()
                if not (resolved == real_root or resolved.is_relative_to(real_root)):
                    escaping.append(f"{path} -> {os.readlink(path)} = {resolved}")
    return escaping


# --- CLI: the single-root hoist ---------------------------------------------------


@posix_links
def test_hoist_leaves_no_symlink_resolving_outside_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("keys")
    downloads = home / "Downloads"
    downloads.mkdir()
    # No member index for TAR, so `archivey x` extracts into ./.ssh/ (named after the
    # archive) and hoists the single top-level entry `top` into the working directory.
    _build_tar(
        downloads / ".ssh.tar",
        [
            ("top", "dir", None),
            ("top/k", "sym", "../../.ssh/authorized_keys"),
            ("top/f", "file", b"data"),
        ],
    )
    monkeypatch.chdir(downloads)

    main(["x", ".ssh.tar"])

    assert _links_escaping(downloads) == []


@posix_links
@pytest.mark.parametrize("policy", ["strict", "standard", "trusted"])
def test_hoist_does_not_move_a_tree_it_could_not_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: str
) -> None:
    # `top/d` stands for a directory the extraction made unreadable (mode 0o300 under
    # STANDARD or TRUSTED): the walk cannot see `k`, so it must not assume it is safe.
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("keys")
    downloads = home / "Downloads"
    downloads.mkdir()
    _build_tar(
        downloads / ".ssh.tar",
        [
            ("top", "dir", None),
            ("top/d", "dir", None),
            ("top/d/k", "sym", "../../../.ssh/authorized_keys"),
            ("top/f", "file", b"data"),
        ],
    )
    monkeypatch.chdir(downloads)
    real_scandir = os.scandir

    def unlistable(path: str = ".") -> Any:
        if os.fspath(path).endswith(f"{os.sep}d"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", unlistable)

    main(["x", "--policy", policy, ".ssh.tar"])

    monkeypatch.undo()
    assert _links_escaping(downloads) == []


@posix_links
@pytest.mark.parametrize(
    ("stem", "entries"),
    [
        # The only top-level entry is itself a link: the move changes the directory
        # its target is read from.
        pytest.param("etc", [("b", "sym", "../etc/passwd")], id="lone-link-top"),
        pytest.param("etc", [("b", "sym", "passwd")], id="lone-link-no-dotdot"),
        # A step up into the wrapper blocks even when it comes back down by name:
        # from the working directory, the same step could reach another name.
        pytest.param(
            "pkg",
            [("top", "dir", None), ("top/a/l", "sym", "../../top/x")],
            id="up-and-back-in",
        ),
        # `a/../passwd` never climbs on paper, but `a` is `top`, so `..` is the
        # wrapper, and after the move the working directory's own `passwd`.
        pytest.param(
            "pkg",
            [
                ("top", "dir", None),
                ("top/sub", "dir", None),
                ("top/sub/a", "sym", ".."),
                ("top/sub/l", "sym", "a/../passwd"),
            ],
            id="chain-hides-a-climb",
        ),
    ],
)
def test_hoist_does_not_move_a_link_whose_meaning_would_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stem: str,
    entries: list,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "passwd").write_text("the operator's file")
    _build_tar(work / f"{stem}.tar", entries)
    monkeypatch.chdir(work)

    main(["x", f"{stem}.tar"])

    # Nothing left the wrapper: the only entry in the working directory besides the
    # operator's file and the archive is the wrapper itself.
    assert sorted(p.name for p in work.iterdir()) == sorted(
        ["passwd", f"{stem}.tar", stem]
    )
    assert f"kept in {stem}/: " in capsys.readouterr().err


@posix_links
@pytest.mark.parametrize(
    ("entries", "unlistable"),
    [
        ([("top", "sym", "passwd")], False),
        ([("top", "dir", None), ("top/k", "sym", "../passwd")], False),
        (
            [
                ("top", "dir", None),
                ("top/sub", "dir", None),
                ("top/sub/a", "sym", ".."),
                ("top/sub/l", "sym", "a/../passwd"),
            ],
            False,
        ),
        # `top/d` stands for a directory extracted without its read bit (0o300 under
        # STANDARD): neither walk can see `k`, so neither may assume it is safe.
        (
            [
                ("top", "dir", None),
                ("top/d", "dir", None),
                ("top/d/k", "sym", "../../passwd"),
            ],
            True,
        ),
    ],
    ids=[
        "lone-symlink",
        "link-leaves-the-entry",
        "chain-hides-a-climb",
        "unlistable-directory",
    ],
)
def test_a_dry_run_predicts_the_hoist_keeping_the_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entries: list,
    unlistable: bool,
) -> None:
    # Each case is one the real hoist leaves in the wrapper. The dry run must say so
    # too, not "would move", and name the same place in its summary.
    if unlistable:
        real_scandir = os.scandir

        def refuse_d(path: Any = ".") -> Any:
            # shutil.rmtree lists by file descriptor; only paths are refused.
            if not isinstance(path, int) and os.fspath(path).endswith(f"{os.sep}d"):
                raise PermissionError(13, "Permission denied", os.fspath(path))
            return real_scandir(path)

        monkeypatch.setattr(os, "scandir", refuse_d)
    runs = {}
    for dry_run in (False, True):
        cwd = tmp_path / ("dry" if dry_run else "real")
        cwd.mkdir()
        _build_tar(cwd / "bundle.tar", entries)
        monkeypatch.chdir(cwd)
        out, err = io.StringIO(), io.StringIO()
        argv = ["x", "--overwrite", "skip", "bundle.tar", "--hide-progress"]
        code = main([*argv, "--dry-run"] if dry_run else argv, out=out, err=err)
        runs[dry_run] = (code, err.getvalue())
    (real_code, real_err), (dry_code, dry_err) = runs[False], runs[True]
    assert "kept in bundle/: " in real_err
    reason = real_err.split("kept in bundle/: ", 1)[1].splitlines()[0]
    assert f"would keep in bundle/: {reason}" in dry_err
    assert "would move" not in dry_err
    assert dry_code == real_code
    assert (
        real_err.splitlines()[-1].split(" → ")[1]
        == dry_err.splitlines()[-1].split(" → ")[1]
    )


@posix_links
@pytest.mark.parametrize("top", ["pkg", "top"], ids=["flatten", "merge-move"])
def test_hoist_moves_a_tree_whose_links_stay_inside_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, top: str
) -> None:
    # The ordinary package shape: a relative `..` link that stays inside the tree.
    _build_tar(
        tmp_path / "pkg.tar",
        [
            (top, "dir", None),
            (f"{top}/lib/a.so", "file", b"so"),
            (f"{top}/bin/a", "sym", "../lib/a.so"),
        ],
    )
    monkeypatch.chdir(tmp_path)

    main(["x", "pkg.tar"])

    assert (tmp_path / top / "bin" / "a").read_bytes() == b"so"
    assert not (tmp_path / top / top).exists()


@posix_links
def test_hoist_still_moves_a_tree_whose_links_only_go_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _build_tar(
        tmp_path / "pkg.tar",
        [
            ("top", "dir", None),
            ("top/x", "file", b"x"),
            ("top/l", "sym", "x"),
            ("top/sub/m", "sym", "./n/o"),
        ],
    )
    monkeypatch.chdir(tmp_path)

    main(["x", "pkg.tar"])

    assert (tmp_path / "top" / "l").read_bytes() == b"x"
    assert not (tmp_path / "pkg").exists()


@posix_links
def test_hoist_flatten_keeps_links_inside_the_reported_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "outside.txt").write_text("the operator's file")
    _build_tar(
        tmp_path / "src.tar",
        [("src", "dir", None), ("src/l", "sym", "../outside.txt")],
    )
    monkeypatch.chdir(tmp_path)

    main(["x", "src.tar"])

    # The summary line reports `src/` as the destination.
    assert _links_escaping(tmp_path / "src") == []


@pytest.mark.parametrize("overwrite", ["error", "skip", "replace", "rename"])
def test_extraction_never_enters_the_operators_own_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
) -> None:
    (tmp_path / "backup").mkdir()
    (tmp_path / "backup" / "notes.txt").write_text("operator data")
    _build_tar(tmp_path / "backup.tar", [("../evil", "file", b"x")])
    monkeypatch.chdir(tmp_path)

    main(["x", "--overwrite", overwrite, "backup.tar"])

    # The wrapper is a new `backup (1)/`, so the hoist can only move this run's files.
    assert sorted(p.name for p in (tmp_path / "backup").iterdir()) == ["notes.txt"]
    assert (tmp_path / "backup" / "notes.txt").read_text() == "operator data"
    assert not (tmp_path / "notes.txt").exists()
    assert "extracting into backup (1)/" in capsys.readouterr().err


# --- Directory members and the caller's directories ---------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("policy", ["strict", "standard"])
def test_a_directory_member_never_widens_an_existing_directory(
    tmp_path: Path, policy: str
) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [
            ("./", "dir", None, {"mode": 0o777}),
            ("./f", "file", b"x"),
            ("pre/", "dir", None, {"mode": 0o777}),
        ],
    )
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "pre").mkdir()
    os.chmod(dest, 0o700)
    os.chmod(dest / "pre", 0o700)

    report = open_and_extract(archive, dest, policy=policy)

    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(dest / "pre").st_mode) == 0o700
    # The results say so, since the tree now differs from the archive.
    kept = {r.member.name: r.kept_mode for r in report.results}
    assert kept == {".": 0o700, "f": None, "pre/": 0o700}


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_directory_this_run_created_still_gets_its_mode(tmp_path: Path) -> None:
    # `d/f` creates `d` before the `d/` member arrives; `d` is still the archive's.
    archive = _build_tar(
        tmp_path / "a.tar",
        [("d/f", "file", b"x"), ("d/", "dir", None, {"mode": 0o750})],
    )
    dest = tmp_path / "out"

    report = open_and_extract(archive, dest, policy="standard")

    assert stat.S_IMODE(os.stat(dest / "d").st_mode) == 0o750
    assert all(r.kept_mode is None for r in report.results)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_destination_this_run_created_gets_the_root_members_mode(
    tmp_path: Path,
) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [("./", "dir", None, {"mode": 0o750}), ("./f", "file", b"x")],
    )
    dest = tmp_path / "out"

    report = open_and_extract(archive, dest, policy="standard")

    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o750
    assert all(r.kept_mode is None for r in report.results)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_directory_keeps_its_stored_mtime(tmp_path: Path, streaming: bool) -> None:
    """Directory metadata is applied once the run ends, so the child written after
    the directory does not move its mtime to now."""
    archive = _build_tar(
        tmp_path / "a.tar",
        [
            ("d", "dir", None, {"mtime": 1_000_000_000}),
            ("d/f", "file", b"x", {"mtime": 1_000_000_000}),
        ],
    )
    dest = tmp_path / "out"

    with archivey.open_archive(archive, streaming=streaming) as reader:
        reader.extract_all(dest)

    assert os.stat(dest / "d").st_mtime == 1_000_000_000


# --- Hardlinks after REPLACE ----------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_hardlink_to_a_replaced_source_does_not_get_the_replacements_content(
    tmp_path: Path, streaming: bool
) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [("a", "file", b"ORIGINAL"), ("A", "file", b"OTHER"), ("h", "hard", "a")],
    )
    dest = tmp_path / "out"

    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(
            dest, policy="standard", overwrite="replace", on_error="continue"
        )

    link = {r.member.name: r for r in report.results}["h"]
    if streaming:
        # The source's bytes streamed past and its path now holds `A`: out of reach.
        assert link.status is ExtractionStatus.FAILED
        assert isinstance(link.error, archivey.ExtractionError)
    else:
        # The second pass re-reads the source, as it does for an excluded one.
        assert link.status is ExtractionStatus.EXTRACTED
        assert (dest / "h").read_bytes() == b"ORIGINAL"


@posix_links
def test_hardlink_never_links_a_file_the_run_did_not_write(tmp_path: Path) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [("a", "file", b"ORIGINAL"), ("A", "sym", "victim"), ("h", "hard", "a")],
    )
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "victim").write_bytes(b"caller's file")

    open_and_extract(
        archive, dest, policy="standard", overwrite="replace", on_error="continue"
    )

    if (dest / "h").exists():
        assert not os.path.samefile(dest / "h", dest / "victim")


# --- Results that say EXTRACTED for content that is gone --------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_replacing_a_directory_revises_the_members_written_inside_it(
    tmp_path: Path, streaming: bool
) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [("d", "dir", None), ("d/f", "file", b"x"), ("d", "file", b"FILE")],
    )
    dest = tmp_path / "out"

    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(dest, overwrite="replace", on_error="continue")

    for result in report.results:
        if result.status is ExtractionStatus.EXTRACTED:
            assert result.path is not None
            assert os.path.lexists(result.path), result.member.name
    extracted = [r for r in report.results if r.status is ExtractionStatus.EXTRACTED]
    assert len({r.path for r in extracted}) == len(extracted)
    # REPLACE removes only an empty directory, as GNU tar does.
    last = report.results[-1]
    assert last.status is ExtractionStatus.FAILED
    assert "not empty" in str(last.error)
    assert (dest / "d" / "f").read_bytes() == b"x"


@posix_links
def test_two_members_written_to_one_file_through_a_symlink_are_not_both_extracted(
    tmp_path: Path,
) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [
            ("d", "dir", None),
            ("s", "sym", "d"),
            ("s/f", "file", b"FIRST"),
            ("d/f", "file", b"SECOND"),
        ],
    )

    report = open_and_extract(archive, tmp_path / "out", overwrite="replace")

    files = [
        r
        for r in report.results
        if r.member.type is archivey.MemberType.FILE
        and r.status is ExtractionStatus.EXTRACTED
    ]
    assert len({os.path.realpath(r.path) for r in files}) == len(files)
    by_name = {r.member.name: r for r in report.results}
    assert by_name["s/f"].status is ExtractionStatus.OVERWRITTEN
    assert by_name["d/f"].collided_with is not None


@posix_links
@pytest.mark.parametrize("streaming", [False, True])
def test_a_collision_through_a_repointed_symlink_lands_where_the_member_named(
    tmp_path: Path, streaming: bool
) -> None:
    # ``s/f`` claims ``d1/f`` while ``s -> d1``. After ``s`` is repointed to ``d2``, the
    # claim's name ``s/f`` names ``d2/f``, so routing ``d1/f`` to that name wrote it
    # into ``d2``.
    archive = _build_tar(
        tmp_path / "a.tar",
        [
            ("d1", "dir", None),
            ("d2", "dir", None),
            ("s", "sym", "d1"),
            ("s/f", "file", b"A"),
            ("s", "sym", "d2"),
            ("s/f", "file", b"C"),
            ("d1/f", "file", b"D"),
        ],
    )
    dest = tmp_path / "out"

    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(
            dest, policy="standard", overwrite="replace", on_error="continue"
        )

    assert (dest / "d1" / "f").read_bytes() == b"D"
    assert (dest / "d2" / "f").read_bytes() == b"C"
    last = report.results[-1]
    assert last.status is ExtractionStatus.EXTRACTED
    assert last.path is not None
    assert os.path.realpath(last.path) == os.path.realpath(dest / "d1" / "f")


# --- Untyped errors -----------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="Linux name limits")
@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(("x" * 300, "file", b"x"), id="component-over-255-bytes"),
        pytest.param(
            ("/".join(["d" * 200] * 25) + "/f", "file", b"x"), id="path-over-4096"
        ),
        pytest.param(("s", "sym", "t" * 5000), id="link-target-over-4096"),
    ],
)
def test_a_name_too_long_for_the_filesystem_is_a_typed_member_failure(
    tmp_path: Path, entry: tuple
) -> None:
    archive = _build_tar(tmp_path / "a.tar", [entry, ("ok", "file", b"y")])

    try:
        report = open_and_extract(archive, tmp_path / "out")
    except archivey.ArchiveyError:
        return  # a typed stop is fine
    first = report.results[0]
    assert first.error is None or isinstance(first.error, archivey.ArchiveyError)


@posix_links
def test_a_symlink_loop_in_the_destination_is_not_a_raw_runtime_error(
    tmp_path: Path,
) -> None:
    archive = _build_tar(
        tmp_path / "a.tar", [("x/f", "file", b"x"), ("ok", "file", b"y")]
    )
    dest = tmp_path / "out"
    dest.mkdir()
    os.symlink("x", dest / "x")  # x -> x

    report = open_and_extract(archive, dest, on_error="continue")

    assert {r.member.name: r.status for r in report.results}["ok"] is (
        ExtractionStatus.EXTRACTED
    )


def test_a_filter_returning_a_non_member_gets_a_type_error_naming_the_filter(
    tmp_path: Path,
) -> None:
    archive = _build_tar(tmp_path / "a.tar", [("f", "file", b"x")])

    with (
        archivey.open_archive(archive) as reader,
        pytest.raises(TypeError, match="filter"),
    ):
        reader.extract_all(tmp_path / "out", filter=lambda member: True)


# --- Directory sources --------------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_a_directory_source_is_not_extracted_into_itself(
    tmp_path: Path, streaming: bool
) -> None:
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "a.txt").write_text("a")
    (source / "sub" / "b.txt").write_text("b")

    names: list[str] = []

    class _Runaway(Exception):
        pass

    def on_progress(progress: archivey.ExtractionProgress) -> None:
        # The source has four entries; a streaming pass reading its own output would
        # otherwise run until the path is too long (tens of seconds).
        names.append(progress.member.name)
        if len(names) > 20:
            raise _Runaway

    try:
        with archivey.open_archive(source, streaming=streaming) as reader:
            reader.extract_all(
                source / "copy", on_error="continue", on_progress=on_progress
            )
    except archivey.ArchiveyError:
        return  # refusing the call is fine
    except _Runaway:
        pass
    assert not [name for name in names if name.startswith("copy")]


# --- Links to links -----------------------------------------------------------------


@posix_links
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    ("entries", "target"),
    [
        # The symlink's target passes through another symlinked directory, where a
        # lookup by member name finds nothing.
        pytest.param(
            [("y/x", "file", b"YX"), ("sub", "sym", "y"), ("s", "sym", "sub/x")],
            "sub/x",
            id="through-a-symlinked-directory",
        ),
        pytest.param(
            [("sub/x", "file", b"YX"), ("s", "sym", "sub/x")],
            "sub/x",
            id="plain-chain",
        ),
        # `h` names another hard link to the symlink, which GNU tar also makes a
        # symlink.
        pytest.param(
            [("sub/x", "file", b"YX"), ("s", "sym", "sub/x"), ("h0", "hard", "s")],
            "sub/x",
            id="through-another-hardlink",
        ),
    ],
)
def test_a_hardlink_to_a_symlink_is_a_second_symlink(
    tmp_path: Path, streaming: bool, entries: list, target: str
) -> None:
    # GNU tar makes `h` a second name for the symlink `s`, so `h` is a symlink with
    # the same target.
    link_to = "h0" if entries[-1][0] == "h0" else "s"
    archive = _build_tar(tmp_path / "a.tar", [*entries, ("h", "hard", link_to)])
    dest = tmp_path / "out"

    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(dest, policy="standard", on_error="continue")

    assert {r.member.name: r.status for r in report.results}["h"] is (
        ExtractionStatus.EXTRACTED
    )
    assert os.readlink(dest / "h") == target
    assert (dest / "h").read_bytes() == b"YX"


@posix_links
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("shape", ["fan-out", "chain"])
def test_hard_links_cost_linear_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    streaming: bool,
    shape: str,
) -> None:
    # Counts rather than wall time. Every link names `base` (fan-out, what GNU tar
    # makes) or the link before it (chain). Each link should check one recorded path
    # before linking and look up one direct target; rechecking every earlier path, or
    # walking the chain from scratch for each link, makes both grow as N².
    from archivey.internal import base_reader, extraction

    n = 300
    entries: list[tuple] = [("base", "file", b"AB")]
    for i in range(n):
        previous = "base" if shape == "fan-out" or i == 0 else f"h{i - 1}"
        entries.append((f"h{i}", "hard", previous))
    archive = _build_tar(tmp_path / "a.tar", entries)
    counts = {"checks": 0, "lookups": 0}

    is_regular_file = extraction._is_regular_file
    direct_target = base_reader.BaseArchiveReader._hardlink_direct_target

    def counting_check(path: Path) -> bool:
        counts["checks"] += 1
        return is_regular_file(path)

    def counting_lookup(self: Any, member: Any) -> Any:
        counts["lookups"] += 1
        return direct_target(self, member)

    monkeypatch.setattr(extraction, "_is_regular_file", counting_check)
    monkeypatch.setattr(
        base_reader.BaseArchiveReader, "_hardlink_direct_target", counting_lookup
    )
    with archivey.open_archive(archive, streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out", policy="standard")

    assert all(r.status is ExtractionStatus.EXTRACTED for r in report.results)
    assert os.stat(tmp_path / "out" / f"h{n - 1}").st_nlink == n + 1
    assert counts["checks"] <= 2 * n
    assert counts["lookups"] <= 2 * n


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "shape", ["bottom-names-nothing", "bottom-names-a-later-file", "forward-run"]
)
def test_a_chain_with_forward_names_costs_linear_lookups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    streaming: bool,
    shape: str,
) -> None:
    # Chains whose links name members not listed before them. Such a link resolves to
    # nothing, and that answer is memoized like any other. "forward-run" is a run of
    # links that each name the next, entered by many later links.
    from archivey.internal import base_reader

    n = 300
    entries: list[tuple]
    if shape == "forward-run":
        half = n // 2
        entries = [(f"n{i}", "hard", f"n{i + 1}") for i in range(1, half)]
        entries.append((f"n{half}", "file", b"AB"))
        entries += [(f"z{j}", "hard", "n1") for j in range(half)]
    else:
        target = "ghost" if shape == "bottom-names-nothing" else "tail"
        entries = [("h0", "hard", target)]
        if shape == "bottom-names-a-later-file":
            entries.append(("tail", "file", b"AB"))
        entries += [(f"h{i}", "hard", f"h{i - 1}") for i in range(1, n)]
    archive = _build_tar(tmp_path / "a.tar", entries)
    lookups = 0
    direct_target = base_reader.BaseArchiveReader._hardlink_direct_target

    def counting_lookup(self: Any, member: Any) -> Any:
        nonlocal lookups
        lookups += 1
        return direct_target(self, member)

    monkeypatch.setattr(
        base_reader.BaseArchiveReader, "_hardlink_direct_target", counting_lookup
    )
    with archivey.open_archive(archive, streaming=streaming) as reader:
        reader.extract_all(tmp_path / "out", policy="standard", on_error="continue")

    assert lookups <= 2 * n


@posix_links
@pytest.mark.parametrize("streaming", [False, True])
def test_a_chain_through_a_later_symlink_extracts_the_same_in_every_mode(
    tmp_path: Path, streaming: bool
) -> None:
    # `h0` names a symlink listed after it, and `h3` and `h4` reach it through `h0`
    # after it is listed. A hard link never resolves forward, so the result must not
    # depend on the mode.
    archive = _build_tar(
        tmp_path / "a.tar",
        [
            ("sub", "dir", None),
            ("sub/x", "file", b"X"),
            ("h0", "hard", "late"),
            ("h1", "hard", "h0"),
            ("h2", "hard", "h1"),
            ("late", "sym", "sub/x"),
            ("h3", "hard", "h2"),
            ("h4", "hard", "h3"),
        ],
    )

    def outcome(dest: Path, streaming: bool) -> dict[str, tuple[str, str]]:
        with archivey.open_archive(archive, streaming=streaming) as reader:
            report = reader.extract_all(dest, policy="standard", on_error="continue")
        kinds = {}
        for r in report.results:
            path = dest / r.member.name
            kind = (
                f"symlink -> {os.readlink(path)}"
                if path.is_symlink()
                else "file"
                if path.is_file()
                else "absent"
            )
            kinds[r.member.name] = (r.status.name, kind)
        return kinds

    reference = outcome(tmp_path / "ref", streaming=False)
    assert outcome(tmp_path / "out", streaming) == reference
    assert reference["late"] == ("EXTRACTED", "symlink -> sub/x")


@posix_links
def test_a_filter_sees_a_hardlink_to_a_symlink_as_the_hardlink(tmp_path: Path) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [("sub/x", "file", b"YX"), ("s", "sym", "sub/x"), ("h", "hard", "s")],
    )
    dest = tmp_path / "out"
    seen: dict[str, archivey.MemberType] = {}

    def no_hardlinks(member: archivey.ArchiveMember) -> archivey.ArchiveMember | None:
        seen[member.name] = member.type
        return None if member.type is archivey.MemberType.HARDLINK else member

    with archivey.open_archive(archive) as reader:
        reader.extract_all(dest, policy="standard", filter=no_hardlinks)

    assert seen["h"] is archivey.MemberType.HARDLINK
    assert not os.path.lexists(dest / "h")


@posix_links
def test_a_hardlink_to_an_escaping_symlink_is_blocked_like_it(tmp_path: Path) -> None:
    archive = _build_tar(
        tmp_path / "a.tar",
        [("s", "sym", "../outside"), ("h", "hard", "s")],
    )
    dest = tmp_path / "out"

    report = open_and_extract(archive, dest, policy="standard")

    statuses = {r.member.name: r.status for r in report.results}
    assert statuses == {"s": ExtractionStatus.BLOCKED, "h": ExtractionStatus.BLOCKED}
    assert not os.path.lexists(dest / "h")


# --- RAR hard links against unrar -------------------------------------------------


def _rar5_with(entries: list[tuple]) -> bytes:
    """A stored RAR5 archive of ``(name, kind, payload)`` entries, as `_build_tar` takes.

    ``hard`` is a RAR5 hard-link redirect, which ``rar`` itself never points at a
    symlink or at a later member; these are the shapes a crafted archive can carry.
    """
    import struct
    import zlib

    from tests.test_audit_rar_iso_dir import _rar5_build, _vint

    def redirect(kind: int, target: str) -> bytes:
        record = (
            _vint(5) + _vint(kind) + _vint(0) + _vint(len(target)) + target.encode()
        )
        return _vint(len(record)) + record

    blocks: list[dict[str, Any]] = [
        {"type": 1, "flags": 0, "body": _vint(0), "extra": b"", "data": b""}
    ]
    for name, kind, payload in entries:
        block: dict[str, Any] = {
            "type": 2,
            "flags": 0,
            "file_flags": 0,
            "unpacked": 0,
            "mtime": None,
            "crc": None,
            "cinfo": 0,
            "host_os": 1,
            "name": name.encode(),
            "extra": b"",
            "data": b"",
        }
        if kind == "dir":
            block.update(file_flags=1, attr=0o40755)
        elif kind == "file":
            block.update(
                attr=0o100644,
                unpacked=len(payload),
                crc=struct.pack("<I", zlib.crc32(payload)),
                data=payload,
            )
        else:
            block.update(
                attr=0o120777 if kind == "sym" else 0o100644,
                extra=redirect(1 if kind == "sym" else 4, payload),
            )
        blocks.append(block)
    blocks.append({"type": 5, "flags": 0, "body": _vint(0), "extra": b"", "data": b""})
    return _rar5_build(blocks)


def _tree(root: Path) -> dict[str, str]:
    """Every entry under ``root``: a symlink's target or a file's content."""
    seen: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            seen[rel] = f"-> {os.readlink(path)}"
        elif path.is_file():
            seen[rel] = path.read_bytes().decode()
    return seen


_SUB = [("sub", "dir", None), ("sub/x", "file", b"X")]


def _link_follows_symlinks(tmp_path: Path) -> bool:
    """Whether ``link(2)`` here links a symlink's target rather than the symlink."""
    probe = tmp_path / "link-probe"
    probe.mkdir()
    (probe / "t").write_bytes(b"")
    (probe / "s").symlink_to("t")
    os.link(probe / "s", probe / "h")
    return not (probe / "h").is_symlink()


@posix_links
@requires_unrar_cli()
@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(
            [*_SUB, ("s", "sym", "sub/x"), ("h", "hard", "s")], id="to-a-symlink"
        ),
        pytest.param(
            [*_SUB, ("h", "hard", "s"), ("s", "sym", "sub/x")], id="to-a-later-symlink"
        ),
        pytest.param(
            [
                *_SUB,
                ("s", "sym", "sub/x"),
                ("h1", "hard", "s"),
                ("h2", "hard", "h1"),
                ("h3", "hard", "h2"),
            ],
            id="chain-to-a-symlink",
        ),
        pytest.param(
            [
                *_SUB,
                ("h0", "hard", "late"),
                ("h1", "hard", "h0"),
                ("late", "sym", "sub/x"),
                ("h2", "hard", "h1"),
            ],
            id="chain-through-a-later-symlink",
        ),
        pytest.param([("h", "hard", "f"), ("f", "file", b"F")], id="to-a-later-file"),
        pytest.param(
            [
                ("n1", "hard", "n2"),
                ("n2", "hard", "n3"),
                ("n3", "file", b"F"),
                ("z", "hard", "n1"),
            ],
            id="chain-to-a-later-file",
        ),
    ],
)
def test_rar_hard_links_extract_as_unrar_does_in_both_modes(
    tmp_path: Path, entries: list[tuple], request: pytest.FixtureRequest
) -> None:
    # unrar links to what it has already written: a hard link whose target comes later
    # fails, and a hard link to a symlink is a second name for the symlink. Both modes
    # must leave the tree unrar leaves.
    import subprocess

    if request.node.callspec.id in {
        "to-a-symlink",
        "chain-to-a-symlink",
    } and _link_follows_symlinks(tmp_path):
        # macOS: unrar calls link(), which follows the symlink there, so its tree
        # depends on the platform. archivey writes a second symlink everywhere, as
        # GNU tar does; that half is covered on Linux.
        pytest.skip("link(2) follows symlinks on this platform, and unrar with it")
    archive = tmp_path / "a.rar"
    archive.write_bytes(_rar5_with(entries))
    expected_root = tmp_path / "unrar"
    expected_root.mkdir()
    subprocess.run(
        ["unrar", "x", "-o+", "-idq", str(archive)],
        cwd=expected_root,
        check=False,
        capture_output=True,
    )
    expected = _tree(expected_root)

    for streaming in (False, True):
        dest = tmp_path / f"out-{streaming}"
        with archivey.open_archive(archive, streaming=streaming) as reader:
            reader.extract_all(dest, policy="standard", on_error="continue")
        assert _tree(dest) == expected, f"streaming={streaming}"


@pytest.mark.parametrize("streaming", [False, True])
def test_a_rar_hard_link_to_a_later_member_has_no_target(
    tmp_path: Path, streaming: bool
) -> None:
    # The reading side of the rule above: `h` names `f`, listed only after it, so `h`
    # has no target and opening it fails, in random access as in a streaming pass.
    from archivey.exceptions import LinkTargetNotFoundError

    archive = tmp_path / "a.rar"
    archive.write_bytes(_rar5_with([("h", "hard", "f"), ("f", "file", b"F")]))
    with archivey.open_archive(archive, streaming=streaming) as reader:
        if streaming:
            for member, stream in reader.stream_members():
                if member.name == "f":
                    assert stream is not None
                    assert stream.read() == b"F"
        listed = {m.name: m for m in reader.members_report().members}
    assert listed["h"].link_target_member is None
    if not streaming:
        with (
            archivey.open_archive(archive) as reader,
            pytest.raises(LinkTargetNotFoundError),
        ):
            reader.read("h")
