"""Extraction of a tree deeper than the interpreter's recursion limit.

An archive of ``a/a/a/…/f`` is a few hundred bytes, and extracting it must give the
tree or a library error, never ``RecursionError``. ``os.makedirs`` recurses once per
missing parent, and before Python 3.13 so do ``os.fwalk`` and ``shutil.rmtree``, which
removed a dry run's scratch copy. The limit is lowered rather than the tree made 1000
levels deep (``tests.stack_util``).
"""

from __future__ import annotations

import errno
import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

import archivey.internal.dry_run as dry_run_module
import archivey.internal.filters as filters_module
from archivey import ExtractionStatus, OverwritePolicy, open_archive
from archivey.internal.dry_run import remove_scratch
from archivey.internal.long_paths import make_dirs
from tests.stack_util import recursion_limit_above_caller

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the tree's path exceeds MAX_PATH on Windows"
)

# Deep enough that one frame per level overflows the headroom below, short enough that
# the paths stay far under PATH_MAX.
DEPTH = 300
# Frames the extraction itself needs above the test, whatever the depth.
HEADROOM = DEPTH // 2


def _deep_tar(*, directory_members: bool) -> bytes:
    """A tar of ``a/a/…/a/f`` (``DEPTH`` directories) and a symlink ``l`` beside
    ``f``, with a member for each directory when ``directory_members``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        if directory_members:
            for level in range(1, DEPTH + 1):
                info = tarfile.TarInfo("/".join(["a"] * level))
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
        leaf = "/".join(["a"] * DEPTH)
        info = tarfile.TarInfo(f"{leaf}/f")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"deep"))
        info = tarfile.TarInfo(f"{leaf}/l")
        info.type = tarfile.SYMTYPE
        info.linkname = "f"
        tf.addfile(info)
    return buf.getvalue()


def _extract(blob: bytes, dest: Path, **kwargs: object) -> list[ExtractionStatus]:
    with (
        recursion_limit_above_caller(HEADROOM),
        open_archive(io.BytesIO(blob)) as reader,
    ):
        report = reader.extract_all(dest, **kwargs)  # type: ignore[arg-type]
    return [result.status for result in report.results]


def _leaf(dest: Path) -> Path:
    return dest.joinpath(*(["a"] * DEPTH))


def _nothing_left_in_temp(tmp_path: Path) -> None:
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("archivey-dry-run-")]


@pytest.fixture(autouse=True)
def _scratch_in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The dry run's scratch copy goes to the temp directory; this one is the test's own,
    # so a scratch tree left behind is seen.
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr("tempfile.tempdir", None)


@pytest.mark.parametrize("directory_members", [False, True], ids=["implied", "listed"])
def test_tree_deeper_than_recursion_limit_extracts(
    tmp_path: Path, directory_members: bool
) -> None:
    blob = _deep_tar(directory_members=directory_members)
    dest = tmp_path / "out"

    statuses = _extract(blob, dest)

    assert set(statuses) == {ExtractionStatus.EXTRACTED}
    assert (_leaf(dest) / "f").read_bytes() == b"deep"
    assert os.readlink(_leaf(dest) / "l") == "f"

    # Again over the tree it made: every directory is there already.
    statuses = _extract(blob, dest, overwrite=OverwritePolicy.REPLACE)
    assert set(statuses) == {ExtractionStatus.EXTRACTED}
    assert (_leaf(dest) / "f").read_bytes() == b"deep"


@pytest.mark.parametrize(
    "fd_walk",
    [False, *([True] if dry_run_module._FD_WALK else [])],
    ids=lambda v: "fd-walk" if v else "path-walk",
)
@pytest.mark.parametrize("directory_members", [False, True], ids=["implied", "listed"])
def test_dry_run_of_a_tree_deeper_than_recursion_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fd_walk: bool,
    directory_members: bool,
) -> None:
    monkeypatch.setattr(dry_run_module, "_FD_WALK", fd_walk)
    blob = _deep_tar(directory_members=directory_members)
    dest = tmp_path / "out"

    statuses = _extract(blob, dest, dry_run=True)

    assert set(statuses) == {ExtractionStatus.EXTRACTED}
    assert not dest.exists()
    _nothing_left_in_temp(tmp_path)

    # Over a real copy of the tree, which the dry run copies into its scratch tree.
    _extract(blob, dest)
    statuses = _extract(blob, dest, dry_run=True, overwrite=OverwritePolicy.REPLACE)
    assert set(statuses) == {ExtractionStatus.EXTRACTED}
    _nothing_left_in_temp(tmp_path)


@pytest.mark.parametrize(
    "fd_walk",
    [False, *([True] if dry_run_module._FD_WALK else [])],
    ids=lambda v: "fd-walk" if v else "path-walk",
)
def test_remove_scratch_removes_a_deep_locked_tree_and_follows_no_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fd_walk: bool
) -> None:
    monkeypatch.setattr(dry_run_module, "_FD_WALK", fd_walk)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"keep")
    scratch = tmp_path / "scratch"
    leaf = scratch.joinpath(*(["d"] * DEPTH))
    leaf.mkdir(parents=True)
    (leaf / "f").write_bytes(b"f")
    (leaf / "to-outside").symlink_to(outside, target_is_directory=True)
    (scratch / "to-outside").symlink_to(outside, target_is_directory=True)
    # Locked bottom-up, so each directory can still be reached while it is locked.
    for directory in [leaf, *leaf.relative_to(scratch).parents]:
        path = scratch / directory
        if path != scratch:
            path.chmod(stat.S_IRUSR | stat.S_IXUSR)
    (scratch / "d").chmod(0)

    with recursion_limit_above_caller(HEADROOM):
        remove_scratch(scratch)

    assert not os.path.lexists(scratch)
    assert (outside / "keep").read_bytes() == b"keep"


def test_make_dirs_creates_a_chain_deeper_than_recursion_limit(tmp_path: Path) -> None:
    leaf = tmp_path.joinpath(*(["d"] * DEPTH))
    with recursion_limit_above_caller(HEADROOM):
        make_dirs(leaf)
        make_dirs(leaf)
    assert leaf.is_dir()


def test_make_dirs_accepts_what_makedirs_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to("real", target_is_directory=True)
    make_dirs(tmp_path / "real")
    make_dirs(tmp_path / "link")
    make_dirs(tmp_path / "link" / "x" / "y")
    assert (tmp_path / "real" / "x" / "y").is_dir()

    monkeypatch.chdir(tmp_path)
    make_dirs("rel/a")
    make_dirs(Path("rel/b"))
    assert (tmp_path / "rel" / "a").is_dir()
    assert (tmp_path / "rel" / "b").is_dir()


def test_make_dirs_raises_what_makedirs_raises(tmp_path: Path) -> None:
    (tmp_path / "file").write_bytes(b"")
    (tmp_path / "dangling").symlink_to("nowhere")
    (tmp_path / "loop").symlink_to("loop")
    with pytest.raises(FileExistsError):
        make_dirs(tmp_path / "file")
    with pytest.raises(NotADirectoryError):
        make_dirs(tmp_path / "file" / "x")
    with pytest.raises(FileExistsError):
        make_dirs(tmp_path / "dangling")
    with pytest.raises(OSError) as loop:
        make_dirs(tmp_path / "loop" / "x")
    assert loop.value.errno == errno.ELOOP
    for path in ("file", "file/x", "dangling", "dangling/x", "loop", "loop/x"):
        with pytest.raises(OSError) as ours:
            make_dirs(tmp_path / path)
        with pytest.raises(OSError) as theirs:
            os.makedirs(tmp_path / path, exist_ok=True)
        assert type(ours.value) is type(theirs.value)


@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
def test_a_deep_chain_of_implied_directories_is_resolved_once_per_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    # Each directory the run creates is resolved from its parent's cached answer, not
    # from the root again: resolving every level from the root cost the depth squared
    # in lookups, and minutes for a small archive 1500 levels deep.
    walks: list[str] = []
    real_walk = filters_module._realpath_posix

    def counted(path: str, asked: str, *, start: str = "") -> str:
        walks.append(path)
        return real_walk(path, asked, start=start)

    monkeypatch.setattr(filters_module, "_realpath_posix", counted)
    statuses = _extract(
        _deep_tar(directory_members=False), tmp_path / "out", dry_run=dry_run
    )
    assert set(statuses) == {ExtractionStatus.EXTRACTED}
    # A few per run and per member (the destination, each member's parent check, the
    # first level created), none per level: one per level would be DEPTH of them.
    assert len(walks) < 20
