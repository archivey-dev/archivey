"""Tests for the directory pseudo-backend."""

from __future__ import annotations

import errno
import io
import logging
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveMember,
    MemberType,
    open_archive,
)
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.types import ContainerFormat, StreamFormat
from tests.scandir_util import patch_dir_entry_stat

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def simple_dir(tmp_path: Path) -> Path:
    """A minimal directory: two files, one subdir, one nested file."""
    (tmp_path / "a.txt").write_bytes(b"hello")
    (tmp_path / "b.txt").write_bytes(b"world")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.txt").write_bytes(b"nested")
    return tmp_path


@pytest.fixture
def symlink_dir(tmp_path: Path) -> Path:
    """Directory containing a symlink pointing to a real file."""
    (tmp_path / "real.txt").write_bytes(b"real content")
    os.symlink("real.txt", tmp_path / "link.txt")
    return tmp_path


@pytest.fixture
def deep_dir(tmp_path: Path) -> Path:
    """Directory with several levels of nesting."""
    (tmp_path / "root.txt").write_bytes(b"root")
    level1 = tmp_path / "level1"
    level1.mkdir()
    (level1 / "l1.txt").write_bytes(b"level1")
    level2 = level1 / "level2"
    level2.mkdir()
    (level2 / "l2.txt").write_bytes(b"level2")
    return tmp_path


# ---------------------------------------------------------------------------
# Format detection and info
# ---------------------------------------------------------------------------


def test_open_directory_returns_reader(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        assert reader.format == ArchiveFormat.DIRECTORY  # type: ignore[attr-defined]


def test_open_directory_as_string(simple_dir: Path) -> None:
    with open_archive(str(simple_dir)) as reader:
        assert reader.format == ArchiveFormat.DIRECTORY  # type: ignore[attr-defined]


def test_explicit_directory_format_is_accepted(simple_dir: Path) -> None:
    with open_archive(simple_dir, format=ArchiveFormat.DIRECTORY) as reader:
        assert reader.format == ArchiveFormat.DIRECTORY  # type: ignore[attr-defined]


def test_conflicting_format_on_directory_raises(simple_dir: Path) -> None:
    # Silently overruling format= would hand back a reader over the directory tree to
    # a caller who asserted something else, and everything downstream would succeed on
    # the wrong data.
    with pytest.raises(archivey.ArchiveyUsageError, match="is a directory"):
        open_archive(simple_dir, format=ArchiveFormat.ZIP)


@pytest.mark.parametrize("form", ["path", "str", "stream"])
@pytest.mark.parametrize(
    "fmt",
    [
        ArchiveFormat.DIRECTORY,
        "directory",
        # An unnamed pair is refused on the container, not reported as a missing backend.
        ArchiveFormat(ContainerFormat.DIRECTORY, StreamFormat.GZIP),
    ],
)
def test_directory_format_on_a_file_raises_a_usage_error(
    tmp_path: Path, form: str, fmt: object
) -> None:
    """The mirror of the conflict above fails the same way.

    It used to escape as ``TypeError: Directory backend requires a directory path
    source``, naming an internal class instead of the argument.
    """
    path = tmp_path / "data.bin"
    path.write_bytes(b"not a directory")
    source: object = {"path": path, "str": str(path), "stream": io.BytesIO(b"x")}[form]
    with pytest.raises(archivey.ArchiveyUsageError, match="is not a directory"):
        open_archive(source, format=fmt)  # type: ignore[call-overload]


def test_directory_format_on_a_missing_path_raises_file_not_found(
    tmp_path: Path,
) -> None:
    """A path that does not exist is reported as missing, as under any other format=.

    Not the usage error above: that one asserts the path is not a directory, which
    nothing read for a path that is absent, and ``except FileNotFoundError`` around the
    open has to keep catching it.
    """
    missing = tmp_path / "absent"
    for fmt in (ArchiveFormat.DIRECTORY, ArchiveFormat.ZIP, None):
        with pytest.raises(FileNotFoundError) as exc_info:
            open_archive(missing, format=fmt)
        assert exc_info.value.errno == errno.ENOENT


def test_directory_format_on_a_path_under_a_file_raises_what_the_os_reports(
    tmp_path: Path,
) -> None:
    """The OS's own error, the same class under every format=.

    ``Path.exists()`` is False for this path too, and a check built on it reported
    ENOENT under ``DIRECTORY`` while ``ZIP`` and ``None`` raised whatever the OS
    reported. The class comes from the OS: POSIX reports ENOTDIR
    (``NotADirectoryError``), Windows reports ERROR_PATH_NOT_FOUND
    (``FileNotFoundError``).
    """
    (tmp_path / "a.txt").write_bytes(b"x")
    under_a_file = tmp_path / "a.txt" / "sub"
    try:
        open(under_a_file, "rb").close()
    except OSError as e:
        expected: type[OSError] = type(e)
    else:  # pragma: no cover - no OS opens a path under a regular file
        pytest.fail(f"opening {under_a_file} succeeded")
    if sys.platform != "win32":
        assert expected is NotADirectoryError
    for fmt in (ArchiveFormat.DIRECTORY, ArchiveFormat.ZIP, None):
        with pytest.raises(OSError) as exc_info:
            open_archive(under_a_file, format=fmt)
        assert type(exc_info.value) is expected, fmt


def test_archive_info_format(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        info = reader.info
        assert info.format == ArchiveFormat.DIRECTORY  # type: ignore[attr-defined]
        assert info.is_solid is False
        assert info.is_encrypted is False
        assert info.is_multivolume is False
        assert info.format_version is None
        assert info.comment is None


def test_cost_receipt(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        cost = reader.cost
        # A directory has no O(1) index; enumeration walks the tree (like a plain TAR).
        assert cost.listing_cost == ListingCost.REQUIRES_SCANNING
        assert cost.access_cost == AccessCost.DIRECT
        assert cost.stream_capability == StreamCapability.SEEKABLE
        assert cost.solid_block_count is None


def test_members_report_if_available_returns_none_before_scan(simple_dir: Path) -> None:
    # A directory has no upfront index: the scan-free peek must NOT trigger a walk,
    # so it returns None until a real pass (members()/members_report()) has run.
    with open_archive(simple_dir) as reader:
        assert reader.members_report_if_available() is None
        reader.members()  # forces the walk
        after = reader.members_report_if_available()
        assert after is not None and len(after) > 0


# ---------------------------------------------------------------------------
# Member listing
# ---------------------------------------------------------------------------


def test_members_returns_list(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        members = reader.members()
        assert isinstance(members, list)
        assert len(members) > 0


def test_members_include_files_and_dirs(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        members = reader.members()
        names = {m.name for m in members}
        assert "a.txt" in names
        assert "b.txt" in names
        assert "sub/" in names
        assert "sub/c.txt" in names


def test_bidi_control_name_warns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    name = "invoice\u202ecod.exe"
    (tmp_path / name).write_bytes(b"x")
    with (
        caplog.at_level(logging.WARNING, logger="archivey.normalization"),
        open_archive(tmp_path) as reader,
    ):
        assert reader.members()[0].name == name
    warnings = [
        record for record in caplog.records if "bidirectional control" in record.message
    ]
    assert len(warnings) == 1


def test_members_have_correct_types(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        by_name = {m.name: m for m in reader.members()}
        assert by_name["a.txt"].type == MemberType.FILE
        assert by_name["b.txt"].type == MemberType.FILE
        assert by_name["sub/"].type == MemberType.DIRECTORY
        assert by_name["sub/c.txt"].type == MemberType.FILE


def test_members_file_sizes(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        by_name = {m.name: m for m in reader.members()}
        assert by_name["a.txt"].size == 5
        assert by_name["b.txt"].size == 5
        assert by_name["sub/c.txt"].size == 6
        # Directories have no size
        assert by_name["sub/"].size is None


def test_members_have_modified_timestamp(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        for member in reader.members():
            assert member.modified is not None


def test_members_ctime_is_st_ctime_except_on_windows(simple_dir: Path) -> None:
    # st_ctime is the inode change time on Unix, and the (deprecated) creation time on
    # Windows, where `ctime` is left None rather than hold a birth time.
    with archivey.open_archive(simple_dir) as archive:
        for member in archive.members():
            st = os.lstat(simple_dir / member.name)
            if os.name == "nt":
                assert member.ctime is None
            else:
                assert member.ctime is not None
                assert abs(member.ctime.timestamp() - st.st_ctime) < 1e-3


def test_members_have_mode(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        for member in reader.members():
            assert member.mode is not None


def test_members_have_member_id(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        for member in reader.members():
            assert member.member_id >= 0


def test_member_ids_are_unique(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        ids = [m.member_id for m in reader.members()]
        assert len(ids) == len(set(ids))


def test_members_belong_to_their_reader(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader, open_archive(simple_dir) as other:
        for member in reader.members():
            assert member in reader
            assert member not in other


# ---------------------------------------------------------------------------
# Iteration order: a directory's own non-dir entries before its subdirectories
# ---------------------------------------------------------------------------


def test_non_dirs_listed_before_subdirs(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        names = [m.name for m in reader]
    # Top-level files precede the subdirectory entry (and therefore its contents).
    assert names.index("a.txt") < names.index("sub/")
    assert names.index("b.txt") < names.index("sub/")
    # Parent-before-children still holds within the subtree.
    assert names.index("sub/") < names.index("sub/c.txt")


def test_walk_order_is_depth_first_preorder(tmp_path: Path) -> None:
    # Pins the order the iterative walk must keep: at each level the non-directory
    # entries by name, then each subdirectory followed by its whole subtree.
    for rel in ("b/y/f", "b/x/f", "b/f", "a/g", "z", "c"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    with open_archive(tmp_path) as reader:
        names = [m.name for m in reader]
    assert names == [
        "c",
        "z",
        "a/",
        "a/g",
        "b/",
        "b/f",
        "b/x/",
        "b/x/f",
        "b/y/",
        "b/y/f",
    ]


# ---------------------------------------------------------------------------
# Iteration
# ---------------------------------------------------------------------------


def test_iter_yields_members(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        members = list(reader)
        assert len(members) > 0
        for m in members:
            assert isinstance(m, ArchiveMember)


def test_no_len(simple_dir: Path) -> None:
    # The reader is deliberately not a collection: no __len__ (see archive-reading);
    # counting goes through members() or iteration.
    with open_archive(simple_dir) as reader:
        with pytest.raises(TypeError):
            len(reader)
        assert len(reader.members()) == len(list(reader))


def test_contains_is_identity_membership(simple_dir: Path, tmp_path: Path) -> None:
    # `member in reader` is identity-based: True for a member this reader yielded,
    # False for one from a different reader; a string operand raises TypeError
    # (name lookup is get()).
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "b.txt").write_bytes(b"x")
    with open_archive(simple_dir) as reader, open_archive(other_dir) as other:
        member = reader.get("a.txt")
        assert member is not None
        assert member in reader
        assert member not in other
        with pytest.raises(TypeError):
            "a.txt" in reader  # noqa: B015 - the expression itself must raise


def test_get_returns_member(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        member = reader.get("a.txt")
        assert member is not None
        assert member.name == "a.txt"
        assert member.type == MemberType.FILE


def test_open_missing_name_raises_key_error(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader, pytest.raises(KeyError):
        reader.open("does_not_exist.txt")


def test_get_returns_none_for_missing(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        assert reader.get("does_not_exist.txt") is None


# ---------------------------------------------------------------------------
# Reading file content
# ---------------------------------------------------------------------------


def test_read_file_by_name(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        data = reader.read("a.txt")
        assert data == b"hello"


def test_read_file_by_member(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        member = reader.get("b.txt")
        data = reader.read(member)
        assert data == b"world"


def test_open_file_returns_binary_io(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        with reader.open("a.txt") as f:
            data = f.read()
        assert data == b"hello"


def test_read_nested_file(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        data = reader.read("sub/c.txt")
        assert data == b"nested"


# ---------------------------------------------------------------------------
# Symlink handling
# ---------------------------------------------------------------------------


def test_symlink_member_type(symlink_dir: Path) -> None:
    with open_archive(symlink_dir) as reader:
        by_name = {m.name: m for m in reader.members()}
        assert "link.txt" in by_name
        assert by_name["link.txt"].type == MemberType.SYMLINK
        assert by_name["link.txt"].link_target == "real.txt"


def test_symlink_link_target_member_resolved(symlink_dir: Path) -> None:
    with open_archive(symlink_dir) as reader:
        link = reader.get("link.txt")
        assert link.link_target_member is not None
        assert link.link_target_member.name == "real.txt"


def test_open_symlink_follows_to_real_content(symlink_dir: Path) -> None:
    with open_archive(symlink_dir) as reader:
        data = reader.read("link.txt")
        assert data == b"real content"


# ---------------------------------------------------------------------------
# Windows NTFS junction handling (runs only on the Windows CI leg)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows-only")
@pytest.mark.skipif(
    sys.version_info < (3, 12), reason="os.DirEntry.is_junction() needs Python 3.12+"
)
def test_windows_junction_detected_and_not_traversed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.txt").write_bytes(b"inside")
    junction = tmp_path / "jx"
    # mklink /J creates a junction and needs no admin rights (unlike a symlink).
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        check=True,
        capture_output=True,
    )

    with open_archive(tmp_path) as reader:
        by_name = {m.name: m for m in reader.members()}

    junction_member = by_name["jx"]
    # A junction is surfaced as a symlink-like leaf, flagged via is_junction.
    assert junction_member.type == MemberType.SYMLINK
    assert junction_member.is_junction is True
    # And it is a reparse point, which is the wider claim is_junction implies. This is
    # the only place either flag is read off a real Windows filesystem rather than off
    # a simulated os.name, so it is worth asserting here and not only in the unit test.
    assert junction_member.is_reparse_point is True
    # It is NOT walked through: its contents do not appear under the junction name.
    assert "jx/inside.txt" not in by_name
    # The real target directory, walked directly, still yields its contents.
    assert "target/inside.txt" in by_name


# ---------------------------------------------------------------------------
# stream_members
# ---------------------------------------------------------------------------


def test_stream_members_yields_all(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        pairs = list(reader.stream_members())
        assert len(pairs) == len(reader.members())


def test_stream_members_files_have_stream(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        for member, stream in reader.stream_members():
            if member.is_file:
                assert stream is not None
                stream.close()
            else:
                assert stream is None


def test_stream_members_with_filter(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        pairs = list(reader.stream_members(members=lambda m: m.is_file))
        for member, stream in pairs:
            assert member.is_file
            if stream is not None:
                stream.close()


# ---------------------------------------------------------------------------
# Convenience properties
# ---------------------------------------------------------------------------


def test_member_is_file_property(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        m = reader.get("a.txt")
        assert m.is_file is True
        assert m.is_dir is False
        assert m.is_link is False


def test_member_is_dir_property(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        m = reader.get("sub/")
        assert m.is_dir is True
        assert m.is_file is False


# ---------------------------------------------------------------------------
# Context manager and close
# ---------------------------------------------------------------------------


def test_context_manager_closes(simple_dir: Path) -> None:
    with open_archive(simple_dir) as reader:
        assert not reader._closed
    assert reader._closed


def test_close_is_idempotent(simple_dir: Path) -> None:
    reader = open_archive(simple_dir)
    reader.close()
    reader.close()  # should not raise


# ---------------------------------------------------------------------------
# Deep nesting
# ---------------------------------------------------------------------------


def test_deep_nested_structure(deep_dir: Path) -> None:
    with open_archive(deep_dir) as reader:
        names = {m.name for m in reader.members()}
        assert "root.txt" in names
        assert "level1/" in names
        assert "level1/l1.txt" in names
        assert "level1/level2/" in names
        assert "level1/level2/l2.txt" in names


def test_deep_nested_read(deep_dir: Path) -> None:
    with open_archive(deep_dir) as reader:
        data = reader.read("level1/level2/l2.txt")
        assert data == b"level2"


@pytest.mark.skipif(
    sys.platform == "win32", reason="the tree's path exceeds MAX_PATH on Windows"
)
def test_tree_deeper_than_recursion_limit_lists(tmp_path: Path) -> None:
    # A tree this deep is ordinary (extract an archive of `a/a/a/…/f` and point a
    # directory reader at the result). The limit is lowered rather than the tree made
    # ~1000 levels deep, so the path stays short enough for every platform's PATH_MAX.
    depth = 300
    leaf = tmp_path.joinpath(*(["d"] * depth))
    leaf.mkdir(parents=True)
    (leaf / "f").write_bytes(b"deep")

    frames = 0
    frame = sys._getframe()
    while frame is not None:
        frames += 1
        frame = frame.f_back
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(frames + depth // 2)
    try:
        with open_archive(tmp_path) as reader:
            names = [m.name for m in reader]
    finally:
        sys.setrecursionlimit(old_limit)

    assert len(names) == depth + 1
    assert names[-1] == "d/" * depth + "f"


# ---------------------------------------------------------------------------
# extract_all — basic smoke test via the ExtractionCoordinator
# ---------------------------------------------------------------------------


def test_extract_all_writes_members(simple_dir: Path, tmp_path: Path) -> None:
    from archivey import ExtractionStatus

    dest = tmp_path.parent / f"{tmp_path.name}-out"
    with open_archive(simple_dir) as reader:
        results = reader.extract_all(dest).results
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "b.txt").read_bytes() == b"world"
    assert (dest / "sub" / "c.txt").read_bytes() == b"nested"
    assert all(r.status is ExtractionStatus.EXTRACTED for r in results)


# ---------------------------------------------------------------------------
# Public API: __version__ accessible
# ---------------------------------------------------------------------------


def test_version_accessible() -> None:
    assert archivey.__version__


def test_archive_format_named_instances() -> None:
    fmt = ArchiveFormat.DIRECTORY  # type: ignore[attr-defined]
    assert repr(fmt) == "ArchiveFormat.DIRECTORY"


# ---------------------------------------------------------------------------
# source_name(): names paths and named streams, None for anonymous streams
# ---------------------------------------------------------------------------


def test_source_name_for_path_and_stream(tmp_path: Path) -> None:
    from archivey.internal.streams.streamtools import source_name

    p = tmp_path / "x.bin"
    p.write_bytes(b"")
    assert source_name(p) == str(p)
    assert source_name(str(p)) == str(p)
    with open(p, "rb") as f:
        assert source_name(f) == str(p)
    # An in-memory stream has no name attribute -> None.
    assert source_name(io.BytesIO(b"")) is None


def test_password_is_accepted_and_recorded(simple_dir: Path) -> None:
    # Directories carry no encryption. A password is a keyring offered, not an assertion
    # about this archive, so it is accepted and the discard is recorded rather than
    # raising (archive-reading: assertion vs resource).
    from archivey.diagnostics import DiagnosticCode

    with open_archive(simple_dir, password="x") as reader:
        assert reader.diagnostics.counts[DiagnosticCode.PASSWORD_ARGUMENT_UNUSED] == 1


# ---------------------------------------------------------------------------
# Scan errors: genuine OSErrors are loud, mid-walk races are tolerated
# ---------------------------------------------------------------------------


def _scandir_raising_for(target: Path, exc: OSError):
    """A wrapper for os.scandir that raises ``exc`` for one specific directory."""
    real_scandir = os.scandir

    def wrapper(path=None):
        # The walk scans a subdirectory through a descriptor where the platform
        # allows it, so match a descriptor by the directory it is open on.
        if isinstance(path, int):
            hit = os.path.samestat(os.fstat(path), os.stat(target))
        else:
            hit = path is not None and Path(path) == target
        if hit:
            raise exc
        return real_scandir(path)

    return wrapper


def test_unreadable_subdirectory_fails_listing(
    simple_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A genuine OSError (permission denied) propagates: silently dropping entries
    # would present an incomplete listing as complete.
    sub = simple_dir / "sub"
    monkeypatch.setattr(
        os, "scandir", _scandir_raising_for(sub, PermissionError(13, "denied"))
    )
    with open_archive(simple_dir) as ar, pytest.raises(PermissionError):
        ar.members()


def test_subdirectory_vanishing_mid_walk_is_skipped(
    simple_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A directory that vanished between listing and descent is a filesystem race,
    # not an error: skipped with a warning, and the rest of the tree still lists.
    import logging

    sub = simple_dir / "sub"
    monkeypatch.setattr(
        os, "scandir", _scandir_raising_for(sub, FileNotFoundError(2, "gone"))
    )
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(simple_dir) as ar,
    ):
        names = {m.name for m in ar.members()}
    assert "a.txt" in names
    assert "sub/" in names  # the dir entry itself was listed before it vanished
    assert not any(n.startswith("sub/") and n != "sub/" for n in names)
    assert any("vanished" in r.message for r in caplog.records)


def test_symlink_vanishing_before_readlink_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `stat` found the link, then it was removed before `readlink`: the same race the
    # stat guard handles, so the entry is skipped and the rest of the listing survives.
    from archivey.diagnostics import DiagnosticCode
    from archivey.internal.backends import directory_reader

    (tmp_path / "a.txt").write_bytes(b"a")
    os.symlink("a.txt", tmp_path / "link")
    (tmp_path / "z.txt").write_bytes(b"z")
    link_path = str(tmp_path / "link")
    real_readlink = os.readlink

    def vanishing_readlink(path: str) -> str:
        if str(path) == link_path:
            raise FileNotFoundError(2, "gone", str(path))
        return real_readlink(path)

    monkeypatch.setattr(directory_reader.os, "readlink", vanishing_readlink)
    with open_archive(tmp_path) as reader:
        names = [m.name for m in reader.members()]
        counts = reader.diagnostics.counts
    assert names == ["a.txt", "z.txt"]
    assert counts[DiagnosticCode.SCAN_ENTRY_VANISHED] == 1


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="DirEntry.stat serves scandir's cached data on Windows, so no fresh lstat",
)
def test_symlink_replaced_by_file_mid_scan_lists_as_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # scandir saw a symlink; by the `lstat` it is a regular file. The member is typed
    # from the `lstat`, so no `readlink` runs on a file (EINVAL on POSIX) and the
    # listing survives.
    (tmp_path / "a.txt").write_bytes(b"a")
    os.symlink("a.txt", tmp_path / "link")
    (tmp_path / "z.txt").write_bytes(b"z")

    def replacing_stat(
        entry: os.DirEntry[str], real_stat: Callable[[], object]
    ) -> object:
        if entry.name == "link" and os.path.islink(entry.path):
            os.unlink(entry.path)
            Path(entry.path).write_bytes(b"now a file")
        return real_stat()

    patch_dir_entry_stat(monkeypatch, replacing_stat)
    with open_archive(tmp_path) as reader:
        types = {m.name: m.type for m in reader.members()}
    assert types == {
        "a.txt": MemberType.FILE,
        "link": MemberType.FILE,
        "z.txt": MemberType.FILE,
    }


# ---------------------------------------------------------------------------
# Hardlinks: later names of one file list as HARDLINK, as a tar records them
# ---------------------------------------------------------------------------


def test_hardlinked_names_list_as_hardlink_to_the_first(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"shared")
    (tmp_path / "sub").mkdir()
    os.link(tmp_path / "a.txt", tmp_path / "b.txt")
    os.link(tmp_path / "a.txt", tmp_path / "sub" / "c.txt")
    with open_archive(tmp_path) as reader:
        members = {m.name: m for m in reader.members()}
        assert members["a.txt"].type == MemberType.FILE
        assert members["a.txt"].size == 6
        for name in ("b.txt", "sub/c.txt"):
            assert members[name].type == MemberType.HARDLINK
            assert members[name].link_target == "a.txt"
            assert members[name].size is None
            assert reader.read(name) == b"shared"


def test_link_count_from_outside_the_tree_is_a_plain_file(tmp_path: Path) -> None:
    # The file's other name is outside the root, so inside the tree it has one name.
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"x")
    os.link(root / "a.txt", tmp_path / "outside.txt")
    with open_archive(root) as reader:
        assert [(m.name, m.type) for m in reader.members()] == [
            ("a.txt", MemberType.FILE)
        ]


def test_hardlinked_directory_extracts_both_names(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_bytes(b"shared")
    os.link(src / "a.txt", src / "b.txt")
    dest = tmp_path / "dest"
    with open_archive(src) as reader:
        reader.extract_all(dest)
    assert (dest / "a.txt").read_bytes() == b"shared"
    assert (dest / "b.txt").read_bytes() == b"shared"


def _hardlinked_pair(root: Path) -> None:
    root.mkdir(exist_ok=True)
    (root / "a.txt").write_bytes(b"shared")
    os.link(root / "a.txt", root / "b.txt")


def _zero_inode(path: str) -> os.stat_result:
    """An lstat with st_ino 0, as a filesystem with no file identity reports it."""
    fields = list(os.stat(path, follow_symlinks=False))
    fields[stat.ST_INO] = 0
    return os.stat_result(fields)


def test_zero_inode_is_no_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A filesystem reporting st_ino 0 (some FUSE and network mounts) with a link count
    # above one must not group files on it: both names list as FILE.
    from archivey.internal.backends import directory_reader

    _hardlinked_pair(tmp_path)

    monkeypatch.setattr(directory_reader, "_STAT_LACKS_IDENTITY", True)
    monkeypatch.setattr(directory_reader, "_identity_stat", _zero_inode)
    with open_archive(tmp_path) as reader:
        types = {m.name: m.type for m in reader.members()}
    assert types == {"a.txt": MemberType.FILE, "b.txt": MemberType.FILE}


def test_identity_stat_path_failure_keeps_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Windows the identity stat takes a path, which can fail past MAX_PATH for a file
    # scandir did list. The file stays listed, as a plain FILE, not skipped as vanished.
    from archivey.diagnostics import DiagnosticCode
    from archivey.internal.backends import directory_reader

    _hardlinked_pair(tmp_path)

    def unreachable(path: str) -> os.stat_result:
        raise FileNotFoundError(2, "path too long", path)

    monkeypatch.setattr(directory_reader, "_STAT_LACKS_IDENTITY", True)
    monkeypatch.setattr(directory_reader, "_identity_stat", unreachable)
    with open_archive(tmp_path) as reader:
        names = [m.name for m in reader.members()]
        counts = reader.diagnostics.counts
    assert names == ["a.txt", "b.txt"]
    assert DiagnosticCode.SCAN_ENTRY_VANISHED not in counts


def test_identity_stat_genuine_error_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.backends import directory_reader

    _hardlinked_pair(tmp_path)

    def denied(path: str) -> os.stat_result:
        raise PermissionError(13, "denied", path)

    monkeypatch.setattr(directory_reader, "_STAT_LACKS_IDENTITY", True)
    monkeypatch.setattr(directory_reader, "_identity_stat", denied)
    with open_archive(tmp_path) as reader, pytest.raises(PermissionError):
        reader.members()


def test_streaming_extract_with_first_name_filtered_out_fails_the_link(
    tmp_path: Path,
) -> None:
    # The accepted cost of listing hardlinks as a tar does: on a forward-only pass, a
    # later name whose first name was filtered out cannot be written, exactly as for a
    # streamed tar.
    from archivey.exceptions import ExtractionError

    src = tmp_path / "src"
    _hardlinked_pair(src)
    dest = tmp_path / "dest"
    with (
        open_archive(src, streaming=True) as reader,
        pytest.raises(ExtractionError, match="forward-only"),
    ):
        reader.extract_all(dest, filter=lambda m: None if m.name == "a.txt" else m)


# ---------------------------------------------------------------------------
# The tree changing between listing and reading (threat-model.md O21,
# dev-docs/formats/directory.md §2.3). Opening a member follows nothing and must find the
# file the walk listed; anything else is refused with OSError.
# ---------------------------------------------------------------------------


def test_a_file_resized_after_listing_is_refused(tmp_path: Path) -> None:
    # Same file, new length: the listed size no longer describes it, so it is refused
    # rather than read at a length the listing never reported (directory.md §2.3).
    (tmp_path / "g.txt").write_bytes(b"12345")
    (tmp_path / "h.txt").write_bytes(b"12345")
    with open_archive(tmp_path) as reader:
        grown = reader.get("g.txt")
        shrunk = reader.get("h.txt")
        (tmp_path / "g.txt").write_bytes(b"1234567890ABC")
        (tmp_path / "h.txt").write_bytes(b"12")
        for member in (grown, shrunk):
            with pytest.raises(OSError, match="changed size") as excinfo:
                reader.read(member)
            assert excinfo.value.errno == errno.ESTALE


def test_a_file_rewritten_at_the_same_size_reads_its_new_content(
    tmp_path: Path,
) -> None:
    # Documented, not desired: nothing checksums a directory member, so same-size new
    # content is indistinguishable from the listed file.
    (tmp_path / "g.txt").write_bytes(b"12345")
    with open_archive(tmp_path) as reader:
        member = reader.get("g.txt")
        (tmp_path / "g.txt").write_bytes(b"ABCDE")
        assert reader.read(member) == b"ABCDE"


def test_a_file_listed_empty_reads_whatever_it_holds_at_open(tmp_path: Path) -> None:
    # A listed size of 0 is exempt from the size check: procfs and sysfs list 0 for
    # files with content, and an empty file has nothing a stale listing could hide.
    (tmp_path / "e.txt").write_bytes(b"")
    with open_archive(tmp_path) as reader:
        member = reader.get("e.txt")
        (tmp_path / "e.txt").write_bytes(b"now filled")
        assert reader.read(member) == b"now filled"


def _swap_in_symlink(path: Path, target: Path) -> None:
    if path.is_dir():
        for child in path.iterdir():
            child.unlink()
        path.rmdir()
    else:
        path.unlink()
    path.symlink_to(target, target_is_directory=target.is_dir())


def test_a_file_swapped_for_a_symlink_after_listing_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"inside")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside the root")
    with open_archive(root) as reader:
        member = reader.get("a.txt")
        _swap_in_symlink(root / "a.txt", outside)
        with pytest.raises(OSError):
            reader.read(member)


def test_a_directory_swapped_for_a_symlink_after_listing_is_refused(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "b.txt").write_bytes(b"inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "b.txt").write_bytes(b"outside the root")
    with open_archive(root) as reader:
        member = reader.get("sub/b.txt")
        _swap_in_symlink(root / "sub", outside)
        with pytest.raises(OSError):
            reader.read(member)


def _outside_tree(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    (outside / "deeper").mkdir(parents=True)
    (outside / "secret.txt").write_bytes(b"outside the root")
    (outside / "deeper" / "secret.txt").write_bytes(b"outside the root")
    return outside


def _scan_without_identities(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scan every subdirectory as if the listing had recorded no identity for it."""
    from archivey.internal.backends.directory_reader import DirectoryReader

    real_open = DirectoryReader._open_listed_directory

    def without_identity(self, directory, rel_prefix, expected):
        return real_open(self, directory, rel_prefix, None)

    monkeypatch.setattr(DirectoryReader, "_open_listed_directory", without_identity)


def _scan_past_path_max(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail the reader's whole-path opens with ENAMETOOLONG, as past ``PATH_MAX``.

    Returns the paths refused, so a test can show the component walk was taken.
    """
    from archivey.internal.backends import directory_reader

    real_os = directory_reader.os
    refused: list[str] = []

    class _LongPathOs:
        def __getattr__(self, name: str) -> object:
            return getattr(real_os, name)

        @staticmethod
        def open(path, flags, *args, dir_fd=None, **kwargs):
            if dir_fd is None and flags & real_os.O_NOFOLLOW:
                refused.append(str(path))
                raise OSError(errno.ENAMETOOLONG, "File name too long", str(path))
            return real_os.open(path, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(directory_reader, "os", _LongPathOs())
    return refused


def _replace_tree(path: Path, kind: str, outside: Path) -> None:
    # The replacement exists before the original goes, so it cannot reuse its inode.
    fresh = path.with_name("fresh.tmp")
    if kind == "symlink":
        fresh.symlink_to(outside, target_is_directory=True)
    elif kind == "file":
        fresh.write_bytes(b"not a directory")
    else:
        fresh.mkdir()
    shutil.rmtree(path)
    fresh.rename(path)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX O_NOFOLLOW walk")
@pytest.mark.parametrize("scan", ["identity", "no_identity", "past_path_max"])
@pytest.mark.parametrize(
    ("swap", "after"),
    [
        ("symlink", "sub/"),
        ("file", "sub/"),
        ("directory", "sub/"),
        ("symlink", "sub/deeper/"),
        ("file", "sub/deeper/"),
    ],
)
def test_every_directory_scan_refuses_a_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan: str,
    swap: str,
    after: str,
) -> None:
    # The walk yields a directory before it scans it; a swap in that window must not
    # list what is now at that path as members of the tree (threat-model O21). `sub/`
    # is swapped once it is yielded, or once `sub/deeper/` is (a parent swap: with
    # the whole path opened, `sub/deeper` then resolves into the link target's own
    # `deeper/`, so only the identity comparison can refuse it). Each way a
    # subdirectory is opened for its scan (the whole path checked against the
    # listing's identity, the component walk with no identity as on some FUSE and
    # network mounts, and the component walk past PATH_MAX, still checked) refuses
    # the same swaps the same way. A symlink or file in the way fails in the kernel
    # and is the cause; a fresh real directory only fails the identity check, so it
    # has no cause and no refusal at all where there is no identity.
    if swap == "directory" and scan == "no_identity":
        pytest.skip("with no identity a fresh directory is indistinguishable")
    if scan == "no_identity":
        _scan_without_identities(monkeypatch)
    refused = _scan_past_path_max(monkeypatch) if scan == "past_path_max" else None
    root = tmp_path / "root"
    (root / "sub" / "deeper").mkdir(parents=True)
    (root / "sub" / "b.txt").write_bytes(b"inside")
    outside = _outside_tree(tmp_path)
    listed: list[str] = []
    with (
        pytest.raises(
            OSError,
            match="was replaced since the directory was listed; not scanning it",
        ) as excinfo,
        open_archive(root, streaming=True) as reader,
    ):
        for member, _stream in reader.stream_members():
            listed.append(member.name)
            if member.name == after:
                _replace_tree(root / "sub", swap, outside)
    assert excinfo.value.errno == errno.ESTALE
    assert after.rstrip("/") in str(excinfo.value)
    cause = excinfo.value.__cause__
    # Only the identity check can see a fresh directory, or a parent symlink whose
    # target has a `deeper/` of its own when the whole path is opened.
    if swap == "directory" or (scan, swap, after) == (
        "identity",
        "symlink",
        "sub/deeper/",
    ):
        assert cause is None
    else:
        assert isinstance(cause, OSError)
        assert cause.errno in (errno.ENOTDIR, errno.ELOOP)
    if after == "sub/":
        assert listed == ["sub/"]
    else:
        assert listed == ["sub/", "sub/b.txt", "sub/deeper/"]
    if refused is not None:
        assert refused


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX O_NOFOLLOW walk")
@pytest.mark.parametrize(
    ("replaced", "kind", "errnos"),
    [
        # O_NOFOLLOW on the file itself: ELOOP (EMLINK on FreeBSD).
        ("a.txt", "symlink", (errno.ELOOP, errno.EMLINK)),
        # O_NOFOLLOW | O_DIRECTORY on a directory component.
        ("sub", "symlink", (errno.ENOTDIR, errno.ELOOP)),
        ("sub", "file", (errno.ENOTDIR,)),
    ],
)
def test_a_member_path_that_fails_in_the_kernel_keeps_the_kernel_error(
    tmp_path: Path, replaced: str, kind: str, errnos: tuple[int, ...]
) -> None:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.txt").write_bytes(b"inside")
    outside = _outside_tree(tmp_path)
    (outside / "a.txt").write_bytes(b"outside the root")
    path = root / "sub" / replaced if replaced == "a.txt" else root / replaced
    with open_archive(root) as reader:
        member = reader.get("sub/a.txt")
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        if kind == "symlink":
            target = outside if replaced == "sub" else outside / replaced
            path.symlink_to(target, target_is_directory=target.is_dir())
        else:
            path.write_bytes(b"inside")
        with pytest.raises(OSError) as excinfo:
            reader.read(member)
    assert excinfo.value.errno in errnos


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot open a directory")
def test_a_file_swapped_for_a_directory_after_listing_is_refused(
    tmp_path: Path,
) -> None:
    # The file itself is opened without O_DIRECTORY, so a directory opens; it is
    # refused on type afterwards.
    (tmp_path / "a.txt").write_bytes(b"listed")
    with open_archive(tmp_path) as reader:
        member = reader.get("a.txt")
        (tmp_path / "a.txt").unlink()
        (tmp_path / "a.txt").mkdir()
        with pytest.raises(OSError, match="is no longer a regular file") as excinfo:
            reader.read(member)
    assert excinfo.value.errno == errno.ESTALE


def test_a_file_replaced_after_listing_is_refused(tmp_path: Path) -> None:
    # Same length as the listed file, so only the (st_dev, st_ino) comparison can
    # catch it; removing that comparison turns this test red.
    (tmp_path / "a.txt").write_bytes(b"listed")
    with open_archive(tmp_path) as reader:
        member = reader.get("a.txt")
        replacement = tmp_path / "new.tmp"
        replacement.write_bytes(b"edited")
        os.replace(replacement, tmp_path / "a.txt")
        with pytest.raises(OSError, match="was replaced") as excinfo:
            reader.read(member)
    assert excinfo.value.errno == errno.ESTALE


def _identityless_open(monkeypatch: pytest.MonkeyPatch, attributes: int) -> None:
    """Simulate Windows for the open: no O_NOFOLLOW, st_ino 0 in the listing."""
    from archivey.internal.backends import directory_reader

    monkeypatch.setattr(directory_reader, "_STAT_LACKS_IDENTITY", True)
    monkeypatch.setattr(directory_reader, "_identity_stat", _zero_inode)
    monkeypatch.setattr(directory_reader, "_HAS_NOFOLLOW", False)
    monkeypatch.setattr(directory_reader, "_file_attributes", lambda path: attributes)


def test_an_identityless_member_that_is_now_a_reparse_point_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.windows_reparse import FILE_ATTRIBUTE_REPARSE_POINT

    _identityless_open(monkeypatch, FILE_ATTRIBUTE_REPARSE_POINT)
    (tmp_path / "a.txt").write_bytes(b"listed")
    with open_archive(tmp_path) as reader:
        member = reader.get("a.txt")
        with pytest.raises(OSError, match="is now a reparse point") as excinfo:
            reader.read(member)
    assert excinfo.value.errno == errno.ESTALE


def test_an_identityless_member_is_checked_on_type_and_size_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With no identity from the listing, a same-size replacement reads (directory.md
    # §2.3); a resize is still refused.
    _identityless_open(monkeypatch, 0)
    (tmp_path / "a.txt").write_bytes(b"listed")
    (tmp_path / "b.txt").write_bytes(b"listed")
    with open_archive(tmp_path) as reader:
        a = reader.get("a.txt")
        b = reader.get("b.txt")
        replacement = tmp_path / "new.tmp"
        replacement.write_bytes(b"edited")
        os.replace(replacement, tmp_path / "a.txt")
        (tmp_path / "b.txt").write_bytes(b"longer now")
        assert reader.read(a) == b"edited"
        with pytest.raises(OSError, match="changed size"):
            reader.read(b)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_file_swapped_for_a_fifo_after_listing_is_refused_without_blocking(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.txt").write_bytes(b"listed")
    with open_archive(tmp_path) as reader:
        member = reader.get("a.txt")
        (tmp_path / "a.txt").unlink()
        os.mkfifo(tmp_path / "a.txt")
        # With no writer on the FIFO, a blocking open would hang the test here.
        with pytest.raises(OSError, match="no longer a regular file"):
            reader.read(member)


def test_hardlinks_and_symlinks_still_read_through_the_checked_open(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.txt").write_bytes(b"data")
    os.link(tmp_path / "a.txt", tmp_path / "b.txt")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.txt").write_bytes(b"nested")
    os.symlink("a.txt", tmp_path / "link")
    with open_archive(tmp_path) as reader:
        assert reader.read("b.txt") == b"data"
        assert reader.read("link") == b"data"
        assert reader.read("sub/c.txt") == b"nested"


def test_a_link_to_a_replaced_file_is_refused(tmp_path: Path) -> None:
    # The listing identity reaches the open through link resolution: a hardlink and a
    # symlink to a file replaced at the same length are both refused.
    (tmp_path / "a.txt").write_bytes(b"listed")
    os.link(tmp_path / "a.txt", tmp_path / "b.txt")
    os.symlink("a.txt", tmp_path / "link")
    with open_archive(tmp_path) as reader:
        reader.members()
        replacement = tmp_path / "new.tmp"
        replacement.write_bytes(b"edited")
        os.replace(replacement, tmp_path / "a.txt")
        for name in ("b.txt", "link"):
            with pytest.raises(OSError, match="was replaced"):
                reader.read(name)


@pytest.mark.parametrize("streaming", [False, True])
def test_extracting_into_the_root_is_refused(tmp_path: Path, streaming: bool) -> None:
    # The walk reads the live tree, so a destination inside the root would be read back
    # as members (and, streaming, nest until the path is too long). ``cp -r`` refuses
    # the same request.
    from archivey import ExtractionError

    (tmp_path / "a").write_bytes(b"x")
    dest = tmp_path / "out"
    with (
        open_archive(tmp_path, streaming=streaming) as reader,
        pytest.raises(ExtractionError, match="into itself"),
    ):
        reader.extract_all(dest)
    assert not dest.exists()
