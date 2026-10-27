"""Extracting a ZIP read from a source that cannot seek.

The pass stages each member's data in a private directory under the destination; once
the central directory, read after the last member, has settled each member's mode, type
and name, the members are placed (``ExtractionCoordinator._stage_then_place``). Each
test extracts the same bytes from a file and from a pipe and expects the same files on
disk and the same results.
"""

from __future__ import annotations

import contextlib
import io
import os
import stat
import struct
import time
import zipfile
from pathlib import Path

import pytest

import archivey
from archivey.config import ExtractionLimits
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ExtractionError,
    FilterRejectionError,
)
from archivey.internal.bomb_tracker import BombTracker
from archivey.types import (
    AbortOn,
    ArchiveMember,
    ExtractionPolicy,
    ExtractionStatus,
    MemberType,
    NameRewrite,
    OnError,
    OverwritePolicy,
)
from tests.sample_archives import CORPUS, build_archive, skip_unless_runnable
from tests.streams_util import NonSeekableBytesIO
from tests.test_zip_pipe import _Hand, _planted_prefix_zip, _reparse_zip, _streamed

needs_symlinks = pytest.mark.skipif(
    not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symlinks"
)
# Also where a backslash in a name is no separator.
posix_modes = pytest.mark.skipif(os.name == "nt", reason="needs POSIX")


def _entry(name: str, *, mode: int | None = None, host: int = 3) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 2, 3, 4, 6))
    info.create_system = host
    if mode is not None:
        info.external_attr = mode << 16
    return info


def _zip(entries: list[tuple[zipfile.ZipInfo, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for info, data in entries:
            zf.writestr(info, data)
    return buf.getvalue()


def _tree(
    root: Path, *, times: bool = True, since: float | None = None
) -> dict[str, tuple[object, ...]]:
    """Each entry under ``root``: its bytes, link target or ``dir``, and for a file or
    directory its mode and modification time (a link gets no metadata applied).

    A time from ``since`` on is the run's own, not the archive's (a folder no
    member names, or one of the caller's), and two runs can straddle a second, so
    it reads ``"now"``. ``times=False`` leaves the times out."""
    tree: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            tree[rel] = ("symlink", os.readlink(path))
            continue
        st = path.stat()
        content = "dir" if path.is_dir() else path.read_bytes()
        mtime: object = int(st.st_mtime)
        if since is not None and st.st_mtime >= since:
            mtime = "now"
        entry = (content, stat.S_IMODE(st.st_mode), mtime)
        tree[rel] = entry if times else entry[:2]
    return tree


def _extract(
    data: bytes, dest: Path, *, piped: bool, **options: object
) -> list[tuple[str, ExtractionStatus, str | None]]:
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    with archivey.open_archive(source, streaming=piped) as reader:
        report = reader.extract_all(dest, **options)  # type: ignore[arg-type]
    return [
        (
            r.member.name,
            r.status,
            None if r.path is None else r.path.relative_to(dest).as_posix(),
        )
        for r in report.results
    ]


def _both(
    data: bytes, tmp_path: Path, *, times: bool = True, **options: object
) -> tuple[
    list[tuple[str, ExtractionStatus, str | None]], dict[str, tuple[object, ...]]
]:
    """Extract ``data`` from a file and from a pipe; assert both end the same, and
    return the results and the tree. ``times=False`` leaves the times out, for a
    destination the caller seeded: a folder of theirs gets the time of the run."""
    started = time.time() - 1
    from_file = _extract(data, tmp_path / "file", piped=False, **options)
    from_pipe = _extract(data, tmp_path / "pipe", piped=True, **options)
    tree = _tree(tmp_path / "file", times=times, since=started)
    piped_tree = _tree(tmp_path / "pipe", times=times, since=started)
    assert from_pipe == from_file
    assert piped_tree == tree
    return from_file, tree


@posix_modes
@pytest.mark.parametrize("policy", list(ExtractionPolicy))
@pytest.mark.parametrize("written", ["sized", "streamed"])
def test_modes_from_the_directory_reach_the_files(
    policy: ExtractionPolicy, written: str, tmp_path: Path
) -> None:
    data = _zip(
        [
            (_entry("tool/", mode=0o40700), b""),
            (_entry("tool/run.sh", mode=0o100755), b"#!/bin/sh\n"),
            (_entry("tool/secret", mode=0o100600), b"key"),
            (_entry("plain.txt", host=0), b"no mode"),
        ]
    )
    if written == "streamed":
        data = _streamed(data)
    results, tree = _both(data, tmp_path, policy=policy)
    assert {s for _, s, _ in results} == {ExtractionStatus.EXTRACTED}
    if policy is not ExtractionPolicy.STRICT:
        assert tree["tool/run.sh"][:2] == (b"#!/bin/sh\n", 0o755)


def test_a_time_only_the_directory_holds_is_applied(tmp_path: Path) -> None:
    """The central entry's extended-timestamp field gives the modification time; the
    local header's copy is renamed to a field no reader knows, so only the
    directory gives that time, and the member is placed with it."""
    when = 1_600_000_000
    info = _entry("a.txt", mode=0o100644)
    info.extra = struct.pack("<HHBl", 0x5455, 5, 1, when)
    data = bytearray(_zip([(info, b"x")]))
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    assert extra_len == 9
    data[30 + name_len : 30 + name_len + 2] = b"\x99\x99"
    _, tree = _both(bytes(data), tmp_path, policy="trusted")
    assert tree["a.txt"][2] == when


def test_a_filter_that_set_a_mode_keeps_it(tmp_path: Path) -> None:
    def chmod(member: ArchiveMember) -> ArchiveMember:
        return member.replace(mode=0o640) if member.name == "a" else member

    data = _zip(
        [(_entry("a", mode=0o100755), b"x"), (_entry("b", mode=0o100755), b"y")]
    )
    _, tree = _both(data, tmp_path, policy="trusted", filter=chmod)
    if os.name != "nt":
        assert tree["a"][:2] == (b"x", 0o640)
        assert tree["b"][:2] == (b"y", 0o755)


def _link_zip(target: str, *, name: str = "link") -> bytes:
    return _zip(
        [
            (_entry("a.txt", mode=0o100644), b"hello"),
            (_entry(name, mode=0o120777), target.encode()),
        ]
    )


@needs_symlinks
def test_a_member_the_directory_types_as_a_link_becomes_one(tmp_path: Path) -> None:
    results, tree = _both(_link_zip("a.txt"), tmp_path, policy="standard")
    assert tree["link"] == ("symlink", "a.txt")
    assert results[1] == ("link", ExtractionStatus.EXTRACTED, "link")


@pytest.mark.parametrize("written", ["sized", "streamed"])
def test_a_link_out_of_the_destination_is_refused_from_a_pipe(
    written: str, tmp_path: Path
) -> None:
    """The local header says a file; the directory says a link that escapes. The
    file written for it is removed, as the refusal from a file writes nothing."""
    data = _link_zip("../../etc/passwd", name="payload")
    if written == "streamed":
        data = _streamed(data)
    results, tree = _both(data, tmp_path, policy="standard", on_error="continue")
    assert results[1][:2] == ("payload", ExtractionStatus.BLOCKED)
    assert "payload" not in tree


def test_a_refused_link_stops_the_run_under_abort_on(tmp_path: Path) -> None:
    from archivey.exceptions import FilterRejectionError

    data = _link_zip("../../etc/passwd", name="payload")
    for piped in (False, True):
        dest = tmp_path / str(piped)
        with pytest.raises(FilterRejectionError):
            _extract(data, dest, piped=piped, abort_on=["blocked_member"])
        assert not (dest / "payload").exists()


def test_a_filter_that_takes_only_files_drops_the_link(tmp_path: Path) -> None:
    def files_only(member: ArchiveMember) -> ArchiveMember | None:
        return member if member.type is MemberType.FILE else None

    results, tree = _both(_link_zip("a.txt"), tmp_path, filter=files_only)
    assert [name for name, _, _ in results] == ["a.txt"]
    assert sorted(tree) == ["a.txt"]


@needs_symlinks
def test_a_filter_that_takes_only_links_keeps_the_link(tmp_path: Path) -> None:
    """The pass sees a provisional file and the filter drops it; the end of the pass
    asks the filter again about the link it became, whose target the reader kept."""

    def links_only(member: ArchiveMember) -> ArchiveMember | None:
        return member if member.type is MemberType.SYMLINK else None

    results, tree = _both(_link_zip("a.txt"), tmp_path, filter=links_only)
    assert [name for name, _, _ in results] == ["link"]
    assert tree == {"link": ("symlink", "a.txt")}


@needs_symlinks
def test_a_members_predicate_that_takes_only_links_keeps_the_link(
    tmp_path: Path,
) -> None:
    results, tree = _both(
        _link_zip("a.txt"),
        tmp_path,
        members=lambda member: member.type is MemberType.SYMLINK,
    )
    assert [name for name, _, _ in results] == ["link"]
    assert tree == {"link": ("symlink", "a.txt")}


def _dos_docs() -> bytes:
    return _zip(
        [
            (_entry("docs\\", host=0), b""),
            (_entry("docs\\r.txt", host=0), b"read me"),
            (_entry("other.txt", host=0), b"other"),
        ]
    )


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (["docs/r.txt"], ["docs/r.txt"]),
        # The name a DOS host's directory never gives: nothing matches, from a pipe
        # too, though the pass staged the member before it knew.
        (["docs\\r.txt"], []),
        (["docs/"], ["docs/"]),
    ],
)
def test_members_by_name_select_what_the_directory_names(
    names: list[str], expected: list[str], tmp_path: Path
) -> None:
    results, tree = _both(_dos_docs(), tmp_path, members=names)
    assert [name for name, _, _ in results] == expected
    assert ("docs/r.txt" in tree) == ("docs/r.txt" in expected)


def test_a_filter_by_a_name_the_directory_gives_extracts_from_a_pipe(
    tmp_path: Path,
) -> None:
    """The filter runs once, at placement, on the name the directory gives."""

    def docs_only(member: ArchiveMember) -> ArchiveMember | None:
        return member if member.name.startswith("docs/") else None

    results, tree = _both(_dos_docs(), tmp_path, filter=docs_only)
    assert [(n, s) for n, s, _ in results] == [
        ("docs/", ExtractionStatus.EXTRACTED),
        ("docs/r.txt", ExtractionStatus.EXTRACTED),
    ]
    assert tree["docs/r.txt"][0] == b"read me"


def test_a_filter_rename_of_a_refused_local_name_fails_from_a_pipe(
    tmp_path: Path,
) -> None:
    """From a file, the filter renames ``../evil.txt`` before the checks and it is
    written as ``safe.txt``. From a pipe, the checks refuse the local header's name
    before anything is staged, so the renamed member has no data to place (DR-5a)."""

    def rename(member: ArchiveMember) -> ArchiveMember:
        return member.replace(name="safe.txt")

    data = _zip([(_entry("../evil.txt"), b"evil!!!")])
    from_file = _extract(data, tmp_path / "file", piped=False, filter=rename)
    from_pipe = _extract(
        data, tmp_path / "pipe", piped=True, filter=rename, on_error="continue"
    )
    assert from_file == [("../evil.txt", ExtractionStatus.EXTRACTED, "safe.txt")]
    assert from_pipe == [("../evil.txt", ExtractionStatus.FAILED, None)]
    assert (tmp_path / "file" / "safe.txt").read_bytes() == b"evil!!!"
    assert list((tmp_path / "pipe").iterdir()) == []


def test_a_member_a_predicate_takes_only_in_the_end_is_an_extraction_error(
    tmp_path: Path,
) -> None:
    """A predicate is asked during the pass too: one that leaves ``docs\\r.txt`` out
    then has its data go by unstaged, and the archive is sound."""

    def docs_only(member: ArchiveMember) -> bool:
        return member.name.startswith("docs/")

    source = NonSeekableBytesIO(_dos_docs())
    with archivey.open_archive(source, streaming=True) as reader:
        report = reader.extract_all(tmp_path, members=docs_only, on_error="continue")
    errors = [r.error for r in report.results if r.error is not None]
    if os.name == "nt":
        assert errors == []
    else:
        assert len(errors) == 1
        assert type(errors[0]) is ExtractionError


def _seed(dest: Path, files: dict[str, bytes]) -> None:
    for name, content in files.items():
        path = dest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


@posix_modes
@pytest.mark.parametrize("overwrite", ["replace", "skip", "rename", "error"])
def test_a_member_the_list_leaves_out_in_the_end_keeps_the_callers_file(
    overwrite: str, tmp_path: Path
) -> None:
    """The pass stages ``x\\y`` while the list could take it by its DOS spelling
    ``x/y``; a Unix host leaves it ``x\\y``, which the list does not take, so it is
    not placed, and what the caller has at ``x/y`` is never touched."""
    data = _zip([(_entry("x\\y"), b"ARCHIVE")])
    for where in ("file", "pipe"):
        _seed(tmp_path / where, {"x/y": b"MINE"})
    results, tree = _both(
        data,
        tmp_path,
        times=False,
        members=["x/y"],
        overwrite=overwrite,
        on_error="continue",
    )
    assert results == []
    assert tree["x/y"][0] == b"MINE"
    assert sorted(tree) == ["x", "x/y"]


@posix_modes
@pytest.mark.parametrize("overwrite", ["replace", "skip", "rename", "error"])
def test_a_member_the_list_leaves_out_in_the_end_keeps_the_callers_parent(
    overwrite: str, tmp_path: Path
) -> None:
    """As above, with the caller's file at ``x``, which ``x/y`` implies is a
    directory: the pass makes ``x/`` there, and the caller's ``x`` is back."""
    data = _zip([(_entry("x\\y"), b"ARCHIVE")])
    for where in ("file", "pipe"):
        _seed(tmp_path / where, {"x": b"MINE"})
    results, tree = _both(
        data,
        tmp_path,
        times=False,
        members=["x/y"],
        overwrite=overwrite,
        on_error="continue",
    )
    assert results == []
    assert tree == {"x": (b"MINE", 0o644)}


@pytest.mark.parametrize("overwrite", ["replace", "skip", "rename", "error"])
def test_a_member_the_list_takes_in_the_end_meets_the_callers_parent(
    overwrite: str, tmp_path: Path
) -> None:
    """``docs\\r.txt`` implies ``docs/``, where the caller has a file: the policy
    decides, from a pipe as from a file."""
    for where in ("file", "pipe"):
        _seed(tmp_path / where, {"docs": b"MINE"})
    data = _zip([(_entry("docs\\r.txt", host=0), b"read me")])
    _results, tree = _both(
        data,
        tmp_path,
        times=False,
        members=["docs/r.txt"],
        overwrite=overwrite,
        on_error="continue",
    )
    expected = {
        "replace": ["docs", "docs/r.txt"],
        "rename": ["docs", "docs (1)", "docs (1)/r.txt"],
    }.get(overwrite, ["docs"])
    assert sorted(tree) == expected
    if overwrite != "replace":
        assert tree["docs"][0] == b"MINE"


@posix_modes
def test_a_run_stopped_in_the_pass_leaves_the_callers_parent(
    tmp_path: Path,
) -> None:
    """As ``test_a_run_stopped_in_the_pass_leaves_the_callers_file``, with the
    caller's file at the parent ``x`` that ``x/y`` implies."""
    data = _zip([(_entry("x\\y"), b"ARCHIVE"), (_entry("../evil"), b"Z")])
    for where, piped in (("file", False), ("pipe", True)):
        _seed(tmp_path / where, {"x": b"MINE"})
        with pytest.raises(ArchiveyError):
            _extract(
                data,
                tmp_path / where,
                piped=piped,
                members=["x/y", "../evil"],
                overwrite="replace",
                abort_on=["blocked_member"],
            )
        assert (tmp_path / where / "x").read_bytes() == b"MINE"
        assert sorted(p.name for p in (tmp_path / where).iterdir()) == ["x"]


def test_a_read_only_file_of_the_callers_is_handled_as_from_a_file(
    tmp_path: Path,
) -> None:
    """Windows refuses to replace it from a file; a pipe must not move it aside."""
    for where in ("file", "pipe"):
        _seed(tmp_path / where, {"docs/r.txt": b"MINE"})
        os.chmod(tmp_path / where / "docs/r.txt", stat.S_IREAD)
    try:
        _results, tree = _both(
            _dos_docs(),
            tmp_path,
            times=False,
            members=["docs/r.txt"],
            overwrite="replace",
            on_error="continue",
        )
    finally:
        for where in ("file", "pipe"):
            os.chmod(tmp_path / where / "docs/r.txt", stat.S_IREAD | stat.S_IWRITE)
    assert sorted(tree) == ["docs", "docs/r.txt"]


@posix_modes
@pytest.mark.parametrize(
    ("second", "options"),
    [
        ("../evil", {"abort_on": ["blocked_member"]}),
        ("z.txt", {"limits": ExtractionLimits(max_entries=1)}),
    ],
)
def test_a_run_stopped_in_the_pass_leaves_the_callers_file(
    second: str, options: dict[str, object], tmp_path: Path
) -> None:
    """The run stops before the directory says whether ``x\\y`` is ``x/y``, so it
    places nothing, and the caller's ``x/y`` is as it was."""
    data = _zip([(_entry("x\\y"), b"ARCHIVE"), (_entry(second), b"Z")])
    for where, piped in (("file", False), ("pipe", True)):
        _seed(tmp_path / where, {"x/y": b"MINE"})
        # From a file the entry limit is never reached: x\\y is not selected.
        stops = piped or "abort_on" in options
        with pytest.raises(ArchiveyError) if stops else contextlib.nullcontext():
            _extract(
                data,
                tmp_path / where,
                piped=piped,
                members=["x/y", second],
                overwrite="replace",
                **options,
            )
        assert (tmp_path / where / "x/y").read_bytes() == b"MINE"
        assert sorted(p.name for p in (tmp_path / where / "x").iterdir()) == ["y"]


@needs_symlinks
def test_a_run_stopped_during_placement_keeps_the_member_placed_before(
    tmp_path: Path,
) -> None:
    """The directory retypes ``payload`` as a link out of the destination, which
    stops the run at its placement; ``docs/r.txt``, placed before it, replaced the
    caller's file."""
    data = _zip(
        [
            (_entry("docs\\r.txt", host=0), b"read me"),
            (_entry("payload", mode=0o120777), b"../../etc/passwd"),
        ]
    )
    for where, piped in (("file", False), ("pipe", True)):
        _seed(tmp_path / where, {"docs/r.txt": b"MINE"})
        with pytest.raises(ArchiveyError):
            _extract(
                data,
                tmp_path / where,
                piped=piped,
                members=["docs/r.txt", "payload"],
                overwrite="replace",
                abort_on=["blocked_member"],
            )
        assert (tmp_path / where / "docs/r.txt").read_bytes() == b"read me"


# A Windows symlink reparse buffer's header, padded past the target cap: as data, a
# member the directory may still make a link at any length.
_REPARSE_FILE = struct.pack("<IHH", 0xA000000C, 12, 0) + b"\0" * 6000
_LONG_FILE = b"L" * 6000


def _possible_links(last: tuple[zipfile.ZipInfo, bytes]) -> bytes:
    return _zip(
        [
            (_entry("abs_link", mode=0o120777), b"/etc/passwd"),
            (_entry("rel_link", mode=0o120777), b"target.txt"),
            (_entry("script.sh", mode=0o100755), b"#!/bin/sh\n"),
            (_entry("target.txt"), b"t"),
            (_entry("reparse.bin", host=0), _REPARSE_FILE),
            (_entry("long.bin", mode=0o100755), _LONG_FILE),
            last,
        ]
    )


@posix_modes
@pytest.mark.parametrize(
    ("last", "options"),
    [
        (
            (_entry("bomb.bin"), b"\0" * 100_000),
            {"limits": ExtractionLimits(max_extracted_bytes=50_000)},
        ),
        ((_entry("../evil"), b"Z"), {"abort_on": ["blocked_member"]}),
    ],
    ids=["limit", "abort_on"],
)
def test_a_run_stopped_in_the_pass_leaves_nothing_in_the_destination(
    last: tuple[zipfile.ZipInfo, bytes], options: dict[str, object], tmp_path: Path
) -> None:
    """The run stops before the directory says which members are links, so no member
    is placed: neither the files whose data could be a link's nor the longer one."""
    with pytest.raises(ArchiveyError):
        _extract(
            _possible_links(last),
            tmp_path,
            piped=True,
            policy="trusted",
            **options,
        )
    assert list(tmp_path.iterdir()) == []


@needs_symlinks
def test_a_run_stopped_during_placement_keeps_what_it_placed(
    tmp_path: Path,
) -> None:
    """The directory makes ``evil`` a link out of the destination, which stops the
    run when placement reaches it: the members placed before it stay, links made, and
    the members after it are not placed. A file read stops at ``evil`` too, before
    writing those."""
    data = _zip(
        [
            (_entry("rel_link", mode=0o120777), b"target.txt"),
            (_entry("target.txt", mode=0o100600), b"t"),
            (_entry("long.bin", mode=0o100755), _LONG_FILE),
            (_entry("evil", mode=0o120777), b"../../etc/passwd"),
            (_entry("late_link", mode=0o120777), b"target.txt"),
            (_entry("late.txt", mode=0o100644), b"late"),
        ]
    )
    for where, piped in (("file", False), ("pipe", True)):
        with pytest.raises(ArchiveyError):
            _extract(data, tmp_path / where, piped=piped, abort_on=["blocked_member"])
    tree = _tree(tmp_path / "file", times=False)
    assert _tree(tmp_path / "pipe", times=False) == tree
    assert tree == {
        "long.bin": (_LONG_FILE, 0o755),
        "rel_link": ("symlink", "target.txt"),
        "target.txt": (b"t", 0o600),
    }


@pytest.mark.parametrize("overwrite", ["replace", "skip"])
def test_a_member_the_list_takes_in_the_end_replaces_the_callers_file(
    overwrite: str, tmp_path: Path
) -> None:
    for where in ("file", "pipe"):
        _seed(tmp_path / where, {"docs/r.txt": b"MINE"})
    _results, tree = _both(
        _dos_docs(), tmp_path, times=False, members=["docs/r.txt"], overwrite=overwrite
    )
    expected = b"read me" if overwrite == "replace" else b"MINE"
    assert tree["docs/r.txt"][0] == expected
    assert sorted(tree) == ["docs", "docs/r.txt"]


@needs_symlinks
def test_a_predicate_that_drops_the_member_in_the_end_keeps_the_callers_file(
    tmp_path: Path,
) -> None:
    """``link`` is a file until the directory says it is a link."""
    for where in ("file", "pipe"):
        _seed(tmp_path / where, {"link": b"MINE"})
    results, tree = _both(
        _link_zip("a.txt"),
        tmp_path,
        times=False,
        members=lambda member: member.type is MemberType.FILE,
        overwrite="replace",
    )
    assert [name for name, _, _ in results] == ["a.txt"]
    assert tree["link"][0] == b"MINE"
    assert sorted(tree) == ["a.txt", "link"]


@needs_symlinks
def test_folders_the_selection_keeps_stay_when_a_link_inside_is_dropped(
    tmp_path: Path,
) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(_entry("a/", mode=0o40755), b"")
        zf.writestr(_entry("a/b/", mode=0o40755), b"")
        zf.writestr(_entry("a/b/link", mode=0o120777), b"../../x")
        zf.writestr(_entry("x", mode=0o100644), b"X")
    results, tree = _both(
        buf.getvalue(),
        tmp_path,
        members=lambda member: member.type is not MemberType.SYMLINK,
    )
    assert [name for name, _, _ in results] == ["a/", "a/b/", "x"]
    assert sorted(tree) == ["a", "a/b", "x"]


@posix_modes
def test_a_folder_the_list_keeps_stays_when_a_member_inside_is_dropped(
    tmp_path: Path,
) -> None:
    data = _zip([(_entry("d/", mode=0o40755), b""), (_entry("d\\x"), b"1")])
    results, tree = _both(data, tmp_path, members=["d/", "d/x"])
    assert [name for name, _, _ in results] == ["d/"]
    assert sorted(tree) == ["d"]


@needs_symlinks
def test_a_member_selected_in_the_end_reports_progress(tmp_path: Path) -> None:
    ticks: dict[str, list[tuple[str, int]]] = {}
    for where, piped in (("file", False), ("pipe", True)):
        seen = ticks[where] = []
        _extract(
            _link_zip("a.txt"),
            tmp_path / where,
            piped=piped,
            members=lambda member: member.type is MemberType.SYMLINK,
            on_progress=lambda p, seen=seen: seen.append(
                (p.member.name, p.members_done)
            ),
        )
    assert ticks["pipe"] == ticks["file"] == [("link", 1)]


@needs_symlinks
def test_a_member_the_filter_drops_in_the_end_reports_progress(tmp_path: Path) -> None:
    ticks: dict[str, list[tuple[str, int]]] = {}
    for where, piped in (("file", False), ("pipe", True)):
        seen = ticks[where] = []
        _extract(
            _link_zip("a.txt"),
            tmp_path / where,
            piped=piped,
            members=lambda member: member.type is MemberType.SYMLINK,
            filter=lambda m: None if m.type is MemberType.SYMLINK else m,
            on_progress=lambda p, seen=seen: seen.append(
                (p.member.name, p.members_done)
            ),
        )
    assert ticks["pipe"] == ticks["file"] == [("link", 1)]


@posix_modes
def test_the_filter_sees_each_member_once_and_final(tmp_path: Path) -> None:
    """The filter runs at placement only, on the member the directory describes."""
    data = _zip([(_entry("a\\"), b"")])
    seen: list[tuple[str, bool]] = []

    def probe(member: ArchiveMember) -> ArchiveMember:
        seen.append((member.name, member.member_state_final))
        return member

    _extract(data, tmp_path, piped=True, filter=probe, on_error="continue")
    assert [final for _, final in seen] == [True]


def test_a_special_file_the_directory_reveals_is_refused(tmp_path: Path) -> None:
    data = _zip([(_entry("fifo", mode=0o010644), b""), (_entry("b"), b"after")])
    results, tree = _both(data, tmp_path, on_error="continue")
    assert results[0][:2] == ("fifo", ExtractionStatus.BLOCKED)
    assert sorted(tree) == ["b"]


@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_a_dos_name_moves_to_its_folder(
    policy: ExtractionPolicy, tmp_path: Path
) -> None:
    """A DOS host makes ``\\`` a separator, which only the directory says."""
    data = _zip(
        [
            (_entry("docs\\", host=0), b""),
            (_entry("docs\\readme.txt", host=0), b"read me"),
        ]
    )
    results, tree = _both(data, tmp_path, policy=policy)
    assert [name for name, _, _ in results] == ["docs/", "docs/readme.txt"]
    assert tree["docs/readme.txt"][0] == b"read me"


def test_a_staged_file_lands_without_a_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A member placed under the name the directory gives lands by a rename of its
    staged file: its bytes are counted once, when staged, and copied never."""
    counted: dict[str, int] = {"decoded": 0, "copied": 0}
    count, count_copy = BombTracker.count, BombTracker.count_copy

    def decoded(self: BombTracker, n: int) -> None:
        counted["decoded"] += n
        count(self, n)

    def copied(self: BombTracker, n: int, *, at_link_limit: bool) -> None:
        counted["copied"] += n
        count_copy(self, n, at_link_limit=at_link_limit)

    monkeypatch.setattr(BombTracker, "count", decoded)
    monkeypatch.setattr(BombTracker, "count_copy", copied)
    data = _zip([(_entry("docs\\readme.txt", host=0), b"read me")])
    _extract(data, tmp_path / "pipe", piped=True)
    assert counted == {"decoded": 7, "copied": 0}
    assert (tmp_path / "pipe" / "docs" / "readme.txt").read_bytes() == b"read me"
    assert sorted(p.name for p in (tmp_path / "pipe").iterdir()) == ["docs"]


@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_a_unix_name_ending_in_a_backslash_is_a_file(
    policy: ExtractionPolicy, tmp_path: Path
) -> None:
    """The pass takes a trailing ``\\`` for a folder until the directory names the
    host; a Unix host makes it a file, empty or not."""
    data = _zip([(_entry("odd\\", mode=0o100644), b""), (_entry("b"), b"after")])
    results, _ = _both(data, tmp_path, policy=policy, on_error="continue")
    assert [status for _, status, _ in results] == [ExtractionStatus.EXTRACTED] * 2


@posix_modes
@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_a_unix_file_ending_in_a_backslash_with_data_fails_from_a_pipe(
    policy: ExtractionPolicy, tmp_path: Path
) -> None:
    """The pass takes it for a folder and stages none of its bytes, so a Unix host
    that makes it a file leaves nothing to place: it fails from a pipe, where the
    file read writes it (a crafted shape; ``dev-docs/formats/zip.md`` §9)."""
    data = _zip([(_entry("odd\\", mode=0o100644), b"data")])
    from_file = _extract(data, tmp_path / "file", piped=False, policy=policy)
    assert [(name, status) for name, status, _ in from_file] == [
        ("odd\\", ExtractionStatus.EXTRACTED)
    ]
    source = NonSeekableBytesIO(data)
    with archivey.open_archive(source, streaming=True) as reader:
        report = reader.extract_all(
            tmp_path / "pipe", policy=policy, on_error="continue"
        )
    [result] = report.results
    assert (result.member.name, result.status) == ("odd\\", ExtractionStatus.FAILED)
    assert isinstance(result.error, ExtractionError)
    assert list((tmp_path / "pipe").iterdir()) == []


def test_a_reparse_member_whose_data_is_no_link_stays_a_file(tmp_path: Path) -> None:
    content = b"not a reparse buffer " * 10
    _, tree = _both(_reparse_zip(content), tmp_path)
    assert tree["tree/entry"][0] == content


@needs_symlinks
def test_a_reparse_member_holding_a_link_buffer_becomes_a_link(tmp_path: Path) -> None:
    from archivey.internal.windows_reparse import IO_REPARSE_TAG_SYMLINK
    from tests.test_windows_reparse import _reparse_buffer

    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "after.txt", "after.txt")
    _, tree = _both(_reparse_zip(buffer), tmp_path)
    assert tree["tree/entry"] == ("symlink", "after.txt")


def _corpus_zips() -> list[object]:
    return [
        pytest.param(entry, id=entry.id)
        for entry in CORPUS
        if "zip" in entry.formats and not entry.passwords
    ]


@pytest.mark.filterwarnings("ignore:Duplicate name")
@pytest.mark.parametrize("entry", _corpus_zips())
def test_the_corpus_extracts_from_a_pipe_as_from_a_file(
    entry: object, tmp_path: Path
) -> None:
    skip_unless_runnable(entry, "zip")  # type: ignore[arg-type]
    path = tmp_path / "corpus.zip"
    build_archive(entry, "zip", path)  # type: ignore[arg-type]
    _both(path.read_bytes(), tmp_path, on_error=OnError.CONTINUE)


# -- Failures found at the end of the pass (design.md, same heading) -----------------


def _piped_report(
    data: bytes, dest: Path, **options: object
) -> archivey.ExtractionReport:
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        return reader.extract_all(dest, **options)  # type: ignore[arg-type]


def _outcomes(
    report: archivey.ExtractionReport,
) -> list[tuple[str, ExtractionStatus, type[BaseException] | None]]:
    return [
        (r.member.name, r.status, None if r.error is None else type(r.error))
        for r in report.results
    ]


def test_an_unlisted_local_entry_is_not_placed(tmp_path: Path) -> None:
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"sub/planted.txt", b"not listed")
    hand.local(b"b.txt", b"two")
    results, tree = _both(hand.directory(0, 2), tmp_path)
    assert [name for name, _, _ in results] == ["a.txt", "b.txt"]
    assert sorted(tree) == ["a.txt", "b.txt"]


def _reversed_pair() -> bytes:
    hand = _Hand()
    hand.local(b"dup.txt", b"first")
    hand.local(b"dup.txt", b"second")
    hand.local(b"other.txt", b"other")
    return hand.directory(1, 0, 2)


def test_a_reversed_same_name_pair_fails_the_current_copy(tmp_path: Path) -> None:
    """The pass staged the second copy; the directory makes the first current, whose
    bytes have gone by. Random access writes "first" there."""
    data = _reversed_pair()
    report = _piped_report(data, tmp_path / "pipe", on_error=OnError.CONTINUE)
    assert _outcomes(report) == [
        ("dup.txt", ExtractionStatus.FAILED, CorruptionError),
        ("dup.txt", ExtractionStatus.SUPERSEDED, None),
        ("other.txt", ExtractionStatus.EXTRACTED, None),
    ]
    assert sorted(p.name for p in (tmp_path / "pipe").iterdir()) == ["other.txt"]
    _extract(data, tmp_path / "file", piped=False)
    assert (tmp_path / "file" / "dup.txt").read_bytes() == b"first"


def test_a_reversed_pair_under_stop_raises_when_placement_reaches_it(
    tmp_path: Path,
) -> None:
    """The first failure in listing order stops the run, so ``other.txt``, after
    it, is not placed."""
    with pytest.raises(CorruptionError, match="current copy") as raised:
        _piped_report(_reversed_pair(), tmp_path, on_error=OnError.STOP)
    assert raised.value.member_name == "dup.txt"
    assert list(tmp_path.iterdir()) == []


def test_an_empty_current_copy_is_written_again(tmp_path: Path) -> None:
    """A copy that needs no bytes can be written at the end."""
    hand = _Hand()
    hand.local(b"dup.txt", b"")
    hand.local(b"dup.txt", b"second")
    report = _piped_report(hand.directory(1, 0), tmp_path)
    # In the order the pass met them; random access lists the directory's order.
    assert _outcomes(report) == [
        ("dup.txt", ExtractionStatus.EXTRACTED, None),
        ("dup.txt", ExtractionStatus.SUPERSEDED, None),
    ]
    assert (tmp_path / "dup.txt").read_bytes() == b""


def test_a_contradicted_descriptor_fails_the_member(tmp_path: Path) -> None:
    data, _whole = _planted_prefix_zip()
    report = _piped_report(data, tmp_path, on_error=OnError.CONTINUE)
    assert _outcomes(report) == [
        ("outer.bin", ExtractionStatus.FAILED, CorruptionError),
        ("after.txt", ExtractionStatus.EXTRACTED, None),
    ]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["after.txt"]


def test_a_contradicted_descriptor_under_stop_raises(tmp_path: Path) -> None:
    data, _whole = _planted_prefix_zip()
    # The planted member's data fails its check as the pass stages it, which would
    # stop the run first (a failure during the pass stops it before the directory
    # can say the member is not listed), so the selection leaves it out. The filter
    # runs only at placement, too late for that.
    with pytest.raises(CorruptionError, match="data descriptor") as raised:
        _piped_report(
            data,
            tmp_path,
            on_error=OnError.STOP,
            members=lambda m: m.name != "inner",
        )
    assert raised.value.member_name == "outer.bin"
    # The first member in listing order fails, so nothing is placed.
    assert list(tmp_path.iterdir()) == []


def _contradicted_header() -> bytes:
    """``a.txt`` and ``b.txt``, with ``a.txt``'s central CRC contradicting the CRC its
    local header holds and its data matches."""
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"b.txt", b"two")
    data = bytearray(hand.directory(0, 1))
    struct.pack_into("<I", data, data.index(b"PK\x01\x02") + 16, 0x1234_5678)
    return bytes(data)


def test_a_contradicted_local_header_fails_the_member(tmp_path: Path) -> None:
    report = _piped_report(_contradicted_header(), tmp_path, on_error=OnError.CONTINUE)
    assert _outcomes(report) == [
        ("a.txt", ExtractionStatus.FAILED, CorruptionError),
        ("b.txt", ExtractionStatus.EXTRACTED, None),
    ]
    # The pass staged a.txt's bytes before the directory contradicted its header.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["b.txt"]


def test_a_contradicted_local_header_under_stop_raises(tmp_path: Path) -> None:
    with pytest.raises(CorruptionError, match="local header and its central") as raised:
        _piped_report(_contradicted_header(), tmp_path, on_error=OnError.STOP)
    assert raised.value.member_name == "a.txt"
    assert list(tmp_path.iterdir()) == []


def _missing_entry(name: bytes = b"b.txt") -> bytes:
    """``a.txt`` and ``b.txt``, with ``b.txt``'s directory entry pointing past the
    stream's last local header, and named ``name`` (five bytes) there."""
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"b.txt", b"two")
    data = bytearray(hand.directory(0, 1))
    cd = data.rindex(b"PK\x01\x02")
    struct.pack_into("<I", data, cd + 42, 999_999)
    assert len(name) == 5
    data[cd + 46 : cd + 51] = name
    return bytes(data)


def test_a_directory_entry_with_no_local_entry_gets_a_failed_result(
    tmp_path: Path,
) -> None:
    report = _piped_report(_missing_entry(), tmp_path, on_error=OnError.CONTINUE)
    assert _outcomes(report) == [
        ("a.txt", ExtractionStatus.EXTRACTED, None),
        ("b.txt", ExtractionStatus.FAILED, CorruptionError),
    ]
    # b.txt's local entry is one the directory does not list, so it is not placed.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt"]


def test_a_name_the_two_headers_disagree_on_is_written_by_the_directory_name(
    tmp_path: Path,
) -> None:
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"b.txt", b"two")
    data = bytearray(hand.directory(0, 1))
    cd = data.rindex(b"PK\x01\x02")
    data[cd + 46 : cd + 51] = b"z.txt"
    results, tree = _both(bytes(data), tmp_path, on_error=OnError.CONTINUE)
    assert [result[:2] for result in results] == [
        ("a.txt", ExtractionStatus.EXTRACTED),
        ("z.txt", ExtractionStatus.EXTRACTED),
    ]
    assert sorted(tree) == ["a.txt", "z.txt"]


def test_a_directory_entry_with_no_local_entry_under_stop_raises(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with pytest.raises(CorruptionError) as raised:
        _piped_report(_missing_entry(), tmp_path, on_error=OnError.STOP)
    assert raised.value.member_name == "b.txt"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt"]
    # The raise is the record: no "Skipping" line beside it.
    assert not [r for r in caplog.records if "Skipping" in r.getMessage()]


def test_a_directory_entry_with_no_local_entry_is_reported_to_on_progress(
    tmp_path: Path,
) -> None:
    seen: list[archivey.ExtractionProgress] = []
    report = _piped_report(
        _missing_entry(), tmp_path, on_error=OnError.CONTINUE, on_progress=seen.append
    )
    failed = report.results[-1].member
    assert report.results[-1].status is ExtractionStatus.FAILED
    assert seen[-1].member is failed
    # One past the pass's count, which already took in the unlisted local copy.
    assert seen[-1].members_done == seen[-2].members_done + 1


def test_a_directory_entry_with_no_local_entry_can_be_blocked(tmp_path: Path) -> None:
    """The policy checks run on it as on any member, and AbortOn applies."""
    report = _piped_report(_missing_entry(b"../.."), tmp_path / "a")
    assert _outcomes(report)[-1][:2] == ("../..", ExtractionStatus.BLOCKED)
    with pytest.raises(FilterRejectionError):
        _piped_report(
            _missing_entry(b"../.."),
            tmp_path / "b",
            abort_on={AbortOn.BLOCKED_MEMBER},
        )


@pytest.mark.skipif(os.name == "nt", reason="'?' is no name character on Windows")
def test_a_directory_entry_with_no_local_entry_records_its_rewrite(
    tmp_path: Path,
) -> None:
    report = _piped_report(
        _missing_entry(b"a?.tx"),
        tmp_path,
        on_error=OnError.CONTINUE,
        policy=ExtractionPolicy.STANDARD,
    )
    result = report.results[-1]
    assert result.status is ExtractionStatus.FAILED
    assert result.presented_name is not None
    assert NameRewrite.PORTABLE_NAME in result.rewrites


def test_a_name_the_two_headers_disagree_on_under_stop_is_written_alike(
    tmp_path: Path,
) -> None:
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"b.txt", b"two")
    data = bytearray(hand.directory(0, 1))
    cd = data.rindex(b"PK\x01\x02")
    data[cd + 46 : cd + 51] = b"z.txt"
    _, tree = _both(bytes(data), tmp_path, on_error=OnError.STOP)
    assert sorted(tree) == ["a.txt", "z.txt"]


def test_a_reversed_pair_under_skip_matches_the_seekable_results(
    tmp_path: Path,
) -> None:
    """Neither copy is written over the caller's file, so neither needs the bytes the
    pass has gone by: each copy gets the result random access gives it."""
    data = _reversed_pair()
    outcomes = {}
    for piped in (True, False):
        dest = tmp_path / ("pipe" if piped else "file")
        dest.mkdir()
        (dest / "dup.txt").write_bytes(b"caller's")
        source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
        with archivey.open_archive(source, streaming=piped) as reader:
            report = reader.extract_all(
                dest, overwrite=OverwritePolicy.SKIP, on_error=OnError.CONTINUE
            )
        outcomes[piped] = sorted(
            (r.member._member_id is not None and r.member.is_current, r.status.value)
            for r in report.results
            if r.member.name == "dup.txt"
        )
        assert (dest / "dup.txt").read_bytes() == b"caller's"
    assert (
        outcomes[True]
        == outcomes[False]
        == [
            (False, "superseded"),
            (True, "not_overwritten"),
        ]
    )


def _failing_filter(member: ArchiveMember) -> ArchiveMember:
    raise ExtractionError("refused by the test", member_name=member.name)


@pytest.mark.parametrize(
    ("options", "status"),
    [
        pytest.param({}, "blocked", id="blocked"),
        pytest.param({"filter": _failing_filter}, "failed", id="filter-fails"),
    ],
)
def test_a_reversed_pair_refused_before_the_write_matches_the_seekable_results(
    tmp_path: Path, options: dict[str, object], status: str
) -> None:
    """A refusal made before the write stands on a copy the directory makes not
    current: random access runs the filter and the policy checks on every copy."""
    hand = _Hand()
    hand.local(b"../dup.txt", b"first")
    hand.local(b"../dup.txt", b"second")
    data = hand.directory(1, 0)
    outcomes = {}
    for piped in (True, False):
        dest = tmp_path / ("pipe" if piped else "file")
        source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
        with archivey.open_archive(source, streaming=piped) as reader:
            report = reader.extract_all(dest, on_error=OnError.CONTINUE, **options)  # type: ignore[arg-type]
        outcomes[piped] = sorted(
            (r.member.is_current, r.status.value) for r in report.results
        )
    assert outcomes[True] == outcomes[False] == [(False, status), (True, status)]


def _compare_with_file_read(
    data: bytes, tmp_path: Path, *, seed: bytes | None = None, **options: object
) -> dict[bool, tuple[list[tuple[str, bool, str, str]], dict[str, bytes]]]:
    """Each run's (name, is_current, status, error type) results, sorted, and what it
    left on disk, for a pipe read (``True``) and a file read (``False``) of ``data``.
    ``seed`` is put at ``b.txt`` in each destination first."""
    runs = {}
    for piped in (True, False):
        dest = tmp_path / ("pipe" if piped else "file")
        dest.mkdir()
        if seed is not None:
            (dest / "b.txt").write_bytes(seed)
        source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
        with archivey.open_archive(source, streaming=piped) as reader:
            report = reader.extract_all(dest, on_error=OnError.CONTINUE, **options)  # type: ignore[arg-type]
        runs[piped] = (
            sorted(
                (
                    r.member.name,
                    r.member.is_current,
                    r.status.value,
                    type(r.error).__name__,
                )
                for r in report.results
            ),
            {p.name: p.read_bytes() for p in dest.iterdir()},
        )
    return runs


def test_a_missing_entry_makes_the_copy_it_follows_not_current(tmp_path: Path) -> None:
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"b.txt", b"two")
    data = bytearray(hand.directory(0, 1))
    # The second entry names a.txt and points where the stream held nothing.
    cd = data.rindex(b"PK\x01\x02")
    struct.pack_into("<I", data, cd + 42, 999_999)
    data[cd + 46 : cd + 51] = b"a.txt"
    runs = _compare_with_file_read(bytes(data), tmp_path)
    assert (
        runs[True]
        == runs[False]
        == (
            [
                ("a.txt", False, "superseded", "NoneType"),
                ("a.txt", True, "failed", "CorruptionError"),
            ],
            {},
        )
    )


@pytest.mark.parametrize(
    ("overwrite", "outcome"),
    [
        (OverwritePolicy.SKIP, ("not_overwritten", "NoneType")),
        (OverwritePolicy.ERROR, ("failed", "ExtractionError")),
    ],
)
def test_a_missing_entry_meets_the_overwrite_policy_first(
    tmp_path: Path, overwrite: OverwritePolicy, outcome: tuple[str, str]
) -> None:
    runs = _compare_with_file_read(
        _missing_entry(), tmp_path, seed=b"caller's", overwrite=overwrite
    )
    assert (
        runs[True]
        == runs[False]
        == (
            [("a.txt", True, "extracted", "NoneType"), ("b.txt", True, *outcome)],
            {"a.txt": b"one", "b.txt": b"caller's"},
        )
    )


# -- Staging (``_stage_then_place``) --------------------------------------------------


def test_a_refused_first_member_stops_the_run_before_the_rest_is_decoded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The universal checks run on the local header's name before anything is
    staged, so ``abort_on`` refuses a hostile archive without decoding the rest."""
    from archivey.internal.extraction import ExtractionCoordinator

    staged: list[int] = []
    write_staged = ExtractionCoordinator._write_staged

    def counting(self: ExtractionCoordinator, *args: object) -> Path:
        staged.append(1)
        return write_staged(self, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(ExtractionCoordinator, "_write_staged", counting)
    data = _zip([(_entry("../../etc/passwd"), b"root"), (_entry("big"), b"\0" * 4096)])
    with pytest.raises(FilterRejectionError):
        _extract(data, tmp_path, piped=True, abort_on={AbortOn.BLOCKED_MEMBER})
    assert staged == []
    assert list(tmp_path.iterdir()) == []


def test_a_refused_local_name_blocks_and_the_stop_run_goes_on(tmp_path: Path) -> None:
    """``on_error="stop"`` does not stop on a refusal: the member is blocked, from a
    pipe as from a file, and the members after it are extracted."""
    data = _zip([(_entry("../../etc/passwd"), b"root"), (_entry("big"), b"\0" * 4096)])
    results, tree = _both(data, tmp_path, on_error="stop")
    assert [(name, status) for name, status, _ in results] == [
        ("../../etc/passwd", ExtractionStatus.BLOCKED),
        ("big", ExtractionStatus.EXTRACTED),
    ]
    assert sorted(tree) == ["big"]


def test_a_data_failure_while_staging_stops_a_stop_run_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.extraction import ExtractionCoordinator

    staged: list[int] = []
    write_staged = ExtractionCoordinator._write_staged

    def failing(
        self: ExtractionCoordinator,
        stream: object,
        position: int,
        emit: object,
    ) -> Path:
        staged.append(position)
        if position == 0:
            raise CorruptionError("damaged by the test")
        return write_staged(self, stream, position, emit)  # type: ignore[arg-type]

    monkeypatch.setattr(ExtractionCoordinator, "_write_staged", failing)
    data = _zip([(_entry("a.txt"), b"one"), (_entry("b.txt"), b"two")])
    with pytest.raises(CorruptionError, match="damaged by the test"):
        _extract(data, tmp_path / "stop", piped=True, on_error="stop")
    assert staged == [0]
    assert list((tmp_path / "stop").iterdir()) == []
    staged.clear()
    results = _extract(data, tmp_path / "continue", piped=True, on_error="continue")
    assert [r[:2] for r in results] == [
        ("a.txt", ExtractionStatus.FAILED),
        ("b.txt", ExtractionStatus.EXTRACTED),
    ]
    assert sorted(p.name for p in (tmp_path / "continue").iterdir()) == ["b.txt"]


@posix_modes
def test_a_staged_file_lands_by_a_rename_with_its_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replaced: list[tuple[str, str]] = []
    real_replace = os.replace

    def recording(src: str, dst: str) -> None:
        replaced.append((os.path.basename(os.path.dirname(src)), os.path.basename(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", recording)
    data = _zip([(_entry("run.sh", mode=0o100750), b"#!/bin/sh\n")])
    _extract(data, tmp_path, piped=True, policy="trusted")
    [(staging, landed)] = replaced
    assert staging.startswith(".archivey-tmp-")
    assert landed == "run.sh"
    assert stat.S_IMODE((tmp_path / "run.sh").stat().st_mode) == 0o750
    # The staged name is gone with its directory.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["run.sh"]


def test_a_staging_directory_that_cannot_be_removed_stays_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real_rmdir = os.rmdir

    def refuse(path: str, *args: object, **kwargs: object) -> None:
        if os.path.basename(path).startswith(".archivey-tmp-"):
            raise PermissionError(13, "Permission denied", path)
        real_rmdir(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "rmdir", refuse)
    _extract(_zip([(_entry("a.txt"), b"one")]), tmp_path, piped=True)
    monkeypatch.undo()
    left = sorted(p.name for p in tmp_path.iterdir())
    assert len(left) == 2
    assert left[0].startswith(".archivey-tmp-")
    assert left[1] == "a.txt"
    assert "staged" in caplog.text


def test_a_read_only_staged_file_is_removed_when_the_run_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows refuses to remove a read-only file; the removal opens it up first."""
    from archivey.internal.extraction import ExtractionCoordinator

    write_staged = ExtractionCoordinator._write_staged

    def read_only(self: ExtractionCoordinator, *args: object) -> Path:
        path = write_staged(self, *args)  # type: ignore[arg-type]
        os.chmod(path, stat.S_IREAD)
        return path

    monkeypatch.setattr(ExtractionCoordinator, "_write_staged", read_only)
    data = _zip([(_entry("a.txt"), b"one"), (_entry("../evil"), b"Z")])
    with pytest.raises(FilterRejectionError):
        _extract(data, tmp_path, piped=True, abort_on={AbortOn.BLOCKED_MEMBER})
    assert list(tmp_path.iterdir()) == []


def test_a_member_staged_and_not_placed_stops_counting_toward_max_entries(
    tmp_path: Path,
) -> None:
    """``a.txt`` counts while staged; the filter drops it, so ``d/``, placed after,
    fits under ``max_entries=1``, as from a file."""
    data = _zip([(_entry("a.txt"), b"one"), (_entry("d/", mode=0o40755), b"")])
    results, tree = _both(
        data,
        tmp_path,
        filter=lambda m: None if m.name == "a.txt" else m,
        limits=ExtractionLimits(max_entries=1),
    )
    assert [name for name, _, _ in results] == ["d/"]
    assert sorted(tree) == ["d"]


def test_progress_reports_each_member_while_staged_then_the_tallies(
    tmp_path: Path,
) -> None:
    """The directory drops ``b.txt``; each member is reported in order while
    staged, and placement makes one more report with the outcome tallies."""
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"b.txt", b"two")
    hand.local(b"c.txt", b"three")
    seen: list[archivey.ExtractionProgress] = []
    _piped_report(hand.directory(0, 2), tmp_path, on_progress=seen.append)
    assert [(p.member.name, p.members_done, p.members_extracted) for p in seen] == [
        ("a.txt", 1, 0),
        ("b.txt", 2, 0),
        ("c.txt", 3, 0),
        ("c.txt", 3, 2),
    ]
    assert [p.member_bytes_written for p in seen[:3]] == [3, 3, 5]


def test_a_collision_abort_keeps_the_member_placed_before_it(tmp_path: Path) -> None:
    data = _zip([(_entry("A.txt"), b"first"), (_entry("a.txt"), b"second")])
    from archivey.exceptions import NameCollisionError

    with pytest.raises(NameCollisionError):
        _extract(
            data,
            tmp_path,
            piped=True,
            overwrite="replace",
            abort_on={AbortOn.NAME_COLLISION},
        )
    assert [(p.name, p.read_bytes()) for p in tmp_path.iterdir()] == [
        ("A.txt", b"first")
    ]


def test_an_unmatched_entry_under_raise_places_nothing(tmp_path: Path) -> None:
    """The member list is known once the directory is read, before any member is
    placed, so a ``RAISE`` disposition refuses the call as from a file."""
    from archivey.config import ArchiveyConfig
    from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy
    from archivey.exceptions import DiagnosticRaisedError

    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on={DiagnosticCode.MEMBER_SELECTOR_UNMATCHED}
        )
    )
    data = _zip([(_entry("a.txt"), b"one")])
    with (
        archivey.open_archive(
            NonSeekableBytesIO(data), streaming=True, config=config
        ) as reader,
        pytest.raises(DiagnosticRaisedError),
    ):
        reader.extract_all(tmp_path, members=["a.txt", "typo.txt"])
    assert list(tmp_path.iterdir()) == []
