"""Absolute member names, the filter running before the safety checks, and
``sanitize_names``.

GNU tar, bsdtar, unzip, 7-Zip and Python's ``tarfile`` ``data`` filter all extract
``/etc/x`` as ``etc/x`` inside the destination. ``STANDARD`` and ``TRUSTED`` do the same;
``STRICT`` refuses. ``tar -P`` writes such archives, usually for backups.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from archivey import (
    AbortOn,
    ExtractionPolicy,
    ExtractionStatus,
    open_archive,
    sanitize_names,
)
from archivey.exceptions import FilterRejectionError, NameRewrittenError
from archivey.internal.filters import reroot_absolute, strip_absolute_root
from archivey.internal.naming import resolve_link_target_name
from archivey.types import ArchiveMember, MemberType


def _tar(path: Path, specs: list[tuple[str, str, object]]) -> Path:
    """(kind, name, payload): kind "file" (bytes), "hard"/"sym" (link name), "dir"."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for kind, name, payload in specs:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert isinstance(payload, bytes)
                info.size = len(payload)
                t.addfile(info, io.BytesIO(payload))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            else:
                assert isinstance(payload, str)
                info.type = tarfile.LNKTYPE if kind == "hard" else tarfile.SYMTYPE
                info.linkname = payload
            t.addfile(info)
    path.write_bytes(buf.getvalue())
    return path


def _files(root: Path) -> set[str]:
    return {
        Path(dirpath, name).relative_to(root).as_posix()
        for dirpath, _, names in os.walk(root)
        for name in names
    }


def _member(
    name: str, *, type: MemberType = MemberType.FILE, link_target: str | None = None
) -> ArchiveMember:
    return ArchiveMember(
        type=type, name=name, raw_name=name.encode(), link_target=link_target
    )


# --- strip_absolute_root / reroot_absolute -------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("/etc/x", "etc/x"),
        ("//etc//x", "etc//x"),
        ("C:/x", "x"),
        ("c:\\x", "x"),
        # Drive-relative (no separator after the colon) is not rooted: "a:b" is an
        # ordinary POSIX name, so re-rooting it would rename it. It stays as it is and
        # check_universal refuses it.
        ("C:x", "C:x"),
        ("\\\\host\\share\\x", "host\\share\\x"),
        ("/C:/x", "x"),
        ("/etc/", "etc/"),
        ("/", "."),
        ("C:", "C:"),
        ("/a:b", "a:b"),
    ],
)
def test_strip_absolute_root(name: str, expected: str) -> None:
    assert strip_absolute_root(name) == expected


def test_reroot_leaves_relative_members_and_symlink_targets_alone() -> None:
    relative = _member("a/b")
    assert reroot_absolute(relative) is relative
    link = _member("/l", type=MemberType.SYMLINK, link_target="/etc/passwd")
    rerooted = reroot_absolute(link)
    assert rerooted.name == "l"
    assert rerooted.link_target == "/etc/passwd"
    # A hardlink target is a member name the link follows, never a path: the filter
    # sees it as stored.
    hard = _member("/b", type=MemberType.HARDLINK, link_target="/a")
    assert reroot_absolute(hard).link_target == "/a"


# --- extraction ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy", [ExtractionPolicy.STANDARD, ExtractionPolicy.TRUSTED]
)
def test_absolute_names_extract_inside_dest(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    src = _tar(
        tmp_path / "a.tar",
        [("file", "/etc/x", b"x"), ("file", "C:/win.txt", b"w"), ("file", "ok", b"o")],
    )
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(dest, policy=policy)
    assert _files(dest) == {"etc/x", "win.txt", "ok"}
    by_name = {res.member.name: res for res in report.results}
    # The result keeps the stored name; the path shows where it went.
    assert by_name["/etc/x"].status is ExtractionStatus.EXTRACTED
    assert by_name["/etc/x"].path == dest / "etc" / "x"


def test_strict_refuses_absolute_names(tmp_path: Path) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "/etc/x", b"x"), ("file", "ok", b"o")])
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(
            dest, policy=ExtractionPolicy.STRICT, on_error="continue"
        )
    assert _files(dest) == {"ok"}
    blocked = [res for res in report.results if res.status is ExtractionStatus.BLOCKED]
    assert [res.member.name for res in blocked] == ["/etc/x"]
    assert isinstance(blocked[0].error, FilterRejectionError)


@pytest.mark.parametrize(
    "policy", [ExtractionPolicy.STANDARD, ExtractionPolicy.TRUSTED]
)
def test_dotdot_is_still_refused_outside_strict(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "../up", b"u"), ("file", "/a/../b", b"b")])
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(dest, policy=policy, on_error="continue")
    assert _files(dest) == set()
    assert all(res.status is ExtractionStatus.BLOCKED for res in report.results)
    assert not (tmp_path / "up").exists()


def test_absolute_hardlink_links_to_the_rerooted_member(tmp_path: Path) -> None:
    """``tar -P`` stores ``/a`` and a hardlink ``/b`` naming ``/a``."""
    src = _tar(
        tmp_path / "a.tar",
        [("file", "/d/a", b"data"), ("hard", "/d/b", "/d/a"), ("hard", "c", "/d/a")],
    )
    dest = tmp_path / "out"
    with open_archive(src) as r:
        assert r.get("/d/b").link_target_member is r.get("/d/a")
        report = r.extract_all(dest, policy=ExtractionPolicy.STANDARD)
    assert all(res.status is ExtractionStatus.EXTRACTED for res in report.results)
    assert (dest / "d" / "b").read_bytes() == b"data"
    assert (dest / "c").read_bytes() == b"data"
    if os.name == "posix":
        assert os.path.samefile(dest / "d" / "a", dest / "d" / "b")


def test_strict_refuses_a_hardlink_to_an_absolute_member(tmp_path: Path) -> None:
    """``/a`` names the member ``/a``, which STRICT refuses, so the link is refused
    with it. ``/b`` names nothing (the archive holds ``b``), so it is not found: the
    target is not re-rooted onto ``b``."""
    src = _tar(
        tmp_path / "a.tar",
        [
            ("file", "/a", b"data"),
            ("file", "b", b"data"),
            ("hard", "c", "/a"),
            ("hard", "d", "/b"),
        ],
    )
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(
            dest, policy=ExtractionPolicy.STRICT, on_error="continue"
        )
    statuses = {res.member.name: res.status for res in report.results}
    assert statuses == {
        "/a": ExtractionStatus.BLOCKED,
        "b": ExtractionStatus.EXTRACTED,
        "c": ExtractionStatus.BLOCKED,
        "d": ExtractionStatus.FAILED,
    }


def test_reroot_is_a_rewrite_for_abort_on_name_sanitized(tmp_path: Path) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "/etc/x", b"x")])
    with open_archive(src) as r, pytest.raises(NameRewrittenError):
        r.extract_all(
            tmp_path / "out",
            policy=ExtractionPolicy.STANDARD,
            abort_on={AbortOn.NAME_SANITIZED},
        )


def test_absolute_symlink_target_is_still_refused(tmp_path: Path) -> None:
    src = _tar(tmp_path / "a.tar", [("sym", "/l", "/etc/passwd")])
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(
            dest, policy=ExtractionPolicy.TRUSTED, on_error="continue"
        )
    assert report.results[0].status is ExtractionStatus.BLOCKED
    assert not os.path.lexists(dest / "l")


# --- the filter runs before the safety checks ------------------------------------------


def test_filter_sees_and_can_rescue_an_unsafe_member(tmp_path: Path) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "../up", b"u")])
    dest = tmp_path / "out"
    seen: list[str] = []

    def rename(member: ArchiveMember) -> ArchiveMember:
        seen.append(member.name)
        return member.replace(name="rescued")

    with open_archive(src) as r:
        report = r.extract_all(dest, policy=ExtractionPolicy.STRICT, filter=rename)
    assert seen == ["../up"]
    assert report.results[0].status is ExtractionStatus.EXTRACTED
    assert (dest / "rescued").read_bytes() == b"u"
    assert report.results[0].member.name == "../up"


def test_filter_sees_the_rerooted_name(tmp_path: Path) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "/etc/x", b"x")])
    seen: list[str] = []

    def record(member: ArchiveMember) -> ArchiveMember:
        seen.append(member.name)
        return member

    with open_archive(src) as r:
        r.extract_all(tmp_path / "out", policy=ExtractionPolicy.STANDARD, filter=record)
    assert seen == ["etc/x"]


@pytest.mark.parametrize("bad", ["/abs", "../up", "a/../b"])
def test_what_the_filter_returns_is_checked(tmp_path: Path, bad: str) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "ok", b"o")])
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(
            dest,
            policy=ExtractionPolicy.TRUSTED,
            filter=lambda m: m.replace(name=bad),
            on_error="continue",
        )
    assert report.results[0].status is ExtractionStatus.BLOCKED
    assert _files(tmp_path) == {"a.tar"}


# --- sanitize_names ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ok/name.txt", "ok/name.txt"),
        ("/etc/x", "etc/x"),
        ("C:\\x", "x"),
        ("../x", "x"),
        ("../../x", "x"),
        ("a/../b", "b"),
        ("a/b/../../../c", "c"),
        ("a/b/../c", "a/c"),
        ("/../etc/x", "etc/x"),
        ("a/..", "."),
        ("a/b/../", "a/"),
        ("CON", "CON_"),
        ("dir/nul.txt", "dir/nul_.txt"),
        ("x/a:b", "x/a_b"),
        ("a:b", "a_b"),  # drive-relative: not stripped, the colon is replaced
        ("C:\\..\\x", "x"),
        ("a\\\\..\\b", "b"),  # an empty segment does not absorb the ..
        ("a\\.\\..\\b", "b"),  # nor does a "." segment
        ("a/./../b", "b"),
        # A "." or empty segment after two others: only the one before it goes.
        ("a/b/./../c", "a/c"),
        ("a/b//../c", "a/c"),
        # Collapsing leaves a leading separator, which goes too: never a rooted name.
        ("a/..//b", "b"),
        ("in\u202evoice", "invoice"),
        ("a\x00b", "a_b"),
    ],
)
def test_sanitize_names_rewrites(name: str, expected: str) -> None:
    member_type = MemberType.DIRECTORY if name.endswith("/") else MemberType.FILE
    assert sanitize_names(_member(name, type=member_type)).name == expected


def test_sanitize_names_returns_the_same_member_when_nothing_changes() -> None:
    member = _member("fine/name.txt")
    assert sanitize_names(member) is member


def test_sanitize_names_keeps_a_hardlink_target_and_symlink_dot_dots() -> None:
    """A hardlink target is a member name: rewriting it would name another member.
    A symlink target keeps its ``..``, since it is a path."""
    hard = sanitize_names(
        _member("/x/../h", type=MemberType.HARDLINK, link_target="/x/../a")
    )
    assert (hard.name, hard.link_target) == ("h", "/x/../a")
    sym = sanitize_names(_member("s", type=MemberType.SYMLINK, link_target="../a"))
    assert sym.link_target == "../a"


def test_sanitize_names_keeps_a_tar_backslash_as_stored() -> None:
    assert sanitize_names(_member("a\\b/../c")).name == "a\\c"


@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_sanitize_names_extracts_what_would_be_refused(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    src = _tar(
        tmp_path / "a.tar",
        [
            ("file", "/etc/x", b"1"),
            ("file", "../up", b"2"),
            ("file", "sub/../inner", b"3"),
            ("file", "CON.txt", b"4"),
        ],
    )
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(dest, policy=policy, filter=sanitize_names)
    assert all(res.status is ExtractionStatus.EXTRACTED for res in report.results)
    assert _files(dest) == {"etc/x", "up", "inner", "CON_.txt"}
    assert not (tmp_path / "up").exists()


# --- hardlink target resolution -------------------------------------------------------


def test_hardlink_target_with_a_leading_slash_names_that_member() -> None:
    assert resolve_link_target_name("x", "/abs", MemberType.HARDLINK) == "/abs"
    assert resolve_link_target_name("x", "//a/./b", MemberType.HARDLINK) == "/a/b"
    assert resolve_link_target_name("x", "/../a", MemberType.HARDLINK) == "/../a"
    assert (
        resolve_link_target_name("x", "/../a", MemberType.HARDLINK, within_root=True)
        is None
    )
    assert resolve_link_target_name("x", "/", MemberType.HARDLINK) is None
    assert resolve_link_target_name("x", "/abs", MemberType.SYMLINK) is None


# --- review round 1 -------------------------------------------------------------------


@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_drive_relative_name_is_not_rerooted_onto_a_real_member(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """``a:b`` is a legal POSIX name, not ``b`` on drive ``A:``. Re-rooting it would
    write it over the real member ``b``; it is refused instead, as before."""
    src = _tar(tmp_path / "a.tar", [("file", "a:b", b"one"), ("file", "b", b"two")])
    dest = tmp_path / "out"
    with open_archive(src) as r:
        report = r.extract_all(dest, policy=policy, on_error="continue")
    statuses = {res.member.name: res.status for res in report.results}
    assert statuses == {
        "a:b": ExtractionStatus.BLOCKED,
        "b": ExtractionStatus.EXTRACTED,
    }
    assert (dest / "b").read_bytes() == b"two"


@pytest.mark.parametrize(
    "keep", [lambda m: None, lambda m: m.replace(name="mine/x")], ids=["drop", "rename"]
)
def test_reroot_abort_ignores_a_member_the_filter_dropped_or_renamed(
    tmp_path: Path, keep
) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "/etc/x", b"x")])
    with open_archive(src) as r:
        r.extract_all(
            tmp_path / "out",
            policy=ExtractionPolicy.STANDARD,
            abort_on={AbortOn.NAME_SANITIZED},
            filter=keep,
        )


def test_reroot_is_recorded_in_presented_name(tmp_path: Path) -> None:
    src = _tar(tmp_path / "a.tar", [("file", "/etc/x", b"x"), ("file", "/etc/y", b"y")])
    dest = tmp_path / "out"

    def rename_y(member: ArchiveMember) -> ArchiveMember:
        return member.replace(name="mine/y") if member.name == "etc/y" else member

    with open_archive(src) as r:
        report = r.extract_all(dest, policy=ExtractionPolicy.STANDARD, filter=rename_y)
    presented = {res.member.name: res.presented_name for res in report.results}
    # A name the filter chose is not a rewrite; the re-rooted one is.
    assert presented == {"/etc/x": "/etc/x", "/etc/y": None}


def test_sanitize_names_leaves_a_hardlink_target_unchanged() -> None:
    hard = _member("h", type=MemberType.HARDLINK, link_target="d/CON.txt")
    assert sanitize_names(hard) is hard
