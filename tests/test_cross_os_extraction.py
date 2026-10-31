"""Extraction under ``STRICT`` and ``STANDARD`` gives the same tree on every OS.

The ``safe-extraction`` rule "Cross-platform name safety is deterministic across policy
levels": an archive extracted on Linux into an NTFS volume ends up as it would on
Windows on that volume. Each test here pins one place where the two used to differ.
The tests run on POSIX and exercise the shared rule; the Windows-only parts either run
only on Windows or simulate the Windows error with monkeypatch.
"""

from __future__ import annotations

import builtins
import errno
import io
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from archivey import (
    ExtractionLimits,
    ExtractionPolicy,
    ExtractionStatus,
    OnError,
    OverwritePolicy,
)
from archivey.exceptions import (
    ExtractionError,
    FilterRejectionError,
    LinkTargetNotFoundError,
    ResourceLimitError,
)
from archivey.internal import extraction, long_paths
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.filters import apply_name_policy
from archivey.internal.link_watch import LinkWatch
from archivey.types import ArchiveMember, MemberType
from tests.extract_util import lock_directories_at_once, open_and_extract

_PORTABLE = pytest.mark.parametrize(
    "policy", [ExtractionPolicy.STRICT, ExtractionPolicy.STANDARD]
)
# STRICT refuses a name holding a backslash or a control character, so only STANDARD
# writes the portable spelling these tests check.
_REWRITES = pytest.mark.parametrize("policy", [ExtractionPolicy.STANDARD])
_POSIX_SYMLINKS = pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")


def _tar(specs: list[tuple[str, str, bytes | str | None]]) -> bytes:
    """A tar from ``(kind, name, payload)``: kind ``file`` or ``ro`` (a read-only file;
    bytes), ``dir`` or ``rodir`` (a read-only directory), ``sym`` or ``hard`` (link
    target)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for kind, name, payload in specs:
            info = tarfile.TarInfo(name)
            if kind in ("file", "ro"):
                assert isinstance(payload, bytes)
                info.size = len(payload)
                info.mode = 0o644 if kind == "file" else 0o444
                tf.addfile(info, io.BytesIO(payload))
                continue
            if kind in ("dir", "rodir"):
                info.type = tarfile.DIRTYPE
                info.mode = 0o755 if kind == "dir" else 0o555
            else:
                assert isinstance(payload, str)
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = payload
            tf.addfile(info)
    return buf.getvalue()


def _member(
    name: str, *, type: MemberType = MemberType.FILE, link_target: str | None = None
) -> ArchiveMember:
    return ArchiveMember(
        type=type, name=name, raw_name=name.encode(), link_target=link_target
    )


def _tree(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


# --- A backslash in a TAR name is a separator --------------------------------------


@_REWRITES
def test_tar_backslash_is_written_as_a_separator(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """Windows writes ``a\\b`` as directory ``a`` and file ``b``; so does every OS."""
    report = open_and_extract(
        io.BytesIO(_tar([("file", "a\\b", b"x")])), tmp_path / "out", policy=policy
    )
    result = report.results[0]
    assert result.status is ExtractionStatus.EXTRACTED
    assert _tree(tmp_path / "out") == ["a", "a/b"]
    assert (tmp_path / "out" / "a" / "b").read_bytes() == b"x"
    # The rewrite is recorded like any other portable rewrite.
    assert result.presented_name == "a\\b"
    assert result.member.name == "a\\b"


@pytest.mark.skipif(os.name == "nt", reason="Windows writes '\\' as a separator")
def test_tar_backslash_is_literal_under_trusted(tmp_path: Path) -> None:
    open_and_extract(
        io.BytesIO(_tar([("file", "a\\b", b"x")])),
        tmp_path / "out",
        policy=ExtractionPolicy.TRUSTED,
    )
    assert _tree(tmp_path / "out") == ["a\\b"]


@_REWRITES
def test_tar_backslash_meets_a_file_of_the_same_name_as_a_slash_does(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """``a`` then ``a\\b``: the outcome is the one ``a`` then ``a/b`` gets."""

    def outcome(name: str, dest: Path) -> list[tuple[ExtractionStatus, str | None]]:
        report = open_and_extract(
            io.BytesIO(_tar([("file", "a", b"1"), ("file", name, b"2")])),
            dest,
            policy=policy,
            on_error=OnError.CONTINUE,
        )
        return [
            (r.status, type(r.error).__name__ if r.error else None)
            for r in report.results
        ]

    slash = outcome("a/b", tmp_path / "slash")
    backslash = outcome("a\\b", tmp_path / "backslash")
    assert backslash == slash
    assert slash[1][0] is ExtractionStatus.FAILED


@_PORTABLE
def test_link_target_backslash_becomes_a_separator(policy: ExtractionPolicy) -> None:
    for type in (MemberType.HARDLINK, MemberType.SYMLINK):
        member = _member("h", type=type, link_target="d\\f")
        assert apply_name_policy(member, policy).link_target == "d/f"


@_REWRITES
def test_hardlink_target_backslash_becomes_a_separator(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The member names hold a ``\\`` too, which STRICT refuses."""
    archive = _tar([("file", "d\\f", b"data"), ("hard", "h\\g", "d\\f")])
    report = open_and_extract(io.BytesIO(archive), tmp_path / "out", policy=policy)
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 2
    assert (tmp_path / "out" / "h" / "g").read_bytes() == b"data"


@_PORTABLE
def test_hardlink_resolves_by_its_stored_target(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The target rewrite does not change which member a hard link names.

    The reader matches a hard link to a member by the stored spelling, before any
    policy runs, so ``d\\f`` does not name the member stored ``d/f`` on any OS. The
    rewrite only puts the target on the path the universal check sees.
    """
    archive = _tar([("file", "d/f", b"data"), ("hard", "h", "d\\f")])
    report = open_and_extract(
        io.BytesIO(archive), tmp_path / "out", policy=policy, on_error=OnError.CONTINUE
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.FAILED,
    ]
    assert isinstance(report.results[1].error, LinkTargetNotFoundError)


@_POSIX_SYMLINKS
@_REWRITES
def test_symlink_to_a_member_named_with_a_backslash_resolves(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The file ``a\\b`` is written at ``a/b``, so the link to it must follow."""
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("file", "a\\b", b"x"), ("sym", "l", "a\\b")])),
        dest,
        policy=policy,
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 2
    assert (dest / "l").read_bytes() == b"x"
    # The member still records the target as stored.
    assert report.results[1].member.link_target == "a\\b"


@_PORTABLE
def test_symlink_target_backslash_cannot_climb_out(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """``..\\x`` is ``../x`` once rewritten, which leaves the destination."""
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("sym", "l", "..\\x")])),
        dest,
        policy=policy,
        on_error=OnError.CONTINUE,
    )
    result = report.results[0]
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.link_target == "..\\x"
    assert not (dest / "l").is_symlink()


@_POSIX_SYMLINKS
@pytest.mark.parametrize("name", ["foo\\x", "foo. /x"])
def test_rewritten_name_is_checked_where_it_is_written(
    tmp_path: Path, name: str
) -> None:
    """The universal check runs again on the rewritten name.

    ``foo\\x`` and ``foo. /x`` name no directory ``foo`` until the policy rewrites them
    to ``foo/x``. A ``foo`` symlink already in the destination that leaves it must
    refuse the member, as it refuses ``foo/x``.
    """
    dest = tmp_path / "out"
    outside = tmp_path / "outside"
    dest.mkdir()
    outside.mkdir()
    (dest / "foo").symlink_to(outside)
    report = open_and_extract(
        io.BytesIO(_tar([("file", name, b"x")])),
        dest,
        policy=ExtractionPolicy.STRICT,
        on_error=OnError.CONTINUE,
    )
    result = report.results[0]
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.member_name == name
    assert list(outside.iterdir()) == []


# --- Characters Windows refuses are escaped ----------------------------------------


@pytest.mark.parametrize(
    "name,written",
    [
        ("a?b", "a%3Fb"),
        ('q"u<o>t|e*', "q%22u%3Co%3Et%7Ce%2A"),
        ("tab\there", "tab%09here"),
        ("line\nbreak\x1f", "line%0Abreak%1F"),
        ("bell\x01", "bell%01"),
        # A '%' in a name the escape rewrites is escaped too, so it reads back.
        ("50%?", "50%25%3F"),
        # Each segment, directories included.
        ("d?r/f*le", "d%3Fr/f%2Ale"),
    ],
)
@_PORTABLE
def test_windows_invalid_characters_are_escaped(
    name: str, written: str, policy: ExtractionPolicy
) -> None:
    if policy is ExtractionPolicy.STRICT and any(c < " " for c in name):
        with pytest.raises(FilterRejectionError, match="control character"):
            apply_name_policy(_member(name), policy)
        return
    out = apply_name_policy(_member(name), policy)
    assert out.name == written


@_PORTABLE
def test_windows_invalid_characters_are_escaped_on_disk(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("file", "what?.txt", b"x"), ("file", "a|b", b"y")])),
        dest,
        policy=policy,
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 2
    assert _tree(dest) == ["a%7Cb", "what%3F.txt"]
    assert [r.presented_name for r in report.results] == ["what?.txt", "a|b"]


def test_plain_names_and_percent_are_not_escaped() -> None:
    for name in ["50%.txt", "café", "a b", "x\x7fy", "#&;'"]:
        member = _member(name)
        assert apply_name_policy(member, ExtractionPolicy.STRICT) is member


@pytest.mark.skipif(os.name == "nt", reason="Windows refuses these names")
def test_windows_invalid_characters_are_written_under_trusted(tmp_path: Path) -> None:
    open_and_extract(
        io.BytesIO(_tar([("file", "what?.txt", b"x")])),
        tmp_path / "out",
        policy=ExtractionPolicy.TRUSTED,
    )
    assert _tree(tmp_path / "out") == ["what?.txt"]


@_PORTABLE
def test_hardlink_to_an_escaped_name_links_to_what_was_written(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("file", "a?b", b"x"), ("hard", "l", "a?b")])),
        dest,
        policy=policy,
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 2
    assert _tree(dest) == ["a%3Fb", "l"]
    assert (dest / "l").read_bytes() == b"x"


# --- Windows device names beyond CON/NUL/COMn/LPTn ----------------------------------


_MORE_DEVICES = ["COM¹", "com².txt", "LPT³", "lpt¹.log", "CONIN$", "conout$.txt"]


@pytest.mark.parametrize("name", _MORE_DEVICES)
@_PORTABLE
def test_more_windows_device_names_are_rejected(
    tmp_path: Path, name: str, policy: ExtractionPolicy
) -> None:
    """Win32 reads ¹²³ as port digits and opens the console for ``CONIN$``/``CONOUT$``,
    so these are refused on every OS, as ``COM1`` is."""
    report = open_and_extract(
        io.BytesIO(_tar([("file", f"d/{name}", b"x")])),
        tmp_path / "out",
        policy=policy,
        on_error=OnError.CONTINUE,
    )
    result = report.results[0]
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert "Windows-reserved device name" in result.error.message


def test_similar_names_are_not_devices() -> None:
    for name in ["COM⁴", "COM0", "COM10", "CONIN", "CONOUT$x", "LPT¹x"]:
        member = _member(name)
        assert apply_name_policy(member, ExtractionPolicy.STRICT) is member


@pytest.mark.skipif(os.name == "nt", reason="these are devices on Windows")
def test_more_windows_device_names_are_written_under_trusted(tmp_path: Path) -> None:
    open_and_extract(
        io.BytesIO(_tar([("file", n, b"x") for n in _MORE_DEVICES])),
        tmp_path / "out",
        policy=ExtractionPolicy.TRUSTED,
    )
    assert _tree(tmp_path / "out") == sorted(_MORE_DEVICES)


# --- Windows name errors are typed --------------------------------------------------


def _win_error(winerror: int, err: int = errno.EINVAL) -> OSError:
    """An ``OSError`` as Windows raises it: ``winerror`` set beside a mapped errno."""
    exc = OSError(err, "simulated")
    setattr(exc, "winerror", winerror)  # noqa: B010 - POSIX OSError has no such slot
    return exc


@pytest.mark.parametrize(
    "winerror,err,message",
    [
        (123, errno.EINVAL, "cannot be represented"),
        (206, errno.ENOENT, "too long"),
        (1314, errno.EINVAL, "privilege"),
    ],
)
def test_windows_name_errors_are_typed(winerror: int, err: int, message: str) -> None:
    exc = _win_error(winerror, err)
    typed = extraction._typed_os_error(exc, "m")
    assert isinstance(typed, ExtractionError)
    assert message in typed.message
    assert typed.member_name == "m"
    assert typed.__cause__ is exc


def test_other_windows_errors_stay_raw() -> None:
    for exc in [
        _win_error(5, errno.EACCES),
        _win_error(87),
        OSError(errno.EINVAL, "x"),
    ]:
        assert extraction._typed_os_error(exc, "m") is exc


@pytest.mark.parametrize("on_error", [OnError.CONTINUE, OnError.STOP])
def test_symlink_privilege_refusal_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, on_error: OnError
) -> None:
    """Windows without Developer Mode or elevation refuses every symlink with 1314."""

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise _win_error(1314)

    monkeypatch.setattr(os, "symlink", refuse)
    archive = io.BytesIO(_tar([("file", "f", b"x"), ("sym", "l", "f")]))
    if on_error is OnError.STOP:
        with pytest.raises(ExtractionError, match="privilege") as info:
            open_and_extract(archive, tmp_path / "out", on_error=on_error)
        assert info.value.member_name == "l"
        return
    report = open_and_extract(archive, tmp_path / "out", on_error=on_error)
    result = report.results[1]
    assert result.status is ExtractionStatus.FAILED
    assert isinstance(result.error, ExtractionError)
    assert "Developer Mode" in result.error.message


# --- Symlink targets use Windows separators on Windows ------------------------------


@_POSIX_SYMLINKS
def test_symlink_target_gets_windows_separators_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulated on POSIX: the link is created with ``\\``, which Windows resolves.

    On POSIX the resulting link dangles (``sub\\file`` is one name there), which is
    enough to see what target was written.
    """
    monkeypatch.setattr(extraction, "_WINDOWS", True)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar(
                [
                    ("dir", "sub", None),
                    ("file", "sub/file", b"x"),
                    ("sym", "l", "sub/file"),
                ]
            )
        ),
        dest,
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert os.readlink(dest / "l") == "sub\\file"
    # The member still records the target as stored.
    assert report.results[2].member.link_target == "sub/file"


@pytest.mark.skipif(os.name != "nt", reason="Windows symlink resolution")
def test_symlink_with_slash_target_resolves_on_windows(tmp_path: Path) -> None:
    probe = tmp_path / "probe"
    try:
        probe.symlink_to("x")
    except OSError:
        pytest.skip("this process may not create symlinks")
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar(
                [
                    ("dir", "sub", None),
                    ("file", "sub/file", b"x"),
                    ("sym", "l", "sub/file"),
                ]
            )
        ),
        dest,
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert (dest / "l").read_bytes() == b"x"


# --- An existing directory keeps its mode only where a mode can differ ------------


@pytest.mark.skipif(os.name == "nt", reason="simulates Windows modes with chmod")
def test_existing_directory_keeps_its_mode_only_where_windows_can_tell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulated on POSIX: Windows reports a writable directory as ``0o777``, and a
    mode applied there sets only the read-only attribute. A ``0o755`` member over an
    existing writable directory changes nothing, so nothing was kept; a ``0o555``
    member would have made it read-only, so its mode was kept. The ``0o755`` one
    used to report ``kept_mode=0o777`` on every existing directory."""
    monkeypatch.setattr(extraction, "_WINDOWS", True)
    dest = tmp_path / "out"
    for name in ("w", "ro"):
        (dest / name).mkdir(parents=True)
        os.chmod(dest / name, 0o777)
    report = open_and_extract(
        io.BytesIO(_tar([("dir", "w/", None), ("rodir", "ro/", None)])),
        dest,
        policy=ExtractionPolicy.STANDARD,
    )
    kept = {r.member.name: r.kept_mode for r in report.results}
    assert kept == {"w/": None, "ro/": 0o777}
    assert stat.S_IMODE(os.stat(dest / "ro").st_mode) == 0o777


# --- A read-only file this run wrote can be replaced --------------------------------


def _refuse_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make POSIX refuse to replace or unlink a read-only file, or remove a read-only
    directory, as Windows does."""
    real_replace, real_unlink, real_rmdir = os.replace, os.unlink, os.rmdir

    def check(path: str | Path) -> None:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return
        kept = stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)
        if kept and not st.st_mode & stat.S_IWRITE:
            raise PermissionError(errno.EACCES, "Access is denied", str(path))

    def replace(src: str | Path, dst: str | Path) -> None:
        check(dst)
        real_replace(src, dst)

    def unlink(path: str | Path) -> None:
        check(path)
        real_unlink(path)

    monkeypatch.setattr(extraction, "_WINDOWS", True)
    monkeypatch.setattr(os, "replace", replace)

    def rmdir(path: str | Path) -> None:
        check(path)
        real_rmdir(path)

    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(os, "rmdir", rmdir)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize("second", ["file", "sym"])
@_PORTABLE
def test_replace_over_a_read_only_file_this_run_wrote(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy: ExtractionPolicy,
    second: str,
) -> None:
    """``README`` stored read-only, then ``readme``: the collision replaces it on every
    OS, by an atomic replace (a file) or an unlink first (a symlink)."""
    if second == "sym" and os.name == "nt":
        pytest.skip("needs POSIX symlinks")
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    payload = b"new" if second == "file" else "elsewhere"
    report = open_and_extract(
        io.BytesIO(_tar([("ro", "README", b"old"), (second, "readme", payload)])),
        dest,
        policy=policy,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.EXTRACTED,
    ]
    if second == "file":
        assert (dest / "README").read_bytes() == b"new"
    else:
        assert os.readlink(dest / "README") == "elsewhere"


def test_streaming_duplicate_of_a_read_only_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A streaming pass writes the first copy before it sees the second."""
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("ro", "f", b"old"), ("ro", "f", b"new")])),
        dest,
        streaming=True,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "f").read_bytes() == b"new"
    assert _mode(dest / "f") == 0o444


def test_streaming_duplicate_that_is_refused_still_removes_the_read_only_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The later copy is blocked, so the parked earlier copy is removed, not replaced:
    random access would never have written it."""
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("ro", "f", b"old"), ("sym", "f", "../../outside")])),
        dest,
        streaming=True,
        on_error=OnError.CONTINUE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.BLOCKED,
    ]
    assert _tree(dest) == []


def test_anti_item_removes_a_read_only_file_this_run_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Driven on the coordinator, as the anti-item tests in test_extraction.py are: no
    test archive of ours carries an anti-item after a read-only file."""
    from archivey.internal.bomb_tracker import BombTracker
    from archivey.internal.extraction import (
        ExtractionCoordinator,
        _Claim,
        _RunState,
    )

    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    dest.mkdir()
    written = dest / "f"
    written.write_bytes(b"x")
    os.chmod(written, 0o444)
    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.STRICT)
    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths={written},
        collision_map={"f": _Claim(written, 0, written)},
    )
    anti = ArchiveMember(type=MemberType.ANTI, name="f")
    result = coordinator._apply_anti_item(anti, written)
    assert result.status is ExtractionStatus.EXTRACTED
    assert not written.exists()


def test_replace_over_a_read_only_directory_this_run_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory stored ``0o555`` (kept under ``STANDARD``), then a file of the same
    name. Simulated: POSIX removes such a directory, so the refusal is patched in.
    What this shows is that the coordinator clears the mode before ``os.rmdir``, not
    that Windows refuses the call. The run applies directory modes when it ends, so
    the mode is applied at once here to make the directory read-only in time."""
    lock_directories_at_once(monkeypatch)
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("rodir", "d", None), ("file", "d", b"x")])),
        dest,
        policy=ExtractionPolicy.STANDARD,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "d").read_bytes() == b"x"


@_POSIX_SYMLINKS
def test_replace_over_a_read_only_directory_first_created_as_a_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``d`` is created as the parent of ``d/x``, emptied when the streaming pass
    removes the parked ``d/x`` for a blocked duplicate, then given ``0o555`` by a
    ``d`` directory member (applied at once here, as in the test above). It is in
    ``created_dirs``, never ``written_paths``, and the later file ``d`` still replaces
    it."""
    lock_directories_at_once(monkeypatch)
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar(
                [
                    ("file", "d/x", b"x"),
                    ("sym", "d/x", "../../outside"),
                    ("rodir", "d", None),
                    ("file", "d", b"y"),
                ]
            )
        ),
        dest,
        policy=ExtractionPolicy.STANDARD,
        streaming=True,
        on_error=OnError.CONTINUE,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.BLOCKED,
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "d").read_bytes() == b"y"


def test_anti_item_removes_a_read_only_directory_this_run_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Driven on the coordinator, as the file case above is."""
    from archivey.internal.bomb_tracker import BombTracker
    from archivey.internal.extraction import (
        ExtractionCoordinator,
        _RunState,
    )

    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    written = dest / "d"
    written.mkdir(parents=True)
    os.chmod(written, 0o555)
    coordinator = ExtractionCoordinator(policy=ExtractionPolicy.STANDARD)
    coordinator._state = _RunState(
        dest=dest,
        dest_root=dest.resolve(),
        tracker=BombTracker(None, None),
        # An anti-item does not read the reader.
        reader=cast("BaseArchiveReader", SimpleNamespace()),
        links=LinkWatch(dest.resolve(), None),
        written_paths={written},
    )
    anti = ArchiveMember(type=MemberType.ANTI, name="d")
    result = coordinator._apply_anti_item(anti, written)
    assert result.status is ExtractionStatus.EXTRACTED
    assert not written.exists()


def test_read_only_flag_stays_on_other_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clearing the flag clears it on the file, so the other names get it back."""
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar([("ro", "a", b"old"), ("hard", "B", "a"), ("file", "b", b"new")])
        ),
        dest,
        policy=ExtractionPolicy.STRICT,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.EXTRACTED,
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "B").read_bytes() == b"new"
    assert (dest / "a").read_bytes() == b"old"
    assert _mode(dest / "a") == 0o444


def test_read_only_file_already_in_the_destination_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only what this run wrote is opened up; the caller's read-only file still
    refuses the replace, as it does on Windows."""
    _refuse_read_only(monkeypatch)
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "f").write_bytes(b"mine")
    os.chmod(dest / "f", 0o444)
    report = open_and_extract(
        io.BytesIO(_tar([("file", "f", b"theirs")])),
        dest,
        overwrite=OverwritePolicy.REPLACE,
        on_error=OnError.CONTINUE,
    )
    assert report.results[0].status is ExtractionStatus.FAILED
    assert (dest / "f").read_bytes() == b"mine"
    assert _mode(dest / "f") == 0o444


@pytest.mark.skipif(
    os.name != "nt", reason="Windows refuses to replace read-only files"
)
def test_replace_over_a_read_only_file_on_windows(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(_tar([("ro", "README", b"old"), ("file", "readme", b"new")])),
        dest,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.OVERWRITTEN,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "README").read_bytes() == b"new"


# --- More hard links than NTFS allows ----------------------------------------------


@pytest.mark.parametrize("refusal", ["emlink", "winerror"])
def test_hard_link_past_the_link_limit_is_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """NTFS allows 1024 names for one file; simulated here with a limit of 2 names.

    The next link is a copy, and the links after it link to the copy.
    """
    real_link = os.link

    def link(src: str | Path, dst: str | Path) -> None:
        if os.stat(src).st_nlink >= 2:
            if refusal == "emlink":
                raise OSError(errno.EMLINK, "Too many links")
            raise _win_error(1142)
        real_link(src, dst)

    monkeypatch.setattr(os, "link", link)
    dest = tmp_path / "out"
    specs: list[tuple[str, str, bytes | str | None]] = [("file", "f", b"data")]
    specs += [("hard", f"h{i}", "f") for i in range(3)]
    report = open_and_extract(io.BytesIO(_tar(specs)), dest)
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 4
    assert all((dest / n).read_bytes() == b"data" for n in ["f", "h0", "h1", "h2"])
    same = os.stat(dest / "f").st_ino
    assert os.stat(dest / "h0").st_ino == same
    assert os.stat(dest / "h1").st_ino != same
    assert os.stat(dest / "h2").st_ino == os.stat(dest / "h1").st_ino


def test_links_past_the_limit_cost_one_attempt_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every older name of a full file is full too, so none is tried again. Trying
    them made the number of ``os.link`` calls quadratic in the archive's link count."""
    real_link = os.link
    calls = 0

    def link(src: str | Path, dst: str | Path) -> None:
        nonlocal calls
        calls += 1
        if os.stat(src).st_nlink >= 4:
            raise OSError(errno.EMLINK, "Too many links")
        real_link(src, dst)

    monkeypatch.setattr(os, "link", link)
    links = 40
    specs: list[tuple[str, str, bytes | str | None]] = [("file", "f", b"data")]
    specs += [("hard", f"h{i}", "f") for i in range(links)]
    report = open_and_extract(io.BytesIO(_tar(specs)), tmp_path / "out")
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * (
        links + 1
    )
    assert calls == links
    assert len({os.stat(p).st_ino for p in (tmp_path / "out").iterdir()}) == 11


def test_link_limit_copies_trip_the_archive_wide_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Copies made because a file ran out of link slots count toward ``max_ratio``: a
    small archive declaring many links to one member must not write far more than its
    size just because the byte cap is high. A cross-device copy is not counted, since
    it depends on the destination, not the archive."""
    real_link = os.link

    def link(src: str | Path, dst: str | Path) -> None:
        if os.stat(src).st_nlink >= 2:
            raise OSError(errno.EMLINK, "Too many links")
        real_link(src, dst)

    payload = bytes(64 * 1024)
    specs: list[tuple[str, str, bytes | str | None]] = [("file", "f", payload)]
    specs += [("hard", f"h{i}", "f") for i in range(40)]
    data = _tar(specs)
    limits = ExtractionLimits(
        max_ratio=len(payload) * 20 / len(data), ratio_activation_threshold=0
    )
    monkeypatch.setattr(os, "link", link)
    with pytest.raises(
        ResourceLimitError,
        match=r"Archive-wide decompression ratio .* bytes copied for hard links past "
        "the filesystem's link-count limit",
    ):
        open_and_extract(io.BytesIO(data), tmp_path / "out", limits=limits)

    def cross_device(src: str | Path, dst: str | Path) -> None:
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(os, "link", cross_device)
    report = open_and_extract(io.BytesIO(data), tmp_path / "out2", limits=limits)
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 41


def test_other_link_errors_still_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def link(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", link)
    report = open_and_extract(
        io.BytesIO(_tar([("file", "f", b"data"), ("hard", "h", "f")])),
        tmp_path / "out",
        on_error=OnError.CONTINUE,
    )
    assert report.results[1].status is ExtractionStatus.FAILED
    assert not (tmp_path / "out" / "h").exists()


# --- Paths past MAX_PATH ------------------------------------------------------------


def test_long_windows_path_gets_the_extended_prefix() -> None:
    deep = "C:\\" + "\\".join(["d" * 50] * 6) + "\\file.txt"
    assert long_paths.extended(deep) == "\\\\?\\" + deep
    # Win32 would normalize these; the extended form must name the same file.
    assert long_paths.extended(deep.replace("\\", "/")) == "\\\\?\\" + deep
    unc = "\\\\server\\share\\" + "\\".join(["d" * 50] * 6)
    assert long_paths.extended(unc) == "\\\\?\\UNC\\" + unc[2:]
    # Short paths, and paths already in a device namespace, are left as given.
    assert long_paths.extended("C:\\short\\f") == "C:\\short\\f"
    assert long_paths.extended("\\\\?\\" + deep) == "\\\\?\\" + deep
    assert long_paths.extended("\\\\.\\" + deep[3:]) == "\\\\.\\" + deep[3:]


def test_extended_prefix_is_stripped_for_display() -> None:
    assert long_paths.plain("\\\\?\\C:\\a\\b") == "C:\\a\\b"
    assert long_paths.plain("\\\\?\\UNC\\server\\share\\a") == "\\\\server\\share\\a"
    assert long_paths.plain("C:\\a") == "C:\\a"
    assert long_paths.plain("/tmp/a") == "/tmp/a"


@pytest.mark.skipif(os.name == "nt", reason="the no-op is the POSIX branch")
def test_long_path_is_a_no_op_off_windows() -> None:
    path = Path("/" + "d" * 400)
    assert long_paths.long_path(path) is path


def _fake_long_paths(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Take the Windows long-path route on POSIX, for every path.

    A second leading ``/`` names the same file on Linux, so the run still works, and
    pathlib keeps it (POSIX leaves two leading slashes to the implementation), so a
    ``Path`` built from a returned path keeps the prefix as one built from ``\\\\?\\``
    does on Windows. Any path that shows it leaked out of the filesystem calls. Returns
    the paths the helper extended.
    """
    seen: list[str] = []

    def fake(path: str) -> str:
        if path.startswith("//"):
            return path
        seen.append(path)
        return "/" + os.path.abspath(path)

    monkeypatch.setattr(long_paths, "_ENABLED", True)
    monkeypatch.setattr(long_paths, "_PREFIXES", (("//", "/"),))
    monkeypatch.setattr(long_paths, "extended", fake)
    return seen


# The filesystem calls the extraction code makes, by module, for the routing inventory.
_ROUTED_CALLS: list[tuple[object, str]] = [
    *(
        (os, name)
        for name in (
            "open",
            "lstat",
            "stat",
            "replace",
            "rename",
            "unlink",
            "rmdir",
            "link",
            "symlink",
            "makedirs",
            "mkdir",
            "chmod",
            "utime",
            "readlink",
            "scandir",
            "walk",
            "access",
        )
    ),
    *((os.path, name) for name in ("lexists", "exists", "isdir", "islink")),
    (shutil, "rmtree"),
    (builtins, "open"),
]


def _spy_on_paths(monkeypatch: pytest.MonkeyPatch, root: Path) -> list[str]:
    """Record each path under ``root`` that archivey's own code hands to a filesystem
    call in ``_ROUTED_CALLS``, as "<call> <path>". Calls the standard library makes
    inside those (``os.makedirs`` calling ``os.mkdir``) are not archivey's and are left
    out: the caller's module decides."""
    seen: list[str] = []
    prefix = os.fspath(root)

    def under_root(value: object) -> str | None:
        if not isinstance(value, (str, os.PathLike)):
            return None
        text = os.fspath(value)
        if not isinstance(text, str):
            return None
        plain = text[1:] if text.startswith("//") else text
        return text if plain.startswith(prefix) else None

    for module, name in _ROUTED_CALLS:
        real = getattr(module, name)

        def spy(
            *args: object, _real: object = real, _name: str = name, **kwargs: object
        ) -> object:
            caller = sys._getframe(1).f_globals.get("__name__", "")
            if caller.startswith("archivey."):
                for value in args:
                    path = under_root(value)
                    if path is not None:
                        seen.append(f"{_name} {path}")
            return _real(*args, **kwargs)  # type: ignore[operator]

        monkeypatch.setattr(module, name, spy)
    return seen


@_POSIX_SYMLINKS
@pytest.mark.parametrize(
    "streaming,dry_run,policy",
    [
        (False, False, ExtractionPolicy.STRICT),
        (True, False, ExtractionPolicy.STRICT),
        (False, True, ExtractionPolicy.STRICT),
        (False, False, ExtractionPolicy.TRUSTED),
    ],
)
@pytest.mark.parametrize("link_limit", [False, True])
def test_filesystem_calls_take_the_long_path_form(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    streaming: bool,
    dry_run: bool,
    policy: ExtractionPolicy,
    link_limit: bool,
) -> None:
    """Each path under the destination (or a dry run's scratch copy) that archivey
    hands to one of ``_ROUTED_CALLS`` is in the long-path form, and no result shows
    that form. A new call site that forgets the helper fails here. ``link_limit``
    refuses every hard link, so the copy fallback runs too."""
    seen = _fake_long_paths(monkeypatch)
    if link_limit:

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise OSError(errno.EMLINK, "Too many links")

        monkeypatch.setattr(os, "link", refuse)
    calls = _spy_on_paths(monkeypatch, Path(tempfile.gettempdir()).resolve())
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar(
                [
                    ("dir", "d", None),
                    ("file", "d/f", b"1"),
                    ("ro", "d/ro", b"2"),
                    ("sym", "d/l", "f"),
                    ("hard", "d/h", "d/f"),
                    ("file", "D/F", b"3"),
                    ("dir", "d/sub", None),
                ]
            )
        ),
        dest,
        streaming=streaming,
        dry_run=dry_run,
        policy=policy,
        overwrite=OverwritePolicy.REPLACE,
    )
    assert seen
    statuses = [r.status for r in report.results]
    if policy is ExtractionPolicy.TRUSTED:
        # No case-only collision: D/F is its own file.
        assert statuses == [ExtractionStatus.EXTRACTED] * 7, report.results
    else:
        assert statuses.count(ExtractionStatus.EXTRACTED) == 6, report.results
    if dry_run:
        # One top-level directory, so its links were walked and recorded.
        assert report._dry_run_links == (("d/l", "f"),)
    else:
        assert (dest / "d" / "h").read_bytes() == b"1"
        assert os.readlink(dest / "d" / "l") == "f"
    assert calls
    unrouted = [call for call in calls if not call.split(" ", 1)[1].startswith("//")]
    assert unrouted == []
    for result in report.results:
        for path in (result.path, result.requested_path, result.collided_with):
            assert path is None or not str(path).startswith("//")


@pytest.mark.skipif(os.name == "nt", reason="the stand-in prefix is POSIX-only")
def test_long_path_errors_name_the_plain_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OS error raised on the long form names the path as the caller gave it."""
    _fake_long_paths(monkeypatch)
    dest = tmp_path / "out"
    dest.mkdir()
    real_makedirs = os.makedirs

    def refuse_taken(name: str, *args: object, **kwargs: object) -> None:
        # The filesystem refuses the folder, as a read-only one would refuse a
        # caller that is not root. ``name`` is the long form.
        if str(name).endswith("/taken"):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), name)
        real_makedirs(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "makedirs", refuse_taken)
    report = open_and_extract(
        io.BytesIO(_tar([("file", "taken/f", b"x")])),
        dest,
        on_error=OnError.CONTINUE,
    )
    result = report.results[0]
    assert result.status is ExtractionStatus.FAILED
    error = result.error
    assert isinstance(error, OSError)
    assert error.filename is not None
    assert not str(error.filename).startswith("//")


def test_too_long_path_without_long_path_support_is_typed() -> None:
    """Win32 reports a path past MAX_PATH as missing (winerror 3); it is a name error."""
    exc = _win_error(3, errno.ENOENT)
    exc.filename = "C:\\" + "d" * 300
    typed = extraction._typed_os_error(exc, "m")
    assert isinstance(typed, ExtractionError)
    assert "too long" in typed.message
    # A short path that is really missing stays what it is, and so does a long path
    # in the extended form, which MAX_PATH does not limit.
    short = _win_error(3, errno.ENOENT)
    short.filename = "C:\\short"
    assert extraction._typed_os_error(short, "m") is short
    extended = _win_error(3, errno.ENOENT)
    extended.filename = "\\\\?\\C:\\" + "d" * 300
    assert extraction._typed_os_error(extended, "m") is extended


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH is a Win32 limit")
def test_path_past_max_path_is_written_on_windows(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    deep = "/".join(["d" * 60] * 5) + "/file.txt"
    assert len(str(dest / deep)) > 300
    report = open_and_extract(
        io.BytesIO(_tar([("file", deep, b"x"), ("sym", deep + ".lnk", "file.txt")])),
        dest,
        on_error=OnError.CONTINUE,
    )
    result = report.results[0]
    assert result.status is ExtractionStatus.EXTRACTED, result.error
    assert result.path is not None
    assert not str(result.path).startswith("\\\\?\\")
    assert result.path == dest / deep
    with open("\\\\?\\" + str(result.path), "rb") as f:
        assert f.read() == b"x"
    link = report.results[1]
    assert link.path is None or not str(link.path).startswith("\\\\?\\")


# --- A symlink to a directory gets the directory flag on Windows ---------------------


def _record_symlinks(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, bool]]:
    """Take the Windows symlink route on POSIX; record each ``os.symlink`` call as
    (target, link name, target_is_directory)."""
    monkeypatch.setattr(extraction, "_DIRECTORY_LINKS", True)
    calls: list[tuple[str, str, bool]] = []
    real = os.symlink

    def spy(src: str, dst: str, target_is_directory: bool = False) -> None:
        calls.append((os.fspath(src), os.path.basename(dst), target_is_directory))
        real(src, dst)

    monkeypatch.setattr(os, "symlink", spy)
    return calls


def _zip(specs: list[tuple[str, str, bytes | str | None]]) -> bytes:
    """A ZIP from ``(kind, name, payload)`` as for ``_tar``: ``file``, ``dir`` or
    ``sym``. A ZIP has a central directory, so the run has its listing up front."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for kind, name, payload in specs:
            if kind == "dir":
                info = zipfile.ZipInfo(name + "/")
                info.create_system = 3
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                zf.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(name)
            # Unix, so the mode in external_attr counts: on Windows ZipInfo defaults
            # to MS-DOS, and the link would read back as a file.
            info.create_system = 3
            if kind == "sym":
                assert isinstance(payload, str)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(info, payload.encode())
            else:
                assert isinstance(payload, bytes)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                zf.writestr(info, payload)
    return buf.getvalue()


_LINK_BEFORE_DIR: list[tuple[str, str, bytes | str | None]] = [
    ("sym", "l", "d"),
    ("dir", "d", None),
    ("file", "d/f", b"x"),
]


@_POSIX_SYMLINKS
def test_symlink_to_a_directory_member_listed_later_is_a_directory_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The archive's listing shows ``d`` is a directory before it is written."""
    calls = _record_symlinks(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(_zip(_LINK_BEFORE_DIR)), dest)
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert calls == [("d", "l", True)]


@_POSIX_SYMLINKS
def test_symlink_to_an_implied_directory_is_a_directory_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``x/f`` shows ``x`` is a directory even without a member for it."""
    calls = _record_symlinks(monkeypatch)
    open_and_extract(
        io.BytesIO(_zip([("sym", "a/l", "../x"), ("file", "x/f", b"1")])),
        tmp_path / "out",
    )
    assert calls == [("../x", "l", True)]


@_POSIX_SYMLINKS
def test_symlink_whose_target_turns_out_a_directory_is_recreated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A streaming pass has no listing: the link is fixed once the run is done."""
    calls = _record_symlinks(monkeypatch)
    dest = tmp_path / "out"
    report = open_and_extract(io.BytesIO(_tar(_LINK_BEFORE_DIR)), dest, streaming=True)
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert calls[0] == ("d", "l", False)
    assert len(calls) == 2
    assert calls[1][0] == "d" and calls[1][2] is True
    assert os.readlink(dest / "l") == "d"
    assert sorted(os.listdir(dest)) == ["d", "l"]
    assert report.results[0].path == dest / "l"


@_POSIX_SYMLINKS
def test_link_read_back_with_the_extended_prefix_is_still_remade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows reads an absolute link target back with the extended prefix; the
    end-of-run pass compares it plain, so the link is still known as this run's."""
    calls = _record_symlinks(monkeypatch)
    _fake_long_paths(monkeypatch)
    real_readlink = os.readlink

    def readlink(path: object) -> str:
        target = real_readlink(path)  # type: ignore[arg-type]
        return "/" + target if target.startswith("/") else target

    monkeypatch.setattr(os, "readlink", readlink)
    dest = tmp_path / "out"

    def absolute(member: ArchiveMember) -> ArchiveMember:
        if member.name == "l":
            return member.replace(link_target=str(dest / "d"))
        return member

    report = open_and_extract(
        io.BytesIO(_tar(_LINK_BEFORE_DIR)), dest, streaming=True, filter=absolute
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert [flag for _, _, flag in calls] == [False, True]
    assert real_readlink(dest / "l") == str(dest / "d")


@_POSIX_SYMLINKS
def test_symlink_to_an_existing_directory_is_a_directory_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_symlinks(monkeypatch)
    open_and_extract(
        io.BytesIO(_tar([("dir", "sub/d", None), ("sym", "sub/l", "../sub/d")])),
        tmp_path / "out",
        streaming=True,
    )
    assert calls == [("../sub/d", "l", True)]


@_POSIX_SYMLINKS
@pytest.mark.parametrize("streaming", [False, True])
def test_file_and_dangling_symlinks_stay_file_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    calls = _record_symlinks(monkeypatch)
    open_and_extract(
        io.BytesIO(
            _tar([("sym", "a", "f"), ("file", "f", b"x"), ("sym", "b", "missing")])
        ),
        tmp_path / "out",
        streaming=streaming,
    )
    assert calls == [("f", "a", False), ("missing", "b", False)]


@_POSIX_SYMLINKS
def test_posix_symlinks_take_no_directory_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[object, ...]] = []
    real = os.symlink

    def spy(*args: object, **kwargs: object) -> None:
        calls.append((*args, *kwargs.items()))
        real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "symlink", spy)
    open_and_extract(io.BytesIO(_tar(_LINK_BEFORE_DIR)), tmp_path / "out")
    assert len(calls) == 1
    assert calls[0][0] == "d"
    assert len(calls[0]) == 2


def _can_symlink(tmp_path: Path) -> bool:
    probe = tmp_path / "probe"
    try:
        probe.symlink_to("x")
    except OSError:
        return False
    probe.unlink()
    return True


@pytest.mark.skipif(os.name != "nt", reason="Windows symlink kinds")
@pytest.mark.parametrize(
    "build,streaming", [(_zip, False), (_tar, False), (_tar, True)]
)
def test_symlink_to_a_later_directory_is_traversable_on_windows(
    tmp_path: Path,
    build: Callable[[list[tuple[str, str, bytes | str | None]]], bytes],
    streaming: bool,
) -> None:
    """With a listing (ZIP) the link is made a directory link at once; without one
    (TAR) it is remade as one when the run ends."""
    if not _can_symlink(tmp_path):
        pytest.skip("this process may not create symlinks")
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(build(_LINK_BEFORE_DIR)), dest, streaming=streaming
    )
    assert [r.status for r in report.results] == [ExtractionStatus.EXTRACTED] * 3
    assert (dest / "l").is_dir()
    assert (dest / "l" / "f").read_bytes() == b"x"


# --- An 8.3 short name aliases a file this run wrote ---------------------------------


def _alias_after_first(
    dest: Path, first: str, alias: str
) -> Callable[[ArchiveMember], ArchiveMember]:
    """A filter that makes ``alias`` a second name of ``first`` just before ``alias``
    is written, as an 8.3 short name is on a volume that has them."""

    def make_alias(member: ArchiveMember) -> ArchiveMember:
        # On a Windows volume that makes 8.3 names the alias is there already.
        if member.name == alias and not os.path.lexists(dest / alias):
            os.link(dest / first, dest / alias)
        return member

    return make_alias


@pytest.mark.parametrize(
    "overwrite",
    [
        OverwritePolicy.ERROR,
        OverwritePolicy.SKIP,
        OverwritePolicy.REPLACE,
        OverwritePolicy.RENAME,
    ],
)
def test_short_name_alias_collides_with_the_member_it_names(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """``LONGFI~1.TXT`` after ``longfilename.txt`` is a collision, not a file that was
    already there: the second name reaches the file this run just wrote."""
    dest = tmp_path / "out"
    first = dest / "longfilename.txt"
    report = open_and_extract(
        io.BytesIO(
            _tar([("file", "longfilename.txt", b"1"), ("file", "LONGFI~1.TXT", b"2")])
        ),
        dest,
        filter=_alias_after_first(dest, "longfilename.txt", "LONGFI~1.TXT"),
        overwrite=overwrite,
        on_error=OnError.CONTINUE,
    )
    one, two = report.results
    assert two.collided_with == first
    if overwrite is OverwritePolicy.REPLACE:
        assert one.status is ExtractionStatus.OVERWRITTEN
        assert two.status is ExtractionStatus.EXTRACTED
        assert two.path == first
        assert first.read_bytes() == b"2"
    elif overwrite is OverwritePolicy.RENAME:
        assert one.status is ExtractionStatus.EXTRACTED
        assert two.status is ExtractionStatus.EXTRACTED
        assert two.path is not None and two.path.read_bytes() == b"2"
        assert first.read_bytes() == b"1"
    else:
        assert one.status is ExtractionStatus.EXTRACTED
        assert first.read_bytes() == b"1"
        assert two.status in (
            ExtractionStatus.FAILED,
            ExtractionStatus.NOT_OVERWRITTEN,
        )


@pytest.mark.parametrize("overwrite", [OverwritePolicy.ERROR, OverwritePolicy.REPLACE])
def test_short_name_alias_is_a_file_already_there_under_trusted(
    tmp_path: Path, overwrite: OverwritePolicy
) -> None:
    """``TRUSTED`` defers to the local OS: the alias meets an entry already there, so
    there is no collision event and the earlier member's result is not revised."""
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar([("file", "longfilename.txt", b"1"), ("file", "LONGFI~1.TXT", b"2")])
        ),
        dest,
        filter=_alias_after_first(dest, "longfilename.txt", "LONGFI~1.TXT"),
        policy=ExtractionPolicy.TRUSTED,
        overwrite=overwrite,
        on_error=OnError.CONTINUE,
    )
    one, two = report.results
    assert one.status is ExtractionStatus.EXTRACTED
    assert two.collided_with is None
    if overwrite is OverwritePolicy.REPLACE:
        assert two.status is ExtractionStatus.EXTRACTED
        assert two.path == dest / "LONGFI~1.TXT"
    else:
        assert two.status is ExtractionStatus.FAILED
        assert isinstance(two.error, ExtractionError)
        assert "already exists" in two.error.message
        assert (dest / "longfilename.txt").read_bytes() == b"1"


def test_hard_link_the_caller_already_had_is_not_a_collision(tmp_path: Path) -> None:
    """A second name of a file this run did not write stays a pre-existing file."""
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "mine").write_bytes(b"caller's")
    os.link(dest / "mine", dest / "alias")
    report = open_and_extract(
        io.BytesIO(_tar([("file", "other", b"1"), ("file", "alias", b"2")])),
        dest,
        on_error=OnError.CONTINUE,
    )
    assert report.results[1].status is ExtractionStatus.FAILED
    assert report.results[1].collided_with is None


@pytest.mark.skipif(os.name != "nt", reason="8.3 short names are a Windows feature")
def test_short_name_alias_on_windows(tmp_path: Path) -> None:
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "longfilename.txt").write_bytes(b"")
    if not (probe / "LONGFI~1.TXT").exists():
        pytest.skip("this volume does not make 8.3 short names")
    dest = tmp_path / "out"
    report = open_and_extract(
        io.BytesIO(
            _tar([("file", "longfilename.txt", b"1"), ("file", "LONGFI~1.TXT", b"2")])
        ),
        dest,
        overwrite=OverwritePolicy.REPLACE,
    )
    one, two = report.results
    assert one.status is ExtractionStatus.OVERWRITTEN
    assert two.status is ExtractionStatus.EXTRACTED
    assert two.collided_with == dest / "longfilename.txt"
    assert (dest / "longfilename.txt").read_bytes() == b"2"


# --- A name another writer creates first clashes as the existence check would -------


_OTHER_WRITER = b"other writer"


def _another_writer_takes(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Simulate another writer (a second extraction into the same folder) creating
    ``name`` as a file between the existence check and the landing. Windows refuses the
    rename of a FILE or HARDLINK with access denied; ``os.symlink`` and ``os.makedirs``
    refuse a taken name on every OS."""
    real_replace = os.replace
    real_makedirs = os.makedirs

    def take(dst: str) -> None:
        Path(dst).write_bytes(_OTHER_WRITER)

    def replace(src: str, dst: str) -> None:
        if os.path.basename(str(dst)) == name:
            take(dst)
            raise PermissionError(errno.EACCES, "Access is denied", str(dst))
        real_replace(src, dst)

    def symlink(src: str, dst: str, target_is_directory: bool = False) -> None:
        take(dst)
        raise FileExistsError(errno.EEXIST, "File exists", str(dst))

    def makedirs(path: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        if os.path.basename(str(path)) == name:
            take(path)
            raise FileExistsError(errno.EEXIST, "File exists", str(path))
        real_makedirs(path, mode, exist_ok)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "symlink", symlink)
    monkeypatch.setattr(os, "makedirs", makedirs)


# What each landing raises when nothing maps it: the other policies.
_UNMAPPED = {
    "file": PermissionError,
    "hard": PermissionError,
    "sym": FileExistsError,
    "dir": FileExistsError,
}


@pytest.mark.parametrize(
    "kind",
    ["file", "hard", pytest.param("sym", marks=_POSIX_SYMLINKS), "dir"],
)
@pytest.mark.parametrize("overwrite", [OverwritePolicy.ERROR, OverwritePolicy.REPLACE])
def test_landing_on_a_name_taken_after_the_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    overwrite: OverwritePolicy,
) -> None:
    """Another writer takes ``b.txt`` between the existence check and the landing.
    Under ERROR that is the clash the check reports, for every member kind; the other
    policies do not handle it, and the landing's own error goes out as it is."""
    dest = tmp_path / "out"
    _another_writer_takes(monkeypatch, "b.txt")
    second: tuple[str, str, bytes | str | None] = {
        "file": ("file", "b.txt", b"ours"),
        "hard": ("hard", "b.txt", "a.txt"),
        "sym": ("sym", "b.txt", "a.txt"),
        "dir": ("dir", "b.txt", None),
    }[kind]
    archive = _tar([("file", "a.txt", b"first"), second])
    raised = ExtractionError if overwrite is OverwritePolicy.ERROR else _UNMAPPED[kind]
    with pytest.raises(raised) as excinfo:
        open_and_extract(io.BytesIO(archive), dest, overwrite=overwrite)
    if raised is ExtractionError:
        assert "Destination already exists" in str(excinfo.value)
    assert (dest / "b.txt").read_bytes() == _OTHER_WRITER
    assert _tree(dest) == ["a.txt", "b.txt"]


@_POSIX_SYMLINKS
def test_a_symlink_landing_on_a_parked_name_taken_again_is_a_clash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlink removes the parked copy of its name before it lands, so a name taken
    after that is another writer's, as for a free name."""

    def symlink(src: str, dst: str, target_is_directory: bool = False) -> None:
        Path(dst).write_bytes(_OTHER_WRITER)
        raise FileExistsError(errno.EEXIST, "File exists", str(dst))

    monkeypatch.setattr(os, "symlink", symlink)
    archive = _tar([("file", "a.txt", b"first"), ("sym", "a.txt", "x")])
    with pytest.raises(ExtractionError, match="Destination already exists"):
        open_and_extract(
            io.BytesIO(archive),
            tmp_path / "out",
            streaming=True,
            overwrite=OverwritePolicy.ERROR,
        )


def test_a_refused_landing_on_a_parked_copy_is_not_a_clash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A streaming pass parks the earlier ``a.txt`` and the later one replaces it under
    any policy. A rename refused there is not the caller's entry in the way, so ERROR
    does not report it as one: the refusal goes out as it is."""
    real_replace = os.replace
    landings = 0

    def replace(src: str, dst: str) -> None:
        nonlocal landings
        if os.path.basename(str(dst)) == "a.txt":
            landings += 1
            if landings == 2:
                raise PermissionError(errno.EACCES, "Access is denied", str(dst))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", replace)
    archive = _tar([("file", "a.txt", b"first"), ("file", "a.txt", b"second")])
    with pytest.raises(PermissionError):
        open_and_extract(
            io.BytesIO(archive),
            tmp_path / "out",
            streaming=True,
            overwrite=OverwritePolicy.ERROR,
        )
    assert landings == 2
