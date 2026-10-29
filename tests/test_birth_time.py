"""Extraction restores a member's birth time (``created``) where the system allows it."""

from __future__ import annotations

import io
import os
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.internal import birth_time, extraction as extraction_module

_BORN = datetime(2001, 2, 3, 4, 5, 6, tzinfo=UTC)
_MODIFIED = datetime(2011, 2, 3, 4, 5, 6, tzinfo=UTC)


# Gated on the system, not on the setter: a setter that failed to load must fail these.
_CAN_SET = pytest.mark.skipif(
    sys.platform not in ("win32", "darwin"), reason="only Windows and macOS set it"
)


def _stat_birth_time(path: Path) -> float:
    st = os.stat(path, follow_symlinks=False)
    if hasattr(st, "st_birthtime"):
        return st.st_birthtime
    assert sys.platform == "win32"
    return st.st_ctime  # the creation time on Windows before 3.12


def _zip() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("d/", b"")
        zf.writestr("d/a.txt", b"hello")
    buf.seek(0)
    return buf


def _extract_with_times(dest: Path) -> None:
    with open_archive(_zip()) as archive:
        archive.extract_all(
            dest, filter=lambda m: m.replace(created=_BORN, modified=_MODIFIED)
        )


@_CAN_SET
def test_set_birth_time_sets_it(tmp_path: Path) -> None:
    assert birth_time.can_set_birth_time()
    path = tmp_path / "f"
    path.write_bytes(b"x")
    assert birth_time.set_birth_time(str(path), _BORN)
    assert _stat_birth_time(path) == pytest.approx(_BORN.timestamp(), abs=1)


@_CAN_SET
def test_extraction_restores_the_birth_time_of_files_and_folders(
    tmp_path: Path,
) -> None:
    assert birth_time.can_set_birth_time()
    _extract_with_times(tmp_path)
    for path in (tmp_path / "d", tmp_path / "d" / "a.txt"):
        assert _stat_birth_time(path) == pytest.approx(_BORN.timestamp(), abs=1)
        assert path.stat().st_mtime == pytest.approx(_MODIFIED.timestamp(), abs=1)


@pytest.mark.skipif(
    sys.platform in ("win32", "darwin"), reason="Windows and macOS can set it"
)
def test_set_birth_time_is_a_no_op_where_the_system_cannot(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"x")
    assert not birth_time.can_set_birth_time()
    assert not birth_time.set_birth_time(str(path), _BORN)


def test_extraction_sets_the_birth_time_after_the_modified_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every file and folder gets its ``created`` time, after ``os.utime``: macOS pulls
    a birth time later than the new modified time back to it."""
    calls: list[tuple[str, object]] = []
    real_utime = os.utime

    def utime(target: object, *args: object, **kwargs: object) -> None:
        calls.append(("utime", target))
        real_utime(target, *args, **kwargs)  # type: ignore[arg-type]

    def set_birth(target: str | int, when: datetime) -> bool:
        calls.append(("birth", when))
        return False

    monkeypatch.setattr(extraction_module.os, "utime", utime)
    monkeypatch.setattr(extraction_module, "set_birth_time", set_birth)
    _extract_with_times(tmp_path)
    kinds = [kind for kind, _ in calls]
    # The file first, then the folder in the deferred pass. On Windows the file's birth
    # time is set again on its final name after the rename (tunnelling).
    file_calls = (
        ["utime", "birth", "birth"] if sys.platform == "win32" else ["utime", "birth"]
    )
    assert kinds == [*file_calls, "utime", "birth"]
    assert {when for kind, when in calls if kind == "birth"} == {_BORN}


def test_a_member_with_no_birth_time_leaves_it_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        extraction_module, "set_birth_time", lambda *args: calls.append(args)
    )
    with open_archive(_zip()) as archive:
        archive.extract_all(tmp_path)
    assert calls == []


def test_a_refused_birth_time_does_not_fail_the_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(target: str | int, when: datetime) -> bool:
        raise OSError("refused")

    monkeypatch.setattr(birth_time, "_SETTER", refuse)
    _extract_with_times(tmp_path)
    assert (tmp_path / "d" / "a.txt").read_bytes() == b"hello"


@_CAN_SET
def test_extraction_over_an_existing_file_sets_the_birth_time(tmp_path: Path) -> None:
    """Replacing a file just written under the same name keeps the member's birth
    time: on Windows, file-system tunnelling would hand the new file the old one's."""
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a.txt").write_bytes(b"old")
    with open_archive(_zip()) as archive:
        archive.extract_all(
            tmp_path,
            overwrite="replace",
            filter=lambda m: m.replace(created=_BORN, modified=_MODIFIED),
        )
    path = tmp_path / "d" / "a.txt"
    assert path.read_bytes() == b"hello"
    assert _stat_birth_time(path) == pytest.approx(_BORN.timestamp(), abs=1)


def test_the_tick_arithmetic_is_exact() -> None:
    """A ``timestamp()`` float times 10**7 is past the integers a float holds."""
    when = datetime(2038, 1, 19, 3, 14, 7, 1, tzinfo=UTC)
    ticks = birth_time._microseconds_since(birth_time._FILETIME_EPOCH, when) * 10
    assert ticks == 137_919_572_470_000_010
