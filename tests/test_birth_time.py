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


@pytest.mark.skipif(
    not birth_time.can_set_birth_time(), reason="this system cannot set a birth time"
)
def test_set_birth_time_sets_it(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"x")
    assert birth_time.set_birth_time(str(path), _BORN)
    assert _stat_birth_time(path) == pytest.approx(_BORN.timestamp(), abs=1)


@pytest.mark.skipif(
    not birth_time.can_set_birth_time(), reason="this system cannot set a birth time"
)
def test_extraction_restores_the_birth_time_of_files_and_folders(
    tmp_path: Path,
) -> None:
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
    assert kinds == ["utime", "birth"] * 2
    assert [when for kind, when in calls if kind == "birth"] == [_BORN, _BORN]


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
