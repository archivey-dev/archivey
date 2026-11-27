"""``extract_all(on_problem=…)``: one setting for what a failed or refused member does.

A problem is a member that failed (damaged data, a write error, an existing entry
under ``overwrite="error"``) or that a safety check refused. The maintainer chose on
2026-11-27 that ``on_problem`` replaces ``on_error``, ``on_blocked`` and ``abort_on``,
with ``"finish"`` as the default: every member is tried, then the call raises the first
problem's error, carrying the whole report.
"""

from __future__ import annotations

import io
import zipfile
from contextlib import nullcontext
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveyUsageError,
    CorruptionError,
    open_archive,
)
from archivey.exceptions import FilterRejectionError
from archivey.types import ExtractionStatus, OnProblem

_PAYLOAD = bytes(range(256)) * 40


def _zip(path: Path, *, damaged: bool = False, unsafe: bool = False) -> Path:
    """``first.txt``, then ``bad.bin`` (one flipped data byte, so its CRC check
    fails) or ``../evil.txt`` (refused by every policy), then ``last.txt``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("first.txt", b"first")
        if damaged:
            zf.writestr("bad.bin", _PAYLOAD)
        if unsafe:
            zf.writestr("../evil.txt", b"evil")
        zf.writestr("last.txt", b"last")
    data = bytearray(buf.getvalue())
    if damaged:
        data[data.find(_PAYLOAD[:512]) + 100] ^= 0xFF
    path.write_bytes(bytes(data))
    return path


def _statuses(report: archivey.ExtractionReport) -> dict[str, ExtractionStatus]:
    return {r.member.name: r.status for r in report.results}


def test_on_problem_is_a_root_name() -> None:
    assert "OnProblem" in archivey.__all__
    assert archivey.OnProblem is OnProblem
    assert [v.value for v in OnProblem] == [
        "stop",
        "finish",
        "continue",
        "keep_partial",
    ]


def test_the_default_finishes_then_raises_the_failure_with_the_report(
    tmp_path: Path,
) -> None:
    src = _zip(tmp_path / "a.zip", damaged=True)
    dest = tmp_path / "out"
    with open_archive(src) as reader, pytest.raises(CorruptionError) as caught:
        reader.extract_all(dest)
    report = caught.value.report
    assert report is not None
    assert _statuses(report) == {
        "first.txt": ExtractionStatus.EXTRACTED,
        "bad.bin": ExtractionStatus.FAILED,
        "last.txt": ExtractionStatus.EXTRACTED,
    }
    # The error raised is the failed member's own.
    assert caught.value is next(r.error for r in report.results if r.error)
    assert (dest / "last.txt").read_bytes() == b"last"
    assert not (dest / "bad.bin").exists()


def test_the_default_finishes_then_raises_a_refusal_with_the_report(
    tmp_path: Path,
) -> None:
    src = _zip(tmp_path / "a.zip", unsafe=True)
    dest = tmp_path / "out"
    with open_archive(src) as reader, pytest.raises(FilterRejectionError) as caught:
        reader.extract_all(dest, on_problem="finish")
    report = caught.value.report
    assert report is not None
    assert _statuses(report)["../evil.txt"] is ExtractionStatus.BLOCKED
    assert (dest / "last.txt").read_bytes() == b"last"


@pytest.mark.parametrize("kind", ["damaged", "unsafe"])
def test_stop_raises_at_the_first_problem(tmp_path: Path, kind: str) -> None:
    src = _zip(tmp_path / "a.zip", **{kind: True})
    dest = tmp_path / "out"
    expected = CorruptionError if kind == "damaged" else FilterRejectionError
    with open_archive(src) as reader, pytest.raises(expected):
        reader.extract_all(dest, on_problem=OnProblem.STOP)
    assert (dest / "first.txt").exists()
    assert not (dest / "last.txt").exists()


@pytest.mark.parametrize("kind", ["damaged", "unsafe"])
def test_continue_returns_the_report(tmp_path: Path, kind: str) -> None:
    src = _zip(tmp_path / "a.zip", **{kind: True})
    dest = tmp_path / "out"
    with open_archive(src) as reader:
        report = reader.extract_all(dest, on_problem="continue")
    assert not report.ok
    problem = "bad.bin" if kind == "damaged" else "../evil.txt"
    expected = (
        ExtractionStatus.FAILED if kind == "damaged" else ExtractionStatus.BLOCKED
    )
    assert _statuses(report)[problem] is expected
    assert (dest / "last.txt").exists()
    assert not (dest / "bad.bin").exists()


def test_keep_partial_keeps_the_damaged_file_and_returns(tmp_path: Path) -> None:
    src = _zip(tmp_path / "a.zip", damaged=True)
    dest = tmp_path / "out"
    with open_archive(src) as reader:
        report = reader.extract_all(dest, on_problem="keep_partial")
    assert _statuses(report)["bad.bin"] is ExtractionStatus.FAILED
    assert (dest / "bad.bin").stat().st_size == len(_PAYLOAD)


def test_a_clean_archive_returns_the_report_in_every_mode(tmp_path: Path) -> None:
    src = _zip(tmp_path / "a.zip")
    for value in OnProblem:
        with open_archive(src) as reader:
            report = reader.extract_all(tmp_path / value.value, on_problem=value)
        assert report.ok


def test_a_bad_value_is_a_usage_error(tmp_path: Path) -> None:
    src = _zip(tmp_path / "a.zip")
    with (
        open_archive(src) as reader,
        pytest.raises(ArchiveyUsageError, match="on_problem"),
    ):
        reader.extract_all(tmp_path / "out", on_problem="halt")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("old", "value"),
    [
        ("on_error", "continue"),
        ("on_blocked", "skip"),
        ("abort_on", ["blocked_member"]),
    ],
)
def test_an_old_keyword_warns_and_keeps_its_behaviour(
    tmp_path: Path, old: str, value: object
) -> None:
    src = _zip(tmp_path / "a.zip", damaged=True)
    # The old default on_error="stop" raises at the damaged member.
    stopped = pytest.raises(CorruptionError) if old != "on_error" else nullcontext()
    with (
        open_archive(src) as reader,
        stopped,
        pytest.warns(DeprecationWarning, match="on_problem") as caught,
    ):
        reader.extract_all(tmp_path / "out", **{old: value})
    assert caught[0].filename == __file__
    if old != "on_error":
        # Under the old rules the failure stopped the run: last.txt is not written.
        assert not (tmp_path / "out" / "last.txt").exists()


def test_an_old_keyword_beside_on_problem_is_a_usage_error(tmp_path: Path) -> None:
    src = _zip(tmp_path / "a.zip")
    with (
        open_archive(src) as reader,
        pytest.raises(ArchiveyUsageError, match="on_problem"),
    ):
        reader.extract_all(tmp_path / "out", on_problem="continue", on_blocked="skip")
