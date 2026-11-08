"""``extract_all(on_blocked=)``: a refused member raises once the rest are written.

Under the default ``on_blocked="raise"`` every safe member is extracted, then the call
raises :class:`FilterRejectionError` carrying the whole report. ``on_blocked="skip"``
returns that report instead. ``abort_on=["blocked_member"]`` still stops at the first
refusal, with no report.
"""

from __future__ import annotations

import copy
import pickle
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ExtractionStatus,
    FilterRejectionError,
    OnBlocked,
    open_archive,
)


def _archive(tmp_path: Path, names: tuple[str, ...]) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as z:
        for name in names:
            z.writestr(name, name.encode())
    return path


_ONE_BAD = ("good1.txt", "../escape.txt", "good2.txt")
_TWO_BAD = ("../one.txt", "good.txt", "/../../two.txt", "../three.txt")


def test_the_default_raises_after_extracting_every_safe_member(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    with (
        open_archive(_archive(tmp_path, _ONE_BAD)) as reader,
        pytest.raises(FilterRejectionError) as info,
    ):
        reader.extract_all(dest)
    error = info.value
    assert (dest / "good1.txt").read_bytes() == b"good1.txt"
    assert (dest / "good2.txt").read_bytes() == b"good2.txt"
    assert not (tmp_path / "escape.txt").exists()
    assert error.member_name == "../escape.txt"
    assert "the rest of the archive was extracted" in str(error)
    assert "and " not in error.raw_message.split("First refusal")[0]
    report = error.report
    assert report is not None
    assert not report.ok
    statuses = {r.member.name: r.status for r in report}
    assert statuses["../escape.txt"] is ExtractionStatus.BLOCKED
    assert statuses["good1.txt"] is ExtractionStatus.EXTRACTED
    assert statuses["good2.txt"] is ExtractionStatus.EXTRACTED
    blocked = next(r for r in report if r.status is ExtractionStatus.BLOCKED)
    assert error.__cause__ is blocked.error


def test_the_message_counts_the_other_refusals(tmp_path: Path) -> None:
    with (
        open_archive(_archive(tmp_path, _TWO_BAD)) as reader,
        pytest.raises(FilterRejectionError) as info,
    ):
        reader.extract_all(tmp_path / "out")
    error = info.value
    assert error.report is not None
    blocked = [r for r in error.report if r.status is ExtractionStatus.BLOCKED]
    assert len(blocked) >= 2
    assert error.member_name == blocked[0].member.name
    assert f", and {len(blocked) - 1} more" in error.raw_message


@pytest.mark.parametrize("on_blocked", ["skip", OnBlocked.SKIP])
def test_skip_returns_the_report(tmp_path: Path, on_blocked: str) -> None:
    dest = tmp_path / "out"
    with open_archive(_archive(tmp_path, _ONE_BAD)) as reader:
        report = reader.extract_all(dest, on_blocked=on_blocked)
    assert not report.ok
    assert (dest / "good2.txt").exists()
    with pytest.raises(FilterRejectionError) as info:
        report.raise_for_failure()
    assert info.value.member_name == "../escape.txt"
    assert info.value.report is None


def test_a_clean_archive_returns_its_report(tmp_path: Path) -> None:
    with open_archive(_archive(tmp_path, ("a.txt", "b.txt"))) as reader:
        report = reader.extract_all(tmp_path / "out")
    assert report.ok
    report.raise_for_failure()


def test_abort_on_still_stops_at_the_first_refusal(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    with (
        open_archive(_archive(tmp_path, _ONE_BAD)) as reader,
        pytest.raises(FilterRejectionError) as info,
    ):
        reader.extract_all(dest, abort_on=["blocked_member"])
    assert info.value.report is None
    assert not (dest / "good2.txt").exists()


def test_a_dry_run_raises_the_same_way(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    with (
        open_archive(_archive(tmp_path, _ONE_BAD)) as reader,
        pytest.raises(FilterRejectionError) as info,
    ):
        reader.extract_all(dest, dry_run=True)
    assert info.value.report is not None
    assert not dest.exists()


def test_the_raised_error_survives_pickle_and_copy(tmp_path: Path) -> None:
    with (
        open_archive(_archive(tmp_path, _ONE_BAD)) as reader,
        pytest.raises(FilterRejectionError) as info,
    ):
        reader.extract_all(tmp_path / "out")
    error = info.value
    for clone in (
        pickle.loads(pickle.dumps(error)),
        copy.copy(error),
        copy.deepcopy(error),
    ):
        assert type(clone) is FilterRejectionError
        assert str(clone) == str(error)
        assert clone.report is not None
        assert [r.status for r in clone.report] == [r.status for r in error.report]


def test_an_unknown_on_blocked_is_refused(tmp_path: Path) -> None:
    with (
        open_archive(_archive(tmp_path, ("a.txt",))) as reader,
        pytest.raises(ValueError, match="on_blocked="),
    ):
        reader.extract_all(tmp_path / "out", on_blocked="ignore")  # type: ignore[arg-type]
