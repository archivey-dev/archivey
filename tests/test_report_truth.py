"""Extraction and listing reports refuse a truth test, as ``VerifyReport`` does: a
sequence's truth is whether it is empty, so a failed extraction or a listing cut short
would read as success. ``ok`` and ``raise_for_failure()`` answer instead."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from archivey import CorruptionError, open_archive


def _tar(path: Path, names: list[str]) -> Path:
    with tarfile.open(path, "w") as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 3
            tf.addfile(info, io.BytesIO(b"abc"))
    return path


def test_extraction_report_refuses_a_truth_test(tmp_path: Path) -> None:
    archive = _tar(tmp_path / "a.tar", ["a.txt"])
    with open_archive(archive) as reader:
        report = reader.extract_all(tmp_path / "out")
    assert report.ok
    assert len(report) == 1
    with pytest.raises(TypeError, match=r"ExtractionReport\.ok"):
        bool(report)


def test_an_empty_extraction_report_is_ok_and_refuses_a_truth_test(
    tmp_path: Path,
) -> None:
    archive = _tar(tmp_path / "empty.tar", [])
    with open_archive(archive) as reader:
        report = reader.extract_all(tmp_path / "out")
    assert report.ok
    with pytest.raises(TypeError, match=r"ExtractionReport\.ok"):
        if report:
            pass


def test_complete_listing_is_ok(tmp_path: Path) -> None:
    archive = _tar(tmp_path / "a.tar", ["a.txt", "b.txt"])
    with open_archive(archive) as reader:
        report = reader.members_report()
    assert report.ok
    report.raise_for_failure()
    assert len(report) == 2
    with pytest.raises(TypeError, match=r"MemberListReport\.ok"):
        bool(report)


def test_listing_cut_short_is_not_ok_and_raises_its_error(tmp_path: Path) -> None:
    archive = _tar(tmp_path / "a.tar", ["a.txt", "b.txt"])
    data = bytearray(archive.read_bytes())
    data[512 + 512 + 148 : 512 + 512 + 156] = b"00000000"  # second header's checksum
    archive.write_bytes(bytes(data))
    with open_archive(archive) as reader:
        report = reader.members_report()
    assert [m.name for m in report] == ["a.txt"]
    assert not report.ok
    assert report.error is not None
    with pytest.raises(CorruptionError) as caught:
        report.raise_for_failure()
    assert caught.value is report.error
    with pytest.raises(TypeError, match=r"MemberListReport\.ok"):
        bool(report)
