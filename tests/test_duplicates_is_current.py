"""Tests for is_current last-entry-wins duplicate-name behaviour.

Verifies that ZIP and TAR archives with two same-name entries:
- mark the earlier one is_current=False and the later one is_current=True
- extract_all under default policy succeeds (no ExtractionError), recording
  SUPERSEDED for the non-current entry and EXTRACTED for the current one
- leaves the *last* entry's content on disk
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.types import ExtractionStatus


def _zip_with_duplicate(tmp_path: Path, name: str, contents: list[bytes]) -> Path:
    """Create a ZIP with multiple entries under the same ``name``."""
    p = tmp_path / "dup.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as zf:
        for data in contents:
            zf.writestr(name, data)
    return p


def _tar_with_duplicate(tmp_path: Path, name: str, contents: list[bytes]) -> Path:
    """Create a TAR with multiple entries under the same ``name``."""
    p = tmp_path / "dup.tar"
    with tarfile.open(p, "w:") as tf:
        for data in contents:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return p


@pytest.mark.parametrize("format_", ["zip", "tar"])
def test_duplicate_name_is_current(tmp_path: Path, format_: str) -> None:
    """Two same-name entries: first is_current=False, last is_current=True."""
    name = "file.txt"
    first_content = b"first version"
    last_content = b"last version"

    if format_ == "zip":
        archive = _zip_with_duplicate(tmp_path, name, [first_content, last_content])
    else:
        archive = _tar_with_duplicate(tmp_path, name, [first_content, last_content])

    with open_archive(archive) as reader:
        members = reader.members()
        assert len(members) == 2
        assert members[0].name == name
        assert members[1].name == name
        assert members[0].is_current is False, "first entry should be non-current"
        assert members[1].is_current is True, "last entry should be current"


@pytest.mark.parametrize("format_", ["zip", "tar"])
def test_duplicate_name_extract_succeeds(tmp_path: Path, format_: str) -> None:
    """extract_all on a dup-name archive: SUPERSEDED + EXTRACTED, last content on disk."""
    name = "file.txt"
    first_content = b"first version"
    last_content = b"last version"

    if format_ == "zip":
        archive = _zip_with_duplicate(tmp_path, name, [first_content, last_content])
    else:
        archive = _tar_with_duplicate(tmp_path, name, [first_content, last_content])

    dest = tmp_path / "out"
    with open_archive(archive) as reader:
        # Default policy (ERROR overwrite) must not raise despite duplicate names,
        # because the non-current entry is skipped as SUPERSEDED before writing.
        report = reader.extract_all(dest)

    results = report.results
    assert len(results) == 2
    by_id = {r.member.member_id: r for r in results}
    first_result = by_id[0]
    last_result = by_id[1]

    assert first_result.status is ExtractionStatus.SUPERSEDED
    assert first_result.path is None
    assert last_result.status is ExtractionStatus.EXTRACTED
    assert last_result.path is not None

    written = (dest / name).read_bytes()
    assert written == last_content, "disk content must be the last entry's content"
