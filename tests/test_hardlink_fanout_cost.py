"""Extracting many hard links to one file, or replacing many files, costs linear time.

Each link used to copy the list of paths already holding its source's content and
search it for its own path. With n links to one file that is n²/2 path comparisons:
16 000 links took 16 s, and 100 000 (a 620 KB ``.tar.gz``) would take about ten
minutes. Found by a sweep that times each format at n and 4n members. Forgetting a
replaced file as a link source scanned every source the same way.

Counts of ``PurePath.__eq__`` and ``__hash__`` calls stand in for the time, so the
tests do not depend on the machine's speed: before the fix, 1000 links made about half
a million comparisons, and 1000 replaced files about 2 million hashes.
"""

from __future__ import annotations

import io
import pathlib
import tarfile
from pathlib import Path

import pytest

from archivey import open_archive

_LINKS = 1000


def _links_to_one_file(n: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("f0")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
        for i in range(1, n):
            info = tarfile.TarInfo(f"f{i}")
            info.type = tarfile.LNKTYPE
            info.linkname = "f0"
            tar.addfile(info)
    return buf.getvalue()


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_many_links_to_one_file_extract_in_linear_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    data = _links_to_one_file(_LINKS)
    calls = 0
    original = pathlib.PurePath.__eq__

    def counting(self: pathlib.PurePath, other: object) -> bool:
        nonlocal calls
        calls += 1
        return original(self, other)

    monkeypatch.setattr(pathlib.PurePath, "__eq__", counting)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        report = reader.extract_all(tmp_path / "out")
    monkeypatch.undo()

    assert len(report.results) == _LINKS
    # A few comparisons per link at most; n²/2 would be half a million.
    assert calls < 10 * _LINKS
    inode = (tmp_path / "out" / "f0").stat().st_ino
    assert all(
        (tmp_path / "out" / f"f{i}").stat().st_ino == inode for i in range(_LINKS)
    )


def _every_name_twice(n: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for _ in range(2):
            for i in range(n):
                info = tarfile.TarInfo(f"f{i}")
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_replacing_every_file_extracts_in_linear_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    # Each replaced file is forgotten as a hard-link source. That scanned every
    # source the run had recorded, so n files and then the same n names again cost
    # n²/2 lookups, each hashing a path: about 2 million hashes for n = 1000.
    data = _every_name_twice(_LINKS)
    calls = 0
    original = pathlib.PurePath.__hash__

    def counting(self: pathlib.PurePath) -> int:
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(pathlib.PurePath, "__hash__", counting)
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        reader.extract_all(tmp_path / "out", overwrite="replace")
    monkeypatch.undo()

    # About 21 per member after the fix.
    assert calls < 100 * _LINKS
    assert len(list((tmp_path / "out").iterdir())) == _LINKS
