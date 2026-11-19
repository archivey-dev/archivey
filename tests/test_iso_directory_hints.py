"""An ISO image read from a URL: the path table's directory hints cut the requests."""

from __future__ import annotations

import io
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")
pycdlib = pytest.importorskip("pycdlib")

from fsspec.implementations.memory import MemoryFileSystem  # noqa: E402

from archivey import open_archive  # noqa: E402
from archivey.internal import remote  # noqa: E402
from archivey.internal.backends import iso_reader  # noqa: E402


def _image(directories: int) -> bytes:
    """ISO 9660 and Joliet trees, each directory with subdirectories and a file, so
    the walk goes back and forth across the directory area of each tree."""
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3)
    for i in range(directories):
        iso.add_directory(f"/D{i}", joliet_path=f"/d{i}")
        for j in range(3):
            iso.add_directory(f"/D{i}/S{j}", joliet_path=f"/d{i}/s{j}")
            iso.add_fp(
                io.BytesIO(b"x" * 3000),
                3000,
                f"/D{i}/S{j}/F.TXT;1",
                joliet_path=f"/d{i}/s{j}/f.txt",
            )
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _list_remote(data: bytes, monkeypatch: pytest.MonkeyPatch) -> tuple[list[str], int]:
    fetches: list[tuple[int, int]] = []
    fetch = remote.RangeSource.fetch

    def counted(self: remote.RangeSource, start: int, end: int) -> bytes:
        fetches.append((start, end))
        return fetch(self, start, end)

    monkeypatch.setattr(remote.RangeSource, "fetch", counted)
    fs = MemoryFileSystem()
    fs.pipe("/iso-hints/a.iso", data)
    try:
        with open_archive(fsspec.open("memory://iso-hints/a.iso")) as reader:
            names = [m.name for m in reader.members()]
    finally:
        fs.rm("/iso-hints", recursive=True)
    return names, len(fetches)


def test_directory_hints_cut_the_requests_of_a_remote_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _image(40)
    names, hinted = _list_remote(data, monkeypatch)

    def no_hints(*_: Any) -> None:
        return None

    monkeypatch.setattr(iso_reader, "_hint_directory_extents", no_hints)
    unhinted_names, unhinted = _list_remote(data, monkeypatch)

    # The same listing, as from a local file; fewer requests.
    with open_archive(io.BytesIO(data)) as reader:
        assert names == unhinted_names == [m.name for m in reader.members()]
    assert hinted < unhinted
    assert hinted <= 6


def test_each_tree_is_hinted_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # pycdlib parses each tree's path table twice (little- and big-endian); only
    # the first, which it walks the tree from, gives hints.
    calls: list[object] = []
    hint = iso_reader._hint_directory_extents

    def counted(*args: Any) -> None:
        calls.append(args[1])
        hint(*args)

    monkeypatch.setattr(iso_reader, "_hint_directory_extents", counted)
    _list_remote(_image(3), monkeypatch)
    assert len(calls) == 2  # the ISO 9660 tree and the Joliet tree
