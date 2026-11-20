"""An ISO image read from a URL: the path table's directory hints cut the requests."""

from __future__ import annotations

import io
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")
pycdlib = pytest.importorskip("pycdlib")

from fsspec.implementations.memory import MemoryFileSystem  # noqa: E402

from archivey import ArchiveyConfig, open_archive  # noqa: E402
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


def _list_remote(
    data: bytes, monkeypatch: pytest.MonkeyPatch, config: ArchiveyConfig | None = None
) -> tuple[list[str], int]:
    fetches: list[tuple[int, int]] = []
    cat = remote.RangeSource._cat

    def counted(
        self: remote.RangeSource, start: int, end: int, *args: Any
    ) -> tuple[int, bytes, bool]:
        fetches.append((start, end))
        return cat(self, start, end, *args)

    monkeypatch.setattr(remote.RangeSource, "_cat", counted)
    fs = MemoryFileSystem()
    fs.pipe("/iso-hints/a.iso", data)
    try:
        with open_archive(
            fsspec.open("memory://iso-hints/a.iso"), config=config
        ) as reader:
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


def test_no_directory_hints_when_reads_fetch_only_what_they_need(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A cluster's gaps are a guess, so ``max_read_through=0`` (fetch only the bytes
    # each read needs) gives no hint at all; the listing is the same.
    calls: list[object] = []

    def counted(*args: Any) -> None:
        calls.append(args)

    monkeypatch.setattr(iso_reader, "_hint_directory_extents", counted)
    data = _image(3)
    names, _ = _list_remote(data, monkeypatch, ArchiveyConfig(max_read_through=0))
    assert calls == []
    with open_archive(io.BytesIO(data)) as reader:
        assert names == [m.name for m in reader.members()]


def test_directory_clusters_span_no_gap_longer_than_max_read_through() -> None:
    hints: list[tuple[int, int]] = []

    class _Iso:
        logical_block_size = 2048

    # Directories at blocks 20, 21 and 40: 38 KiB from 21 to 40.
    parsed = (None, {20: 0, 21: 0, 40: 0, 41: 0})
    iso_reader._hint_directory_extents(
        _Iso(), parsed, lambda a, b: hints.append((a, b)), 16 * 1024
    )
    assert hints == [(20 * 2048, 22 * 2048), (40 * 2048, 42 * 2048)]
    hints.clear()
    iso_reader._hint_directory_extents(
        _Iso(), parsed, lambda a, b: hints.append((a, b)), 64 * 1024
    )
    assert hints == [(20 * 2048, 42 * 2048)]
