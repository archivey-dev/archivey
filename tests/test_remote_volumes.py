"""Volume discovery over ``fsspec`` (``fsspec-integration`` §volumes).

A remote set is found by the same naming rules as a local one, from one ``ls`` of the
named file's directory, and each volume is read as its own ``OpenFile``.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")

from fsspec.core import OpenFile  # noqa: E402
from fsspec.implementations.memory import MemoryFileSystem  # noqa: E402

from archivey import open_archive  # noqa: E402
from archivey.internal.volumes import (  # noqa: E402
    RemoteVolumePath,
    discover_volume_siblings,
)

FIXTURES = Path(__file__).parent / "fixtures" / "rar"
RAR_HEAD = b"Rar!\x1a\x07\x01\x00"


class CountingMemoryFS(MemoryFileSystem):
    """A memory file system of its own that counts ``ls`` calls."""

    cachable = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.store: dict[str, Any] = {}
        self.pseudo_dirs = [""]
        self.listings = 0

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> Any:
        self.listings += 1
        return super().ls(path, detail=detail, **kwargs)


@pytest.fixture
def fs() -> Iterator[CountingMemoryFS]:
    yield CountingMemoryFS()


def _zip_parts(count: int) -> tuple[list[bytes], dict[str, bytes]]:
    members = {f"m{i}.txt": f"member {i}\n".encode() * 200 for i in range(6)}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    data = buf.getvalue()
    step = -(-len(data) // count)
    return [data[i : i + step] for i in range(0, len(data), step)], members


def test_a_numbered_set_opens_as_one_reader_from_one_listing(
    fs: CountingMemoryFS,
) -> None:
    parts, members = _zip_parts(3)
    for index, part in enumerate(parts, 1):
        fs.pipe(f"/d/x.zip.{index:03d}", part)
    fs.pipe("/d/unrelated.txt", b"x")
    listings_before = fs.listings
    with open_archive(OpenFile(fs, "/d/x.zip.001", mode="rb")) as reader:
        assert fs.listings - listings_before == 1
        assert reader.info.extra["zip.volume_count"] == 3
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == (
            members
        )


@pytest.mark.parametrize(
    ("named", "siblings"),
    [
        ("tinyvol.part1.rar", ["tinyvol.part2.rar"]),
        ("tinyvol_rnn.rar", ["tinyvol_rnn.r00"]),
    ],
)
def test_a_rar_set_opens_from_any_naming_scheme(
    fs: CountingMemoryFS, named: str, siblings: list[str]
) -> None:
    for name in [named, *siblings]:
        fs.pipe(f"/d/{name}", (FIXTURES / name).read_bytes())
    with open_archive(FIXTURES / named) as local:
        expected = {m.name: m.size for m in local.members()}
        assert local.info.extra["rar.volume_count"] == len(siblings) + 1
    with open_archive(OpenFile(fs, f"/d/{named}", mode="rb")) as reader:
        assert reader.info.extra["rar.volume_count"] == len(siblings) + 1
        assert {m.name: m.size for m in reader.members()} == expected


# Name sets where the choice is the rules' (padding, case, gaps, strays): the remote
# pick is the local one, name for name.
NAME_SETS = [
    ("q.part1.rar", ["q.part1.rar", "q.part2.rar", "q.part02.rar"]),
    ("x.7z.001", ["x.7z.001", "x.7z.002", "x.7z.0002", "x.7z.003"]),
    ("a.rar", ["a.rar", "a.r00", "a.r01", "A.R02", "a.r04", "backup.z01"]),
    ("a.r01", ["a.r00", "a.r01", "a.r03"]),
    ("lone.part1.rar", ["lone.part1.rar"]),
    ("plain.zip", ["plain.zip", "plain.zip.001"]),
]


@pytest.mark.parametrize(("named", "names"), NAME_SETS)
def test_remote_discovery_picks_what_local_discovery_picks(
    fs: CountingMemoryFS, tmp_path: Path, named: str, names: list[str]
) -> None:
    for name in names:
        (tmp_path / name).write_bytes(RAR_HEAD)
        fs.pipe(f"/d/{name}", RAR_HEAD)
    local = discover_volume_siblings(tmp_path / named)
    remote = discover_volume_siblings(RemoteVolumePath(fs, f"/d/{named}", {}))
    assert (None if remote is None else [p.name for p in remote]) == (
        None if local is None else [p.name for p in local]
    )
    assert fs.listings <= 1


class UnlistableFS(CountingMemoryFS):
    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> Any:
        raise PermissionError("listing refused")


def test_a_file_system_that_cannot_list_opens_the_volume_alone(
    tmp_path: Path,
) -> None:
    """As a lone local first part does: refused as an incomplete set."""
    from archivey import TruncatedError

    fs = UnlistableFS()
    parts, _ = _zip_parts(3)
    for index, part in enumerate(parts, 1):
        fs.pipe(f"/d/x.zip.{index:03d}", part)
    (tmp_path / "x.zip.001").write_bytes(parts[0])
    with pytest.raises(TruncatedError, match="found part 1 only"):
        open_archive(tmp_path / "x.zip.001")
    with pytest.raises(TruncatedError, match="found part 1 only"):
        open_archive(OpenFile(fs, "/d/x.zip.001", mode="rb"))


def test_a_discovered_link_is_refused(tmp_path: Path) -> None:
    """``islink`` from the listing is honoured as a local sibling link is."""
    fs = fsspec.filesystem("file")
    (tmp_path / "x.zip.001").write_bytes(b"a")
    (tmp_path / "target").write_bytes(b"b")
    (tmp_path / "x.zip.002").symlink_to(tmp_path / "target")
    from archivey import OpenError

    with pytest.raises(OpenError, match="symbolic link"):
        discover_volume_siblings(
            RemoteVolumePath(fs, (tmp_path / "x.zip.001").as_posix(), {})
        )
