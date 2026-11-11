"""Volume sets over ``fsspec`` (``fsspec-integration`` §volumes).

An ``OpenFile`` is never searched for the other parts of its set, whatever
``discover_volumes`` says (maintainer ruling, 2026-11-11): archivey lists no remote
folder and probes no sibling name. A remote set is passed as a list of ``OpenFile``
objects, and a lone part whose set turns out to need more parts is refused with a
message that names that list.
"""

from __future__ import annotations

import io
import shutil
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")

from fsspec.core import OpenFile  # noqa: E402
from fsspec.implementations.memory import MemoryFileSystem  # noqa: E402

from archivey import (  # noqa: E402
    ArchiveyConfig,
    DiagnosticCode,
    TruncatedError,
    UnsupportedFeatureError,
    open_archive,
)
from archivey.internal.volumes import REMOTE_VOLUMES_AS_LIST  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "rar"


class CountingMemoryFS(MemoryFileSystem):
    """A memory file system of its own that counts ``ls``, ``info`` and existence
    checks, the calls a search for sibling volumes would make."""

    cachable = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.store: dict[str, Any] = {}
        self.pseudo_dirs = [""]
        self.listings = 0
        self.infos: list[str] = []

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> Any:
        self.listings += 1
        return super().ls(path, detail=detail, **kwargs)

    def info(self, path: str, **kwargs: Any) -> Any:
        self.infos.append(self._strip_protocol(path))
        return super().info(path, **kwargs)

    def assert_no_search(self, named: str) -> None:
        """No listing, and no question about any file but the one named."""
        assert self.listings == 0
        assert set(self.infos) <= {named}


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


def _read_all(source: object, config: ArchiveyConfig | None = None) -> None:
    with open_archive(source, config=config) as reader:
        for member in reader.members():
            if member.is_file:
                reader.read(member)


RAR_SETS = {
    "tinyvol.part1.rar": ["tinyvol.part1.rar", "tinyvol.part2.rar"],
    "tinyvol_rnn.rar": ["tinyvol_rnn.rar", "tinyvol_rnn.r00"],
}


@pytest.mark.parametrize("discover", [True, False])
@pytest.mark.parametrize(
    ("named", "error"),
    [
        # A first volume whose end-of-archive block says another follows.
        ("tinyvol.part1.rar", TruncatedError),
        ("tinyvol_rnn.rar", TruncatedError),
        # A later volume, which is not where a set starts.
        ("tinyvol.part2.rar", UnsupportedFeatureError),
        ("tinyvol_rnn.r00", UnsupportedFeatureError),
    ],
)
def test_a_remote_rar_part_is_not_searched_and_the_error_names_the_list(
    fs: CountingMemoryFS,
    named: str,
    error: type[Exception],
    discover: bool,
) -> None:
    """Every part of the set is beside it, and none is looked for: the open lists no
    folder, and the refusal says to pass the parts as a list."""
    for names in RAR_SETS.values():
        for name in names:
            fs.pipe(f"/d/{name}", (FIXTURES / name).read_bytes())
    with pytest.raises(error) as caught:
        _read_all(
            OpenFile(fs, f"/d/{named}", mode="rb"),
            ArchiveyConfig(discover_volumes=discover),
        )
    assert REMOTE_VOLUMES_AS_LIST in str(caught.value)
    fs.assert_no_search(f"/d/{named}")


@pytest.mark.parametrize("ext", ["zip", "7z"])
def test_a_remote_numbered_first_part_is_refused_by_name_naming_the_list(
    fs: CountingMemoryFS, ext: str
) -> None:
    """As a lone local part is (``found part 1 only``), with the list remedy added,
    and before any byte is read."""
    for index in (1, 2, 3):
        fs.pipe(f"/d/x.{ext}.{index:03d}", b"part")
    with pytest.raises(TruncatedError, match="found part 1 only") as caught:
        open_archive(OpenFile(fs, f"/d/x.{ext}.001", mode="rb"))
    assert REMOTE_VOLUMES_AS_LIST in str(caught.value)
    fs.assert_no_search(f"/d/x.{ext}.001")


def test_a_local_numbered_first_part_alone_keeps_its_message(tmp_path: Path) -> None:
    """The remedy is for a remote part: a local one was searched for."""
    (tmp_path / "x.zip.001").write_bytes(b"part")
    with pytest.raises(TruncatedError, match="found part 1 only") as caught:
        open_archive(tmp_path / "x.zip.001")
    assert REMOTE_VOLUMES_AS_LIST not in str(caught.value)


def test_a_list_of_open_files_opens_a_numbered_set(fs: CountingMemoryFS) -> None:
    parts, members = _zip_parts(3)
    for index, part in enumerate(parts, 1):
        fs.pipe(f"/d/x.zip.{index:03d}", part)
    files = [OpenFile(fs, f"/d/x.zip.{index:03d}", mode="rb") for index in (1, 2, 3)]
    with open_archive(files) as reader:
        assert reader.info.extra["zip.volume_count"] == 3
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == (
            members
        )
    assert fs.listings == 0


@pytest.mark.parametrize("named", sorted(RAR_SETS))
def test_a_list_of_open_files_opens_a_rar_set(fs: CountingMemoryFS, named: str) -> None:
    names = RAR_SETS[named]
    for name in names:
        fs.pipe(f"/d/{name}", (FIXTURES / name).read_bytes())
    with open_archive(FIXTURES / named) as local:
        expected = {m.name: m.size for m in local.members()}
        assert local.info.extra["rar.volume_count"] == len(names)
    with open_archive([OpenFile(fs, f"/d/{name}", mode="rb") for name in names]) as (
        reader
    ):
        assert reader.info.extra["rar.volume_count"] == len(names)
        assert {m.name: m.size for m in reader.members()} == expected
    assert fs.listings == 0


def test_a_listed_remote_set_with_a_gap_is_refused_as_a_local_one_is(
    fs: CountingMemoryFS, tmp_path: Path
) -> None:
    parts, _ = _zip_parts(3)
    for index in (1, 3):
        fs.pipe(f"/d/x.zip.{index:03d}", parts[index - 1])
        (tmp_path / f"x.zip.{index:03d}").write_bytes(parts[index - 1])
    with pytest.raises(TruncatedError, match="missing part 2"):
        open_archive(tmp_path / "x.zip.001")
    with pytest.raises(TruncatedError, match="missing part 2"):
        open_archive(
            [OpenFile(fs, f"/d/x.zip.{index:03d}", mode="rb") for index in (1, 3)]
        )


@pytest.mark.parametrize(
    "named", ["basic_nonsolid__.rar", "single.part1.rar", "single.exe"]
)
def test_a_remote_single_file_archive_opens_without_a_search(
    fs: CountingMemoryFS, named: str
) -> None:
    """A complete archive opens alone, under a volume-shaped name too, with no
    diagnostic and no listing; ``.r00`` siblings of the same base are ignored."""
    data = (FIXTURES / "basic_nonsolid__.rar").read_bytes()
    fs.pipe(f"/d/{named}", data)
    stem = named.split(".")[0]
    fs.pipe(f"/d/{stem}.r00", b"Rar!\x1a\x07\x01\x00")
    with open_archive(FIXTURES / "basic_nonsolid__.rar") as local:
        expected = [m.name for m in local.members()]
    with open_archive(OpenFile(fs, f"/d/{named}", mode="rb")) as reader:
        assert [m.name for m in reader.members()] == expected
        assert reader.info.extra["rar.volume_count"] == 1
        # The transport note every memory:// open gets; nothing about volumes.
        assert set(reader.diagnostics.counts) == {
            DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE
        }
    fs.assert_no_search(f"/d/{named}")


def test_a_remote_zip_opens_without_a_search(fs: CountingMemoryFS) -> None:
    parts, members = _zip_parts(1)
    fs.pipe("/d/plain.zip", parts[0])
    fs.pipe("/d/plain.zip.001", b"x")
    with open_archive(OpenFile(fs, "/d/plain.zip", mode="rb")) as reader:
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == (
            members
        )
    fs.assert_no_search("/d/plain.zip")


@pytest.mark.parametrize("named", sorted(RAR_SETS))
def test_local_discovery_is_unchanged(tmp_path: Path, named: str) -> None:
    """The same files that a remote open does not search for are found beside a
    local path."""
    for name in RAR_SETS[named]:
        shutil.copy(FIXTURES / name, tmp_path / name)
    with open_archive(tmp_path / named) as reader:
        assert reader.info.extra["rar.volume_count"] == len(RAR_SETS[named])
        for member in reader.members():
            if member.is_file:
                reader.read(member)
