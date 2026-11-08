"""Volume discovery over ``fsspec`` (``fsspec-integration`` §volumes).

A remote set is found by the same naming rules as a local one, from one ``ls`` of the
named file's directory, and each volume is read as its own ``OpenFile``.
"""

from __future__ import annotations

import io
import logging
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

fsspec = pytest.importorskip("fsspec")

from fsspec.core import OpenFile  # noqa: E402
from fsspec.implementations.memory import MemoryFileSystem  # noqa: E402

from archivey import SourceChangedError, TruncatedError, open_archive  # noqa: E402
from archivey.exceptions import _UsageValueError  # noqa: E402
from archivey.internal.volumes import (  # noqa: E402
    RemoteVolumePath,
    discover_volume_siblings,
)

FIXTURES = Path(__file__).parent / "fixtures" / "rar"
RAR_HEAD = b"Rar!\x1a\x07\x01\x00"


class CountingMemoryFS(MemoryFileSystem):
    """A memory file system of its own that counts ``ls`` and ``info`` calls."""

    cachable = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.store: dict[str, Any] = {}
        self.pseudo_dirs = [""]
        self.listings = 0
        self.infos = 0

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> Any:
        self.listings += 1
        return super().ls(path, detail=detail, **kwargs)

    def info(self, path: str, **kwargs: Any) -> Any:
        self.infos += 1
        return super().info(path, **kwargs)


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
    infos_before = fs.infos
    with open_archive(OpenFile(fs, "/d/x.zip.001", mode="rb")) as reader:
        assert fs.listings - listings_before == 1
        # Each part's size comes from the listing: no part costs a request of its
        # own before its bytes are read.
        assert fs.infos == infos_before
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


def test_a_remote_set_with_a_gap_is_refused_as_a_local_one_is(
    fs: CountingMemoryFS, tmp_path: Path
) -> None:
    from archivey import TruncatedError

    parts, _ = _zip_parts(3)
    for index in (1, 3):
        fs.pipe(f"/d/x.zip.{index:03d}", parts[index - 1])
        (tmp_path / f"x.zip.{index:03d}").write_bytes(parts[index - 1])
    with pytest.raises(TruncatedError, match="missing part 2"):
        open_archive(tmp_path / "x.zip.001")
    with pytest.raises(TruncatedError, match="missing part 2"):
        open_archive(OpenFile(fs, "/d/x.zip.001", mode="rb"))
    # A list the caller gives is checked by name too.
    with pytest.raises(TruncatedError, match="missing part 2"):
        open_archive(
            [OpenFile(fs, f"/d/x.zip.{index:03d}", mode="rb") for index in (1, 3)]
        )


class ClientResponseError(Exception):
    """Stands in for ``aiohttp.ClientResponseError``, which fsspec's HTTP file system
    raises for an error status other than 404, so the test needs no ``aiohttp``. It is
    not an ``OSError``; its ``status`` is an ``int``, as aiohttp's is."""

    def __init__(self, status: int) -> None:
        super().__init__(f"{status}, message='refused'")
        self.status = status


class BrokenFS(CountingMemoryFS):
    """``ls`` fails, and ``cat_file`` fails for the paths in ``unreadable``, with
    ``error`` (a refused HTTP request when not given)."""

    def __init__(
        self,
        error: BaseException | None = None,
        *,
        listable: bool = False,
        unreadable: tuple[str, ...] = (),
    ) -> None:
        super().__init__()
        self.error = error or ClientResponseError(403)
        self.listable = listable
        self.unreadable = unreadable

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> Any:
        if not self.listable:
            raise self.error
        return super().ls(path, detail=detail, **kwargs)

    def cat_file(self, path: str, *args: Any, **kwargs: Any) -> Any:
        if self._strip_protocol(path) in self.unreadable:
            raise self.error
        return super().cat_file(path, *args, **kwargs)


def _single_rar() -> bytes:
    return (FIXTURES / "basic_nonsolid__.rar").read_bytes()


def test_a_listing_refused_over_http_opens_the_named_file_alone(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An HTTP 403 for the listing is not an ``OSError``, but it is a refusal: the file
    the caller named opens as with ``discover_volumes=False``."""
    fs = BrokenFS()
    fs.pipe("/d/a.rar", _single_rar())
    with open_archive(FIXTURES / "basic_nonsolid__.rar") as local:
        expected = [m.name for m in local.members()]
    with (
        caplog.at_level(logging.DEBUG, logger="archivey.detection"),
        open_archive(OpenFile(fs, "/d/a.rar", mode="rb")) as reader,
    ):
        assert [m.name for m in reader.members()] == expected
    assert "403, message='refused'" in caplog.text


def test_a_signature_peek_that_is_refused_leaves_the_part_out() -> None:
    """``a.r05`` past a gap is taken only when its first bytes read as RAR; a peek
    that is refused reads as "not RAR", and ``a.rar`` opens alone."""
    fs = BrokenFS(listable=True, unreadable=("/d/a.r05",))
    fs.pipe("/d/a.rar", _single_rar())
    fs.pipe("/d/a.r05", RAR_HEAD)
    assert discover_volume_siblings(RemoteVolumePath(fs, "/d/a.rar", {})) is None
    with open_archive(OpenFile(fs, "/d/a.rar", mode="rb")) as reader:
        assert reader.members()


@pytest.mark.parametrize(
    "named",
    ["tinyvol.part1.rar", "tinyvol_rnn.rar"],
)
def test_a_first_part_whose_listing_is_refused_is_refused_as_a_lone_part(
    fs: CountingMemoryFS, named: str
) -> None:
    """The later parts are there but cannot be found: the error is the one for a
    first part with no siblings beside it."""
    broken = BrokenFS()
    broken.pipe(f"/d/{named}", (FIXTURES / named).read_bytes())
    fs.pipe(f"/d/{named}", (FIXTURES / named).read_bytes())

    def failure(source: OpenFile) -> tuple[type[BaseException], str]:
        with pytest.raises(Exception) as caught, open_archive(source) as reader:
            for member in reader.members():
                if member.is_file:
                    reader.read(member)
        return type(caught.value), str(caught.value)

    alone = failure(OpenFile(fs, f"/d/{named}", mode="rb"))
    assert issubclass(alone[0], TruncatedError)
    assert failure(OpenFile(broken, f"/d/{named}", mode="rb")) == alone


def test_a_numbered_first_part_whose_listing_is_refused_is_refused_alone() -> None:
    fs = BrokenFS()
    parts, _ = _zip_parts(3)
    for index, part in enumerate(parts, 1):
        fs.pipe(f"/d/x.zip.{index:03d}", part)
    with pytest.raises(TruncatedError, match="found part 1 only"):
        open_archive(OpenFile(fs, "/d/x.zip.001", mode="rb"))


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("expired credentials"),
        AttributeError("'NoneType' object has no attribute 'session'"),
        ClientResponseError(503),
        MemoryError(),
        SourceChangedError("changed"),
        _UsageValueError("bad call"),
    ],
    ids=[
        "RuntimeError",
        "AttributeError",
        "HTTP503",
        "MemoryError",
        "SourceChangedError",
        "ArchiveyUsageError",
    ],
)
@pytest.mark.parametrize("step", ["ls", "cat_file"])
def test_a_discovery_failure_that_is_not_a_refusal_propagates(
    error: BaseException, step: str
) -> None:
    """Only a refusal (``OSError``, no ``ls``, an HTTP 4xx) means "no siblings". An
    unknown error, a server error or out of memory propagates (DR-15a), so a complete
    set is not reported as one with parts missing."""
    if step == "ls":
        fs = BrokenFS(error)
    else:
        fs = BrokenFS(error, listable=True, unreadable=("/d/a.r05",))
        fs.pipe("/d/a.r05", RAR_HEAD)
    fs.pipe("/d/a.rar", _single_rar())
    with pytest.raises(type(error)):
        discover_volume_siblings(RemoteVolumePath(fs, "/d/a.rar", {}))
