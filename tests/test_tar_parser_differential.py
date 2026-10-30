"""The native TAR walker against stdlib ``tarfile``, field by field and byte by byte.

``tarfile`` is the oracle here, as ``py7zr`` and ``rarfile`` are for 7z and RAR: on a
well-formed archive both must list the same members with the same data. The archives
come from the test corpus (written by ``tarfile``) and from GNU tar, which writes the
shapes ``tarfile`` does not (old GNU sparse with real holes, the three PAX sparse
versions, ``oldgnu``). GNU tar is the format's official tool, so those cases skip where
it is not installed.

Known differences, where the native walker follows GNU tar on purpose, are covered in
``test_tar_parser.py`` with crafted archives, not here.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from archivey.formats import ForwardStream
from archivey.internal.backends.tar_parser import (
    TarEndKind,
    TarEntry,
    TarWalker,
    validate_sparse_map,
)
from tests.sample_archives import CORPUS, corpus_archive_path
from tests.tar_build import forward

_REGULAR = frozenset((b"0", b"\x00", b"7", b"S"))  # what tarfile.isreg() accepts


def _member_data(stream: ForwardStream, entry: TarEntry) -> bytes:
    """The member's logical bytes, holes as zeros, read where the walk left them."""
    assert stream.offset == entry.data_offset
    sparse = entry.sparse
    stored = entry.stored_size
    if sparse is None:
        return stream.read(stored)
    assert validate_sparse_map(sparse, entry.size, stored, "m") is None
    out = bytearray(entry.size)
    for offset, length in zip(sparse.offsets, sparse.lengths, strict=True):
        out[offset : offset + length] = stream.read(length)
    return bytes(out)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape")


def _native_listing(path: Path) -> list[tuple[object, ...]]:
    rows = []
    with path.open("rb") as file:
        stream = forward(file)
        walker = TarWalker(stream)
        while isinstance(entry := walker.next_entry(), TarEntry):
            typeflag = entry.typeflag
            name = _text(entry.name)
            if typeflag == b"5" or entry.old_style_directory:
                typeflag, name = b"5", name.rstrip("/")
            uname = entry.uname_pax.value if entry.uname_pax else entry.uname
            gname = entry.gname_pax.value if entry.gname_pax else entry.gname
            data = _member_data(stream, entry) if typeflag in _REGULAR else None
            link = _text(entry.linkname) if entry.linkname is not None else None
            rows.append(
                (name, typeflag, entry.size, link, entry.uid, entry.gid)
                + (_text(uname), _text(gname), entry.header.mode & 0o7777)
                + (entry.sparse_format is not None, data)
            )
        assert walker.end is not None and walker.end.kind is TarEndKind.ZERO_BLOCK
    return rows


def _tarfile_listing(path: Path) -> list[tuple[object, ...]]:
    rows = []
    with tarfile.open(path, encoding="utf-8", errors="surrogateescape") as tar:
        for info in tar:
            data = None
            if info.isreg():
                extracted = tar.extractfile(info)
                assert extracted is not None
                data = extracted.read()
            link = info.linkname if info.issym() or info.islnk() else None
            rows.append(
                (info.name, info.type, info.size, link, info.uid, info.gid)
                + (info.uname, info.gname, info.mode & 0o7777)
                + (info.issparse(), data)
            )
    return rows


def _forward_only_matches(path: Path) -> None:
    """A walk that skips by reading gives the same members, at the same offsets, as
    one that seeks, and its stream holds their stored bytes there."""
    data = path.read_bytes()
    seekable = TarWalker(forward(io.BytesIO(data)))
    stream = forward(io.BytesIO(data), seekable=False)
    reading = TarWalker(stream)
    while isinstance(a := seekable.next_entry(), TarEntry):
        b = reading.next_entry()
        assert isinstance(b, TarEntry)
        assert (a.name, a.data_offset, a.stored_size) == (
            b.name,
            b.data_offset,
            b.stored_size,
        )
        assert (
            stream.read(b.stored_size)
            == data[a.data_offset : a.data_offset + a.stored_size]
        )
    assert reading.next_entry() == seekable.end


_TAR_ENTRIES = [entry for entry in CORPUS if "tar" in entry.formats]


@pytest.mark.parametrize("entry", _TAR_ENTRIES, ids=lambda e: e.id)
def test_corpus_listing_matches_tarfile(entry, tmp_path: Path) -> None:
    path = corpus_archive_path(entry, "tar", tmp_path)
    assert _native_listing(path) == _tarfile_listing(path)
    _forward_only_matches(path)


def _tarfile_archive(path: Path, fmt: int) -> Path:
    def add(
        tar: tarfile.TarFile, name: str, data: bytes = b"", **attrs: object
    ) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        for key, value in attrs.items():
            setattr(info, key, value)
        tar.addfile(info, io.BytesIO(data) if data else None)

    with tarfile.open(path, "w", format=fmt, encoding="utf-8") as tar:
        add(tar, "plain.txt", b"hello\n", uname="user", gname="group", uid=1000)
        add(tar, "dir/", type=tarfile.DIRTYPE, mode=0o755)
        add(tar, "dir/" + "n" * 90 + "/" + "m" * 60, b"deep")
        add(tar, "link", type=tarfile.SYMTYPE, linkname="plain.txt")
        add(tar, "hard", type=tarfile.LNKTYPE, linkname="plain.txt")
        add(tar, "big", os.urandom(70_000))
        add(tar, "empty")
        add(tar, "fifo", type=tarfile.FIFOTYPE)
        add(tar, "dev", type=tarfile.CHRTYPE, devmajor=1, devminor=3)
        if fmt != tarfile.USTAR_FORMAT:
            add(tar, "long/" + "x" * 200, b"long name")
            add(tar, "longlink", type=tarfile.SYMTYPE, linkname="t" * 150)
            add(tar, "café-日本.txt", b"utf8", uid=2**22)
    return path


@pytest.mark.parametrize(
    "fmt",
    [tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT],
    ids=["ustar", "gnu", "pax"],
)
def test_tarfile_formats_match(fmt: int, tmp_path: Path) -> None:
    path = _tarfile_archive(tmp_path / "t.tar", fmt)
    assert _native_listing(path) == _tarfile_listing(path)
    _forward_only_matches(path)


def _gnu_tar() -> str | None:
    tar = shutil.which("tar")
    if tar is None:
        return None
    try:
        version = subprocess.run(
            [tar, "--version"], capture_output=True, check=True, text=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return tar if "GNU tar" in version else None


_GNU_TAR = _gnu_tar()
needs_gnu_tar = pytest.mark.skipif(_GNU_TAR is None, reason="needs GNU tar")


def _sparse_tree(root: Path) -> Path:
    root.mkdir()
    (root / "a.txt").write_bytes(b"hello\n")
    with (root / "holes").open("wb") as f:  # data, a hole, data, ends in data
        f.seek(100_000)
        f.write(b"x" * 700)
        f.seek(300_000)
        f.write(b"y" * 5)
    with (root / "trailing-hole").open("wb") as f:  # starts with data, ends in a hole
        f.write(b"start")
        f.seek(70_000)
        f.write(b"z" * 3)
        f.truncate(90_000)
    with (root / "many-chunks").open("wb") as f:  # more chunks than the header holds
        for i in range(40):
            f.seek(i * 8192)
            f.write(b"c" * 10)
        f.truncate(41 * 8192)
    deep = root / ("d" * 120) / ("e" * 110)
    deep.parent.mkdir()
    deep.write_bytes(b"deep\n")
    (root / "sym").symlink_to("a.txt")
    os.link(root / "a.txt", root / "hard")
    return root


@needs_gnu_tar
@pytest.mark.parametrize(
    "options",
    [
        ["--format=gnu"],
        ["--format=oldgnu"],
        ["--format=posix"],
        ["--format=pax", "--sparse-version=0.0"],
        ["--format=pax", "--sparse-version=0.1"],
        ["--format=pax", "--sparse-version=1.0"],
    ],
    ids=[
        "gnu",
        "oldgnu",
        "posix",
        "pax-sparse-0.0",
        "pax-sparse-0.1",
        "pax-sparse-1.0",
    ],
)
def test_gnu_tar_archives_match(options: list[str], tmp_path: Path) -> None:
    assert _GNU_TAR is not None
    tree = _sparse_tree(tmp_path / "tree")
    path = tmp_path / "t.tar"
    subprocess.run(
        [_GNU_TAR, *options, "--sparse", "-cf", str(path), "-C", str(tree), "."],
        check=True,
        capture_output=True,
    )
    native = _native_listing(path)
    assert native == _tarfile_listing(path)
    assert sum(1 for row in native if row[-2]) == 3  # the three sparse files
    _forward_only_matches(path)


@needs_gnu_tar
def test_gnu_incremental_names_have_no_prefix(tmp_path: Path) -> None:
    """GNU tar's incremental mode fills the old GNU atime slot, which sits where a
    ustar header has its ``prefix``. tarfile joins those digits to every name; the
    native parser reads ``prefix`` only under the ustar magic, as GNU tar does. This
    is the one listing difference from tarfile on a GNU tar archive."""
    assert _GNU_TAR is not None
    tree = tmp_path / "tree"
    (tree / "d" / "sub").mkdir(parents=True)
    (tree / "d" / "f.txt").write_bytes(b"hi\n")
    path = tmp_path / "inc.tar"
    subprocess.run(
        [_GNU_TAR, "--format=gnu", "--incremental", "-cf", str(path)]
        + ["-C", str(tree), "d"],
        check=True,
        capture_output=True,
    )
    native = _native_listing(path)
    oracle = _tarfile_listing(path)
    assert [row[0] for row in native] == ["d/", "d/sub/", "d/f.txt"]
    # tarfile gives the same names under the atime digits: "15262452373/d/".
    assert all(row[0].split("/", 1)[0].isdigit() for row in oracle)
    assert [row[1:] for row in native] == [row[1:] for row in oracle]
    _forward_only_matches(path)
