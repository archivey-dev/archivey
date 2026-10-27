"""archivey-cpio against archives written by GNU cpio and bsdcpio
(``data/make-archives.sh``), read from a file and from a pipe."""

from __future__ import annotations

import ast
import io
import os
import random
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from archivey_cpio import CPIO, CpioPlugin, CpioReader

import archivey
from archivey import (
    CorruptionError,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    detect_format,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.plugins import SequentialReader, register_format

DATA = Path(__file__).parent / "data"
PACKAGE = Path(__file__).parents[1] / "src" / "archivey_cpio"

# The tree make-archives.sh writes, as archivey lists it.
CONTENT = {
    "a.txt": b"hello\n",
    "dir/blocks.bin": random.Random(1).randbytes(10000),
    "dir/sub/text.txt": "".join(f"line {i}\n" for i in range(2500)).encode(),
    "dir/zero-hard.txt": b"",
    "zero.txt": b"",
    "dir/hard.txt": b"hello\n",
}
TYPES = {
    "blk": MemberType.OTHER,
    "chr": MemberType.OTHER,
    "dir/": MemberType.DIRECTORY,
    "dir/blocks.bin": MemberType.FILE,
    "dir/link": MemberType.SYMLINK,
    "dir/sub/": MemberType.DIRECTORY,
    "dir/sub/text.txt": MemberType.FILE,
    "empty/": MemberType.DIRECTORY,
    "fifo": MemberType.OTHER,
}
# Which name of each hard-linked pair carries the data: the first in binary and odc,
# the last in newc and crc.
LINKED = {
    "bin": ("a.txt", "dir/zero-hard.txt"),
    "odc": ("a.txt", "dir/zero-hard.txt"),
    "newc": ("dir/hard.txt", "dir/zero-hard.txt"),
    "crc": ("dir/hard.txt", "dir/zero-hard.txt"),
}
ARCHIVES = {
    "gnu-bin": "bin",
    "gnu-odc": "odc",
    "gnu-newc": "newc",
    "gnu-crc": "crc",
    "bsd-odc": "odc",
    "bsd-newc": "newc",
}


@pytest.fixture(scope="session", autouse=True)
def _registered() -> None:
    register_format(CpioPlugin)


class _Pipe(io.RawIOBase):
    """A source that cannot seek, as a pipe."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        return self._inner.readinto(b)


def _archive(tmp_path: Path, data: bytes, name: str = "t.cpio") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _check_listing(members: list[archivey.ArchiveMember], variant: str) -> None:
    by_name = {m.name: m for m in members}
    assert len(by_name) == len(members) == 13
    for name, kind in TYPES.items():
        assert by_name[name].type is kind, name
    assert by_name["dir/link"].link_target == "../a.txt"
    assert by_name["blk"].extra["special_file_type"] == "block_device"
    assert by_name["fifo"].extra["special_file_type"] == "fifo"
    for first in LINKED[variant]:
        assert by_name[first].type is MemberType.FILE
    # Each hard link names the member with the data, listed before it.
    names = [m.name for m in members]
    for member in members:
        if member.type is MemberType.HARDLINK:
            assert member.link_target in LINKED[variant]
            assert names.index(member.link_target) < names.index(member.name)
    assert by_name["dir/sub/text.txt"].mode == 0o644
    assert by_name["dir/sub/text.txt"].uid == 0
    assert by_name["dir/sub/text.txt"].modified is not None
    assert by_name["dir/sub/text.txt"].modified.timestamp() == 0


@pytest.mark.parametrize("name", ARCHIVES)
def test_list_and_read(name: str) -> None:
    variant = ARCHIVES[name]
    with open_archive(DATA / f"{name}.cpio") as reader:
        assert reader.format == CPIO
        assert reader.info.format_version == variant
        members = reader.members()
        _check_listing(members, variant)
        for member_name, data in CONTENT.items():
            # A hard link reads its target's data.
            assert reader.read(member_name) == data, member_name
        if variant == "crc":
            with reader.open("dir/blocks.bin") as stream:
                stream.read()
                assert stream.verified is archivey.Verification.CONTENT


@pytest.mark.parametrize("name", ARCHIVES)
def test_stream_from_a_pipe(name: str) -> None:
    variant = ARCHIVES[name]
    data = (DATA / f"{name}.cpio").read_bytes()
    seen: dict[str, bytes] = {}
    members = []
    # A binary archive has no magic: on a nameless stream, detection runs no probe.
    fmt = CPIO if variant == "bin" else None
    with open_archive(_Pipe(data), streaming=True, format=fmt) as reader:
        assert reader.format == CPIO
        for member, stream in reader.stream_members():
            members.append(member)
            if stream is not None:
                seen[member.name] = stream.read()
    _check_listing(members, variant)
    # Only the files with the data have streams; their links read through them.
    first, empty = LINKED[variant]
    assert seen == {
        "dir/blocks.bin": CONTENT["dir/blocks.bin"],
        "dir/sub/text.txt": CONTENT["dir/sub/text.txt"],
        first: b"hello\n",
        empty: b"",
    }


@pytest.mark.parametrize("name", ["gnu-odc", "gnu-newc"])
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_extract(tmp_path: Path, name: str, pipe: bool) -> None:
    data = (DATA / f"{name}.cpio").read_bytes()
    dest = tmp_path / "out"
    source = _Pipe(data) if pipe else DATA / f"{name}.cpio"
    with open_archive(source, streaming=pipe) as reader:
        reader.extract_all(dest)
    for member_name, content in CONTENT.items():
        assert (dest / member_name).read_bytes() == content
    assert os.readlink(dest / "dir" / "link") == "../a.txt"
    assert (dest / "a.txt").stat().st_ino == (dest / "dir" / "hard.txt").stat().st_ino
    assert (dest / "empty").is_dir()


def test_an_os_pipe(tmp_path: Path) -> None:
    data = (DATA / "gnu-newc.cpio").read_bytes()
    read_fd, write_fd = os.pipe()

    def write() -> None:
        with open(write_fd, "wb") as out:
            out.write(data)

    writer = threading.Thread(target=write)
    writer.start()
    try:
        with (
            open(read_fd, "rb", buffering=0) as pipe,
            open_archive(pipe, streaming=True) as reader,
        ):
            names = [m.name for m, _ in reader.stream_members()]
    finally:
        writer.join()
    assert "dir/sub/text.txt" in names


def test_detection() -> None:
    for name, variant in ARCHIVES.items():
        if variant == "bin":
            continue
        info = detect_format(io.BytesIO((DATA / f"{name}.cpio").read_bytes()))
        assert info.format == CPIO, name
        assert info.detected_by == "magic"
        assert info.from_plugin
    # The binary variant has no ASCII magic: the probe finds it where probes run.
    probing = archivey.ArchiveyConfig(always_probe_content=True)
    data = (DATA / "gnu-bin.cpio").read_bytes()
    assert detect_format(io.BytesIO(data), config=probing).format == CPIO
    assert detect_format(DATA / "gnu-bin.cpio").format == CPIO
    not_cpio = io.BytesIO(b"\xc7\x71" + bytes(40))
    with pytest.raises(archivey.FormatDetectionError):
        detect_format(not_cpio, config=probing)


def _offset_of(data: bytes, content: bytes) -> int:
    at = data.find(content)
    assert at > 0
    return at


def test_a_crc_mismatch_raises(tmp_path: Path) -> None:
    data = bytearray((DATA / "gnu-crc.cpio").read_bytes())
    at = _offset_of(bytes(data), CONTENT["dir/blocks.bin"][:64])
    data[at + 100] ^= 0xFF
    path = _archive(tmp_path, bytes(data))
    with open_archive(path) as reader:
        assert reader.read("dir/sub/text.txt") == CONTENT["dir/sub/text.txt"]
        with pytest.raises(CorruptionError, match="cpio-crc"):
            reader.read("dir/blocks.bin")


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_cut_archive_keeps_the_members_before_the_cut(
    tmp_path: Path, pipe: bool
) -> None:
    data = (DATA / "gnu-newc.cpio").read_bytes()
    cut = data[: _offset_of(data, CONTENT["dir/sub/text.txt"][:64]) + 1000]
    source = _Pipe(cut) if pipe else _archive(tmp_path, cut)
    names = []
    with (
        open_archive(source, streaming=pipe) as reader,
        pytest.raises(TruncatedError),
    ):
        for member, stream in reader.stream_members():
            names.append(member.name)
            if stream is not None:
                stream.read()
    assert names[-1] == "dir/sub/text.txt"
    assert "dir/blocks.bin" in names


def _without_trailer(data: bytes) -> bytes:
    return data[: data.index(b"TRAILER!!!") - 110]


def test_a_missing_trailer_is_truncation(tmp_path: Path) -> None:
    data = (DATA / "gnu-newc.cpio").read_bytes()
    path = _archive(tmp_path, _without_trailer(data))
    with open_archive(path) as reader, pytest.raises(TruncatedError, match="trailer"):
        reader.members()


def test_data_after_the_trailer_is_reported(tmp_path: Path) -> None:
    data = (DATA / "gnu-newc.cpio").read_bytes()
    with open_archive(_archive(tmp_path, data + b"junk")) as reader:
        reader.members()
        counts = reader.diagnostics.counts
    assert counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1
    with open_archive(_archive(tmp_path, data + bytes(4096), "z.cpio")) as reader:
        reader.members()
        assert DiagnosticCode.ARCHIVE_TRAILING_DATA not in reader.diagnostics.counts


def test_not_a_cpio_archive(tmp_path: Path) -> None:
    with pytest.raises(CorruptionError, match="No CPIO header"):
        open_archive(_archive(tmp_path, b"070799" + bytes(200)), format="cpio")
    with pytest.raises(TruncatedError, match="empty"):
        open_archive(_archive(tmp_path, b""), format="cpio")
    bad = bytearray((DATA / "gnu-newc.cpio").read_bytes())
    bad[6:14] = b"xxxxxxxx"
    with pytest.raises(CorruptionError, match="not a number"):
        open_archive(_archive(tmp_path, bytes(bad)), format="cpio")


def test_too_many_held_links(tmp_path: Path) -> None:
    config = archivey.ArchiveyConfig(
        listing_limits=archivey.ListingLimits(max_members=1)
    )
    with (
        open_archive(DATA / "gnu-newc.cpio", config=config) as reader,
        pytest.raises(ResourceLimitError),
    ):
        reader.members()


def _imports(path: Path) -> Iterator[str]:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def test_the_package_uses_only_public_archivey() -> None:
    """The point of the package: a format added from outside, through the plugin API."""
    used = {name for path in PACKAGE.rglob("*.py") for name in _imports(path)}
    archivey_modules = {name for name in used if name.split(".")[0] == "archivey"}
    assert archivey_modules == {"archivey", "archivey.diagnostics", "archivey.plugins"}


def test_the_reader_is_a_sequential_reader() -> None:
    assert issubclass(CpioReader, SequentialReader)
