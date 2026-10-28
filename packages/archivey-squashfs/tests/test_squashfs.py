"""archivey-squashfs against images written by mksquashfs (``data/make-images.sh``)."""

from __future__ import annotations

import ast
import importlib.util
import io
import random
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest
from archivey_squashfs import SQUASHFS, SquashfsPlugin, lzo
from archivey_squashfs.reader import SquashfsReader

import archivey
from archivey import (
    ArchiveyConfig,
    CorruptionError,
    FormatPolicy,
    MemberType,
    OptionalLibrary,
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.plugins import register_format

DATA = Path(__file__).parent / "data"
PACKAGE = Path(__file__).parents[1] / "src" / "archivey_squashfs"

# The tree make-images.sh writes, as ``archivey`` lists it.
CONTENT = {
    "a.txt": b"hello\n",
    "dir/blocks.bin": random.Random(1).randbytes(10000),
    "dir/sub/text.txt": "".join(f"line {i}\n" for i in range(2500)).encode(),
    "sparse.bin": b"x" * 4096 + bytes(8192) + b"y" * 4096,
}
TYPES = {
    "a.txt": MemberType.FILE,
    "blk": MemberType.OTHER,
    "chr": MemberType.OTHER,
    "dir/": MemberType.DIRECTORY,
    "dir/blocks.bin": MemberType.FILE,
    "dir/hard.txt": MemberType.HARDLINK,
    "dir/link": MemberType.SYMLINK,
    "dir/sub/": MemberType.DIRECTORY,
    "dir/sub/text.txt": MemberType.FILE,
    "empty/": MemberType.DIRECTORY,
    "fifo": MemberType.OTHER,
    "sparse.bin": MemberType.FILE,
}

_LZ4 = importlib.util.find_spec("lz4") is not None
_PYTHON_LZO = pytest.mark.skipif(
    importlib.util.find_spec("lzo") is None, reason="needs python-lzo"
)
_ZSTD = archivey.format_availability(archivey.ArchiveFormat.ZST).support is not (
    archivey.FormatSupport.NONE
)
IMAGES = [
    "gzip",
    "xz",
    "xz-bcj",
    "lzma",
    pytest.param("lz4", marks=pytest.mark.skipif(not _LZ4, reason="needs lz4")),
    pytest.param("zstd", marks=pytest.mark.skipif(not _ZSTD, reason="needs zstd")),
    "lzo",
    "lzo1x-1",
    "uncompressed",
    "no-fragments",
    "tail-ends",
]


@pytest.fixture(scope="session", autouse=True)
def _registered() -> None:
    register_format(SquashfsPlugin)


def _image(tmp_path: Path, data: bytes, name: str = "t.sqfs") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("image", IMAGES)
def test_lists_and_reads_every_member(image: str) -> None:
    with open_archive(DATA / f"{image}.sqfs") as archive:
        members = {m.name: m for m in archive.members()}
        assert {name: m.type for name, m in members.items()} == TYPES
        for name, data in CONTENT.items():
            assert members[name].size == len(data)
            assert archive.read(name) == data
        assert members["dir/link"].link_target == "../a.txt"
        assert members["dir/hard.txt"].link_target == "a.txt"
        assert archive.read("dir/hard.txt") == CONTENT["a.txt"]
        assert members["chr"].extra["special_file_type"] == "char_device"
        assert members["blk"].extra["special_file_type"] == "block_device"
        assert members["fifo"].extra["special_file_type"] == "fifo"
        assert members["blk"].mode == 0o600
        assert members["a.txt"].mode == 0o644
        assert members["a.txt"].uid == members["a.txt"].gid == 0
        assert archive.info.format == SQUASHFS
        assert archive.info.format_version == "4.0"
        assert archive.info.extra["squashfs.block_size"] == 4096


@pytest.fixture(params=["python", pytest.param("python-lzo", marks=_PYTHON_LZO)])
def lzo_decoder(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Each LZO decoder in turn: the package's own, and liblzo through python-lzo."""
    if request.param == "python":
        monkeypatch.setattr(lzo, "_python_lzo", lambda: None)
    return request.param


@pytest.mark.parametrize("image", ["lzo", "lzo1x-1"])
def test_lzo_images_with_each_decoder(lzo_decoder: str, image: str) -> None:
    with open_archive(DATA / f"{image}.sqfs") as archive:
        for name, data in CONTENT.items():
            assert archive.read(name) == data


def test_a_damaged_lzo_block(tmp_path: Path, lzo_decoder: str) -> None:
    data = bytearray((DATA / "lzo.sqfs").read_bytes())
    # The inode table's one metadata block, which LZO compresses: a changed first
    # byte changes its first instruction.
    table = _superblock_field(data, _INODE_TABLE, "<Q")
    assert not _superblock_field(data, table, "<H") & 0x8000
    data[table + 2] ^= 0xFF
    with pytest.raises(CorruptionError, match="LZO block"):
        open_archive(_image(tmp_path, bytes(data))).members()


def test_detected_by_magic_and_by_name(tmp_path: Path) -> None:
    info = detect_format(DATA / "gzip.sqfs")
    assert info.format == SQUASHFS
    assert info.from_plugin
    renamed = _image(tmp_path, (DATA / "gzip.sqfs").read_bytes(), "image.bin")
    assert detect_format(renamed).format == SQUASHFS


def test_seeks_within_a_file() -> None:
    data = CONTENT["dir/blocks.bin"]
    with (
        open_archive(DATA / "tail-ends.sqfs", seekable_members=True) as archive,
        archive.open("dir/blocks.bin") as stream,
    ):
        stream.seek(9000)  # in the tail, which sits in a fragment
        assert stream.read(500) == data[9000:9500]
        stream.seek(100)  # back into the first block
        assert stream.read(5000) == data[100:5100]
        assert stream.seek(0, io.SEEK_END) == len(data)


def test_extracts_files_links_and_directories(tmp_path: Path) -> None:
    with open_archive(DATA / "gzip.sqfs") as archive:
        archive.extract_all(tmp_path)
    for name, data in CONTENT.items():
        assert (tmp_path / name).read_bytes() == data
    assert (tmp_path / "dir" / "link").readlink() == Path("../a.txt")
    assert (tmp_path / "dir" / "hard.txt").stat().st_ino == (
        tmp_path / "a.txt"
    ).stat().st_ino
    assert (tmp_path / "empty").is_dir()
    assert not (tmp_path / "fifo").exists()


def test_streams_members_in_one_pass() -> None:
    with open_archive(DATA / "xz.sqfs", streaming=True) as archive:
        read = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert read == CONTENT


# ── Damaged images ─────────────────────────────────────────────────────────────────
#
# The uncompressed image keeps its tables as plain bytes, so a test can find a field
# and change it. Its inode and directory tables each fit in one metadata block.


def _uncompressed() -> bytearray:
    return bytearray((DATA / "uncompressed.sqfs").read_bytes())


def _superblock_field(data: bytes, offset: int, fmt: str) -> int:
    return struct.unpack_from(fmt, data, offset)[0]


_INODE_TABLE, _DIRECTORY_TABLE = 64, 72


def _entry_offset(data: bytes, name: bytes) -> int:
    """Where the directory entry for ``name`` starts in the image."""
    table = _superblock_field(data, _DIRECTORY_TABLE, "<Q")
    # The entry is 8 bytes and then the name, whose stored size is its length - 1.
    return data.index(struct.pack("<H", len(name) - 1) + name, table) - 6


def _inode_offset(data: bytes, name: bytes) -> int:
    """Where the inode the entry for ``name`` points at starts in the image."""
    entry = _entry_offset(data, name)
    (offset,) = struct.unpack_from("<H", data, entry)
    table = _superblock_field(data, _INODE_TABLE, "<Q")
    return table + 2 + offset  # one block: its 2-byte header, then the inodes


def test_a_truncated_image(tmp_path: Path) -> None:
    data = (DATA / "gzip.sqfs").read_bytes()
    with pytest.raises(TruncatedError):
        open_archive(_image(tmp_path, data[: len(data) // 2]))


@pytest.mark.parametrize(
    ("offset", "value", "error", "match"),
    [
        (12, struct.pack("<I", 3000), CorruptionError, "block size"),
        (28, struct.pack("<H", 3), UnsupportedFeatureError, "version 3.0"),
        (0, b"sqsh", UnsupportedFeatureError, "big-endian"),
        (20, struct.pack("<H", 9), CorruptionError, "compressor id 9"),
    ],
)
def test_a_bad_superblock(
    tmp_path: Path, offset: int, value: bytes, error: type[Exception], match: str
) -> None:
    data = _uncompressed()
    data[offset : offset + len(value)] = value
    with pytest.raises(error, match=match):
        open_archive(_image(tmp_path, bytes(data)))


def test_a_directory_listed_inside_itself(tmp_path: Path) -> None:
    """A walk that followed the entry would never end."""
    data = _uncompressed()
    sub = _entry_offset(data, b"sub")
    data[sub : sub + 2] = data[_entry_offset(data, b"dir") :][:2]
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="listed twice"),
    ):
        archive.members()


def test_a_name_with_a_slash(tmp_path: Path) -> None:
    data = _uncompressed()
    entry = _entry_offset(data, b"a.txt")
    data[entry + 8 : entry + 13] = b"a/txt"
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="named"),
    ):
        archive.members()


def test_an_entry_whose_inode_has_another_type(tmp_path: Path) -> None:
    data = _uncompressed()
    entry = _entry_offset(data, b"a.txt")
    data[entry + 4 : entry + 6] = struct.pack("<H", 1)  # says directory
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="listed as type 1"),
    ):
        archive.members()


def test_a_fragment_past_the_table(tmp_path: Path) -> None:
    data = _uncompressed()
    # a.txt has a second name, so its inode is an extended one: the fragment index
    # follows the 16-byte header, the 8-byte start, size and sparse count, and the
    # 4-byte link count.
    inode = _inode_offset(data, b"a.txt")
    assert struct.unpack_from("<HI", data, inode + 0)[0] == 9
    assert struct.unpack_from("<I", data, inode + 44) == (0,)
    data[inode + 44 : inode + 48] = struct.pack("<I", 1000)
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="fragment 1000"),
    ):
        archive.read("a.txt")


def test_a_truncation_names_the_structure_it_cuts(tmp_path: Path) -> None:
    """An id table index placed at the image's last bytes runs past its end."""
    data = _uncompressed()
    used = _superblock_field(data, 40, "<Q")
    data[48:56] = struct.pack("<Q", used - 4)  # the id table index, 8 bytes per block
    with pytest.raises(
        TruncatedError,
        match=f"the id table index at {used - 4} runs past the image end",
    ):
        open_archive(_image(tmp_path, bytes(data))).members()


def test_a_data_block_shorter_than_the_file_needs(tmp_path: Path) -> None:
    data = _uncompressed()
    inode = _inode_offset(data, b"blocks.bin")
    # The first entry of the block-size list, after the 32-byte file inode.
    (stored,) = struct.unpack_from("<I", data, inode + 32)
    assert stored == 4096 | 1 << 24
    data[inode + 32 : inode + 36] = struct.pack("<I", 4000 | 1 << 24)
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="holds 4000 bytes, not 4096"),
    ):
        archive.read("dir/blocks.bin")


def test_a_data_block_longer_than_the_block_size(tmp_path: Path) -> None:
    """A stored length is refused before any read: a crafted 16 MiB entry costs nothing."""
    data = _uncompressed()
    inode = _inode_offset(data, b"blocks.bin")
    data[inode + 32 : inode + 36] = struct.pack("<I", 0xFFFFFF)  # compressed, 16 MiB
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match=f"declares {0xFFFFFF} bytes"),
    ):
        archive.read("dir/blocks.bin")


def test_a_metadata_block_longer_than_the_format_allows(tmp_path: Path) -> None:
    data = _uncompressed()
    table = _superblock_field(data, _INODE_TABLE, "<Q")
    data[table : table + 2] = struct.pack("<H", 0x8000 | 8193)
    with pytest.raises(CorruptionError, match="declares 8193 bytes"):
        open_archive(_image(tmp_path, bytes(data))).members()


def test_a_symlink_target_longer_than_the_kernel_allows(tmp_path: Path) -> None:
    data = _uncompressed()
    inode = _inode_offset(data, b"link")
    data[inode + 20 : inode + 24] = struct.pack("<I", 70000)
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="70000"),
    ):
        archive.members()


# ── The package ────────────────────────────────────────────────────────────────────


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
    assert archivey_modules == {"archivey", "archivey.plugins"}


def test_the_reader_is_an_indexed_reader() -> None:
    assert issubclass(SquashfsReader, archivey.plugins.IndexedReader)


@pytest.mark.skipif(not _LZ4, reason="needs lz4")
def test_lz4_turned_off_by_the_policy_reads_as_not_installed() -> None:
    config = ArchiveyConfig(
        formats=FormatPolicy(exclude_libraries={OptionalLibrary.LZ4})
    )
    with (
        pytest.raises(PackageNotInstalledError, match="exclude_libraries") as e,
        open_archive(DATA / "lz4.sqfs", config=config) as archive,
    ):
        archive.read("a.txt")
    (component,) = e.value.missing
    assert component.name is OptionalLibrary.LZ4
    assert "exclude_libraries" in component.reason
