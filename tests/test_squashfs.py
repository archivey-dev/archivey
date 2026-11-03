"""The SquashFS reader against images written by mksquashfs
(``fixtures/squashfs/make-images.sh``)."""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import io
import random
import struct
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveMember,
    ArchiveyConfig,
    CorruptionError,
    FormatPolicy,
    MemberType,
    OptionalLibrary,
    PackageNotInstalledError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.internal.backends import squashfs_reader
from archivey.internal.backends.squashfs_reader import SquashfsReader
from archivey.internal.excluded_libraries import EXCLUDED_REASON
from archivey.internal.streams.codecs import deps, lzo_decoder as archivey_lzo

SQUASHFS = archivey.ArchiveFormat.SQUASHFS
DATA = Path(__file__).parent / "fixtures" / "squashfs"

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
        # Two of sparse.bin's four blocks are stored with size 0, under a basic inode.
        assert {n for n, m in members.items() if m.is_sparse} == {"sparse.bin"}
        assert members["a.txt"].uid == members["a.txt"].gid == 0
        assert archive.info.format == SQUASHFS
        assert archive.info.format_version == "4.0"
        assert archive.info.extra["squashfs.block_size"] == 4096


@pytest.fixture(params=["python", pytest.param("python-lzo", marks=_PYTHON_LZO)])
def lzo_decoder(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Each LZO decoder in turn: archivey's in Python, and liblzo through python-lzo."""
    if request.param == "python":
        monkeypatch.setattr(archivey_lzo, "_python_lzo", lambda *_: None)
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
    assert not info.from_plugin
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


# ── Member order and block reuse ────────────────────────────────────────────────────


def _decoded_blocks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The start of every block the readers opened from now on decode, in order."""
    starts: list[int] = []
    block_decoder = SquashfsReader._block_decoder

    def recording(self: SquashfsReader, compressor: str) -> Callable[..., bytes]:
        decode = block_decoder(self, compressor)

        def decode_and_record(start: int, length: int, limit: int) -> bytes:
            starts.append(start)
            return decode(start, length, limit)

        return decode_and_record

    monkeypatch.setattr(SquashfsReader, "_block_decoder", recording)
    return starts


def _read_all(
    path: Path, streaming: bool = False
) -> list[tuple[ArchiveMember, bytes | None]]:
    with open_archive(path, streaming=streaming) as archive:
        return [(m, s.read() if s else None) for m, s in archive.stream_members()]


# tar-order.sqfs: sqfstar fills fragments in the order the tar holds the files,
# f0 f5 | f1 f6 | f2 f7 | f3 f8 | f4 f9 | d/f10, two to a 4 KiB block.
_TAR_ORDER = {
    **{f"f{i}": random.Random(i).randbytes(100) * 15 for i in range(10)},
    "d/f10": random.Random(10).randbytes(100) * 15,
    "big": random.Random(11).randbytes(64) * 64,  # one whole block, no tail
}


@pytest.mark.parametrize("streaming", [False, True])
def test_fragments_filled_out_of_listing_order_are_each_decoded_once(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    """In name order the files cycle through five fragment blocks, one more than the
    reader keeps, so each small file would decode a whole block. The files with a tail
    come in fragment order instead, after the directory and the members with no tail,
    and before the hard link."""
    decoded = _decoded_blocks(monkeypatch)
    read = _read_all(DATA / "tar-order.sqfs", streaming)
    assert [m.name for m, _ in read] == [
        "big", "d/", "link",
        "f0", "f5", "f1", "f6", "f2", "f7", "f3", "f8", "f4", "f9", "d/f10",
        "hard",
    ]  # fmt: skip
    assert {m.name: data for m, data in read if data is not None} == _TAR_ORDER
    assert {m.name: m.link_target for m, _ in read if m.link_target} == {
        "link": "f0",
        "hard": "f3",
    }
    assert sorted(decoded) == sorted(set(decoded))


def test_fragment_entries_naming_one_block_decode_it_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two fragment-table entries may point at the same block. Here entry 5 (d/f10's)
    points at entry 0's: sorted by entry, the block would be read for f0 and f5, then
    four others, then d/f10 again, past what the reader keeps. Sorted by where the
    block is, it decodes once."""
    fragment = SquashfsReader._fragment
    monkeypatch.setattr(
        SquashfsReader, "_fragment", lambda self, i: fragment(self, 0 if i == 5 else i)
    )
    decoded = _decoded_blocks(monkeypatch)
    read = _read_all(DATA / "tar-order.sqfs")
    # d/f10 is at offset 0 of that block too, and listed before f0.
    assert [m.name for m, _ in read][3:6] == ["d/f10", "f0", "f5"]
    assert sorted(decoded) == sorted(set(decoded))


def test_a_duplicate_name_keeps_listing_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The last entry listed under a name is the current one, in every format. Two
    entries named f1 here (f5's renamed): sorting them by fragment would put the one
    listed second first, so an image with a duplicate name keeps listing order."""
    entries = SquashfsReader._entries

    def renamed(self: SquashfsReader, listing: tuple[int, int, int]) -> Iterator:
        for name, *rest in entries(self, listing):
            yield (b"f1" if name == b"f5" else name, *rest)

    monkeypatch.setattr(SquashfsReader, "_entries", renamed)
    with open_archive(DATA / "tar-order.sqfs") as archive:
        archive.extract_all(tmp_path)
    assert (tmp_path / "f1").read_bytes() == _TAR_ORDER["f5"]


def test_fragments_filled_out_of_listing_order_extract(tmp_path: Path) -> None:
    with open_archive(DATA / "tar-order.sqfs") as archive:
        archive.extract_all(tmp_path)
    for name, data in _TAR_ORDER.items():
        assert (tmp_path / name).read_bytes() == data
    assert (tmp_path / "hard").stat().st_ino == (tmp_path / "f3").stat().st_ino
    assert (tmp_path / "link").readlink() == Path("f0")


@pytest.mark.parametrize("image", ["gzip", "tail-ends", "tail-ends-two-streams"])
def test_fragments_filled_in_name_order_keep_listing_order(
    monkeypatch: pytest.MonkeyPatch, image: str
) -> None:
    """mksquashfs fills one fragment at a time in name order, or two with
    ``-tailends`` (small files and tail ends): the kept blocks cover the listing, and
    the members stay in it, depth first and by name."""
    decoded = _decoded_blocks(monkeypatch)
    names = [m.name for m, _ in _read_all(DATA / f"{image}.sqfs")]
    assert names == sorted(names, key=lambda name: name.rstrip("/").split("/"))
    assert sorted(decoded) == sorted(set(decoded))


def test_first_pass_reads_each_inode_once_in_table_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first pass reads the inodes of everything but directories once each, sorted
    by where they are in the inode table, whatever order the entries name them in; the
    second reads each again, by its entry, as it makes the member, except for a hard
    link, which takes what it needs from the member it names. Each listing is read
    backwards here, so the entries name the inodes against table order; dir/hard.txt
    names a.txt's inode a second time."""
    read: list[tuple[int, int]] = []
    inode = SquashfsReader._inode
    entries = SquashfsReader._entries
    monkeypatch.setattr(
        SquashfsReader,
        "_entries",
        lambda self, listing: iter(list(entries(self, listing))[::-1]),
    )

    def recording(self: SquashfsReader, block: int, offset: int) -> object:
        found = inode(self, block, offset)
        if found.type != squashfs_reader._DIR:
            read.append((block, offset))
        return found

    monkeypatch.setattr(SquashfsReader, "_inode", recording)
    with open_archive(DATA / "gzip.sqfs") as archive:
        members = archive.members()
    assert len(members) == len(TYPES)
    unique = sorted(set(read))
    assert read[: len(unique)] == unique
    made = [
        m for m in members if m.type not in (MemberType.DIRECTORY, MemberType.HARDLINK)
    ]
    assert len(read) == len(unique) + len(made)


def _inode_header(kind: int, number: int) -> bytes:
    return struct.pack("<HHHHII", kind, 0o644, 0, 0, 0, number)


def _metadata(data: bytes) -> bytes:
    """An uncompressed metadata block."""
    return struct.pack("<H", len(data) | 0x8000) + data


def _flat_image(inodes: bytes, entries: list[tuple[bytes, int, int, int]]) -> bytes:
    """An uncompressed image of ``entries`` (name, type, inode block, offset in it)
    under the root, given the inode table without the root's inode."""
    listing = b"".join(
        struct.pack("<III", 0, block, number)
        + struct.pack("<HhHH", offset, 0, kind, len(name) - 1)
        + name
        for number, (name, kind, block, offset) in enumerate(entries, 2)
    )
    assert len(listing) <= 8192 - 3
    root_ref = len(inodes)
    root = _inode_header(1, 1) + struct.pack(
        "<IIHHI", 0, 2, len(listing) + 3, 0, len(entries) + 2
    )
    inodes += _metadata(root)
    inode_table = 96
    directory_table = inode_table + len(inodes)
    ids = _metadata(struct.pack("<I", 0))
    id_block = directory_table + len(_metadata(listing))
    id_table = id_block + len(ids)
    body = inodes + _metadata(listing) + ids + struct.pack("<Q", id_block)
    end = 96 + len(body)
    superblock = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        0x73717368, len(entries) + 1, 0, 4096, 0, 1, 12, 0, 1, 4, 0,
        root_ref << 16, end, id_table, 0xFFFFFFFFFFFFFFFF,
        inode_table, directory_table, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    )  # fmt: skip
    return superblock + body


def _empty_file(number: int) -> bytes:
    return _inode_header(2, number) + struct.pack("<IIII", 0, 0xFFFFFFFF, 0, 0)


def _one_inode_per_block(names: list[bytes]) -> bytes:
    """Empty files under the root, each file's inode in a metadata block of its own and
    the table in reverse listing order, so every inode the listing reads in its own
    order misses the metadata cache."""
    inodes, refs = b"", {}
    for number, name in reversed(list(enumerate(names, 2))):
        refs[name] = len(inodes)
        inodes += _metadata(_empty_file(number))
    return _flat_image(inodes, [(name, 2, refs[name], 0) for name in names])


def _counting_decodes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The start of every metadata block the readers opened from now on decode."""
    decoded: list[int] = []
    block = SquashfsReader._metadata_block

    def recording(self: SquashfsReader, pos: int) -> tuple[bytes, int]:
        if pos not in self._metadata:
            decoded.append(pos)
        return block(self, pos)

    monkeypatch.setattr(SquashfsReader, "_metadata_block", recording)
    return decoded


def test_inodes_each_in_a_block_decode_linearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crafted image can put each inode in a metadata block of its own and order the
    table against the listing, so the cache rarely hits on an inode. The first pass
    reads the table in order and the second in listing order, so each inode's block
    decodes at most twice."""
    names = [f"f{i:03}".encode() for i in range(300)]
    path = _image(tmp_path, _one_inode_per_block(names))
    decoded = _counting_decodes(monkeypatch)
    with open_archive(path) as archive:
        assert [m.name for m in archive.members()] == [n.decode() for n in names]
    assert len(decoded) <= 2 * len(names) + 4


def _four_inodes_a_block(block_of: Callable[[int], int]) -> tuple[bytes, list[bytes]]:
    """320 empty files under the root, listed by name, with file i's inode in
    metadata block ``block_of(i)`` of 80, four to a block."""
    contents: list[bytes] = [b""] * 80
    where = []
    for i in range(320):
        block = block_of(i)
        where.append((block, len(contents[block])))
        contents[block] += _empty_file(i + 2)
    starts, inodes = [], b""
    for data in contents:
        starts.append(len(inodes))
        inodes += _metadata(data)
    names = [f"f{i:03}".encode() for i in range(320)]
    entries = [(names[i], 2, starts[b], o) for i, (b, o) in enumerate(where)]
    return _flat_image(inodes, entries), names


def _keeps(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """How many inodes each listing from now on keeps for its second pass."""
    kept: list[int] = []
    keep = SquashfsReader._kept_inodes

    def recording(
        self: SquashfsReader,
        entries: list[squashfs_reader._Entry],
        files: squashfs_reader._FileScan,
    ) -> dict[tuple[int, int], squashfs_reader._Inode]:
        inodes = keep(self, entries, files)
        kept.append(len(inodes))
        return inodes

    monkeypatch.setattr(SquashfsReader, "_kept_inodes", recording)
    return kept


# The order f0, f80, f160, f240, f1, f81, ...: four to a block in table order.
_STRIDED = [b * 4 + k for k in range(4) for b in range(80)]


@pytest.mark.parametrize("stride", ["table", "member order"])
def test_an_order_that_strides_the_inode_table_keeps_the_inodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stride: str
) -> None:
    """320 files whose inodes are four to a metadata block in 80 blocks, more than the
    reader's cache keeps. When the members come in an order that cycles through the 80
    blocks, reading each inode again would decode a block per member, so the listing
    keeps the inodes and each block decodes at most twice in all. Either the table
    strides against the listing, or the table follows the listing and the members come
    in another order (here put in place of the fragment order)."""
    if stride == "table":
        data, names = _four_inodes_a_block(lambda i: i % 80)
        expected = [n.decode() for n in names]
    else:
        data, names = _four_inodes_a_block(lambda i: i // 4)
        expected = [names[i].decode() for i in _STRIDED]
        monkeypatch.setattr(
            SquashfsReader, "_in_fragment_order", lambda self, *_: _STRIDED
        )
    kept = _keeps(monkeypatch)
    decoded = _counting_decodes(monkeypatch)
    with open_archive(_image(tmp_path, data)) as archive:
        assert [m.name for m in archive.members()] == expected
    assert len(decoded) <= 2 * 80 + 4
    assert kept == [320]


def test_an_order_that_follows_the_inode_table_reads_the_inodes_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same 80 blocks, with the members in table order: the second pass reads
    each inode again, and each block decodes twice, once per pass."""
    data, names = _four_inodes_a_block(lambda i: i // 4)
    kept = _keeps(monkeypatch)
    decoded = _counting_decodes(monkeypatch)
    with open_archive(_image(tmp_path, data)) as archive:
        assert [m.name for m in archive.members()] == [n.decode() for n in names]
    assert len(decoded) <= 2 * 80 + 4
    assert kept == []


def test_hard_links_do_not_read_their_inode_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five entries name one symlink inode whose 200-byte target is stored in 1-byte
    metadata blocks, more than the cache keeps: each read of that inode decodes about
    224 blocks. The four hard links take what they need from the member they name, so
    the listing reads the inode twice (once per pass), not once per entry more."""
    target = b"t" * 200
    symlink = _inode_header(3, 2) + struct.pack("<II", 5, len(target)) + target
    inodes = b"".join(_metadata(symlink[i : i + 1]) for i in range(len(symlink)))
    names = [f"l{i}".encode() for i in range(5)]
    path = _image(tmp_path, _flat_image(inodes, [(n, 3, 0, 0) for n in names]))
    decoded = _counting_decodes(monkeypatch)
    with open_archive(path) as archive:
        members = archive.members()
    assert [(m.name, m.type, m.link_target) for m in members] == [
        ("l0", MemberType.SYMLINK, "t" * 200),
        *[(n.decode(), MemberType.HARDLINK, "l0") for n in names[1:]],
    ]
    assert len(decoded) <= 2 * len(symlink) + 4


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


class _Pipe(io.RawIOBase):
    """A source that cannot seek, as a pipe."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        return self._inner.readinto(b)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_pipe_is_refused_with_the_reason(streaming: bool) -> None:
    """The tables come after the data, so not even a streaming pass reads a pipe."""
    data = (DATA / "gzip.sqfs").read_bytes()
    with pytest.raises(StreamNotSeekableError, match="inode tables come after"):
        open_archive(_Pipe(data), streaming=streaming)


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
    offset: int, value: bytes, error: type[Exception], match: str
) -> None:
    """From a stream with no name, so the magic alone selects the reader."""
    data = _uncompressed()
    data[offset : offset + len(value)] = value
    with pytest.raises(error, match=match):
        open_archive(io.BytesIO(bytes(data)))


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


def test_a_name_that_is_not_utf8_follows_encoding(tmp_path: Path) -> None:
    """SquashFS declares no name encoding, so ``encoding=`` replaces the escape fallback."""
    data = _uncompressed()
    entry = _entry_offset(data, b"a.txt")
    data[entry + 8 : entry + 13] = b"\xe9.txt"
    path = _image(tmp_path, bytes(data))
    with open_archive(path) as archive:
        assert "\udce9.txt" in {m.name.rpartition("/")[2] for m in archive.members()}
    with open_archive(path, encoding="latin-1") as archive:
        assert "\xe9.txt" in {m.name.rpartition("/")[2] for m in archive.members()}


def test_an_entry_whose_inode_has_another_type(tmp_path: Path) -> None:
    data = _uncompressed()
    entry = _entry_offset(data, b"a.txt")
    data[entry + 4 : entry + 6] = struct.pack("<H", 1)  # says directory
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="listed as type 1"),
    ):
        archive.members()


def test_a_block_list_of_holes_larger_than_the_table_on_disk() -> None:
    """A 1 GiB file of holes: its 32 KiB list of zeros compresses to far less, so the
    bound on the lists is the decoded table, not the bytes it takes in the image."""
    with open_archive(DATA / "large-sparse.sqfs") as archive:
        members = {m.name: m for m in archive.members()}
        assert members["holes.bin"].size == 1 << 30
        assert members["holes.bin"].is_sparse
        assert not members["data.bin"].is_sparse


def test_a_block_list_longer_than_the_inode_table(tmp_path: Path) -> None:
    """A size that needs more blocks than the table holds is refused before the scan."""
    data = _uncompressed()
    inode = _inode_offset(data, b"a.txt")  # extended: the size follows the start
    data[inode + 24 : inode + 32] = struct.pack("<Q", 1 << 40)
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="block lists"),
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


def _blocks_bin_start(data: bytes) -> int:
    """Where ``dir/blocks.bin``'s first data block starts in the uncompressed image."""
    return data.index(CONTENT["dir/blocks.bin"][:64])


@pytest.mark.parametrize("cut", [4, 10])
def test_a_compressed_data_block_cut_inside_its_stored_size(
    tmp_path: Path, cut: int
) -> None:
    """A zlib block whose stored size stops ``cut`` bytes short of its stream: with 4,
    only the Adler-32 is missing and the block still decodes to its full length."""
    data = _uncompressed()
    start = _blocks_bin_start(data)
    stream = zlib.compress(bytes(4096))
    data[start : start + len(stream)] = stream
    inode = _inode_offset(data, b"blocks.bin")
    data[inode + 32 : inode + 36] = struct.pack("<I", len(stream) - cut)  # compressed
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match=f"the block at {start}: ") as caught,
    ):
        archive.read("dir/blocks.bin")
    # The image holds the whole stored block: the stored size is wrong, not the image cut.
    assert not isinstance(caught.value, TruncatedError)


@pytest.mark.parametrize("cut", [4, 10])
def test_a_compressed_fragment_block_cut_inside_its_stored_size(
    tmp_path: Path, cut: int
) -> None:
    """Nothing else checks a fragment block's decoded length, so a cut one gave a
    silent prefix (or, with only the Adler-32 cut, unchecked bytes)."""
    data = _uncompressed()
    start = _blocks_bin_start(data)
    stream = zlib.compress(b"hello\n" + bytes(100))
    data[start : start + len(stream)] = stream
    table = _superblock_field(data, 80, "<Q")  # the fragment table index
    entries = _superblock_field(data, table, "<Q") + 2  # one uncompressed block
    assert struct.unpack_from("<QI", data, entries) == (42178, 6 | 1 << 24)
    data[entries : entries + 12] = struct.pack("<QI", start, len(stream) - cut)
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match=f"the block at {start}: ") as caught,
    ):
        archive.read("a.txt")
    assert not isinstance(caught.value, TruncatedError)


def test_a_name_longer_than_the_kernel_allows(tmp_path: Path) -> None:
    """The kernel and unsquashfs refuse an entry name over 256 bytes."""
    data = _uncompressed()
    entry = _entry_offset(data, b"a.txt")
    data[entry + 6 : entry + 8] = struct.pack("<H", 256)  # 257 bytes
    with (
        open_archive(_image(tmp_path, bytes(data))) as archive,
        pytest.raises(CorruptionError, match="name of 257 bytes"),
    ):
        archive.members()


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


def test_the_internal_names_the_reader_imports() -> None:
    """The reader uses archivey's own lz4 handling, which a plugin cannot reach; any
    other internal name it starts to import is a choice to make here, not by accident."""
    tree = ast.parse(Path(squashfs_reader.__file__).read_text())
    internal = {
        f"{node.module}.{alias.name}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("archivey.")
        and node.module.split(".")[1] in ("internal", "terminal")
        for alias in node.names
    }
    assert internal == {
        "archivey.internal.excluded_libraries.as_reported",
        "archivey.internal.format_adapter.register_builtin_format",
        "archivey.internal.overrides.override",
        "archivey.internal.streams.codecs.deps",
        "archivey.internal.streams.codecs.isolated.Natives",
        "archivey.internal.streams.codecs.isolated.natives_for",
        "archivey.internal.streams.codecs.lz4_codec.LZ4_REQUIREMENT",
        "archivey.terminal.quoted",
    }


def test_the_reader_is_an_indexed_reader() -> None:
    assert issubclass(SquashfsReader, archivey.formats.IndexedReader)


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
    assert component.reason == EXCLUDED_REASON


def test_lz4_under_pypy_gives_the_reason_not_install_advice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reason = "archivey does not use lz4 under PyPy, for the test"
    # What deps does under PyPy: no lz4.block, and the reason on the requirement.
    monkeypatch.setattr(deps, "lz4_block", None)
    requirement = dataclasses.replace(squashfs_reader.LZ4_REQUIREMENT, reason=reason)
    monkeypatch.setattr(squashfs_reader, "LZ4_REQUIREMENT", requirement)
    with (
        pytest.raises(PackageNotInstalledError, match="for the test") as exc_info,
        open_archive(DATA / "lz4.sqfs") as archive,
    ):
        archive.read("a.txt")
    (component,) = exc_info.value.missing
    assert component.name is OptionalLibrary.LZ4
    assert component.reason == reason
    assert "pip install" not in str(exc_info.value)
