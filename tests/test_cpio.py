"""The CPIO reader against archives written by GNU cpio and bsdcpio
(``fixtures/cpio/make-archives.sh``), read from a file and from a pipe."""

from __future__ import annotations

import gzip
import io
import lzma
import os
import random
import struct
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

import archivey
from archivey import (
    CorruptionError,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.formats import SequentialReader
from archivey.internal.backends import cpio_reader
from archivey.internal.backends.cpio_reader import MAX_NAME_BYTES, CpioReader
from tests.public_names import assert_only_public_archivey

CPIO = archivey.ArchiveFormat.CPIO
DATA = Path(__file__).parent / "fixtures" / "cpio"

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
        assert reader.info.format_version is None
        assert reader.info.extra["cpio.variant"] == variant
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
    assert os.readlink(dest / "dir" / "link") == os.path.join("..", "a.txt")
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
        assert not info.from_plugin
    # The binary variant has no ASCII magic: the probe finds it where probes run.
    probing = archivey.ArchiveyConfig(always_probe_content=True)
    data = (DATA / "gnu-bin.cpio").read_bytes()
    assert detect_format(io.BytesIO(data), config=probing).format == CPIO
    assert detect_format(DATA / "gnu-bin.cpio").format == CPIO
    not_cpio = io.BytesIO(b"\xc7\x71" + bytes(40))
    with pytest.raises(archivey.FormatDetectionError):
        detect_format(not_cpio, config=probing)


@pytest.mark.parametrize(
    ("stream", "compress", "suffix"),
    [
        (archivey.StreamFormat.GZIP, lambda d: gzip.compress(d, mtime=0), ".gz"),
        (archivey.StreamFormat.XZ, lzma.compress, ".xz"),
    ],
    ids=["gz", "xz"],
)
def test_a_compressed_binary_archive_is_found_by_its_probe(
    tmp_path: Path,
    stream: archivey.StreamFormat,
    compress: Callable[[bytes], bytes],
    suffix: str,
) -> None:
    """GNU cpio's default output, compressed: the binary probe runs on the decoded
    bytes where the name says ``.cpio.gz`` or the config asks for every probe, and
    nowhere else, as on an uncompressed source."""
    data = compress((DATA / "gnu-bin.cpio").read_bytes())
    fmt = archivey.ArchiveFormat(CPIO.container, stream)
    named = tmp_path / f"t.cpio{suffix}"
    named.write_bytes(data)
    with open_archive(named) as reader:
        assert reader.format == fmt
        _check_listing(reader.members(), "bin")
    probing = archivey.ArchiveyConfig(always_probe_content=True)
    assert detect_format(io.BytesIO(data), config=probing).format == fmt
    bare = archivey.ArchiveFormat(archivey.ContainerFormat.RAW_STREAM, stream)
    assert detect_format(io.BytesIO(data)).format == bare
    other = tmp_path / f"t.tar{suffix}"
    other.write_bytes(data)
    assert detect_format(other).format == bare


def _binary(name: bytes) -> bytes:
    """A little-endian binary archive of one empty file, then the trailer."""
    out = b""
    for stored in (name + b"\0", b"TRAILER!!!\0"):
        # magic, dev, ino, mode, uid, gid, nlink, rdev, mtime (2), namesize, filesize (2)
        fields = (0o070707, 0, 1, 0o100644, 0, 0, 1, 0, 0, 0, len(stored), 0, 0)
        out += struct.pack("<13H", *fields) + stored + b"\0" * (len(stored) & 1)
    return out


@pytest.mark.parametrize(("name_size", "found"), [(400, True), (600, False)])
def test_a_compressed_binary_archive_needs_its_first_name_in_512_bytes(
    tmp_path: Path, name_size: int, found: bool
) -> None:
    """Inside a compressor the probe sees the first 512 decoded bytes, so a first name
    that ends past them is not found there; uncompressed, the same archive is."""
    data = _binary(b"n" * name_size)
    plain = tmp_path / "t.cpio"
    plain.write_bytes(data)
    assert detect_format(plain).format == CPIO
    packed = tmp_path / "t.cpio.gz"
    packed.write_bytes(gzip.compress(data, mtime=0))
    pair = archivey.ArchiveFormat(CPIO.container, archivey.StreamFormat.GZIP)
    assert detect_format(packed).format == (
        pair if found else archivey.ArchiveFormat.GZ
    )
    with open_archive(packed, format="cpio.gz") as reader:
        assert [m.name for m in reader.members()] == ["n" * name_size]


@pytest.mark.parametrize(
    ("stream", "compress"),
    [
        (archivey.StreamFormat.GZIP, lambda data: gzip.compress(data, mtime=0)),
        (archivey.StreamFormat.XZ, lzma.compress),
    ],
    ids=["gz", "xz"],
)
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_inside_a_compression_stream(
    stream: archivey.StreamFormat, compress: Callable[[bytes], bytes], pipe: bool
) -> None:
    """``.cpio.gz`` and ``.cpio.xz``: archivey decodes the stream, the reader sees
    cpio, found by its magic in the decoded bytes."""
    data = compress((DATA / "gnu-newc.cpio").read_bytes())
    fmt = archivey.ArchiveFormat(CPIO.container, stream)
    assert detect_format(io.BytesIO(data)).format == fmt
    source = _Pipe(data) if pipe else io.BytesIO(data)
    with open_archive(source, streaming=pipe) as reader:
        assert reader.format == fmt
        members = []
        for member, member_stream in reader.stream_members():
            members.append(member)
            if member.name in CONTENT and member_stream is not None:
                assert member_stream.read() == CONTENT[member.name], member.name
    _check_listing(members, "newc")


@pytest.mark.parametrize(
    ("spelling", "stream", "compress"),
    [
        ("cpio.gz", archivey.StreamFormat.GZIP, lambda d: gzip.compress(d, mtime=0)),
        ("cpio.xz", archivey.StreamFormat.XZ, lzma.compress),
    ],
    ids=["gz", "xz"],
)
def test_a_compressed_pair_is_spelled_like_a_plugins(
    tmp_path: Path,
    spelling: str,
    stream: archivey.StreamFormat,
    compress: Callable[[bytes], bytes],
) -> None:
    """``format="cpio.gz"`` names the pair, which has no named constant;
    ``format="cpio"`` on the same bytes reads them as plain CPIO and refuses them."""
    path = tmp_path / "t.bin"
    path.write_bytes(compress((DATA / "gnu-newc.cpio").read_bytes()))
    with open_archive(path, format=spelling) as reader:
        assert reader.format == archivey.ArchiveFormat(CPIO.container, stream)
        _check_listing(reader.members(), "newc")
    with pytest.raises(CorruptionError, match="No CPIO header"):
        open_archive(path, format="cpio").close()


@pytest.mark.parametrize("compressed", [False, True], ids=["plain", "gz"])
def test_seeks_inside_a_member(tmp_path: Path, compressed: bool) -> None:
    """With ``seekable_members=True`` a member stream seeks, plain and inside a
    compression stream (the shared seek matrix has no CPIO row)."""
    data = (DATA / "gnu-newc.cpio").read_bytes()
    path = tmp_path / ("t.cpio.gz" if compressed else "t.cpio")
    path.write_bytes(gzip.compress(data, mtime=0) if compressed else data)
    content = CONTENT["dir/blocks.bin"]
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("dir/blocks.bin") as stream,
    ):
        assert stream.seekable()
        stream.seek(5000)
        assert stream.read(100) == content[5000:5100]
        stream.seek(10)
        assert stream.read() == content[10:]


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


TRAILER = b"TRAILER!!!"
_FILE = 0o100644


def _newc(*members: tuple[bytes, int, int, int, bytes], nul: bool = True) -> bytes:
    """A newc archive of (name, mode, inode, nlink, data) members, then the trailer.
    ``nul=False`` leaves the first member's name without its NUL."""
    out = bytearray()
    for i, (name, mode, ino, nlink, data) in enumerate(
        members + ((TRAILER, 0, 0, 1, b""),)
    ):
        stored = name if (i == 0 and not nul) else name + b"\0"
        fields = (ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(stored), 0)
        header = b"070701" + b"".join(b"%08X" % value for value in fields)
        out += header + stored + bytes(-(len(header) + len(stored)) % 4)
        out += data + bytes(-len(data) % 4)
    return bytes(out)


def test_too_many_held_links(tmp_path: Path) -> None:
    """The reader's own bound on links held back for their data: archivey's
    max_members counts yielded members only, and a held link is not yet one."""
    links = [(f"l{i}".encode(), _FILE, 7, 6, b"") for i in range(5)]
    data = _newc(*links, (b"data", _FILE, 7, 6, b"x"))
    config = archivey.ArchiveyConfig(
        listing_limits=archivey.ListingLimits(max_members=2)
    )
    with (
        pytest.raises(ResourceLimitError, match="waiting for their data"),
        open_archive(_archive(tmp_path, data), config=config) as reader,
    ):
        reader.members()


def test_a_held_link_keeps_its_stored_name(tmp_path: Path) -> None:
    """A held hard link is reported when its name is normalized, as any member is."""
    data = _newc((b"dir//weird", _FILE, 7, 2, b""), (b"plain", _FILE, 7, 2, b"x"))
    path = _archive(tmp_path, data)
    with open_archive(path) as reader:
        members = reader.members()
        counts = reader.diagnostics.counts
    assert [(m.name, m.type) for m in members] == [
        ("plain", MemberType.FILE),
        ("dir/weird", MemberType.HARDLINK),
    ]
    assert counts[DiagnosticCode.MEMBER_NAME_NORMALIZED] == 1
    strict = archivey.ArchiveyConfig(diagnostic_policy=archivey.DiagnosticPolicy.STRICT)
    with (
        pytest.raises(archivey.DiagnosticRaisedError),
        open_archive(path, config=strict) as reader,
    ):
        reader.members()


def test_a_name_that_is_not_utf8_follows_encoding(tmp_path: Path) -> None:
    """CPIO declares no name encoding, so ``encoding=`` replaces the escape fallback."""
    path = _archive(tmp_path, _newc((b"caf\xe9.txt", _FILE, 1, 1, b"x")))
    with open_archive(path) as reader:
        assert [m.name for m in reader.members()] == ["caf\udce9.txt"]
    with open_archive(path, encoding="latin-1") as reader:
        assert [m.name for m in reader.members()] == ["café.txt"]


def test_hostile_headers(tmp_path: Path) -> None:
    def opened(data: bytes) -> None:
        with open_archive(_archive(tmp_path, data), format="cpio") as reader:
            reader.members()

    with pytest.raises(CorruptionError, match="not NUL-terminated"):
        opened(_newc((b"a", _FILE, 1, 1, b"x"), nul=False))
    with pytest.raises(CorruptionError, match="is crc, in a newc archive"):
        mixed = bytearray(_newc((b"a", _FILE, 1, 1, b"x"), (b"b", _FILE, 2, 1, b"y")))
        # The second header: 110 + "a\0" + pad (112), then the data and its pad (116).
        mixed[116:122] = b"070702"
        opened(bytes(mixed))
    long_name = bytearray(_newc((b"a", _FILE, 1, 1, b"x")))
    long_name[94:102] = b"%08X" % (MAX_NAME_BYTES + 1)
    with pytest.raises(CorruptionError, match=f"a name of {MAX_NAME_BYTES + 1} bytes"):
        opened(bytes(long_name))


def _odc_member(name: bytes, data: bytes, *, ino: int, uid: int = 0) -> bytes:
    stored = name + b"\0"
    fields = (0, ino, _FILE, uid, 0, 1, 0, 0o1234567, len(stored), len(data))
    widths = (6, 6, 6, 6, 6, 6, 6, 11, 6, 11)
    header = b"070707" + b"".join(
        b"%0*o" % (w, v) for w, v in zip(widths, fields, strict=True)
    )
    return header + stored + data


def _afio_large_member(
    name: bytes, data: bytes, *, ino: int, uid: int, xsize: int = 0
) -> bytes:
    """A member under afio's large header, its fields laid out as libarchive reads
    them: dev, ino, 'm', mode (octal), uid, gid, nlink, rdev, mtime, 'n', namesize,
    flag, xsize, 's', filesize, ':'."""
    stored = name + b"\0"
    header = b"070727%08X%016Xm%06o%08X%08X%08X%08X%016Xn%04X%04X%04Xs%016X:" % (
        0x63,
        ino,
        _FILE,
        uid,
        0,
        1,
        0,
        0x4B694A10,
        len(stored),
        0,
        xsize,
        len(data),
    )
    assert len(header) == 116
    return header + stored + data


def _odc_trailer() -> bytes:
    return _odc_member(TRAILER, b"", ino=0)


def test_afio_large_headers(tmp_path: Path) -> None:
    """afio writes odc, but gives a member whose fields need it its large header
    (libarchive's test_read_format_cpio_afio has one such member, for a uid of
    65536): both kinds read in one archive, which stays odc."""
    data = (
        _odc_member(b"file1", b"0123456789abcdef\n", ino=1)
        + _afio_large_member(b"file2", b"0123456789abcdef\n", ino=2, uid=65536)
        + _odc_trailer()
    )
    data += bytes(-len(data) % 5120)  # afio's block size
    for source in (_archive(tmp_path, data), _Pipe(data)):
        with open_archive(source, streaming=True) as reader:
            got = [
                (m.name, m.uid, m.size, s.read()) for m, s in reader.stream_members()
            ]
            assert reader.info.extra["cpio.variant"] == "odc"
        assert got == [
            ("file1", 0, 17, b"0123456789abcdef\n"),
            ("file2", 65536, 17, b"0123456789abcdef\n"),
        ]
    with open_archive(_archive(tmp_path, data)) as reader:
        (_, second) = reader.members()
    assert second.modified == datetime.fromtimestamp(0x4B694A10, UTC)
    # An archive whose first member has the large header is found by its magic.
    first_large = _afio_large_member(b"big", b"x", ino=1, uid=1 << 20) + _odc_trailer()
    assert detect_format(io.BytesIO(first_large)).format == CPIO
    with open_archive(io.BytesIO(first_large)) as reader:
        assert [(m.name, m.uid) for m in reader.members()] == [("big", 1 << 20)]


def test_afio_large_header_damage(tmp_path: Path) -> None:
    def opened(data: bytes) -> None:
        with open_archive(_archive(tmp_path, data), format="cpio") as reader:
            reader.members()

    good = _afio_large_member(b"a", b"x", ino=1, uid=1) + _odc_trailer()
    no_m = bytearray(good)
    no_m[30:31] = b"x"
    with pytest.raises(CorruptionError, match="no 'm' separator"):
        opened(bytes(no_m))
    bad_digit = bytearray(good)
    bad_digit[37:38] = b"g"  # in the uid field
    with pytest.raises(CorruptionError, match="the uid field"):
        opened(bytes(bad_digit))
    extra = _afio_large_member(b"a", b"x", ino=1, uid=1, xsize=4) + _odc_trailer()
    with pytest.raises(UnsupportedFeatureError, match="4 bytes of extra data"):
        opened(extra)


def test_the_reader_uses_only_public_archivey() -> None:
    """Written as a format added from outside would be."""
    assert_only_public_archivey(cpio_reader.__file__)


def test_the_reader_is_a_sequential_reader() -> None:
    assert issubclass(CpioReader, SequentialReader)
