"""Reading the UDF tree of an ISO image, and UDF-only images.

Most images here come from ``tests/udf_builder.py``, which lays out shapes no writer
the suite can run produces (a UDF-only image with files, a metadata partition,
Extended File Entries, unrecorded extents). 7-Zip lists and extracts what it supports
of them the same way (checked when the builder was written). Bridge images come from
``pycdlib`` and, when installed, ``genisoimage -udf``.
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from archivey import detect_format, open_archive
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    MemberTimestampContext,
    ReaderDisagreementContext,
)
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.udf import (
    Span,
    UdfEntry,
    UdfVolume,
    _Partition,
    decode_dstring,
    udf_timestamp,
)
from archivey.types import ArchiveFormat, MemberType
from tests.conftest import requires, requires_binary
from tests.udf_builder import BLOCK, WHEN, Node, build_udf, directory, retag

pytestmark = requires("pycdlib")


def _tree() -> Node:
    return directory(
        "",
        directory("Ünïcode dir ✓", Node("inner.txt", b"inner")),
        Node("big.bin", bytes(range(256)) * 20, split=True),
        Node("inline.txt", b"tiny", inline=True),
        Node("sparse.bin", b"ab", sparse=5000),
        Node("indirect.txt", b"indirect", indirect=True),
        Node("link", file_type=12, target="../x/./y"),
        Node("abs", file_type=12, target="/etc/hosts"),
        Node("fifo", file_type=9),
        Node("perm.sh", b"#!", permissions=0x1CA4, uid=0, gid=0xFFFFFFFF),
    )


_EXPECTED = {
    "Ünïcode dir ✓/": (MemberType.DIRECTORY, None),
    "Ünïcode dir ✓/inner.txt": (MemberType.FILE, b"inner"),
    "big.bin": (MemberType.FILE, bytes(range(256)) * 20),
    "inline.txt": (MemberType.FILE, b"tiny"),
    "sparse.bin": (MemberType.FILE, b"ab" + bytes(5000)),
    "indirect.txt": (MemberType.FILE, b"indirect"),
    "link": (MemberType.SYMLINK, None),
    "abs": (MemberType.SYMLINK, None),
    "fifo": (MemberType.OTHER, None),
    "perm.sh": (MemberType.FILE, b"#!"),
}


def _udf_only(**kwargs: object) -> bytes:
    return build_udf(_tree(), **kwargs)  # type: ignore[arg-type]


def _volume(image: bytes) -> UdfVolume:
    return UdfVolume(
        lambda offset, n: image[offset : offset + n],
        len(image),
        archive_name=None,
        budget=None,
    )


# --- UDF-only images -------------------------------------------------------------


def test_a_udf_only_image_is_detected_as_iso(tmp_path: Path) -> None:
    """A UDF-only image has ``BEA01`` where an ISO 9660 image has ``CD001``."""
    path = tmp_path / "disc.img"
    path.write_bytes(_udf_only())
    assert detect_format(path).format is ArchiveFormat.ISO
    assert detect_format(io.BytesIO(path.read_bytes())).format is ArchiveFormat.ISO
    with open_archive(path) as reader:
        assert reader.info.extra["iso.namespace"] == "udf"
        assert reader.info.comment == "UDFTEST"


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({}, id="file-entries"),
        pytest.param({"extended": True}, id="extended-file-entries"),
        pytest.param({"long_ad": True}, id="long-ad"),
        pytest.param({"metadata": True}, id="metadata-partition"),
    ],
)
def test_a_udf_only_image_lists_and_reads(kwargs: dict[str, bool]) -> None:
    """Every shape lists the same members with the same data: data in extents, in
    the File Entry, continued in an Allocation Extent Descriptor, after an unrecorded
    extent (zeros), behind an indirect entry, and in a metadata partition."""
    with open_archive(io.BytesIO(_udf_only(**kwargs))) as reader:
        members = {m.name: m for m in reader.members()}
        assert sorted(members) == sorted(_EXPECTED)
        for name, (member_type, data) in _EXPECTED.items():
            member = members[name]
            assert member.type is member_type, name
            if data is not None:
                assert member.size == len(data)
                assert reader.read(member) == data
        assert members["link"].link_target == "../x/./y"
        assert members["abs"].link_target == "/etc/hosts"
        assert members["fifo"].extra["special_file_type"] == "fifo"


def test_udf_metadata_maps_to_posix() -> None:
    """Permissions map class by class (UDF: execute 1, write 2, read 4 per class),
    ``0xFFFFFFFF`` is no owner, and an Extended File Entry adds the creation time."""
    with open_archive(io.BytesIO(_udf_only(extended=True))) as reader:
        members = {m.name: m for m in reader.members()}
    perm = members["perm.sh"]
    # 0x1CA4: owner rwx (0x1C00), group read and execute (0xA0), other read (0x4).
    assert perm.mode == 0o754
    assert (perm.uid, perm.gid) == (0, None)
    assert members["Ünïcode dir ✓/inner.txt"].mode == 0o555
    for member in members.values():
        assert member.modified == WHEN
        assert member.created == WHEN
        assert member.accessed == WHEN
    with open_archive(io.BytesIO(_udf_only())) as reader:
        assert all(m.created is None for m in reader.members())


def test_a_udf_member_reads_with_seeks() -> None:
    """A file joined from a recorded extent and zeros seeks like any member."""
    with open_archive(io.BytesIO(_udf_only()), seekable_members=True) as reader:
        (member,) = [m for m in reader.members() if m.name == "sparse.bin"]
        with reader.open(member) as stream:
            assert stream.seekable()
            stream.seek(4000)
            assert stream.read(10) == bytes(10)
            stream.seek(0)
            assert stream.read(3) == b"ab\0"


def test_names_decode_by_their_compression_id() -> None:
    assert decode_dstring(b"\x08caf\xe9") == "café"
    assert decode_dstring(b"\x10" + "日本".encode("utf-16-be")) == "日本"
    assert decode_dstring(b"\x10\x00a\x00") == "a�"
    assert decode_dstring(b"\x10\xd8\x00") == "\ud800"
    assert decode_dstring(b"") == ""


def test_timestamps() -> None:
    assert udf_timestamp(bytes(12)) == (None, False)
    raw = struct.pack("<HhBBBBBBBB", (1 << 12) | 60, 2020, 1, 2, 3, 4, 5, 6, 7, 8)
    value, invalid = udf_timestamp(raw)
    assert not invalid and value is not None
    assert value.utcoffset().total_seconds() == 3600  # type: ignore[union-attr]
    assert value.microsecond == 60_708
    unspecified = struct.pack(
        "<HhBBBBBBBB", (1 << 12) | 0x801, 2020, 1, 2, 3, 4, 5, 0, 0, 0
    )
    assert udf_timestamp(unspecified)[0] == datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
    bad = struct.pack("<HhBBBBBBBB", 1 << 12, 2020, 13, 2, 3, 4, 5, 0, 0, 0)
    assert udf_timestamp(bad) == (None, True)


def test_a_sub_second_field_over_99_flags_the_date() -> None:
    """Each sub-second field holds 0-99; one over keeps the seconds and is flagged."""
    raw = struct.pack("<HhBBBBBBBB", 1 << 12, 2024, 5, 6, 7, 8, 9, 200, 0, 0)
    assert udf_timestamp(raw) == (datetime(2024, 5, 6, 7, 8, 9, tzinfo=UTC), True)


def test_first_extent_skips_an_unrecorded_span() -> None:
    """The first recorded byte is what other trees point at, not a leading hole."""
    entry = UdfEntry(
        location=0,
        file_type=5,
        uid=None,
        gid=None,
        permissions=0,
        info_length=4096,
        modified=b"",
        accessed=b"",
        attribute=b"",
        created=None,
        spans=(Span(None, 2048), Span(8192, 2048)),
        inline=None,
        partition=0,
    )
    assert entry.first_extent == 8192
    sparse = UdfEntry(**{**_fields(entry), "spans": (Span(None, 2048),)})
    assert sparse.first_extent is None


def _fields(entry: UdfEntry) -> dict[str, object]:
    return {name: getattr(entry, name) for name in UdfEntry.__slots__}


class _Weigh:
    def __init__(self) -> None:
        self.nbytes = 0

    def add_udf_member(self) -> None:
        pass

    def add_udf_bytes(self, nbytes: int) -> None:
        self.nbytes += nbytes


def test_an_extent_over_many_metadata_runs_costs_one_step_per_run() -> None:
    """A 1 GiB extent in a metadata partition of 201 runs is split once per run, not
    walked block by block (about 3 s per extent before), and each extra span is
    weighed against the metadata budget."""
    image = build_udf(directory("", Node("f", b"x" * 10)), metadata=True)
    weigh = _Weigh()
    volume = UdfVolume(
        lambda offset, n: image[offset : offset + n],
        len(image),
        archive_name=None,
        budget=weigh,
    )
    big = 0x3FFFF800 // BLOCK
    runs = tuple((10 + 2 * index, 1) for index in range(200)) + ((1000, big),)
    firsts = tuple(range(200)) + (200,)
    volume._partitions[1] = _Partition(0, 200 + big, runs, firsts)
    before = weigh.nbytes
    started = time.monotonic()
    for _ in range(20):
        spans = volume._extent_spans(1, 0, 0x3FFFF800, "a file's extent")
    assert time.monotonic() - started < 2
    assert len(spans) == 201
    assert spans[0] == Span(10 * BLOCK, BLOCK)
    assert sum(span.length for span in spans) == 0x3FFFF800
    assert weigh.nbytes - before == 20 * 200 * 16
    # A block inside the last run maps through the same bisect.
    assert volume._block_offset(1, 205, "x") == (1000 + 5) * BLOCK


def test_an_invalid_udf_date_is_reported() -> None:
    bad = struct.pack("<HhBBBBBBBB", 1 << 12, 2020, 13, 2, 3, 4, 5, 0, 0, 0)
    image = build_udf(directory("", Node("a", b"x", times=bad)))
    with open_archive(io.BytesIO(image)) as reader:
        (member,) = reader.members()
        assert member.modified is None
        found = {
            d.context.field
            for d in reader.diagnostics.retained
            if isinstance(d.context, MemberTimestampContext)
        }
    assert found == {"modified", "accessed", "ctime"}


def test_trailing_data_after_a_udf_only_image_is_reported() -> None:
    image = _udf_only()
    with open_archive(io.BytesIO(image)) as reader:
        reader.members()
        assert not reader.diagnostics.retained
    with open_archive(io.BytesIO(image + b"appended")) as reader:
        reader.members()
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
    assert isinstance(diagnostic.context, ArchiveEofContext)


# --- what is refused --------------------------------------------------------------


@pytest.mark.parametrize(
    "ident", [b"*UDF Sparable Partition", b"*UDF Virtual Partition"]
)
def test_sparable_and_virtual_partitions_are_unsupported(ident: bytes) -> None:
    image = build_udf(directory("", Node("a", b"x")), metadata=True, map_ident=ident)
    with pytest.raises(UnsupportedFeatureError, match="partition"):
        open_archive(io.BytesIO(image))


def _patch_entry(image: bytes, name: str, edit: object) -> bytes:
    """``image`` with the File Entry of ``name`` changed by ``edit(bytearray)`` and
    its tag recomputed."""
    location = next(n.entry.location for n in _volume(image).walk() if n.path == name)
    data = bytearray(image)
    entry = bytearray(data[location : location + BLOCK])
    edit(entry)  # type: ignore[operator]
    data[location : location + BLOCK] = retag(entry)
    return bytes(data)


def test_a_damaged_file_entry_is_corrupt() -> None:
    image = bytearray(build_udf(directory("", Node("a", b"x"))))
    location = next(n.entry.location for n in _volume(bytes(image)).walk())
    image[location + 4] ^= 0xFF  # the tag checksum
    with pytest.raises(CorruptionError, match="checksum"):
        open_archive(io.BytesIO(bytes(image)))


def test_extents_shorter_than_the_length_are_corrupt() -> None:
    image = build_udf(directory("", Node("a", b"x" * 100)))

    def longer(entry: bytearray) -> None:
        struct.pack_into("<Q", entry, 56, 5000)

    with pytest.raises(CorruptionError, match="extents hold 100 bytes of its 5000"):
        open_archive(io.BytesIO(_patch_entry(image, "a", longer)))


def test_overlapping_extents_are_refused_on_read() -> None:
    """Two extents over the same blocks would let a small image list a large file."""
    image = build_udf(directory("", Node("a", b"x" * BLOCK * 2)))

    def overlap(entry: bytearray) -> None:
        # One short_ad of 4096 bytes becomes two of 4096 over the same blocks.
        (length,) = struct.unpack_from("<I", entry, 172)
        ad = entry[176 : 176 + length]
        struct.pack_into("<I", entry, 172, 2 * length)
        entry[176 : 176 + 2 * length] = ad + ad
        struct.pack_into("<Q", entry, 56, 4 * BLOCK)

    with open_archive(io.BytesIO(_patch_entry(image, "a", overlap))) as reader:
        (member,) = reader.members()
        assert member.size == 4 * BLOCK
        with pytest.raises(CorruptionError, match="overlap"):
            reader.read(member)


def test_a_file_identifier_naming_the_root_is_a_loop() -> None:
    image = build_udf(directory("", directory("d", Node("f", b"x"))))
    volume = _volume(image)
    root_block = (volume.root.location // BLOCK) - 300  # partition starts at 300
    data = bytearray(image)
    # The root's File Identifier for "d" is the second in the root's directory data.
    directory_offset = volume.root.spans[0].offset
    assert directory_offset is not None
    first = (38 + 0 + 3) & ~3  # the parent entry: no name
    fid = directory_offset + first
    assert data[fid : fid + 2] == b"\x01\x01"
    struct.pack_into("<I", data, fid + 24, root_block)
    length = 38 + data[fid + 19]
    total = (length + 3) & ~3
    data[fid : fid + total] = retag(data[fid : fid + total])
    with pytest.raises(CorruptionError, match="forms a loop"):
        open_archive(io.BytesIO(bytes(data)))


def test_listing_limits_count_a_udf_only_tree() -> None:
    image = build_udf(directory("", *(Node(f"f{i}", b"x") for i in range(10))))
    fits = ArchiveyConfig(listing_limits=ListingLimits(max_members=10))
    with open_archive(io.BytesIO(image), config=fits) as reader:
        assert len(reader.members()) == 10
    below = ArchiveyConfig(listing_limits=ListingLimits(max_members=9))
    with pytest.raises(ResourceLimitError, match="max_members=9.*UDF"):
        open_archive(io.BytesIO(image), config=below)
    tight = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=1000))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=1000.*UDF"):
        open_archive(io.BytesIO(image), config=tight)


def test_a_cut_udf_only_image() -> None:
    """Cut before its anchor or inside its tree, the image is ``TruncatedError`` at
    open; cut inside a file's data, it opens, and that file raises
    ``TruncatedError`` when read."""
    image = build_udf(directory("", Node("a", b"a" * 3000), Node("b", b"b" * 3000)))
    with pytest.raises(TruncatedError, match="anchor"):
        open_archive(io.BytesIO(image[: 256 * BLOCK + 100]))
    root = _volume(image).root.spans[0].offset
    assert root is not None
    with pytest.raises(TruncatedError, match="ends before its directory"):
        open_archive(io.BytesIO(image[: root + 10]))
    start = image.index(b"b" * 3000)
    with open_archive(io.BytesIO(image[: start + 100])) as reader:
        members = {m.name: m for m in reader.members()}
        assert reader.read(members["a"]) == b"a" * 3000
        with pytest.raises(TruncatedError):
            reader.read(members["b"])


# --- bridge images ----------------------------------------------------------------


def _bridge(*, rock_ridge: bool, joliet: bool) -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(
        interchange_level=1,
        udf="2.60",
        rock_ridge="1.09" if rock_ridge else None,
        joliet=3 if joliet else None,
    )
    names: dict[str, str] = {"udf_path": "/A long UDF name.txt"}
    if rock_ridge:
        names["rr_name"] = "rock ridge name.txt"
    if joliet:
        names["joliet_path"] = "/joliet name.txt"
    iso.add_fp(io.BytesIO(b"data"), 4, "/FILE.TXT;1", **names)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


@pytest.mark.parametrize(
    ("rock_ridge", "joliet", "namespace", "name"),
    [
        (True, True, "rock_ridge", "rock ridge name.txt"),
        (True, False, "rock_ridge", "rock ridge name.txt"),
        (False, True, "udf", "A long UDF name.txt"),
        (False, False, "udf", "A long UDF name.txt"),
    ],
)
def test_the_namespace_order_is_rock_ridge_udf_joliet_plain(
    rock_ridge: bool, joliet: bool, namespace: str, name: str
) -> None:
    """Ruled by davi, 2026-11-18: Rock Ridge, then UDF, then Joliet, then plain."""
    with open_archive(io.BytesIO(_bridge(rock_ridge=rock_ridge, joliet=joliet))) as r:
        assert r.info.extra["iso.namespace"] == namespace
        (member,) = r.members()
        assert member.name == name
        assert r.read(member) == b"data"
        assert not r.diagnostics.retained


def test_a_bridge_with_an_unsupported_udf_partition_lists_joliet() -> None:
    """A UDF tree archivey cannot read is passed over for the ISO 9660 trees."""
    image = bytearray(_bridge(rock_ridge=False, joliet=True))
    regid = b"\0" + b"*UDF Sparable Partition".ljust(23, b"\0") + bytes(8)
    sparable = struct.pack("<BBH", 2, 64, 0) + regid + struct.pack("<HH", 1, 0)
    sparable = sparable.ljust(64, b"\0")
    for block in range(len(image) // BLOCK):
        offset = block * BLOCK
        if image[offset : offset + 2] != b"\x06\x00":  # a Logical Volume Descriptor
            continue
        descriptor = bytearray(image[offset : offset + 440 + 64])
        struct.pack_into("<II", descriptor, 264, 64, 1)
        descriptor[440:504] = sparable
        struct.pack_into("<H", descriptor, 10, len(descriptor) - 16)
        image[offset : offset + len(descriptor)] = retag(descriptor)
    with open_archive(io.BytesIO(bytes(image))) as reader:
        assert reader.info.extra["iso.namespace"] == "joliet"
        assert [m.name for m in reader.members()] == ["joliet name.txt"]


def test_a_file_only_in_the_iso_tree_is_reported_when_udf_is_listed() -> None:
    """A Windows install image keeps a README in its ISO 9660 tree only, for readers
    without UDF; listing UDF reports it."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=1, udf="2.60")
    iso.add_fp(io.BytesIO(b"read me"), 7, "/README.TXT;1")
    iso.add_fp(io.BytesIO(b"payload"), 7, "/DATA.BIN;1", udf_path="/install.wim")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    with open_archive(io.BytesIO(out.getvalue())) as reader:
        assert [m.name for m in reader.members()] == ["install.wim"]
        found = [
            (d.context.member_name, d.context.shape)
            for d in reader.diagnostics.retained
            if isinstance(d.context, ReaderDisagreementContext)
        ]
    assert found == [("README.TXT", "file_only_in_iso9660")]


# --- real producers -------------------------------------------------------------


@requires_binary("genisoimage")
@pytest.mark.parametrize(
    ("flags", "namespace"),
    [(["-udf"], "udf"), (["-udf", "-J"], "udf"), (["-udf", "-R", "-J"], "rock_ridge")],
)
def test_genisoimage_udf_bridge_images(
    tmp_path: Path, flags: list[str], namespace: str
) -> None:
    source = tmp_path / "src"
    (source / "A Long Directory Name").mkdir(parents=True)
    (source / "A Long Directory Name" / "a file with a long name.txt").write_bytes(
        b"hello"
    )
    (source / "big.bin").write_bytes(bytes(range(256)) * 400)
    image = tmp_path / "out.iso"
    subprocess.run(
        ["genisoimage", "-quiet", *flags, "-o", str(image), str(source)], check=True
    )
    with open_archive(image) as reader:
        assert reader.info.extra["iso.namespace"] == namespace
        members = {m.name: m for m in reader.members()}
        assert sorted(members) == [
            "A Long Directory Name/",
            "A Long Directory Name/a file with a long name.txt",
            "big.bin",
        ]
        assert reader.read(members["big.bin"]) == bytes(range(256)) * 400
        assert not reader.diagnostics.retained


@requires_binary("mkudffs")
@pytest.mark.parametrize(
    ("media", "revision", "block"),
    [("dvd", "1.02", 2048), ("dvd", "2.01", 2048), ("hd", "2.01", 512)],
)
def test_mkudffs_empty_file_systems_open(
    tmp_path: Path, media: str, revision: str, block: int
) -> None:
    image = tmp_path / "empty.udf"
    image.write_bytes(bytes(4 << 20))
    subprocess.run(
        [
            "mkudffs",
            f"--media-type={media}",
            f"--udfrev={revision}",
            "--label=LBL",
            str(image),
        ],
        check=True,
        capture_output=True,
    )
    assert _volume(image.read_bytes()).block_size == block
    with open_archive(image) as reader:
        assert reader.info.comment == "LBL"
        assert reader.members() == []


@requires_binary("mkudffs")
def test_a_virtual_allocation_table_is_unsupported(tmp_path: Path) -> None:
    """mkudffs writes a BD-R file system with a Virtual Allocation Table."""
    image = tmp_path / "bdr.udf"
    image.write_bytes(bytes(4 << 20))
    subprocess.run(
        ["mkudffs", "--media-type=bdr", "--udfrev=2.50", str(image)],
        check=True,
        capture_output=True,
    )
    with pytest.raises(UnsupportedFeatureError, match="virtual partition"):
        open_archive(image)


def test_7z_lists_the_builder_images_the_same_way(tmp_path: Path) -> None:
    """The builder's images are what 7-Zip reads too, for the shapes it supports."""
    seven = shutil.which("7z")
    if seven is None:
        pytest.skip("requires 7z")
    image = build_udf(
        directory("", directory("d", Node("f", b"x")), Node("Ünï ✓", b"y")),
        metadata=True,
    )
    path = tmp_path / "disc.udf"
    path.write_bytes(image)
    result = subprocess.run(
        [seven, "l", "-tudf", "-slt", str(path)], check=True, capture_output=True
    )
    paths = sorted(
        line.removeprefix("Path = ")
        for line in result.stdout.decode().splitlines()
        if line.startswith("Path = ") and line != f"Path = {path}"
    )
    with open_archive(io.BytesIO(image)) as reader:
        ours = sorted(m.name.rstrip("/") for m in reader.members())
    assert paths == ours
