"""Reading the UDF tree of an ISO image, and UDF-only images.

Most images here come from ``tests/udf_builder.py``, which lays out shapes no writer
the suite can run produces (a UDF-only image with files, a metadata partition,
Extended File Entries, unrecorded extents). 7-Zip lists and extracts what it supports
of them the same way (checked when the builder was written). Bridge images come from
``pycdlib`` and, when installed, ``genisoimage -udf``.
"""

from __future__ import annotations

import dataclasses
import io
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
    _crc_itu,
    _Partition,
    decode_dstring,
    udf_timestamp,
)
from archivey.types import ArchiveFormat, MemberType
from tests.conftest import (
    requires,
    requires_binary,
    run_7z,
    sevenzip_version,
    sevenzip_version_text,
)
from tests.udf_builder import BLOCK, WHEN, Node, build_udf, directory, retag, tag


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


class _CountedSpans(tuple):  # type: ignore[type-arg]
    walks = 0

    def __iter__(self):  # type: ignore[no-untyped-def]
        type(self).walks += 1
        return super().__iter__()


def test_first_extent_walks_the_spans_once_per_entry() -> None:
    """Every name on a shared entry reads ``first_extent`` while listing; an entry of
    thousands of unrecorded spans must not be walked once per name."""
    _CountedSpans.walks = 0
    spans = _CountedSpans([Span(None, 2048)] * 1000 + [Span(8192, 2048)])
    entry = UdfEntry(**{**_fields(_inline_directory(b"")), "spans": spans})
    assert [entry.first_extent for _ in range(100)] == [8192] * 100
    assert _CountedSpans.walks == 1


def _fields(entry: UdfEntry) -> dict[str, object]:
    return {f.name: getattr(entry, f.name) for f in dataclasses.fields(entry) if f.init}


class _Weigh:
    def __init__(self) -> None:
        self.nbytes = 0
        self.path_bytes = 0

    def add_udf_member(self) -> None:
        pass

    def add_udf_bytes(self, nbytes: int) -> None:
        self.nbytes += nbytes

    def add_udf_path(self, path: str, raw_path: bytes) -> None:
        self.path_bytes += (len(path) if path.isascii() else 4 * len(path)) + len(
            raw_path
        )


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
    # Runs apart on disc, as _metadata_partition leaves them: one span per run.
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


def _inline_directory(data: bytes) -> UdfEntry:
    return UdfEntry(
        location=0,
        file_type=4,
        uid=None,
        gid=None,
        permissions=0,
        info_length=len(data),
        modified=b"",
        accessed=b"",
        attribute=b"",
        created=None,
        spans=(),
        inline=data,
        partition=0,
    )


def test_zeros_inside_a_directory_are_refused() -> None:
    """Zeros where a File Identifier should start end the directory only when nothing
    follows them; a gap with descriptors after it is corrupt, not a quiet stop."""
    volume = _volume(_udf_only())
    assert list(volume._children(_inline_directory(bytes(64)))) == []
    gap = _inline_directory(bytes(16) + b"\x01" * 40)
    with pytest.raises(CorruptionError, match="zeros where a file identifier"):
        list(volume._children(gap))


def test_extended_allocation_descriptors_are_unsupported() -> None:
    """UDF records only short and long descriptors; an extended one is refused rather
    than read with its recorded and information lengths ignored."""
    volume = _volume(_udf_only())
    area = struct.pack("<IIIIH2x", 2048, 10, 10, 64, 0)
    with pytest.raises(UnsupportedFeatureError, match="extended allocation"):
        volume._allocation(area, 2, 0, None, 10)


def test_contiguous_metadata_runs_are_one_run() -> None:
    """Metadata file extents that follow each other on disc merge into one run, so
    an extent over them is one step and one span, not one step per extent."""
    image = build_udf(_tree(), metadata=True, split_metadata_file=True)
    volume = _volume(image)
    part = volume._partitions[1]
    assert part.metadata is not None
    assert len(part.metadata) == 1
    assert part.length > 1
    with open_archive(io.BytesIO(image)) as reader:
        assert {m.name for m in reader.members()} == set(_EXPECTED)


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


def _bitwise_crc(data: bytes) -> int:
    """ECMA-167 7.2.6 CRC, one bit at a time, as the standard writes it."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


@pytest.mark.parametrize("length", [0, 1, 2, 5, 100, 2032])
def test_the_descriptor_crc_matches_the_bitwise_definition(length: int) -> None:
    data = bytes((index * 151 + length) & 0xFF for index in range(length))
    assert _crc_itu(data) == _bitwise_crc(data)
    assert _crc_itu(b"\xff" * length) == _bitwise_crc(b"\xff" * length)


_PARTITION_START = 300  # the builder's partition start, in blocks


def _fan_out(
    count: int,
    *,
    chain: int,
    first: int = 0,
    full_crc: bool = False,
    extra: tuple[int, ...] = (),
) -> bytes:
    """A UDF-only image whose root holds ``count`` File Identifiers, each naming the
    ICB at index ``first`` of a chain of ``chain`` Indirect Entries that ends at one
    file's File Entry (index ``chain`` is the File Entry itself). ``extra`` names
    more chain indexes, one File Identifier each, after those. With ``full_crc``
    every descriptor of the chain has a CRC over its whole block."""
    image = bytearray(build_udf(directory("", Node("f", data=b"x" * 10))))
    volume = _volume(bytes(image))
    root = volume.root
    entry_at = volume.names[0].entry.location
    entry_block = entry_at // BLOCK - _PARTITION_START
    if full_crc:
        entry = bytearray(image[entry_at : entry_at + BLOCK])
        struct.pack_into("<H", entry, 10, BLOCK - 16)
        image[entry_at : entry_at + BLOCK] = retag(entry)
    base = len(image) // BLOCK - _PARTITION_START
    for index in range(chain):
        following = base + index + 1 if index < chain - 1 else entry_block
        body = struct.pack("<IHHHBBIHH", 0, 4096, 0, 1, 0, 3, 0, 0, 0)
        body += struct.pack("<IIH6x", BLOCK, following, 0)
        if full_crc:
            body = body.ljust(BLOCK - 16, b"\0")
        image += tag(259, base + index, body).ljust(BLOCK, b"\0")

    def icb(index: int) -> int:
        return entry_block if index == chain else base + index

    def fid(name: bytes, block: int, characteristics: int) -> bytes:
        body = struct.pack("<HBB", 1, characteristics, len(name))
        body += struct.pack("<IIH6x", BLOCK, block, 0)
        body += struct.pack("<H", 0) + name
        body += bytes((-(16 + len(body))) % 4)
        return tag(257, 0, body)

    root_block = root.location // BLOCK - _PARTITION_START
    targets = [first] * count + list(extra)
    data = fid(b"", root_block, 0x0A) + b"".join(
        fid(b"\x08%06d" % number, icb(index), 0) for number, index in enumerate(targets)
    )
    directory_block = len(image) // BLOCK - _PARTITION_START
    image += data.ljust(-(-len(data) // BLOCK) * BLOCK, b"\0") + bytes(BLOCK)
    length = len(image) // BLOCK - _PARTITION_START
    for block in (33, 49):  # the main and reserve Partition Descriptors
        descriptor = bytearray(image[block * BLOCK : (block + 1) * BLOCK])
        struct.pack_into("<I", descriptor, 192, length)
        image[block * BLOCK : (block + 1) * BLOCK] = retag(descriptor)
    entry = bytearray(image[root.location : root.location + BLOCK])
    struct.pack_into("<Q", entry, 56, len(data))
    struct.pack_into("<II", entry, 176, len(data), directory_block)
    image[root.location : root.location + BLOCK] = retag(entry)
    return bytes(image)


def test_file_identifiers_naming_one_indirect_chain_read_it_once() -> None:
    """Many File Identifiers can name one ICB. Each ICB is parsed once: 200 names on
    a chain of 63 Indirect Entries read 64 entry blocks, not 200 times as many."""
    image = _fan_out(200, chain=63)
    reads: list[int] = []

    def read_at(offset: int, n: int) -> bytes:
        reads.append(offset)
        return image[offset : offset + n]

    volume = UdfVolume(read_at, len(image), archive_name=None, budget=None)
    assert len(volume.names) == 200
    assert {name.entry.location for name in volume.names} == {
        volume.names[0].entry.location
    }
    assert len(reads) < 150
    with open_archive(io.BytesIO(image)) as reader:
        assert [member.size for member in reader.members()] == [10] * 200


def _weight(image: bytes) -> int:
    weigh = _Weigh()
    UdfVolume(
        lambda offset, n: image[offset : offset + n],
        len(image),
        archive_name=None,
        budget=weigh,
    )
    return weigh.nbytes


def test_indirect_entries_and_descriptor_crcs_are_weighed() -> None:
    """An Indirect Entry is weighed as its tag and what its CRC covers, and a File
    Entry as what its CRC covers when that is more than it declares: the CRC is
    work done on every byte it covers."""
    plain = _weight(_fan_out(1, chain=0))
    chained = _weight(_fan_out(1, chain=63))
    assert chained - plain == 63 * (16 + 36)
    full = _weight(_fan_out(1, chain=63, full_crc=True))
    # 63 whole blocks, and the File Entry's whole block instead of the 184 bytes
    # (176 fixed, one short allocation descriptor) it declares.
    assert full - plain == 63 * BLOCK + BLOCK - 184
    # Named again, a parsed chain is not weighed again.
    # 48 bytes per File Identifier: 38 fixed, a 7-byte name, padding to 4.
    assert _weight(_fan_out(50, chain=63, full_crc=True)) - full == 49 * 48
    cap = ListingLimits(max_metadata_bytes=plain + BLOCK)
    image = _fan_out(1, chain=63, full_crc=True)
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes.*UDF"):
        open_archive(io.BytesIO(image), config=ArchiveyConfig(listing_limits=cap))


def test_a_chain_running_into_one_already_followed_is_counted_whole() -> None:
    """The bound of 64 indirect entries holds for a chain that ends in one parsed
    before: 63 entries pass, the 64th refuses as an uncached walk would."""
    assert len(_volume(_fan_out(1, chain=64, first=1)).names) == 1
    with pytest.raises(CorruptionError, match="chain too long"):
        _volume(_fan_out(1, chain=64, first=1, extra=(0,)))
    with pytest.raises(CorruptionError, match="chain too long"):
        _volume(_fan_out(1, chain=64))


def _nested(depth: int, name: bytes = b"\x08a") -> bytes:
    """A UDF-only image of ``depth`` nested directories, each named ``name`` (a CS0
    dstring): one File Entry block per level, its directory data inside the entry."""
    image = bytearray(build_udf(directory("")))
    root_at = _volume(bytes(image)).root.location
    template = image[root_at : root_at + 176]  # a File Entry's fixed part
    start = 300  # the builder's partition start, in blocks

    def fid(name: bytes, block: int, characteristics: int) -> bytes:
        body = struct.pack("<HBB", 1, characteristics, len(name))
        body += struct.pack("<IIH6x", BLOCK, block, 0)
        body += struct.pack("<H", 0) + name
        body += bytes((-(16 + len(body))) % 4)
        return tag(257, 0, body)

    def entry(block: int, data: bytes) -> bytes:
        fields = bytearray(template)
        struct.pack_into("<H", fields, 16 + 18, 3)  # data inside the entry
        struct.pack_into("<Q", fields, 56, len(data))
        struct.pack_into("<II", fields, 168, 0, len(data))
        fields += data
        struct.pack_into("<H", fields, 10, len(fields) - 16)
        struct.pack_into("<I", fields, 12, block)
        return retag(fields).ljust(BLOCK, b"\0")

    root = root_at // BLOCK - start
    base = len(image) // BLOCK - start
    levels = []
    parent = root
    for level in range(depth):
        block = base + level
        child = fid(name, block + 1, 0x02) if level < depth - 1 else b""
        levels.append(entry(block, fid(b"", parent, 0x0A) + child))
        parent = block
    image[root_at : root_at + BLOCK] = entry(
        root, fid(b"", root, 0x0A) + fid(name, base, 0x02)
    )
    image += b"".join(levels) + bytes(BLOCK)
    length = len(image) // BLOCK - start
    for block in (33, 49):  # the main and reserve Partition Descriptors
        descriptor = bytearray(image[block * BLOCK : (block + 1) * BLOCK])
        struct.pack_into("<I", descriptor, 192, length)
        image[block * BLOCK : (block + 1) * BLOCK] = retag(descriptor)
    return bytes(image)


def test_the_full_paths_of_a_deep_tree_are_weighed_at_open() -> None:
    """Every full path is built at open, and nested directories make them grow with
    the square of the depth: each path, text and stored bytes, is weighed as it is
    built, apart from the tree's bytes."""
    image = _nested(500)
    weigh = _Weigh()
    volume = UdfVolume(
        lambda offset, n: image[offset : offset + n],
        len(image),
        archive_name=None,
        budget=weigh,
    )
    assert len(volume.names) == 500
    assert weigh.path_bytes == sum(
        len(name.path) + len(name.raw_path) for name in volume.names
    )
    assert weigh.nbytes < 200_000 < weigh.path_bytes
    cap = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=200_000))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=200000.*paths"):
        open_archive(io.BytesIO(image), config=cap)
    roomy = ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=weigh.path_bytes)
    )
    with open_archive(io.BytesIO(image), config=roomy) as reader:
        assert reader.info.extra["iso.namespace"] == "udf"


def test_a_non_ascii_path_is_weighed_as_the_listing_weighs_its_name() -> None:
    """The text of a path is weighed by the listing's rule for a name: 4 bytes a
    character when it is not ASCII. The stored bytes are 2 a character here."""
    image = _nested(300, "é".encode("utf-16_be").join((b"\x10", b"")))
    volume = _volume(image)
    assert volume.names[-1].path == "/".join(["é"] * 300)
    stored = sum(len(name.raw_path) for name in volume.names)
    text = sum(len(name.path) for name in volume.names)
    weight = 4 * text + stored
    over = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=weight - 1))
    with pytest.raises(ResourceLimitError, match="bytes of paths"):
        open_archive(io.BytesIO(image), config=over)
    exact = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=weight))
    open_archive(io.BytesIO(image), config=exact).close()


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


@requires("pycdlib")
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


@requires("pycdlib")
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


@requires("pycdlib")
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
    version = sevenzip_version()
    if version is None or version < (23, 0):
        # The image has a UDF 2.50 metadata partition and the listing asks for UTF-8
        # (-scc); p7zip 16.02 (Homebrew's 7z on macOS) exits 2 on it. 23.01 is what
        # the builder was checked against.
        pytest.skip(
            f"requires 7-Zip 23 or later, found {sevenzip_version_text(version)}"
        )
    image = build_udf(
        directory("", directory("d", Node("f", b"x")), Node("Ünï ✓", b"y")),
        metadata=True,
    )
    path = tmp_path / "disc.udf"
    path.write_bytes(image)
    result = run_7z(["l", "-tudf", "-slt", "-sccUTF-8", str(path)], check=True)
    paths = sorted(
        line.removeprefix("Path = ").replace("\\", "/")
        for line in result.stdout.decode().splitlines()
        if line.startswith("Path = ") and line != f"Path = {path}"
    )
    with open_archive(io.BytesIO(image)) as reader:
        ours = sorted(m.name.rstrip("/") for m in reader.members())
    assert paths == ours
