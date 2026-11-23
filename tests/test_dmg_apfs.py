"""The DMG reader on APFS containers (plan Part E, ``internal/backends/apfs.py``).

The ``hdiutil`` fixtures in ``tests/fixtures/external/dmg_hdiutil/`` are the truth for
what a real image holds: macOS's own listing and hashes of the mounted volume are beside
them. ``tests/apfs_build.py`` writes the rest: plain and hashed keys, several volumes,
sparse files and clones, and the damage no tool writes.
"""

from __future__ import annotations

import hashlib
import io
import struct
import unicodedata
from array import array
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CorruptionError,
    DiagnosticCode,
    ListingLimits,
    MemberType,
    ResourceLimitError,
    UnsupportedFeatureError,
    Verification,
    open_archive,
)
from archivey.formats import ReaderSource
from archivey.internal.backends import apfs
from tests import apfs_build as a, dmg_build as d
from tests.conftest import requires

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"

_APFS_IMAGES = {
    "apfs-UDZO.dmg": ["zlib"],
    "apfs-UDBZ.dmg": ["bzip2"],
    "apfs-ULFO.dmg": ["lzfse"],
    "apfs-ULMO.dmg": ["xz"],
    "apfs-UDRO.dmg": ["raw"],
}
# The encrypted ones (password "archivey"): UDZO images inside the encrcdsa layer.
_APFS_ENCRYPTED = {
    "apfs-UDZO-AES-128.dmg": ["zlib"],
    "apfs-UDZO-AES-256.dmg": ["zlib"],
}


def _open(image: bytes, **kwargs: object):
    return open_archive(io.BytesIO(image), **kwargs)  # type: ignore[arg-type]


def _codes(reader) -> list[DiagnosticCode]:
    return [diag.code for diag in reader.diagnostics.retained]


def _read_all(image: bytes, **kwargs: object) -> tuple[dict, dict[str, bytes]]:
    with _open(image, **kwargs) as reader:
        members = {m.name: m for m in reader.members()}
        data = {n: reader.read(m) for n, m in members.items() if m.is_file}
    return members, data


def _listed_until_error(image: bytes, error: type[Exception], match: str) -> list[str]:
    """The members listed before the listing raises ``error``."""
    seen: list[str] = []
    with _open(image) as reader, pytest.raises(error, match=match):
        for member in reader:
            seen.append(member.name)
    return seen


# ── The hdiutil fixtures ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(n, marks=requires("cryptography")) if "-AES-" in n else n
        for n in sorted({**_APFS_IMAGES, **_APFS_ENCRYPTED})
    ],
)
def test_an_hdiutil_apfs_image_lists_and_reads_as_macos_mounts_it(name: str) -> None:
    hashes = {}
    for line in (
        (_FIXTURES / "apfs-sha256.txt").read_text(encoding="utf-8").splitlines()
    ):
        digest, path = line.split(None, 1)
        hashes[path.removeprefix("./")] = digest
    encrypted = name in _APFS_ENCRYPTED
    password = "archivey" if encrypted else None
    with open_archive(_FIXTURES / name, password=password) as reader:
        members = {m.name: m for m in reader.members()}
        info = reader.info
        assert info.is_encrypted is encrypted
        assert all(m.is_encrypted is encrypted for m in members.values())
        files = {
            n: hashlib.sha256(reader.read(m)).hexdigest()
            for n, m in members.items()
            if m.type is MemberType.FILE
        }
        assert not _codes(reader)
    # APFS keeps names as written: café.txt is composed here, decomposed on HFS+.
    cafe = unicodedata.normalize("NFC", "sub dir/café.txt")
    assert cafe in members
    assert sorted(members) == sorted(
        [
            "Applications",
            "compressed.txt",
            "hello.txt",
            "link-rel",
            "random.bin",
            "sub dir/",
            cafe,
            "sub dir/hardlink.txt",
            "text.txt",
        ]
    )
    assert files == {
        unicodedata.normalize("NFC", p): h
        for p, h in hashes.items()
        if p != "sub dir/hardlink.txt"
    }
    link = members["sub dir/hardlink.txt"]
    assert link.type is MemberType.HARDLINK
    assert link.link_target == "hello.txt"
    assert members["Applications"].link_target == "/Applications"
    assert members["link-rel"].link_target == "hello.txt"
    compressed = members["compressed.txt"]
    assert compressed.size == 360_000
    assert "com.apple.decmpfs" not in compressed.extra["dmg.xattrs"]
    assert "com.apple.ResourceFork" not in compressed.extra["dmg.xattrs"]
    assert "com.apple.fs.symlink" not in members["link-rel"].extra["dmg.xattrs"]
    assert members["hello.txt"].extra["dmg.xattrs"]["com.example.test"] == (
        b"xattr value"
    )
    assert members["hello.txt"].mode == 0o644
    assert members["hello.txt"].modified is not None
    assert info.format is ArchiveFormat.DMG
    assert info.extra["dmg.filesystem"] == "APFS"
    assert info.extra["dmg.volume_name"] == "Fixture"
    assert info.extra["dmg.apfs_volumes"] == ["Fixture"]
    assert info.extra["dmg.run_codecs"] == {**_APFS_IMAGES, **_APFS_ENCRYPTED}[name]


# ── Builder images ───────────────────────────────────────────────────────────────────

_TEXT = b"The quick brown fox jumps over the lazy dog.\n" * 4000
_BIG = bytes(range(256)) * 1200
_SPARSE = b"a" * 4096 + bytes(8192) + b"b" * 4096 + bytes(4096)


def _tree() -> list[d.Node]:
    nodes = [
        d.Node(
            "hello.txt",
            data=b"hello dmg\n",
            mtime=1_600_000_000,
            xattrs={"com.example.small": b"v", "user.big": b"x" * 5000},
        ),
        d.Node("frag.bin", data=_BIG, fragment=12),
        d.Node("clone.bin", data=_BIG),
        d.Node("sparse.bin", data=_SPARSE),
        d.Node("a/first.txt", data=b"linked content\n"),
        d.Node("b/second.txt", kind="hardlink", target="a/first.txt"),
        d.Node("link", kind="symlink", target="hello.txt"),
        d.Node("empty", kind="dir"),
        d.Node("fifo", kind="fifo"),
        d.Node("rsrc.txt", data=b"data fork", resource_fork=b"resource fork bytes"),
    ]
    for kind in (3, 4, 7, 8, 9, 10, 11, 12):
        data = _TEXT[:300] if kind in (3, 7, 9, 11) else _TEXT
        nodes.append(d.Node(f"comp/t{kind}.txt", data=data, compression=kind))
    return nodes


def _expected() -> dict[str, bytes]:
    return {n.path: n.data for n in _tree() if n.kind == "file"}


def _container(**options: object) -> a.Apfs:
    defaults: dict[str, object] = {
        "name": "Vol",
        "holes": {"sparse.bin": [(4096, 4096)]},
        "zero_extents": {"sparse.bin": [(8192, 4096)]},
        "clones": {"clone.bin": "frag.bin"},
    }
    defaults.update(options)
    nodes = defaults.pop("nodes", None) or _tree()
    return a.write_apfs(nodes, **defaults)  # type: ignore[arg-type]


@pytest.mark.parametrize("hashed", [True, False], ids=["hashed", "plain"])
@pytest.mark.parametrize("layout", ["gpt", "apm", "none"])
def test_every_layout_and_key_kind_reads(layout: str, hashed: bool) -> None:
    image = a.apfs_dmg(_container(hashed=hashed).container, layout=layout)
    members, data = _read_all(image)
    assert data == _expected()
    second = members["b/second.txt"]
    assert second.type is MemberType.HARDLINK
    assert second.link_target == "a/first.txt"
    assert members["link"].link_target == "hello.txt"
    assert members["fifo"].type is MemberType.OTHER
    assert members["fifo"].extra["special_file_type"] == "fifo"
    assert members["empty/"].type is MemberType.DIRECTORY
    hello = members["hello.txt"]
    assert hello.extra["dmg.xattrs"] == {"com.example.small": b"v", "user.big": None}
    assert members["rsrc.txt"].extra["dmg.resource_fork_size"] == 19
    assert hello.modified is not None and hello.modified.year == 2020


@pytest.mark.parametrize(
    "codec", [d.RAW, d.ZLIB, d.BZIP2, d.LZMA, d.ADC, d.LZFSE], ids=hex
)
def test_every_run_codec_reads(codec: int) -> None:
    _, data = _read_all(a.apfs_dmg(_container().container, codec=codec))
    assert data == _expected()


def test_holes_and_zero_extents_read_as_zeros() -> None:
    members, data = _read_all(a.apfs_dmg(_container().container))
    assert data["sparse.bin"] == _SPARSE
    assert members["sparse.bin"].is_sparse is True
    assert members["frag.bin"].is_sparse is False


def test_a_clone_shares_its_source_blocks_and_reads_the_same() -> None:
    written = _container()
    assert written.data_blocks["clone.bin"] == written.data_blocks["frag.bin"]
    _, data = _read_all(a.apfs_dmg(written.container))
    assert data["clone.bin"] == data["frag.bin"] == _BIG


def test_random_access_reads_inside_a_large_file() -> None:
    big = bytes(range(251)) * 12_000
    image = a.apfs_dmg(a.write_apfs([d.Node("big.bin", data=big)]).container)
    with (
        _open(image, seekable_members=True) as reader,
        reader.open("big.bin") as stream,
    ):
        stream.seek(2_500_000)
        assert stream.read(1000) == big[2_500_000:2_501_000]


def test_several_volumes_list_under_their_names() -> None:
    container = a.write_apfs(
        [d.Node("readme.txt", data=b"in Data\n")],
        name="Data",
        more_volumes=[("Data", [d.Node("readme.txt", data=b"in the second\n")])],
    )
    with _open(a.apfs_dmg(container.container)) as reader:
        data = {m.name: reader.read(m) for m in reader.members() if m.is_file}
        assert reader.info.extra["dmg.apfs_volumes"] == ["Data", "Data"]
        assert "dmg.volume_name" not in reader.info.extra
    assert data == {
        "Data/readme.txt": b"in Data\n",
        "Data 1/readme.txt": b"in the second\n",
    }


def test_apfs_beside_hfs_lists_both_under_their_names() -> None:
    hfs = d.write_hfsplus([d.Node("old.txt", data=b"hfs")], name="Old")
    container = a.write_apfs([d.Node("new.txt", data=b"apfs")], name="New")
    disk = d.write_gpt(
        [
            d.Partition(hfs.volume, name="Old"),
            d.Partition(container.container, name="New", gpt_type=d.APFS_GUID),
        ]
    )
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        data = {m.name: reader.read(m) for m in reader.members() if m.is_file}
        assert reader.info.extra["dmg.volumes"] == ["Old", "New"]
    assert data == {"Old/old.txt": b"hfs", "New/new.txt": b"apfs"}


# ── Checkpoints and object maps ──────────────────────────────────────────────────────


def test_a_newer_checkpoint_with_a_bad_checksum_is_passed_over() -> None:
    image = a.apfs_dmg(_container(newer_checkpoint="bad-checksum").container)
    with _open(image) as reader:
        assert reader.read("hello.txt") == b"hello dmg\n"
        assert not _codes(reader)


def test_an_incomplete_newer_checkpoint_is_reported_and_the_older_one_read() -> None:
    image = a.apfs_dmg(_container(newer_checkpoint="missing-map").container)
    with _open(image) as reader:
        assert reader.read("hello.txt") == b"hello dmg\n"
        structures = [
            diag.context.structure
            for diag in reader.diagnostics.retained
            if diag.code is DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT
        ]
    assert structures == ["apfs_checkpoint"]


def _source(data: bytes) -> ReaderSource:
    def view(start: int, length: int | None) -> io.BytesIO:
        end = len(data) if length is None else start + length
        return io.BytesIO(data[start:end])

    return ReaderSource(view, len(data), None, lambda o, n: data[o : o + n])


def test_an_object_deleted_after_a_transaction_is_found_before_it() -> None:
    layout = a._Layout(next=1)
    records = [
        (struct.pack("<QQ", 500, 10), struct.pack("<IIQ", 0, 4096, 77)),
        (struct.pack("<QQ", 500, 11), struct.pack("<IIQ", 1, 4096, 0)),  # deleted
    ]
    root, _ = a._omap_tree(layout, records, 10, None)
    at = layout.take()
    body = bytearray(4096)
    struct.pack_into("<IIIIQ", body, 32, 0, 0, a.PHYSICAL | 2, a.PHYSICAL | 2, root)
    layout.blocks[at] = a._object(body, at, 10, a.PHYSICAL | a.T_OMAP)
    raw = bytearray(4096 * (layout.next + 1))
    for where, block in layout.blocks.items():
        raw[where * 4096 : where * 4096 + 4096] = block
    blocks = apfs._Blocks(_source(bytes(raw)), 4096, layout.next + 1)

    def omap(xid: int) -> apfs._Omap:
        return apfs._Omap(blocks, at, xid, "the map", lambda n, w: None)

    assert omap(10).lookup(500) == (77, 0)
    assert omap(11).lookup(500) is None
    assert omap(11).lookup(501) is None


def test_the_damage_index_finds_what_a_scan_of_every_range_finds() -> None:
    import random

    rng = random.Random(7)

    def key() -> tuple[int, ...]:
        return tuple(rng.randrange(6) for _ in range(rng.randrange(1, 4)))

    for _ in range(300):
        index = apfs.DamageIndex()
        ranges = []
        for _ in range(rng.randrange(8)):
            low = None if rng.random() < 0.15 else key()
            high = None if rng.random() < 0.15 else key()
            if low is not None and high is not None and high < low:
                low, high = high, low
            index.append(apfs.Damage(low, high, 0, ""))
            ranges.append((low, high))
        prefix = key()[:2]
        n = len(prefix)
        expected = any(
            (low is None or low[:n] <= prefix) and (high is None or high[:n] >= prefix)
            for low, high in ranges
        )
        assert (index.first_holding(prefix) is not None) == expected, (ranges, prefix)


def _flip(
    address: Callable[[bytearray, a.Apfs], int],
) -> Callable[[bytearray, a.Apfs], None]:
    def patch(container: bytearray, info: a.Apfs) -> None:
        container[address(container, info) * info.block_size + 3000] ^= 0x5A

    return patch


def _omap_of_volume(container: bytearray, info: a.Apfs) -> int:
    at = info.volume_superblocks[0] * info.block_size
    return struct.unpack_from("<Q", container, at + 128)[0]


def _tree_of(container: bytearray, omap_object: int, block_size: int) -> int:
    return struct.unpack_from("<Q", container, omap_object * block_size + 48)[0]


_OBJECTS = {
    "checkpoint superblock": lambda c, i: i.checkpoint_superblock,
    "checkpoint map": lambda c, i: i.checkpoint_superblock - 1,
    "container object map": lambda c, i: i.container_omap,
    "container object map tree": lambda c, i: _tree_of(
        c, i.container_omap, i.block_size
    ),
    "volume superblock": lambda c, i: i.volume_superblocks[0],
    "volume object map": _omap_of_volume,
    "volume object map tree": lambda c, i: _tree_of(
        c, _omap_of_volume(c, i), i.block_size
    ),
    "filesystem root": lambda c, i: i.fs_root,
}


@pytest.mark.parametrize("what", sorted(_OBJECTS))
def test_a_checksum_failure_in_any_object_is_corruption(what: str) -> None:
    image = a.apfs_dmg(_container(patch=_flip(_OBJECTS[what])).container)
    with _open(image) as reader, pytest.raises(CorruptionError, match="APFS"):
        reader.members()


def test_a_damaged_block_0_is_refused_at_open() -> None:
    image = a.apfs_dmg(_container(patch=_flip(lambda c, i: 0)).container)
    with pytest.raises(CorruptionError, match="block 0"):
        _open(image)


def test_a_checkpoint_area_over_the_scan_budget_is_a_resource_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Raw runs: every block the scan reads is read from the file and counted (a
    # decoded run is counted once, when it is decoded).
    monkeypatch.setattr(apfs, "SCAN_BUDGET", 4 * 4096)
    image = a.apfs_dmg(_container().container, codec=d.RAW)
    with _open(image) as reader, pytest.raises(ResourceLimitError, match="checkpoint"):
        reader.members()


def test_a_checkpoint_area_in_zero_fill_runs_counts_against_the_scan_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Descriptor blocks of zeros are stored as zero-fill runs, which read nothing
    # from the file; the scan still checks each one, so each counts.
    monkeypatch.setattr(apfs, "SCAN_BUDGET", 4 * 4096)
    written = _container()

    def zero_ring(container: bytearray, info: a.Apfs) -> None:
        size = info.block_size
        container[size : size * (1 + a.DESC_BLOCKS)] = bytes(size * a.DESC_BLOCKS)

    broken = _container(patch=zero_ring)
    assert written.block_size == broken.block_size
    # One run per block, so the zeroed blocks are runs of their own.
    image = a.apfs_dmg(broken.container, codec=d.RAW, run_sectors=8)
    with _open(image) as reader, pytest.raises(ResourceLimitError, match="checkpoint"):
        reader.members()


# ── Damaged nodes (D7) ───────────────────────────────────────────────────────────────


def test_a_damaged_leaf_delivers_every_member_outside_it() -> None:
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x" * (i + 1)) for i in range(60)]
    written = a.write_apfs(nodes, leaf_records=8)
    assert len(written.fs_leaves) > 4
    middle = written.fs_leaves[len(written.fs_leaves) // 2]
    broken = a.write_apfs(nodes, leaf_records=8, patch=_flip(lambda c, i: middle))
    seen = _listed_until_error(
        a.apfs_dmg(broken.container), CorruptionError, "cannot be used"
    )
    assert 30 < len(seen) < 60


def _children_missing(container: bytearray, info: a.Apfs) -> None:
    """Point every child of the filesystem root at a virtual id the object map does
    not hold, so each one is a damaged range."""
    size = info.block_size
    at = info.fs_root * size
    _, _, count, toc_at, _ = struct.unpack_from("<HHIHH", container, at + 32)
    toc = at + 56 + toc_at
    values_end = at + size - 40
    for i in range(count):
        _, _, value_at, _ = struct.unpack_from("<HHHH", container, toc + 8 * i)
        struct.pack_into("<Q", container, values_end - value_at, 0xFFFF_FFF0 + i)
    a.reseal(container, info.fs_root, size)


def test_damaged_ranges_count_against_max_metadata_bytes_as_they_are_found() -> None:
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x") for i in range(100)]
    written = a.write_apfs(nodes, leaf_records=4, patch=_children_missing)
    assert len(written.fs_leaves) > 90
    image = a.apfs_dmg(written.container)
    with _open(image) as reader, pytest.raises(CorruptionError, match="cannot be used"):
        reader.members()
    # Each lost child is a range of about 250 bytes; a cap that holds the object map
    # but not 90 of them stops the walk.
    limits = ListingLimits(max_metadata_bytes=20_000)
    with (
        _open(image, config=ArchiveyConfig(listing_limits=limits)) as reader,
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
    ):
        reader.members()


def test_a_damaged_leaf_error_also_names_the_first_other_problem() -> None:
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x") for i in range(60)]
    nodes.append(d.Node("bad", data=b"b", raw_name=b"x/y"))
    options = {"leaf_records": 8, "hashed": False}
    written = a.write_apfs(nodes, **options)  # type: ignore[arg-type]
    middle = written.fs_leaves[len(written.fs_leaves) // 2]
    broken = a.write_apfs(nodes, patch=_flip(lambda c, i: middle), **options)  # type: ignore[arg-type]
    with (
        _open(a.apfs_dmg(broken.container)) as reader,
        pytest.raises(CorruptionError) as raised,
    ):
        reader.members()
    message = str(raised.value)
    assert "cannot be used" in message
    assert "also, a directory record names 'x/y'" in message


def test_a_lost_extent_leaf_fails_only_that_file_and_never_reads_zeros() -> None:
    nodes = [
        d.Node("A", data=b"a" * 4096 + bytes(4096) + b"b" * 4096),
        d.Node("B", data=b"B" * 9000),
        d.Node("C", data=b"C" * 5000),
    ]
    options = {
        "hashed": False,
        "holes": {"A": [(4096, 4096)]},
        "split_before": [("B", apfs.EXTENT), ("C", apfs.INODE)],
    }
    written = a.write_apfs(nodes, **options)  # type: ignore[arg-type]
    assert len(written.fs_leaves) == 3
    # Leaf 2 holds B's extents and nothing else; B's inode id is its stream id.
    assert written.inodes["B"] == written.streams["B"]
    leaf = written.fs_leaves[1]
    broken = a.write_apfs(nodes, patch=_flip(lambda c, i: leaf), **options)  # type: ignore[arg-type]
    with _open(a.apfs_dmg(broken.container)) as reader:
        listed = {}
        with pytest.raises(CorruptionError, match="cannot be used"):
            for member in reader:
                listed[member.name] = member
        assert sorted(listed) == ["A", "B", "C"]
        assert reader.read(listed["A"]) == b"a" * 4096 + bytes(4096) + b"b" * 4096
        assert reader.read(listed["C"]) == b"C" * 5000
        with pytest.raises(CorruptionError, match="damaged node"):
            reader.read(listed["B"])


def test_a_read_from_a_known_hole_into_a_lost_extent_raises() -> None:
    # A: an extent at 0, a hole, then an extent at 8192 that sits alone in a leaf
    # which is then damaged. The zeros served for the hole must not run on over the
    # lost extent.
    data = b"a" * 4096 + bytes(4096) + b"b" * 4096
    nodes = [d.Node("A", data=data), d.Node("Z", data=b"z")]
    options = {
        "hashed": False,
        "holes": {"A": [(4096, 4096)]},
        "split_before": [("A", apfs.EXTENT, 8192), ("Z", apfs.INODE)],
    }
    written = a.write_apfs(nodes, **options)  # type: ignore[arg-type]
    assert len(written.fs_leaves) == 3
    leaf = written.fs_leaves[1]
    broken = a.write_apfs(nodes, patch=_flip(lambda c, i: leaf), **options)  # type: ignore[arg-type]
    with _open(a.apfs_dmg(broken.container)) as reader:
        listed = {}
        with pytest.raises(CorruptionError, match="cannot be used"):
            for member in reader:
                listed[member.name] = member
        assert reader.read(listed["Z"]) == b"z"
        with pytest.raises(CorruptionError, match="damaged node"):
            reader.read(listed["A"])


# ── What a data stream costs ─────────────────────────────────────────────────────────


class _Stub:
    """The parts of a volume ``stream_reader`` uses: a container of ``count`` blocks
    whose every byte is zero."""

    def __init__(self, count: int = 1 << 40) -> None:
        self.container = self
        self._blocks = apfs._Blocks(self, 4096, count)  # type: ignore[arg-type]
        self.source = self

    def read_exact(self, offset: int, n: int) -> bytes:
        return bytes(n)


def test_inodes_sharing_one_data_stream_check_its_extents_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = 40
    nodes = [d.Node(f"f{i:02d}", data=b"same") for i in range(files)]

    def share(records: list) -> None:
        inodes = [r for r in records if r.kind == apfs.INODE and r.path]
        shared = inodes[0].oid
        for rec in inodes:
            value = bytearray(rec.value)
            struct.pack_into("<Q", value, 8, shared)  # private_id: the stream
            rec.value = bytes(value)
        for i in range(1, 101):  # sparse extents past the data, as many as fit
            key = struct.pack("<QQ", shared | apfs.EXTENT << 60, i * 4096)
            value = struct.pack("<QQQ", 4096, 0, 0)
            records.append(a._Record(shared, apfs.EXTENT, (i * 4096,), key, value))

    checked: list[int] = []
    check = apfs._check_stream

    def counted(flat, damage, stream, bs, count):  # type: ignore[no-untyped-def]
        checked.append(stream)
        return check(flat, damage, stream, bs, count)

    monkeypatch.setattr(apfs, "_check_stream", counted)
    members, data = _read_all(
        a.apfs_dmg(a.write_apfs(nodes, patch_records=share).container)
    )
    assert sorted(data) == [f"f{i:02d}" for i in range(files)]
    assert set(data.values()) == {b"same"}
    assert not any(m.is_sparse for m in members.values())
    # One check of the 101 extents serves the listing and every read.
    assert len(checked) == 1


def test_a_stream_check_is_kept_and_charged_only_when_it_is_costly() -> None:
    charged: list[int] = []
    tree = apfs.FsTree(charged.append)
    few = apfs._KEPT_VIEW_MIN // 2
    many = apfs._KEPT_VIEW_MIN + 1
    tree.extents[16] = array("Q", [x for i in range(few) for x in (i * 4096, 4096, 7)])
    tree.extents[17] = array("Q", [x for i in range(many) for x in (i * 4096, 4096, 7)])
    for _ in range(3):
        apfs.stream_reader(_Stub(), tree, 16, few * 4096, "few")  # type: ignore[arg-type]
        apfs.stream_reader(_Stub(), tree, 17, many * 4096, "many")  # type: ignore[arg-type]
    assert list(tree.stream_views) == [17]
    assert charged == [apfs._VIEW_COST]


def test_a_kept_stream_check_raises_for_every_file_that_opens_the_stream() -> None:
    tree = apfs.FsTree()
    flat = [x for i in range(40) for x in (i * 4096, 4096, 7)]
    flat[-3] = 0  # the last extent starts inside the first: overlapping
    tree.extents[16] = array("Q", flat)
    for name in ("one", "two"):
        with pytest.raises(CorruptionError, match=f"^{name} has overlapping extents"):
            apfs.stream_reader(_Stub(), tree, 16, 4096, name)  # type: ignore[arg-type]
    assert 16 in tree.stream_views


class _Counted(int):
    """An offset that counts how often it is compared."""

    compared = 0

    def __lt__(self, other: object) -> bool:
        _Counted.compared += 1
        return int(self) < other  # type: ignore[operator]

    def __gt__(self, other: object) -> bool:
        _Counted.compared += 1
        return int(self) > other  # type: ignore[operator]


def _paired_damage(pairs: int) -> tuple[apfs.FsTree, list[apfs.Damage], int]:
    """A stream of ``pairs`` pairs of contiguous extents, each pair followed by a gap
    of two blocks, and a damaged range between the two extents of each pair: no gap
    is one a lost extent could fill, so every read succeeds."""
    bs = 4096
    stream = 16
    flat: list[int] = []
    ranges: list[apfs.Damage] = []
    for k in range(pairs):
        base = k * 4 * bs
        flat += [base, bs, 0, base + bs, bs, 0]
        low = (stream, apfs.EXTENT, _Counted(base + 1))
        high = (stream, apfs.EXTENT, _Counted(base + bs))
        ranges.append(apfs.Damage(low, high, 99, "x"))
    tree = apfs.FsTree()
    tree.extents[stream] = array("Q", flat)
    return tree, ranges, pairs * 4 * bs


def test_reading_the_holes_of_a_stream_with_damaged_ranges_is_not_quadratic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pairs = 300
    tree, ranges, size = _paired_damage(pairs)
    # The ranges as the damage index yields them, with offsets that count compares.
    monkeypatch.setattr(tree.damage, "holding", lambda prefix: iter(ranges))
    _Counted.compared = 0
    read, sparse = apfs.stream_reader(_Stub(), tree, 16, size, "f")  # type: ignore[arg-type]
    assert sparse
    assert read(0, size) == bytes(size)
    # A scan of every range for each of the 300 gaps compares 90,000 times or more;
    # a bisection, a few times the log of the ranges per gap.
    assert _Counted.compared < 20 * pairs


def test_a_hole_raises_for_the_first_damaged_range_a_scan_finds() -> None:
    import random

    rng = random.Random(11)
    bs = 4096
    for _ in range(300):
        flat: list[int] = []
        at = 0
        for _ in range(rng.randrange(6)):
            at += bs * rng.randrange(3)
            flat += [at, bs, 0]
            at += bs
        size = at + bs * rng.randrange(3)
        tree = apfs.FsTree()
        tree.extents[16] = array("Q", flat)
        for i in range(rng.randrange(5)):
            low = rng.randrange(size + 1)
            high = low + rng.randrange(1, 3 * bs)
            tree.damage.append(
                apfs.Damage((16, apfs.EXTENT, low), (16, apfs.EXTENT, high), i, "x")
            )
        if rng.random() < 0.2:
            tree.damage.append(apfs.Damage((16, apfs.EXTENT, size), None, 9, "x"))
        lost = []
        for each in tree.damage.holding((16, apfs.EXTENT)):
            assert each.low is not None
            low = each.low[2] if each.low[:2] == (16, apfs.EXTENT) else 0
            high = each.high[2] if each.high is not None else float("inf")
            lost.append((low, high, each.address))
        starts = flat[0::3]
        read, _ = apfs.stream_reader(_Stub(), tree, 16, size, "f")  # type: ignore[arg-type]
        for offset in range(0, size, bs):
            # What the scan of every range found before ranges were bisected.
            index = max(0, len([s for s in starts if s <= offset]) - 1)
            end = starts[index] + bs if starts and starts[index] <= offset else offset
            if starts and starts[index] <= offset < end:
                continue
            following = next((s for s in starts if s > offset), offset + bs)
            stop = min(offset + bs, following)
            before = max((s for s in starts if s <= offset), default=-1)
            hit = next((w for lo, hi, w in lost if lo < stop and hi > before), None)
            if hit is None:
                assert read(offset, stop - offset) == bytes(stop - offset)
            else:
                with pytest.raises(CorruptionError, match=rf"\(block {hit}: x\)"):
                    read(offset, stop - offset)


def test_a_damaged_object_map_leaf_fails_the_lookups_it_held() -> None:
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x") for i in range(40)]
    options = {"leaf_records": 6, "omap_leaf_entries": 2}
    written = a.write_apfs(nodes, **options)  # type: ignore[arg-type]
    assert len(written.omap_leaves) > 2
    first = written.omap_leaves[0]
    broken = a.write_apfs(nodes, patch=_flip(lambda c, i: first), **options)  # type: ignore[arg-type]
    seen = _listed_until_error(
        a.apfs_dmg(broken.container), CorruptionError, "damaged node of the object map"
    )
    assert 0 < len(seen) < 40


def test_a_symlink_whose_target_record_is_lost_is_not_listed() -> None:
    nodes = [
        d.Node("a.txt", data=b"a"),
        d.Node("s", kind="symlink", target="a.txt"),
        d.Node("z.txt", data=b"z"),
    ]
    options = {"split_before": [("s", apfs.XATTR), ("z.txt", apfs.INODE)]}
    written = a.write_apfs(nodes, **options)  # type: ignore[arg-type]
    leaf = written.fs_leaves[1]
    broken = a.write_apfs(nodes, patch=_flip(lambda c, i: leaf), **options)  # type: ignore[arg-type]
    seen = _listed_until_error(
        a.apfs_dmg(broken.container), CorruptionError, "1 members"
    )
    assert sorted(seen) == ["a.txt", "z.txt"]


# ── Damage in an intact node ─────────────────────────────────────────────────────────


def _patched(patch: Callable[[list], None], nodes: list[d.Node] | None = None) -> bytes:
    nodes = nodes or [
        d.Node("a.txt", data=b"a" * 5000),
        d.Node("sub/b.txt", data=b"b"),
        d.Node("z.txt", data=b"z"),
    ]
    return a.apfs_dmg(a.write_apfs(nodes, hashed=False, patch_records=patch).container)


def _record(records: list, path: str, kind: int):
    return next(r for r in records if r.path == path and r.kind == kind)


def test_a_directory_reached_twice_is_listed_once_then_corruption() -> None:
    def loop(records: list) -> None:
        # A second record in sub naming sub itself.
        sub = _record(records, "sub", apfs.DIR_REC)
        inode = struct.unpack_from("<Q", sub.value)[0]
        raw = b"again\0"
        key = struct.pack("<QH", inode | apfs.DIR_REC << 60, len(raw)) + raw
        records.append(
            a._Record(inode, apfs.DIR_REC, (raw,), key, sub.value, "sub/again")
        )

    seen = _listed_until_error(_patched(loop), CorruptionError, "second time")
    assert sorted(seen) == ["a.txt", "sub/", "sub/b.txt", "z.txt"]


def test_an_entry_naming_a_missing_inode_is_corruption_after_the_others() -> None:
    def drop(records: list) -> None:
        records.remove(_record(records, "sub/b.txt", apfs.INODE))

    seen = _listed_until_error(_patched(drop), CorruptionError, "does not hold")
    assert sorted(seen) == ["a.txt", "sub/", "z.txt"]


def test_a_name_with_a_slash_is_corruption_after_the_others() -> None:
    nodes = [d.Node("a.txt", data=b"a"), d.Node("bad", data=b"b", raw_name=b"x/y")]
    seen = _listed_until_error(_patched(lambda r: None, nodes), CorruptionError, "x/y")
    assert seen == ["a.txt"]


def test_a_record_that_does_not_parse_drops_only_its_leaf() -> None:
    nodes = [d.Node(f"a{i}.txt", data=b"x") for i in range(40)]

    def cut(records: list) -> None:
        # Called for each volume's records; only the first holds a5.txt.
        rec = next(
            (r for r in records if r.path == "a5.txt" and r.kind == apfs.INODE), None
        )
        if rec is None:
            return
        records[records.index(rec)] = a._Record(
            rec.oid, rec.kind, rec.secondary, rec.key, rec.value[:20], rec.path
        )

    written = a.write_apfs(
        nodes,
        name="One",
        leaf_records=8,
        more_volumes=[("Two", [d.Node("b.txt", data=b"b")])],
        patch_records=cut,
    )
    seen = _listed_until_error(
        a.apfs_dmg(written.container), CorruptionError, "inode record is too short"
    )
    assert "Two/b.txt" in seen
    listed = [name for name in seen if name.startswith("One/a")]
    assert "One/a5.txt" not in listed
    # The members of the dropped leaf are missing; every other one is listed.
    assert 30 <= len(listed) < 39


def test_a_record_in_a_directory_the_root_does_not_reach_is_corruption() -> None:
    nodes = [
        d.Node("a.txt", data=b"a"),
        d.Node("m.txt", data=b"m"),
        d.Node("z.txt", data=b"z"),
    ]

    def move(records: list) -> None:
        rec = _record(records, "m.txt", apfs.DIR_REC)
        key = struct.pack("<Q", 9999 | apfs.DIR_REC << 60) + rec.key[8:]
        records[records.index(rec)] = a._Record(
            9999, rec.kind, rec.secondary, key, rec.value, rec.path
        )

    seen = _listed_until_error(
        _patched(move, nodes), CorruptionError, "1 directory records are in directories"
    )
    assert seen == ["a.txt", "z.txt"]


def test_a_link_count_the_sibling_links_disagree_with_is_reported() -> None:
    nodes = [
        d.Node("a/first.txt", data=b"linked\n"),
        d.Node("b/second.txt", kind="hardlink", target="a/first.txt"),
    ]

    def drop_one(records: list) -> None:
        records.remove(_record(records, "a/first.txt", apfs.SIBLING_LINK))

    for patch, expected in ((lambda r: None, 0), (drop_one, 1)):
        with _open(_patched(patch, nodes)) as reader:
            names = sorted(m.name for m in reader.members())
            found = [
                diag
                for diag in reader.diagnostics.retained
                if diag.code is DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT
            ]
        assert names == ["a/", "a/first.txt", "b/", "b/second.txt"]
        assert len(found) == expected
    assert found[0].context.structure == "link_count"
    assert "has 1 hard-link records and its inode says 2 links" in found[0].message


def _edit_extent(
    path: str, edit: Callable[[bytearray], None]
) -> Callable[[list], None]:
    def patch(records: list) -> None:
        rec = _record(records, path, apfs.EXTENT)
        value = bytearray(rec.value)
        edit(value)
        rec.value = bytes(value)

    return patch


@pytest.mark.parametrize(
    ("edit", "match"),
    [
        (lambda v: struct.pack_into("<Q", v, 8, 1 << 40), "past the container"),
        (lambda v: struct.pack_into("<Q", v, 16, 5), "encryption id"),
    ],
    ids=["past the container", "crypto id"],
)
def test_a_bad_extent_fails_that_file_only(edit: Callable, match: str) -> None:
    with _open(_patched(_edit_extent("a.txt", edit))) as reader:
        assert reader.read("z.txt") == b"z"
        with pytest.raises(CorruptionError, match=match):
            reader.read("a.txt")


def test_overlapping_extents_fail_that_file_only() -> None:
    def overlap(records: list) -> None:
        rec = _record(records, "a.txt", apfs.EXTENT)
        key = bytearray(rec.key)
        struct.pack_into("<Q", key, 8, 4096)
        records.append(
            a._Record(rec.oid, apfs.EXTENT, (4096,), bytes(key), rec.value, "a.txt")
        )

    with _open(_patched(overlap)) as reader:
        assert reader.read("z.txt") == b"z"
        with pytest.raises(CorruptionError, match="overlapping"):
            reader.read("a.txt")


def test_a_compressed_file_without_its_attribute_raises_on_read() -> None:
    nodes = [d.Node("c.txt", data=_TEXT, compression=8), d.Node("z.txt", data=b"z")]

    def drop(records: list) -> None:
        records.remove(
            next(r for r in records if r.kind == apfs.XATTR and b"decmpfs" in r.key)
        )

    with _open(_patched(drop, nodes)) as reader:
        assert reader.read("z.txt") == b"z"
        with pytest.raises(CorruptionError, match="no com.apple.decmpfs"):
            reader.read("c.txt")


def test_a_type_that_disagrees_with_the_mode_is_reported_and_the_mode_wins() -> None:
    def as_dir(records: list) -> None:
        rec = _record(records, "z.txt", apfs.DIR_REC)
        value = bytearray(rec.value)
        struct.pack_into("<H", value, 16, 4)
        rec.value = bytes(value)

    with _open(_patched(as_dir)) as reader:
        assert reader.read("z.txt") == b"z"
        assert DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT in _codes(reader)


# ── Refusals ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("options", "match"),
    [
        ({"volume_flags": 0}, "encrypted APFS volume"),
        ({"volume_incompatible": 0x21}, "sealed APFS volume"),
    ],
    ids=["encrypted", "sealed"],
)
def test_an_unreadable_volume_is_refused_by_name(options: dict, match: str) -> None:
    image = a.apfs_dmg(a.write_apfs([d.Node("a.txt", data=b"a")], **options).container)
    with _open(image) as reader, pytest.raises(UnsupportedFeatureError, match=match):
        reader.members()


def test_a_refused_volume_is_reported_once_however_often_the_listing_is_asked() -> None:
    image = a.apfs_dmg(
        a.write_apfs([d.Node("a.txt", data=b"a")], volume_flags=0).container
    )
    with _open(image) as reader:
        for _ in range(3):
            with pytest.raises(
                UnsupportedFeatureError,
                match="holds no volume archivey reads: it holds an encrypted APFS "
                "volume ",
            ):
                reader.members()
        reader.info  # noqa: B018
        unlisted = _codes(reader).count(DiagnosticCode.ARCHIVE_UNLISTED_DATA)
    assert unlisted == 1


def test_a_fusion_container_is_refused_at_open() -> None:
    container = a.write_apfs([d.Node("a.txt", data=b"a")], container_incompatible=0x102)
    with pytest.raises(UnsupportedFeatureError, match="Fusion"):
        _open(a.apfs_dmg(container.container))


def test_an_encrypted_volume_beside_a_readable_one_is_reported() -> None:
    container = a.write_apfs(
        [d.Node("a.txt", data=b"a")],
        name="Open",
        more_volumes=[("Locked", [d.Node("b.txt", data=b"b")])],
        patch=_encrypt_second_volume,
    )
    with _open(a.apfs_dmg(container.container)) as reader:
        names = [m.name for m in reader.members()]
        unlisted = [
            diag
            for diag in reader.diagnostics.retained
            if diag.code is DiagnosticCode.ARCHIVE_UNLISTED_DATA
        ]
    assert names == ["a.txt"]
    assert len(unlisted) == 1
    assert "encrypted APFS volume" in unlisted[0].message
    assert unlisted[0].context.member_name == "Locked"


def test_a_compressed_file_hides_its_decmpfs_attribute_under_every_name() -> None:
    nodes = [
        d.Node("a.txt", data=_TEXT, compression=4, xattrs={"user.tag": b"t"}),
        d.Node("b.txt", kind="hardlink", target="a.txt"),
    ]
    image = a.apfs_dmg(a.write_apfs(nodes).container)
    with _open(image) as reader:
        members = {m.name: m for m in reader.members()}
    for name in ("a.txt", "b.txt"):
        xattrs = members[name].extra["dmg.xattrs"]
        assert "user.tag" in xattrs
        assert "com.apple.decmpfs" not in xattrs


def _mark_first_volume_nodes_encrypted(container: bytearray, info: a.Apfs) -> None:
    """Set the encrypted flag on every mapping of the first volume's object map,
    which the volume's own flags say is not encrypted."""
    size = info.block_size
    for leaf in info.omap_leaves:
        at = leaf * size
        flags, _, count, toc_at, _ = struct.unpack_from("<HHIHH", container, at + 32)
        assert flags & 4  # fixed-size entries
        toc = at + 56 + toc_at
        values_end = at + size - (40 if flags & 1 else 0)
        for i in range(count):
            _, value_at = struct.unpack_from("<HH", container, toc + 4 * i)
            struct.pack_into("<I", container, values_end - value_at, 4)
        a.reseal(container, leaf, size)


def test_an_encrypted_mapping_in_a_plain_volume_does_not_stop_the_other_volumes() -> (
    None
):
    container = a.write_apfs(
        [d.Node("a.txt", data=b"a")],
        name="Broken",
        more_volumes=[("Fine", [d.Node("b.txt", data=b"b")])],
        patch=_mark_first_volume_nodes_encrypted,
    )
    seen = _listed_until_error(
        a.apfs_dmg(container.container), CorruptionError, "marks node"
    )
    assert "Fine/b.txt" in seen


def _encrypt_second_volume(container: bytearray, info: a.Apfs) -> None:
    at = info.volume_superblocks[1]
    struct.pack_into("<Q", container, at * info.block_size + 264, 0)
    a.reseal(container, at)


# ── Verify ───────────────────────────────────────────────────────────────────────────

_MARK = b"marked file content\n"


def _padding_flipper(flip: bool) -> Callable[[int, bytes], bytes]:
    """A run encoder that, when ``flip``, changes a byte in the unused end of the block
    holding ``_MARK``, after the builder took the CRC-32 of the real bytes. No member
    read reaches it."""

    def encode(kind: int, data: bytes) -> bytes:
        at = data.find(_MARK)
        if flip and at >= 0:
            at += 1000
            data = data[:at] + bytes([data[at] ^ 0xFF]) + data[at + 1 :]
        return d.encode_run(kind, data)

    return encode


@pytest.mark.parametrize("flip", [False, True], ids=["intact", "changed"])
def test_verify_all_checks_every_volume_of_an_apfs_container(flip: bool) -> None:
    container = a.write_apfs(
        [d.Node("a.txt", data=_MARK)],
        name="One",
        more_volumes=[("Two", [d.Node("b.txt", data=b"b")])],
    )
    image = a.apfs_dmg(
        container.container, codec=d.ZLIB, run_sectors=8, encode=_padding_flipper(flip)
    )
    with _open(image) as reader:
        files = [m for m in reader.members() if m.is_file]
        assert {m.name for m in files} == {"One/a.txt", "Two/b.txt"}
        assert {m.verifiable for m in files} == {Verification.CHECKSUM}
        assert reader.read("One/a.txt") == _MARK
        report = reader.verify_all()
        if not flip:
            assert report.ok, report.failures
            assert {m.verified for m in files} == {Verification.CHECKSUM}
        else:
            # The volumes share their partition's check, so both fail.
            assert {m.name for m, _ in report.failures} == {"One/a.txt", "Two/b.txt"}
            assert all("CRC-32" in str(e) for _, e in report.failures)


# ── Limits ───────────────────────────────────────────────────────────────────────────


def test_max_metadata_bytes_applies_to_the_filesystem_tree() -> None:
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x") for i in range(200)]
    image = a.apfs_dmg(a.write_apfs(nodes).container)
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=20_000))
    with (
        _open(image, config=config) as reader,
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
    ):
        reader.members()


def test_max_metadata_bytes_counts_the_kept_trees_with_the_members() -> None:
    nodes = [d.Node(f"{i:03d}" + "n" * 200, data=b"x") for i in range(100)]
    image = a.apfs_dmg(a.write_apfs(nodes).container)
    with _open(image) as reader:
        reader.members()
        tracker = reader._listing_tracker  # type: ignore[attr-defined]
        kept, total = tracker._kept_bytes, tracker.metadata_bytes
        # A second listing counts the kept trees once, not again.
        reader.members()
        assert tracker.metadata_bytes == total
    # The kept trees fit on their own, and so do the members; together they do not.
    limit = total - 1
    assert 0 < kept < limit
    assert 0 < total - kept < limit
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=limit))
    with (
        _open(image, config=config) as reader,
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
    ):
        reader.members()
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=total))
    with _open(image, config=config) as reader:
        assert len(reader.members()) == len(reader.members())


def test_a_zero_extent_bomb_stops_at_the_ratio_guard() -> None:
    size = 1 << 40
    container = a.write_apfs(
        [d.Node("bomb.bin", data=b"")],
        patch_records=_huge_hole("bomb.bin", size),
    )
    with _open(a.apfs_dmg(container.container)) as reader:
        members = {m.name: m for m in reader.members()}
        assert members["bomb.bin"].size == size
        assert members["bomb.bin"].is_sparse
        with pytest.raises(ResourceLimitError), reader.open("bomb.bin") as stream:
            while stream.read(1 << 20):
                pass


def _huge_hole(path: str, size: int) -> Callable[[list], None]:
    def patch(records: list) -> None:
        rec = _record(records, path, apfs.INODE)
        value = bytearray(rec.value)
        # The data stream extended field is the last one; its size is its first word.
        struct.pack_into("<Q", value, len(value) - 40, size)
        rec.value = bytes(value)

    return patch


# ── 7-Zip ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(set(_APFS_IMAGES) - {"apfs-ULMO.dmg"}))
def test_7zip_extracts_what_archivey_reads_from_hdiutil_apfs_images(
    tmp_path: Path, name: str
) -> None:
    from tests.test_dmg import _compare_with_7zip

    _compare_with_7zip(
        tmp_path,
        (_FIXTURES / name).read_bytes(),
        may_lack=set(),
        compressed={"compressed.txt"},
        volume_folder=False,
    )


@pytest.mark.parametrize("hashed", [True, False], ids=["hashed", "plain"])
def test_7zip_extracts_what_archivey_reads_from_builder_apfs_images(
    tmp_path: Path, hashed: bool
) -> None:
    from tests.test_dmg import _compare_with_7zip

    lacking = {f"comp/t{k}.txt" for k in (10, 11, 12)}
    compressed = {n.path for n in _tree() if n.compression is not None}
    _compare_with_7zip(
        tmp_path,
        # 7-Zip 23.01 reports a Data Error for a hole with no extent, and reads an
        # extent at block 0 from the container's block 0 rather than as zeros (the
        # Linux APFS driver and the reference read both as holes), so this image
        # writes the holes' zeros as data.
        a.apfs_dmg(_container(hashed=hashed, holes={}, zero_extents={}).container),
        may_lack=lacking,
        compressed=compressed,
        volume_folder=False,
    )
