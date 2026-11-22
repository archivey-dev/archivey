"""The DMG reader (``internal/backends/dmg_reader.py``): UDIF images holding HFS+.

Two sources of images. The ``hdiutil`` fixtures in
``tests/fixtures/external/dmg_hdiutil/`` are the truth for what a real image holds:
macOS's own listing, hashes and extended attributes of the mounted volume are beside
them. ``tests/dmg_build.py`` writes the rest: every run codec and partition layout,
HFSX, journals, several volumes, and the damage and limit cases no tool writes.
"""

from __future__ import annotations

import hashlib
import io
import struct
import sys
import unicodedata
import uuid
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
    StreamNotSeekableError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.internal.backends.dmg_reader import volume_names
from tests import dmg_build as d

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"

# The unencrypted HFS+ images, by run codec.
_HFS_IMAGES = {
    "hfs-UDZO.dmg": ["zlib"],
    "hfs-UDBZ.dmg": ["bzip2"],
    "hfs-ULFO.dmg": ["lzfse"],
    "hfs-ULMO.dmg": ["xz"],
    "hfs-UDRO.dmg": ["raw"],
}


def _open(image: bytes, **kwargs: object):
    return open_archive(io.BytesIO(image), **kwargs)  # type: ignore[arg-type]


def _codes(reader) -> list[DiagnosticCode]:
    return [diag.code for diag in reader.diagnostics.retained]


def _structures(reader) -> list[str]:
    return [
        diag.context.structure
        for diag in reader.diagnostics.retained
        if diag.code is DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT
    ]


def _sha256_listing(name: str) -> dict[str, str]:
    out = {}
    for line in (_FIXTURES / name).read_text(encoding="utf-8").splitlines():
        digest, path = line.split(None, 1)
        out[path.removeprefix("./")] = digest
    return out


# ── The hdiutil fixtures ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(_HFS_IMAGES))
def test_an_hdiutil_image_lists_and_reads_as_macos_mounts_it(name: str) -> None:
    hashes = _sha256_listing("hfs-sha256.txt")
    with open_archive(_FIXTURES / name) as reader:
        members = {m.name: m for m in reader.members()}
        info = reader.info
        files = {
            n: hashlib.sha256(reader.read(m)).hexdigest()
            for n, m in members.items()
            if m.type is MemberType.FILE
        }
        assert not _codes(reader)
    cafe = unicodedata.normalize("NFD", "sub dir/café.txt")
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
    # The hard link's first path holds the data; the second names it.
    assert files == {
        unicodedata.normalize("NFD", p): h
        for p, h in hashes.items()
        if p != "sub dir/hardlink.txt"
    }
    link = members["sub dir/hardlink.txt"]
    assert link.type is MemberType.HARDLINK
    assert link.link_target == "hello.txt"
    assert members["Applications"].type is MemberType.SYMLINK
    assert members["Applications"].link_target == "/Applications"
    assert members["link-rel"].link_target == "hello.txt"
    # compressed.txt is decmpfs type 8 (LZVN in the resource fork); its size is the
    # decoded size, and the attribute that holds it is not listed.
    assert members["compressed.txt"].size == 360_000
    assert "com.apple.decmpfs" not in members["compressed.txt"].extra["dmg.xattrs"]
    assert members["hello.txt"].extra["dmg.xattrs"]["com.example.test"] == (
        b"xattr value"
    )
    assert members["hello.txt"].mode == 0o644
    assert members["hello.txt"].modified is not None
    assert info.format is ArchiveFormat.DMG
    assert info.format_version == "UDIF 4"
    assert info.extra["dmg.filesystem"] == "HFS+"
    assert info.extra["dmg.volume_name"] == "Fixture"
    assert info.extra["dmg.volumes"] == ["Fixture"]
    assert info.extra["dmg.partition_scheme"] == "GPT"
    assert info.extra["dmg.run_codecs"] == _HFS_IMAGES[name]
    assert info.extra["dmg.code_signature"] is False


def test_the_adc_image_reads() -> None:
    with open_archive(_FIXTURES / "hfs-UDCO.dmg") as reader:
        assert reader.info.extra["dmg.run_codecs"] == ["adc"]
        data = reader.read("repeat.txt")
    assert len(data) == 300_000
    assert hashlib.sha256(data).hexdigest().startswith("f49602b2")


@pytest.mark.parametrize(
    "name",
    [
        "hfs-UDZO-AES-128.dmg",
        "hfs-UDZO-AES-256.dmg",
        "apfs-UDZO-AES-128.dmg",
        "apfs-UDZO-AES-256.dmg",
    ],
)
def test_an_encrypted_image_is_refused_by_name(name: str) -> None:
    path = _FIXTURES / name
    assert detect_format(path).format is ArchiveFormat.DMG
    with pytest.raises(UnsupportedFeatureError, match="encrypted DMG disk image"):
        open_archive(path)


def test_a_version_1_encrypted_image_is_named_from_its_last_bytes() -> None:
    image = bytes(4096) + b"cdsaencr"
    info = detect_format(io.BytesIO(image))
    assert info.format is ArchiveFormat.DMG
    # The trailer tier reads one 512-byte tail: the 8-byte mark is its end.
    assert info.cost_receipt is not None
    with pytest.raises(UnsupportedFeatureError, match="cdsaencr"):
        _open(image)


# ── Builder images: every codec, layout and volume kind ──────────────────────────────

_TEXT = b"The quick brown fox jumps over the lazy dog.\n" * 4000
_BIG = bytes(range(256)) * 1200


def _tree() -> list[d.Node]:
    nodes = [
        d.Node(
            "hello.txt",
            data=b"hello dmg\n",
            mtime=1_600_000_000,
            xattrs={"com.example.small": b"v", "user.big": b"x" * 5000},
        ),
        d.Node("frag.bin", data=_BIG, fragment=12),
        d.Node("sub dir/first.txt", data=b"linked content\n"),
        d.Node("other/second.txt", kind="hardlink", target="sub dir/first.txt"),
        d.Node("link", kind="symlink", target="hello.txt"),
        d.Node("empty", kind="dir"),
        d.Node("fifo", kind="fifo"),
        d.Node("rsrc.txt", data=b"data fork", resource_fork=b"resource fork bytes"),
    ]
    for kind in (3, 4, 7, 8, 9, 10, 11, 12):
        data = _TEXT[:300] if kind in (3, 7, 9, 11) else _TEXT
        nodes.append(d.Node(f"comp/t{kind}.txt", data=data, compression=kind))
    for kind in (4, 8, 10, 12):
        nodes.append(d.Node(f"comp/big{kind}.bin", data=_BIG, compression=kind))
    return nodes


def _expected() -> dict[str, bytes]:
    return {
        n.path: n.data
        for n in _tree()
        if n.kind == "file" and n.path != "other/second.txt"
    }


def _image(nodes: list[d.Node] | None = None, **options: object) -> bytes:
    hfs = {"name": "Vol", "attributes_in_fork": ("user.big",)}
    hfs.update(options.pop("hfs_options", {}))  # type: ignore[arg-type]
    return d.dmg_of(_tree() if nodes is None else nodes, hfs_options=hfs, **options)  # type: ignore[arg-type]


def _read_all(image: bytes, **kwargs: object) -> tuple[dict[str, object], dict]:
    """The members by name, and the bytes of each file."""
    with _open(image, **kwargs) as reader:
        members = {m.name: m for m in reader.members()}
        data = {n: reader.read(m) for n, m in members.items() if m.is_file}
    return members, data


@pytest.mark.parametrize("layout", ["gpt", "apm", "none"])
@pytest.mark.parametrize(
    "codec", [d.RAW, d.ZLIB, d.BZIP2, d.LZMA, d.ADC, d.LZFSE], ids=hex
)
def test_every_codec_and_layout_reads(layout: str, codec: int) -> None:
    members, data = _read_all(_image(layout=layout, codec=codec))
    assert {n: v for n, v in data.items() if n in _expected()} == _expected()
    second = members["other/second.txt"]
    assert second.type is MemberType.HARDLINK
    assert second.link_target == "sub dir/first.txt"
    assert members["link"].type is MemberType.SYMLINK
    assert members["link"].link_target == "hello.txt"
    assert members["empty/"].type is MemberType.DIRECTORY
    assert members["fifo"].type is MemberType.OTHER
    assert members["fifo"].extra["special_file_type"] == "fifo"
    assert members["rsrc.txt"].extra["dmg.resource_fork_size"] == 19
    # D2: names, and values up to 1 KiB; a larger one is listed without its value.
    assert members["hello.txt"].extra["dmg.xattrs"] == {
        "com.example.small": b"v",
        "user.big": None,
    }
    assert members["hello.txt"].modified.timestamp() == 1_600_000_000  # type: ignore[union-attr]
    # Nothing of the hidden folders is listed.
    assert not [n for n in members if "HFS+ Private" in n]


@pytest.mark.parametrize("options", [{"hfsx": True}, {"block_size": 512}])
def test_hfsx_and_small_blocks_read(options: dict) -> None:
    image = _image(hfs_options=options)
    with _open(image) as reader:
        files = {m.name: reader.read(m) for m in reader.members() if m.is_file}
        hfsx = reader.info.extra["dmg.filesystem"]
    assert {n: v for n, v in files.items() if n in _expected()} == _expected()
    assert hfsx == ("HFSX" if options.get("hfsx") else "HFS+")


@pytest.mark.parametrize("state", ["clean", "need-init"])
def test_a_journal_with_nothing_to_replay_is_hidden(state: str) -> None:
    nodes = [d.Node("a.txt", data=b"a")]
    members, _ = _read_all(_image(nodes, hfs_options={"journal": state}))
    assert sorted(members) == ["a.txt"]


@pytest.mark.parametrize(
    ("state", "message"),
    [("pending", "unreplayed journal"), ("external", "external journal")],
)
def test_a_journal_that_may_hold_changes_is_refused(state: str, message: str) -> None:
    with pytest.raises(UnsupportedFeatureError, match=message):
        _open(_image([d.Node("a.txt", data=b"a")], hfs_options={"journal": state}))


def test_a_name_with_a_slash_lists_with_a_colon() -> None:
    nodes = [d.Node("x", data=b"slash", raw_name="a/b".encode("utf-16-be"))]
    members, data = _read_all(_image(nodes))
    assert data == {"a:b": b"slash"}
    assert list(members) == ["a:b"]


def test_a_pipe_is_refused_with_the_reason() -> None:
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._inner = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def readinto(self, b) -> int:  # type: ignore[override]
            return self._inner.readinto(b)

    with pytest.raises(StreamNotSeekableError, match="run tables are at the end"):
        open_archive(Pipe(_image([d.Node("a", data=b"a")])), format=ArchiveFormat.DMG)


def test_random_access_reads_inside_a_large_file() -> None:
    nodes = [d.Node("big.bin", data=_BIG * 8, fragment=5)]
    with (
        _open(_image(nodes), seekable_members=True) as reader,
        reader.open("big.bin") as stream,
    ):
        stream.seek(1_500_000)
        assert stream.read(1000) == (_BIG * 8)[1_500_000:1_501_000]


# ── Several volumes ──────────────────────────────────────────────────────────────────


def _volumes(*names: str, apfs: bool = False) -> bytes:
    parts = []
    for name in names:
        hfs = d.write_hfsplus(
            [
                d.Node("readme.txt", data=f"in {name}\n".encode()),
                d.Node("zlink.txt", kind="hardlink", target="readme.txt"),
            ],
            name=name,
        )
        parts.append(d.Partition(hfs.volume, name=name))
    if apfs:
        # The NXSB magic and nothing else: the probe calls it APFS, the open finds
        # block 0 damaged.
        container = bytearray(64 * d.SECTOR)
        container[32:36] = b"NXSB"
        struct.pack_into("<I", container, 36, 4096)
        parts.append(
            d.Partition(bytes(container), name="Container", gpt_type=d.APFS_GUID)
        )
    disk = d.write_gpt(parts)
    return d.write_udif(disk.segments, tables=disk.tables).image


def test_several_volumes_list_under_their_names() -> None:
    members, data = _read_all(_volumes("Data", "data", ""))
    assert data == {
        "Data/readme.txt": b"in Data\n",
        "data 1/readme.txt": b"in data\n",
        "Untitled/readme.txt": b"in \n",
    }
    # Each hard link stays inside its own volume.
    assert members["data 1/zlink.txt"].link_target == "data 1/readme.txt"
    assert members["Untitled/zlink.txt"].link_target == "Untitled/readme.txt"
    assert members["Data/"].type is MemberType.DIRECTORY


def test_volume_names_follow_the_mount_points() -> None:
    assert volume_names(["A", "a", "A", "", ".", "..", "x/y"]) == [
        "A",
        "a 1",
        "A 2",
        "Untitled",
        "Untitled 1",
        "Untitled 2",
        "x:y",
    ]


def test_a_damaged_apfs_container_beside_hfs_fails_after_the_hfs_members() -> None:
    names = []
    with (
        pytest.raises(CorruptionError, match="APFS"),
        _open(_volumes("Data", apfs=True)) as reader,
    ):
        for member in reader:
            names.append(member.name)
    assert sorted(names) == ["readme.txt", "zlink.txt"]


def test_an_hfs_volume_beside_hfs_plus_is_reported_and_not_listed() -> None:
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    wrapper = bytearray(64 * d.SECTOR)
    wrapper[1024:1026] = b"BD"
    disk = d.write_gpt(
        [d.Partition(hfs.volume), d.Partition(bytes(wrapper), name="Old")]
    )
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        unlisted = [
            diag
            for diag in reader.diagnostics.retained
            if diag.code is DiagnosticCode.ARCHIVE_UNLISTED_DATA
        ]
    assert len(unlisted) == 1
    assert "HFS volume" in unlisted[0].message
    assert unlisted[0].context.member_name == "Old"


def test_an_image_with_no_filesystem_names_its_partitions() -> None:
    disk = d.write_gpt([d.Partition(bytes(64 * d.SECTOR), name="Blank")])
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with pytest.raises(UnsupportedFeatureError, match="no HFS\\+ or APFS.*'Blank'"):
        _open(image)


def test_an_hfs_wrapper_is_refused_by_name() -> None:
    volume = bytearray(64 * d.SECTOR)
    volume[1024:1026] = b"BD"
    disk = d.write_gpt([d.Partition(bytes(volume))])
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with pytest.raises(UnsupportedFeatureError, match="HFS wrapper"):
        _open(image)


def test_a_partition_type_that_disagrees_is_reported_and_read() -> None:
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    disk = d.write_apm([d.Partition(hfs.volume, apm_type="Apple_APFS")])
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert reader.read("a.txt") == b"a"
        assert "partition_name" in _structures(reader)


def test_a_damaged_primary_gpt_falls_back_to_the_backup() -> None:
    def break_crc(header: bytearray) -> None:
        header[16] ^= 0xFF

    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    disk = d.write_gpt([d.Partition(hfs.volume)], patch_header=break_crc)
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert reader.read("a.txt") == b"a"
        assert reader.info.extra["dmg.partition_scheme"] == "GPT"
        assert "gpt_primary" in _structures(reader)


def test_a_damaged_entry_array_uses_the_run_tables() -> None:
    def break_entries(entries: bytearray) -> None:
        # The first entry ends past the disk: both copies share the array.
        struct.pack_into("<Q", entries, 40, 1 << 40)

    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    disk = d.write_gpt([d.Partition(hfs.volume)], patch_entries=break_entries)
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert reader.read("a.txt") == b"a"
        assert reader.info.extra["dmg.partition_scheme"] == "none"
        assert "partition_map" in _structures(reader)


# ── Catalog edge cases and damage ────────────────────────────────────────────────────


def _patch_file(name: str, edit: Callable[[bytearray], None]):
    raw = name.encode("utf-16-be")

    def patch(records: list[d.CatalogRecord]) -> None:
        for record in records:
            if record.name == raw and struct.unpack_from(">h", record.body)[0] == 2:
                edit(record.body)

    return patch


def test_a_mode_only_symlink_is_a_symlink() -> None:
    def no_finder(body: bytearray) -> None:
        body[48:56] = bytes(8)

    nodes = [d.Node("a", data=b""), d.Node("l", kind="symlink", target="a")]
    members, _ = _read_all(
        _image(nodes, hfs_options={"patch_catalog": _patch_file("l", no_finder)})
    )
    assert members["l"].type is MemberType.SYMLINK
    assert members["l"].link_target == "a"


def test_a_finder_symlink_with_a_file_mode_is_a_file_and_reported() -> None:
    def file_mode(body: bytearray) -> None:
        struct.pack_into(">H", body, 42, 0o100644)

    nodes = [d.Node("a", data=b""), d.Node("l", kind="symlink", target="a")]
    with _open(
        _image(nodes, hfs_options={"patch_catalog": _patch_file("l", file_mode)})
    ) as reader:
        member = reader.get("l")
        assert member.type is MemberType.FILE
        assert reader.read(member) == b"a"
        assert "member_type" in _structures(reader)


def test_a_directory_hard_link_lists_and_its_read_is_refused() -> None:
    def directory_link(body: bytearray) -> None:
        body[48:56] = b"fdrpMACS"

    nodes = [d.Node("a", data=b"x"), d.Node("b", data=b"y")]
    with _open(
        _image(nodes, hfs_options={"patch_catalog": _patch_file("a", directory_link)})
    ) as reader:
        assert reader.read("b") == b"y"
        with pytest.raises(UnsupportedFeatureError, match="directory hard link"):
            reader.read("a")


def test_a_hard_link_without_its_inode_raises_on_read() -> None:
    def other_link(body: bytearray) -> None:
        struct.pack_into(">I", body, 44, 9999)

    nodes = [
        d.Node("a", data=b"x"),
        d.Node("b", kind="hardlink", target="a"),
        d.Node("c", data=b"z"),
    ]
    with _open(
        _image(nodes, hfs_options={"patch_catalog": _patch_file("b", other_link)})
    ) as reader:
        assert reader.read("a") == b"x"
        assert reader.read("c") == b"z"
        with pytest.raises(CorruptionError, match="inode 9999"):
            reader.read("b")


def test_a_compressed_file_without_its_attribute_raises_on_read() -> None:
    def flag(body: bytearray) -> None:
        body[41] |= 0x20  # UF_COMPRESSED, and no com.apple.decmpfs

    nodes = [d.Node("a", data=b"x"), d.Node("b", data=b"y")]
    with _open(
        _image(nodes, hfs_options={"patch_catalog": _patch_file("a", flag)})
    ) as reader:
        assert reader.read("b") == b"y"
        with pytest.raises(CorruptionError, match="no com.apple.decmpfs"):
            reader.read("a")


def test_an_extent_past_the_volume_fails_that_file_only() -> None:
    def far(body: bytearray) -> None:
        struct.pack_into(">I", body, 88 + 16, 0x7FFFFFF0)  # first extent's start

    nodes = [d.Node("a", data=b"x" * 5000), d.Node("b", data=b"y")]
    with _open(
        _image(nodes, hfs_options={"patch_catalog": _patch_file("a", far)})
    ) as reader:
        names = [m.name for m in reader.members()]
        assert reader.read("b") == b"y"
        with pytest.raises(CorruptionError, match="past the volume"):
            reader.read("a")
    assert names == ["a", "b"]


def test_a_long_symlink_target_is_reported() -> None:
    nodes = [d.Node("l", kind="symlink", target="t" * 2000)]
    with _open(_image(nodes)) as reader:
        member = reader.get("l")
        assert member.link_target is None
        assert DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE in _codes(reader)


def test_a_catalog_leaf_loop_delivers_the_members_before_it() -> None:
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x") for i in range(120)]

    def loop(nodes_: list[bytearray]) -> None:
        # The first leaf links to itself: the chain reaches it twice.
        first = next(i for i, n in enumerate(nodes_) if n[8:9] == b"\xff")
        struct.pack_into(">I", nodes_[first], 0, first)

    seen: list[str] = []
    with (
        _open(
            _image(nodes, hfs_options={"patch_catalog_nodes": loop, "node_size": 512})
        ) as reader,
        pytest.raises(CorruptionError, match="twice"),
    ):
        for member in reader:
            seen.append(member.name)
    assert seen  # the first leaf's members came before the error
    assert len(seen) < 120


def test_a_folder_parent_loop_delivers_the_other_members() -> None:
    """A folder whose parent chain loops cannot be placed: the members in it are left
    out, the others are listed, and the error comes at the end (DR-2)."""
    nodes = [
        d.Node("a/s/x", data=b"x"),
        d.Node("m/one", data=b"1"),
        d.Node("z/two", data=b"2"),
        d.Node("top", data=b"t"),
    ]

    def loop(records: list[d.CatalogRecord]) -> None:
        def folder(name: str) -> d.CatalogRecord:
            raw = name.encode("utf-16-be")
            return next(
                r
                for r in records
                if r.name == raw and struct.unpack_from(">h", r.body)[0] == 1
            )

        # Folder ``a`` now sits in its own child ``s``.
        folder("a").parent = struct.unpack_from(">I", folder("s").body, 8)[0]

    seen: list[str] = []
    with (
        _open(_image(nodes, hfs_options={"patch_catalog": loop})) as reader,
        pytest.raises(CorruptionError, match="parent chain loops"),
    ):
        for member in reader:
            seen.append(member.name)
    assert {"m/one", "z/two", "top"} <= set(seen)
    assert not any(name.startswith("a/") for name in seen)


def test_type_9_without_its_marker_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No sample shows type 9 data without the 0xCC byte, so it is not called damage."""
    real = d._decmpfs

    def no_marker(kind: int, data: bytes) -> tuple[bytes, bytes]:
        value, fork = real(kind, data)
        return (value[:16] + value[17:], fork) if kind == 9 else (value, fork)

    monkeypatch.setattr(d, "_decmpfs", no_marker)
    image = _image(
        [d.Node("t9", data=b"plain", compression=9), d.Node("ok", data=b"1")]
    )
    with _open(image) as reader:
        assert reader.read("ok") == b"1"
        with pytest.raises(UnsupportedFeatureError, match="0xCC"):
            reader.read("t9")


# ── Limits and UDIF structure ────────────────────────────────────────────────────────


def test_max_members_applies() -> None:
    nodes = [d.Node(f"f{i}", data=b"x") for i in range(20)]
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=5))
    with (
        pytest.raises(ResourceLimitError, match="max_members"),
        _open(_image(nodes), config=config) as reader,
    ):
        reader.members()


def test_max_metadata_bytes_applies_to_the_catalog() -> None:
    nodes = [d.Node(f"folder{i:03d}/f", data=b"x") for i in range(200)]
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=4096))
    with (
        pytest.raises(ResourceLimitError),
        _open(_image(nodes), config=config) as reader,
    ):
        reader.members()


def test_a_property_list_over_its_cap_is_refused_before_it_is_read() -> None:
    def huge(koly: bytearray) -> None:
        struct.pack_into(">Q", koly, 224, 65 << 20)

    image = d.write_udif(bytes(64 * d.SECTOR), patch_koly=huge).image
    with pytest.raises(ResourceLimitError, match="property list"):
        _open(image, format=ArchiveFormat.DMG)


def test_a_segmented_image_is_refused() -> None:
    def segmented(koly: bytearray) -> None:
        struct.pack_into(">I", koly, 60, 2)

    image = d.write_udif(bytes(64 * d.SECTOR), patch_koly=segmented).image
    with pytest.raises(UnsupportedFeatureError, match="segmented"):
        _open(image)


def test_an_unknown_run_type_fails_the_reads_that_need_it() -> None:
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a" * 100_000)])
    disk = d.write_gpt([d.Partition(hfs.volume)])
    # Only runs of the file's data have the unknown type: the open and the listing
    # read none of them.
    image = d.write_udif(
        disk.segments,
        tables=disk.tables,
        run_sectors=8,
        choose=lambda sector, data: 0x80000009 if data == b"a" * len(data) else d.RAW,
        encode=lambda kind, data: data,
    ).image
    with _open(image) as reader:
        member = reader.get("a.txt")
        with pytest.raises(UnsupportedFeatureError, match="0x80000009"):
            reader.read(member)


def test_layout_options_read() -> None:
    nodes = [d.Node("a.txt", data=b"layout\n" * 100)]
    for options in (
        {"koly_at_front": True},
        {"data_fork_at": 4096},
        {"mish_data_offset": 512},
        {"code_signature": bytes(300)},
    ):
        with _open(_image(nodes, **options)) as reader:
            assert reader.read("a.txt") == b"layout\n" * 100, options
            assert reader.info.extra["dmg.code_signature"] is (
                "code_signature" in options
            )


def test_bytes_outside_every_structure_are_reported() -> None:
    # Filler before the data fork that no structure the koly block declares covers.
    image = _image([d.Node("a", data=b"a")], data_fork_at=4096)
    with _open(image) as reader:
        assert reader.read("a") == b"a"
        assert DiagnosticCode.ARCHIVE_TRAILING_DATA in _codes(reader)


def test_more_partitions_than_archivey_probes_is_a_resource_limit() -> None:
    # No partition map, so the run tables are the candidates: 129 of them.
    tables = [d.Table(f"p{i} (Apple_HFS : {i})", i, 1) for i in range(129)]
    image = d.write_udif(bytes(129 * d.SECTOR), tables=tables).image
    with pytest.raises(ResourceLimitError, match="128"):
        _open(image)


def test_the_gpt_partition_type_names_only_describe() -> None:
    other = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B9B72699C7")  # Microsoft basic data
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    disk = d.write_gpt([d.Partition(hfs.volume, gpt_type=other)])
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert reader.read("a.txt") == b"a"


# ── Oracle: 7-Zip ────────────────────────────────────────────────────────────────────

# Where 7-Zip and archivey differ on purpose (design §9.3):
# - 7-Zip writes both paths of a file hard link as empty files, and the data under
#   ``[HFS+ Private Data]/iNode<n>``; archivey lists the first path as the file and
#   the later ones as hard links to it, and hides the private folder as the mount
#   does.
# - 7-Zip skips absolute symlinks (``/Applications``); archivey lists them.
# - 7-Zip writes extended attributes as ``name:attr`` side files and the resource
#   fork as ``name:rsrc``; archivey lists them in ``extra`` (D2).
# - 7-Zip 23.01 cannot read xz (ULMO) images; archivey reads them.
# - 7-Zip refuses decmpfs types 10, 11 and 12; archivey reads them.
# - 7-Zip writes a FIFO or device as an empty file; archivey lists it as ``OTHER``.
_7Z_PRIVATE = "[HFS+ Private Data]"


def _7z_files(
    tmp_path: Path, image: bytes, *, volume_folder: bool = True
) -> dict[str, bytes] | None:
    """What 7-Zip extracts, below the volume's folder: regular files only, without
    attribute and resource fork side files. ``None`` when it cannot read the image."""
    import os

    from tests.conftest import run_7z

    path = tmp_path / "image.dmg"
    path.write_bytes(image)
    out = tmp_path / "out"
    result = run_7z(["x", "-y", f"-o{out}", str(path)], text=True)
    if "Unsupported Method" in result.stdout + result.stderr and not out.exists():
        return None
    files = {}
    for root, _dirs, names in os.walk(out):
        for n in names:
            full = Path(root) / n
            rel = full.relative_to(out).as_posix()
            if volume_folder:
                rel = rel.split("/", 1)[-1]
            if full.is_symlink() or not full.is_file() or ":" in n:
                continue
            files[unicodedata.normalize("NFC", rel)] = full.read_bytes()
    return files


def _archivey_files(image: bytes) -> tuple[dict[str, bytes], set[str]]:
    """archivey's files by NFC name, and the paths 7-Zip writes as empty files: the
    hard links and the special files."""
    files: dict[str, bytes] = {}
    links: set[str] = set()
    with _open(image) as reader:
        for member in reader.members():
            name = unicodedata.normalize("NFC", member.name)
            if member.type is MemberType.FILE:
                files[name] = reader.read(member)
            elif member.type in (MemberType.HARDLINK, MemberType.OTHER):
                links.add(name)
    return files, links


def _compare_with_7zip(
    tmp_path: Path,
    image: bytes,
    *,
    may_lack: set[str],
    compressed: set[str],
    volume_folder: bool = True,
) -> None:
    """``compressed``: the decmpfs files. On macOS 7-Zip leaves their data fork empty
    and hands the compression to the file system, where macOS's own mount shows their
    data (``hfs-sha256.txt``), so there an empty file is 7-Zip's, not a difference."""
    import shutil

    from tests.conftest import sevenzip_version

    if shutil.which("7z") is None:
        pytest.skip("7z not installed")
    # p7zip 17.05 opens builder volumes with a Headers Error.
    if (sevenzip_version() or (0, 0)) < (23, 1):
        pytest.skip("7-Zip older than 23.01 does not read these HFS+ volumes")
    ours, links = _archivey_files(image)
    # 7-Zip extracts an HFS+ volume into a folder named after it, an APFS volume's
    # files at the top.
    theirs = _7z_files(tmp_path, image, volume_folder=volume_folder)
    if theirs is None or not any(not k.startswith(_7Z_PRIVATE) for k in theirs):
        pytest.skip("this 7-Zip cannot read the image")
    inodes = {k: v for k, v in theirs.items() if k.startswith(_7Z_PRIVATE)}
    theirs = {k: v for k, v in theirs.items() if k not in inodes}
    if sys.platform == "darwin":
        for name in compressed:
            if theirs.get(name) == b"":
                del theirs[name]
                may_lack = may_lack | {name}
    # A hard link's paths are empty files in 7-Zip's HFS+ extraction, its data the
    # inode's; on APFS 7-Zip writes the data at each path.
    for name in links | {n for n in ours if theirs.get(n) == b"" and ours[n]}:
        if name in theirs:
            got = theirs.pop(name)
            assert got == b"" or got in ours.values(), name
    for name, data in ours.items():
        if name in may_lack and name not in theirs:
            continue
        if name in theirs:
            assert theirs[name] == data, name
        else:
            assert data in inodes.values(), name
    assert set(theirs) <= set(ours), sorted(set(theirs) - set(ours))


# 7-Zip 23.01 cannot read xz runs, so the ULMO image is left out.
@pytest.mark.parametrize("name", sorted(set(_HFS_IMAGES) - {"hfs-ULMO.dmg"}))
def test_7zip_extracts_what_archivey_reads_from_hdiutil_images(
    tmp_path: Path, name: str
) -> None:
    # The root files macOS's listing flags ``compressed`` (``ls -lO``).
    listing = (_FIXTURES / "hfs-listing.txt").read_text(encoding="utf-8")
    compressed = {
        line.split(maxsplit=9)[-1]
        for line in listing.split("\n\n", 1)[0].splitlines()
        if " compressed " in line
    }
    assert compressed == {"compressed.txt"}
    _compare_with_7zip(
        tmp_path,
        (_FIXTURES / name).read_bytes(),
        may_lack=set(),
        compressed=compressed,
    )


@pytest.mark.parametrize("layout", ["gpt", "apm", "none"])
@pytest.mark.parametrize("codec", [d.RAW, d.ZLIB, d.BZIP2, d.ADC, d.LZFSE], ids=hex)
def test_7zip_extracts_what_archivey_reads_from_builder_images(
    tmp_path: Path, layout: str, codec: int
) -> None:
    lacking = {f"comp/t{k}.txt" for k in (10, 11, 12)} | {
        f"comp/big{k}.bin" for k in (10, 12)
    }
    compressed = {n.path for n in _tree() if n.compression is not None}
    _compare_with_7zip(
        tmp_path,
        _image(layout=layout, codec=codec),
        may_lack=lacking,
        compressed=compressed,
    )


def test_strict_raises_on_a_structure_the_read_worked_around() -> None:
    from archivey import ArchiveyError, DiagnosticPolicy

    def break_crc(header: bytearray) -> None:
        header[16] ^= 0xFF

    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    disk = d.write_gpt([d.Partition(hfs.volume)], patch_header=break_crc)
    image = d.write_udif(disk.segments, tables=disk.tables).image
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(ArchiveyError, match="primary GPT"),
        _open(image, config=config) as reader,
    ):
        reader.members()
