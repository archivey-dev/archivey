"""The DMG test writers in ``dmg_build.py`` (DMG plan, B.1).

The writers are checked against tools that are not ours: ``fsck.hfsplus`` (``hfsprogs``)
for the HFS+ volumes, 7-Zip for whole images, and the ``hdiutil`` fixtures in
``tests/fixtures/external/dmg_hdiutil/`` for the UDIF and GPT fields. The tool checks skip
when the tool is not installed. A small UDIF reader here, independent of the archivey
reader that Part B adds, checks every run codec and layout option.
"""

from __future__ import annotations

import bz2
import hashlib
import lzma
import os
import plistlib
import random
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from archivey.internal.streams.codecs.adc_decoder import adc_decompress
from archivey.internal.streams.codecs.lzfse_decoder import lzfse_decompress
from tests import dmg_build as d
from tests.conftest import run_7z

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"

_FSCK = shutil.which("fsck.hfsplus")
_7Z = shutil.which("7z")
needs_fsck = pytest.mark.skipif(
    _FSCK is None, reason="fsck.hfsplus (hfsprogs) not installed"
)
needs_7z = pytest.mark.skipif(_7Z is None, reason="7z not installed")

_CODECS = (d.RAW, d.ZLIB, d.BZIP2, d.LZMA, d.ADC, d.LZFSE)


# ── A small UDIF reader, for these tests only ────────────────────────────────────────


def _koly(image: bytes, at: int | None = None) -> tuple:
    at = len(image) - 512 if at is None else at
    fields = d.KOLY.unpack_from(image, at)
    assert fields[0] == b"koly"
    return fields


def _tables(
    image: bytes, koly: tuple, base: int = 0
) -> list[tuple[tuple, list[tuple], dict]]:
    """Each ``blkx`` entry as (mish header fields, runs, plist entry)."""
    plist = plistlib.loads(image[base + koly[15] : base + koly[15] + koly[16]])
    out = []
    for entry in plist["resource-fork"]["blkx"]:
        mish = entry["Data"]
        head = d.MISH.unpack_from(mish)
        assert head[0] == b"mish"
        runs = [
            d.RUN.unpack_from(mish, d.MISH.size + d.RUN.size * i)
            for i in range(head[11])
        ]
        out.append((head, runs, entry))
    return out


def _decode(kind: int, stored: bytes, size: int) -> bytes:
    if kind == d.RAW:
        return stored
    if kind == d.ZLIB:
        return zlib.decompress(stored)
    if kind == d.BZIP2:
        return bz2.decompress(stored)
    if kind == d.LZMA:
        return lzma.decompress(stored)
    if kind == d.ADC:
        return adc_decompress(stored, size)
    if kind == d.LZFSE:
        return lzfse_decompress(stored, size)
    raise AssertionError(f"run type {kind:#x}")


def _read_disk(image: bytes, *, koly_at: int | None = None, base: int = 0) -> bytes:
    """The disk of a UDIF image, checking every table CRC and the master checksum.
    ``base`` is where the image's offsets count from (512 when ``koly`` is in front)."""
    koly = _koly(image, koly_at)
    disk = bytearray(koly[22] * d.SECTOR)
    crcs = b""
    for head, runs, _entry in _tables(image, koly, base):
        first, data_offset = head[2], head[4]
        crc = 0
        for kind, _c, sector, count, offset, length in runs:
            if kind == d.END:
                continue
            at = (first + sector) * d.SECTOR
            size = count * d.SECTOR
            if kind in (d.ZERO, d.IGNORE):
                piece = bytes(size)
            else:
                start = base + koly[5] + data_offset + offset
                piece = _decode(kind, image[start : start + length], size)
                assert len(piece) == size
            disk[at : at + size] = piece
            if kind != d.IGNORE:
                crc = zlib.crc32(piece, crc)
        assert head[8:10] == (2, 32)
        assert head[10][:4] == struct.pack(">I", crc)
        crcs += head[10][:4]
    assert koly[20][:4] == struct.pack(">I", zlib.crc32(crcs))
    if koly[12] == 2:  # some hdiutil images (UDCO) carry no data fork checksum
        fork = image[base + koly[5] : base + koly[5] + koly[6]]
        assert koly[14][:4] == struct.pack(">I", zlib.crc32(fork))
    return bytes(disk)


def _hdiutil_disk(
    name: str,
) -> tuple[bytes, list[tuple[tuple, list[tuple], dict]], tuple]:
    image = (_FIXTURES / name).read_bytes()
    koly = _koly(image)
    return _read_disk(image), _tables(image, koly), koly


# ── CRC-32 over zeros ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("n", [0, 1, 2, 3, 7, 512, 4095, 65536, 1_000_003])
@pytest.mark.parametrize("crc", [0, 0x12345678, 0xFFFFFFFF])
def test_crc32_zeros_matches_zlib(n: int, crc: int) -> None:
    assert d.crc32_zeros(crc, n) == zlib.crc32(bytes(n), crc)


def test_crc32_zeros_composes() -> None:
    # 2^50 zero bytes cannot be checked against zlib directly; splitting them in two
    # at any point must give the same register.
    n = 1 << 50
    whole = d.crc32_zeros(0, n)
    for cut in (1, 12345, 1 << 30, n - 1):
        assert d.crc32_zeros(d.crc32_zeros(0, cut), n - cut) == whole


# ── UDIF ─────────────────────────────────────────────────────────────────────────────


def _mixed_disk(sectors: int = 5000) -> bytes:
    rng = random.Random(1)
    out = bytearray()
    pick = 0
    while len(out) < sectors * d.SECTOR:
        pick = (pick + 1) % 3  # random, zero and text pieces in turn
        n = rng.randrange(1, 150) * d.SECTOR
        if pick == 0:
            out += bytes(n)
        elif pick == 1:
            out += rng.randbytes(n)
        else:
            out += (b"archivey dmg test " * (n // 18 + 1))[:n]
    return bytes(out[: sectors * d.SECTOR])


@pytest.mark.parametrize("codec", _CODECS, ids=hex)
def test_udif_round_trip(codec: int) -> None:
    mixed = _mixed_disk()
    disk = mixed[: 2000 * d.SECTOR] + bytes(600 * d.SECTOR) + mixed[2000 * d.SECTOR :]
    segments = [mixed[: 2000 * d.SECTOR], d.Zeros(600), mixed[2000 * d.SECTOR :]]
    tables = [
        d.Table("a", 0, 1000),
        d.Table("free", 1000, 30, free=True),
        d.Table("b", 1030, 4570),
    ]
    expected = bytearray(disk)
    expected[1000 * d.SECTOR : 1030 * d.SECTOR] = bytes(30 * d.SECTOR)
    udif = d.write_udif(segments, tables=tables, codec=codec, run_sectors=256)
    assert _read_disk(udif.image) == bytes(expected)
    kinds = {r.kind for r in udif.runs}
    assert {d.ZERO, d.IGNORE, codec} <= kinds
    for r in udif.runs:  # each written run is where the descriptor says
        if r.kind == codec and codec != d.RAW:
            stored = udif.image[r.stored_at : r.stored_at + r.stored_length]
            assert (
                _decode(codec, stored, r.sectors * d.SECTOR)
                == disk[r.sector * d.SECTOR : (r.sector + r.sectors) * d.SECTOR]
            )


def test_udif_choose_and_encode() -> None:
    disk = _mixed_disk(600)
    udif = d.write_udif(
        disk,
        run_sectors=100,
        choose=lambda sector, _data: d.ZLIB if sector % 200 == 0 else d.BZIP2,
    )
    assert _read_disk(udif.image) == disk
    kinds = {r.sector: r.kind for r in udif.runs if r.kind not in (d.ZERO, d.END)}
    assert {k for s, k in kinds.items() if s % 200 == 0} <= {d.ZLIB}
    assert d.BZIP2 in kinds.values()


@pytest.mark.parametrize(
    "options",
    [
        {"data_fork_at": 4096},
        {"mish_data_offset": 1000},
        {"data_fork_at": 333, "mish_data_offset": 77},
        {"code_signature": b"\xfa\xde\x0c\xc0" + bytes(200)},
        {"trailing": b"junk after the image"},
    ],
    ids=["data_fork_at", "mish_data_offset", "both", "signed", "trailing"],
)
def test_udif_layout_options(options: dict) -> None:
    disk = _mixed_disk(800)
    udif = d.write_udif(disk, codec=d.ZLIB, **options)
    assert _read_disk(udif.image, koly_at=udif.koly_at) == disk
    koly = _koly(udif.image, udif.koly_at)
    assert koly[5] == udif.data_fork_at
    assert koly[5] == options.get("data_fork_at", 0)
    assert all(
        t[0][4] == options.get("mish_data_offset", 0) for t in _tables(udif.image, koly)
    )
    sig_at, sig_len = struct.unpack_from(
        ">QQ", udif.image, udif.koly_at + d.CODE_SIGNATURE_AT
    )
    signature = options.get("code_signature")
    if signature is None:
        assert (sig_at, sig_len) == (0, 0)
    else:
        assert udif.image[sig_at : sig_at + sig_len] == signature
        assert sig_at == udif.plist_at + udif.plist_length
        assert sig_at + sig_len == udif.koly_at
    assert udif.image.endswith(options.get("trailing", b""))


def test_udif_koly_at_front() -> None:
    disk = _mixed_disk(300)
    udif = d.write_udif(disk, codec=d.ZLIB, koly_at_front=True)
    assert udif.koly_at == 0
    # The old layout counts the data fork from the start of the file, after koly.
    koly = _koly(udif.image, 0)
    assert koly[5] == 512
    assert _read_disk(udif.image, koly_at=0) == disk


def test_udif_sparse_disk_of_a_petabyte() -> None:
    sectors = (1 << 50) // d.SECTOR
    udif = d.write_udif([d.Zeros(sectors)])
    assert len(udif.image) < 8192
    koly = _koly(udif.image)
    assert koly[22] == sectors
    ((head, runs, _),) = _tables(udif.image, koly)
    assert [(r[0], r[3]) for r in runs] == [(d.ZERO, sectors), (d.END, 0)]
    assert head[10][:4] == struct.pack(">I", d.crc32_zeros(0, 1 << 50))


def test_udif_hooks() -> None:
    disk = _mixed_disk(100)

    def koly(k: bytearray) -> None:
        k[0:4] = b"kolz"

    def mish(index: int, m: bytearray) -> None:
        m[0:4] = b"misz"

    def plist(p: dict) -> None:
        p["resource-fork"]["extra"] = []

    udif = d.write_udif(
        disk, patch_koly=koly, patch_mish=mish, patch_plist=plist, sector_count=7
    )
    assert udif.image[udif.koly_at : udif.koly_at + 4] == b"kolz"
    fields = d.KOLY.unpack_from(udif.image, udif.koly_at)
    assert fields[22] == 7
    xml = plistlib.loads(udif.image[udif.plist_at : udif.plist_at + udif.plist_length])
    assert "extra" in xml["resource-fork"]
    assert xml["resource-fork"]["blkx"][0]["Data"][:4] == b"misz"
    raw = d.write_udif(disk, plist_bytes=b"not a plist")
    assert raw.image[raw.plist_at : raw.plist_at + raw.plist_length] == b"not a plist"


# ── Against the hdiutil fixtures ─────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["hfs-ULFO.dmg", "apfs-ULFO.dmg"])
def test_udif_fields_match_hdiutil(name: str) -> None:
    disk, theirs, their_koly = _hdiutil_disk(name)
    part = next(
        t for t in theirs if "Apple_HFS" in t[2]["Name"] or "Apple_APFS" in t[2]["Name"]
    )
    first, count = part[0][2], part[0][3]
    gpt_type = d.APFS_GUID if "APFS" in part[2]["Name"] else d.HFS_GUID
    ours_disk = d.write_gpt(
        [d.Partition(disk[first * 512 : (first + count) * 512], gpt_type=gpt_type)]
    )
    udif = d.write_udif(ours_disk.segments, tables=ours_disk.tables, codec=d.LZFSE)
    our_koly = _koly(udif.image)
    ours = _tables(udif.image, our_koly)

    # koly: everything but offsets, lengths, checksums and the segment ID.
    same = (1, 2, 3, 4, 9, 10, 12, 13, 18, 19, 21, 22)
    assert [our_koly[i] for i in same] == [their_koly[i] for i in same]
    # The tables: names, ranges, entry fields, and the mish fields that are not sizes.
    assert len(ours) == len(theirs)
    for (oh, oruns, oe), (th, truns, te) in zip(ours, theirs, strict=True):
        assert {k: v for k, v in oe.items() if k != "Data"} == {
            k: v for k, v in te.items() if k != "Data"
        }
        assert oh[1:4] == th[1:4]
        assert oh[6] == th[6]  # block descriptor number
        assert oh[8:10] == th[8:10]
        if "Apple_Free" in te["Name"]:
            assert [r[0] for r in oruns] == [r[0] for r in truns] == [d.IGNORE, d.END]
            assert oh[10] == th[10] == bytes(128)
        else:
            assert (
                oh[5] == th[5]
                or "Apple_HFS" in te["Name"]
                or "Apple_APFS" in te["Name"]
            )
    image = (_FIXTURES / name).read_bytes()
    their_plst = plistlib.loads(image[their_koly[15] : their_koly[15] + their_koly[16]])
    our_plst = plistlib.loads(
        udif.image[udif.plist_at : udif.plist_at + udif.plist_length]
    )
    assert our_plst["resource-fork"]["plst"] == their_plst["resource-fork"]["plst"]


@pytest.mark.parametrize("name", ["hfs-ULFO.dmg", "apfs-ULFO.dmg", "hfs-UDCO.dmg"])
def test_gpt_matches_hdiutil(name: str) -> None:
    disk, theirs, _ = _hdiutil_disk(name)
    part = next(
        t
        for t in theirs
        if "(Apple_HFS" in t[2]["Name"] or "(Apple_APFS" in t[2]["Name"]
    )
    first, count = part[0][2], part[0][3]
    gpt_type = d.APFS_GUID if "APFS" in part[2]["Name"] else d.HFS_GUID
    tail = len(disk) // 512 - 33 - (first + count)
    written = d.write_gpt(
        [d.Partition(disk[first * 512 : (first + count) * 512], gpt_type=gpt_type)],
        tail=tail,
    )
    ours = b"".join(
        s if isinstance(s, bytes) else bytes(s.sectors * 512) for s in written.segments
    )
    assert len(ours) == len(disk)
    assert [(t.name, t.first_sector, t.sector_count) for t in written.tables] == [
        (t[2]["Name"], t[0][2], t[0][3]) for t in theirs
    ]

    def masked_header(b: bytes) -> bytes:  # the CRCs and the disk GUID differ
        h = bytearray(b[:92])
        for start, end in ((16, 20), (56, 72), (88, 92)):
            h[start:end] = bytes(end - start)
        return bytes(h)

    def masked_entry(b: bytes) -> bytes:  # the partition GUID differs
        return b[:16] + b[32:128]

    assert ours[:512] == disk[:512]  # protective MBR
    for at in (512, len(disk) - 512):
        assert masked_header(ours[at:]) == masked_header(disk[at:])
        h = bytearray(ours[at : at + 92])
        crc = struct.unpack_from("<I", h, 16)[0]
        h[16:20] = bytes(4)
        assert zlib.crc32(h) == crc
    for at in (1024, len(disk) - 33 * 512):
        assert masked_entry(ours[at : at + 128]) == masked_entry(disk[at : at + 128])
        assert ours[at + 128 : at + 32 * 512] == disk[at + 128 : at + 32 * 512]


# ── HFS+ through fsck.hfsplus ────────────────────────────────────────────────────────

_TEXT = b"hello dmg\n" * 3000
_BIG = bytes(range(256)) * 2000


def _rich_tree() -> list[d.Node]:
    nodes = [
        d.Node(
            "hello.txt",
            data=b"hello dmg\n",
            xattrs={"com.apple.provenance": b"\x01\x02", "user.big": b"x" * 5000},
        ),
        d.Node("frag.bin", data=_BIG, fragment=12),
        d.Node("sub dir/first.txt", data=b"linked content\n"),
        d.Node("other/second.txt", kind="hardlink", target="sub dir/first.txt"),
        d.Node("link", kind="symlink", target="hello.txt"),
        d.Node("café.txt", data=b"cafe"),
        d.Node("Case.txt", data=b"upper"),
        d.Node("empty", kind="dir"),
        d.Node("fifo", kind="fifo"),
        d.Node("rsrc.txt", data=b"data fork", resource_fork=b"resource fork bytes"),
    ]
    for kind in (3, 4, 7, 8, 9, 10, 11, 12):
        data = _TEXT[:300] if kind in (3, 7, 9, 11) else _TEXT
        nodes.append(d.Node(f"comp/t{kind}.txt", data=data, compression=kind))
    for kind in (4, 8, 10, 12):  # several 64 KiB chunks, some stored behind a marker
        nodes.append(d.Node(f"comp/big{kind}.bin", data=_BIG, compression=kind))
    nodes += [d.Node(f"many/f{i:04d}.txt", data=str(i).encode()) for i in range(300)]
    return nodes


_LINKED = ("sub dir/first.txt", "other/second.txt")


def _expected_files() -> dict[str, bytes]:
    return {
        n.path: n.data
        for n in _rich_tree()
        if n.kind == "file" and n.path not in _LINKED
    }


def _fsck(tmp_path: Path, volume: bytes) -> list[str]:
    path = tmp_path / "volume.img"
    path.write_bytes(volume)
    result = subprocess.run(
        ["fsck.hfsplus", "-n", "-f", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    problems = [
        line.strip()
        for line in result.stdout.splitlines()
        if not line.startswith("**")
        and "Executing fsck_hfs" not in line
        and "volume name" not in line
    ]
    return problems if result.returncode else []


@needs_fsck
@pytest.mark.parametrize(
    "options",
    [
        {},
        {"hfsx": True},
        {"hfsx": True, "case_sensitive": False},
        {"journaled": True},
        {"node_size": 8192},
        {"block_size": 512},
        {"block_size": 2048},
        {"block_size": 65536},
    ],
    ids=[
        "hfsplus",
        "hfsx",
        "hfsx-folding",
        "journaled",
        "node8k",
        "block512",
        "block2k",
        "block64k",
    ],
)
def test_hfsplus_passes_fsck(tmp_path: Path, options: dict) -> None:
    hfs = d.write_hfsplus(
        _rich_tree(), name="Fixture", attributes_in_fork=("user.big",), **options
    )
    assert _fsck(tmp_path, hfs.volume) == []


@needs_fsck
def test_hfsplus_hooks_break_the_volume(tmp_path: Path) -> None:
    def bad_header(vh: bytearray) -> None:
        struct.pack_into(">I", vh, 32, 1)  # fileCount

    hfs = d.write_hfsplus(
        _rich_tree()[:3], patch_header=bad_header, attributes_in_fork=("user.big",)
    )
    assert _fsck(tmp_path, hfs.volume)

    def drop_thread(records: list[d.CatalogRecord]) -> None:
        records[:] = [r for r in records if struct.unpack_from(">h", r.body)[0] != 4]

    hfs = d.write_hfsplus(
        _rich_tree()[:3], patch_catalog=drop_thread, attributes_in_fork=("user.big",)
    )
    assert _fsck(tmp_path, hfs.volume)


def test_hfsplus_records_where_things_went() -> None:
    nodes = _rich_tree()
    hfs = d.write_hfsplus(nodes, attributes_in_fork=("user.big",))
    assert hfs.volume[1024:1026] == b"H+"
    assert hfs.volume[-1024:-1022] == b"H+"
    assert hfs.cnids[""] == 2
    assert len(hfs.forks["frag.bin"]) == 12
    first, _count = hfs.forks["frag.bin"][0]
    assert (
        hfs.volume[first * hfs.block_size : first * hfs.block_size + 256] == _BIG[:256]
    )
    head = hfs.volume[hfs.catalog_at : hfs.catalog_at + hfs.catalog_node_size]
    assert struct.unpack_from(">b", head, 8)[0] == 1  # header node
    assert len(hfs.catalog_leaves) > 1


# ── Whole images through 7-Zip ───────────────────────────────────────────────────────


def _7z_extract(tmp_path: Path, image: bytes) -> tuple[dict[str, bytes], set[str], str]:
    """The files 7-Zip extracts (paths below the volume name), the ones it reports
    as an unsupported method, and its output."""
    path = tmp_path / "image.dmg"
    path.write_bytes(image)
    out = tmp_path / "out"
    result = run_7z(["x", "-y", f"-o{out}", str(path)], text=True)
    text = result.stdout + result.stderr
    unsupported = {
        line.split(" : ", 1)[1].strip().split("/", 1)[-1]
        for line in text.splitlines()
        if line.startswith("ERROR: Unsupported Method : ")
    }
    other_errors = [
        line
        for line in text.splitlines()
        if line.startswith("ERROR") and "Unsupported Method" not in line
    ]
    assert not other_errors, text
    files = {}
    for root, _dirs, names in os.walk(out):
        for n in names:
            full = Path(root) / n
            rel = full.relative_to(out).as_posix()
            if full.is_file() and not full.is_symlink():
                files[rel.split("/", 1)[-1]] = full.read_bytes()
    return files, unsupported, text


# 7-Zip decodes decmpfs types 3, 4, 7, 8 and 9 and reports 10, 11 and 12 (stored in
# the resource fork, LZFSE) as an unsupported method (``HfsHandler.cpp``); 7-Zip 23.01
# cannot read xz (ULMO) runs at all. A 7-Zip that reads more must read it right.
_7Z_MAY_LACK = {f"comp/t{k}.txt" for k in (10, 11, 12)} | {
    f"comp/big{k}.bin" for k in (10, 12)
}


@needs_7z
@pytest.mark.parametrize("layout", ["gpt", "apm", "none"])
@pytest.mark.parametrize("codec", _CODECS, ids=hex)
def test_7zip_reads_images(tmp_path: Path, layout: str, codec: int) -> None:
    image = d.dmg_of(
        _rich_tree(),
        layout=layout,
        codec=codec,
        hfs_options={"name": "Fixture", "attributes_in_fork": ("user.big",)},
    )
    files, unsupported, text = _7z_extract(tmp_path, image)
    if codec == d.LZMA and any(not u.startswith("comp/") for u in unsupported):
        pytest.skip("this 7-Zip cannot read xz runs")
    assert unsupported <= _7Z_MAY_LACK, text
    for path, data in _expected_files().items():
        if path in unsupported:
            continue
        got = files.get(path)
        assert got is not None, (path, sorted(files)[:20])
        assert hashlib.sha256(got).hexdigest() == hashlib.sha256(data).hexdigest(), path
    # 7-Zip lists both paths of a hard link as empty files and the data under the
    # private folder, for hdiutil's images as for these.
    assert all(files.get(p) == b"" for p in _LINKED)
    inodes = [k for k in files if k.startswith("[HFS+ Private Data]/iNode")]
    assert [files[k] for k in inodes] == [b"linked content\n"]


# 7-Zip 23.01 locates runs from offset 0 (512 with ``koly`` in front) and ignores the
# data fork offset, which later versions add; ``data_fork_at`` is checked by the reader
# above only.
@needs_7z
@pytest.mark.parametrize(
    "options",
    [
        {"mish_data_offset": 512},
        {"code_signature": bytes(300)},
        {"koly_at_front": True},
    ],
    ids=["mish-offset", "signed", "koly-front"],
)
def test_7zip_reads_layout_options(tmp_path: Path, options: dict) -> None:
    nodes = [d.Node("a.txt", data=b"layout\n" * 100)]
    files, unsupported, text = _7z_extract(
        tmp_path, d.dmg_of(nodes, codec=d.ZLIB, **options)
    )
    assert not unsupported, text
    assert files.get("a.txt") == b"layout\n" * 100
