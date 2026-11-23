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
import time
import unicodedata
import uuid
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CorruptionError,
    DecoderLimits,
    DiagnosticCode,
    EncryptionError,
    ListingLimits,
    MemberType,
    ResourceLimitError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from archivey.internal.backends import dmg_encrypted
from archivey.internal.backends.dmg_reader import volume_names
from tests import dmg_build as d
from tests.conftest import requires

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"

# The unencrypted HFS+ images, by run codec.
_HFS_IMAGES = {
    "hfs-UDZO.dmg": ["zlib"],
    "hfs-UDBZ.dmg": ["bzip2"],
    "hfs-ULFO.dmg": ["lzfse"],
    "hfs-ULMO.dmg": ["xz"],
    "hfs-UDRO.dmg": ["raw"],
}
# The encrypted ones (password "archivey"): UDZO images inside the encrcdsa layer.
_HFS_ENCRYPTED = {
    "hfs-UDZO-AES-128.dmg": ["zlib"],
    "hfs-UDZO-AES-256.dmg": ["zlib"],
}
# The encrypted images need ``cryptography``; the core-only CI jobs lack it.
_NEEDS_CRYPTO = requires("cryptography")


def _with_crypto_marks(names: object) -> list:
    return [
        pytest.param(n, marks=_NEEDS_CRYPTO) if "-AES-" in n else n
        for n in names  # type: ignore[attr-defined]
    ]


_ENCRYPTED_FIXTURES = [
    *_HFS_ENCRYPTED,
    "apfs-UDZO-AES-128.dmg",
    "apfs-UDZO-AES-256.dmg",
]


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


@pytest.mark.parametrize(
    "name", _with_crypto_marks(sorted({**_HFS_IMAGES, **_HFS_ENCRYPTED}))
)
def test_an_hdiutil_image_lists_and_reads_as_macos_mounts_it(name: str) -> None:
    hashes = _sha256_listing("hfs-sha256.txt")
    encrypted = name in _HFS_ENCRYPTED
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
    assert info.extra["dmg.run_codecs"] == {**_HFS_IMAGES, **_HFS_ENCRYPTED}[name]
    assert info.extra["dmg.code_signature"] is False
    assert info.extra.get("dmg.encryption") == (
        f"AES-{name[-7:-4]}" if encrypted else None
    )


def test_the_adc_image_reads() -> None:
    with open_archive(_FIXTURES / "hfs-UDCO.dmg") as reader:
        assert reader.info.extra["dmg.run_codecs"] == ["adc"]
        data = reader.read("repeat.txt")
    assert len(data) == 300_000
    assert hashlib.sha256(data).hexdigest().startswith("f49602b2")


@_NEEDS_CRYPTO
@pytest.mark.parametrize("name", sorted(_ENCRYPTED_FIXTURES))
def test_an_encrypted_hdiutil_image_asks_for_its_password(name: str) -> None:
    path = _FIXTURES / name
    assert detect_format(path).format is ArchiveFormat.DMG
    with pytest.raises(EncryptionError, match="the disk image is encrypted"):
        open_archive(path)
    with pytest.raises(EncryptionError, match="Wrong password for the disk image"):
        open_archive(path, password="wrong")
    # A list of passwords and a provider reach it as they reach a ZIP.
    with open_archive(path, password=["wrong", "archivey"]) as reader:
        assert reader.read("hello.txt") == b"hello dmg\n"
    asked: list[object] = []

    def provider(request: object) -> str:
        asked.append(request)
        return "archivey"

    with open_archive(path, password=provider) as reader:
        assert reader.read("hello.txt") == b"hello dmg\n"
    assert len(asked) == 1


@_NEEDS_CRYPTO
@pytest.mark.parametrize("name", sorted(_ENCRYPTED_FIXTURES))
def test_an_encrypted_image_charges_its_key_derivation(name: str) -> None:
    # Each fixture asks for 370 370 to 454 545 PBKDF2 rounds (macOS times them).
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(max_key_derivation_rounds=300_000)
    )
    with pytest.raises(ResourceLimitError, match="key derivation"):
        open_archive(_FIXTURES / name, password="archivey", config=config)


def _encrypted(image: bytes | None = None, **options: object) -> bytes:
    return d.encrypt_dmg(_image() if image is None else image, **options)  # type: ignore[arg-type]


@_NEEDS_CRYPTO
@pytest.mark.parametrize(
    "options",
    [
        {},
        {"key_bits": 256},
        {"key_bits": 192},
        {"block_size": 4096},
        {"entries": [d.EncryptedEntry(wrap="3des")]},
        # An image with no key mark: the koly block alone confirms the password.
        {"entries": [d.EncryptedEntry(wrap="3des", mark=False)]},
        {"entries": [d.EncryptedEntry(mark=False)]},
    ],
    ids=[
        "aes-128",
        "aes-256",
        "aes-192",
        "4096-blocks",
        "3des",
        "3des-no-mark",
        "no-mark",
    ],
)
def test_an_encrypted_builder_image_reads_as_the_plain_one(options: dict) -> None:
    plain_members, plain_data = _read_all(_image())
    members, data = _read_all(_encrypted(**options), password="secret")
    assert data == plain_data
    assert sorted(members) == sorted(plain_members)
    assert all(m.is_encrypted for m in members.values())  # type: ignore[attr-defined]


@_NEEDS_CRYPTO
@pytest.mark.parametrize("mark", [True, False], ids=["mark", "no-mark"])
def test_an_encrypted_image_with_its_koly_block_first_reads(mark: bool) -> None:
    # The old layout puts the koly block in the first 512 bytes; the right password
    # finds it there, as the unencrypted reader does, and is not sent to the raw-disk
    # refusal.
    plain = _image(koly_at_front=True)
    image = _encrypted(plain, entries=[d.EncryptedEntry(mark=mark)])
    _, data = _read_all(image, password="secret")
    assert data == _read_all(plain)[1]
    with pytest.raises(EncryptionError, match="Wrong password"):
        _open(image, password="other")


@_NEEDS_CRYPTO
def test_image_keys_keep_the_keys_out_of_their_repr() -> None:
    keys = dmg_encrypted.ImageKeys(b"K" * 16, b"H" * 20, True)
    assert "KKKK" not in repr(keys) and "HHHH" not in repr(keys)


@_NEEDS_CRYPTO
def test_any_password_entry_of_an_encrypted_image_unlocks_it() -> None:
    image = _encrypted(
        entries=[
            d.EncryptedEntry(kind=2),  # a certificate entry, skipped
            d.EncryptedEntry(password=b"first"),
            d.EncryptedEntry(password=b"second", wrap="3des"),
        ]
    )
    for password in ("first", "second"):
        _, data = _read_all(image, password=password)
        assert data["hello.txt"] == _expected()["hello.txt"]
    with pytest.raises(EncryptionError, match="Wrong password"):
        _open(image, password="third")


@_NEEDS_CRYPTO
def test_an_image_locked_only_by_a_certificate_is_refused_by_name() -> None:
    image = _encrypted(entries=[d.EncryptedEntry(kind=2)])
    with pytest.raises(UnsupportedFeatureError, match="certificate or keychain"):
        _open(image, password="secret")


@_NEEDS_CRYPTO
def test_a_wrong_password_that_passes_the_padding_check_is_rejected() -> None:
    # The unwrapped key's padding is right but neither the koly block nor the key
    # mark is there: a wrong password passes the padding check about once in 256.
    image = _encrypted(
        entries=[
            d.EncryptedEntry(
                mark=False, patch_plain=lambda p: p.__setitem__(0, p[0] ^ 1)
            )
        ]
    )
    with pytest.raises(EncryptionError, match="Wrong password"):
        _open(image, password="secret")


@_NEEDS_CRYPTO
def test_an_encrypted_raw_disk_is_refused_after_its_password() -> None:
    raw = d.write_gpt(
        [d.Partition(d.write_hfsplus([d.Node("a.txt", data=b"hi")]).volume)]
    )
    disk = b"".join(s for s in raw.segments if isinstance(s, bytes))
    image = d.encrypt_dmg(disk)
    with pytest.raises(EncryptionError, match="Wrong password"):
        _open(image, password="nope")
    with pytest.raises(UnsupportedFeatureError, match="read-write"):
        _open(image, password="secret")


@_NEEDS_CRYPTO
def test_a_damaged_encrypted_block_is_corruption_not_a_wrong_password() -> None:
    image = bytearray(_encrypted(_image(codec=d.ZLIB)))
    # A byte inside the encrypted data fork, well before the plist and koly.
    image[d.DATA_OFFSET + 2048] ^= 0xFF
    with (
        pytest.raises(CorruptionError) as exc_info,
        _open(bytes(image), password="secret") as reader,
    ):
        for member in reader.members():
            if member.is_file:
                reader.read(member)
    assert not isinstance(exc_info.value, EncryptionError)


def _header_patch(offset: int, fmt: str, value: int):
    def patch(header: bytearray) -> None:
        struct.pack_into(fmt, header, offset, value)

    return patch


def _blob_patch(offset: int, fmt: str, value: int):
    def patch(blob: bytearray) -> None:
        struct.pack_into(fmt, blob, offset, value)

    return patch


@_NEEDS_CRYPTO
@pytest.mark.parametrize(
    ("options", "error", "match"),
    [
        (
            {"patch_header": _header_patch(8, ">I", 3)},
            UnsupportedFeatureError,
            "version 3",
        ),
        (
            {"patch_header": _header_patch(20, ">I", 17)},
            UnsupportedFeatureError,
            "only AES",
        ),
        (
            {"patch_header": _header_patch(32, ">I", 256)},
            UnsupportedFeatureError,
            "HMAC key",
        ),
        (
            {"patch_header": _header_patch(52, ">I", 1024)},
            UnsupportedFeatureError,
            "1024-byte blocks",
        ),
        (
            {"patch_header": _header_patch(72, ">I", 17)},
            ResourceLimitError,
            "17 key entries",
        ),
        (
            {"patch_header": _header_patch(64, ">Q", 8)},
            CorruptionError,
            "inside its own key table",
        ),
        (
            {"patch_header": _header_patch(56, ">Q", 0)},
            CorruptionError,
            "0 bytes of encrypted data",
        ),
        (
            {"patch_header": _header_patch(56, ">Q", 1 << 40)},
            TruncatedError,
            "before the end of its encrypted data",
        ),
        (
            {"patch_header": _header_patch(80, ">Q", 1 << 20)},
            CorruptionError,
            "outside the header",
        ),
        (
            {"patch_header": _header_patch(88, ">Q", 20)},
            CorruptionError,
            "shorter than its",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(0, ">I", 104))]},
            UnsupportedFeatureError,
            "algorithm 104",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(88, ">I", 99))]},
            UnsupportedFeatureError,
            "only AES and 3DES",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(96, ">I", 1))]},
            UnsupportedFeatureError,
            "only CBC",
        ),
        (
            {"patch_header": _header_patch(72, ">I", 0)},
            CorruptionError,
            "no key entries",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(8, ">I", 0))]},
            CorruptionError,
            "0 PBKDF2 iterations",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(12, ">I", 33))]},
            CorruptionError,
            "33-byte salt",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(48, ">I", 17))]},
            CorruptionError,
            "17-byte IV",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(100, ">I", 40))]},
            CorruptionError,
            "40-byte wrapped key",
        ),
        (
            {"patch_header": _header_patch(12, ">I", 8)},
            UnsupportedFeatureError,
            "8-byte block IV",
        ),
        (
            {"entries": [d.EncryptedEntry(patch_blob=_blob_patch(8, ">I", 2**31))]},
            UnsupportedFeatureError,
            "2147483648 PBKDF2 iterations",
        ),
        (
            {"patch_header": _header_patch(88, ">Q", 5000)},
            ResourceLimitError,
            "5000 bytes; archivey reads at most 4096",
        ),
    ],
)
def test_a_damaged_encrypted_header_is_refused_before_any_password(
    options: dict, error: type[Exception], match: str
) -> None:
    image = _encrypted(**options)
    for password in (None, "secret"):
        with pytest.raises(error, match=match):
            _open(image, password=password)


@_NEEDS_CRYPTO
def test_a_cut_encrypted_image_is_truncated_before_any_password() -> None:
    image = _encrypted()
    with pytest.raises(TruncatedError, match="before the end of its encrypted data"):
        _open(image[:-1])


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


def test_a_compressed_hard_link_hides_its_decmpfs_attribute_under_every_name() -> None:
    nodes = [
        d.Node("a.txt", data=_TEXT, compression=4, xattrs={"user.tag": b"t"}),
        d.Node("b.txt", kind="hardlink", target="a.txt"),
    ]
    members, data = _read_all(_image(nodes))
    assert data["a.txt"] == _TEXT
    for name in ("a.txt", "b.txt"):
        xattrs = members[name].extra["dmg.xattrs"]  # type: ignore[attr-defined]
        assert "user.tag" in xattrs
        assert "com.apple.decmpfs" not in xattrs


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


def _volume_names_by_probing(labels: list[str]) -> list[str]:
    """The naming rule spelled out: probe `` 1``, `` 2``, ... against every name
    taken so far, compared but for case."""
    taken: list[str] = []
    for label in labels:
        base = label.replace("/", ":")
        if base in ("", ".", ".."):
            base = "Untitled"
        name, n = base, 0
        while name.casefold() in {t.casefold() for t in taken}:
            n += 1
            name = f"{base} {n}"
        taken.append(name)
    return taken


def test_volume_names_match_the_probing_rule() -> None:
    import random

    rng = random.Random(1786)
    pieces = [
        "a",
        "A",
        "a 1",
        "A 2",
        "ß",
        "SS",
        "ss",
        "",
        ".",
        "Untitled",
        "UNTITLED 1",
    ]
    for _ in range(2000):
        labels = rng.choices(pieces, k=rng.randint(1, 12))
        assert volume_names(labels) == _volume_names_by_probing(labels), labels


@pytest.mark.timeout(30)
def test_volume_names_that_differ_only_in_case_are_named_in_linear_time() -> None:
    """Each suffix probe rebuilt the casefolded set of the names taken, so labels
    that differ only in case took cubic time (800 of them took seconds)."""
    labels = ["a", "A"] * 10_000
    start = time.perf_counter()
    names = volume_names(labels)
    assert time.perf_counter() - start < 5
    assert names[:4] == ["a", "A 1", "a 2", "A 3"]
    assert len({n.casefold() for n in names}) == len(labels)


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


def test_overlapping_apm_entries_use_the_run_tables() -> None:
    """Two map entries over the same sectors: the map is refused, as a GPT's would be,
    so the volume is listed once."""
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    volume = hfs.volume + bytes(-len(hfs.volume) % d.SECTOR)

    def same_start(index: int, entry: bytearray) -> None:
        if index == 2:  # the second partition's entry starts at the first's sector
            struct.pack_into(">I", entry, 8, 64)

    disk = d.write_apm(
        [d.Partition(volume, name="one"), d.Partition(bytes(len(volume)), name="two")],
        patch_map=same_start,
    )
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert [m.name for m in reader.members() if m.is_file] == ["a.txt"]
        assert reader.info.extra["dmg.partition_scheme"] == "none"
        assert "partition_map" in _structures(reader)


def test_overlapping_gpt_entries_use_the_run_tables() -> None:
    """The GPT twin of the test above: the second entry starts at the first's
    sector (the CRCs are computed after the patch)."""
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a")])
    volume = hfs.volume + bytes(-len(hfs.volume) % d.SECTOR)

    def same_start(entries: bytearray) -> None:
        (first,) = struct.unpack_from("<Q", entries, 32)
        struct.pack_into("<Q", entries, 128 + 32, first)

    disk = d.write_gpt(
        [d.Partition(volume, name="one"), d.Partition(bytes(len(volume)), name="two")],
        patch_entries=same_start,
    )
    image = d.write_udif(disk.segments, tables=disk.tables).image
    with _open(image) as reader:
        assert [m.name for m in reader.members() if m.is_file] == ["a.txt"]
        assert reader.info.extra["dmg.partition_scheme"] == "none"
        assert "partition_map" in _structures(reader)


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


def test_an_extents_file_short_of_its_blocks_is_corruption() -> None:
    """The extents overflow file has no overflow extents of its own (TN1150): its
    fork record holding fewer blocks than it says is damage, not a lookup."""

    def short(header: bytearray) -> None:
        at = 192 + 12  # the extents file fork's totalBlocks
        struct.pack_into(">I", header, at, struct.unpack_from(">I", header, at)[0] + 5)

    image = d.dmg_of(
        [d.Node("a.bin", data=b"x" * 4096 * 12, fragment=12)],
        hfs_options={"patch_header": short},
    )
    with (
        pytest.raises(CorruptionError, match="extents overflow file's eight"),
        _open(image) as reader,
    ):
        reader.members()
        reader.read("a.bin")


def _count_extents_nodes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The node numbers the extents overflow B-tree reads, in order."""
    from archivey.internal.backends import hfsplus

    reads: list[int] = []
    node = hfsplus._BTree.node

    def counted(self, number: int):  # type: ignore[no-untyped-def]
        if self._name == "extents":
            reads.append(number)
        return node(self, number)

    monkeypatch.setattr(hfsplus._BTree, "node", counted)
    return reads


def test_overflow_extents_are_read_along_the_leaf_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fork with many overflow records finds the first one down the index and walks
    the leaf chain from there: each extents node is read once per fork reader, not
    once per record."""
    data = bytes(range(256)) * 2 * 400  # 400 blocks of 512 bytes
    image = d.dmg_of(
        [d.Node("a.bin", data=data, fragment=400)],
        hfs_options={"block_size": 512, "node_size": 512},
    )
    reads = _count_extents_nodes(monkeypatch)
    with _open(image, seekable_members=True) as reader:
        assert reader.read("a.bin") == data
        with reader.open("a.bin") as stream:
            for at in (0, 511, 512, 100_000, len(data) - 1):
                stream.seek(at)
                assert stream.read(700) == data[at : at + 700]
    # 49 overflow records of 8 extents, about 10 to a 512-byte node.
    assert max(Counter(reads).values()) <= 2  # one walk per fork reader: read, open
    assert len(set(reads)) < 15


@pytest.mark.parametrize("link", ["skip", "loop"])
def test_a_broken_extents_leaf_chain_falls_back_to_a_search(
    monkeypatch: pytest.MonkeyPatch, link: str
) -> None:
    """When the extents leaf chain does not lead to the next overflow record (it skips
    a leaf, or loops), that record is searched for from the root, so the file reads
    as before."""
    from archivey.internal.backends import hfsplus

    data = bytes(range(256)) * 2 * 400
    image = d.dmg_of(
        [d.Node("a.bin", data=data, fragment=400)],
        hfs_options={"block_size": 512, "node_size": 512},
    )
    node = hfsplus._BTree.node
    broken: list[int] = []

    def relinked(self, number: int):  # type: ignore[no-untyped-def]
        flink, kind, height, records = node(self, number)
        if self._name == "extents" and kind == -1 and flink and not broken:
            broken.append(number)
            flink = flink + 1 if link == "skip" else number
        return flink, kind, height, records

    monkeypatch.setattr(hfsplus._BTree, "node", relinked)
    with _open(image) as reader:
        assert reader.read("a.bin") == data
    assert broken


def test_extents_past_the_fork_size_are_not_looked_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocks allocated past a fork's size are never read, so their overflow records
    are not looked up: a 0-byte fork listing many extents costs no extents read."""

    def zero_size(body: bytearray) -> None:
        struct.pack_into(">Q", body, 88, 0)  # the data fork's logicalSize

    image = d.dmg_of(
        [d.Node("a.bin", data=bytes(512 * 200), fragment=200)],
        hfs_options={
            "block_size": 512,
            "patch_catalog": _patch_file("a.bin", zero_size),
        },
    )
    reads = _count_extents_nodes(monkeypatch)
    with _open(image) as reader:
        assert reader.read("a.bin") == b""
    assert reads == []


def _attribute_extent_records(
    monkeypatch: pytest.MonkeyPatch,
    count: int,
    total_blocks: int | None = None,
    first_only: bool = False,
) -> None:
    """Make the builder add ``count`` extent records (0x30) of eight one-block
    extents after each fork attribute record (0x20), or only after the first one in
    key order, and set that fork's block count to ``total_blocks`` when given."""
    real = d._btree

    def btree(records, node_size, **kwargs):
        if kwargs.get("max_key") == 266:  # the attributes tree
            out = []
            done = False
            for key, data in records:
                if struct.unpack_from(">I", data)[0] != 0x20 or (first_only and done):
                    out.append((key, data))
                    continue
                done = True
                if total_blocks is not None:
                    data = bytearray(data)
                    struct.pack_into(">I", data, 8 + 12, total_blocks)
                    data = bytes(data)
                out.append((key, data))
                body = struct.pack(">II", 0x30, 0) + struct.pack(">II", 1, 1) * 8
                out += [(key, body)] * count
            records = out
        return real(records, node_size, **kwargs)

    monkeypatch.setattr(d, "_btree", btree)


def test_attribute_extents_past_the_fork_blocks_fail_that_file_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Extent records (0x30) that hold more blocks than the attribute's fork: that
    file is listed without the attribute, with a warning, and the others list."""
    _attribute_extent_records(monkeypatch, 3, first_only=True)
    image = d.dmg_of(
        [
            d.Node("a", data=b"1", xattrs={"x": b"v" * 10, "y": b"w"}),
            d.Node("b", data=b"2", xattrs={"x": b"v" * 10, "y": b"w"}),
        ],
        hfs_options={"attributes_in_fork": ["x"]},
    )
    with _open(image) as reader:
        members = {m.name: m for m in reader.members()}
        assert DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED in _codes(reader)
    assert members["a"].extra["dmg.xattrs"] == {"y": b"w"}
    assert members["b"].extra["dmg.xattrs"] == {"x": None, "y": b"w"}


def test_attribute_extents_are_charged_to_max_metadata_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 200 records of eight extents: 1600 extents of about 100 bytes each in memory,
    # past a 64 KiB cap. At 8 bytes each (their size on disk) they would fit.
    _attribute_extent_records(monkeypatch, 200, total_blocks=0xFFFF_FFFF)
    image = d.dmg_of(
        [d.Node("f", data=b"hi", xattrs={"x": b"v" * 10})],
        hfs_options={"attributes_in_fork": ["x"], "node_size": 32768},
    )
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=64 << 10))
    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
        _open(image, config=config) as reader,
    ):
        reader.members()


def test_a_fork_attribute_split_over_an_extent_record_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A decmpfs attribute in a fork whose extents go on in an extent record (0x30):
    the file reads whole."""
    data = bytes(range(256)) * 40  # with its header, three blocks of 4096
    real = d._btree

    def btree(records, node_size, **kwargs):
        if kwargs.get("max_key") != 266:  # not the attributes tree
            return real(records, node_size, **kwargs)
        out = []
        for key, body in records:
            if struct.unpack_from(">I", body)[0] != 0x20:
                out.append((key, body))
                continue
            start, blocks = struct.unpack_from(">II", body, 8 + 16)
            assert blocks >= 2
            head = bytearray(body)
            struct.pack_into(">II", head, 8 + 16, start, 1)
            more_key = bytearray(key)
            struct.pack_into(">I", more_key, 8, 1)  # the record's start block
            more = struct.pack(">IIII", 0x30, 0, start + 1, blocks - 1) + bytes(56)
            out += [(key, bytes(head)), (bytes(more_key), more)]
        return real(out, node_size, **kwargs)

    monkeypatch.setattr(d, "_btree", btree)
    image = d.dmg_of(
        [d.Node("f", data=data, compression=9)],
        hfs_options={"attributes_in_fork": ["com.apple.decmpfs"]},
    )
    with _open(image) as reader:
        assert reader.read("f") == data


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


def _cut_chain(nodes_: list[bytearray]) -> None:
    # The first leaf's forward link is 0: the chain ends there.
    first = next(i for i, n in enumerate(nodes_) if n[8:9] == b"\xff")
    struct.pack_into(">I", nodes_[first], 0, 0)


def _miscount(nodes_: list[bytearray]) -> None:
    # The header record's leafRecords, after the node descriptor, depth and root.
    at = 14 + 2 + 4
    struct.pack_into(
        ">I", nodes_[0], at, struct.unpack_from(">I", nodes_[0], at)[0] + 1
    )


@pytest.mark.parametrize(
    ("patch", "match", "listed"),
    [
        (_cut_chain, "ends at node", lambda n: 0 < n < 60),
        (_miscount, "header declares", lambda n: n == 60),
    ],
    ids=["cut", "miscounted"],
)
def test_a_catalog_leaf_chain_short_of_its_header_is_corruption(
    patch: Callable[[list[bytearray]], None],
    match: str,
    listed: Callable[[int], bool],
) -> None:
    """A leaf chain that ends before the header's lastLeafNode, or holds another
    number of records than its leafRecords, has lost members: the members it found
    are listed, then the error comes."""
    nodes = [d.Node(f"f{i:03d}.txt", data=b"x") for i in range(60)]
    seen: list[str] = []
    with (
        _open(
            _image(nodes, hfs_options={"patch_catalog_nodes": patch, "node_size": 512})
        ) as reader,
        pytest.raises(CorruptionError, match=match),
    ):
        for member in reader:
            seen.append(member.name)
    assert listed(len(seen))


def test_an_attributes_leaf_chain_short_of_its_header_is_corruption() -> None:
    """The attributes B-tree gets the same check: every member is listed, then the
    error comes."""
    nodes = [
        d.Node(f"f{i}.txt", data=b"x", xattrs={"user.tag": b"t"}) for i in range(4)
    ]
    seen: list[str] = []
    with (
        _open(
            _image(
                nodes,
                hfs_options={"patch_attributes_nodes": _miscount, "node_size": 512},
            )
        ) as reader,
        pytest.raises(CorruptionError, match="attributes B-tree.*header declares"),
    ):
        for member in reader:
            seen.append(member.name)
    assert sorted(seen) == [f"f{i}.txt" for i in range(4)]


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


@pytest.mark.parametrize(
    "stored", ["..", ".", "", "a\0b"], ids=["dotdot", "dot", "empty", "nul"]
)
def test_an_hfs_name_that_cannot_be_a_path_component_is_damage(stored: str) -> None:
    """A catalog name that is ``..``, ``.``, empty or holds a NUL is left out, the
    other members are listed, and the listing ends with the error (DR-2)."""
    nodes = [
        d.Node("sub/bad", data=b"x", raw_name=stored.encode("utf-16-be")),
        d.Node("sub/ok", data=b"ok"),
        d.Node("top", data=b"t"),
    ]
    seen: list[str] = []
    with (
        _open(_image(nodes)) as reader,
        pytest.raises(CorruptionError, match="cannot be a path component"),
    ):
        for member in reader:
            seen.append(member.name)
    assert sorted(seen) == ["sub/", "sub/ok", "top"]


def test_a_bad_name_beside_an_orphan_names_both() -> None:
    nodes = [
        d.Node("sub/bad", data=b"x", raw_name="..".encode("utf-16-be")),
        d.Node("o/orph", data=b"o"),
        d.Node("top", data=b"t"),
    ]

    def orphan(records: list[d.CatalogRecord]) -> None:
        raw = "orph".encode("utf-16-be")
        next(r for r in records if r.name == raw).parent = 9999

    seen: list[str] = []
    with (
        _open(_image(nodes, hfs_options={"patch_catalog": orphan})) as reader,
        pytest.raises(
            CorruptionError,
            match=r"\('\.\.' in the folder 'sub'\) and is not listed; also, 1 record is",
        ),
    ):
        for member in reader:
            seen.append(member.name)
    assert sorted(seen) == ["o/", "sub/", "top"]


def test_an_hfs_folder_named_dotdot_leaves_out_what_it_holds() -> None:
    """A folder stored as ``..`` listed its child as ``../evil.txt``."""
    nodes = [
        d.Node("up", kind="dir", raw_name="..".encode("utf-16-be")),
        d.Node("up/deeper/evil.txt", data=b"evil"),
        d.Node("ok", data=b"ok"),
    ]
    seen: list[str] = []
    with (
        _open(_image(nodes)) as reader,
        pytest.raises(
            CorruptionError, match=r"'\.\.' in the folder '/'.*nor are 2 records inside"
        ),
    ):
        for member in reader:
            seen.append(member.name)
    assert seen == ["ok"]


def test_an_hfs_name_with_a_slash_is_listed_with_a_colon() -> None:
    nodes = [d.Node("a", data=b"a", raw_name="x/y".encode("utf-16-be"))]
    _, data = _read_all(_image(nodes))
    assert data == {"x:y": b"a"}


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


def test_a_type_10_chunk_without_its_marker_is_corrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS reads a type 10 chunk only after a 0xCC byte and refuses one without."""
    real = d._decmpfs

    def no_marker(kind: int, data: bytes) -> tuple[bytes, bytes]:
        value, fork = real(kind, data)
        if kind == 10:
            fork = struct.pack("<II", 8, 8 + len(data)) + data
        return value, fork

    monkeypatch.setattr(d, "_decmpfs", no_marker)
    image = _image(
        [d.Node("t10", data=b"plain", compression=10), d.Node("ok", data=b"1")]
    )
    with _open(image) as reader:
        assert reader.read("ok") == b"1"
        with pytest.raises(CorruptionError, match="0xCC"):
            reader.read("t10")


@pytest.mark.parametrize("kind", [7, 11])
def test_a_compressed_chunk_past_its_size_names_that_size(
    monkeypatch: pytest.MonkeyPatch, kind: int
) -> None:
    """An inline LZVN (7) or LZFSE (11) value that decodes to 3 bytes more than its
    header's size: the error names the size."""
    real = d._decmpfs

    def short(kind_: int, data: bytes) -> tuple[bytes, bytes]:
        value, fork = real(kind_, data)
        if kind_ == kind:
            value = value[:8] + struct.pack("<Q", len(data) - 3) + value[16:]
        return value, fork

    monkeypatch.setattr(d, "_decmpfs", short)
    image = _image([d.Node("c", data=b"abcdefgh", compression=kind)])
    with (
        _open(image) as reader,
        pytest.raises(CorruptionError, match="decodes to more than 5 bytes"),
    ):
        reader.read("c")


@pytest.mark.parametrize(
    "damage", ["renamed", "moved", "missing", "short", "long name"]
)
def test_a_folder_thread_that_disagrees_is_reported(damage: str) -> None:
    """Paths come from the folder records; a thread record that is missing, unreadable,
    or names another parent or name is reported once, and the listing is the same."""
    nodes = [d.Node("a/x", data=b"x"), d.Node("b/y", data=b"y")]

    def patch(records: list[d.CatalogRecord]) -> None:
        def folder_id(name: str) -> int:
            raw = name.encode("utf-16-be")
            record = next(
                r
                for r in records
                if r.name == raw and struct.unpack_from(">h", r.body)[0] == 1
            )
            return struct.unpack_from(">I", record.body, 8)[0]

        a = folder_id("a")
        thread = next(
            r
            for r in records
            if r.parent == a and struct.unpack_from(">h", r.body)[0] == 3
        )
        if damage == "missing":
            records.remove(thread)
        elif damage == "moved":
            struct.pack_into(">I", thread.body, 4, folder_id("b"))
        elif damage == "short":
            del thread.body[8:]
        elif damage == "long name":
            struct.pack_into(">H", thread.body, 8, 300)
        else:
            struct.pack_into(">H", thread.body, 10, ord("z"))

    with _open(_image(nodes, hfs_options={"patch_catalog": patch})) as reader:
        names = sorted(m.name for m in reader.members())
        assert _structures(reader) == ["folder_thread"]
    assert names == ["a/", "a/x", "b/", "b/y"]


def test_folder_threads_are_charged_for_the_memory_they_hold() -> None:
    """Many tiny thread records cost far more than their 10 bytes each to keep."""

    def patch(records: list[d.CatalogRecord]) -> None:
        for cnid in range(100_000, 102_000):
            body = bytearray(struct.pack(">hhIH", 3, 0, 2, 0))
            records.append(d.CatalogRecord(cnid, b"", body))

    image = _image([d.Node("a/x", data=b"x")], hfs_options={"patch_catalog": patch})
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=256 << 10))
    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
        _open(image, config=config) as reader,
    ):
        reader.members()


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


def test_max_metadata_bytes_applies_to_folder_paths_in_a_hidden_folder() -> None:
    """The folders inside a hidden folder never become members, so only the charge
    of their built paths stops a deep chain: the paths cost the square of its depth."""
    path = ".HFS+ Private Directory Data\r/" + "/".join(["n" * 255] * 200)
    image = _image([d.Node(path, kind="dir")], hfs_options={"node_size": 32768})
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=1 << 20))
    with (
        pytest.raises(ResourceLimitError, match="HFS\\+ folder paths"),
        _open(image, config=config) as reader,
    ):
        reader.members()


def test_a_property_list_over_its_cap_is_refused_before_it_is_read() -> None:
    def huge(koly: bytearray) -> None:
        struct.pack_into(">Q", koly, 224, 65 << 20)

    image = d.write_udif(bytes(64 * d.SECTOR), patch_koly=huge).image
    with pytest.raises(ResourceLimitError, match="property list"):
        _open(image, format=ArchiveFormat.DMG)


@pytest.mark.parametrize("encoding", [b"UTF-9", b"rot13"])
def test_a_property_list_with_an_unusable_encoding_is_corruption(
    encoding: bytes,
) -> None:
    image = d.dmg_of([d.Node("a.txt", data=b"hi")])
    damaged = image.replace(b'encoding="UTF-8"', b'encoding="' + encoding + b'"')
    assert damaged != image
    with pytest.raises(CorruptionError, match="property list .* does not parse"):
        _open(damaged)


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


# ── The partition CRC-32 pass (design §7.2) ──────────────────────────────────────────


def _files(reader) -> list:
    return [m for m in reader.members() if m.is_file]


@pytest.mark.parametrize(
    "name",
    _with_crypto_marks(sorted({**_HFS_IMAGES, **_HFS_ENCRYPTED}) + ["hfs-UDCO.dmg"]),
)
def test_verify_all_raises_every_file_of_an_hdiutil_image_to_checksum(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.backends.udif import UdifImage

    passes: list[str] = []
    table_crc = UdifImage.table_crc

    def counted(self: UdifImage, table: object, draw: object = None) -> int:
        passes.append(table.name)  # type: ignore[attr-defined]
        return table_crc(self, table, draw)  # type: ignore[arg-type]

    monkeypatch.setattr(UdifImage, "table_crc", counted)
    password = "archivey" if name in _HFS_ENCRYPTED else None
    with open_archive(_FIXTURES / name, password=password) as reader:
        files = _files(reader)
        assert files
        assert {m.verifiable for m in files} == {Verification.CHECKSUM}
        # A plain read proves the length only: it does not run the pass.
        for m in files:
            reader.read(m)
        assert {m.verified for m in files} == {Verification.LENGTH}
        assert not passes
        report = reader.verify_all()
        assert report.ok, report.failures
        assert {m.verified for m in files} == {Verification.CHECKSUM}
        # The one table over the HFS+ partition, checked once; kept for the next call.
        assert passes == ["disk image (Apple_HFS : 4)"]
        assert reader.verify_all().ok
        assert len(passes) == 1


def _boot_block_flipper(which: set[int]) -> Callable[[int, bytes], bytes]:
    """A run encoder that changes byte 100 of the boot blocks of the HFS+ volumes
    numbered in ``which`` (0 for the first), after the builder took the CRC-32 of the
    real bytes. Nothing reads the boot blocks: no member read reaches the change."""
    seen = [0]

    def encode(kind: int, data: bytes) -> bytes:
        if data[1024:1026] in (b"H+", b"HX"):
            n = seen[0]
            seen[0] += 1
            if n in which:
                data = data[:100] + bytes([data[100] ^ 0xFF]) + data[101:]
        return d.encode_run(kind, data)

    return encode


def _two_volumes(*, merged: bool = False, flip: frozenset[int] = frozenset()) -> bytes:
    """Two HFS+ volumes in a GPT disk, in zlib runs of 8 sectors. With ``merged``,
    one run table covers both partitions and the sectors between them. ``flip``
    names the volumes whose boot blocks the stored runs change."""
    parts = []
    for name in ("One", "Two"):
        hfs = d.write_hfsplus(
            [d.Node("readme.txt", data=f"in {name}\n".encode() * 50)], name=name
        )
        parts.append(d.Partition(hfs.volume, name=name))
    disk = d.write_gpt(parts)
    tables = disk.tables
    if merged:
        start = disk.starts[0]
        last = next(t for t in tables if t.first_sector == disk.starts[1])
        end = last.first_sector + last.sector_count
        tables = sorted(
            [t for t in tables if not start <= t.first_sector < end]
            + [d.Table("both volumes", start, end - start)],
            key=lambda t: t.first_sector,
        )
    return d.write_udif(
        disk.segments,
        tables=tables,
        run_sectors=8,
        encode=_boot_block_flipper(set(flip)),
    ).image


def _failed(report) -> set[str]:
    return {m.name for m, _ in report.failures}


def test_a_change_no_member_reads_is_caught_by_verify_all() -> None:
    image = _two_volumes(flip=frozenset({1}))
    with _open(image) as reader:
        # Every read passes: the changed byte is in no member's data.
        assert reader.read("Two/readme.txt") == b"in Two\n" * 50
        report = reader.verify_all()
        assert _failed(report) == {"Two/readme.txt"}
        (error,) = {e for _, e in report.failures}
        assert isinstance(error, CorruptionError)
        assert "Two (Apple_HFS : 5)" in str(error)
        assert "CRC-32" in str(error)
        assert reader.get("One/readme.txt").verified is Verification.CHECKSUM
        assert reader.get("Two/readme.txt").verified is Verification.LENGTH
        # Kept: a second call fails the same files, decoding nothing again.
        assert _failed(reader.verify_all()) == {"Two/readme.txt"}


def test_one_table_over_two_partitions_is_checked_whole() -> None:
    with _open(_two_volumes(merged=True)) as reader:
        assert reader.verify_all().ok
        assert {m.verified for m in _files(reader)} == {Verification.CHECKSUM}
    # A change in the second partition fails the files of both.
    with _open(_two_volumes(merged=True, flip=frozenset({1}))) as reader:
        report = reader.verify_all()
        assert _failed(report) == {"One/readme.txt", "Two/readme.txt"}
        assert "both volumes" in str(report.failures[0][1])


def test_a_run_that_fails_to_decode_in_the_pass_names_the_run() -> None:
    def broken(kind: int, data: bytes) -> bytes:
        stored = d.encode_run(kind, data)
        # The run that ends the volume, with its alternate volume header, which
        # nothing reads but the pass: its Adler-32 no longer matches.
        if data[-1024:-1022] == b"H+":
            return stored[:-1] + bytes([stored[-1] ^ 1])
        return stored

    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a" * 3000)])
    disk = d.write_gpt([d.Partition(hfs.volume)])
    image = d.write_udif(
        disk.segments, tables=disk.tables, run_sectors=8, encode=broken
    ).image
    with _open(image) as reader:
        assert reader.read("a.txt") == b"a" * 3000
        report = reader.verify_all()
        (pair,) = report.failures
        assert pair[0].name == "a.txt"
        assert "zlib run for disk sector" in str(pair[1])


def test_a_partition_with_an_unchecked_table_stays_at_length() -> None:
    def no_crc(index: int, mish: bytearray) -> None:
        struct.pack_into(">II", mish, 64, 0, 0)  # checksum type and bits: none

    hfs = d.write_hfsplus([d.Node("a.txt", data=b"a" * 3000)])
    disk = d.write_gpt([d.Partition(hfs.volume)])
    image = d.write_udif(disk.segments, tables=disk.tables, patch_mish=no_crc).image
    with _open(image) as reader:
        assert reader.get("a.txt").verifiable is Verification.LENGTH
        assert reader.verify_all().ok
        assert reader.get("a.txt").verified is Verification.LENGTH


def test_a_zero_fill_run_of_a_petabyte_is_checked_in_no_time() -> None:
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"zeros follow\n")])
    volume = hfs.volume + bytes(-len(hfs.volume) % d.SECTOR)
    huge = 1 << 41  # sectors: 2^50 bytes
    sectors = len(volume) // d.SECTOR + huge
    image = d.write_udif(
        [volume, d.Zeros(huge)],
        tables=[d.Table("disk image (Apple_HFS : 0)", 0, sectors)],
    ).image
    with _open(image) as reader:
        assert reader.get("a.txt").verifiable is Verification.CHECKSUM
        started = time.monotonic()
        assert reader.verify_all().ok, reader.verify_all().failures
        assert time.monotonic() - started < 5
        assert reader.get("a.txt").verified is Verification.CHECKSUM


def test_a_wrong_data_fork_checksum_fails_the_checked_files() -> None:
    def wrong(koly: bytearray) -> None:
        koly[88] ^= 0xFF  # the first byte of the data fork's CRC-32

    image = _image([d.Node("a.txt", data=b"fork\n")], patch_koly=wrong)
    with _open(image) as reader:
        report = reader.verify_all()
        assert _failed(report) == {"a.txt"}
        assert "data fork" in str(report.failures[0][1])


def test_a_wrong_master_checksum_fails_the_checked_files() -> None:
    def wrong(koly: bytearray) -> None:
        koly[0x168] ^= 0xFF  # the first byte of the master CRC-32

    image = _image([d.Node("a.txt", data=b"master\n")], patch_koly=wrong)
    with _open(image) as reader:
        report = reader.verify_all()
        assert _failed(report) == {"a.txt"}
        assert "master checksum" in str(report.failures[0][1])


def test_the_pass_is_held_to_the_archive_wide_ratio() -> None:
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"small\n")])
    volume = hfs.volume + bytes(-len(hfs.volume) % d.SECTOR)
    filler = b"\x01" * (
        4 << 20
    )  # past the volume, in the same table: no member reads it
    sectors = (len(volume) + len(filler)) // d.SECTOR
    image = d.write_udif(
        [volume, filler], tables=[d.Table("disk image (Apple_HFS : 0)", 0, sectors)]
    ).image
    limits = DecoderLimits(max_ratio=50.0, ratio_activation_threshold=0)
    config = ArchiveyConfig(decoder_limits=limits)
    with _open(image, config=config) as reader:
        assert reader.read("a.txt") == b"small\n"
        report = reader.verify_all()
        ((member, error),) = report.failures
        assert member.name == "a.txt"
        assert "did not run" in str(error)
        assert isinstance(error.__cause__, ResourceLimitError)
        assert member.verified is Verification.LENGTH
    with _open(image) as reader:
        assert reader.verify_all().ok


def test_raw_runs_that_share_stored_bytes_count_toward_the_pass_ratio() -> None:
    hfs = d.write_hfsplus([d.Node("a.txt", data=b"small\n")])
    volume = hfs.volume + bytes(-len(hfs.volume) % d.SECTOR)
    first_filler = len(volume) // d.SECTOR
    filler = b"\x01" * (4 << 20)  # 1024 raw runs of 8 sectors past the volume
    sectors = first_filler + len(filler) // d.SECTOR

    def alias(index: int, mish: bytearray) -> None:
        # Every filler run reads the first filler run's stored bytes.
        (count,) = struct.unpack_from(">I", mish, d.MISH.size - 4)
        first = None
        for i in range(count):
            at = d.MISH.size + d.RUN.size * i
            kind, _, sector, _, offset, _ = d.RUN.unpack_from(mish, at)
            if kind != d.RAW or sector < first_filler:
                continue
            if first is None:
                first = offset
            struct.pack_into(">QQ", mish, at + 24, first, 8 * d.SECTOR)

    stored = [False]

    def store_once(kind: int, data: bytes) -> bytes:
        # The filler's bytes are stored once; ``alias`` points every run at them.
        if data != filler[: len(data)]:
            return data
        if stored[0]:
            return b""
        stored[0] = True
        return data

    image = d.write_udif(
        [volume, filler],
        tables=[d.Table("disk image (Apple_HFS : 0)", 0, sectors)],
        choose=lambda sector, data: d.RAW,
        encode=store_once,
        run_sectors=8,
        patch_mish=alias,
    ).image
    assert len(image) < len(volume) + (256 << 10)
    # 4 MiB of raw runs read from 4 KiB of stored filler: past a ratio of 2.
    limits = DecoderLimits(max_ratio=2.0, ratio_activation_threshold=0)
    with _open(image, config=ArchiveyConfig(decoder_limits=limits)) as reader:
        assert reader.read("a.txt") == b"small\n"
        ((member, error),) = reader.verify_all().failures
        assert member.name == "a.txt"
        assert "did not run" in str(error)
        assert isinstance(error.__cause__, ResourceLimitError)
