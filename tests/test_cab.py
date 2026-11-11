"""Microsoft cabinets: stored, MSZIP and LZX folders, read through the CAB backend."""

from __future__ import annotations

import functools
import io
import random
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

import archivey
from archivey import (
    AccessCost,
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyError,
    CompressionAlgorithm,
    CorruptionError,
    DecoderLimits,
    DiagnosticCode,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from archivey.internal.backends import cab_reader
from archivey.internal.streams.codecs import lzx_decoder
from archivey.internal.streams.codecs.lzx_decoder import LzxDecoder
from tests.cab_util import (
    FRAME,
    BitWriter,
    CabFile,
    CabFolder,
    LzxEncoder,
    _Token,
    block_checksum,
    canonical_codes,
    checksum as oracle_checksum,
    code_lengths,
    write_cab,
)

LIBARCHIVE = Path(__file__).parent / "fixtures" / "external" / "cab_libarchive"
_RNG = random.Random(7)
TEXT = b"".join(
    b"line %d: %s\n" % (i, bytes(_RNG.choice(b"abcdefgh ") for _ in range(i % 40)))
    for i in range(4000)
)
BLOB = _RNG.randbytes(70001)
# x86-like bytes: CALL opcodes the E8 translation rewrites.
CODE = bytes(_RNG.choice([0xE8, 0x00, 0x01, 0xFF, 0x90]) for _ in range(40000))
FILES = [
    CabFile("docs\\text.txt", TEXT),
    CabFile("blob.bin", BLOB),
    CabFile("bin\\code.exe", CODE),
]
NAMES = ["docs/text.txt", "blob.bin", "bin/code.exe"]

LZX_CASES = {
    "lzx-15": CabFolder("lzx", 15),
    "lzx-16": CabFolder("lzx", 16),
    "lzx-21": CabFolder("lzx", 21),
    "lzx-aligned": CabFolder(
        "lzx", 17, LzxEncoder(window_bits=17, blocks=("aligned",), block_size=50000)
    ),
    # An odd-sized uncompressed block that crosses a frame, then the pad byte.
    "lzx-mixed": CabFolder(
        "lzx",
        15,
        LzxEncoder(
            window_bits=15,
            blocks=("verbatim", "uncompressed", "aligned"),
            block_size=20001,
        ),
    ),
    "lzx-e8": CabFolder(
        "lzx",
        16,
        LzxEncoder(
            window_bits=16,
            e8_file_size=12_000_000,
            blocks=("verbatim", "uncompressed"),
            block_size=40001,
        ),
    ),
    "lzx-no-runs": CabFolder("lzx", 16, LzxEncoder(window_bits=16, use_runs=False)),
}
CASES = {"stored": CabFolder("none"), "mszip": CabFolder("mszip"), **LZX_CASES}


def _cab(folder: CabFolder, files: list[CabFile] = FILES) -> bytes:
    return write_cab(files, [folder])


@functools.cache
def _case(case: str) -> bytes:
    """The three files in one folder of ``case``, encoded once per run."""
    return _cab(CASES[case])


@functools.cache
def _lzx_unchecked() -> bytes:
    return _cab(CabFolder("lzx", 16, checksums=False), FILES[:1])


@pytest.mark.parametrize("case", list(CASES))
def test_every_method_lists_and_reads(case: str) -> None:
    raw = _case(case)
    with open_archive(io.BytesIO(raw)) as reader:
        assert reader.format == ArchiveFormat.CAB
        assert reader.info.format_version == "1.3"
        solid = case != "stored"
        assert reader.info.is_solid is solid
        assert reader.cost.access_cost is (
            AccessCost.SOLID if solid else AccessCost.DIRECT
        )
        read = {}
        for member, stream in reader.stream_members():
            assert stream is not None
            read[member.name] = stream.read()
            assert member.verified is Verification.CHECKSUM
            assert member.modified is not None
            assert member.modified.year == 2025
        assert read == dict(zip(NAMES, (f.data for f in FILES), strict=True))
        algo = reader.members()[0].compression[0].algo
        expected = {
            "stored": CompressionAlgorithm.STORED,
            "mszip": CompressionAlgorithm.DEFLATE,
        }.get(case, CompressionAlgorithm.LZX)
        assert algo is expected
        assert not reader.diagnostics.retained


@pytest.mark.skipif(shutil.which("cabextract") is None, reason="needs cabextract")
@pytest.mark.parametrize("case", list(CASES))
def test_cabextract_reads_what_the_test_writer_writes(
    case: str, tmp_path: Path
) -> None:
    # The LZX encoder is ours too: cabextract (libmspack) keeps the decoder honest.
    path = tmp_path / "t.cab"
    path.write_bytes(_case(case))
    out = tmp_path / "out"
    subprocess.run(["cabextract", "-q", "-d", str(out), str(path)], check=True)
    for name, f in zip(NAMES, FILES, strict=True):
        assert (out / name).read_bytes() == f.data


@pytest.mark.parametrize(
    ("fixture", "method"),
    [
        ("test_read_format_cab_1.cab", CompressionAlgorithm.STORED),
        ("test_read_format_cab_2.cab", CompressionAlgorithm.DEFLATE),
        ("test_read_format_cab_3.cab", CompressionAlgorithm.LZX),
    ],
)
def test_makecab_cabinets(fixture: str, method: CompressionAlgorithm) -> None:
    # Written by Microsoft's makecab.exe, for libarchive's tests.
    file1 = b" " * 26 + b"file 1 contents\n" + b"hello\n" * 3
    file2 = b" " * 26 + b"file 2 contents\n" + b"hello\n" * 6
    with open_archive(LIBARCHIVE / fixture) as reader:
        members = {m.name: m for m in reader.members()}
        assert members["dir1/file1"].compression[0].algo is method
        assert reader.read("dir1/file1") == file1
        assert reader.read("dir2/file2") == file2
        assert reader.read("empty") == b""
        if "zero" in members:
            assert reader.read("zero") == bytes(33000)
        assert reader.verify_all().failures == ()


def test_a_code_page_name_decodes_with_encoding() -> None:
    path = LIBARCHIVE / "test_read_format_cab_filename_cp932.cab"
    with open_archive(path, encoding="cp932") as reader:
        assert [m.name for m in reader.members()] == [
            "表だよ/漢字.txt",
            "表だよ/一覧表.txt",
        ]
    with open_archive(path) as reader:
        # Not UTF-8 and no encoding: the bytes survive as surrogates.
        assert "\udc95" in reader.members()[0].name


def test_members_open_in_any_order_and_seek() -> None:
    raw = _case("lzx-mixed")
    with open_archive(io.BytesIO(raw), seekable_members=True) as reader:
        assert reader.read("bin/code.exe") == CODE
        assert reader.read("docs/text.txt") == TEXT
        with reader.open("blob.bin") as stream:
            stream.seek(65000)
            assert stream.read(10) == BLOB[65000:65010]
            stream.seek(5)
            assert stream.read(10) == BLOB[5:15]


def test_members_read_in_order_decode_each_frame_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    real = LzxDecoder.decode_frame

    def counting(self: LzxDecoder, size: int) -> bytes:
        nonlocal calls
        calls += 1
        return real(self, size)

    monkeypatch.setattr(LzxDecoder, "decode_frame", counting)
    raw = _case("lzx-16")
    with open_archive(io.BytesIO(raw)) as reader:
        for name in NAMES:
            reader.read(name)
    total = sum(len(f.data) for f in FILES)
    assert calls == -(-total // FRAME)


def test_stored_blocks_before_a_member_are_not_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[int] = []
    real = cab_reader._FolderStream._payload

    def recording(self: cab_reader._FolderStream, number: int) -> bytes:
        payloads.append(number)
        return real(self, number)

    monkeypatch.setattr(cab_reader._FolderStream, "_payload", recording)
    first = (len(TEXT) + len(BLOB)) // FRAME
    with open_archive(io.BytesIO(_case("stored"))) as reader:
        assert reader.read("bin/code.exe") == CODE
        assert min(payloads) == first
        # Going on from the first member's stream skips the blocks between.
        assert reader.read("docs/text.txt") == TEXT
        payloads.clear()
        assert reader.read("bin/code.exe") == CODE
        assert min(payloads) == first


def test_reserve_areas_are_skipped() -> None:
    raw = write_cab(FILES, [CabFolder("mszip")], reserve=(20, 3, 5))
    with open_archive(io.BytesIO(raw)) as reader:
        assert reader.read("blob.bin") == BLOB


def test_several_folders() -> None:
    files = [
        CabFile("a", TEXT, folder=0),
        CabFile("b", BLOB, folder=1),
        CabFile("c", CODE, folder=2),
    ]
    raw = write_cab(files, [CabFolder("lzx"), CabFolder("none"), CabFolder("mszip")])
    with open_archive(io.BytesIO(raw)) as reader:
        assert reader.read("c") == CODE
        assert reader.read("a") == TEXT
        assert reader.read("b") == BLOB


def test_names_and_attributes() -> None:
    files = [
        CabFile("dir\\sub\\file.txt", b"x", attribs=0x21),
        CabFile("caf\xe9.txt", b"y", raw_name="café.txt".encode(), attribs=0xE1),
    ]
    with open_archive(io.BytesIO(_cab(CabFolder("none"), files))) as reader:
        first, second = reader.members()
        assert first.name == "dir/sub/file.txt"
        assert first.raw_name == b"dir\\sub\\file.txt"
        assert first.windows_attrs == 0x21
        assert second.name == "café.txt"
        # _A_EXEC and _A_NAME_IS_UTF are cabinet-only: not Windows attributes.
        assert second.windows_attrs == 0x21


def test_detection() -> None:
    raw = _cab(CabFolder("none"))
    assert detect_format(io.BytesIO(raw)).format == ArchiveFormat.CAB


def test_an_empty_cabinet_lists_nothing() -> None:
    raw = write_cab([], [])
    with open_archive(io.BytesIO(raw), format=ArchiveFormat.CAB) as reader:
        assert reader.members() == []


def test_an_invalid_date_is_reported() -> None:
    files = [CabFile("a", b"x", date=0x5A21 | 0x1F0, time=0)]  # month 15
    with open_archive(io.BytesIO(_cab(CabFolder("none"), files))) as reader:
        (member,) = reader.members()
        assert member.modified is None
        codes = [d.code for d in member.diagnostics]
        assert codes == [DiagnosticCode.MEMBER_TIMESTAMP_INVALID]


def test_a_block_without_a_checksum_reads_unverified() -> None:
    raw = _cab(CabFolder("mszip", checksums=False))
    with open_archive(io.BytesIO(raw)) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
            assert member.verified is Verification.LENGTH


def _data_start(raw: bytes) -> int:
    (start,) = struct.unpack_from("<I", raw, 36)
    return start


def test_a_bad_checksum_fails_the_read() -> None:
    raw = bytearray(_cab(CabFolder("mszip")))
    raw[_data_start(raw) + 8 + 10] ^= 0xFF
    with (
        open_archive(io.BytesIO(bytes(raw))) as reader,
        pytest.raises(CorruptionError, match="checksum"),
    ):
        reader.read("docs/text.txt")


def test_the_checksum_matches_libmspack() -> None:
    raw = (LIBARCHIVE / "test_read_format_cab_2.cab").read_bytes()
    start = _data_start(raw)
    checksum, stored, decoded = struct.unpack_from("<IHH", raw, start)
    assert checksum
    assert block_checksum(raw[start + 8 : start + 8 + stored], decoded) == checksum


def test_the_reader_checksum_matches_the_word_by_word_one() -> None:
    # The reader folds the words as one integer; every length around a word and a
    # fold boundary, with and without a seed, gives what XORing word by word gives.
    raw = (LIBARCHIVE / "test_read_format_cab_2.cab").read_bytes()
    start = _data_start(raw)
    stored_checksum, stored, decoded = struct.unpack_from("<IHH", raw, start)
    payload = raw[start + 8 : start + 8 + stored]
    assert cab_reader._block_checksum(payload, decoded) == stored_checksum
    rng = random.Random(11)
    for size in [*range(70), 255, 256, 257, 4095, 4096, 4097, 32767, 32768, 32771]:
        data = rng.randbytes(size)
        seed = rng.getrandbits(32)
        assert cab_reader._checksum(data) == oracle_checksum(data)
        assert cab_reader._checksum(data, seed) == oracle_checksum(data, seed)


@pytest.mark.parametrize("flag", [1, 2])
def test_a_cabinet_set_is_refused(flag: int) -> None:
    raw = write_cab(FILES, [CabFolder("none")], flags=flag, set_names=b"x\0y\0")
    with pytest.raises(UnsupportedFeatureError, match="set"):
        open_archive(io.BytesIO(raw))


def test_quantum_lists_but_does_not_read() -> None:
    raw = _cab(CabFolder("quantum", 10), [CabFile("q", b"data")])
    with open_archive(io.BytesIO(raw)) as reader:
        (member,) = reader.members()
        assert member.compression[0].algo is CompressionAlgorithm.QUANTUM
        with pytest.raises(UnsupportedFeatureError, match="Quantum"):
            reader.read("q")


def _patch_folder_type(raw: bytes, value: int) -> bytes:
    out = bytearray(raw)
    struct.pack_into("<H", out, 36 + 6, value)
    return bytes(out)


@pytest.mark.parametrize(
    ("kind", "error", "match"),
    [
        (3 | (14 << 8), CorruptionError, "LZX window"),
        (3 | (22 << 8), CorruptionError, "LZX window"),
        (7, UnsupportedFeatureError, "method 7"),
    ],
)
def test_a_folder_archivey_cannot_decode(
    kind: int, error: type[Exception], match: str
) -> None:
    raw = _patch_folder_type(_cab(CabFolder("none"), [CabFile("a", b"x")]), kind)
    with open_archive(io.BytesIO(raw)) as reader:
        reader.members()
        with pytest.raises(error, match=match):
            reader.read("a")


def _file_record(raw: bytes) -> int:
    (files_at,) = struct.unpack_from("<I", raw, 16)
    return files_at


@pytest.mark.parametrize(
    ("folder", "match"), [(1, "folder 1"), (0xFFFD, "another cabinet")]
)
def test_a_file_in_a_folder_that_is_not_there(folder: int, match: str) -> None:
    raw = bytearray(_cab(CabFolder("none"), [CabFile("a", b"x")]))
    struct.pack_into("<H", raw, _file_record(raw) + 8, folder)
    with (
        open_archive(io.BytesIO(bytes(raw))) as reader,
        pytest.raises(CorruptionError, match=match),
    ):
        reader.members()


def test_a_file_past_its_folder_end() -> None:
    raw = bytearray(_cab(CabFolder("none"), [CabFile("a", b"xyz")]))
    struct.pack_into("<I", raw, _file_record(raw), 10)
    with (
        open_archive(io.BytesIO(bytes(raw))) as reader,
        pytest.raises(CorruptionError, match="decodes to 3"),
    ):
        reader.read("a")


def _second_block(raw: bytes) -> int:
    """Where the first folder's second CFDATA header starts (no reserve areas)."""
    start = _data_start(raw)
    (stored,) = struct.unpack_from("<H", raw, start + 4)
    return start + 8 + stored


@pytest.mark.parametrize(("value", "match"), [(0, "has no output"), (40000, "at most")])
@pytest.mark.parametrize("method", ["none", "mszip", "lzx"])
def test_a_refused_block_fails_only_the_members_that_reach_it(
    method: str, value: int, match: str
) -> None:
    # libmspack reads a decoded size of 0 as a block split across cabinets, and
    # fails it in a cabinet with no next one. It reads each block header only when
    # the decoder needs that block, so the members before it still read.
    files = [CabFile("a", TEXT[:100]), CabFile("b", BLOB[:51200])]
    raw = bytearray(_cab(CabFolder(method), files))
    struct.pack_into("<H", raw, _second_block(raw) + 6, value)
    with open_archive(io.BytesIO(bytes(raw))) as reader:
        assert reader.read("a") == TEXT[:100]
        with pytest.raises(CorruptionError, match=match):
            reader.read("b")
    with open_archive(io.BytesIO(bytes(raw))) as reader:
        names = []
        with pytest.raises(CorruptionError, match=match):
            for member, stream in reader.stream_members():
                assert stream is not None
                stream.read()
                names.append(member.name)
        assert names == ["a"]


def test_an_empty_member_decodes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    real = LzxDecoder.decode_frame

    def counting(self: LzxDecoder, size: int) -> bytes:
        nonlocal calls
        calls += 1
        return real(self, size)

    monkeypatch.setattr(LzxDecoder, "decode_frame", counting)
    files = [CabFile("a", TEXT), CabFile("empty", b"")]
    with open_archive(io.BytesIO(_cab(CabFolder("lzx"), files))) as reader:
        assert reader.read("empty") == b""
        assert calls == 0
        assert reader.read("a") == TEXT


def test_the_lzx_window_counts_against_max_decoder_memory() -> None:
    raw = _cab(CabFolder("lzx", 21), [CabFile("a", b"hello" * 1000)])
    low = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 20))
    with open_archive(io.BytesIO(raw), config=low) as reader:
        with pytest.raises(ResourceLimitError, match="LZX window"):
            reader.read("a")
        # The declaration is noted before the comparison, so a refusal records it.
        assert reader._resource_usage().decoder_memory == 1 << 21
    enough = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 21))
    with open_archive(io.BytesIO(raw), config=enough) as reader:
        assert reader.read("a") == b"hello" * 1000
        assert reader._resource_usage().decoder_memory == 1 << 21


def test_a_name_with_no_end_is_refused() -> None:
    raw = _cab(CabFolder("none"), [CabFile("a" * 300, b"x")])
    with (
        open_archive(io.BytesIO(raw)) as reader,
        pytest.raises(CorruptionError, match="255 bytes"),
    ):
        reader.members()


def test_an_empty_name_is_refused() -> None:
    raw = _cab(CabFolder("none"), [CabFile("", b"x")])
    with (
        open_archive(io.BytesIO(raw)) as reader,
        pytest.raises(CorruptionError, match="empty name"),
    ):
        reader.members()


def test_an_oversized_block_is_refused() -> None:
    raw = bytearray(_cab(CabFolder("none"), [CabFile("a", b"x")]))
    struct.pack_into("<H", raw, _data_start(raw) + 6, 40000)
    with (
        open_archive(io.BytesIO(bytes(raw))) as reader,
        pytest.raises(CorruptionError, match="at most"),
    ):
        reader.read("a")


def test_an_mszip_block_without_its_signature() -> None:
    raw = bytearray(_cab(CabFolder("mszip", checksums=False), [CabFile("a", TEXT)]))
    raw[_data_start(raw) + 8] = ord("X")
    with (
        open_archive(io.BytesIO(bytes(raw))) as reader,
        pytest.raises(CorruptionError, match="CK"),
    ):
        reader.read("a")


@pytest.mark.parametrize("case", ["stored", "mszip", "lzx-16"])
def test_a_cut_cabinet(case: str) -> None:
    raw = _case(case)
    cut = raw[: len(raw) - 5000]
    with open_archive(io.BytesIO(cut)) as reader:
        assert reader.read("docs/text.txt") == TEXT
        with pytest.raises(TruncatedError):
            reader.read("bin/code.exe")
    with (
        pytest.raises(TruncatedError),
        open_archive(io.BytesIO(raw[: _file_record(raw) + 20])) as reader,
    ):
        reader.members()


@pytest.mark.parametrize("seed", range(40))
def test_damaged_lzx_raises_an_archivey_error(seed: int) -> None:
    rng = random.Random(seed)
    raw = bytearray(_lzx_unchecked())
    start = _data_start(raw)
    for _ in range(1 + seed % 4):
        raw[rng.randrange(start + 8, len(raw))] ^= 1 << rng.randrange(8)
    with open_archive(io.BytesIO(bytes(raw))) as reader:
        try:
            reader.read("docs/text.txt")
        except ArchiveyError:
            pass


def _lzx_stream(tokens: list[_Token], size: int) -> list[bytes]:
    """One verbatim block of the given tokens, as LZX frames."""
    from tests.cab_util import BitWriter, _FrameState

    encoder = LzxEncoder(window_bits=15)
    encoder._main_lengths = [0] * (256 + 30 * 8)
    encoder._length_lengths = [0] * 249
    writer = BitWriter()
    writer.bits(0, 1)
    frames: list[bytes] = []
    state = _FrameState(writer, frames)
    encoder._compressed("verbatim", tokens, 0, state, 256 + 30 * 8)
    state.finish(size)
    return frames


def _decode(frames: list[bytes], size: int) -> bytes:
    it = iter(frames)
    decoder = LzxDecoder(15, lambda: next(it, None))
    return decoder.decode_frame(size)


def test_lzx_a_match_before_the_start_is_damage() -> None:
    # Distance 5 after one literal; slot 4 (formatted 7 = base 6 + 1).
    frames = _lzx_stream([_Token(literal=65), _Token(length=3, slot=4, footer=1)], 4)
    with pytest.raises(CorruptionError, match="before the stream start"):
        _decode(frames, 4)


def test_lzx_a_repeated_offset_and_overlap() -> None:
    # R0 starts as 1: "A" then a match of 9 at distance 1 repeats it.
    frames = _lzx_stream([_Token(literal=65), _Token(length=9, slot=0)], 10)
    assert _decode(frames, 10) == b"A" * 10


def test_lzx_a_cut_stream_is_truncated() -> None:
    frames = _lzx_stream([_Token(literal=i % 256) for i in range(3000)], 3000)
    data = frames[0][: len(frames[0]) // 2]
    with pytest.raises(TruncatedError):
        _decode([data], 3000)


def test_lzx_a_match_past_the_frame_is_damage() -> None:
    frames = _lzx_stream([_Token(literal=65), _Token(length=9, slot=0)], 10)
    with pytest.raises(CorruptionError, match="frame"):
        _decode(frames, 5)


def test_lzx_frames_are_whole() -> None:
    assert len(_lzx_stream([_Token(literal=1)] * FRAME, FRAME)) == 1
    with pytest.raises(ValueError, match="frame size"):
        _decode([b""], FRAME + 1)


def _shared_blocks(folders: int, blocks: int) -> bytes:
    """A cabinet whose folders all name one run of one-byte stored blocks, with one
    file in each that covers its folder. (A block of no output is refused, an empty
    file reads no table, and files must cover their folder to its end.)"""
    files_at = 36 + 8 * folders
    files = b"".join(
        struct.pack("<IIHHHH", blocks, 0, i, 0x5A21, 0x6000, 0x20) + b"f%d\0" % i
        for i in range(folders)
    )
    data_at = files_at + len(files)
    body = (
        struct.pack("<IHH", data_at, blocks, 0) * folders
        + files
        + (struct.pack("<IHH", 0, 1, 1) + b"x") * blocks
    )
    header = struct.pack(
        "<4sIIIIIBBHHHHH",
        b"MSCF",
        0,
        36 + len(body),
        0,
        files_at,
        0,
        3,
        1,
        folders,
        folders,
        0,
        0,
        0,
    )
    return header + body


def test_kept_block_tables_are_weighed_against_max_metadata_bytes() -> None:
    raw = _shared_blocks(4, 100)
    weight = cab_reader._BLOCK_WEIGHT * 100
    config = archivey.ArchiveyConfig(
        listing_limits=archivey.ListingLimits(max_metadata_bytes=3 * weight)
    )
    with open_archive(io.BytesIO(raw), config=config) as reader:
        members = reader.members()
        for member in members[:3]:
            assert reader.read(member) == b"x" * 100
        assert (
            reader.read(members[0]) == b"x" * 100
        )  # a kept table is not weighed again
        with pytest.raises(
            archivey.ResourceLimitError,
            match=f"max_metadata_bytes={3 * weight} .*{3 * weight} bytes, and folder 3's "
            "passes the limit at block 1 of 100",
        ):
            reader.read(members[3])


def test_folders_sharing_their_blocks_cannot_exhaust_memory() -> None:
    # 200 folders x 20 000 blocks would keep about 1 GiB of block tables; the
    # default 64 MiB stops it a few folders in.
    read = 0
    with (
        open_archive(io.BytesIO(_shared_blocks(200, 20000))) as reader,
        pytest.raises(archivey.ResourceLimitError, match="block tables"),
    ):
        for member in reader.members():
            reader.read(member)
            read += 1
    assert read == 64 * 2**20 // (cab_reader._BLOCK_WEIGHT * 20000)


# ── LZX streams written bit by bit ─────────────────────────────────────────────
#
# Window 2**15 (496 main symbols), one block, an empty length tree. Each length is
# written on its own through a pretree that has every code, so a test states the
# main tree as {symbol: length}.

_PRE_LENGTHS = [4] * 12 + [5] * 8
_PRE_CODES = canonical_codes(_PRE_LENGTHS)


def _pre(w: BitWriter, code: int) -> None:
    w.bits(_PRE_CODES[code], _PRE_LENGTHS[code])


def _lengths(w: BitWriter, lengths: list[int], first: int, last: int, run: int) -> None:
    """One pretree-coded range. With ``run``, its last three entries and one past it
    take that length through a same-length run (pretree code 19)."""
    for n in _PRE_LENGTHS:
        w.bits(n, 4)
    for x in range(first, last - 3 if run else last):
        _pre(w, -lengths[x] % 17)
    if run:
        _pre(w, 19)
        w.bits(0, 1)  # a run of 4
        _pre(w, -run % 17)


def _raw_lzx(
    size: int,
    main: dict[int, int],
    *,
    block_type: int = 1,
    aligned: list[int] | None = None,
    run_past_main: int = 0,
) -> BitWriter:
    """A writer holding the E8 bit and one block header; the caller writes the
    symbols."""
    w = BitWriter()
    w.bits(0, 1)
    w.bits(block_type, 3)
    w.bits(size >> 8, 16)
    w.bits(size & 0xFF, 8)
    for n in aligned or ():
        w.bits(n, 3)
    lengths = [0] * 496
    for symbol, n in main.items():
        lengths[symbol] = n
    _lengths(w, lengths, 0, 256, 0)
    _lengths(w, lengths, 256, 496, run_past_main)
    _lengths(w, [0] * 249, 0, 249, 0)
    return w


def _end(w: BitWriter, pad: int = 8) -> bytes:
    w.align()
    w.raw(bytes(pad))
    return w.take()


def _decoder(data: bytes) -> LzxDecoder:
    chunks = iter([data])
    return LzxDecoder(15, lambda: next(chunks, None))


@pytest.mark.parametrize(
    ("lengths", "message"),
    [([1, 1, 1], "overfills"), ([1, 2], "does not fill"), ([2, 2, 2], "does not fill")],
)
def test_lzx_a_tree_that_does_not_fill_its_code_space_is_damage(
    lengths: list[int], message: str
) -> None:
    with pytest.raises(CorruptionError, match=f"LZX main tree {message}"):
        lzx_decoder._build_table(lengths, len(lengths), "main")


def _zero_lengths(w: BitWriter, count: int, codes: dict[int, int]) -> None:
    """``count`` lengths of 0 as pretree runs, through 2-bit ``codes``."""
    while count >= 20:
        run = min(count, 51)
        w.bits(codes[18], 2)
        w.bits(run - 20, 5)
        count -= run
    if count >= 4:
        w.bits(codes[17], 2)
        w.bits(count - 4, 4)
        count = 0
    for _ in range(count):
        w.bits(codes[0], 2)


def test_lzx_a_tree_with_an_unreachable_long_code_is_damage() -> None:
    """A pretree whose four 2-bit codes fill the code space, plus an 8-bit code for
    symbol 1. cabextract decodes on (lzxd.c stops at its 6-bit first table level and
    never sees the 8-bit code), but no encoder writes such a tree: it comes from
    damage, and the bytes after it are wrong. archivey refuses it, on purpose."""
    pre = [0] * 20
    pre[0] = pre[16] = pre[17] = pre[18] = 2
    pre[1] = 8
    codes = {0: 0b00, 16: 0b01, 17: 0b10, 18: 0b11}
    size = 100
    w = BitWriter()
    w.bits(0, 1)
    w.bits(1, 3)  # a verbatim block
    w.bits(size >> 8, 16)
    w.bits(size & 0xFF, 8)
    for first, last, ones in ((0, 256, 2), (256, 496, 0), (0, 249, 0)):
        for n in pre:
            w.bits(n, 4)
        for _ in range(ones):
            w.bits(codes[16], 2)  # length (0 - 16) % 17 = 1
        _zero_lengths(w, last - first - ones, codes)
    for i in range(size):
        w.bits(i & 1, 1)
    with pytest.raises(CorruptionError, match="pretree tree overfills"):
        _decoder(_end(w)).decode_frame(size)


def test_lzx_long_codes_decode_through_sub_tables() -> None:
    # Codes of 1 to 16 bits: the root takes 10 bits, the rest go to sub-tables.
    lengths = [*range(1, 16), 16, 16]
    tree = lzx_decoder._build_table(lengths, len(lengths), "main")
    assert tree is not None
    table, root = tree
    assert root == 10
    assert len(table) < 1 << 11  # not the 65 536 entries of a one-level table
    w = BitWriter()
    codes = canonical_codes(lengths)
    for symbol in [16, 0, 9, 10, 15, 3, 11]:
        w.bits(codes[symbol], lengths[symbol])
    decoder = _decoder(_end(w))
    assert [decoder._read_symbol(tree, "main") for _ in range(7)] == [
        16,
        0,
        9,
        10,
        15,
        3,
        11,
    ]


def test_lzx_only_the_length_tree_may_have_no_codes() -> None:
    # lzxd.c builds the length tree with BUILD_TABLE_MAYBE_EMPTY, every other tree
    # with BUILD_TABLE, which fails on a table that is not full.
    assert lzx_decoder._build_table([0] * 8, 8, "length", may_be_empty=True) is None
    with pytest.raises(CorruptionError, match="LZX aligned tree has no codes"):
        lzx_decoder._build_table([0] * 8, 8, "aligned")


def test_lzx_an_empty_aligned_tree_is_damage_even_when_unused() -> None:
    # Four literals, and no match that would read the aligned tree.
    w = _raw_lzx(4, {65: 1, 66: 1}, block_type=2, aligned=[0] * 8)
    w.bits(0b0101, 4)
    with pytest.raises(CorruptionError, match="LZX aligned tree has no codes"):
        _decoder(_end(w)).decode_frame(4)


def test_lzx_an_empty_main_tree_is_damage_in_an_empty_block() -> None:
    w = _raw_lzx(0, {})
    with pytest.raises(CorruptionError, match="LZX main tree has no codes"):
        _decoder(_end(w)).decode_frame(1)


def test_lzx_a_length_out_of_range_gives_its_symbol_no_code() -> None:
    # As lzxd.c, which keeps code lengths in bytes: lengths above 16 take no code
    # space, and do make the tree not empty.
    tree = lzx_decoder._build_table([1, 1, 255, 254], 4, "main")
    assert tree is not None
    with pytest.raises(CorruptionError, match="LZX length tree does not fill"):
        lzx_decoder._build_table([0, 255], 2, "length", may_be_empty=True)


def test_lzx_a_same_length_run_of_code_18_wraps_as_lzxd_does() -> None:
    # Pretree code 19, then symbol 18 as the run's delta: lzxd.c computes
    # 0 - 18 + 17 = -1 into an unsigned char, 255, so the four symbols have no
    # code and the literal tree (all 256 at 8 bits) is complete on its own.
    pre = [0] * 20
    pre[9], pre[18], pre[17], pre[19] = 1, 2, 3, 3
    codes = canonical_codes(pre)
    w = BitWriter()

    def sym(code: int) -> None:
        w.bits(codes[code], pre[code])

    def zeros(*runs: int) -> None:
        for run in runs:
            sym(18)
            w.bits(run - 20, 5)

    w.bits(0, 1)  # no E8
    w.bits(1, 3)  # verbatim
    w.bits(0, 16)
    w.bits(4, 8)  # 4 bytes
    for n in pre:
        w.bits(n, 4)
    for _ in range(256):
        sym(9)  # (0 - 9) mod 17: 8 bits
    for n in pre:
        w.bits(n, 4)
    sym(19)
    w.bits(0, 1)  # a run of 4
    sym(18)
    zeros(51, 51, 51, 51, 32)  # the rest of 256 to 496
    for n in pre:
        w.bits(n, 4)
    zeros(51, 51, 51, 51, 45)  # an empty length tree
    for c in b"ABCD":
        w.bits(c, 8)
    decoder = _decoder(_end(w))
    assert decoder.decode_frame(4) == b"ABCD"
    assert decoder._main_lengths[256:261] == [255, 255, 255, 255, 0]


def test_lzx_a_match_past_the_end_of_the_window_is_damage() -> None:
    # The window is one frame: 32 766 x 'A', then a match of 4 at distance 1.
    w = _raw_lzx(32770, {65: 1, 258: 1})
    w.bits(0, 32766)
    w.bits(1, 1)
    with pytest.raises(CorruptionError, match="past the end of the window"):
        _decoder(_end(w)).decode_frame(FRAME)


def test_lzx_a_match_from_more_than_a_window_back_is_damage() -> None:
    # Slot 30 is one past the last a 2**15 window has; a same-length run in the
    # main tree's last range reaches it, as lzxd.c allows. After two windows of
    # 'A', a match at distance 40 000 is inside the output but not the window.
    w = _raw_lzx(2 * FRAME + 2, {65: 1}, run_past_main=3)  # 493 to 496: 3 bits
    for _ in range(2):
        w.bits(0, FRAME)
        w.align()
    w.bits(0b111, 3)  # symbol 496: slot 30, a match of 2
    w.bits(40000 + 2 - lzx_decoder._POSITION_BASE[30], 14)
    decoder = _decoder(_end(w))
    assert decoder.decode_frame(FRAME) == b"A" * FRAME
    assert decoder.decode_frame(FRAME) == b"A" * FRAME
    with pytest.raises(CorruptionError, match="before the stream start"):
        decoder.decode_frame(2)


def test_lzx_a_match_past_the_end_of_its_block_is_damage() -> None:
    # A block of 5 bytes: 'A', then a match of 8 that ends the 9-byte frame.
    w = _raw_lzx(5, {65: 1, 262: 1})
    w.bits(0b01, 2)
    with pytest.raises(CorruptionError, match="past the end of its block"):
        _decoder(_end(w)).decode_frame(9)


def test_lzx_a_stream_that_reads_past_its_end_is_truncated() -> None:
    w = _raw_lzx(800, {0: 1, 1: 1})
    w.bits(0, 800)
    whole = _end(w, pad=0)
    assert _decoder(whole).decode_frame(800) == bytes(800)
    # Four bytes short, the decoder reads zeros past the end: more than the two
    # lzxd.c reads before it refuses the stream.
    with pytest.raises(TruncatedError, match="ends before its output"):
        _decoder(whole[:-4]).decode_frame(800)


@pytest.mark.parametrize("size", [800, 801], ids=["word-end", "mid-word-end"])
def test_lzx_a_frame_lzxd_reads_past_the_two_zero_bytes_for_is_truncated(
    size: int,
) -> None:
    """lzxd.c reads 16 bits ahead of each symbol, and one more word at the end of a
    frame whose last word it has not used up. With the last word cut, the zeros
    after the input still decode to the right bytes here, but lzxd.c needs more
    than its two zero bytes to read them, so it refuses the stream (cabextract:
    "error in CAB data format"). Checking only the bits used accepted it.
    """
    w = _raw_lzx(size, {0: 1, 1: 1})
    w.bits(0, size)
    whole = _end(w, pad=0)
    assert _decoder(whole).decode_frame(size) == bytes(size)
    with pytest.raises(TruncatedError, match="ends before its output"):
        _decoder(whole[:-2]).decode_frame(size)


def test_lzx_a_frame_with_nothing_read_ahead_may_end_in_the_zero_bytes() -> None:
    """When the last field of a frame ends on a word boundary and fills what
    lzxd.c read for the symbol before it, lzxd.c holds no bits ahead, and the
    two zero bytes after the input may be the frame's last word."""
    # A 2**17 window, with the match symbol for slot 32 (15 extra bits) as the code
    # "0": the code and its extra bits are one word. Two frames of 'A' first, so
    # the match (distance 65 534, all extra bits zero) reaches back into them.
    match = 256 + 32 * 8  # slot 32, a match of 2
    size = 2 * FRAME + 10
    w = BitWriter()
    w.bits(0, 1)
    w.bits(1, 3)  # a verbatim block
    w.bits(size >> 8, 16)
    w.bits(size & 0xFF, 8)
    lengths = [0] * (256 + 34 * 8)
    lengths[match], lengths[65], lengths[66] = 1, 2, 2  # "0", "10", "11"
    _lengths(w, lengths, 0, 256, 0)
    _lengths(w, lengths, 256, len(lengths), 0)
    _lengths(w, [0] * 249, 0, 249, 0)
    for frame_symbols in (FRAME, FRAME, 8):
        for _ in range(frame_symbols):
            w.bits(0b10, 2)  # 'A'
        w.align()
    w.bits(0, 16)  # the match: code "0" and 15 zero extra bits
    data = w.take()
    expected = [b"A" * FRAME, b"A" * FRAME, b"A" * 10]
    for stream in (data, data[:-2]):
        chunks = iter([stream])
        decoder = LzxDecoder(17, lambda chunks=chunks: next(chunks, None))
        assert [decoder.decode_frame(len(f)) for f in expected] == expected


@pytest.mark.parametrize(
    ("cut", "expected"), [(2, b"abcdef\0\0"), (3, None)], ids=["two", "three"]
)
def test_lzx_a_stored_block_may_read_the_two_zero_bytes(
    cut: int, expected: bytes | None
) -> None:
    """lzxd.c reads stored bytes from its two zero bytes past the input too, and
    refuses the stream only past them: cabextract reads a stored block cut by two
    bytes, with zeros for them, and refuses one cut by three."""
    w = BitWriter()
    w.bits(0, 1)
    _uncompressed_block(w, b"abcdefgh", (1, 1, 1))
    stream = _end(w, pad=0)[:-cut]
    if expected is None:
        with pytest.raises(TruncatedError, match="inside an uncompressed block"):
            _decoder(stream).decode_frame(8)
    else:
        assert _decoder(stream).decode_frame(8) == expected


def test_format_is_listed() -> None:
    assert ArchiveFormat.CAB in archivey.list_supported_formats()


@pytest.mark.parametrize("method", ["none", "mszip", "lzx"])
@pytest.mark.parametrize("seekable_members", [False, True])
def test_a_read_returns_every_byte_asked_for(
    method: str, seekable_members: bool
) -> None:
    # Full-count (ADR 0014): a short read is the member's end. A folder read stops at
    # the end of each data block or LZX frame, and the member stream returned that
    # short read as it was, so read(n) past a block boundary lost the rest of the
    # member. Found by fuzzing a seek and a read against the bytes of a sequential
    # read.
    data = random.Random(7).randbytes(100_000)
    cab = write_cab([CabFile("a", data)], [CabFolder(method=method)])
    with archivey.open_archive(
        io.BytesIO(cab), seekable_members=seekable_members
    ) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            assert stream.read(70_000) == data[:70_000]
            assert stream.read(70_000) == data[70_000:]
            if seekable_members:
                stream.seek(31_000)
                assert stream.read(40_000) == data[31_000:71_000]


# ── Edges the mutation sweep found untested ───────────────────────────────────


def _lzxd_undo_e8(frame: bytes, offset: int, file_size: int) -> bytes:
    """lzxd.c's E8 step, written as libmspack writes it (a byte walk that steps
    over each translated CALL), to check the decoder's ``find`` loop against."""
    if file_size >= 1 << 31:
        file_size -= 1 << 32  # lzxd.c holds the size in a signed 32-bit int
    out = bytearray(frame)
    if len(out) <= 10:
        return bytes(out)
    i, current = 0, offset
    while i < len(out) - 10:
        if out[i] != 0xE8:
            i += 1
            current += 1
            continue
        value = int.from_bytes(out[i + 1 : i + 5], "little", signed=True)
        if value >= -current and value < file_size:
            rel = value - current if value >= 0 else value + file_size
            out[i + 1 : i + 5] = (rel & 0xFFFFFFFF).to_bytes(4, "little")
        i += 5
        current += 5
    return bytes(out)


def _e8_frame(offset: int, file_size: int, size: int, seed: int) -> bytes:
    """A frame of CALLs whose targets sit on and around the bounds the step
    checks: ``-current``, 0 and ``file_size``, with E8 bytes up to the frame end."""
    rng = random.Random(seed)
    signed = file_size - (1 << 32) if file_size >= 1 << 31 else file_size
    out = bytearray()
    while len(out) < size:
        current = offset + len(out)
        value = rng.choice(
            [
                -current,
                -current - 1,
                -1,
                0,
                1,
                signed - 1,
                signed,
                rng.randrange(-current, max(signed, 1)),
            ]
        )
        out += b"\xe8" + (value & 0xFFFFFFFF).to_bytes(4, "little")
        out += bytes(rng.choice([0, 1, 2]))
    return bytes(out[:size])


@pytest.mark.parametrize("size", [10, 11, 15, 16, 4000, FRAME])
@pytest.mark.parametrize(
    ("offset", "file_size"),
    [(0, 12_000_000), (5 * FRAME, 300_000), (FRAME, 1 << 31), (0, 0xFFFFFFFF)],
    ids=["first-frame", "later-frame", "size-2-31", "size-max"],
)
def test_lzx_e8_step_matches_lzxd(size: int, offset: int, file_size: int) -> None:
    decoder = LzxDecoder(16, lambda: None)
    decoder._intel_size = file_size
    decoder._offset = offset
    for seed in range(3):
        frame = _e8_frame(offset, file_size, size, seed)
        assert decoder._undo_e8(frame) == _lzxd_undo_e8(frame, offset, file_size)


def test_lzx_e8_step_leaves_the_last_ten_bytes_alone() -> None:
    """A CALL that starts in the frame's last 10 bytes stays as it is."""
    decoder = LzxDecoder(16, lambda: None)
    decoder._intel_size = 1 << 20
    target = (100).to_bytes(4, "little")
    frame = bytes(9) + b"\xe8" + target + bytes(6)  # E8 at size - 11: translated
    assert decoder._undo_e8(frame)[10:14] == (100 - 9).to_bytes(4, "little")
    frame = bytes(10) + b"\xe8" + target + bytes(5)  # E8 at size - 10: not
    assert decoder._undo_e8(frame) == frame


def _uncompressed_block(w: BitWriter, data: bytes, r: tuple[int, int, int]) -> None:
    w.bits(3, 3)
    w.bits(len(data) >> 8, 16)
    w.bits(len(data) & 0xFF, 8)
    w.align(whole_word_if_aligned=True)
    w.raw(b"".join(v.to_bytes(4, "little") for v in r))
    w.raw(data)
    if len(data) & 1:
        w.raw(b"\0")


def test_lzx_an_uncompressed_block_sets_the_repeated_offsets() -> None:
    """R0, R1 and R2 come from the block header, whatever the decoder held."""
    w = BitWriter()
    w.bits(0, 1)
    _uncompressed_block(w, b"abcd", (0x01020304, 5, 0x0A0B0C0D))
    decoder = _decoder(_end(w))
    assert decoder.decode_frame(4) == b"abcd"
    assert (decoder._r0, decoder._r1, decoder._r2) == (0x01020304, 5, 0x0A0B0C0D)


@pytest.mark.parametrize("first", [b"abcd", b"abcde"], ids=["even", "odd"])
def test_lzx_only_an_odd_uncompressed_block_is_padded(first: bytes) -> None:
    """The pad byte after an uncompressed block is there only for an odd length:
    the next block's header follows an even one at once."""
    w = BitWriter()
    w.bits(0, 1)
    _uncompressed_block(w, first, (1, 1, 1))
    _uncompressed_block(w, b"wxyz", (1, 1, 1))
    data = first + b"wxyz"
    assert _decoder(_end(w)).decode_frame(len(data)) == data


def test_lzx_the_e8_step_stops_after_32768_frames() -> None:
    """lzxd.c translates CALLs in the first 32768 frames (1 GiB) only."""
    file_size = 1 << 24
    call = b"\x90\xe8" + (0x7000).to_bytes(4, "little")
    frame = call + bytes(FRAME - len(call))
    w = BitWriter()
    w.bits(1, 1)
    w.bits(file_size >> 16, 16)
    w.bits(file_size & 0xFFFF, 16)
    _uncompressed_block(w, frame * 3, (1, 1, 1))
    decoder = _decoder(_end(w))
    decoder._frame = 32766
    out = [decoder.decode_frame(FRAME) for _ in range(3)]
    for k, got in enumerate(out):
        translated = _lzxd_undo_e8(frame, k * FRAME, file_size)
        assert translated != frame
        assert got == (translated if k < 2 else frame), k


def test_a_cabinet_cut_inside_a_block_header_reads_the_blocks_before_it() -> None:
    """A cut that leaves part of a CFDATA header is the folder's end, not damage
    in the blocks before it: a file inside them still reads."""
    files = [CabFile("a.txt", b"alpha" * 20), CabFile("b.bin", BLOB)]
    raw = write_cab(files, [CabFolder("none")])
    (start,) = struct.unpack_from("<I", raw, 36)
    stored = struct.unpack_from("<H", raw, start + 4)[0]
    second = start + 8 + stored
    for cut in (second + 3, second + 7):
        with open_archive(io.BytesIO(raw[:cut])) as reader:
            assert reader.read("a.txt") == b"alpha" * 20
            with pytest.raises(TruncatedError):
                reader.read("b.bin")


def test_lzx_length_codes_longer_than_the_lookup_table() -> None:
    """Length codes past the decoder's 10-bit first table go through its second
    level: twelve lengths used 1, 1, 2, 4, ... 1024 times make an 11-bit code."""
    tokens: list[_Token] = []
    expected = bytearray()
    counts = [1 << k for k in range(10, -1, -1)] + [1]
    for i, count in enumerate(counts):
        length = 9 + i
        for j in range(count):
            byte = 65 + (i + j) % 26
            # A literal, then a match at R0 = 1 that repeats it.
            tokens += [_Token(literal=byte), _Token(length=length, slot=0)]
            expected += bytes([byte]) * (length + 1)
    freqs = counts + [0] * (249 - len(counts))
    assert max(code_lengths(freqs, 16)) > lzx_decoder._ROOT_BITS
    assert _decode(_lzx_stream(tokens, len(expected)), len(expected)) == expected


# ── The file table's layout ───────────────────────────────────────────────────
#
# No checksum covers a CFFILE record, so a damaged offset or size would read other,
# correctly checksummed bytes of the folder. Files must tile their folder.


def _file_records(raw: bytes) -> list[tuple[int, bytes]]:
    """``(where, record with its name)`` for each CFFILE record, in table order."""
    (files_at,) = struct.unpack_from("<I", raw, 16)
    (count,) = struct.unpack_from("<H", raw, 28)
    records = []
    pos = files_at
    for _ in range(count):
        end = raw.index(b"\0", pos + 16) + 1
        records.append((pos, raw[pos:end]))
        pos = end
    return records


def _patch_file(
    raw: bytes, index: int, *, size: int | None = None, offset: int | None = None
) -> bytes:
    out = bytearray(raw)
    where, _record = _file_records(raw)[index]
    if size is not None:
        struct.pack_into("<I", out, where, size)
    if offset is not None:
        struct.pack_into("<I", out, where + 4, offset)
    return bytes(out)


def _reversed_table(raw: bytes) -> bytes:
    """The same cabinet with its file records in reverse order."""
    records = _file_records(raw)
    start = records[0][0]
    end = records[-1][0] + len(records[-1][1])
    return raw[:start] + b"".join(r for _, r in reversed(records)) + raw[end:]


@pytest.mark.parametrize("case", ["stored", "mszip", "lzx-16"])
@pytest.mark.parametrize(
    ("index", "shift", "word"),
    [(1, -10, "overlaps"), (1, 10, "leaves a gap"), (0, 1, "leaves a gap")],
    ids=["overlap", "gap", "first-not-at-0"],
)
def test_a_file_table_that_does_not_tile_its_folder_is_refused(
    case: str, index: int, shift: int, word: str
) -> None:
    """The fuzzer's shape: a moved offset reads other checksummed bytes and passed
    ``verify_all()``. Which record is wrong cannot be told, so the open fails."""
    raw = _case(case)
    _where, record = _file_records(raw)[index]
    (offset,) = struct.unpack_from("<I", record, 4)
    damaged = _patch_file(raw, index, offset=offset + shift)
    with pytest.raises(CorruptionError, match=f"{word} .*file table is damaged"):
        open_archive(io.BytesIO(damaged))


def test_a_last_file_that_stops_short_of_its_folder_is_refused() -> None:
    """A smaller size on the last file leaves no gap between files, but stops before
    the folder does: the read refuses it rather than return a cut file as checked."""
    raw = _case("mszip")
    damaged = _patch_file(raw, 2, size=len(CODE) - 1)
    with open_archive(io.BytesIO(damaged)) as reader:
        assert [m.name for m in reader.members()] == NAMES
        with pytest.raises(CorruptionError, match="decodes to .*file table is damaged"):
            reader.read("bin/code.exe")


def test_files_listed_out_of_offset_order_still_tile() -> None:
    """Order in the table is the writer's choice; only the layout counts."""
    raw = _reversed_table(_case("mszip"))
    with open_archive(io.BytesIO(raw)) as reader:
        assert [m.name for m in reader.members()] == NAMES[::-1]
        assert reader.read("blob.bin") == BLOB
        assert reader.verify_all().failures == ()


def test_an_empty_file_anywhere_in_the_folder_is_accepted() -> None:
    """An empty file reads no bytes, so its offset is not checked."""
    files = [*FILES, CabFile("empty", b"")]
    raw = _patch_file(_cab(CabFolder("mszip"), files), 3, offset=12345)
    with open_archive(io.BytesIO(raw)) as reader:
        assert reader.read("empty") == b""
        assert reader.read("blob.bin") == BLOB


def test_the_listing_estimates_checksum_and_the_read_agrees() -> None:
    """The listing used to say ``LENGTH`` while a read reached ``CHECKSUM``."""
    with open_archive(io.BytesIO(_case("lzx-16"))) as reader:
        members = reader.members()
        assert [m.verifiable for m in members] == [Verification.CHECKSUM] * 3
        assert reader.verify_all().failures == ()
        assert [m.verified for m in members] == [Verification.CHECKSUM] * 3


def test_a_folder_without_checksums_settles_at_length_on_open() -> None:
    raw = _cab(CabFolder("mszip", checksums=False))
    with open_archive(io.BytesIO(raw)) as reader:
        member = reader.get("blob.bin")
        assert member.verifiable is Verification.CHECKSUM  # the listing's estimate
        assert reader.read(member) == BLOB
        assert member.verifiable is Verification.LENGTH
        assert member.verified is Verification.LENGTH
