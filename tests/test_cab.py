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
    ArchiveyError,
    CompressionAlgorithm,
    CorruptionError,
    DiagnosticCode,
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
        assert reader.verify_all() == ()


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
    monkeypatch.setenv("ARCHIVEY_NATIVE", "0")  # counts the Python decoder's frames
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
    """A cabinet whose folders all name one run of empty stored blocks, one empty
    file in each."""
    files_at = 36 + 8 * folders
    files = b"".join(
        struct.pack("<IIHHHH", 0, 0, i, 0x5A21, 0x6000, 0x20) + b"f%d\0" % i
        for i in range(folders)
    )
    data_at = files_at + len(files)
    body = (
        struct.pack("<IHH", data_at, blocks, 0) * folders
        + files
        + struct.pack("<IHH", 0, 0, 0) * blocks
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
            assert reader.read(member) == b""
        assert reader.read(members[0]) == b""  # a kept table is not weighed again
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


def test_lzx_a_tree_with_no_codes_is_none() -> None:
    assert lzx_decoder._build_table([0] * 8, 8, "aligned") is None


def test_lzx_an_aligned_match_with_an_empty_aligned_tree_is_damage() -> None:
    # 'A' and a slot-8 match (3 extra bits, which an aligned block reads through
    # the aligned tree), with the aligned tree empty.
    w = _raw_lzx(40, {65: 1, 320: 1}, block_type=2, aligned=[0] * 8)
    w.bits(0, 30)  # 30 x 'A'
    w.bits(1, 1)  # the match
    w.bits(0, 3 + 8)
    with pytest.raises(CorruptionError, match="aligned symbol read from an empty"):
        _decoder(_end(w)).decode_frame(40)


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


def test_format_is_listed() -> None:
    assert ArchiveFormat.CAB in archivey.list_supported_formats()
