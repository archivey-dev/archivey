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
from archivey.internal.streams.codecs.lzx_decoder import LzxDecoder
from tests.cab_util import (
    FRAME,
    CabFile,
    CabFolder,
    LzxEncoder,
    _Token,
    block_checksum,
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
    with open_archive(io.BytesIO(_case("stored"))) as reader:
        assert reader.read("bin/code.exe") == CODE
    first = (len(TEXT) + len(BLOB)) // FRAME
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
        CabFile("caf\xe9.txt", b"y", raw_name="café.txt".encode(), attribs=0xA0),
    ]
    with open_archive(io.BytesIO(_cab(CabFolder("none"), files))) as reader:
        first, second = reader.members()
        assert first.name == "dir/sub/file.txt"
        assert first.raw_name == b"dir\\sub\\file.txt"
        assert first.windows_attrs == 0x21
        assert second.name == "café.txt"


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


def test_format_is_listed() -> None:
    assert ArchiveFormat.CAB in archivey.list_supported_formats()
