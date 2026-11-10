"""ZIP methods 2 to 5 (Reduce) and 10 (DCL Implode).

No tool on the test image writes or reads either method (7-Zip says "Unsupported
Method", ``unar`` 1.10.1 "not fully supported", and Debian's ``unzip`` is built without
Reduce), so the checks against a real writer are fixed bytes: two Reduce streams PKZIP
0.92 wrote (``tests/fixtures/external/reduce_pkzip092``) and the DCL example in zlib's
``contrib/blast/blast.c``. The other archives come from the test-only encoders in
``tests/zip_legacy_build.py``.
"""

from __future__ import annotations

import io
import random
from pathlib import Path

import pytest

from archivey import CompressionAlgorithm, open_archive
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.streams.codecs.zip_legacy_decoder import (
    DclImplodeDecompressor,
    ReduceDecompressor,
)
from tests.streams_util import NonSeekableBytesIO
from tests.zip_legacy_build import (
    BitWriter,
    LegacyEntry,
    build_zip,
    dcl_implode,
    dcl_implode_entry,
    reduce,
    reduce_entry,
)
from tests.zipcrypto import build_zipcrypto_zip

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "reduce_pkzip092"
_TEXT = (Path(__file__).parent.parent / "README.md").read_bytes()[:4000]

_DATA = {
    "empty": b"",
    "one-byte": b"x",
    "text": _TEXT,
    "zeros": bytes(1500),
    "random": random.Random(1).randbytes(600),
    # The escape byte, alone and in runs, as a literal and inside copies.
    "escapes": bytes([0x90, 1, 0x90, 0x90, 0]) * 120,
}

_DCL_VARIANTS = [(coded, bits) for coded in (False, True) for bits in (4, 5, 6)]


def _decode_all(
    decompressor: ReduceDecompressor | DclImplodeDecompressor, data: bytes
) -> bytes:
    out = decompressor.decompress(data)
    decompressor.end_input()
    return out


def _entries() -> list[LegacyEntry]:
    entries = []
    for key, data in _DATA.items():
        for factor in (1, 2, 3, 4):
            entries.append(reduce_entry(f"reduce-{factor}/{key}", data, factor=factor))
        for coded, bits in _DCL_VARIANTS:
            entries.append(
                dcl_implode_entry(
                    f"dcl-{int(coded)}{bits}/{key}", data, coded=coded, window_bits=bits
                )
            )
    return entries


@pytest.fixture(scope="module")
def legacy_zip(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    entries = _entries()
    path = tmp_path_factory.mktemp("reduce") / "reduce.zip"
    path.write_bytes(build_zip(entries))
    return path, {e.name: e.data for e in entries}


def test_pkzip_reduce_streams_decode() -> None:
    """PKZIP 0.92's own output (factor 4), the second one with a copy from before the
    start, which reads zeros as Info-ZIP ``unreduce`` reads it."""
    hamlet = (_FIXTURES / "hamlet_2048.txt").read_bytes()
    stream = (_FIXTURES / "reduce_hamlet_2048.bin").read_bytes()
    assert _decode_all(ReduceDecompressor(2048, factor=4), stream) == hamlet
    zeros = (_FIXTURES / "reduce_zero_reduced.bin").read_bytes()
    assert _decode_all(ReduceDecompressor(3072, factor=4), zeros) == hamlet + bytes(
        1024
    )


def test_blast_example_decodes() -> None:
    """The example in zlib's ``blast.c``: a coded-literal-free stream with a 1 KiB
    window."""
    decoder = DclImplodeDecompressor(None)
    assert _decode_all(decoder, bytes.fromhex("00048224258f807f")) == b"AIAIAIAIAIAIA"
    assert decoder.eof


def test_the_encoders_exercise_every_feature() -> None:
    for factor in (1, 2, 3, 4):
        _, stats = reduce(_DATA["zeros"] + _DATA["escapes"], factor=factor)
        assert stats.long_copies > 0
        assert stats.escaped_literals > 0
        assert stats.before_start > 0
        _, stats = reduce(_TEXT, factor=factor)
        assert stats.far_copies > 0
        # Every index width, 1 to 5 bits.
        widths = {max(1, (n - 1).bit_length()) for n in stats.follower_sizes}
        assert widths == {1, 2, 3, 4, 5}
    for coded, bits in _DCL_VARIANTS:
        _, dstats = dcl_implode(_TEXT + bytes(600), coded=coded, window_bits=bits)
        assert dstats.two_byte_copies > 0
        assert dstats.longest == 518


def test_members_decode_from_a_file(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    seen = {}
    with open_archive(path) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
            algo = member.compression[0].algo
            if member.name.startswith("reduce-"):
                assert algo is CompressionAlgorithm.REDUCE
            else:
                assert algo is CompressionAlgorithm.DCL_IMPLODE
    assert seen == expected


def test_members_decode_from_a_pipe(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    seen = {}
    with open_archive(NonSeekableBytesIO(path.read_bytes()), streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    assert seen == expected


def test_random_access_and_small_reads(legacy_zip: tuple[Path, dict]) -> None:
    path, expected = legacy_zip
    with open_archive(path) as reader:
        for name in ("reduce-4/text", "dcl-16/text", "reduce-1/escapes"):
            with reader.open(reader.get(name)) as stream:
                parts = []
                while chunk := stream.read(7):
                    parts.append(chunk)
            assert b"".join(parts) == expected[name]


def _read_one(entry: LegacyEntry, compressed: bytes) -> bytes:
    data = build_zip([LegacyEntry(entry.name, entry.data, entry.method, compressed)])
    with open_archive(io.BytesIO(data)) as reader:
        return reader.read(reader.get(entry.name))


def _one_of_each() -> list:
    return [
        *(
            pytest.param(reduce_entry("x", _TEXT, factor=f), id=f"reduce-{f}")
            for f in (1, 4)
        ),
        *(
            pytest.param(
                dcl_implode_entry("x", _TEXT, coded=coded, window_bits=bits),
                id=f"dcl-{int(coded)}{bits}",
            )
            for coded, bits in ((False, 4), (True, 6))
        ),
    ]


@pytest.mark.parametrize("entry", _one_of_each())
def test_cut_data_is_truncated(entry: LegacyEntry) -> None:
    with pytest.raises(TruncatedError):
        _read_one(entry, entry.compressed[:-10])


@pytest.mark.parametrize("entry", _one_of_each())
@pytest.mark.parametrize("extra", [b"\x00", b"\x01\x02"], ids=["zero", "junk"])
def test_bytes_after_the_end_are_refused(entry: LegacyEntry, extra: bytes) -> None:
    """Reduce ends at the member's size and DCL Implode at its end code; a whole byte
    after either is not padding (DR-3)."""
    with pytest.raises(CorruptionError, match="left after its end"):
        _read_one(entry, entry.compressed + extra)


def _follower_sets(sizes: dict[int, int]) -> BitWriter:
    """A Reduce stream's follower sets: ``sizes[byte]`` followers (each byte ``A``)
    for the bytes named, none for the others."""
    out = BitWriter()
    for byte in range(255, -1, -1):
        count = sizes.get(byte, 0)
        out.write(count, 6)
        for _ in range(count):
            out.write(ord("A"), 8)
    return out


def test_a_follower_set_over_32_is_refused() -> None:
    stream = _follower_sets({7: 33}).getvalue() + bytes(40)
    with pytest.raises(CorruptionError, match="over 32"):
        _decode_all(ReduceDecompressor(10, factor=1), stream)


def test_a_follower_index_past_its_set_is_refused() -> None:
    """Byte 0 (the one before the first) has three followers; index 3 names none."""
    out = _follower_sets({0: 3})
    out.write(0, 1)
    out.write(3, 2)
    with pytest.raises(CorruptionError, match="past the 3 followers"):
        _decode_all(ReduceDecompressor(10, factor=1), out.getvalue() + bytes(4))


@pytest.mark.parametrize(
    ("header", "message"),
    [
        pytest.param(b"\x02\x04", "literal mode 2", id="literal-mode"),
        pytest.param(b"\x00\x03", "window size 3", id="small-window"),
        pytest.param(b"\x00\x07", "window size 7", id="large-window"),
    ],
)
def test_bad_dcl_headers_are_refused(header: bytes, message: str) -> None:
    with pytest.raises(CorruptionError, match=message):
        _decode_all(DclImplodeDecompressor(None), header + bytes(8))


def test_a_dcl_copy_from_before_the_start_is_refused() -> None:
    """``blast.c`` refuses it ("distance is too far back"), where Reduce reads zeros."""
    # Flag bit 1 first: a copy (length 3, distance 1) with no output yet.
    out = BitWriter()
    out.write(0, 8)
    out.write(4, 8)
    out.write(1, 1)
    out.write_msb_first(0b00, 2)  # length symbol 0 (3), inverted code 11
    out.write_msb_first(0b11, 2)  # distance high bits 0, inverted code 00
    out.write(0, 4)
    with pytest.raises(CorruptionError, match="before the start"):
        _decode_all(DclImplodeDecompressor(None), out.getvalue() + bytes(4))


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(reduce_entry("a.txt", _TEXT, factor=3), id="reduce"),
        pytest.param(
            dcl_implode_entry("a.txt", _TEXT, coded=True, window_bits=5), id="dcl"
        ),
    ],
)
def test_an_encrypted_member_reads(entry: LegacyEntry) -> None:
    """ZipCrypto around either method, with the right and a wrong password."""
    data = build_zipcrypto_zip(
        b"pw",
        b"a.txt",
        entry.data,
        compression=entry.method,
        compressed=entry.compressed,
    )
    with open_archive(io.BytesIO(data), password=b"pw") as reader:
        assert reader.read(reader.get("a.txt")) == _TEXT
    with (
        open_archive(io.BytesIO(data), password=b"wrong") as reader,
        pytest.raises(EncryptionError),
    ):
        reader.read(reader.get("a.txt"))


def test_a_pipe_reduce_member_with_a_data_descriptor_is_refused() -> None:
    """With bit 3 the size is only after the data, and Reduce does not mark its end.
    From a file, the central directory gives the size and the member reads."""
    data = build_zip([reduce_entry("x", _TEXT, factor=2)], descriptor=True)
    with (
        open_archive(NonSeekableBytesIO(data), streaming=True) as reader,
        pytest.raises(UnsupportedFeatureError, match="Reduce"),
    ):
        for _, stream in reader.stream_members():
            assert stream is not None
            stream.read()
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.read(reader.get("x")) == _TEXT


def test_a_pipe_dcl_member_with_a_data_descriptor_reads() -> None:
    """DCL Implode marks its end, so a pipe finds where the data stops."""
    entries = [
        dcl_implode_entry("x", _TEXT, coded=True, window_bits=6),
        dcl_implode_entry("y", b"second", coded=False, window_bits=4),
    ]
    data = build_zip(entries, descriptor=True)
    seen = {}
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    assert seen == {"x": _TEXT, "y": b"second"}
