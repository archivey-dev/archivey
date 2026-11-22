"""The pure-Python LZFSE, LZVN and ADC decoders (DMG plan, Part A).

Real data: the LZFSE runs of two ``hdiutil`` images (``tests/fixtures/external/
dmg_hdiutil``), checked against the CRC-32 each image stores for its partitions.
Oracle: the ``lzfse`` package (Apple's reference C code), which writes streams for the
round trips and decodes the ``bvx1`` blocks built here. It runs in a subprocess,
because importing it re-enables the GIL on a free-threaded build.
"""

from __future__ import annotations

import pickle
import plistlib
import random
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from archivey import CompressionAlgorithm, CompressionMethod, FormatPolicy
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.codecs import lzfse_decoder
from archivey.internal.streams.codecs.adc_decoder import adc_decompress
from archivey.internal.streams.codecs.lzfse_decoder import (
    lzfse_decompress,
    lzvn_decompress,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"
_IMAGES = ("hfs-ULFO.dmg", "apfs-ULFO.dmg")
_ADC_IMAGE = "hfs-UDCO.dmg"

_ZERO, _RAW, _IGNORE, _ADC, _LZFSE = 0, 1, 2, 0x80000004, 0x80000007
_COMMENT, _END = 0x7FFFFFFE, 0xFFFFFFFF


def _tables(path: Path) -> list[tuple[int, list[tuple[int, int, int, int]]]]:
    """Each ``blkx`` table of a UDIF image: its CRC-32 and its runs as (type, sectors,
    stored offset, stored length). Just enough of UDIF for these tests."""
    data = path.read_bytes()
    koly = data[-512:]
    assert koly[:4] == b"koly"
    (data_fork,) = struct.unpack_from(">Q", koly, 24)
    xml_off, xml_len = struct.unpack_from(">QQ", koly, 216)
    plist = plistlib.loads(data[xml_off : xml_off + xml_len])
    tables = []
    for entry in plist["resource-fork"]["blkx"]:
        mish = entry["Data"]
        assert mish[:4] == b"mish"
        (data_off,) = struct.unpack_from(">Q", mish, 24)
        ck_type, ck_bits = struct.unpack_from(">II", mish, 64)
        assert (ck_type, ck_bits) == (2, 32)
        (crc,) = struct.unpack_from(">I", mish, 72)
        (count,) = struct.unpack_from(">I", mish, 200)
        runs = []
        for i in range(count):
            kind, _c, _sec, sectors, off, length = struct.unpack_from(
                ">IIQQQQ", mish, 204 + 40 * i
            )
            runs.append((kind, sectors, data_fork + data_off + off, length))
        tables.append((crc, runs))
    return tables


def _lzfse_runs() -> list[tuple[bytes, int]]:
    runs = []
    for name in _IMAGES:
        data = (_FIXTURES / name).read_bytes()
        for _crc, table in _tables(_FIXTURES / name):
            for kind, sectors, off, length in table:
                if kind == _LZFSE:
                    runs.append((data[off : off + length], sectors * 512))
    return runs


def _blocks(stream: bytes) -> list[tuple[bytes, int, int]]:
    """(magic, offset, length) of each block before ``bvx$``."""
    out = []
    pos = 0
    while stream[pos : pos + 4] != b"bvx$":
        magic = stream[pos : pos + 4]
        if magic == b"bvx-":
            length = 8 + struct.unpack_from("<I", stream, pos + 4)[0]
        elif magic == b"bvxn":
            length = 12 + struct.unpack_from("<I", stream, pos + 8)[0]
        else:
            assert magic == b"bvx2"
            _n_raw, p0, p1, p2 = struct.unpack_from("<IQQQ", stream, pos + 4)
            length = (p2 & 0xFFFFFFFF) + ((p0 >> 20) & 0xFFFFF) + ((p1 >> 40) & 0xFFFFF)
        out.append((magic, pos, length))
        pos += length
    return out


def _oracle(op: str, items: list[bytes]) -> list[bytes | None]:
    """``lzfse.compress`` or ``lzfse.decompress`` on each item, in a subprocess;
    ``None`` where the package refuses."""
    script = (
        "import pickle, sys, lzfse\n"
        "items = pickle.load(sys.stdin.buffer)\n"
        "out = []\n"
        "for x in items:\n"
        "    try:\n"
        f"        out.append(lzfse.{op}(x))\n"
        "    except lzfse.error:\n"
        "        out.append(None)\n"
        "pickle.dump(out, sys.stdout.buffer)\n"
    )
    done = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", script],
        input=pickle.dumps(items),
        capture_output=True,
        check=True,
    )
    return pickle.loads(done.stdout)


def _have_lzfse() -> bool:
    done = subprocess.run(
        [sys.executable, "-c", "import lzfse"], capture_output=True, check=False
    )
    return done.returncode == 0


requires_lzfse = pytest.mark.skipif(
    not _have_lzfse(), reason="the lzfse package is not installed"
)


# --- Real data -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "codec"), [(name, _LZFSE) for name in _IMAGES] + [(_ADC_IMAGE, _ADC)]
)
def test_fixture_partitions_match_their_crc(name: str, codec: int) -> None:
    """Every partition of the image decodes to the CRC-32 hdiutil stored for it: zero
    fill and raw runs as they are, LZFSE and ADC runs through their decoders, ignore
    runs left out (the measured rule)."""
    data = (_FIXTURES / name).read_bytes()
    decoded_runs = 0
    for crc, runs in _tables(_FIXTURES / name):
        value = 0
        for kind, sectors, off, length in runs:
            size = sectors * 512
            if kind == _ZERO:
                value = zlib.crc32(bytes(size), value)
            elif kind == _RAW:
                value = zlib.crc32(data[off : off + length], value)
            elif kind == codec:
                decode = lzfse_decompress if kind == _LZFSE else adc_decompress
                out = decode(data[off : off + length], size)
                assert len(out) == size
                value = zlib.crc32(out, value)
                decoded_runs += 1
            else:
                assert kind in (_IGNORE, _COMMENT, _END)
        assert value == crc
    assert decoded_runs >= 7


def test_adc_image_holds_the_files_it_was_made_from() -> None:
    """``hfs-UDCO.dmg`` holds ``repeat.txt`` (300,000 bytes of one repeated line, so
    ADC writes long matches) and ``hello.txt``; both appear whole in the decoded disk."""
    path = _FIXTURES / _ADC_IMAGE
    data = path.read_bytes()
    disk = bytearray()
    for _crc, runs in _tables(path):
        for kind, sectors, off, length in runs:
            if kind == _ZERO:
                disk += bytes(sectors * 512)
            elif kind == _RAW:
                disk += data[off : off + length]
            elif kind == _ADC:
                disk += adc_decompress(data[off : off + length], sectors * 512)
    assert (b"hello adc fixture\n" * 20_000)[:300_000] in disk
    assert b"hello dmg\n" in disk


def test_fixtures_hold_every_block_kind_hdiutil_writes() -> None:
    kinds = {
        magic for stream, _size in _lzfse_runs() for magic, _o, _l in _blocks(stream)
    }
    assert kinds == {b"bvx2", b"bvxn"}
    assert any(len(_blocks(stream)) > 1 for stream, _size in _lzfse_runs())


def test_raw_lzvn_decodes_the_payload_of_each_bvxn_block() -> None:
    """decmpfs types 7 and 8 store LZVN with no block header: each ``bvxn`` payload of
    the fixtures, alone, decodes to the block's output."""
    seen = 0
    for stream, size in _lzfse_runs():
        blocks = _blocks(stream)
        if [m for m, _o, _l in blocks] != [b"bvxn"]:
            continue
        _magic, pos, length = blocks[0]
        (n_raw,) = struct.unpack_from("<I", stream, pos + 4)
        payload = stream[pos + 12 : pos + length]
        assert lzvn_decompress(payload, n_raw) == lzfse_decompress(stream, size)
        seen += 1
    assert seen >= 4


# --- The reference implementation as oracle --------------------------------------


def _inputs(seed: int, count: int) -> list[bytes]:
    rnd = random.Random(seed)
    words = [
        bytes(rnd.choice(b"abcdefghij \n") for _ in range(rnd.randint(1, 9)))
        for _ in range(80)
    ]
    items = [b"", b"a", bytes(100_000), rnd.randbytes(70_000)]
    for i in range(count):
        n = rnd.choice((rnd.randint(1, 5000), rnd.randint(1, 200_000)))
        text = b"".join(rnd.choice(words) for _ in range(n))[:n]
        items.append(text if i % 3 else bytes(rnd.randint(0, 3) for _ in range(n)))
    return items


@requires_lzfse
def test_reference_encoder_output_round_trips() -> None:
    items = _inputs(1, 300)
    streams = _oracle("compress", items)
    kinds = set()
    for data, stream in zip(items, streams, strict=True):
        assert stream is not None
        kinds |= {m for m, _o, _l in _blocks(stream)}
        assert lzfse_decompress(stream, len(data)) == data
    assert {b"bvx-", b"bvxn", b"bvx2"} <= kinds


def _to_v1(stream: bytes) -> bytes:
    """The same stream with each ``bvx2`` block rewritten as ``bvx1``: the header's
    fields unpacked into the 772-byte v1 header, the payloads unchanged."""
    out = bytearray()
    for magic, pos, length in _blocks(stream):
        if magic != b"bvx2":
            out += stream[pos : pos + length]
            continue
        n_raw, p0, p1, p2 = struct.unpack_from("<IQQQ", stream, pos + 4)
        header_size = p2 & 0xFFFFFFFF
        freq = lzfse_decoder._v2_frequencies(stream, pos + 32, pos + header_size)
        n_lit_payload = (p0 >> 20) & 0xFFFFF
        n_lmd_payload = (p1 >> 40) & 0xFFFFF
        out += struct.pack(
            "<4s6Ii4HiHHH360H",
            b"bvx1",
            n_raw,
            n_lit_payload + n_lmd_payload,
            p0 & 0xFFFFF,
            (p0 >> 40) & 0xFFFFF,
            n_lit_payload,
            n_lmd_payload,
            ((p0 >> 60) & 7) - 7,
            *[(p1 >> s) & 0x3FF for s in (0, 10, 20, 30)],
            ((p1 >> 60) & 7) - 7,
            (p2 >> 32) & 0x3FF,
            (p2 >> 42) & 0x3FF,
            (p2 >> 52) & 0x3FF,
            *freq,
        )
        out += b"\0\0"  # the struct's padding to 4-byte alignment
        out += stream[pos + header_size : pos + length]
    return bytes(out + b"bvx$")


@requires_lzfse
def test_bvx1_blocks_decode_as_the_reference_decodes_them() -> None:
    items = [d for d in _inputs(2, 60) if len(d) > 5000]
    streams = _oracle("compress", items)
    v1 = [_to_v1(s) for s in streams if s is not None]
    assert sum(b"bvx1" in s for s in v1) > 10
    reference = _oracle("decompress", v1)
    for data, stream, ref in zip(items, v1, reference, strict=True):
        assert ref == data
        assert lzfse_decompress(stream, len(data)) == data


@requires_lzfse
def test_fixture_runs_decode_as_the_reference_decodes_them() -> None:
    runs = _lzfse_runs()
    reference = _oracle("decompress", [stream for stream, _size in runs])
    for (stream, size), ref in zip(runs, reference, strict=True):
        assert lzfse_decompress(stream, size) == ref


# --- Damage ------------------------------------------------------------------------


def _small_streams() -> list[tuple[bytes, bytes]]:
    """(data, stream) with one block of each kind hdiutil writes, plus a stored block,
    taken from the fixtures so no encoder is needed."""
    out = []
    for stream, size in _lzfse_runs():
        kinds = [m for m, _o, _l in _blocks(stream)]
        if kinds in ([b"bvxn"], [b"bvx2"]) and len(stream) < 1000:
            out.append((lzfse_decompress(stream, size), stream))
    out.append((b"hello", b"bvx-\x05\0\0\0hello" + b"bvx$"))
    return out


def test_every_truncation_raises() -> None:
    for data, stream in _small_streams():
        for cut in range(len(stream)):
            with pytest.raises(CorruptionError):
                lzfse_decompress(stream[:cut], len(data))


def test_ending_before_the_end_block_is_truncation() -> None:
    _data, stream = _small_streams()[-1]
    with pytest.raises(TruncatedError):
        lzfse_decompress(stream[:-4], 100)


def test_bytes_after_the_end_block_are_refused() -> None:
    data, stream = _small_streams()[0]
    with pytest.raises(CorruptionError, match="follow the end of the LZFSE stream"):
        lzfse_decompress(stream + b"\0", len(data))


def test_output_past_max_length_is_refused() -> None:
    for data, stream in _small_streams():
        with pytest.raises(CorruptionError, match="more than"):
            lzfse_decompress(stream, len(data) - 1)


def test_bit_flips_raise_corruption_or_decode_within_the_limit() -> None:
    """No mutation of a valid stream crashes, loops or passes the limit: each raises
    :class:`CorruptionError` or returns at most ``max_length`` bytes."""
    rnd = random.Random(5)
    for data, stream in _small_streams():
        for _ in range(400):
            broken = bytearray(stream)
            for _ in range(rnd.randint(1, 3)):
                broken[rnd.randrange(len(broken))] ^= 1 << rnd.randrange(8)
            try:
                out = lzfse_decompress(bytes(broken), len(data))
            except CorruptionError:
                continue
            assert len(out) <= len(data)


def test_unknown_block_magic() -> None:
    with pytest.raises(CorruptionError, match="unknown LZFSE block magic"):
        lzfse_decompress(b"bvx3\0\0\0\0bvx$", 10)


def test_empty_stream_decodes_to_nothing() -> None:
    assert lzfse_decompress(b"bvx-\0\0\0\0bvx$", 0) == b""


def _v2_field(stream: bytes, word: int, shift: int, bits: int, value: int) -> bytes:
    """``stream`` with one packed field of its first ``bvx2`` header set to ``value``."""
    pos = 8 + 8 * word
    (packed,) = struct.unpack_from("<Q", stream, pos)
    packed = (packed & ~(((1 << bits) - 1) << shift)) | (value << shift)
    return stream[:pos] + struct.pack("<Q", packed) + stream[pos + 8 :]


def _v2_stream() -> tuple[bytes, bytes]:
    for data, stream in _small_streams():
        if stream[:4] == b"bvx2":
            return data, stream
    raise AssertionError("no bvx2 fixture block")


def test_bvx2_block_must_decode_to_its_declared_size() -> None:
    data, stream = _v2_stream()
    (n_raw,) = struct.unpack_from("<I", stream, 4)
    short = stream[:4] + struct.pack("<I", n_raw - 1) + stream[8:]
    with pytest.raises(CorruptionError, match="more than its"):
        lzfse_decompress(short, len(data))
    long = stream[:4] + struct.pack("<I", n_raw + 1) + stream[8:]
    with pytest.raises(CorruptionError, match="its header says"):
        lzfse_decompress(long, len(data) + 1)


def test_bvx2_literal_count_must_be_a_multiple_of_4() -> None:
    data, stream = _v2_stream()
    (p0,) = struct.unpack_from("<Q", stream, 8)
    broken = _v2_field(stream, 0, 0, 20, (p0 & 0xFFFFF) + 1)
    with pytest.raises(CorruptionError, match="not a multiple of 4"):
        lzfse_decompress(broken, len(data))


def test_bvx2_initial_state_out_of_range() -> None:
    data, stream = _v2_stream()
    broken = _v2_field(stream, 2, 32, 10, 64)  # the L state; 64 states
    with pytest.raises(CorruptionError, match="state out of range"):
        lzfse_decompress(broken, len(data))


def _v2_block(
    n_raw: int, n_literals: int, n_matches: int, lmd_payload: int = 7
) -> bytes:
    """A ``bvx2`` block with an empty frequency area (every frequency 0, so every
    symbol costs no bits), all states 0 and zero-filled payloads."""
    p0 = n_literals | (7 << 20) | (n_matches << 40) | (7 << 60)
    p1 = (lmd_payload << 40) | (7 << 60)
    p2 = 32
    payload = bytes(7 + lmd_payload)
    return b"bvx2" + struct.pack("<IQQQ", n_raw, p0, p1, p2) + payload


def test_bvx2_block_with_an_empty_frequency_area_decodes() -> None:
    assert lzfse_decompress(_v2_block(0, 0, 0) + b"bvx$", 0) == b""


@pytest.mark.parametrize(
    ("n_literals", "n_matches", "message"),
    [
        (40_000, 0, "40000 literals for 0 bytes"),
        (0, 1, "1 matches for 0 bytes"),
    ],
)
def test_bvx2_work_is_bounded_by_its_output(
    n_literals: int, n_matches: int, message: str
) -> None:
    # Such blocks cost no input bits per symbol: unchecked, 46 bytes would buy 10,000
    # loop iterations that write nothing.
    stream = _v2_block(0, n_literals, n_matches) * 100 + b"bvx$"
    with pytest.raises(CorruptionError, match=message):
        lzfse_decompress(stream, 0)


def test_bvx2_bit_stream_shorter_than_its_first_load() -> None:
    # The match stream's first load may not reach back into the literal payload.
    with pytest.raises(CorruptionError, match="shorter than its first load"):
        lzfse_decompress(_v2_block(0, 0, 0, lmd_payload=3) + b"bvx$", 0)


def test_bvx2_header_shorter_than_its_fixed_fields() -> None:
    data, stream = _v2_stream()
    broken = _v2_field(stream, 2, 0, 32, 16)
    with pytest.raises(CorruptionError, match="block header of 16 bytes"):
        lzfse_decompress(broken, len(data))


def test_bvx2_matches_may_not_use_more_literals_than_decoded() -> None:
    data, stream = _v2_stream()
    (p0,) = struct.unpack_from("<Q", stream, 8)
    broken = _v2_field(stream, 0, 0, 20, (p0 & 0xFFFFF) - 4)
    with pytest.raises(CorruptionError, match="uses more literals than it decoded"):
        lzfse_decompress(broken, len(data))


def test_truncated_bvx1_header() -> None:
    _data, stream = _v2_stream()
    with pytest.raises(TruncatedError, match="inside a block header"):
        lzfse_decompress(_to_v1(stream)[:700], 1 << 20)


def test_lzvn_block_declaring_no_output_is_refused() -> None:
    stream = b"bvxn" + struct.pack("<II", 0, 8) + b"\x06" + bytes(7) + b"bvx$"
    with pytest.raises(CorruptionError, match="declares no output"):
        lzfse_decompress(stream, 100)


def test_lzvn_block_must_use_its_whole_payload() -> None:
    for data, stream in _small_streams():
        if stream[:4] != b"bvxn":
            continue
        _n_raw, n_payload = struct.unpack_from("<II", stream, 4)
        padded = (
            stream[:8]
            + struct.pack("<I", n_payload + 1)
            + stream[12 : 12 + n_payload]
            + b"\0"
            + stream[12 + n_payload :]
        )
        with pytest.raises(CorruptionError, match="follow the end of an LZVN block"):
            lzfse_decompress(padded, len(data))
        return
    raise AssertionError("no bvxn fixture block")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            b"\xe3abc\x00\x05" + b"\x06" + b"\0" * 7,
            "before the start",
        ),  # distance 5 > 3
        (
            b"\xe3abc\xf1" + b"\x06" + b"\0" * 7,
            "before the start",
        ),  # no previous distance
        (b"\x1e", "undefined LZVN opcode"),
        (b"\x70", "undefined LZVN opcode"),
        (b"\xd5", "undefined LZVN opcode"),
        (b"\x7e", "undefined LZVN opcode"),
        (b"\xe3abc\x07\x00", "ends inside an opcode"),  # lrg_d
        (b"\xe3abc\x01", "ends inside an opcode"),  # sml_d
        (b"\xe3abc\xa0\x00", "ends inside an opcode"),  # med_d
        (b"\xe0", "ends inside an opcode"),  # lrg_l
        (b"\xf0", "ends inside an opcode"),  # lrg_m
        (b"\xe3ab", "ends inside a literal"),
        (b"\xe3abc\x06\0\0", "ends inside its end marker"),
        (b"\xe3abc", "before its end-of-stream opcode"),
        (b"\xe3abc\x06" + b"\0" * 7 + b"x", "follow the end of the LZVN data"),
    ],
)
def test_lzvn_damage(payload: bytes, message: str) -> None:
    with pytest.raises(CorruptionError, match=message):
        lzvn_decompress(payload, 100)


def test_lzvn_opcodes() -> None:
    # literal "abc", then sml_d (L=0, M=3, D=3), nop, pre_d (L=1 "d", M=3), sml_m (M=2),
    # lrg_l (16 + 1 literals), lrg_m (16 + 0, D=1 from... the previous distance)
    payload = (
        b"\xe3abc"
        + bytes([0b00000000, 3])  # sml_d: L=0, M=3, D=3 -> "abc"
        + b"\x0e"  # nop
        + bytes([0b01000110]) + b"d"  # pre_d: L=1 "d", M=3, D=3 -> "bcd"
        + b"\xf2"  # sml_m: M=2, D=3 -> "bc"
        + b"\xe0\x01" + b"q" * 17  # lrg_l: 17 literals
        + b"\xf0\x00"  # lrg_m: M=16, D=3 -> "qqq..."
        + b"\x06" + b"\0" * 7
    )  # fmt: skip
    expected = b"abc" + b"abc" + b"d" + b"bcd" + b"bc" + b"q" * 17 + b"q" * 16
    assert lzvn_decompress(payload, len(expected)) == expected
    with pytest.raises(CorruptionError, match="more than"):
        lzvn_decompress(payload, len(expected) - 1)


def test_lzvn_overruns_name_lzvn_and_the_limit_that_was_passed() -> None:
    four = b"\xe4abcd" + b"\x06" + bytes(7)  # four literals, then end-of-stream
    with pytest.raises(
        CorruptionError, match="^LZVN data decodes to more than 2 bytes"
    ):
        lzvn_decompress(four, 2)
    # sml_d: L=1 "a", then M=3 at D=1 -> "aaaa"; the match is what passes the limit.
    match = bytes([0b01000000, 1]) + b"a" + b"\x06" + bytes(7)
    with pytest.raises(
        CorruptionError, match="^LZVN data decodes to more than 2 bytes"
    ):
        lzvn_decompress(match, 2)
    # A bvxn block that declares 3 bytes and writes 4, far below max_length.
    stream = b"bvx-" + struct.pack("<I", 100) + bytes(100)
    stream += b"bvxn" + struct.pack("<II", 3, len(four)) + four + b"bvx$"
    with pytest.raises(
        CorruptionError, match="^LZVN block decodes to more than its 3 bytes"
    ):
        lzfse_decompress(stream, 1000)


# --- ADC -------------------------------------------------------------------------


def _adc_literal(data: bytes) -> bytes:
    """ADC with one-byte literal commands only: valid, and about twice its output."""
    return b"".join(b"\x80" + data[i : i + 1] for i in range(len(data)))


def test_adc_commands() -> None:
    stream = (
        b"\x83abcd"  # literal run of 4
        + bytes([0b00000000, 3])  # short match: length 3, distance 4 -> "abc"
        + bytes([0b01000000, 0, 6])  # long match: length 4, distance 7 -> "abcd"
        + bytes([0b00111100 | 0, 0])  # short match: length 18, distance 1 -> 18 x "d"
    )
    expected = b"abcd" + b"abc" + b"abcd" + b"d" * 18
    assert adc_decompress(stream, len(expected)) == expected


def test_adc_one_byte_literals_twice_the_size() -> None:
    data = random.Random(3).randbytes(4096)
    stream = _adc_literal(data)
    assert len(stream) == 2 * len(data)
    assert adc_decompress(stream, len(data)) == data


@pytest.mark.parametrize(
    ("stream", "error", "message"),
    [
        (b"\x83abc", TruncatedError, "literal run"),
        (b"\x80a\x40\x00", TruncatedError, "match"),
        (b"\x80a\x00", TruncatedError, "match"),
        (b"\x80a\x00\x01", CorruptionError, "before the start"),  # distance 2 > 1
        (b"\x00\x00", CorruptionError, "before the start"),
    ],
)
def test_adc_damage(stream: bytes, error: type[Exception], message: str) -> None:
    with pytest.raises(error, match=message):
        adc_decompress(stream, 100)


def test_adc_output_past_max_length() -> None:
    with pytest.raises(CorruptionError, match="more than 3 bytes"):
        adc_decompress(b"\x83abcd", 3)
    with pytest.raises(CorruptionError, match="more than 5 bytes"):
        adc_decompress(b"\x80a\x3c\x00", 5)


# --- Public names ----------------------------------------------------------------


@pytest.mark.parametrize(
    "algo",
    [CompressionAlgorithm.LZFSE, CompressionAlgorithm.LZVN, CompressionAlgorithm.ADC],
)
def test_new_methods_can_be_excluded(algo: CompressionAlgorithm) -> None:
    policy = FormatPolicy(exclude=[algo])
    assert algo in policy.exclude
    assert policy._excluded_methods((CompressionMethod(algo),)) == ((algo, algo),)


def test_excluding_lzvn_excludes_lzfse_but_not_the_reverse() -> None:
    lzfse, lzvn = CompressionAlgorithm.LZFSE, CompressionAlgorithm.LZVN
    no_lzvn = FormatPolicy(exclude=[lzvn])
    assert no_lzvn._excluded_methods((CompressionMethod(lzfse),)) == ((lzfse, lzvn),)
    no_lzfse = FormatPolicy(exclude=[lzfse])
    assert no_lzfse._excluded_methods((CompressionMethod(lzvn),)) == ()
