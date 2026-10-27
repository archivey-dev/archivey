"""The 7z RISC-V branch filter (method ``0x0B``), decoded in Python.

The oracles are 7-Zip 24 or later (two committed archives 7-Zip 26.05 wrote from real
RISC-V code, and, when a 7-Zip that has the filter is on ``PATH``, archives and with
``-m1=Copy`` the filtered bytes it writes) and ``_reference``, a halfword-by-halfword
port of liblzma's ``riscv_encode`` and ``riscv_decode`` kept deliberately naive so it
shares no code with the decoder under test.
"""

from __future__ import annotations

import collections
import hashlib
import io
import random
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import TruncatedError, UnsupportedFeatureError
from archivey.internal.backends import sevenzip_parser, sevenzip_pipeline
from archivey.internal.backends.sevenzip_parser import SevenZipCoder
from archivey.internal.backends.sevenzip_pipeline import plan_folder
from archivey.internal.streams.codecs.lzma_filter_decoder import (
    FilterStream,
    PythonBranchFilterDecoder,
)
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV, riscv_decode
from archivey.types import CompressionAlgorithm
from tests.conftest import run_7z, sevenzip_with_riscv

_FIXTURES = Path(__file__).parent / "fixtures" / "sevenzip"
_RISCV = b"\x0b"
_LZMA2 = b"\x21"
_M32 = 0xFFFFFFFF


def _reference(
    data: bytes,
    pc: int,
    *,
    encode: bool,
    counts: collections.Counter[str] | None = None,
) -> bytes:
    """liblzma's ``riscv_encode`` / ``riscv_decode``, one halfword at a time.

    The whole buffer is the stream: the last 7 bytes are never converted, as at the
    end of a stream. ``counts`` tallies the conversions by kind.
    """
    buf = bytearray(data)
    i = 0
    while i <= len(buf) - 8:
        now = (pc + i) & _M32
        first = buf[i]
        if first == 0xEF:
            b1, b2, b3 = buf[i + 1], buf[i + 2], buf[i + 3]
            if b1 & 0x0D:
                i += 2
                continue
            if encode:
                addr = (
                    ((b1 & 0xF0) << 8)
                    | ((b2 & 0x0F) << 16)
                    | ((b2 & 0x10) << 7)
                    | ((b2 & 0xE0) >> 4)
                    | ((b3 & 0x7F) << 4)
                    | ((b3 & 0x80) << 13)
                )
                addr = (addr + now) & _M32
                buf[i + 1] = (b1 & 0x0F) | ((addr >> 13) & 0xF0)
                buf[i + 2] = (addr >> 9) & 0xFF
                buf[i + 3] = (addr >> 1) & 0xFF
            else:
                addr = (((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1)) - now
                addr &= _M32
                buf[i + 1] = (b1 & 0x0F) | ((addr >> 8) & 0xF0)
                buf[i + 2] = (
                    ((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)
                )
                buf[i + 3] = ((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)
            if counts is not None:
                counts["jal"] += 1
            i += 4
            continue
        if first & 0x7F != 0x17:
            i += 2
            continue
        inst = int.from_bytes(buf[i : i + 4], "little")
        if inst & 0xE80:
            # rd is neither x0 nor x2: a real pair when encoding, a fake one decoding.
            inst2 = int.from_bytes(buf[i + 4 : i + 8], "little")
            if ((inst << 8) ^ ((inst2 - 3) & _M32)) & 0xF8003:
                i += 6
                continue
            if encode:
                addr = inst & 0xFFFFF000
                addr += (inst2 >> 20) - ((inst2 >> 19) & 0x1000)
                addr = (addr + now) & _M32
                inst = 0x17 | (2 << 7) | ((inst2 << 12) & _M32)
                second = addr.to_bytes(4, "big")
            else:
                addr = ((inst & 0xFFFFF000) + (inst2 >> 20)) & _M32
                inst = 0x17 | (2 << 7) | ((inst2 << 12) & _M32)
                second = addr.to_bytes(4, "little")
            if counts is not None:
                counts["auipc_pair"] += 1
        else:
            # rd is x0 or x2: only the special form converts.
            rs1 = inst >> 27
            if (((inst - 0x3117) << 18) & _M32) >= (rs1 & 0x1D):
                i += 4
                continue
            if encode:
                fake_addr = int.from_bytes(buf[i + 4 : i + 8], "little")
                second = (((inst >> 12) | (fake_addr << 20)) & _M32).to_bytes(
                    4, "little"
                )
                inst = 0x17 | (rs1 << 7) | (fake_addr & 0xFFFFF000)
            else:
                addr = (int.from_bytes(buf[i + 4 : i + 8], "big") - now) & _M32
                second = (((inst >> 12) | (addr << 20)) & _M32).to_bytes(4, "little")
                inst = 0x17 | (rs1 << 7) | ((addr + 0x800) & 0xFFFFF000)
            if counts is not None:
                counts["auipc_special"] += 1
        buf[i : i + 4] = (inst & _M32).to_bytes(4, "little")
        buf[i + 4 : i + 8] = second
        i += 8
    return bytes(buf)


def _jal(rng: random.Random) -> bytes:
    rd = rng.choice((1, 5, 1, 5, 6))  # x6 is not converted
    return (0x6F | (rd << 7) | (rng.getrandbits(20) << 12)).to_bytes(4, "little")


def _auipc_pair(rng: random.Random) -> bytes:
    """AUIPC rd then an I-type instruction based on rd (ADDI, LD or JALR)."""
    rd = rng.choice([r for r in range(32) if r not in (0, 2)])
    auipc = 0x17 | (rd << 7) | (rng.getrandbits(20) << 12)
    opcode, funct3 = rng.choice(((0x13, 0), (0x03, 3), (0x67, 0)))
    second = (
        (rng.getrandbits(12) << 20)
        | (rd << 15)
        | (funct3 << 12)
        | (rng.getrandbits(5) << 7)
        | opcode
    )
    return auipc.to_bytes(4, "little") + second.to_bytes(4, "little")


def _auipc_x0_x2(rng: random.Random) -> bytes:
    """AUIPC with rd x0 or x2 and random bits: what the encoder must leave decodable."""
    rd = rng.choice((0, 2))
    auipc = 0x17 | (rd << 7) | (rng.getrandbits(20) << 12)
    return auipc.to_bytes(4, "little") + rng.getrandbits(32).to_bytes(4, "little")


def _payload(items: int, *, tail: bytes = b"", seed: int = 1) -> bytes:
    """Mostly JAL and AUIPC pairs, between 2-byte (compressed) and 4-byte fillers.

    The 2-byte fillers put the 4-byte instructions at both alignments mod 4.
    """
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(items):
        pick = rng.random()
        if pick < 0.25:
            out += _jal(rng)
        elif pick < 0.45:
            out += _auipc_pair(rng)
        elif pick < 0.55:
            out += _auipc_x0_x2(rng)
        elif pick < 0.8:
            out += rng.getrandbits(16).to_bytes(2, "little")
        else:
            out += rng.getrandbits(32).to_bytes(4, "little")
    return bytes(out + tail)


# About 30 000 items is roughly 140 KB: three of the stream's 64 KiB reads.
_PAYLOAD = _payload(30_000, tail=b"\xef\x00\x17\x01\x00")


def _encode(data: bytes, pc: int) -> bytes:
    return _reference(data, pc, encode=True)


def test_payload_exercises_every_conversion() -> None:
    counts: collections.Counter[str] = collections.Counter()
    _reference(_PAYLOAD, 0, encode=True, counts=counts)
    assert counts["jal"] > 3000
    assert counts["auipc_pair"] > 3000
    assert counts["auipc_special"] > 100
    assert len(_PAYLOAD) > 2 * 65536  # spans three 64 KiB reads


def test_reference_round_trips() -> None:
    for pc in (0, 2, 0x12345678):
        encoded = _encode(_PAYLOAD, pc)
        assert encoded != _PAYLOAD
        assert _reference(encoded, pc, encode=False) == _PAYLOAD


@pytest.mark.parametrize("pc", [0, 2, 0x1000, 0x12345678, _M32 - 5])
def test_decode_matches_reference(pc: int) -> None:
    encoded = _encode(_PAYLOAD, pc)
    decoded = riscv_decode(encoded, pc)
    assert 0 <= len(encoded) - len(decoded) <= 7
    assert decoded + encoded[len(decoded) :] == _PAYLOAD
    assert decoded == _reference(encoded, pc, encode=False)[: len(decoded)]


@pytest.mark.parametrize("size", range(17))
def test_short_input(size: int) -> None:
    # Under 8 bytes nothing is final; from 8 on, at most 7 bytes wait.
    data = _PAYLOAD[:size]
    encoded = _encode(data, 0)
    decoded = riscv_decode(encoded, 0)
    if size < 8:
        assert decoded == b""
    assert len(encoded) - len(decoded) <= 7
    assert decoded + encoded[len(decoded) :] == data


@pytest.mark.parametrize("tail_length", range(8))
def test_tail_is_passed_through(tail_length: int) -> None:
    # A JAL-shaped tail is not converted: its last 7 bytes never are.
    tail = (b"\xef\x00\x00\x00\x17\x01\x00")[:tail_length]
    for items in (0, 1, 9):
        data = _payload(items, tail=tail, seed=items)
        encoded = _encode(data, 0)
        decoder = PythonBranchFilterDecoder(
            decode=riscv_decode, start_offset=0, unpack_size=len(data)
        )
        out = decoder.feed(encoded).data + decoder.flush().data
        assert out == data
        assert decoder.pending_error is None


@pytest.mark.parametrize("piece", [1, 2, 3, 7, 4097, 65537])
@pytest.mark.parametrize("max_length", [-1, 3, 4096])
def test_chunk_boundaries(piece: int, max_length: int) -> None:
    pc = 0x1002
    data = _PAYLOAD[: 3 * 4097 + 5] if piece < 8 else _PAYLOAD
    encoded = _encode(data, pc)
    decoder = PythonBranchFilterDecoder(
        decode=riscv_decode, start_offset=pc, unpack_size=len(data)
    )
    out = bytearray()
    for start in range(0, len(encoded), piece):
        out += decoder.feed(encoded[start : start + piece], max_length).data
        while not decoder.needs_input:
            out += decoder.feed(b"", max_length).data
    out += decoder.flush().data
    assert bytes(out) == data
    assert decoder.finished
    assert decoder.pending_error is None


def test_filter_stream_reads_in_small_pieces_and_seeks_back() -> None:
    encoded = _encode(_PAYLOAD, 0)
    stream = FilterStream(
        io.BytesIO(encoded),
        lzma_filter={"id": FILTER_RISCV},
        unpack_size=len(_PAYLOAD),
        seekable=True,
    )
    try:
        out = bytearray()
        while piece := stream.read(4093):
            out += piece
        assert bytes(out) == _PAYLOAD
        stream.seek(65530)
        assert stream.read(20) == _PAYLOAD[65530:65550]
    finally:
        stream.close()


def test_truncated_input_is_reported() -> None:
    encoded = _encode(_PAYLOAD[:4096], 0)
    stream = FilterStream(
        io.BytesIO(encoded[:-5]), lzma_filter={"id": FILTER_RISCV}, unpack_size=4096
    )
    try:
        with pytest.raises(TruncatedError):
            stream.read()
    finally:
        stream.close()


# --- planning ---------------------------------------------------------------------------


def _folder(coders: list[SevenZipCoder], size: int) -> sevenzip_parser.SevenZipFolder:
    return sevenzip_parser.SevenZipFolder(
        coders=coders,
        bind_pairs=[(i + 1, i) for i in range(len(coders) - 1)],
        packed_indices=[0],
        unpack_sizes=[size] * len(coders),
        crc=None,
        digest_defined=False,
    )


def test_riscv_after_lzma2_is_its_own_stage() -> None:
    # Python's lzma refuses filter id 11 in a raw chain, so it never joins one.
    lzma2 = SevenZipCoder(_LZMA2, 1, 1, b"\x10")
    riscv = SevenZipCoder(_RISCV, 1, 1, (0x1002).to_bytes(4, "little"))
    chain, stage = plan_folder(_folder([lzma2, riscv], 64)).stages
    assert isinstance(chain, sevenzip_pipeline._LzmaChainStage)
    assert [f["id"] for f in chain.filters] == [0x21]
    assert isinstance(stage, sevenzip_pipeline._FilterStage)
    assert stage.lzma_filter == {"id": FILTER_RISCV, "start_offset": 0x1002}


def test_odd_riscv_start_offset_is_refused_at_plan_time() -> None:
    # 7-Zip refuses it too (E_NOTIMPL): instructions are 2-byte aligned.
    riscv = SevenZipCoder(_RISCV, 1, 1, (3).to_bytes(4, "little"))
    with pytest.raises(UnsupportedFeatureError, match="start offset 3 .*multiple of 2"):
        plan_folder(_folder([riscv], 16))


# --- archives 7-Zip wrote ---------------------------------------------------------------

# tests/fixtures/sevenzip/README.md says how these were written.
_FIXTURE_SHA256 = "f400e521f7f241b2c6e2125e5c3347793dae20db81838db15c32e7de2f2554d1"


@pytest.mark.parametrize("name", ["riscv_lzma2.7z", "riscv_offset_lzma2.7z"])
def test_committed_7zip_archive_reads(name: str) -> None:
    # Real RISC-V code from a Go executable; the member CRC checks the decode too.
    with open_archive(_FIXTURES / name) as reader:
        (member,) = reader.members()
        assert tuple(m.algo for m in member.compression) == (
            CompressionAlgorithm.BCJ,
            CompressionAlgorithm.LZMA2,
        )
        with reader.open(member) as stream:
            data = stream.read()
    assert len(data) == 49155
    assert hashlib.sha256(data).hexdigest() == _FIXTURE_SHA256
    counts: collections.Counter[str] = collections.Counter()
    _reference(data, 0, encode=True, counts=counts)
    assert counts["jal"] > 100
    assert counts["auipc_pair"] > 100
    # Real code never has the x0/x2 AUIPC form: riscv_special_lzma2.7z covers it.
    assert counts["auipc_special"] == 0


def test_committed_7zip_archive_with_every_conversion_reads() -> None:
    # The third conversion, AUIPC with rd = x0 or x2, checked against 7-Zip's own
    # encoder where no 7-Zip 24 is installed too.
    with open_archive(_FIXTURES / "riscv_special_lzma2.7z") as reader:
        (member,) = reader.members()
        data = reader.read(member)
    assert data == _payload(600)
    counts: collections.Counter[str] = collections.Counter()
    _reference(data, 0, encode=True, counts=counts)
    assert counts["auipc_special"] > 0


def _require_7z_riscv() -> str:
    program = sevenzip_with_riscv()
    if program is None:
        pytest.skip(
            "no 7-Zip on PATH can write the RISC-V filter (7-Zip 24 or later can; "
            "scripts/install-7zip-from-source.sh builds one)"
        )
    return program


def _write_7z(tmp_path: Path, methods: list[str], payload: bytes) -> Path:
    program = _require_7z_riscv()
    (tmp_path / "code.bin").write_bytes(payload)
    run_7z(
        ["a", "-mhc=off", *methods, "a.7z", "code.bin"],
        cwd=tmp_path,
        check=True,
        program=program,
    )
    return tmp_path / "a.7z"


@pytest.mark.parametrize("start", [0, 0x1002])
def test_7zip_filtered_bytes_match_the_reference(tmp_path: Path, start: int) -> None:
    # With Copy as the codec, the pack stream right after the 32-byte signature
    # header is 7-Zip's RISC-V encoding of the payload, unwrapped.
    riscv = f"-m0=RISCV:{start}" if start else "-m0=RISCV"
    archive = _write_7z(tmp_path, [riscv, "-m1=Copy"], _PAYLOAD)
    stored = archive.read_bytes()[32 : 32 + len(_PAYLOAD)]
    assert stored == _encode(_PAYLOAD, start) != _PAYLOAD
    decoded = riscv_decode(stored, start)
    assert decoded + stored[len(decoded) :] == _PAYLOAD


@pytest.mark.parametrize(
    "methods",
    [
        ["-m0=RISCV", "-m1=Copy"],
        ["-mf=RISCV"],
        ["-m0=RISCV", "-m1=LZMA"],
        ["-m0=RISCV:4098", "-m1=LZMA2"],
        ["-m0=Delta:4", "-m1=RISCV", "-m2=LZMA2"],
        ["-m0=RISCV", "-m1=Delta:4", "-m2=LZMA2"],
        ["-m0=ARM64", "-m1=RISCV", "-m2=LZMA2"],
    ],
    ids=lambda methods: "+".join(m.split("=")[1] for m in methods),
)
def test_7zip_archive_reads(tmp_path: Path, methods: list[str]) -> None:
    archive = _write_7z(tmp_path, methods, _PAYLOAD)
    with open_archive(archive) as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.read() == _PAYLOAD
        with reader.open(member) as stream:
            out = bytearray()
            while piece := stream.read(4093):
                out += piece
            assert bytes(out) == _PAYLOAD
