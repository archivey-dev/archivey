"""The 7z ARM64 branch filter (method ``0x0A``), decoded in Python.

The oracles are 7-Zip itself (archives it writes, and with ``-m1=Copy`` the filtered
bytes it stores) and ``_reference``, a word-by-word port of liblzma's ``arm64_code``
kept deliberately naive so it shares no code with the decoder under test.
"""

from __future__ import annotations

import io
import os
import random
import struct
import subprocess
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import TruncatedError, UnsupportedFeatureError
from archivey.internal.backends import sevenzip_parser, sevenzip_pipeline
from archivey.internal.backends.sevenzip_parser import SevenZipCoder
from archivey.internal.backends.sevenzip_pipeline import plan_folder
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64, arm64_decode
from archivey.internal.streams.codecs.lzma_filter_decoder import (
    FilterStream,
    PythonBranchFilterDecoder,
)
from tests.conftest import requires_binary, sevenzip_lists_arm64

_ARM64 = b"\x0a"
_LZMA2 = b"\x21"
_M32 = 0xFFFFFFFF


def _reference(data: bytes, pc: int, *, encode: bool) -> bytes:
    """liblzma's ``arm64_code``, one word at a time."""
    buf = bytearray(data)
    for i in range(0, len(buf) - 3, 4):
        now = (pc + i) & _M32
        instr = int.from_bytes(buf[i : i + 4], "little")
        if instr >> 26 == 0x25:
            shift = now >> 2 if encode else (-(now >> 2)) & _M32
            instr = 0x94000000 | ((instr + shift) & 0x03FFFFFF)
        elif instr & 0x9F000000 == 0x90000000:
            src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001FFFFC)
            if (src + 0x00020000) & 0x001C0000:
                continue
            shift = now >> 12 if encode else (-(now >> 12)) & _M32
            dest = (src + shift) & _M32
            instr &= 0x9000001F
            instr |= (dest & 3) << 29
            instr |= (dest & 0x0003FFFC) << 3
            instr |= ((-(dest & 0x00020000)) & _M32) & 0x00E00000
        else:
            continue
        buf[i : i + 4] = instr.to_bytes(4, "little")
    return bytes(buf)


def _bl(rng: random.Random) -> int:
    return 0x94000000 | rng.getrandbits(26)


def _adrp(rng: random.Random, *, near: bool) -> int:
    # A 21-bit page immediate. liblzma converts only those within +/-512 MiB (the
    # top four bits all clear or all set); a far one must pass through untouched.
    if near:
        src = rng.getrandbits(17) | (0x1E0000 if rng.random() < 0.5 else 0)
    else:
        src = rng.getrandbits(21) | 0x40000
    return (
        0x90000000
        | ((src & 3) << 29)
        | ((src >> 2) << 5)
        | rng.getrandbits(5)
        | (rng.getrandbits(1) << 31)
    )


def _payload(words: int, *, tail: bytes = b"", seed: int = 1) -> bytes:
    """Words that are mostly BL and ADRP (near and far), the rest random."""
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(words):
        pick = rng.random()
        if pick < 0.3:
            word = _bl(rng)
        elif pick < 0.5:
            word = _adrp(rng, near=True)
        elif pick < 0.6:
            word = _adrp(rng, near=False)
        else:
            word = rng.getrandbits(32)
        out += word.to_bytes(4, "little")
    # Branches on both sides of the 64 KiB read boundary of the filter stream.
    for index, word in ((16383, _bl(rng)), (16384, _adrp(rng, near=True))):
        if index < words:
            out[4 * index : 4 * index + 4] = word.to_bytes(4, "little")
    return bytes(out + tail)


# 40 000 words is 160 KB: three of the stream's 64 KiB reads, with a 3-byte tail.
_PAYLOAD = _payload(40_000, tail=b"\x01\x00\x94")


def test_payload_exercises_both_instruction_kinds() -> None:
    encoded = _reference(_PAYLOAD, 0, encode=True)
    changed = [
        _PAYLOAD[i + 3]
        for i in range(0, len(_PAYLOAD) - 3, 4)
        if _PAYLOAD[i : i + 4] != encoded[i : i + 4]
    ]
    assert sum(1 for top in changed if top & 0xFC == 0x94) > 1000
    assert sum(1 for top in changed if top & 0x9F == 0x90) > 1000
    assert encoded[-3:] == _PAYLOAD[-3:]


@pytest.mark.parametrize("pc", [0, 4, 0x1000, 0x12345678, _M32 - 7])
def test_decode_matches_reference(pc: int) -> None:
    encoded = _reference(_PAYLOAD, pc, encode=True)
    whole = len(_PAYLOAD) & ~3
    decoded = arm64_decode(encoded, pc)
    assert decoded == _reference(encoded, pc, encode=False)[:whole]
    assert decoded == _PAYLOAD[:whole]


@pytest.mark.parametrize("tail_length", [0, 1, 2, 3])
def test_unaligned_tail_is_passed_through(tail_length: int) -> None:
    # A tail whose last byte is a BL opcode byte: it is not a whole word, so it is
    # never converted, whether alone or behind whole words.
    tail = b"\x94\x94\x94"[:tail_length]
    for words in (0, 1, 7):
        data = _payload(words, tail=tail, seed=words)
        encoded = _reference(data, 0, encode=True)
        decoder = PythonBranchFilterDecoder(
            decode=arm64_decode, start_offset=0, unpack_size=len(data)
        )
        out = decoder.feed(encoded).data + decoder.flush().data
        assert out == data
        assert out[len(out) - tail_length :] == tail
        assert decoder.pending_error is None


@pytest.mark.parametrize("piece", [1, 2, 3, 5, 4097, 65537])
@pytest.mark.parametrize("max_length", [-1, 3, 4096])
def test_chunk_boundaries(piece: int, max_length: int) -> None:
    pc = 0x1000
    data = _PAYLOAD[: 3 * 4097 + 2] if piece < 4 else _PAYLOAD
    encoded = _reference(data, pc, encode=True)
    decoder = PythonBranchFilterDecoder(
        decode=arm64_decode, start_offset=pc, unpack_size=len(data)
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
    encoded = _reference(_PAYLOAD, 0, encode=True)
    stream = FilterStream(
        io.BytesIO(encoded),
        lzma_filter={"id": FILTER_ARM64},
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
    encoded = _reference(_PAYLOAD[:4096], 0, encode=True)
    stream = FilterStream(
        io.BytesIO(encoded[:-5]), lzma_filter={"id": FILTER_ARM64}, unpack_size=4096
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


def test_arm64_after_lzma2_is_its_own_stage() -> None:
    # Python's lzma refuses filter id 10 in a raw chain, so it never joins one.
    lzma2 = SevenZipCoder(_LZMA2, 1, 1, b"\x10")
    arm64 = SevenZipCoder(_ARM64, 1, 1, (0x2000).to_bytes(4, "little"))
    chain, stage = plan_folder(_folder([lzma2, arm64], 64)).stages
    assert isinstance(chain, sevenzip_pipeline._LzmaChainStage)
    assert [f["id"] for f in chain.filters] == [0x21]
    assert chain.end_check_size == 64
    assert isinstance(stage, sevenzip_pipeline._FilterStage)
    assert stage.lzma_filter == {"id": FILTER_ARM64, "start_offset": 0x2000}


def test_misaligned_arm64_start_offset_is_refused_at_plan_time() -> None:
    # 7-Zip refuses it too (E_NOTIMPL): the filter works on 4-byte words.
    arm64 = SevenZipCoder(_ARM64, 1, 1, (2).to_bytes(4, "little"))
    with pytest.raises(UnsupportedFeatureError, match="start offset 2 .*multiple of 4"):
        plan_folder(_folder([arm64], 16))


# --- 7-Zip as the oracle ----------------------------------------------------------------


def _require_7z_arm64() -> None:
    if not sevenzip_lists_arm64():
        pytest.skip("this 7z cannot write the ARM64 filter (7-Zip 23 or later can)")


def _write_7z(tmp_path: Path, methods: list[str], payload: bytes) -> Path:
    _require_7z_arm64()
    (tmp_path / "code.bin").write_bytes(payload)
    subprocess.run(
        ["7z", "a", "-mhc=off", *methods, "a.7z", "code.bin"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return tmp_path / "a.7z"


@requires_binary("7z")
@pytest.mark.parametrize("start", [0, 0x1000])
def test_7zip_filtered_bytes_match_the_reference(tmp_path: Path, start: int) -> None:
    # With Copy as the codec, the pack stream right after the 32-byte signature
    # header is 7-Zip's ARM64 encoding of the payload, unwrapped.
    arm64 = f"-m0=ARM64:{start}" if start else "-m0=ARM64"
    archive = _write_7z(tmp_path, [arm64, "-m1=Copy"], _PAYLOAD)
    stored = archive.read_bytes()[32 : 32 + len(_PAYLOAD)]
    assert stored == _reference(_PAYLOAD, start, encode=True) != _PAYLOAD
    assert arm64_decode(stored, start) == _PAYLOAD[: len(_PAYLOAD) & ~3]


@requires_binary("7z")
@pytest.mark.parametrize(
    "methods",
    [
        ["-m0=ARM64", "-m1=Copy"],
        ["-mf=ARM64"],
        ["-m0=ARM64", "-m1=LZMA"],
        ["-m0=ARM64:4096", "-m1=LZMA2"],
        ["-m0=ARM64:4096", "-m1=LZMA"],
        ["-m0=Delta:4", "-m1=ARM64", "-m2=LZMA2"],
        ["-m0=ARM64", "-m1=Delta:4", "-m2=LZMA2"],
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


def _arm64_elf(size: int) -> bytes:
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack(
        "<HHIQQQIHHHHHH", 2, 183, 1, 0x400000, 64, 0, 0, 64, 56, 0, 64, 0, 0
    )
    return header + os.urandom(size // 2) + bytes(size - size // 2)


@requires_binary("7z")
@pytest.mark.parametrize("explicit", [True, False], ids=["mf-arm64", "default"])
def test_7zip_picks_arm64_for_an_aarch64_executable(
    tmp_path: Path, explicit: bool
) -> None:
    # 7-Zip 23.01 picks ARM64 by itself for an AArch64 ELF with the execute bit
    # (``Method = ARM64 LZMA2``), as it picks BCJ for x86.
    payload = _arm64_elf(40_000)
    exe = tmp_path / "armexe"
    exe.write_bytes(payload)
    exe.chmod(0o755)
    _require_7z_arm64()
    subprocess.run(
        ["7z", "a", *(["-mf=ARM64"] if explicit else []), "a.7z", "armexe"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    listing = subprocess.run(
        ["7z", "l", "-slt", "a.7z"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    if "ARM64" not in listing:
        pytest.skip("this 7z did not write the ARM64 filter")
    with open_archive(tmp_path / "a.7z") as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.read() == payload
