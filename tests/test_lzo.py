"""archivey's LZO1X decoder in Python, on streams written by liblzo and on damaged
ones, among them the metadata blocks of the SquashFS test images, and compress-utils'
decoder against it on the same damaged blocks."""

from __future__ import annotations

import importlib.util
import random
import struct
import tracemalloc
from pathlib import Path

import pytest

from archivey.internal.streams.codecs.lzo_decoder import (
    LzoError,
    lzo1x_decompress_python as decompress_python,
)

# Each written by python-lzo (liblzo2 2.10): ``lzo.compress(data, level, False)``.
_END = b"\x11\x00\x00"
_SQUASHFS_DATA = Path(__file__).parent / "fixtures" / "squashfs"


def test_only_the_end_marker_is_empty() -> None:
    assert decompress_python(_END, 0) == b""


def test_a_first_literal_run() -> None:
    # 17 + 6: six literals, then the end marker.
    assert decompress_python(b"\x17hello\n" + _END, 6) == b"hello\n"


def test_an_overlapping_match_repeats_its_bytes() -> None:
    # "ab", then a match 2 bytes back of 98 bytes: 32 (its length in the next byte),
    # the length - 33, and the distance - 1 shifted left 2.
    stream = b"\x13ab" + bytes([32, 98 - 33]) + ((2 - 1) << 2).to_bytes(2, "little")
    data = b"ab" * 50
    assert decompress_python(stream + _END, len(data)) == data


@pytest.mark.parametrize(
    ("stream", "match"),
    [
        (b"", "ends inside"),
        (b"\x17hel", "passes the end"),
        (b"\x17hello\n", "ends inside"),
        (b"\x17hello\n" + _END + b"x", "1 bytes follow"),
        (b"\x14abc" + bytes([33]) + (100 << 2).to_bytes(2, "little"), "before the"),
    ],
)
def test_damage_raises(stream: bytes, match: str) -> None:
    with pytest.raises(LzoError, match=match):
        decompress_python(stream, 1 << 16)


@pytest.mark.parametrize("marker", [_END, b"\x11\x03\x00"])
def test_the_end_marker_ignores_its_low_bits(marker: bytes) -> None:
    """Writers end a block with 17, 0, 0. The low 2 bits of the distance field are a
    literal count that no decoder reads at the end marker: the kernel's, liblzo2's
    and compress-utils' all end the block there."""
    stream = b"\x17hello\n" + marker
    assert decompress_python(stream, 6) == b"hello\n"
    with pytest.raises(LzoError, match="1 bytes follow"):
        decompress_python(stream + b"x", 6)


@pytest.mark.parametrize(
    ("marker", "length"),
    [
        (b"\x12\x00\x00", 4),
        (b"\x17\x00\x00", 9),
        (b"\x12\x03\x00", 4),
        (b"\x10\x00\x05\x00\x00", 269),
    ],
)
def test_an_end_marker_of_another_length_is_refused(marker: bytes, length: int) -> None:
    """No writer produces these. The kernel's decoder, which reads SquashFS images,
    and compress-utils refuse them; liblzo2, and so ``lzop``, ends the block at any
    length. archivey refuses them whichever decoder runs."""
    stream = b"\x17hello\n" + marker
    with pytest.raises(LzoError, match=f"end marker has a length of {length}, not 3"):
        decompress_python(stream, 6)
    if importlib.util.find_spec("compress_utils") is not None:
        import compress_utils

        with pytest.raises(compress_utils.CompressError):
            compress_utils.decompress(stream, "lzo", expected_size=6)


def test_the_limit_is_kept() -> None:
    with pytest.raises(LzoError, match="more than 5 bytes"):
        decompress_python(b"\x17hello\n" + _END, 5)


def test_matches_liblzo() -> None:
    lzo = pytest.importorskip("lzo")
    rng = random.Random(3)
    for _ in range(40):
        alphabet = rng.choice([b"ab", b"abcdefgh", bytes(range(256))])
        data = bytes(rng.choice(alphabet) for _ in range(rng.randrange(20000)))
        for level in (1, 9):
            stream = lzo.compress(data, level, False)
            assert decompress_python(stream, len(data)) == data


def _metadata_blocks(name: str) -> list[bytes]:
    """The compressed metadata blocks of an LZO image: its inode and directory tables."""
    image = (_SQUASHFS_DATA / name).read_bytes()
    fields = struct.unpack_from("<IIIIIHHHHHHQQQQQQQQ", image)
    inodes, directories = fields[15], fields[16]
    end = min(v for v in fields[13:19] if directories < v != 0xFFFF_FFFF_FFFF_FFFF)
    blocks, pos = [], inodes
    while pos + 2 <= end:
        header = int.from_bytes(image[pos : pos + 2], "little")
        length = header & 0x7FFF
        if not header & 0x8000:
            blocks.append(image[pos + 2 : pos + 2 + length])
        pos += 2 + length
    return blocks


def test_damaged_blocks_raise_only_lzo_error() -> None:
    # Seeded byte flips, cuts and insertions over the blocks mksquashfs wrote: each
    # attempt decodes to at most the limit or raises LzoError, never anything else.
    blocks = _metadata_blocks("lzo.sqfs") + _metadata_blocks("lzo1x-1.sqfs")
    assert len(blocks) >= 4
    rng = random.Random(7)
    for _ in range(600):
        stream = bytearray(rng.choice(blocks))
        for _ in range(rng.randrange(1, 4)):
            kind = rng.randrange(3)
            at = rng.randrange(len(stream) + 1)
            if kind == 0 and at < len(stream):
                stream[at] = rng.randrange(256)
            elif kind == 1:
                del stream[at:]
            else:
                stream[at:at] = bytes([rng.randrange(256)])
        limit = rng.choice([64, 512, 8192])
        try:
            decoded = decompress_python(bytes(stream), limit)
        except LzoError:
            continue
        assert len(decoded) <= limit


def test_compress_utils_agrees_on_damaged_blocks() -> None:
    """Seeded damage to the SquashFS metadata blocks: compress-utils decodes the same
    bytes, or refuses, exactly where the Python decoder does."""
    compress_utils = pytest.importorskip("compress_utils")
    blocks = _metadata_blocks("lzo.sqfs") + _metadata_blocks("lzo1x-1.sqfs")
    rng = random.Random(11)
    accepted = 0
    for _ in range(3000):
        stream = bytearray(rng.choice(blocks))
        at = rng.randrange(len(stream) + 1)
        kind = rng.randrange(4)
        if kind == 0 and at < len(stream):
            stream[at] ^= 1 << rng.randrange(8)
        elif kind == 1:
            del stream[at:]
        elif kind == 2:
            stream[at:at] = bytes([rng.randrange(256)])
        limit = rng.choice([64, 512, 8192])
        try:
            expected: bytes | None = decompress_python(bytes(stream), limit)
        except LzoError:
            expected = None
        try:
            got: bytes | None = compress_utils.decompress(
                bytes(stream), "lzo", expected_size=limit
            )
        except compress_utils.CompressError:
            got = None
        assert got == expected, bytes(stream).hex()
        accepted += expected is not None
    assert accepted > 100


def test_an_over_long_match_is_refused_before_it_is_copied() -> None:
    # Two literals, then a match whose length field is 2000 zero bytes long: it asks
    # for ~510 000 bytes. The limit refuses it before the copy, so the decoder never
    # holds more than the limit (shown to fail with
    # ``if len(out) + length > limit`` removed from ``lzo_decoder.py``).
    stream = (
        b"\x13ab" + b"\x20" + bytes(2000) + b"\x01" + (1 << 2).to_bytes(2, "little")
    )
    tracemalloc.start()
    try:
        with pytest.raises(LzoError, match="more than 4096 bytes"):
            decompress_python(stream + _END, 4096)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 64 * 1024


@pytest.mark.parametrize("match", [False, True])
def test_long_length_extensions_keep_the_limit_and_refuse_a_cut(match: bool) -> None:
    zeros = bytes(1024)
    if match:
        # One literal, then an M3 match at distance one, with an extended length.
        prefix = b"\x12x\x20"
        size = 1 + len(zeros) * 255 + 31 + 1 + 2
        suffix = b"\x00\x00"
        expected = b"x" * size
    else:
        # A literal run: every zero extends its length by 255 bytes.
        prefix = b"\x00"
        size = len(zeros) * 255 + 15 + 1 + 3
        suffix = b"x" * size
        expected = suffix
    stream = prefix + zeros + b"\x01" + suffix + _END
    assert decompress_python(stream, size) == expected
    with pytest.raises(LzoError, match="more than"):
        decompress_python(stream, size - 1)
    with pytest.raises(LzoError, match="ends inside an instruction"):
        decompress_python(prefix + zeros, size)
