"""archivey's LZO1X decoder in Python, on streams written by liblzo and on damaged
ones, among them the metadata blocks of the SquashFS test images."""

from __future__ import annotations

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
        (b"\x15abcd\x12\x00\x00", "damaged end marker"),
    ],
)
def test_damage_raises(stream: bytes, match: str) -> None:
    with pytest.raises(LzoError, match=match):
        decompress_python(stream, 1 << 16)


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
