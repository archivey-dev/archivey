"""The package's LZO1X decoder, on streams written by liblzo and on damaged ones."""

from __future__ import annotations

import random

import pytest
from archivey_squashfs.lzo import LzoError, decompress_python

# Each written by python-lzo (liblzo2 2.10): ``lzo.compress(data, level, False)``.
_END = b"\x11\x00\x00"


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
