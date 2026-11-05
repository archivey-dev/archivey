"""Random access inside a gzip member without ``rapidgzip``: zlib snapshot points.

On declared seek demand the standard-library engine records ``decompressobj.copy()``
about every MiB of output (``GzipDecoder``, ``ZlibSnapshot``), so a backward seek
decodes from the nearest snapshot instead of from the start of the member.
"""

from __future__ import annotations

import functools
import gzip
import io
import itertools
import random
import struct
from typing import Any

import pytest

from archivey.exceptions import CorruptionError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import decompressor_stream
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.deflate_decoder import (
    SNAPSHOT_SPACING,
    ZlibSnapshot,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream


@functools.cache
def _payload() -> bytes:
    """About 6 MiB of text-like data: compressible, so a member spans many feeds."""
    rng = random.Random(5)
    words = [rng.randbytes(rng.randrange(2, 9)).hex().encode() for _ in range(4000)]
    return b" ".join(rng.choice(words) for _ in range(500_000))[: 6 << 20]


def _open(data: bytes, *, seekable: bool = True) -> Any:
    config = StreamConfig(seekable=seekable, use_rapidgzip=AcceleratorMode.OFF)
    return open_codec_stream(Codec.GZIP, io.BytesIO(data), config=config)


def _engine(stream: Any) -> DecompressorStream:
    inner = stream
    while not isinstance(inner, DecompressorStream):
        inner = inner._inner
    return inner


def _snapshots(stream: Any) -> list[int]:
    return [
        p.decompressed_offset
        for p in _engine(stream)._seek_points
        if isinstance(p.state, ZlibSnapshot)
    ]


def test_a_forward_read_records_snapshots_and_seeks_resume_from_them() -> None:
    payload = _payload()
    with _open(gzip.compress(payload, 6)) as stream:
        assert stream.read() == payload
        offsets = _snapshots(stream)
        assert len(offsets) >= len(payload) // SNAPSHOT_SPACING - 1
        assert all(b - a >= SNAPSHOT_SPACING for a, b in itertools.pairwise(offsets))
        for target in (5_000_000, 1_234_567, 3_000_001, 10):
            stream.seek(target)
            assert stream.read(70_000) == payload[target : target + 70_000]
        stream.seek(5_000_000)
        engine = _engine(stream)
        stream.read(1)
        # The decode now runs from the nearest snapshot, not from the start.
        assert engine._find_best_seek_point(5_000_000).decompressed_offset > 4_000_000


def test_a_decode_resumed_from_a_snapshot_still_checks_the_trailer() -> None:
    payload = _payload()
    data = bytearray(gzip.compress(payload, 6))
    crc = struct.unpack_from("<I", data, len(data) - 8)[0]
    struct.pack_into("<I", data, len(data) - 8, crc ^ 1)
    with _open(bytes(data)) as stream:
        assert stream.read(4 << 20) == payload[: 4 << 20]
        assert _snapshots(stream)
        stream.seek(3 << 20)
        with pytest.raises(CorruptionError):
            stream.read()


def test_without_declared_seeking_no_snapshot_is_taken() -> None:
    payload = _payload()
    with _open(gzip.compress(payload, 6), seekable=False) as stream:
        assert stream.read() == payload
        assert _snapshots(stream) == []


def test_a_second_pass_adds_no_snapshot_beside_the_first_ones() -> None:
    payload = _payload()
    with _open(gzip.compress(payload, 6)) as stream:
        stream.read()
        first = _snapshots(stream)
        stream.seek(first[1] + 300_000)
        assert stream.read() == payload[first[1] + 300_000 :]
        points = _snapshots(stream)
        gap = SNAPSHOT_SPACING // 2
        assert all(b - a >= gap for a, b in itertools.pairwise(points))


def test_snapshots_past_the_memory_cap_are_thinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    held = ZlibSnapshot(None).held_bytes
    monkeypatch.setattr(decompressor_stream, "MAX_SNAPSHOT_BYTES", 2 * held)
    payload = _payload()
    data = gzip.compress(payload, 6)
    with _open(data) as stream:
        assert stream.read() == payload
        offsets = _snapshots(stream)
        assert 1 <= len(offsets) <= 2
        engine = _engine(stream)
        assert engine._snapshot_bytes == len(offsets) * held
        assert engine._snapshot_spacing > SNAPSHOT_SPACING
        for target in (5_500_000, 100):
            stream.seek(target)
            assert stream.read(1000) == payload[target : target + 1000]
