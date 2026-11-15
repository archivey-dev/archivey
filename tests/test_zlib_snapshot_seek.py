"""Random access inside DEFLATE data without ``rapidgzip``: zlib snapshot points.

On declared seek demand the standard-library engine records ``decompressobj.copy()``
about every MiB of output (``GzipDecoder``, ``ZlibDecoder``, ``ZlibSnapshot``), so a
backward seek decodes from the nearest snapshot instead of from the start of the gzip
member, zlib stream or raw DEFLATE stream.
"""

from __future__ import annotations

import functools
import gzip
import io
import itertools
import random
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.exceptions import CorruptionError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import decompressor_stream
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.deflate_decoder import (
    SNAPSHOT_SPACING,
    GzipDecoder,
    ZlibDecoder,
    ZlibSnapshot,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream, SeekPoint
from archivey.internal.streams.native_memory import ZLIB_COPY_LEAKS

# Where ``copy()`` leaks (PyPy), no snapshot is taken; the last test here pins that.
_SNAPSHOTS = pytest.mark.skipif(
    ZLIB_COPY_LEAKS, reason="no zlib snapshots where copy() leaks (PyPy)"
)


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


@_SNAPSHOTS
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


@_SNAPSHOTS
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


@_SNAPSHOTS
def test_without_declared_seeking_no_snapshot_is_taken() -> None:
    payload = _payload()
    with _open(gzip.compress(payload, 6), seekable=False) as stream:
        assert stream.read() == payload
        assert _snapshots(stream) == []


@_SNAPSHOTS
def test_a_second_pass_adds_no_snapshot_beside_the_first_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fails with ``ZlibSnapshot.min_gap`` 0: the second pass resumes at the second
    member's start, whose compressed offset is not a multiple of the read size, so its
    feeds start elsewhere than the first pass's and its snapshots land beside theirs."""
    payload = _payload()
    cut = 3 << 20
    first_member = gzip.compress(payload[:cut], 6)
    assert len(first_member) % (64 << 10)
    data = first_member + gzip.compress(payload[cut:], 6)
    offered: list[int] = []
    real_add = DecompressorStream.add_seek_points

    def spy(self: DecompressorStream, points: list[SeekPoint]) -> None:
        offered.extend(
            p.decompressed_offset for p in points if isinstance(p.state, ZlibSnapshot)
        )
        real_add(self, points)

    monkeypatch.setattr(DecompressorStream, "add_seek_points", spy)
    with _open(data) as stream:
        assert stream.read() == payload
        first = _snapshots(stream)
        offered.clear()
        stream.seek(cut + 10)
        assert stream.read() == payload[cut + 10 :]
        points = _snapshots(stream)
    assert set(offered) - set(points), "the second pass dropped no snapshot"
    assert set(first) <= set(points)
    gap = SNAPSHOT_SPACING // 2
    assert all(b - a >= gap for a, b in itertools.pairwise(points))


@_SNAPSHOTS
def test_snapshots_keep_their_spacing_on_data_that_compresses_well() -> None:
    """One 64 KiB read of zeros decodes to far more than a feed's 1 MiB of output, so
    snapshots are taken on the feeds that go on with the input left over."""
    payload = bytes(24 << 20)
    with _open(gzip.compress(payload, 6)) as stream:
        while stream.read(1 << 20):
            pass
        offsets = _snapshots(stream)
        assert len(offsets) >= len(payload) // SNAPSHOT_SPACING - 1
        stream.seek(20 << 20)
        assert stream.read(1000) == bytes(1000)


@_SNAPSHOTS
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


def _open_codec(codec: Codec, data: bytes) -> Any:
    config = StreamConfig(seekable=True, use_rapidgzip=AcceleratorMode.OFF)
    return open_codec_stream(codec, io.BytesIO(data), config=config)


@_SNAPSHOTS
@pytest.mark.parametrize(
    ("codec", "wbits"), [(Codec.ZLIB, zlib.MAX_WBITS), (Codec.DEFLATE, -15)]
)
def test_zlib_and_raw_deflate_seek_from_snapshots(codec: Codec, wbits: int) -> None:
    payload = _payload()
    packer = zlib.compressobj(6, zlib.DEFLATED, wbits)
    data = packer.compress(payload) + packer.flush()
    with _open_codec(codec, data) as stream:
        while stream.read(1 << 20):
            pass
        offsets = _snapshots(stream)
        assert len(offsets) >= len(payload) // SNAPSHOT_SPACING - 1
        for target in (5_000_000, 1_234_567, 10):
            stream.seek(target)
            assert stream.read(70_000) == payload[target : target + 70_000]
        assert _engine(stream)._find_best_seek_point(5_000_000).decompressed_offset > (
            4_000_000
        )


@_SNAPSHOTS
def test_a_zlib_decode_resumed_from_a_snapshot_still_checks_the_adler() -> None:
    payload = _payload()
    data = bytearray(zlib.compress(payload, 6))
    data[-1] ^= 1
    with _open_codec(Codec.ZLIB, bytes(data)) as stream:
        while len(stream.read(1 << 20)) and stream.tell() < 4 << 20:
            pass
        assert _snapshots(stream)
        stream.seek(3 << 20)
        with pytest.raises(CorruptionError):
            stream.read()


@_SNAPSHOTS
def test_a_zip_member_seeks_from_snapshots(tmp_path: Path) -> None:
    payload = _payload()
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", payload)
    config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF)
    with (
        open_archive(path, seekable_members=True, config=config) as archive,
        archive.open("a.txt") as member,
    ):
        while member.read(1 << 20):
            pass
        assert _snapshots(member)
        member.seek(4_000_000)
        assert member.read(1000) == payload[4_000_000:4_001_000]


def _compressed(wbits: int) -> bytes:
    packer = zlib.compressobj(6, zlib.DEFLATED, wbits)
    return packer.compress(_payload()) + packer.flush()


@_SNAPSHOTS
@pytest.mark.parametrize(
    ("make", "wbits"),
    [
        (lambda: GzipDecoder(index=True), 31),
        (lambda: ZlibDecoder(zlib.MAX_WBITS, index=True), zlib.MAX_WBITS),
        (lambda: ZlibDecoder(-15, index=True), -15),
    ],
    ids=["gzip", "zlib", "deflate"],
)
def test_every_snapshot_resumes_at_its_own_offsets(make: Any, wbits: int) -> None:
    """Fails when a snapshot's compressed offset counts the chunk its feed brings (the
    ``_fed_end`` update moved above the snapshot). Unbounded feeds of fixed chunks put
    every snapshot on a feed with new input, which the stream's bounded reads do not."""
    payload = _payload()
    data = _compressed(wbits)
    decoder = make()
    points = []
    for at in range(0, len(data), 64 << 10):
        points += decoder.feed(data[at : at + (64 << 10)]).points
    snapshots = [p for p in points if isinstance(p.state, ZlibSnapshot)]
    assert len(snapshots) >= 2
    for point in snapshots:
        resumed = decoder.recreate(point, io.BytesIO())
        out = resumed.feed(data[point.compressed_offset :]).data
        start = point.decompressed_offset
        assert out[:100_000] == payload[start : start + 100_000]


@_SNAPSHOTS
def test_snapshots_a_resumed_decode_records_are_at_their_true_offsets() -> None:
    """Fails when a decoder resumed from a snapshot counts its output from 0: the points
    it records past the first pass's end then carry wrong output offsets."""
    payload = _payload()
    with _open_codec(Codec.ZLIB, _compressed(zlib.MAX_WBITS)) as stream:
        while stream.tell() < 2_500_000:
            stream.read(1 << 20)
        first = _snapshots(stream)
        stream.seek(first[0] + 10)
        while stream.read(1 << 20):
            pass
        later = [p for p in _snapshots(stream) if p > 3_500_000]
        assert later
        for target in later:
            stream.seek(target + 1000)
            assert stream.read(5000) == payload[target + 1000 : target + 6000]


@pytest.mark.parametrize(
    ("codec", "wbits"),
    [(Codec.GZIP, 31), (Codec.ZLIB, zlib.MAX_WBITS), (Codec.DEFLATE, -15)],
    ids=["gzip", "zlib", "deflate"],
)
def test_where_copies_leak_no_snapshot_is_taken_and_seeks_still_land(
    codec: Codec, wbits: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where ``copy()`` leaks (PyPy; patched in here, so every interpreter runs it),
    a gzip, zlib or raw DEFLATE read on seek demand records no snapshot, and a
    backward seek decodes from the start of the stream instead, to the same bytes."""
    from archivey.internal.streams.codecs import deflate_decoder

    monkeypatch.setattr(deflate_decoder, "ZLIB_COPY_LEAKS", True)
    payload = _payload()
    packer = zlib.compressobj(6, zlib.DEFLATED, wbits)
    with _open_codec(codec, packer.compress(payload) + packer.flush()) as stream:
        assert stream.read() == payload
        assert _snapshots(stream) == []
        target = len(payload) - (2 << 20)
        assert stream.seek(target) == target
        assert stream.read(4096) == payload[target : target + 4096]
