"""Members of a compressed TAR rise to ``CHECKSUM`` as soon as the block checks of
the codec cover their data (``checked_spans``), not only when a walk reaches the
stream's end.

Spec ``compressed-streams`` §"A stream reports the verification it has reached and can
reach" (the `.tar.bz2` and `.tar.xz` rows).
"""

from __future__ import annotations

import bz2
import functools
import gzip
import io
import lzma
import random
import struct
import subprocess
import tarfile
import zlib

import pytest

import archivey
from archivey import Verification
from archivey.exceptions import CorruptionError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import checked_spans
from archivey.internal.streams.checked_spans import CheckedSpans
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.decompressor_stream import DecompressorStream
from tests.conftest import requires, requires_binary
from tests.streams_util import NonSeekableBytesIO


def test_spans_merge_where_they_touch_or_overlap() -> None:
    spans = CheckedSpans()
    spans.watch()
    spans.add(10, 20)
    spans.add(30, 40)
    assert spans.covers(10, 20)
    assert not spans.covers(10, 30)
    spans.add(20, 30)
    assert spans.covers(10, 40)
    spans.add(5, 12)
    assert spans.covers(5, 40)
    assert not spans.covers(4, 6)
    spans.add(7, 7)  # empty: nothing
    assert spans.take_new() == [(10, 20), (30, 40), (20, 30), (5, 12)]
    assert spans.take_new() == []


def test_new_ranges_that_follow_each_other_are_one_range() -> None:
    spans = CheckedSpans()
    spans.watch()
    spans.add(0, 5)
    spans.add(5, 9)
    assert spans.take_new() == [(0, 9)]


def test_past_the_span_limit_the_first_span_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(checked_spans, "MAX_SPANS", 2)
    spans = CheckedSpans()
    for start in (0, 10, 20):
        spans.add(start, start + 5)
    assert not spans.covers(0, 5)
    assert spans.covers(10, 15)
    assert spans.covers(20, 25)


_COUNT = 30


def test_unwatched_spans_log_no_new_ranges() -> None:
    spans = CheckedSpans()
    for start in range(0, 100, 10):
        spans.add(start, start + 5)
    assert spans.covers(20, 25)
    spans.watch()
    assert spans.take_new() == []


def test_the_new_range_log_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checked_spans, "MAX_SPANS", 3)
    spans = CheckedSpans()
    spans.watch()
    for start in range(0, 100, 10):
        spans.add(start, start + 5)
    assert spans.take_new() == [(70, 75), (80, 85), (90, 95)]


@requires("bz3")
def test_bytes_decoded_from_an_index_point_are_not_checked_spans() -> None:
    """A seek to a point the file's own block headers named counts nothing: its
    offsets are the index's. A decode from the start, past the same blocks, does."""
    block = 65 << 10
    data = random.Random(3).randbytes(block * 4)
    with open_codec_stream(
        Codec.BZIP3, io.BytesIO(_bz3(data)), config=StreamConfig(seekable=True)
    ) as stream:
        engine = stream
        while not isinstance(engine, DecompressorStream):
            engine = engine._inner
        spans = engine.checked_spans
        assert stream.seek(0, io.SEEK_END) == len(data)  # the index walk
        stream.seek(2 * block)
        assert stream.read(block) == data[2 * block : 3 * block]
        assert not spans.covers(2 * block, 2 * block + 1)
        stream.seek(0)
        assert stream.read(block) == data[:block]
        assert spans.covers(0, block)


def _members(count: int = _COUNT) -> list[tuple[str, bytes]]:
    rng = random.Random(1)
    return [
        (
            f"f{i}",
            bytes(rng.choice(b"abcdefgh ") for _ in range(rng.randint(1000, 60000))),
        )
        for i in range(count)
    ]


@functools.cache
def _tar() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in _members():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def _bz3(data: bytes) -> bytes:
    from bz3.backends import BZ3Compressor

    compressor = BZ3Compressor(65 << 10)
    return compressor.compress(data) + compressor.flush()


def _levels_while_streaming(
    blob: bytes, source: object = None, config: object = None
) -> dict[str, Verification]:
    """Each file's level when the walk hands out the last member, before it reaches
    the stream's end."""
    files: list[archivey.ArchiveMember] = []
    levels: dict[str, Verification] = {}
    source = NonSeekableBytesIO(blob) if source is None else source
    with archivey.open_archive(source, streaming=True, config=config) as archive:
        for member, stream in archive.stream_members():
            if member.is_file:
                files.append(member)
            if member.name == f"f{_COUNT - 1}":
                levels = {m.name: m.verified for m in files}
            if stream is not None:
                stream.read()
    return levels


@pytest.mark.parametrize(
    "compress",
    [
        pytest.param(lambda data: bz2.compress(data, 1), id="bzip2"),
        pytest.param(_bz3, id="bzip3", marks=requires("bz3")),
    ],
)
def test_a_member_is_checksum_verified_once_its_blocks_pass(compress) -> None:
    levels = _levels_while_streaming(compress(_tar()))
    # The last member is still being walked, and its data may end in the stream's
    # last block. Every earlier one, small members listed after the check of their
    # block passed among them, is in checked blocks.
    names = [name for name, _ in _members()]
    early = {name: levels[name] for name in names[:-1]}
    assert set(early.values()) == {Verification.CHECKSUM}, early


def _xz_blocks(data: bytes, *options: str) -> bytes:
    """``data`` as one xz stream of 50 KiB blocks."""
    return subprocess.run(
        ["xz", "-c", "-1", "--block-size=50KiB", *options],
        input=data,
        capture_output=True,
        check=True,
    ).stdout


def _xz_streams(data: bytes) -> bytes:
    """``data`` as xz streams of 100 kB each, one block each."""
    step = 100_000
    return b"".join(
        lzma.compress(data[i : i + step], preset=1) for i in range(0, len(data), step)
    )


@pytest.mark.parametrize(
    "compress",
    [
        pytest.param(_xz_blocks, id="xz-blocks", marks=requires_binary("xz")),
        pytest.param(_xz_streams, id="xz-streams"),
    ],
)
def test_an_xz_member_is_checksum_verified_once_its_blocks_pass(compress) -> None:
    levels = _levels_while_streaming(compress(_tar()))
    names = [name for name, _ in _members()]
    # A block is checked once the decode is past its end, so the files in the last
    # block wait for the end of the stream.
    early = {name: levels[name] for name in names[:-5]}
    assert set(early.values()) == {Verification.CHECKSUM}, early


@pytest.mark.parametrize(
    "blob",
    [
        pytest.param(lambda: gzip.compress(_tar()), id="gzip"),
        pytest.param(lambda: lzma.compress(_tar(), preset=1), id="xz-one-block"),
        pytest.param(
            lambda: _xz_blocks(_tar(), "-C", "none"),
            id="xz-no-check",
            marks=requires_binary("xz"),
        ),
    ],
)
def test_without_block_checks_nothing_rises_before_the_end(blob) -> None:
    levels = _levels_while_streaming(blob())
    assert Verification.CHECKSUM not in set(levels.values())


@pytest.mark.parametrize(
    "compress",
    [
        pytest.param(lambda data: bz2.compress(data, 1), id="bzip2"),
        pytest.param(_xz_blocks, id="xz-blocks", marks=requires_binary("xz")),
    ],
)
def test_the_members_before_a_damaged_block_are_checksum_verified(compress) -> None:
    blob = bytearray(compress(_tar()))
    blob[len(blob) * 3 // 4] ^= 0x55
    seen: list[archivey.ArchiveMember] = []
    source = NonSeekableBytesIO(bytes(blob))
    with (
        pytest.raises(CorruptionError),
        archivey.open_archive(source, streaming=True) as archive,
    ):
        for member, stream in archive.stream_members():
            seen.append(member)
            if stream is not None:
                stream.read()
    files = [m for m in seen if m.is_file]
    # The first blocks hold well over the first member.
    assert files[0].verified is Verification.CHECKSUM
    assert files[-1].verified is not Verification.CHECKSUM


def test_listing_then_random_access_keeps_checksum() -> None:
    blob = bz2.compress(_tar(), 1)
    with archivey.open_archive(io.BytesIO(blob)) as archive:
        members = [m for m in archive.members() if m.is_file]
        assert {m.verified for m in members} == {Verification.CHECKSUM}
        with archive.open(members[10]) as stream:
            assert stream.read() == dict(_members())["f10"]
        assert members[10].verified is Verification.CHECKSUM


@requires("rapidgzip")
def test_bzip2_the_accelerator_decodes_raises_only_at_the_end(tmp_path) -> None:
    """The accelerator's bytes carry no block checks of archivey's: its files wait
    for the end of the stream, as the docs say."""
    path = tmp_path / "a.tar.bz2"
    path.write_bytes(bz2.compress(_tar(), 1))
    config = archivey.ArchiveyConfig(use_indexed_bzip2=AcceleratorMode.ON)
    levels = _levels_while_streaming(b"", source=path, config=config)
    assert Verification.CHECKSUM not in set(levels.values())


def _mbi(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _tiny_chunk_xz(data: bytes) -> bytes:
    """One xz stream (CRC32 check, one block) storing ``data`` as one-byte LZMA2
    uncompressed chunks: a Python walk step for every four input bytes."""
    flags = b"\x00\x01"  # CRC32
    header = b"\xfd7zXZ\x00" + flags + struct.pack("<I", zlib.crc32(flags))
    # block header: size byte, flags (1 filter), filter LZMA2 id 0x21, props size 1,
    # dict byte Block header: size byte, flags (one filter), LZMA2 (0x21) with its
    # dictionary property, padding, CRC32.
    content = bytes([0x00]) + b"\x21" + b"\x01" + b"\x16"
    raw = b"\x00" + content  # size byte placeholder
    total = len(raw) + 4
    total += -total % 4
    size_byte = total // 4 - 1
    hdr = bytes([size_byte]) + content
    hdr += b"\x00" * (total - 4 - len(hdr))
    hdr += struct.pack("<I", zlib.crc32(hdr))
    chunks = bytearray()
    for i, b in enumerate(data):
        chunks += bytes([1 if i == 0 else 2, 0, 0, b])
    chunks += b"\x00"
    block = hdr + bytes(chunks)
    unpadded = len(block) + 4
    block += b"\x00" * (-len(block) % 4)
    block += struct.pack("<I", zlib.crc32(data))
    index = b"\x00" + _mbi(1) + _mbi(unpadded) + _mbi(len(data))
    index += b"\x00" * (-len(index) % 4)
    index += struct.pack("<I", zlib.crc32(index))
    back = struct.pack("<I", len(index) // 4 - 1)
    footer = struct.pack("<I", zlib.crc32(back + flags)) + back + flags + b"YZ"
    return header + block + index + footer


def test_a_walk_over_tiny_xz_chunks_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stream of one-byte chunks would make the walk for block checks a Python step
    per few input bytes; it stops early, and the decode is unchanged."""
    from archivey.internal.streams.codecs import xz_decoder

    steps = 0
    chunk = xz_decoder._XzBlockWalker._chunk

    def counting(self: object, field: bytes) -> None:
        nonlocal steps
        steps += 1
        chunk(self, field)

    monkeypatch.setattr(xz_decoder._XzBlockWalker, "_chunk", counting)
    data = random.Random(1).randbytes(50_000)
    blob = _tiny_chunk_xz(data)
    assert lzma.decompress(blob) == data
    with open_codec_stream(Codec.XZ, io.BytesIO(blob)) as stream:
        assert stream.read() == data
    assert steps < 1000
