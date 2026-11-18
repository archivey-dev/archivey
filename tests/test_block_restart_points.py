"""Restart points at the blocks of lzop, legacy LZ4 and Snappy, and at further LZ4 frames.

Each of these formats compresses every block on its own, and no checksum covers more
than one block, so a decode can start at any block (``BlockResumable``). With declared
seek demand, a forward read records each block's start, and a seek back resumes at the
block it lands in instead of decoding from the start of the file. Nothing indexes the
blocks without decoding them, so a seek forward still decodes its way there.
"""

from __future__ import annotations

import io
import random
from typing import Any

import pytest

from archivey.exceptions import CorruptionError
from archivey.internal.config import StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.lz4_legacy import LEGACY_MAGIC
from archivey.internal.streams.codecs.snappy_framed import MAX_CHUNK_DATA
from archivey.internal.streams.decompressor_stream import DecompressorStream
from tests.conftest import requires
from tests.lzop_build import make_lzop
from tests.test_snappy_framed import _data_chunk, _frame, stored_frame, written_frame

BLOCK = 3000
DATA = random.Random(7).randbytes(BLOCK * 5 + 123)
STARTS = list(range(0, len(DATA), BLOCK))


def _open(codec: Codec, raw: bytes, *, seekable: bool = True) -> Any:
    return open_codec_stream(
        codec, io.BytesIO(raw), config=StreamConfig(seekable=seekable)
    )


def _engine(stream: Any) -> DecompressorStream:
    inner = stream
    while not isinstance(inner, DecompressorStream):
        inner = inner._inner
    return inner


def _points(stream: Any) -> list[int]:
    return [p.decompressed_offset for p in _engine(stream)._seek_points]


def _lz4_legacy(data: bytes, block_size: int = BLOCK) -> bytes:
    import lz4.block

    out = bytearray(LEGACY_MAGIC)
    for at in range(0, len(data), block_size):
        body = lz4.block.compress(data[at : at + block_size], store_size=False)
        out += len(body).to_bytes(4, "little") + body
    return bytes(out)


def _lz4_frames(data: bytes, frame_size: int = BLOCK) -> bytes:
    import lz4.frame

    return b"".join(
        lz4.frame.compress(data[at : at + frame_size])
        for at in range(0, len(data), frame_size)
    )


def _snappy(data: bytes) -> bytes:
    return written_frame(data)


# Each case: the codec, a file of DATA in blocks of BLOCK bytes, and the marks it needs.
CASES = [
    pytest.param(Codec.LZOP, lambda d: make_lzop(d, block_size=BLOCK), id="lzop"),
    pytest.param(Codec.LZ4, _lz4_legacy, id="lz4-legacy", marks=requires("lz4")),
    pytest.param(Codec.LZ4, _lz4_frames, id="lz4-frames", marks=requires("lz4")),
]


@pytest.mark.parametrize(("codec", "build"), CASES)
def test_a_forward_read_records_each_block(codec: Codec, build: Any) -> None:
    with _open(codec, build(DATA)) as stream:
        assert stream.read() == DATA
        assert _points(stream) == STARTS


@pytest.mark.parametrize(("codec", "build"), CASES)
def test_a_backward_seek_resumes_at_its_block(codec: Codec, build: Any) -> None:
    with _open(codec, build(DATA)) as stream:
        assert stream.read() == DATA
        for pos in (STARTS[4] + 7, STARTS[2] + 9, STARTS[3], 5):
            assert _engine(stream).nearest_resume_offset(pos) == pos - pos % BLOCK
            assert stream.seek(pos) == pos
            assert stream.read(100) == DATA[pos : pos + 100]
        # A read on from a resumed block crosses into the blocks after it.
        stream.seek(STARTS[1] + 10)
        assert stream.read() == DATA[STARTS[1] + 10 :]


@pytest.mark.parametrize(("codec", "build"), CASES)
def test_undeclared_seek_demand_keeps_no_points(codec: Codec, build: Any) -> None:
    with _open(codec, build(DATA), seekable=False) as stream:
        assert stream.read() == DATA
        assert _points(stream) == [0]


def test_lzop_points_go_on_into_a_further_file() -> None:
    raw = make_lzop(DATA, block_size=BLOCK) + make_lzop(DATA, block_size=BLOCK)
    with _open(Codec.LZOP, raw) as stream:
        assert stream.read() == DATA + DATA
        assert _points(stream) == STARTS + [len(DATA) + s for s in STARTS]
        pos = len(DATA) + STARTS[2] + 4
        stream.seek(pos)
        assert stream.read() == (DATA + DATA)[pos:]


def test_lzop_still_checks_the_blocks_after_a_resumed_one() -> None:
    raw = bytearray(make_lzop(DATA, block_size=BLOCK))
    # Stored blocks: each is its two lengths, its Adler-32, then its data.
    header = len(make_lzop(b"")) - 4
    raw[header + 4 * (12 + BLOCK) + 12] ^= 1  # the fifth block's first byte
    with _open(Codec.LZOP, bytes(raw)) as stream:
        assert stream.read(STARTS[4]) == DATA[: STARTS[4]]
        stream.seek(STARTS[2] + 1)
        assert _engine(stream).nearest_resume_offset(stream.tell()) == STARTS[2]
        assert stream.read(10) == DATA[STARTS[2] + 1 : STARTS[2] + 11]
        with pytest.raises(CorruptionError, match="checksum"):
            stream.read()


SNAPPY_DATA = random.Random(8).randbytes(MAX_CHUNK_DATA * 4 + 99)
SNAPPY_STARTS = list(range(0, len(SNAPPY_DATA), MAX_CHUNK_DATA))


@pytest.mark.parametrize("build", [stored_frame, written_frame], ids=["stored", "raw"])
def test_snappy_resumes_at_a_data_chunk(build: Any) -> None:
    with _open(Codec.SNAPPY, build(SNAPPY_DATA)) as stream:
        assert stream.read() == SNAPPY_DATA
        assert _points(stream) == SNAPPY_STARTS
        pos = SNAPPY_STARTS[3] + 11
        assert _engine(stream).nearest_resume_offset(pos) == SNAPPY_STARTS[3]
        stream.seek(pos)
        assert stream.read(64) == SNAPPY_DATA[pos : pos + 64]
        stream.seek(SNAPPY_STARTS[1] + 1)
        assert stream.read() == SNAPPY_DATA[SNAPPY_STARTS[1] + 1 :]


def test_snappy_names_offsets_in_the_file_after_a_resume() -> None:
    raw = bytearray(stored_frame(SNAPPY_DATA))
    chunk = 4 + 4 + MAX_CHUNK_DATA
    # The last chunk's CRC: a decode from the start reads the chunks before it first.
    last = 10 + 4 * chunk
    raw[last + 4] ^= 1
    with _open(Codec.SNAPPY, bytes(raw)) as stream:
        assert stream.read(SNAPPY_STARTS[4]) == SNAPPY_DATA[: SNAPPY_STARTS[4]]
        stream.seek(SNAPPY_STARTS[3] + 5)
        assert _engine(stream).nearest_resume_offset(stream.tell()) == SNAPPY_STARTS[3]
        with pytest.raises(CorruptionError, match=f"chunk at offset {last}"):
            stream.read()


@requires("lz4")
def test_one_lz4_frame_has_no_point_but_the_origin() -> None:
    import lz4.frame

    raw = lz4.frame.compress(DATA, block_size=lz4.frame.BLOCKSIZE_MAX64KB)
    with _open(Codec.LZ4, raw) as stream:
        assert stream.read() == DATA
        assert _points(stream) == [0]
        stream.seek(STARTS[3])
        assert stream.read(10) == DATA[STARTS[3] : STARTS[3] + 10]


def test_an_empty_snappy_chunk_is_no_point() -> None:
    # It would share its output offset with the next chunk, with another state.
    first, last = SNAPPY_DATA[:1000], SNAPPY_DATA[1000:61000]
    raw = _frame(_data_chunk(first), _data_chunk(b""), _data_chunk(last))
    with _open(Codec.SNAPPY, raw) as stream:
        assert stream.read() == first + last
        assert _points(stream) == [0, 1000]
        stream.seek(1500)
        assert stream.read(10) == last[500:510]
