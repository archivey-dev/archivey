"""Random access in bzip3: every block is a seek point, and the block headers are an index.

``seekable-decompressor-streams`` §"bzip3 uses its blocks". Each block decodes on its own
and its header gives its compressed and decoded size, so a forward read records each
block's start, and on a source that can seek the headers are walked without decoding.
The walk is trusted like the xz and lzip indexes (threat-model O17).
"""

from __future__ import annotations

import functools
import io
import random
import struct
from typing import Any

import pytest

from archivey import ProcessIsolation
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.config import StreamConfig
from archivey.internal.streams.codecs import Codec, bzip3_codec, open_codec_stream
from archivey.internal.streams.decompressor_stream import DecompressorStream, SeekPoint
from tests.conftest import requires

pytestmark = requires("bz3")

BLOCK = 65 << 10
# Six blocks of hard-to-compress bytes, so each block is about its own size.
DATA = random.Random(3).randbytes(BLOCK * 5 + 1000)
STARTS = list(range(0, len(DATA), BLOCK))


def _bz3(data: bytes = DATA, block_size: int = BLOCK) -> bytes:
    from bz3.backends import BZ3Compressor

    compressor = BZ3Compressor(block_size)
    return compressor.compress(data) + compressor.flush()


@functools.cache
def _raw() -> bytes:
    """The six-block file, built on first use: the core-only legs lack ``bz3``."""
    return _bz3()


def _block_offsets(raw: bytes) -> list[int]:
    out, pos = [], 9
    while pos < len(raw):
        out.append(pos)
        pos += 8 + struct.unpack_from("<i", raw, pos)[0]
    return out


def _open(
    source: Any,
    *,
    seekable: bool = True,
    isolation: ProcessIsolation = ProcessIsolation.NONE,
) -> Any:
    config = StreamConfig(seekable=seekable, process_isolation=isolation)
    return open_codec_stream(Codec.BZIP3, source, config=config)


def _engine(stream: Any) -> DecompressorStream:
    inner = stream
    while not isinstance(inner, DecompressorStream):
        inner = inner._inner
    return inner


def _points(stream: Any) -> list[int]:
    return [p.decompressed_offset for p in _engine(stream)._seek_points]


@pytest.fixture
def decoded_blocks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """How many bytes each block decode produced, in order."""
    seen: list[int] = []
    original = bzip3_codec.Bzip3Decompressor._decode_block

    def counting(self: Any, compressed: int, decoded: int) -> None:
        seen.append(decoded)
        original(self, compressed, decoded)

    monkeypatch.setattr(bzip3_codec.Bzip3Decompressor, "_decode_block", counting)
    return seen


def test_the_file_has_several_blocks() -> None:
    assert len(_block_offsets(_raw())) == len(STARTS)


def test_the_walk_gives_the_size_and_every_block_without_decoding(
    decoded_blocks: list[int],
) -> None:
    with _open(io.BytesIO(_raw())) as stream:
        assert stream.seek(0, io.SEEK_END) == len(DATA)
        assert decoded_blocks == []
        assert _points(stream) == STARTS


@pytest.mark.parametrize("isolation", list(ProcessIsolation), ids=lambda i: i.name)
def test_a_seek_decodes_only_the_block_it_lands_in(
    isolation: ProcessIsolation, decoded_blocks: list[int]
) -> None:
    with _open(io.BytesIO(_raw()), isolation=isolation) as stream:
        for pos in (STARTS[4] + 7, STARTS[1] + 3, len(DATA) - 5, STARTS[2]):
            del decoded_blocks[:]
            assert stream.seek(pos) == pos
            assert stream.read(5) == DATA[pos : pos + 5]
            # The count is taken in this process only.
            if isolation is ProcessIsolation.NONE:
                assert len(decoded_blocks) == 1


def test_a_forward_read_records_each_block() -> None:
    with _open(io.BytesIO(_raw())) as stream:
        assert stream.read() == DATA
        assert _points(stream) == STARTS


def test_a_backward_seek_after_a_read_resumes_at_its_block(
    decoded_blocks: list[int],
) -> None:
    with _open(io.BytesIO(_raw())) as stream:
        assert stream.read() == DATA
        del decoded_blocks[:]
        assert _engine(stream).nearest_resume_offset(STARTS[2] + 9) == STARTS[2]
        stream.seek(STARTS[2] + 9)
        assert stream.read(100) == DATA[STARTS[2] + 9 : STARTS[2] + 109]
        assert len(decoded_blocks) == 1


def test_undeclared_seek_demand_keeps_no_points() -> None:
    with _open(io.BytesIO(_raw()), seekable=False) as stream:
        assert stream.read() == DATA
        assert _points(stream) == [0]


def test_a_file_of_one_block_has_no_point_but_the_start() -> None:
    raw = _bz3(b"abc" * 100)
    with _open(io.BytesIO(raw)) as stream:
        assert stream.seek(0, io.SEEK_END) == 300
        assert _points(stream) == [0]
        stream.seek(150)
        assert stream.read() == (b"abc" * 100)[150:]


def test_an_empty_file_has_size_zero() -> None:
    raw = _bz3(b"")
    with _open(io.BytesIO(raw)) as stream:
        assert stream.seek(0, io.SEEK_END) == 0
        assert stream.read() == b""


def test_a_file_cut_inside_a_block_has_no_size_and_raises_at_the_cut() -> None:
    last = _block_offsets(_raw())[-1]
    raw = _raw()[: last + 20]
    with _open(io.BytesIO(raw)) as stream:
        assert _engine(stream).try_get_size() is None
        # The blocks before the cut are still points.
        stream.seek(STARTS[3] + 1)
        assert stream.read(10) == DATA[STARTS[3] + 1 : STARTS[3] + 11]
        with pytest.raises(TruncatedError):
            stream.seek(STARTS[5] + 1)
            stream.read(10)


def test_bytes_after_the_last_block_end_the_walk_and_fail_the_decode() -> None:
    with _open(io.BytesIO(_raw() + b"junk!!!!!!")) as stream:
        assert _engine(stream).try_get_size() is None
        stream.seek(STARTS[4])
        assert stream.read(BLOCK) == DATA[STARTS[4] : STARTS[5]]
        with pytest.raises(CorruptionError):
            stream.read()


def test_the_walk_stops_at_a_header_the_decoder_would_refuse() -> None:
    offsets = _block_offsets(_raw())
    raw = bytearray(_raw())
    struct.pack_into("<i", raw, offsets[3] + 4, BLOCK + 1)
    points, size = bzip3_codec.build_bzip3_index(io.BytesIO(raw), SeekPoint(0, 0), None)
    assert [p.decompressed_offset for p in points] == STARTS[1:3]
    assert size is None


def test_the_walk_lists_only_points_after_the_last_known_one() -> None:
    points, size = bzip3_codec.build_bzip3_index(
        io.BytesIO(_raw()), SeekPoint(STARTS[3], 0), None
    )
    assert [p.decompressed_offset for p in points] == STARTS[4:]
    assert [p.compressed_offset for p in points] == _block_offsets(_raw())[4:]
    assert all(p.state == BLOCK for p in points)
    assert size == len(DATA)


@pytest.mark.parametrize(
    "raw", [b"", b"BZ3v", b"BZ2v1\x00\x00\x01\x00", b"BZ3v1\x00\x00\x00\x00"]
)
def test_the_walk_finds_nothing_without_a_valid_header(raw: bytes) -> None:
    assert bzip3_codec.build_bzip3_index(io.BytesIO(raw), SeekPoint(0, 0), None) == (
        [],
        None,
    )
