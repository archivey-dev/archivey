"""bzip2 one block at a time (``bzip2_blocks``): every byte handed out has passed its
block's CRC, a damaged block gives none of its bytes, and every block checked is a
seek point.

Spec ``compressed-streams`` §"In-house decoders hand back their bytes before an error"
and ``seekable-decompressor-streams`` §"bzip2 uses its blocks".
"""

from __future__ import annotations

import bz2
import functools
import io
import random
from typing import Any

import pytest

from archivey import ProcessIsolation
from archivey.exceptions import CorruptionError, ResourceLimitError, TruncatedError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, bzip2_blocks, open_codec_stream
from archivey.internal.streams.codecs.bzip2_blocks import (
    BLOCK_MAGIC,
    EOS_MAGIC,
    Bzip2BlockDecompressor,
    Bzip2BlockStart,
    find_markers,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream
from archivey.internal.streams.resume import ResumeReachedStreamEnd
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO


def _text(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    words = [
        bytes(rng.choice(b"abcdefghijklmnop") for _ in range(rng.randint(2, 9)))
        for _ in range(3000)
    ]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + b" "
    return bytes(out[:size])


# Level 1: 100 kB blocks, so 700 kB of text is at least seven blocks, at several bit
# offsets.
DATA = _text(700_000, 3)


@functools.cache
def _bz2(level: int = 1) -> bytes:
    return bz2.compress(DATA, level)


def _decode(
    blob: bytes, decomp: Bzip2BlockDecompressor | None = None, chunk: int = 65536
) -> tuple[bytes, Bzip2BlockDecompressor]:
    """Drive the decompressor as ``FramedDecoder`` does; raise what it raises."""
    decomp = decomp or Bzip2BlockDecompressor()
    out = bytearray()
    pos = 0
    while not decomp.eof:
        if not decomp.needs_input:
            out += decomp.decompress(b"")
        elif pos < len(blob):
            out += decomp.decompress(blob[pos : pos + chunk])
            pos += chunk
        else:
            decomp.end_input()
            while piece := decomp.decompress(b""):
                out += piece
            break
    return bytes(out), decomp


def _block_starts(blob: bytes) -> list[tuple[int, int, Bzip2BlockStart]]:
    _out, decomp = _decode(blob)
    return [(c, d, s) for c, d, s in decomp.take_block_starts()]  # type: ignore[misc]


def _config(**kwargs: Any) -> StreamConfig:
    return StreamConfig(use_indexed_bzip2=AcceleratorMode.OFF, **kwargs)


def _engine(stream: Any) -> DecompressorStream:
    inner = stream
    while not isinstance(inner, DecompressorStream):
        inner = inner._inner
    return inner


def test_the_scan_finds_every_block_and_the_end_marker() -> None:
    blob = _bz2()
    starts = _block_starts(blob)
    markers = find_markers(blob, 0, len(blob) * 8)
    blocks = [bit for bit, magic, _crc in markers if magic == BLOCK_MAGIC]
    assert blocks == [8 * c + s.bit for c, _d, s in starts]
    assert [magic for _bit, magic, _crc in markers][-1] == EOS_MAGIC
    assert len(starts) >= 7
    assert len({s.bit for _c, _d, s in starts}) > 1


@pytest.mark.parametrize("chunk", [1, 7, 4096, 1 << 20])
@pytest.mark.parametrize("level", [1, 9])
def test_any_feed_size_decodes_the_stream(chunk: int, level: int) -> None:
    blob = _bz2(level) if chunk > 7 else bz2.compress(DATA[:150_000], 1)
    want = DATA if chunk > 7 else DATA[:150_000]
    out, decomp = _decode(blob + b"after", chunk=chunk)
    assert out == want
    # What was fed past the end-of-stream marker: all of it for large feeds; small
    # feeds stop sooner, at a prefix of it.
    assert decomp.eof
    if chunk > 7:
        assert decomp.unused_data == b"after"
    assert b"after".startswith(decomp.unused_data)


def test_an_empty_stream_decodes_to_nothing() -> None:
    out, decomp = _decode(bz2.compress(b"") + b"BZh9")
    assert out == b""
    assert decomp.eof
    assert decomp.unused_data == b"BZh9"


@pytest.mark.parametrize("level", [1, 9])
def test_every_block_resumes_to_the_end_with_its_combined_crc(level: int) -> None:
    """A resumed decode checks the stream's end-of-stream CRC from the CRC the point
    carries: it ends cleanly, with no decode from the start."""
    blob = _bz2(level)
    for comp, decoded, state in _block_starts(blob):
        decomp = Bzip2BlockDecompressor()
        decomp.resume(state)
        out, _ = _decode(blob[comp:], decomp)
        assert out == DATA[decoded:], decoded
        assert decomp.eof


def test_a_point_without_its_combined_crc_hands_the_end_back() -> None:
    blob = _bz2()
    comp, decoded, state = _block_starts(blob)[3]
    decomp = Bzip2BlockDecompressor()
    decomp.resume(Bzip2BlockStart(state.bit, 9, None))
    got = bytearray()
    with pytest.raises(ResumeReachedStreamEnd):
        pos = comp
        while True:
            if decomp.needs_input and pos < len(blob):
                got += decomp.decompress(blob[pos : pos + 4096])
                pos += 4096
            elif decomp.needs_input:
                decomp.end_input()
                got += decomp.decompress(b"")
            else:
                got += decomp.decompress(b"")
    assert bytes(got) == DATA[decoded:]


def test_a_wrong_combined_crc_raises_after_every_block() -> None:
    blob = bytearray(_bz2())
    blob[-2] ^= 0x01  # inside the end-of-stream marker's combined CRC
    decomp = Bzip2BlockDecompressor()
    got = bytearray()
    with pytest.raises(CorruptionError, match="combined CRC"):
        got += decomp.decompress(bytes(blob), 1 << 22)
        got += decomp.decompress(b"", 1 << 22)
        decomp.end_input()
        while True:
            got += decomp.decompress(b"")
    assert bytes(got) == DATA


def test_a_match_inside_a_block_is_not_taken_for_a_block_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every candidate the scan adds inside a block drains nothing and is passed over."""
    real = find_markers

    def with_false_matches(data: Any, first: int, end: int) -> list[Any]:
        found = real(data, first, end)
        fake = [(bit, BLOCK_MAGIC, 0) for bit in range(first + 1001, end, 30_011)]
        return sorted(found + fake)

    monkeypatch.setattr(bzip2_blocks, "find_markers", with_false_matches)
    out, decomp = _decode(_bz2())
    assert out == DATA
    assert len(decomp.take_block_starts()) == len(_block_starts(_bz2()))


def _damaged(level: int = 1, block: int = 3, offset: int = 5000) -> tuple[bytes, int]:
    """The stream with a byte flipped inside block ``block``, and where its output
    starts."""
    blob = _bz2(level)
    comp, decoded, _state = _block_starts(blob)[block]
    bad = bytearray(blob)
    bad[comp + offset] ^= 0x55
    return bytes(bad), decoded


def _read_all(stream: Any, size: int) -> tuple[bytes, BaseException | None]:
    got = bytearray()
    try:
        while piece := stream.read(size):
            got += piece
    except CorruptionError as exc:
        return bytes(got), exc
    return bytes(got), None


@pytest.mark.parametrize("pipe", [False, True])
@pytest.mark.parametrize("size", [61, 4096, 1 << 20])
@pytest.mark.parametrize(
    "isolation", [ProcessIsolation.NONE, ProcessIsolation.NATIVE_DECODERS]
)
def test_a_damaged_block_gives_none_of_its_bytes(
    pipe: bool, size: int, isolation: ProcessIsolation
) -> None:
    """Every byte of the blocks before the damage, none of the damaged block, then the
    error, whatever the read size or source."""
    blob, good = _damaged()
    source = NonSeekableBytesIO(blob) if pipe else io.BytesIO(blob)
    config = _config(process_isolation=isolation)
    with open_codec_stream(Codec.BZIP2, source, config=config) as stream:
        got, error = _read_all(stream, size)
    assert isinstance(error, CorruptionError)
    assert got == DATA[:good]


@pytest.mark.parametrize("pipe", [False, True])
@pytest.mark.parametrize("size", [61, 1 << 20])
@pytest.mark.parametrize(
    "isolation", [ProcessIsolation.NONE, ProcessIsolation.NATIVE_DECODERS]
)
@pytest.mark.parametrize("block", [1, 4, 6])
def test_a_damaged_block_header_keeps_the_block_before_it(
    pipe: bool, size: int, isolation: ProcessIsolation, block: int
) -> None:
    """A block whose magic is damaged: ``bz2`` checks the block before it and refuses
    the header in one call. That block's bytes still come out, then the error."""
    blob = bytearray(_bz2())
    _comp, good, _state = _block_starts(bytes(blob))[block]
    bit = find_markers(bytes(blob), 0, 8 * len(blob))[block][0]
    blob[bit // 8 + 2] ^= 0x10
    source = NonSeekableBytesIO(bytes(blob)) if pipe else io.BytesIO(bytes(blob))
    config = _config(process_isolation=isolation)
    with open_codec_stream(Codec.BZIP2, source, config=config) as stream:
        got, error = _read_all(stream, size)
    assert isinstance(error, CorruptionError)
    assert got == DATA[:good]


def test_restart_points_are_the_blocks_and_a_seek_decodes_one_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = _bz2()
    starts = [d for _c, d, _s in _block_starts(blob)]
    config = _config(restart_points=True)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(blob), config=config) as stream:
        assert stream.read() == DATA
        points = [p.decompressed_offset for p in _engine(stream)._seek_points]
        assert points == starts
        fed: list[int] = []
        real = Bzip2BlockDecompressor.decompress

        def counting(self: Any, data: bytes, max_length: int = -1) -> bytes:
            fed.append(len(data))
            return real(self, data, max_length)

        monkeypatch.setattr(Bzip2BlockDecompressor, "decompress", counting)
        target = starts[4] + 10
        assert stream.seek(target) == target
        assert stream.read(1000) == DATA[target : target + 1000]
        # One block of input, read from the source in 64 KiB pieces.
        assert sum(fed) < 2 * len(blob) // 7 + (1 << 16)


def test_without_restart_points_no_point_is_kept() -> None:
    with open_codec_stream(Codec.BZIP2, io.BytesIO(_bz2()), config=_config()) as s:
        assert s.read() == DATA
        assert [p.decompressed_offset for p in _engine(s)._seek_points] == [0]


def test_a_block_over_the_memory_cap_is_refused() -> None:
    runs = bz2.compress(b"\0" * 30_000_000, 9)
    with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
        _decode(runs, Bzip2BlockDecompressor(memory_cap=1 << 20))
    out, _ = _decode(runs, Bzip2BlockDecompressor(memory_cap=1 << 30))
    assert len(out) == 30_000_000


@pytest.mark.parametrize("cut", [3, 20, 1000, -3])
def test_a_cut_stream_is_truncated_after_its_whole_blocks(cut: int) -> None:
    blob = _bz2()
    cut_at = cut if cut > 0 else len(blob) + cut
    with open_codec_stream(
        Codec.BZIP2, io.BytesIO(blob[:cut_at]), config=_config()
    ) as stream:
        got = bytearray()
        with pytest.raises(TruncatedError):
            while piece := stream.read(1 << 16):
                got += piece
    whole = bz2.BZ2Decompressor().decompress(blob[:cut_at])
    assert bytes(got) == whole


@requires("rapidgzip")
@pytest.mark.parametrize("size", [4096, 1 << 20])
@pytest.mark.parametrize("block", [1, 3, 6])
def test_the_accelerator_gives_the_same_bytes_before_a_damaged_block(
    size: int, block: int
) -> None:
    """rapidgzip's takeover hands the read to this decoder: the bytes and the error
    match ``use_indexed_bzip2=OFF``."""
    blob, good = _damaged(block=block)
    config = StreamConfig(use_indexed_bzip2=AcceleratorMode.ON, seekable=True)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(blob), config=config) as stream:
        got, error = _read_all(stream, size)
    assert isinstance(error, CorruptionError)
    assert got == DATA[:good]


@requires("rapidgzip")
def test_takeover_points_carry_their_stream_level_and_combined_crc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rapidgzip takeover's points, read from its index, resume to the end of their
    stream and check its combined CRC there: no decode from the start."""
    import rapidgzip

    from archivey.internal.streams.codecs import bzip2_codec

    first = bz2.compress(DATA[:300_000], 3)
    two = first + bz2.compress(DATA, 1)
    full = DATA[:300_000] + DATA
    with rapidgzip.IndexedBzip2File(io.BytesIO(two), parallelization=0) as f:
        f.read()
        offsets = f.block_offsets()

    class _Index:
        def available_block_offsets(self) -> dict[int, int]:
            return offsets

    monkeypatch.setattr(bzip2_codec, "_BZIP2_RESUME_POINTS", 1000)
    points = bzip2_codec._bzip2_resume_points(
        _Index(),  # type: ignore[arg-type]
        len(full),
        lambda: io.BytesIO(two),
    )
    assert len(points) == len(_block_starts(first)) + len(_block_starts(_bz2())) - 1
    for point in points:
        state = point.state
        assert isinstance(state, Bzip2BlockStart)
        in_first = point.compressed_offset < len(first)
        assert state.level == (3 if in_first else 1)
        decomp = Bzip2BlockDecompressor()
        decomp.resume(state)
        out, _ = _decode(
            two[point.compressed_offset : len(first) if in_first else len(two)],
            decomp,
        )
        end = 300_000 if in_first else len(full)
        assert out == full[point.decompressed_offset : end]
        assert decomp.eof
