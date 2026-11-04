"""zlib resumes a DEFLATE decode at a block boundary that is not on a byte boundary.

``deflate_resume`` starts the input with made-up empty blocks so that zlib's bit
position lines up with the source's, and gives zlib the output before the point as its
window. The streams here end a block with ``Z_BLOCK``, which leaves the next block
starting part-way into a byte, and their second part refers back into the first. The
bit the second part starts at is found by trying all eight; the builder collects one
stream for each.
"""

from __future__ import annotations

import functools
import io
import random
import zlib

import pytest

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.codecs.deflate_decoder import (
    GzipDecompressorStream,
    ZlibDecoder,
    ZlibDecompressorStream,
)
from archivey.internal.streams.codecs.deflate_resume import (
    WINDOW_SIZE,
    DeflateResume,
    DeflateResumeDecoder,
    stream_end,
)
from archivey.internal.streams.decompressor_stream import SeekPoint
from archivey.internal.streams.resume import ResumeReachedStreamEnd

_WORDS = [
    bytes(random.Random(i).choices(b"abcdefghij ", k=2 + i % 8)) for i in range(400)
]


def _text(rng: random.Random, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        out += rng.choice(_WORDS)
    return bytes(out[:size])


def _decoder(bit: int, window: bytes) -> DeflateResumeDecoder:
    return DeflateResumeDecoder(
        DeflateResume(bit, window),
        ZlibDecoder(-15),
        corruption=lambda exc: CorruptionError(str(exc)),
        truncated="cut",
    )


def _feed(
    decoder: DeflateResumeDecoder, data: bytes, step: int, out: bytearray
) -> bytearray:
    """Feed ``data`` in ``step``-byte pieces, asking for at most 4 KiB at a time, and
    add the output to ``out``, which keeps it if the decoder raises."""
    for i in range(0, len(data), step):
        out += decoder.feed(data[i : i + step], 4096).data
        while not decoder.needs_input:
            out += decoder.feed(b"", 4096).data
    return out


def _decodes_from(bit: int, head: bytes, tail: bytes, data: bytes) -> bool:
    decoder = _decoder(bit, head[-WINDOW_SIZE:])
    out = bytearray()
    try:
        _feed(decoder, tail, 500, out)
    except ResumeReachedStreamEnd:
        pass
    except CorruptionError:
        return False
    return len(out) > len(data) // 2 and data.startswith(out)


@functools.cache
def _stream(bit: int) -> tuple[bytes, int, bytes, bytes]:
    """A raw DEFLATE stream whose second part starts ``bit`` bits into a byte.

    Returns the stream, the byte the second part starts in, and the two parts' output.
    """
    for n in range(100):
        rng = random.Random(n)
        head = _text(rng, WINDOW_SIZE + 997 * n)
        data = head[500:20_500] + _text(rng, 100_000)
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        first = compressor.compress(head) + compressor.flush(zlib.Z_BLOCK)
        stream = first + compressor.compress(data) + compressor.flush()
        if _decodes_from(bit, head, stream[len(first) :], data):
            return stream, len(first), head, data
    raise AssertionError(f"no stream with a block starting at bit {bit}")


@pytest.mark.parametrize("bit", range(8))
def test_a_resumed_decode_reaches_the_end_and_says_to_start_over(bit: int) -> None:
    """Up to the end of the stream every byte is right; the end raises, since a resumed
    decode cannot check the checksum that follows it."""
    stream, start, head, data = _stream(bit)
    decoder = _decoder(bit, head[-WINDOW_SIZE:])
    got = bytearray()
    with pytest.raises(ResumeReachedStreamEnd):
        for i in range(start, len(stream), 300):
            got += decoder.feed(stream[i : i + 300]).data
        decoder.flush()
    assert data.startswith(bytes(got))
    assert len(got) > len(data) // 2


@pytest.mark.parametrize("bit", range(8))
@pytest.mark.parametrize("keep", [0.6, 0.97])
def test_a_cut_stream_gives_what_zlib_from_the_start_gives(
    bit: int, keep: float
) -> None:
    """A source cut at a byte: the resumed decode delivers exactly what zlib, decoding
    the cut source from its start, delivers past the point, then reports truncation."""
    stream, start, head, _ = _stream(bit)
    cut = stream[: start + int((len(stream) - start) * keep)]
    whole = zlib.decompressobj(-15)
    expected = (whole.decompress(cut) + whole.flush())[len(head) :]
    decoder = _decoder(bit, head[-WINDOW_SIZE:])
    got = _feed(decoder, cut[start:], 777, bytearray()) + decoder.flush().data
    assert got == expected
    assert isinstance(decoder.pending_error, TruncatedError)


def test_a_point_outside_the_format_is_refused() -> None:
    with pytest.raises(ValueError, match="not a DEFLATE resume point"):
        _decoder(8, b"")
    with pytest.raises(ValueError, match="not a DEFLATE resume point"):
        _decoder(0, b"x" * (WINDOW_SIZE + 1))


@pytest.mark.parametrize("bit", [0, 3, 6])
def test_a_stream_seeks_through_a_resume_point(bit: int) -> None:
    """The point goes into a ``DecompressorStream`` like any seek point: a seek past it
    starts there, and one before it starts from the origin."""
    stream, start, head, data = _stream(bit)
    cut = stream[: len(stream) - 2000]
    decompressed = ZlibDecompressorStream(io.BytesIO(cut), wbits=-15)
    point = DeflateResume(bit, head[-WINDOW_SIZE:])
    decompressed.add_seek_points([SeekPoint(len(head), start, point)])
    decompressed.seek(len(head) + 5000)
    assert decompressed.read(10_000) == data[5000:15000]
    assert type(decompressed._decoder) is DeflateResumeDecoder
    whole = zlib.decompressobj(-15)
    expected = whole.decompress(cut) + whole.flush()
    rest = bytearray()
    with pytest.raises(TruncatedError):
        while block := decompressed.read(1 << 16):
            rest += block
    assert bytes(rest) == expected[len(head) + 15000 :]
    decompressed.seek(100)
    assert decompressed.read(100) == head[100:200]
    assert type(decompressed._decoder) is ZlibDecoder


def test_gzip_maps_a_corrupt_resumed_decode_like_its_own() -> None:
    """A resumed gzip decode that meets bad data raises the gzip decoder's error."""
    header = b"\x1f\x8b\x08\x00" + b"\0" * 6
    # BTYPE 11 is reserved: zlib refuses the block.
    stream = GzipDecompressorStream(io.BytesIO(header + b"\x07" * 64))
    stream.add_seek_points([SeekPoint(10, len(header), DeflateResume(0, b""))])
    # The seek decodes nothing; the read after it meets the bad block.
    assert stream.seek(20) == 20
    with pytest.raises(CorruptionError):
        stream.read(1)


@pytest.mark.parametrize("bit", [0, 3, 6])
def test_stream_end_finds_the_final_block_from_a_resume_point(bit: int) -> None:
    stream, start, head, data = _stream(bit)
    end = len(head) + len(data)
    point = SeekPoint(len(head), start, DeflateResume(bit, head[-WINDOW_SIZE:]))
    assert stream_end(io.BytesIO(stream), point, end)[0] == end
    assert stream_end(io.BytesIO(stream), None, end)[0] == end
    # The input runs out first, or the output passes the cap: no end.
    cut = stream[: start + (len(stream) - start) // 2]
    assert stream_end(io.BytesIO(cut), point, end)[0] is None
    assert stream_end(io.BytesIO(stream), point, end - 1)[0] is None


def test_stream_end_drains_output_a_max_length_cut_held_back() -> None:
    """The decode is cut to 1 MiB pieces: output just past one, with the final block,
    can still be in zlib when the input runs out, and the stream still ends there."""
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    size = (1 << 20) + 100
    full = compressor.compress(bytes(size)) + compressor.flush()
    assert stream_end(io.BytesIO(full), None, 1 << 40)[0] == size
    assert stream_end(io.BytesIO(full[: len(full) // 2]), None, 1 << 40)[0] is None
    assert stream_end(io.BytesIO(full[:-1]), None, 1 << 40)[0] is None


def test_stream_end_needs_a_final_block() -> None:
    """A stream cut right after a whole block decodes every byte with no error, and
    has no end."""
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = compressor.compress(b"payload " * 100) + compressor.flush(zlib.Z_FULL_FLUSH)
    assert len(zlib.decompressobj(-15).decompress(body)) == 800
    assert stream_end(io.BytesIO(body), None, 800)[0] is None
    final = body + compressor.flush()
    assert stream_end(io.BytesIO(final), None, 800)[0] == 800
