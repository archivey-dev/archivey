"""``bzip2_resume``: a bzip2 decode started at a block boundary from rapidgzip's index.

The takeover in ``tests/test_accelerator_takeover.py`` depends on it; these tests pin the
decoder itself: the bit shift, a resume from every block of a one- and a two-stream
file, and a resume over a cut stream.
"""

from __future__ import annotations

import bz2
import io
import random
from typing import cast

import pytest

from archivey.exceptions import TruncatedError
from archivey.internal.config import DEFAULT_STREAM_CONFIG
from archivey.internal.streams.codecs.base import CodecParams
from archivey.internal.streams.codecs.bzip2_codec import Bzip2Codec
from archivey.internal.streams.codecs.bzip2_resume import (
    BitShifter,
    Bzip2Resume,
    Bzip2ResumeDecoder,
)
from archivey.internal.streams.decompressor_stream import DecompressorStream, SeekPoint
from archivey.internal.streams.resume import ResumeReachedStreamEnd
from tests.conftest import requires
from tests.test_accelerator_takeover import (
    _block_bits,
    _bzip2,
    _bzip2_cut,
    _bzip2_two_streams,
)

pytestmark = requires("rapidgzip")


def _plain_bzip2(blob: bytes) -> DecompressorStream:
    """The codec's own plain decode, with the accelerator off."""
    stream = Bzip2Codec().open_framed(
        io.BytesIO(blob), CodecParams(), DEFAULT_STREAM_CONFIG
    )
    return cast(DecompressorStream, stream)


@pytest.mark.parametrize("bit", range(8))
def test_the_bit_shifter_matches_a_whole_shift(bit: int) -> None:
    data = random.Random(bit).randbytes(1000)
    shifter = BitShifter(bit)
    out = b"".join(shifter.feed(data[i : i + 37]) for i in range(0, 1000, 37))
    out += shifter.flush()
    whole = (int.from_bytes(data, "big") << bit) & ((1 << 8000) - 1)
    assert out == whole.to_bytes(1000, "big")


@pytest.mark.parametrize("blob_name", ["one", "two"])
def test_every_block_resumes_to_the_stream_end(blob_name: str) -> None:
    """From each block, the resumed decode reproduces the data up to its stream's end,
    where it raises ``ResumeReachedStreamEnd`` rather than a verdict."""
    blob = _bzip2() if blob_name == "one" else _bzip2_two_streams()
    full = bz2.decompress(blob)
    import rapidgzip

    with rapidgzip.IndexedBzip2File(io.BytesIO(blob), parallelization=0) as f:
        f.read()
        offsets = f.block_offsets()
    delivered = tried = 0
    for bit, decoded in sorted(offsets.items())[1:]:
        if decoded >= len(full):
            continue
        tried += 1
        stream = _plain_bzip2(blob)
        stream.add_seek_points([SeekPoint(decoded, bit // 8, Bzip2Resume(bit % 8))])
        got = bytearray()
        with pytest.raises(ResumeReachedStreamEnd):
            stream.seek(decoded)
            while block := stream.read(7777):
                got += block
        assert bytes(got) == full[decoded : decoded + len(got)]
        delivered += bool(got)
    # The read that decodes a stream's last block also meets its end, and raises before
    # it returns, and a point at the end-of-stream marker of a stream that is not the
    # last meets it at once: every other point delivers.
    streams = 1 if blob_name == "one" else 2
    assert delivered >= tried - 2 * streams


def test_a_resumed_decode_of_a_cut_stream_delivers_the_stdlib_bytes() -> None:
    blob = _bzip2_cut("later-block")
    bits = _block_bits(_bzip2())
    whole = bz2.BZ2Decompressor().decompress(blob)
    import rapidgzip

    with rapidgzip.IndexedBzip2File(io.BytesIO(_bzip2()), parallelization=0) as f:
        f.read()
        decoded = f.block_offsets()[bits[5]]
    decoder = Bzip2ResumeDecoder(Bzip2Resume(bits[5] % 8), base=None)  # type: ignore[arg-type]
    tail = blob[bits[5] // 8 :]
    out = decoder.feed(tail).data + decoder.flush().data
    assert whole[decoded:] == out
    assert isinstance(decoder.pending_error, TruncatedError)
