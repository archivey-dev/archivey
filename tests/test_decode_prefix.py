"""The bytes a damaged stream gives before its error.

Spec ``compressed-streams``: each decoder call is fed the compressed input up to the
next 64 KiB boundary from the decoder's start and asks for what the read asks, at most
64 KiB. On a source that can seek, a call that raises is decoded again to the failing
byte, so every bounded read size gets every byte the decoder gives before its error.
A pipe loses at most the call that failed. These tests fail with read-size-scaled
feeding (``read(n)`` fed ``min(n, 1 MiB)`` of input and asked ``n`` bytes per call).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from archivey.exceptions import ArchiveyError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, deps, open_codec_stream
from archivey.internal.streams.decompressor_stream import probe_streams
from tests.streams_util import NonSeekableBytesIO, ShortReadNonSeekable


def _text(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    words = [
        bytes(rng.choice(b"abcdefghij") for _ in range(rng.randint(2, 9)))
        for _ in range(500)
    ]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + b" "
    return bytes(out[:size])


PAYLOAD = _text(3_000_000, 1)


def _damage(data: bytes, at: float) -> bytes:
    pos = int(len(data) * at)
    junk = random.Random(7).randbytes(64)
    return data[:pos] + junk + data[pos + 64 :]


def _zstd(data: bytes) -> bytes:
    if deps.zstd is None:
        pytest.skip("no zstd module")
    return deps.zstd.compress(data)


CODECS: dict[str, tuple[Codec, Callable[[bytes], bytes]]] = {
    "gzip": (Codec.GZIP, lambda d: gzip.compress(d, mtime=0)),
    "xz": (Codec.XZ, lambda d: lzma.compress(d, format=lzma.FORMAT_XZ)),
    "bzip2": (Codec.BZIP2, bz2.compress),
    "zstd": (Codec.ZSTD, _zstd),
}

_CONFIG = StreamConfig(
    use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF
)


def _prefix(
    source: Any, codec: Codec, size: int, config: StreamConfig = _CONFIG
) -> tuple[int, str | None]:
    """Bytes read in ``read(size)`` steps before the stream raised, and the error type."""
    got = 0
    with open_codec_stream(codec, source, config=config) as stream:
        try:
            while chunk := stream.read(size):
                got += len(chunk)
        except ArchiveyError as exc:
            return got, type(exc).__name__
    return got, None


@pytest.mark.parametrize("name", list(CODECS))
def test_every_bounded_read_size_gets_the_same_prefix(name: str) -> None:
    codec, compress = CODECS[name]
    damaged = _damage(compress(PAYLOAD), 0.5)
    expected = _prefix(io.BytesIO(damaged), codec, 65536)
    assert expected[1] is not None, "the damage must surface as an error"
    for size in (7, 4096, 100_000, 1 << 20, 5 << 20):
        assert _prefix(io.BytesIO(damaged), codec, size) == expected, size


@pytest.mark.parametrize("name", ["gzip", "xz"])
def test_a_pipe_loses_at_most_one_call(name: str) -> None:
    """A pipe cannot be decoded again: a read loses at most the decoder call that
    failed, which asks for what the read asks, up to 64 KiB. Short source reads give
    no fewer bytes than that bound allows."""
    codec, compress = CODECS[name]
    damaged = _damage(compress(PAYLOAD), 0.5)
    whole = _prefix(io.BytesIO(damaged), codec, 1 << 20)
    large = _prefix(NonSeekableBytesIO(damaged), codec, 1 << 20)
    small = _prefix(NonSeekableBytesIO(damaged), codec, 512)
    assert large[1] == small[1] == whole[1] is not None
    assert whole[0] - 65536 <= large[0] <= small[0] <= whole[0]
    assert whole[0] - 512 <= small[0]
    short = _prefix(ShortReadNonSeekable(damaged, 1000), codec, 512)  # type: ignore[arg-type]
    assert short[1] == whole[1]
    assert whole[0] - 512 <= short[0] <= whole[0]


def _exact_prefix(data: bytes, codec: Codec) -> int:
    """Bytes a decoder gives before its error, asked for one output byte per call."""
    got = 0
    with (
        probe_streams(),
        open_codec_stream(codec, io.BytesIO(data), config=_CONFIG) as stream,
    ):
        try:
            while stream.read(1):
                got += 1
        except ArchiveyError:
            pass
    return got


@pytest.mark.parametrize("name", list(CODECS))
def test_a_file_gets_every_byte_before_the_error(name: str) -> None:
    codec, compress = CODECS[name]
    damaged = _damage(compress(PAYLOAD[:300_000]), 0.5)
    got, error = _prefix(io.BytesIO(damaged), codec, 1 << 20)
    assert error is not None
    assert got == _exact_prefix(damaged, codec)


def test_damage_in_the_second_gzip_member_keeps_the_first_whole() -> None:
    first = _text(500_000, 2)
    data = gzip.compress(first, mtime=0) + _damage(gzip.compress(PAYLOAD, mtime=0), 0.5)
    expected = _prefix(io.BytesIO(data), Codec.GZIP, 65536)
    assert expected[1] is not None
    assert expected[0] > len(first)
    for size in (7, 1 << 20):
        assert _prefix(io.BytesIO(data), Codec.GZIP, size) == expected


def test_a_whole_stream_read_raises_without_a_prefix() -> None:
    damaged = _damage(gzip.compress(PAYLOAD, mtime=0), 0.5)
    source = io.BytesIO(damaged)
    with (
        open_codec_stream(Codec.GZIP, source, config=_CONFIG) as stream,
        pytest.raises(ArchiveyError),
    ):
        stream.read()


def test_rapidgzip_gives_the_same_prefix_as_the_standard_library() -> None:
    pytest.importorskip("rapidgzip")
    compressed = gzip.compress(PAYLOAD, mtime=0)
    rng = random.Random(8)
    at = rng.randrange(100_000, len(compressed) - 100_000)
    damaged = compressed[:at] + rng.randbytes(64) + compressed[at + 64 :]
    expected = _prefix(io.BytesIO(damaged), Codec.GZIP, 65536)
    assert expected[1] is not None, "the damage must surface as an error"
    on = replace(_CONFIG, use_rapidgzip=AcceleratorMode.ON)
    for size in (7, 65536, 1 << 20):
        assert _prefix(io.BytesIO(damaged), Codec.GZIP, size, on) == expected, size


@pytest.mark.parametrize("size", [512, 1 << 20])
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_lzop_hands_back_the_blocks_before_a_damaged_one(size: int, pipe: bool) -> None:
    """The in-house lzop decoder decodes the next block once a block's output is
    handed out; a damaged next block must not take the good block's tail with it."""
    from tests.lzop_build import make_lzop

    data = _text(600_000, 4)
    damaged = bytearray(make_lzop(data))  # stored 256 KiB blocks
    damaged[len(damaged) - 1000] ^= 0xFF  # inside the third block
    source = NonSeekableBytesIO(bytes(damaged)) if pipe else io.BytesIO(bytes(damaged))
    assert _prefix(source, Codec.LZOP, size) == (2 * 256 * 1024, "CorruptionError")
