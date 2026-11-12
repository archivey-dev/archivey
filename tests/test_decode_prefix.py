"""The bytes a damaged stream gives before its error.

Spec ``compressed-streams``: each decoder call is fed the compressed input up to the
next 64 KiB boundary from the decoder's start and asks for what the read asks, at most
1 MiB on a file and 64 KiB on a pipe. On a source that can seek, a call that raises
is decoded again to the failing byte, so every bounded read size gets every byte the
decoder gives before its error.
A pipe loses at most the call that failed. These tests fail with read-size-scaled
feeding (``read(n)`` fed ``min(n, 1 MiB)`` of input and asked ``n`` bytes per call).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import zlib
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from archivey import ProcessIsolation
from archivey.exceptions import ArchiveyError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    deflate_decoder,
    deps,
    open_codec_stream,
)
from archivey.internal.streams.codecs.deflate_decoder import GzipDecoder, ZlibDecoder
from archivey.internal.streams.decompressor_stream import probe_streams
from tests.conftest import requires
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
    for size in (61, 4096, 100_000, 1 << 20, 5 << 20):
        assert _prefix(io.BytesIO(damaged), codec, size) == expected, size


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


_DEFLATE_FAMILY: dict[str, tuple[Codec, Callable[[bytes], bytes]]] = {
    "gzip": CODECS["gzip"],
    "zlib": (Codec.ZLIB, zlib.compress),
    "deflate": (Codec.DEFLATE, lambda d: _raw_deflate(d)),
}


_DEFLATE_WBITS = {"gzip": 31, "zlib": zlib.MAX_WBITS, "deflate": -zlib.MAX_WBITS}


@pytest.mark.parametrize("name", list(_DEFLATE_FAMILY))
@pytest.mark.parametrize("size", [512, 1 << 20])
def test_deflate_from_a_pipe_gets_every_byte_before_the_error(
    name: str, size: int
) -> None:
    """A pipe cannot be decoded again, but zlib's state can be copied before each
    call: the copy decodes the failing call's input again to the error."""
    codec, _ = _DEFLATE_FAMILY[name]
    good = PAYLOAD[:500_000]
    compressor = zlib.compressobj(wbits=_DEFLATE_WBITS[name])
    # A full flush ends on a byte boundary, so the next byte is a block header:
    # 0x07 is a final block of the reserved type 3, which every inflater refuses.
    # Damage at a random spot can decode on in raw deflate, which has no checksum,
    # and where it stops depends on the zlib build.
    damaged = (
        compressor.compress(good)
        + compressor.flush(zlib.Z_FULL_FLUSH)
        + b"\x07"
        + bytes(64)
    )
    expected = _prefix(io.BytesIO(damaged), codec, 1 << 20)
    # zlib, asked for one byte per call, can meet the bad header before it hands
    # out the last good byte; the file path decodes again that way too.
    assert expected[1] is not None
    assert len(good) - 1 <= expected[0] <= len(good)
    assert _prefix(NonSeekableBytesIO(damaged), codec, size) == expected


def test_a_second_gzip_member_from_a_pipe_gets_every_byte_before_the_error() -> None:
    first = _text(200_000, 2)
    data = gzip.compress(first, mtime=0) + _damage(
        gzip.compress(PAYLOAD[:500_000], mtime=0), 0.5
    )
    expected = _prefix(io.BytesIO(data), Codec.GZIP, 1 << 20)
    assert expected[0] > len(first)
    assert _prefix(NonSeekableBytesIO(data), Codec.GZIP, 1 << 20) == expected


@pytest.mark.parametrize("decoder_type", [ZlibDecoder, GzipDecoder])
def test_an_unbounded_inflate_step_is_not_replayed(
    decoder_type: type[ZlibDecoder | GzipDecoder], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unbounded read raises without the prefix, so the step takes no copy:
    replaying a high-ratio step one byte per call costs millions of calls."""
    if decoder_type is GzipDecoder:
        decoder: ZlibDecoder | GzipDecoder = GzipDecoder()
        good = gzip.compress(b"\0" * (8 << 20), mtime=0)
    else:
        decoder = ZlibDecoder(zlib.MAX_WBITS)
        good = zlib.compress(b"\0" * (8 << 20))
    damaged = good[:-1] + bytes([good[-1] ^ 1])  # the trailing checksum
    decoder.keep_output_before_errors()
    replays: list[int] = []
    monkeypatch.setattr(
        deflate_decoder,
        "_decode_to_error",
        lambda *args: replays.append(1) or b"",
    )
    with pytest.raises(ArchiveyError):
        decoder.feed(damaged, -1)
        decoder.flush()
    assert replays == []


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


_RAW: dict[Codec, Callable[[], Any]] = {
    Codec.GZIP: lambda: zlib.decompressobj(31),
    Codec.XZ: lzma.LZMADecompressor,
    Codec.BZIP2: bz2.BZ2Decompressor,
}


def _exact_prefix(data: bytes, codec: Codec) -> int:
    """Bytes a decoder gives before its error, asked for one output byte per call.

    A standard-library decoder is driven directly (one-byte reads through the stream
    stack take seconds per 100 kB); the others through the stream, under
    ``probe_streams`` so nothing is handed back or decoded again.
    """
    if codec in _RAW:
        return _raw_exact_prefix(data, _RAW[codec]())
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


def _raw_exact_prefix(data: bytes, decoder: Any) -> int:
    got = 0
    zlib_like = hasattr(decoder, "unconsumed_tail")
    pending = data
    try:
        while not decoder.eof:
            out = decoder.decompress(pending, 1)
            got += len(out)
            if zlib_like:
                pending = decoder.unconsumed_tail
                if not out and not pending:
                    break
            else:
                pending = b""
                if not out and decoder.needs_input:
                    break
    except (OSError, EOFError, zlib.error, lzma.LZMAError):
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
    for size in (61, 1 << 20):
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
    for size in (61, 65536, 1 << 20):
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


def _bad_code(data: bytes, at: float) -> bytes:
    """``data`` with eight bytes of set bits at ``at``: an LZW code past the table."""
    damaged = bytearray(data)
    pos = int(len(damaged) * at)
    damaged[pos : pos + 8] = b"\xff" * 8
    return bytes(damaged)


def _unix_compress(data: bytes) -> bytes:
    from tests.streams_util import make_unix_compress

    return make_unix_compress(data)


def _shrink(data: bytes) -> bytes:
    from tests.zip_legacy_build import shrink

    return shrink(data)[0]


@pytest.mark.parametrize(
    ("codec", "compress"),
    [
        pytest.param(Codec.UNIX_COMPRESS, _unix_compress, marks=requires("ncompress")),
        (Codec.SHRINK, _shrink),
    ],
    ids=["unix_compress", "shrink"],
)
@pytest.mark.parametrize("size", [512, 1 << 20])
def test_lzw_decoders_hand_back_every_byte_before_a_bad_code(
    codec: Codec, compress: Callable[[bytes], bytes], size: int
) -> None:
    """The in-house LZW decoders (.Z and ZIP Shrink) decode a whole input slice per
    call; a bad code in it must not take the bytes before it along, even from a pipe,
    where nothing can be decoded again."""
    damaged = _bad_code(compress(_text(300_000, 4)), 0.5)
    expected = _exact_prefix(damaged, codec)
    assert 0 < expected < 300_000
    pipe = _prefix(NonSeekableBytesIO(damaged), codec, size)
    assert pipe == (expected, "CorruptionError")


def test_an_interrupt_during_the_second_decode_reaches_the_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Ctrl-C while a failed call is decoded again is not held behind the bytes a
    large read already gathered."""
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    real = DecompressorStream._redecode_step
    calls = 0

    def interrupt_on_third(self: Any, decoder: Any, max_length: int) -> Any:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise KeyboardInterrupt
        return real(self, decoder, max_length)

    monkeypatch.setattr(DecompressorStream, "_redecode_step", interrupt_on_third)
    damaged = _damage(gzip.compress(PAYLOAD, mtime=0), 0.5)
    with (
        open_codec_stream(Codec.GZIP, io.BytesIO(damaged), config=_CONFIG) as stream,
        pytest.raises(KeyboardInterrupt),
    ):
        while stream.read(5 << 20):
            pass
    assert calls == 3


def _bzip3(data: bytes) -> bytes:
    from bz3.backends import BZ3Compressor

    compressor = BZ3Compressor(65 << 10)
    return compressor.compress(data) + compressor.flush()


def _ppmd8(data: bytes) -> bytes:
    import pyppmd

    encoder = pyppmd.Ppmd8Encoder(6, 1 << 20, 0)
    return encoder.encode(data) + encoder.flush(True)


_PROBED: dict[str, tuple[Codec, Callable[[bytes], bytes]]] = {
    **CODECS,
    "bzip3": (Codec.BZIP3, _bzip3),
    "ppmd": (Codec.PPMD, _ppmd8),
}


def _probed_prefix(
    data: bytes, codec: Codec, size: int, config: StreamConfig
) -> tuple[int, str | None]:
    params = CodecParams()
    if codec is Codec.PPMD:
        params = CodecParams(ppmd_order=6, ppmd_mem_size=1 << 20, pack_size=len(data))
    got = 0
    with open_codec_stream(
        codec, io.BytesIO(data), config=config, params=params
    ) as stream:
        try:
            while chunk := stream.read(size):
                got += len(chunk)
        except ArchiveyError as exc:
            return got, type(exc).__name__
    return got, None


@pytest.mark.parametrize(
    "name",
    [
        *CODECS,
        pytest.param("bzip3", marks=requires("bz3")),
        pytest.param("ppmd", marks=requires("pyppmd")),
    ],
)
def test_probes_find_the_byte_one_byte_calls_find(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The re-decode searches for the failing byte with probes of many bytes; it hands
    back exactly the bytes a decode asking for one byte per call hands back, wherever
    the damage falls in the read."""
    from archivey.internal.streams import decompressor_stream

    codec, compress = _PROBED[name]
    # In process: one-byte calls to a child process take about 2 ms each.
    config = replace(_CONFIG, process_isolation=ProcessIsolation.NONE)
    packed = compress(PAYLOAD[:400_000])
    rng = random.Random(name)
    real_probe = decompressor_stream._redecode_probe
    for _ in range(4):
        at = rng.randrange(len(packed) // 10, len(packed) - 100)
        damaged = packed[:at] + rng.randbytes(16) + packed[at + 16 :]
        for size in (4096, 65536):
            monkeypatch.setattr(decompressor_stream, "_redecode_probe", real_probe)
            probed = _probed_prefix(damaged, codec, size, config)
            assert probed[1] is not None, "the damage must surface as an error"
            monkeypatch.setattr(decompressor_stream, "_redecode_probe", lambda *_: 1)
            assert probed == _probed_prefix(damaged, codec, size, config), (at, size)


def test_a_large_read_finds_the_failing_byte_in_few_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 1 MiB read that meets damage far into the read does not ask for one byte per
    call up to it: the probes take a few restarts and a few thousand calls. One byte
    per call cost about 1 µs each in process and 0.1 to 2 ms each to a child process
    (PPMd, bzip3)."""
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    counts = {"restarts": 0, "calls": 0}
    restart, step = (
        DecompressorStream._redecode_restart,
        DecompressorStream._redecode_step,
    )

    def counting_restart(self: Any, *args: Any) -> Any:
        counts["restarts"] += 1
        return restart(self, *args)

    def counting_step(self: Any, *args: Any) -> Any:
        counts["calls"] += 1
        return step(self, *args)

    monkeypatch.setattr(DecompressorStream, "_redecode_restart", counting_restart)
    monkeypatch.setattr(DecompressorStream, "_redecode_step", counting_step)
    codec, compress = CODECS["xz"]
    damaged = _damage(compress(PAYLOAD), 0.5)
    got, error = _prefix(io.BytesIO(damaged), codec, 1 << 20)
    assert error is not None
    assert got % (1 << 20) > 100_000, "the damage must be far into the read"
    assert counts["restarts"] <= 8
    assert counts["calls"] <= 4096


_NO_RECOVERY = replace(_CONFIG, recover_partial_data=False)


@pytest.mark.parametrize("name", list(CODECS))
def test_recovery_off_does_not_decode_again(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``recover_partial_data=False``: the read that meets the damage raises the same
    error with no second decode, and the bytes the failing decoder call gave before
    it are lost."""
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    codec, compress = CODECS[name]
    damaged = _damage(compress(PAYLOAD), 0.5)
    recovered = _prefix(io.BytesIO(damaged), codec, 1 << 20)
    restarts = 0
    real = DecompressorStream._redecode_restart

    def counting(self: Any, *args: Any) -> Any:
        nonlocal restarts
        restarts += 1
        return real(self, *args)

    monkeypatch.setattr(DecompressorStream, "_redecode_restart", counting)
    got, error = _prefix(io.BytesIO(damaged), codec, 1 << 20, _NO_RECOVERY)
    assert restarts == 0
    assert error == recovered[1]
    # The calls before the failing one still come back; the failing call's are lost.
    # bzip2 and zstd fail at a block or frame start, where that call gave nothing.
    assert recovered[0] - (1 << 20) <= got <= recovered[0]
    if name in ("gzip", "xz"):
        assert got < recovered[0]


def test_recovery_off_takes_no_deflate_copy_on_a_pipe() -> None:
    """On a pipe the deflate decoder keeps the bytes before an error by copying its
    state before each call; with recovery off it takes no copy, so the failing call's
    bytes are lost there too."""
    damaged = _damage(gzip.compress(PAYLOAD, mtime=0), 0.5)
    kept = _prefix(NonSeekableBytesIO(damaged), Codec.GZIP, 1 << 20)
    lost = _prefix(NonSeekableBytesIO(damaged), Codec.GZIP, 1 << 20, _NO_RECOVERY)
    assert lost[1] == kept[1] is not None
    assert lost[0] < kept[0]
