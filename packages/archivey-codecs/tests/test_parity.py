"""Differential tests: every Rust kernel against the pure-Python decoder it replaces.

Same input, same output bytes; on damage, the same error kind and the same message.
Run from the archivey checkout with archivey-codecs installed:
``uv run pytest packages/archivey-codecs/tests``.
"""

from __future__ import annotations

import gc
import io
import os
import random
import sys
import weakref
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))

if os.environ.get("CODECS_REQUIRED") == "1":
    import archivey_codecs  # CI: a missing build must fail, not skip
else:
    archivey_codecs = pytest.importorskip("archivey_codecs")

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.lha_reader import crc16 as lha_crc16
from archivey.internal.backends.zipcrypto import ZipCryptoKeys
from archivey.internal.streams.codecs.arm64_filter import arm64_decode
from archivey.internal.streams.codecs.bcj2_filter import Bcj2DecoderStream
from archivey.internal.streams.codecs.lzo_decoder import (
    LzoError,
    lzo1x_decompress_python,
)
from archivey.internal.streams.codecs.lzx_decoder import LzxDecoder
from archivey.internal.streams.codecs.riscv_filter import riscv_decode

SEEDS = int(os.environ.get("CODECS_PARITY_CASES", "300"))


def outcome(fn: Callable[[], object]) -> tuple[str, object]:
    """What ``fn`` returned, or the kind and message of what it raised."""
    try:
        return ("ok", fn())
    except (TruncatedError, archivey_codecs.TruncatedDataError) as exc:
        return ("truncated", str(exc))
    except (CorruptionError, archivey_codecs.CorruptDataError, LzoError) as exc:
        return ("corrupt", str(exc))
    except (UnsupportedFeatureError, archivey_codecs.UnsupportedDataError) as exc:
        return ("unsupported", str(exc))
    except (IndexError, ValueError) as exc:
        return (type(exc).__name__, str(exc))


def sample_data(rng: random.Random, size: int) -> bytes:
    """Compressible bytes: runs, repeats and some noise."""
    words = [rng.randbytes(rng.randint(1, 12)) for _ in range(40)]
    out = bytearray()
    while len(out) < size:
        pick = rng.random()
        if pick < 0.6:
            out += rng.choice(words)
        elif pick < 0.8:
            out += bytes([rng.randrange(256)]) * rng.randint(1, 300)
        else:
            out += rng.randbytes(rng.randint(1, 64))
    return bytes(out[:size])


def damage(rng: random.Random, data: bytes) -> bytes:
    if not data:
        return data
    buf = bytearray(data)
    kind = rng.random()
    if kind < 0.4:
        for _ in range(rng.randint(1, 4)):
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
    elif kind < 0.7:
        del buf[rng.randrange(len(buf)) :]
    else:
        at = rng.randrange(len(buf))
        buf[at:at] = rng.randbytes(rng.randint(1, 8))
    return bytes(buf)


# ── LZO1X ──────────────────────────────────────────────────────────────────────────


def _lzo_compressor() -> Callable[[bytes, int], bytes]:
    """An LZO1X compressor: python-lzo, else compress-utils when its build can
    compress LZO1X (0.12.1's wheels decode it only); the test skips without either."""
    try:
        import lzo

        return lambda data, level: lzo.compress(data, level, False)
    except ImportError:
        pass
    try:
        import compress_utils

        compress_utils.compress(b"probe", "lzo", 1)
    except Exception:  # noqa: BLE001 - not installed, or built without LZO1X
        pytest.skip("no LZO1X compressor: install python-lzo")
    return lambda data, level: compress_utils.compress(data, "lzo", level)


def test_lzo_parity() -> None:
    compress = _lzo_compressor()
    rng = random.Random(1)
    for case in range(SEEDS):
        data = sample_data(rng, rng.randint(0, 200_000))
        block = compress(data, rng.choice((1, 9)))
        if case % 2:
            block = damage(rng, block)
        limit = rng.choice((len(data), len(data) // 2 + 1, 1 << 20))
        assert lzo_python(block, limit) == lzo_rust(block, limit), case
    for case in range(SEEDS):
        block = rng.randbytes(rng.randint(0, 64))
        assert lzo_python(block, 4096) == lzo_rust(block, 4096), case


def lzo_python(block: bytes, out_size: int) -> tuple[str, object]:
    """The Python twin with ``lzo1x.decompress``'s exact ``out_size``: a block that
    decodes to fewer bytes is damage."""
    got = outcome(lambda: lzo1x_decompress_python(block, out_size))
    if got[0] == "ok" and len(got[1]) != out_size:  # type: ignore[arg-type]
        return ("corrupt", f"the block decodes to {len(got[1])} bytes, not {out_size}")  # type: ignore[arg-type]
    return got


def lzo_rust(block: bytes, out_size: int) -> tuple[str, object]:
    return outcome(lambda: archivey_codecs.lzo1x.decompress(block, out_size=out_size))


# ── Branch filters ─────────────────────────────────────────────────────────────────


def filter_input(rng: random.Random, size: int, hot: bytes) -> bytes:
    """Random bytes thick with the bytes that start a converted instruction."""
    return bytes(
        rng.choice(hot) if rng.random() < 0.3 else rng.randrange(256)
        for _ in range(size)
    )


def filter_chunks(data: bytes, rng: random.Random) -> list[bytes]:
    cuts = sorted(rng.randrange(len(data) + 1) for _ in range(rng.randint(0, 6)))
    return [data[a:b] for a, b in zip([0, *cuts], [*cuts, len(data)], strict=True)]


def filter_python(decode: Callable, data: bytes, pc: int, rng: random.Random) -> list:
    """archivey's own streaming filter decoder, fed the same chunks."""
    from archivey.internal.streams.codecs.lzma_filter_decoder import (
        PythonBranchFilterDecoder,
    )

    state = rng.getstate()
    decoder = PythonBranchFilterDecoder(
        decode=decode, start_offset=pc, unpack_size=len(data)
    )
    out = [decoder.feed(chunk).data for chunk in filter_chunks(data, rng)]
    out.append(decoder.flush().data)
    rng.setstate(state)
    return out


def filter_rust(make: Callable, data: bytes, pc: int, rng: random.Random) -> list:
    decoder = make(pc)
    out = [decoder.decode(chunk) for chunk in filter_chunks(data, rng)]
    out.append(decoder.flush())
    assert decoder.total_in == len(data)
    assert decoder.total_out == len(data)
    return out


def test_arm64_parity() -> None:
    rng = random.Random(2)
    hot = bytes([0x94, 0x95, 0x96, 0x97, 0x90, 0xB0, 0xD0, 0xF0])
    for _ in range(SEEDS):
        data = filter_input(rng, rng.randint(0, 5000), hot)
        pc = rng.choice((0, 4 * rng.randrange(1 << 20), (1 << 32) - 4, 1 << 40))
        assert filter_python(arm64_decode, data, pc, rng) == filter_rust(
            archivey_codecs.filters.Arm64Decoder, data, pc, rng
        )


def test_riscv_parity() -> None:
    rng = random.Random(3)
    hot = bytes([0xEF, 0x17, 0x97, 0x13, 0x67])
    for _ in range(SEEDS):
        data = filter_input(rng, rng.randint(0, 5000), hot)
        pc = rng.choice((0, 2 * rng.randrange(1 << 20), (1 << 32) - 2))
        assert filter_python(riscv_decode, data, pc, rng) == filter_rust(
            archivey_codecs.filters.RiscvDecoder, data, pc, rng
        )


# ── CRC-16 ─────────────────────────────────────────────────────────────────────────


def test_crc16_parity() -> None:
    rng = random.Random(7)
    for _ in range(SEEDS // 3):
        data = rng.randbytes(rng.randint(0, 5000))
        start = rng.randrange(1 << 16)
        assert lha_crc16(data, start) == archivey_codecs.crc16_arc(data, start)
        running = archivey_codecs.Crc16Arc()
        expected = 0
        for chunk in filter_chunks(data, rng):
            running.update(chunk)
            expected = lha_crc16(chunk, expected)
        assert running.digest() == expected.to_bytes(2, "big")


# ── ZipCrypto ──────────────────────────────────────────────────────────────────────


def test_zipcrypto_parity() -> None:
    rng = random.Random(4)
    for _ in range(SEEDS // 3):
        password = rng.randbytes(rng.randint(0, 40))
        py = ZipCryptoKeys(password)
        rs = archivey_codecs.zipcrypto.Decryptor(password)
        for _ in range(rng.randint(1, 5)):
            chunk = rng.randbytes(rng.randint(0, 40_000))
            assert py.decrypt(chunk) == rs.decrypt(bytearray(chunk))
        clone = rs.copy()
        assert clone.decrypt(b"abc") == rs.decrypt(b"abc")


# ── LZX ────────────────────────────────────────────────────────────────────────────


def lzx_python(chunks: list[bytes], sizes: list[int], window: int):
    """The Python decoder's output for every frame, and how it stopped."""
    feed = iter(chunks)
    out = bytearray()
    try:
        decoder = LzxDecoder(window, lambda: next(feed, None))
        for size in sizes:
            out += decoder.decode_frame(size)
    except Exception as exc:  # noqa: BLE001
        return bytes(out), outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return bytes(out), ("ok", None)


def lzx_rust(
    chunks: list[bytes], output_size: int, window: int, rng: random.Random
) -> tuple[bytes, tuple[str, object]]:
    """The push decoder's output, fed ``chunks`` in random pieces with random
    ``max_length`` caps, saved and restored (or copied) at random points."""
    lzx = archivey_codecs.lzx
    out = bytearray()
    data = b"".join(chunks)
    try:
        d = lzx.Decompressor(window, output_size=output_size)
    except Exception as exc:  # noqa: BLE001
        return b"", outcome(lambda e=exc: (_ for _ in ()).throw(e))
    at = 0

    def step() -> None:
        nonlocal d, at
        cap = rng.choice((-1, -1, 1, 5000, 40_000))
        if at < len(data) and (d.needs_input or rng.random() < 0.3):
            n = rng.choice((1, 100, 5000, 40_000, len(data)))
            piece, at = data[at : at + n], at + n
            out.extend(d.decompress(piece, cap))
        else:
            out.extend(d.decompress(b"", cap))
        pick = rng.random()
        if pick < 0.1:
            restored = lzx.Decompressor.from_state(d.getstate())
            assert restored.total_out == d.total_out
            assert restored.total_in == d.total_in
            at = d.total_in
            d = restored
        elif pick < 0.15:
            d = d.copy()

    try:
        for _ in range(10_000):
            if d.eof or (at >= len(data) and d.needs_input):
                break
            step()
        while not d.eof:
            got = d.flush(rng.choice((-1, 1, 7000)))
            out += got
            if not got:
                break
            if not d.eof and rng.random() < 0.3:
                # Saved during flush(): the restored decoder is not flushed, so it
                # takes the input from its total_in again, then flushes on.
                restored = lzx.Decompressor.from_state(d.getstate())
                assert restored.total_out == d.total_out
                assert restored.total_in == d.total_in
                assert restored.decompress(data[restored.total_in :], 0) == b""
                d = restored
    except Exception as exc:  # noqa: BLE001
        return bytes(out), outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return bytes(out), ("ok", None)


def lzx_streams(rng: random.Random):
    from cab_util import FRAME, LzxEncoder

    layouts = [
        ("verbatim",),
        ("aligned",),
        ("uncompressed",),
        ("verbatim", "uncompressed", "aligned"),
    ]
    for case in range(max(8, SEEDS // 10)):
        window = rng.choice((15, 16, 17, 21))
        size = rng.randint(1, 5 * FRAME)
        data = sample_data(rng, size)
        if case % 3 == 0:
            # x86-looking code, for the E8 translation.
            data = bytes(b if rng.random() > 0.05 else 0xE8 for b in data)
        enc = LzxEncoder(
            window_bits=window,
            blocks=rng.choice(layouts),
            block_size=rng.choice((FRAME, 10_000, 70_000)),
            e8_file_size=rng.choice((0, 0, size, 12_000_000)),
        )
        frames = enc.encode(data)
        sizes = [min(FRAME, size - i) for i in range(0, size, FRAME)]
        yield case, window, frames, sizes, data


def test_lzx_eof_counts_stop_where_the_stream_does() -> None:
    """At ``eof``, ``total_in`` and ``unused_data`` split the input where the LZX
    stream ends: words the bit buffer fetched ahead belong to what follows."""
    from cab_util import LzxEncoder

    rng = random.Random(11)
    for blocks in (("verbatim",), ("aligned",), ("uncompressed",)):
        for size in (1, 100, 5000, 40_000):
            data = sample_data(rng, size)
            stream = b"".join(LzxEncoder(window_bits=15, blocks=blocks).encode(data))
            for cap in (-1, 1):
                d = archivey_codecs.lzx.Decompressor(15, output_size=size)
                out = bytearray(d.decompress(stream + b"appendix", cap))
                while not d.eof:
                    out += d.flush(cap)
                assert out == data, (blocks, size)
                assert d.unused_data == b"appendix", (blocks, size, d.unused_data)
                assert d.total_in == len(stream), (blocks, size)
                # Restored at eof, it ends where this one does, with nothing after.
                r = archivey_codecs.lzx.Decompressor.from_state(d.getstate())
                assert r.eof
                assert r.total_in == len(stream)
                assert r.unused_data == b""


def test_lzx_owed_pad_byte_in_a_later_call() -> None:
    """An odd final uncompressed block owes a pad byte: fed in a later call, it still
    belongs to the stream, so the split matches the one-call decode; with no more
    input, ``flush()`` ends the stream without it."""
    from cab_util import LzxEncoder

    stream = b"".join(
        LzxEncoder(window_bits=15, blocks=("uncompressed",)).encode(b"hello")
    )
    lzx = archivey_codecs.lzx
    whole = lzx.Decompressor(15, output_size=5)
    assert whole.decompress(stream + b"trailer") == b"hello"
    assert (whole.total_in, whole.unused_data) == (len(stream), b"trailer")
    d = lzx.Decompressor(15, output_size=5)
    assert d.decompress(stream[:-1]) == b"hello"
    assert not d.eof
    assert d.needs_input
    r = lzx.Decompressor.from_state(d.getstate())
    for dec in (d, r):
        assert dec.decompress(stream[dec.total_in :] + b"trailer") == b""
        assert dec.eof
        assert (dec.total_in, dec.unused_data) == (len(stream), b"trailer")
    cut = lzx.Decompressor(15, output_size=5)
    assert cut.decompress(stream[:-1]) == b"hello"
    assert cut.flush() == b""
    assert cut.eof
    assert (cut.total_in, cut.unused_data) == (len(stream) - 1, b"")


def test_lzx_parity_clean_and_damaged() -> None:
    rng = random.Random(5)
    for case, window, frames, sizes, data in lzx_streams(rng):
        py = lzx_python(frames, sizes, window)
        rs = lzx_rust(frames, sum(sizes), window, rng)
        assert py == (data, ("ok", None)), case
        assert rs == py, case
        for trial in range(6):
            bad = list(frames)
            k = rng.randrange(len(bad))
            bad[k] = damage(rng, bad[k])
            if trial % 3 == 0:
                bad = bad[: rng.randrange(len(bad) + 1)]
            py = lzx_python(bad, sizes, window)
            rs = lzx_rust(bad, sum(sizes), window, rng)
            # The push decoder stops at the declared size; the Python decoder does
            # too, so what follows the last frame is not compared.
            assert py == rs, (case, trial)


def test_lzx_short_e8_last_frame_in_one_byte_slices() -> None:
    """A short last frame with E8 translation on, fed and read one byte at a time:
    the translation must see the frame's real length, not a full frame."""
    from cab_util import FRAME, LzxEncoder

    rng = random.Random(9)
    size = FRAME + 700
    data = bytes(0xE8 if i % 9 == 0 else rng.randrange(256) for i in range(size))
    frames = LzxEncoder(window_bits=16, e8_file_size=size).encode(data)
    stream = b"".join(frames)
    assert lzx_python(frames, [FRAME, 700], 16) == (data, ("ok", None))
    d = archivey_codecs.lzx.Decompressor(16, output_size=size)
    out = bytearray()
    for i in range(len(stream)):
        out += d.decompress(stream[i : i + 1], 1)
    while not d.eof:
        got = d.flush(1)
        if not got:
            break
        out += got
    assert bytes(out) == data


def test_lzx_random_input() -> None:
    rng = random.Random(6)
    for case in range(SEEDS):
        window = rng.randint(14, 22)
        chunks = [rng.randbytes(rng.randint(0, 3000)) for _ in range(rng.randint(0, 3))]
        sizes = [32768] * rng.randint(0, 3) + [rng.randint(1, 32768)]
        py = lzx_python(chunks, sizes, window)
        rs = lzx_rust(chunks, sum(sizes), window, rng)
        assert py == rs, case


# ── BCJ2 ───────────────────────────────────────────────────────────────────────────


def bcj2_python(streams: tuple[bytes, ...], size: int):
    """The Python stream's output, with the bytes decoded before an error."""
    stream = Bcj2DecoderStream(*(io.BytesIO(s) for s in streams), unpack_size=size)
    try:
        return stream.read(size), ("ok", None)
    except Exception as exc:  # noqa: BLE001
        partial = bytes(stream._pending)
        return partial, outcome(lambda e=exc: (_ for _ in ()).throw(e))


def bcj2_rust(streams: tuple[bytes, ...], size: int, rng: random.Random):
    """The Rust decoder's output, read in random amounts and saved and restored (onto
    new streams placed at ``total_in``) at random points."""
    bcj2 = archivey_codecs.bcj2
    out = bytearray()
    try:
        d = bcj2.Decompressor(*(io.BytesIO(s) for s in streams), out_size=size)
        for _ in range(100_000):
            if d.eof:
                break
            out += d.read(rng.choice((1, 7, 4096, 70_000, -1)))
            if rng.random() < 0.1:
                try:
                    state = d.getstate()
                except ValueError:
                    continue  # an error waits for the next read()
                total_in, total_out = d.total_in, d.total_out
                fresh = [io.BytesIO(s) for s in streams]
                for f, at in zip(fresh, total_in, strict=True):
                    f.seek(at)
                d = bcj2.Decompressor.from_state(state, *fresh)
                assert (d.total_in, d.total_out) == (total_in, total_out)
    except Exception as exc:  # noqa: BLE001
        return bytes(out), outcome(lambda e=exc: (_ for _ in ()).throw(e))
    assert d.read() == b""
    return bytes(out), ("ok", None)


class _RangeEncoder:
    """LZMA's range encoder, with the probability model BCJ2 decodes with."""

    def __init__(self) -> None:
        self.low, self.range, self.cache, self.cache_size = 0, 0xFFFFFFFF, 0, 1
        self.out = bytearray()
        self.probs = [1024] * 258

    def _shift_low(self) -> None:
        if self.low < 0xFF000000 or self.low > 0xFFFFFFFF:
            carry, temp = self.low >> 32, self.cache
            while True:
                self.out.append((temp + carry) & 0xFF)
                temp = 0xFF
                self.cache_size -= 1
                if self.cache_size == 0:
                    break
            self.cache = (self.low >> 24) & 0xFF
        self.cache_size += 1
        self.low = (self.low & 0x00FFFFFF) << 8

    def bit(self, context: int, bit: bool) -> None:
        p = self.probs[context]
        bound = (self.range >> 11) * p
        if bit:
            self.low += bound
            self.range -= bound
            self.probs[context] = p - (p >> 5)
        else:
            self.range = bound
            self.probs[context] = p + ((2048 - p) >> 5)
        while self.range < 1 << 24:
            self.range <<= 8
            self._shift_low()

    def finish(self) -> bytes:
        for _ in range(5):
            self._shift_low()
        return bytes(self.out)


def bcj2_encode(rng: random.Random, size: int) -> tuple[bytes, ...]:
    """Valid BCJ2 streams for ``size`` bytes of x86-looking output, with random
    convert decisions and targets: the four streams end where the decoder stops."""
    main, call, jump = bytearray(), bytearray(), bytearray()
    enc = _RangeEncoder()
    out_len, prev = 0, 0
    while out_len < size:
        b = (
            rng.choice(b"\xe8\xe9\x0f\x85")
            if rng.random() < 0.2
            else rng.randrange(256)
        )
        main.append(b)
        out_len += 1
        candidate = b in (0xE8, 0xE9) or (b & 0xF0 == 0x80 and prev == 0x0F)
        if not candidate or out_len == size:
            prev = b
            continue
        context = prev if b == 0xE8 else 256 if b == 0xE9 else 257
        convert = rng.random() < 0.5
        enc.bit(context, convert)
        if not convert:
            prev = b
            continue
        target = rng.getrandbits(32)
        dest = (target - (out_len + 4)) & 0xFFFFFFFF
        (call if b == 0xE8 else jump).extend(target.to_bytes(4, "big"))
        out_len = min(size, out_len + 4)
        prev = dest >> 24
    return bytes(main), bytes(call), bytes(jump), enc.finish()


def test_bcj2_parity() -> None:
    rng = random.Random(8)
    clean = 0
    for case in range(max(20, SEEDS // 5)):
        size = rng.randint(0, 200_000)
        if case % 2 == 0:
            # Valid streams, then one of: untouched, a stream cut short, a stream
            # with bytes added, or a changed range coder byte.
            streams = list(bcj2_encode(rng, size))
            out_size = size
            which, how = rng.randrange(4), rng.randrange(4)
            s = streams[which]
            if how == 1 and s:
                streams[which] = s[: rng.randrange(len(s))]
            elif how == 2:
                streams[which] = s + rng.randbytes(rng.randint(1, 5))
            elif how == 3 and len(streams[3]) > 5:
                k = rng.randrange(5, len(streams[3]))
                rc = bytearray(streams[3])
                rc[k] ^= 1 << rng.randrange(8)
                streams[3] = bytes(rc)
            streams = tuple(streams)
        else:
            main = bytes(
                rng.choice(b"\xe8\xe9\x0f\x85\x80")
                if rng.random() < 0.2
                else rng.randrange(256)
                for _ in range(size)
            )
            call = rng.randbytes(rng.randint(0, 4000) * 4 + rng.choice((0, 0, 1, 3)))
            jump = rng.randbytes(rng.randint(0, 4000) * 4)
            rc = b"\0" + rng.randbytes(rng.randint(0, 20_000))
            if case % 4 == 1:
                rc = rng.randbytes(rng.randint(0, 6))
            elif case % 4 == 3:
                # A start 7-Zip refuses: a non-zero first byte, five bytes or more.
                rc = bytes([rng.randint(1, 255)]) + rng.randbytes(rng.randint(4, 50))
            out_size = rng.choice((size, size + 1000, max(0, size - 50), size * 2))
            streams = (main, call, jump, rc)
        py = bcj2_python(streams, out_size)
        clean += py[1] == ("ok", None)
        assert bcj2_rust(streams, out_size, rng) == py, case
    # The success path (all four streams used up exactly) must be compared too.
    assert clean >= 3, clean


def test_bcj2_clean_decode_matches() -> None:
    """Valid streams decode to the same bytes on both sides, the first bit of the
    range coder a convert (the start 7-Zip writes when the first branch converts)."""
    rc_convert = b"\x00" + b"\xff" * 3 + b"\xfe"
    streams = (b"\xe8", (0x12345678).to_bytes(4, "big"), b"", rc_convert)
    py = bcj2_python(streams, 5)
    assert py[1] == ("ok", None)
    assert bcj2_rust(streams, 5, random.Random(0)) == py


# ── Unix compress (.Z) LZW ─────────────────────────────────────────────────────────


def pack_lzw(
    rng: random.Random, max_width: int, block_mode: bool, widen9: bool, n: int
) -> bytes:
    """A .Z stream of ``n`` random codes that a decoder can follow: valid codes, with
    CLEARs, width increases and the writer's group padding. Not compressed data."""
    out = bytearray([0x1F, 0x9D, (0x80 if block_mode else 0) | max_width])
    width, next_code, prev = 9, (257 if block_mode else 256), None
    era: list[int] = []

    def flush_era(pad: bool) -> None:
        acc = nbits = 0
        chunk = bytearray()
        for code in era:
            acc |= code << nbits
            nbits += width
            while nbits >= 8:
                chunk.append(acc & 0xFF)
                acc >>= 8
                nbits -= 8
        if nbits:
            chunk.append(acc & 0xFF)
        if pad:
            chunk += bytes(-len(chunk) % width)
        out.extend(chunk)
        era.clear()

    for _ in range(n):
        if block_mode and prev is not None and rng.random() < 0.002:
            era.append(256)
            flush_era(True)
            width, next_code, prev = 9, 257, None
            continue
        if prev is None:
            code = rng.randrange(256)
        else:
            code = rng.randrange(
                min(
                    next_code + 1,
                    1 << width,
                    512 if width == 10 and max_width == 9 else 1 << 16,
                )
            )
            if block_mode and code == 256:
                code = 255
        era.append(code)
        mask = (1 << width) - 1
        if prev is not None and next_code <= mask:
            next_code += 1
        prev = code
        if next_code > mask and width < max_width:
            flush_era(True)
            width += 1
        elif max_width == 9 and widen9 and width == 9 and next_code > 511:
            flush_era(True)
            width = 10
    flush_era(False)
    return bytes(out)


def lzw_python(data: bytes, rng: random.Random, kwargs: dict):
    """The Python twin fed ``data`` in random chunks with random budgets: all output
    before the first error, the error, the end report and the CLEAR offsets (its
    segment sizes summed from the stream's start)."""
    from archivey.internal.streams.codecs.unix_compress_decoder import LzwState

    out = bytearray()
    offsets: list[tuple[int, int]] = []
    try:
        state = LzwState(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return ("init", type(exc).__name__)
    at = [0, 0]

    def note(units: list) -> None:
        if at == [0, 0] and not kwargs and state.header_params is not None:
            at[0] = 3
        for decomp, comp in units:
            at[0] += comp
            at[1] += decomp
            offsets.append(tuple(at))

    end: tuple = ("ok", None)
    try:
        pos = 0
        while pos < len(data):
            step = rng.randint(0, 3000)
            got, units = state.feed(data[pos : pos + step], rng.choice((-1, 0, 100)))
            out += got
            note(units)
            pos += step
        for _ in range(3):
            got, units = state.feed(b"", -1)
            out += got
            note(units)
        got, units = state.flush()
        out += got
        note(units)
    except Exception as exc:  # noqa: BLE001
        end = outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return (bytes(out), end, state.truncation, state.header_params, offsets)


def lzw_rust(data: bytes, rng: random.Random, kwargs: dict):
    """``lzw.Decompressor`` fed the same way, with random ``max_length`` caps that
    every call must keep, saved and restored (then fed from ``total_in``) at random
    points."""
    out = bytearray()
    offsets: list[tuple[int, int]] = []
    try:
        d = archivey_codecs.lzw.Decompressor(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return ("init", type(exc).__name__)

    def take(got: bytes, cap: int) -> None:
        assert cap < 0 or len(got) <= cap
        out.extend(got)
        offsets.extend(d.clear_offsets)

    end: tuple = ("ok", None)
    try:
        pos = 0
        while pos < len(data):
            step = rng.randint(0, 3000)
            cap = rng.choice((-1, 0, 1, 100, 5000))
            take(d.decompress(memoryview(data[pos : pos + step]), cap), cap)
            pos += step
            assert d.total_in <= pos
            if rng.random() < 0.1:
                try:
                    state = d.getstate()
                except ValueError:
                    continue  # an error waits for the next call
                totals = (d.total_in, d.total_out)
                d = archivey_codecs.lzw.Decompressor.from_state(state)
                assert (d.total_in, d.total_out) == totals
                pos = d.total_in
        while not d.needs_input:
            cap = rng.choice((-1, 1, 7000))
            take(d.decompress(b"", cap), cap)
        while not d.eof:
            cap = rng.choice((-1, 1, 7000))
            take(d.flush(cap), cap)
    except Exception as exc:  # noqa: BLE001
        end = outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return (bytes(out), end, d.truncation, d.header_params, offsets)


def test_lzw_parity() -> None:
    rng = random.Random(7)
    cases = []
    try:
        import ncompress

        for _ in range(20):
            raw = sample_data(rng, rng.randint(0, 300_000))
            buf = io.BytesIO()
            ncompress.compress(io.BytesIO(raw), buf)
            cases.append(buf.getvalue())
    except ImportError:
        pass
    for _ in range(SEEDS):
        cases.append(
            pack_lzw(
                rng,
                rng.choice((9, 9, 10, 12, 16)),
                rng.random() < 0.8,
                rng.random() < 0.5,
                rng.randint(0, 4000),
            )
        )
    for case, data in enumerate(cases):
        for variant in range(3):
            d = data if variant == 0 else damage(rng, data)
            kwargs: dict = {}
            if variant == 2 and len(d) > 3 and rng.random() < 0.5:
                kwargs = {
                    "max_width": max(9, d[2] & 0x1F),
                    "block_mode": bool(d[2] & 0x80),
                    "nine_bit_widens": rng.choice((None, True, False)),
                }
                if kwargs["max_width"] > 16:
                    continue
                d = d[3:]
            seed = rng.random()
            py = lzw_python(d, random.Random(seed), kwargs)
            rs = lzw_rust(d, random.Random(seed), kwargs)
            if py[0] != "init" and py[1][0] != "ok":
                # A step that fails drops its own CLEARs (both decoders), so on
                # damage which CLEARs are reported depends on how input is split: one
                # list is a prefix of the other.
                short, long = sorted((py[4], rs[4]), key=len)
                assert long[: len(short)] == short, (case, variant)
                py, rs = py[:4], rs[:4]
            assert py == rs, (case, variant)


# ── Bindings ───────────────────────────────────────────────────────────────────────


def test_callback_cycles_are_collected() -> None:
    """A decoder held by the object its input streams are bound to is freed by the
    garbage collector. (The LZX decoder takes pushed input, so it holds no callback.)"""

    class Bcj2Holder:
        def __init__(self) -> None:
            self.d = archivey_codecs.bcj2.Decompressor(
                self, self, self, self, out_size=1
            )

        def read(self, n: int) -> bytes:
            return b""

    class FailingBcj2Holder(Bcj2Holder):
        """Its streams raise, so the decoder keeps the error, whose traceback holds
        the frame that holds this object."""

        def read(self, n: int) -> bytes:
            raise OSError("disk gone")

    def fail_once() -> weakref.ref:
        holder = FailingBcj2Holder()
        with pytest.raises(OSError):
            holder.d.read()
        return weakref.ref(holder)

    for make in (Bcj2Holder,):
        holder = make()
        ref = weakref.ref(holder)
        del holder
        gc.collect()
        assert ref() is None, make
    ref = fail_once()
    gc.collect()
    assert ref() is None, "a stored error kept the decoder alive"


def test_lzw_width_is_checked() -> None:
    with pytest.raises(ValueError, match="outside 9 to 16"):
        archivey_codecs.lzw.Decompressor(max_width=30, block_mode=True)
    with pytest.raises(ValueError, match="give block_mode with max_width"):
        archivey_codecs.lzw.Decompressor(max_width=12)
    # As in the Python twin, a lone block_mode is ignored: the header decides.
    from archivey.internal.streams.codecs.unix_compress_decoder import LzwState

    header = b"\x1f\x9d\x90"  # 16 bits, block mode
    py = LzwState(block_mode=False)
    py.feed(header)
    rs = archivey_codecs.lzw.Decompressor(block_mode=False)
    rs.decompress(header)
    assert py.header_params == rs.header_params == (16, True)
