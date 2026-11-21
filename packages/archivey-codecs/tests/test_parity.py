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


def lzx_frames(make: Callable, chunks: list[bytes], sizes: list[int], window: int):
    """Decode every frame with ``make``'s decoder; stop at the first error."""
    feed = iter(chunks)
    out: list[object] = []
    try:
        decoder = make(window, lambda: next(feed, None))
    except Exception as exc:  # noqa: BLE001
        return [outcome(lambda e=exc: (_ for _ in ()).throw(e))]
    for size in sizes:
        got = outcome(lambda s=size: decoder.decode_frame(s))
        out.append(got)
        if got[0] != "ok":
            break
    return out


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
        yield case, window, frames, sizes


def test_lzx_parity_clean_and_damaged() -> None:
    import archivey_codecs as n

    rng = random.Random(5)
    for case, window, frames, sizes in lzx_streams(rng):
        py = lzx_frames(LzxDecoder, frames, sizes, window)
        rs = lzx_frames(n._codecs._LzxFrameDecoder, frames, sizes, window)
        assert py == rs, case
        assert all(kind == "ok" for kind, _ in py), case
        for trial in range(6):
            bad = list(frames)
            k = rng.randrange(len(bad))
            bad[k] = damage(rng, bad[k])
            if trial % 3 == 0:
                bad = bad[: rng.randrange(len(bad) + 1)]
            py = lzx_frames(LzxDecoder, bad, sizes, window)
            rs = lzx_frames(n._codecs._LzxFrameDecoder, bad, sizes, window)
            assert py == rs, (case, trial)


def test_lzx_random_input() -> None:
    import archivey_codecs as n

    rng = random.Random(6)
    for case in range(SEEDS):
        window = rng.randint(14, 22)
        chunks = [rng.randbytes(rng.randint(0, 3000)) for _ in range(rng.randint(0, 3))]
        sizes = [32768] * rng.randint(1, 3) + [rng.randint(-1, 40000)]
        py = lzx_frames(LzxDecoder, chunks, sizes, window)
        rs = lzx_frames(n._codecs._LzxFrameDecoder, chunks, sizes, window)
        assert py == rs, case


def test_lzx_callback_error_passes_through() -> None:
    import archivey_codecs as n

    class Boom(Exception):
        pass

    def more() -> bytes:
        raise Boom

    with pytest.raises(Boom):
        n._codecs._LzxFrameDecoder(16, more).decode_frame(32768)


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
    every call must keep."""
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


# ── BCJ2 ───────────────────────────────────────────────────────────────────────────


def bcj2_python(streams: tuple[bytes, ...], size: int):
    """The Python stream's output, with the bytes decoded before an error."""
    from archivey.internal.streams.codecs.bcj2_filter import Bcj2DecoderStream

    stream = Bcj2DecoderStream(*(io.BytesIO(s) for s in streams), unpack_size=size)
    try:
        return stream.read(size), ("ok", None)
    except Exception as exc:  # noqa: BLE001
        partial = bytes(stream._pending)
        return partial, outcome(lambda e=exc: (_ for _ in ()).throw(e))


def bcj2_rust(streams: tuple[bytes, ...], size: int):
    """``Bcj2Core`` driven as the Python stream drives its own loop."""
    core = archivey_codecs._codecs._Bcj2Core(*(io.BytesIO(s).read for s in streams))
    out = bytearray()
    try:
        while len(out) < size:
            out += core.decode_block(size - len(out))
        core.check_inputs_finished()
    except Exception as exc:  # noqa: BLE001
        out += core.take_partial()
        return bytes(out), outcome(lambda e=exc: (_ for _ in ()).throw(e))
    return bytes(out), ("ok", None)


def test_bcj2_parity() -> None:
    rng = random.Random(8)
    for case in range(max(20, SEEDS // 5)):
        size = rng.randint(0, 200_000)
        main = bytes(
            rng.choice(b"\xe8\xe9\x0f\x85\x80")
            if rng.random() < 0.2
            else rng.randrange(256)
            for _ in range(size)
        )
        call = rng.randbytes(rng.randint(0, 4000) * 4 + rng.choice((0, 0, 1, 3)))
        jump = rng.randbytes(rng.randint(0, 4000) * 4)
        rc = b"\0" + rng.randbytes(rng.randint(0, 20_000))
        if case % 4 == 0:
            rc = rng.randbytes(rng.randint(0, 6))
        out_size = rng.choice((size, size + 1000, max(0, size - 50), size * 2))
        streams = (main, call, jump, rc)
        assert bcj2_rust(streams, out_size) == bcj2_python(streams, out_size), case


# ── Bindings ───────────────────────────────────────────────────────────────────────


def test_callback_cycles_are_collected() -> None:
    """A decoder held by the object its input callback is bound to, as the CAB reader
    holds its LZX decoder, is freed by the garbage collector."""

    class LzxHolder:
        def __init__(self) -> None:
            self.d = archivey_codecs._codecs._LzxFrameDecoder(21, self.more)

        def more(self) -> None:
            return None

    class Bcj2Holder:
        def __init__(self) -> None:
            self.d = archivey_codecs._codecs._Bcj2Core(
                self.read, self.read, self.read, self.read
            )

        def read(self, n: int) -> bytes:
            return b""

    for make in (LzxHolder, Bcj2Holder):
        holder = make()
        ref = weakref.ref(holder)
        del holder
        gc.collect()
        assert ref() is None, make


def test_lzw_width_is_checked() -> None:
    with pytest.raises(ValueError, match="outside 9 to 16"):
        archivey_codecs.lzw.Decompressor(max_width=30, block_mode=True)
    with pytest.raises(ValueError, match="together"):
        archivey_codecs.lzw.Decompressor(max_width=12)
