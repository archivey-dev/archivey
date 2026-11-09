"""Differential tests: every Rust kernel against the pure-Python decoder it replaces.

Same input, same output bytes; on damage, the same error kind and the same message.
Run from the archivey checkout with the native package installed:
``uv run pytest packages/archivey-native/tests``.
"""

from __future__ import annotations

import os
import random
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))

archivey_native = pytest.importorskip("archivey_native")

from archivey.exceptions import (  # noqa: E402
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.zipcrypto import ZipCryptoKeys  # noqa: E402
from archivey.internal.streams.codecs.arm64_filter import arm64_decode  # noqa: E402
from archivey.internal.streams.codecs.lzo_decoder import (  # noqa: E402
    LzoError,
    lzo1x_decompress_python,
)
from archivey.internal.streams.codecs.lzx_decoder import LzxDecoder  # noqa: E402
from archivey.internal.streams.codecs.riscv_filter import riscv_decode  # noqa: E402

SEEDS = int(os.environ.get("NATIVE_PARITY_CASES", "300"))


def outcome(fn: Callable[[], object]) -> tuple[str, object]:
    """What ``fn`` returned, or the kind and message of what it raised."""
    try:
        return ("ok", fn())
    except (TruncatedError, archivey_native.TruncatedData) as exc:
        return ("truncated", str(exc))
    except (CorruptionError, archivey_native.CorruptData, LzoError) as exc:
        return ("corrupt", str(exc))
    except (UnsupportedFeatureError, archivey_native.UnsupportedData) as exc:
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


def test_lzo_parity() -> None:
    lzo = pytest.importorskip("lzo")
    rng = random.Random(1)
    for case in range(SEEDS):
        data = sample_data(rng, rng.randint(0, 200_000))
        block = lzo.compress(data, rng.choice((1, 9)), False)
        if case % 2:
            block = damage(rng, block)
        limit = rng.choice((len(data), len(data) // 2 + 1, 1 << 20))
        py = outcome(lambda: lzo1x_decompress_python(block, limit))
        rs = outcome(lambda: archivey_native.lzo1x_decompress(block, limit))
        assert py == rs, (case, py[0], rs[0])
    for case in range(SEEDS):
        block = rng.randbytes(rng.randint(0, 64))
        py = outcome(lambda: lzo1x_decompress_python(block, 4096))
        rs = outcome(lambda: archivey_native.lzo1x_decompress(block, 4096))
        assert py == rs, case


# ── Branch filters ─────────────────────────────────────────────────────────────────


def filter_input(rng: random.Random, size: int, hot: bytes) -> bytes:
    """Random bytes thick with the bytes that start a converted instruction."""
    return bytes(
        rng.choice(hot) if rng.random() < 0.3 else rng.randrange(256)
        for _ in range(size)
    )


def test_arm64_parity() -> None:
    rng = random.Random(2)
    hot = bytes([0x94, 0x95, 0x96, 0x97, 0x90, 0xB0, 0xD0, 0xF0])
    for _ in range(SEEDS):
        data = filter_input(rng, rng.randint(0, 5000), hot)
        pc = rng.choice((0, 4 * rng.randrange(1 << 20), (1 << 32) - 4, 1 << 40))
        assert arm64_decode(data, pc) == archivey_native.arm64_decode(data, pc)


def test_riscv_parity() -> None:
    rng = random.Random(3)
    hot = bytes([0xEF, 0x17, 0x97, 0x13, 0x67])
    for _ in range(SEEDS):
        data = filter_input(rng, rng.randint(0, 5000), hot)
        pc = rng.choice((0, 2 * rng.randrange(1 << 20), (1 << 32) - 2))
        assert riscv_decode(data, pc) == archivey_native.riscv_decode(data, pc)


# ── ZipCrypto ──────────────────────────────────────────────────────────────────────


def test_zipcrypto_parity() -> None:
    rng = random.Random(4)
    for _ in range(SEEDS // 3):
        password = rng.randbytes(rng.randint(0, 40))
        py, rs = ZipCryptoKeys(password), archivey_native.ZipCryptoKeys(password)
        for _ in range(rng.randint(1, 5)):
            chunk = rng.randbytes(rng.randint(0, 40_000))
            assert py.decrypt(chunk) == rs.decrypt(chunk)
            assert (py.k0, py.k1, py.k2) == (rs.k0, rs.k1, rs.k2)
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
    import archivey_native as n

    rng = random.Random(5)
    for case, window, frames, sizes in lzx_streams(rng):
        py = lzx_frames(LzxDecoder, frames, sizes, window)
        rs = lzx_frames(n.LzxDecoder, frames, sizes, window)
        assert py == rs, case
        assert all(kind == "ok" for kind, _ in py), case
        for trial in range(6):
            bad = list(frames)
            k = rng.randrange(len(bad))
            bad[k] = damage(rng, bad[k])
            if trial % 3 == 0:
                bad = bad[: rng.randrange(len(bad) + 1)]
            py = lzx_frames(LzxDecoder, bad, sizes, window)
            rs = lzx_frames(n.LzxDecoder, bad, sizes, window)
            assert py == rs, (case, trial)


def test_lzx_random_input() -> None:
    import archivey_native as n

    rng = random.Random(6)
    for case in range(SEEDS):
        window = rng.randint(14, 22)
        chunks = [rng.randbytes(rng.randint(0, 3000)) for _ in range(rng.randint(0, 3))]
        sizes = [32768] * rng.randint(1, 3) + [rng.randint(-1, 40000)]
        py = lzx_frames(LzxDecoder, chunks, sizes, window)
        rs = lzx_frames(n.LzxDecoder, chunks, sizes, window)
        assert py == rs, case


def test_lzx_callback_error_passes_through() -> None:
    import archivey_native as n

    class Boom(Exception):
        pass

    def more() -> bytes:
        raise Boom

    with pytest.raises(Boom):
        n.LzxDecoder(16, more).decode_frame(32768)


# ── Unix compress (.Z) LZW ─────────────────────────────────────────────────────────


def pack_lzw(rng: random.Random, max_width: int, block_mode: bool, widen9: bool, n: int) -> bytes:
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
            code = rng.randrange(min(next_code + 1, 1 << width, 512 if width == 10 and max_width == 9 else 1 << 16))
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


def lzw_run(make: Callable, data: bytes, rng: random.Random, kwargs: dict) -> list:
    """Feed ``data`` in random chunks with random budgets; record every result."""
    try:
        state = make(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return [("init", type(exc).__name__)]
    log: list[object] = []
    pos = 0
    errors = 0
    while pos < len(data) and errors < 2:
        step = rng.randint(0, 3000)
        budget = rng.choice((-1, -1, 0, 1, 100, 5000))
        got = outcome(lambda: state.feed(data[pos : pos + step], budget))
        log.append((got, state.needs_input, state.header_params, state.nine_bit_widens))
        pos += step
        if got[0] != "ok":
            errors += 1
    for _ in range(3):
        if errors >= 2:
            break
        got = outcome(lambda: state.feed(b"", rng.choice((-1, 10))))
        log.append(got)
    got = outcome(state.flush)
    log.append((got, state.truncated, state.truncation, state.is_finished()))
    return log


def test_lzw_parity() -> None:
    from archivey.internal.streams.codecs.unix_compress_decoder import LzwState

    if True:
        rng = random.Random(7)
        cases = []
        try:
            import ncompress
            import io

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
                py = lzw_run(LzwState, d, random.Random(seed), kwargs)
                rs = lzw_run(archivey_native.LzwState, d, random.Random(seed), kwargs)
                assert py == rs, (case, variant)
