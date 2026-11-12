"""Benchmark probe strategies for DecompressorStream._redecode_to_error.

Usage (from the repo root):
    uv run python dev-docs/investigations/redecode-probe-strategies/bench.py \
        gzip,xz-1block,bzip3-1M-blocks,ppmd8-flip 20000,300000,1500000,2700000 \
        4096,65536,1048576 none,linear,g2r64,L2048 > results.jsonl
    python dev-docs/investigations/redecode-probe-strategies/analyze.py results.jsonl

``none`` switches the re-decode off (the baseline the others are measured over);
``linear`` is one byte per call. Results are one JSON line per run.
"""

from __future__ import annotations

import gzip
import io
import json
import random
import subprocess
import sys
import time
from typing import Any

import archivey.internal.streams.decompressor_stream as ds
from archivey.exceptions import ArchiveyError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.base import CodecParams

CONFIG = StreamConfig(
    use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF
)


def text(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    words = [
        bytes(rng.choice(b"abcdefghijklmnop") for _ in range(rng.randint(2, 9)))
        for _ in range(3000)
    ]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + b" "
        if rng.random() < 0.01:
            out += rng.randbytes(rng.randint(1, 40))
    return bytes(out[:size])


# ---- strategies -------------------------------------------------------------
def ratio(r: float):
    def f(done: int, hi: int, met: bool) -> int:
        return max(1, int((hi - done) / r))

    return f


def gallop(start: int, r: float):
    def f(done: int, hi: int, met: bool) -> int:
        if not met:
            return max(1, min(hi - done, max(start, done)))
        return max(1, int((hi - done) / r))

    return f


def gal(g: int, r: float):
    def f(done: int, hi: int, met: bool) -> int:
        if not met:
            return max(1, min(hi - done, done * (g - 1)))
        return max(1, int((hi - done) / r))

    return f


def lin_then(L: int, g: int, r: float):
    def f(done: int, hi: int, met: bool) -> int:
        if not met:
            if done < L:
                return 1
            return max(1, min(hi - done, done * (g - 1)))
        if hi - done <= L:
            return 1
        return max(1, int((hi - done) / r))

    return f


SKI = {"R": 0.0, "t0": 0.0, "n": 0}


def ski(g: int, r: float):
    def f(done: int, hi: int, met: bool) -> int:
        now = time.perf_counter()
        el = now - SKI["t0"]
        SKI["n"] += 1
        c = el / SKI["n"]
        R = SKI["R"]
        if not met:
            if el < R:
                return 1
            return max(1, min(hi - done, max(1, done) * (g - 1)))
        if (hi - done) * c <= R:
            return 1
        return max(1, int((hi - done) / r))

    return f


STRATS: dict[str, Any] = {
    "L512": lin_then(512, 2, 64),
    "L2048": lin_then(2048, 2, 64),
    "ski": ski(2, 64),
    "g2r4": gal(2, 4),
    "g2r8": gal(2, 8),
    "g2r16": gal(2, 16),
    "g4r8": gal(4, 8),
    "g4r16": gal(4, 16),
    "g8r16": gal(8, 16),
    "g2r2": gal(2, 2),
    "g2r32": gal(2, 32),
    "g2r64": gal(2, 64),
    "g4r32": gal(4, 32),
    "g4r64": gal(4, 64),
    "g2r128": gal(2, 128),
    "linear": lambda d, h, m: 1,
    "r2": ratio(2),
    "r4": ratio(4),
    "r8": ratio(8),
    "r16": ratio(16),
    "r32": ratio(32),
    "r64": ratio(64),
    "gallop4k-r8": gallop(4096, 8),
    "gallop4k-r16": gallop(4096, 16),
}

REAL_PROBE = ds._redecode_probe
STATS = {"restarts": 0, "steps": 0, "redecodes": 0}
real_restart = ds.DecompressorStream._redecode_restart
real_step = ds.DecompressorStream._redecode_step
real_redecode = ds.DecompressorStream._redecode_to_error


def restart(self, point, target):
    STATS["restarts"] += 1
    t = time.perf_counter()
    out = real_restart(self, point, target)
    SKI["t0"] = time.perf_counter()
    SKI["R"] = SKI["t0"] - t
    SKI["n"] = 0
    return out


def step(self, decoder, n):
    STATS["steps"] += 1
    return real_step(self, decoder, n)


BASELINE = [False]


def redecode(self, before):
    STATS["redecodes"] += 1
    if BASELINE[0]:
        return b""
    return real_redecode(self, before)


ds.DecompressorStream._redecode_restart = restart
ds.DecompressorStream._redecode_step = step
ds.DecompressorStream._redecode_to_error = redecode


def run(codec, data: bytes, params: CodecParams, read_size: int, config=CONFIG):
    got = 0
    err = None
    with open_codec_stream(codec, io.BytesIO(data), config=config, params=params) as s:
        try:
            while chunk := s.read(read_size):
                got += len(chunk)
        except ArchiveyError as exc:
            err = type(exc).__name__
    return got, err


# ---- cases ------------------------------------------------------------------
def flip(data: bytes, pos: int, n: int = 16, seed: int = 5) -> bytes:
    junk = random.Random(seed).randbytes(n)
    return data[:pos] + junk + data[pos + n :]


def case_gzip(depth: int):
    raw = text(depth + 3_000_000, 1)
    comp = gzip.compress(raw, mtime=0)
    # compressed offset of `depth` approx proportional
    pos = int(len(comp) * depth / len(raw))
    return Codec.GZIP, flip(comp, pos), CodecParams(), CONFIG


def case_xz(depth: int, block: int | None = None):
    raw = text(depth + 3_000_000, 2)
    args = ["xz", "-6", "-c", "-T1"]
    if block:
        args.append(f"--block-size={block}")
    comp = subprocess.run(args, input=raw, capture_output=True, check=True).stdout
    pos = int(len(comp) * depth / len(raw))
    return Codec.XZ, flip(comp, pos), CodecParams(), CONFIG


def case_bz3(depth: int, block: int = 1 << 20):
    from bz3.backends import BZ3Compressor

    raw = text(depth + 3_000_000, 3)
    c = BZ3Compressor(block)
    comp = c.compress(raw) + c.flush()
    pos = int(len(comp) * depth / len(raw))
    return Codec.BZIP3, flip(comp, pos), CodecParams(), CONFIG


def case_ppmd(depth: int, mode: str):
    import pyppmd

    raw = text(depth + 2_000_000, 4)
    enc = pyppmd.Ppmd8Encoder(6, 16 << 20, 0)
    comp = enc.encode(raw) + enc.flush(True)
    pos = int(len(comp) * depth / len(raw))
    if mode == "cut":
        data = comp[:pos]
    else:
        data = flip(comp, pos)
    params = CodecParams(ppmd_order=6, ppmd_mem_size=16 << 20, pack_size=len(data))
    return Codec.PPMD, data, params, CONFIG


CASES = {
    "gzip": case_gzip,
    "xz-1block": lambda d: case_xz(d),
    "xz-256k-blocks": lambda d: case_xz(d, 256 << 10),
    "bzip3-1M-blocks": case_bz3,
    "ppmd8-cut": lambda d: case_ppmd(d, "cut"),
    "ppmd8-flip": lambda d: case_ppmd(d, "flip"),
}


def main() -> None:
    case_names = sys.argv[1].split(",")
    depths = [int(x) for x in sys.argv[2].split(",")]
    read_sizes = [int(x) for x in sys.argv[3].split(",")]
    strats = sys.argv[4].split(",")
    for cname in case_names:
        for depth in depths:
            codec, data, params, config = CASES[cname](depth)
            for rs in read_sizes:
                ref = None
                for sname in strats:
                    BASELINE[0] = sname == "none"
                    # The strategies above predate the restart distance argument;
                    # "real" is what the library does.
                    strat = STRATS.get(sname, STRATS["linear"])
                    ds._redecode_probe = (
                        REAL_PROBE
                        if sname == "real"
                        else (lambda d, h, m, *_, f=strat: f(d, h, m))
                    )
                    for k in STATS:
                        STATS[k] = 0
                    t = time.perf_counter()
                    got = run(codec, data, params, rs, config)
                    dt = time.perf_counter() - t
                    if ref is None and sname != "none":
                        ref = got
                    row = {
                        "case": cname,
                        "depth": depth,
                        "read": rs,
                        "strat": sname,
                        "secs": round(dt, 4),
                        "prefix": got[0],
                        "err": got[1],
                        "same": got == ref,
                        **STATS,
                    }
                    print(json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
