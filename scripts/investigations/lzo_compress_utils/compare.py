"""Compare three raw LZO1X block decoders: archivey's Python one, python-lzo
(liblzo2) and compress-utils (lzokay-derived C). Differential fuzz plus speed.

Usage: python compare.py fuzz N   |   python compare.py bench
"""

from __future__ import annotations

import os
import random
import resource
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import compress_utils as cu
import lzo

from archivey.internal.streams.codecs.lzo_decoder import lzo1x_decompress_python


def dec_py(d, n):
    return lzo1x_decompress_python(d, n)


def dec_lzo(d, n):
    return lzo.decompress(d, False, n)


def dec_cu(d, n):
    return cu.decompress(d, "lzo", expected_size=n)


DECODERS = {"py": dec_py, "lzo": dec_lzo, "cu": dec_cu}


def _source() -> bytes:
    """archivey's own Python source, as compressible text."""
    return b"".join(p.read_bytes() for p in sorted(Path("src/archivey").rglob("*.py")))


def corpus() -> list[bytes]:
    rng = random.Random(1)
    text = Path(__file__).read_bytes()
    src = _source()
    rand = rng.randbytes(70_000)
    mixed = b"".join(
        rng.choice(
            [
                b"\0" * rng.randint(1, 3000),
                rng.randbytes(rng.randint(1, 200)),
                text[: rng.randint(1, 500)],
            ]
        )
        for _ in range(300)
    )
    return [
        b"",
        b"a",
        b"hello\n",
        text,
        src[:200_000],
        rand,
        mixed,
        b"\0" * 100_000,
        b"ab" * 40_000,
    ]


def seeds() -> list[tuple[bytes, int]]:
    out = []
    for raw in corpus():
        for level in (1, 9):
            out.append((lzo.compress(raw, level, False), len(raw)))
    return out


def mutate(rng: random.Random, block: bytes) -> bytes:
    b = bytearray(block)
    op = rng.randrange(6)
    if op == 0 and b:  # bit flips
        for _ in range(rng.randint(1, 4)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    elif op == 1 and b:  # random byte values
        for _ in range(rng.randint(1, 4)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif op == 2:  # truncate
        del b[rng.randrange(len(b) + 1) :]
    elif op == 3:  # trailing junk
        b += rng.randbytes(rng.randint(1, 8))
    elif op == 4 and b:  # splice a chunk elsewhere
        i, j = sorted(rng.randrange(len(b) + 1) for _ in range(2))
        k = rng.randrange(len(b) + 1)
        b[k:k] = b[i:j]
    else:  # small random block
        b = bytearray(rng.randbytes(rng.randint(1, 40)))
    return bytes(b)


def outcome(fn, d, n):
    try:
        return ("ok", fn(d, n))
    except Exception as e:  # noqa: BLE001
        return ("err", type(e).__name__)


def work(args):
    seed, count = args
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    rng = random.Random(seed)
    sd = seeds()
    stats: Counter = Counter()
    examples: dict = {}
    for _ in range(count):
        block, size = rng.choice(sd)
        d = mutate(rng, block)
        # Container limit: the true size, a bit more, or less than it.
        n = rng.choice(
            [size, size + rng.randint(0, 64), max(0, size - rng.randint(1, 64)), 4096]
        )
        r = {k: outcome(f, d, n) for k, f in DECODERS.items()}
        if r["cu"][0] == "err" and r["py"][0] == "ok":
            # Is it only the end marker? Rewrite the last 3 bytes to the canonical 11 00 00.
            fixed = (
                d[:-3] + b"\x11\x00\x00"
                if len(d) >= 3 and 0x10 <= d[-3] <= 0x17
                else None
            )
            same = fixed is not None and outcome(dec_cu, fixed, n) == r["py"]
            stats["cu-only-refusal-" + ("end-marker" if same else "OTHER")] += 1
        for k, (_, v) in r.items():
            if r[k][0] == "ok" and len(v) > n:
                stats[f"{k}-over-limit"] += 1
        key = tuple(
            (
                k,
                r[k][0],
                r[k][1] == r["py"][1] if r[k][0] == "ok" == r["py"][0] else None,
            )
            for k in ("lzo", "cu")
        ) + (("py", r["py"][0]),)
        stats[key] += 1
        if len(examples.setdefault(key, [])) < 5:
            examples[key].append(
                (
                    d.hex()[-24:],
                    len(d),
                    n,
                    {k: (a, b if a == "err" else len(b)) for k, (a, b) in r.items()},
                )
            )
    return stats, examples


def fuzz(total: int) -> None:
    jobs = os.cpu_count() or 4
    per = total // (jobs * 8)
    stats: Counter = Counter()
    examples: dict = {}
    with ProcessPoolExecutor(jobs) as ex:
        for s, e in ex.map(work, [(i, per) for i in range(jobs * 8)]):
            stats.update(s)
            for k, v in e.items():
                examples.setdefault(k, []).extend(v)
    print(f"cases: {per * jobs * 8}")
    for k, v in stats.most_common():
        print(v, k)
        for x in examples.get(k, [])[:6]:
            print("   e.g. tail", x)


def bench() -> None:
    rng = random.Random(2)
    src = _source()
    binary = Path(sys.executable).read_bytes()
    datasets = {
        "python source": src,
        "binary (python exe)": binary,
        "random": rng.randbytes(1 << 20),
    }
    print(
        "| data | block | python-lzo MB/s | compress-utils MB/s | archivey Python MB/s |"
    )
    print("| --- | ---: | ---: | ---: | ---: |")
    for name, data in datasets.items():
        for bs in (4096, 128 << 10, 256 << 10):
            blocks = [data[i : i + bs] for i in range(0, min(len(data), 4 << 20), bs)]
            blocks = [b for b in blocks if len(b) == bs]
            comp = [lzo.compress(b, 1, False) for b in blocks]
            row = []
            for k in ("lzo", "cu", "py"):
                f = DECODERS[k]
                assert all(f(c, bs) == b for c, b in zip(comp, blocks))
                reps = 1 if k == "py" else 20
                t = time.perf_counter()
                for _ in range(reps):
                    for c in comp:
                        f(c, bs)
                dt = time.perf_counter() - t
                row.append(reps * len(blocks) * bs / dt / 1e6)
            print(
                f"| {name} | {bs // 1024} KiB | {row[0]:.0f} | {row[1]:.0f} | {row[2]:.1f} |"
            )


if __name__ == "__main__":
    if sys.argv[1] == "fuzz":
        fuzz(int(sys.argv[2]))
    else:
        bench()
