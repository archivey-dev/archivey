# ruff: noqa: B023 - every lambda here runs at once, inside its loop iteration
"""Kernel-level timings: each Rust kernel against the Python decoder it replaces.

Prints one row per kernel: input size, Python MB/s, Rust MB/s, speed-up.
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))

import archivey_native as n

from archivey.internal.backends.zipcrypto import ZipCryptoKeys
from archivey.internal.streams.codecs.arm64_filter import arm64_decode
from archivey.internal.streams.codecs.lzo_decoder import lzo1x_decompress_python
from archivey.internal.streams.codecs.lzx_decoder import LzxDecoder
from archivey.internal.streams.codecs.riscv_filter import riscv_decode


def best(fn, repeat=3):
    times = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return min(times)


def row(name, size, py, rs, extra=""):
    mb = size / 1e6
    print(
        f"{name:34} {mb:7.1f} MB  py {mb / py:8.1f} MB/s  rust {mb / rs:8.1f} MB/s  x{py / rs:6.1f} {extra}"
    )


def corpus(size: int) -> bytes:
    # Real text and code: the CPython stdlib sources, repeated to size.
    import sysconfig

    out = bytearray()
    for p in sorted(Path(sysconfig.get_paths()["stdlib"]).glob("*.py")):
        out += p.read_bytes()
        if len(out) >= size:
            break
    while len(out) < size:
        out += out[: size - len(out)]
    return bytes(out[:size])


def main() -> None:
    rng = random.Random(0)
    text = corpus(16 << 20)

    # LZO1X, as SquashFS uses it: 128 KiB blocks.
    import lzo

    blocks = [
        lzo.compress(text[i : i + 131072], 1, False)
        for i in range(0, len(text), 131072)
    ]
    py = best(lambda: [lzo1x_decompress_python(b, 131072) for b in blocks], 1)
    rs = best(lambda: [n.lzo1x_decompress(b, 131072) for b in blocks])
    c = best(lambda: [lzo.decompress(b, False, 131072) for b in blocks])
    row(
        "LZO1X (128 KiB blocks)",
        len(text),
        py,
        rs,
        f"(python-lzo/liblzo2 {len(text) / 1e6 / c:.0f} MB/s)",
    )

    # ZipCrypto.
    data = text[: 8 << 20]
    py = best(lambda: ZipCryptoKeys(b"secret").decrypt(data), 1)
    rs = best(lambda: n.ZipCryptoKeys(b"secret").decrypt(data))
    row("ZipCrypto decrypt", len(data), py, rs)

    # Branch filters on an executable and on text (few candidates).
    elf = Path(sys.executable).resolve().read_bytes()
    lib = max(
        Path("/usr/lib/x86_64-linux-gnu").glob("libpython3*.so*"),
        key=lambda p: p.stat().st_size,
        default=None,
    )
    exe = (elf + (lib.read_bytes() if lib else b""))[: 16 << 20]
    hot = bytes(
        rng.choice(b"\x94\x95\x90\xb0") if rng.random() < 0.25 else rng.randrange(256)
        for _ in range(4 << 20)
    )
    for label, buf in (("x86 binary", exe), ("dense candidates", hot), ("text", text)):
        py = best(lambda: arm64_decode(buf, 0), 2)
        rs = best(lambda: n.arm64_decode(buf, 0))
        row(f"ARM64 filter, {label}", len(buf), py, rs)
    hot = bytes(
        rng.choice(b"\xef\x17\x97") if rng.random() < 0.25 else rng.randrange(256)
        for _ in range(4 << 20)
    )
    for label, buf in (("x86 binary", exe), ("dense candidates", hot), ("text", text)):
        py = best(lambda: riscv_decode(buf, 0), 2)
        rs = best(lambda: n.riscv_decode(buf, 0))
        row(f"RISC-V filter, {label}", len(buf), py, rs)

    # LZX: a stream from the test suite's encoder (Python, so kept small).
    from cab_util import FRAME, LzxEncoder

    for label, layout, sample in (
        ("LZX verbatim, text", ("verbatim",), text[: 3 << 20]),
        ("LZX aligned, x86 binary", ("aligned",), exe[: 3 << 20]),
    ):
        frames = LzxEncoder(window_bits=21, blocks=layout).encode(sample)
        sizes = [min(FRAME, len(sample) - i) for i in range(0, len(sample), FRAME)]

        def run(cls):
            it = iter(frames)
            d = cls(21, lambda: next(it, None))
            out = b"".join(d.decode_frame(s) for s in sizes)
            assert out == sample

        py = best(lambda: run(LzxDecoder), 1)
        rs = best(lambda: run(n.LzxDecoder))
        row(label, len(sample), py, rs)


if __name__ == "__main__":
    main()
