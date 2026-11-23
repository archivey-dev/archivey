# ruff: noqa: B023 - every lambda here runs at once, inside its loop iteration
"""Kernel-level timings: each Rust kernel against its Python twin, run by the same
code through the kernels' one API.

Prints one row per kernel: input size, Python MB/s, Rust MB/s, speed-up.
"""

from __future__ import annotations

import random
import sys
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))

import archivey_codecs

from archivey.internal.kernels.python import filters, lzfse, lzo1x, lzx, zipcrypto

PYTHON = types.SimpleNamespace(
    filters=filters, lzfse=lzfse, lzo1x=lzo1x, lzx=lzx, zipcrypto=zipcrypto
)
RUST = archivey_codecs


def both(fn, py_repeat=1):
    """``fn`` timed with each side: (Python, Rust)."""
    return best(lambda: fn(PYTHON), py_repeat), best(lambda: fn(RUST))


def best(fn, repeat=3):
    times = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return min(times)


def filtered(decoder, buf: bytes) -> bytes:
    return decoder.decode(buf) + decoder.flush()


def row(name, size, py, rs, extra=""):
    mb = size / 1e6
    print(
        f"{name:34} {mb:7.1f} MB  py {mb / py:8.1f} MB/s"
        f"  rust {mb / rs:8.1f} MB/s  x{py / rs:6.1f} {extra}"
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

    sizes = [len(text[i : i + 131072]) for i in range(0, len(text), 131072)]
    blocks = [
        lzo.compress(text[i : i + 131072], 1, False)
        for i in range(0, len(text), 131072)
    ]
    py, rs = both(
        lambda c: [
            c.lzo1x.decompress(b, out_size=k)
            for b, k in zip(blocks, sizes, strict=True)
        ]
    )
    c = best(lambda: [lzo.decompress(b, False, 131072) for b in blocks])
    row(
        "LZO1X (128 KiB blocks)",
        len(text),
        py,
        rs,
        f"(python-lzo/liblzo2 {len(text) / 1e6 / c:.0f} MB/s)",
    )

    # LZFSE, as DMG runs hold it: 1 MiB chunks (bvx2 blocks), and 4 KiB chunks, which
    # the encoder writes as LZVN (bvxn blocks).
    import lzfse as lzfse_package

    for label, chunk in (
        ("LZFSE (1 MiB runs)", 1 << 20),
        ("LZFSE as LZVN (4 KiB)", 4096),
    ):
        data = text[: 8 << 20]
        pieces = [data[i : i + chunk] for i in range(0, len(data), chunk)]
        streams = [lzfse_package.compress(p) for p in pieces]
        sizes = [len(p) for p in pieces]
        py, rs = both(
            lambda c: [
                c.lzfse.decompress(z, out_size=k) for z, k in zip(streams, sizes)
            ]
        )
        c = best(lambda: [lzfse_package.decompress(z) for z in streams])
        row(label, len(data), py, rs, f"(lzfse package {len(data) / 1e6 / c:.0f} MB/s)")

    # ZipCrypto.
    data = text[: 8 << 20]
    py, rs = both(lambda c: c.zipcrypto.Decryptor(b"secret").decrypt(data))
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
        py, rs = both(lambda c: filtered(c.filters.Arm64Decoder(0), buf), 2)
        row(f"ARM64 filter, {label}", len(buf), py, rs)
    hot = bytes(
        rng.choice(b"\xef\x17\x97") if rng.random() < 0.25 else rng.randrange(256)
        for _ in range(4 << 20)
    )
    for label, buf in (("x86 binary", exe), ("dense candidates", hot), ("text", text)):
        py, rs = both(lambda c: filtered(c.filters.RiscvDecoder(0), buf), 2)
        row(f"RISC-V filter, {label}", len(buf), py, rs)

    # LZX: a stream from the test suite's encoder (Python, so kept small).
    from cab_util import LzxEncoder

    for label, layout, sample in (
        ("LZX verbatim, text", ("verbatim",), text[: 3 << 20]),
        ("LZX aligned, x86 binary", ("aligned",), exe[: 3 << 20]),
    ):
        frames = LzxEncoder(window_bits=21, blocks=layout).encode(sample)

        def run(c):
            d = c.lzx.Decompressor(21, output_size=len(sample))
            out = b"".join(d.decompress(f) for f in frames) + d.flush()
            assert out == sample

        py, rs = both(run)
        row(label, len(sample), py, rs)


if __name__ == "__main__":
    main()
