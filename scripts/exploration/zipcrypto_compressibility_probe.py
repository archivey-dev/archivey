"""Calibrate the STORED-member compressibility probe for ZipCrypto disambiguation.

Wrong ZipCrypto keys yield effectively-random plaintext. Real STORED plaintext is
often incompressible (that is why it was stored), but compressible plaintext
(text, CSV, …) shrinks under a fast compressor. The probe must:

* **never** accept a wrong-key chunk (false accept → wrong password wins until the
  caller's EOF CRC fails — still safe, but defeats the point of the accelerator);
* **often** accept a clearly-compressible correct chunk (avoid a full CRC pass);
* **never reject** on incompressible correct plaintext (fall through to CRC).

This script compares zlib level 1 vs zstd (backports.zstd / compression.zstd) across
payload classes and chunk sizes, and proposes accept margins.

Run from repo root::

    uv run --no-sync python scripts/exploration/zipcrypto_compressibility_probe.py
"""

from __future__ import annotations

import argparse
import importlib
import os
import statistics
import struct
import zlib
from dataclasses import dataclass


def _zstd_module():  # type: ignore[no-untyped-def]
    for name in ("compression.zstd", "backports.zstd"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


_zstd = _zstd_module()


@dataclass(frozen=True)
class RatioSample:
    label: str
    compressor: str
    chunk_size: int
    ratio: float  # compressed_len / raw_len; < 1 means shrinkage
    raw_len: int
    comp_len: int


def compress_zlib(data: bytes, level: int = 1) -> bytes:
    return zlib.compress(data, level=level)


def compress_zstd(data: bytes, level: int = 1) -> bytes:
    if _zstd is None:
        raise RuntimeError("zstd backend not available")
    # backports.zstd and compression.zstd both expose compress().
    return _zstd.compress(data, level)  # type: ignore[no-any-return]


def ratio(raw: bytes, compressed: bytes) -> float:
    if not raw:
        return 1.0
    return len(compressed) / len(raw)


def payload_classes(chunk_size: int) -> dict[str, bytes]:
    """Representative first-chunk payloads for STORED members."""
    text = (b"The quick brown fox jumps over the lazy dog.\n" * (chunk_size // 45 + 2))[
        :chunk_size
    ]
    zeros = b"\x00" * chunk_size
    random = os.urandom(chunk_size)

    # JPEG-like: SOI + APP0 + mostly high-entropy body (already compressed).
    jpegish = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF" + os.urandom(chunk_size - 10)
    jpegish = jpegish[:chunk_size]

    # PNG-like: 8-byte signature + IHDR-ish + entropy.
    pngish = b"\x89PNG\r\n\x1a\n" + os.urandom(chunk_size - 8)
    pngish = pngish[:chunk_size]

    # Nested ZIP local-header-ish + deflated-looking body.
    zipish = (
        struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0, 0, 100, 200, 4, 0)
        + b"a.txt"
        + os.urandom(chunk_size - 34)
    )[:chunk_size]

    # MP4/ftyp-like header then entropy.
    mp4ish = b"\x00\x00\x00\x18ftypisom" + os.urandom(chunk_size - 12)
    mp4ish = mp4ish[:chunk_size]

    # JSON / CSV-ish structured text.
    jsonish = (
        b'{"id": 12345, "name": "alice", "active": true}\n' * (chunk_size // 48 + 2)
    )[:chunk_size]

    # Low-entropy but not text: run-length friendly bytes.
    rle = bytes([i % 16 for i in range(chunk_size)])

    return {
        "text": text,
        "json": jsonish,
        "zeros": zeros,
        "rle": rle,
        "random": random,
        "jpegish": jpegish,
        "pngish": pngish,
        "zipish": zipish,
        "mp4ish": mp4ish,
    }


def measure(
    chunk_sizes: list[int],
    trials_random: int,
) -> list[RatioSample]:
    samples: list[RatioSample] = []
    compressors: list[tuple[str, object]] = [("zlib-1", lambda d: compress_zlib(d, 1))]
    if _zstd is not None:
        compressors.append(("zstd-1", lambda d: compress_zstd(d, 1)))
        compressors.append(("zstd-3", lambda d: compress_zstd(d, 3)))

    for size in chunk_sizes:
        classes = payload_classes(size)
        for label, data in classes.items():
            if label == "random":
                continue  # handled with many trials below
            for cname, cfn in compressors:
                comp = cfn(data)
                samples.append(
                    RatioSample(
                        label, cname, size, ratio(data, comp), len(data), len(comp)
                    )
                )

        # Many random trials — this is the wrong-key distribution.
        for cname, cfn in compressors:
            ratios = []
            for _ in range(trials_random):
                data = os.urandom(size)
                comp = cfn(data)
                r = ratio(data, comp)
                ratios.append(r)
                samples.append(
                    RatioSample("random", cname, size, r, len(data), len(comp))
                )
            print(
                f"  random/{cname}/chunk={size}: "
                f"min={min(ratios):.4f} p50={statistics.median(ratios):.4f} "
                f"p99={sorted(ratios)[int(0.99 * (len(ratios) - 1))]:.4f} "
                f"max={max(ratios):.4f}"
            )
    return samples


def print_class_table(samples: list[RatioSample], chunk_size: int) -> None:
    print(f"\n=== Non-random classes at chunk_size={chunk_size} ===")
    by: dict[tuple[str, str], RatioSample] = {}
    for s in samples:
        if s.chunk_size != chunk_size or s.label == "random":
            continue
        by[(s.label, s.compressor)] = s
    compressors = sorted({c for (_, c) in by})
    labels = sorted({lab for (lab, _) in by})
    header = f"{'class':<10} " + " ".join(f"{c:>10}" for c in compressors)
    print(header)
    for lab in labels:
        cells = []
        for c in compressors:
            s = by.get((lab, c))
            cells.append(f"{s.ratio:10.4f}" if s else f"{'—':>10}")
        print(f"{lab:<10} " + " ".join(cells))


def propose_thresholds(samples: list[RatioSample]) -> None:
    print("\n=== Threshold proposals ===")
    print(
        "Accept when ratio <= T (i.e. compressed_len <= T * raw_len).\n"
        "Constraint: max(random ratio) must stay strictly above T for every\n"
        "chunk size we might use; compressible classes should land below T."
    )
    for cname in sorted({s.compressor for s in samples}):
        print(f"\n  compressor={cname}")
        for size in sorted({s.chunk_size for s in samples}):
            random_ratios = [
                s.ratio
                for s in samples
                if s.compressor == cname
                and s.chunk_size == size
                and s.label == "random"
            ]
            if not random_ratios:
                continue
            # zlib/zstd add a small header, so random ratio is typically slightly > 1.
            # A safe T is well below the observed random minimum.
            rmin = min(random_ratios)
            # Suggested T: midpoint between best compressible text and random floor,
            # but never above (rmin - margin).
            text_ratios = [
                s.ratio
                for s in samples
                if s.compressor == cname and s.chunk_size == size and s.label == "text"
            ]
            jpeg_ratios = [
                s.ratio
                for s in samples
                if s.compressor == cname
                and s.chunk_size == size
                and s.label == "jpegish"
            ]
            text_r = text_ratios[0] if text_ratios else float("nan")
            jpeg_r = jpeg_ratios[0] if jpeg_ratios else float("nan")
            # Conservative: require at least 12.5% shrinkage (T=0.875), and also stay
            # 5 percentage points below the worst random we saw.
            t_shrink = 0.875
            t_vs_random = rmin - 0.05
            t = min(t_shrink, t_vs_random)
            print(
                f"    chunk={size:>7}: random_min={rmin:.4f}  text={text_r:.4f}  "
                f"jpegish={jpeg_r:.4f}  proposed_T={t:.4f}  "
                f"(margin_to_random={rmin - t:.4f})"
            )


def header_vs_body_note(chunk_sizes: list[int]) -> None:
    """For media-like payloads, does a *smaller* first chunk look more compressible
    because of headers?"""
    print("\n=== Header effect: jpegish/pngish/mp4ish ratio vs chunk size ===")
    if _zstd is None:
        compressors = [("zlib-1", lambda d: compress_zlib(d, 1))]
    else:
        compressors = [
            ("zlib-1", lambda d: compress_zlib(d, 1)),
            ("zstd-1", lambda d: compress_zstd(d, 1)),
        ]
    for label in ("jpegish", "pngish", "mp4ish", "zipish", "text", "random"):
        row = f"  {label:<8}"
        for size in chunk_sizes:
            data = (
                payload_classes(size)[label] if label != "random" else os.urandom(size)
            )
            # one-shot for illustration
            cfn = compressors[0][1]
            row += f"  {size}:{ratio(data, cfn(data)):.3f}"
        print(row + f"  ({compressors[0][0]})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trials-random", type=int, default=500, help="random trials per chunk size"
    )
    args = parser.parse_args()

    chunk_sizes = [256, 1024, 4096, 16 * 1024, 64 * 1024, 256 * 1024]
    print(f"zstd available: {_zstd is not None} ({getattr(_zstd, '__name__', None)})")
    print("\n=== Random (wrong-key) ratio distributions ===")
    samples = measure(chunk_sizes, args.trials_random)
    for size in (4096, 64 * 1024, 256 * 1024):
        print_class_table(samples, size)
    header_vs_body_note(chunk_sizes)
    propose_thresholds(samples)

    print(
        "\n=== Practical recommendation (draft, pending maintainer sign-off) ===\n"
        "  * Prefer zstd level 1 when the zstd backend is importable; else zlib level 1.\n"
        "    (Core must stay zero-dep, so zlib is the required fallback.)\n"
        "  * Chunk size 64 KiB: large enough that compressor headers are negligible and\n"
        "    text clearly separates from random; small enough to stay cheap.\n"
        "  * Accept margin T ≈ 0.875 (12.5% shrinkage) — well below observed random_min\n"
        "    (~1.00+) and above typical media-header-only shrinkage at 64 KiB.\n"
        "  * Skip probe for members smaller than ~4 KiB (full CRC pass is cheap).\n"
        "  * Probe is accept-only: ratio > T means 'no signal', never reject.\n"
    )


if __name__ == "__main__":
    main()
