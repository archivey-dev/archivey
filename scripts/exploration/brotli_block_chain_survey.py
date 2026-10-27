"""Does a valid Brotli stream ever carry consecutive *declaring* meta-blocks?

Supporting `dev-docs/investigations/brotli-uncompressed-block-runs.md`, which asks whether
the completeness gate's chain walk (`archivey.internal.streams.codecs.brotli_framing`) could be
replaced by a single fixed test: "the meta-block after the first must be compressed".

This script re-measures the two numbers that settled it, on whatever machine you run it on:

1. **False negatives.** Build a corpus of valid Brotli streams — synthesised here, plus any
   `.br` files and WOFF2 fonts you point it at — and count how many each rule rejects. A
   valid complete stream must never be rejected; the chain walk scored 0, the fixed test
   scored 74/1914.
2. **False positives.** Random blobs at several declared source sizes, counting what each
   rule rejects among the ones the content probe accepts.

It also censuses the shape of each stream's **first** meta-block, which answers the doc's
second question: whether `ISLAST` is only ever set on an empty meta-block (it is not — 91%
of real streams are a single compressed meta-block with `ISLAST` set, so a rule rejecting
"final but not empty" would reject them all).

Every corpus entry is verified by a full `brotli.decompress` round-trip before it counts,
so a "false negative" here is always a genuinely valid stream.

Needs the `Brotli` binding and archivey importable (it imports the real gate, unmodified,
rather than a copy). Read-only apart from the temporary corpus it builds in memory.

    python3 scripts/exploration/brotli_block_chain_survey.py
    python3 scripts/exploration/brotli_block_chain_survey.py --scan ~/fonts /usr/share
"""

from __future__ import annotations

import argparse
import glob
import math
import os
import struct
import sys
from collections import Counter
from pathlib import Path

import brotli

from archivey.internal.streams.codecs.brotli_framing import (
    BrotliFirstBlock,
    first_block_overruns_source,
    parse_first_metablock,
)

# The chain walk and the mid-stream header parser land with #265. On an older checkout
# the script still measures the first-block gate; the two comparison columns are skipped.
try:
    from archivey.internal.streams.codecs.brotli_framing import (
        chain_proves_invalid,
        parse_metablock,
    )

    HAVE_CHAIN_WALK = True
except ImportError:  # pragma: no cover - depends on the checkout
    HAVE_CHAIN_WALK = False

PREFIX = 4096
TEXT = b"the quick brown fox jumps over the lazy dog. "


def second_block_must_be_compressed(prefix: bytes, source_length: int, read_at) -> bool:
    """The proposed simplification, against the same parser the chain walk uses.

    True == "reject". A declaring first block is allowed, but whatever follows it must be
    a compressed meta-block (or an empty-last landing exactly on EOF).
    """
    assert HAVE_CHAIN_WALK, "needs parse_metablock from #265"
    info = parse_first_metablock(prefix)
    if not info.declares_length:
        return False
    assert info.consumed is not None and info.declared_length is not None
    nxt = info.consumed + info.declared_length
    if nxt > source_length:
        return True
    if info.is_last:
        return nxt != source_length
    header = read_at(nxt, 24)
    if not header:
        return True
    following = parse_metablock(header, first=False)
    if following.outcome is BrotliFirstBlock.COMPRESSED:
        return False
    if following.outcome is BrotliFirstBlock.EMPTY_LAST:
        assert following.consumed is not None
        return nxt + following.consumed != source_length
    return True


def _text(n: int) -> bytes:
    return (TEXT * (n // len(TEXT) + 2))[:n]


def _flushed(chunks, quality: int, lgwin: int = 22) -> bytes:
    compressor = brotli.Compressor(quality=quality, lgwin=lgwin)
    out = []
    for chunk in chunks:
        out.append(compressor.process(chunk))
        out.append(compressor.flush())
    out.append(compressor.finish())
    return b"".join(out)


def synthesise() -> list[tuple[str, bytes]]:
    """Whole-file and flushed streams, over compressible and incompressible payloads."""
    corpus: list[tuple[str, bytes]] = []
    for quality in (0, 1, 2, 5, 9, 11):
        for name, payload in (
            ("random-1M", os.urandom(1 << 20)),
            ("random-odd", os.urandom(1_000_003)),
            ("random-4M", os.urandom(4 << 20)),
            ("text-1M", _text(1 << 20)),
            ("random+text", os.urandom(2 << 20) + _text(2 << 20)),
            ("text+random", _text(2 << 20) + os.urandom(2 << 20)),
        ):
            corpus.append(
                (f"{name}.q{quality}", brotli.compress(payload, quality=quality))
            )
        # Flushed streams: the meta-block boundaries are the caller's chunk boundaries.
        for name, chunks in (
            ("flush-1B-text", [_text(1)] * 3),
            ("flush-10B-random", [os.urandom(10)] * 3),
            (
                "flush-mixed",
                [os.urandom(1), os.urandom(2), os.urandom(3), os.urandom(300)],
            ),
            ("flush-64K-random", [os.urandom(65536)] * 4),
            ("flush-alternating", [os.urandom(5000), _text(5000), os.urandom(5000)]),
        ):
            corpus.append((f"{name}.q{quality}", _flushed(chunks, quality)))
    return corpus


def woff2_stream(data: bytes) -> bytes | None:
    """Extract the raw Brotli stream from a WOFF2 font, validated by round-trip."""
    if data[:4] != b"wOF2" or len(data) < 48:
        return None
    total_compressed = struct.unpack(">I", data[20:24])[0]
    meta_offset = struct.unpack(">I", data[28:32])[0]
    priv_offset = struct.unpack(">I", data[36:40])[0]
    end = meta_offset or priv_offset or len(data)
    for start in [end - total_compressed, *range(48, min(end, 3000))]:
        if start < 48:
            continue
        blob = data[start : start + total_compressed]
        if len(blob) < total_compressed:
            continue
        try:
            brotli.decompress(blob)
        except brotli.error:
            continue
        return blob
    return None


def scan(roots: list[str]) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = []
    for root in roots:
        for pattern in ("**/*.br", "**/*.woff2"):
            for path in glob.glob(os.path.join(root, pattern), recursive=True):
                try:
                    data = Path(path).read_bytes()
                except OSError:
                    continue
                blob = woff2_stream(data) if path.endswith(".woff2") else data
                if blob is not None:
                    found.append((path, blob))
    return found


def _reader(blob: bytes):
    def read_at(offset: int, length: int) -> bytes:
        return blob[offset : offset + length]

    return read_at


def false_negatives(corpus: list[tuple[str, bytes]]) -> None:
    valid = []
    for name, blob in corpus:
        try:
            brotli.decompress(blob)
        except brotli.error:
            continue
        valid.append((name, blob))
    print(f"valid complete streams: {len(valid)} (of {len(corpus)} candidates)")

    chain_rejects, fixed_rejects = [], []
    for name, blob in valid:
        size = len(blob)
        prefix, read_at = blob[:PREFIX], _reader(blob)
        if not HAVE_CHAIN_WALK:
            continue
        if chain_proves_invalid(prefix, size, read_at=read_at):
            chain_rejects.append(name)
        if second_block_must_be_compressed(prefix, size, read_at):
            fixed_rejects.append(name)

    total = len(valid)
    if not HAVE_CHAIN_WALK:
        print(
            "  chain walk absent from this checkout — rerun on #265 to compare the rules"
        )
        return
    print(
        f"  chain walk (shipped)              rejects {len(chain_rejects):5d} / {total}"
    )
    print(
        f"  'second block must be compressed' rejects {len(fixed_rejects):5d} / {total}"
    )
    for name in fixed_rejects[:15]:
        print(f"      {name}")
    if len(fixed_rejects) > 15:
        print(f"      … and {len(fixed_rejects) - 15} more")


def first_block_metadata(corpus: list[tuple[str, bytes]]) -> None:
    """Streams that open with a metadata meta-block, and what it holds.

    `brotli --comment=B64` emits its comment as a prologue metadata block, so a `.br`
    written that way starts with one and the bytes sit in the clear right after the header.
    """
    hits = 0
    for name, blob in corpus:
        info = parse_first_metablock(blob[:PREFIX])
        if info.outcome is not BrotliFirstBlock.METADATA:
            continue
        hits += 1
        assert info.consumed is not None and info.declared_length is not None
        body = blob[info.consumed : info.consumed + min(info.declared_length, 64)]
        shown = "".join(chr(b) if 32 <= b < 127 else "." for b in body)
        print(f"  {name}: MSKIPLEN={info.declared_length} {shown!r}")
    if not hits:
        print("  none — no stream in this corpus opens with a metadata meta-block")


def first_block_shapes(corpus: list[tuple[str, bytes]]) -> None:
    """What detection actually sees. `ISLAST` on a non-empty block is the common case."""
    shapes: Counter[str] = Counter()
    for _, blob in corpus:
        info = parse_first_metablock(blob[:PREFIX])
        if info.outcome is BrotliFirstBlock.EMPTY_LAST:
            shapes["empty-last"] += 1
        else:
            last = " ISLAST" if getattr(info, "is_last", False) else ""
            shapes[f"{info.outcome.value}{last}"] += 1
    total = sum(shapes.values())
    for shape, count in shapes.most_common():
        print(f"  {count:5d}  ({100 * count / total:5.1f}%)  {shape}")
    if not HAVE_CHAIN_WALK:
        print("  (ISLAST not annotated: BrotliFraming.is_last lands with #265)")
    print(
        "  (the synthetic corpus is skewed toward incompressible payloads by design —"
    )
    print("   --scan a real font/.br population for the distribution the doc reports)")


def declared_lengths(corpus: list[tuple[str, bytes]]) -> None:
    """Is there an exploitable granularity in non-last uncompressed block lengths?"""
    lengths: Counter[int] = Counter()
    for _, blob in corpus:
        info = parse_first_metablock(blob[:PREFIX])
        # An uncompressed meta-block is never the last one: ISUNCOMPRESSED is only
        # read when ISLAST is clear.
        if info.outcome is BrotliFirstBlock.UNCOMPRESSED:
            assert info.declared_length is not None
            lengths[info.declared_length] += 1
    if not lengths:
        print("  no uncompressed first blocks in this corpus")
        return
    divisor = 0
    for length in lengths:
        divisor = math.gcd(divisor, length)
    print(f"  distinct first-block uncompressed lengths: {len(lengths)}")
    print(f"  min {min(lengths)}  max {max(lengths)}  gcd {divisor}")


def probe_accepts(prefix: bytes) -> bool:
    try:
        brotli.Decompressor().process(prefix)
    except brotli.error:
        return False
    return True


def false_positives(trials: int) -> None:
    print(
        f"{'source size':>12} {'probe acc':>10} {'first-block':>13} {'fixed':>13} {'chain':>13}"
    )
    for size in (4096, 65536, 1 << 20, 16 << 20):
        accepted = gate = fixed = chain = 0
        for _ in range(trials):
            blob = os.urandom(min(size, PREFIX))
            if not probe_accepts(blob):
                continue
            accepted += 1

            def read_at(
                offset: int, length: int, blob: bytes = blob, size: int = size
            ) -> bytes:
                if offset >= size:
                    return b""
                if offset < len(blob):
                    return blob[offset : min(offset + length, len(blob))]
                return os.urandom(min(length, size - offset))

            if first_block_overruns_source(blob, size):
                gate += 1
            if not HAVE_CHAIN_WALK:
                continue
            if second_block_must_be_compressed(blob, size, read_at):
                fixed += 1
            if chain_proves_invalid(blob, size, read_at=read_at):
                chain += 1

        def residual(rejected: int, accepted: int = accepted) -> str:
            if not HAVE_CHAIN_WALK and rejected == 0:
                return "n/a"
            return f"{100 * (accepted - rejected) / trials:.3f}%"

        print(
            f"{size:>12} {100 * accepted / trials:>9.3f}% "
            f"{f'{100 * (accepted - gate) / trials:.3f}%':>13} "
            f"{residual(fixed):>13} {residual(chain):>13}"
        )
    print("  (columns after 'probe acc' are the residual false-positive rate per rule)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scan",
        nargs="*",
        default=[],
        metavar="ROOT",
        help="directories to search for real .br / .woff2 streams",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=20000,
        help="random blobs per size for the false-positive table",
    )
    args = parser.parse_args()

    corpus = synthesise()
    print(f"synthesised {len(corpus)} streams")
    if args.scan:
        found = scan(args.scan)
        print(f"found {len(found)} real streams under {', '.join(args.scan)}")
        corpus += found

    print("\n== false negatives (valid streams a rule rejects — must be zero) ==")
    false_negatives(corpus)
    print("\n== first-block shapes (a non-empty ISLAST block is the common case) ==")
    first_block_shapes(corpus)
    print("\n== streams opening with a metadata meta-block ==")
    first_block_metadata(corpus)
    print("\n== first-block uncompressed lengths ==")
    declared_lengths(corpus)
    print(f"\n== false positives ({args.trials} random blobs per size) ==")
    false_positives(args.trials)
    return 0


if __name__ == "__main__":
    sys.exit(main())
