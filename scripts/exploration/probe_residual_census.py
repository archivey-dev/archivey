"""Census the content-probe residual on a real filesystem tree.

`brotli-probe-framing-gate` landed the first-block framing check;
`probe-completeness-gate` cut the residual further; `probe-provenance-unconfirmed`
keys the `format_unconfirmed` channel on probe-only provenance (any confidence).
This script measures what is left: how often a content probe still claims a file
that is not that format, which probe claims it, at what confidence, whether
anything corroborated the claim, and therefore whether a later decode failure
carries an unconfirmed signal.

It answers three questions the follow-up changes rest on:

1. **How big is the residual after the gates?** Every probe hit is decoded to
   completion with the real codec, so a genuine `.br` file is counted as genuine
   rather than inflating the false-positive count. That distinction matters: a
   real tree has both.
2. **How much of it is invisible?** After provenance, an uncorroborated probe hit
   stamps at any confidence. Corroborated hits (matching extension, inner-TAR
   upgrade) correctly stay silent. Whether a given file would stamp is read from
   the library's own predicate rather than restated here, so this column can
   still report a regression instead of echoing one.
3. **What would a completeness rule buy?** When a file is no larger than the peeked
   prefix, the probe can see all of it, so tolerating "ran out of input" is unsound: a
   complete valid stream must terminate cleanly. The script reports how many
   fabrications that rejects and, critically, how many genuine streams it would cost.
   (Shipped in `probe-completeness-gate`; the column remains for regression.)

Read-only: opens files, reads at most `DETECTION_LIMIT` bytes for the probe, and reads
whole files only to verify genuineness. Nothing is written or modified.

Usage:
    uv run python scripts/exploration/probe_residual_census.py [ROOT ...]

Defaults to a few standard system roots. `uv run` matters — the probes need the
optional `brotli` decoder to be importable, and the verification step needs it too.
"""

from __future__ import annotations

import argparse
import collections
import lzma
import os
import sys
import zlib
from dataclasses import dataclass

DEFAULT_ROOTS = ["/usr/lib", "/usr/bin", "/usr/share", "/usr/local"]

# Size buckets for the report, chosen so the "fits in the peeked prefix" boundary is
# visible rather than averaged away.
_BUCKETS = [
    (16, "<16 B"),
    (64, "16-63 B"),
    (1024, "64 B-1 KiB"),
    (4096, "1-4 KiB"),
    (65536, "4-64 KiB"),
    (1 << 20, "64 KiB-1 MiB"),
]


@dataclass(frozen=True)
class Hit:
    """One file a content probe claimed, and what it really turned out to be."""

    fmt: str
    confidence: str
    genuine: bool
    size: int
    path: str
    corroborated: bool = False
    stamps: bool = False
    """Whether a decode failure on this file would actually be stamped.

    Read from the library's own predicate (``core._format_provenance(...).probe_only``),
    never restated here. The point of this census is to catch the stamp and the fabricated
    population drifting apart — the previous keying left 53% of fabrications unsignalled,
    and this script is what found that. A local reimplementation of the rule, or a constant,
    cannot detect the next such drift.
    """


def _bucket(size: int) -> str:
    for limit, name in _BUCKETS:
        if size < limit:
            return name
    return ">=1 MiB"


def _decode_errors() -> tuple[type[BaseException], ...]:
    """Exception types a full decode can raise, resolved once.

    ``brotli.error`` derives straight from ``Exception``, so it has to be named rather
    than reached through a common base. ``MemoryError`` is in the list because a
    fabricated stream that happens to decode can declare an enormous output.
    """
    errors: list[type[BaseException]] = [
        OSError,
        ValueError,
        EOFError,
        MemoryError,
        lzma.LZMAError,
        zlib.error,
    ]
    try:
        import brotli
    except ImportError:
        pass
    else:
        errors.append(brotli.error)
    return tuple(errors)


DECODE_ERRORS = _decode_errors()


def _verify(fmt: str, data: bytes) -> bool:
    """True when ``data`` really is a complete, valid stream of ``fmt``.

    A decode to completion is the only honest test. Anything short of it is the same
    truncation-tolerant check the probe already failed to distinguish with.
    """
    try:
        if fmt == "BROTLI":
            import brotli

            brotli.decompress(data)
        elif fmt == "LZMA_ALONE":
            lzma.decompress(data, format=lzma.FORMAT_ALONE)
        elif fmt == "ZLIB":
            zlib.decompress(data)
        else:
            return False
    except DECODE_ERRORS:
        return False
    return True


def census(roots: list[str], limit: int | None = None) -> tuple[list[Hit], int]:
    from archivey import detect_format
    from archivey.core import _format_provenance
    from archivey.exceptions import ArchiveyError
    from archivey.internal.detection import DETECTION_LIMIT
    from archivey.internal.registry import get_registry

    probes = get_registry().content_probes()
    hits: list[Hit] = []
    scanned = 0

    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    size = os.path.getsize(path)
                    if size == 0:
                        continue
                    with open(path, "rb") as fh:
                        head = fh.read(DETECTION_LIMIT)
                except OSError:
                    continue
                scanned += 1
                if limit is not None and scanned > limit:
                    return hits, scanned - 1

                claimed = False
                for _fmt, probe in probes:
                    # A probe is contracted to return a bool, so anything it raises is a
                    # finding rather than noise — but the codec errors below can surface
                    # from a decoder the probe drives, and one odd file should not end a
                    # 60 000-file sweep.
                    try:
                        if probe(head, source_length=size):
                            claimed = True
                            break
                    except DECODE_ERRORS:
                        continue
                if not claimed:
                    continue

                # Ask the real detector rather than trusting probe order: extension and
                # magic may still override, and only detect_format knows the confidence.
                try:
                    info = detect_format(path)
                except (ArchiveyError, OSError, ValueError):
                    continue
                if info.detected_by != "content_probe":
                    continue

                fmt = str(info.format).replace("ArchiveFormat.", "")
                try:
                    with open(path, "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                hits.append(
                    Hit(
                        fmt,
                        info.confidence.value,
                        _verify(fmt, data),
                        size,
                        path,
                        info.corroborated,
                        _format_provenance(path, None, info).probe_only,
                    )
                )

    return hits, scanned


def report(hits: list[Hit], scanned: int) -> None:
    from archivey.internal.detection import DETECTION_LIMIT

    genuine = [h for h in hits if h.genuine]
    fabricated = [h for h in hits if not h.genuine]

    print(f"scanned {scanned} files; {len(hits)} claimed by a content probe")
    print(f"  genuine streams : {len(genuine)}")
    print(
        f"  fabricated      : {len(fabricated)}  "
        f"({100 * len(fabricated) / scanned:.3f}% of the tree)"
    )

    print(
        "\nby (format, confidence) — 'unstamped' means a decode failure would carry no"
    )
    print(
        "format_unconfirmed signal (probe-only provenance; confidence is irrelevant):\n"
    )
    print(
        f"  {'format / confidence':34} {'genuine':>8} {'fabricated':>11} {'stamped?':>9}"
    )
    keys = sorted({(h.fmt, h.confidence) for h in hits})
    for fmt, conf in keys:
        g = sum(1 for h in genuine if h.fmt == fmt and h.confidence == conf)
        f = sum(1 for h in fabricated if h.fmt == fmt and h.confidence == conf)
        # A hit in this bucket stamps iff at least one fabrication is uncorroborated.
        bucket_fab = [h for h in fabricated if h.fmt == fmt and h.confidence == conf]
        if not bucket_fab:
            stamped = "n/a"
        elif any(h.stamps for h in bucket_fab):
            stamped = "yes"
        else:
            stamped = "no (corr.)"
        print(f"  {fmt + ' / ' + conf:34} {g:8} {f:11} {stamped:>9}")

    stamped_fab = [h for h in fabricated if h.stamps]
    corroborated_fab = [h for h in fabricated if h.corroborated]
    unstamped_fab = [h for h in fabricated if not h.stamps]
    print(f"\n  fabrications that stamp on failure           : {len(stamped_fab)}")
    print(f"  corroborated fabrications (correctly silent): {len(corroborated_fab)}")
    print(f"  fabrications with NO signal at all          : {len(unstamped_fab)}")

    # The two must agree: after probe-provenance-unconfirmed, "stamps" is exactly
    # "uncorroborated", so a divergence means the stamp predicate and the corroboration
    # field have drifted apart — which is the regression this census exists to catch.
    drift = [h for h in fabricated if h.stamps == h.corroborated]
    if drift:
        print(
            f"\n  !! {len(drift)} fabrication(s) where stamps != (not corroborated) —"
            " the stamp predicate and FormatInfo.corroborated disagree:"
        )
        for h in drift[:10]:
            print(
                f"      {h.fmt:11} corroborated={h.corroborated!s:5}"
                f" stamps={h.stamps!s:5}  {os.path.basename(h.path)}"
            )

    if unstamped_fab:
        print("\n  unstamped fabrications (a decode failure names no doubt):")
        for h in sorted(unstamped_fab, key=lambda h: -h.size)[:10]:
            print(f"      {h.fmt:11} {h.size:>10}  {os.path.basename(h.path)}")

    print(f"\nsize distribution of fabrications (prefix is {DETECTION_LIMIT} B):\n")
    counts = collections.Counter(_bucket(h.size) for h in fabricated)
    order = [name for _limit, name in _BUCKETS] + [">=1 MiB"]
    for name in order:
        if counts.get(name):
            print(f"  {name:14} {counts[name]:5}")

    fits_fab = [h for h in fabricated if h.size <= DETECTION_LIMIT]
    fits_gen = [h for h in genuine if h.size <= DETECTION_LIMIT]
    print("\ncompleteness rule — 'a file no larger than the peeked prefix is fully")
    print("visible, so a valid stream must decode to completion':\n")
    print(
        f"  fabrications it rejects : {len(fits_fab)} of {len(fabricated)}"
        f"  ({100 * len(fits_fab) / max(len(fabricated), 1):.0f}%)"
    )
    print(
        f"  genuine streams it costs: {len(fits_gen)}"
        f"   <-- must be 0; every one of these decodes cleanly by definition"
    )
    # What the completeness rule leaves behind: fabrications too large for the probe to
    # have seen whole. After provenance, those still stamp when uncorroborated.
    remaining_probe_only = [
        h for h in fabricated if h.size > DETECTION_LIMIT and h.stamps
    ]
    print(f"  stamping fabrications above the prefix: {len(remaining_probe_only)}")
    for h in sorted(remaining_probe_only, key=lambda h: -h.size)[:10]:
        print(f"      {h.fmt:11} {h.size:>10}  {os.path.basename(h.path)}")

    if genuine:
        print("\ngenuine streams found (these must never be rejected):")
        for h in genuine:
            print(
                f"  {h.fmt:11} {h.confidence:9} {h.size:>10}  {os.path.basename(h.path)}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("roots", nargs="*", default=None, help="directories to scan")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="stop after this many files (for a quick pass)",
    )
    args = parser.parse_args(argv)

    roots = args.roots or [r for r in DEFAULT_ROOTS if os.path.isdir(r)]
    if not roots:
        print("no readable roots to scan", file=sys.stderr)
        return 1

    hits, scanned = census(roots, args.limit)
    if not scanned:
        print("no files scanned", file=sys.stderr)
        return 1
    report(hits, scanned)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
