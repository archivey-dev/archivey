"""Measure what each configurable limit costs per unit, to size limits for a deployment.

    uv run python scripts/measure_limit_costs.py [--members 100000] [--extract-mib 256]

Builds synthetic archives in a temporary directory, times archivey on them, and prints
one row per limit: the cost of one unit (one member, one byte of names, one key
derivation round, ...) and that cost scaled to the limit's default. Numbers depend on
the machine and the Python version; run it where the service will run.

What it measures:

- ``listing_limits.max_members``: listing a stored ZIP and a TAR of empty members.
  Time is from a plain run, memory from a separate run under ``tracemalloc`` (which
  slows the code down, so its time is not used). Memory is what the open reader still
  holds once the listing is done.
- ``listing_limits.max_metadata_bytes``: the same, with long member names, reported per
  byte the limit charges (a ZIP member's name counts twice, as ``name`` and ``raw_name``).
- ``decoder_limits.max_key_derivation_rounds``: RAR5's PBKDF2-HMAC-SHA256 and 7z's
  SHA-256 cycles, through archivey's own derivation functions.
- ``extraction_limits.max_extracted_bytes``: extracting one deflated member, a run of
  zeros, to disk. Incompressible data decodes faster per output byte, so this is the
  slow end.
- ``extraction_limits.max_entries``: extracting many empty members to disk.

Not measured: ``decoder_limits.max_decoder_memory`` and ``spool_limits.max_bytes`` already
count memory and disk bytes directly; ``extraction_limits.max_ratio`` (and its
``ratio_activation_threshold``) is a proportion with no cost of its own; and
``decoder_limits.max_ppmd_held_input`` is a memory bound too: archivey holds up to
that many compressed bytes of a PPMd member, and about as much again while the decoder
copies them.
"""

from __future__ import annotations

import argparse
import gc
import io
import tarfile
import tempfile
import time
import tracemalloc
import zipfile
from collections.abc import Callable
from pathlib import Path

import archivey
from archivey.internal.backends.rar_parser import _rar5_pbkdf2
from archivey.internal.backends.sevenzip_aes import derive_sevenzip_aes_key
from archivey.internal.listing_limits import member_metadata_bytes

MiB = 2**20


def _member_name(i: int, name_len: int) -> str:
    base = f"dir{i // 1000:04d}/file{i:07d}"
    return base + "x" * max(0, name_len - len(base) - 4) + ".txt"


def build_zip(path: Path, n: int, name_len: int) -> None:
    """A stored ZIP of ``n`` empty members."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for i in range(n):
            z.writestr(_member_name(i, name_len), b"")


def build_tar(path: Path, n: int, name_len: int) -> None:
    """A TAR of ``n`` empty members."""
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as t:
        for i in range(n):
            t.addfile(tarfile.TarInfo(_member_name(i, name_len)), io.BytesIO(b""))


def list_time(path: Path) -> tuple[float, int]:
    gc.collect()
    start = time.perf_counter()
    with archivey.open_archive(path) as archive:
        n = len(archive.members())
    return time.perf_counter() - start, n


def charged_metadata_bytes(path: Path) -> int:
    """What ``listing_limits.max_metadata_bytes`` charges for the archive's members."""
    with archivey.open_archive(path) as archive:
        return sum(member_metadata_bytes(m) for m in archive.members())


def list_memory(path: Path) -> int:
    """Bytes the reader holds after listing, measured under tracemalloc."""
    gc.collect()
    tracemalloc.start()
    try:
        with archivey.open_archive(path) as archive:
            archive.members()
            gc.collect()
            held, _peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return held


def time_call(fn: Callable[[], object]) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


def fmt_time(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:.1f} s"
    if seconds >= 1e-3:
        return f"{seconds * 1e3:.1f} ms"
    if seconds >= 1e-6:
        return f"{seconds * 1e6:.1f} us"
    return f"{seconds * 1e9:.0f} ns"


def fmt_bytes(n: float) -> str:
    for unit, size in (("GiB", 2**30), ("MiB", MiB), ("KiB", 1024)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n:.0f} B"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--members", type=int, default=100_000, help="members per listing test"
    )
    parser.add_argument(
        "--extract-mib", type=int, default=256, help="size of the extraction test"
    )
    parser.add_argument(
        "--kdf-log2", type=int, default=20, help="log2 of key derivation rounds timed"
    )
    args = parser.parse_args()

    listing = archivey.ListingLimits()
    decoder = archivey.DecoderLimits()
    extraction = archivey.ExtractionLimits()
    rows: list[tuple[str, str, str]] = []

    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        n = args.members

        for kind, build in (("ZIP", build_zip), ("TAR", build_tar)):
            path = tmp / f"members.{kind.lower()}"
            build(path, n, 30)
            seconds, listed = list_time(path)
            held = list_memory(path)
            assert listed == n, (listed, n)
            per_s, per_b = seconds / n, held / n
            rows.append(
                (
                    f"`max_members` ({kind})",
                    f"{fmt_time(per_s)}, {fmt_bytes(per_b)} per member",
                    (
                        f"{fmt_time(per_s * listing.max_members)}, "
                        f"{fmt_bytes(per_b * listing.max_members)}"
                    ),
                )
            )

        long_n = max(1, n // 10)
        path = tmp / "long_names.zip"
        build_zip(path, long_n, 1000)
        charged = charged_metadata_bytes(path)
        seconds, _ = list_time(path)
        held = list_memory(path)
        per_s, per_b = seconds / charged, held / charged
        rows.append(
            (
                "`max_metadata_bytes` (ZIP, 1000-byte names)",
                f"{fmt_time(per_s * MiB)}, {fmt_bytes(per_b * MiB)} per MiB charged",
                (
                    f"{fmt_time(per_s * listing.max_metadata_bytes)}, "
                    f"{fmt_bytes(per_b * listing.max_metadata_bytes)}"
                ),
            )
        )

        rounds = 2**args.kdf_log2
        rar = time_call(lambda: _rar5_pbkdf2(b"password", b"s" * 16, rounds)) / rounds
        sz = (
            time_call(
                lambda: derive_sevenzip_aes_key(
                    b"password", salt=b"", cycles=args.kdf_log2
                )
            )
            / rounds
        )
        for label, per in (("RAR5", rar), ("7z", sz)):
            rows.append(
                (
                    f"`max_key_derivation_rounds` ({label})",
                    f"{fmt_time(per)} per round",
                    fmt_time(per * decoder.max_key_derivation_rounds),
                )
            )

        size = args.extract_mib * MiB
        path = tmp / "big.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("big.bin", b"\0" * size)
        out = tmp / "out_big"
        with archivey.open_archive(path) as archive:
            seconds = time_call(
                lambda: archive.extract_all(
                    out, limits=archivey.ExtractionLimits.UNLIMITED
                )
            )
        per = seconds / size
        rows.append(
            (
                "`max_extracted_bytes` (deflated zeros, to disk)",
                f"{fmt_time(per * MiB)} per MiB",
                fmt_time(per * extraction.max_extracted_bytes),
            )
        )

        path = tmp / "members.zip"
        out = tmp / "out_many"
        with archivey.open_archive(path) as archive:
            seconds = time_call(lambda: archive.extract_all(out))
        per = seconds / n
        rows.append(
            (
                "`max_entries` (empty files, to disk)",
                f"{fmt_time(per)} per entry",
                fmt_time(per * extraction.max_entries),
            )
        )

    print(f"members={n} extract={args.extract_mib} MiB kdf=2^{args.kdf_log2}\n")
    print("| Limit | Cost per unit | At the default |")
    print("|---|---|---|")
    for row in rows:
        print("| " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()
