"""Accelerators where ``AUTO`` turns them on: large, realistically compressible input.

Run::

    uv run --extra all python -m benchmarks.accel_auto
    uv run --extra all python -m benchmarks.accel_auto --size-mib 32 --runs 5

The harness's ``*_accel_on`` rows force the accelerator ON on fixtures far below
``RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE`` (16 MiB) and compress about 100:1, so they
measure the child process's start-up and nothing else. This script builds inputs above
the thresholds from text-like data (seeded words, about 3:1 under gzip -6) and compares
the default ``AUTO`` with ``seekable_members=True`` (the setting under which ``AUTO``
engages) against ``OFF``. It reports; it gates nothing.

Cases:

- a single ``.gz``, read to the end;
- a ``.tar.gz`` of 1 MiB members, every member read;
- a ``.tar.bz2`` of the same members (``use_indexed_bzip2``, 1 MiB threshold);
- a ZIP with one DEFLATE member of the full size: read to the end, and 20 reads of
  64 KiB at seeded random offsets (the access a seekable member is for).

Each case is timed ``--runs`` times after one warm-up, ``AUTO`` and ``OFF`` alternating,
and the minimum is printed with the ``AUTO / OFF`` ratio.
"""

from __future__ import annotations

import argparse
import gzip
import io
import random
import sys
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable
from pathlib import Path

from archivey import open_archive
from archivey.config import (
    INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE,
    RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE,
    AcceleratorMode,
    ArchiveyConfig,
)

_WORDS = [
    "archive",
    "member",
    "stream",
    "header",
    "block",
    "index",
    "offset",
    "length",
    "checksum",
    "format",
    "reader",
    "data",
    "value",
    "table",
    "record",
    "entry",
    "name",
    "path",
    "size",
    "time",
    "file",
    "directory",
    "link",
    "error",
    "the",
    "of",
    "and",
    "to",
    "in",
    "is",
    "that",
    "for",
    "it",
    "as",
    "with",
    "was",
    "on",
    "be",
    "by",
    "at",
    "this",
    "from",
    "or",
    "an",
    "are",
]
_MEMBER_SIZE = 1 << 20
_RANDOM_READS = 20
_RANDOM_READ_SIZE = 64 << 10

CONFIGS = {
    "auto": ArchiveyConfig(),
    "off": ArchiveyConfig(
        use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF
    ),
}


def text_like(size: int, seed: int) -> bytes:
    """Seeded words with digits mixed in: compresses about 3:1 under gzip -6."""
    rng = random.Random(seed)
    out = io.BytesIO()
    while out.tell() < size:
        line = " ".join(rng.choice(_WORDS) for _ in range(12))
        out.write(f"{line} {rng.randrange(1 << 30)}\n".encode())
    return out.getvalue()[:size]


def build(root: Path, size: int) -> dict[str, Path]:
    members = [
        (f"m{i:03d}.txt", text_like(_MEMBER_SIZE, i))
        for i in range(size // _MEMBER_SIZE)
    ]
    whole = b"".join(data for _, data in members)
    paths = {
        "gz": root / "single.gz",
        "tar_gz": root / "members.tar.gz",
        "tar_bz2": root / "members.tar.bz2",
        "zip_member": root / "one-member.zip",
    }
    paths["gz"].write_bytes(gzip.compress(whole, mtime=0))
    for key, mode in (("tar_gz", "w:gz"), ("tar_bz2", "w:bz2")):
        with tarfile.open(paths[key], mode) as tf:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    with zipfile.ZipFile(paths["zip_member"], "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", whole)
    return paths


def _read_all(path: Path, config: ArchiveyConfig) -> None:
    with open_archive(path, config=config, seekable_members=True) as reader:
        for member in reader.members():
            if member.is_file:
                with reader.open(member) as stream:
                    while stream.read(1 << 20):
                        pass


def _random_reads(path: Path, config: ArchiveyConfig) -> None:
    with open_archive(path, config=config, seekable_members=True) as reader:
        member = reader.members()[0]
        rng = random.Random(7)
        with reader.open(member) as stream:
            for _ in range(_RANDOM_READS):
                stream.seek(rng.randrange(member.size - _RANDOM_READ_SIZE))
                stream.read(_RANDOM_READ_SIZE)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--size-mib", type=int, default=64)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args(argv)
    size = args.size_mib << 20

    cases: list[tuple[str, str, Callable[[Path, ArchiveyConfig], None]]] = [
        ("gz_read_all", "gz", _read_all),
        ("tar_gz_read_all", "tar_gz", _read_all),
        ("tar_bz2_read_all", "tar_bz2", _read_all),
        ("zip_member_read_all", "zip_member", _read_all),
        ("zip_member_random_reads", "zip_member", _random_reads),
    ]
    with tempfile.TemporaryDirectory(prefix="archivey-accel-") as tmp:
        paths = build(Path(tmp), size)
        print(
            f"{args.size_mib} MiB of text-like data; thresholds: rapidgzip "
            f"{RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE >> 20} MiB, bzip2 "
            f"{INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE >> 20} MiB compressed"
        )
        for key, path in paths.items():
            print(f"  {key}: {path.stat().st_size / (1 << 20):.1f} MiB compressed")
        print(f"\n{'case':<26} {'auto':>9} {'off':>9} {'auto/off':>9}")
        for name, key, op in cases:
            best: dict[str, float] = {}
            for label, config in CONFIGS.items():
                op(paths[key], config)  # warm-up
            for _ in range(args.runs):
                for label, config in CONFIGS.items():
                    start = time.perf_counter()
                    op(paths[key], config)
                    elapsed = time.perf_counter() - start
                    best[label] = min(best.get(label, elapsed), elapsed)
            print(
                f"{name:<26} {best['auto'] * 1000:>7.0f}ms {best['off'] * 1000:>7.0f}ms "
                f"{best['auto'] / best['off']:>8.2f}x"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
