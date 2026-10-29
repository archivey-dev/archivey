"""Built-in TAR reader against TAR on the sequential plugin shape (``tar_sequential``).

The plugin-API change ports TAR onto the sequential shape as the test of that shape;
this measures what the shape costs before anything replaces the built-in reader.
Both read the same archives with the same parser (``TarWalker``) and the same member
typing (``TarReader._to_member``), so the difference is the shape: the adapter, the
``ForwardStream`` the walker reads, and member data served by the adapter.

Usage::

    uv run python benchmarks/tar_sequential_compare.py [--repeat 7] [--quick]

Prints the best wall time of ``--repeat`` runs for each archive and operation, and the
port's ratio to the built-in reader.
"""

from __future__ import annotations

import argparse
import functools
import gzip
import io
import random
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from archivey import ArchiveFormat, ContainerFormat, StreamFormat, open_archive
from archivey.formats import register_format
from archivey.internal.backends.tar_sequential import (
    TAR_SEQUENTIAL,
    TarSequentialHandler,
)
from archivey.internal.format_adapter import registration_scope


def _build(path: Path, count: int, size_range: tuple[int, int], seed: int) -> None:
    rng = random.Random(seed)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for i in range(count):
            data = rng.randbytes(rng.randint(*size_range))
            info = tarfile.TarInfo(f"d{i % 50}/file{i}.bin")
            info.size = len(data)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    if path.suffix == ".gz":
        raw = gzip.compress(raw, compresslevel=1, mtime=0)
    path.write_bytes(raw)


def _ops(work: Path) -> dict[str, Callable[[Path, ArchiveFormat], None]]:
    def listing(path: Path, fmt: ArchiveFormat) -> None:
        with open_archive(path, format=fmt) as reader:
            reader.members()

    def stream_members(path: Path, fmt: ArchiveFormat) -> None:
        with open_archive(path, format=fmt) as reader:
            for _, stream in reader.stream_members():
                if stream is not None:
                    stream.read()

    def pipe_stream(path: Path, fmt: ArchiveFormat) -> None:
        with (
            path.open("rb") as raw,
            open_archive(raw, format=fmt, streaming=True) as reader,
        ):
            for _, stream in reader.stream_members():
                if stream is not None:
                    stream.read()

    def read_each(path: Path, fmt: ArchiveFormat) -> None:
        with open_archive(path, format=fmt) as reader:
            for member in reader.members():
                if member.is_file:
                    reader.read(member)

    def extract_all(path: Path, fmt: ArchiveFormat) -> None:
        dest = work / "out"
        if dest.exists():
            shutil.rmtree(dest)
        with open_archive(path, format=fmt) as reader:
            reader.extract_all(dest)

    return {
        "list": listing,
        "stream_members": stream_members,
        "pipe stream": pipe_stream,
        "read each": read_each,
        "extract_all": extract_all,
    }


def _best(fn: Callable[[], None], repeat: int) -> float:
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--quick", action="store_true", help="smaller archives")
    args = parser.parse_args()
    scale = 4 if args.quick else 1
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        archives = {
            "4000 small files": (work / "small.tar", 4000 // scale, (20, 600)),
            "4000 small files, gz": (work / "small.tar.gz", 4000 // scale, (20, 600)),
            "40 files of 1 MiB": (work / "large.tar", 40 // scale, (1 << 20, 1 << 20)),
            "40 files of 1 MiB, gz": (
                work / "large.tar.gz",
                40 // scale,
                (1 << 20, 1 << 20),
            ),
        }
        for seed, (path, count, sizes) in enumerate(archives.values()):
            _build(path, count, sizes, seed)
        ops = _ops(work)
        print(
            f"{'archive':<24}{'operation':<16}{'built-in':>10}{'port':>10}{'ratio':>8}"
        )
        with registration_scope():
            register_format(TarSequentialHandler)
            for label, (path, count, _) in archives.items():
                stream = (
                    StreamFormat.GZIP
                    if path.suffix == ".gz"
                    else StreamFormat.UNCOMPRESSED
                )
                # Both get the format, so neither pays for detection.
                builtin = ArchiveFormat(ContainerFormat.TAR, stream)
                port = ArchiveFormat(TAR_SEQUENTIAL.container, stream)
                for name, op in ops.items():
                    builtin_s = _best(functools.partial(op, path, builtin), args.repeat)
                    port_s = _best(functools.partial(op, path, port), args.repeat)
                    print(
                        f"{label:<24}{name:<16}{builtin_s * 1000:>8.1f}ms"
                        f"{port_s * 1000:>8.1f}ms{port_s / builtin_s:>8.2f}"
                    )


if __name__ == "__main__":
    main()
