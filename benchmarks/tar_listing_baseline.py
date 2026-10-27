"""Non-gating TAR header-parse and listing baseline (many tiny members).

Times ``parse_header_block`` on one ustar header and the listing of a plain tar of
8000 members of 32 bytes each, next to ``tarfile.getmembers``. Tiny members make the
per-header work the larger part of the listing. There is **no** pass/fail threshold:
re-run before any performance claim about TAR header parsing or listing, and compare
before/after with the same recipe on the same host.

Example::

    uv run python benchmarks/tar_listing_baseline.py

Sample run (2026-10-16, Linux x86_64 4-core VM, CPython 3.11, illustrative only)::

    parse_header_block      5.0 us   (8.5 before the one-unpack numeric fields)
    archivey listing      275.0 ms  (8000 members; 305-330 before)
    tarfile getmembers    170.0 ms

The machine was slower end to end than for the 2026-10-13 sample (``tarfile`` itself
145 -> 170 ms), so compare before and after only within one session, as both numbers
here are.
"""

from __future__ import annotations

import argparse
import io
import tarfile
import tempfile
import timeit
from pathlib import Path

from archivey import open_archive
from archivey.internal.backends.tar_parser import parse_header_block


def _make_tar(path: Path, members: int, size: int) -> None:
    payload = b"x" * size
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        for i in range(members):
            info = tarfile.TarInfo(name=f"d{i % 50}/f{i}.bin")
            info.size = size
            tf.addfile(info, io.BytesIO(payload))


def _best(stmt: object, number: int, repeat: int) -> float:
    return min(timeit.repeat(stmt, number=number, repeat=repeat)) / number  # type: ignore[arg-type]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--members", type=int, default=8000)
    parser.add_argument("--size", type=int, default=32)
    parser.add_argument("--repeat", type=int, default=7)
    args = parser.parse_args()

    header = tarfile.TarInfo(name="dir/file.txt")
    header.size = 32
    block = header.tobuf(format=tarfile.USTAR_FORMAT)[:512]
    parse = _best(lambda: parse_header_block(block, 0), 50_000, args.repeat)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "tiny.tar"
        _make_tar(path, args.members, args.size)

        def archivey_list() -> None:
            with open_archive(path) as reader:
                list(reader.members())

        def tarfile_list() -> None:
            with tarfile.open(path, "r:") as tf:
                tf.getmembers()

        ours = _best(archivey_list, 1, args.repeat)
        theirs = _best(tarfile_list, 1, args.repeat)

    print(f"parse_header_block    {parse * 1e6:7.1f} us")
    print(f"archivey listing      {ours * 1e3:7.1f} ms  ({args.members} members)")
    print(f"tarfile getmembers    {theirs * 1e3:7.1f} ms")


if __name__ == "__main__":
    main()
