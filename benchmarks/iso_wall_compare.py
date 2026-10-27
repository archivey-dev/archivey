"""Non-gating ISO wall-time comparison, for a change to how the ISO reader is built.

Builds three Rock Ridge + Joliet images with pycdlib (many small files, a deep tree,
a few large files) and times, for each: open and list, read every file in listing
order, and open a few files at random. Each figure is the best of ``--repeat`` runs.
There is no threshold: run it on the base commit and on the change, with the same
``--out`` directory for the images, and compare the two JSON files.

Example::

    uv run --extra all python benchmarks/iso_wall_compare.py --images /tmp/iso \\
        --json before.json
"""

from __future__ import annotations

import argparse
import io
import json
import random
import time
from collections.abc import Callable
from pathlib import Path

import pycdlib

from archivey import open_archive


def _build(path: Path, files: list[tuple[str, bytes]]) -> None:
    """Write ``files`` (``"dir/sub/name"``) with short ISO 9660 names under them."""
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", joliet=3)
    iso_dirs: dict[str, str] = {"": ""}
    for index, (name, data) in enumerate(files):
        parts = name.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            if directory in iso_dirs:
                continue
            iso_dirs[directory] = (
                f"{iso_dirs['/'.join(parts[: depth - 1])]}/D{len(iso_dirs)}"
            )
            iso.add_directory(
                iso_dirs[directory],
                rr_name=parts[depth - 1],
                joliet_path="/" + directory,
            )
        parent = iso_dirs["/".join(parts[:-1])]
        iso.add_fp(
            io.BytesIO(data),
            len(data),
            f"{parent}/F{index}.;1",
            rr_name=parts[-1],
            joliet_path="/" + name,
        )
    iso.write(str(path))
    iso.close()


def _corpus() -> dict[str, list[tuple[str, bytes]]]:
    rng = random.Random(1)
    small = [
        (f"dir{i // 100}/file{i}.txt", rng.randbytes(rng.randrange(100, 3000)))
        for i in range(3000)
    ]
    deep = [
        ("/".join(f"level{d}" for d in range(depth)) + f"/leaf{depth}.bin", b"x" * 500)
        for depth in range(1, 60)
    ]
    large = [(f"big{i}.bin", rng.randbytes(16 << 20)) for i in range(4)]
    return {"small": small, "deep": deep, "large": large}


def _best(fn: Callable[[], object], repeat: int) -> float:
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def _list(path: Path) -> None:
    with open_archive(path) as reader:
        reader.members()


def _read_all(path: Path) -> None:
    with open_archive(path) as reader:
        for member in reader.members():
            if member.is_file:
                with reader.open(member) as stream:
                    while stream.read(1 << 20):
                        pass


def _random_open(path: Path) -> None:
    with open_archive(path) as reader:
        files = [m for m in reader.members() if m.is_file]
        rng = random.Random(2)
        for member in rng.sample(files, min(50, len(files))):
            with reader.open(member) as stream:
                stream.read(4096)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    args.images.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, float]] = {}
    for name, files in _corpus().items():
        path = args.images / f"{name}.iso"
        if not path.exists():
            _build(path, files)
        results[name] = {
            "list": _best(lambda p=path: _list(p), args.repeat),
            "read_all": _best(lambda p=path: _read_all(p), args.repeat),
            "random_open": _best(lambda p=path: _random_open(p), args.repeat),
        }
        print(
            name,
            "  ".join(f"{k}={v * 1000:.1f}ms" for k, v in results[name].items()),
        )
    args.json.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
