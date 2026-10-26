"""What rapidgzip does on this machine: speed against the standard library, and the index
it builds, through each source kind archivey hands it.

It answered whether rapidgzip pays on Windows (dev-docs/formats/gzip.md §2.3: in process
yes, through the child no, so AUTO keeps sequential reads off there). Run it again on a
new platform, or after a change to the child, before changing where AUTO applies.

Run from a checkout with the dev environment (``uv sync --all-extras --group dev``)::

    uv run python scripts/exploration/rapidgzip_platform_probe.py
    uv run python scripts/exploration/rapidgzip_platform_probe.py --json probe.json

Read-only apart from a temporary directory it deletes. Prints a Markdown report.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import platform
import random
import sys
import tempfile
import time
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import rapidgzip

import archivey
from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream

MIB = 1 << 20


def _mixed(size: int) -> bytes:
    """About 1.5:1 at level 6: a third random, the rest words."""
    rng = random.Random(0)
    words = [
        bytes(rng.choices(b"abcdefghijklmnopqrstuvwxyz", k=rng.randint(2, 9)))
        for _ in range(5000)
    ]
    parts = []
    for i in range(size // MIB):
        if i % 3 == 0:
            parts.append(rng.randbytes(MIB))
        else:
            parts.append(b" ".join(rng.choices(words, k=200_000))[:MIB])
    return b"".join(parts)


def _text(size: int) -> bytes:
    """About 3:1: words only."""
    rng = random.Random(1)
    words = [bytes(rng.choices(b"abcdefghij", k=rng.randint(2, 7))) for _ in range(800)]
    return b" ".join(rng.choices(words, k=size // 4))[:size]


def _best(fn: Callable[[], object], runs: int) -> float:
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return round(min(times) * 1000, 1)


def _drain(stream: Any) -> int:
    total = 0
    while chunk := stream.read(MIB):
        total += len(chunk)
    return total


def _in_process(
    name: str, data: bytes, gz: bytes, raw: bytes, path: Path, runs: int
) -> list[dict]:
    rows = []
    sources: dict[str, Callable[[bytes], object]] = {
        "path": lambda _blob: str(path),
        # A Python file object, as archivey hands the child (Windows always does).
        "BytesIO": io.BytesIO,
    }
    for kind, blob in (("gzip", gz), ("raw deflate", raw)):
        for source_name, make in sources.items():
            if source_name == "path" and kind != "gzip":
                continue
            for p in (0, 1, 2, 4):

                def run(p: int = p, make: Callable = make, blob: bytes = blob) -> int:
                    with rapidgzip.open(make(blob), parallelization=p) as f:
                        return _drain(f)

                row: dict[str, Any] = {
                    "data": name,
                    "format": kind,
                    "source": source_name,
                    "p": p,
                }
                try:
                    row["ms"] = _best(run, runs)
                    with rapidgzip.open(make(blob), parallelization=p) as f:
                        _drain(f)
                        offsets = f.block_offsets()
                    row["index_points"] = len(offsets)
                except Exception as exc:  # noqa: BLE001 - a probe reports, never stops
                    row["error"] = repr(exc)
                rows.append(row)
    rows.append(
        {
            "data": name,
            "format": "gzip",
            "source": "zlib (stdlib)",
            "p": "-",
            "ms": _best(lambda: zlib.decompress(gz, 31), runs),
        }
    )
    rows.append(
        {
            "data": name,
            "format": "raw deflate",
            "source": "zlib (stdlib)",
            "p": "-",
            "ms": _best(lambda: zlib.decompress(raw, -15), runs),
        }
    )
    return rows


def _through_archivey(name: str, zpath: Path, gpath: Path, runs: int) -> list[dict]:
    rows = []
    seen: list[int | None] = []
    find_point = RapidgzipChildStream.end_check_point

    def record(self: RapidgzipChildStream, end: int) -> Any:
        offsets = self.block_offsets()
        seen.append(len(offsets))
        return find_point(self, end)

    RapidgzipChildStream.end_check_point = record  # type: ignore[method-assign]
    try:
        for label, path in (("zip member", zpath), ("gz file", gpath)):
            for mode in (AcceleratorMode.OFF, AcceleratorMode.ON, AcceleratorMode.AUTO):

                def run(path: Path = path, mode: AcceleratorMode = mode) -> int:
                    config = ArchiveyConfig(use_rapidgzip=mode)
                    with archivey.open_archive(path, config=config) as ar:
                        (member,) = ar.members()
                        with ar.open(member) as stream:
                            return _drain(stream)

                seen.clear()
                row: dict[str, Any] = {"data": name, "what": label, "mode": mode.name}
                try:
                    row["ms"] = _best(run, runs)
                    row["end_check_index_points"] = sorted(set(seen)) or "-"
                except Exception as exc:  # noqa: BLE001
                    row["error"] = repr(exc)
                rows.append(row)
    finally:
        RapidgzipChildStream.end_check_point = find_point  # type: ignore[method-assign]
    return rows


def _table(rows: list[dict]) -> str:
    keys: list[str] = []
    for row in rows:
        keys += [k for k in row if k not in keys]
    lines = ["| " + " | ".join(keys) + " |", "|" + " --- |" * len(keys)]
    lines += ["| " + " | ".join(str(r.get(k, "")) for k in keys) + " |" for r in rows]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--size", type=int, default=40, help="MiB of data per corpus")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    env = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "process_cpu_count": getattr(os, "process_cpu_count", lambda: None)(),
        "rapidgzip": getattr(rapidgzip, "__version__", "?"),
        "archivey": archivey.__version__,
    }
    in_process: list[dict] = []
    archivey_rows: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (
            ("mixed", _mixed(args.size * MIB)),
            ("text", _text(args.size * MIB)),
        ):
            gz = gzip.compress(data, 6)
            compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
            raw = compressor.compress(data) + compressor.flush()
            gpath = Path(tmp, f"{name}.gz")
            gpath.write_bytes(gz)
            zpath = Path(tmp, f"{name}.zip")
            with zipfile.ZipFile(
                zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6
            ) as zf:
                zf.writestr("a", data)
            env[f"{name}_ratio"] = round(len(data) / len(gz), 2)
            in_process += _in_process(name, data, gz, raw, gpath, args.runs)
            archivey_rows += _through_archivey(name, zpath, gpath, args.runs)

    print("# rapidgzip platform probe\n")
    print("\n".join(f"- {k}: {v}" for k, v in env.items()))
    print("\n## rapidgzip in this process\n")
    print(_table(in_process))
    print("\n## Through archivey (child process)\n")
    print(_table(archivey_rows))
    if args.json:
        args.json.write_text(
            json.dumps(
                {"env": env, "in_process": in_process, "archivey": archivey_rows},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
