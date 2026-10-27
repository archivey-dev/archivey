"""Measure where rapidgzip's bzip2 decoder in a child process beats the standard library.

archivey runs rapidgzip's bzip2 decoder in a child process (``rapidgzip_child.py``), so
each accelerated stream pays for a process start. This script reads bzip2 files of
several sizes in full through ``open_codec_stream``, with ``use_indexed_bzip2`` ``OFF``
and ``ON``, and prints the best of three wall times for each. The break-even size is
what ``INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE`` rests on. The payload is random words,
which bzip2 compresses about four to one.

Usage::

    uv run --no-sync python scripts/bench_bzip2_child.py
    taskset -c 0 uv run --no-sync python scripts/bench_bzip2_child.py  # one core

Wall times on one machine; they are for comparing the two columns.
"""

from __future__ import annotations

import bz2
import os
import random
import tempfile
import time

from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream

_SIZES_MIB = (0.1, 0.5, 1, 2, 4, 8)


def _text(rng: random.Random, words: list[bytes], size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        out += b" ".join(rng.choices(words, k=1000)) + b"\n"
    return bytes(out[:size])


def _read_time(path: str, mode: AcceleratorMode) -> float:
    config = StreamConfig(seekable=True, use_indexed_bzip2=mode)
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        with open_codec_stream(Codec.BZIP2, path, config=config) as stream:
            while stream.read(1 << 16):
                pass
        best = min(best, time.perf_counter() - start)
    return best


def main() -> None:
    rng = random.Random(1)
    letters = b"abcdefghijklmnopqrstuvwxyz"
    words = [bytes(rng.choices(letters, k=rng.randint(2, 9))) for _ in range(5000)]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "payload.bz2")
        for mib in _SIZES_MIB:
            compressed = bz2.compress(_text(rng, words, int(mib * 4 * 2**20)), 9)
            with open(path, "wb") as f:
                f.write(compressed)
            off = _read_time(path, AcceleratorMode.OFF)
            on = _read_time(path, AcceleratorMode.ON)
            print(
                f"compressed {len(compressed) / 2**20:5.2f} MiB: "
                f"stdlib {off * 1000:5.0f} ms, child {on * 1000:5.0f} ms"
            )


if __name__ == "__main__":
    main()
