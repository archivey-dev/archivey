"""Measure what running rapidgzip in a child process costs, against in-process and stdlib.

rapidgzip 0.16 aborts the process on a truncated DEFLATE stream, so archivey decodes the
DEFLATE family through rapidgzip in a child process (``rapidgzip_child.py``). This script
records the numbers that design rests on, and the ``AUTO`` threshold
(``RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE``): the child's fixed start from rows 1 and 4, and
the per-MB saving of a child read over the stdlib from row 2.

1. Child start-up: spawn to first reply, with and without ``import rapidgzip``.
2. A full sequential read of a ~100 MB-output gzip: stdlib ``zlib``, rapidgzip in-process
   (``parallelization=0`` and ``1``), and rapidgzip in a child over a pipe (several chunk
   sizes) and over shared memory.
3. A seek + small read round trip, in-process and through the child.
4. The same numbers through archivey itself (``open_codec_stream``), which uses the
   child whenever rapidgzip is selected.

Usage::

    uv run --no-sync python scripts/bench_rapidgzip_child.py [--mb 100] [--repeats 3]

Wall times on one machine; they are for comparing the rows with each other.
"""

from __future__ import annotations

import argparse
import gzip
import os
import random
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import IO

import rapidgzip

# A minimal worker, independent of archivey's, so the transport can be measured in
# isolation. Requests: <BQ> (op, arg). op 0 = read(arg) over the pipe, op 1 = readinto
# the shared-memory buffer (arg = size), op 2 = seek(arg). Reply: <q> (value) then, for
# op 0, that many bytes.
_WORKER = textwrap.dedent(
    """
    import os, struct, sys
    t0 = __import__("time").perf_counter()
    import rapidgzip
    path, par, shm_name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    f = rapidgzip.open(path, parallelization=par)
    shm = None
    if shm_name != "-":
        from multiprocessing import shared_memory
        shm = shared_memory.SharedMemory(name=shm_name)
    REQ, REP = struct.Struct("<BQ"), struct.Struct("<q")
    stdout.write(REP.pack(0)); stdout.flush()
    while True:
        req = stdin.read(REQ.size)
        if len(req) < REQ.size:
            break
        op, arg = REQ.unpack(req)
        if op == 0:
            data = f.read(arg)
            stdout.write(REP.pack(len(data))); stdout.write(data)
        elif op == 1:
            n = f.readinto(shm.buf[:arg])
            stdout.write(REP.pack(n))
        else:
            stdout.write(REP.pack(f.seek(arg)))
        stdout.flush()
    f.close()
    if shm is not None:
        shm.close()
    """
)

_REQ = struct.Struct("<BQ")
_REP = struct.Struct("<q")


def _payload(size: int) -> bytes:
    """Text-like data, about 3:1 under gzip -6: 1 MiB of word salad, tiled with a
    per-tile header so no two tiles are identical."""
    rng = random.Random(0)
    words = [
        "".join(
            rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 9))
        )
        for _ in range(4000)
    ]
    tile = " ".join(rng.choice(words) for _ in range(180_000)).encode()[: 1 << 20]
    parts = []
    for i in range(size // len(tile) + 1):
        parts.append(f"<tile {i}>".encode())
        parts.append(tile)
    return b"".join(parts)[:size]


def _best(fn: Callable[[], object], repeats: int) -> float:
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return min(times)


def _read_exact(stream: IO[bytes], size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise RuntimeError("worker exited")
    return data


class _Child:
    def __init__(
        self,
        path: str,
        parallelization: int,
        shm_name: str = "-",
        script: str = _WORKER,
    ) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-P", "-c", script, path, str(parallelization), shm_name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
        )
        assert self.proc.stdout is not None and self.proc.stdin is not None
        self.out = self.proc.stdout
        self.inp = self.proc.stdin
        _read_exact(self.out, _REP.size)

    def call(self, op: int, arg: int) -> int:
        self.inp.write(_REQ.pack(op, arg))
        (value,) = _REP.unpack(_read_exact(self.out, _REP.size))
        return value

    def read(self, n: int) -> bytes:
        size = self.call(0, n)
        if not size:
            return b""
        buf = bytearray(size)
        view = memoryview(buf)
        got = 0
        while got < size:
            k = self.out.readinto(view[got:])
            if not k:
                raise RuntimeError("worker exited")
            got += k
        return bytes(buf)

    def close(self) -> None:
        self.inp.close()
        self.proc.wait()
        self.out.close()


def measure_startup(repeats: int) -> None:
    print("## 1. Child start-up (spawn -> first reply), best of", repeats)
    bare = "import sys; sys.stdout.buffer.write(b'x'); sys.stdout.flush()"
    with_import = (
        "import rapidgzip, sys; sys.stdout.buffer.write(b'x'); sys.stdout.flush()"
    )

    def spawn(code: str) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-P", "-c", code], stdout=subprocess.PIPE, bufsize=0
        )
        assert proc.stdout is not None
        proc.stdout.read(1)
        proc.wait()
        proc.stdout.close()

    t_bare = _best(lambda: spawn(bare), repeats * 3)
    t_imp = _best(lambda: spawn(with_import), repeats * 3)
    start = time.perf_counter()
    import importlib

    importlib.reload(rapidgzip)
    t_reload = time.perf_counter() - start
    print(f"  python -P, no imports         : {t_bare * 1000:7.1f} ms")
    print(f"  python -P + import rapidgzip  : {t_imp * 1000:7.1f} ms")
    print(f"  (in-process reload, reference): {t_reload * 1000:7.1f} ms")
    print()


def measure_throughput(path: str, data_len: int, repeats: int) -> None:
    print(
        f"## 2. Full sequential read, {data_len / 1e6:.0f} MB output, best of {repeats}"
    )
    rows: list[tuple[str, float]] = []

    def stdlib() -> None:
        d = zlib.decompressobj(wbits=31)
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                d.decompress(chunk)

    rows.append(("stdlib zlib (1 MiB chunks)", _best(stdlib, repeats)))

    def gzip_stream() -> None:
        from archivey.internal.streams.codecs.deflate_decoder import (
            GzipDecompressorStream,
        )

        with GzipDecompressorStream(path) as s:
            while s.read(1 << 20):
                pass

    rows.append(
        ("archivey stdlib engine (GzipDecompressorStream)", _best(gzip_stream, repeats))
    )

    for par in (0, 1):

        def inproc(par: int = par) -> None:
            with rapidgzip.open(path, parallelization=par) as f:
                while f.read(1 << 20):
                    pass

        rows.append(
            (f"rapidgzip in-process, parallelization={par}", _best(inproc, repeats))
        )

    for par in (0, 1):
        for chunk in (64 << 10, 1 << 20, 4 << 20):

            def piped(par: int = par, chunk: int = chunk) -> None:
                c = _Child(path, par)
                while c.read(chunk):
                    pass
                c.close()

            rows.append(
                (
                    f"child pipe, par={par}, chunk {chunk >> 10} KiB",
                    _best(piped, repeats),
                )
            )

    from multiprocessing import shared_memory

    for par in (0, 1):
        chunk = 4 << 20

        def shm_read(par: int = par, chunk: int = chunk) -> None:
            shm = shared_memory.SharedMemory(create=True, size=chunk)
            try:
                c = _Child(path, par, shm.name)
                while n := c.call(1, chunk):
                    bytes(shm.buf[:n])  # the copy a caller-facing read() would make
                c.close()
            finally:
                shm.close()
                try:
                    shm.unlink()
                except FileNotFoundError:
                    pass  # Python < 3.13: the child's resource tracker unlinked it

        rows.append(
            (
                f"child shared memory, par={par}, chunk 4096 KiB",
                _best(shm_read, repeats),
            )
        )

    for name, seconds in rows:
        print(
            f"  {name:<50}: {seconds * 1000:8.0f} ms  {data_len / seconds / 1e6:7.0f} MB/s"
        )
    print()


def measure_seeks(path: str, data_len: int, repeats: int) -> None:
    print("## 3. seek + read(4096) round trip, after the index is built")
    rng = random.Random(1)
    targets = [rng.randrange(0, data_len - 4096) for _ in range(200)]
    for par in (0, 1):
        with rapidgzip.open(path, parallelization=par) as f:
            while f.read(1 << 22):
                pass

            def inproc() -> None:
                for t in targets:
                    f.seek(t)
                    f.read(4096)

            t_in = _best(inproc, repeats) / len(targets)
        c = _Child(path, par)
        while c.read(1 << 22):
            pass

        def child() -> None:
            for t in targets:
                c.call(2, t)  # noqa: B023 - called within this iteration
                c.read(4096)  # noqa: B023 - called within this iteration

        t_child = _best(child, repeats) / len(targets)
        c.close()
        print(
            f"  par={par}: in-process {t_in * 1e6:8.1f} us   child {t_child * 1e6:8.1f} us"
            f"   (+{(t_child - t_in) * 1e6:.1f} us per round trip)"
        )
    print()


def measure_archivey(path: str, data_len: int, repeats: int) -> None:
    """Through archivey's own codec layer, whatever it does on this branch."""
    from archivey.internal.config import AcceleratorMode, StreamConfig
    from archivey.internal.streams.codecs import Codec, open_codec_stream

    print(f"## 4. archivey open_codec_stream(GZIP), best of {repeats}")
    for mode in (AcceleratorMode.OFF, AcceleratorMode.ON):
        config = StreamConfig(seekable=True, use_rapidgzip=mode)

        def read_all(config: StreamConfig = config) -> None:
            with open_codec_stream(Codec.GZIP, path, config=config) as s:
                while s.read(1 << 20):
                    pass

        t = _best(read_all, repeats)
        print(
            f"  use_rapidgzip={mode.name:<4} full read      : {t * 1000:8.0f} ms"
            f"  {data_len / t / 1e6:7.0f} MB/s"
        )

        def open_close(config: StreamConfig = config) -> None:
            with open_codec_stream(Codec.GZIP, path, config=config) as s:
                s.read(1)

        t = _best(open_close, repeats * 3)
        print(f"  use_rapidgzip={mode.name:<4} open+read(1)   : {t * 1000:8.1f} ms")
    rng = random.Random(1)
    targets = [rng.randrange(0, data_len - 4096) for _ in range(200)]
    config = StreamConfig(seekable=True, use_rapidgzip=AcceleratorMode.ON)
    with open_codec_stream(Codec.GZIP, path, config=config) as s:
        while s.read(1 << 22):
            pass

        def seeks() -> None:
            for t in targets:
                s.seek(t)
                s.read(4096)

        t = _best(seeks, repeats) / len(targets)
    print(f"  use_rapidgzip=ON   seek+read(4096) : {t * 1e6:8.1f} us")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mb", type=int, default=100, help="uncompressed size in MB")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--skip-archivey", action="store_true", help="skip section 4 (archivey itself)"
    )
    args = parser.parse_args()

    print(
        f"python {sys.version.split()[0]}, rapidgzip {getattr(rapidgzip, '__version__', '?')}, "
        f"{os.cpu_count()} CPUs\n"
    )
    measure_startup(args.repeats)
    data = _payload(args.mb * 1_000_000)
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "bench.gz")
        compressed = gzip.compress(data, compresslevel=6)
        Path(path).write_bytes(compressed)
        print(
            f"payload {len(data) / 1e6:.0f} MB -> {len(compressed) / 1e6:.1f} MB gzip\n"
        )
        del compressed
        measure_throughput(path, len(data), args.repeats)
        measure_seeks(path, len(data), args.repeats)
        if not args.skip_archivey:
            measure_archivey(path, len(data), args.repeats)


if __name__ == "__main__":
    main()
