"""Measure full and random reads through the rapidgzip child, against the stdlib.

``bench_process_isolation.py`` covers ``process_isolation`` with the accelerators off;
this script covers ``use_rapidgzip`` and ``use_indexed_bzip2``, which always decode in a
child process (``rapidgzip_child.py``). The investigation page
``dev-docs/investigations/process-isolation-overhead.md`` quotes its output.

Three parts:

1. **Full reads.** Each archive is read to the end of every member, each case in a fresh
   interpreter (a warm-up read, then the best of three), under the default
   ``KNOWN_CRASHES``:

   - ``stdlib``: the standard-library module alone (``gzip``, ``bz2``, ``zipfile``,
     ``tarfile``);
   - ``OFF``: both accelerators ``OFF``, read with ``stream_members()``;
   - ``AUTO``: the default config, read with ``stream_members()``;
   - ``AUTO seek``: the default config with ``seekable_members=True``, each member read
     through ``open()``;
   - ``ON seek``: both accelerators ``ON``, read like ``AUTO seek``.

   The derived figures after the table: what one rapidgzip stream costs beyond the
   standard library (the single 1 MiB ``.gz``), and what each further ZIP member costs
   under ``OFF`` and ``ON seek`` (the slope over the member counts at a fixed 32 MiB;
   ``ON seek`` reuses one child for the members of the archive).
2. **One large ZIP member, in parts.** A 40 MiB DEFLATE member, with
   ``seekable_members=True``: the full read under ``AUTO`` and ``OFF``, the open plus
   the first byte, and a plain ``zlib`` decode of the member's raw data, which is what
   the end check of a ZIP or 7z member repeats (``refuse_input_after_end``).
3. **Reads after seeks.** One DEFLATE member of 4, 16 and 64 MiB, opened with
   ``seekable_members=True``: 20 reads of 64 KiB, each after a seek, under ``OFF`` and
   ``ON``, in three orders: ascending offsets (every seek is forward), descending
   offsets (every seek is back), and random offsets. The offsets are spread evenly
   over the member. The time starts after the open and the first byte. A seek back
   under ``OFF`` decodes the member again from its start, so its cost grows with the
   offset; rapidgzip restarts from its own index, so its cost depends little on where
   the seek lands. The rows show how the gap changes with size and order rather than
   one ratio.

``--only seeks`` runs part 3 alone.

The payload is random words and numbers, which gzip compresses about two to one.

Usage::

    uv run --no-sync python scripts/bench_accelerator_reads.py

Wall times on one machine; they are for comparing the columns.
"""

from __future__ import annotations

import bz2
import gzip
import io
import os
import random
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

_MIB = 1 << 20
_MODES = ("stdlib", "off", "auto", "auto_seek", "on_seek")
_HEADINGS = ("stdlib", "OFF", "AUTO", "AUTO seek", "ON seek")
_ZIP_COUNTS = (1, 16, 256)


def _text(size: int) -> bytes:
    rng = random.Random(1234)
    letters = "abcdefghijklmnopqrstuvwxyz"
    words = ["".join(rng.choices(letters, k=rng.randint(2, 10))) for _ in range(5000)]
    out: list[str] = []
    total = 0
    while total < size:
        line = " ".join(rng.choices(words, k=12)) + f" {rng.randint(0, 10**9)}\n"
        out.append(line)
        total += len(line)
    return "".join(out).encode()[:size]


def _zip(path: Path, payload: bytes, count: int, method: int) -> None:
    each = len(payload) // count
    with zipfile.ZipFile(path, "w", method) as zf:
        for i in range(count):
            zf.writestr(f"m{i:05}.txt", payload[i * each : (i + 1) * each])


def _tar(path: Path, payload: bytes, count: int, mode: str) -> None:
    each = len(payload) // count
    with tarfile.open(path, mode) as tf:  # type: ignore[call-overload]
        for i in range(count):
            data = payload[i * each : (i + 1) * each]
            info = tarfile.TarInfo(f"m{i:05}.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _build(root: Path) -> list[Path]:
    payload = _text(64 * _MIB)
    paths: list[Path] = []
    for mib in (1, 16, 64):
        path = root / f"{mib:02d}M.gz"
        path.write_bytes(gzip.compress(payload[: mib * _MIB], 6, mtime=0))
        paths.append(path)
    for mib in (1, 16):
        path = root / f"{mib:02d}M.bz2"
        path.write_bytes(bz2.compress(payload[: mib * _MIB], 9))
        paths.append(path)
    for count in _ZIP_COUNTS:
        path = root / f"deflate-{count}x-32M.zip"
        _zip(path, payload[: 32 * _MIB], count, zipfile.ZIP_DEFLATED)
        paths.append(path)
    path = root / "bzip2-1x-16M.zip"
    _zip(path, payload[: 16 * _MIB], 1, zipfile.ZIP_BZIP2)
    paths.append(path)
    for count in (1, 1024):
        path = root / f"{count}x-32M.tar.gz"
        _tar(path, payload[: 32 * _MIB], count, "w:gz")
        paths.append(path)
    path = root / "1x-16M.tar.bz2"
    _tar(path, payload[: 16 * _MIB], 1, "w:bz2")
    paths.append(path)
    return paths


def _drain(stream: io.BufferedIOBase | object) -> None:
    while stream.read(_MIB):  # type: ignore[attr-defined]
        pass


def _stdlib_read(path: str) -> None:
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                with zf.open(info) as stream:
                    _drain(stream)
    elif ".tar." in path:
        with tarfile.open(path, "r:*") as tf:
            for member in tf:
                stream = tf.extractfile(member)
                if stream is not None:
                    _drain(stream)
    else:
        opener = gzip.open if path.endswith(".gz") else bz2.open
        with opener(path) as stream:
            _drain(stream)


def _archivey_read(path: str, mode: str) -> Callable[[], None]:
    from archivey import open_archive
    from archivey.config import AcceleratorMode, ArchiveyConfig

    if mode == "off":
        config = ArchiveyConfig(
            use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF
        )
    elif mode == "on_seek":
        config = ArchiveyConfig(
            use_rapidgzip=AcceleratorMode.ON, use_indexed_bzip2=AcceleratorMode.ON
        )
    else:
        config = ArchiveyConfig()

    def sequential() -> None:
        with open_archive(path, config=config) as reader:
            for _member, stream in reader.stream_members():
                if stream is not None:
                    _drain(stream)

    def seekable() -> None:
        with open_archive(path, config=config, seekable_members=True) as reader:
            for member in reader.members():
                if member.is_file:
                    with reader.open(member) as stream:
                        _drain(stream)

    return seekable if mode.endswith("_seek") else sequential


def _time_one(path: str, mode: str) -> float:
    """Best of three full reads after a warm-up, in this process."""
    read = (
        (lambda: _stdlib_read(path)) if mode == "stdlib" else _archivey_read(path, mode)
    )
    read()
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        read()
        best = min(best, time.perf_counter() - start)
    return best


def _in_fresh_process(*args: str) -> list[float]:
    done = subprocess.run(
        [sys.executable, __file__, *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONWARNINGS": "ignore"},
    )
    return [float(word) for word in done.stdout.split()]


def _full_reads(paths: list[Path]) -> None:
    print("Full reads, best of three, ms")
    print(f"{'archive':22}" + "".join(f"{h:>11}" for h in _HEADINGS))
    results: dict[str, list[float]] = {}
    for path in paths:
        times = [_in_fresh_process("--one", str(path), mode)[0] for mode in _MODES]
        results[path.name] = times
        print(f"{path.name:22}" + "".join(f"{t * 1000:11.0f}" for t in times))
    print()
    one_gz = results["01M.gz"]
    print(
        "one rapidgzip stream beyond the stdlib (01M.gz, ON seek - stdlib): "
        f"{(one_gz[4] - one_gz[0]) * 1000:.0f} ms"
    )
    first, last = _ZIP_COUNTS[0], _ZIP_COUNTS[-1]
    # Not AUTO seek: AUTO leaves members under its size threshold to the stdlib, so
    # its rows mix the two decoders.
    for column in (1, 4):
        slope = (
            results[f"deflate-{last}x-32M.zip"][column]
            - results[f"deflate-{first}x-32M.zip"][column]
        ) / (last - first)
        print(
            f"each further ZIP member, {_HEADINGS[column]} "
            f"(deflate {first}x to {last}x at 32 MiB): {slope * 1000:.2f} ms"
        )


def _member_data(path: str) -> bytes:
    """The raw DEFLATE data of the archive's first member."""
    with zipfile.ZipFile(path) as zf:
        info = zf.infolist()[0]
    with open(path, "rb") as f:
        f.seek(info.header_offset)
        header = f.read(30)
        name_len, extra_len = struct.unpack_from("<HH", header, 26)
        f.seek(info.header_offset + 30 + name_len + extra_len)
        return f.read(info.compress_size)


def _parts(path: str) -> list[float]:
    """Seconds for the parts of one large member's read, best of three each."""
    from archivey import open_archive
    from archivey.config import AcceleratorMode, ArchiveyConfig

    off = ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF)

    def full(config: ArchiveyConfig) -> Callable[[], None]:
        def run() -> None:
            with (
                open_archive(path, config=config, seekable_members=True) as reader,
                reader.open(reader.members()[0]) as stream,
            ):
                _drain(stream)

        return run

    def first_byte() -> None:
        with (
            open_archive(path, seekable_members=True) as reader,
            reader.open(reader.members()[0]) as stream,
        ):
            stream.read(1)

    raw = _member_data(path)

    def plain_zlib() -> None:
        zlib.decompressobj(-15).decompress(raw)

    def best(run: Callable[[], None]) -> float:
        run()
        times = []
        for _ in range(3):
            start = time.perf_counter()
            run()
            times.append(time.perf_counter() - start)
        return min(times)

    return [
        best(full(ArchiveyConfig())),
        best(full(off)),
        best(first_byte),
        best(plain_zlib),
    ]


_SEEK_SIZES_MIB = (4, 16, 64)
_ORDERS = ("ascending", "descending", "random")


def _seek_reads(path: str, mode: str, order: str) -> float:
    """Seconds for 20 reads of 64 KiB after seeks in ``order``, after the open and the
    first byte; best of three."""
    from archivey import open_archive
    from archivey.config import AcceleratorMode, ArchiveyConfig

    accel = AcceleratorMode.OFF if mode == "off" else AcceleratorMode.ON
    config = ArchiveyConfig(use_rapidgzip=accel)
    best = float("inf")
    for attempt in range(4):
        with open_archive(path, config=config, seekable_members=True) as reader:
            member = reader.members()[0]
            assert member.size is not None
            step = (member.size - 65536) // 20
            offsets = [i * step for i in range(20)]
            if order == "descending":
                offsets.reverse()
            elif order == "random":
                random.Random(attempt).shuffle(offsets)
            with reader.open(member) as stream:
                stream.read(1)
                start = time.perf_counter()
                for offset in offsets:
                    stream.seek(offset)
                    stream.read(65536)
                elapsed = time.perf_counter() - start
        if attempt:
            best = min(best, elapsed)
    return best


def _seeks(root: Path) -> None:
    print()
    print("20 reads of 64 KiB after seeks, one DEFLATE member, best of three, ms")
    print(
        f"{'member':8}" + "".join(f"{o + ' OFF':>16}{o + ' ON':>15}" for o in _ORDERS)
    )
    payload = _text(max(_SEEK_SIZES_MIB) * _MIB)
    for mib in _SEEK_SIZES_MIB:
        path = root / f"deflate-1x-{mib}M.zip"
        _zip(path, payload[: mib * _MIB], 1, zipfile.ZIP_DEFLATED)
        cells = ""
        for order in _ORDERS:
            for mode in ("off", "on"):
                seconds = _in_fresh_process("--seeks", str(path), mode, order)[0]
                width = 16 if mode == "off" else 15
                cells += f"{seconds * 1000:{width}.0f}"
        print(f"{mib:>4} MiB" + cells)


def _large_member(root: Path) -> None:
    path = root / "deflate-1x-40M.zip"
    _zip(path, _text(40 * _MIB), 1, zipfile.ZIP_DEFLATED)
    auto, off, first, plain = _in_fresh_process("--parts", str(path))
    print()
    print("One 40 MiB DEFLATE member, seekable_members=True, best of three, ms")
    print(f"  full read, AUTO (rapidgzip child): {auto * 1000:.0f}")
    print(f"  full read, OFF (stdlib zlib):      {off * 1000:.0f}")
    print(f"  AUTO open + first byte:            {first * 1000:.0f}")
    print(f"  plain zlib decode of the raw data: {plain * 1000:.0f}")


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--one":
        print(_time_one(sys.argv[2], sys.argv[3]))
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--parts":
        print(*_parts(sys.argv[2]))
        return
    if len(sys.argv) == 5 and sys.argv[1] == "--seeks":
        print(_seek_reads(sys.argv[2], sys.argv[3], sys.argv[4]))
        return
    only_seeks = sys.argv[1:] == ["--only", "seeks"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if not only_seeks:
            _full_reads(_build(root))
            _large_member(root)
        _seeks(root)


if __name__ == "__main__":
    main()
