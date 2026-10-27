"""Measure what ``ArchiveyConfig.process_isolation`` costs, per MiB and per decoder.

The ``ProcessIsolation`` docstrings and the security page quote these figures. Each
archive below is read in full under ``NONE``, ``KNOWN_CRASHES`` and ``NATIVE_DECODERS``,
with the accelerators off, each case in a fresh interpreter (a warm-up read, then the
best of three). Single streams of several sizes give the cost per MiB of output; ZIP and
7z archives of one member and of many give the cost per decoder. A solid 7z folder is
read by one decoder, so it pays the per-decoder cost once; what it pays per member read
comes out of the same pairs. The derived figures are printed after the table.

The 7z archives need a ``7z`` program on ``PATH`` (py7zr's PPMd writer produces
archives that fail their own CRC); without one, or where it refuses a method, their rows
are skipped with a note, as the zstd rows are without a zstd module. The payload is
random words, which gzip compresses about two to one.

Usage::

    uv run --no-sync python scripts/bench_process_isolation.py

Wall times on one machine; they are for comparing the columns.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

_MIB = 1 << 20
# Members in the many-member archives; the derived figures divide by it.
_MEMBERS = 1024
_MODES = ("none", "known_crashes", "native_decoders")


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


def _zstd_compress(data: bytes) -> bytes | None:
    try:
        from compression import zstd  # type: ignore[import-not-found]
    except ImportError:
        try:
            from backports import zstd  # type: ignore[import-not-found,no-redef]
        except ImportError:
            return None
    return zstd.compress(data)


def _write_7z(
    path: Path, members: dict[str, bytes], method: str, *, solid: bool
) -> bool:
    program = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if program is None:
        print(f"skipped {path.name}: no 7z program on PATH")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in members.items():
            Path(tmp, name).write_bytes(data)
        done = subprocess.run(
            [
                program,
                "a",
                f"-m0={method}",
                f"-ms={'on' if solid else 'off'}",
                str(path),
            ]
            + sorted(members),
            cwd=tmp,
            check=False,
            capture_output=True,
            text=True,
        )
    if done.returncode != 0:
        print(f"skipped {path.name}: {program} failed: {done.stderr.strip()}")
        return False
    return True


def _zip_name(count: int) -> str:
    return f"deflate-{count}x-8M.zip"


def _7z_name(method: str, *, solid: bool) -> str:
    return f"{method.lower()}-{'solid' if solid else 'nonsolid'}-{_MEMBERS}x4K.7z"


def _build(root: Path) -> list[Path]:
    payload = _text(64 * _MIB)
    paths: list[Path] = []

    def single(name: str, data: bytes | None) -> None:
        if data is None:
            print(f"skipped {name}: no zstd module (Python 3.14, or backports.zstd)")
            return
        (root / name).write_bytes(data)
        paths.append(root / name)

    for mib in (1, 16, 64):
        part = payload[: mib * _MIB]
        single(f"{mib:02d}M.gz", gzip.compress(part, 6, mtime=0))
        single(f"{mib:02d}M.zst", _zstd_compress(part))
        if mib <= 16:
            single(f"{mib:02d}M.bz2", bz2.compress(part, 9))
            single(f"{mib:02d}M.xz", lzma.compress(part))
    for count in (1, _MEMBERS):
        name = _zip_name(count)
        each = 8 * _MIB // count
        with zipfile.ZipFile(root / name, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(count):
                zf.writestr(f"m{i:05}.txt", payload[i * each : (i + 1) * each])
        paths.append(root / name)
    small = {
        f"m{i:05}.txt": payload[i * 4096 : (i + 1) * 4096] for i in range(_MEMBERS)
    }
    for method, solid in (
        ("LZMA2", False),
        ("LZMA2", True),
        ("PPMd", False),
        ("PPMd", True),
    ):
        name = _7z_name(method, solid=solid)
        if _write_7z(root / name, small, method, solid=solid):
            paths.append(root / name)
    return paths


def _time_one(path: str, mode: str) -> float:
    """Best of three full reads after a warm-up, in this process."""
    from archivey import open_archive
    from archivey.config import AcceleratorMode, ArchiveyConfig, ProcessIsolation

    config = ArchiveyConfig(
        process_isolation=ProcessIsolation(mode),
        use_rapidgzip=AcceleratorMode.OFF,
        use_indexed_bzip2=AcceleratorMode.OFF,
    )

    def read_all() -> None:
        with open_archive(path, config=config) as reader:
            for _member, stream in reader.stream_members():
                if stream is not None:
                    while stream.read(_MIB):
                        pass

    read_all()
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        read_all()
        best = min(best, time.perf_counter() - start)
    return best


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--one":
        print(_time_one(sys.argv[2], sys.argv[3]))
        return
    with tempfile.TemporaryDirectory() as tmp:
        paths = _build(Path(tmp))
        print(f"{'archive':32}" + "".join(f"{mode:>17}" for mode in _MODES))
        results: dict[str, list[float]] = {}
        for path in paths:
            times = [
                float(
                    subprocess.run(
                        [sys.executable, __file__, "--one", str(path), mode],
                        check=True,
                        capture_output=True,
                        text=True,
                        env={**os.environ, "PYTHONWARNINGS": "ignore"},
                    ).stdout.split()[-1]
                )
                for mode in _MODES
            ]
            results[path.name] = times
            base = times[0]
            cells = "".join(f"{t * 1000:9.0f} ms {t / base:4.2f}x" for t in times)
            print(f"{path.name:32}{cells}")
        _print_derived(results)


def _extra(results: dict[str, list[float]], name: str, mode: int) -> float | None:
    """Seconds ``name`` took under ``_MODES[mode]`` beyond ``NONE``."""
    times = results.get(name)
    return None if times is None else times[mode] - times[0]


def _print_derived(results: dict[str, list[float]]) -> None:
    """The per-decoder and per-member figures the docstrings quote, from paired rows:
    the extra time of the many-decoder archive minus that of its one-decoder pair, per
    extra decoder; and a solid folder's extra time per member it reads. A row for a
    codec the mode leaves in this process is marked as the control: its figure is the
    noise between runs, and should be about zero."""
    print()
    pairs = (
        ("ZIP deflate", "deflate", _zip_name(_MEMBERS), _zip_name(1)),
        (
            "7z LZMA2",
            "lzma2",
            _7z_name("LZMA2", solid=False),
            _7z_name("LZMA2", solid=True),
        ),
        (
            "7z PPMd",
            "ppmd",
            _7z_name("PPMd", solid=False),
            _7z_name("PPMd", solid=True),
        ),
    )
    for mode in (1, 2):

        def note(codec: str, mode: int = mode) -> str:
            isolated = _MODES[mode] == "native_decoders" or codec == "ppmd"
            return "" if isolated else "  (control: not isolated in this mode)"

        for label, codec, many, one in pairs:
            extra_many = _extra(results, many, mode)
            extra_one = _extra(results, one, mode)
            if extra_many is None or extra_one is None:
                continue
            per = (extra_many - extra_one) / (_MEMBERS - 1) * 1000
            print(
                f"{_MODES[mode]:>16} {label:12} per decoder: {per:.2f} ms{note(codec)}"
            )
        for label, codec, _many, one in pairs[1:]:
            extra = _extra(results, one, mode)
            if extra is not None:
                per = extra / _MEMBERS * 1000
                print(
                    f"{_MODES[mode]:>16} {label} solid, per 4 KiB member read: "
                    f"{per:.2f} ms{note(codec)}"
                )


if __name__ == "__main__":
    main()
