"""What a caller-supplied stream costs, measured across two source trees.

The harness (``benchmarks/harness.py``) opens every case from a ``Path``. That is the
cheap path and the one the gate watches, but it is blind to the source boundary's
treatment of a *stream*: a ``Path`` is opened by the reader, which owns the handle, so
nothing the boundary does to a caller's object shows up there at all. This probe fills
that gap. It is a **probe, not a gate** — it writes no baseline and CI does not run it.

Run it against one tree::

    uv run --extra all python -m benchmarks.caller_stream_probe --repeats 8

Compare two trees by pointing ``PYTHONPATH`` at each one's ``src`` in turn. The
interpreter, the installed dependencies and the fixtures stay identical, so the only
thing that differs is archivey itself::

    git worktree add /tmp/before <sha>
    ARCHIVEY_BENCH_CACHE=/tmp/bench-corpus \\
        PYTHONPATH=/tmp/before/src uv run --no-sync python -m \\
        benchmarks.caller_stream_probe --repeats 8 --out /tmp/before.json
    ARCHIVEY_BENCH_CACHE=/tmp/bench-corpus \\
        uv run --no-sync python -m benchmarks.caller_stream_probe \\
        --repeats 8 --out /tmp/after.json
    python -m benchmarks.caller_stream_probe --compare /tmp/before.json /tmp/after.json

``ARCHIVEY_BENCH_CACHE`` is what makes the two sides comparable: without it each run
builds its own corpus, and the harness's first comparison rule is to check the workload
before the clock. This module imports only the public API and
``benchmarks.fixtures``, so one copy of it runs unchanged against an older tree that
never contained it.

**Reading the numbers.** Per-case wall noise here is a few percent, so the driver
alternates the two sides and takes the per-case minimum, as ``harness.py`` prescribes;
one run each way cannot resolve a small effect. Every shape is a treatment, ``path``
included: the source boundary builds one object for a path too, so no shape is left
untouched to serve as the control. The noise floor comes from each side instead. With
``--compare-globs`` and at least two runs a side, the runs of one side are split into
odd and even halves and compared with each other; that ratio is what the same code
measures against itself, and every before/after ratio should be read against it, not
against 1.00.

The shapes: ``path`` is a ``Path``; ``file`` is ``open(path, "rb")``, already buffered;
``bytesio`` is a ``BytesIO``, also already buffered; ``raw`` is
``open(path, "rb", buffering=0)``, a seekable ``RawIOBase`` with no buffer, the one shape
the boundary adds a read buffer to.

Measurement is **off**. It is the benchmark harness's own switch, it adds a wrapper on
both sides, and an ordinary caller never enables it — so leaving it on would measure a
cost nobody pays and hide the one they do.
"""

from __future__ import annotations

import argparse
import glob
import io
import json
import statistics
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import BinaryIO

from archivey import open_archive
from benchmarks import fixtures

_OPS = ("open_list", "read_all")
_SHAPES = ("path", "file", "bytesio", "raw")


def _op_open_list(source: Path | BinaryIO) -> int:
    with open_archive(source) as reader:
        _ = reader.info
        return len(list(reader.members()))


def _op_read_all(source: Path | BinaryIO) -> int:
    total = 0
    with open_archive(source) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                total += len(stream.read())
    return total


_OP_FUNCS: dict[str, Callable[[Path | BinaryIO], int]] = {
    "open_list": _op_open_list,
    "read_all": _op_read_all,
}


def _cases(root: Path | None, scale: str) -> list[tuple[str, Path]]:
    """The harness's own fixtures, plus its listing-heavy 7z.

    The wrapper's cost is per call rather than per byte, so an archive of many small
    members is where it has the best chance of showing; ``solid_7z`` is the opposite
    end, where one long decode dwarfs everything at the source.
    """
    fx = fixtures.materialize_fixtures(root, scale=scale)
    candidates: list[tuple[str, Path | None]] = [
        ("zip", fx.zip_path),
        ("zip_lzma", fx.zip_lzma_path),
        ("tar_gz", fx.targz_path),
        ("solid_7z", fx.solid_7z),
        ("many_member_7z", fx.many_7z),
    ]
    return [(name, path) for name, path in candidates if path is not None]


def _time_one(
    op: Callable[[Path | BinaryIO], int],
    make_source: Callable[[], Path | BinaryIO],
    repeats: int,
) -> tuple[float, int]:
    """Best of ``repeats``, with the source built outside the clock every time.

    A stream is consumed by the op, so it cannot be reused; building it inside the
    timed region would charge one shape for a ``BytesIO`` construction and the other
    for an ``open()``, which is not what is being compared.
    """
    best = float("inf")
    result = -1
    for _ in range(repeats):
        source = make_source()
        started = time.perf_counter()
        result = op(source)
        elapsed = time.perf_counter() - started
        if isinstance(source, io.IOBase):
            source.close()
        best = min(best, elapsed)
    return best, result


def _measure(root: Path | None, scale: str, repeats: int) -> dict[str, object]:
    rows: dict[str, dict[str, float]] = {}
    results: dict[str, int] = {}
    for name, path in _cases(root, scale):
        data = path.read_bytes()
        makers: dict[str, Callable[[], Path | BinaryIO]] = {
            "path": lambda path=path: path,  # type: ignore[misc]  # bind the loop var
            "file": lambda path=path: open(path, "rb"),  # type: ignore[misc]  # ditto  # noqa: SIM115 - the handle outlives this statement; its owner closes it
            "bytesio": lambda data=data: io.BytesIO(data),  # type: ignore[misc]  # ditto
            "raw": lambda path=path: open(path, "rb", buffering=0),  # type: ignore[misc]  # ditto  # noqa: SIM115 - the handle outlives this statement; its owner closes it
        }
        for op_name in _OPS:
            for shape in _SHAPES:
                key = f"{name}/{op_name}/{shape}"
                best, result = _time_one(_OP_FUNCS[op_name], makers[shape], repeats)
                rows.setdefault(key, {})["wall_s"] = best
                results[key] = result
    return {
        "archivey_path": _archivey_source_root(),
        "repeats": repeats,
        "scale": scale,
        "cases": rows,
        "results": results,
    }


def _archivey_source_root() -> str:
    import archivey

    return str(Path(archivey.__file__).resolve().parent.parent)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _merge_best(runs: Iterable[dict[str, object]]) -> dict[str, float]:
    """Per-case minimum across alternating runs of the same side."""
    best: dict[str, float] = {}
    for run in runs:
        cases = run["cases"]
        assert isinstance(cases, dict)
        for key, row in cases.items():
            wall = float(row["wall_s"])
            if key not in best or wall < best[key]:
                best[key] = wall
    return best


def _noise_floor(runs: list[dict[str, object]]) -> list[float]:
    """Per-case ratios of one side's odd runs against its even runs.

    Both halves ran the same code, so what these ratios show is the measurement's own
    spread. Needs two runs; with fewer there is nothing to split and the list is empty.
    """
    if len(runs) < 2:
        return []
    odd = _merge_best(runs[0::2])
    even = _merge_best(runs[1::2])
    return [even[key] / odd[key] for key in odd if key in even]


def _compare(before_paths: list[Path], after_paths: list[Path]) -> int:
    before_runs = [_load(p) for p in before_paths]
    after_runs = [_load(p) for p in after_paths]
    for label, runs in (("before", before_runs), ("after", after_runs)):
        results = [run["results"] for run in runs]
        if any(r != results[0] for r in results[1:]):
            print(f"{label}: runs disagree on what was read; refusing to compare")
            return 1
    if before_runs[0]["results"] != after_runs[0]["results"]:
        print("the two sides read different data; the numbers are not comparable")
        return 1

    before = _merge_best(before_runs)
    after = _merge_best(after_runs)
    print(f"{'case':<38} {'before ms':>10} {'after ms':>10} {'ratio':>7}")
    by_shape: dict[str, list[float]] = {}
    for key in sorted(before):
        if key not in after:
            continue
        ratio = after[key] / before[key]
        by_shape.setdefault(key.rsplit("/", 1)[1], []).append(ratio)
        print(
            f"{key:<38} {before[key] * 1000:>10.2f} {after[key] * 1000:>10.2f} "
            f"{ratio:>7.3f}"
        )
    print()
    for shape in _SHAPES:
        ratios = by_shape.get(shape)
        if ratios:
            print(f"{shape + ' sources:':<24} median {statistics.median(ratios):.3f}")
    for label, runs in (("before", before_runs), ("after", after_runs)):
        floor = _noise_floor(runs)
        if floor:
            spread = max(abs(1 - r) for r in floor)
            print(
                f"noise floor ({label}, odd vs even runs): "
                f"median {statistics.median(floor):.3f}, widest {spread:.1%}"
            )
        else:
            print(f"noise floor ({label}): needs two or more runs")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--scale", default=fixtures.DEFAULT_SCALE)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    parser.add_argument(
        "--compare-globs",
        nargs=2,
        metavar=("BEFORE_GLOB", "AFTER_GLOB"),
        help="Compare every run matching each glob, taking the per-case minimum.",
    )
    args = parser.parse_args(argv)

    if args.compare:
        return _compare([Path(args.compare[0])], [Path(args.compare[1])])
    if args.compare_globs:
        # glob.glob, not Path.glob: the runs usually live outside the repo and
        # Path.glob refuses an absolute pattern.
        before = [Path(p) for p in sorted(glob.glob(args.compare_globs[0]))]
        after = [Path(p) for p in sorted(glob.glob(args.compare_globs[1]))]
        if not before or not after:
            print("no runs matched one of the globs")
            return 1
        return _compare(before, after)

    report = _measure(args.root, args.scale, args.repeats)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out} ({report['archivey_path']})")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
