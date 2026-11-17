"""Round 4: probe strategies that follow the restart cost, damage 3 MB to 100 MB deep.

Usage (from the repo root), one codec per process:
    uv run python dev-docs/investigations/redecode-probe-strategies/depth.py \
        ppmd8-flip 3000000:0/260000/520000/780000,100000000:0/260000/520000/780000 \
        65536,1048576 none,L2048,K1024,SQ,KSQ > results.jsonl

A depth ``base:o1/o2`` runs ``base + o1``, ``base + o2``, ... so the damage falls at
different places in a read. Rows are bench.py's, one JSON line per run.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
import bench

import archivey.internal.streams.decompressor_stream as ds

# Where the failing call started, and the seek point a restart decodes from.
CTX = {"before": 0, "point": 0}
_restart = ds.DecompressorStream._redecode_restart
_redecode = ds.DecompressorStream._redecode_to_error


def restart(self: Any, point: Any, target: int) -> Any:
    CTX["point"] = point.decompressed_offset
    return _restart(self, point, target)


def redecode(self: Any, before: int) -> bytes:
    CTX["before"] = before
    return _redecode(self, before)


ds.DecompressorStream._redecode_restart = restart
ds.DecompressorStream._redecode_to_error = redecode
CHILD = {"on": False}


def behind_plus(done: int) -> int:
    """Bytes a restart decodes to get back to ``done``."""
    return CTX["before"] + done - CTX["point"]


def scaled_stretch(per_call: int, split: int = 64):
    """K: one byte per call over max(2 KiB, restart bytes / per_call), then g2r64."""

    def f(done: int, hi: int, met: bool) -> int:
        stretch = max(2048, behind_plus(done) // per_call)
        if not met:
            return 1 if done < stretch else max(1, min(hi - done, done))
        return 1 if hi - done <= stretch else max(1, (hi - done) // split)

    return f


def sqrt_rule(per_call: float, restart_calls: float, front: bool):
    """SQ (front=False): one byte at the start and over a tail of F + sqrt(2F)
    bytes, probes of sqrt(2n) otherwise, F the restart cost in calls. KSQ (front=True)
    also steps one byte per call while the search has covered less than F."""

    def f(done: int, hi: int, met: bool) -> int:
        left = hi - done
        if done == 0 or left <= 1:
            return 1
        cost = restart_calls + behind_plus(done) / per_call
        if (front and not met and done < cost) or left <= cost + math.sqrt(2 * cost):
            return 1
        return max(2, min(left - 1, math.ceil(math.sqrt(2 * left))))

    return f


def by_mode(inproc: Any, child: Any):
    return lambda d, h, m: (child if CHILD["on"] else inproc)(d, h, m)


bench.STRATS.update(
    {
        "K1024": scaled_stretch(1024),
        # The per-call costs measured here: about 1 µs in process with gzip at 5 ns
        # and xz at 15 ns a byte; about 0.1 ms to a child with PPMd at 190 ns a byte.
        "SQ": by_mode(sqrt_rule(200, 5, False), sqrt_rule(512, 150, False)),
        "KSQ-by-mode": by_mode(sqrt_rule(100, 5, True), sqrt_rule(512, 150, True)),
        "KSQ": by_mode(sqrt_rule(1024, 5, True), sqrt_rule(1024, 150, True)),
    }
)


def main() -> None:
    name = sys.argv[1]
    CHILD["on"] = name.startswith(("ppmd", "bzip3"))
    depths = []
    for spec in sys.argv[2].split(","):
        base, _, offsets = spec.partition(":")
        depths += [
            int(base) + int(o) for o in (offsets.split("/") if offsets else ["0"])
        ]
    sys.argv = [sys.argv[0], name, ",".join(map(str, depths)), *sys.argv[3:5]]
    bench.main()


if __name__ == "__main__":
    main()
