"""Per-member cost and throughput, fitted from a ladder of archives.

A whole-archive wall time mixes three costs: a fixed one per open, one per member, and
one per byte of data. A single fixture only gives their sum, so a ratio against the
stdlib on it says little about an archive of a different shape. This module times a
ladder of archives, from many tiny members to a few large ones, and fits

    list_ms = open_ms + members x list_us
    read_ms = open_ms + members x read_us + MiB / throughput

``open_ms`` and ``list_us`` come from listing the two fit rungs, 2048 x 8 KiB and
64 x 256 KiB. ``read_us`` and the throughput come from reading the same two rungs with
``open_ms`` held fixed: both hold 16 MiB, so their difference fixes the per-member
cost, and the 256 KiB rung, where members cost little, fixes the throughput. The
other rungs are not used in the fit. Each one gets a prediction and the error against
what it measured; a large error means the linear model does not hold for that shape,
and the fitted numbers should not be quoted for it.

The throughput rung is in the middle of the ladder, so there are check rungs on
both sides of it: 512 x 16 KiB tests the model between the two fit rungs, and
16 x 1 MiB and 4 x 4 MiB test it beyond them, where real archives of large members
sit. With the heap warm (below), the cost per byte stays about the same up to 4 MiB
members on both sides.

Both sides are fitted the same way: archivey (``open_archive``) and the stdlib peer
(``zipfile`` / ``tarfile`` read in one forward pass). Both read the same files, so
the comparison between them is fair even where the absolute numbers move from host
to host.

Throughput depends on the codec and on how well the data compresses, so it is one
number per ladder: DEFLATE ZIP and uncompressed TAR. The ladder builds its own
archives (its shapes are not ``fixtures.Scale``s) from its own payload, in which
every 4 KiB block is 1 KiB of seeded random bytes and 3 KiB of zeros. That keeps
the compression ratio near 4:1 at every member size; the harness corpus repeats one
4 KiB pattern, so its large members compress about 250:1 and the per-byte work would
change with member size. Uncompressed TAR runs no codec, so the report shows no
throughput for it: its byte cost is only what is left of a 256 KiB read once the
per-member cost (fitted on the 8 KiB rung) is taken out, about a quarter of the
measurement, so it carries the per-member error several times over and the large
check rungs miss it on most runs. The fit is still in the JSON.

Every rung is timed with the heap in the same state. glibc raises its mmap threshold
after a large block is freed, and from then on smaller output buffers come from the
heap without page faults: a zipfile read of 64 x 256 KiB took 11.7 ms in a fresh
process and 6.6 ms after one 4 MiB block had been allocated and freed. The
threshold has to end up above a request for that request to come off the heap, so a
block the size of the largest member warms every rung but the largest: the
4 x 4 MiB read still took about 9000 page faults per pass after a 4 MiB block, and
about 200 after an 8 MiB one (zipfile 35.5 ms against 25.5 ms). So before timing
anything, the run allocates and frees one block twice the size of the largest
member, which puts every rung, and both sides, in the warm state a long-running
process has.

The report shows the open cost, the reading rate and the throughput. The reading rate
is members per second through a ``stream_members()`` pass with the byte cost taken
out, so it includes listing each member; the listing fit is kept in the JSON only.

The smallest members are 8 KiB, not a few bytes, because of TAR. Its reader takes an
8 KiB block per header read, so headers of members under about 7.5 KiB come several
to a read, and such an archive lists and reads faster per member than one with larger
members, where every header costs its own seek and read. With 16-byte members at the
tiny end, the fit took the cheap case as the per-member cost and every middle rung
came out slower than predicted. Archives of very small TAR members do better than the
fitted rate.

Run::

    uv run python -m benchmarks.cost_model

``benchmarks.harness --mode full`` runs it too and adds a "Cost model" section to its
report and a ``cost_model`` key to its JSON. Nothing here is a gate.
"""

from __future__ import annotations

import argparse
import io
import json
import random
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from archivey import open_archive

# (members, member size) from many small members to a few large ones.
LADDER: tuple[tuple[int, int], ...] = (
    (2048, 8 * 1024),
    (512, 16 * 1024),
    (64, 256 * 1024),
    (16, 1024 * 1024),
    (4, 4 * 1024 * 1024),
)
# The rungs the fit uses (indices into LADDER); the others check it.
FIT_RUNGS = (0, 2)
# A check rung whose list or read time is further than this from the prediction is
# flagged in the report, and its side's row is marked. The listing fit counts too,
# because the published open cost comes from it. A smaller miss passes unflagged, so
# the fitted numbers carry about this much slack.
CHECK_TOLERANCE = 0.25
# ...and by at least this much. Listing a large-member rung takes well under a
# millisecond, where timer and scheduler noise alone is a large fraction; like the
# drift gate's cost floor, this keeps such rungs from flagging every row.
CHECK_MIN_ABS_MS = 0.5
MIB = 1024 * 1024


@dataclass
class Rung:
    members: int
    member_size: int
    list_ms: float
    read_ms: float


@dataclass
class Fit:
    open_ms: float
    list_us_per_member: float
    read_us_per_member: float
    throughput_mib_s: float | None
    """None when the fit came out non-positive: the bytes cost too little to measure."""

    def predict_list(self, members: int) -> float:
        return self.open_ms + members * self.list_us_per_member / 1e3

    def predict_read(self, members: int, nbytes: int) -> float:
        per_mib = 1e3 / self.throughput_mib_s if self.throughput_mib_s else 0.0
        return (
            self.open_ms
            + members * self.read_us_per_member / 1e3
            + nbytes / MIB * per_mib
        )


def fit(rungs: list[Rung]) -> Fit:
    """Fit the model on the ``FIT_RUNGS`` of ``rungs`` (one per ``LADDER`` entry)."""
    tiny, large = rungs[FIT_RUNGS[0]], rungs[FIT_RUNGS[1]]
    # Listing: two points, two unknowns.
    list_ms_per_member = (tiny.list_ms - large.list_ms) / (tiny.members - large.members)
    open_ms = tiny.list_ms - tiny.members * list_ms_per_member
    # Reading: open_ms held fixed, then two points for per-member and per-MiB.
    n1, b1, t1 = tiny.members, tiny.members * tiny.member_size / MIB, tiny.read_ms
    n2, b2, t2 = large.members, large.members * large.member_size / MIB, large.read_ms
    t1 -= open_ms
    t2 -= open_ms
    det = n1 * b2 - n2 * b1
    read_ms_per_member = (t1 * b2 - t2 * b1) / det
    ms_per_mib = (n1 * t2 - n2 * t1) / det
    return Fit(
        open_ms=open_ms,
        list_us_per_member=list_ms_per_member * 1e3,
        read_us_per_member=read_ms_per_member * 1e3,
        throughput_mib_s=1e3 / ms_per_mib if ms_per_mib > 0 else None,
    )


def _payload(i: int, size: int) -> bytes:
    """Member ``i``'s data: 1 KiB of seeded random bytes then 3 KiB of zeros, per
    4 KiB block, so it compresses about 4:1 whatever ``size`` is."""
    rng = random.Random(i)
    out = bytearray()
    while len(out) < size:
        out += rng.randbytes(1024)
        out += bytes(3072)
    return bytes(out[:size])


def _build_zip(path: Path, members: int, size: int) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(members):
            zf.writestr(f"f{i:05d}.bin", _payload(i, size))


def _build_tar(path: Path, members: int, size: int) -> None:
    with tarfile.open(path, "w") as tf:
        for i in range(members):
            data = _payload(i, size)
            info = tarfile.TarInfo(f"f{i:05d}.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _ay_list(path: Path) -> None:
    with open_archive(path) as reader:
        list(reader.members())


def _ay_read(path: Path) -> None:
    with open_archive(path) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


def _zip_list(path: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        zf.infolist()


def _zip_read(path: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.is_dir():
                zf.read(info)


def _tar_list(path: Path) -> None:
    with tarfile.open(path, "r:") as tf:
        tf.getmembers()


def _tar_read(path: Path) -> None:
    with tarfile.open(path, "r:") as tf:
        for member in tf:
            if member.isfile():
                f = tf.extractfile(member)
                if f is not None:
                    f.read()


LADDERS: dict[str, dict[str, Any]] = {
    "zip": {
        "build": _build_zip,
        "suffix": ".zip",
        "codec": True,
        "peer": "zipfile",
        "peer_list": _zip_list,
        "peer_read": _zip_read,
    },
    "tar": {
        "build": _build_tar,
        "suffix": ".tar",
        "codec": False,
        "peer": "tarfile",
        "peer_list": _tar_list,
        "peer_read": _tar_read,
    },
}


def _best_ms(fns: dict[str, Callable[[], None]], rounds: int) -> dict[str, float]:
    """The fastest of ``rounds`` timings of each function, alternating their order.

    The minimum, not the median: the fit subtracts rung times from each other, and
    once the heap is warm (``run_cost_model``) what is left of the noise is upward.
    """
    for fn in fns.values():
        fn()  # warm the page cache and imports
    best = dict.fromkeys(fns, float("inf"))
    names = list(fns)
    for i in range(rounds):
        for name in names if i % 2 == 0 else reversed(names):
            t0 = time.perf_counter()
            fns[name]()
            best[name] = min(best[name], (time.perf_counter() - t0) * 1e3)
    return best


def measure_ladder(fmt: str, root: Path, *, rounds: int = 9) -> dict[str, Any]:
    """Build (or reuse) ``fmt``'s ladder under ``root``, time it, and fit both sides."""
    spec = LADDERS[fmt]
    ours: list[Rung] = []
    theirs: list[Rung] = []
    for members, size in LADDER:
        path = root / f"ladder-{members}x{size}{spec['suffix']}"
        if not path.exists():
            spec["build"](path, members, size)
        t = _best_ms(
            {
                "ay_list": lambda p=path: _ay_list(p),
                "ay_read": lambda p=path: _ay_read(p),
                "peer_list": lambda p=path: spec["peer_list"](p),
                "peer_read": lambda p=path: spec["peer_read"](p),
            },
            rounds,
        )
        ours.append(Rung(members, size, t["ay_list"], t["ay_read"]))
        theirs.append(Rung(members, size, t["peer_list"], t["peer_read"]))
    out: dict[str, Any] = {
        "format": fmt,
        "peer": spec["peer"],
        "codec": spec["codec"],
        "sides": {},
    }
    for side, rungs in (("archivey", ours), (spec["peer"], theirs)):
        f = fit(rungs)
        checks = []
        for r in (r for i, r in enumerate(rungs) if i not in FIT_RUNGS):
            nbytes = r.members * r.member_size
            for op, measured, predicted in (
                ("list", r.list_ms, f.predict_list(r.members)),
                ("read", r.read_ms, f.predict_read(r.members, nbytes)),
            ):
                err = (measured - predicted) / measured if measured > 0 else 0.0
                checks.append(
                    {
                        "members": r.members,
                        "member_size": r.member_size,
                        "op": op,
                        "measured_ms": measured,
                        "predicted_ms": predicted,
                        "error": err,
                    }
                )
        out["sides"][side] = {
            "fit": asdict(f),
            "rungs": [asdict(r) for r in rungs],
            "checks": checks,
        }
    return out


def run_cost_model(root: Path, *, rounds: int = 9) -> list[dict[str, Any]]:
    """Time both ladders under ``root``. The ladder is a fixed size, 72 MiB of member
    data per format (about 100 MB on disk for both, most of it the uncompressed TAR),
    whatever ``--scale`` the harness was given."""
    root.mkdir(parents=True, exist_ok=True)
    # Warm the heap first (module docstring): one block twice the size of the largest
    # member, allocated and freed.
    block = bytearray(2 * max(size for _members, size in LADDER))
    del block
    return [measure_ladder(fmt, root, rounds=rounds) for fmt in LADDERS]


def _fmt_size(n: int) -> str:
    for unit, scale in (("MiB", MIB), ("KiB", 1024)):
        if n >= scale:
            return f"{n // scale} {unit}"
    return f"{n} B"


def _fmt_rung(rung: tuple[int, int]) -> str:
    return f"{rung[0]} × {_fmt_size(rung[1])}"


def _fmt_open(open_ms: float) -> str:
    """The fitted open cost. It is the listing fit's intercept, so a negative one
    means that fit did not resolve the open cost (it is below what the ladder can
    separate from the per-member cost), not that the cost is near zero."""
    if open_ms < 0:
        return "not resolved"
    return f"{open_ms:.2f} ms" if open_ms >= 0.01 else "under 0.01 ms"


def _fmt_rate(us_per_member: float) -> str:
    """A per-member cost as members per second, the figure a reader can weigh
    against their own archive."""
    if us_per_member <= 0:
        return "too fast to fit"
    rate = 1e6 / us_per_member
    if rate >= 1e6:
        return f"{rate / 1e6:.1f}M members/s"
    return f"{rate / 1e3:.0f}k members/s"


def format_cost_model(results: list[dict[str, Any]]) -> list[str]:
    """Markdown lines for the harness report."""
    lines = [
        "",
        "## Cost model",
        "",
        f"Fitted from {_fmt_rung(LADDER[FIT_RUNGS[0]])} and "
        f"{_fmt_rung(LADDER[FIT_RUNGS[1]])}, checked against "
        + ", ".join(_fmt_rung(r) for i, r in enumerate(LADDER) if i not in FIT_RUNGS)
        + " (see `benchmarks/cost_model.py`). Reading is members per second "
        "through a `stream_members()` pass, listing included, with the byte cost taken "
        "out. Throughput is the data rate once per-member costs are taken out, on data "
        "that compresses about 4:1. Uncompressed TAR shows none: with no codec its byte "
        "cost is a small remainder of the fit, and its large check rungs are expected "
        "to miss. Both sides "
        "read the same files, so the comparison between them holds even where the "
        "absolute numbers move between hosts. A row marked * has a check rung whose "
        f"listing or read time is more than {CHECK_TOLERANCE:.0%} and at least "
        f"{CHECK_MIN_ABS_MS} ms off its fit (the open cost comes from the listing "
        "fit); a smaller miss is not flagged. "
        "Not a gate.",
        "",
        "| format | side | open | reading | throughput |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    flagged: list[str] = []
    for res in results:
        for side, data in res["sides"].items():
            f = data["fit"]
            thr = f["throughput_mib_s"]
            misses = [
                c
                for c in data["checks"]
                if abs(c["error"]) > CHECK_TOLERANCE
                and abs(c["measured_ms"] - c["predicted_ms"]) >= CHECK_MIN_ABS_MS
            ]
            mark = " \\*" if misses else ""
            lines.append(
                f"| {res['format']} | {side}{mark} | {_fmt_open(f['open_ms'])} | "
                f"{_fmt_rate(f['read_us_per_member'])} | "
                + (
                    "no codec |"
                    if not res.get("codec", True)
                    else f"{thr:.0f} MiB/s |"
                    if thr
                    else "too fast to fit |"
                )
            )
            for c in misses:
                flagged.append(
                    f"- {res['format']} {side} {c['op']} "
                    f"{c['members']} × {_fmt_size(c['member_size'])}: measured "
                    f"{c['measured_ms']:.2f} ms, predicted {c['predicted_ms']:.2f} ms "
                    f"({c['error']:+.0%})"
                )
    lines.append("")
    if flagged:
        lines.append(
            f"Check rungs off the fit by more than {CHECK_TOLERANCE:.0%} and "
            f"{CHECK_MIN_ABS_MS} ms (the rows marked *; treat their numbers with care):"
        )
        lines.extend(flagged)
    else:
        lines.append(
            f"Every check rung is within {CHECK_TOLERANCE:.0%} or {CHECK_MIN_ABS_MS} ms "
            "of the fit's prediction."
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=None)
    parser.add_argument("--rounds", type=int, default=9)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
    root = args.fixture_dir or Path(tempfile.mkdtemp(prefix="archivey-ladder-"))
    results = run_cost_model(root, rounds=args.rounds)
    print("\n".join(format_cost_model(results)))
    if args.json_out is not None:
        args.json_out.write_text(json.dumps(results, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
