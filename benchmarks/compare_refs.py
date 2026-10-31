"""Compare harness wall times of two refs measured on the same machine (stdlib only).

``benchmark-compare.yml`` runs ``benchmarks.harness`` for a baseline ref and a
candidate ref in turn, several rounds each, on one runner, and hands every JSON to
this script. For each case it keeps the fastest run of each side, which is the run
the machine disturbed least, and prints one Markdown table:

- ``baseline ms`` / ``candidate ms``: the fastest wall time of each side.
- ``x``: candidate over baseline. Below 1 is faster.
- ``x vs peer``: the same ratio after dividing each side by its own stdlib peer from
  the same runs (``wall_ratio``), which cancels a runner that sped up or slowed down
  between the two sides. Empty where the case has no peer.

A case counts as slower or faster only when ``x`` passes the band *and* the gap is
at least ``--min-ms``, so sub-millisecond cases do not flag on timer noise. Cases
only one side has (new or removed cases) are listed apart. The script never fails
on a timing: it only reports.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load(paths: list[Path]) -> dict[str, list[dict[str, Any]]]:
    """Every run's row for each case, skipped rows left out."""
    rows: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        payload = json.loads(path.read_text())
        for row in payload.get("results", []):
            if row.get("skipped") or not row.get("wall_s"):
                continue
            rows.setdefault(row["case"], []).append(row)
    return rows


def _best(rows: list[dict[str, Any]]) -> tuple[float, float | None]:
    """The fastest wall time, and the fastest peer time of the same runs."""
    wall = min(r["wall_s"] for r in rows)
    peers = [r["stdlib_wall_s"] for r in rows if r.get("stdlib_wall_s")]
    return wall, (min(peers) if peers else None)


def compare(
    baseline: dict[str, list[dict[str, Any]]],
    candidate: dict[str, list[dict[str, Any]]],
    *,
    labels: tuple[str, str],
    band: float,
    min_ms: float,
) -> str:
    """The Markdown report for two sides' rows."""
    lines = [
        f"### Wall time: `{labels[1]}` vs `{labels[0]}`",
        "",
        (
            f"Fastest of {_runs(baseline)} baseline and {_runs(candidate)} candidate "
            f"run(s) per case, same runner. Flagged when x is past {band:.2f} (or "
            f"below {1 / band:.2f}) and the gap is at least {min_ms:g} ms."
        ),
        "",
        "| case | baseline ms | candidate ms | x | x vs peer | |",
        "|---|---:|---:|---:|---:|---|",
    ]
    slower = faster = 0
    for case in sorted(set(baseline) & set(candidate)):
        b_wall, b_peer = _best(baseline[case])
        c_wall, c_peer = _best(candidate[case])
        x = c_wall / b_wall
        gap_ms = abs(c_wall - b_wall) * 1e3
        norm = ""
        if b_peer and c_peer:
            norm = f"{(c_wall / c_peer) / (b_wall / b_peer):.2f}"
        flag = ""
        if gap_ms >= min_ms and x > band:
            flag, slower = "slower", slower + 1
        elif gap_ms >= min_ms and x < 1 / band:
            flag, faster = "faster", faster + 1
        lines.append(
            f"| {case} | {b_wall * 1e3:.1f} | {c_wall * 1e3:.1f} | {x:.2f} | "
            f"{norm} | {flag} |"
        )
    lines += ["", f"**{slower} slower, {faster} faster.**"]
    only_b = sorted(set(baseline) - set(candidate))
    only_c = sorted(set(candidate) - set(baseline))
    if only_b:
        lines += ["", "Only in the baseline: " + ", ".join(f"`{c}`" for c in only_b)]
    if only_c:
        lines += ["", "Only in the candidate: " + ", ".join(f"`{c}`" for c in only_c)]
    return "\n".join(lines) + "\n"


def _runs(rows: dict[str, list[dict[str, Any]]]) -> int:
    return max((len(v) for v in rows.values()), default=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", type=Path, nargs="+", required=True)
    parser.add_argument("--candidate", type=Path, nargs="+", required=True)
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--candidate-label", default="candidate")
    parser.add_argument("--band", type=float, default=1.15)
    parser.add_argument("--min-ms", type=float, default=1.0)
    parser.add_argument("--md-out", type=Path)
    args = parser.parse_args(argv)
    report = compare(
        _load(args.baseline),
        _load(args.candidate),
        labels=(args.baseline_label, args.candidate_label),
        band=args.band,
        min_ms=args.min_ms,
    )
    if args.md_out is not None:
        args.md_out.write_text(report)
    sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
