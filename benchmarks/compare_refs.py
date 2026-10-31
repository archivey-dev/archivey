"""Compare harness wall times of two refs measured on the same machine (stdlib only).

``benchmark-compare.yml`` runs ``benchmarks.harness`` for a baseline ref and a
candidate ref in turn, several rounds each, on one runner, and hands every JSON to
this script. For each case it keeps each side's fastest run, the run the machine
disturbed least, and prints one Markdown table:

- ``baseline ms`` / ``candidate ms``: the wall time of each side's fastest run.
- ``x``: candidate over baseline. Below 1 is faster.
- ``x vs peer``: the same ratio after dividing each side's fastest wall time by the
  stdlib peer time measured in that same run, which cancels a runner that sped up or
  slowed down between the two sides. Empty where that run has no peer.
- ``workload``: why the two sides may not be comparable. ``input differs`` means the
  fixture changed between the refs (``unpacked_bytes``), so the wall times measure
  different work. ``decoded A -> B`` means archivey decoded a different amount for
  the same input (``bytes_decompressed``): a finding of its own, less work or
  over-decoding.

A case counts as slower or faster only when ``x`` passes the band *and* the gap is
at least ``--min-ms``. Effects inside the band are not resolved by a few rounds; the
15-20-run procedure in ``benchmarks/harness.py`` measures those. Cases with no
comparable data on one side (added, removed, or skipped in every run there) are
listed apart, a skipped case with its note. The script never fails on a timing.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Side:
    """One side's runs: every measured row per case, and why skipped cases were."""

    rows: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    scales: set[str] = field(default_factory=set)
    runs: int = 0


def _load(paths: list[Path]) -> Side:
    side = Side(runs=len(paths))
    for path in paths:
        payload = json.loads(path.read_text())
        side.scales.add(json.dumps(payload.get("scale_detail"), sort_keys=True))
        for row in payload.get("results", []):
            case = row["case"]
            if row.get("skipped") or not row.get("wall_s"):
                side.skipped.setdefault(case, row.get("notes") or "skipped")
                continue
            side.rows.setdefault(case, []).append(row)
    for case in side.rows:
        side.skipped.pop(case, None)  # measured in at least one run
    return side


def _fastest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return min(rows, key=lambda r: r["wall_s"])


def _workload(b: dict[str, Any], c: dict[str, Any]) -> str:
    notes = []
    if b.get("unpacked_bytes") != c.get("unpacked_bytes"):
        notes.append("input differs")
    if b.get("bytes_decompressed") != c.get("bytes_decompressed"):
        notes.append(
            f"decoded {b.get('bytes_decompressed')} -> {c.get('bytes_decompressed')}"
        )
    return "; ".join(notes)


def compare(
    baseline: Side,
    candidate: Side,
    *,
    labels: tuple[str, str],
    band: float,
    min_ms: float,
) -> str:
    """The Markdown report for two sides."""
    lines = [
        f"### Wall time: `{labels[1]}` vs `{labels[0]}`",
        "",
        (
            f"Fastest of up to {baseline.runs} baseline and {candidate.runs} candidate "
            f"run(s) per case, same runner. Flagged when x is past {band:.2f} (or "
            f"below {1 / band:.2f}) and the gap is at least {min_ms:g} ms. An "
            "unflagged row is not shown to be unchanged: effects inside the band need "
            "the 15-20-run procedure in benchmarks/harness.py."
        ),
    ]
    if baseline.scales != candidate.scales:
        lines += ["", "**The fixture scale differs between the sides.**"]
    lines += [
        "",
        "| case | baseline ms | candidate ms | x | x vs peer | | workload |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    slower = faster = 0
    for case in sorted(set(baseline.rows) & set(candidate.rows)):
        b = _fastest(baseline.rows[case])
        c = _fastest(candidate.rows[case])
        x = c["wall_s"] / b["wall_s"]
        gap_ms = abs(c["wall_s"] - b["wall_s"]) * 1e3
        norm = ""
        if b.get("stdlib_wall_s") and c.get("stdlib_wall_s"):
            b_ratio = b["wall_s"] / b["stdlib_wall_s"]
            norm = f"{(c['wall_s'] / c['stdlib_wall_s']) / b_ratio:.2f}"
        flag = ""
        if gap_ms >= min_ms and x > band:
            flag, slower = "slower", slower + 1
        elif gap_ms >= min_ms and x < 1 / band:
            flag, faster = "faster", faster + 1
        lines.append(
            f"| {case} | {b['wall_s'] * 1e3:.1f} | {c['wall_s'] * 1e3:.1f} | {x:.2f} | "
            f"{norm} | {flag} | {_workload(b, c)} |"
        )
    lines += ["", f"**{slower} slower, {faster} faster.**"]
    for name, mine, other in (
        ("baseline", baseline, candidate),
        ("candidate", candidate, baseline),
    ):
        only = sorted(set(mine.rows) - set(other.rows))
        if only:
            lines += [
                "",
                f"Measured only in the {name} (added, removed, or skipped on the "
                "other side): " + ", ".join(f"`{c}`" for c in only),
            ]
        for case in sorted(mine.skipped):
            lines += [
                "",
                f"Skipped in every {name} run: `{case}` ({mine.skipped[case]})",
            ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", type=Path, nargs="+", required=True)
    parser.add_argument("--candidate", type=Path, nargs="+", required=True)
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--candidate-label", default="candidate")
    parser.add_argument("--band", type=float, default=1.15)
    # One host, one job: a sub-millisecond case that moves is a real change, as in
    # the release checklist's own same-host comparison.
    parser.add_argument("--min-ms", type=float, default=0.0)
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
