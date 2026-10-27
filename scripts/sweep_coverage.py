"""Count codebase-sweep coverage from the `SWEPT` markers on #315.

The sweep is a cold whole-file reading pass over `src/`, run in batches, posting its
findings as review threads on
[#315](https://github.com/archivey-dev/archivey/pull/315). Coverage used to be counted by
eyeballing those threads, and it was wrong twice in a row — 24% and then 35% against a
truth of 12% and 23% — because a file with no findings looks exactly like a file nobody
opened. Both snapshots also counted fifteen maintainer questions as sweep output.

So a sweep now posts one top-level comment per file it finishes, whose first line is a
machine-readable marker (the shape lives in
`.claude/skills/code-review-skill/reference/whole-file-sweep.md`):

    **SWEPT** `src/archivey/internal/backends/zip_reader.py` — pass=S1 date=2026-09-17 \
lines=1612 findings=3 ids=S1-F1,S1-F2,S1-F3 reviewer=cursor head=94468bd

This script reads those lines and reports coverage against the tree it is run in. It
takes whole comment bodies and ignores everything that is not a marker, so you can pipe
the #315 comments in unfiltered:

    gh api --paginate repos/archivey-dev/archivey/issues/315/comments --jq '.[].body' \
      | python3 scripts/sweep_coverage.py

`--paginate` is what makes that correct rather than merely usually correct: the endpoint
serves 100 comments a page, #315 is already past 30 and gains one marker per file swept,
and a truncated fetch loses markers *silently* — the files on the dropped page come back
as unswept and the next batch brief sends an agent over code someone has already read.
Without `gh` — a Claude Code session has none — page explicitly, and raise the range
until the last page prints nothing:

    for p in 1 2 3; do \
      curl -s "https://api.github.com/repos/archivey-dev/archivey/issues/315/comments?per_page=100&page=$p" \
      | python3 -c 'import json,sys; [print(c["body"]) for c in json.load(sys.stdin)]'; \
    done | python3 scripts/sweep_coverage.py

Any other route to the comment bodies works too — the script only cares about the marker
lines — as long as it reaches the last page.

    python3 scripts/sweep_coverage.py --markers markers.txt   # from a file
    python3 scripts/sweep_coverage.py --unswept               # list what is left, biggest first
    python3 scripts/sweep_coverage.py --by-pass               # per-batch breakdown

Counting rules, deliberately narrow:

* **The denominator is the tree, not a remembered number** — every `.py` under `src/`, as
  it stands in this checkout.
* **One marker per path counts once.** A re-sweep posts a second marker; the newest `date=`
  wins and the file is still one file. A path that carries two markers from the *same* pass
  is a double post rather than a re-sweep, so it is reported — it cannot inflate the figure,
  but it means two agents read the same file or one posted twice.
* **Lines come from the tree, not from the marker.** `lines=` in the marker records what
  was read then; the coverage figure is about the code that exists now. Where the two
  differ by more than 10% the file is reported as drifted — it was read, but not as it
  stands.
* **A marker whose path is not in the tree** (renamed, moved, deleted) is reported and not
  counted. It needs re-anchoring by hand: a new marker at the new path, carrying the old
  read's fields unchanged plus a final `moved_from=<old path>`. That marker counts the
  file at its new path, and the old path stops being reported as orphaned. A file whose
  code was folded into another is not re-anchored; it stays reported.
* **Threads are never counted.** Nothing in here looks at findings to decide coverage;
  `findings=` is carried through for the per-batch report only.
* **`ids=` is opaque.** It must be present, and that is all. Batches have used more than one
  ID form and a posted ID is never renumbered, so do not add a check that IDs start with the
  `pass=` value — it would fire on correct history.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# `**SWEPT** `<path>` — key=value key=value ...`
MARKER_RE = re.compile(r"^\s*\*\*SWEPT\*\*\s+`([^`]+)`\s*[—-]\s*(.+?)\s*$")
FIELD_RE = re.compile(r"(\w+)=(\S+)")

REQUIRED_FIELDS = ("pass", "date", "lines", "findings", "ids", "reviewer", "head")
DRIFT_TOLERANCE = 0.10


@dataclass(frozen=True)
class Marker:
    path: str
    batch: str
    date: str
    lines: int
    findings: int
    reviewer: str
    head: str
    moved_from: str | None = None


def parse_markers(text: str) -> tuple[list[Marker], list[str]]:
    """Pull every marker out of `text`. Returns the markers and the malformed lines."""
    markers: list[Marker] = []
    malformed: list[str] = []
    for line in text.splitlines():
        match = MARKER_RE.match(line)
        if match is None:
            continue
        path, rest = match.groups()
        fields = dict(FIELD_RE.findall(rest))
        missing = [name for name in REQUIRED_FIELDS if name not in fields]
        if missing:
            malformed.append(f"{path}: missing {', '.join(missing)}")
            continue
        try:
            lines = int(fields["lines"])
            findings = int(fields["findings"])
        except ValueError:
            malformed.append(f"{path}: lines= and findings= must be integers")
            continue
        markers.append(
            Marker(
                path=path,
                batch=fields["pass"],
                date=fields["date"],
                lines=lines,
                findings=findings,
                reviewer=fields["reviewer"],
                head=fields["head"],
                moved_from=fields.get("moved_from"),
            )
        )
    return markers, malformed


def newest_per_path(markers: list[Marker]) -> dict[str, Marker]:
    """A re-sweep supersedes the earlier read of the same file; the file still counts once."""
    latest: dict[str, Marker] = {}
    for marker in markers:
        previous = latest.get(marker.path)
        if previous is None or marker.date >= previous.date:
            latest[marker.path] = marker
    return latest


def orphaned_paths(
    markers: list[Marker], latest: dict[str, Marker], tree: dict[str, int]
) -> list[str]:
    """Marker paths that are gone from the tree and that no re-anchor marker answers.

    A re-anchor is a marker at a path in the tree whose `moved_from=` names the old
    path. The old marker is left alone on the hub as the record; it is only no longer
    news. Every marker is consulted, not just the newest per path: a later re-sweep at
    the new path supersedes the re-anchor for coverage but carries no `moved_from=`,
    and must not bring the old path back.
    """
    re_anchored = {
        marker.moved_from
        for marker in markers
        if marker.path in tree and marker.moved_from is not None
    }
    return sorted(set(latest) - set(tree) - re_anchored)


def has_drifted(read_lines: int, tree_lines: int) -> bool:
    """Has the file moved far enough since it was read that the reading is stale?

    The band is symmetric: code deleted since the sweep invalidates a reading as surely as
    code added, because what the reviewer reasoned about is gone either way. The boundary
    itself is inside the band — exactly `DRIFT_TOLERANCE` is not yet drift — so a file that
    has grown by a tenth is reported as still swept rather than flickering between the two.
    """
    return abs(tree_lines - read_lines) > DRIFT_TOLERANCE * max(read_lines, 1)


def duplicates_within_a_pass(markers: list[Marker]) -> list[tuple[str, str, int]]:
    """Two markers for one file in one pass: a double post, not a re-sweep."""
    seen: dict[tuple[str, str], int] = {}
    for marker in markers:
        seen[marker.path, marker.batch] = seen.get((marker.path, marker.batch), 0) + 1
    return [(path, batch, n) for (path, batch), n in sorted(seen.items()) if n > 1]


BATCH_KEY_RE = re.compile(r"^([A-Za-z]*)(\d*)(.*)$")


def batch_sort_key(batch: str) -> tuple[str, int, str]:
    """Order batch ids the way a reader counts them: S2 before S15, S3a beside S3.

    Plain `sorted()` is lexicographic, which puts S15 and S16 between S1 and S2 — a
    breakdown nobody can read against the plan. The numeric run is what needs ordering
    numerically; the letters around it fall back to string order, so an unnumbered or
    oddly shaped id still sorts deterministically rather than raising.
    """
    prefix, digits, suffix = BATCH_KEY_RE.match(batch).groups()  # always matches
    return (prefix, int(digits) if digits else -1, suffix)


def tree_line_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        counts[rel] = len(path.read_text(encoding="utf-8").splitlines())
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--markers",
        default="-",
        help="file holding the #315 comment bodies, or - for stdin (the default)",
    )
    parser.add_argument(
        "--unswept", action="store_true", help="list the unswept files, largest first"
    )
    parser.add_argument(
        "--by-pass", action="store_true", help="break the total down by batch"
    )
    args = parser.parse_args()

    raw = (
        sys.stdin.read()
        if args.markers == "-"
        else Path(args.markers).read_text(encoding="utf-8")
    )
    markers, malformed = parse_markers(raw)
    latest = newest_per_path(markers)
    tree = tree_line_counts()

    swept = {path: marker for path, marker in latest.items() if path in tree}
    orphaned = orphaned_paths(markers, latest, tree)
    drifted = [
        (path, marker.lines, tree[path])
        for path, marker in sorted(swept.items())
        if has_drifted(marker.lines, tree[path])
    ]

    total_files, total_lines = len(tree), sum(tree.values())
    swept_lines = sum(tree[path] for path in swept)
    percent = 100.0 * swept_lines / total_lines if total_lines else 0.0

    print(f"src/        {total_files:4d} files  {total_lines:6d} lines")
    print(f"swept       {len(swept):4d} files  {swept_lines:6d} lines  {percent:5.1f}%")
    print(
        f"unswept     {total_files - len(swept):4d} files  "
        f"{total_lines - swept_lines:6d} lines  {100.0 - percent:5.1f}%"
    )

    if args.by_pass:
        print("\nby pass:")
        batches: dict[str, list[Marker]] = {}
        for marker in swept.values():
            batches.setdefault(marker.batch, []).append(marker)
        for batch in sorted(batches, key=batch_sort_key):
            group = batches[batch]
            lines = sum(tree[marker.path] for marker in group)
            findings = sum(marker.findings for marker in group)
            print(
                f"  {batch:<5} {len(group):3d} files  {lines:6d} lines  "
                f"{findings:3d} findings  ({group[0].date})"
            )

    if args.unswept:
        print("\nunswept, largest first:")
        for path, lines in sorted(tree.items(), key=lambda kv: -kv[1]):
            if path not in swept:
                print(f"  {lines:5d}  {path}")

    for path, batch, count in duplicates_within_a_pass(markers):
        print(
            f"\nDUPLICATE marker: {path} has {count} markers from pass {batch} "
            f"(counted once)",
            file=sys.stderr,
        )
    for path, recorded, now in drifted:
        print(
            f"\nDRIFTED  {path}: read at {recorded} lines, now {now}", file=sys.stderr
        )
    for path in orphaned:
        print(f"ORPHANED marker: {path} is not in src/ any more", file=sys.stderr)
    for problem in malformed:
        print(f"MALFORMED marker: {problem}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
