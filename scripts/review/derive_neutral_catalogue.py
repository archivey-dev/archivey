#!/usr/bin/env python3
"""Derive `catalogue-neutral.md` from `catalogue.md` by stripping field 4.

Topic 10's brief (`review/problem-catalogue/brief.md` §Definition of done #4) requires
the redacted view to be *derivable* and committed, so that the fresh-design comparison
in `experiment.md` cannot accidentally be run against the annotated catalogue.

Field 4 ("Answer today") and the per-entry `Sources` list are removed; the id,
category, Problem, Symptom and Evidence survive. Run after editing `catalogue.md`:

    python scripts/review/derive_neutral_catalogue.py

`scripts/tests/test_review_problem_catalogue.py` asserts the committed file matches this
script's output, so the two cannot drift.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = ROOT / "review" / "problem-catalogue" / "catalogue.md"
NEUTRAL = ROOT / "review" / "problem-catalogue" / "catalogue-neutral.md"

ENTRY_RE = re.compile(r"^### ((?:FQ|UL|SEC|PLAT|PERF|API|PKG|CONC)-\d+) — (.*)$")
# Anything from the answer field or the source list onwards is field-4 material.
STRIP_FROM_RE = re.compile(r"^\*\*(?:Answer today|Sources)\.\*\*")

HEADER = """# `catalogue-neutral.md` — the problem catalogue, fields 1–3

**Derived, not authored.** Generated from [`catalogue.md`](catalogue.md) by
`scripts/review/derive_neutral_catalogue.py`, which strips field 4 ("Answer today") and the
per-entry source list. Edit `catalogue.md` and re-run the script; a test asserts this
file matches its output.

This is the artifact the fresh-design comparison is run against
([`experiment.md`](experiment.md)). It exists as a separate committed file so that
redaction is not a manual step at experiment time — the failure it prevents is handing a
frontier model the annotated catalogue by accident, which would invalidate the whole
exercise.

Each entry states a **problem** the world poses, the **symptom** someone observes, and the
**evidence** that it is real. What any particular library does about it is deliberately
absent. Categories: format quirk · upstream library defect · security / hostile input ·
platform & filesystem · performance & memory · API and usage pattern · packaging &
dependency · concurrency & lifetime.

Entry ids are stable and shared with the annotated catalogue, so a finding against an
entry here can be traced back.

---
"""


def derive(text: str) -> str:
    out: list[str] = [HEADER]
    section: str | None = None
    emitted_section: str | None = None
    keep = False
    buf: list[str] = []

    def flush() -> None:
        while buf and not buf[-1].strip():
            buf.pop()
        if buf:
            out.append("\n".join(buf) + "\n\n---\n")
        buf.clear()

    for line in text.splitlines():
        if line.startswith("## "):
            section = line
            continue
        m = ENTRY_RE.match(line)
        if m:
            flush()
            if section != emitted_section and section is not None:
                out.append(f"\n{section}\n")
                emitted_section = section
            keep = True
            buf.append(line)
            continue
        if not keep:
            continue
        if STRIP_FROM_RE.match(line):
            keep = False
            flush()
            continue
        if line.strip() == "---":
            keep = False
            flush()
            continue
        buf.append(line)
    flush()
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    derived = derive(CATALOGUE.read_text(encoding="utf-8"))
    if "--check" in sys.argv:
        current = NEUTRAL.read_text(encoding="utf-8") if NEUTRAL.exists() else ""
        if current != derived:
            print(
                f"{NEUTRAL} is stale; run: python {Path(__file__).name}",
                file=sys.stderr,
            )
            return 1
        return 0
    NEUTRAL.write_text(derived, encoding="utf-8")
    entries = derived.count("\n### ")
    print(f"wrote {NEUTRAL.relative_to(ROOT)} ({entries} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
