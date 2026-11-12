"""Assert no spec prose refers to "this change".

A delta requirement body is written inside a change directory, where "this change" is
unambiguous. `openspec archive` then folds that body into `openspec/specs/`, where it is
not: the change has moved to `openspec/changes/archive/` and a reader of the authoritative
spec has no way to tell which one was meant. Nine such phrases had accumulated across
`format-detection`, `cli`, `safe-extraction` and `error-handling` before anyone counted.

Most of them turned out not to be worth naming, either — they were pre-merge arguments
("this change is a strict increase in what is stamped", "it SHALL ship anyway because…")
whose other referents, the prior behaviour and the pre-change tree, are gone too. So the
rule is not "name the change": it is that the spec states the contract as it stands, and
the reasoning behind it lives in the change's `design.md`, which `openspec/config.yaml`
rules.specs already says.

Two places are checked, for the same reason:

  - `openspec/specs/` — permanent text, so any occurrence is already wrong.
  - `openspec/changes/<id>/specs/` — becomes permanent on archive, so an occurrence here
    is the same defect with a delay. `PENDING` below grandfathers the changes that carried
    one when this check landed; each entry must go before that change archives, and the
    check fails if an id in `PENDING` has become clean, so the list cannot rot.

`design.md`, `proposal.md` and `tasks.md` are not checked: none of them is archived into
the specs, and "this change" is exactly the right phrase there.

Also runnable by hand:

    uv run python scripts/checks/check_openspec_self_reference.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPECS = ROOT / "openspec" / "specs"
CHANGES = ROOT / "openspec" / "changes"

# "this change", "this change's", "This Change" — but not "this changes the…".
SELF_REF = re.compile(r"\bthis change(?:'s)?\b(?!s)", re.IGNORECASE)

# Changes that already carried the phrase when this check landed. Delete an entry when
# that change's deltas are cleaned up; the check below fails on a stale entry, so this
# list shrinks to nothing rather than quietly becoming permanent.
PENDING = {
    "single-file-open-time-validation",
}


def hits(path: Path) -> list[tuple[int, str]]:
    found = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if SELF_REF.search(line):
            found.append((lineno, line.strip()))
    return found


failures: list[str] = []
stale: list[str] = []

for spec in sorted(SPECS.rglob("spec.md")):
    for lineno, line in hits(spec):
        failures.append(f"  {spec.relative_to(ROOT)}:{lineno}: {line}")

for change in sorted(CHANGES.iterdir()):
    if not change.is_dir() or change.name == "archive":
        continue
    change_hits = [
        (spec, lineno, line)
        for spec in sorted((change / "specs").rglob("spec.md"))
        for lineno, line in hits(spec)
    ]
    if change.name in PENDING:
        if not change_hits:
            stale.append(change.name)
        continue
    for spec, lineno, line in change_hits:
        failures.append(f"  {spec.relative_to(ROOT)}:{lineno}: {line}")

if stale:
    listing = "\n".join(f"  - {name}" for name in stale)
    sys.exit(
        f'FAIL: {len(stale)} change(s) in PENDING no longer refer to "this change":\n\n'
        f"{listing}\n\n"
        f"Remove them from PENDING in scripts/checks/check_openspec_self_reference.py. The list\n"
        f"exists to shrink; an entry that no longer applies makes it look like the debt\n"
        f"is still there."
    )

if failures:
    listing = "\n".join(failures)
    sys.exit(
        f'FAIL: {len(failures)} spec line(s) refer to "this change":\n\n'
        f"{listing}\n\n"
        f"A requirement body becomes permanent text in openspec/specs/ on `openspec\n"
        f"archive`, at which point the change it names has moved to\n"
        f"openspec/changes/archive/ and the referent is gone.\n\n"
        f"Prefer deleting the clause: it is usually a pre-merge argument (what the change\n"
        f"moves, what it would have removed, how it compares to the prior behaviour) whose\n"
        f"other referents are archived too. The spec states the contract as it stands.\n"
        f"Where the reasoning is worth keeping, it belongs in the change's design.md --\n"
        f'openspec/config.yaml rules.specs: "Leave investigations and rejected\n'
        f'alternatives to design.md". Naming the change id is the last resort, for a\n'
        f"cross-reference a reader of the archived spec would actually follow."
    )

print('no spec prose refers to "this change"')
