"""Assert no finished OpenSpec change is left unarchived.

Merging a change does not apply it. The deltas under `openspec/changes/<change>/specs/`
only reach the authoritative `openspec/specs/` when someone runs `openspec archive`.

Three changes in a row (#212, #213, #214) merged complete and unarchived, each time
leaving `openspec/specs/` describing an API or a set of extras that no longer shipped.
The specs are the authority, so any window in which a finished change sits unarchived is
a window where the authority is wrong.

A change is "finished" here on the same terms `openspec list` uses to print
`✓ Complete`: its `tasks.md` has at least one checkbox and every one of them is `[x]`.
Anything else — `[ ]`, or the `[~]` partial marker used in a couple of archived changes —
counts as outstanding, so this errs toward staying quiet.

Runs on pull requests as well as on `main`. The rule it enforces is therefore
**archive in the PR that finishes the change**, which is usually the same PR that
proposed and implemented it. A change that is genuinely still in motion — design moving
under review, or an archive deliberately batched with a sibling change — leaves its
trailing task unchecked and this stays quiet. Checking the last box is the claim that the
work is done; archiving is what makes that claim true.

Also runnable by hand:

    uv run python scripts/checks/check_openspec_archived.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGES = Path(__file__).resolve().parents[2] / "openspec" / "changes"

# `- [x] 1.1 …`, at any indent. The archived corpus also uses `- [~]` for partially-done
# work, which this deliberately does not treat as done.
CHECKBOX = re.compile(r"^\s*- \[(.)\]", re.MULTILINE)

finished: list[str] = []
for change in sorted(CHANGES.iterdir()):
    # `archive/` holds the already-archived changes; everything else is in flight.
    if not change.is_dir() or change.name == "archive":
        continue

    tasks = change / "tasks.md"
    if not tasks.is_file():
        # A change can legitimately exist before its tasks are written; nothing to judge.
        continue

    marks = CHECKBOX.findall(tasks.read_text(encoding="utf-8"))
    if marks and all(mark in "xX" for mark in marks):
        finished.append(f"{change.name} ({len(marks)} tasks, all complete)")

if finished:
    listing = "\n".join(f"  - {name}" for name in finished)
    sys.exit(
        f"FAIL: {len(finished)} finished OpenSpec change(s) are still unarchived, so\n"
        f"their deltas have not been applied to openspec/specs/:\n\n"
        f"{listing}\n\n"
        f"Archive each one *in this branch*, then commit the resulting spec updates:\n\n"
        f'  npm install -g --prefix "$HOME/.local" @fission-ai/openspec\n'
        f"  openspec archive <change> --yes\n\n"
        f"Archiving belongs in the PR that finishes the change, not in a follow-up: the\n"
        f"deltas are what make openspec/specs/ describe what actually ships.\n\n"
        f"If a change is complete but should NOT be archived yet — the design is still\n"
        f"moving under review, or the archive is deliberately batched with a sibling\n"
        f"change — leave its trailing task unchecked rather than checking it off early.\n"
        f"An unchecked box is an honest 'not done yet'; a checked one is a claim that\n"
        f"the change has landed in the specs."
    )

print("no finished OpenSpec change is left unarchived")
