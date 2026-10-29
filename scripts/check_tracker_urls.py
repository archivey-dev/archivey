"""Fail on an internal-tracker URL in a tracked file.

AGENTS.md: no internal-tracker URLs or keys in the repository, pull request text or
commits; write "tracked internally". A tracker URL committed to a review summary sat on
`main` for eight days before a later pull request removed it, because nothing checked.
This checks the files only; pull request text and commit messages are not in the tree.

A URL counts when the host, in any letter case, is followed by a workspace or path
segment (`linear.app/<name>`), which every link to a real issue, review or project has.
The scan is per line, so a URL wrapped across two lines is not seen. The `<` in this
docstring's example keeps the file from matching its own pattern. The skill that tells
agents how to read an issue URL writes its shape with an ellipsis
(`linear.app/…/issue/ABC-123`), which does not match either, so no allowlist is needed.

Bare issue keys are not checked here, because the `ABC-123` shape is common in
legitimate text (`DR-23`, `ADR-0014`, placeholder keys in skills). AGENTS.md still
forbids a real key in any file of the repo.

Stdlib only. Also runnable by hand:

    python3 scripts/check_tracker_urls.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACKER_URL = re.compile(rb"linear\.app/[A-Za-z0-9_-]+", re.IGNORECASE)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    return [name for name in out.decode("utf-8").split("\0") if name]


def main() -> int:
    hits: list[str] = []
    for name in tracked_files():
        path = ROOT / name
        if not path.is_file():  # a deleted file not yet staged, or a submodule
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:  # binary
            continue
        for number, line in enumerate(data.splitlines(), start=1):
            match = TRACKER_URL.search(line)
            if match:
                hits.append(f"{name}:{number}: {match.group().decode()}")
    if not hits:
        print("ok: no internal-tracker URL in a tracked file")
        return 0
    print("Internal-tracker URLs in tracked files (write 'tracked internally'):")
    for hit in hits:
        print(f"  {hit}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
