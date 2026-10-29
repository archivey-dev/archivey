#!/usr/bin/env python3
"""Write the prompt for a review-loop round, as GitHub Actions step outputs.

`.github/workflows/review-loop.yml` runs this before each reviewer it starts and
appends what it prints to ``$GITHUB_OUTPUT``: ``prompt`` (the filled-in
`.github/review-loop-prompt.md`), and ``round`` and ``final`` for the round it is.
Stdlib only.

Reads ``PR``, ``GITHUB_REPOSITORY``, ``ROUND`` (the gate's round), ``MAX_ROUNDS`` and
``PASS`` from the environment. ``PASS=deep`` is the deep pass, which runs as the round
after the gate's, in the same workflow run; anything else is an ordinary round.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / ".github" / "review-loop-prompt.md"

#: The paragraph a deep pass's prompt carries, in place of ``{PASS}``.
DEEP_PASS = """
This round is the deep pass. Earlier rounds, by another reviewer, approved this
pull request, and this repository runs one full review by a stronger model on a deep
pull request once that happens. Read it as a first look, not as a fix round: the
whole change against the base, with the reference doc §1 names for a first look, at
the deep tier. Their findings are on the pull request; do not repeat them, skip the
status bullets for their IDs, and look hardest at what they could have missed. Cursor
is reviewing it at the same time, so leave its comments alone.
"""


def render(env: dict[str, str]) -> tuple[str, int, bool]:
    """The prompt, the round it is for, and whether that round is the agents' last."""
    deep = env.get("PASS") == "deep"
    max_rounds = int(env["MAX_ROUNDS"])
    rnd = int(env["ROUND"]) + (1 if deep else 0)
    text = TEMPLATE.read_text(encoding="utf-8")
    # The comment at the top is for whoever edits the template, not for the reviewer.
    text = re.sub(r"\A<!--.*?-->\n", "", text, flags=re.DOTALL)
    values = {
        "PR": env["PR"],
        "REPOSITORY": env["GITHUB_REPOSITORY"],
        "ROUND": str(rnd),
        "MAX_ROUNDS": str(max_rounds),
        "PASS": DEEP_PASS if deep else "",
    }
    for name, value in values.items():
        text = text.replace("{" + name + "}", value)
    return text, rnd, rnd >= max_rounds


def main() -> int:
    text, rnd, final = render(dict(os.environ))
    # A delimiter the prompt cannot contain, as GitHub's multiline output syntax needs.
    delimiter = f"EOF_{secrets.token_hex(16)}"
    sys.stdout.write(f"prompt<<{delimiter}\n{text}\n{delimiter}\n")
    sys.stdout.write(f"round={rnd}\nfinal={str(final).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
