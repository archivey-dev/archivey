#!/usr/bin/env python3
"""Write the prompt for a review-loop round, as GitHub Actions step outputs.

`.github/workflows/review-loop.yml` runs this before each reviewer it starts and
appends what it prints to ``$GITHUB_OUTPUT``: ``prompt`` (the filled-in
`.github/review-loop-prompt.md`), and ``round`` and ``final`` for the round it is.
Stdlib only.

Reads ``PR``, ``GITHUB_REPOSITORY``, ``ROUND`` (the gate's round), ``MAX_ROUNDS`` and
``PASS`` from the environment. ``PASS=opus`` is the pull request's Opus round
(`OPUS_PASS_TIERS` in the gate); anything else is an ordinary round.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / ".github" / "review-loop-prompt.md"

#: The paragraph the Opus round's prompt carries, in place of ``{PASS}``, when it is not
#: the pull request's first round: rounds by another reviewer came before it, because
#: its tier rose after them or they ran before the Opus round moved to the front.
OPUS_LATE = """
This round is the pull request's one review by Opus. Earlier rounds, by another
reviewer, came before it. Read it as a first look, not as a fix round: the whole
change against the base, with the reference doc §1 names for a first look, at the
tier §1 gives it. Their findings are on the pull request; do not repeat them, skip
the status bullets for their IDs, and look hardest at what they could have missed,
and at severities they may have rated too low. Number your findings on from the
highest ID already on the pull request, as §6 asks across rounds, so none collides
with theirs.
"""


def render(env: dict[str, str]) -> tuple[str, int, bool]:
    """The prompt, the round it is for, and whether that round is the agents' last."""
    max_rounds = int(env["MAX_ROUNDS"])
    rnd = int(env["ROUND"])
    text = TEMPLATE.read_text(encoding="utf-8")
    # The comment at the top is for whoever edits the template, not for the reviewer.
    text = re.sub(r"\A<!--.*?-->\n", "", text, flags=re.DOTALL)
    values = {
        "PR": env["PR"],
        "REPOSITORY": env["GITHUB_REPOSITORY"],
        "ROUND": str(rnd),
        "MAX_ROUNDS": str(max_rounds),
        "PASS": OPUS_LATE if env.get("PASS") == "opus" and rnd > 1 else "",
    }
    for name, value in values.items():
        text = text.replace("{" + name + "}", value)
    return text, rnd, rnd >= max_rounds


def main() -> int:
    text, rnd, final = render(dict(os.environ))
    # A delimiter the prompt cannot contain, as GitHub's multiline output syntax needs.
    delimiter = f"EOF_{secrets.token_hex(16)}"
    out = (
        f"prompt<<{delimiter}\n{text}\n{delimiter}\n"
        f"round={rnd}\nfinal={str(final).lower()}\n"
    )
    # UTF-8 and `\n` whatever the platform: the prompt has emoji, and GITHUB_OUTPUT
    # wants the delimiter alone on its line.
    sys.stdout.buffer.write(out.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
