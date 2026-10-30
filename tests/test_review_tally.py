"""The weekly review tally, exercised on hand-built comments instead of GitHub.

`scripts/review_tally.py` reads round markers, findings and dispositions back from the
shapes the review loop and the two review skills post. These cases pin those shapes, so
a change to one of them that the tally would silently stop counting fails here.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_tally.py"

_spec = importlib.util.spec_from_file_location("review_tally", SCRIPT)
assert _spec is not None and _spec.loader is not None
tally = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package; `@dataclass` looks its module up in `sys.modules`.
sys.modules[_spec.name] = tally
_spec.loader.exec_module(tally)

BOT = {"login": "claude[bot]"}
ACTIONS = {"login": "github-actions[bot]"}
DAVI = {"login": "davitf"}


def marker(n: int, verdict: str, extra: str = "") -> dict:
    line = (
        f"<!-- archivey-review-round n={n} sha={'a' * 40} verdict={verdict}{extra} -->"
    )
    return {"user": ACTIONS, "body": line + "\n\nRound closed."}


def inline(cid: int, kid: str, emoji: str, rnd: int, text: str = "Something.") -> dict:
    return {
        "id": cid,
        "user": BOT,
        "pull_request_review_id": 900 + rnd,
        "body": f"### {kid} · {emoji} `[x]` · `CONFIRMED`\n\n"
        f"**Claude Code** · `code-review-skill` · round {rnd} · `abc`\n\n{text}",
    }


def reply(to: int, text: str, user: dict = DAVI) -> dict:
    return {"id": to * 10, "in_reply_to_id": to, "user": user, "body": text}


def test_rounds_come_from_the_workflow_markers_only():
    comments = [
        marker(1, "conditional", " next=opus"),
        marker(2, "findings", " pass=opus"),
        {"user": DAVI, "body": marker(3, "approved")["body"]},  # a person quoting one
        marker(3, "approved"),
    ]
    rounds = tally.read_rounds(comments)
    assert [(r.n, r.verdict, r.opus_pass) for r in rounds] == [
        (1, "conditional", False),
        (2, "findings", True),
        (3, "approved", False),
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Fixed in 2920841, by removing the hand-kept list", "fixed"),
        ("### K6 · fixed in `5afdbb5`", "fixed"),
        ("Taken in ae7553a0.", "fixed"),
        ("Kept, re-commented in ca2ea80.", "disproven"),
        ("No change. The cache grows by one class.", "disproven"),
        ("Disproven: the bound is checked first.", "disproven"),
        ("Escalated to the maintainer.", "escalated"),
        ("Split into its own PR, #1200.", "split"),
        ("Hmm.", "other"),
    ],
)
def test_a_reply_states_its_disposition(text, expected):
    assert tally.classify(tally._strip_heading(text)) == expected


def test_findings_get_their_round_severity_and_reply():
    reviews = [
        {
            "id": 901,
            "user": BOT,
            "body": "## Round 1 · ✅ Approve, conditional on K1\n\n"
            "**Findings**\n- K1 · 🟢 · CONFIRMED · stale name · {422 error}\n",
        },
    ]
    comments = [
        inline(1, "K2", "🔴", 2, "The K1 fix moved the bound past the read."),
        reply(1, "Fixed in abc123: the bound comes first again."),
        inline(2, "K3", "🟡", 2, "There is no test; K2's fix would want one."),
    ]
    issue_comments = [
        {"user": DAVI, "body": "## Round 1 · 1 fixed\n\n- K1 · fixed in `def`"}
    ]
    found = tally.read_findings(7, reviews, comments, issue_comments)
    assert [(f.id, f.severity, f.round, f.disposition, f.from_fix) for f in found] == [
        ("K1", "nit", 1, "fixed", False),
        ("K2", "blocking", 2, "fixed", True),
        # "K2's fix" is about a fix still to come, not one that caused this finding.
        ("K3", "important", 2, "no reply", False),
    ]


def test_the_report_splits_findings_around_the_opus_pass():
    pr = tally.PullRequest(
        1,
        "A change",
        [
            tally.Round(1, "conditional", False),
            tally.Round(2, "findings", True),
            tally.Round(3, "approved", False),
        ],
        [
            tally.Finding(1, "K1", "important", 1, False, "fixed"),
            tally.Finding(1, "K2", "blocking", 2, False, "fixed"),
            tally.Finding(1, "K3", "important", 2, False, "disproven"),
            tally.Finding(1, "K4", "nit", 3, True, "fixed"),
        ],
    )
    out = tally.report([pr], datetime(2026, 10, 30, tzinfo=UTC))
    assert "- **First approving round:** round 1: 1" in out
    assert "- **Ended on a conditional approval:** 0 of 1" in out
    assert "  - before the pass: 1 important" in out
    assert "  - the pass: 1 blocking, 1 important" in out
    assert "  - after the pass: 1 nit" in out
    assert "- **Dispositions:** 3 fixed, 1 disproven" in out
    assert "- **Raised by an earlier fix:** 1: #1 K4" in out
    assert "conditional → findings (Opus pass) → approved" in out


def test_an_empty_window_says_so():
    out = tally.report(
        [tally.PullRequest(1, "No review")], datetime(2026, 10, 30, tzinfo=UTC)
    )
    assert "No merged pull request in the window had a review round." in out
