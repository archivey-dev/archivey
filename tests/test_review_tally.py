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
        marker(2, "findings", " pass=opus shape=skipped"),
        {"user": DAVI, "body": marker(3, "approved")["body"]},  # a person quoting one
        marker(3, "approved", " shape=2"),
    ]
    rounds = tally.read_rounds(comments)
    assert [(r.n, r.verdict, r.opus_pass, r.opus_next) for r in rounds] == [
        (1, "conditional", False, True),
        (2, "findings", True, False),
        (3, "approved", False, False),
    ]
    # A conditional approval that the Opus pass follows did not stop the loop.
    assert tally.PullRequest(1, "t", rounds).passed_at == 3
    # A close that could not check the posting shape is not stored as zero misses.
    assert [r.shape for r in rounds] == [0, None, 2]
    out = tally.report([tally.PullRequest(1, "t", rounds)], "#1")
    assert "- **Rounds whose posts missed the posting shape:** 1: #1 round 3 (2)" in out
    assert "- **Rounds whose posting shape was not checked:** 1: #1 round 2" in out


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
        # Agreement is not a fix, and the earliest word decides.
        ("Agreed, but kept as is.", "disproven"),
        ("Agreed, will do.", "other"),
        ("Hmm.", "other"),
        ("Agreed, and I took the second direction in this PR.", "fixed"),
        ("I've left this as is.", "disproven"),
        ("Stays as is.", "disproven"),
        # A half-open fix is not a fix.
        ("Reproduced, and partly fixed in e83f9441.", "other"),
        ("Not fixed: the bound is the maintainer's call.", "other"),
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
            "**Findings**\n- K1 · 🟢 · CONFIRMED · stale name · {422 error}\n"
            # The template's spelling, for a finding with no line to anchor on.
            "- **K4** 🟡 `CONFIRMED` — the PR body is stale\n"
            "  - **K5** · 📚 `[learning]` · `CONFIRMED` — why the bound is first\n",
        },
        {
            "id": 902,
            "user": BOT,
            # A status line in a later round is not a new finding.
            "body": "## Round 2 · 🔄 Request Changes\n\n- **K4** fixed in `abc`\n"
            "- **K6** fixed in `abc`\n",
        },
    ]
    comments = [
        inline(1, "K2", "🔴", 2, "The K1 fix moved the bound past the read."),
        reply(1, "Fixed in abc123: the bound comes first again."),
        inline(2, "K3", "🟡", 2, "There is no test; K2's fix would want one."),
        inline(3, "K7", "🟡", 2),
        reply(3, "### K7 · for davitf\n\nLeft open: the maintainer's call."),
        {**reply(3, "### K7 · fixed in `abc`\n\nAs decided."), "id": 31},
        {**reply(3, "Agreed, will do."), "id": 32},
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
        ("K4", "important", 1, "no reply", False),
        ("K5", "learning", 1, "no reply", False),
        # Escalated, answered, then fixed: the last stated disposition stands, and
        # a reply that states none does not undo it.
        ("K7", "important", 2, "fixed", False),
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
            tally.Finding(1, "K5", "nit", None, False, "fixed"),
            tally.Finding(1, "K6", "other", 2, False, "fixed"),
        ],
    )
    out = tally.report([pr], "since 2026-10-30")
    assert out.startswith("# Review tally: since 2026-10-30")
    assert "- **1 reviewed pull request**, 3 rounds" in out
    assert "- **First approving round:** round 1: 1" in out
    assert "- **Ended on a conditional approval:** 0 of 1" in out
    assert "  - before the pass: 1 important" in out
    # A heading the parser could not read is still shown, not dropped.
    assert "  - the pass: 1 blocking, 1 important, 1 other" in out
    assert "  - after the pass: 1 nit" in out
    assert "  - with no round on them, so left out above: 1" in out
    assert "- **Dispositions:** 5 fixed, 1 disproven" in out
    assert "- **Raised by an earlier fix:** 1: #1 K4" in out
    assert "conditional → findings (Opus pass) → approved" in out


def test_an_empty_window_says_so():
    out = tally.report([tally.PullRequest(1, "No review")], "since 2026-10-30")
    assert "No merged pull request in the window had a review round." in out


def test_a_window_the_pages_do_not_cover_fails_rather_than_report_part(monkeypatch):
    page = [
        {
            "number": 1,
            "title": "t",
            "merged_at": None,
            "updated_at": "2026-10-30T00:00:00Z",
        }
    ]
    monkeypatch.setattr(tally, "_gh_one", lambda path: page)
    with pytest.raises(SystemExit, match="window is not covered"):
        tally.merged_since("o/r", datetime(2026, 1, 1, tzinfo=UTC))
    # Once updates are older than the window, the pages stop there.
    assert tally.merged_since("o/r", datetime(2026, 10, 31, tzinfo=UTC)) == []


def test_raising_shapes_status_lines_and_summary_clauses():
    reviews = [
        {
            "id": 901,
            "user": BOT,
            "body": "## Round 1 · 🔄 Request Changes\n\n"
            "**K6 · 🟢 `[nit]` · `CONFIRMED` — a stale comment\n\n"
            "- 🟡 `[important]` · `CONFIRMED` · **K8** the cap is unchecked\n"
            # A gist that starts with a fix word is still a finding.
            "- 🟢 `[nit]` · `CONFIRMED` · **K9** removed the old name\n",
        },
        {
            "id": 902,
            "user": BOT,
            # A later round's status line keeps its emoji; it is a disposition.
            "body": "## Round 2 · ✅ Approve\n\n- **K6** 🟢 fixed in `005ea01c` — ok\n"
            "- **K8** 🟡 declined — the cap is the caller's\n",
        },
        {
            "id": 903,
            "user": {"login": "cursor[bot]"},
            "body": "## Round 2 · 🔄 Request Changes\n\n- C1 · 🟡 · CONFIRMED · reads twice\n",
        },
    ]
    issue_comments = [
        {
            "user": DAVI,
            "body": "- **K8:** the PR body now describes what the module checks.\n"
            "Summary: K1 is moot. C1: fixed in `abc`.",
        }
    ]
    found = tally.read_findings(7, reviews, [], issue_comments)
    assert [(f.id, f.severity, f.round, f.disposition) for f in found] == [
        ("C1", "important", 2, "fixed"),
        # Raised in round 1 and closed by round 2's status line.
        ("K6", "nit", 1, "fixed"),
        # A reply that names it and states nothing does not hide the status line.
        ("K8", "important", 1, "disproven"),
        ("K9", "nit", 1, "no reply"),
    ]
