"""The posting-shape check, on hand-built posts instead of GitHub.

`scripts/review_shape.py` says which of a round's posts miss the shape
`code-review-skill` §3 and §6 ask for. Each case breaks one rule and expects exactly that
miss, and a well-formed round expects none, so a rule that stops firing, or fires on a
good review, fails here.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_shape.py"

_spec = importlib.util.spec_from_file_location("review_shape", SCRIPT)
assert _spec is not None and _spec.loader is not None
shape = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = shape
_spec.loader.exec_module(shape)

BOT = {"login": "claude[bot]"}
ACTIONS = {"login": "github-actions[bot]"}
FOOT = "\n\n---\n" + shape.FOOTER

BODY = (
    "## Round 2 · 🔄 Request Changes\n\n"
    "**Claude Code** · `code-review-skill` · `abc` · scope `x..abc`\n\n"
    "### 1. Maintainer briefing\n\nIt reads.\n\n"
    "<details><summary>Measured this round · what's fine</summary>\n\n- None.\n\n"
    "</details>" + FOOT
)
FINDING = (
    "### K3 · 🟡 `[important]` · `CONFIRMED`\n\n"
    "**Claude Code** · `code-review-skill` · round 2 · `abc`\n\nThe bound is late."
    + FOOT
)
REPLY = "### K1 · still open\n\n**Claude Code** · round 2\n\nNot yet." + FOOT


def event(body: str = BODY, finding: str = FINDING, reply: str = REPLY) -> dict:
    return {
        "round": 2,
        "issue_comments": [
            # Round 1's close: everything before it belongs to round 1.
            {
                "user": ACTIONS,
                "created_at": "2026-10-30T10:00:00Z",
                "body": "<!-- archivey-review-round n=1 verdict=findings -->\n\nClosed.",
            },
        ],
        "reviews": [
            # Round 1's own body, badly shaped, which this round must not re-report.
            {"id": 1, "user": BOT, "submitted_at": "2026-10-30T09:00:00Z", "body": "x"},
            {
                "id": 2,
                "user": BOT,
                "submitted_at": "2026-10-30T11:00:00Z",
                "body": body,
            },
            # The empty review GitHub makes around a batch of inline comments.
            {"id": 3, "user": BOT, "submitted_at": "2026-10-30T11:00:01Z", "body": ""},
        ],
        "review_comments": [
            {
                "id": 10,
                "user": BOT,
                "created_at": "2026-10-30T11:00:00Z",
                "body": finding,
            },
            {
                "id": 11,
                "in_reply_to_id": 5,
                "user": BOT,
                "created_at": "2026-10-30T11:00:00Z",
                "body": reply,
            },
            # The implementer's reply is not the reviewer's to shape.
            {
                "id": 12,
                "in_reply_to_id": 10,
                "user": {"login": "davitf"},
                "created_at": "2026-10-30T11:30:00Z",
                "body": "Fixed in abc.",
            },
        ],
    }


def test_a_well_formed_round_has_no_misses():
    assert shape.check(event()) == []


@pytest.mark.parametrize(
    ("change", "miss"),
    [
        (
            {"body": BODY.replace("## Round 2", "## Round two")},
            "no review body headed `## Round 2 ·`",
        ),
        (
            {"body": BODY.replace("**Claude Code** · ", "Claude: ")},
            "the review body has no attribution line under its heading",
        ),
        (
            {
                "body": BODY.replace(
                    "<details><summary>Measured", "<details><summary>Data"
                )
            },
            "the review body has no collapsed `Measured this round` list",
        ),
        (
            {"body": BODY.replace(FOOT, "")},
            "the review body does not end with the attribution footer",
        ),
        (
            {"body": BODY.replace("It reads.", "| a | b |\n|---|---|\n| 1 | 2 |")},
            "the review body has a table",
        ),
        (
            {
                "body": BODY.replace(
                    "It reads.",
                    '{"message":"Validation Failed","errors":[],"status":"422"}',
                )
            },
            "the review body carries a GitHub API error message",
        ),
        (
            {"finding": FINDING.replace("### K3 · ", "### Finding 3 · ")},
            "inline finding 10 has no `### K<n> ·` heading",
        ),
        (
            {"finding": FINDING.replace(FOOT, "")},
            "inline finding 10 does not end with the attribution footer",
        ),
        (
            {"reply": REPLY.replace("### K1 · ", "K1: ")},
            "reply 11 has no `### K<n> ·` heading",
        ),
    ],
    ids=[
        "heading",
        "attribution",
        "measured",
        "footer",
        "table",
        "api-error",
        "finding-heading",
        "finding-footer",
        "reply-heading",
    ],
)
def test_each_rule_reports_its_own_miss(change, miss):
    assert shape.check(event(**change)) == [miss]


def test_a_table_inside_a_code_block_is_not_one():
    body = BODY.replace("It reads.", "```\n| a | b |\n|---|---|\n```")
    assert shape.check(event(body=body)) == []


def test_the_script_reads_and_writes_json():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(event(finding=FINDING.replace(FOOT, ""))),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert json.loads(result.stdout) == {
        "misses": ["inline finding 10 does not end with the attribution footer"]
    }
