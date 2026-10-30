#!/usr/bin/env python3
"""Count what the review loop found and what the implementer did with each finding.

The review skill gives every finding an ID and a severity, and
`address-review-findings` gives every one a disposition. This reads both back from
merged pull requests and reports what a retrospective would otherwise count by hand:

- rounds per pull request, and the round whose verdict first approved it;
- how many pull requests ended on a conditional approval, whose last fixes no round read;
- findings by severity, and which ones the Opus pass raised rather than a loop round;
- what happened to each finding: fixed, disproven, escalated, split, or no reply found;
- findings that name an earlier finding's fix as their cause.

    python3 scripts/review_tally.py --days 7
    python3 scripts/review_tally.py --since 2026-10-30 --pr 1141 --pr 1143

It reads GitHub with ``gh api`` (REST only) and prints Markdown, which
`.github/workflows/review-tally.yml` writes to its job summary each week. The parsing
is in pure functions, so `tests/test_review_tally.py` runs without GitHub.

The counts are as good as the posted shapes they read. A finding is a ``### K<n> ·``
heading by ``claude[bot]``, in an inline comment or a review body. Its disposition is
the first disposition word in a reply on its thread, or on a line that names its ID in a
comment by anyone else; a finding with neither counts as ``no reply``.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

#: Who posts reviews, and who posts the round markers (`review_loop_gate.ROUND_MARKER`).
REVIEWER = "claude[bot]"
WORKFLOW = "github-actions[bot]"
ROUND_MARKER = "<!-- archivey-review-round"

#: Verdicts that approve, so a round with one of these passed (`review_loop_gate`).
APPROVING = frozenset({"clean", "approved", "conditional"})

SEVERITIES = {"🔴": "blocking", "🟡": "important", "🟢": "nit", "💡": "suggestion"}

#: A finding's heading, ``### K3 · 🟡 `[important]` · `CONFIRMED` ``, or its line in a
#: review body's findings list, ``- K3 · 🟡 · CONFIRMED · ...``.
_FINDING = re.compile(r"^(?:#{2,4} |- )(K\d+) · (\S+)", re.MULTILINE)
#: The attribution line under it names the round: ``· round 2 ·``.
_ROUND = re.compile(r"· round (\d+) ·")
_FIELD = re.compile(r"(\w+)=(\S+)")
_ID = re.compile(r"\bK(\d+)\b")

#: A finding raised by an earlier fix: "The K4 fix ...", "the K10 re-wrap ...". Not
#: "K3's fix", which reviewers write about a fix still to come.
_FROM_FIX = re.compile(r"\bthe K\d+ (?:fix|re-?wr\w*|rewrite|change)\b", re.IGNORECASE)

#: Disposition words, looked for on the first line of a reply (`classify`). The skill's
#: four (§2) plus the verbs implementers write instead of "fixed".
DISPOSITIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "escalated",
        re.compile(
            r"\b(escalat\w*|for davitf|maintainer (decision|call))\b", re.IGNORECASE
        ),
    ),
    (
        "split",
        re.compile(r"\b(split|own PR|separate PR|follow-up PR)\b", re.IGNORECASE),
    ),
    (
        "disproven",
        re.compile(
            r"\b(disproven|not a bug|kept|keeping|stays as is|no change|declined|intentional|by design|won't fix)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fixed",
        re.compile(
            r"\b(fixed|fix(?:es)? in|done|taken|applied|now uses|removed|renamed|added|rewrapped|re-?wrote|rewritten|"
            r"reworded|moved|changed|updated|dropped|replaced)\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass
class Round:
    n: int
    verdict: str
    opus_pass: bool


@dataclass
class Finding:
    pr: int
    id: str
    severity: str
    round: int | None
    from_fix: bool
    disposition: str = "no reply"


@dataclass
class PullRequest:
    number: int
    title: str
    rounds: list[Round] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed_at(self) -> int | None:
        """The first round whose verdict approved, or ``None``."""
        for r in self.rounds:
            if r.verdict in APPROVING:
                return r.n
        return None

    @property
    def opus_round(self) -> int | None:
        return next((r.n for r in self.rounds if r.opus_pass), None)


def read_rounds(issue_comments: list[dict]) -> list[Round]:
    """The rounds the workflow's closing comments record, in order."""
    rounds: dict[int, Round] = {}
    for c in issue_comments:
        if c.get("user", {}).get("login") != WORKFLOW:
            continue
        line = (c.get("body") or "").split("\n", 1)[0]
        if not line.startswith(ROUND_MARKER):
            continue
        fields = dict(_FIELD.findall(line))
        try:
            n = int(fields.get("n", ""))
        except ValueError:
            continue
        rounds[n] = Round(n, fields.get("verdict", "").rstrip("-> "), "pass" in fields)
    return [rounds[n] for n in sorted(rounds)]


def classify(text: str) -> str:
    """The disposition a reply's first line states first, or ``other``.

    The earliest word wins: "Fixed in abc, with the name kept on one line" is a fix.
    """
    line = text.strip().split("\n", 1)[0]
    hits = [(m.start(), name) for name, p in DISPOSITIONS if (m := p.search(line))]
    return min(hits)[1] if hits else "other"


def _finding(pr: int, heading: re.Match[str], body: str) -> Finding:
    rest = body[heading.end() :]
    text = (
        rest.split("\n", 1)[0]
        if heading.group(0).startswith("-")
        else rest.split("\n### ", 1)[0]
    )
    round_match = _ROUND.search(text[:400])
    return Finding(
        pr=pr,
        id=heading.group(1),
        severity=SEVERITIES.get(heading.group(2), "other"),
        round=int(round_match.group(1)) if round_match else None,
        from_fix=bool(_FROM_FIX.search(text)),
    )


def read_findings(
    pr: int,
    reviews: list[dict],
    review_comments: list[dict],
    issue_comments: list[dict],
) -> list[Finding]:
    """Every finding the reviewer raised, each with its disposition."""
    found: dict[str, Finding] = {}
    thread_of: dict[int, str] = {}
    rounds_by_review: dict[int, int] = {}

    for r in reviews:
        if r.get("user", {}).get("login") != REVIEWER:
            continue
        body = r.get("body") or ""
        head = re.match(r"## Round (\d+)", body)
        if head:
            rounds_by_review[r["id"]] = int(head.group(1))
        for m in _FINDING.finditer(body):
            f = _finding(pr, m, body)
            if f.round is None and head:
                f.round = int(head.group(1))
            found.setdefault(f.id, f)

    for c in review_comments:
        if c.get("in_reply_to_id") or c.get("user", {}).get("login") != REVIEWER:
            continue
        body = c.get("body") or ""
        m = _FINDING.match(body)
        if not m:
            continue
        f = _finding(pr, m, body)
        if f.round is None:
            f.round = rounds_by_review.get(c.get("pull_request_review_id") or -1)
        # An inline heading is the finding itself; a review-body line may only list it.
        found[f.id] = f
        thread_of[c["id"]] = f.id

    for c in review_comments:
        target = thread_of.get(c.get("in_reply_to_id") or -1)
        if (
            target
            and c.get("user", {}).get("login") != REVIEWER
            and found[target].disposition == "no reply"
        ):
            found[target].disposition = classify(_strip_heading(c.get("body") or ""))

    # Top-level disposition comments: one line per finding, keyed by its ID.
    others = [
        c.get("body") or ""
        for c in [*issue_comments, *reviews]
        if c.get("user", {}).get("login") not in (REVIEWER, WORKFLOW)
    ]
    for body in others:
        for line in body.splitlines():
            ids = _ID.findall(line[:40])
            if not ids:
                continue
            f = found.get(f"K{ids[0]}")
            if f and f.disposition == "no reply":
                kind = classify(_ID.sub("", line, count=1))
                if kind != "other":
                    f.disposition = kind

    return sorted(found.values(), key=lambda f: int(f.id[1:]))


def _strip_heading(body: str) -> str:
    """A reply headed ``### K6 · fixed in `abc`'' carries its disposition in the heading."""
    return re.sub(r"^#+\s*K\d+\s*·\s*", "", body.strip())


def report(prs: list[PullRequest], since: datetime) -> str:
    reviewed = [p for p in prs if p.rounds]
    findings = [f for p in reviewed for f in p.findings]
    out = [f"# Review tally since {since:%Y-%m-%d}", ""]
    if not reviewed:
        return "\n".join(
            [*out, "No merged pull request in the window had a review round."]
        )

    rounds = Counter(len(p.rounds) for p in reviewed)
    passed = Counter(p.passed_at for p in reviewed)
    conditional = [p for p in reviewed if p.rounds[-1].verdict == "conditional"]
    total_rounds = sum(len(p.rounds) for p in reviewed)
    out += [
        f"- **{len(reviewed)} reviewed pull requests**, {total_rounds} rounds "
        f"({total_rounds / len(reviewed):.1f} each); "
        + ", ".join(
            f"{k} round{'s' * (k != 1)}: {v}" for k, v in sorted(rounds.items())
        ),
        "- **First approving round:** "
        + ", ".join(
            f"{'never' if k is None else f'round {k}'}: {v}"
            for k, v in sorted(passed.items(), key=lambda kv: kv[0] or 99)
        ),
        f"- **Ended on a conditional approval:** {len(conditional)} of {len(reviewed)}",
    ]

    by_sev = Counter(f.severity for f in findings)
    out.append(
        f"- **{len(findings)} findings:** "
        + ", ".join(
            f"{by_sev[s]} {s}" for s in [*SEVERITIES.values(), "other"] if by_sev[s]
        )
    )

    with_pass = [p for p in reviewed if p.opus_round is not None]
    if with_pass:
        before = Counter()
        during = Counter()
        after = Counter()
        unplaced = 0
        for p in with_pass:
            for f in p.findings:
                if f.round is None:
                    unplaced += 1
                    continue
                bucket = (
                    during
                    if f.round == p.opus_round
                    else before
                    if f.round < (p.opus_round or 0)
                    else after
                )
                bucket[f.severity] += 1
        out.append(f"- **Opus pass, on {len(with_pass)} pull requests:**")
        for name, c in (
            ("before the pass", before),
            ("the pass", during),
            ("after the pass", after),
        ):
            out.append(
                f"  - {name}: "
                + (
                    ", ".join(f"{c[s]} {s}" for s in SEVERITIES.values() if c[s])
                    or "none"
                )
            )
        if unplaced:
            out.append(f"  - with no round on them, so left out above: {unplaced}")

    disp = Counter(f.disposition for f in findings)
    out.append(
        "- **Dispositions:** "
        + ", ".join(
            f"{disp[k]} {k}"
            for k in ["fixed", "disproven", "escalated", "split", "other", "no reply"]
            if disp[k]
        )
    )
    from_fix = [f for f in findings if f.from_fix]
    out.append(
        f"- **Raised by an earlier fix:** {len(from_fix)}"
        + (": " + ", ".join(f"#{f.pr} {f.id}" for f in from_fix) if from_fix else "")
    )

    out += ["", "## Per pull request", ""]
    for p in reviewed:
        verdicts = " → ".join(
            r.verdict + (" (Opus pass)" if r.opus_pass else "") for r in p.rounds
        )
        sev = Counter(f.severity for f in p.findings)
        out.append(
            f"- #{p.number} {p.title}: {verdicts}; "
            + (
                ", ".join(f"{sev[s]} {s}" for s in SEVERITIES.values() if sev[s])
                or "no findings"
            )
        )
    return "\n".join(out)


def _gh(path: str) -> list:
    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", path],
        check=True,
        capture_output=True,
        text=True,
    )
    return [item for page in json.loads(result.stdout) for item in page]


#: How many pages of 100 closed pull requests `merged_since` reads at most.
MAX_PAGES = 50


def merged_since(repo: str, since: datetime) -> list[tuple[int, str]]:
    """Pull requests merged at or after ``since``, newest update first.

    Repository-scoped on purpose: a Claude session's token can read ``repos/...`` but
    not the search API. Raises `SystemExit` if the window is longer than `MAX_PAGES`
    pages reach, rather than report on part of it.
    """
    found = []
    for page in range(1, MAX_PAGES + 1):
        batch = _gh_one(
            f"repos/{repo}/pulls?state=closed&sort=updated&direction=desc"
            f"&per_page=100&page={page}"
        )
        for pr in batch:
            merged = pr.get("merged_at")
            if merged and datetime.fromisoformat(merged) >= since:
                found.append((pr["number"], pr["title"]))
        last = batch[-1]["updated_at"] if batch else None
        # Merging updates a pull request, so once updates are older than the window
        # no later page can hold a merge inside it.
        if not last or datetime.fromisoformat(last) < since:
            return found
    raise SystemExit(
        f"{MAX_PAGES * 100} closed pull requests read and the window is not covered; "
        "shorten it with --days or --since"
    )


def fetch(repo: str, since: datetime, numbers: list[int]) -> list[PullRequest]:
    if not numbers:
        found = merged_since(repo, since)
    else:
        found = [(n, _gh_one(f"repos/{repo}/pulls/{n}")["title"]) for n in numbers]
    prs = []
    for number, title in sorted(found):
        issue_comments = _gh(f"repos/{repo}/issues/{number}/comments?per_page=100")
        reviews = _gh(f"repos/{repo}/pulls/{number}/reviews?per_page=100")
        review_comments = _gh(f"repos/{repo}/pulls/{number}/comments?per_page=100")
        prs.append(
            PullRequest(
                number,
                title,
                read_rounds(issue_comments),
                read_findings(number, reviews, review_comments, issue_comments),
            )
        )
    return prs


def _gh_one(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path], check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--repo", default="archivey-dev/archivey")
    window = parser.add_mutually_exclusive_group()
    window.add_argument("--days", type=int, default=7, help="merged in the last N days")
    window.add_argument("--since", help="merged on or after this date (YYYY-MM-DD)")
    parser.add_argument(
        "--pr", type=int, action="append", default=[], help="these pull requests only"
    )
    args = parser.parse_args(argv)
    since = (
        datetime.fromisoformat(args.since).replace(tzinfo=UTC)
        if args.since
        else datetime.now(UTC) - timedelta(days=args.days)
    )
    print(report(fetch(args.repo, since, args.pr), since))
    return 0


if __name__ == "__main__":
    sys.exit(main())
