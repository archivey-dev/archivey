#!/usr/bin/env python3
"""Say so on a pull request when it stops merging cleanly into ``main``.

GitHub starts no ``pull_request`` workflow run for a pull request that has a merge
conflict: a push to its branch starts no CI, and adding the ``review`` label starts no
review round. Nothing fails and nothing is posted, so the agent watching the pull
request waits for a closing comment or a CI result that never comes.
`.github/workflows/conflict-notice.yml` runs this when ``main`` moves and hourly.

For each open pull request from this repository that GitHub reports as conflicted:

- **One comment per head commit**, whose first line is `marker`. A comment is a pull
  request event, so it wakes the watching session where the silence did not. A head
  that already has one gets no second, however often ``main`` moves.
- **The ``review`` label comes off**, with a comment saying so, whenever it is on a
  conflicted pull request: adding a label that is already there raises no event, so a
  label left on would make adding it again after the merge do nothing. This is checked
  on every run, not only the one that posts the notice, because the label can be added
  after it. A label added less than `LABEL_GRACE` ago is left for the next run: its
  review run may already be queued, and `review_loop_gate.py` refuses a round whose
  label is gone by the time the gate reads it.

Stdlib only; GitHub is reached through the ``gh`` command. ``--dry-run`` prints what
would be done and changes nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

REVIEW_LABEL = "review"
NO_REVIEW_LABEL = "no-review"
#: Who the workflow posts as, because it uses `GITHUB_TOKEN`. Posting with another
#: token would hide every earlier notice from the duplicate check.
COMMENT_AUTHOR = "github-actions[bot]"
#: How long a freshly added label is left for its own review run. A run that starts at
#: once reads the label within a minute or two; one queued behind a round in flight on
#: the same pull request (`review-loop.yml` never cancels one) waits for that round,
#: which its job caps at 45 minutes. Waiting longer only defers the removal to a later
#: hourly run; the conflict notice itself is not held back.
LABEL_GRACE = timedelta(minutes=50)


def marker(head_sha: str) -> str:
    return f"<!-- archivey-merge-conflict head={head_sha} -->"


def _footer(repository: str) -> str:
    # A relative link does not resolve from an issue comment, so spell the URL out.
    doc = f"https://github.com/{repository}/blob/main/dev-docs/review-loop.md"
    return f"\n\n---\n_Posted by the [conflict notice workflow]({doc})._\n"


LABEL_NOTE = (
    f"The `{REVIEW_LABEL}` label was on it, and a conflicted pull request starts no "
    "review round, so it has been taken off. Add it again after the merge."
)


@dataclass(frozen=True)
class Action:
    #: The comment to post, or empty for none.
    comment: str = ""
    remove_label: bool = False


def decide(
    pr: dict,
    comment_bodies: list[str],
    label_added_at: datetime | None,
    now: datetime,
    repository: str,
) -> Action:
    """What to do about one open pull request.

    ``pr`` is the REST pull request object; ``comment_bodies`` are the bodies of this
    workflow's own earlier comments on it; ``label_added_at`` is when the ``review``
    label was last added, if known.
    """
    if pr.get("mergeable") is not False:
        return Action()

    head = str(pr["head"]["sha"])
    labels = {label["name"] for label in pr.get("labels", [])}
    remove = REVIEW_LABEL in labels and (
        label_added_at is None or now - label_added_at >= LABEL_GRACE
    )
    flagged = any(body.startswith(marker(head)) for body in comment_bodies)

    if not flagged:
        body = (
            f"{marker(head)}\n**This pull request conflicts with `main`.** GitHub starts "
            "no `pull_request` workflow run for a conflicted pull request, so CI and the "
            "review loop stay silent until it merges cleanly. Merge `main` into the "
            "branch, resolve the conflict and push."
        )
        if remove:
            body += "\n\n" + LABEL_NOTE
        return Action(body + _footer(repository), remove)

    if remove:
        # Already told about this head, but the label was added since. Taking it off
        # without a word would read as a round having started.
        return Action(LABEL_NOTE + _footer(repository), True)
    return Action()


# --- GitHub ---------------------------------------------------------------------------


def _gh(*args: str) -> str:
    # stderr is left to the step log, where gh says why a call failed.
    return subprocess.run(
        ["gh", *args], check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def _gh_list(path: str) -> list[dict]:
    # `--slurp` makes one JSON array of the pages, so nothing is cut off by a reader
    # that stops early.
    pages = json.loads(_gh("api", path, "--paginate", "--slurp"))
    return [item for page in pages for item in page]


def _parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text)


def label_added_at(events: list[dict]) -> datetime | None:
    """When the ``review`` label was last added, from the issue events API."""
    added = [
        _parse_time(e["created_at"])
        for e in events
        if e.get("event") == "labeled"
        and (e.get("label") or {}).get("name") == REVIEW_LABEL
    ]
    return max(added, default=None)


def _read_pr(repo: str, number: int) -> dict:
    # GitHub computes `mergeable` in the background after the base moves and reports
    # null until it has; reading the pull request also asks for it.
    pr: dict = {}
    for attempt in range(6):
        pr = json.loads(_gh("api", f"repos/{repo}/pulls/{number}"))
        if pr.get("mergeable") is not None:
            break
        if attempt < 5:
            time.sleep(10)
    return pr


def main(argv: list[str]) -> int:
    dry_run = "--dry-run" in argv
    repo = os.environ["REPO"]
    now = datetime.now(UTC)

    open_prs = _gh_list(f"repos/{repo}/pulls?state=open&per_page=100")
    for listed in open_prs:
        # A fork's branch is not ours to merge into. `no-review` marks the review hub,
        # whose diff is the whole repository.
        if (listed.get("head", {}).get("repo") or {}).get("full_name") != repo:
            continue
        if any(label["name"] == NO_REVIEW_LABEL for label in listed.get("labels", [])):
            continue
        number = int(listed["number"])
        pr = _read_pr(repo, number)
        print(f"#{number} mergeable={json.dumps(pr.get('mergeable'))}")
        if pr.get("mergeable") is not False:
            continue

        comments = _gh_list(f"repos/{repo}/issues/{number}/comments?per_page=100")
        bodies = [
            str(c.get("body") or "")
            for c in comments
            if (c.get("user") or {}).get("login") == COMMENT_AUTHOR
        ]
        events = _gh_list(f"repos/{repo}/issues/{number}/events?per_page=100")
        action = decide(pr, bodies, label_added_at(events), now, repo)

        # The comment first: if it fails, the label stays on and the next run tries
        # both again. Taking the label off first could leave it gone with nothing said,
        # which reads as a round having started.
        if action.comment:
            print("  commenting:\n" + action.comment)
            if not dry_run:
                _gh(
                    "pr",
                    "comment",
                    str(number),
                    "--repo",
                    repo,
                    "--body",
                    action.comment,
                )
        if action.remove_label:
            print("  taking the review label off")
            if not dry_run:
                path = f"repos/{repo}/issues/{number}/labels/{REVIEW_LABEL}"
                status = subprocess.run(
                    ["gh", "api", "--method", "DELETE", "--silent", path], check=False
                ).returncode
                print(f"  label removal exit status {status}")
        if not action.comment and not action.remove_label:
            print("  nothing to do")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
