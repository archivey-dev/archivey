#!/usr/bin/env python3
"""Open, update or close the alert issue for one finished workflow run on ``main``.

`.github/workflows/scheduled-failure-alert.yml` runs this when a watched workflow finishes
a scheduled or post-merge (``push``) run; that file says which runs and why. There is one
open issue per workflow, titled ``Scheduled run failing: <workflow>``:

- **A failed run** opens the issue, or comments on the open one. Each report lists the
  jobs that failed (none when the run started no jobs or its jobs could not be read) and
  keeps that list in a hidden `MARKER` line. A job that the previous report's list did
  not name is marked **new**, so a second failure in a workflow that is already red does
  not read as the old one. A report with no earlier list marks nothing new.
- **A green scheduled run** closes the issue. A green ``push`` run closes nothing: some
  workflows search for much less time after a merge than on their schedule.

Only text this workflow posted is read for the previous list: anyone can comment on a
public issue, and a planted list would hide new failures.

Stdlib only; GitHub is reached through the ``gh`` command. The run is described by the
environment variables the workflow sets (`main` lists them).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

#: The hidden line that carries a report's failed jobs, tab-separated.
MARKER = "<!-- failed-jobs: {} -->"
_MARKER_RE = re.compile(r"^<!-- failed-jobs: (.*) -->$", re.MULTILINE)

#: Logins ``gh`` reports for text the workflow's token posted (comments, issue author).
BOT_LOGINS = frozenset({"github-actions", "app/github-actions", "github-actions[bot]"})

FAILED = frozenset({"failure", "timed_out"})


@dataclass(frozen=True)
class Action:
    """What to do with the workflow's issue. ``kind`` is close, comment, create or none."""

    kind: str
    body: str = ""


def title(workflow: str) -> str:
    return f"Scheduled run failing: {workflow}"


def failed_jobs(jobs: list[dict]) -> list[str]:
    """The names of the jobs that failed or timed out, sorted, each once."""
    return sorted({j["name"] for j in jobs if j.get("conclusion") in FAILED})


def previous_jobs(issue: dict) -> list[str] | None:
    """The job list of the newest report this workflow posted, or None if it has none."""
    texts = []
    if _login(issue.get("author")) in BOT_LOGINS:
        texts.append(issue.get("body") or "")
    texts += [
        c.get("body") or ""
        for c in issue.get("comments") or []
        if _login(c.get("author")) in BOT_LOGINS
    ]
    for text in reversed(texts):
        found = _MARKER_RE.findall(text)
        if found:
            return [name for name in found[-1].split("\t") if name]
    return None


def _login(author: dict | None) -> str:
    return (author or {}).get("login") or ""


def jobs_block(jobs: list[str], previous: list[str] | None) -> tuple[str, int]:
    """The report's job list and marker, and how many of the jobs are new."""
    if not jobs:
        return "", 0
    lines, new = [], 0
    for job in jobs:
        if previous is not None and job not in previous:
            lines.append(f"- **new:** `{job}`")
            new += 1
        else:
            lines.append(f"- `{job}`")
    marker = MARKER.format("\t".join(jobs))
    return "\n\nFailed jobs:\n" + "\n".join(lines) + "\n\n" + marker, new


def decide(
    *,
    workflow: str,
    conclusion: str,
    event: str,
    sha: str,
    run_url: str,
    issue: dict | None,
    jobs: list[str],
) -> Action:
    """The action for one finished run, given the open issue (None when there is none)."""
    line = f"`{conclusion}` on {sha[:12]}: {run_url}"
    if conclusion == "success":
        if issue is not None and event == "schedule":
            return Action("close", f"Green again, {line}")
        return Action("none")
    previous = previous_jobs(issue) if issue is not None else None
    block, new = jobs_block(jobs, previous)
    if issue is not None:
        lead = f"New failure in {new} job(s)" if new else "Still failing"
        return Action("comment", f"{lead}, {line}{block}")
    return Action(
        "create",
        f"The `{event}` run of `{workflow}` on `main` failed, {line}{block}\n\n"
        "This issue gets a comment on each further failed scheduled or post-merge run\n"
        "and closes on the next green scheduled run. See dev-docs/maintenance.md for "
        "what a red run of each\nworkflow means.\n\n"
        "Opened by `.github/workflows/scheduled-failure-alert.yml`.",
    )


def _gh(*args: str) -> str:
    # stderr is left to the step log, where gh says why a call failed.
    return subprocess.run(
        ["gh", *args], check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def _run_jobs(run_id: str) -> list[str]:
    try:
        data = json.loads(_gh("run", "view", run_id, "--json", "jobs"))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        # Without the list the report reads as it did before jobs were named.
        return []
    return failed_jobs(data.get("jobs") or [])


def main() -> int:
    env = os.environ
    workflow, conclusion = env["WORKFLOW"], env["CONCLUSION"]
    name = title(workflow)
    open_issues = json.loads(
        _gh(
            "issue",
            "list",
            "--state",
            "open",
            "--limit",
            "500",
            "--json",
            "number,title",
        )
    )
    number = next((i["number"] for i in open_issues if i["title"] == name), None)
    issue = None
    if number is not None:
        issue = json.loads(
            _gh("issue", "view", str(number), "--json", "author,body,comments")
        )
    jobs = _run_jobs(env["RUN_ID"]) if conclusion != "success" else []
    action = decide(
        workflow=workflow,
        conclusion=conclusion,
        event=env["EVENT"],
        sha=env["SHA"],
        run_url=env["RUN_URL"],
        issue=issue,
        jobs=jobs,
    )
    if action.kind == "close":
        _gh(
            "issue",
            "close",
            str(number),
            "--reason",
            "completed",
            "--comment",
            action.body,
        )
    elif action.kind == "comment":
        _gh("issue", "comment", str(number), "--body", action.body)
    elif action.kind == "create":
        _gh(
            "issue",
            "create",
            "--title",
            name,
            "--assignee",
            env["ASSIGNEE"],
            "--body",
            action.body,
        )
    print(f"{action.kind}: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
