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
- **A red run whose only problem is jobs no runner picked up** changes nothing the first
  time. GitHub cancels such a job without running a step ("The job was not acquired by
  Runner of type hosted"), for example when macOS runners are short, and the run ends
  as a failure although no code ran. When the workflow's previous scheduled or
  post-merge run on `main` lost a job the same way, the run reports as a failure that
  names the lost jobs, so a shortage that lasts, or a job no runner can ever take, is
  not silent. A job that failed, timed out, or started and was then cancelled always
  reports the run.
- **A green scheduled run** closes the issue. A green ``push`` run closes nothing: some
  workflows search for much less time after a merge than on their schedule.

Only text this workflow posted is read for the previous list: anyone can comment on a
public issue, and a planted list would hide new failures.

Stdlib only; GitHub is reached through the ``gh`` command. The run is described by the
environment variables the workflow sets (`main` lists them) and, for the run's attempt,
by the ``workflow_run`` event file (`_attempt`).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass

#: The hidden line that carries a report's failed jobs, as a JSON list. JSON escapes a
#: tab or newline in a name, and `encode_jobs` escapes ``>`` so no name can end the
#: HTML comment.
MARKER = "<!-- failed-jobs: {} -->"
_MARKER_RE = re.compile(r"^<!-- failed-jobs: (.*) -->$", re.MULTILINE)


def encode_jobs(jobs: list[str]) -> str:
    return json.dumps(jobs).replace(">", "\\u003e")


def decode_jobs(text: str) -> list[str] | None:
    try:
        jobs = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(jobs, list) or not all(isinstance(j, str) for j in jobs):
        return None
    return jobs


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


#: Job conclusions that do not make a run red.
_FINE = frozenset({"success", "skipped", "neutral"})


def _is_lost(job: dict) -> bool:
    return job.get("conclusion") == "cancelled" and not job.get("steps")


def lost_jobs(jobs: list[dict]) -> list[str]:
    """The jobs GitHub cancelled before any step ran, when they are the run's only problem.

    Such a job was never taken by a runner, so nothing in the repository was checked.
    The list is empty when any other job did not pass: one that failed or timed out, or
    one that started and was then cancelled. That run reports as usual.
    """
    if not all(_is_lost(j) for j in jobs if j.get("conclusion") not in _FINE):
        return []
    return sorted({j["name"] for j in jobs if _is_lost(j)})


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
            return decode_jobs(found[-1])
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
    marker = MARKER.format(encode_jobs(jobs))
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
    lost: Sequence[str] = (),
) -> Action:
    """The action for one finished run, given the open issue (None when there is none).

    ``lost`` names jobs no runner took. They are listed under their own heading and
    left out of the marker, so **new** keeps meaning newly failing.
    """
    line = f"`{conclusion}` on {sha[:12]}: {run_url}"
    if conclusion == "success":
        if issue is not None and event == "schedule":
            return Action("close", f"Green again, {line}")
        return Action("none")
    previous = previous_jobs(issue) if issue is not None else None
    block, new = jobs_block(jobs, previous)
    if lost:
        block += (
            "\n\nJobs no runner took in this run (cancelled before any step):\n"
            + "\n".join(f"- `{job}`" for job in lost)
            + "\n\nThe previous run also lost a job, or its jobs could not be read."
        )
    if issue is not None:
        noun = "job" if new == 1 else "jobs"
        lead = f"New failure in {new} {noun}" if new else "Still failing"
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


def _attempt() -> str:
    """The attempt that finished, from the ``workflow_run`` event GitHub saved for the job.

    A rerun may already be the run's latest attempt, which ``gh run view`` reads by
    default. Read from the event file, not passed in from the workflow, so the workflow
    puts no event text in its environment.
    """
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
        return str(int(json.load(f)["workflow_run"]["run_attempt"]))


def _run_jobs(run_id: str, attempt: str) -> list[dict]:
    try:
        data = json.loads(
            _gh("run", "view", run_id, "--attempt", attempt, "--json", "jobs")
        )
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        # Without the list the report reads as it did before jobs were named.
        return []
    return data.get("jobs") or []


def _previous_run_lost(workflow: str, run_id: str) -> bool:
    """Whether the previous scheduled or post-merge run on `main` also lost a job.

    Its newest attempt counts, so a green rerun clears it. A cancelled or skipped run is
    passed over, as the alert passes over such runs: a superseded run's queued jobs
    also end cancelled with no steps. True when the runs or the previous run's jobs
    cannot be read: a report that might be noise is better than a gap nobody sees.
    """
    try:
        runs = json.loads(
            _gh(
                "run",
                "list",
                "--workflow",
                workflow,
                "--branch",
                "main",
                "--limit",
                "20",
                "--json",
                "databaseId,event,status,conclusion",
            )
        )
        previous = next(
            (
                str(run["databaseId"])
                for run in runs
                if str(run.get("databaseId")) != run_id
                and run.get("status") == "completed"
                and run.get("conclusion") not in ("cancelled", "skipped")
                and run.get("event") in ("schedule", "push")
            ),
            None,
        )
        if previous is None:
            return False
        data = json.loads(_gh("run", "view", previous, "--json", "jobs"))
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError):
        return True
    return bool(lost_jobs(data.get("jobs") or []))


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
    attempt = _attempt()
    run_jobs = _run_jobs(env["RUN_ID"], attempt) if conclusion != "success" else []
    lost = lost_jobs(run_jobs)
    if lost and not _previous_run_lost(workflow, env["RUN_ID"]):
        print(f"none: {name} (no runner took {', '.join(lost)}; no job failed)")
        return 0
    jobs = failed_jobs(run_jobs)
    action = decide(
        workflow=workflow,
        conclusion=conclusion,
        event=env["EVENT"],
        sha=env["SHA"],
        run_url=env["RUN_URL"] + "/attempts/" + attempt,
        issue=issue,
        jobs=jobs,
        lost=lost,
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
