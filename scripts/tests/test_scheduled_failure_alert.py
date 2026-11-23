"""The scheduled failure alert's reports, exercised without GitHub.

`scripts/ci/scheduled_failure_alert.py` keeps one issue per red workflow on ``main``. A
mistake there is silence: a new failure that reads as the old one, as on 2026-11-14 when
the PyPy core-only step broke inside an issue the minimum-versions leg kept open. The
cases are pinned here, and `test_main_drives_gh` runs the script end to end against a
stub ``gh`` on ``PATH``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "scheduled_failure_alert.py"
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled-failure-alert.yml"

_spec = importlib.util.spec_from_file_location("scheduled_failure_alert", SCRIPT)
assert _spec is not None and _spec.loader is not None
alert = importlib.util.module_from_spec(_spec)
# `@dataclass` looks its own module up by name, so register it before executing.
sys.modules[_spec.name] = alert
_spec.loader.exec_module(alert)

BOT = {"login": "github-actions"}
PYPY = "pypy3.11"
LOWEST = "ubuntu-24.04 / py3.11 / all-lowest"


def report(conclusion="failure", event="schedule", issue=None, jobs=(PYPY, LOWEST)):
    return alert.decide(
        workflow="CI",
        conclusion=conclusion,
        event=event,
        sha="0123456789abcdef",
        run_url="https://run",
        issue=issue,
        jobs=list(jobs),
    )


def issue_with(*comments: tuple[dict, str], body: str = "", author=BOT) -> dict:
    return {
        "author": author,
        "body": body,
        "comments": [{"author": a, "body": b} for a, b in comments],
    }


def marker(*jobs: str) -> str:
    return alert.MARKER.format(alert.encode_jobs(list(jobs)))


def test_failed_jobs_keeps_failures_and_timeouts_only() -> None:
    jobs = [
        {"name": "b", "conclusion": "failure"},
        {"name": "a", "conclusion": "timed_out"},
        {"name": "c", "conclusion": "success"},
        {"name": "d", "conclusion": "cancelled"},
        {"name": "b", "conclusion": "failure"},
    ]
    assert alert.failed_jobs(jobs) == ["a", "b"]


def test_a_run_with_no_failure_names_the_job_that_did_not_pass() -> None:
    lost = {"name": "macos", "conclusion": "cancelled", "steps": []}
    started = {"name": "ubuntu", "conclusion": "cancelled", "steps": [{"name": "x"}]}
    broken = {"name": "win", "conclusion": "startup_failure", "steps": []}
    passed = {"name": "docs", "conclusion": "success", "steps": [{"name": "x"}]}
    assert alert.failed_jobs([lost, started, broken, passed]) == ["ubuntu", "win"]
    assert alert.failed_jobs([lost, passed]) == []


def test_a_job_no_runner_took_is_listed_as_lost() -> None:
    # Issue 1654: macOS runners were short, GitHub cancelled the job before any step,
    # and the other jobs passed.
    lost = {"name": "macos", "conclusion": "cancelled", "steps": []}
    passed = {"name": "ubuntu", "conclusion": "success", "steps": [{"name": "x"}]}
    assert alert.lost_jobs([lost, passed]) == ["macos"]
    # A real failure next to a lost job reports as usual.
    failed = {"name": "win", "conclusion": "failure", "steps": [{"name": "x"}]}
    assert alert.lost_jobs([lost, failed]) == []
    # A job cancelled after it started (or a run with no jobs) is not this case.
    started = {**lost, "steps": [{"name": "x"}]}
    assert alert.lost_jobs([started, passed]) == []
    assert alert.lost_jobs([]) == []


@pytest.mark.parametrize("other", ["cancelled", "startup_failure", "action_required"])
def test_a_lost_job_does_not_hide_another_bad_job(other: str) -> None:
    # A job that started and was then cancelled (a runner shutdown, or a
    # timeout-minutes hit reported as cancelled) is a real problem next to a lost one.
    lost = {"name": "macos", "conclusion": "cancelled", "steps": []}
    bad = {"name": "ubuntu", "conclusion": other, "steps": [{"name": "x"}]}
    passed = {"name": "win", "conclusion": "success", "steps": [{"name": "x"}]}
    assert alert.lost_jobs([lost, bad, passed]) == []
    # Skipped and neutral jobs leave a lost job as the only problem.
    skipped = {"name": "docs", "conclusion": "skipped", "steps": []}
    neutral = {"name": "lint", "conclusion": "neutral", "steps": [{"name": "x"}]}
    assert alert.lost_jobs([lost, skipped, neutral, passed]) == ["macos"]


def test_a_new_issue_lists_the_jobs_and_keeps_the_marker() -> None:
    action = report()
    assert action.kind == "create"
    assert f"- `{PYPY}`" in action.body
    assert "**new:**" not in action.body
    assert marker(PYPY, LOWEST) in action.body
    assert alert.previous_jobs(issue_with(body=action.body)) == [PYPY, LOWEST]


def test_an_issue_with_no_earlier_list_marks_nothing_new() -> None:
    action = report(issue=issue_with((BOT, "Still failing, `failure` on x")))
    assert action.kind == "comment"
    assert action.body.startswith("Still failing, ")
    assert "**new:**" not in action.body
    assert marker(PYPY, LOWEST) in action.body


def test_a_job_the_previous_list_did_not_name_is_new() -> None:
    issue = issue_with((BOT, "Still failing\n\n" + marker(LOWEST)))
    action = report(issue=issue)
    assert action.body.startswith("New failure in 1 job, ")
    assert f"- **new:** `{PYPY}`" in action.body
    assert f"- `{LOWEST}`" in action.body


def test_the_newest_list_wins() -> None:
    issue = issue_with(
        (BOT, marker(LOWEST)), (BOT, marker(PYPY, LOWEST)), body=marker()
    )
    assert report(issue=issue).body.startswith("Still failing, ")


def test_a_list_posted_by_someone_else_is_ignored() -> None:
    # Anyone can comment on a public issue; a planted list must not hide a new failure.
    planted = (({"login": "someone"}), marker(PYPY, LOWEST))
    issue = issue_with((BOT, marker(LOWEST)), planted)
    assert f"- **new:** `{PYPY}`" in report(issue=issue).body
    # Nor does an issue body count unless the workflow opened the issue.
    by_person = issue_with(body=marker(PYPY, LOWEST), author={"login": "someone"})
    assert alert.previous_jobs(by_person) is None


def test_a_run_with_no_jobs_names_none() -> None:
    action = report(conclusion="startup_failure", issue=issue_with(), jobs=())
    assert (
        action.body == "Still failing, `startup_failure` on 0123456789ab: https://run"
    )


def test_green_closes_only_on_a_scheduled_run() -> None:
    issue = issue_with()
    assert report("success", issue=issue) == alert.Action(
        "close", "Green again, `success` on 0123456789ab: https://run"
    )
    assert report("success", "push", issue=issue).kind == "none"
    assert report("success").kind == "none"


def test_the_workflow_calls_this_script_with_its_environment() -> None:
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = data["jobs"]["alert"]["steps"][-1]
    assert step["run"].strip() == "python3 scripts/ci/scheduled_failure_alert.py"
    source = SCRIPT.read_text(encoding="utf-8")
    used = {
        name
        for name in step["env"]
        if f'env["{name}"]' in source or name in {"GH_TOKEN", "GH_REPO"}
    }
    assert used == set(step["env"])
    assert data["permissions"]["actions"] == "read"
    # The checkout of scripts/ci needs it; a permissions block sets the rest to none.
    assert data["permissions"]["contents"] == "read"


STUB = """#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["GH_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:2] == ["issue", "list"]:
    print(json.dumps([{"number": 7, "title": "Scheduled run failing: CI"}]))
elif args[:2] == ["issue", "view"]:
    print(os.environ["GH_ISSUE"])
elif args[:2] == ["run", "list"]:
    print(json.dumps([
        {"databaseId": 6, "event": "push", "status": "in_progress"},
        {"databaseId": 5, "event": "push", "status": "completed"},
        {"databaseId": 4, "event": "workflow_dispatch", "status": "completed"},
        {"databaseId": 2, "event": "push", "status": "completed",
         "conclusion": "cancelled"},
        {"databaseId": 3, "event": "schedule", "status": "completed"},
    ]))
elif args[:2] == ["run", "view"]:
    if args[2] != "5" and os.environ.get("GH_PREVIOUS_FAILS"):
        sys.exit(1)
    key = "GH_JOBS" if args[2] == "5" else "GH_PREVIOUS_JOBS"
    print(os.environ.get(key) or json.dumps(
        {"jobs": [{"name": "pypy3.11", "conclusion": "failure"}]}))
"""


def test_main_drives_gh(tmp_path: Path) -> None:
    stub = tmp_path / "gh"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    log = tmp_path / "log"
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"workflow_run": {"run_attempt": 1}}), encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "GH_LOG": str(log),
        "GH_ISSUE": json.dumps(issue_with((BOT, marker(LOWEST)))),
        "WORKFLOW": "CI",
        "CONCLUSION": "failure",
        "EVENT": "schedule",
        "SHA": "0123456789abcdef",
        "RUN_URL": "https://run",
        "RUN_ID": "5",
        "GITHUB_EVENT_PATH": str(event),
        "ASSIGNEE": "davitf",
    }
    subprocess.run([sys.executable, str(SCRIPT)], env=env, check=True)
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert ["run", "view", "5", "--attempt", "1", "--json", "jobs"] in calls
    assert calls[-1][:3] == ["issue", "comment", "7"]
    assert "- **new:** `pypy3.11`" in calls[-1][-1]
    assert "https://run/attempts/1" in calls[-1][-1]

    def run(jobs: dict, previous: dict) -> list[list[str]]:
        env["GH_JOBS"], env["GH_PREVIOUS_JOBS"] = json.dumps(jobs), json.dumps(previous)
        log.unlink()
        subprocess.run([sys.executable, str(SCRIPT)], env=env, check=True)
        return [
            json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
        ]

    lost = {"jobs": [{"name": "macos", "conclusion": "cancelled", "steps": []}]}
    green = {"jobs": [{"name": "macos", "conclusion": "success", "steps": [{"n": 1}]}]}
    # A first lost job changes nothing; run 3 (the previous scheduled run) was green.
    calls = run(lost, green)
    assert calls[-1] == ["run", "view", "3", "--json", "jobs"]
    # A second one in a row reports, naming the lost job.
    calls = run(lost, lost)
    assert calls[-1][:3] == ["issue", "comment", "7"]
    body = calls[-1][-1]
    assert "Jobs no runner took in this run" in body
    assert "or its jobs could not be read" in body
    assert "- `macos`" in body
    # Lost jobs stay out of the failed list and its marker.
    assert "Failed jobs" not in body
    # A previous run that lost a job next to another bad job also counts.
    started = {"name": "ubuntu", "conclusion": "cancelled", "steps": [{"n": 1}]}
    calls = run(lost, {"jobs": [*lost["jobs"], started]})
    assert calls[-1][:3] == ["issue", "comment", "7"]
    # A lost job next to a started-then-cancelled one reports, naming the latter.
    calls = run({"jobs": [*lost["jobs"], started]}, green)
    assert calls[-1][:3] == ["issue", "comment", "7"]
    assert "- **new:** `ubuntu`" in calls[-1][-1]
    # A previous run whose jobs cannot be read counts as lost: report.
    env["GH_PREVIOUS_FAILS"] = "1"
    calls = run(lost, green)
    assert calls[-1][:3] == ["issue", "comment", "7"]


@pytest.mark.parametrize("odd", ["name\twith\ttab", "line\nbreak", "ends --> here"])
def test_any_job_name_round_trips_through_the_marker(odd: str) -> None:
    created = report(jobs=(odd, PYPY))
    assert alert.previous_jobs(issue_with(body=created.body)) == [odd, PYPY]
    assert report(issue=issue_with(body=created.body), jobs=(odd,)).body.startswith(
        "Still failing, "
    )


def test_two_new_jobs_say_jobs() -> None:
    action = report(issue=issue_with((BOT, marker("other"))))
    assert action.body.startswith("New failure in 2 jobs, ")
