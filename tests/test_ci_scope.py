"""`scripts/ci_scope.py` and the `scope` job in ci.yml that uses it.

A merge group that changes no library, dependency or CI path skips the queue-only jobs.
A wrong answer here either runs the whole matrix for nothing or, worse, lets a library
change into main without the legs only the queue runs, so both the path rule and the
wiring are pinned.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_scope.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
QUEUE_ONLY = ("test-queue", "unar-distro-packages", "pypy", "atheris")

_spec = importlib.util.spec_from_file_location("ci_scope", SCRIPT)
assert _spec and _spec.loader
scope = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scope)


@pytest.mark.parametrize(
    "paths",
    [
        ["src/archivey/formats/zip_reader.py"],
        ["docs/index.md", "src/archivey/__init__.py"],
        ["packages/archivey-cpio/src/archivey_cpio/reader.py"],
        ["pyproject.toml"],
        ["uv.lock"],
        [".github/workflows/ci.yml"],
        [".github/workflows/atheris-fuzz.yml"],
        ["scripts/setup-dev-env.sh"],
        [],
    ],
)
def test_a_library_dependency_or_ci_change_runs_everything(paths: list[str]) -> None:
    assert scope.needs_full(paths)


@pytest.mark.parametrize(
    "paths",
    [
        ["scripts/review_prep.py", "tests/test_review_prep.py"],
        [".claude/skills/code-review-skill/SKILL.md", "AGENTS.md"],
        [".github/workflows/review-loop.yml"],
        ["dev-docs/review-eval/results.md"],
        # A name that only starts like a FULL path.
        ["src_notes.md", "pyproject.toml.bak"],
    ],
)
def test_other_changes_run_the_pull_request_set(paths: list[str]) -> None:
    assert not scope.needs_full(paths)


def test_a_cut_off_diff_runs_everything() -> None:
    assert scope.needs_full(["AGENTS.md"], truncated=True)


def test_the_script_writes_a_github_output_line() -> None:
    def run(stdin: str, *args: str) -> str:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    assert run("AGENTS.md\n\n") == "full=false\n"
    assert run("AGENTS.md\nsrc/archivey/core.py\n") == "full=true\n"
    assert run("AGENTS.md\n", "--truncated") == "full=true\n"


def test_the_full_paths_exist() -> None:
    for path in scope.FULL:
        assert (ROOT / path).exists(), path


def test_the_queue_only_jobs_wait_on_scope_and_run_when_it_did_not() -> None:
    """Each queue-only job needs `scope` and runs unless it said `full=false`, so a
    skipped scope (the daily run, a dispatch) or a failed one runs them."""
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    assert jobs["scope"]["if"] == "github.event_name == 'merge_group'"
    for name in QUEUE_ONLY:
        job = jobs[name]
        assert job["needs"] == "scope", name
        assert "!cancelled()" in job["if"], name
        assert "needs.scope.outputs.full != 'false'" in job["if"], name
    # The gate fails a group whose scope failed, and every queue-only job counts.
    assert {"scope", *QUEUE_ONLY} <= set(jobs["gate"]["needs"])
    # Nothing else waits on scope: the pull request set starts at once.
    waiting = {n for n, j in jobs.items() if "scope" in (j.get("needs") or [])}
    assert waiting - {"gate"} == set(QUEUE_ONLY)
