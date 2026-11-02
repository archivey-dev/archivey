"""`scripts/ci_scope.py` and the `scope` job in ci.yml that uses it.

A merge group that changes no library, library test, dependency or CI path skips the
queue-only jobs. A wrong answer here either runs the whole matrix for nothing or, worse,
lets a library change into main without the legs only the queue runs, so both the path
rule and the wiring are pinned.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
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
        ["tests/test_zip.py"],
        ["tests/conftest.py"],
        ["scripts/gen_rar_fixtures.py"],
        ["scripts/commons_compress/CcList.java"],
        ["pyproject.toml"],
        ["uv.lock"],
        [".github/workflows/ci.yml"],
        [".github/workflows/atheris-fuzz.yml"],
        ["scripts/setup-dev-env.sh"],
        ["scripts/junit_failure_lines.py"],
        ["scripts/ci_scope.py"],
        [],
    ],
)
def test_a_library_test_dependency_or_ci_change_runs_everything(
    paths: list[str],
) -> None:
    assert scope.needs_full(paths)


@pytest.mark.parametrize(
    "paths",
    [
        ["scripts/review_prep.py", "scripts/review_tally.py"],
        # A script with its tests: those run in the lint job, which every run has.
        ["scripts/review_prep.py", "scripts/tests/test_review_prep.py"],
        ["scripts/tests/test_ci_scope.py"],
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


def test_every_script_the_workflows_run_is_a_full_path() -> None:
    """A script only a skipped job runs (PyPy's JUnit summary, the unar installers)
    would otherwise merge untested. `release.py` is only named in a comment, and
    `scripts/tests` runs in the lint job, which no group skips."""
    named = set()
    for workflow in (CI, CI.with_name("atheris-fuzz.yml")):
        named |= set(re.findall(r"scripts/[\w.-]+", workflow.read_text()))
    assert named - {"scripts/release.py", "scripts/tests"} <= set(scope.FULL)


#: Script paths a library test names only in prose or as a member name inside an
#: archive, so not a file the test reads.
_NAMED_NOT_READ = {"scripts/release.py", "scripts/py7zr"}


def test_every_script_a_library_test_reads_is_a_full_path() -> None:
    """A library test that reads or runs a script (a fixture generator, a scan it
    checks) must run on every leg when that script changes, or a script edit that breaks
    it on macOS or PyPy only would merge. The scan takes ``scripts/...`` strings and
    ``"scripts" / "name"`` joins from every file under ``tests/``."""
    named: set[str] = set()
    for path in (ROOT / "tests").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        named |= set(re.findall(r"scripts/[\w./-]*[\w-]", text))
        named |= {
            f"scripts/{m}"
            for m in re.findall(r"""["']scripts["']\s*/\s*["']([\w./-]+)["']""", text)
        }
    assert "scripts/gen_rar_fixtures.py" in named, "the scan found nothing"
    uncovered = sorted(n for n in named - _NAMED_NOT_READ if not scope.needs_full([n]))
    assert not uncovered, f"add these to FULL in scripts/ci_scope.py: {uncovered}"


def test_script_tests_are_outside_full() -> None:
    """``scripts/tests/`` is not under ``tests/``, so a script change with its tests
    needs only the pull request set, which runs them in the lint job."""
    assert not scope.needs_full(["scripts/tests/test_review_prep.py"])
    yaml = pytest.importorskip("yaml")
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    runs = [step.get("run", "") for step in jobs["lint"]["steps"]]
    assert any("pytest scripts/tests" in run for run in runs)
    assert "scope" not in _needs(jobs["lint"])


def _needs(job: dict) -> list[str]:
    """A job's `needs:`, which YAML gives as a string for one and a list for more."""
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def test_the_queue_only_jobs_wait_on_scope_and_run_when_it_did_not() -> None:
    """Each queue-only job needs `scope` and runs unless it said `full=false`, so a
    skipped scope (the daily run, a dispatch) or a failed one runs them. PyYAML is a dev
    dependency, so the core-only legs skip this one; the others run it."""
    yaml = pytest.importorskip("yaml")
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    assert jobs["scope"]["if"] == "github.event_name == 'merge_group'"
    for name in QUEUE_ONLY:
        job = jobs[name]
        assert _needs(job) == ["scope"], name
        assert "!cancelled()" in job["if"], name
        assert "needs.scope.outputs.full != 'false'" in job["if"], name
    # The gate fails a group whose scope failed, and every queue-only job counts.
    assert {"scope", *QUEUE_ONLY} <= set(_needs(jobs["gate"]))
    # Nothing else waits on scope: the pull request set starts at once.
    waiting = {n for n, j in jobs.items() if "scope" in _needs(j)}
    assert waiting - {"gate"} == set(QUEUE_ONLY)
