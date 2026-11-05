"""`scripts/ci/ci_scope.py` and the `scope` job in ci.yml that uses it.

A pull request or merge group that changes no library, library test, dependency or CI
path skips some jobs: the library legs of the pull request set on a pull request push,
the queue-only jobs in the merge queue. A wrong answer here either runs the whole
matrix for nothing or, worse, lets a library change into main without the legs only the
queue runs, so both the path rule and the wiring are pinned.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "ci_scope.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
QUEUE_ONLY = ("test-queue", "unar-distro-packages", "pypy", "atheris")
#: The pull request set's library legs: a pull request push skips them when `scope`
#: says ``full=false``; the merge queue always runs them.
PR_LIBRARY = ("test", "free-threaded-concurrency", "benchmark", "lzo-oracle")

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
        ["scripts/fixtures/gen_rar_fixtures.py"],
        ["scripts/fixtures/commons_compress/CcList.java"],
        ["pyproject.toml"],
        ["uv.lock"],
        [".github/workflows/ci.yml"],
        [".github/workflows/atheris-fuzz.yml"],
        ["scripts/setup-dev-env.sh"],
        ["scripts/ci/junit_failure_lines.py"],
        ["scripts/ci/ci_scope.py"],
        ["scripts/investigations/scan_archives.py"],
        ["scripts/checks/api_surface.py"],
        # Files outside the code that a library test or a skipped job reads.
        ["benchmarks/harness.py"],
        ["benchmarks/conftest.py"],
        ["docs/api.md"],
        ["dev-docs/api-surface.txt"],
        ["dev-docs/tar-minefield-results.md"],
        ["LICENSE"],
        [".github/workflows/publish.yml"],
        [".python-version"],
        [".gitattributes"],
        # A script in no folder yet, or in a new one, counts until it is sorted.
        ["scripts/new_tool.py"],
        ["scripts/newfolder/x.py"],
        # A name that only starts like a NOT_FULL folder.
        ["scripts/reviewer.py"],
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
        ["scripts/review/review_prep.py", "scripts/review/review_tally.py"],
        # A script with its tests: those run in the lint job, which every run has.
        ["scripts/review/review_prep.py", "scripts/tests/test_review_prep.py"],
        ["scripts/tests/test_ci_scope.py"],
        ["scripts/release/release.py", "scripts/docs/llmstxt_preprocess.py"],
        [".claude/skills/code-review-skill/SKILL.md", "AGENTS.md"],
        [".github/workflows/review-loop.yml"],
        ["dev-docs/review-eval/results.md"],
        # Read by pre-commit on a developer's machine, by no CI job.
        [".pre-commit-config.yaml"],
        [".github/workflows/pr-gate.yml"],
        # Read by the script tests, which the lint job runs on every push.
        ["review/problem-catalogue/catalogue.md"],
        # A name that only starts like a FULL path.
        ["src_notes.md", "pyproject.toml.bak"],
    ],
)
def test_other_changes_are_not_full_paths(paths: list[str]) -> None:
    assert not scope.needs_full(paths)


def test_every_doc_ci_re_includes_for_a_library_test_is_a_full_path() -> None:
    """ci.yml's path filter re-includes a doc file a test reads so a change to it starts
    the workflow. A library test's doc must also be on `FULL`, or that run skips the
    test that reads it."""
    spec = importlib.util.spec_from_file_location(
        "ci_doc_paths", Path(__file__).with_name("test_ci_doc_paths.py")
    )
    assert spec and spec.loader
    doc_paths = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doc_paths)
    library_docs = {
        path: reader
        for path, reader in doc_paths.TEST_READ.items()
        if (ROOT / "tests" / f"{reader}.py").exists()
    }
    assert "docs/api.md" in library_docs, "the scan found nothing"
    uncovered = sorted(p for p in library_docs if not scope.needs_full([p]))
    assert not uncovered, f"add these to FULL: {uncovered}"


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
    for path in scope.FULL + scope.NOT_FULL:
        assert (ROOT / path).exists(), path


def test_every_script_the_workflows_run_is_a_full_path() -> None:
    """A script only a skipped job runs (PyPy's JUnit summary, the unar installers)
    would otherwise merge untested. `release.py` is only named in a comment, and
    `scripts/tests/` runs in the lint job, which no group skips."""
    named = set()
    for workflow in (CI, CI.with_name("atheris-fuzz.yml")):
        named |= set(re.findall(r"scripts/[\w./-]*[\w-]", workflow.read_text()))
    assert "scripts/ci/ci_scope.py" in named, "the scan found nothing"
    named -= {"scripts/release/release.py", "scripts/tests"}
    uncovered = sorted(
        n
        for n in named
        if not n.startswith("scripts/tests/") and not scope.needs_full([n])
    )
    assert not uncovered, f"move these out of the NOT_FULL folders: {uncovered}"


#: Script paths a library test names only in prose or as a member name inside an
#: archive, so not a file the test reads.
_NAMED_NOT_READ = {"scripts/release/release.py", "scripts/py7zr"}


_PART = r"""\s*/\s*["']([\w.-]+)["']"""
_JOIN = re.compile(r"""["']scripts["']((?:""" + _PART + r")+)")


def _script_paths(text: str) -> set[str]:
    """The ``scripts/...`` strings in ``text``, and each ``"scripts" / "a" / "b"`` join
    spelled out to its full path."""
    named = set(re.findall(r"scripts/[\w./-]*[\w-]", text))
    for join in _JOIN.finditer(text):
        named.add("/".join(["scripts", *re.findall(_PART, join[1])]))
    return named


def test_the_scan_spells_out_a_join_into_a_folder() -> None:
    """A join into a NOT_FULL folder must come out whole: its first part alone
    (``scripts/review``) has no trailing slash, so it would count as a full-run path."""
    text = 'SCRIPT = ROOT / "scripts" / "review" / "review_prep.py"\n'
    assert _script_paths(text) == {"scripts/review/review_prep.py"}
    assert not scope.needs_full(["scripts/review/review_prep.py"])


def test_every_script_a_library_test_reads_is_a_full_path() -> None:
    """A library test that reads or runs a script (a fixture generator, a scan it
    checks) must run on every leg when that script changes, or a script edit that breaks
    it on macOS or PyPy only would merge. The scan takes ``scripts/...`` strings and
    ``"scripts" / ...`` joins from every file under ``tests/``."""
    named: set[str] = set()
    joined: set[str] = set()
    for path in (ROOT / "tests").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        named |= _script_paths(text)
        joined |= _script_paths("".join(m[0] for m in _JOIN.finditer(text)))
    assert "scripts/fixtures/gen_rar_fixtures.py" in named, "the scan found nothing"
    assert "scripts/investigations/scan_archives.py" in joined, (
        "no join was spelled out"
    )
    uncovered = sorted(n for n in named - _NAMED_NOT_READ if not scope.needs_full([n]))
    assert not uncovered, f"move these out of the NOT_FULL folders: {uncovered}"


def test_script_tests_are_outside_full() -> None:
    """``scripts/tests/`` is not under ``tests/``, so changing a script test needs only
    the pull request set, which runs it in the lint job."""
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
    skipped scope (the daily run, a dispatch) or a failed one runs them. The lint job
    runs it with the dev group, which has PyYAML."""
    yaml = pytest.importorskip("yaml")
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    assert jobs["scope"]["if"] == (
        "github.event_name == 'merge_group' || github.event_name == 'pull_request'"
    )
    for name in QUEUE_ONLY:
        job = jobs[name]
        assert _needs(job) == ["scope"], name
        assert "!cancelled()" in job["if"], name
        assert "needs.scope.outputs.full != 'false'" in job["if"], name
    # The gate fails a group whose scope failed, and every queue-only job counts.
    assert {"scope", *QUEUE_ONLY} <= set(_needs(jobs["gate"]))
    # Besides those, only the pull request set's library legs wait on scope; lint,
    # which runs the script tests, starts at once.
    waiting = {n for n, j in jobs.items() if "scope" in _needs(j)}
    assert waiting - {"gate"} == {*QUEUE_ONLY, *PR_LIBRARY}


def test_a_script_only_pull_request_skips_the_library_legs_only_there() -> None:
    """Each library leg of the pull request set runs unless it is a pull request push
    whose scope said `full=false`: the merge queue, the daily run and a dispatch run it,
    and so does a pull request whose scope failed or found library paths."""
    yaml = pytest.importorskip("yaml")
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    expected = (
        "${{ !cancelled() && (github.event_name != 'pull_request' "
        "|| needs.scope.outputs.full != 'false') }}"
    )
    for name in PR_LIBRARY:
        job = jobs[name]
        assert _needs(job) == ["scope"], name
        assert job["if"] == expected, name
        assert {name} <= set(_needs(jobs["gate"])), name
    env = next(
        step["env"] for step in jobs["scope"]["steps"] if step.get("id") == "scope"
    )
    assert "github.event.pull_request.base.sha" in env["BASE"]
    assert "github.event.pull_request.head.sha" in env["HEAD"]
