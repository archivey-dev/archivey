"""The `pull_request: paths:` filter that keeps docs-only pull requests off the code CI.

`ci.yml` carries the list. A pull request whose files all fall outside it does not start
it, and reports no check from it at all, so a careless edit here shows up as nothing
rather than as a red check. This cannot run GitHub's matcher; it pins the edit that would
break the scheme silently: a doc file that a test reads losing its re-include (or the
re-include moving above the `!` entries, where GitHub's in-order evaluation would exclude
it again). `atheris-fuzz.yml` used to carry a copy; it no longer runs on pull requests
(it runs nightly and on a dispatch), and a test here keeps it that way, so a second
list cannot come back unchecked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FILTERED = ("ci.yml",)
# Doc paths a test reads, and the test that reads each one.
TEST_READ = {
    "docs/api.md": "test_public_api",
    "dev-docs/tar-minefield-results.md": "test_tar_minefield_corpus",
    "LICENSE": "test_cli_companion_package",
    "review/problem-catalogue/**": "test_review_problem_catalogue",
}


def _pull_request_paths(text: str) -> list[str]:
    """The `- entry` lines under `on.pull_request.paths`, comments skipped, quotes off."""
    return _trigger_paths(text, "pull_request")


def _trigger_paths(text: str, trigger: str) -> list[str]:
    """The `- entry` lines under `on.<trigger>.paths`, comments skipped, quotes off."""
    lines = text.splitlines()
    start = lines.index(f"  {trigger}:")
    entries: list[str] = []
    in_paths = False
    for line in lines[start + 1 :]:
        if line and not line.startswith("    "):
            break
        stripped = line.strip()
        if line.startswith("    paths:"):
            in_paths = True
        elif in_paths and stripped.startswith("- "):
            entries.append(stripped[2:].strip('"'))
        elif in_paths and stripped and not stripped.startswith("#"):
            break
    return entries


@pytest.fixture(scope="module")
def lists() -> dict[str, list[str]]:
    return {
        name: _pull_request_paths((WORKFLOWS / name).read_text(encoding="utf-8"))
        for name in FILTERED
    }


def test_ci_has_the_filter(lists: dict[str, list[str]]) -> None:
    assert lists["ci.yml"], "ci.yml has no pull_request paths filter"


def test_atheris_does_not_run_on_pull_requests() -> None:
    """The fuzz runs nightly and on a dispatch only: neither a pull request push nor the
    merge queue (ci.yml no longer calls it) starts it."""
    text = (WORKFLOWS / "atheris-fuzz.yml").read_text(encoding="utf-8")
    assert "\n  pull_request:" not in text
    assert "\n  workflow_call:" not in text
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "uses: ./.github/workflows/atheris-fuzz.yml" not in ci


#: Side workflows: stress runs, soaks, probes and the fsspec consumers. They run on a
#: schedule, on a dispatch, or after a merge to main, never on a pull request push,
#: where their setup and runner wait cost more than they caught.
NOT_ON_PULL_REQUESTS = (
    "accelerator-crash-search.yml",
    "accelerator-fuzz-soak.yml",
    "fsspec-consumers.yml",
    "ppmd-native-stress.yml",
    "rapidgzip-truncation-sweep.yml",
    "writer-timestamps.yml",
)


@pytest.mark.parametrize("name", NOT_ON_PULL_REQUESTS)
def test_side_workflow_does_not_run_on_pull_requests(name: str) -> None:
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    assert "\n  pull_request:" not in text


def test_test_read_docs_are_reincluded_after_every_exclusion(
    lists: dict[str, list[str]],
) -> None:
    entries = lists["ci.yml"]
    last_exclusion = max(i for i, e in enumerate(entries) if e.startswith("!"))
    for path, reader in TEST_READ.items():
        assert path in entries, f"{path} ({reader} reads it) is not re-included"
        assert entries.index(path) > last_exclusion, (
            f"{path} sits above a `!` entry, so GitHub excludes it again"
        )
