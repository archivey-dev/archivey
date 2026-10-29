"""The review eval's cases load and point at real commits (scripts/review_eval.py)."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "review_eval", ROOT / "scripts" / "review_eval.py"
)
assert _spec is not None and _spec.loader is not None
review_eval = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package; `@dataclass` looks its module up by name while executing.
sys.modules["review_eval"] = review_eval
_spec.loader.exec_module(review_eval)
CASES = review_eval.load_cases()


def test_case_ids_are_unique():
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_case_is_complete(case):
    assert re.fullmatch(r"[0-9a-f]{40}", case.head)
    assert re.fullmatch(r"[0-9a-f]{40}", case.base)
    assert case.bug and case.caught_if and case.files
    assert case.round >= 1
    assert case.body.startswith("# ")
    for spec in case.files:
        assert spec.split(":")[0].startswith("src/"), spec


def _have(sha: str) -> bool:
    return _have_in(ROOT, sha)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_case_commits_are_in_history(case):
    """`base` is an ancestor of `head`: fails on a mistyped SHA or a `base` from
    another line of history. Skipped when the clone lacks either commit (CI's
    shallow checkout; most heads live only under `refs/pull/<n>/head`), which the
    runner fetches before a run."""
    if not (_have(case.head) and _have(case.base)):
        pytest.skip("head or base commit not in this clone")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", case.base, case.head],
        cwd=ROOT,
        check=False,
    )
    assert ancestor.returncode == 0


def test_prepare_holds_history_up_to_head_only(tmp_path):
    """The replay repository has HEAD at `head`, `main` and `origin/main` at `base`,
    today's `review_prep.py`, and no commit after `head` (the fix must not be
    findable)."""
    if not _have("HEAD~2"):
        pytest.skip("shallow clone")
    git = review_eval.git
    later, head, base = (git("rev-parse", r) for r in ("HEAD", "HEAD~1", "HEAD~2"))
    case = review_eval.Case(
        id="prepare-test", pr=0, round=1, head=head, base=base, fixed_by="",
        files=["src/x"], bug="b", caught_if="c",
    )  # fmt: skip
    repo = review_eval.prepare(case, tmp_path)
    assert git("rev-parse", "HEAD", cwd=repo) == head
    assert git("rev-parse", "main", cwd=repo) == base
    assert git("rev-parse", "origin/main", cwd=repo) == base
    assert not _have_in(repo, later)
    copied = repo / "scripts" / "review_prep.py"
    assert copied.read_bytes() == (ROOT / "scripts" / "review_prep.py").read_bytes()


def _have_in(repo: Path, sha: str) -> bool:
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=repo,
        check=False,
        stderr=subprocess.DEVNULL,
    )
    return probe.returncode == 0
