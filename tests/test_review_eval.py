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
    assert case.body.startswith("# ")
    for spec in case.files:
        assert spec.split(":")[0].startswith("src/"), spec


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_case_commits_are_in_history(case):
    """`base` is an ancestor of `head`, when this clone holds `head` (CI's shallow
    checkout may not)."""
    have = subprocess.run(
        ["git", "cat-file", "-e", f"{case.head}^{{commit}}"], cwd=ROOT, check=False
    )
    if have.returncode != 0:
        pytest.skip("head commit not in this clone")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", case.base, case.head],
        cwd=ROOT,
        check=False,
    )
    assert ancestor.returncode == 0
