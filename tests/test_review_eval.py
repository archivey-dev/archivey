"""The review eval's cases load and point at real commits (scripts/review_eval.py)."""

from __future__ import annotations

import importlib.util
import json
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


def test_reads_counts_each_file_tool_output_and_api_call_once(tmp_path: Path) -> None:
    early = {"input_tokens": 1, "cache_read_input_tokens": 100, "output_tokens": 2}
    usage = {"input_tokens": 1, "cache_read_input_tokens": 100, "output_tokens": 5}
    events = [
        # One API call arrives as one event per content block; the last has its totals.
        {"type": "assistant", "message": {"id": "m1", "usage": early, "content": [
            {"type": "tool_use", "id": "t1", "name": "Read",
             "input": {"file_path": "/r/SKILL.md"}}]}},
        {"type": "assistant", "message": {"id": "m1", "usage": usage, "content": [
            {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "ls"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "abcd"},
            {"type": "tool_result", "tool_use_id": "t2",
             "content": [{"type": "text", "text": "xy"}]}]}},
        # An event with no id counts as a call of its own.
        {"type": "assistant", "message": {"usage": {"output_tokens": 3}, "content": [
            {"type": "text", "text": "done"}]}},
        {"type": "result", "result": "review"},
    ]  # fmt: skip
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    read = review_eval.reads(transcript)
    assert read["files"] == {"/r/SKILL.md": 4, "(Bash)": 2}
    assert read["usage"] == {
        "input": 1,
        "cache_read": 100,
        "cache_write": 0,
        "output": 8,
    }
