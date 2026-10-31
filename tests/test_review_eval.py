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


def test_reads_counts_each_file_and_tool_output_and_takes_the_result_totals(
    tmp_path: Path,
) -> None:
    partial = {"input_tokens": 1, "cache_read_input_tokens": 100, "output_tokens": 2}
    events = [
        {"type": "assistant", "message": {"id": "m1", "usage": partial, "content": [
            {"type": "tool_use", "id": "t1", "name": "Read",
             "input": {"file_path": "/r/SKILL.md"}},
            {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "ls"}},
            {"type": "tool_use", "id": "t5", "name": "Read",
             "input": {"file_path": "/r/CONTRIBUTING.md"}},
            # A lone shell read counts for its file; one inside a longer command does not.
            {"type": "tool_use", "id": "t3", "name": "Bash",
             "input": {"command": "sed -n '161,437p' CONTRIBUTING.md"}},
            {"type": "tool_use", "id": "t4", "name": "Bash",
             "input": {"command": "cat CONTRIBUTING.md | head"}},
            # So does a script of two reads, a comment, or two files.
            {"type": "tool_use", "id": "t6", "name": "Bash", "input": {
                "command": "head -n 20 src/foo.py\nsed -n '1,40p' CONTRIBUTING.md"}},
            {"type": "tool_use", "id": "t7", "name": "Bash",
             "input": {"command": "cat CONTRIBUTING.md # the guide"}},
            {"type": "tool_use", "id": "t8", "name": "Bash",
             "input": {"command": "head A B"}},
            # `./x` and `a/../x` are the same file as `x`.
            {"type": "tool_use", "id": "t9", "name": "Bash",
             "input": {"command": "head -n 5 ./CONTRIBUTING.md"}},
            {"type": "tool_use", "id": "t10", "name": "Read",
             "input": {"file_path": "/r/foo/../CONTRIBUTING.md"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "abcd"},
            {"type": "tool_result", "tool_use_id": "t2",
             "content": [{"type": "text", "text": "xy"}]},
            {"type": "tool_result", "tool_use_id": "t3", "content": "rules"},
            {"type": "tool_result", "tool_use_id": "t4", "content": "z"},
            {"type": "tool_result", "tool_use_id": "t5", "content": "whole"},
            {"type": "tool_result", "tool_use_id": "t6", "content": "MULTI"},
            {"type": "tool_result", "tool_use_id": "t7", "content": "HASH"},
            {"type": "tool_result", "tool_use_id": "t8", "content": "AB"},
            {"type": "tool_result", "tool_use_id": "t9", "content": "DOT"},
            {"type": "tool_result", "tool_use_id": "t10", "content": "UP"}]}},
        # The streamed events undercount output; the result event has the run's totals.
        {"type": "result", "result": "review", "usage": {
            "input_tokens": 1, "cache_read_input_tokens": 100,
            "cache_creation_input_tokens": 7, "output_tokens": 900}},
    ]  # fmt: skip
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    # Under the root, a Read (absolute) and a shell read (relative) of one file add up.
    read = review_eval.reads(transcript, Path("/r"))
    assert read["files"] == {"SKILL.md": 4, "(Bash)": 14, "CONTRIBUTING.md": 15}
    assert read["usage"] == {
        "input": 1,
        "cache_read": 100,
        "cache_write": 7,
        "output": 900,
    }


def test_claude_keeps_the_transcript_of_a_run_that_timed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"], output="partial\n")

    monkeypatch.setattr(review_eval.subprocess, "run", run)
    transcript = tmp_path / "transcript.jsonl"
    with pytest.raises(subprocess.TimeoutExpired):
        review_eval.claude(
            "p", model="m", cwd=tmp_path, tools="", env={}, transcript=transcript
        )
    assert transcript.read_text(encoding="utf-8") == "partial\n"


def test_summary_totals_turns_and_guide_reads(tmp_path: Path) -> None:
    case = CASES[0]
    work = tmp_path / case.id
    work.mkdir()
    (work / "meta.json").write_text(json.dumps({"turns": 9, "seconds": 60}))
    (work / "judge.json").write_text(json.dumps({"caught": "yes"}))
    files = {"CONTRIBUTING.md": 5, "dev-docs/x.md": 2, "src/a.py": 40, "(Bash)": 70}
    (work / "reads.json").write_text(json.dumps({"files": files}))
    text = review_eval.summary([case], tmp_path)
    assert "Turns: 9. Guide characters read: 7, of them `CONTRIBUTING.md`: 5." in text
