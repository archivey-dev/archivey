"""The review session summary, run on a hand-built execution file.

`scripts/review_loop_trace.py` reads the SDK messages `claude-code-action` writes after
a review round. These cases pin the message shapes it relies on (one event per content
block sharing a message id, subagent events carrying `parent_tool_use_id`) and that no
tool result text reaches the summary or the trace.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "review_loop_trace.py"

_spec = importlib.util.spec_from_file_location("review_loop_trace", SCRIPT)
assert _spec is not None and _spec.loader is not None
trace_mod = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package; `@dataclass` looks its module up in `sys.modules`.
sys.modules[_spec.name] = trace_mod
_spec.loader.exec_module(trace_mod)

SECRET = "ghs_resultTextThatMustNotLeak"


def assistant(mid: str, part: dict, parent: str | None = None, cache: int = 0) -> dict:
    return {
        "type": "assistant",
        "parent_tool_use_id": parent,
        "message": {
            "id": mid,
            "model": "claude-opus-5-5",
            "content": [part],
            "usage": {"input_tokens": 2, "cache_read_input_tokens": cache},
        },
    }


def tool_use(tid: str, name: str, **args: object) -> dict:
    return {"type": "tool_use", "id": tid, "name": name, "input": args}


def result(tid: str, text: str, parent: str | None = None) -> dict:
    return {
        "type": "user",
        "parent_tool_use_id": parent,
        "message": {
            "content": [{"type": "tool_result", "tool_use_id": tid, "content": text}]
        },
    }


MESSAGES = [
    {"type": "system", "subtype": "init", "model": "claude-opus-5-5"},
    # Turn 1: three calls in one response, each its own event.
    assistant("m1", {"type": "text", "text": "Reading the diff."}, cache=1000),
    assistant("m1", tool_use("t1", "Bash", command="gh pr diff 7")),
    assistant("m1", tool_use("t2", "Read", file_path="src/a.py")),
    assistant(
        "m1",
        tool_use(
            "t3",
            "Agent",
            subagent_type="Explore",
            model="sonnet",
            description="Find callers",
            prompt="Who calls f?",
        ),
    ),
    result("t1", "x" * 500),
    result("t2", SECRET),
    # The subagent's own turns.
    assistant("s1", tool_use("u1", "Grep", pattern="f\\("), parent="t3"),
    result("u1", "src/b.py:3", parent="t3"),
    assistant("s2", {"type": "text", "text": "Two callers."}, parent="t3"),
    result("t3", "callers: b.py:3, c.py:9"),
    # Turn 2: one call alone.
    assistant("m2", tool_use("t4", "Read", file_path="src/b.py"), cache=5000),
    result("t4", "y" * 50),
    assistant("m3", {"type": "text", "text": "Done."}, cache=6000),
    {
        "type": "result",
        "num_turns": 5,
        "duration_ms": 120000,
        "total_cost_usd": 1.5,
        "modelUsage": {"claude-opus-5-5": {"costUSD": 1.4, "outputTokens": 900}},
        "subagent_stats": {"by_type": {"Explore": 1}},
        "permission_denials": [
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf build"}}
        ],
    },
]


def test_counts_main_turns_apart_from_subagent_turns() -> None:
    trace = trace_mod.parse(MESSAGES)
    assert [t.index for t in trace.agent_turns("main")] == [1, 2, 3]
    assert len(trace.agent_turns("t3")) == 2
    first = trace.agent_turns("main")[0]
    assert [c.tool for c in first.calls] == ["Bash", "Read", "Agent"]
    assert trace.calls["t1"].result_chars == 500


def test_summary_names_batching_subagents_and_denials() -> None:
    text = trace_mod.summary(trace_mod.parse(MESSAGES))
    assert "3 turns, 4 tool calls (5 turns counting subagents)" in text
    assert "1 sent two or more calls at once (most in one turn: 3)" in text
    assert "largest context: 6002 tokens" in text
    assert "**Subagents: 1** (Explore 1)" in text
    assert "Explore, sonnet: Find callers. 2 turns (1 Grep)" in text
    assert "Bash `gh pr diff 7`: 500 chars" in text
    assert "Bash `rm -rf build`" in text


def test_no_result_text_in_summary_or_trace(tmp_path: Path) -> None:
    source = tmp_path / "exec.json"
    source.write_text(json.dumps(MESSAGES), encoding="utf-8")
    out = tmp_path / "trace.jsonl"
    assert trace_mod.main([str(source), "--trace", str(out)]) == 0
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert SECRET not in out.read_text()
    assert SECRET not in trace_mod.summary(trace_mod.parse(MESSAGES))
    agent = next(r for r in records if r.get("tool") == "Agent")
    assert agent["input"]["prompt"] == "Who calls f?"
    assert agent["result_chars"] == len("callers: b.py:3, c.py:9")


def test_reads_stream_json_lines_and_tolerates_a_missing_file(tmp_path: Path) -> None:
    source = tmp_path / "exec.jsonl"
    source.write_text("\n".join(json.dumps(m) for m in MESSAGES), encoding="utf-8")
    assert len(trace_mod.load_messages(source)) == len(MESSAGES)
    assert trace_mod.main([str(tmp_path / "absent.json")]) == 0


def test_long_inputs_are_capped() -> None:
    call = trace_mod.Call(1, "main", 1, "Bash", {"command": "z" * 1000})
    capped = trace_mod._capped_input(call)["command"]
    assert len(capped) < 1000 and capped.endswith("[+600]")
