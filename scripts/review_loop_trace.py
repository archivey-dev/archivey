"""Summarize what a review round's Claude session did, from the action's execution file.

The review step runs with `show_full_output` off, so its log shows only the start and
the closing totals. `claude-code-action` still writes every SDK message to
`$RUNNER_TEMP/claude-execution-output.json`. This script reads that file and writes:

- a Markdown summary (to stdout; the workflow appends it to the job summary): turns,
  tool calls per turn, subagents and what they did, the largest tool results the main
  agent took in, and any permission denials;
- with `--trace`, a JSON Lines file with one record per assistant turn and per tool
  call, uploaded as a short-lived artifact for later analysis.

Neither output carries a tool's result text, only its size. A result is where a secret
would show up (an `env`, a token in an error), and the job log is public while an
artifact is not masked, so only what the model itself wrote is kept: its text and each
tool call's input, every string capped. The model can still repeat what a result
showed, so every kept string also has known token shapes (`TOKEN_SHAPES`) replaced.

Usage: review_loop_trace.py EXECUTION_FILE [--trace OUT.jsonl]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# Caps on what the model wrote, so one long prompt cannot swamp the summary or trace.
TEXT_CAP = 600
INPUT_CAP = 400
PROMPT_CAP = 4000
TOP_RESULTS = 8
SUBAGENT_TOOLS = ("Agent", "Task")


# Token shapes the model could repeat from a result it read: Anthropic keys and OAuth
# tokens, GitHub tokens of every prefix, and fine-grained GitHub PATs.
TOKEN_SHAPES = re.compile(
    r"sk-ant-[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+"
)


def _redact(text: str) -> str:
    return TOKEN_SHAPES.sub("[redacted]", text)


def _cap(text: str, limit: int) -> str:
    text = _redact(text)
    return text if len(text) <= limit else text[:limit] + f"… [+{len(text) - limit}]"


def _code(text: object, limit: int) -> str:
    """`text` as one inline code span, so nothing a tool input holds renders as
    Markdown in the public job summary: backticks inside become `'`, newlines spaces."""
    flat = " ".join(str(text).replace("`", "'").split())
    return f"`{_cap(flat, limit)}`" if flat else "`-`"


def _result_chars(content: object) -> int:
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        return sum(
            len(part.get("text", "")) for part in content if isinstance(part, dict)
        )
    return 0


def _target(name: str, args: object) -> str:
    """The one argument that says what a call was about, for a one-line listing."""
    if not isinstance(args, dict):
        return " ".join(str(args).split()) if args else name
    for key in ("file_path", "pattern", "command", "url", "description", "path"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return " ".join(value.split())
    return name


@dataclass
class Call:
    seq: int
    agent: str  # "main", or the id of the Agent call that started the subagent
    turn: int
    tool: str
    input: object  # a dict from the SDK; anything else is kept, capped
    result_chars: int = 0
    is_error: bool = False


@dataclass
class Turn:
    agent: str
    index: int
    model: str
    text: str = ""
    calls: list[Call] = field(default_factory=list)
    usage: dict = field(default_factory=dict)


@dataclass
class Trace:
    turns: list[Turn]
    calls: dict[str, Call]  # by tool_use id
    result: dict

    def agent_turns(self, agent: str) -> list[Turn]:
        return [t for t in self.turns if t.agent == agent]


def load_messages(path: Path) -> list[dict]:
    """The action writes a JSON array; a stream-json transcript is one per line."""
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()]
    return data if isinstance(data, list) else [data]


def parse(messages: list[dict]) -> Trace:
    turns: list[Turn] = []
    by_message: dict[tuple[str, str], Turn] = {}
    calls: dict[str, Call] = {}
    result: dict = {}
    seq = 0
    for event in messages:
        kind = event.get("type")
        if kind == "result":
            result = event
            continue
        message = event.get("message") or {}
        content = message.get("content")
        agent = event.get("parent_tool_use_id") or "main"
        if kind == "assistant":
            # The SDK sends one event per content block; blocks of one API response
            # share its message id, and together they are one turn.
            turn_key = (agent, message.get("id") or f"anon-{len(turns)}")
            turn = by_message.get(turn_key)
            if turn is None:
                index = sum(1 for t in turns if t.agent == agent) + 1
                turn = Turn(agent, index, message.get("model", "?"))
                by_message[turn_key] = turn
                turns.append(turn)
            # Each block's event repeats the response's usage; output counts in these
            # are partial, so the trace keeps only the input side.
            for field_name, value in (message.get("usage") or {}).items():
                if isinstance(value, int):
                    turn.usage[field_name] = max(turn.usage.get(field_name, 0), value)
            for part in content if isinstance(content, list) else []:
                if part.get("type") == "text":
                    turn.text += part.get("text", "")
                elif part.get("type") == "tool_use":
                    seq += 1
                    call = Call(
                        seq,
                        agent,
                        turn.index,
                        part.get("name", "?"),
                        part.get("input", {}),
                    )
                    turn.calls.append(call)
                    calls[part.get("id", f"anon-{seq}")] = call
        elif kind == "user" and isinstance(content, list):
            for part in content:
                if part.get("type") != "tool_result":
                    continue
                call = calls.get(part.get("tool_use_id", ""))
                if call is not None:
                    call.result_chars = _result_chars(part.get("content"))
                    call.is_error = bool(part.get("is_error"))
    return Trace(turns, calls, result)


def _cap_strings(value: object, limit: int) -> object:
    """Every string in `value`, at any depth, cut to `limit`."""
    if isinstance(value, str):
        return _cap(value, limit)
    if isinstance(value, dict):
        return {
            _cap(str(key), limit): _cap_strings(item, limit)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [_cap_strings(item, limit) for item in value]
    return value


def _capped_input(call: Call) -> object:
    limit = PROMPT_CAP if call.tool in SUBAGENT_TOOLS else INPUT_CAP
    return _cap_strings(call.input, limit)


def trace_records(trace: Trace) -> list[dict]:
    records: list[dict] = []
    for turn in trace.turns:
        usage = turn.usage
        records.append(
            {
                "kind": "turn",
                "agent": turn.agent,
                "turn": turn.index,
                "model": turn.model,
                "tool_calls": len(turn.calls),
                "text": _cap(turn.text.strip(), TEXT_CAP),
                "input_tokens": usage.get("input_tokens", 0),
                "cache_read": usage.get("cache_read_input_tokens", 0),
                "cache_write": usage.get("cache_creation_input_tokens", 0),
            }
        )
        for call in turn.calls:
            records.append(
                {
                    "kind": "call",
                    "seq": call.seq,
                    "agent": call.agent,
                    "turn": call.turn,
                    "tool": call.tool,
                    "input": _capped_input(call),
                    "result_chars": call.result_chars,
                    "is_error": call.is_error,
                }
            )
    return records


def summary(trace: Trace) -> str:
    result = trace.result
    main = trace.agent_turns("main")
    main_calls = [c for t in main for c in t.calls]
    lines = ["### Review session trace", ""]
    seconds = (result.get("duration_ms") or 0) / 1000
    # The result's `num_turns` counts subagents' turns too; the main agent's own are
    # the responses parsed here.
    lines.append(
        f"- Main agent: {len(main)} turns, {len(main_calls)} tool calls "
        f"({result.get('num_turns', '?')} turns counting subagents), "
        f"{seconds / 60:.1f} min, ${result.get('total_cost_usd', 0):.2f} in all"
    )
    if main:
        peak = max(
            t.usage.get("cache_read_input_tokens", 0)
            + t.usage.get("cache_creation_input_tokens", 0)
            + t.usage.get("input_tokens", 0)
            for t in main
        )
        lines.append(f"- Main agent's largest context: {peak} tokens")
    acting = [t for t in main if t.calls]
    if acting:
        batched = [t for t in acting if len(t.calls) > 1]
        lines.append(
            f"- Turns that called tools: {len(acting)}; {len(batched)} sent two or more "
            f"calls at once (most in one turn: {max(len(t.calls) for t in acting)})"
        )
    tools = Counter(c.tool for c in main_calls)
    if tools:
        listed = ", ".join(f"{_code(name, 40)} {n}" for name, n in tools.most_common())
        lines.append(f"- Main agent's tool calls: {listed}")
    for model, usage in sorted((result.get("modelUsage") or {}).items()):
        cost = usage.get("costUSD")
        if cost is not None:
            lines.append(
                f"- {_code(model, 60)}: ${cost:.2f}, "
                f"{usage.get('outputTokens', 0)} output tokens"
            )

    spawns = [
        (tool_id, call)
        for tool_id, call in trace.calls.items()
        if call.agent == "main" and call.tool in SUBAGENT_TOOLS
    ]
    stats = result.get("subagent_stats") or {}
    by_type = ", ".join(
        f"{_code(k, 40)} {n}" for k, n in (stats.get("by_type") or {}).items()
    )
    lines += [
        "",
        f"**Subagents: {len(spawns)}**" + (f" ({by_type})" if by_type else ""),
    ]
    for tool_id, call in spawns:
        sub = trace.agent_turns(tool_id)
        sub_calls = Counter(c.tool for t in sub for c in t.calls)
        args = call.input if isinstance(call.input, dict) else {}
        model = args.get("model") or (sub[0].model if sub else "inherited")
        kind = args.get("subagent_type", "general-purpose")
        did = (
            ", ".join(f"{n} {_code(k, 40)}" for k, n in sub_calls.most_common())
            or "no calls seen"
        )
        lines.append(
            f"- main turn {call.turn}: {_code(kind, 40)}, {_code(model, 40)}: "
            f"{_code(_target(call.tool, call.input), 120)}. {len(sub)} turns ({did}); "
            f"returned {call.result_chars} chars"
        )

    biggest = sorted(main_calls, key=lambda c: c.result_chars, reverse=True)[
        :TOP_RESULTS
    ]
    biggest = [c for c in biggest if c.result_chars]
    if biggest:
        lines += ["", "**Largest results the main agent read**"]
        for call in biggest:
            lines.append(
                f"- turn {call.turn}, {_code(call.tool, 40)} "
                f"{_code(_target(call.tool, call.input), 100)}: "
                f"{call.result_chars} chars"
            )

    denials = result.get("permission_denials") or []
    if denials:
        lines += ["", "**Permission denials**"]
        for denial in denials:
            name = str(denial.get("tool_name", "?"))
            args = denial.get("tool_input") or {}
            lines.append(f"- {_code(name, 40)} {_code(_target(name, args), 160)}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("execution_file", type=Path)
    parser.add_argument("--trace", type=Path, help="write a JSON Lines trace here")
    args = parser.parse_args(argv)
    if not args.execution_file.is_file():
        print(
            f"No execution file at {args.execution_file}; nothing to summarize. "
            "The review step may have timed out or been cancelled: the action writes "
            "the file only once its session ends."
        )
        return 0
    trace = parse(load_messages(args.execution_file))
    sys.stdout.write(summary(trace))
    if args.trace:
        with args.trace.open("w", encoding="utf-8") as out:
            for record in trace_records(trace):
                out.write(json.dumps(record) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
