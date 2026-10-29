"""Tests for `scripts/review_loop_prompt.py`, which writes each review round's prompt."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_loop_prompt.py"

_spec = importlib.util.spec_from_file_location("review_loop_prompt", SCRIPT)
assert _spec is not None and _spec.loader is not None
prompt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prompt)

ENV = {
    "PR": "7",
    "GITHUB_REPOSITORY": "archivey-dev/archivey",
    "ROUND": "2",
    "MAX_ROUNDS": "5",
    "PASS": "",
}


def test_an_ordinary_round_fills_every_placeholder() -> None:
    text, rnd, final = prompt.render(ENV)
    assert (rnd, final) == (2, False)
    for name in ("PR", "REPOSITORY", "ROUND", "MAX_ROUNDS", "PASS", "CONDITIONAL"):
        assert "{" + name + "}" not in text
    assert "archivey-dev/archivey" in text
    assert "Opus pass" not in text
    # The editors' header stays out of the reviewer's prompt.
    assert not text.startswith("<!--")


def test_the_opus_pass_after_an_approval_is_the_round_after_the_gate_s() -> None:
    text, rnd, final = prompt.render(ENV | {"PASS": "opus-after", "TIER": "standard"})
    assert rnd == 3
    assert final is False
    assert "This round is the Opus pass." in text
    assert "Cursor" not in text


def test_the_opus_pass_after_the_fixes_is_the_gate_s_own_round() -> None:
    text, rnd, _ = prompt.render(ENV | {"PASS": "opus", "TIER": "standard"})
    assert rnd == 2
    assert "This round is the Opus pass." in text


def test_on_a_deep_pull_request_the_pass_leaves_cursor_alone() -> None:
    for pass_ in ("opus", "opus-after"):
        text, _, _ = prompt.render(ENV | {"PASS": pass_, "TIER": "deep"})
        assert "leave its comments alone" in text


def test_an_opus_pass_at_the_cap_is_the_last_round() -> None:
    _, rnd, final = prompt.render(ENV | {"ROUND": "4", "PASS": "opus-after"})
    assert (rnd, final) == (5, True)


def test_the_output_is_one_multiline_value_and_two_plain_ones() -> None:
    out = subprocess.run(
        [sys.executable, str(SCRIPT)],
        # The whole environment: Python on Windows does not start without SYSTEMROOT.
        env=os.environ | ENV,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    head, _, rest = out.partition("\n")
    assert head.startswith("prompt<<EOF_")
    delimiter = head.removeprefix("prompt<<")
    body, _, tail = rest.partition(f"\n{delimiter}\n")
    assert delimiter not in body
    assert tail == "round=2\nfinal=false\n"


def test_a_standard_or_deep_round_is_told_what_follows_an_approval() -> None:
    told = "an approval is followed by that pass"
    for tier in ("standard", "deep"):
        text, _, _ = prompt.render(ENV | {"TIER": tier})
        assert told in text
    for tier in ("light", ""):
        text, _, _ = prompt.render(ENV | {"TIER": tier})
        assert told not in text
    # The pass itself is past that rule.
    text, _, _ = prompt.render(ENV | {"TIER": "standard", "PASS": "opus"})
    assert told not in text
    assert "Number your findings on from the highest" in text
