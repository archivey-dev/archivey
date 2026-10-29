"""Tests for `scripts/review_loop_prompt.py`, which writes each review round's prompt."""

from __future__ import annotations

import importlib.util
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
    for name in ("PR", "REPOSITORY", "ROUND", "MAX_ROUNDS", "PASS"):
        assert "{" + name + "}" not in text
    assert "archivey-dev/archivey" in text
    assert "deep pass" not in text
    # The editors' header stays out of the reviewer's prompt.
    assert not text.startswith("<!--")


def test_the_deep_pass_is_the_round_after_the_gate_s() -> None:
    text, rnd, final = prompt.render(ENV | {"PASS": "deep"})
    assert rnd == 3
    assert final is False
    assert "This round is the deep pass." in text


def test_a_deep_pass_at_the_cap_is_the_last_round() -> None:
    _, rnd, final = prompt.render(ENV | {"ROUND": "4", "PASS": "deep"})
    assert (rnd, final) == (5, True)


def test_the_output_is_one_multiline_value_and_two_plain_ones() -> None:
    out = subprocess.run(
        [sys.executable, str(SCRIPT)],
        env=ENV,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    head, _, rest = out.partition("\n")
    assert head.startswith("prompt<<EOF_")
    delimiter = head.removeprefix("prompt<<")
    body, _, tail = rest.partition(f"\n{delimiter}\n")
    assert delimiter not in body
    assert tail == "round=2\nfinal=false\n"
