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
    for name in ("PR", "REPOSITORY", "ROUND", "MAX_ROUNDS", "PASS"):
        assert "{" + name + "}" not in text
    assert "archivey-dev/archivey" in text
    assert "Opus" not in text
    # The editors' header stays out of the reviewer's prompt.
    assert not text.startswith("<!--")


def test_the_opus_round_as_the_first_is_an_ordinary_first_look() -> None:
    text, rnd, _ = prompt.render(ENV | {"ROUND": "1", "PASS": "opus"})
    assert rnd == 1
    assert "Opus" not in text


def test_an_opus_round_after_other_rounds_reads_past_them() -> None:
    text, rnd, _ = prompt.render(ENV | {"PASS": "opus"})
    assert rnd == 2
    assert "one review by Opus" in text
    assert "Number your findings on from the" in text


def test_the_last_round_is_final() -> None:
    _, rnd, final = prompt.render(ENV | {"ROUND": "5"})
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
