"""The investigation's corpus report distinguishes parity from incomplete workers."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts/investigations/snappy_compress_utils/corpus.py"
)


@pytest.mark.parametrize(
    ("candidate", "returncode", "outcome", "differs"),
    [
        ({"accepted": True, "sha256": "expected"}, 0, "match", False),
        ({"accepted": True, "sha256": "changed"}, 0, "differs", True),
        ({"accepted": False, "error": "ValueError"}, 0, "differs", True),
        (None, 0, "timeout", False),
        (None, -9, "worker_exit", False),
    ],
)
def test_worker_outcome_controls_parity_and_repros(
    tmp_path, monkeypatch, candidate, returncode, outcome, differs
):
    fixtures = tmp_path / "source/tests/fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sample.txt").write_bytes(b"payload")
    output = tmp_path / "result"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--py-snappy-repo",
            str(tmp_path / "source"),
            "--output",
            str(output),
        ],
    )
    monkeypatch.setitem(
        sys.modules,
        "common",
        SimpleNamespace(SNAPPY_PACKAGES=("fake",), decode=None, reference=None),
    )
    monkeypatch.setitem(
        sys.modules,
        "differential",
        SimpleNamespace(observe=lambda call: {"accepted": True, "sha256": "expected"}),
    )
    monkeypatch.setitem(
        sys.modules, "pysnappy", SimpleNamespace(compress=lambda data: data)
    )
    monkeypatch.setitem(
        sys.modules,
        "resource",
        SimpleNamespace(setrlimit=lambda *args: None, RLIMIT_AS=0, RLIMIT_CPU=1),
    )

    def run(command, **kwargs):
        if candidate is None and returncode == 0:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, returncode, json.dumps(candidate))

    monkeypatch.setattr(subprocess, "run", run)
    runpy.run_path(str(SCRIPT), run_name="__main__")
    [row] = json.loads((output / "corpus.json").read_text())
    assert row["differs"] is differs
    assert row["outcome"] == outcome
    assert (output / "fake-sample.txt.bin").exists() is differs
