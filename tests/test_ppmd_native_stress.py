"""Subprocess stress for PPMd native flakes (non-required CI / local investigation).

These tests deliberately re-run scenarios from ``scripts/ppmd_native_stress.py`` so they
have a pytest entry point. They are **excluded from the default suite** via the
``ppmd_native_stress`` marker (selected only by the non-blocking stress workflow).

See ``dev-docs/known-issues.md``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import requires

pytestmark = [
    pytest.mark.ppmd_native_stress,
    requires("pyppmd"),
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "scripts" / "ppmd_native_stress.py"


def _iters() -> int:
    return int(os.environ.get("ARCHIVEY_PPMD_STRESS_ITERS", "20"))


def _run_scenarios(*scenarios: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            str(_iters()),
            "--scenarios",
            *scenarios,
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


@requires("py7zr")
def test_warmup_codecs_subprocess_stress() -> None:
    """Linux repro: other 7z codecs then PPMd in one child (~1/3 native abort).

    Also a useful Windows axis. Expect this to fail red when the flake reproduces —
    that is the point of the non-blocking stress job.
    """
    proc = _run_scenarios("warmup_codecs")
    assert proc.returncode == 0, (
        "PPMd warmup_codecs stress saw crashes/failures "
        f"(rc={proc.returncode}).\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
    )


def test_raw_ppmd_minimal_surface_subprocess_stress() -> None:
    """Fresh-process raw ``pyppmd`` / archivey streams — no 7z container."""
    proc = _run_scenarios(
        "raw_pyppmd7",
        "raw_pyppmd8",
        "raw_archivey_ppmd7",
        "raw_archivey_ppmd8",
    )
    assert proc.returncode == 0, (
        "raw PPMd minimal-surface stress saw crashes/failures "
        f"(rc={proc.returncode}).\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
    )


@requires("py7zr")
def test_fresh_baseline_7z_subprocess_stress() -> None:
    """Original CI fixture shape in isolated children."""
    proc = _run_scenarios("fresh_baseline")
    assert proc.returncode == 0, (
        "fresh_baseline 7z PPMd stress saw crashes/failures "
        f"(rc={proc.returncode}).\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
    )
