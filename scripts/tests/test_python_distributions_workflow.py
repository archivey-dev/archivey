"""python-distributions.yml: the suite on Pythons built by someone other than uv.

Its point is the codec libraries those Pythons link, so the tests pin what would quietly
turn it into another copy of ci.yml's legs: uv falling back to its own interpreter, or a
distribution dropping out of the matrix. The release gate and the failure alert are
checked by test_release_script.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "python-distributions.yml"


# ci.yml's [all] legs run these outside the main pytest (dev-docs/known-issues.md).
_SPLIT_OUT = (
    "tests/test_property_safety.py",
    "tests/test_rapidgzip_deflate_zlib.py",
    "tests/test_accelerator_shutdown.py",
    "tests/test_accelerator_corruption.py",
    "tests/test_ppmd_raw_streams.py",
)


def _load() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_it_runs_daily_on_a_dispatch_and_when_it_changes() -> None:
    on = _load()[True]
    assert set(on) == {"schedule", "workflow_dispatch", "pull_request"}
    assert set(on["pull_request"]["paths"]) == {
        ".github/workflows/python-distributions.yml",
        "scripts/ci/print_codec_libraries.py",
    }


def test_uv_never_brings_its_own_python() -> None:
    env = _load()["env"]
    assert env["UV_PYTHON_PREFERENCE"] == "only-system"
    assert env["UV_PYTHON_DOWNLOADS"] == "never"


def test_every_distribution_has_a_leg() -> None:
    jobs = _load()["jobs"]
    rows = jobs["hosted"]["strategy"]["matrix"]["include"]
    sources = {(row["source"], row["os"]) for row in rows}
    assert sources == {
        ("python.org", "macos-latest"),
        ("python.org", "windows-latest"),
        ("conda-forge", "ubuntu-latest"),
    }
    images = {
        row["image"] for row in jobs["container"]["strategy"]["matrix"]["include"]
    }
    assert images == {"fedora:latest", "ubuntu:22.04"}


def test_each_leg_runs_the_suite_on_the_chosen_interpreter() -> None:
    jobs = _load()["jobs"]
    for name in ("hosted", "container"):
        runs = [step.get("run", "") for step in jobs[name]["steps"]]
        assert any("uv sync --python" in run for run in runs), name
        assert any("pytest tests/" in run for run in runs), name
        assert any("print_codec_libraries.py" in run for run in runs), name
        main = next(run for run in runs if "pytest tests/ " in run)
        for module in _SPLIT_OUT:
            assert f"--ignore={module}" in main, (name, module)
        assert any("ci_run_native_modules.py" in run for run in runs), name
        assert any(
            "test_ppmd_raw_streams.py --allow-exit-after-green" in run for run in runs
        ), name
        assert any("pytest tests/test_property_safety.py" in run for run in runs), name
    hosted = "\n".join(step.get("run", "") for step in jobs["hosted"]["steps"])
    assert 'test "$want" = "$got"' in hosted


def test_the_library_printer_runs() -> None:
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ci" / "print_codec_libraries.py")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for key in ("python ", "zlib ", "liblzma", "openssl"):
        assert key in out
