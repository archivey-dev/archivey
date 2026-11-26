"""The macOS DMG check retries ``hdiutil create`` only while the disk is busy."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts/investigations/dmg_macos_check.py"
)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dmg_macos_check", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BUSY = "hdiutil: create failed - Resource busy"


def _done(returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["hdiutil"], returncode, "", stderr)


@pytest.fixture
def check(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = _load()
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    return module


def _replay(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    outcomes: list[subprocess.CompletedProcess[str]],
) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def run(
        *args: str, password: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return outcomes[len(calls) - 1]

    monkeypatch.setattr(module, "_run", run)
    return calls


def test_a_busy_create_is_tried_again_until_it_succeeds(
    check: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _replay(monkeypatch, check, [_done(1, BUSY), _done(1, BUSY), _done(0)])
    made = check._create_image("-format", "UDRO", "out.dmg")
    assert made.returncode == 0
    assert len(calls) == 3
    assert all(call[:2] == ("hdiutil", "create") for call in calls)


def test_a_create_still_busy_after_every_attempt_returns_the_last_failure(
    check: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = check.CREATE_ATTEMPTS
    calls = _replay(monkeypatch, check, [_done(1, BUSY)] * attempts)
    made = check._create_image("out.dmg")
    assert made.returncode == 1
    assert "Resource busy" in made.stderr
    assert len(calls) == attempts


def test_a_create_that_fails_for_another_reason_is_not_tried_again(
    check: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _replay(
        monkeypatch, check, [_done(1, "hdiutil: create failed - format not supported")]
    )
    made = check._create_image("-format", "UDCO", "out.dmg")
    assert made.returncode == 1
    assert len(calls) == 1
