"""The macOS DMG check tries an ``hdiutil`` call again only while it says the disk is
busy."""

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

BUSY = "hdiutil: create failed - Resource busy"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dmg_macos_check", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _done(returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["hdiutil"], returncode, "", stderr)


class _Fake:
    """``_run_once`` replayed from ``outcomes``; records each call and each sleep."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        outcomes: list[subprocess.CompletedProcess[str]],
    ) -> None:
        self.module = _load()
        self.outcomes = outcomes
        self.calls: list[tuple[str, ...]] = []
        self.sleeps: list[float] = []
        monkeypatch.setattr(self.module, "_run_once", self._run_once)
        monkeypatch.setattr(self.module.time, "sleep", self.sleeps.append)

    def _run_once(
        self, *args: str, password: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        return self.outcomes[len(self.calls) - 1]


@pytest.mark.parametrize("verb", ["create", "attach", "detach", "verify"])
def test_a_busy_hdiutil_call_is_tried_again_until_it_succeeds(
    monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    fake = _Fake(monkeypatch, [_done(1, BUSY), _done(1, BUSY), _done(0)])
    done = fake.module._run("hdiutil", verb, "image.dmg")
    assert done.returncode == 0
    assert fake.calls == [("hdiutil", verb, "image.dmg")] * 3
    assert fake.sleeps == [5, 10]


def test_a_call_still_busy_after_every_attempt_returns_the_last_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = _load().HDIUTIL_ATTEMPTS
    fake = _Fake(monkeypatch, [_done(1, BUSY)] * attempts)
    done = fake.module._run("hdiutil", "create", "image.dmg")
    assert done.returncode == 1
    assert "Resource busy" in done.stderr
    assert len(fake.calls) == attempts
    # No wait after the last try.
    assert fake.sleeps == [5, 10, 15]


def test_a_call_that_fails_for_another_reason_is_not_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake(
        monkeypatch, [_done(1, "hdiutil: create failed - format not supported")]
    )
    done = fake.module._run("hdiutil", "create", "-format", "UDCO", "image.dmg")
    assert done.returncode == 1
    assert len(fake.calls) == 1
    assert fake.sleeps == []


def test_a_busy_answer_from_another_program_is_not_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake(monkeypatch, [_done(8, "fsck_hfs: Resource busy")])
    done = fake.module._run("fsck_hfs", "-n", "/dev/disk4s1")
    assert done.returncode == 8
    assert len(fake.calls) == 1
    assert fake.sleeps == []
