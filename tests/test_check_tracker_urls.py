"""``scripts/check_tracker_urls.py`` finds a tracker URL and passes on this tree."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_tracker_urls.py"
_spec = importlib.util.spec_from_file_location("check_tracker_urls", SCRIPT)
assert _spec is not None and _spec.loader is not None
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


# The host is spliced in, so this file does not trip the check it tests.
_HOST = b"linear" + b".app"


@pytest.mark.parametrize(
    "line",
    [
        b"see https://" + _HOST + b"/someteam/issue/ABC-12/title",
        b"(<https://" + _HOST + b"/someteam/review/a-pr-1234>)",
        _HOST + b"/someteam",
        b"Linear" + b".app/someteam/issue/ABC-12 has the detail",
    ],
)
def test_a_url_into_a_workspace_is_found(line: bytes) -> None:
    assert check.TRACKER_URL.search(line)


@pytest.mark.parametrize(
    "line",
    [
        b"an issue URL looks like (`" + _HOST + b"/\xe2\x80\xa6/issue/ABC-123`)",
        b"tracked internally (ABC-12)",
        _HOST,
    ],
)
def test_a_shape_or_a_bare_key_is_not(line: bytes) -> None:
    assert not check.TRACKER_URL.search(line)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_a_tracked_url_fails_the_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The failing path: a tracked file with a URL returns 1 and names file:line; the
    same tree passes once the file leaves the index."""
    _git(tmp_path, "init", "-q")
    (tmp_path / "ok.md").write_bytes(b"tracked internally\n")
    (tmp_path / "a.md").write_bytes(
        b"x\nsee https://" + _HOST + b"/someteam/issue/A-1\n"
    )
    (tmp_path / "blob.bin").write_bytes(b"\0" + _HOST + b"/someteam")
    _git(tmp_path, "add", "-A")
    monkeypatch.setattr(check, "ROOT", tmp_path)
    assert check.main() == 1
    out = capsys.readouterr().out
    assert "a.md:2: " in out
    assert "blob.bin" not in out and "ok.md" not in out
    _git(tmp_path, "rm", "-q", "--cached", "a.md")
    assert check.main() == 0


def test_this_tree_has_none() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout
