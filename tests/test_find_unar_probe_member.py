"""`scripts/investigations/find_unar_probe_member.py`: its patched-``unar`` model, on fixtures.

The model says which members Debian's patched ``unar`` drops without running ``unar``.
These tests hold it to what that ``unar`` does with the ``unar_drop*`` and
``unar_stale*`` fixtures (``dev-docs/known-issues.md``), so the search that picked the
probe member keeps answering for the right reason.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from archivey.internal.external import unar

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "investigations" / "find_unar_probe_member.py"
_RAR = ROOT / "tests" / "fixtures" / "rar"

_spec = importlib.util.spec_from_file_location("find_unar_probe_member", SCRIPT)
assert _spec is not None and _spec.loader is not None
finder = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package; `@dataclass` looks its module up by name while executing.
sys.modules["find_unar_probe_member"] = finder
_spec.loader.exec_module(finder)


def _first_dropped(fixture: str) -> int | None:
    """The index of the first member the model says is dropped, in archive order."""
    state = finder.SolidState()
    for index, entry in enumerate(finder.members_data((_RAR / fixture).read_bytes())):
        assert entry.method != 0
        if finder.patched_unar_runs_short(entry.packed, entry.size, state):
            return index
    return None


@pytest.mark.parametrize(
    ("fixture", "dropped"),
    [
        ("unar_drop__.rar", 0),
        ("unar_drop_solid__.rar", 1),
        # ``a.txt`` and ``b.txt`` decode; ``c.txt`` is the first member dropped.
        ("unar_stale_solid__.rar", 2),
    ],
)
def test_the_model_drops_what_the_patched_unar_drops(
    fixture: str, dropped: int
) -> None:
    assert _first_dropped(fixture) == dropped


def test_the_probe_member_is_the_one_embedded() -> None:
    [entry] = finder.members_data(unar._RAR5_PROBE_ARCHIVE)
    assert entry.method != 0
    assert entry.size == len(unar._RAR5_PROBE_MEMBER)
    assert finder.patched_unar_runs_short(entry.packed, entry.size)


def test_a_validation_that_compares_nothing_fails() -> None:
    """No case reaches ``unar``, so the run has shown no agreement: it must not pass."""
    assert finder.validate("/nonexistent/rar", "/nonexistent/unar", 0) != 0
