"""The `pull_request: paths:` list of `ppmd-native-stress.yml`.

That workflow is the only place the stress marker, the hard raw-streams soak and the
valgrind gate run on a pull request. A pull request outside its list starts no run and
reports no check, so a renamed file or a new script step shows up as nothing rather than
as a red check. This pins the list against the tree and against the scripts the
workflow's own steps run.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from test_ci_doc_paths import _pull_request_paths

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ppmd-native-stress.yml"


def _entries() -> list[str]:
    entries = _pull_request_paths(WORKFLOW.read_text(encoding="utf-8"))
    assert entries, "ppmd-native-stress.yml has no pull_request paths filter"
    return entries


def test_every_entry_matches_a_file() -> None:
    missing = [e for e in _entries() if not list(ROOT.glob(e))]
    assert not missing, f"paths entries that match no file: {missing}"


def test_every_script_the_steps_run_is_listed() -> None:
    scripts = set(
        re.findall(
            r"python (scripts/[\w./-]+\.py)", WORKFLOW.read_text(encoding="utf-8")
        )
    )
    assert scripts, (
        "no `python scripts/...` step found; the pattern may have missed one"
    )
    entries = _entries()
    unlisted = sorted(
        s for s in scripts if not any(fnmatch.fnmatch(s, e) for e in entries)
    )
    assert not unlisted, f"scripts run by the workflow but not in its paths: {unlisted}"
