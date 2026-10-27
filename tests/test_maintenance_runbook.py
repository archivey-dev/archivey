"""`dev-docs/maintenance.md` lists every workflow and every optional package.

The runbook's two tables restate facts the repo holds elsewhere: the files in
`.github/workflows/` and the `[recommended]` and `[seekable]` extras. A new workflow or
package that the tables miss leaves the page silent on the day someone needs it, so the
lists are checked here.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = (ROOT / "dev-docs" / "maintenance.md").read_text(encoding="utf-8")


def test_every_workflow_is_listed() -> None:
    workflows = sorted(p.name for p in (ROOT / ".github" / "workflows").glob("*.yml"))
    missing = [name for name in workflows if f"`{name}`" not in RUNBOOK]
    assert not missing, f"dev-docs/maintenance.md does not list: {missing}"


def test_every_optional_package_is_listed() -> None:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        extras = tomllib.load(fh)["project"]["optional-dependencies"]
    names = {
        re.split(r"[<>=!~;\s\[]", requirement, maxsplit=1)[0]
        for extra in ("recommended", "seekable")
        for requirement in extras[extra]
    }
    missing = sorted(name for name in names if f"`{name}`" not in RUNBOOK)
    assert not missing, f"dev-docs/maintenance.md does not list: {missing}"
