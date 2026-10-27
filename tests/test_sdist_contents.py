"""The sdist allowlist in pyproject.toml and the names publish.yml expects stay in step.

publish.yml checks the built sdists only on a release tag, so a change to one list
without the other would otherwise first fail after the tag is pushed.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"

# What hatch adds to every sdist on its own: generated metadata, the project file, and
# the repo-root .gitignore.
BACKEND_ADDED = {"PKG-INFO", "pyproject.toml", ".gitignore"}


def _expected(sdist_glob: str) -> set[str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        rf"^\s*check {re.escape(sdist_glob)} \"([^\"]*)\"$", text, re.MULTILINE
    )
    assert match is not None, f"publish.yml has no `check {sdist_glob} ...` line"
    return set(match.group(1).split())


def test_archivey_sdist_expectation_matches_only_include() -> None:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        sdist = tomllib.load(fh)["tool"]["hatch"]["build"]["targets"]["sdist"]
    listed = {name.rstrip("/") for name in sdist["only-include"]}
    assert _expected("dist/archivey/archivey-*.tar.gz") == listed | BACKEND_ADDED


def test_cli_sdist_expectation_matches_its_folder() -> None:
    folder = REPO_ROOT / "packages" / "archivey-cli"
    files = {p.name for p in folder.iterdir() if not p.name.startswith(".")}
    files -= {"dist", "build"}
    assert _expected("dist/archivey-cli/archivey_cli-*.tar.gz") == files | BACKEND_ADDED
