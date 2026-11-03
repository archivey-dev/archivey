"""The lint/type toolchain is pinned exactly, and pinned in only one place.

Two properties, both cheap to lose and both invisible until someone else's checkout
disagrees with yours:

1. **Exact pins, not floors.** These tools decide what the gates *report*. A floor lets
   `uv sync --resolution lowest-direct` — the `[all-lowest]` CI leg, and step 2 of
   CONTRIBUTING's three-config rule — resolve a years-old version: `ruff>=0.11.0` gave
   0.11.0, which reported 367 "errors" the current version does not, on an unchanged
   tree. `ruff format` output also changes between versions, so a floor lets one
   contributor reformat the whole repo just by having a newer one.

2. **One source of truth for ruff.** `.pre-commit-config.yaml` resolves its own copy
   through the framework hook path, while `scripts/install-git-hooks.sh` runs the
   dev-group copy via `uv run`. Two paths, two versions, silently different formatting.

Deliberately *not* applied to pytest or the optional format libraries: exercising those
across versions is the point of the `[all-lowest]` leg, and their version does not change
whether the tree is considered clean.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"

# Version decides what the gates report → must be exact.
EXACTLY_PINNED = ("ruff", "pyrefly", "ty")


def _dev_requirements() -> dict[str, str]:
    """``package name -> full requirement string`` for the dev dependency group."""
    with open(PYPROJECT, "rb") as fh:
        data = tomllib.load(fh)
    out: dict[str, str] = {}
    for req in data["dependency-groups"]["dev"]:
        name = re.split(r"[<>=!;\[ ]", req, maxsplit=1)[0].strip()
        out[name] = req
    return out


@pytest.mark.parametrize("package", EXACTLY_PINNED)
def test_lint_and_type_tools_are_pinned_exactly(package: str) -> None:
    requirement = _dev_requirements().get(package)
    assert requirement is not None, f"{package} is not in the dev dependency group"
    assert "==" in requirement, (
        f"{package} must be pinned exactly (found {requirement!r}). A floor lets "
        f"--resolution lowest-direct install a version that reports different results "
        f"on an unchanged tree; see this module's docstring."
    )


def test_pre_commit_ruff_matches_the_dev_group() -> None:
    """The framework hook and `uv run ruff` must be the same ruff."""
    pinned = _dev_requirements()["ruff"].split("==", 1)[1].strip()
    text = PRE_COMMIT.read_text(encoding="utf-8")
    match = re.search(r"astral-sh/ruff-pre-commit\s*\n\s*rev:\s*v?([^\s#]+)", text)
    assert match is not None, "could not find the ruff-pre-commit rev"
    assert match.group(1) == pinned, (
        f".pre-commit-config.yaml pins ruff {match.group(1)} but the dev group pins "
        f"{pinned}. They format differently; bump both together."
    )
