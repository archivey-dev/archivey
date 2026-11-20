"""``packages/archivey-cli`` stays in lockstep with the root package.

The companion distribution exists so ``uvx archivey-cli`` runs the CLI with
``[recommended]`` installed: Python packaging has no default extras, so ``uvx archivey``
gets the core only. It is published from the same tag as ``archivey``, so its version must
equal the root version, and its dependency must pin that same version. Otherwise a release
uploads an ``archivey-cli`` that installs an older or newer library than the tag.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPANION_DIR = REPO_ROOT / "packages" / "archivey-cli"


def _project(path: Path) -> dict[str, Any]:
    with open(path, "rb") as fh:
        return tomllib.load(fh)["project"]


ROOT = _project(REPO_ROOT / "pyproject.toml")
COMPANION = _project(COMPANION_DIR / "pyproject.toml")


def test_companion_version_matches_root() -> None:
    assert COMPANION["version"] == ROOT["version"]


def test_companion_pins_recommended_at_the_same_version() -> None:
    # fsspec and aiohttp make HTTP(S) URL arguments work out of the box; the library
    # declares neither (docs/remote.md), so only the CLI package brings them.
    assert COMPANION["dependencies"][:3] == [
        f"archivey[recommended]=={ROOT['version']}",
        "fsspec>=2024.0.0",
        "aiohttp>=3.9.0",
    ]
    assert "recommended" in ROOT["optional-dependencies"]


def test_companion_adds_the_other_extras_where_they_have_wheels() -> None:
    """bzip3 and rapidgzip come with the same floors as the root's [bzip3] and
    [seekable], each behind a marker that keeps it to platforms with wheels."""
    extras = ROOT["optional-dependencies"]
    added = {
        req.split(";")[0].strip(): req.split(";")[1]
        for req in COMPANION["dependencies"][3:]
    }
    assert set(added) == {*extras["bzip3"], *extras["seekable"]}
    for marker in added.values():
        assert "platform_python_implementation == 'CPython'" in marker


def test_companion_scripts_run_the_root_cli() -> None:
    target = ROOT["scripts"]["archivey"]
    assert COMPANION["scripts"] == {"archivey": target, "archivey-cli": target}


def test_companion_python_floor_matches_root() -> None:
    assert COMPANION["requires-python"] == ROOT["requires-python"]


def test_companion_holds_no_code() -> None:
    assert not list(COMPANION_DIR.rglob("*.py"))
    with open(COMPANION_DIR / "pyproject.toml", "rb") as fh:
        wheel = tomllib.load(fh)["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel == {"bypass-selection": True}


def test_companion_ships_the_root_licence() -> None:
    root = (REPO_ROOT / "LICENSE").read_bytes()
    assert (COMPANION_DIR / "LICENSE").read_bytes() == root


def test_publish_workflow_builds_and_uploads_the_companion() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    assert "uv build packages/archivey-cli --out-dir dist/archivey-cli" in workflow
    assert workflow.count("packages-dir: dist/archivey-cli/") == 2
