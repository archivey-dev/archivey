"""Guard: every package pinned in a user-facing extra is used by ``src/``.

The packaging contract (``packaging-and-extras``) is that an optional **extra** lists only
libraries some ``src/`` code path actually imports for that capability — never a dead or
test-only dependency. This test enforces it mechanically so a stray pin can't slip back in
(as ``python-xz`` and ``pyzstd`` once had — see ``dev-docs/library-analysis.md``).

It parses ``[project.optional-dependencies]`` from ``pyproject.toml``, expands the bundle
extras (``archivey[...]`` self-references) down to leaf third-party packages, and asserts each
is referenced by some ``src/`` file — with a small, documented allowlist for capabilities whose
implementation is a later phase.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_SRC = _REPO_ROOT / "src"

# PyPI distribution name -> the module name ``src/`` would import, when they differ.
# (Most match; listed here only for the exceptions / for clarity.)
_IMPORT_NAME = {
    "lz4": "lz4",
    "backports-zstd": "backports.zstd",
    "bzip3": "bz3",
}

# Packages pinned ahead of their implementation phase: the extra is part of the documented
# packaging surface, but the feature's ``src/`` code lands later. Keep this list short and
# justified; remove an entry once the feature is implemented and imports its package.
# Empty while every user-facing extra package is already wired in ``src/``.
_PENDING_IMPLEMENTATION: dict[str, str] = {}


def _load_optional_dependencies() -> dict[str, list[str]]:
    with open(_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    return data["project"]["optional-dependencies"]


def _requirement_dist_name(requirement: str) -> str:
    """The bare PyPI name from a requirement string (drop version, markers, extras)."""
    # Strip environment markers and version specifiers; keep the leading name token.
    head = re.split(r"[<>=!~;\[ ]", requirement.strip(), maxsplit=1)[0]
    return head.lower().replace("_", "-")


def _leaf_packages(extras: dict[str, list[str]]) -> set[str]:
    """All third-party leaf packages across every user-facing extra (bundles expanded)."""
    leaves: set[str] = set()
    for requirements in extras.values():
        for req in requirements:
            name = _requirement_dist_name(req)
            if name == "archivey":
                continue  # an ``archivey[...]`` bundle self-reference; its targets are also keys
            leaves.add(name)
    return leaves


def _src_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in _SRC.rglob("*.py"))


def test_every_extra_package_is_used_by_src() -> None:
    extras = _load_optional_dependencies()
    leaves = _leaf_packages(extras)
    src_text = _src_text()

    unused: list[str] = []
    for dist in sorted(leaves):
        if dist in _PENDING_IMPLEMENTATION:
            continue
        module = _IMPORT_NAME.get(dist, dist.replace("-", "_"))
        if not re.search(rf"\b{re.escape(module)}\b", src_text):
            unused.append(dist)

    assert not unused, (
        "These packages are pinned in a user-facing extra but are not imported by any "
        f"src/ code path: {unused}. Either wire the dependency into src/, move it to the "
        "dev dependency group (if it is test-only), or remove it. If it is pinned ahead of "
        "its implementation phase, add it to _PENDING_IMPLEMENTATION with a justification. "
        "See dev-docs/library-analysis.md and the packaging-and-extras spec."
    )


def test_pending_allowlist_entries_are_still_unimplemented() -> None:
    """Tighten the allowlist automatically: once a pending package IS imported, drop it."""
    src_text = _src_text()
    became_used: list[str] = []
    for dist in _PENDING_IMPLEMENTATION:
        module = _IMPORT_NAME.get(dist, dist.replace("-", "_"))
        # A bare-word match in a docstring/comment is fine to ignore; require an import-ish use.
        if re.search(
            rf"(?m)^\s*(import|from)\s+{re.escape(module)}\b", src_text
        ) or re.search(rf'import_module\(\s*["\']{re.escape(module)}', src_text):
            became_used.append(dist)
    assert not became_used, (
        f"{became_used} are now imported by src/; remove them from _PENDING_IMPLEMENTATION "
        "so the guard covers them like every other extra package."
    )


def test_pyzstd_and_python_xz_are_not_in_any_extra() -> None:
    """Regression: the two evaluated-and-dropped libraries must not reappear in an extra."""
    leaves = _leaf_packages(_load_optional_dependencies())
    for dropped in ("pyzstd", "python-xz"):
        assert dropped not in leaves, (
            f"{dropped} was removed from the extras by the compression-library evaluation "
            "(see dev-docs/library-analysis.md); it must not be pinned in a user-facing extra."
        )


def test_atheris_is_fuzz_group_not_runtime_extra() -> None:
    """atheris is CI-only (PEP 735 ``fuzz`` group), never a user-facing extra / ``[all]``."""
    with open(_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    leaves = _leaf_packages(data["project"]["optional-dependencies"])
    assert "atheris" not in leaves
    fuzz = data.get("dependency-groups", {}).get("fuzz", [])
    assert any(_requirement_dist_name(req) == "atheris" for req in fuzz), (
        "atheris must be declared in the PEP 735 fuzz dependency group"
    )


if __name__ == "__main__":  # pragma: no cover - convenience for manual runs
    sys.exit(pytest.main([__file__, "-v"]))
