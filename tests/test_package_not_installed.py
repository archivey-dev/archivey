"""``PackageNotInstalledError.missing``: the components a raise is about, as data.

Every raise names what is missing in ``missing``, the same ``MissingComponent`` that
``format_availability`` reports, so a caller can act on it without parsing the message.
The one raise that leaves it empty is a program that was found but could not start.
"""

from __future__ import annotations

import ast
import pickle

import pytest

from archivey import ArchiveFormat, OptionalLibrary, PackageNotInstalledError
from archivey.internal.registry import format_availability, get_registry
from archivey.types import MissingComponent
from tests.source_trees import ROOT, SOURCE_TREES, source_files

# ``spawn_for_stdout``'s refusal for a program that was found but could not start:
# nothing is missing to name.
_EMPTY_ON_PURPOSE = {("src/archivey/internal/external/cli.py", "not_started")}


def test_every_raise_passes_missing() -> None:
    """A new raise site without ``missing=`` would give callers an empty tuple."""
    offenders = []
    sites = 0
    for rel, path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "PackageNotInstalledError"
            ):
                continue
            sites += 1
            if any(k.arg == "missing" for k in node.keywords):
                continue
            first = ast.unparse(node.args[0]) if node.args else ""
            if (rel, first) in _EMPTY_ON_PURPOSE:
                continue
            offenders.append(f"{rel}:{node.lineno}")
    assert sites > 10, "the scan found almost no raise sites, so it guards nothing"
    assert not offenders, "PackageNotInstalledError without missing=: " + ", ".join(
        offenders
    )


def test_the_scans_cover_every_package_with_code() -> None:
    """A layout change that moved a plugin's code out of ``packages/*/src`` would drop
    it from every source scan silently: the site-count floors pass on archivey alone."""
    with_code = {
        path.parent.relative_to(ROOT).parts[1]
        for path in ROOT.glob("packages/*/**/*.py")
        if "tests" not in path.relative_to(ROOT).parts
    }
    scanned = {tree.parent.name for tree in SOURCE_TREES[1:]}
    # No package in packages/ holds code today (the format readers are built in); the
    # check still catches one added later outside packages/*/src.
    assert with_code == scanned


def test_missing_survives_pickling() -> None:
    component = MissingComponent(OptionalLibrary.PYPPMD, "pip install archivey")
    exc = PackageNotInstalledError("no pyppmd", missing=(component,))
    copy = pickle.loads(pickle.dumps(exc))
    assert copy.missing == (component,)
    assert str(copy) == str(exc)


def test_a_format_refused_for_a_missing_package_names_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "archivey.internal.registry._optional", lambda name: None, raising=True
    )
    with pytest.raises(PackageNotInstalledError) as exc_info:
        get_registry().reader_for_format(ArchiveFormat.ISO)
    availability = format_availability(ArchiveFormat.ISO)
    assert exc_info.value.missing == availability.missing
    (component,) = exc_info.value.missing
    assert component.name is OptionalLibrary.PYCDLIB
