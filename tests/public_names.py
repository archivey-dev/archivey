"""Checks that a built-in reader written against ``archivey.formats`` imports only
public names and reads no private attribute of an archivey object, as a format added
from outside would. ``tests/test_plugin_modules_use_public_api.py`` lists the modules
it holds to that."""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterator
from pathlib import Path

import archivey

# The public modules a reader may import from, with the names each makes public.
# ``archivey.types``, ``archivey.exceptions`` and ``archivey.detection`` hold names
# ``archivey`` re-exports, and a module inside archivey imports them from there to
# avoid an import cycle.
_PUBLIC = {
    "archivey": archivey.__all__,
    "archivey.types": archivey.__all__,
    "archivey.exceptions": archivey.__all__,
    "archivey.detection": archivey.__all__,
    "archivey.formats": importlib.import_module("archivey.formats").__all__,
    "archivey.diagnostics": importlib.import_module("archivey.diagnostics").__all__,
    "archivey.terminal": importlib.import_module("archivey.terminal").__all__,
}


def _imported_names(path: Path) -> Iterator[tuple[str, str]]:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            yield from ((alias.name, "") for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield from ((node.module, alias.name) for alias in node.names)


def assert_only_public_archivey(module_file: str | None) -> None:
    """Every archivey name the module imports is public, apart from the call that
    registers it as a built-in format, ``override``, the typing decorator every
    library source carries (a format from outside would take ``typing.override``),
    and the salvage search's three names, which have no plugin hook yet."""
    assert module_file is not None
    for module, name in _imported_names(Path(module_file)):
        if module.split(".")[0] != "archivey":
            continue
        if module == "archivey.internal.format_adapter":
            assert name == "register_builtin_format", name
            continue
        if module == "archivey.internal.overrides":
            assert name == "override", name
            continue
        if module == "archivey.internal.salvage":
            # The salvage search, which plugins get later through a hook of their
            # own (openspec/changes/salvage-mode, design decision 4).
            assert name in ("HeaderSearch", "WalkSalvage", "walk_salvage"), name
            continue
        assert module in _PUBLIC, module
        assert name in _PUBLIC[module], (module, name)


# The public API of ``collections.namedtuple``, spelled with an underscore so that it
# cannot clash with a field name.
_NAMEDTUPLE_API = frozenset(
    {"_asdict", "_field_defaults", "_fields", "_make", "_replace"}
)


def _own_private_names(tree: ast.Module) -> set[str]:
    """The private names a module defines itself: its functions, classes and class or
    module variables, and each attribute it assigns on ``self`` or ``cls``
    (``self._seen = ...``). A store onto another object is not the module's own."""
    own: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            own.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            own.add(node.id)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Name)
            and node.value.id in {"self", "cls"}
        ):
            # Only a store on itself: ``context._nest = 1`` writes core state.
            own.add(node.attr)
    return {name for name in own if name.startswith("_")}


def foreign_private_reads(path: Path) -> list[str]:
    """Each ``x._name`` in ``path`` whose ``_name`` the module does not define itself,
    as ``file:line expression``. Such a name belongs to an archivey object (a
    ``ReaderContext``, a ``ReaderSource``, a base class's state reached through
    ``self``), which a format written outside archivey cannot rely on. Dunder names
    are not private and are skipped, and so are the documented methods of a named
    tuple (``_replace`` and its kin), which only look private.

    The check reads attribute syntax only. ``getattr(x, "_name")`` is invisible to it,
    and so is a read of a core attribute that shares its name with one the module
    defines; both are review matters."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    own = _own_private_names(tree)
    return sorted(
        (
            f"{path.name}:{node.lineno} {ast.unparse(node)}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr.startswith("_")
            and not node.attr.startswith("__")
            and node.attr not in own
            and node.attr not in _NAMEDTUPLE_API
        ),
        key=lambda hit: int(hit.split(" ")[0].rsplit(":", 1)[1]),
    )
