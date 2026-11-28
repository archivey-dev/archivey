"""Checks that a built-in reader written against ``archivey.formats`` imports only
public names and reads no private attribute of an archivey object, as a format added
from outside would. ``tests/test_plugin_modules_use_public_api.py`` lists the modules
it holds to that."""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterator
from pathlib import Path
from types import FunctionType


# The public modules a reader may import from, with the names each makes public: the
# root and every module of ``api_surface.PUBLIC_MODULES``, each with its own
# ``__all__``. A module inside archivey imports a root name from its defining
# submodule, to avoid an import cycle.
def _public_all() -> dict[str, list[str]]:
    public: dict[str, list[str]] = {}
    for module_name in _public_modules():
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue  # an optional dependency is missing (``archivey.fsspec``)
        public[module_name] = list(module.__all__)
    return public


def _imported_names(path: Path) -> Iterator[tuple[str, str]]:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            yield from ((alias.name, "") for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield from ((node.module, alias.name) for alias in node.names)


def assert_only_public_archivey(module_file: str | None) -> None:
    """Every archivey name the module imports is public. Core registers the module's
    handler from its table (``internal/format_table.py``), and the module carries its
    own ``override`` shim, as a format from outside would."""
    assert module_file is not None
    public = _public_all()
    for module, name in _imported_names(Path(module_file)):
        if module.split(".")[0] != "archivey":
            continue
        assert module in public, module
        assert name in public[module], (module, name)


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


def _public_modules() -> tuple[str, ...]:
    """``PUBLIC_MODULES`` from ``scripts/checks/api_surface.py``: the root and every
    public submodule, the modules whose ``__all__`` carries the compatibility promise."""
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "checks" / "api_surface.py"
    )
    tree = ast.parse(script.read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "PUBLIC_MODULES"
        ):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError("scripts/checks/api_surface.py defines no PUBLIC_MODULES")


def public_objects() -> dict[str, object]:
    """Every public name, one entry per object, keyed ``module.name``.

    A name is public when the root's or a public submodule's ``__all__`` lists it
    (the root docstring's two tiers). An object listed by several modules (a root
    name its submodule lists too) is keyed by the first module, root first, so a guard
    that sweeps this checks each object once. A module whose optional dependency is
    missing (``archivey.fsspec``) is skipped.
    """
    return {spellings[0]: obj for obj, spellings in _by_object()}


def public_spellings() -> list[list[str]]:
    """Every ``module.name`` spelling of each public object, root first."""
    return [spellings for _, spellings in _by_object()]


def _by_object() -> list[tuple[object, list[str]]]:
    # A class or function is the same object under each spelling. Any other value (a
    # constant, an alias) is matched by its bare name, since two unrelated constants
    # can be equal and share an ``id``.
    groups: dict[object, tuple[object, list[str]]] = {}
    for module_name in _public_modules():
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        for name in getattr(module, "__all__", ()):
            obj = getattr(module, name)
            key = id(obj) if isinstance(obj, (type, FunctionType)) else name
            groups.setdefault(key, (obj, []))[1].append(f"{module_name}.{name}")
    return list(groups.values())
