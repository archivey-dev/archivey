"""Checks that a built-in reader written against ``archivey.formats`` imports only
public names, as a format added from outside would."""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterator
from pathlib import Path

import archivey

# The public modules a reader may import from, with the names each makes public.
# ``archivey.types`` and ``archivey.exceptions`` hold names ``archivey`` re-exports, and
# a module inside archivey imports them from there to avoid an import cycle.
_PUBLIC = {
    "archivey": archivey.__all__,
    "archivey.types": archivey.__all__,
    "archivey.exceptions": archivey.__all__,
    "archivey.formats": importlib.import_module("archivey.formats").__all__,
    "archivey.diagnostics": importlib.import_module("archivey.diagnostics").__all__,
}


def _imported_names(path: Path) -> Iterator[tuple[str, str]]:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            yield from ((alias.name, "") for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield from ((node.module, alias.name) for alias in node.names)


def assert_only_public_archivey(
    module_file: str | None, *, own: tuple[str, ...] = ()
) -> None:
    """Every archivey name the module imports is public, apart from the call that
    registers it as a built-in format and the reader's ``own`` helper modules."""
    assert module_file is not None
    for module, name in _imported_names(Path(module_file)):
        if module.split(".")[0] != "archivey" or f"{module}.{name}" in own:
            continue
        if module == "archivey.internal.format_adapter":
            assert name == "register_builtin_format", name
            continue
        assert module in _PUBLIC, module
        assert name in _PUBLIC[module], (module, name)
