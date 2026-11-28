"""The deprecation shim for public names that moved to another module (DR-12a).

A public module whose names moved keeps a table of them, ``{name: new module}``, and a
module ``__getattr__`` (PEP 562) that calls :func:`moved_name`. The old spelling then
still works for one minor release, with a ``DeprecationWarning`` that names the new
import. The same module imports each moved name under ``if TYPE_CHECKING:`` so a type
checker, which does not run ``__getattr__``, types the old spelling as the real object;
``tests/test_root_tiers.py`` checks that the block and the table name the same names.
"""

from __future__ import annotations

import enum
import importlib
import os
import sys
import warnings

#: Frames in these files are archivey's own (or the ``enum`` machinery a conversion
#: runs through), so a deprecation warning skips them to reach the caller.
_INTERNAL_PREFIX = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep
_ENUM_FILE = os.path.abspath(enum.__file__)


def moved_name(module_name: str, table: dict[str, str], name: str) -> object:
    """Return ``name`` from its new module, warning at the caller's line.

    ``stacklevel=3`` skips this function and the module ``__getattr__`` that called
    it, so the warning points at ``module.Name`` or ``from module import Name`` in
    the caller's code. Raises ``AttributeError`` for a name not in ``table``.

    A ``from package import Name`` of a moved name, where the module is a package (the
    root), runs this twice: importlib's ``_handle_fromlist`` asks ``hasattr`` first,
    then the import fetches the name. Both warnings point at the import line, so the
    default filter shows one; an ``always`` filter records two.
    """
    new_module = table.get(name)
    if new_module is None:
        raise AttributeError(f"module {module_name!r} has no attribute {name!r}")
    warnings.warn(
        f"{module_name}.{name} is deprecated; use {new_module}.{name} "
        f"(from {new_module} import {name}). archivey 0.7.0 removes the old spelling.",
        DeprecationWarning,
        stacklevel=3,
    )
    return getattr(importlib.import_module(new_module), name)


def caller_stacklevel() -> int:
    """The ``stacklevel`` that points a warning at the first frame outside archivey.

    For a warning raised deep inside a conversion, where the depth depends on the entry
    point (``DiagnosticCode("old")`` runs through ``enum``, ``DiagnosticPolicy(raise_on=
    {"old"})`` through the policy's coercion). Call it as the ``stacklevel=`` argument
    of ``warnings.warn``, from the function that warns.
    """
    frame = sys._getframe(1)
    level = 1
    while frame.f_back is not None:
        filename = os.path.abspath(frame.f_code.co_filename)
        if not (filename.startswith(_INTERNAL_PREFIX) or filename == _ENUM_FILE):
            break
        frame = frame.f_back
        level += 1
    return level
