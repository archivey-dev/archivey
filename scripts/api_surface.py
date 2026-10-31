#!/usr/bin/env python3
"""Write, check or compare the public API surface, one line per item.

The surface is what the stability policy (``docs/how-it-is-built.md`` §Versioning and
stability) promises: the list of public submodules, every name ``archivey`` and those
submodules export, with its signature, fields, properties and enum values, and the
``archivey`` command's verbs, options and exit codes. ``dev-docs/api-surface.txt``
holds it, and ``tests/test_api_surface.py`` fails when that file is stale, so a pull
request that changes the API shows the change in its diff.

``release.py notes`` compares the surface at the last tag with this checkout's and
says whether the release can be a patch: see :func:`classify`.

Usage::

    python scripts/api_surface.py --write     # regenerate dev-docs/api-surface.txt
    python scripts/api_surface.py --check     # exit 1 if the file is stale
    python scripts/api_surface.py --src DIR   # print the surface of DIR/archivey
    python scripts/api_surface.py --compare-to OLD   # what changed since OLD's surface
    python scripts/api_surface.py --modules-from FILE  # FILE's list of public modules

Stdlib only.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import importlib
import inspect
import sys
import types
import typing
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SURFACE_FILE = ROOT / "dev-docs" / "api-surface.txt"
#: The API page of the tree being measured; ``--src DIR`` reads ``DIR/../docs/api.md``.
API_PAGE = ROOT / "docs" / "api.md"

HEADER = (
    "# The public API surface, written by scripts/api_surface.py --write.\n"
    "# tests/test_api_surface.py fails when this file is stale. Do not edit it by hand.\n"
)

#: The public submodules. A module with ``__all__`` exports that list; one without
#: exports the names the API page documents under it (``::: archivey.module.Name``).
#: A module or name the measured tree lacks is left out, so measuring an older tree
#: reports it as added.
PUBLIC_MODULES = (
    "archivey",
    "archivey.detection_cost",
    "archivey.diagnostics",
    "archivey.paths",
    "archivey.formats",
    "archivey.terminal",
)

#: The enums a patch release may add values to: the diagnostic codes, and the enums
#: whose docstring tells callers to treat the set as open-ended. The rule is in the
#: stability policy (``docs/how-it-is-built.md`` §Versioning and stability and DR-12a in
#: ``dev-docs/design-rules.md``, which PR #993 adds). Adding an enum here is a promise
#: to callers, so ``tests/test_api_surface.py`` pins the set.
OPEN_ENUMS = frozenset(
    {
        "archivey.CompressionAlgorithm",
        "archivey.DiagnosticCode",
    }
)
#: The experimental names: the format and codec plugin interface, and the names that
#: exist only for it. The stability policy leaves them out (``docs/how-it-is-built.md``
#: §Versioning and stability): any release may change or remove them, with no
#: deprecation release. A line whose own name is one of them (or under one) never makes
#: a release a minor; a stable line that only mentions one in a signature still does,
#: and the maintainer judges it (see :func:`classify`). ``tests/test_api_surface.py``
#: pins the list: adding a name takes away a promise to callers.
EXPERIMENTAL = (
    "archivey.formats",
    "archivey.PluginContainer",
    "archivey.PluginStream",
    "archivey.FormatPolicy.replace",
    "archivey.FormatInfo.from_plugin",
)
#: The literal type that lists every diagnostic code string, which grows with them.
CODE_LITERALS = frozenset({"archivey.diagnostics.DiagnosticCodeStr"})

_SKIP_NAMES = frozenset({"__version__"})
#: Classes whose constructor only archivey calls: a plugin receives these objects,
#: so their ``__init__`` is internal even though the class is public.
_SKIP_INIT = frozenset(
    {"archivey.formats.ReaderContext", "archivey.formats.ReaderSource"}
)


# ── Formatting ───────────────────────────────────────────────────────────────────────


def _fmt_type(tp: object) -> str:
    """A type or annotation as text that does not depend on the Python version.

    It handles the shapes the public annotations use, and raises on any other, so a
    new shape fails here rather than writing one interpreter's ``repr`` into the file.
    """
    if isinstance(tp, str):
        return tp
    if tp is None or tp is type(None):
        return "None"
    if tp is Ellipsis:
        return "..."
    if isinstance(tp, typing.ForwardRef):
        return tp.__forward_arg__
    if isinstance(tp, typing.TypeVar):
        return tp.__name__
    origin = typing.get_origin(tp)
    if origin is typing.Union or isinstance(tp, types.UnionType):
        return " | ".join(_fmt_type(arg) for arg in typing.get_args(tp))
    if origin is typing.Literal:
        return "Literal[" + ", ".join(repr(arg) for arg in typing.get_args(tp)) + "]"
    if origin is not None:
        args = typing.get_args(tp)
        name = getattr(origin, "__qualname__", repr(origin))
        if args and isinstance(args[0], list):
            params = "[" + ", ".join(_fmt_type(a) for a in args[0]) + "]"
            return f"{name}[{params}, {_fmt_type(args[1])}]"
        return f"{name}[{', '.join(_fmt_type(a) for a in args)}]"
    if isinstance(tp, type):
        return tp.__qualname__
    raise TypeError(f"api_surface cannot format the annotation {tp!r}; add its shape")


def _fmt_value(value: object) -> str:
    """A default or constant value as stable text."""
    if isinstance(value, enum.Enum):
        return f"{type(value).__qualname__}.{value.name}"
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return repr(value)
    if isinstance(value, (frozenset, set)):
        return "{" + ", ".join(sorted(_fmt_value(v) for v in value)) + "}"
    if isinstance(value, tuple):
        inner = ", ".join(_fmt_value(v) for v in value)
        return f"({inner},)" if len(value) == 1 else f"({inner})"
    if isinstance(value, list):
        return "[" + ", ".join(_fmt_value(v) for v in value) + "]"
    if type(value).__name__ == "_HAS_DEFAULT_FACTORY_CLASS":
        return "<factory>"
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return f"{type(value).__qualname__}(...)"
    if callable(value):
        return getattr(value, "__qualname__", type(value).__qualname__)
    return f"<{type(value).__qualname__}>"


def _fmt_signature(func: object) -> str:
    try:
        sig = inspect.signature(func)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "(...)"
    params = list(sig.parameters.values())
    last_positional_only = max(
        (i for i, p in enumerate(params) if p.kind is p.POSITIONAL_ONLY), default=-1
    )
    parts: list[str] = []
    for i, param in enumerate(params):
        if param.name.startswith("_"):
            continue
        if param.kind is param.KEYWORD_ONLY and not any(
            p.kind in (p.KEYWORD_ONLY, p.VAR_POSITIONAL) for p in params[:i]
        ):
            parts.append("*")
        text = param.name
        if param.kind is param.VAR_POSITIONAL:
            text = "*" + text
        elif param.kind is param.VAR_KEYWORD:
            text = "**" + text
        if param.annotation is not param.empty:
            text += f": {_fmt_type(param.annotation)}"
        if param.default is not param.empty:
            text += f" = {_fmt_value(param.default)}"
        parts.append(text)
        if i == last_positional_only:
            parts.append("/")
    result = "(" + ", ".join(parts) + ")"
    if sig.return_annotation is not sig.empty:
        result += f" -> {_fmt_type(sig.return_annotation)}"
    return result


# ── Collecting ───────────────────────────────────────────────────────────────────────


def _documented_names(module: str) -> list[str]:
    prefix = f"::: {module}."
    names = []
    page = API_PAGE.read_text(encoding="utf-8") if API_PAGE.exists() else ""
    for line in page.splitlines():
        if line.startswith(prefix):
            rest = line[len(prefix) :].strip()
            if rest and "." not in rest:
                names.append(rest)
    return names


def _exported_names(module: types.ModuleType) -> list[str]:
    names = getattr(module, "__all__", None)
    if names is None:
        names = _documented_names(module.__name__)
    return [n for n in names if n not in _SKIP_NAMES]


def _is_class_var(annotation: object) -> bool:
    if isinstance(annotation, str):
        return annotation.startswith(("ClassVar", "typing.ClassVar"))
    return typing.get_origin(annotation) is typing.ClassVar


def _own_classes(cls: type) -> list[type]:
    """``cls`` and its bases that archivey defines, most derived first."""
    return [
        c
        for c in cls.__mro__
        if c.__module__ == "archivey" or c.__module__.startswith("archivey.")
    ]


def _bases(cls: type) -> list[object]:
    """``cls.__bases__``, with a bare ``Generic`` given its type parameters."""
    generic = [
        b
        for b in cls.__dict__.get("__orig_bases__", ())
        if typing.get_origin(b) is typing.Generic
    ]
    return [
        generic[0] if b is typing.Generic and generic else b
        for b in cls.__bases__
        if b is not object
    ]


def _class_lines(qualname: str, cls: type) -> Iterator[str]:
    bases = ", ".join(_fmt_type(b) for b in _bases(cls))
    yield f"class {qualname}({bases})"
    if issubclass(cls, enum.Enum):
        tag = "open-enum" if qualname in OPEN_ENUMS else "enum"
        yield f"{tag} {qualname}"
        for member in cls:
            yield f"value {qualname}.{member.name} = {member.value!r}"
    own = _own_classes(cls)
    if (
        not issubclass(cls, enum.Enum)
        and qualname not in _SKIP_INIT
        and "__init__" in {n for c in own for n in vars(c)}
    ):
        yield f"init {qualname}{_fmt_signature(cls)}"
    fields: dict[str, str] = {}
    for c in reversed(own):
        for name, annotation in inspect.get_annotations(c).items():
            if name.startswith("_") or _is_class_var(annotation):
                continue
            fields[name] = _fmt_type(annotation)
    if dataclasses.is_dataclass(cls):
        for field in dataclasses.fields(cls):
            if field.name.startswith("_"):
                continue
            text = fields.get(field.name, _fmt_type(field.type))
            if field.default is not dataclasses.MISSING:
                text += f" = {_fmt_value(field.default)}"
            elif field.default_factory is not dataclasses.MISSING:
                text += " = <factory>"
            fields[field.name] = text
    for name, text in sorted(fields.items()):
        yield f"field {qualname}.{name}: {text}"
    members: dict[str, object] = {}
    for c in reversed(own):
        for name, value in vars(c).items():
            if not name.startswith("_") and name not in fields:
                members[name] = value
    for name, value in sorted(members.items()):
        target = f"{qualname}.{name}"
        if isinstance(value, property):
            ret = (
                inspect.signature(value.fget).return_annotation if value.fget else None
            )
            shown = "" if ret in (None, inspect.Signature.empty) else _fmt_type(ret)
            yield f"property {target}: {shown}".rstrip(": ").rstrip()
        elif isinstance(value, (staticmethod, classmethod)):
            kind = type(value).__name__
            yield f"{kind} {target}{_fmt_signature(value.__func__)}"
        elif inspect.isfunction(value):
            yield f"method {target}{_fmt_signature(value)}"
        elif issubclass(cls, enum.Enum) and isinstance(value, enum.Enum):
            continue
        elif not callable(value):
            yield f"attribute {target} = {_fmt_value(value)}"


def _name_lines(qualname: str, obj: object) -> Iterator[str]:
    if inspect.isclass(obj):
        yield from _class_lines(qualname, obj)
    elif inspect.isfunction(obj):
        yield f"function {qualname}{_fmt_signature(obj)}"
    elif qualname in CODE_LITERALS:
        for value in typing.get_args(obj):
            yield f"code-literal {qualname} {value!r}"
    elif isinstance(obj, types.UnionType) or typing.get_origin(obj) is not None:
        yield f"alias {qualname} = {_fmt_type(obj)}"
    elif isinstance(obj, (frozenset, set, tuple)):
        yield f"constant {qualname}: {type(obj).__qualname__}"
        for item in sorted(_fmt_value(v) for v in obj):
            yield f"item {qualname} {item}"
    else:
        yield f"constant {qualname} = {_fmt_value(obj)}"


def _action_text(action: argparse.Action) -> str:
    """What a script relies on in an option or argument: how it is read, and its values."""
    kind = type(action).__name__.strip("_").removesuffix("Action") or "Store"
    parts = [f"action={kind}"]
    if action.nargs is not None:
        parts.append(f"nargs={action.nargs!r}")
    if action.type is not None:
        parts.append(
            f"type={getattr(action.type, '__name__', type(action.type).__name__)}"
        )
    if action.choices is not None:
        parts.append("choices={" + ", ".join(sorted(map(str, action.choices))) + "}")
    if action.required and action.option_strings:
        parts.append("required")
    if action.default not in (None, argparse.SUPPRESS):
        parts.append(f"default={_fmt_value(action.default)}")
    return " [" + " ".join(parts) + "]"


def _cli_lines() -> Iterator[str]:
    import argparse as ap

    from archivey.cli import exit_codes
    from archivey.cli.main import build_parser

    for name, value in sorted(vars(exit_codes).items()):
        if name.startswith("EXIT_") and isinstance(value, int):
            yield f"cli-exit {name} = {value}"

    def options(prefix: str, parser: ap.ArgumentParser) -> Iterator[str]:
        for action in parser._actions:
            if isinstance(action, ap._SubParsersAction):
                for verb, sub in sorted(action.choices.items()):
                    yield f"cli-verb {prefix}{verb}"
                    yield from options(f"{prefix}{verb} ", sub)
            elif action.option_strings:
                flags = ", ".join(sorted(action.option_strings))
                where = prefix.strip() or "(global)"
                yield f"cli-option {where} {flags}{_action_text(action)}"
            elif action.dest != "help":
                where = prefix.strip() or "(global)"
                yield f"cli-arg {where} {action.dest}{_action_text(action)}"

    yield from options("", build_parser())


def surface_lines() -> list[str]:
    """Every line of the surface of the ``archivey`` that ``import`` finds."""
    lines: list[str] = []
    root = importlib.import_module("archivey")
    for module_name in PUBLIC_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        lines.append(f"module {module_name}")
        for name in sorted(_exported_names(module)):
            if not hasattr(module, name):
                continue
            obj = getattr(module, name)
            qualname = f"{module_name}.{name}"
            if (
                module is not root
                and name in root.__all__
                and getattr(root, name) is obj
            ):
                # The same object as a root export: name the second path only.
                lines.append(f"reexport {qualname} = archivey.{name}")
            else:
                lines.extend(_name_lines(qualname, obj))
    lines.extend(_cli_lines())
    return lines


def render(lines: Iterable[str]) -> str:
    return HEADER + "".join(line + "\n" for line in lines)


def parse(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


# ── Comparing ────────────────────────────────────────────────────────────────────────


def _owner(line: str) -> str:
    """The class or name a ``value`` or ``code-literal`` line adds to."""
    target = line.split(" ", 2)[1]
    return target.rsplit(".", 1)[0] if line.startswith("value ") else target


def is_experimental(line: str) -> bool:
    """Whether ``line`` describes a name under :data:`EXPERIMENTAL`."""
    parts = line.split(" ", 2)
    if len(parts) < 2:
        return False
    # ``init archivey.X(...)`` and ``function archivey.f(...)`` carry their signature.
    target = parts[1].split("(", 1)[0].rstrip(":")
    return any(target == name or target.startswith(name + ".") for name in EXPERIMENTAL)


def classify(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    """Split the changes into (needs a minor release, allowed in a patch).

    Each entry is a ``+`` or ``-`` line. A removed or changed line needs a minor
    release, unless the line's own name is experimental (:func:`is_experimental`). An
    added line is allowed in a patch only when its own name is experimental, or it adds
    a value to an open-ended enum or a diagnostic code string (DR-12a). Anything else
    added (a name, a parameter, a field, an item of ``ARCHIVE_INTEGRITY_CODES``, a CLI
    option) needs a minor release. A stable line that only mentions an experimental
    name, such as ``FormatPolicy``'s constructor with its ``replace=`` parameter, is
    judged as a stable line: the maintainer then decides whether the change is a minor.
    """
    old_set, new_set = set(old), set(new)
    open_enums = {
        line.split(" ", 1)[1] for line in old + new if line.startswith("open-enum ")
    }
    minor: list[str] = []
    patch: list[str] = []
    for line in old:
        if line not in new_set:
            (patch if is_experimental(line) else minor).append("- " + line)
    for line in new:
        if line in old_set:
            continue
        allowed = (
            (line.startswith("value ") and _owner(line) in open_enums)
            or line.startswith("code-literal ")
            or is_experimental(line)
        )
        (patch if allowed else minor).append("+ " + line)
    return minor, patch


def report(old: list[str], new: list[str]) -> str:
    minor, patch = classify(old, new)
    out: list[str] = []
    if minor:
        out.append("The public API changed in a way a patch release may not:")
        out.extend("  " + line for line in minor)
    if patch:
        out.append("Changes a patch release may make:")
        out.extend("  " + line for line in patch)
    if not minor and not patch:
        out.append("The public API did not change.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="regenerate the file")
    group.add_argument("--check", action="store_true", help="exit 1 if it is stale")
    group.add_argument(
        "--compare-to",
        type=Path,
        metavar="OLD",
        help="print what changed since the surface in OLD; the first line is"
        " 'minor', 'patch' or 'none'",
    )
    parser.add_argument(
        "--src", type=Path, help="import archivey from this src directory instead"
    )
    parser.add_argument(
        "--modules-from",
        type=Path,
        metavar="FILE",
        help="take the list of public modules from the `module` lines of FILE",
    )
    args = parser.parse_args(argv)
    global API_PAGE, PUBLIC_MODULES
    if args.src is not None:
        sys.path.insert(0, str(args.src.resolve()))
        API_PAGE = args.src.resolve().parent / "docs" / "api.md"
    if args.modules_from is not None:
        # An older tree's own list of public modules, from its committed surface file.
        modules = [
            line.split(" ", 1)[1]
            for line in parse(args.modules_from.read_text(encoding="utf-8"))
            if line.startswith("module ")
        ]
        if modules:
            PUBLIC_MODULES = tuple(modules)
    lines = surface_lines()
    text = render(lines)
    if args.compare_to is not None:
        old = parse(args.compare_to.read_text(encoding="utf-8"))
        minor, patch = classify(old, lines)
        print("minor" if minor else "patch" if patch else "none")
        print(report(old, lines))
    elif args.write:
        SURFACE_FILE.write_text(text, encoding="utf-8")
    elif args.check:
        current = (
            SURFACE_FILE.read_text(encoding="utf-8") if SURFACE_FILE.exists() else ""
        )
        if current != text:
            print(
                f"{SURFACE_FILE.relative_to(ROOT)} is stale; run"
                " `uv run python scripts/api_surface.py --write`",
                file=sys.stderr,
            )
            return 1
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
