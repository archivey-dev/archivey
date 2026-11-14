"""The committed API surface file is current, and the patch-or-minor rule reads it right.

``dev-docs/api-surface.txt`` is how a pull request shows that it changes the public API,
and ``scripts/release/release.py notes`` reads the same lines to say whether a release can be a
patch (``docs/how-it-is-built.md`` §Versioning and stability).
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import importlib.util
import inspect
import sys
import typing
from enum import Enum
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "checks" / "api_surface.py"

_spec = importlib.util.spec_from_file_location("api_surface_script", SCRIPT)
assert _spec is not None and _spec.loader is not None
api_surface = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = api_surface
_spec.loader.exec_module(api_surface)


def test_surface_file_is_current() -> None:
    # archivey.fsspec imports fsspec, which no archivey extra installs; the legs that
    # have it check its lines.
    pytest.importorskip("fsspec", reason="archivey.fsspec needs fsspec")
    committed = api_surface.SURFACE_FILE.read_text(encoding="utf-8")
    current = api_surface.render(api_surface.surface_lines())
    assert committed == current, (
        "dev-docs/api-surface.txt is stale: run"
        " `uv run python scripts/checks/api_surface.py --write` and commit the result"
    )


def test_surface_covers_the_promised_parts() -> None:
    lines = api_surface.parse(api_surface.SURFACE_FILE.read_text(encoding="utf-8"))
    kinds = {line.split(" ", 1)[0] for line in lines}
    assert {"function", "class", "field", "value", "cli-verb", "cli-option"} <= kinds
    assert "cli-exit EXIT_USAGE = 2" in lines
    assert "open-enum archivey.CompressionAlgorithm" in lines
    assert "open-enum archivey.DiagnosticCode" in lines
    assert any(
        line.startswith("item archivey.ARCHIVE_INTEGRITY_CODES ") for line in lines
    )


_OLD = [
    "class archivey.DiagnosticCode(StrEnum)",
    "open-enum archivey.DiagnosticCode",
    "value archivey.DiagnosticCode.A = 'a'",
    "class archivey.MemberType(Enum)",
    "enum archivey.MemberType",
    "value archivey.MemberType.FILE = 'file'",
    "code-literal archivey.diagnostics.DiagnosticCodeStr 'a'",
    "constant archivey.ARCHIVE_INTEGRITY_CODES: frozenset",
    "function archivey.open_archive(path: str) -> ArchiveReader",
]


def _classify(new: list[str]) -> tuple[list[str], list[str]]:
    return api_surface.classify(_OLD, new)


def test_unchanged_surface_needs_nothing() -> None:
    assert _classify(list(_OLD)) == ([], [])


def test_new_diagnostic_code_fits_a_patch() -> None:
    minor, patch = _classify(
        [
            *_OLD,
            "value archivey.DiagnosticCode.B = 'b'",
            "code-literal archivey.diagnostics.DiagnosticCodeStr 'b'",
        ]
    )
    assert minor == []
    assert len(patch) == 2


def test_new_value_in_a_closed_enum_needs_a_minor() -> None:
    minor, patch = _classify([*_OLD, "value archivey.MemberType.PIPE = 'pipe'"])
    assert minor == ["+ value archivey.MemberType.PIPE = 'pipe'"]
    assert patch == []


def test_new_strict_code_needs_a_minor() -> None:
    line = "item archivey.ARCHIVE_INTEGRITY_CODES DiagnosticCode.A"
    assert _classify([*_OLD, line]) == ([f"+ {line}"], [])


def test_changed_signature_needs_a_minor() -> None:
    new = [line for line in _OLD if not line.startswith("function ")]
    new.append(
        "function archivey.open_archive(path: str, *, x: int = 0) -> ArchiveReader"
    )
    minor, patch = _classify(new)
    assert len(minor) == 2  # the old line removed, the new one added
    assert patch == []


def test_removed_enum_value_needs_a_minor() -> None:
    new = [line for line in _OLD if line != "value archivey.DiagnosticCode.A = 'a'"]
    assert _classify(new) == (["- value archivey.DiagnosticCode.A = 'a'"], [])


def test_experimental_names_are_pinned() -> None:
    # A change to these never needs a minor. Adding one takes away a promise to callers.
    assert api_surface.EXPERIMENTAL == (
        "archivey.formats",
        "archivey.PluginContainer",
        "archivey.PluginStream",
        "archivey.FormatPolicy.replace",
        "archivey.FormatInfo.from_plugin",
        "archivey.Verification",
        "archivey.ArchiveStream.verified",
        "archivey.ArchiveStream.verifiable",
        "archivey.ArchiveStream.verify",
        "archivey.ArchiveMember.verified",
        "archivey.ArchiveMember.verifiable",
        "archivey.ForwardArchiveReader.verify_all",
        "archivey.ArchiveReader.verify_all",
        "archivey.VerifyReport",
        "archivey.BackendUse",
        "archivey.BackendKindStr",
        "archivey.ForwardArchiveReader.backends_used",
        "archivey.ArchiveReader.backends_used",
    )


def test_a_stable_signature_naming_an_experimental_type_still_needs_a_minor() -> None:
    old = "init archivey.FormatPolicy(*, replace: Mapping | None = None) -> None"
    new = "init archivey.FormatPolicy(*) -> None"
    minor, patch = api_surface.classify([old], [new])
    assert minor == [f"- {old}", f"+ {new}"]
    assert patch == []


def test_a_change_to_an_experimental_name_fits_a_patch() -> None:
    old = [
        *_OLD,
        "module archivey.formats",
        "class archivey.formats.FormatHandler(ABC)",
        "function archivey.formats.register_format(handler: type) -> None",
        "field archivey.FormatPolicy.replace: Mapping[ContainerFormat, type]",
    ]
    new = [
        *_OLD,
        "module archivey.formats",
        "function archivey.formats.register_format(handler: type, *, x: int) -> None",
        "class archivey.PluginContainer(StrEnum)",
    ]
    minor, patch = api_surface.classify(old, new)
    assert minor == []
    assert len(patch) == 5


def test_a_stable_name_beside_an_experimental_one_still_needs_a_minor() -> None:
    # A prefix match covers the name and what is under it, not every name it begins.
    for line in (
        "function archivey.formats_list() -> list",
        "field archivey.FormatPolicy.replace_all: bool",
        "field archivey.FormatPolicy.only: frozenset",
    ):
        assert not api_surface.is_experimental(line), line
        assert _classify([*_OLD, line]) == ([f"+ {line}"], [])


def test_every_experimental_entry_names_something() -> None:
    lines = api_surface.parse(api_surface.SURFACE_FILE.read_text(encoding="utf-8"))
    for name in api_surface.EXPERIMENTAL:
        assert any(
            api_surface.is_experimental(line) and name in line for line in lines
        ), name


def test_open_enums_are_pinned() -> None:
    # A patch release may add values to these. Adding one is a promise to callers.
    lines = api_surface.parse(api_surface.SURFACE_FILE.read_text(encoding="utf-8"))
    assert sorted(line for line in lines if line.startswith("open-enum ")) == [
        "open-enum archivey.CompressionAlgorithm",
        "open-enum archivey.DiagnosticCode",
    ]
    # An entry that renders no line (a re-exported name, a typo) would do nothing.
    for name in api_surface.OPEN_ENUMS:
        assert f"open-enum {name}" in lines
    for name in api_surface.CODE_LITERALS:
        assert any(line.startswith(f"code-literal {name} ") for line in lines)


def test_surface_lists_the_public_modules() -> None:
    # release.py reads these lines from the tag's file, so a module made public since
    # then shows as added.
    lines = api_surface.parse(api_surface.SURFACE_FILE.read_text(encoding="utf-8"))
    modules = [line.split(" ", 1)[1] for line in lines if line.startswith("module ")]
    assert modules == list(api_surface.PUBLIC_MODULES)


def test_cli_lines_say_how_an_option_is_read() -> None:
    lines = api_surface.parse(api_surface.SURFACE_FILE.read_text(encoding="utf-8"))
    assert "cli-arg cat patterns [action=Store nargs='*']" in lines


def test_modules_from_reports_a_newly_public_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An older tree whose surface file did not list archivey.terminal yet: measured with
    # that list, the module and its names show as added.
    full = api_surface.PUBLIC_MODULES
    monkeypatch.setattr(api_surface, "PUBLIC_MODULES", full)  # main() reassigns it
    old_list = tmp_path / "old-surface.txt"
    old_list.write_text(
        "".join(
            f"module {name}\n"
            for name in api_surface.PUBLIC_MODULES
            if name != "archivey.terminal"
        ),
        encoding="utf-8",
    )
    old_surface = tmp_path / "old.txt"
    assert api_surface.main(["--modules-from", str(old_list)]) == 0
    old_surface.write_text(capsys.readouterr().out, encoding="utf-8")
    assert "archivey.terminal" not in old_surface.read_text(encoding="utf-8")

    monkeypatch.setattr(api_surface, "PUBLIC_MODULES", full)
    lines = api_surface.surface_lines()
    minor, patch = api_surface.classify(
        api_surface.parse(old_surface.read_text(encoding="utf-8")), lines
    )
    assert "+ module archivey.terminal" in minor
    assert any(line.startswith("+ function archivey.terminal.") for line in minor)
    assert patch == []


# --- constructors declared for type checkers ---------------------------------------


def _unparse(node: ast.AST | None) -> str:
    assert node is not None
    return ast.unparse(node)


def _type_checking_init_classes() -> list[type]:
    """Every class under ``src/archivey`` with an ``__init__`` under ``TYPE_CHECKING``."""
    src = ROOT / "src"
    classes: list[type] = []
    for path in sorted((src / "archivey").rglob("*.py")):
        if "if TYPE_CHECKING:" not in path.read_text(encoding="utf-8"):
            continue
        parts = path.relative_to(src).with_suffix("").parts
        module_name = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        try:
            module = importlib.import_module(module_name)
        except ImportError:  # an optional dependency this environment lacks
            continue
        for class_name in api_surface.type_checking_inits(module_name):
            classes.append(getattr(module, class_name))
    return classes


def test_the_scan_finds_the_known_typed_constructors() -> None:
    from archivey import ArchiveFormat, ArchiveyConfig

    assert {ArchiveFormat, ArchiveyConfig} <= set(_type_checking_init_classes())


@pytest.mark.parametrize(
    "cls", _type_checking_init_classes(), ids=lambda cls: cls.__qualname__
)
def test_a_type_checking_init_matches_the_generated_one(cls: type) -> None:
    """The declared ``__init__`` may widen an annotation, and change nothing else.

    A dataclass that converts a string spelling in ``__post_init__`` declares its
    constructor's wider input types in ``if TYPE_CHECKING: def __init__``, which
    ``@dataclass`` leaves alone at runtime, so the generated ``__init__`` still runs.
    The declaration is a second copy of the parameter list, and nothing else checks it:
    a field added, renamed, reordered or given a default without it would type-check
    one call and run another. Each parameter must match the generated one in name,
    kind and whether it has a default (the declaration writes every default as
    ``...``), and its annotation must be the field's own, optionally followed by
    ``| X`` for further accepted input types. Those must be a ``Literal`` alias or an
    enum, never a bare ``str``, so a misspelling stays a type error.
    """
    assert dataclasses.is_dataclass(cls)
    stub = api_surface.type_checking_inits(cls.__module__)[cls.__qualname__]
    module = sys.modules[cls.__module__]
    assert _unparse(stub.returns) == "None"
    assert not (stub.args.posonlyargs or stub.args.vararg or stub.args.kwarg)

    declared = [
        (arg, inspect.Parameter.POSITIONAL_OR_KEYWORD, default)
        for arg, default in zip(
            stub.args.args,
            [None] * (len(stub.args.args) - len(stub.args.defaults))
            + list(stub.args.defaults),
            strict=True,
        )
    ] + [
        (arg, inspect.Parameter.KEYWORD_ONLY, default)
        for arg, default in zip(
            stub.args.kwonlyargs, stub.args.kw_defaults, strict=True
        )
    ]
    generated = list(inspect.signature(cls.__init__).parameters.values())
    assert [arg.arg for arg, _, _ in declared] == [p.name for p in generated]

    for (arg, kind, default), param in zip(declared[1:], generated[1:], strict=True):
        where = f"{cls.__qualname__}.__init__({param.name}=)"
        assert kind is param.kind, f"{where}: {kind} here, {param.kind} generated"
        has_default = param.default is not inspect.Parameter.empty
        assert (default is not None) == has_default, f"{where}: default differs"
        if default is not None:
            assert _unparse(default) == "...", f"{where}: write the default as ..."
        assert arg.annotation is not None, f"{where}: no annotation"
        annotation = _unparse(arg.annotation)
        field_type = str(param.annotation)
        assert annotation == field_type or annotation.startswith(f"{field_type} | "), (
            f"{where}: {annotation!r} does not start with the field's {field_type!r}"
        )
        for extra in annotation.removeprefix(field_type).split(" | ")[1:]:
            accepted = getattr(module, extra, None)
            is_literal = typing.get_origin(accepted) is typing.Literal
            is_enum = isinstance(accepted, type) and issubclass(accepted, Enum)
            assert is_literal or is_enum, (
                f"{where}: {extra!r} is not a Literal alias or an enum"
            )
