"""The committed API surface file is current, and the patch-or-minor rule reads it right.

``dev-docs/api-surface.txt`` is how a pull request shows that it changes the public API,
and ``scripts/release.py notes`` reads the same lines to say whether a release can be a
patch (``docs/how-it-is-built.md`` §Versioning and stability).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "api_surface.py"

_spec = importlib.util.spec_from_file_location("api_surface_script", SCRIPT)
assert _spec is not None and _spec.loader is not None
api_surface = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = api_surface
_spec.loader.exec_module(api_surface)


def test_surface_file_is_current() -> None:
    committed = api_surface.SURFACE_FILE.read_text(encoding="utf-8")
    current = api_surface.render(api_surface.surface_lines())
    assert committed == current, (
        "dev-docs/api-surface.txt is stale: run"
        " `uv run python scripts/api_surface.py --write` and commit the result"
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
