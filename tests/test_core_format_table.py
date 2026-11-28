"""Core registers the readers written against ``archivey.formats`` from a table of its
own (``internal/format_table.py``), the first form of the manifest's entries. A reader
module only defines its handler: what DMG, pkg, LHA and ARJ passed through the internal
registration call (a trailer, a refinement check, a stub scan) is data in the table."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from archivey.formats import FormatHandler
from archivey.internal import format_table
from archivey.internal.backends import lha_reader, udif
from archivey.internal.registry import get_registry
from archivey.types import ArchiveFormat

# The 13 readers the plugin plan moves out of core.
_HANDLER_MODULES = (
    "ar_reader",
    "arj_reader",
    "cab_reader",
    "cpio_reader",
    "deb_reader",
    "dmg_reader",
    "iso_reader",
    "lha_reader",
    "makeself_reader",
    "pkg_reader",
    "rpm_reader",
    "squashfs_reader",
    "xar_reader",
)


def _module_file(name: str) -> Path:
    module = importlib.import_module(f"archivey.internal.backends.{name}")
    assert module.__file__ is not None
    return Path(module.__file__)


# The calls that put a format in the registry.
_REGISTRATION_CALLS = frozenset(
    {"register_builtin_format", "register_reader", "register_format", "register_plugin"}
)


def _uses_a_registration_call(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    used = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    } | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    return bool(used & _REGISTRATION_CALLS - {"register_reader"})


def test_no_backend_module_registers_a_handler_itself() -> None:
    """Every module in ``backends/``, so that a new reader written against
    ``archivey.formats`` needs its entry in the table: one that called
    ``register_builtin_format`` itself would fail here."""
    backends = _module_file("ar_reader").parent
    assert [
        path.name
        for path in sorted(backends.glob("*.py"))
        if _uses_a_registration_call(path)
    ] == []


@pytest.mark.parametrize("name", _HANDLER_MODULES)
def test_the_reader_module_does_not_register_itself(name: str) -> None:
    tree = ast.parse(_module_file(name).read_text(encoding="utf-8"))
    used = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    } | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not used & _REGISTRATION_CALLS


def test_the_table_lists_each_handler_module_once() -> None:
    modules = [
        entry.handler.partition(":")[0].rpartition(".")[2]
        for entry in format_table.CORE_FORMATS
        if isinstance(entry, format_table.HandlerEntry)
    ]
    assert sorted(modules) == sorted(_HANDLER_MODULES)


def test_each_table_entry_names_a_handler_class() -> None:
    for entry in format_table.CORE_FORMATS:
        if isinstance(entry, format_table.HandlerEntry):
            handler = format_table.load(entry.handler)
            assert isinstance(handler, type) and issubclass(handler, FormatHandler)


def test_deb_registers_before_ar() -> None:
    """A ``.deb`` starts with ar's magic, and the first magic that matches wins."""
    names = [
        entry.handler
        for entry in format_table.CORE_FORMATS
        if isinstance(entry, format_table.HandlerEntry)
    ]
    deb = next(i for i, n in enumerate(names) if n.endswith(":DebHandler"))
    ar = next(i for i, n in enumerate(names) if n.endswith(":ArHandler"))
    assert deb < ar


def test_the_dmg_trailer_is_the_koly_block_udif_parses() -> None:
    (dmg,) = (
        entry
        for entry in format_table.CORE_FORMATS
        if isinstance(entry, format_table.HandlerEntry)
        and entry.handler.endswith(":DmgHandler")
    )
    koly = dmg.trailers[0]
    assert koly.magic == udif.KOLY_SIGNATURE
    assert koly.length == udif.KOLY_SIZE
    assert koly.format == ArchiveFormat.DMG


def test_the_registry_has_the_table_declarations() -> None:
    registry = get_registry()
    trailers = {t.magic for t in registry.trailer_entries()}
    assert udif.KOLY_SIGNATURE in trailers
    assert b"cdsaencr" in trailers
    refinements = registry.magic_refinements()[ArchiveFormat.XAR]
    assert [fmt for fmt, _ in refinements] == [ArchiveFormat.PKG]
    lha_stub = [
        sig.magic
        for sig in registry.sfx_magic_entries()
        if sig.format == ArchiveFormat.LHA
    ]
    assert lha_stub == [m.data for m in lha_reader.LhaHandler.magic]
    assert registry.sfx_parser_scanned_formats() >= {
        ArchiveFormat.LHA,
        ArchiveFormat.ARJ,
    }


def test_the_table_turns_salvage_on_for_its_salvage_readers() -> None:
    """``salvage=True`` reaches a reader only when its backend says it searches past
    damage. The table declares that for ar, CPIO and deb, the readers with a salvage
    walk; every other table handler reads as the default and records
    ``SALVAGE_UNAVAILABLE``."""
    registry = get_registry()
    salvaging = {ArchiveFormat.AR, ArchiveFormat.CPIO, ArchiveFormat.DEB}
    for entry in format_table.CORE_FORMATS:
        if not isinstance(entry, format_table.HandlerEntry):
            continue
        handler = format_table.load(entry.handler)
        backend = registry.registered_reader(handler.format)  # type: ignore[attr-defined]
        assert backend is not None, entry.handler
        assert backend.SUPPORTS_SALVAGE is (handler.format in salvaging), entry.handler  # type: ignore[attr-defined]
