"""The CLI is built on archivey's public API only.

``archivey.cli`` is the first consumer of the library and the example other front ends
copy. If it reaches into ``archivey.internal``, it can depend on something no caller can
rely on, and an internal refactor can break it without touching any public name. The
display helpers a front end needs beyond the core surface live in :mod:`archivey.terminal`.
See CONTRIBUTING.md, "The CLI uses only public API."
"""

from __future__ import annotations

import ast
from pathlib import Path

CLI_DIR = Path(__file__).resolve().parents[1] / "src" / "archivey" / "cli"

# The deliberate exception, keyed by the hit text ``_internal_imports`` reports, minus
# the line number, so each entry names exactly one import statement and nothing else.
# ``--track-io`` reads the IO counters, which are not public API: the CLI is also a
# debugging tool for the library, so it may see what a caller cannot.
ALLOWED_INTERNAL_IMPORTS = frozenset(
    {
        "common.py: from archivey.internal.measurement import enable_measurement, io_stats",
    }
)


def _without_line(hit: str) -> str:
    location, _, statement = hit.partition(" ")
    return f"{location.rsplit(':', 1)[0]}: {statement}"


def _offending(hits: list[str]) -> list[str]:
    return [hit for hit in hits if _without_line(hit) not in ALLOWED_INTERNAL_IMPORTS]


def _internal_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative: stays inside archivey.cli
            module = node.module or ""
            names = [module] + [f"{module}.{alias.name}" for alias in node.names]
        else:
            continue
        if any(
            name == "archivey.internal" or name.startswith("archivey.internal.")
            for name in names
        ):
            found.append(f"{path.name}:{node.lineno} {ast.unparse(node)}")
    return found


def test_cli_imports_nothing_from_internal() -> None:
    files = sorted(CLI_DIR.rglob("*.py"))
    assert files, f"no CLI sources under {CLI_DIR}"
    hits = [hit for path in files for hit in _internal_imports(path)]
    offending = _offending(hits)
    assert offending == [], (
        "archivey.cli must use only public API; move what it needs to a public module "
        f"(archivey.terminal for display helpers): {offending}"
    )
    # An allowlist entry whose import is gone would admit the next one silently.
    stale = ALLOWED_INTERNAL_IMPORTS - {_without_line(hit) for hit in hits}
    assert not stale, f"allowlisted CLI imports no longer present: {sorted(stale)}"


def test_the_guard_sees_an_internal_import(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import archivey.internal.source\n"
        "from archivey import internal\n"
        "from archivey.internal.registry import get_registry\n",
        encoding="utf-8",
    )
    assert len(_internal_imports(probe)) == 3


def test_the_allowlist_admits_one_statement_not_its_file(tmp_path: Path) -> None:
    """A second internal import in the allowlisted file is still reported."""
    probe = tmp_path / "common.py"
    probe.write_text(
        "from archivey.internal.measurement import enable_measurement, io_stats\n"
        "from archivey.internal.registry import get_registry\n",
        encoding="utf-8",
    )
    offending = _offending(_internal_imports(probe))
    assert offending == [
        "common.py:2 from archivey.internal.registry import get_registry"
    ]


# Private attributes the CLI may read on an object that is not its own, keyed like
# ``ALLOWED_INTERNAL_IMPORTS`` by ``file: expression``, so an entry admits that
# expression in that file and not the same attribute name on another object or in
# another module. The four dry-run fields are the ``cli`` spec's recorded exception; the
# rest are argparse's (``_actions``, ``_SubParsersAction``) and the CLI's own namespace
# default (``_reserved_message``), none of which belong to the library.
#
# The guard reads attribute syntax only: ``getattr(member, "_name")`` and other
# dynamic lookups are invisible to it, so a read spelled that way is a review matter.
ALLOWED_PRIVATE_ATTRIBUTES = frozenset(
    {
        "extract_cmd.py: report._dry_run_entries",
        "extract_cmd.py: report._dry_run_links",
        "extract_cmd.py: report._dry_run_top_level",
        "extract_cmd.py: report._resource_usage",
        "main.py: parser._actions",
        "main.py: verb_parser._actions",
        "main.py: argparse._SubParsersAction",
        "main.py: args._reserved_message",
    }
)


def _private_attribute_reads(path: Path) -> list[str]:
    """Each ``x._name`` read in ``path`` where ``x`` is not ``self`` or ``cls``, as
    ``file:line expression``. Dunder names are not private and are skipped."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        f"{path.name}:{node.lineno} {ast.unparse(node)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr.startswith("_")
        and not node.attr.startswith("__")
        and ast.unparse(node.value) not in ("self", "cls")
    ]


def _offending_attributes(hits: list[str]) -> list[str]:
    return [hit for hit in hits if _without_line(hit) not in ALLOWED_PRIVATE_ATTRIBUTES]


def test_cli_reads_no_private_library_attribute() -> None:
    """A private field such as ``ArchiveMember._link_target_absent`` is internal state
    even though Python lets the CLI read it; what the CLI needs has a public name
    (here ``ArchiveMember.link_target_unrecorded``). Attribute syntax only: see the
    comment on ``ALLOWED_PRIVATE_ATTRIBUTES``."""
    files = sorted(CLI_DIR.rglob("*.py"))
    assert files, f"no CLI sources under {CLI_DIR}"
    hits = [hit for path in files for hit in _private_attribute_reads(path)]
    offending = _offending_attributes(hits)
    assert offending == [], f"archivey.cli reads private attributes: {offending}"
    # As for the import allowlist: an entry whose read is gone would admit the next.
    stale = ALLOWED_PRIVATE_ATTRIBUTES - {_without_line(hit) for hit in hits}
    assert not stale, f"allowlisted private reads no longer present: {sorted(stale)}"


def test_the_private_attribute_guard_sees_a_read(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "def f(member, self):\n    return member._link_target_absent, self._own\n",
        encoding="utf-8",
    )
    assert _private_attribute_reads(probe) == ["probe.py:2 member._link_target_absent"]


def test_the_private_attribute_allowlist_admits_one_site_not_its_name(
    tmp_path: Path,
) -> None:
    """An allowlisted attribute read on another object, or in another file, is still
    reported."""
    probe = tmp_path / "extract_cmd.py"
    probe.write_text(
        "x = report._dry_run_links\ny = member._dry_run_links\n", encoding="utf-8"
    )
    other = tmp_path / "test_cmd.py"
    other.write_text("z = report._dry_run_links\n", encoding="utf-8")
    hits = _private_attribute_reads(probe) + _private_attribute_reads(other)
    assert _offending_attributes(hits) == [
        "extract_cmd.py:2 member._dry_run_links",
        "test_cmd.py:1 report._dry_run_links",
    ]
