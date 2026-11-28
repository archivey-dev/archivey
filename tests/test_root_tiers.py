"""The two tiers of the public namespace (0.6.0).

The package root keeps the names most callers need: the entry functions, the reader,
member, format, policy and report types, and the errors callers catch most. Every other
public name lives in the submodule that defines it (DR-13). A name that left the root
in 0.6.0 still works as ``archivey.<name>`` for the 0.6 series, with a
``DeprecationWarning`` that names the new import (DR-12a); 0.7.0 removes it.
"""

from __future__ import annotations

import ast
import importlib
import re
import warnings
from pathlib import Path

import pytest

import archivey

REPO = Path(__file__).resolve().parents[1]

#: The root names the maintainer chose on 2026-11-27.
ROOT_NAMES = frozenset(
    {
        "__version__",
        "open_archive",
        "open_stream",
        "detect_format",
        "format_availability",
        "ArchiveReader",
        "ForwardArchiveReader",
        "ArchiveStream",
        "ArchiveMember",
        "MemberType",
        "ArchiveInfo",
        "ArchiveFormat",
        "ContainerFormat",
        "StreamFormat",
        "ExtractionPolicy",
        "ExtractionReport",
        "ArchiveyConfig",
        "FormatPolicy",
        "Diagnostic",
        "DiagnosticCode",
        "DiagnosticPolicy",
        "ArchiveyError",
        "ArchiveyUsageError",
        "FormatDetectionError",
        "CorruptionError",
        "TruncatedError",
        "EncryptionError",
        "ResourceLimitError",
        "UnsupportedFeatureError",
        "PackageNotInstalledError",
    }
)

#: Every name that left the root in 0.6.0, and the submodule it is imported from now.
MOVED = {
    "AcceleratorMode": "archivey.config",
    "DecoderLimits": "archivey.config",
    "DEFAULT_ARCHIVEY_CONFIG": "archivey.config",
    "ExtractionLimits": "archivey.config",
    "ListingLimits": "archivey.config",
    "PartialDataRecovery": "archivey.config",
    "PasswordInput": "archivey.config",
    "PasswordProvider": "archivey.config",
    "PasswordRequest": "archivey.config",
    "ProcessIsolation": "archivey.config",
    "RarDecompressor": "archivey.config",
    "SalvageLimits": "archivey.config",
    "SpoolLimits": "archivey.config",
    "list_known_formats": "archivey.core",
    "list_supported_formats": "archivey.core",
    "AccessCost": "archivey.cost",
    "CostReceipt": "archivey.cost",
    "ListingCost": "archivey.cost",
    "StreamCapability": "archivey.cost",
    "DetectionConfidence": "archivey.detection",
    "FormatInfo": "archivey.detection",
    "ARCHIVE_INTEGRITY_CODES": "archivey.diagnostics",
    "DiagnosticContext": "archivey.diagnostics",
    "DiagnosticSummary": "archivey.diagnostics",
    "MemberListReport": "archivey.diagnostics",
    "OnDiagnostic": "archivey.diagnostics",
    "VerifyReport": "archivey.diagnostics",
    "DiagnosticRaisedError": "archivey.exceptions",
    "ExtractionError": "archivey.exceptions",
    "FilterRejectionError": "archivey.exceptions",
    "LinkTargetNotFoundError": "archivey.exceptions",
    "LinkTargetNotFoundReason": "archivey.exceptions",
    "NameCollisionError": "archivey.exceptions",
    "NameRewrittenError": "archivey.exceptions",
    "OpenError": "archivey.exceptions",
    "ReadError": "archivey.exceptions",
    "ResourceUnavailableError": "archivey.exceptions",
    "SourceChangedError": "archivey.exceptions",
    "StreamNotSeekableError": "archivey.exceptions",
    "sanitize_names": "archivey.paths",
    "MemberPass": "archivey.reader",
    "MemberSelector": "archivey.reader",
    "AbortOn": "archivey.types",
    "ArchiveInfoExtra": "archivey.types",
    "BackendKindStr": "archivey.types",
    "BackendUse": "archivey.types",
    "CompressionAlgorithm": "archivey.types",
    "CompressionMethod": "archivey.types",
    "CreateSystem": "archivey.types",
    "ExtractionProgress": "archivey.types",
    "ExtractionResult": "archivey.types",
    "ExtractionStatus": "archivey.types",
    "FormatAvailability": "archivey.types",
    "FormatSupport": "archivey.types",
    "HashAlgorithm": "archivey.types",
    "MemberExtra": "archivey.types",
    "MemberFilter": "archivey.types",
    "MissingComponent": "archivey.types",
    "NameRewrite": "archivey.types",
    "OnBlocked": "archivey.types",
    "OnError": "archivey.types",
    "OptionalLibrary": "archivey.types",
    "OverwritePolicy": "archivey.types",
    "PluginContainer": "archivey.types",
    "PluginStream": "archivey.types",
    "SourceProgress": "archivey.types",
    "Verification": "archivey.types",
}

#: The names ``archivey.core.__all__`` listed until 0.6.0 that ``core`` does not define,
#: and the submodule each is imported from now.
CORE_MOVED = {
    "AcceleratorMode": "archivey.config",
    "DEFAULT_ARCHIVEY_CONFIG": "archivey.config",
    "ExtractionLimits": "archivey.config",
    "ListingLimits": "archivey.config",
    "DetectionConfidence": "archivey.detection",
    "FormatAvailability": "archivey.types",
    "FormatSupport": "archivey.types",
    "MissingComponent": "archivey.types",
}

#: Experimental names leave the root with no deprecation release (DR-12a).
EXPERIMENTAL_MOVED = frozenset({"PluginContainer", "PluginStream"})


def test_root_all_is_the_chosen_tier() -> None:
    assert set(archivey.__all__) == ROOT_NAMES


@pytest.mark.parametrize("name", sorted(MOVED))
def test_a_moved_name_is_public_in_its_submodule(name: str) -> None:
    module = importlib.import_module(MOVED[name])
    assert name in module.__all__
    assert name not in archivey.__all__


@pytest.mark.parametrize("name", sorted(set(MOVED) - EXPERIMENTAL_MOVED))
def test_a_moved_name_still_works_from_the_root_with_a_warning(name: str) -> None:
    new_path = f"{MOVED[name]}.{name}"
    with pytest.warns(DeprecationWarning, match=re.escape(new_path)) as caught:
        value = getattr(archivey, name)
    assert value is getattr(importlib.import_module(MOVED[name]), name)
    # The warning points at the caller's line, not at archivey (DR-12a).
    assert caught[0].filename == __file__


def test_from_import_of_a_moved_name_warns_at_the_import_line() -> None:
    with pytest.warns(
        DeprecationWarning, match=r"archivey\.config\.DecoderLimits"
    ) as caught:
        from archivey import DecoderLimits  # noqa: F401
    # A from-import of a package's moved name warns twice (``moved_name``); each
    # warning points at the import line.
    assert {w.filename for w in caught} == {__file__}


#: Names that left ``archivey.core.__all__`` and stay bound there, with no warning,
#: because ``archivey.core``'s signatures name them (``core._MOVED_IN_0_6``'s comment).
CORE_STILL_BOUND = {
    "ArchiveyConfig": "archivey.config",
    "FormatInfo": "archivey.detection",
}


@pytest.mark.parametrize("name", sorted(CORE_STILL_BOUND))
def test_a_name_core_signatures_use_stays_importable_from_core(name: str) -> None:
    import archivey.core

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        value = getattr(archivey.core, name)
    assert value is getattr(importlib.import_module(CORE_STILL_BOUND[name]), name)
    assert name not in archivey.core.__all__


def test_a_type_checker_sees_the_names_core_keeps_bound() -> None:
    """``core`` imports each name of ``CORE_STILL_BOUND`` as ``X as X``, the spelling a
    type checker takes as a re-export, so a typed ``from archivey.core import X`` is
    not refused a release early (pyright's ``reportPrivateImportUsage``)."""
    tree = ast.parse(
        Path(importlib.import_module("archivey.core").__file__).read_text()
    )
    reexported = {
        alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.asname == alias.name
    }
    assert set(CORE_STILL_BOUND) <= reexported


@pytest.mark.parametrize("module_name", ["archivey", "archivey.core"])
def test_a_star_import_binds_only_the_listed_names(module_name: str) -> None:
    """``import *`` reads ``__all__``, which no longer lists the moved names, so it
    binds only the names that stay and warns about none (CHANGELOG **Breaking:**)."""
    namespace: dict[str, object] = {}
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        exec(f"from {module_name} import *", namespace)  # noqa: S102
    names = {n for n in namespace if n != "__builtins__"}
    assert names == set(importlib.import_module(module_name).__all__)


@pytest.mark.parametrize(
    ("module_name", "name"),
    [
        ("archivey", "sanitize_names"),
        ("archivey", "list_known_formats"),
        ("archivey", "list_supported_formats"),
    ],
)
def test_a_reference_pickled_by_0_5_loads_with_a_warning(
    module_name: str, name: str
) -> None:
    """A function reference pickled before 0.6 names the root. It loads through the
    shim with the warning in 0.6; re-saving it records the new module."""
    import pickle

    data = f"c{module_name}\n{name}\n.".encode()  # protocol 0, as 0.5 wrote it
    with pytest.warns(DeprecationWarning):
        function = pickle.loads(data)
    assert pickle.loads(pickle.dumps(function)) is function
    assert f"{function.__module__}.{name}" != f"{module_name}.{name}"


@pytest.mark.parametrize("name", sorted(CORE_MOVED))
def test_a_name_that_left_core_still_works_with_a_warning(name: str) -> None:
    import archivey.core

    new_path = f"{CORE_MOVED[name]}.{name}"
    with pytest.warns(DeprecationWarning, match=re.escape(new_path)) as caught:
        value = getattr(archivey.core, name)
    assert value is getattr(importlib.import_module(CORE_MOVED[name]), name)
    assert caught[0].filename == __file__
    assert name not in archivey.core.__all__


@pytest.mark.parametrize(
    ("module_name", "table"),
    [("archivey", "_MOVED_IN_0_6"), ("archivey.core", "_MOVED_IN_0_6")],
)
def test_a_type_checker_sees_every_moved_name(module_name: str, table: str) -> None:
    """The ``TYPE_CHECKING`` block imports each moved name from its new module.

    A type checker does not run ``__getattr__``, so without that block it types the
    old spelling as ``object`` and a typed caller fails at once instead of a release
    later.
    """
    module = importlib.import_module(module_name)
    assert module.__file__ is not None
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    seen: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
        ):
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom) and stmt.module:
                    for alias in stmt.names:
                        if alias.asname == alias.name:
                            seen[alias.name] = stmt.module
    assert seen == getattr(module, table)


@pytest.mark.parametrize("name", sorted(EXPERIMENTAL_MOVED))
def test_experimental_names_leave_the_root_at_once(name: str) -> None:
    with pytest.raises(AttributeError):
        getattr(archivey, name)


def test_a_root_name_does_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for name in ROOT_NAMES:
            getattr(archivey, name)


def test_an_unknown_name_is_still_an_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no_such_name"):
        archivey.no_such_name  # noqa: B018


def test_the_old_spelling_scan_sees_both_shims() -> None:
    text = (
        "archivey.DecoderLimits\nfrom archivey import (ReadError, open_archive)\n"
        "archivey.core.FormatSupport\nfrom archivey.core import ExtractionLimits\n"
        "archivey.core.open_archive\nfrom archivey.config import DecoderLimits\n"
    )
    assert _old_spellings(text) == [
        "archivey.DecoderLimits",
        "from archivey import ReadError",
        "archivey.core.FormatSupport",
        "from archivey.core import ExtractionLimits",
    ]


#: Each shimmed module and the names it still serves under their old spelling.
_SHIMS = {"archivey": MOVED, "archivey.core": CORE_MOVED}


def _old_spellings(text: str) -> list[str]:
    found: list[str] = []
    for module, moved in _SHIMS.items():
        dotted = re.escape(module)
        attr = re.compile(rf"(?<![\w.]){dotted}\.(" + "|".join(moved) + r")\b")
        found += [m.group(0) for m in attr.finditer(text)]
        for m in re.finditer(rf"from {dotted} import (\([^)]*\)|[^\n]*)", text):
            names = re.findall(r"\b(\w+)\b(?:\s+as\s+\w+)?", m.group(1).strip("()"))
            found += [f"from {module} import {n}" for n in names if n in moved]
    return found


_OLD_ANCHOR = re.compile(r'<span id="archivey\.\w+"></span>')


def test_the_repository_uses_only_the_new_spellings() -> None:
    """Code, tests, user docs and specs import each moved name from its submodule.

    The changelog is history, and this file names the old spellings on purpose. The
    API page's old-anchor spans keep the old spelling as an id on purpose too.
    """
    paths = [
        *(REPO / "src").rglob("*.py"),
        *(REPO / "tests").rglob("*.py"),
        *(REPO / "scripts").rglob("*.py"),
        *(REPO / "benchmarks").rglob("*.py"),
        *(REPO / "docs").rglob("*.md"),
        *(REPO / "openspec" / "specs").rglob("*.md"),
        REPO / "README.md",
    ]
    offenders = {
        str(path.relative_to(REPO)): hits
        for path in paths
        if path != Path(__file__)
        and (
            hits := _old_spellings(
                _OLD_ANCHOR.sub("", path.read_text(encoding="utf-8"))
            )
        )
    }
    assert offenders == {}


def test_the_api_page_keeps_each_moved_name_s_old_anchor() -> None:
    """A link to ``api/#archivey.<Name>`` from before 0.6 still lands on the entry: the
    page keeps an anchor with the old id beside each moved name's new heading. Which
    names have an entry at all is ``test_public_api.py``'s check."""
    page = (REPO / "docs" / "api.md").read_text(encoding="utf-8")
    missing = sorted(
        name
        for name, module in MOVED.items()
        if name not in EXPERIMENTAL_MOVED  # never served under the old spelling
        if f"\n::: {module}.{name}\n" in page
        if f'<span id="archivey.{name}"></span>\n\n::: {module}.{name}\n' not in page
    )
    assert missing == []
