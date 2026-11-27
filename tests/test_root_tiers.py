"""The two tiers of the public namespace (0.6.0).

The package root keeps the names most callers need: the entry functions, the reader,
member, format, policy and report types, and the errors callers catch most. Every other
public name lives in the submodule that defines it (DR-13). A name that left the root
in 0.6.0 still works as ``archivey.<name>`` for the 0.6 series, with a
``DeprecationWarning`` that names the new import (DR-12a); 0.7.0 removes it.
"""

from __future__ import annotations

import importlib
import re
import warnings
from pathlib import Path

import pytest

import archivey

REPO = Path(__file__).resolve().parents[1]

#: The root names the maintainer chose on 2026-11-27, with ``OnProblem``, the
#: extraction setting that replaces ``on_error``, ``on_blocked`` and ``abort_on``.
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
        "OnProblem",
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
    # stacklevel=2: the warning points at the caller's line, not at archivey.
    assert caught[0].filename == __file__


def test_from_import_of_a_moved_name_warns_at_the_import_line() -> None:
    with pytest.warns(
        DeprecationWarning, match=r"archivey\.config\.DecoderLimits"
    ) as caught:
        from archivey import DecoderLimits  # noqa: F401
    assert caught[0].filename == __file__


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


_OLD_ATTR = re.compile(r"(?<![\w.])archivey\.(" + "|".join(MOVED) + r")\b")


def _old_spellings(text: str) -> list[str]:
    found = [m.group(0) for m in _OLD_ATTR.finditer(text)]
    for m in re.finditer(r"from archivey import (\([^)]*\)|[^\n]*)", text):
        names = re.findall(r"\b(\w+)\b(?:\s+as\s+\w+)?", m.group(1).strip("()"))
        found += [f"from archivey import {n}" for n in names if n in MOVED]
    return found


def test_the_repository_uses_only_the_new_spellings() -> None:
    """Code, tests and user docs import each moved name from its submodule.

    The changelog is history, and this file names the old spellings on purpose.
    """
    paths = [
        *(REPO / "src").rglob("*.py"),
        *(REPO / "tests").rglob("*.py"),
        *(REPO / "scripts").rglob("*.py"),
        *(REPO / "benchmarks").rglob("*.py"),
        *(REPO / "docs").rglob("*.md"),
        REPO / "README.md",
    ]
    offenders = {
        str(path.relative_to(REPO)): hits
        for path in paths
        if path != Path(__file__)
        and (hits := _old_spellings(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}
