"""Archivey — Python library for reading, streaming, and safely extracting archives.

The public API has two tiers. The names most callers need are importable from
``archivey`` itself and listed in ``__all__``: the entry functions, the reader, member,
format and report types, the configuration and policy types, and the errors callers
catch most. Every other public name is imported from the submodule that defines it:

- :mod:`archivey.core` — ``open_archive`` / ``open_stream`` / detection and the format
  registry queries
- :mod:`archivey.reader` — ``ArchiveReader`` / ``ForwardArchiveReader`` ABCs and the
  member selection types
- :mod:`archivey.types` — formats, members, compression, extraction policies/results,
  format availability
- :mod:`archivey.detection` — ``FormatInfo`` / ``DetectionConfidence``
- :mod:`archivey.config` — ``ArchiveyConfig``, limits, passwords, accelerators
- :mod:`archivey.cost` — listing/access cost receipt
- :mod:`archivey.diagnostics` — advisory codes, summaries, extraction reports
- :mod:`archivey.exceptions` — the whole error hierarchy
- :mod:`archivey.format_policy` — ``FormatPolicy``, which formats one open may use
- :mod:`archivey.detection_cost` — detection budgets and receipts
- :mod:`archivey.terminal` — terminal-safe display helpers
- :mod:`archivey.paths` — destination naming, member globs and ``sanitize_names``
- :mod:`archivey.formats` — the experimental interface for adding formats

Each submodule's ``__all__`` lists its public names, with the same compatibility promise
as the root's. The root exposes no other public name apart from submodules. A name that
left the root in 0.6.0 still works as ``archivey.<name>`` for the 0.6 series, with a
``DeprecationWarning`` that names its submodule; 0.7.0 removes that spelling.
"""

# Declared here so type checkers see a ``str``; the value comes from the module
# ``__getattr__`` at the end of this file, on first access.
__version__: str

from archivey.config import ArchiveyConfig
from archivey.core import detect_format, format_availability, open_archive, open_stream
from archivey.diagnostics import (
    Diagnostic,
    DiagnosticCode,
    DiagnosticPolicy,
    ExtractionReport,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    EncryptionError,
    FormatDetectionError,
    PackageNotInstalledError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.format_policy import FormatPolicy
from archivey.reader import ArchiveReader, ArchiveStream, ForwardArchiveReader
from archivey.types import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    ContainerFormat,
    ExtractionPolicy,
    MemberType,
    OnProblem,
    StreamFormat,
)

__all__ = [
    "ArchiveFormat",
    "ArchiveInfo",
    "ArchiveMember",
    "ArchiveReader",
    "ArchiveStream",
    "ArchiveyConfig",
    "ArchiveyError",
    "ArchiveyUsageError",
    "ContainerFormat",
    "CorruptionError",
    "Diagnostic",
    "DiagnosticCode",
    "DiagnosticPolicy",
    "EncryptionError",
    "ExtractionPolicy",
    "ExtractionReport",
    "FormatDetectionError",
    "FormatPolicy",
    "ForwardArchiveReader",
    "MemberType",
    "OnProblem",
    "PackageNotInstalledError",
    "ResourceLimitError",
    "StreamFormat",
    "TruncatedError",
    "UnsupportedFeatureError",
    "__version__",
    "detect_format",
    "format_availability",
    "open_archive",
    "open_stream",
]

# Eager backend registration so list_supported_formats / format_availability work
# immediately after `import archivey` (open_archive also imports as a safety net).
# Aliased so the statement does not bind `archivey` on itself: a plain
# `import archivey.internal.backends` puts `archivey.archivey` on the package root.
import archivey.internal.backends as _backends  # noqa: F401

#: The names that left the root in 0.6.0, and the submodule each is imported from now.
#: ``__getattr__`` below still serves them, with a ``DeprecationWarning``, for the 0.6
#: series (DR-12a); 0.7.0 deletes this table. ``PluginContainer`` and ``PluginStream``
#: are experimental, so they left with no deprecation release and are not here.
_MOVED_IN_0_6: dict[str, str] = {
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
    "SourceProgress": "archivey.types",
    "Verification": "archivey.types",
}


def _pin_public_module() -> None:
    """Report a public module as the module of every public function defined under ``internal``.

    Public classes are defined in public modules (:mod:`archivey.reader`,
    :mod:`archivey.types`, :mod:`archivey.detection`, …), so their ``__module__`` is
    already a stable path and this leaves them alone. Five public functions are still
    defined under ``archivey.internal``: ``detect_format``, the three registry queries
    and ``sanitize_names``. ``pickle`` records a function's ``__module__``, so a
    persisted reference to one would otherwise name an internal path that could then
    never move without breaking the caller's data. Pinned here, it names the public
    module that exports it, the root first, which is stable, and ``repr()``, ``help()``
    and ``inspect.getmodule`` say the same. The internal layout stays free to change;
    ``internal`` imports still see the same objects.

    Computed over each public module's ``__all__`` rather than listed, so a function
    added later is covered too. Classes are not pinned: a class's string annotations
    and ``inspect.getsource`` both go through its ``__module__``, and a pin would send
    them to the wrong namespace. A public class belongs in a public module, and
    ``tests/test_public_api.py`` fails on one defined under ``internal``.
    """
    import sys
    from types import FunctionType

    import archivey.core
    import archivey.paths

    for module in (sys.modules[__name__], archivey.core, archivey.paths):
        for name in module.__all__:
            if name == "__version__":
                continue  # a str, and not bound until first access (``__getattr__``)
            obj = vars(module)[name]
            if isinstance(obj, FunctionType) and obj.__module__.startswith(
                "archivey.internal"
            ):
                obj.__module__ = module.__name__


_pin_public_module()
del _pin_public_module


def _bind_annotation_names() -> None:
    """Give the modules that import a public annotation's type only for type checking
    that type at runtime, so ``typing.get_type_hints`` resolves every public signature.

    These modules import each other, so the names cannot be imported at the top of the
    module: ``types`` and ``diagnostics`` raise ``exceptions``' errors, and
    ``exceptions`` names their classes in its constructors; ``diagnostics`` builds on
    ``types``' classes, and ``ArchiveMember.diagnostics`` returns ``Diagnostic``. This
    is the one place such names are bound, once every module has loaded; a module with
    no cycle imports its annotation types directly. ``tests/test_public_annotations.py``
    fails when a new public annotation needs one.
    """
    import archivey.exceptions as exceptions_module
    import archivey.types as types_module
    from archivey.diagnostics import Diagnostic, ExtractionReport
    from archivey.types import ArchiveFormat, MemberType, MissingComponent

    bindings = {
        exceptions_module: (
            Diagnostic,
            ExtractionReport,
            ArchiveFormat,
            MemberType,
            MissingComponent,
        ),
        types_module: (Diagnostic,),
    }
    for module, names in bindings.items():
        for obj in names:
            vars(module).setdefault(obj.__name__, obj)


_bind_annotation_names()
del _bind_annotation_names


def __getattr__(name: str) -> object:
    """Compute ``__version__`` on first access, and serve the moved names (PEP 562).

    A name in ``_MOVED_IN_0_6`` is imported from its submodule and returned with a
    ``DeprecationWarning`` that names the new import. ``stacklevel=2`` attributes it to
    the caller's line, for ``archivey.Name`` and ``from archivey import Name`` alike.
    The value is not cached in the module globals, so every use warns.

    ``importlib.metadata`` is a measurable part of ``import archivey`` on a core-only
    install, for a string most callers never read. (Some optional codec packages import
    it for their own version, so with those installed the saving is smaller.) The
    version is cached in the module globals, so this runs once; the import stays inside
    the function so nothing from it reaches the public namespace.
    """
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            value = version("archivey")
        except PackageNotFoundError:
            value = "0.0.0+unknown"
        globals()["__version__"] = value
        return value
    module_name = _MOVED_IN_0_6.get(name)
    if module_name is not None:
        import importlib
        import warnings

        warnings.warn(
            f"archivey.{name} is deprecated; use {module_name}.{name} "
            f"(from {module_name} import {name}). archivey 0.7.0 removes the old "
            "spelling.",
            DeprecationWarning,
            stacklevel=2,
        )
        return getattr(importlib.import_module(module_name), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
