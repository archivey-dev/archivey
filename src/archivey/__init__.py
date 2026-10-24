"""Archivey — Python library for reading, streaming, and safely extracting archives.

Public surface layout (this package root only — not ``internal`` / ``cli``):

- :mod:`archivey.core` — ``open_archive`` / ``open_stream`` / detection
- :mod:`archivey.reader` — ``ArchiveReader`` / ``ForwardArchiveReader`` ABCs
- :mod:`archivey.types` — formats, members, compression, extraction policies/results,
  format availability
- :mod:`archivey.detection` — ``FormatInfo`` / ``DetectionConfidence``
- :mod:`archivey.config` — ``ArchiveyConfig``, limits, passwords, accelerators
- :mod:`archivey.cost` — listing/access cost receipt
- :mod:`archivey.diagnostics` — advisory codes, summaries, extraction reports
- :mod:`archivey.exceptions` — error hierarchy
- :mod:`archivey.detection_cost` — detection budgets and receipts; public, not re-exported
- :mod:`archivey.terminal` — terminal-safe display helpers; public, not re-exported

Names in ``__all__`` are the documented API, and the root exposes no other public
name apart from submodules. Niche names, such as the ``*Context`` diagnostic payloads
and the ``*_AUTO_MIN_COMPRESSED_SIZE`` thresholds, are available only from their
submodule (:mod:`archivey.diagnostics`, :mod:`archivey.config`).
"""

# Declared here so type checkers see a ``str``; the value comes from the module
# ``__getattr__`` at the end of this file, on first access.
__version__: str

from archivey.config import (
    DEFAULT_ARCHIVEY_CONFIG,
    AcceleratorMode,
    ArchiveyConfig,
    DecoderLimits,
    ExtractionLimits,
    ListingLimits,
    PasswordInput,
    PasswordProvider,
    PasswordRequest,
    ProcessIsolation,
    RarDecompressor,
    SpoolLimits,
)
from archivey.core import (
    detect_format,
    format_availability,
    list_known_formats,
    list_supported_formats,
    open_archive,
    open_stream,
)
from archivey.cost import (
    AccessCost,
    CostReceipt,
    ListingCost,
    StreamCapability,
)
from archivey.detection import DetectionConfidence, FormatInfo
from archivey.diagnostics import (
    ARCHIVE_INTEGRITY_CODES,
    Diagnostic,
    DiagnosticCode,
    DiagnosticContext,
    DiagnosticPolicy,
    DiagnosticSummary,
    ExtractionReport,
    MemberListReport,
    OnDiagnostic,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    DiagnosticRaisedError,
    EncryptionError,
    ExtractionError,
    FilterRejectionError,
    FormatDetectionError,
    LinkTargetNotFoundError,
    LinkTargetNotFoundReason,
    NameCollisionError,
    NameRewrittenError,
    OpenError,
    PackageNotInstalledError,
    ReadError,
    ResourceLimitError,
    ResourceUnavailableError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.filters import sanitize_names
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.reader import (
    ArchiveReader,
    ForwardArchiveReader,
    MemberPass,
    MemberSelector,
)
from archivey.types import (
    AbortOn,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    ContainerFormat,
    CreateSystem,
    ExtractionPolicy,
    ExtractionProgress,
    ExtractionResult,
    ExtractionStatus,
    FormatAvailability,
    FormatSupport,
    HashAlgorithm,
    MemberExtra,
    MemberFilter,
    MemberType,
    MissingComponent,
    NameRewrite,
    OnError,
    OverwritePolicy,
    StreamFormat,
    Verification,
)

__all__ = [
    "ARCHIVE_INTEGRITY_CODES",
    "DEFAULT_ARCHIVEY_CONFIG",
    "AbortOn",
    "AcceleratorMode",
    "AccessCost",
    "ArchiveFormat",
    "ArchiveInfo",
    "ArchiveInfoExtra",
    "ArchiveMember",
    "ArchiveReader",
    "ArchiveStream",
    "ArchiveyConfig",
    "ArchiveyError",
    "ArchiveyUsageError",
    "CompressionAlgorithm",
    "CompressionMethod",
    "ContainerFormat",
    "CorruptionError",
    "CostReceipt",
    "CreateSystem",
    "DecoderLimits",
    "DetectionConfidence",
    "Diagnostic",
    "DiagnosticCode",
    "DiagnosticContext",
    "DiagnosticPolicy",
    "DiagnosticRaisedError",
    "DiagnosticSummary",
    "EncryptionError",
    "ExtractionError",
    "ExtractionLimits",
    "ExtractionPolicy",
    "ExtractionProgress",
    "ExtractionReport",
    "ExtractionResult",
    "ExtractionStatus",
    "FilterRejectionError",
    "FormatAvailability",
    "FormatDetectionError",
    "FormatInfo",
    "FormatSupport",
    "ForwardArchiveReader",
    "HashAlgorithm",
    "LinkTargetNotFoundError",
    "LinkTargetNotFoundReason",
    "ListingCost",
    "ListingLimits",
    "MemberExtra",
    "MemberFilter",
    "MemberListReport",
    "MemberPass",
    "MemberSelector",
    "MemberType",
    "MissingComponent",
    "NameCollisionError",
    "NameRewrite",
    "NameRewrittenError",
    "OnDiagnostic",
    "OnError",
    "OpenError",
    "OverwritePolicy",
    "PackageNotInstalledError",
    "PasswordInput",
    "PasswordProvider",
    "PasswordRequest",
    "ProcessIsolation",
    "RarDecompressor",
    "ReadError",
    "ResourceLimitError",
    "ResourceUnavailableError",
    "SpoolLimits",
    "StreamCapability",
    "StreamFormat",
    "StreamNotSeekableError",
    "TruncatedError",
    "UnsupportedFeatureError",
    "Verification",
    "__version__",
    "detect_format",
    "format_availability",
    "list_known_formats",
    "list_supported_formats",
    "open_archive",
    "open_stream",
    "sanitize_names",
]

# Eager backend registration so list_supported_formats / format_availability work
# immediately after `import archivey` (open_archive also imports as a safety net).
# Aliased so the statement does not bind `archivey` on itself: a plain
# `import archivey.internal.backends` puts `archivey.archivey` on the package root.
import archivey.internal.backends as _backends  # noqa: F401


def _pin_public_module() -> None:
    """Report ``archivey`` as the module of every public name defined under ``internal``.

    Public data types are defined in public modules (:mod:`archivey.types`,
    :mod:`archivey.detection`, …), so their ``__module__`` is already a stable path and
    this leaves them alone. Six names in ``__all__`` are still defined under
    ``archivey.internal``: ``ArchiveStream`` (an implementation class on the internal
    stream base, never pickled) and five functions (``detect_format``, the three
    registry queries and ``sanitize_names``). ``pickle`` records a class's or function's
    ``__module__``, so a persisted reference to one would otherwise name an internal path
    that could then never move without breaking the caller's data. Pinned here, it names
    ``archivey``, which is stable, and ``repr()``, ``help()`` and ``inspect.getmodule``
    say the same. The internal layout stays free to change; ``internal`` imports still
    see the same objects.

    The pin is the safety net, not the design: a new public class belongs in a public
    module, and ``tests/test_public_api.py`` fails on one defined under ``internal``
    other than ``ArchiveStream``.

    Computed over ``__all__`` rather than listed, so a name added later is covered too.
    Only classes and functions: an instance reports its class's module, and pinning it
    would set an attribute on the instance (or fail, on a frozen dataclass).

    Two lookups go through a class's ``__module__`` and would follow the pin to the
    wrong namespace:

    - **Annotations.** Under ``from __future__ import annotations`` a class's hints are
      strings, evaluated against ``sys.modules[cls.__module__]``, where ``Path`` or
      ``DetectionCostReceipt`` are not names. So each class's own hints are resolved
      *before* the pin, and ``typing.get_type_hints`` keeps working. A hint that cannot
      resolve here (a ``TYPE_CHECKING``-only name, or an attribute of such a module) is
      left as it was rather than failing the import; ``tests/test_public_api.py``
      catches it instead.
    - **Source.** ``inspect.getsource`` finds a class's file through its module, and
      there is no way to point it elsewhere. On a pinned class it raises ``OSError``;
      ``__firstlineno__`` is dropped so Python 3.13+ raises too, instead of returning
      lines of this file. Functions are unaffected: they carry their own code object.
    """
    import typing
    from types import FunctionType

    namespace = globals()
    for name in __all__:
        if name == "__version__":
            continue  # a str, and not bound until first access (``__getattr__`` below)
        obj = namespace[name]
        if not isinstance(obj, (type, FunctionType)):
            continue
        if not obj.__module__.startswith("archivey.internal"):
            continue
        if isinstance(obj, type):
            # Own annotations only, without importing inspect at import time.
            own = obj.__dict__.get("__annotations__")  # noqa: RUF063
            if own:
                try:
                    hints = typing.get_type_hints(obj, include_extras=True)
                except (NameError, AttributeError):
                    pass
                else:
                    obj.__annotations__ = {key: hints[key] for key in own}
            if "__firstlineno__" in obj.__dict__:
                delattr(obj, "__firstlineno__")
        obj.__module__ = __name__


_pin_public_module()
del _pin_public_module


def __getattr__(name: str) -> object:
    """Compute ``__version__`` on first access (PEP 562).

    ``importlib.metadata`` is a measurable part of ``import archivey`` on a core-only
    install, for a string most callers never read. (Some optional codec packages import
    it for their own version, so with those installed the saving is smaller.) The value
    is cached in the module globals, so this runs once; the import stays inside the
    function so nothing from it reaches the public namespace.
    """
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            value = version("archivey")
        except PackageNotFoundError:
            value = "0.0.0+unknown"
        globals()["__version__"] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
