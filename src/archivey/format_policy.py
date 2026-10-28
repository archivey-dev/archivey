"""Which format readers one open may use: :class:`FormatPolicy`.

A caller sets it as ``ArchiveyConfig(formats=FormatPolicy(...))``, per call, as it sets
``diagnostic_policy``. Detection still reports the true built-in format; the policy then
decides whether that format opens. A plugin format the policy turns off is left out of
detection altogether, so its code does not run and its signals cannot claim a file that
an allowed plugin matches.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from archivey.exceptions import _UsageTypeError, _UsageValueError
from archivey.internal.arg_checks import check_instance
from archivey.types import ArchiveFormat, ContainerFormat, PluginContainer, StreamFormat

__all__ = ["FormatPolicy"]

# One entry of ``only`` or ``exclude``: a container or a compression, each half of an
# ArchiveFormat.
_FormatEntry = ContainerFormat | PluginContainer | StreamFormat

_CALL = "FormatPolicy()"


def _entry_name(entry: _FormatEntry) -> str:
    return f"{type(entry).__name__}.{entry.name}"


def _coerce_entries(values: object, *, param: str) -> frozenset[_FormatEntry]:
    """``values`` as a frozenset of members, refusing anything that is not one.

    Members only, not their string spellings: ``"zip"`` would name a container and
    ``"gz"`` a compression, so a string cannot say which half of the format it is.
    """
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise _UsageTypeError(
            f"{_CALL} takes a collection of ContainerFormat, PluginContainer and "
            f"StreamFormat members for {param}, got {values!r}."
        )
    entries: set[_FormatEntry] = set()
    for value in values:
        if isinstance(value, ArchiveFormat):
            raise _UsageTypeError(
                f"{_CALL} takes containers and compressions for {param}, not the "
                f"format {value!r}: pass {_entry_name(value.container)}, and "
                f"{_entry_name(value.stream)} for its compression."
            )
        if not isinstance(value, (ContainerFormat, PluginContainer, StreamFormat)):
            raise _UsageTypeError(
                f"{_CALL} takes ContainerFormat, PluginContainer and StreamFormat "
                f"members for {param}, got {value!r} ({type(value).__name__})."
            )
        if value is ContainerFormat.UNKNOWN:
            raise _UsageValueError(
                f"{_CALL} got ContainerFormat.UNKNOWN in {param}, which names no "
                "format."
            )
        entries.add(value)
    return frozenset(entries)


@dataclass(frozen=True, init=False)
class FormatPolicy:
    """Which formats one call may open.

    Set it on :attr:`ArchiveyConfig.formats <archivey.ArchiveyConfig.formats>`::

        # ZIP, and TAR with or without gzip or xz. Nothing else opens.
        UPLOADS = ArchiveyConfig(
            formats=FormatPolicy(only={C.ZIP, C.TAR, S.GZIP, S.XZ})
        )
        # Everything except RAR, and no plugin formats.
        NO_RAR = ArchiveyConfig(formats=FormatPolicy(exclude={C.RAR}, plugins=False))

    An :class:`~archivey.ArchiveFormat` is a container and a compression, and both
    halves must pass. ``only={C.TAR}`` refuses ``.tar.gz`` until ``S.GZIP`` is listed
    too; ``StreamFormat.UNCOMPRESSED`` always passes. The default policy allows every
    format.

    :func:`~archivey.open_archive`, :func:`~archivey.open_stream` and the CLI refuse a
    format the policy does not allow with :class:`~archivey.UnsupportedFeatureError`,
    whose message names the entry to change; ``format=`` does not bypass the policy.
    :func:`~archivey.detect_format` reports the true format of a built-in file whatever
    the policy says, so a caller can check :meth:`allows` before opening. A plugin
    format the policy turns off is not detected at all: its magic, extensions and
    content probe are left out of that call, and the detection receipt records each
    tier that left one out as ``NOT_ENABLED_BY_POLICY``.

    The policy decides which reader runs, not what detection reads: magic, the
    self-extracting archive scan and the built-in content probes still run on every
    input, within ``ArchiveyConfig.detection_budget``.
    """

    only: frozenset[ContainerFormat | PluginContainer | StreamFormat] | None
    """The containers and compressions that may open, or ``None`` for all of them."""

    exclude: frozenset[ContainerFormat | PluginContainer | StreamFormat]
    """The containers and compressions that may not open."""

    plugins: bool
    """Whether registered plugin formats may open. Use ``False`` with ``exclude``;
    under ``only`` a plugin opens only when its container is listed."""

    # A hand-written __init__, as DiagnosticPolicy has: the parameters take any
    # iterable, and the fields always hold frozensets.
    def __init__(
        self,
        *,
        only: Iterable[ContainerFormat | PluginContainer | StreamFormat] | None = None,
        exclude: Iterable[ContainerFormat | PluginContainer | StreamFormat] = (),
        plugins: bool = True,
    ) -> None:
        only_parsed = None if only is None else _coerce_entries(only, param="only=")
        exclude_parsed = _coerce_entries(exclude, param="exclude=")
        check_instance(plugins, bool, call="FormatPolicy(plugins=…)", allow_none=False)
        if StreamFormat.UNCOMPRESSED in exclude_parsed:
            raise _UsageValueError(
                f"{_CALL} got StreamFormat.UNCOMPRESSED in exclude=, which would turn "
                "off ZIP, TAR, 7z, RAR, ISO and directories alike. List the containers "
                "to refuse instead."
            )
        if only_parsed is not None:
            both = only_parsed & exclude_parsed
            if both:
                names = ", ".join(sorted(_entry_name(e) for e in both))
                raise _UsageValueError(
                    f"{_CALL} got entries in both only= and exclude=: {names}."
                )
            listed_plugins = [e for e in only_parsed if isinstance(e, PluginContainer)]
            if listed_plugins and not plugins:
                names = ", ".join(sorted(_entry_name(e) for e in listed_plugins))
                raise _UsageValueError(
                    f"{_CALL} lists the plugin containers {names} in only= but sets "
                    "plugins=False. Drop one of the two."
                )
        object.__setattr__(self, "only", only_parsed)
        object.__setattr__(self, "exclude", exclude_parsed)
        object.__setattr__(self, "plugins", plugins)

    def allows(self, fmt: ArchiveFormat) -> bool:
        """Whether ``fmt`` may open under this policy."""
        return self._refusal(fmt) is None

    def _refusal(self, fmt: ArchiveFormat) -> str | None:
        """The refusal text for ``fmt``, naming the entry to change, or ``None``."""
        reason = self._reason(fmt)
        if reason is None:
            return None
        return f"ArchiveyConfig.formats does not allow {fmt.display_name}: {reason}."

    def _reason(self, fmt: ArchiveFormat) -> str | None:
        container = fmt.container
        if isinstance(container, PluginContainer) and not self.plugins:
            return "plugins=False turns off every plugin format"
        if container in self.exclude:
            return f"exclude= lists {_entry_name(container)}"
        if self.only is not None and container not in self.only:
            return f"only= does not list {_entry_name(container)}; add it to open this"
        stream = fmt.stream
        if stream is StreamFormat.UNCOMPRESSED:
            return None
        if stream in self.exclude:
            return f"exclude= lists {_entry_name(stream)}"
        if self.only is not None and stream not in self.only:
            return f"only= does not list {_entry_name(stream)}; add it to open this"
        return None

    @property
    def _turns_off_plugins(self) -> bool:
        """Whether some plugin format could be off: the cheap test detection makes
        before it filters each plugin signal through :meth:`allows`."""
        return not self.plugins or self.only is not None or bool(self.exclude)
