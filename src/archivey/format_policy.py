"""Which format readers one open may use: :class:`FormatPolicy`.

A caller sets it as ``ArchiveyConfig(formats=FormatPolicy(...))``, per call, as it sets
``diagnostic_policy``. Detection still reports the true built-in format; the policy then
decides whether that format opens. A plugin format the policy turns off is left out of
detection altogether, so its code does not run and its signals cannot claim a file that
an allowed plugin matches.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from archivey.exceptions import _UsageTypeError, _UsageValueError
from archivey.internal.arg_checks import check_instance
from archivey.internal.enum_args import coerce_enum_collection
from archivey.internal.excluded_libraries import is_excluded_module
from archivey.internal.overrides import override
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    OptionalLibrary,
    PluginContainer,
    PluginStream,
    StreamFormat,
)

if TYPE_CHECKING:
    from archivey.formats import FormatHandler
    from archivey.types import OptionalLibraryStr

__all__ = ["FormatPolicy"]

# One entry of ``only`` or ``exclude``: a container or a compression, each half of an
# ArchiveFormat.
_FormatEntry = ContainerFormat | PluginContainer | StreamFormat | PluginStream

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
            f"{_CALL} takes a collection of ContainerFormat, PluginContainer, "
            f"StreamFormat and PluginStream members for {param}, got {values!r}."
        )
    entries: set[_FormatEntry] = set()
    for value in values:
        if isinstance(value, ArchiveFormat):
            raise _UsageTypeError(
                f"{_CALL} takes containers and compressions for {param}, not the "
                f"format {value!r}: pass {_entry_name(value.container)}, and "
                f"{_entry_name(value.stream)} for its compression."
            )
        if not isinstance(
            value, (ContainerFormat, PluginContainer, StreamFormat, PluginStream)
        ):
            raise _UsageTypeError(
                f"{_CALL} takes ContainerFormat, PluginContainer, StreamFormat and "
                f"PluginStream members for {param}, got {value!r} "
                f"({type(value).__name__})."
            )
        if value is ContainerFormat.UNKNOWN:
            raise _UsageValueError(
                f"{_CALL} got ContainerFormat.UNKNOWN in {param}, which names no "
                "format."
            )
        entries.add(value)
    return frozenset(entries)


# Standard library modules a caller may try to exclude. Core formats need them, so
# they are refused by name rather than as unknown spellings.
_STDLIB_CODECS = frozenset({"zlib", "bz2", "lzma"})


def _coerce_libraries(values: object) -> frozenset[OptionalLibrary]:
    """``exclude_libraries=`` as a frozenset of members, refusing any other name."""
    param = "exclude_libraries="
    if isinstance(values, OptionalLibrary):
        # A StrEnum member is a str, so the shared helper would call it a bare string.
        raise _UsageTypeError(
            f"{_CALL} takes a set of OptionalLibrary for {param}, but got the single "
            f"member OptionalLibrary.{values.name}. Pass a set, e.g. "
            f"{{OptionalLibrary.{values.name}}}."
        )
    if isinstance(values, Iterable) and not isinstance(values, (str, bytes)):
        stdlib = sorted(
            v for v in values if isinstance(v, str) and v.lower() in _STDLIB_CODECS
        )
        if stdlib:
            raise _UsageValueError(
                f"{_CALL} got {', '.join(map(repr, stdlib))} in {param}: the "
                "standard library codecs cannot be turned off, since core formats "
                "decode with them. Refuse the containers and compressions that "
                "carry them with only= or exclude= instead."
            )
    return coerce_enum_collection(values, OptionalLibrary, call=_CALL, param=param)


def _check_named_plugins(
    replace: Mapping[ContainerFormat, type[FormatHandler]],
    only: frozenset[_FormatEntry] | None,
    excluded: frozenset[OptionalLibrary],
) -> None:
    """Refuse a policy that names a plugin needing a package it excludes.

    The caller named that plugin, in ``replace=`` or by its container in ``only=``,
    so a policy that cannot use it is a mistake in the policy. A plugin registered
    after the policy is built is not checked here; its open refuses instead.
    """
    if not excluded:
        return
    named: list[tuple[str, type[FormatHandler]]] = [
        (f"replace= reads {_entry_name(container)} with", plugin)
        for container, plugin in replace.items()
    ]
    listed = {e for e in only or () if isinstance(e, PluginContainer)}
    if listed:
        # Imported here: the plugin adapter imports the config, which builds a default
        # policy as it loads.
        from archivey.internal.format_adapter import registered_plugins

        named.extend(
            (f"only= lists {_entry_name(plugin.format.container)}, read by", plugin)
            for plugin in registered_plugins()
            if plugin.format.container in listed
        )
    for where, plugin in named:
        clash = sorted(
            name for name in plugin.requires if is_excluded_module(name, excluded)
        )
        if clash:
            raise _UsageValueError(
                f"{_CALL} {where} {plugin.__name__}, which requires "
                f"{', '.join(clash)}, but exclude_libraries= turns "
                f"{'it' if len(clash) == 1 else 'them'} off. Drop the plugin or the "
                "exclusion."
            )


class _Replacements(Mapping[ContainerFormat, "type[FormatHandler]"]):
    """A read-only, hashable mapping, so a policy and the config holding it stay
    hashable as every other config field is."""

    __slots__ = ("_items",)

    def __init__(self, items: Mapping[ContainerFormat, type[FormatHandler]]) -> None:
        self._items = dict(items)

    @override
    def __getitem__(self, key: ContainerFormat) -> type[FormatHandler]:
        return self._items[key]

    @override
    def __iter__(self) -> Iterator[ContainerFormat]:
        return iter(self._items)

    @override
    def __len__(self) -> int:
        return len(self._items)

    @override
    def __hash__(self) -> int:
        return hash(frozenset(self._items.items()))

    @override
    def __repr__(self) -> str:
        return repr(self._items)


def _coerce_replacements(values: object) -> _Replacements:
    if not isinstance(values, Mapping):
        raise _UsageTypeError(
            f"{_CALL} takes a mapping of ContainerFormat to FormatHandler subclass for "
            f"replace=, got {values!r}."
        )
    if values:
        # Imported here, and only when there is something to check: the plugin adapter
        # imports the config, which builds a default policy as it loads.
        from archivey.internal.format_adapter import check_replacement

        for container, plugin in values.items():
            check_replacement(container, plugin)
    return _Replacements(values)


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

    :func:`~archivey.open_archive` and :func:`~archivey.open_stream` refuse a format
    the policy does not allow with :class:`~archivey.UnsupportedFeatureError`,
    whose message names every entry to change; ``format=`` does not bypass the policy.
    :func:`~archivey.detect_format` reports the true format of a built-in file whatever
    the policy says, so a caller can check :meth:`allows` before opening. A plugin
    format or codec the policy turns off is not detected at all: its magic, extensions and
    content probe are left out of that call, and the detection receipt records each
    tier that left one out as ``NOT_ENABLED_BY_POLICY``.

    Otherwise the policy decides which reader runs, not what detection reads: magic,
    the self-extracting archive scan and the built-in content probes still run on every
    input, within ``ArchiveyConfig.detection_budget``. The one exception is a content
    probe whose format needs a package ``exclude_libraries`` turns off, which does not
    run, so the package is not called.

    ``replace=`` reads a built-in container with a plugin instead of the built-in
    reader (see :attr:`replace`)::

        MY_ZIP = ArchiveyConfig(formats=FormatPolicy(replace={C.ZIP: MyZipPlugin}))
    """

    only: (
        frozenset[ContainerFormat | PluginContainer | StreamFormat | PluginStream]
        | None
    )
    """The containers and compressions that may open, or ``None`` for all of them."""

    exclude: frozenset[ContainerFormat | PluginContainer | StreamFormat | PluginStream]
    """The containers and compressions that may not open."""

    plugins: bool
    """Whether registered plugin formats and plugin codecs may open. Use ``False``
    with ``exclude``; under ``only`` a plugin opens only when its container (or its
    :class:`~archivey.PluginStream`, for a codec) is listed.

    Stable, unlike the experimental plugin interface it refuses: ``plugins=False``
    keeps working whatever happens to that interface."""

    replace: Mapping[ContainerFormat, type[FormatHandler]]
    """Built-in containers read by a plugin instead of the built-in reader.

    Experimental, with ``archivey.formats``: any release may change it.

    A key is ``ContainerFormat.ZIP``, ``SEVEN_Z``, ``RAR``, ``ISO`` or ``SQUASHFS``.
    Its plugin is a ``archivey.formats.FormatHandler`` that is not registered: its
    ``format`` is the built-in one (``ArchiveFormat.ZIP``), and it declares no
    ``extensions``, ``magic`` or ``probe``, because the file is found by the built-in
    detection. The reader's ``format`` is the built-in format and ``format_info.from_plugin`` is
    false. The plugin gets what any indexed plugin gets, a seekable source from the
    start of the archive, so a multi-volume set and an archive behind a
    self-extracting stub are refused with :class:`~archivey.UnsupportedFeatureError`,
    a source that cannot seek with :class:`~archivey.StreamNotSeekableError`, and a
    raw CD sector image detected as ISO as the built-in reader refuses it. The
    format's own ``ArchiveyConfig`` options reach the plugin through
    ``ReaderContext.config``."""

    exclude_libraries: frozenset[OptionalLibrary]
    """Optional packages that read as not installed in this call.

    Each entry is an :class:`~archivey.OptionalLibrary` member or its value, such as
    ``"pyppmd"``; any other name is refused when the policy is built. An excluded
    package decodes nothing in the call, and one that archivey imports on first use
    (``brotli``, ``pyppmd``, ``inflate64``, ``rapidgzip``) is not imported for it. What
    happens is what happens when the package is missing: an accelerator under ``AUTO``
    falls back to the standard library, a member that needs it raises
    :class:`~archivey.PackageNotInstalledError` when opened, and a format that needs
    it refuses at open. The error's ``missing`` names the package with this setting as
    its ``reason``. :func:`~archivey.format_availability` answers for it when passed
    the config. Other calls in the process, on any thread, are unaffected.

    archivey uses one zstd module per process, ``compression.zstd`` where it imports
    and ``backports.zstd`` otherwise; excluding that module turns zstd off, and
    excluding the other changes nothing. ``zlib``, ``bz2`` and ``lzma`` cannot be
    excluded. A policy that names a plugin (in ``replace=``, or by its container in
    ``only=``) whose ``requires`` lists an excluded package is refused."""

    # A hand-written __init__, as DiagnosticPolicy has: the parameters take any
    # iterable, and the fields always hold frozensets.
    def __init__(
        self,
        *,
        only: Iterable[ContainerFormat | PluginContainer | StreamFormat | PluginStream]
        | None = None,
        exclude: Iterable[
            ContainerFormat | PluginContainer | StreamFormat | PluginStream
        ] = (),
        plugins: bool = True,
        replace: Mapping[ContainerFormat, type[FormatHandler]] | None = None,
        exclude_libraries: Iterable[OptionalLibrary | OptionalLibraryStr] = (),
    ) -> None:
        only_parsed = None if only is None else _coerce_entries(only, param="only=")
        exclude_parsed = _coerce_entries(exclude, param="exclude=")
        check_instance(plugins, bool, call="FormatPolicy(plugins=…)", allow_none=False)
        if StreamFormat.UNCOMPRESSED in exclude_parsed:
            raise _UsageValueError(
                f"{_CALL} got StreamFormat.UNCOMPRESSED in exclude=, which would turn "
                "off every container (ZIP, TAR, 7z and the rest) and directories alike. "
                "List the containers to refuse instead."
            )
        if only_parsed is not None:
            both = only_parsed & exclude_parsed
            if both:
                names = ", ".join(sorted(_entry_name(e) for e in both))
                raise _UsageValueError(
                    f"{_CALL} got entries in both only= and exclude=: {names}."
                )
            listed_plugins = [
                e for e in only_parsed if isinstance(e, (PluginContainer, PluginStream))
            ]
            if listed_plugins and not plugins:
                names = ", ".join(sorted(_entry_name(e) for e in listed_plugins))
                raise _UsageValueError(
                    f"{_CALL} lists the plugin formats {names} in only= but sets "
                    "plugins=False. Drop one of the two."
                )
        replace_parsed = _coerce_replacements({} if replace is None else replace)
        for container in replace_parsed:
            if container in exclude_parsed or (
                only_parsed is not None and container not in only_parsed
            ):
                raise _UsageValueError(
                    f"{_CALL} replaces {_entry_name(container)} but only= or exclude= "
                    "turns it off. Allow the container, or drop the replacement."
                )
        libraries = _coerce_libraries(exclude_libraries)
        _check_named_plugins(replace_parsed, only_parsed, libraries)
        object.__setattr__(self, "replace", replace_parsed)
        object.__setattr__(self, "exclude_libraries", libraries)
        object.__setattr__(self, "only", only_parsed)
        object.__setattr__(self, "exclude", exclude_parsed)
        object.__setattr__(self, "plugins", plugins)

    def _replacement_for(self, fmt: ArchiveFormat) -> type[FormatHandler] | None:
        """The plugin :attr:`replace` names to read ``fmt``, else ``None``.

        The one place that answers it: the open's refusals for a replacement and the
        reader it opens with both follow this answer.
        """
        container = fmt.container
        if not isinstance(container, ContainerFormat):
            return None
        plugin = self.replace.get(container)
        return plugin if plugin is not None and plugin.format == fmt else None

    def allows(self, fmt: ArchiveFormat) -> bool:
        """Whether ``fmt`` may open under this policy."""
        return self._refusal(fmt) is None

    def _refusal(self, fmt: ArchiveFormat) -> str | None:
        """The refusal text for ``fmt``, naming every entry to change, or ``None``."""
        reasons = self._reasons(fmt)
        if not reasons:
            return None
        return (
            f"ArchiveyConfig.formats does not allow {fmt.display_name}: "
            f"{', and '.join(reasons)}."
        )

    def _reasons(self, fmt: ArchiveFormat) -> list[str]:
        """Why ``fmt`` is refused, one reason per setting to change, so a format that
        fails on both halves names both in one refusal."""
        reasons: list[str] = []
        unlisted: list[_FormatEntry] = []
        container = fmt.container
        if isinstance(container, PluginContainer) and not self.plugins:
            reasons.append("plugins=False turns off every plugin format")
        elif container in self.exclude:
            reasons.append(f"exclude= lists {_entry_name(container)}")
        elif self.only is not None and container not in self.only:
            unlisted.append(container)
        stream = fmt.stream
        if isinstance(stream, PluginStream) and not self.plugins:
            reasons.append("plugins=False turns off every plugin codec")
        elif stream is not StreamFormat.UNCOMPRESSED:
            if stream in self.exclude:
                reasons.append(f"exclude= lists {_entry_name(stream)}")
            elif self.only is not None and stream not in self.only:
                unlisted.append(stream)
        if unlisted:
            names = " or ".join(_entry_name(e) for e in unlisted)
            pronoun = "it" if len(unlisted) == 1 else "them"
            reasons.append(f"only= does not list {names}; add {pronoun} to open this")
        return reasons

    @property
    def _turns_off_plugins(self) -> bool:
        """Whether some plugin format could be off: the cheap test detection makes
        before it filters each plugin signal through :meth:`allows`."""
        return not self.plugins or self.only is not None or bool(self.exclude)
