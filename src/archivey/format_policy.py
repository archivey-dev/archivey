"""Which format readers one open may use: :class:`FormatPolicy`.

A caller sets it as ``ArchiveyConfig(formats=FormatPolicy(...))``, per call, as it sets
``diagnostic_policy``. Detection still reports the true built-in format; the policy then
decides whether that format opens. A plugin format the policy turns off is left out of
detection altogether, so its code does not run and its signals cannot claim a file that
an allowed plugin matches.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, cast

from archivey.exceptions import _UsageTypeError, _UsageValueError
from archivey.internal.arg_checks import check_instance
from archivey.internal.enum_args import coerce_enum_collection
from archivey.internal.excluded_libraries import is_excluded_module
from archivey.internal.overrides import override
from archivey.types import (
    ArchiveFormat,
    CompressionAlgorithm,
    CompressionMethod,
    ContainerFormat,
    OptionalLibrary,
    OptionalLibraryStr,
    PluginContainer,
    PluginStream,
    StreamFormat,
)

if TYPE_CHECKING:
    from archivey.formats import FormatHandler, IndexedFormatHandler

__all__ = ["FormatPolicy"]

# One entry of ``only`` or ``exclude``: a container or a compression, each half of an
# ArchiveFormat.
_FormatEntry = ContainerFormat | PluginContainer | StreamFormat | PluginStream
# One entry of ``exclude``: a format entry, or a member compression method.
_ExcludeEntry = _FormatEntry | CompressionAlgorithm

# Methods ``exclude`` cannot name: no decoder runs for either, so turning one off would
# refuse nothing or everything.
_UNEXCLUDABLE_METHODS = frozenset(
    {CompressionAlgorithm.STORED, CompressionAlgorithm.UNKNOWN}
)

_CALL = "FormatPolicy()"


# The method each whole-file compression decodes with, so a method in ``exclude``
# refuses a file compressed with it as a whole too. ``.Z`` and bzip3 have no
# CompressionAlgorithm member: only their StreamFormat refuses them.
_STREAM_METHODS: dict[StreamFormat, CompressionAlgorithm] = {
    StreamFormat.GZIP: CompressionAlgorithm.DEFLATE,
    StreamFormat.ZLIB: CompressionAlgorithm.DEFLATE,
    StreamFormat.BZIP2: CompressionAlgorithm.BZIP2,
    StreamFormat.XZ: CompressionAlgorithm.XZ,
    StreamFormat.LZMA_ALONE: CompressionAlgorithm.LZMA,
    StreamFormat.LZIP: CompressionAlgorithm.LZMA,
    StreamFormat.ZSTD: CompressionAlgorithm.ZSTD,
    StreamFormat.LZ4: CompressionAlgorithm.LZ4,
    StreamFormat.MOZLZ4: CompressionAlgorithm.LZ4,
    StreamFormat.BROTLI: CompressionAlgorithm.BROTLI,
    StreamFormat.LZOP: CompressionAlgorithm.LZO,
}


def _entry_name(entry: _ExcludeEntry) -> str:
    return f"{type(entry).__name__}.{entry.name}"


def _coerce_entries(
    values: object, *, param: str, methods: bool = False
) -> frozenset[_ExcludeEntry]:
    """``values`` as a frozenset of members, refusing anything that is not one.

    Members only, not their string spellings: ``"zip"`` would name a container and
    ``"gz"`` a compression, so a string cannot say which half of the format it is.
    ``methods`` admits :class:`~archivey.CompressionAlgorithm` members (``exclude=``
    only).
    """
    kinds = (
        "ContainerFormat, PluginContainer, StreamFormat, PluginStream and "
        "CompressionAlgorithm"
        if methods
        else "ContainerFormat, PluginContainer, StreamFormat and PluginStream"
    )
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise _UsageTypeError(
            f"{_CALL} takes a collection of {kinds} members for {param}, got "
            f"{values!r}."
        )
    entries: set[_ExcludeEntry] = set()
    for value in values:
        if isinstance(value, ArchiveFormat):
            raise _UsageTypeError(
                f"{_CALL} takes containers and compressions for {param}, not the "
                f"format {value!r}: pass {_entry_name(value.container)}, and "
                f"{_entry_name(value.stream)} for its compression."
            )
        if isinstance(value, CompressionAlgorithm):
            if not methods:
                raise _UsageTypeError(
                    f"{_CALL} got {_entry_name(value)} in {param}, which takes formats "
                    "only: a member's compression method can be refused with "
                    "exclude=, not allowed with only=."
                )
            if value in _UNEXCLUDABLE_METHODS:
                raise _UsageValueError(
                    f"{_CALL} got {_entry_name(value)} in {param}: STORED decodes "
                    "nothing and UNKNOWN names no method, so neither can be turned "
                    "off."
                )
            entries.add(value)
            continue
        if not isinstance(
            value, (ContainerFormat, PluginContainer, StreamFormat, PluginStream)
        ):
            raise _UsageTypeError(
                f"{_CALL} takes {kinds} members for {param}, got {value!r} "
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


def _coerce_libraries(
    values: object, param: str = "exclude_libraries="
) -> frozenset[OptionalLibrary]:
    """``exclude_libraries=`` or ``only_libraries=`` as a frozenset of members,
    refusing any other name."""
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
    replace: Mapping[ContainerFormat, type[IndexedFormatHandler]],
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
                f"{', '.join(clash)}, but exclude_libraries= or only_libraries= "
                f"turns {'it' if len(clash) == 1 else 'them'} off. Drop the plugin, "
                "or let the package run."
            )


class _Replacements(Mapping[ContainerFormat, "type[IndexedFormatHandler]"]):
    """A read-only, hashable mapping, so a policy and the config holding it stay
    hashable as every other config field is."""

    __slots__ = ("_items",)

    def __init__(
        self, items: Mapping[ContainerFormat, type[IndexedFormatHandler]]
    ) -> None:
        self._items = dict(items)

    @override
    def __getitem__(self, key: ContainerFormat) -> type[IndexedFormatHandler]:
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
            f"{_CALL} takes a mapping of ContainerFormat to IndexedFormatHandler subclass for "
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

    ``only`` and ``exclude`` check the file the call opens, not what is inside it. A
    stream format there (``S.XZ``) is the compression around the whole file: a ``.xz``
    file, or the xz around a ``.tar.xz``. It is not the xz codec. An xz-compressed ZIP
    member, or the xz payload a plugin reader decodes inside its own archive, still
    decodes under ``exclude={S.XZ}``: a member's compression is part of its archive's
    format. ``plugins``, ``exclude_libraries`` and ``only_libraries`` turn off the code
    that decodes, wherever it runs, so they hold for every member too: under
    ``plugins=False`` no plugin codec decodes anything in the call, and an excluded
    package decodes nothing.
    A :class:`~archivey.CompressionAlgorithm` in ``exclude`` turns that decoder off:
    it refuses every member compressed with that method, in every archive the call
    opens, and a file compressed with it as a whole.

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
    probe whose format needs a package the policy turns off (``exclude_libraries`` or
    ``only_libraries``), which does not run, so the package is not called.

    ``replace=`` reads a built-in container with a plugin instead of the built-in
    reader (see :attr:`replace`)::

        MY_ZIP = ArchiveyConfig(formats=FormatPolicy(replace={C.ZIP: MyZipPlugin}))

    One preset is provided:

    - ``FormatPolicy.COMMON`` is for files you did not make, such as uploads: the
      formats people send today and nothing else. It is
      ``FormatPolicy(only={C.ZIP, C.TAR, C.RAR, C.SEVEN_Z, C.RAW_STREAM, S.GZIP,
      S.BZIP2, S.XZ, S.ZSTD}, exclude={SHRINK, IMPLODE, REDUCE, DCL_IMPLODE})``, the
      last four being the ZIP methods only PKZIP 1.x and earlier wrote. Disk images,
      packages, cabinets, the rarer compressions and plugin formats are refused, so
      their readers and their pure-Python decoders do not run, and so is a format a
      later release adds. Each entry is a deliberate choice, and a release changes
      one only with a changelog line. To add a format, build on it:
      ``FormatPolicy(only=FormatPolicy.COMMON.only | {S.LZ4},
      exclude=FormatPolicy.COMMON.exclude)``. It bounds which code runs, not how long
      it runs: a 7z member's BCJ2 filter and ZipCrypto still decode in Python.
    """

    COMMON: ClassVar[FormatPolicy]

    only: (
        frozenset[ContainerFormat | PluginContainer | StreamFormat | PluginStream]
        | None
    )
    """The containers and compressions of the file the call may open, or ``None`` for
    all of them.

    Only the file the call opens is checked. A member's compression is not: under
    ``only={C.ZIP}`` an xz-compressed ZIP member still decodes."""

    exclude: frozenset[
        ContainerFormat
        | PluginContainer
        | StreamFormat
        | PluginStream
        | CompressionAlgorithm
    ]
    """The containers and compressions of the file the call may not open, and the
    member compression methods it may not decode.

    A container or a :class:`~archivey.StreamFormat` is checked against the file the
    call opens only. ``exclude={S.XZ}`` refuses a ``.xz`` or ``.tar.xz`` file, but an
    xz-compressed ZIP member, or a plugin's xz payload, still decodes.

    A :class:`~archivey.CompressionAlgorithm` turns that decoder off instead. It
    refuses a file compressed with it as a whole: ``CompressionAlgorithm.XZ`` refuses
    a ``.xz`` and a ``.tar.xz`` file, ``DEFLATE`` a ``.gz``, ``LZMA`` a ``.lzma`` and a
    ``.lz``. And it is checked against every member, in every archive the call opens,
    whatever its format. A member whose
    :attr:`~archivey.ArchiveMember.compression` lists one is still listed, with its
    metadata, but opening, reading or extracting it raises
    :class:`~archivey.UnsupportedFeatureError` that names the entry, before any of its
    data is decoded. A symbolic link whose target is stored as such data is listed
    without a target and reported, as one whose target cannot be decoded is. A
    format that compresses data inside itself without listing the method on its
    members (a ``.deb``'s ``data.tar.xz``, an RPM payload, SquashFS blocks, a
    makeself payload) is refused when it opens, with ``UnsupportedFeatureError``.
    ``.Z`` and bzip3 have no method member, so only ``S.UNIX_COMPRESS`` and
    ``S.BZIP3`` refuse them. ``STORED`` and ``UNKNOWN`` cannot be listed: the first
    decodes nothing, and the second names no method. ``only`` takes no methods.

    Use it to keep slow or rarely used decoders from running on files you did not
    make: ``{CompressionAlgorithm.SHRINK, CompressionAlgorithm.IMPLODE,
    CompressionAlgorithm.REDUCE, CompressionAlgorithm.DCL_IMPLODE}`` turns off the ZIP
    methods only PKZIP 1.x and earlier wrote, which archivey decodes in pure Python.
    To turn off a package wherever it decodes, use ``exclude_libraries`` or
    ``only_libraries``."""

    plugins: bool
    """Whether registered plugin formats and plugin codecs may run in this call. Use
    ``False`` with ``exclude``; under ``only``, a file in a plugin format opens only
    when its container (or its :class:`~archivey.PluginStream`, for a codec) is listed.

    ``False`` turns a plugin codec off everywhere in the call: as the compression of
    the file opened, and inside an archive, when a reader (a ``replace=`` plugin, for
    example) asks ``ReaderContext.decompress`` for it. A plugin format, or a format
    with a plugin codec, is off inside an archive too: ``ReaderContext.open_nested``
    refuses it. Each refusal raises
    :class:`~archivey.UnsupportedFeatureError` that names this setting, before the
    codec's code runs. A ``replace=`` reader is not a plugin format, so it still opens.

    Stable, unlike the experimental plugin interface it refuses: ``plugins=False``
    keeps working whatever happens to that interface."""

    replace: Mapping[ContainerFormat, type[IndexedFormatHandler]]
    """Built-in containers read by a plugin instead of the built-in reader.

    Experimental, with ``archivey.formats``: any release may change it.

    A key is ``ContainerFormat.ZIP``, ``SEVEN_Z``, ``RAR``, ``ISO``, ``SQUASHFS``,
    ``CAB``, ``XAR``, ``LHA`` or ``ARJ``.
    Its plugin is a ``archivey.formats.IndexedFormatHandler`` that is not registered: its
    ``format`` is the built-in one (``ArchiveFormat.ZIP``), and it declares no
    ``extensions``, ``magic`` or ``probe``, because the file is found by the built-in
    detection. The reader's ``format`` is the built-in format and ``format_info.from_plugin`` is
    false. The plugin gets what any indexed plugin gets, a seekable source from the
    start of the archive, so a multi-volume set and an archive behind a
    self-extracting stub are refused with :class:`~archivey.UnsupportedFeatureError`,
    a source that cannot seek with :class:`~archivey.StreamNotSeekableError`, and a
    raw CD sector image detected as ISO (only the built-in reader strips its sectors). The
    format's own ``ArchiveyConfig`` options reach the plugin through
    ``ReaderContext.config``."""

    exclude_libraries: frozenset[OptionalLibrary]
    """Optional packages that read as not installed in this call.

    Each entry is an :class:`~archivey.OptionalLibrary` member or its value, such as
    ``"pyppmd"``; any other name is refused when the policy is built. An excluded
    package decodes nothing in the call, inside an archive as for a whole file, and
    one that archivey imports on first use (``brotli``, ``pyppmd``, ``inflate64``,
    ``rapidgzip``) is not imported for it. What happens is what happens when the
    package is missing: an accelerator under ``AUTO`` falls back to the standard
    library, a member that needs it raises :class:`~archivey.PackageNotInstalledError`
    when opened, and a format that needs it refuses at open. The error's ``missing``
    names the package with this setting as its ``reason``.
    :func:`~archivey.format_availability` answers for it when passed the config. Other
    calls in the process, on any thread, are unaffected.

    archivey uses one zstd module per process, ``compression.zstd`` where it imports
    and ``backports.zstd`` otherwise; excluding that module turns zstd off, and
    excluding the other changes nothing. ``zlib``, ``bz2`` and ``lzma`` cannot be
    excluded. A policy that names a plugin (in ``replace=``, or by its container in
    ``only=``) whose ``requires`` lists an excluded package is refused."""

    only_libraries: frozenset[OptionalLibrary] | None
    """The optional packages the call may decode with, or ``None`` for all of them.

    The allowlist form of :attr:`exclude_libraries`, as ``only`` is of ``exclude``:
    every :class:`~archivey.OptionalLibrary` it does not list reads as not installed in
    this call, with the same effects, including on a package a later archivey release
    adds. ``only_libraries=set()`` runs with no optional package; on Python 3.14 that
    also turns off the standard library's ``compression.zstd``, which is listed as one.
    Both may be set,
    as long as no package is in both.

    It covers archivey's own optional packages. A plugin's own modules are not
    :class:`~archivey.OptionalLibrary` members, so it leaves them alone: ``plugins=``
    turns plugins off. Zstandard runs on ``compression.zstd`` where the interpreter has
    it and ``backports.zstd`` otherwise, so list both to keep zstd everywhere."""

    _libraries_off: frozenset[OptionalLibrary] = field(
        init=False, repr=False, compare=False
    )
    """Every package the call reads as not installed: :attr:`exclude_libraries`, and
    each one :attr:`only_libraries` does not list. Every check reads this, never the
    two fields."""

    # A hand-written __init__, as DiagnosticPolicy has: the parameters take any
    # iterable, and the fields always hold frozensets.
    def __init__(
        self,
        *,
        only: Iterable[ContainerFormat | PluginContainer | StreamFormat | PluginStream]
        | None = None,
        exclude: Iterable[
            ContainerFormat
            | PluginContainer
            | StreamFormat
            | PluginStream
            | CompressionAlgorithm
        ] = (),
        plugins: bool = True,
        replace: Mapping[ContainerFormat, type[IndexedFormatHandler]] | None = None,
        exclude_libraries: Iterable[OptionalLibrary | OptionalLibraryStr] = (),
        only_libraries: Iterable[OptionalLibrary | OptionalLibraryStr] | None = None,
    ) -> None:
        only_parsed = (
            None
            if only is None
            # Without ``methods``, every entry is a format entry.
            else cast("frozenset[_FormatEntry]", _coerce_entries(only, param="only="))
        )
        exclude_parsed = _coerce_entries(exclude, param="exclude=", methods=True)
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
        only_libs = (
            None
            if only_libraries is None
            else _coerce_libraries(only_libraries, "only_libraries=")
        )
        libraries_off = libraries
        if only_libs is not None:
            both_libs = only_libs & libraries
            if both_libs:
                names = ", ".join(sorted(lib.value for lib in both_libs))
                raise _UsageValueError(
                    f"{_CALL} got packages in both only_libraries= and "
                    f"exclude_libraries=: {names}."
                )
            libraries_off = libraries | (frozenset(OptionalLibrary) - only_libs)
        _check_named_plugins(replace_parsed, only_parsed, libraries_off)
        object.__setattr__(self, "replace", replace_parsed)
        object.__setattr__(self, "exclude_libraries", libraries)
        object.__setattr__(self, "only_libraries", only_libs)
        object.__setattr__(self, "_libraries_off", libraries_off)
        object.__setattr__(self, "only", only_parsed)
        object.__setattr__(self, "exclude", exclude_parsed)
        object.__setattr__(self, "plugins", plugins)

    def _replacement_for(self, fmt: ArchiveFormat) -> type[IndexedFormatHandler] | None:
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

    def allows_library(self, module: OptionalLibrary | str) -> bool:
        """Whether the call may decode with ``module``, an import name.

        ``False`` when :attr:`exclude_libraries` lists the package ``module`` is or is
        part of (``lz4.block`` is part of ``lz4``), or :attr:`only_libraries` does not
        list it. A name that is not an :class:`~archivey.OptionalLibrary`, such as a
        plugin's own module or ``zlib``, is always allowed. ``module`` is the exact
        import name and is case-sensitive (``"LZ4"`` is not ``lz4``); a non-string raises
        ``ArchiveyUsageError``. A plugin reader that
        imports an optional package outside its ``requires`` asks this before it imports
        it.
        """
        check_instance(
            module, str, call="FormatPolicy.allows_library(module=…)", allow_none=False
        )
        return not is_excluded_module(str(module), self._libraries_off)

    def _refusal(self, fmt: ArchiveFormat) -> str | None:
        """The refusal text for ``fmt``, naming every entry to change, or ``None``."""
        reasons = self._reasons(fmt)
        if not reasons:
            return None
        return (
            f"ArchiveyConfig.formats does not allow {fmt.display_name}: "
            f"{', and '.join(reasons)}."
        )

    def _excluded_methods(
        self, compression: tuple[CompressionMethod, ...]
    ) -> tuple[CompressionAlgorithm, ...]:
        """The methods of a member's ``compression`` chain that :attr:`exclude` lists,
        in chain order and once each; empty when the member may decode."""
        hits: list[CompressionAlgorithm] = []
        for method in compression:
            if method.algo in self.exclude and method.algo not in hits:
                hits.append(method.algo)
        return tuple(hits)

    def _codec_refusal(
        self, codec: StreamFormat | PluginStream | CompressionAlgorithm
    ) -> str | None:
        """The refusal text for ``codec`` decoding inside an open (a member's data, or
        the rest of an archive a reader hands on), or ``None``.

        Only ``plugins``, ``exclude_libraries``, ``only_libraries`` and a method in
        ``exclude`` reach that far; ``only`` and the format entries of ``exclude`` choose the file
        opened, so they are not asked. An excluded package is refused by the codec
        layer, which reads it as missing.
        """
        if isinstance(codec, CompressionAlgorithm):
            if codec in self.exclude:
                return (
                    f"ArchiveyConfig.formats does not allow {_entry_name(codec)}: "
                    "exclude= lists it"
                )
            return None
        method = _STREAM_METHODS.get(codec) if isinstance(codec, StreamFormat) else None
        if method is not None and method in self.exclude:
            return (
                f"ArchiveyConfig.formats does not allow {_entry_name(codec)} data in "
                f"this archive: exclude= lists {_entry_name(method)}, which it "
                "decodes with"
            )
        if isinstance(codec, PluginStream) and not self.plugins:
            return (
                f"ArchiveyConfig.formats does not allow the plugin codec "
                f"{_entry_name(codec)}: plugins=False turns off every plugin codec, "
                "inside an archive as for a whole file"
            )
        return None

    def _nested_refusal(self, fmt: ArchiveFormat) -> str | None:
        """The refusal text for ``fmt`` read as an archive inside an open
        (``ReaderContext.open_nested``), or ``None``.

        As for :meth:`_codec_refusal`, only ``plugins`` and a method in ``exclude``
        reach that far here: a plugin container or plugin codec does not run under
        ``plugins=False``, and a stream format whose method ``exclude`` lists does not
        run at all. ``exclude_libraries`` holds in the reader lookup.
        """
        reasons: list[str] = []
        stream = fmt.stream
        method = (
            _STREAM_METHODS.get(stream) if isinstance(stream, StreamFormat) else None
        )
        if method is not None and method in self.exclude:
            reasons.append(
                f"exclude= lists {_entry_name(method)}, which "
                f"{_entry_name(stream)} decodes with"
            )
        if not self.plugins and isinstance(fmt.container, PluginContainer):
            reasons.append("plugins=False turns off every plugin format")
        if not self.plugins and isinstance(fmt.stream, PluginStream):
            reasons.append("plugins=False turns off every plugin codec")
        if not reasons:
            return None
        return (
            f"ArchiveyConfig.formats does not allow {fmt.display_name} inside an "
            f"archive: {', and '.join(reasons)}."
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
            method = (
                _STREAM_METHODS.get(stream)
                if isinstance(stream, StreamFormat)
                else None
            )
            if stream in self.exclude:
                reasons.append(f"exclude= lists {_entry_name(stream)}")
            elif method is not None and method in self.exclude:
                reasons.append(
                    f"exclude= lists {_entry_name(method)}, which "
                    f"{_entry_name(stream)} decodes with"
                )
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
        return (
            not self.plugins
            or self.only is not None
            or any(not isinstance(e, CompressionAlgorithm) for e in self.exclude)
        )


FormatPolicy.COMMON = FormatPolicy(
    only={
        ContainerFormat.ZIP,
        ContainerFormat.TAR,
        ContainerFormat.RAR,
        ContainerFormat.SEVEN_Z,
        ContainerFormat.RAW_STREAM,
        StreamFormat.GZIP,
        StreamFormat.BZIP2,
        StreamFormat.XZ,
        StreamFormat.ZSTD,
    },
    exclude={
        CompressionAlgorithm.SHRINK,
        CompressionAlgorithm.IMPLODE,
        CompressionAlgorithm.REDUCE,
        CompressionAlgorithm.DCL_IMPLODE,
    },
)
