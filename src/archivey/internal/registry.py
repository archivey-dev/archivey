"""Backend registry: maps ArchiveFormat to ReadBackend classes.

Registration is **unconditional**: every known backend — core and optional alike —
registers when its module is imported. Availability is then derived centrally from the
optional dependency's module-or-``None`` sentinel, so the registry can report a tri-state,
compositional :class:`~archivey.FormatSupport` (FULL / PARTIAL / NONE) and produce install-hint
errors, rather than silently dropping a format whose dependency is absent (see
``backend-registry``).
"""

from __future__ import annotations

import functools
import importlib
from collections.abc import Callable
from types import ModuleType
from typing import TYPE_CHECKING, Protocol

from archivey.config import ArchiveyConfig, ProcessIsolation
from archivey.cost import StreamCapability
from archivey.exceptions import (
    PackageNotInstalledError,
    UnsupportedFeatureError,
)
from archivey.internal.arg_checks import check_config
from archivey.internal.base_reader import ReadBackend
from archivey.internal.excluded_libraries import (
    NO_EXCLUSIONS,
    as_excluded,
    is_excluded_module,
)
from archivey.internal.format_args import coerce_archive_format
from archivey.internal.sfx import HitValidator
from archivey.internal.streams.codecs import (
    SINGLE_FILE_CODECS,
    STREAM_CODECS,
    Codec,
    codec_for_stream_format,
    codec_requirement,
    is_codec_available,
)
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    FormatAvailability,
    FormatSupport,
    MagicSignature,
    MissingComponent,
    OptionalLibrary,
    PluginContainer,
    StreamFormat,
    TrailerSignature,
)

if TYPE_CHECKING:
    from archivey.format_policy import FormatPolicy
    from archivey.plugins import FormatPlugin


class ContentProbe(Protocol):
    """Callable shape for registry content probes.

    ``source_length`` is optional: when detection knows a cheap byte size it is passed
    through so a probe can reject declared framing that cannot fit, or an incomplete
    decode when the whole source is visible. ``read_at`` is an optional bounded read
    facility for probes that follow a self-describing block chain past the peeked
    prefix; absent by default. ``charge_decode(n)`` asks the caller's decode allowance
    for the total ``[0, n)`` of compressed bytes a probe will read and decode past its
    sample (Brotli's chain decode), before it reads them; ``False`` means not covered,
    and the probe keeps its verdict.
    ``isolation`` is the caller's ``process_isolation``: where the probe's trial decode
    runs.
    """

    def __call__(
        self,
        prefix: bytes,
        /,
        *,
        source_length: int | None = None,
        read_at: Callable[[int, int], bytes | None] | None = None,
        charge_decode: Callable[[int], bool] | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool: ...


__all__ = [
    "BackendRegistry",
    "ContentProbe",
    "MissingComponent",
    "format_availability",
    "get_registry",
    "list_known_formats",
    "list_supported_formats",
    "register_reader",
]


# Optional member-codecs each container can use, beyond the always-present stdlib codecs.
# A format is FULL when all of these are available, PARTIAL when some are missing (a
# multi-codec container still opens and lists). Single-codec formats (bare RAW_STREAM
# compressors and compressed tars) are handled separately: their sole stream codec
# missing makes them NONE, not PARTIAL.
_CONTAINER_OPTIONAL_CODECS: dict[
    ContainerFormat | PluginContainer, tuple[Codec, ...]
] = {
    ContainerFormat.SEVEN_Z: (
        Codec.PPMD,
        Codec.DEFLATE64,
        Codec.ZSTD,
        Codec.BROTLI,
        Codec.LZ4,
    ),
    ContainerFormat.ZIP: (Codec.DEFLATE64, Codec.ZSTD, Codec.PPMD),
}

# How each optional codec is obtained (install hint surfaced to the caller) now lives on
# the codec descriptors; read via codec_requirement() so a codec's package / extra / hint
# is declared in exactly one place (see ``backend-registry``).


@functools.cache
def _optional(name: str) -> ModuleType | None:
    """Return the named module, or ``None`` when it (the optional extra) is not installed.

    Memoized, because Python has no negative import cache: a *present* module is a
    ``sys.modules`` hit, but a **missing** one re-runs the finders over every
    ``sys.path`` entry on every call — measured at ~46 µs against ~0.6 µs. That cost
    lands on the ``open_archive`` path (``reader_for_format`` -> ``format_availability``
    -> here) and once per format in ``list_supported_formats()``, so an environment that
    skipped an extra pays it repeatedly for an answer that does not change.

    The accepted trade is that a dependency installed into an already-running
    interpreter is not picked up; a caller that needs it to be can call
    ``_optional.cache_clear()``. That is a real difference from ``extension_map()``
    below, which is also cached but *invalidated* — ``register_reader`` drops its cache
    so a registration after first use cannot be missed. Nothing invalidates this one,
    because a registration can happen mid-process and an install cannot. Tests that
    simulate a missing extra replace this function rather than hiding the module, so the
    memo does not leak between them.
    """
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


class BackendRegistry:
    """Central registry mapping formats to their read backends."""

    def __init__(self) -> None:
        self._readers: dict[ArchiveFormat, type[ReadBackend]] = {}
        # Unique reader classes in registration order (a class may serve several formats).
        self._reader_classes: list[type[ReadBackend]] = []
        # Plugin backends (``archivey.plugins.register_format``), kept apart so every
        # detection table lists them after the built-in backends and the stream codecs:
        # detection takes the first match in table order, so a built-in signal wins.
        self._plugin_classes: list[type[ReadBackend]] = []
        self._extension_map_cache: dict[str, ArchiveFormat] | None = None

    def register_reader(self, backend_cls: type[ReadBackend]) -> None:
        if backend_cls not in self._reader_classes:
            self._reader_classes.append(backend_cls)
        for fmt in backend_cls.FORMATS:
            self._readers[fmt] = backend_cls
        self._extension_map_cache = None

    def register_plugin_backend(self, backend_cls: type[ReadBackend]) -> None:
        """Register a plugin's backend after every built-in one (see ``_plugin_classes``)."""
        self._plugin_classes.append(backend_cls)
        for fmt in backend_cls.FORMATS:
            self._readers[fmt] = backend_cls
        self._extension_map_cache = None

    def plugin_backends(self) -> tuple[type[ReadBackend], ...]:
        """The backends :meth:`register_plugin_backend` registered, in that order."""
        return tuple(self._plugin_classes)

    def save_plugin_state(self) -> Callable[[], None]:
        """Save what :meth:`register_plugin_backend` writes; the result restores it."""
        readers = dict(self._readers)
        plugin_classes = list(self._plugin_classes)

        def restore() -> None:
            self._readers = readers
            self._plugin_classes = plugin_classes
            self._extension_map_cache = None

        return restore

    # --- detection tables (aggregated from two sources) ----------------------------------
    # The container format backends (`ReadBackend.MAGIC`/`EXTENSIONS`/`CONTENT_PROBES`) and
    # the stream-codec objects (`STREAM_CODECS`). The detector reads both via these methods,
    # so a new standalone codec is detectable by adding one `StreamCodec` — no edits here.

    def magic_entries(self) -> list[MagicSignature]:
        """All exact magic signals across registered backends and the stream codecs."""
        entries: list[MagicSignature] = []
        for cls in self._reader_classes:
            entries.extend(cls.MAGIC)
        for codec in STREAM_CODECS:
            entries.extend(codec.magic)
        for cls in self._plugin_classes:
            entries.extend(cls.MAGIC)
        return entries

    def magic_prefix_walks(self) -> list[tuple[ArchiveFormat, Callable[[bytes], bool]]]:
        """(format, walk) pairs for magic that may sit behind a format's own prefix frames.

        ``walk(prefix)`` answers "is my exact magic in there, behind structural frames I
        define?" — today only zstd, whose skippable frames may precede the first regular
        frame. Declared on the codec like every other detection signal, so the detector
        stays format-agnostic; a hit is reported as the exact magic match it is.
        """
        return [
            (codec.single_file_format, codec.magic_behind_prefix)
            for codec in SINGLE_FILE_CODECS
            if codec.walks_magic_prefix and codec.single_file_format is not None
        ]

    def sfx_magic_entries(self) -> list[MagicSignature]:
        """Magic the SFX scan hunts for behind an executable stub.

        Only the backends that can ship as a self-extracting archive declare any
        (``ReadBackend.SFX_MAGIC``); the stream codecs never do, since a stub plus a
        bare compressed stream is not a thing anyone produces.
        """
        entries: list[MagicSignature] = []
        for cls in self._reader_classes:
            entries.extend(cls.SFX_MAGIC)
        return entries

    def sfx_hit_validators(
        self,
    ) -> dict[ArchiveFormat, HitValidator]:
        """Format-owned checks the SFX scan calls on a candidate-relative view.

        Collected from ``ReadBackend.SFX_HIT_VALIDATOR`` next to ``SFX_MAGIC``. A
        missing validator means a needle match is enough. ZIP, 7z, and RAR each
        supply one so ``detection.py`` does not parse those formats.
        """
        mapping: dict[ArchiveFormat, HitValidator] = {}
        for cls in self._reader_classes:
            validator = cls.SFX_HIT_VALIDATOR
            if validator is None:
                continue
            for sig in cls.SFX_MAGIC:
                mapping[sig.format] = validator
        return mapping

    def sfx_parser_scanned_formats(self) -> frozenset[ArchiveFormat]:
        """Formats whose parser runs its own capped SFX scan.

        Collected from ``ReadBackend.SFX_PARSER_SCANS``. The detector applies the
        rejection cap to these formats only.
        """
        return frozenset(
            sig.format
            for cls in self._reader_classes
            if cls.SFX_PARSER_SCANS
            for sig in cls.SFX_MAGIC
        )

    def trailer_entries(self) -> list[TrailerSignature]:
        """Trailer magic declared by registered backends.

        Exact magic at the start of a fixed-length block at EOF. The detector
        reads that block only on a cheap seek, and a hit outranks a near-magic
        format the trailer lists in ``preempts``.
        """
        entries: list[TrailerSignature] = []
        for cls in self._reader_classes:
            entries.extend(cls.TRAILER)
        return entries

    def content_probes(
        self,
    ) -> list[tuple[ArchiveFormat, ContentProbe]]:
        """(format, probe) pairs for formats recognized by a content probe.

        Drawn from the backends and from the stream codecs that override the no-op base
        content probe (Brotli, which has no magic; zlib, whose 2-byte header is too
        unspecific to trust on its own; LZMA Alone, whose properties byte is similarly
        too weak for exact magic). Probes accept ``prefix`` and optional
        ``source_length=``.
        """
        probes: list[tuple[ArchiveFormat, ContentProbe]] = []
        for cls in self._reader_classes:
            probes.extend(cls.CONTENT_PROBES)
        for codec in SINGLE_FILE_CODECS:
            if codec.probes_content and codec.single_file_format is not None:
                probes.append((codec.single_file_format, codec.content_probe))
        for cls in self._plugin_classes:
            probes.extend(cls.CONTENT_PROBES)
        return probes

    def extension_map(self) -> dict[str, ArchiveFormat]:
        """The merged ``extension -> format`` map across backends and the stream codecs.

        Cached after first build: registration is import-time (and rare in tests), while
        detection (``_detect_format_body``) looks the map up on every ``detect_format``
        call, so once per ``open_archive``. Invalidated on ``register_reader``.
        """
        cached = self._extension_map_cache
        if cached is not None:
            return cached
        merged: dict[str, ArchiveFormat] = {}
        for cls in self._reader_classes:
            merged.update(cls.EXTENSIONS)
        for codec in SINGLE_FILE_CODECS:
            if codec.single_file_format is not None:
                for ext in codec.extensions:
                    merged[ext] = codec.single_file_format
        for cls in self._plugin_classes:
            # Registration refuses an extension already in the map, so a plugin
            # never overwrites a built-in entry here.
            merged.update(cls.EXTENSIONS)
        self._extension_map_cache = merged
        return merged

    # --- availability --------------------------------------------------------------------

    def _missing_dependency(
        self, backend_cls: type[ReadBackend], excluded: frozenset[OptionalLibrary]
    ) -> str | None:
        """The first module the backend needs that does not import, or that
        ``excluded`` turns off, else ``None``. An excluded one is not imported."""
        dep = backend_cls.OPTIONAL_DEPENDENCY
        for name in (
            *((dep,) if dep is not None else ()),
            *backend_cls.REQUIRED_MODULES,
        ):
            if is_excluded_module(name, excluded) or _optional(name) is None:
                return name
        return None

    def format_availability(
        self,
        fmt: ArchiveFormat,
        *,
        check_programs: bool = False,
        excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS,
        replacement: type[FormatPlugin] | None = None,
    ) -> FormatAvailability:
        """Compute the tri-state support of ``fmt`` compositionally (see ``backend-registry``).

        ``check_programs`` also asks the backend for missing external programs
        (``ReadBackend.missing_programs``), which can run them to identify them. Only
        the public query sets it: a missing program never makes a format ``NONE``, so
        the open path and ``list_supported_formats`` get the same answer without it.

        ``excluded`` and ``replacement`` are a call's ``FormatPolicy`` answers: the
        packages it turns off, which count as absent, and the plugin that reads ``fmt``
        in place of the registered backend (``FormatPolicy._replacement_for``).
        """
        if replacement is not None:
            # Imported here: the plugin adapter imports this module.
            from archivey.internal.plugin_adapter import replacement_backend

            return self._backend_availability(
                fmt,
                replacement_backend(replacement),
                check_programs=check_programs,
                member_codecs=False,
                excluded=excluded,
            )
        backend_cls = self._readers.get(fmt)
        if backend_cls is None:
            # No backend, so no source shape to report: the SEEKABLE default stands as
            # the conservative answer.
            return FormatAvailability(fmt, FormatSupport.NONE, ())
        return self._backend_availability(
            fmt,
            backend_cls,
            check_programs=check_programs,
            member_codecs=True,
            excluded=excluded,
        )

    def _backend_availability(
        self,
        fmt: ArchiveFormat,
        backend_cls: type[ReadBackend],
        *,
        check_programs: bool,
        member_codecs: bool,
        excluded: frozenset[OptionalLibrary],
    ) -> FormatAvailability:
        """The support of ``fmt`` when ``backend_cls`` reads it.

        ``member_codecs`` folds in the optional member codecs the built-in reader of
        the container can use; a replacement plugin decodes its members its own way,
        so only its own ``requires`` count. A package in ``excluded`` counts as
        absent, with the policy as its ``reason``.
        """

        # Derived from the flag open_archive() itself enforces, so the queryable answer
        # cannot drift from the enforced one. Reported on every path below, including the
        # unavailable ones — whether a format needs to seek does not depend on whether
        # its dependency happens to be installed.
        required_source = (
            StreamCapability.FORWARD_ONLY
            if backend_cls.SUPPORTS_STREAMING_NON_SEEKABLE
            else StreamCapability.SEEKABLE
        )

        if not backend_cls.READ_IMPLEMENTED:
            # Recognised, not readable. An empty ``missing`` is the answer: there
            # is nothing to install, and open raises UnsupportedFeatureError
            # before the seekability check. ``required_source`` is still the
            # flag, which is what the spool recipe branches on.
            return FormatAvailability(fmt, FormatSupport.NONE, (), required_source)

        dep = self._missing_dependency(backend_cls, excluded)
        if dep is not None:
            hint = backend_cls.INSTALL_HINT or f"install {dep}"
            return FormatAvailability(
                fmt,
                FormatSupport.NONE,
                (
                    as_excluded(MissingComponent(dep, hint))
                    if is_excluded_module(dep, excluded)
                    else MissingComponent(dep, hint),
                ),
                required_source,
            )

        # The format's own stream codec — a bare single-file compressor's sole codec, or
        # the outer codec of a compressed tar (`tar.<codec>`). With it missing the archive
        # cannot even be listed, so the format is NONE (the single-codec rule in
        # ``backend-registry``), not PARTIAL.
        if fmt.stream != StreamFormat.UNCOMPRESSED:
            stream_codec = codec_for_stream_format(fmt.stream)
            if not is_codec_available(stream_codec, excluded):
                requirement = codec_requirement(stream_codec, excluded)
                assert requirement is not None  # an optional codec always declares one
                return FormatAvailability(
                    fmt, FormatSupport.NONE, (requirement,), required_source
                )

        # Backend + stream codec usable; fold in the optional *member* codecs the
        # container can use. A multi-codec container missing some still opens -> PARTIAL.
        missing: list[MissingComponent] = []
        for codec in (
            _CONTAINER_OPTIONAL_CODECS.get(fmt.container, ()) if member_codecs else ()
        ):
            if not is_codec_available(codec, excluded):
                requirement = codec_requirement(codec, excluded)
                assert requirement is not None  # an optional codec always declares one
                missing.append(requirement)
        if check_programs:
            missing.extend(backend_cls.missing_programs())

        if not missing:
            return FormatAvailability(fmt, FormatSupport.FULL, (), required_source)
        return FormatAvailability(
            fmt, FormatSupport.PARTIAL, tuple(missing), required_source
        )

    # --- selection -----------------------------------------------------------------------

    def unread_format_message(self, fmt: ArchiveFormat) -> str | None:
        """The refusal text for a format that is recognised but not read, else ``None``.

        ``open_archive`` raises it with the archive name before it asks for a reader;
        ``reader_for_format`` raises the same text for a direct caller.
        """
        backend_cls = self._readers.get(fmt)
        if backend_cls is None or backend_cls.READ_IMPLEMENTED:
            return None
        return (
            backend_cls.UNSUPPORTED_MESSAGE
            or f"Reading {fmt.display_name} is not supported."
        )

    def needs_seekable_source(self, fmt: ArchiveFormat) -> bool:
        """Whether ``fmt`` cannot be read from a non-seekable source in either mode.

        ``format_availability(fmt).required_source`` for a registered format, which is
        read from the backend class, never from its optional package, so the answer
        is the same whether or not that package imports. ``open_archive`` refuses a
        read-once source with it before ``reader_for_format``, so a pipe is not told to
        install a package it still could not be read with. ``False`` for a format with
        no backend: ``reader_for_format`` names that absence instead.
        """
        if fmt not in self._readers:
            return False
        # One derivation of the flag, shared with ``format_availability``, so the
        # refusal and the queryable ``required_source`` cannot drift apart.
        return (
            self.format_availability(fmt).required_source is StreamCapability.SEEKABLE
        )

    def needs_excluded_package(
        self, fmt: ArchiveFormat, excluded: frozenset[OptionalLibrary]
    ) -> bool:
        """Whether the backend registered for ``fmt`` needs a module ``excluded`` turns
        off: its ``OPTIONAL_DEPENDENCY`` or one of its ``REQUIRED_MODULES``."""
        backend = self._readers.get(fmt)
        if backend is None or not excluded:
            return False
        dep = backend.OPTIONAL_DEPENDENCY
        return any(
            is_excluded_module(name, excluded)
            for name in (
                *((dep,) if dep is not None else ()),
                *backend.REQUIRED_MODULES,
            )
        )

    def registered_reader(self, fmt: ArchiveFormat) -> type[ReadBackend] | None:
        """The backend class registered for ``fmt``, without the availability check.

        Its class attributes (``SUPPORTS_PASSWORD``, ``USES_ENCODING``, ...) are
        readable whether or not its optional package imports. ``None`` when no backend
        is registered. Use ``reader_for_format`` to get a class that can open.
        """
        return self._readers.get(fmt)

    def reader_for_format(
        self,
        fmt: ArchiveFormat,
        *,
        replacement: type[FormatPlugin] | None = None,
        excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS,
    ) -> type[ReadBackend]:
        """The backend class that opens ``fmt``: ``replacement``'s, else the registered
        one.

        ``replacement`` is what ``FormatPolicy._replacement_for(fmt)`` answered for the
        caller's policy; ``None`` asks for the registered backend. Raises when that
        backend cannot read here: ``UnsupportedFeatureError`` for no backend or a
        recognised-only format, ``PackageNotInstalledError`` for a missing package, a
        replacement plugin's ``requires`` included, and one in ``excluded`` (the
        caller's ``FormatPolicy.exclude_libraries``). The caller has already refused a
        format the policy does not allow.
        """
        if replacement is not None:
            # Imported here: the plugin adapter imports this module.
            from archivey.internal.plugin_adapter import replacement_backend

            availability = self.format_availability(
                fmt, excluded=excluded, replacement=replacement
            )
            if availability.support is FormatSupport.NONE:
                hints = "; ".join(
                    f"{m.name} ({m.advice})" for m in availability.missing
                )
                raise PackageNotInstalledError(
                    f"Format {fmt.display_name} is read by {replacement.__name__} "
                    f"(ArchiveyConfig.formats.replace), which is not available: "
                    f"missing {hints}",
                    missing=availability.missing,
                    source_format=fmt,
                )
            return replacement_backend(replacement)
        availability = self.format_availability(fmt, excluded=excluded)
        if availability.support is FormatSupport.NONE:
            backend_cls = self._readers.get(fmt)
            if backend_cls is None:
                raise UnsupportedFeatureError(
                    f"No read backend registered for format {fmt.display_name}",
                    source_format=fmt,
                )
            unread_message = self.unread_format_message(fmt)
            if unread_message is not None:
                raise UnsupportedFeatureError(unread_message, source_format=fmt)
            hints = "; ".join(f"{m.name} ({m.advice})" for m in availability.missing)
            raise PackageNotInstalledError(
                f"Format {fmt.display_name} is not available: missing {hints}",
                missing=availability.missing,
                source_format=fmt,
            )
        return self._readers[fmt]

    # --- queries -------------------------------------------------------------------------

    def list_known_formats(self) -> list[ArchiveFormat]:
        """Every format the registry knows, including those with support NONE."""
        return list(self._readers.keys())

    def list_supported_formats(
        self, policy: FormatPolicy | None = None
    ) -> list[ArchiveFormat]:
        """Formats readable now — support FULL or PARTIAL (NONE excluded) — under
        ``policy``'s excluded libraries and replacements when one is given."""
        if policy is None:
            return [
                fmt
                for fmt in self._readers
                if self.format_availability(fmt).support is not FormatSupport.NONE
            ]
        return [
            fmt
            for fmt in self._readers
            if self.format_availability(
                fmt,
                excluded=policy.exclude_libraries,
                replacement=policy._replacement_for(fmt),
            ).support
            is not FormatSupport.NONE
        ]


# Module-level singleton
_registry = BackendRegistry()


def register_reader(backend_cls: type[ReadBackend]) -> None:
    _registry.register_reader(backend_cls)


def get_registry() -> BackendRegistry:
    return _registry


def format_availability(
    fmt: ArchiveFormat | str,
    *,
    check_programs: bool = True,
    config: ArchiveyConfig | None = None,
) -> FormatAvailability:
    """Public query: the tri-state support level of ``fmt`` and its missing components.

    ``fmt`` is an :class:`~archivey.ArchiveFormat` — the ``(container, stream)`` pair —
    or that format spelled as a string, such as ``"zip"`` or ``"tar.gz"``. Anything
    else, a :class:`~archivey.StreamFormat` or a :class:`~archivey.ContainerFormat`
    included, raises :class:`~archivey.ArchiveyUsageError` rather than answering: each
    is half of the pair, not a format.

    RAR is ``PARTIAL``, with ``unrar`` in ``missing``, when no RARLAB ``unrar`` or
    ``rar`` 6.0 or later is on ``PATH``: it still opens and lists, and stored members
    read. To find out, the first call runs each candidate once to read its banner, for
    at most 10 seconds each; the answer is cached per binary.
    It describes the default ``rar_decompressor`` (``AUTO``).
    ``check_programs=False`` runs no program: missing programs are then not counted,
    and RAR reports as it would with ``unrar`` installed.

    Without ``config`` the answer is what this environment provides. With it, two
    fields of ``config.formats`` change it, and no other: a package in
    ``exclude_libraries`` counts as absent, listed in ``missing`` with the policy as its
    ``reason``, and a container in ``replace`` is answered for the plugin that reads it,
    whose ``requires`` count as a registered plugin's do. Whether the format may open is
    another question, answered by ``config.formats.allows(fmt)``; a caller needs both.
    """
    # A non-ArchiveFormat used to fall through to a fabricated record — NONE with an
    # empty ``missing``, indistinguishable from a legitimate unsupported answer, and a
    # ``format`` field violating its own declared type. The check is here rather than on
    # the method so internal callers, which hold an ArchiveFormat by construction, keep
    # the plain lookup.
    resolved = coerce_archive_format(
        fmt, call="format_availability()", allow_none=False
    )
    check_config(config, call="format_availability(config=…)")
    if config is None:
        return _registry.format_availability(resolved, check_programs=check_programs)
    policy = config.formats
    return _registry.format_availability(
        resolved,
        check_programs=check_programs,
        excluded=policy.exclude_libraries,
        replacement=policy._replacement_for(resolved),
    )


def list_supported_formats(
    *, config: ArchiveyConfig | None = None
) -> list[ArchiveFormat]:
    """Public query: formats readable now (support FULL or PARTIAL).

    With ``config``, the formats whose :func:`format_availability` under that config is
    FULL or PARTIAL. It does not filter by ``config.formats.allows()``: the formats a
    call may open are ``[f for f in list_supported_formats(config=cfg) if
    cfg.formats.allows(f)]``.
    """
    check_config(config, call="list_supported_formats(config=…)")
    return _registry.list_supported_formats(None if config is None else config.formats)


def list_known_formats() -> list[ArchiveFormat]:
    """Public query: every format the registry knows, including support NONE."""
    return _registry.list_known_formats()
