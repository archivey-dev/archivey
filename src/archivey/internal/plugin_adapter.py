"""The adapter between ``archivey.plugins`` and the internal reader machinery.

A plugin reader does not subclass :class:`BaseArchiveReader`. :class:`PluginReaderAdapter`
is the one subclass that serves every plugin: it implements the four abstract methods
by calling the plugin's :class:`~archivey.plugins.IndexedReader`, so the walk, the
passes, link handling and extraction stay internal (the ``plugin-api`` OpenSpec change,
design §1).

:func:`register_plugin` builds one :class:`ReadBackend` subclass per plugin and
registers it after the built-in backends, so a built-in signal always wins (§4).
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Generator, Iterator, Mapping
from contextlib import contextmanager
from typing import BinaryIO, ClassVar

from archivey.config import ArchiveyConfig, ProcessIsolation
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.exceptions import ArchiveyError, ArchiveyUsageError
from archivey.internal import format_args
from archivey.internal.base_reader import (
    BaseArchiveReader,
    ReadBackend,
    reject_start_offset,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.format_args import add_plugin_spellings, plugin_spelling_clash
from archivey.internal.naming import emit_member_name_normalized, normalize_member_name
from archivey.internal.open_site import OpenSite
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import ContentProbe, get_registry
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.streams.streamtools import LockedStream, SharedSource
from archivey.plugins import (
    FormatPlugin,
    IndexedReader,
    MemberData,
    PluginContext,
    PluginSource,
)
from archivey.types import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    ContainerFormat,
    MagicSignature,
    MemberStreams,
    PluginContainer,
    StreamFormat,
)


class PluginReaderAdapter(BaseArchiveReader):
    """Serves one plugin reader through the internal reader contract."""

    def __init__(
        self,
        plugin: FormatPlugin,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
    ) -> None:
        super().__init__(
            format,
            streaming,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
        self._source = source
        # The plugin may hold a handle of its own (a library over ``source.path``), so
        # under CONCURRENT every call into it, and every read of a stream it returned,
        # takes one lock (``_handle_guard``). The exception is ``translate_exception``,
        # which ``base_reader`` runs outside the lock. The views of ``PluginSource``
        # need none, but archivey cannot tell which kind of reader it was given.
        if MemberStreams.CONCURRENT in member_streams:
            self._handle_lock = threading.Lock()
        self._shared = SharedSource(source, wrap_handle=self._seek_handle_wrapper())
        plugin_source = PluginSource(self._shared.view, self._shared.size, source.path)
        context = PluginContext(encoding=encoding, archive_name=archive_name)
        with self._translated_errors(), self._handle_guard():
            reader = plugin.open(plugin_source, context)
        # Each check that the plugin kept to the interface sits outside the error
        # boundary, so a plugin's broad ``translate_exception`` cannot report a plugin
        # bug as a fault in the archive.
        if not isinstance(reader, IndexedReader):
            raise TypeError(
                f"{type(plugin).__name__}.open() returned "
                f"{type(reader).__name__}, not an IndexedReader"
            )
        self._reader = reader
        self._MEMBER_LIST_UPFRONT = reader.member_list_upfront

    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        return self._reader.translate_exception(exc)

    def _iter_members(self) -> Iterator[ArchiveMember]:
        with self._translated_errors(), self._handle_guard():
            records = iter(self._reader.iter_members())
        index = 0
        while True:
            with self._translated_errors(), self._handle_guard():
                record = next(records, None)
            if record is None:
                return
            member = record.member
            if not isinstance(member, ArchiveMember):
                raise TypeError(
                    f"{type(self._reader).__name__}.iter_members() yielded "
                    f"{type(member).__name__}, not an ArchiveMember"
                )
            presented = member.name
            member.name = normalize_member_name(
                presented, member.type, backslash_is_separator=False
            )
            member._raw = record.locator
            emit_member_name_normalized(
                self._diagnostics_collector,
                member=member,
                presented_name=presented,
                archive_name=self._archive_name,
                member_id=index,
            )
            index += 1
            yield member

    def _open_member(self, member: ArchiveMember) -> ArchiveStream:
        with self._translated_errors(member.name), self._handle_guard():
            data = self._reader.open_member(member, member._raw)
        if not isinstance(data, MemberData):
            raise TypeError(
                f"{type(self._reader).__name__}.open_member() returned "
                f"{type(data).__name__}, not MemberData"
            )
        stream: BinaryIO = data.stream
        if self._handle_lock is not None:
            stream = LockedStream(stream, self._handle_lock)
        expected: dict = dict(member.hashes)
        expected.update(data.expected_hashes)
        return self._wrap_member_stream(
            stream,
            member.name,
            size=member.size,
            # A listed size is enforced, so a short stream raises TruncatedError and
            # a long one CorruptionError. A file listed with no size is read to the
            # end of its stream, and only its digests are checked.
            expected_size=member.size,
            expected_hashes=expected or None,
            verify_member=member,
            fill_size=member.size is None,
            checks_content=data.checked,
        )

    def _get_archive_info(self) -> ArchiveInfo:
        with self._translated_errors(), self._handle_guard():
            info = self._reader.archive_info()
        cost = CostReceipt(
            listing_cost=(
                ListingCost.INDEXED
                if self._reader.member_list_upfront
                else ListingCost.REQUIRES_SCANNING
            ),
            access_cost=AccessCost.SOLID if info.is_solid else AccessCost.DIRECT,
            stream_capability=StreamCapability.SEEKABLE,
            solid_block_count=None,
        )
        # A plugin's keys are its own, namespaced by its format (``"cpio.variant"``),
        # so they are not in the inventory of built-in keys and are copied in as data.
        extra = ArchiveInfoExtra()
        extra.update(info.extra)
        return ArchiveInfo(
            format=self._format,
            format_version=info.format_version,
            is_solid=info.is_solid,
            member_count=None,
            comment=info.comment,
            is_encrypted=False,
            is_multivolume=False,
            cost=cost,
            extra=extra,
        )

    def _close_archive(self) -> None:
        try:
            with self._translated_errors(), self._handle_guard():
                self._reader.close()
        finally:
            self._shared.close()


class _PluginBackend(ReadBackend):
    """Base of the backend class :func:`register_plugin` builds for each plugin."""

    PLUGIN: ClassVar[type[FormatPlugin]]

    def open_read(
        self,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        passwords: _PasswordCandidates | None,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
        start_offset: int = 0,
    ) -> PluginReaderAdapter:
        reject_start_offset(start_offset, format, archive_name)
        return PluginReaderAdapter(
            self.PLUGIN(),
            source,
            format,
            streaming,
            encoding if self.USES_ENCODING else None,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )


def _prefix_probe(probe: object) -> ContentProbe:
    """Adapt a plugin's ``probe(prefix)`` to the registry's probe shape.

    The plugin gets the peeked prefix only: no ``read_at`` and no decode allowance, so
    it cannot make detection read more of an untrusted source.
    """
    assert callable(probe)

    def content_probe(
        prefix: bytes,
        /,
        *,
        source_length: int | None = None,
        read_at: Callable[[int, int], bytes | None] | None = None,
        charge_decode: Callable[[int], bool] | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        return bool(probe(prefix))

    return content_probe


def _check_plugin(plugin: type[FormatPlugin]) -> ArchiveFormat:
    if not (isinstance(plugin, type) and issubclass(plugin, FormatPlugin)):
        raise ArchiveyUsageError(
            f"register_format() takes a FormatPlugin subclass, got {plugin!r}"
        )
    fmt = getattr(plugin, "format", None)
    if not isinstance(fmt, ArchiveFormat):
        raise ArchiveyUsageError(
            f"{plugin.__name__}.format must be an ArchiveFormat, got {fmt!r}"
        )
    if not isinstance(fmt.container, PluginContainer):
        raise ArchiveyUsageError(
            f"{plugin.__name__}.format must use a PluginContainer member as its "
            f"container, got {fmt.container!r}"
        )
    if fmt.stream != StreamFormat.UNCOMPRESSED:
        raise ArchiveyUsageError(
            f"{plugin.__name__}.format must have an UNCOMPRESSED stream: outer "
            "compression around a plugin format is not supported yet"
        )
    registry = get_registry()
    if registry.registered_reader(fmt) is not None:
        raise ArchiveyUsageError(f"Format {fmt.display_name} is already registered")
    value = fmt.container.value
    if value in {c.value for c in ContainerFormat}:
        raise ArchiveyUsageError(
            f"{plugin.__name__}: container value {value!r} is a built-in format's"
        )
    for other in registry.list_known_formats():
        if isinstance(other.container, PluginContainer) and (
            other.container.value == value
        ):
            raise ArchiveyUsageError(
                f"{plugin.__name__}: container value {value!r} is already used by "
                f"{other.display_name}"
            )
    clash = plugin_spelling_clash(fmt)
    if clash is not None:
        spelling, owner = clash
        raise ArchiveyUsageError(
            f"{plugin.__name__}: format= spelling {spelling!r} already names "
            f"{owner.display_name}; choose a container value and member name no "
            "format uses"
        )
    claimed = {ext.lower(): owner for ext, owner in registry.extension_map().items()}
    for ext in plugin.extensions:
        if not ext.startswith(".") or len(ext) < 2:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: extension {ext!r} must be a dot followed by at "
                "least one character"
            )
        owner = claimed.get(ext.lower())
        if owner is not None:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: extension {ext!r} is already claimed by "
                f"{owner.display_name}"
            )
    for magic in plugin.magic:
        if magic.offset < 0 or not magic.data:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: magic {magic!r} needs a non-negative offset "
                "and at least one byte"
            )
    if plugin.probe is not None and not callable(plugin.probe):
        raise ArchiveyUsageError(f"{plugin.__name__}.probe must be callable or None")
    return fmt


def register_plugin(plugin: type[FormatPlugin]) -> None:
    """Build the backend class for ``plugin`` and register it (``register_format``)."""
    fmt = _check_plugin(plugin)
    extensions: Mapping[str, ArchiveFormat] = dict.fromkeys(plugin.extensions, fmt)
    probe = plugin.probe
    requires = tuple(plugin.requires)
    attrs: dict[str, object] = {
        "PLUGIN": plugin,
        "FORMATS": (fmt,),
        "EXTENSIONS": extensions,
        "MAGIC": tuple(MagicSignature(m.offset, m.data, fmt) for m in plugin.magic),
        "CONTENT_PROBES": (((fmt, _prefix_probe(probe)),) if probe is not None else ()),
        "USES_ENCODING": bool(plugin.uses_encoding),
        "NON_SEEKABLE_REASON": "its reader needs random access to the archive",
        "INSTALL_HINT": plugin.install_hint,
        "REQUIRED_MODULES": requires,
    }
    backend = type(f"{plugin.__name__}Backend", (_PluginBackend,), attrs)
    get_registry().register_plugin_backend(backend)
    add_plugin_spellings(fmt)


@contextmanager
def registration_scope() -> Generator[None]:
    """Undo, on exit, every :func:`register_plugin` made inside it.

    ``register_format`` is permanent by design, so this is for tests. It restores each
    table :func:`register_plugin` writes; a table that function comes to write is saved
    here too, next to the others.
    """
    restore_registry = get_registry().save_plugin_state()
    spellings = dict(format_args._plugin_spellings)
    try:
        yield
    finally:
        restore_registry()
        format_args._plugin_spellings.clear()
        format_args._plugin_spellings.update(spellings)
