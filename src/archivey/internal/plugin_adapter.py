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

import lzma
import threading
from collections.abc import Iterator, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, BinaryIO, ClassVar

from archivey.config import ArchiveyConfig
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticContext,
    validate_code_context,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    UnsupportedFeatureError,
)
from archivey.internal.base_reader import (
    BaseArchiveReader,
    ReadBackend,
    reject_start_offset,
)
from archivey.internal.config import stream_config_from_archivey
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.format_args import add_plugin_spellings
from archivey.internal.naming import emit_member_name_normalized, normalize_member_name
from archivey.internal.open_site import OpenSite
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import ContentProbe, get_registry
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import ArchiveStream, RewindWarning
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    decode_lzma_filter_properties,
    open_codec_stream,
)
from archivey.internal.streams.respawn import RespawnStream
from archivey.internal.streams.streamtools import (
    LockedStream,
    SharedSource,
    is_seekable,
)
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
    CompressionAlgorithm,
    ContainerFormat,
    MagicSignature,
    MemberStreams,
    PluginContainer,
    StreamFormat,
)

if TYPE_CHECKING:
    from archivey.config import ProcessIsolation


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
        self._plugin = plugin
        # The plugin may hold a handle of its own (a library over ``source.path``), so
        # under CONCURRENT every call into it, and every read of a stream it returned,
        # takes one lock. The views of ``PluginSource`` need none, but archivey cannot
        # tell which kind of reader it was given.
        if MemberStreams.CONCURRENT in member_streams:
            self._handle_lock = threading.Lock()
        self._shared = SharedSource(source, wrap_handle=self._seek_handle_wrapper())
        plugin_source = PluginSource(self._shared.view, self._shared.size, source.path)
        # The member decoder config, as ZIP builds its own: the compressed bytes a
        # plugin hands ``decompress`` are the codec's whole input, so a byte after the
        # codec's end of stream is damage.
        self._decoder_config = replace(
            stream_config_from_archivey(
                self._config,
                streaming=streaming,
                seekable=MemberStreams.SEEKABLE in member_streams,
                usage=self._usage,
            ),
            refuse_input_after_end=True,
        )
        # The walk position of the member being listed: the id registration will
        # stamp on it, for a report made before it is yielded.
        self._walk_index = 0
        context = PluginContext(
            encoding=encoding,
            archive_name=archive_name,
            config=config,
            decompress=self._decompress,
            report=self._report,
            link_target_unavailable=self._link_target_unavailable,
        )
        with self._translated_errors(), self._handle_guard():
            reader = plugin.open(plugin_source, context)
        if not isinstance(reader, IndexedReader):
            raise TypeError(
                f"{type(plugin).__name__}.open() returned "
                f"{type(reader).__name__}, not an IndexedReader"
            )
        self._reader = reader
        self._MEMBER_LIST_UPFRONT = reader.member_list_upfront

    def _decompress(
        self,
        data: BinaryIO,
        method: CompressionAlgorithm,
        size: int | None,
        properties: bytes | None,
    ) -> BinaryIO:
        """``PluginContext.decompress``: ``data`` through archivey's codec layer."""
        codec = _PLUGIN_CODECS.get(method)
        if codec is None:
            raise UnsupportedFeatureError(
                f"PluginContext.decompress() does not decode {method.name}",
                source_format=self._format,
                archive_name=self._archive_name,
            )
        params = CodecParams(single_stream=True)
        if codec is Codec.LZMA or codec is Codec.LZMA2:
            want = 5 if codec is Codec.LZMA else 1
            if properties is None or len(properties) != want:
                raise CorruptionError(
                    f"{method.name} needs {want} bytes of properties, got "
                    f"{'none' if properties is None else len(properties)}"
                )
            what = f"{self._format.display_name} {method.name} member"
            filter_id = lzma.FILTER_LZMA1 if codec is Codec.LZMA else lzma.FILTER_LZMA2
            params = CodecParams(
                filters=[
                    decode_lzma_filter_properties(filter_id, properties, what=what)
                ],
                # Raw LZMA1 may have no end marker: it stops at the stored size.
                unpack_size=size if codec is Codec.LZMA else None,
            )
        return open_codec_stream(
            codec,
            data,
            config=self._decoder_config,
            params=params,
            collector=self._diagnostics_collector,
        )

    def _member_id(self, member: ArchiveMember | None) -> int | None:
        if member is None:
            return None
        return member._member_id if member._member_id is not None else self._walk_index

    def _report(
        self,
        code: DiagnosticCode,
        message: str,
        details: DiagnosticContext,
        member: ArchiveMember | None,
    ) -> None:
        """``PluginContext.report``: one diagnostic, with the archive and member filled
        in."""
        if code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE:
            raise ArchiveyUsageError(
                "report SYMLINK_TARGET_UNAVAILABLE with "
                "PluginContext.link_target_unavailable()"
            )
        try:
            validate_code_context(code, details)
        except ValueError as exc:
            raise ArchiveyUsageError(f"PluginContext.report(): {exc}") from None
        fill: dict[str, object] = {}
        if getattr(details, "archive_name", "") is None:
            fill["archive_name"] = self._archive_name
        if getattr(details, "member_id", "") is None and member is not None:
            fill["member_id"] = self._member_id(member)
        self._diagnostics_collector.emit(
            code=code,
            message=message,
            context=replace(details, **fill) if fill else details,  # type: ignore[type-var]
            member=member,
            attach_to_member=member is not None,
        )

    def _link_target_unavailable(
        self,
        member: ArchiveMember,
        reason: str,
        message: str,
        target_in_archive: bool,
    ) -> None:
        member.link_target = None
        self._emit_link_target_unavailable(
            member,
            reason=reason,
            message=message,
            target_in_archive=target_in_archive,
            member_id=self._member_id(member),
        )

    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        # Before ``open()`` returns there is no reader: only the plugin translates.
        reader = getattr(self, "_reader", None)
        translated = None if reader is None else reader.translate_exception(exc)
        return (
            translated
            if translated is not None
            else self._plugin.translate_exception(exc)
        )

    def _iter_members(self) -> Iterator[ArchiveMember]:
        # One boundary and one guard for the whole walk: both are reusable, and
        # building them per member is a measurable part of listing a large archive.
        boundary = self._translated_errors()
        guard = self._handle_guard()
        with boundary, guard:
            records = iter(self._reader.iter_members())
        index = 0
        while True:
            self._walk_index = index
            with boundary, guard:
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

    def _plugin_member_data(self, member: ArchiveMember) -> MemberData:
        """Call the plugin's ``open_member``, with its stream under the handle lock."""
        with self._translated_errors(member.name), self._handle_guard():
            data = self._reader.open_member(member, member._raw)
            if not isinstance(data, MemberData):
                raise TypeError(
                    f"{type(self._reader).__name__}.open_member() returned "
                    f"{type(data).__name__}, not MemberData"
                )
        if self._handle_lock is not None:
            data = data._replace(stream=LockedStream(data.stream, self._handle_lock))
        return data

    def _open_member(self, member: ArchiveMember) -> ArchiveStream:
        data = self._plugin_member_data(member)
        stream: BinaryIO = data.stream
        rewind: RewindWarning | None = None
        if self._seek_declared() and not is_seekable(stream):
            # The caller asked for seekable members and the plugin's stream reads
            # forward only: a forward seek reads through, and a backward one opens
            # the member again from the start (``open_member`` once more). With no
            # listed size, a seek from the end reads through to find it.
            stream = RespawnStream(
                lambda: self._plugin_member_data(member).stream,
                stream,
                size=member.size,
                what=f"{self._format.display_name} member data",
            )
            rewind = RewindWarning(
                codec_name=self._format.display_name, suggest_install=False
            )
        expected = (
            {**member.hashes, **data.expected_hashes}
            if data.expected_hashes
            else member.hashes
        )
        return self._wrap_member_stream(
            stream,
            member.name,
            size=member.size,
            # The listed size is always enforced, so a short stream raises
            # TruncatedError and a long one CorruptionError.
            expected_size=member.size,
            expected_hashes=expected or None,
            verify_member=member,
            fill_size=member.size is None,
            checks_content=data.checked,
            custom_digests=(
                {d.name: (d.expected, d.new) for d in data.digests}
                if data.digests
                else None
            ),
            rewind_warning=rewind,
        )

    def _get_archive_info(self) -> ArchiveInfo:
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


# The methods ``PluginContext.decompress`` decodes. PPMd, the branch filters and RAR
# need parameters or framing a plain method name cannot carry.
_PLUGIN_CODECS: dict[CompressionAlgorithm, Codec] = {
    CompressionAlgorithm.STORED: Codec.STORED,
    CompressionAlgorithm.DEFLATE: Codec.DEFLATE,
    CompressionAlgorithm.DEFLATE64: Codec.DEFLATE64,
    CompressionAlgorithm.BZIP2: Codec.BZIP2,
    CompressionAlgorithm.ZSTD: Codec.ZSTD,
    CompressionAlgorithm.LZ4: Codec.LZ4,
    CompressionAlgorithm.BROTLI: Codec.BROTLI,
    CompressionAlgorithm.LZMA: Codec.LZMA,
    CompressionAlgorithm.LZMA2: Codec.LZMA2,
}


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
        read_at: object = None,
        charge_decode: object = None,
        isolation: ProcessIsolation | None = None,
    ) -> bool:
        return bool(probe(prefix))

    return content_probe  # type: ignore[return-value]


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
    builtin_extensions = {ext.lower() for ext in registry.extension_map()}
    for ext in plugin.extensions:
        if not ext.startswith(".") or len(ext) < 2:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: extension {ext!r} must start with a dot"
            )
        if ext.lower() in builtin_extensions:
            raise ArchiveyUsageError(
                f"{plugin.__name__}: extension {ext!r} is already claimed by "
                f"{registry.extension_map()[ext].display_name}"
                if ext in registry.extension_map()
                else f"{plugin.__name__}: extension {ext!r} is already claimed"
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


def _backend_class(
    plugin: type[FormatPlugin], fmt: ArchiveFormat, overrides: Mapping[str, object]
) -> type[_PluginBackend]:
    probe = plugin.probe
    attrs: dict[str, object] = {
        "PLUGIN": plugin,
        "FORMATS": (fmt,),
        "EXTENSIONS": dict.fromkeys(plugin.extensions, fmt),
        "MAGIC": tuple(MagicSignature(m.offset, m.data, fmt) for m in plugin.magic),
        "CONTENT_PROBES": (((fmt, _prefix_probe(probe)),) if probe is not None else ()),
        "USES_ENCODING": bool(plugin.uses_encoding),
        "NON_SEEKABLE_REASON": "its reader needs random access to the archive",
        "INSTALL_HINT": plugin.install_hint,
        "REQUIRED_MODULES": tuple(plugin.requires),
        **overrides,
    }
    return type(f"{plugin.__name__}Backend", (_PluginBackend,), attrs)


def register_plugin(plugin: type[FormatPlugin]) -> None:
    """Build the backend class for ``plugin`` and register it (``register_format``)."""
    fmt = _check_plugin(plugin)
    get_registry().register_plugin_backend(_backend_class(plugin, fmt, {}))
    add_plugin_spellings(fmt)


def register_builtin_plugin(
    plugin: type[FormatPlugin], **overrides: object
) -> type[ReadBackend]:
    """Register a built-in format whose reader is written against ``archivey.plugins``.

    The format keeps its built-in container, extensions, magic and place among the
    built-in backends, so detection does not change and ``FormatInfo.from_plugin`` is
    false. ``overrides`` sets backend attributes a plugin cannot declare
    (``NON_SEEKABLE_REASON``, ``OPTIONAL_DEPENDENCY``). Returns the backend class.
    """
    backend = _backend_class(plugin, plugin.format, overrides)
    get_registry().register_reader(backend)
    return backend
