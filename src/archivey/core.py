"""Public entry points: open archives and query format support.

``open_archive`` pipeline (in order): register backends → refuse a wrong-typed
``format=`` → validate streaming/concurrency → resolve source → incomplete
numbered-volume refuse (``.7z.NNN`` / ``.zip.NNN`` / ``.exe.NNN``) then Info-ZIP
``.zNN`` (both skipped when ``format=`` is an explicit non-joinable format) →
detect or accept format (a stub-only ``.exe`` / ``.sfx`` with no archive magic
follows the split first volume beside it) → other multi-volume checks → raw CD
sector image refusal (ISO, seekable source) → recognised-only refusal (DMG) →
read-once capability refusal (a non-seekable source for a format that needs seek in
either mode; its ``password=`` / ``encoding=`` diagnostics are emitted first) →
backend lookup and availability check (``PackageNotInstalledError``) →
``password=`` / ``encoding=`` diagnostics → access-mode refusal (a non-seekable
source with ``streaming=False``) → normalize stream origin →
``backend.open_read(...)``.
"""

from __future__ import annotations

import errno
import os
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal, cast, overload

from archivey.config import (
    DEFAULT_ARCHIVEY_CONFIG,
    AcceleratorMode,
    ArchiveyConfig,
    ExtractionLimits,
    ListingLimits,
    PasswordInput,
)
from archivey.detection import DetectionConfidence, FormatInfo
from archivey.diagnostics import (
    DiagnosticCode,
    UnusedArgumentContext,
)
from archivey.exceptions import (
    FormatDetectionError,
    StreamNotSeekableError,
    UnsupportedFeatureError,
    _UsageTypeError,
    _UsageValueError,
)
from archivey.internal.arg_checks import (
    check_config,
    check_encoding,
    check_path_not_empty,
    raise_if_text_stream,
    raise_if_write_only_stream,
)
from archivey.internal.backends.iso_reader import refuse_raw_sector_image
from archivey.internal.backends.zip_detect import (
    ZIP_MULTI_VOLUME_MSG,
    is_zip_split_segment_name,
)
from archivey.internal.config import stream_config_from_archivey
from archivey.internal.detection import (
    detect_format,
    detect_format_into,
    directory_format_info,
    probe_config,
)
from archivey.internal.diagnostics_collector import collector_from_config
from archivey.internal.format_args import (
    coerce_archive_format,
    coerce_stream_or_archive_format,
    outer_stream_format,
)
from archivey.internal.format_provenance import FormatProvenance
from archivey.internal.open_site import OpenSite, capture_open_site
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import (
    format_availability,
    get_registry,
    list_known_formats,
    list_supported_formats,
)
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.streams.codecs import codec_for_stream_format, open_codec_stream
from archivey.internal.streams.streamtools import OneReadEachStream, is_stream
from archivey.internal.volumes import (
    OpenSourceInput,
    ResolvedSource,
    first_volume_for_stub,
    incomplete_lone_numbered_volume_error,
    is_sfx_stub_name,
    resolve_source,
)
from archivey.reader import ArchiveReader, ForwardArchiveReader
from archivey.terminal import display_path
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    FormatAvailability,
    FormatSupport,
    MemberStreams,
    MissingComponent,
    StreamFormat,
)

if TYPE_CHECKING:
    from archivey.internal.base_reader import ReadBackend
    from archivey.internal.diagnostics_collector import DiagnosticCollector

__all__ = [
    "DEFAULT_ARCHIVEY_CONFIG",
    "AcceleratorMode",
    "ArchiveyConfig",
    "DetectionConfidence",
    "ExtractionLimits",
    "FormatAvailability",
    "FormatInfo",
    "FormatSupport",
    "ListingLimits",
    "MissingComponent",
    "detect_format",
    "format_availability",
    "list_known_formats",
    "list_supported_formats",
    "open_archive",
    "open_stream",
]


def _format_provenance(
    source_path: Path | None,
    requested_format: ArchiveFormat | None,
    detected: FormatInfo | None,
    *,
    is_directory: bool = False,
) -> FormatProvenance:
    """Record where the resolved format came from, for the empty-listing check.

    ``detected is None`` means detection never ran: either the caller asserted a format,
    or the source is a directory path (which resolves to ``DIRECTORY`` before detection).
    A directory path is ``"directory"`` even with ``format=DIRECTORY`` passed: the
    filesystem decided it, and any other ``format=`` is refused before this point.
    The re-detection source is kept only for the asserted case, and only when the
    opened source is one file (``source_path``) — reopening a file cannot disturb the
    reader, while seeking a live stream back to its origin can. It is the source as
    resolution left it, not the caller's argument: a later RAR part, a followed stub
    and a joined set all open something other than the name the caller passed, and
    re-detecting that name would judge a different file.
    """
    if detected is not None:
        chosen_by = "extension" if detected.detected_by == "extension" else "content"
        # Provenance, not confidence: stamp when a probe was the sole evidence.
        probe_only = (
            detected.detected_by == "content_probe" and not detected.corroborated
        )
        return FormatProvenance(chosen_by=chosen_by, probe_only=probe_only)
    if requested_format is None or is_directory:
        return FormatProvenance(chosen_by="directory")
    return FormatProvenance(chosen_by="argument", source=source_path)


def _raise_multi_volume_not_supported(
    fmt: ArchiveFormat, archive_name: str | None
) -> None:
    raise UnsupportedFeatureError(
        f"Format {fmt!r} does not support multi-volume archives.",
        source_format=fmt,
        archive_name=archive_name,
    )


def _refuse_unjoined_volume_names(
    resolved: ResolvedSource,
    format: ArchiveFormat | None,
    archive_name: str | None,
) -> None:
    if resolved.volume_count != 1:
        return
    # Numbered parts are joined for ZIP and 7z. An explicit other format= (P8)
    # must be honoured or refused as a format conflict, not rewritten as a
    # missing-volume error.
    if format is None or format in (ArchiveFormat.ZIP, ArchiveFormat.SEVEN_Z):
        error = incomplete_lone_numbered_volume_error(archive_name)
        if error is not None:
            raise error
    if is_zip_split_segment_name(archive_name) and (
        format is None or format == ArchiveFormat.ZIP
    ):
        raise UnsupportedFeatureError(
            ZIP_MULTI_VOLUME_MSG,
            archive_name=archive_name,
            source_format=ArchiveFormat.ZIP,
        )


def _follow_stub_volume(
    slot: _SourceSlot, format: ArchiveFormat | None, config: ArchiveyConfig | None
) -> ResolvedSource | None:
    """Switch ``slot`` from a stub-only ``.exe`` / ``.sfx`` to the split set beside it.

    Returns the resolved first volume, or ``None`` when no split volume sits beside
    the stub (``slot`` is then unchanged). Raises :class:`ArchiveyUsageError` when
    ``format`` names a different container than the volume's, and the volume-name
    refusals of :func:`_refuse_unjoined_volume_names`.
    """
    stub = slot.current.path
    if stub is None:
        return None
    alt = first_volume_for_stub(stub)
    if alt is None:
        return None
    resolved = resolve_source(alt)
    try:
        if format is not None:
            try:
                info = detect_format(
                    resolved.source,
                    config=probe_config(config),
                    follow_stub_volumes=False,
                )
            except FormatDetectionError:
                # This probe only catches a confident container mismatch. A volume
                # it cannot identify proves no conflict; the real detection after the
                # switch reports it, to the caller's own collector.
                pass
            else:
                if info.format.container != format.container:
                    # DR-15's value half: format= is a usable type, and the call
                    # refuses this value because it conflicts with what the source is.
                    raise _UsageValueError(
                        f"{display_path(stub)} has no archive magic; the split first "
                        f"volume beside it is {info.format.display_name}, but "
                        f"format={format!r} was requested."
                    )
        _refuse_unjoined_volume_names(resolved, format, resolved.archive_name)
    except BaseException:
        resolved.source.close()
        raise
    slot.replace(resolved.source)
    return resolved


# Two overloads carry the access mode into the return type: the default
# ``streaming=False`` gives the full ``ArchiveReader``, while ``streaming=True`` or a
# flag known only at run time gives ``ForwardArchiveReader``, which lacks the
# random-access methods, so a type checker flags a call that would raise.
@overload
def open_archive(
    source: OpenSourceInput,
    *,
    format: ArchiveFormat | str | None = None,
    streaming: Literal[False] = False,
    seekable_members: bool = False,
    concurrent_operations: bool = False,
    password: PasswordInput = None,
    encoding: str | None = None,
    config: ArchiveyConfig | None = None,
) -> ArchiveReader: ...


@overload
def open_archive(
    source: OpenSourceInput,
    *,
    format: ArchiveFormat | str | None = None,
    streaming: bool,
    seekable_members: bool = False,
    concurrent_operations: bool = False,
    password: PasswordInput = None,
    encoding: str | None = None,
    config: ArchiveyConfig | None = None,
) -> ForwardArchiveReader: ...


def open_archive(
    source: OpenSourceInput,
    *,
    format: ArchiveFormat | str | None = None,
    streaming: bool = False,
    seekable_members: bool = False,
    concurrent_operations: bool = False,
    password: PasswordInput = None,
    encoding: str | None = None,
    config: ArchiveyConfig | None = None,
) -> ForwardArchiveReader:
    """Open an archive for reading.

    ``streaming=False`` (the default) opens for random access and fails fast at open
    time on a non-seekable source. ``streaming=True`` promises forward-only, single-pass
    access (works on any source, but disables random-access methods).

    The return type follows the access mode: :class:`~archivey.ArchiveReader` for the
    default ``streaming=False``, and :class:`~archivey.ForwardArchiveReader`, which
    lacks ``members()``, ``get()``, ``open()`` and ``read()``, for ``streaming=True``
    or a flag whose value is known only at run time. A type checker then flags a
    random-access call on a streaming reader. Every reader is an ``ArchiveReader`` at
    run time; the difference is in the annotations only.

    By default member streams are forward-only, one may be open at a time, and reader
    operations do not overlap. Two keyword flags opt into more, each unlocking one
    specific trap:

    - ``seekable_members=True`` — ``seek()`` on a member stream from random
      ``open()`` works. Without it, ``seek()`` raises
      ``io.UnsupportedOperation``. A backward seek may re-decompress from the
      start when there is no index or accelerator. A ``stream_members()``
      stream never seeks, with or without this flag.
    - ``concurrent_operations=True`` — operations on the reader may overlap, from one
      thread or several, on every format: random ``open()`` / ``read()`` / ``get()``
      / ``members()``, iteration, ``stream_members()`` passes and ``extract_all()``.
      Each works as if it ran on a reader of its own. A single member stream object
      still has one owner, first-touch materialization is coordinated rather than
      parallel, and ``close()`` waits for calls in flight. Overlap is correct, not
      always cheaper. Without it, a second overlapping ``open()``, or a random-access
      call or another pass beside a running pass, raises ``ArchiveyUsageError``;
      ``close()`` beside a pass suspended at a yield closes the reader, and resuming
      the pass raises.

    ``open_stream`` uses the same vocabulary for the single-stream case
    (``open_stream(..., seekable=True)``); concurrency is meaningless there, so it has
    no counterpart. Declared concurrency does **not** gate solid open-order cost — see
    ``AccessCost`` / ``stream_members()``.

    ``streaming=True`` combined with ``concurrent_operations=True`` is rejected
    (``ArchiveyUsageError``): a forward-only pass cannot fan out.

    ``config`` supplies library tuning knobs (accelerator modes, the diagnostic
    policy, default extraction limits, and listing resource limits via
    ``listing_limits``). ``None`` selects the module default
    :data:`~archivey.DEFAULT_ARCHIVEY_CONFIG`.

    The format is auto-detected from the source's magic bytes (then its extension) unless
    ``format=`` is passed explicitly. A directory path opens as a directory pseudo-archive.
    A non-seekable stream keeps the bytes detection peeked in a replay prefix that the
    backend's first reads drain, so detection never consumes bytes the backend needs.
    A stream must be blocking: when a non-blocking one has nothing ready (its ``read``
    returns ``None``), opening or reading raises ``BlockingIOError``, not an archivey
    error.

    A seekable stream source is taken to hold the archive **starting at its current
    position**: detection peeks from there and restores the position, and the opener
    then rebases a mid-positioned stream to a zero origin so every backend sees the
    archive begin at ``tell() == 0`` (an archive embedded mid-file works uniformly,
    without manual slicing).

    ``encoding`` names the codec for member names whose encoding the archive does not
    declare and whose bytes are not valid UTF-8 (ZIP, TAR, ISO and RAR 1.5-4). A name
    whose bytes are valid UTF-8 is decoded as UTF-8 in every format, with or without
    ``encoding``, and ``encoding`` replaces only the format's fallback (cp437 or
    ``ArchiveyConfig.zip_unflagged_fallback_encoding`` for ZIP, the host's code page for
    RAR 1.5-4, surrogate escapes for TAR and ISO). ``member.raw_name`` keeps the stored
    bytes. A ZIP comment without the UTF-8 flag (the archive comment always) and an
    8-bit RAR 1.5-4 comment decode the same way as a name without a declared encoding,
    and a byte the codec does not define survives as a lone surrogate. The one
    difference is that a RAR comment's last fallback is always windows-1252. 7z,
    directory and single-file sources decode names another way, ignore it, and record
    ``ENCODING_ARGUMENT_UNUSED``.

    ``source`` may be an ordered sequence of paths or binary streams that together form
    a multi-volume archive (7z concatenates volumes; RAR opens volume 1 and lets
    ``unrar`` resolve siblings). A length-1 sequence is treated as a single source.

    ``password`` accepts a single value, an ordered sequence of candidate passwords, or
    a provider callable. List the most likely password first — especially for 7z, where
    each wrong candidate pays an expensive key derivation.

    With multiple candidates (or a provider), formats whose per-open password check is
    weak may need a confirmation read before a candidate is accepted. For traditional
    ZipCrypto this is usually cheap: compressed members are confirmed from a bounded
    decompressed prefix. **STORED** ZipCrypto members are the niche exception — roughly
    1/256 of wrong passwords pass the one-byte open check, and with no decompressor to
    reject garbage the reader must scan the member once (CRC over every surviving
    candidate in parallel) to decide. That full pass is rare in practice (multiple
    passwords *and* a colliding wrong candidate *and* a STORED member) but can matter
    for very large stored members. With a single password there is no confirmation
    read, so a wrong ZipCrypto password that passes the one-byte check fails on the
    member's own read, as an ``EncryptionError`` saying the password may be wrong or
    the member corrupt.

    A password supplied for a *format* with no encryption at all (TAR, ISO, a
    directory, the single-file compressed streams) is **accepted, not refused** — it is
    a resource offered, not a claim about this archive. A concrete password (a string,
    bytes, or a list of them) is recorded as ``PASSWORD_ARGUMENT_UNUSED``; a provider
    callable is not, because it is only a way to ask for a password, and such a format
    never asks. That is what lets a batch job pass one keyring at every archive. The
    check is per format, made before any header is read: an unencrypted ZIP, 7z or RAR
    records nothing, because those formats can use a password. Diagnostics also log
    at ``WARNING`` by default, so a job passing a password list will log once per
    archive of a format without encryption; silence it with
    ``ArchiveyConfig(diagnostic_policy=DiagnosticPolicy(ignore={
    DiagnosticCode.PASSWORD_ARGUMENT_UNUSED}))``, which keeps the count without the log
    line.

    Reader calls made after the open raise the same ``ReadError`` subclasses for damage,
    a wrong password or a missing link target that shows only when a member is read.

    Raises:
        FormatDetectionError: No format matches the source's contents or name.
        StreamNotSeekableError: The source cannot seek and ``streaming=False``, or the
            format needs to seek in either access mode (every format except TAR, ZIP and
            the single-file compressed streams).
        CorruptionError: The archive's header is damaged or cut short. A numbered split
            set with a missing part raises the subclass
            :class:`~archivey.TruncatedError`.
        EncryptionError: The member list is encrypted (7z, RAR) and no password given
            opens it.
        UnsupportedFeatureError: The format is recognized, but this archive uses a
            variant or feature archivey cannot read.
        PackageNotInstalledError: The format needs an optional package that is not
            installed, such as ``pycdlib`` for ISO.
        ResourceLimitError: The archive exceeds a limit that is checked at open, such as
            :class:`~archivey.ListingLimits` ``max_members`` while a ZIP, 7z, RAR or ISO
            index is parsed, or :class:`~archivey.DecoderLimits` for data the open
            decodes.
        DiagnosticRaisedError: A diagnostic that the :class:`~archivey.DiagnosticPolicy`
            in the config raises on, recorded while the archive is detected or opened.
        ArchiveyUsageError: One argument has a type or value the call cannot use (then
            also a ``TypeError`` or ``ValueError``), or ``streaming=True`` is combined
            with ``concurrent_operations=True``.
        FileNotFoundError: The path does not exist. Other ``OSError`` from reading the
            source is not wrapped either.
    """
    # Safety net for `from archivey.core import open_archive` (package __init__ also
    # imports backends so list_supported_formats works on a bare `import archivey`).
    import archivey.internal.backends  # noqa: F401

    open_site = capture_open_site()

    format = coerce_archive_format(format, call="open_archive(format=…)")
    if format is not None and format.container is ContainerFormat.UNKNOWN:
        # Detection's answer for "none of the above", not a format a caller can assert;
        # tested on the container so an unnamed pair such as (UNKNOWN, GZIP) is refused
        # too. Refused here rather than in coerce_archive_format:
        # format_availability(UNKNOWN) is a legitimate query that answers NONE.
        raise _UsageValueError(
            f"open_archive(format=…) cannot open {format!r}, which names no format; "
            f"pass the archive's format, or None to auto-detect."
        )
    check_config(config, call="open_archive(config=…)")
    check_encoding(encoding, call="open_archive(encoding=…)")

    if streaming and concurrent_operations:
        raise _UsageValueError(
            "open_archive(streaming=True) cannot be combined with "
            "concurrent_operations=True: a forward-only pass has one progressive decoder "
            "and cannot fan out concurrent member streams."
        )

    # The public surface is two booleans; everything below the entry point keeps
    # working in MemberStreams flags, held on the reader and its state. No public
    # attribute carries them and CostReceipt does not either.
    member_streams = MemberStreams(0)
    if seekable_members:
        member_streams |= MemberStreams.SEEKABLE
    if concurrent_operations:
        member_streams |= MemberStreams.CONCURRENT

    passwords = _PasswordCandidates.from_input(password)

    effective_config = config if config is not None else DEFAULT_ARCHIVEY_CONFIG
    # Collector is created before detection so open + detect share one budget /
    # occurrence order, and reader.diagnostics covers both.
    collector = collector_from_config(effective_config)
    resolved = resolve_source(source)
    slot = _SourceSlot(resolved.source)
    try:
        return _open_resolved(
            slot,
            resolved,
            format=format,
            streaming=streaming,
            passwords=passwords,
            encoding=encoding,
            config=effective_config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
    except BaseException:
        # Once a reader exists it closes its source; until then nobody else will.
        slot.current.close()
        raise


class _SourceSlot:
    """The source an open is working on, closing each one it is replaced by."""

    def __init__(self, source: ArchiveSource) -> None:
        self.current = source

    def replace(self, source: ArchiveSource) -> ArchiveSource:
        old = self.current
        self.current = source
        old.close()
        return source


def _note_unused_arguments(
    backend_cls: type[ReadBackend],
    resolved_format: ArchiveFormat,
    *,
    archive_name: str | None,
    passwords: _PasswordCandidates,
    encoding: str | None,
    collector: DiagnosticCollector,
) -> None:
    """Emit the ``password=`` / ``encoding=`` hygiene diagnostics for ``backend_cls``.

    Reads only class attributes, so it runs for a backend whose optional package is
    missing too. Both access-mode refusals call it first, so a refused open reports the
    same hygiene whichever half refuses it.
    """
    # `password=` and `encoding=` are *resources offered for use if needed*, not
    # assertions about this archive, so a backend that cannot use one is a diagnostic
    # rather than a refusal (``archive-reading`` §"assertion vs resource"). `format=` is
    # the assertion, and ``_open_resolved`` still refuses it for a directory path.
    if passwords.has_concrete_passwords() and not backend_cls.SUPPORTS_PASSWORD:
        # Every form opens alike: none is refused. Only a concrete value is recorded,
        # because a provider callable offers a password only if asked, and a format
        # with no encryption never asks. A caller (the CLI, a batch job) can then pass
        # one provider everywhere without a warning on every TAR or gzip.
        collector.emit(
            code=DiagnosticCode.PASSWORD_ARGUMENT_UNUSED,
            message=(
                f"password= was supplied for {resolved_format.display_name}, which "
                f"carries no encryption a password could unlock; it will not be used."
            ),
            context=UnusedArgumentContext(
                archive_name=archive_name,
                argument="password",
                format=resolved_format.display_name,
                reason="format carries no encryption",
            ),
        )

    if encoding is not None and not backend_cls.USES_ENCODING:
        # Only the caller's explicit encoding: an open that passed none asked for nothing.
        collector.emit(
            code=DiagnosticCode.ENCODING_ARGUMENT_UNUSED,
            message=(
                f"encoding={encoding!r} was supplied for "
                f"{resolved_format.display_name}, which decodes member names without "
                f"it; the value will not be applied."
            ),
            context=UnusedArgumentContext(
                archive_name=archive_name,
                argument="encoding",
                format=resolved_format.display_name,
                reason="backend decodes member names without a caller-supplied encoding",
            ),
        )


def _open_resolved(
    slot: _SourceSlot,
    resolved: ResolvedSource,
    *,
    format: ArchiveFormat | None,
    streaming: bool,
    passwords: _PasswordCandidates,
    encoding: str | None,
    config: ArchiveyConfig,
    collector: DiagnosticCollector,
    member_streams: MemberStreams,
    open_site: OpenSite | None,
) -> ArchiveReader:
    """Detect the format of a resolved source and hand it to its backend.

    ``slot`` holds the one source detection and the backend read. It changes when a
    self-extracting stub is followed to its volume or a RAR set is reopened from volume
    1; ``open_archive`` closes whatever it holds if this raises.
    """
    archive_source = slot.current
    archive_name = resolved.archive_name

    # Numbered 7-Zip parts (``.7z.NNN`` / ``.zip.NNN`` / ``.exe.NNN``) and Info-ZIP
    # ``.zNN``: middle/last parts often have no magic at offset 0, so detection
    # would raise FormatDetectionError or CorruptionError. Refuse by name first.
    # A joined set has ``volume_count > 1`` and is skipped. An explicit
    # ``format=TAR_GZ`` (etc.) is honoured or refused as a format conflict, never
    # rewritten as a volume error (P8).
    #
    # A lone numbered part names the missing siblings (``TruncatedError``). Info-ZIP
    # ``.zNN`` stays the ZIP rejoin-first ``UnsupportedFeatureError`` — those are
    # never concatenated.
    _refuse_unjoined_volume_names(resolved, format, archive_name)

    # --- Resolve format: a directory path is DIRECTORY (and a conflicting explicit
    # format= is rejected, not ignored); else caller format, else magic detect. ---
    resolved_format = format
    if archive_source.is_directory:
        # Silently overruling format= here would hand back a reader over the directory
        # tree for a caller who asserted something else -- the wrong data, succeeding.
        # Every other explicit-format conflict is refused loudly; so is this one.
        if format is not None and format != ArchiveFormat.DIRECTORY:
            assert archive_source.path is not None  # the directory form has a path
            # DR-15's value half: format= conflicts with what the source is.
            raise _UsageValueError(
                f"{archive_name or display_path(archive_source.path)} is a directory, but format="
                f"{format!r} was requested. Pass a path to an archive file, or "
                f"format=ArchiveFormat.DIRECTORY to read the directory tree."
            )
        resolved_format = ArchiveFormat.DIRECTORY
    elif format is not None and format.container is ContainerFormat.DIRECTORY:
        # The mirror of the conflict above, refused the same way; tested on the
        # container, so an unnamed pair such as (DIRECTORY, GZIP) gets this message
        # rather than "no read backend". A path the OS cannot stat (missing, under a
        # file, a symlink loop) raises the OS's own error first, as it does under every
        # other format=; Path.exists() would fold all of those into "missing".
        if archive_source.path is not None:
            os.stat(archive_source.path)
        where = archive_name or (
            display_path(archive_source.path)
            if archive_source.path is not None
            else "The source stream"
        )
        # DR-15's value half: format= conflicts with what the source is.
        raise _UsageValueError(
            f"{where} is not a directory, but format={format!r} was requested. Pass a "
            f"directory path, or the archive's own format (or None to auto-detect)."
        )

    detected: FormatInfo | None = None
    # What ``reader.format_info`` reports. A directory is decided without running
    # detection, but ``detect_format`` gives it a fixed answer, so the reader does too.
    format_info: FormatInfo | None = (
        directory_format_info()
        if archive_source.is_directory and format is None
        else None
    )
    if resolved_format is None:
        # A non-seekable source keeps what detection peeks in its own replay prefix,
        # so the backend gets the same object and reads those bytes first.
        # Probe *this* file only. Public detect_format follows a stub-only exe to
        # the volume beside it; doing that here would report 7z/ZIP while still
        # handing the stub bytes to the backend.
        try:
            detected = detect_format_into(
                archive_source,
                config=config,
                collector=collector,
                follow_stub_volumes=False,
            )
        except FormatDetectionError:
            followed = _follow_stub_volume(slot, format, config)
            if followed is None:
                raise
            resolved = followed
            detected = detect_format_into(
                slot.current, config=config, collector=collector
            )
        resolved_format = detected.format
        format_info = detected
    elif archive_source.path is not None and is_sfx_stub_name(archive_source.path.name):
        # format= still follows a stub-only miss. Skipping this made
        # detect_format(p); open_archive(p, format=info.format) open the MZ
        # bytes as ZIP/7z while auto-detect joined the split set.
        try:
            detect_format(
                archive_source,
                config=probe_config(config),
                follow_stub_volumes=False,
            )
        except FormatDetectionError:
            resolved = _follow_stub_volume(slot, resolved_format, config) or resolved
    archive_source = slot.current
    archive_name = resolved.archive_name

    # ZIP is here for 7-Zip's ``-v`` byte slices, which rejoin into an ordinary ZIP.
    # Info-ZIP's spanned sets never reach this point as a joined source (they are not
    # volume-shaped to ``discover_volume_siblings``); an explicitly passed sequence of
    # their parts is still caught by the reader's EOCD disk-field check.
    if resolved.volume_count > 1 and resolved_format.container not in (
        ContainerFormat.SEVEN_Z,
        ContainerFormat.RAR,
        ContainerFormat.ZIP,
    ):
        _raise_multi_volume_not_supported(resolved_format, archive_name)

    # A raw CD sector image is claimed as ISO only so it can be refused by name. Ahead
    # of the availability check, so the answer does not depend on pycdlib; a
    # non-seekable source is left to the read-once refusal below, which is also ahead
    # of it.
    if resolved_format == ArchiveFormat.ISO and archive_source.seekable():
        refuse_raw_sector_image(archive_source, resolved_format, archive_name)

    # Detection claims a recognised-only format (DMG) so this refusal can name it and
    # carry ``archive_name``. It comes before ``reader_for_format``, which raises the
    # same text but takes no archive name. Such a backend's own ``open_read`` must
    # raise the same refusal too, as ``UdifBackend`` does; nothing provides that.
    registry = get_registry()
    unread_message = registry.unread_format_message(resolved_format)
    if unread_message is not None:
        raise UnsupportedFeatureError(
            unread_message,
            source_format=resolved_format,
            archive_name=archive_name,
        )

    # Access-mode contract: streaming=False never implicitly buffers a pipe.
    # streaming=True still needs a format with a front-to-back walk (TAR, ZIP's local
    # headers, raw codecs); ISO, 7z and RAR cannot.
    source_is_read_once = (
        not archive_source.is_directory and not archive_source.seekable()
    )
    # Capability first, mode second: for a format that needs seek in *either* mode
    # the requested mode is not what went wrong, so both modes get the one message
    # naming the only fix. Proposing streaming=True here would send the caller into
    # a second refusal explaining the retry could never have worked. Ahead of the
    # availability check for the same reason: a piped ISO without pycdlib would
    # otherwise be told to install it, and only then that a pipe cannot be read.
    #
    # The argument-hygiene diagnostics still run first, as they do ahead of the mode
    # half below: a refused open reports the same ``password=`` / ``encoding=``
    # diagnostics whichever half refuses it. They read only class attributes, so they
    # need no optional package.
    if source_is_read_once and registry.needs_seekable_source(resolved_format):
        refused_cls = registry.registered_reader(resolved_format)
        assert refused_cls is not None  # needs_seekable_source is False without one
        _note_unused_arguments(
            refused_cls,
            resolved_format,
            archive_name=archive_name,
            passwords=passwords,
            encoding=encoding,
            collector=collector,
        )
        raise StreamNotSeekableError(
            f"Format {resolved_format.display_name} cannot be read from a non-seekable source "
            f"in either access mode ({refused_cls.NON_SEEKABLE_REASON}). Buffer it to "
            f"disk or a BytesIO and reopen.",
            source_format=resolved_format,
            archive_name=archive_name,
        )

    backend_cls = registry.reader_for_format(resolved_format)

    # The capability half above emits these too, so either refusal half reports them.
    _note_unused_arguments(
        backend_cls,
        resolved_format,
        archive_name=archive_name,
        passwords=passwords,
        encoding=encoding,
        collector=collector,
    )

    # The mode half of the access-mode refusal; the capability half is above. This one
    # stays after the availability check: the format can be read from a pipe, so the
    # missing package is a real step on the way, not a detour.
    if source_is_read_once and not streaming:
        raise StreamNotSeekableError(
            f"Random access (streaming=False) requires a seekable source. Open with "
            f"streaming=True for a single forward pass over this "
            f"{resolved_format.display_name} stream, "
            f"or buffer it to disk or a BytesIO and reopen.",
            source_format=resolved_format,
            archive_name=archive_name,
        )

    # Mid-file seekable streams: rebase so every backend sees tell()==0 at the first
    # archive byte (done after detection, which peeked from the same origin).
    if archive_source.seekable():
        archive_source.rebase_to_current_position()

    # A self-extracting source has an executable stub before the archive; detection
    # reports where the payload starts and the backend opens there. Handed over as an
    # explicit argument rather than by slicing here, so a path source stays a path:
    # RAR needs one to hand `unrar`, and turning it into a stream would spill the whole
    # archive to a temp file for every compressed member (`_ensure_archive_path`). The
    # argument carries the same promise a slice would — see `ReadBackend.open_read`.
    payload_offset = detected.payload_offset if detected is not None else 0

    backend = backend_cls()
    reader = backend.open_read(
        archive_source,
        format=resolved_format,
        streaming=streaming,
        passwords=passwords,
        encoding=encoding,
        archive_name=archive_name,
        config=config,
        collector=collector,
        member_streams=member_streams,
        open_site=open_site,
        start_offset=payload_offset,
    )
    # An empty listing is only interesting when the bytes never confirmed the format.
    # That is known here and the listing is not, so carry it to the reader rather than
    # adding a parameter to every backend's open_read for a fact none of them reads.
    reader._format_provenance = _format_provenance(
        archive_source.path,
        format,
        detected,
        is_directory=archive_source.is_directory,
    )
    reader._format_info = format_info
    # After provenance, so an open-time decode failure carries format_unconfirmed.
    try:
        reader._validate_at_open()
    except BaseException:
        reader.close()
        raise
    return reader


def open_stream(
    source: str | Path | BinaryIO,
    *,
    format: StreamFormat | ArchiveFormat | str | None = None,
    seekable: bool = False,
    config: ArchiveyConfig | None = None,
) -> ArchiveStream:
    """Open a single-file compressed stream and return a decompressing stream.

    This is the compressed-streams entry point for a bare ``.gz`` / ``.bz2`` / ``.xz`` /
    … payload (no archive container). ``seekable`` is the same capability
    :func:`open_archive` spells ``seekable_members``; concurrency is not a concept here
    — the call returns exactly one stream — so there is no counterpart to
    ``concurrent_operations``.

    ``seekable=False`` (the default) returns a forward-only stream: ``seekable()`` is
    ``False``, ``seek()`` raises ``io.UnsupportedOperation``, and no seek index or
    accelerator is instantiated. Pass ``seekable=True`` to opt into the
    seekable-decompressor-streams contract (native indexes, demand-driven accelerator
    ``AUTO``, loud slow rewinds on the non-accelerated path).

    ``format`` accepts a :class:`~archivey.StreamFormat`, a raw-stream
    :class:`~archivey.ArchiveFormat` (e.g. ``ArchiveFormat.GZ``), a compressed-tar
    :class:`~archivey.ArchiveFormat` (e.g. ``ArchiveFormat.TAR_GZ``), or ``None`` to
    auto-detect.

    For a compressed tar (``.tar.gz``, ``.tar.xz``, …), whether detected or passed as
    ``format=ArchiveFormat.TAR_GZ`` and so on, the returned stream removes the
    compression layer only and yields the tar bytes, as ``gzip.open`` does;
    ``open_archive(open_stream(p), streaming=True)`` then lists the same members as
    ``open_archive(p)``. Any other container (ZIP, 7z, RAR, ISO, an uncompressed tar)
    has no compression layer to remove: detecting one raises
    :class:`~archivey.FormatDetectionError`, and passing one as ``format=`` raises
    :class:`~archivey.ArchiveyUsageError`. Use :func:`open_archive` for those.

    A stream must be blocking: when a non-blocking one has nothing ready (its ``read``
    returns ``None``), opening or reading raises ``BlockingIOError``, not an archivey
    error.

    Reading the returned stream raises ``CorruptionError`` (or ``TruncatedError``) for
    damaged data, on the read that finds it.

    Raises:
        FormatDetectionError: No compression format matches the source, or the source is
            an archive container (ZIP, 7z, RAR, ISO, an uncompressed tar).
        StreamNotSeekableError: ``seekable=True`` and the source cannot seek.
        ResourceLimitError: The stream asks a decoder for more memory than
            :class:`~archivey.DecoderLimits` allows, raised by the read of the returned
            stream that starts the decoder.
        PackageNotInstalledError: The format needs an optional package that is not
            installed.
        DiagnosticRaisedError: A diagnostic that the :class:`~archivey.DiagnosticPolicy`
            in the config raises on, recorded while the stream is detected or opened.
        ArchiveyUsageError: One argument has a type or value the call cannot use (then
            also a ``TypeError`` or ``ValueError``): a directory path, or a container
            format passed as ``format=``.
        FileNotFoundError: The path does not exist.
    """
    import archivey.internal.backends  # noqa: F401

    # Before any I/O: a value of neither format type used to fall through to
    # auto-detection, which silently discards the caller's assertion.
    format = coerce_stream_or_archive_format(format, call="open_stream(format=…)")
    if (
        isinstance(format, ArchiveFormat)
        and format.container is ContainerFormat.UNKNOWN
    ):
        # Not a container: detection's answer for "none of the above". Refused here,
        # as open_archive refuses it, so a missing path or a directory does not answer
        # first; the container refusal in _resolve_stream_format would also send the
        # caller to open_archive, which refuses it as well.
        raise _UsageValueError(
            f"open_stream cannot open {format!r}, which names no format; pass a "
            "StreamFormat or a raw-stream ArchiveFormat (e.g. ArchiveFormat.GZ), "
            "or None to auto-detect."
        )
    check_config(config, call="open_stream(config=…)")

    effective_config = config if config is not None else DEFAULT_ARCHIVEY_CONFIG
    collector = collector_from_config(effective_config)

    if isinstance(source, (str, Path)):
        check_path_not_empty(source, call="open_stream()")
        path = Path(source)
        if path.is_dir():
            # Split out of the is_file() check: a directory exists, so "not found" sends
            # the caller looking for a missing file. open_archive() reads the same path
            # happily as a directory archive, which is the likely intent. DR-15's
            # value half: the path is a usable type whose value this call refuses.
            raise _UsageValueError(
                f"{display_path(path)} is a directory, not a compressed stream; "
                f"use open_archive() to read a directory tree"
            )
        if not path.exists():
            # errno and filename set, as open() sets them, so callers that format
            # OSError by its fields (the CLI does) report it like any missing path.
            raise FileNotFoundError(
                errno.ENOENT, "Compressed stream not found", str(path)
            )
        # A FIFO or device path is a non-seekable source with no path, read once
        # through the source, exactly as open_archive reads it.
        codec_input = ArchiveSource.for_path(path)
    else:
        if not is_stream(source):
            raise_if_text_stream(source)
            raise_if_write_only_stream(source)
            raise _UsageTypeError(
                f"open_stream source must be a path or binary stream, got {type(source)!r}"
            )
        # The same boundary open_archive uses: full-count, borrowed, bounded, and a
        # replay prefix for detection when the stream cannot be rewound. A codec — or a
        # seek-index accelerator reading the source itself — must not mistake a legal
        # short ``read(n)`` for a truncated stream.
        codec_input = ArchiveSource.for_stream(source)
        # The mid-stream origin contract: the payload starts where the caller left it.
        codec_input.rebase_to_current_position()
    # The returned stream owns the source from here, as a reader does: closing it closes
    # the source (which never closes the caller's object), and so does any refusal
    # before there is a stream to close.
    try:
        return _open_stream_from_source(
            codec_input, format, seekable, effective_config, collector
        )
    except BaseException:
        codec_input.close()
        raise


def _open_stream_from_source(
    codec_input: ArchiveSource,
    format: StreamFormat | ArchiveFormat | None,
    seekable: bool,
    effective_config: ArchiveyConfig,
    collector: DiagnosticCollector,
) -> ArchiveStream:
    source_is_seekable = codec_input.seekable()

    if seekable and not source_is_seekable:
        raise StreamNotSeekableError(
            "open_stream(seekable=True) requires a seekable source. Buffer the stream "
            "to disk or a BytesIO and reopen, or open with seekable=False for a "
            "forward-only pass."
        )

    stream_format = _resolve_stream_format(
        format, codec_input, collector, effective_config
    )
    # Only an explicit format= can be UNCOMPRESSED: detection never returns a
    # RAW_STREAM/UNCOMPRESSED pair, so this is the caller's mistake, not the input's.
    if stream_format is StreamFormat.UNCOMPRESSED:
        raise _UsageValueError(
            "open_stream requires a compressed stream format "
            f"(got {stream_format!r}); use open_archive for uncompressed containers."
        )

    codec = codec_for_stream_format(stream_format)
    # The codec stream is the whole source, so bytes after its end are reported.
    stream_config = replace(
        stream_config_from_archivey(
            effective_config,
            streaming=False,
            seekable=seekable and source_is_seekable,
        ),
        report_trailing_data=True,
    )
    # A path goes to the codec as a path: it opens its own handles and can use
    # path-only accelerator features, and the source then never opens one.
    codec_source: str | BinaryIO
    if codec_input.path is not None:
        codec_source = str(codec_input.path)
    elif source_is_seekable:
        codec_source = codec_input
    else:
        # What has arrived, one read of the source per feed, as the readers feed a
        # codec (``BaseArchiveReader._codec_input``).
        codec_source = OneReadEachStream(cast("BinaryIO", codec_input.arrived_view()))
    return open_codec_stream(
        codec,
        codec_source,
        config=stream_config,
        collector=collector,
        seekable=seekable and source_is_seekable,
        on_close=codec_input.close,
    )


def _resolve_stream_format(
    format: StreamFormat | ArchiveFormat | None,
    open_source: ArchiveSource,
    collector: DiagnosticCollector,
    config: ArchiveyConfig,
) -> StreamFormat:
    """Map open_stream's ``format=`` argument (or auto-detect) to a StreamFormat.

    Only ``None`` reaches the detection branch below: ``open_stream`` has already
    converted a string spelling and refused a value of neither format type
    (``coerce_stream_or_archive_format``), so falling through here means the caller
    asked for auto-detection.
    """
    if isinstance(format, StreamFormat):
        return format
    if isinstance(format, ArchiveFormat):
        # An UNKNOWN container never reaches here: open_stream refuses it before any I/O.
        outer = outer_stream_format(format)
        if outer is None:
            raise _UsageValueError(
                f"open_stream does not accept container format {format!r}; "
                "pass a StreamFormat, a raw-stream ArchiveFormat "
                "(e.g. ArchiveFormat.GZ) or a compressed tar, or use open_archive."
            )
        return outer

    # The invariant the docstring states, enforced rather than described: without it a
    # future caller of this private helper would auto-detect a value it was handed,
    # which is the silent fall-through this function's boundary check exists to close.
    assert format is None, f"unvalidated format argument reached detection: {format!r}"

    # The caller says the source is a compressed stream, so a probe answers only which
    # codec it is, never whether it is an archive: every probe runs, whatever its name.
    if not config.always_probe_content:
        config = replace(config, always_probe_content=True)
    detected = detect_format_into(open_source, config=config, collector=collector)
    outer = outer_stream_format(detected.format)
    if outer is None:
        # Detection found a container, not a compressed stream: to open_stream that is
        # the same answer as finding nothing it can open.
        raise FormatDetectionError(
            "Not a single-file compressed stream. Use open_archive for archive "
            "containers.",
            source_format=detected.format,
        )
    return outer
