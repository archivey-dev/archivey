"""BaseArchiveReader ABC and the ReadBackend ABC."""

from __future__ import annotations

import contextlib
import logging
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import (
    Callable,
    Collection,
    Generator,
    Hashable,
    Iterator,
    Mapping,
    Sequence,
    Set as AbstractSet,
)
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, replace
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    ClassVar,
    Literal,
    NamedTuple,
    NoReturn,
    Self,
    cast,
)

if TYPE_CHECKING:
    from archivey.internal.bomb_tracker import ReadRatioTally
    from archivey.internal.password import _PasswordCandidates
    from archivey.internal.registry import ContentProbe

from archivey.config import (
    DEFAULT_ARCHIVEY_CONFIG,
    ArchiveyConfig,
    DecoderLimits,
    ExtractionLimits,
)
from archivey.cost import CostReceipt
from archivey.detection import FormatInfo
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticSummary,
    DirectoryDataContext,
    EmptyArchiveContext,
    EncryptedVerificationContext,
    ExtractionReport,
    MemberListReport,
    MemberTimestampContext,
    NameEncodingContext,
    SpecialFileDataContext,
    SymlinkTargetContext,
    UnconfirmedFormatContext,
    raw_name_to_base64,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    EncryptionError,
    LinkTargetNotFoundError,
    LinkTargetNotFoundReason,
    PackageNotInstalledError,
    ReadError,
    ResourceLimitError,
    ResourceUnavailableError,
    UnsupportedFeatureError,
    _UsageTypeError,
    _UsageValueError,
    raw_message_of,
)
from archivey.internal.arg_checks import (
    check_callable,
    check_dest,
    check_extraction_limits,
    check_path_not_empty,
    describe_value,
)
from archivey.internal.diagnostics_collector import (
    DiagnosticCollector,
    EmitLog,
    collector_from_config,
)
from archivey.internal.enum_args import coerce_enum, coerce_enum_collection
from archivey.internal.file_copy_pass import DEFAULT_FILE_COPY_PASS, FileCopyPass
from archivey.internal.format_provenance import FormatProvenance
from archivey.internal.listing_limits import ListingLimitTracker
from archivey.internal.logs import backends as logger, integrity as integrity_logger
from archivey.internal.measurement import (
    ByteCounter,
    IoStats,
    SeekCounter,
    measurement_enabled,
)
from archivey.internal.member_pass import MemberPassImpl
from archivey.internal.naming import (
    emit_link_target_controls,
    emit_member_name_controls,
    link_target_name_keys,
    name_controls_possible,
    resolve_link_target_name,
)
from archivey.internal.open_site import OpenSite
from archivey.internal.password import is_unverified_data_error
from archivey.internal.password_confirm import UnverifiedPasswordReadWatch
from archivey.internal.reader_state import (
    LiveStreamReservation,
    ReaderState,
)
from archivey.internal.resource_usage import ResourceUsage, ResourceUsageRecorder
from archivey.internal.selection import (
    CollectionSelector,
    normalize_member_selector,
)
from archivey.internal.sfx import HitValidator
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import (
    ArchiveStreamImpl,
    ExceptionTranslator,
    MemberStreamParts,
    RewindWarning,
    _Opened,
    as_closed_source_error,
    compose_translators,
)
from archivey.internal.streams.counting import (
    CountingReader,
    OutputCountingStream,
    SeekCountingStream,
)
from archivey.internal.streams.streamtools import (
    OneReadEachStream,
    ReadableStream,
    is_seekable,
    read_exact,
    source_byte_size,
)
from archivey.internal.streams.verify import CustomDigests
from archivey.internal.timestamps import TimestampIssue
from archivey.internal.walk_handoff import WalkHandoffStream
from archivey.internal.windows_reparse import (
    REPARSE_HEADER_BYTES,
    parse_reparse_data,
    reparse_payload_length,
)
from archivey.reader import ArchiveReader, MemberPass
from archivey.terminal import escape_control_chars, quoted
from archivey.types import (
    EXTRA_IS_FILE_COPY,
    EXTRA_IS_JUNCTION,
    EXTRA_SPECIAL_FILE_TYPE,
    AbortOn,
    AbortOnStr,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    ExtractionPolicy,
    ExtractionPolicyStr,
    ExtractionProgress,
    HashAlgorithm,
    MagicSignature,
    MemberFilter,
    MemberSelectorArg,
    MemberStreams,
    MemberType,
    MissingComponent,
    OnError,
    OnErrorStr,
    OptionalLibrary,
    OverwritePolicy,
    OverwritePolicyStr,
    PluginStream,
    StreamFormat,
    TrailerSignature,
)

UNREADABLE_LINK_TARGET_ERRORS: tuple[type[ArchiveyError], ...] = (
    CorruptionError,
    UnsupportedFeatureError,
    PackageNotInstalledError,
)
"""What a read of one link's data-stored target may raise without failing the listing.

Damage (``CorruptionError``, and ``TruncatedError`` under it), a method or variant this
reader does not decode (``UnsupportedFeatureError``), and an optional library the
member's data needs that is not installed (``PackageNotInstalledError``: a codec, or
``cryptography`` for WinZip AES) are each about that one member's data. Listing
and a data pass leave the link targetless and report it
(``_report_unreadable_link_target``); opening or extracting the link reads it again and
raises the error itself. ``EncryptionError`` is not here: the backends catch it where
they read and report it with its own reason.
"""

MAX_LINK_TARGET_BYTES = 4096
"""Longest symlink target, in stored bytes, that a reader accepts from member data.

ZIP, 7z and RAR4 store a symlink's target as the member's *data*, which can be
compressed, so without a bound a few hundred KiB of archive decode to gigabytes inside
``members()``. A target is a path: ``PATH_MAX`` is 4096 on Linux and 1024 on macOS, so
no symlink a POSIX system wrote is longer. A longer one is treated as corrupt or
malicious — left unset with a ``SYMLINK_TARGET_UNAVAILABLE`` diagnostic, never
truncated, since a shortened path would point somewhere the archive did not say.

On Windows the number is a policy, not a consequence of ``PATH_MAX``: an extended-length
path runs to 32 767 UTF-16 units, so a genuine Windows symlink could carry a longer
target, and the same cap applied to a reparse buffer's target refuses it. That is
deliberate. The maintainer's ruling is about target length whatever format carries it —
a target over 4096 bytes is rejected as corrupt or malicious — so it is not a bug on
Windows input.

Targets stored in a header (TAR's ``linkname``, RAR5's redirection record, Rock Ridge)
are not read through this cap: the header parser has already allocated them, and
``ListingLimits.max_metadata_bytes`` weighs them at registration.
"""


_UnconfirmedEvidence = Literal["extension", "content_probe"]


# Members ``_drain_walk`` pulls per hold of the walk lock: enough that the lock and
# guards cost nothing per member, few enough that a pass on another thread is not kept
# waiting for a whole listing.
_DRAIN_BATCH = 256


class _UnconfirmedWording(NamedTuple):
    code: DiagnosticCode
    evidence_text: str  # "identified only by {evidence_text}"
    evidence_short: str  # "unconfirmed ({evidence_short})"


_UNCONFIRMED_EVIDENCE: Mapping[_UnconfirmedEvidence, _UnconfirmedWording] = {
    "extension": _UnconfirmedWording(
        DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED,
        "its file extension",
        "extension only",
    ),
    "content_probe": _UnconfirmedWording(
        DiagnosticCode.PROBE_FORMAT_UNCONFIRMED,
        "a content probe",
        "content probe only",
    ),
}
"""A decode-failure diagnostic per unconfirmed evidence: its code and two phrasings.

The extension code is also the empty-listing code, which
``_emit_listed_empty_unconfirmed`` emits with its own message.
"""


def _closer_of(source: Iterator[object]) -> Callable[[], None] | None:
    """The ``close`` of a backend's pass iterator when it is a generator, else ``None``.

    Recorded as the pass token's ``pass_closer`` so that ``close()`` can wind the
    backend pass down before teardown when the caller's iterator is suspended at a yield.
    """
    return source.close if isinstance(source, Generator) else None


def _apply_last_entry_wins_is_current(members: list[ArchiveMember]) -> None:
    """Stamp is_current for duplicate names (last same-name entry wins).

    A member the backend already marked not current (a RAR ``path;N`` file-version
    history row, an older plain ISO 9660 version) keeps that flag and takes no part
    in the count: a superseded version stays superseded even when a crafted archive
    repeats it. Members whose ``name`` appears only once among the rest are left
    unchanged.
    """
    current_names = [member.name for member in members if member.is_current]
    if len(set(current_names)) == len(current_names):
        # No duplicate names, the common case: nothing to stamp.
        return
    counts: dict[str, int] = {}
    for name in current_names:
        counts[name] = counts.get(name, 0) + 1

    seen: set[str] = set()
    for member in reversed(members):
        if counts.get(member.name, 0) < 2 or not member.is_current:
            continue
        if member.name in seen:
            member.is_current = False
        else:
            member.is_current = True
            seen.add(member.name)


def _settle_listing(
    members: list[ArchiveMember], *, links_too: bool = False, sizes_too: bool = False
) -> None:
    """The walk will not update ``members`` again (``member_state_final``).

    ``links_too``: nor will anything read their unread link targets or fill their
    unread size (the reader closed). ``sizes_too``: nor will a read fill their unread
    size (a ``streaming=True`` pass ended or failed: its members cannot be read again).
    """
    for member in members:
        member._listing_pending = False
        if links_too:
            member._link_target_unread = False
        if links_too or sizes_too:
            member._size_unread = False


class SolidRun(NamedTuple):
    """Where an ``open()`` starts decoding: :meth:`BaseArchiveReader._solid_run`.

    ``key`` names the run (a 7z folder, a solid RAR archive), and every open of a member
    in it decodes from the run's start: ``offset`` is the member's first byte in the
    run's decoded output, ``size`` its length.
    """

    key: Hashable
    offset: int
    size: int


@dataclass(frozen=True)
class _Materialized:
    """The published member listing: the report, frozen when the walk is published.

    Setting ``BaseArchiveReader._materialized`` to one of these is the single atomic
    point at which a listing becomes visible to other threads and later calls. Name
    lookups read the walk's own index, ``BaseArchiveReader._listed_by_name``.
    """

    report: MemberListReport


def _new_read_ratio_tally() -> ReadRatioTally:
    # Imported here: the codec layer imports reader-side modules at load.
    from archivey.internal.bomb_tracker import ReadRatioTally

    return ReadRatioTally()


def pass_has_data(member: ArchiveMember) -> bool:
    """Whether a data pass yields a stream for ``member``: the members ``open()`` reads.

    A ``FILE``, and a ``DIRECTORY`` whose header declares data (a non-zero ``size``):
    the bytes ``MEMBER_DIRECTORY_DATA_IGNORED`` reports and extraction does not write
    (DR-25). Every other member has no data of its own, so the pass yields ``None``.
    ``open()`` applies the same test to the member a link resolves to, so a pass and
    a random-access read deliver the same bytes and refuse the same members, except
    a bit-3 ZIP directory read from a source that cannot seek: its size arrives after
    its data, so ``size`` is ``None`` when the pass reaches it and the pass yields
    ``None`` where ``open()`` from a seekable source reads.
    """
    if member.is_file:
        return True
    return member.type is MemberType.DIRECTORY and bool(member.size)


def reject_start_offset(
    start_offset: int, fmt: ArchiveFormat, archive_name: str | None
) -> None:
    """Refuse a nonzero ``open_read(start_offset=…)`` for a format that cannot honour it.

    Only the self-extracting formats (RAR / 7z / ZIP) are ever handed a nonzero offset,
    because only they can carry an executable stub and only they are scanned for one by
    ``detect_format``. Reaching here with an offset means a caller invented one, and
    reading from byte 0 instead would answer with the wrong bytes rather than say so.
    """
    if start_offset:
        raise UnsupportedFeatureError(
            f"{fmt.display_name} cannot be opened at a nonzero start offset "
            f"({start_offset}): the format carries no self-extracting stub.",
            source_format=fmt,
            archive_name=archive_name,
        )


class ReadBackend(ABC):
    """Stateless factory for creating ArchiveReader instances.

    Each backend declares its magic and extensions **as data**, and every entry names
    the :class:`ArchiveFormat` it implies, so a *multi-format* backend (the single
    ``SingleFileBackend``, the TAR backend over ``TAR`` + its compressed combos) can map
    each signal to the right format. The detector aggregates these across all registered
    backends; backends carry no ``detect()`` method.
    """

    FORMATS: tuple[ArchiveFormat, ...]
    # Whether the backend also reads each of its ``FORMATS`` inside every single-file
    # compression stream: TAR's ``.tar.gz``, a sequential plugin's ``.cpio.gz``. The
    # registry makes those pairs when asked, from the codecs registered then, so a
    # codec registered later reaches them too; ``FORMATS`` does not list them.
    STREAM_PAIRS: ClassVar[bool] = False
    # The extensions a stream's own is appended to for those pairs: ``.tar`` gives
    # ``.tar.gz``, ``.tar.xz``, and so on. Each must also be an ``EXTENSIONS`` key,
    # which names the container. Other pair spellings (``.tgz``) go in ``EXTENSIONS``.
    PAIR_EXTENSIONS: ClassVar[tuple[str, ...]] = ()
    # Whether this is the backend for a single compressed file, with no container:
    # ``ArchiveFormat(RAW_STREAM, <stream>)`` for every single-file codec, made when
    # asked like the pairs above. Only ``SingleFileBackend`` sets it.
    RAW_STREAMS: ClassVar[bool] = False
    # ".gz" -> ArchiveFormat.GZ
    EXTENSIONS: Mapping[str, ArchiveFormat] = {}
    # Exact magic-byte signals as data (offset, bytes, format), accepted on the byte match.
    MAGIC: tuple[MagicSignature, ...] = ()
    # Magic the inner-container probe looks for in the first 512 decoded bytes of a
    # single-file compressed stream, naming the uncompressed container it finds there:
    # TAR's ``ustar`` makes a ``.gz`` a ``TAR_GZ``, and a sequential plugin's magic makes
    # one ``(<plugin container>, GZIP)``. Only a backend that reads that container
    # through every single-file codec declares it.
    INNER_MAGIC: tuple[MagicSignature, ...] = ()
    # Magic to hunt for *behind an executable stub*, for the formats that ship as
    # self-extracting archives (RAR / 7z / ZIP). The offset is 0 because these are
    # magic at offset 0 of the *payload*, wherever in the file that starts; the
    # detector searches for them within the shared SFX_MAX window when the leading
    # bytes look executable-shaped, and reports the match position as
    # ``FormatInfo.payload_offset``. Deliberately a separate, narrower table than
    # ``MAGIC``: ZIP declares only its local-file header here, because scanning a stub
    # for the EOCD or spanned markers would claim any file containing those four bytes.
    SFX_MAGIC: tuple[MagicSignature, ...] = ()
    # Format-owned check the SFX scan calls on a candidate-relative view plus
    # known remaining length from that origin (``None`` if the source size is
    # unknown). ``None`` here means "needle match is enough". ZIP, 7z, and RAR
    # all supply one so a stub that merely contains their magic bytes is not
    # claimed: ZIP's local-header sanity check, 7z ``StartHeaderCRC``, RAR 5
    # main-header CRC32 / RAR 4 MAIN.
    # Returns :class:`~archivey.internal.sfx.HitOutcome`; the detector treats
    # anything other than ``VALID`` as "skip and continue".
    # Subclasses that supply a function must wrap it in ``staticmethod`` — a bare
    # function on the class body is a descriptor, and an instance lookup would bind
    # ``self`` as the first argument. The other detection tables (MAGIC, SFX_MAGIC)
    # are inert data and do not have this problem.
    SFX_HIT_VALIDATOR: ClassVar[HitValidator | None] = None
    # Whether this backend's parser finds a payload behind a stub with its own capped
    # forward scan (``sfx.scan_for_magic``), as the RAR and 7z parsers do. The
    # detector applies the same rejection cap to these formats only, so detection
    # gives up exactly where forced ``format=`` does. A format whose reader locates
    # its directory another way (ZIP reads the end of central directory from the
    # tail) has no scan to agree with and is never capped.
    SFX_PARSER_SCANS: ClassVar[bool] = False
    # Formats this backend reads that have no exact magic and are recognized by a content
    # probe instead: (format, probe) pairs, where the probe inspects a peeked prefix and
    # returns True on a match (Brotli has no signature; zlib's 2-byte header is too weak).
    CONTENT_PROBES: tuple[tuple[ArchiveFormat, ContentProbe], ...] = ()
    # Formats this backend reads whose first block checks itself, with no magic to find:
    # (format, check) pairs, where the check takes the peeked prefix and returns True
    # when it opens with such a block (a v7 TAR header, by its checksum). Stronger
    # evidence than a content probe, so it runs on every source, named or not.
    HEADER_CHECKS: tuple[tuple[ArchiveFormat, Callable[[bytes], bool]], ...] = ()
    # Exact magic at the start of a fixed-length block at EOF. A hit is ``magic`` /
    # ``CERTAIN``, and it outranks a near-magic format listed in ``preempts``.
    TRAILER: tuple[TrailerSignature, ...] = ()
    # False when the backend exists so detection can name the format, and open
    # refuses it. Availability is NONE with nothing to install.
    READ_IMPLEMENTED: bool = True
    # The ``UnsupportedFeatureError`` text when ``READ_IMPLEMENTED`` is false.
    UNSUPPORTED_MESSAGE: str | None = None
    # Whether open_archive(streaming=True) may open a NON-SEEKABLE source: true for,
    # among others, TAR, ZIP (by its local headers) and the single-file codecs; false
    # for, among others, ISO and 7z. Each backend with it false says why in
    # NON_SEEKABLE_REASON. Random access (streaming=False) always requires a seekable
    # source (repeatable open()/read() cannot be honored over one forward pass, and
    # the library never implicitly buffers), so that side needs no per-backend flag.
    SUPPORTS_STREAMING_NON_SEEKABLE: bool = False
    # Why a format with the flag above False cannot come from a non-seekable source,
    # as a clause for open_archive()'s StreamNotSeekableError. Formats differ: 7z's
    # index is at the end, but RAR's headers are at the front and its header walk and
    # unrar are what need seeks.
    NON_SEEKABLE_REASON: str = "its index is not at the front of the stream"
    # Whether this backend's format has encryption a password could unlock. Checked
    # centrally by open_archive(): a password passed for a format that cannot use one is
    # accepted and recorded as PASSWORD_ARGUMENT_UNUSED (a keyring offered, not an
    # assertion about this archive). ZIP sets this True; the native 7z/RAR readers too.
    SUPPORTS_PASSWORD: bool = False
    # Whether this backend applies a caller-supplied `encoding=` when decoding member
    # names. False for backends that decode names some other way — 7z stores UTF-16LE,
    # the directory and single-file names come from the filesystem — so open_archive()
    # can record ENCODING_ARGUMENT_UNUSED instead of the backend silently
    # `del encoding`-ing it, which is how five of them used to differ from ZIP and TAR
    # with no signal at all.
    USES_ENCODING: bool = False
    # The optional package this backend needs, such as ``OptionalLibrary.PYCDLIB``; the
    # registry derives availability centrally from whether it imports. ``None`` for core
    # backends.
    OPTIONAL_DEPENDENCY: OptionalLibrary | None = None
    # More modules the backend imports, checked after ``OPTIONAL_DEPENDENCY`` the same
    # way. Only plugin backends set it (``FormatHandler.requires``); ``INSTALL_HINT``
    # covers them all.
    REQUIRED_MODULES: tuple[str, ...] = ()
    # Human-readable install hint surfaced when the dependency is absent
    # (e.g. "pip install archivey[recommended]").
    INSTALL_HINT: str | None = None

    @classmethod
    def missing_programs(cls) -> tuple[MissingComponent, ...]:
        """External programs this backend can use that are not usable here.

        A backend that still opens and lists without them makes its format ``PARTIAL``
        in the public ``format_availability()`` query. Only that query calls this: a
        backend may run a program once to identify it, and ``open_archive`` must not
        pay for that. Empty for backends that run no external program.
        """
        return ()

    @abstractmethod
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
    ) -> BaseArchiveReader:
        """Open ``source`` as ``format`` (the resolved format the registry selected this
        backend for — either detected by ``open_archive`` or supplied by the caller).

        ``source`` is the :class:`ArchiveSource` the boundary built. The reader this
        returns owns it and closes it on teardown; a constructor that raises leaves it to
        ``open_archive``, which closes it. A
        multi-format backend uses it to pick its concrete codec/variant rather than
        re-inspecting the source.

        ``collector`` is the prospective reader's diagnostic collector (created before
        detection). When omitted, the reader creates one from ``config``.

        ``start_offset`` is where the archive proper begins inside ``source`` — nonzero
        only for a self-extracting archive behind an executable stub, where it carries
        detection's ``FormatInfo.payload_offset``. A backend that accepts it MUST behave
        exactly as if it had been handed a view of ``source`` starting at that offset:
        nothing before it belongs to the archive. (The one visible difference is that a
        backend may still use the original path for an external tool that finds the
        payload itself — ``unrar`` on an SFX file.) Backends whose formats never carry a
        stub reject a nonzero value rather than silently reading from byte 0.
        """
        ...


def special_file_has_data_report(
    member: ArchiveMember,
) -> tuple[DiagnosticCode, str, SpecialFileDataContext]:
    """The ``MEMBER_SPECIAL_FILE_HAS_DATA`` report for a ``FILE`` whose stored type is
    a device, FIFO or socket (``extra["special_file_type"]`` is set): its code, message
    and context, without the archive name or member id."""
    special = member.extra.get(EXTRA_SPECIAL_FILE_TYPE)
    assert isinstance(special, str)
    size = member.size
    stored = "data" if size is None else f"{size} bytes"
    # "unknown" stands for file-type bits no Unix type uses; the four named
    # kinds read as nouns.
    kind = (
        "an unrecognized file type"
        if special == "unknown"
        else f"a {special.replace('_', ' ')}"
    )
    return (
        DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA,
        (
            f"Member {quoted(member.name)} is listed as a file: the archive marks it "
            f"as {kind} and stores {stored} for it."
        ),
        SpecialFileDataContext(
            member_name=member.name, special_file_type=special, size=size
        ),
    )


class BaseArchiveReader(ArchiveReader):
    """Internal helper base for all format readers — the backend contract lives here.

    Implements the public :class:`ArchiveReader` surface (iteration, lookup, link
    following, lifecycle). Format backends extend **this**, not ``ArchiveReader``.

    Implementing a backend
    ----------------------
    **MUST implement** (abstract):

    - ``_iter_members()``       — yield every :class:`ArchiveMember` once, in archive
      order.
    - ``_open_member(member)``  — open a ``FILE`` member's data and return it as
      ``_member_parts(raw, ...)``. One ``ArchiveStream`` then serves it (every member
      handle the library hands out is one: uniform error translation/stamping, the
      ``size`` advertisement, and room to grow shared handle features).
    - ``_get_archive_info()``   — return the :class:`ArchiveInfo` (format, solidity,
      cost, …).
    - ``_close_archive()``      — release resources (called exactly once, via
      ``close()``).

    **MUST set** when it differs from the default (``True``):

    - ``_MEMBER_LIST_UPFRONT``    — does the backend have a true upfront index (central
      directory, 7z header, or a header walk already done at open, as RAR's) that yields
      the full member list *without a further scan*? This is the predicate behind
      :meth:`members_report_if_available` (it returns a report when ``True``, else
      ``None``). It does **not** gate the access-mode-enforced methods — those key off
      the ``streaming`` flag alone.

    Access-mode enforcement (independent of the flag above): a ``streaming=True`` reader
    is forward-only, so ``members``/``get``/``open``/``read`` all raise
    ``ArchiveyUsageError`` — uniformly, not per-backend. Only a single pass of
    ``__iter__``/``stream_members``/``extract_all`` is allowed; ``members_report()`` may
    finish or return that pass. ``members_report_if_available()`` is a scan-free,
    index-only peek. ``member in reader`` is identity-based and scan-free, so it works in
    either mode; there is no ``__len__``/``__getitem__`` (name lookup is ``get()``).

    **MAY override**:

    - ``_solid_run(member)`` — where ``open()`` starts decoding for ``member``, for a
      backend whose every open decodes a shared run from its start. Feeds the
      once-per-reader re-decode record; the default (``None``) never logs.
    - ``_iter_with_data()`` — see its own docstring. The default is correct for
      random-access / indexed backends only; **streaming / solid backends MUST override
      it** (correctness, not just efficiency). Streaming backends that override
      ``_iter_with_data()`` **MUST** route their forward metadata pass through the shared
      instance-held progressive pass (``_begin_forward_pass``) so
      ``members_report()`` can finish an interrupted pass and the resolved cache is
      finalized on completion. A backend whose own pass walks a cached list (7z, solid
      RAR) iterates ``_listed_members()``, which does that in streaming and drains the
      shared walk in random access, so its members are the reader's own objects.

    Everything else here (``_materialize_members``, ``_resolve_link``,
    ``_open_with_link_follow``, ``_stamp_error_context``) is internal plumbing and is not
    an extension point.
    """

    # Is the full member list available without reading member data (e.g. a central
    # directory)? Drives members_report_if_available(); does not gate the streaming methods.
    _MEMBER_LIST_UPFRONT: bool = True
    # Can a symlink's target be stored as member data, read by ``_ensure_link_target``
    # (ZIP, 7z, RAR 4)? Such a link reads ``member_state_final=False`` until that read.
    # Elsewhere the target is set while the member is typed, so nothing is left to read.
    _LINK_TARGETS_IN_DATA: bool = False
    # Does a forward pass change members it has already yielded, once the walk ends (a
    # ZIP read from a pipe, whose central directory comes last)? ``extract_all`` then
    # stages each such member's data and places the members only once the walk has
    # ended (``ExtractionCoordinator._stage_then_place``).
    _REVISES_YIELDED_MEMBERS: bool = False

    def __init__(
        self,
        format: ArchiveFormat,
        streaming: bool,
        archive_name: str | None,
        config: ArchiveyConfig | None = None,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
    ) -> None:
        self._format = format
        self._streaming = streaming
        self._archive_name = archive_name
        self._config = config if config is not None else DEFAULT_ARCHIVEY_CONFIG
        self._diagnostics_collector = (
            collector if collector is not None else collector_from_config(self._config)
        )
        self._member_streams = member_streams
        self._open_site = open_site
        self._state = ReaderState(member_streams=member_streams, open_site=open_site)
        # A random, opaque identity token (not id(self), which the allocator can reuse
        # after a reader is garbage-collected — a member of a dead reader must never
        # pass another reader's identity check; and not a plain counter, whose small
        # sequential values invite confusion with member_id or hardcoding).
        self._archive_id = uuid.uuid4().hex
        # How far open() has decoded each solid run (``_solid_run``), until one open
        # decodes again bytes an earlier one decoded: that logs the advice once (an
        # INFO record by ruling, not a diagnostic or a warnings.warn), and counting
        # stops (``None``).
        self._solid_decoded: dict[Hashable, tuple[int, int]] | None = {}
        self._solid_decoded_lock = threading.Lock()
        # The archive's source, recorded by every backend's constructor. The reader owns
        # it: teardown closes it after ``_close_archive``. Also backs
        # ``compressed_source_size`` below.
        self._source: ArchiveSource | None = None
        # A counter wrapping the raw compressed source, set by a backend that decompresses
        # a stream source; backs compressed_bytes_consumed (the live decompression-ratio
        # denominator for a source whose total size is not cheaply knowable).
        self._compressed_input_counter: CountingReader | None = None
        # What open() and stream_members() streams have decoded, for the archive-wide
        # ratio they are held to (``_hold_to_ratio``).
        self._read_ratio_tally = _new_read_ratio_tally()
        # Opt-in benchmark counters (see archivey.internal.measurement). When measurement
        # is off these stay None and wrap helpers are identity — zero hot-path overhead.
        self._measure = measurement_enabled()
        self._decompressed_counter: ByteCounter | None = (
            ByteCounter() if self._measure else None
        )
        self._seek_counter: SeekCounter | None = (
            SeekCounter() if self._measure else None
        )
        self._materialized: _Materialized | None = None
        # The one member walk (see ``_pull_member``). Every listing method and every
        # pass reads ``_listed``, so each member is one object, registered once, and
        # ``_iter_members()`` runs once for a walk that completes. ``_walk`` is the
        # backend's generator while the walk is unfinished; ``_walk_done`` is set when it
        # ends, cleanly or on terminal damage, and ``_walk_error`` holds that damage.
        # Its object identity is a contract: extraction tells listing damage (write the
        # prefix, then raise) from a member fault by ``exc is _walk_error``, so a pass
        # that ends on the damage re-raises this object and never wraps it.
        # ``_walk_failure`` poisons a streaming walk that failed any other way, since
        # its prefix was already handed out and cannot be walked again. Until a
        # random-access walk ends, ``_walk_built`` keeps every member object it produced
        # and ``_walk_emits`` a log of what the backend emitted typing each position
        # (see ``_pull_replayable``): a walk started over after a failure replays those
        # positions onto the same objects, with their diagnostics already emitted and
        # attached. A streaming walk keeps neither.
        # ``_walk_presented`` counts the positions whose presentation checks have run;
        # ``_presenting`` logs the emits of a position whose checks raised part way, so
        # the retry replays them (see ``_register_member``). ``_walk_position``
        # counts the members the walk has produced.
        self._listed: list[ArchiveMember] = []
        # The member id of each member the walk yielded and ``_drop_listed`` then took
        # out of the listing; extraction does not place them, and drops what it staged
        # for them (``ExtractionCoordinator._stage_then_place``).
        self._dropped_listed: set[int] = set()
        # Members the end of a revising walk fails (``_REVISES_YIELDED_MEMBERS``), in
        # the index's order, with why: the walk's error is the first of them, and
        # extraction gives each its result.
        self._failed_at_end: list[tuple[ArchiveMember, CorruptionError]] = []
        # Name to the member listed under it, or to a list of them in listing order
        # once a second member has that name: a list here always holds two or more. A
        # list per name would be one more object per member for the collector to walk.
        # Read it through ``_listed_named`` or ``_last_by_exact_name``.
        self._listed_by_name: dict[str, ArchiveMember | list[ArchiveMember]] = {}
        self._walk_position: int = 0
        self._walk: Iterator[ArchiveMember] | None = None
        self._walk_done: bool = False
        self._walk_error: CorruptionError | None = None
        self._walk_failure: BaseException | None = None
        # ``_walk_ahead`` met ``_walk_failure``; the next pull raises it as it is.
        self._walk_failure_unraised: bool = False
        self._walk_pulling: bool = False
        # Every pull, every pass cursor step and link finalization hold this lock, so
        # the passes and listing calls a CONCURRENT reader runs side by side share the
        # one walk: each reads ``_listed`` at its own position and pulls the next member
        # when it reaches the end. Re-entrant, so a callback that re-enters the walk on
        # the same thread reaches the ``_walk_pulling`` check instead of deadlocking.
        # It is taken after the materialization election, never before it.
        self._walk_lock = threading.RLock()
        # A random-access pass's member stream that reads through the walk
        # (``_walk_handoff_locked``); the walk detaches it before its next pull
        # (``_before_pull_locked``). Set only under ``_walk_lock``, so none appears
        # during a batch of pulls.
        self._walk_stream: WalkHandoffStream | None = None
        self._walk_built: list[ArchiveMember] = []
        self._walk_emits: dict[int, EmitLog] = {}
        # An unused log from a position that emitted nothing (``_pull_replayable``).
        self._spare_emit_log: EmitLog | None = None
        self._walk_presented: int = 0
        self._presenting: tuple[int, EmitLog] | None = None
        # Set by open_archive on the reader it is about to return; read only by the
        # empty-listing check in _publish_materialized. None for a reader built directly.
        self._format_provenance: FormatProvenance | None = None
        # Set by open_archive beside the provenance: the detection result it opened by,
        # served as ``format_info``. None for a reader built directly or under format=.
        self._format_info: FormatInfo | None = None
        # PROBE_/EXTENSION_FORMAT_UNCONFIRMED on a failed read is one provenance fact
        # per reader, not per raised exception — retries must not multiply the
        # diagnostic (or burn retention slots).
        self._unconfirmed_failure_emitted: bool = False
        # Makes the test-and-set of ``_unconfirmed_failure_emitted`` one step.
        self._unconfirmed_failure_lock = threading.Lock()
        self._listing_tracker = ListingLimitTracker(self._config.listing_limits)
        # How close this reader came to each reader-lifetime limit (private; read by
        # the scan script and ``archivey extract --dry-run``).
        self._usage = ResourceUsageRecorder()
        self._usage.watch_listing(self._listing_tracker)
        self._forward_pass_started: bool = False
        self._progressive_gen: Iterator[ArchiveMember] | None = None
        self._closed = False
        # A backend that shares one underlying handle across member streams (the TAR
        # walk's stream, pycdlib _cdfp) sets this to a lock under CONCURRENT (and TAR
        # also under streaming). Backends acquire it via ``_handle_guard()`` so the "lock
        # when present, no-op otherwise" branch lives in one place. ``None`` = no shared
        # handle to serialize (default readers, path-per-open backends).
        self._handle_lock: threading.Lock | None = None

    def _handle_guard(self) -> AbstractContextManager[object]:
        """Hold the backend's shared-handle lock if one is set, else a no-op context.

        Collapses the repeated ``if self._handle_lock is not None: with lock: … else: …``
        branch that every shared-handle backend otherwise copy-pastes (and can forget to
        keep in sync on one arm).
        """
        return self._handle_lock if self._handle_lock is not None else nullcontext()

    def _raise_translated(
        self,
        exc: Exception,
        member_name: str | None = None,
        *,
        stamp_encryption: bool = True,
    ) -> NoReturn:
        """Translate ``exc`` via ``_translate_exception``, stamp context, and raise.

        The single backend-side error boundary (the out-of-stream counterpart of
        ``ArchiveStreamImpl._fail``): an already-typed ``ArchiveyError`` is stamped and
        re-raised as-is; a closed source (``as_closed_source_error``) raises a usage
        error naming ``member_name``, as it does inside a member stream; a
        raw exception the translator recognizes is stamped and raised chained to the
        original; an unrecognized exception propagates unchanged (the catch-all-free
        rule in CONTRIBUTING). ``stamp_encryption=False`` skips member stamping for
        ``EncryptionError`` (ZIP's password errors carry their own message and must
        not be reattributed).
        """
        if isinstance(exc, ArchiveyError):
            self._stamp_error_context(exc, member_name)
            raise exc
        closed = as_closed_source_error(exc, member_name)
        if closed is not None:
            # Checked before the backend's translator, which may map every ValueError
            # to corruption (ZIP's bad-offset rule, ISO's pycdlib rule).
            raise closed from exc
        translated = self._translate_exception(exc)
        if translated is None:
            raise exc
        if stamp_encryption or not isinstance(translated, EncryptionError):
            self._stamp_error_context(translated, member_name)
        raise translated from exc

    def _translated_errors(
        self,
        member_name: str | None = None,
        *,
        stamp_encryption: bool = True,
    ) -> AbstractContextManager[None]:
        """Context manager routing any exception from the body through ``_raise_translated``.

        Backends wrap every direct call into their underlying library with this instead
        of hand-rolling the translate/stamp/raise tail per site — the pattern that
        repeatedly drifted (one site catching a narrower tuple than its siblings).
        Take the boundary OUTSIDE ``_handle_guard()`` so translation and stamping never
        run while a shared-handle lock is held. ``BaseException`` (KeyboardInterrupt,
        GeneratorExit) passes through untouched.
        """
        return _TranslatedErrorBoundary(self, member_name, stamp_encryption)

    def _seek_declared(self) -> bool:
        return self._state.seekable

    def _register_public_stream(
        self,
        stream: ArchiveStreamImpl,
        token: LiveStreamReservation | None = None,
    ) -> ArchiveStreamImpl:
        """Admit ``stream`` under the live-stream gate and attach lease release on close.

        ``token`` is a reservation already taken (eager ``open()``); bind is
        infallible. Without ``token`` this acquires a new slot (the extraction
        coordinator re-opening a retyped member). A ``stream_members()`` pass's streams
        do not come here (``ReaderState.admit_pass_streams``).

        The gate also records the stream, weakly and in open order, for ``close()``
        to close if the caller has not (stdlib parity: ``ZipFile.close()`` and
        ``TarFile.close()`` invalidate member streams too). A stream the caller drops
        without closing needs no finalizer of its own: ``IOBase.__del__`` calls
        ``close()`` on it, and ``close()`` runs the hook below in its ``finally``.
        """
        if token is None:
            self._state.acquire_live_stream(stream)
        else:
            self._state.bind_live_stream(token, stream)

        # Capture the identity token, not the stream. The stream holds this hook, so a
        # hook that referenced the stream would make a cycle, and a dropped stream would
        # then wait for the cyclic collector to be closed, holding its file descriptor
        # until it ran.
        stream_id = id(stream)

        def _on_close() -> None:
            if self._state.release_live_stream_id(stream_id):
                self._maybe_teardown()

        stream._on_close = _on_close
        return stream

    def _internal_member_opens(self) -> _InternalMemberOpens:
        """Context manager: library-internal opens are exempt from the live-stream gate."""
        return _InternalMemberOpens(self._state)

    def _maybe_teardown(self, pending: Exception | None = None) -> None:
        """Run archive teardown outside lifecycle state once the last lease drops.

        ``pending`` is a failure from ``close()``'s own steps before teardown: the pass
        wind-down, the member-stream close, or both as one ``ExceptionGroup``. It is
        combined with a teardown failure into an ``ExceptionGroup`` (D9). Teardown is
        never retried; the lifecycle is marked complete even when ``_close_archive``
        fails.
        """
        if not self._state.claim_teardown():
            if pending is not None:
                raise pending
            return
        teardown_exc: Exception | None = None
        try:
            try:
                self._close_archive()
            finally:
                # After the backend: whatever it built reads through the source, so the
                # source goes last. It closes only what archivey opened or built.
                source = self._source
                if source is not None:
                    source.close()
        except Exception as exc:  # noqa: BLE001 - combine with pending close() failure
            # Held, not swallowed: every path below raises it. Exception, not
            # BaseException: an interrupt propagates alone, through the finally.
            teardown_exc = exc
        finally:
            # Also on an interrupt: teardown is never retried, so it is complete either way.
            self._state.complete_teardown()
        if pending is not None and teardown_exc is not None:
            raise ExceptionGroup(
                "close-time cleanup and archive teardown both failed",
                [pending, teardown_exc],
            )
        if pending is not None:
            raise pending
        if teardown_exc is not None:
            raise teardown_exc

    @abstractmethod
    def _iter_members(self) -> Iterator[ArchiveMember]:
        """Yield every member once, in archive order.

        The base calls this once per reader for a walk that completes, and every listing
        method and pass reads what it yielded (see ``_pull_member``), so a member is typed
        once and is one object.

        **Order stability is still required:** a random-access walk that fails part-way
        on anything but archive damage (a listing limit, an interrupt) is discarded, and
        the next call walks again. ``member_id`` is the enumeration position, so that
        second walk must yield the same members in the same order.
        """
        ...

    def _drive_pass_streams(
        self,
        members: Iterator[ArchiveMember],
        *,
        open_member: Callable[[ArchiveMember], ArchiveStreamImpl | None],
        close_previous: bool = True,
        cleanup: Callable[[], None] | None = None,
        after_members: Callable[[], None] | None = None,
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """Shared close-previous / open / yield / finally driver for ``_iter_with_data``.

        Backends supply an ``open_member`` hook (return ``None`` for non-file members)
        and an optional ``cleanup`` for pass-scoped resources (solid block, ``unrar``
        pipe). ``close_previous=False`` is for TAR streaming, where the walk invalidates
        the prior member stream on advance.

        The driver **always** closes the last still-open stream in its ``finally``
        before running ``cleanup`` — never tear down a solid block / pipe under a live
        member wrapper. Double-close with ``stream_members``'s ``finally`` is fine:
        ``ArchiveStream.close`` is idempotent.
        """
        previous: ArchiveStreamImpl | None = None
        try:
            for member in members:
                if close_previous and previous is not None:
                    previous.close()
                    previous = None
                stream = open_member(member)
                if stream is not None:
                    previous = stream
                yield member, stream
            if after_members is not None:
                after_members()
        finally:
            if previous is not None:
                previous.close()
            if cleanup is not None:
                cleanup()

    def _iter_with_data(
        self, copies: FileCopyPass = DEFAULT_FILE_COPY_PASS
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """Yield (member, stream) pairs in archive order; backs ``stream_members``.

        This default is for **random-access / fully-indexed** backends only (ZIP,
        directory): it calls ``_materialize_members()``, which eagerly drains
        ``_iter_members()`` and builds the name map *before* yielding anything.

        Streaming / forward-only / solid backends **must override** this — it is a
        correctness requirement, not just an optimization. A non-seekable TAR or a solid
        7z/RAR cannot enumerate every member before reading data, so the override must
        produce ``(member, stream)`` pairs progressively from a single forward pass and
        must **not** call ``_materialize_members()``. The yielded stream is only valid
        until the iterator advances (see the ``stream_members`` contract in
        ``archive-reading``); it is ``None`` for every member :func:`pass_has_data`
        rejects.

        When ``streaming=True`` and the backend does not override, this default pulls
        from the shared instance-held progressive pass and opens each file member on
        demand.

        The yielded streams are **lazy**: the member's data is opened on the first read,
        not at yield time. A consumer that skips a member (a ``stream_members`` selector,
        a filtered extraction) therefore pays nothing for it — no seek to its data, no
        decompressor setup — and an open-time error (e.g. a wrong password) surfaces only
        if the member is actually read, not merely iterated past. The exception is a
        symlink under ``read_link_targets``: its target is read when the pass reaches
        it, before the selector runs (link finalization read the same bytes at EOF
        before), so a strict policy can raise its target diagnostics there.

        ``copies`` matters only to a backend with file copies (RAR, which overrides
        this); ``_iter_stream_members`` applies ``copies.streams`` for every backend.
        """
        if (
            not self._streaming
            and not self._walk_done
            and self._pass_reads_through_walk()
        ):
            yield from self._iter_with_data_through_walk()
            return
        report: MemberListReport | None = None
        members = self._begin_forward_pass() if self._streaming else None
        if members is None:
            report = self._materialize_members().report
            members = iter(report.members)

        def _open(member: ArchiveMember) -> ArchiveStreamImpl | None:
            self._read_pass_link_target(member)
            if pass_has_data(member):
                return self._lazy_member_stream(member, register=False)
            return None

        def _raise_report_error() -> None:
            if report is not None and report.error is not None:
                raise report.error

        yield from self._drive_pass_streams(
            members,
            open_member=_open,
            close_previous=True,
            after_members=_raise_report_error,
        )

    def _iter_with_data_through_walk(
        self,
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """``stream_members()`` on a random-access reader, in one forward pass.

        Until the walk has ended, the walk and the data share one pass: the member is
        registered and yielded, and its data is read through the walk before the walk
        parses the next header, so every read goes forward. Members are registered as
        they arrive, as the base's walk registers them, so ``members()`` afterwards
        serves the same list, and the pass links a hardlink to an earlier member only,
        as the streaming pass does. The pass has its own cursor over the reader's one
        walk, so a pass abandoned early does not make the next one start part-way. A
        pass over a listing that is already complete is the default's, which reads the
        members' data in archive order: one forward sweep too, after one seek back to
        the first member.
        """

        def _open(member: ArchiveMember) -> ArchiveStreamImpl | None:
            self._read_pass_link_target(member)
            if not pass_has_data(member):
                return None
            return self._lazy_member_stream(
                member, self._open_member_in_walk, register=False
            )

        yield from self._drive_pass_streams(
            _ProgressivePassIterator(self), open_member=_open
        )

    def _read_pass_link_target(self, member: ArchiveMember) -> None:
        """A data pass has reached ``member``: read its link target before yielding it.

        A streaming pass resolves links when it ends, after the caller has had the
        member. The read here serves two needs. In ZIP, a reparse point whose data is
        not a link buffer is a file, and the caller needs its stream now (the 7z pass
        does the same read). In every format that stores the target as data, an
        unreadable one (damaged, or in a method or codec this install cannot decode)
        must be reported before the link is handed out. A random-access listing has
        read it already (the memo, or the unreadable flag, makes this a no-op).

        An unreadable target is reported here rather than left to link finalization: a
        pass the caller leaves early, or one a later member stops, never finalizes,
        and a strict policy must refuse before the link is handed out. Finalization
        skips a link already reported as unreadable.
        """
        if (
            not self._config.read_link_targets
            or member.type is not MemberType.SYMLINK
            # Already read and reported; reading it again would only re-raise.
            or member._link_target_unreadable
        ):
            return
        try:
            self._read_link_target_on_request(member)
        except UNREADABLE_LINK_TARGET_ERRORS as exc:
            self._report_unreadable_link_target(member, exc)

    def _lazy_member_stream(
        self,
        member: ArchiveMember,
        open_member: Callable[[ArchiveMember], BinaryIO | MemberStreamParts]
        | None = None,
        *,
        track_output: bool = False,
        register: bool = True,
    ) -> ArchiveStreamImpl:
        """A stream over ``member``'s data that defers ``_open_member`` to the first read.

        Closing it before any read never opens the member at all. ``_open_member``
        returns the member's parts, and this handle takes them over
        (:meth:`ArchiveStreamImpl._adopt`): it is the only handle the member gets.
        ``open_member`` replaces it, and may return a raw byte stream instead: then
        ``track_output=True``, because nothing inside the opener counts the bytes.
        Deferral does not change what a failed open raises — only when.

        ``register=False`` is for a data pass's streams: the pass holds the live-stream
        slot for all of them (:meth:`_iter_stream_members`), so they are not admitted
        one by one.
        """
        opener = self._open_member if open_member is None else open_member
        stream = self._wrap_member_stream(
            member.name,
            lambda: opener(member),
            size=member.size,
            # Default False: ``_open_member`` already counts, in ``_member_parts``.
            track_output=track_output,
            seekable=self._seek_declared(),
        )
        return self._register_public_stream(stream) if register else stream

    def _ratio_limits(self) -> DecoderLimits:
        """The ratio fields this reader's decodes are held to: ``decoder_limits``, or
        what a deprecated ``extraction_limits`` ratio field sets."""
        from archivey.internal.bomb_tracker import ratio_limits

        config = self._config
        return ratio_limits(config.decoder_limits, config.extraction_limits)

    def _hold_to_ratio(self, stream: ArchiveStreamImpl, member: ArchiveMember) -> None:
        """Hold a member stream ``open()`` or ``stream_members()`` gives the caller to
        ``decoder_limits.max_ratio``, as extraction holds what it writes
        (:class:`MemberRatioGuard`). ``member`` is the member whose data it reads.

        Extraction's own passes are not held here: its ``BombTracker`` applies the
        limits the ``extract_all`` call was given.
        """
        # Imported here, as in ``_open_outer_codec_stream``.
        from archivey.internal.bomb_tracker import MemberRatioGuard

        limits = self._ratio_limits()
        if limits.max_ratio is None:
            return
        counter = self._compressed_input_counter
        tally = self._read_ratio_tally
        static_size = self._trusted_source_size()
        stream._hold_inner(
            lambda inner: MemberRatioGuard(
                inner,
                limits=limits,
                member=member,
                tally=tally,
                static_size=static_size,
                consumed=None if counter is None else lambda: counter.bytes_read,
            )
        )

    def _open_member_handle(self, member: ArchiveMember) -> ArchiveStreamImpl:
        """``_open_member`` as an open handle, for code that reads the member itself."""
        return self._member_stream(self._open_member(member))

    @abstractmethod
    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        """Open ``member``'s data (no link following) and say how to serve it.

        Backends return ``_member_parts(raw, member.name, ...)``. The caller serves the
        parts with one handle: ``reader.open()`` builds it (``_member_stream``), and a
        lazy handle takes them over on its first read (``_lazy_member_stream``). Code
        that reads the member itself calls ``_open_member_handle``.

        **Reentrancy invariant (random-access backends).** For a backend that advertises
        independent member open (``streaming=False``, byte-range / independent access —
        ZIP, single-file, and the future native 7z/RAR readers), this method MUST be a
        function of ``(member, shared source)`` only:

        - it MUST NOT keep unsynchronized per-open scratch on ``self`` that another
          concurrent open can overwrite;
        - synchronized shared bookkeeping (leases, password caches, handle locks) is
          permitted;
        - any archivey-owned byte-range access MUST go through a
          :class:`~archivey.internal.streams.streamtools.SharedSource` view (see
          *Multiple concurrently-open member streams* in ``archive-reading``).

        Immutable, already-materialized state (the member list / name index) MAY be read
        read-only. Backends whose member addressing is owned by an external library that
        already coordinates the shared handle (ISO via ``pycdlib``) are not required to
        route through an archivey ``SharedSource`` view, but archivey-owned reader state
        still MUST NOT hold unsynchronized per-open scratch.

        Concurrent ``open`` is supported when the reader declared concurrency
        (``MemberStreams.CONCURRENT``, from ``open_archive(concurrent_operations=True)``):
        first-touch materialization is coordinated
        (wait/share), and after the snapshot is published workers may fan out. Forward-only
        / streaming passes remain single-owner. See ``dev-docs/investigations/parallel-reader.md``.
        """
        ...

    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        """Map a raw exception (from a codec/library while reading a member) to an
        ``ArchiveyError`` subclass, or return ``None`` to let it propagate unchanged.

        This is the backend's per-library translator hook (see ``error-handling`` and
        CONTRIBUTING). The default translates nothing; backends override it to map their
        library's known exceptions. It MUST NOT contain a catch-all that converts any
        ``Exception`` — an unrecognized error returns ``None`` so it surfaces and can be
        mapped deliberately.
        """
        return None

    def _track_decompressed(self, stream: BinaryIO) -> BinaryIO:
        """Wrap ``stream`` to count decoded/output bytes when measurement is on.

        Backends call this on the stream that *is* the decompressor (or stored-data)
        output: member streams for ZIP/TAR/single-file, folder/solid-block streams for
        solid 7z/RAR. Identity when measurement is off.
        """
        counter = self._decompressed_counter
        if counter is None:
            return stream
        return OutputCountingStream(stream, counter)

    def _seek_handle_wrapper(self) -> Callable[[BinaryIO], BinaryIO] | None:
        """Return a ``SharedSource(wrap_handle=…)`` callback when measurement is on."""
        counter = self._seek_counter
        if counter is None:
            return None
        return lambda handle: SeekCountingStream(handle, counter)

    def _track_source_seeks(self, source: BinaryIO) -> BinaryIO:
        """Wrap the source to count seeks when measurement is on; identity otherwise.

        The counter owns and closes what it is given. So pass it the reader's own
        :class:`ArchiveSource` (which the reader closes anyway, and which never closes
        the caller's object) or a non-owning view over it, never a borrowed stream
        directly. The single-file reader's metadata probes wrap a view for this reason.
        """
        counter = self._seek_counter
        if counter is None:
            return source
        return SeekCountingStream(source, counter)

    @property
    def bytes_decompressed(self) -> int:
        """Total decoded/output bytes counted while measurement was enabled, else 0.

        Distinct from :attr:`compressed_bytes_consumed` (compressed *input* pressure for
        the live ratio guard). Internal / harness-facing.
        """
        c = self._decompressed_counter
        return c.total if c is not None else 0

    @property
    def source_seek_count(self) -> int:
        """Number of ``seek`` calls on the instrumented archive source, else 0."""
        c = self._seek_counter
        return c.count if c is not None else 0

    def _wrap_member_stream(
        self,
        member_name: str | None,
        open_fn: Callable[[], BinaryIO | MemberStreamParts],
        *,
        size: int | None = None,
        track_output: bool = True,
        seekable: bool | None = None,
        expected_hashes: Mapping[HashAlgorithm, bytes] | None = None,
        expected_size: int | None = None,
        digest_transforms: Mapping[HashAlgorithm, Callable[[bytes], bytes]]
        | None = None,
        verify_member: ArchiveMember | None = None,
        end_check: Callable[[int], None] | None = None,
        fill_size: bool = False,
        rewind_warning: RewindWarning | None = None,
        translate: ExceptionTranslator | None = None,
        checks_content: bool = False,
        custom_digests: CustomDigests | None = None,
        bounded: bool = False,
    ) -> ArchiveStreamImpl:
        """A member stream that calls ``open_fn`` on its first read: one
        ``ArchiveStream``, whose read/seek errors route through the backend's
        translator and are stamped with format/archive/member context.

        The arguments are :meth:`_member_parts`'s, and ``seekable`` defaults to
        declared. If ``open_fn`` returns ``MemberStreamParts`` (from ``_open_member``),
        the handle takes them over (:meth:`ArchiveStreamImpl._adopt`); if it returns an
        ``ArchiveStream``, :meth:`ArchiveStreamImpl._ensure_open` collapses the nesting.
        Either way callers never see a double wrapper. With ``track_output``, a bytes
        stream ``open_fn`` returns is counted; parts pass through, as they count their
        own. Pass ``track_output=False`` when it returns an ``ArchiveStream``. A never-opened handle
        skips verify on close, so solid unread members stay cheap.

        A stream already open is served by ``_member_stream(_member_parts(...))``.
        """
        if track_output:

            def tracked_open(
                raw_open: Callable[[], BinaryIO | MemberStreamParts] = open_fn,
            ) -> BinaryIO | MemberStreamParts:
                opened = raw_open()
                if isinstance(opened, MemberStreamParts):
                    # ``_member_parts`` already counted these bytes.
                    return opened
                return self._track_decompressed(opened)

            use_open: Callable[[], BinaryIO | MemberStreamParts] = tracked_open
        else:
            use_open = open_fn
        return ArchiveStreamImpl(
            use_open,
            translate=(
                self._translate_exception
                if translate is None
                else compose_translators(translate, self._translate_exception)
            ),
            stamp=lambda exc: self._stamp_error_context(exc, member_name),
            lazy=True,
            seekable=(self._seek_declared() if seekable is None else seekable),
            size=size,
            collector=self._diagnostics_collector,
            expected_hashes=expected_hashes,
            expected_size=expected_size,
            digest_transforms=digest_transforms,
            verify_member=verify_member,
            end_check=end_check,
            fill_size=fill_size,
            archive_name=self._archive_name,
            rewind_warning=rewind_warning,
            member_name=member_name,
            checks_content=checks_content,
            custom_digests=custom_digests,
            bounded=bounded,
        )

    def _member_parts(
        self,
        inner: BinaryIO,
        member_name: str | None,
        *,
        size: int | None = None,
        track_output: bool = True,
        seekable: bool | None = None,
        expected_hashes: Mapping[HashAlgorithm, bytes] | None = None,
        expected_size: int | None = None,
        digest_transforms: Mapping[HashAlgorithm, Callable[[bytes], bytes]]
        | None = None,
        verify_member: ArchiveMember | None = None,
        end_check: Callable[[int], None] | None = None,
        fill_size: bool = False,
        rewind_warning: RewindWarning | None = None,
        translate: ExceptionTranslator | None = None,
        checks_content: bool = False,
        custom_digests: CustomDigests | None = None,
        bounded: bool = False,
    ) -> MemberStreamParts:
        """A raw member stream and how to serve it: what ``_open_member`` returns.

        The handle that serves it (``_member_stream``, or a lazy handle that adopts it)
        routes read/seek errors through the backend's translator and stamps them with
        format/archive/member context, so a decode error surfaces as a stamped
        ``ArchiveyError`` rather than a raw codec exception. ``size`` is the handle's
        decompressed length (the fsspec-style ``size``), for cheap nested-archive
        source sizing.

        ``checks_content`` says that ``inner`` checks every byte against a checksum of
        its own when read from the start to the end, and raises on a mismatch (a
        plugin's ``MemberData.checked``): such a read counts as ``CONTENT``.
        ``custom_digests`` are digests whose hasher the caller supplies (a plugin's
        ``MemberData.digests``), checked as ``expected_hashes`` are. ``bounded`` says
        ``inner`` never returns a byte past ``expected_size`` (a plugin's
        ``MemberData.bounded``): the read past the end that looks for one is skipped.

        Seekability is gated by ``MemberStreams.SEEKABLE``: without it the handle reports
        non-seekable even when ``inner`` could seek. Pass ``seekable=`` to override the
        default, declared ∧ ``is_seekable(inner)``. A lazy handle that adopts the parts
        keeps its own (declared).

        When measurement is on and ``track_output`` is true (the default), decoded bytes
        delivered through the handle are added to :attr:`bytes_decompressed`. Solid
        backends that already count at the folder/block decode layer pass
        ``track_output=False`` to avoid double-counting.

        Pass ``expected_hashes`` / ``expected_size`` to fuse container digest and
        length verification into the handle (no separate ``VerifyingStream`` layer).

        For a member with no ``expected_size``, ``end_check`` is called with its
        length when a read reaches its end, before the digest verdict, and raises to
        refuse it. ``fill_size=True`` with ``verify_member`` gives
        ``verify_member.size`` that length: once the digests match, or, with no
        digest to check, once a read from the start that skips no byte reaches the
        end cleanly (``MemberVerifier``). It is the late size of a member whose format
        records none, or records one that cannot be trusted (a macOS ZIP's size
        modulo 2³²).

        ``translate`` is the translator of a codec ``inner`` was opened with
        (:func:`~archivey.internal.streams.codecs.registry.open_codec_raw`). It is asked
        before the backend's, as it would be had ``inner`` been the codec's own
        ``ArchiveStream`` collapsed into this one.
        """
        if track_output:
            inner = self._track_decompressed(inner)
        if seekable is None and (
            # A nested ``ArchiveStream`` is asked now, as its own declaration counts.
            # Any other stream is asked on first use, if ever: a lazy handle that
            # adopts the parts never asks.
            not self._seek_declared() or isinstance(inner, ArchiveStreamImpl)
        ):
            seekable = self._seek_declared() and is_seekable(inner)
        # Positional: this runs once per member, and keywords cost more than the
        # build itself (18 fields: about 0.9 us by keyword, 0.3 us positional, on
        # CPython 3.13). The names match the parameters, in order.
        return MemberStreamParts(
            inner,
            member_name,
            self._stamp_error_context,
            translate,
            seekable,
            size,
            rewind_warning,
            checks_content,
            self._diagnostics_collector,
            self._archive_name,
            expected_hashes,
            expected_size,
            digest_transforms,
            verify_member,
            end_check,
            fill_size,
            custom_digests,
            bounded,
        )

    def _member_stream(self, parts: MemberStreamParts) -> ArchiveStreamImpl:
        """The handle that serves ``parts``, open on their stream.

        The handle owns the stream from here. If building it raises (a digest the
        verifier refuses under a ``RAISE`` policy), the stream is closed.
        """
        stamp = parts.stamp
        member_name = parts.member_name
        translate = parts.translate
        try:
            return ArchiveStreamImpl(
                # ``seekable=None``: settled on first use
                # (``ArchiveStreamImpl._seek_allowed``).
                _Opened(parts.inner, settle_seekable=parts.seekable is None),
                translate=(
                    self._translate_exception
                    if translate is None
                    else compose_translators(translate, self._translate_exception)
                ),
                stamp=lambda exc: stamp(exc, member_name),
                seekable=bool(parts.seekable),
                size=parts.size,
                collector=parts.collector,
                expected_hashes=parts.expected_hashes,
                expected_size=parts.expected_size,
                digest_transforms=parts.digest_transforms,
                verify_member=parts.verify_member,
                end_check=parts.end_check,
                fill_size=parts.fill_size,
                archive_name=parts.archive_name,
                rewind_warning=parts.rewind_warning,
                member_name=member_name,
                checks_content=parts.checks_content,
                custom_digests=parts.custom_digests,
                bounded=parts.bounded,
            )
        except BaseException:
            with contextlib.suppress(Exception):
                parts.inner.close()
            raise

    @abstractmethod
    def _get_archive_info(self) -> ArchiveInfo: ...

    @abstractmethod
    def _close_archive(self) -> None: ...

    def _emit_empty_listing_diagnostics(self) -> None:
        """Report a clean, zero-member listing, and an unconfirmed format behind it.

        Not an error: a legitimately empty tar is 10240 zero bytes, byte-identical to a
        zero-filled garbage file of the same length, so no predicate over the bytes can
        separate them and any "zero members is a problem" rule would reject a file
        ``tar(1)`` itself produces. Saying "this archive is empty" is the true thing;
        "this file is probably garbage" would be a guess.

        The format codes narrow that: they fire only when the format was never confirmed
        against the bytes. Both run only on an empty listing, so a normal archive pays
        nothing.
        """
        format_name = self._format.display_name
        self._diagnostics_collector.emit(
            code=DiagnosticCode.EMPTY_ARCHIVE,
            message=f"Archive listed no members ({format_name})",
            context=EmptyArchiveContext(
                archive_name=self._archive_name, format=format_name
            ),
        )

        provenance = self._format_provenance
        if provenance is None:
            return

        if provenance.chosen_by == "extension":
            # Detection fell through to the filename because magic, the content probes
            # and far magic all declined — the same answer detect_format gives when it
            # refuses the bytes. No rescan is needed to know the format is unconfirmed.
            self._emit_listed_empty_unconfirmed("extension", None)
            return

        if provenance.chosen_by != "argument" or provenance.source is None:
            # "content"/"directory": the bytes agreed. A stream argument records no
            # source, rather than seeking a live source back to its origin.
            return

        from archivey.exceptions import ArchiveyError as _ArchiveyError
        from archivey.internal.detection import detect_format, probe_config

        try:
            # The detection settings only: see probe_config for why not the caller's
            # config.
            detected = detect_format(
                provenance.source, config=probe_config(self._config)
            ).format
        except (_ArchiveyError, OSError, ValueError):
            # Detection refuses these bytes outright — or cannot read them at all.
            #
            # OSError is not hypothetical: this is the only place that reopens the
            # archive **by name**, and the reader is otherwise immune to the path
            # changing under it because it holds an open handle. Without this arm a
            # deleted/unreadable path turned a *successful* empty listing into
            # FileNotFoundError, so a diagnostic decided whether listing worked. A
            # probe that exists to add an advisory must never do that.
            detected = None
        if detected is self._format:
            return
        self._emit_listed_empty_unconfirmed(
            "argument", detected.display_name if detected is not None else None
        )

    def _emit_listed_empty_unconfirmed(
        self,
        chosen_by: Literal["argument", "extension"],
        detected_format: str | None,
    ) -> None:
        format_name = self._format.display_name
        detected_text = detected_format or "nothing (detection refuses these bytes)"
        self._diagnostics_collector.emit(
            code=DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY
            if chosen_by == "argument"
            else DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED,
            message=f"Listed no members as {format_name}, which was chosen by "
            f"{chosen_by} and not confirmed by the archive's bytes; "
            f"content detection reports {detected_text}",
            context=self._unconfirmed_context(chosen_by, detected_format),
        )

    def _unconfirmed_context(
        self,
        chosen_by: Literal["argument", "extension", "content_probe"],
        detected_format: str | None,
    ) -> UnconfirmedFormatContext:
        return UnconfirmedFormatContext(
            archive_name=self._archive_name,
            format=self._format.display_name,
            chosen_by=chosen_by,
            detected_format=detected_format,
        )

    def _mark_format_unconfirmed(
        self,
        exc: ArchiveyError,
        evidence: _UnconfirmedEvidence,
    ) -> None:
        """Stamp a decode failure under an unconfirmed format and emit its diagnostic.

        ``evidence`` says what the format rested on: a content probe with nothing
        corroborating it (``PROBE_FORMAT_UNCONFIRMED``), or the filename alone, because
        every content signal declined (``EXTENSION_FORMAT_UNCONFIRMED``).
        """
        code, evidence_text, evidence_short = _UNCONFIRMED_EVIDENCE[evidence]
        if not exc.format_unconfirmed:
            # The stamped message speaks of the format the exception names, which a
            # lower layer (a codec, the spool) may have set to something other than
            # this reader's format; the diagnostic below speaks of the reader's.
            stamped_format = (exc.source_format or self._format).display_name
            detail = exc.raw_message.rstrip(".")
            unconfirmed = (
                f"Format identification was unconfirmed ({evidence_short}); "
                f"the source may not be {stamped_format}."
            )
            if isinstance(exc, ResourceUnavailableError):
                # The system ran short, maybe part-way through (a decoder process
                # killed from outside), so no limit is to blame and output may exist.
                new_msg = (
                    f"{unconfirmed} The read was stopped because the system ran short: "
                    f"{detail}. Partial output may already have been produced"
                )
            elif isinstance(exc, ResourceLimitError):
                # A limit stops the read rather than the decoder failing on it, and a
                # decoder-memory refusal stops it before anything is decoded, so
                # neither "decode failed" nor "partial output" would be true of it.
                new_msg = f"{unconfirmed} The read was stopped by a limit: {detail}"
            else:
                new_msg = (
                    f"{unconfirmed} Decode failed: {detail}. "
                    f"Partial output may already have been produced"
                )
            escaped = escape_control_chars(new_msg)
            exc.raw_message = new_msg
            exc.message = escaped
            exc.args = (escaped,)
            exc.format_unconfirmed = True

        # Test and set in one step: two threads failing at once on a CONCURRENT
        # reader would otherwise both pass the test and emit twice. Set before
        # emitting, for the reason below.
        with self._unconfirmed_failure_lock:
            if self._unconfirmed_failure_emitted:
                return
            self._unconfirmed_failure_emitted = True

        # Under PEDANTIC (RAISE on every code), a bare emit would raise DiagnosticRaisedError
        # mid-raise and destroy the typed TruncatedError/CorruptionError/
        # ResourceLimitError. escalate_as keeps that type when RAISE fires; under
        # COLLECT we leave it unset so the already-stamped ``exc`` is re-raised by the
        # caller.
        raising = code in self._diagnostics_collector.policy.raise_on

        # The flag is set above, before emitting: under RAISE the emit does not return,
        # and a flag set afterwards would never be reached — every retried read would
        # record the diagnostic again. `diagnostics` splits those concerns ("deduplication is a
        # presentation concern; escalation is not"), and normally a deduplicated code
        # still escalates on later occurrences via `escalate_only`. This code needs no
        # such re-escalation: the caller re-raises the stamped `exc` — same type, same
        # `format_unconfirmed=True` — on every occurrence, so a caller who asked to be
        # stopped is stopped whether or not the diagnostic fires a second time.
        reader_format = self._format.display_name
        escalate_as: type[BaseException] | None = None
        escalate_message: str | None = None
        escalate_kwargs: dict[str, object] | None = None
        if raising:
            escalate_as = type(exc)
            escalate_message = exc.raw_message
            escalate_kwargs = {
                "source_format": exc.source_format,
                "archive_name": exc.archive_name,
                "member_name": exc.member_name,
                "link_target": exc.link_target,
                "format_unconfirmed": True,
            }
        self._diagnostics_collector.emit(
            code=code,
            message=f"Reading {reader_format} failed (a decode failure or a limit), and "
            f"it was identified only by {evidence_text}; the source may not be that "
            f"format",
            context=self._unconfirmed_context(
                evidence,
                # An extension guess is what detection falls back to when it refuses
                # the bytes, so it has no content answer to restate.
                reader_format if evidence == "content_probe" else None,
            ),
            escalate_as=escalate_as,
            escalate_message=escalate_message,
            escalate_kwargs=escalate_kwargs,
        )

    def _finalize_and_publish(
        self, error: ArchiveyError | None, *, child_scope: bool
    ) -> _Materialized:
        """Resolve the walk's links, then publish it as the report.

        The running totals are re-checked first: a target read on request
        (``_read_link_target_on_request``) is weighed without enforcing, and a listing
        over the limits is never published.

        ``child_scope`` makes the link-target reads a private child scope of the active
        operation, exempt from the live-stream gate: true for random-access
        materialization, false when a forward pass finalizes.
        """
        self._listing_tracker.assert_within_limits()
        # Under the walk lock: a pass cursor beside it links the members it yields.
        with self._walk_lock:
            self._finalize_links(error=error, child_scope=child_scope)
            return self._publish_materialized(error=error)

    def _publish_materialized(self, *, error: ArchiveyError | None) -> _Materialized:
        members = self._listed
        # Links are resolved to members now, and is_current was stamped when the walk
        # ended, so nothing changes these members from here. Not when the walk ends: a
        # peek can end it long before a pass resolves its links. A streaming pass
        # ends here too, so no later read can fill a size it left unknown.
        _settle_listing(members, sizes_too=self._streaming)
        if error is not None:
            self._stamp_error_context(error)
        elif not members:
            # Emitted before the snapshot below so it appears on the published report.
            self._emit_empty_listing_diagnostics()
        holder = _Materialized(
            report=MemberListReport(
                members=tuple(members),
                error=error,
                diagnostics=self._diagnostics_collector.snapshot(),
            ),
        )
        self._materialized = holder
        return holder

    def _finalize_links(
        self,
        *,
        error: ArchiveyError | None,
        child_scope: bool,
    ) -> None:
        """Resolve hardlink/symlink targets with one double-fault policy.

        A ``CorruptionError`` / ``TruncatedError``, an ``UnsupportedFeatureError`` or a
        ``PackageNotInstalledError`` reading one link's target leaves that link
        targetless and reported (``_report_unreadable_link_target``), and the others
        resolve. Past that, when ``error is not None`` (incomplete listing /
        terminal pass damage), a secondary ``CorruptionError`` is swallowed so the
        recovered prefix stays publishable. When ``error is None`` (clean EOF / complete
        listing), it propagates.

        Eager materialization uses a child scope + internal-open exemption for
        link-data reads; a streaming pass's finalization does not open a child scope.
        ``is_current`` is not stamped here: the walk stamps it once, when it ends
        (``_end_walk``), and link resolution never reads it.

        Targets stored as member data are read here only under
        ``ArchiveyConfig.read_link_targets``. With it off this is listing, or a pass
        advancing, and neither reads member data on its own: the target stays unset,
        nothing is emitted, and ``_link_target_resolved`` stays unset too, so a read the
        caller asks for later (``extract_all``, ``open()``) is not swallowed by the memo.
        The targets a header carries were set while the member was typed, so they need
        no read and are resolved to members below either way.

        A target read from member data here was still ``None`` when the member was
        registered, so registration weighed it as nothing. It is added to the listing
        tracker as it arrives, with the limits enforced, so ``max_metadata_bytes``
        covers every target the published list will carry.
        """
        members = self._listed
        if not any(member.is_link for member in members):
            return
        read_targets = self._config.read_link_targets

        def _resolve() -> None:
            if read_targets:
                unread = [
                    member
                    for member in members
                    if member.is_link
                    and member.link_target is None
                    and not member._link_target_resolved
                    # A pass that read it first has reported it already.
                    and not member._link_target_unreadable
                ]
                if unread:
                    self._prepare_link_target_reads(unread)
                for member in unread:
                    try:
                        self._resolve_link_target(member)
                    except UNREADABLE_LINK_TARGET_ERRORS as exc:
                        self._report_unreadable_link_target(member, exc)
                        continue
                    if member.link_target is not None:
                        self._listing_tracker.account_link_target(member.link_target)
            # One memo per finalize: every link on a walked chain shares its terminal,
            # so a chain of N links costs O(N) rather than a fresh walk per member.
            terminals: dict[int, ArchiveMember | None] = {}
            for member in members:
                if member.is_link and member.link_target:
                    self._resolve_link(member, terminals)

        try:
            if child_scope:
                # Also wraps ``_internal_member_opens()`` (live-stream gate exemption) —
                # the two always travel together for eager link-data reads.
                # Link-data reads are a private child scope under an active pass when one
                # exists; otherwise they only need the live-stream gate exemption.
                child = self._state.enter_child_scope("link_reads")
                try:
                    with self._internal_member_opens():
                        _resolve()
                finally:
                    if child is not None:
                        self._state.release_child(child)
            else:
                _resolve()
        except CorruptionError:
            if error is None:
                raise

    def _report_unreadable_link_target(
        self, member: ArchiveMember, exc: ArchiveyError
    ) -> None:
        """Leave a link whose target data cannot be read listed, targetless, and reported.

        ``exc`` is one of ``UNREADABLE_LINK_TARGET_ERRORS``. One member's data says
        nothing about the others, and a listing that raised would take every other
        member with it. So the link stays in the list with ``link_target`` unset and
        ``SYMLINK_TARGET_UNAVAILABLE`` says why: ``reason="target_data_damaged"`` for
        damage, ``"target_data_unsupported"`` for a method or variant this reader does
        not decode, ``"package_not_installed"`` for a missing optional library. A strict
        policy still refuses the archive, since the code is an integrity one. The memo
        stays unset, so opening or extracting the link reads the target again and
        raises the error itself. ``_link_target_unreadable`` marks it reported, so link
        finalization after a ``stream_members()`` pass that read it first does not
        report it twice.
        """
        if isinstance(exc, CorruptionError):
            reason = "target_data_damaged"
        elif isinstance(exc, PackageNotInstalledError):
            reason = "package_not_installed"
        else:
            reason = "target_data_unsupported"
        self._emit_link_target_unavailable(
            member,
            reason=reason,
            message=(
                f"The symlink target of {quoted(member.name)} could not be read: "
                f"{raw_message_of(exc).rstrip('.')}. Leaving link_target unset."
            ),
            # The archive does carry the target; reading it failed. Extraction fails
            # this member rather than dropping it under a status that reads as success.
            target_in_archive=True,
        )
        # After the emit: if a strict policy raises there, the next look reports again.
        member._link_target_unreadable = True

    def _prepare_link_target_reads(self, members: list[ArchiveMember]) -> None:
        """Hook: ``members`` are about to have their data-stored targets read.

        Called by link finalization with every link it is about to read, before the
        first read, so a backend whose link data sits inside a shared decode (a 7z
        solid folder) can read them in one sweep instead of one decode per link. The
        base does nothing.
        """
        return

    # --- The member walk -------------------------------------------------------------
    #
    # One ``_iter_members()`` walk per reader, owned here. Everything reads ``_listed``
    # by position and pulls the next member when it reaches the end of what has been
    # walked: the index-only peek, materialization, the streaming pass, and a backend's
    # own data pass. A member is stamped, checked and counted once, when it is pulled.

    def _pull_member(self) -> ArchiveMember | None:
        """Pull the next member from the walk, or ``None`` once the walk has ended.

        Registers the member (id stamp, presentation checks, listing accounting with
        the limits enforced), indexes its name and appends it to ``_listed``. A member
        that crosses a limit raises ``ResourceLimitError`` here, before it is listed.

        The walk ends when the backend's generator is exhausted or raises terminal
        archive damage (``CorruptionError`` / ``TruncatedError``); the damage is kept in
        ``_walk_error`` and the prefix stays listed. Any other failure is
        ``_abandon_walk``'s: discarded in random access, where no member has been handed
        out yet, and poisoned in streaming, where the prefix already has.
        """
        with self._walk_lock:
            return self._pull_members_locked(1)

    def _before_pull_locked(self) -> None:
        """Hand off a pass's stream before the walk moves.

        A random-access pass may still be reading the member the walk is at through
        the walk (:meth:`_walk_handoff_locked`). That stream moves to a view of its own first
        (:class:`WalkHandoffStream`), so a pull for another caller, such as
        ``members()`` from another thread under ``CONCURRENT``, does not cut it off.
        The pass's own next pull hands over a stream it is about to close, which costs
        nothing.

        Called under ``_walk_lock`` once per :meth:`_pull_members_locked` call, before
        one or more pulls, so it must leave nothing for the walk to hand off for the
        whole batch: whatever it hands off must only be set under ``_walk_lock``, so
        nothing new appears until the lock is released."""
        live = self._walk_stream
        if live is not None:
            self._walk_stream = None
            live.detach()

    def _walk_handoff_locked(
        self, in_place: BinaryIO | None, reopen: Callable[[int], BinaryIO]
    ) -> BinaryIO:
        """A pass's member data, through the walk when the walk is at it.

        Called under ``_walk_lock``. ``in_place`` reads the member's data through the
        walk's own stream, or is ``None`` when the walk is not at the start of it;
        ``reopen(start)`` opens a view of the data of its own from ``start``. Only one
        stream reads through the walk at a time: any other open (a second pass behind
        the first, or one in step with it) gets a view of its own.
        """
        live = self._walk_stream
        if in_place is None or (live is not None and not live.closed):
            if in_place is not None:
                in_place.close()
            return reopen(0)
        stream = WalkHandoffStream(in_place, reopen, self._walk_lock)
        self._walk_stream = stream
        return stream

    def _pull_members_locked(self, count: int) -> ArchiveMember | None:
        """Pull up to ``count`` members (at least one), as ``_pull_member`` describes,
        and return the last one pulled, or ``None`` once the walk has ended. One hook
        call, one guard and one ``try`` cover them all: draining a listing of many small
        members pulls each one through this loop, not through a call each. Called under
        ``_walk_lock``."""
        assert count >= 1, count
        self._before_pull_locked()
        if self._walk_done:
            return None
        if self._walk_failure is not None:
            if self._walk_failure_unraised:
                self._walk_failure_unraised = False
                raise self._walk_failure
            raise ReadError(
                "The archive scan previously failed "
                f"({type(self._walk_failure).__name__}); the member list is incomplete "
                "and cannot be resumed. Reopen the archive to retry."
            ) from self._walk_failure
        if self._walk_pulling:
            # A diagnostic callback fired while the backend was typing a member, and it
            # called back into this reader for a listing. The generator is suspended
            # mid-``next``; pulling again would raise "generator already executing".
            raise ArchiveyUsageError(
                "Reader re-entered while it is listing its members on this same "
                "thread (e.g. from a diagnostic callback). Callbacks must not call "
                "back into the reader that triggered them."
            )
        self._walk_pulling = True
        try:
            if self._walk is None:
                self._account_archive_comment()
                self._walk = self._iter_members()
            # Read once for the batch: only ``_end_walk`` and ``_abandon_walk`` drop
            # ``_walk``, and the loop leaves right after either.
            walk = self._walk
            streaming = self._streaming
            member: ArchiveMember | None = None
            for _ in range(count):
                position = self._walk_position
                try:
                    if streaming:
                        # A streaming walk is never started over (``_abandon_walk``
                        # poisons it), so it has nothing to replay and keeps no log.
                        member = next(walk)
                    else:
                        member = self._pull_replayable(position)
                except StopIteration:
                    self._end_walk(None)
                    return None
                except CorruptionError as exc:
                    self._end_walk(exc)
                    return None
                self._register_member(position, member)
                self._walk_position = position + 1
                self._index_member_name(member)
                self._listed.append(member)
            return member
        except BaseException as exc:
            self._abandon_walk(exc)
            raise
        finally:
            self._walk_pulling = False

    def _pull_replayable(self, position: int) -> ArchiveMember:
        """Advance a random-access walk to ``position``, replaying what a failed one did.

        Each position's emits are logged while the backend types it. A walk started
        over after a discarded failure types it again, and a backend that builds fresh
        objects (ZIP, ISO, TAR) emits again: those replay from the log, including a
        position the failed walk was part way through, so each finding is recorded
        once. Once the backend has built the member, the log keeps only its codes: the
        object built first is the one kept, and it carries its attachments itself. A
        position that emitted nothing keeps no log. So until the walk ends it holds a
        code per emit, bounded by the listing limits like the member list, and a
        diagnostic only for the member being typed.
        """
        assert self._walk is not None
        log = self._walk_emits.get(position)
        fresh = log is None
        if log is None:
            # Most positions emit nothing, so their log is reused for the next one.
            log = self._spare_emit_log or EmitLog()
            self._spare_emit_log = None
            self._walk_emits[position] = log
        member = self._diagnostics_collector.call_replaying(log, self._walk.__next__)
        if not log.codes:
            del self._walk_emits[position]
            if fresh:
                # Nothing was recorded, so the log is as new: ``emit`` records a
                # detail or a raise only beside a code, and ``call_replaying`` has
                # dropped its reference to the log.
                assert log.details == [] and log.raised is None
                self._spare_emit_log = log
        else:
            log.settle()
        if position < len(self._walk_built):
            return self._walk_built[position]
        self._walk_built.append(member)
        return member

    def _end_walk(self, error: CorruptionError | None) -> None:
        """Record that the walk ended, and stamp last-entry-wins once, over what it listed.

        This is where ``is_current`` is stamped for duplicate names, whichever consumer
        ended the walk. On terminal damage it covers the recovered prefix the
        incomplete report holds: ``is_current`` defaults to ``True``, so an unstamped
        prefix would read every shadowed duplicate as current.
        """
        self._walk = None
        self._walk_done = True
        self._walk_error = error
        self._walk_built = []
        self._walk_emits = {}
        if error is not None:
            self._stamp_error_context(error)
        _apply_last_entry_wins_is_current(self._listed_in_index_order())

    def _listed_in_index_order(self) -> list[ArchiveMember]:
        """``_listed`` in the order the archive's index lists them, which decides which
        of two same-name members is current.

        The walk's order, unless a backend whose walk is not its index learns the
        index's order only at the end (a ZIP read from a pipe walks its local headers,
        and the central directory, read last, decides).
        """
        return self._listed

    def _drop_listed(self, dropped: list[ArchiveMember]) -> None:
        """Take members the walk has yielded out of the listing, at the end of the walk:
        the backend has learned that the archive's index does not list them.

        They keep their ids, so the ids of the listing have gaps where they were, and
        nothing changes them from here (``member_state_final``).

        Safe for the cursors that read ``_listed`` by position only when the backend
        calls it from the end of its walk under a forward pass: that pass's single
        cursor is then past every member, and ``ReaderState.acquire_pass`` refuses a
        second operation beside it, so no cursor stands behind a dropped member.
        """
        gone = {id(member) for member in dropped}
        for member in dropped:
            # Every member the walk yielded has its id (``_pull_member``).
            assert member._member_id is not None
            self._dropped_listed.add(member._member_id)
        self._listed = [member for member in self._listed if id(member) not in gone]
        # One pass per name: dropping one member at a time would rebuild a shared
        # name's entry once per member.
        for name in {member.name for member in dropped}:
            self._unindex_members(name, gone)
        _settle_listing(dropped, links_too=True)

    def _abandon_walk(self, exc: BaseException) -> None:
        """A pull failed without terminal damage: discard the walk, or poison it."""
        close = getattr(self._walk, "close", None)
        self._walk = None
        if close is not None:
            close()
        if self._streaming:
            # The pass has already yielded the prefix, so it cannot be walked again
            # without handing the caller a second object for the same member.
            self._walk_failure = exc
            # Nothing stamps the prefix now, and nothing can read it again, so it will
            # not change.
            _settle_listing(self._listed, sizes_too=True)
            return
        # A later call starts over, and ``_iter_members`` yields the same order;
        # ``_pull_member`` replays the positions the failed walk reached onto the same
        # objects. A random-access pass that already holds members of this walk (TAR's
        # one-pass walk) pulls up to its own position again
        # (``_ProgressivePassIterator._step_locked``), so it gets those same objects.
        self._listed = []
        self._listed_by_name = {}
        self._walk_position = 0
        self._listing_tracker.reset()

    def _drain_walk(self) -> None:
        """Pull to the end of the walk, in batches of ``_DRAIN_BATCH`` members.

        Each batch takes ``_walk_lock`` once. On a ``CONCURRENT`` reader the drain also
        yields between batches, so a pass on another thread waits about one batch for it,
        not the whole listing."""
        concurrent = self._state.concurrent
        while True:
            with self._walk_lock:
                if self._pull_members_locked(_DRAIN_BATCH) is None:
                    return
            if concurrent:
                # Under the GIL a release alone is no hand-off: this thread keeps
                # running and takes the lock again before a waiter gets to run. A short
                # sleep gives the GIL up so a waiter can take the lock (``sleep(0)``
                # hands over less reliably). It is a syscall, about 0.5 µs per member
                # in wall time, so only a reader that can have such a waiter pays it.
                time.sleep(1e-6)

    def _walk_ahead(self) -> None:
        """Drain a streaming walk before its pass reads data; a failure waits for it.

        For a backend whose pass reads better with the whole listing first: ZIP on a
        seekable source reads its directory once, then member data forward only. A
        pull that fails poisons the walk as in any streaming pass, and the pass then
        yields the members listed before it and raises it when it gets there, as it
        would with the listing and the data interleaved. Terminal damage is kept in
        ``_walk_error`` and raised at the end of the pass as usual, and the limit check
        at the end of the walk is left to the pass as well.
        """
        assert self._streaming
        if self._walk_done or not self._state.begin_materialization():
            return
        try:
            self._drain_walk()
        except Exception as exc:
            if exc is not self._walk_failure:
                raise
            self._walk_failure_unraised = True
        finally:
            self._state.fail_materialization()

    def _ensure_walked(self) -> None:
        """Drain the walk under the first-touch election, without resolving links.

        For the consumers that need the whole list but not its link targets: the peek
        and a backend's own random-access data pass. Under ``CONCURRENT`` a caller that
        overlaps another thread's walk or materialization waits for it; without it the
        overlap raises, as materialization does. The election is handed back unpublished
        afterwards, so ``members()`` can still resolve links and publish.
        """
        # A walk published while we waited on the election has ended too.
        if not self._walk_done and self._state.begin_materialization():
            try:
                self._drain_walk()
            finally:
                self._state.fail_materialization()
        self._listing_tracker.assert_within_limits()

    def _own_member(self, member: ArchiveMember) -> ArchiveMember | None:
        """The listed object ``member`` stands for: itself, or the member a
        ``replace()`` copy was made from. ``None`` for one this reader did not list.

        A late field a read fills (``size``) goes on this object, never on a copy
        (``ArchiveMember.replace``).
        """
        member_id = member._member_id
        if member_id is None or member._archive_id != self._archive_id:
            return None
        for listed in self._listed:
            if listed is member or listed._member_id == member_id:
                return listed
        return None

    def _listed_members(self) -> Iterator[ArchiveMember]:
        """The listed members for a backend's own data pass, then the walk's damage.

        Streaming pulls through the shared forward pass, so the pass registers,
        finalizes and publishes like every other backend's. Random access drains the
        walk first; a pass that reaches the end then finalizes its links and publishes
        the listing as the streaming pass does, so a 7z or RAR4 symlink whose target is
        its data has that target after the pass in both modes. A pass abandoned early
        never gets here and resolves nothing. Under ``CONCURRENT`` a ``members()`` call
        beside the pass can publish first; the pass then publishes nothing
        (``_finalize_pass_links`` goes through the election).
        """
        if self._streaming:
            yield from self._begin_forward_pass()
            return
        self._ensure_walked()
        yield from list(self._listed)
        error = self._walk_error
        self._finalize_pass_links(error=error)
        if error is not None:
            raise error

    def _materialize_members(self) -> _Materialized:
        """Materialize members into one report plus name index.

        ``CorruptionError`` / ``TruncatedError`` during listing publish an incomplete
        report. Resource limits, interrupts, and all other failures leave the reader
        unmaterialized and propagate unchanged. A failure in link resolution keeps the
        walk: the members may already have been handed out by a peek, and a retry
        resolves the links that were not finished.
        """
        published = self._published_within_limits()
        if published is not None:
            return published

        if not self._state.begin_materialization():
            # Another thread published while we waited (or cache was already ready).
            published = self._published_within_limits()
            assert published is not None
            return published

        try:
            self._drain_walk()
            # Prefer the original listing error on the report; leave unresolved links
            # as-is when a secondary link-target fault is swallowed.
            holder = self._finalize_and_publish(self._walk_error, child_scope=True)
            self._state.complete_materialization()
            return holder
        except BaseException:
            # MUST be BaseException, not Exception: a KeyboardInterrupt/MemoryError/
            # SystemExit raised mid-scan (7z folder decode, TAR header walk, a bomb) would
            # otherwise leave cache_state stuck at MATERIALIZING forever — a non-concurrent
            # reader then raises a misleading "materialization already in progress", and a
            # CONCURRENT waiter blocks on the CV with no owner left to notify it. We reset
            # the election state and re-raise so the interrupt still propagates unchanged.
            # (mark_reader_closed's drain path handles BaseException the same way.) The
            # walk has already discarded itself, if it was the walk that failed.
            self._materialized = None
            self._state.fail_materialization()
            raise

    def _published_within_limits(self) -> _Materialized | None:
        """The published listing, or ``None``; a published one is re-checked first.

        A link target read on request after publication (``_read_link_target_on_request``)
        is weighed without enforcing, so the totals can cross a limit after the report
        was published; the listing methods then refuse it on the way out.
        """
        materialized = self._materialized
        if materialized is not None:
            self._listing_tracker.assert_within_limits()
        return materialized

    def _list_before_extraction(self) -> None:
        """List the archive before an extraction, if this reader lists first.

        Called by the extraction coordinator before its pass. On a random-access reader
        the default lists every member first, with the limits enforced, so nothing is
        written from an archive over them. A backend whose listing is itself a scan of
        the data may instead list as members arrive during the pass (TAR, a sequential
        format: :meth:`_pass_reads_through_walk`), and not decode the archive twice. A streaming reader always does that: its one pass is
        the listing. Every pass enforces the limits as it registers members.

        A listing that ends in damage does not raise here: the pass writes the
        members listed before it and then raises the damage, as a TAR pass does.

        A random-access pass that reads through the walk
        (:meth:`_pass_reads_through_walk`) lists as members arrive too, until the walk
        has ended: it registers each member with the limits enforced, so
        ``ResourceLimitError`` is raised at the member that crosses a cap, before it is
        written, as ``members()`` raises it. The members before it are written, as a
        streaming pass writes them (DR-5).
        """
        if not self._streaming and (
            self._walk_done or not self._pass_reads_through_walk()
        ):
            self._materialize_members()

    def _pass_reads_through_walk(self) -> bool:
        """Whether a random-access pass reads member data through the walk.

        A backend whose listing is a scan of the data (TAR, a sequential format) says
        yes: until the walk has ended, ``stream_members()`` and extraction then share
        one forward pass with it, through :meth:`_open_member_in_walk`, and a solid
        archive is decoded once instead of once for the headers and again for the
        data. False by default. A backend with file copies (``FileCopyPass``) must not
        say yes: this pass does not take them."""
        return False

    def _open_member_in_walk(self, member: ArchiveMember) -> MemberStreamParts:
        """``member``'s data for a pass that reads through the walk
        (:meth:`_pass_reads_through_walk`), usually through :meth:`_walk_handoff_locked`."""
        raise NotImplementedError

    def _account_archive_comment(self) -> None:
        self._listing_tracker.account_archive_comment(self._archive_comment())

    def _archive_comment(self) -> str | None:
        """The archive comment, weighed before the member walk starts.

        ``ArchiveInfo``'s by default. A backend whose ``ArchiveInfo`` can cost a pass
        over its index (ZIP's ``member_count``) answers directly, so starting the walk
        does not walk the index first.
        """
        return self._get_archive_info().comment

    def _register_member(
        self,
        idx: int,
        member: ArchiveMember,
    ) -> None:
        """Assign identity, run backend-independent presentation checks, and account.

        Runs when the walk pulls the member at ``idx``. A walk started over after a
        discarded failure (``_abandon_walk``) pulls the same positions onto the same
        objects (``_pull_member``); their presentation checks, counted by position in
        ``_walk_presented``, are not repeated, so a deceptive name is reported once
        whichever backend built it. A check whose emit raised is not counted as run, so
        a strict policy refuses again on the retry; the emits before it are replayed
        from ``_presenting`` rather than counted twice (``_present_member``). The
        listing tracker was reset with the discarded walk, so the member is counted
        again.
        """
        member._member_id = idx
        member._archive_id = self._archive_id
        if idx >= self._walk_presented:
            if name_controls_possible(member):
                self._present_member(idx, member)
            self._walk_presented = idx + 1
        is_symlink = member.type is MemberType.SYMLINK
        if member.link_target == "" and (
            is_symlink or member.type is MemberType.HARDLINK
        ):
            # A target the header carries (TAR, RAR5, ISO Rock Ridge) is set while the
            # member is typed, so this is the first place every backend's passes share.
            # Emit first and clear after: a strict policy that raises here leaves the
            # member as it was, so a walk started over reports it again.
            self._emit_empty_link_target(member)
            member.link_target = None
            member._link_target_resolved = True
        # Settled when its listing resolves links.
        member._listing_pending = True
        if (
            is_symlink
            and member.link_target is None
            and not member._link_target_resolved
            and self._LINK_TARGETS_IN_DATA
        ):
            member._link_target_unread = True
        self._listing_tracker.account_member(member)

    def _present_member(self, idx: int, member: ArchiveMember) -> None:
        """Run the name and link-target checks for the member at ``idx``.

        One member can make several of these emits (a name and a target, up to three
        codes each). If a later one raises, the earlier ones already count, so a walk
        started over replays this position's log rather than emitting them again, and
        the emit that raised raises again from the log. A streaming walk is never
        started over, so it keeps no log.
        """
        collector = self._diagnostics_collector
        if self._streaming:
            emit_member_name_controls(
                collector, member=member, archive_name=self._archive_name
            )
            emit_link_target_controls(
                collector, member=member, archive_name=self._archive_name
            )
            return
        if self._presenting is None or self._presenting[0] != idx:
            self._presenting = (idx, EmitLog())
        with collector.replaying(self._presenting[1]):
            emit_member_name_controls(
                collector, member=member, archive_name=self._archive_name
            )
            # A target the header carries is known now. A target stored as member
            # data is checked when it is read (`_resolve_link_target`), so each
            # member is checked once either way.
            emit_link_target_controls(
                collector, member=member, archive_name=self._archive_name
            )
        self._presenting = None

    def _emit_empty_link_target(self, member: ArchiveMember) -> None:
        """Report a symlink or hard link whose stored target is the empty string.

        No filesystem takes an empty path as a link target, and an empty name matches
        no member, so the archive records no target for this link, the same as a
        writer that stored none. It is presented
        the same way: ``link_target`` unset, and extraction records
        ``LINK_TARGET_UNAVAILABLE`` for it instead of passing ``""`` to ``os.symlink``.
        """
        self._emit_link_target_unavailable(
            member,
            reason="target_empty",
            message=(
                f"The {'symlink' if member.type is MemberType.SYMLINK else 'hard link'} "
                f"target of {quoted(member.name)} is stored as an empty "
                f"string; leaving link_target unset."
            ),
            target_in_archive=False,
        )

    def _ensure_link_target(self, member: ArchiveMember) -> None:
        """Populate ``link_target`` from member data when needed. Base is a no-op."""
        return

    def _resolve_link_target(self, member: ArchiveMember) -> None:
        """Run the backend's link-target hook at most once per member.

        Nothing the hook can learn changes between two calls on the same member: the
        archive's bytes are fixed and a password is reader-level, never per-open. So a
        second call only re-opens and re-decompresses the member and emits the same
        diagnostic again — which would count one targetless link twice in
        ``DiagnosticSummary.counts``, and under a ``RAISE`` disposition would raise at
        whatever later access happened to touch the member rather than during listing.

        Under the walk lock, so two threads following the same link on a
        ``CONCURRENT`` reader read and report it once: the second finds the memo. The
        walk lock and not a lock of its own: link finalization already holds it while
        it calls this, so a second lock would have to be taken in that same order
        everywhere.
        """
        with self._walk_lock:
            self._resolve_link_target_locked(member)

    def _resolve_link_target_locked(self, member: ArchiveMember) -> None:
        if member.link_target is not None or member._link_target_resolved:
            return
        try:
            self._ensure_link_target(member)
        except UNREADABLE_LINK_TARGET_ERRORS:
            # Damaged target data stays damaged, and a method or codec this install
            # cannot decode stays undecodable: a later read raises the same error and
            # sets nothing, so the member will not change.
            member._link_target_unread = False
            raise
        if member.type is MemberType.SYMLINK and member.link_target == "":
            # A target stored as member data (ZIP, 7z) of zero bytes. Cleared
            # before the emit, the reverse of `_register_member`: if a strict policy
            # raises here, the memo below stays unset and a later lookup reads the
            # member again and reports it again.
            member.link_target = None
            self._emit_empty_link_target(member)
        emit_link_target_controls(
            self._diagnostics_collector,
            member=member,
            archive_name=self._archive_name,
        )
        # After, not before: a hook that raised did not look and come back empty, it
        # never finished. `_finalize_links` reports an unreadable target (damage, an
        # unsupported method, a missing codec) here and lists the link without a
        # target, so marking it resolved on the way out would trade the real error for
        # a generic "Link target is unknown" when the caller opens or extracts the link.
        # A backend that catches EncryptionError returns normally, so the repeated-read
        # case this memo exists for is still covered.
        member._link_target_resolved = True
        member._link_target_unread = False

    def _read_link_target_on_request(self, member: ArchiveMember) -> None:
        """Read ``member``'s target because the caller asked for this link.

        The read ``ArchiveyConfig.read_link_targets=False`` leaves to the caller:
        ``extract_all`` on a link its selector and filter accepted, and ``open()``
        following one. It fills ``link_target`` in place, and under either setting it
        is the same read link finalization would make, so a filled target is never
        read twice. The target is weighed by the listing tracker like one finalization
        reads, without enforcing: this is not a listing call, and the published report
        will carry it.
        """
        # Under the walk lock, as _resolve_link_target is: the check, the read and the
        # weighing happen once for two threads following the same link.
        with self._walk_lock:
            if member.link_target is not None or member._link_target_resolved:
                return
            self._resolve_link_target_locked(member)
            if member.link_target is not None:
                self._listing_tracker.account_link_target(
                    member.link_target, enforce=False
                )

    def _emit_link_target_unavailable(
        self,
        member: ArchiveMember,
        *,
        reason: str,
        message: str,
        target_in_archive: bool,
        member_id: int | None = None,
    ) -> None:
        """Report that a link's target could not be read, and why.

        Every path that *looks* for a link's target and leaves ``link_target`` unset
        goes through here. That is the whole guarantee `safe-extraction` and
        ``docs/extracting.md`` make about the ``LINK_TARGET_UNAVAILABLE`` outcome: it says
        only that extraction wrote nothing, so the *reason* has to reach the caller on
        the diagnostics channel, and ``SYMLINK_TARGET_UNAVAILABLE`` is in
        ``ARCHIVE_INTEGRITY_CODES`` so a strict policy refuses the archive outright.
        A backend that returns quietly instead makes that guarantee false.

        One path leaves the target unset without looking and does not come here:
        ``ArchiveyConfig.read_link_targets=False``, under which listing and a pass
        skip data-stored targets (``_finalize_links``). Nothing was read and nothing
        failed, and an integrity code there would have a strict policy refuse an
        archive over a setting the caller chose. A read the caller then asks for
        (``extract_all`` on an accepted link, ``open()`` following one) does look, and
        reports here like any other.

        ``target_in_archive`` says whether the archive carries a target this reader
        could not reach — compressed, split across volumes, encrypted — as against
        recording none at all. Extraction turns the first into a per-member failure and
        only the second into ``LINK_TARGET_UNAVAILABLE``, because a member the archive
        describes in full must not go missing from the output under a status that reads
        as success. The caller decides it because the caller is the only place that
        knows; inferring it downstream from "the lookup finished" is what this
        parameter replaced.

        ``member_id`` is for a backend calling this while the member is still being
        *typed*, before :meth:`_register_member` has stamped it: the member's position
        in the walk, which is the id registration will stamp, so the report names the
        member the caller will see.
        """
        member._link_target_absent = not target_in_archive
        self._diagnostics_collector.emit(
            code=DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE,
            message=message,
            context=SymlinkTargetContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member._member_id
                if member._member_id is not None
                else member_id,
                reason=reason,
            ),
            member=member,
            attach_to_member=True,
            logger=logger,
        )

    def _emit_link_target_too_long(
        self, member: ArchiveMember, *, member_id: int | None = None
    ) -> None:
        """Report a data-stored link target over :data:`MAX_LINK_TARGET_BYTES`.

        The archive does carry a target, so ``target_in_archive`` is true: extraction
        fails the member rather than reporting it as a link the archive left empty, and
        ``SYMLINK_TARGET_UNAVAILABLE`` being an integrity code makes a strict policy
        refuse the whole archive.
        """
        self._emit_link_target_unavailable(
            member,
            reason="target_too_long",
            message=(
                f"The symlink target of {quoted(member.name)} is longer than "
                f"{MAX_LINK_TARGET_BYTES} bytes; treating it as corrupt and leaving "
                f"link_target unset."
            ),
            target_in_archive=True,
            member_id=member_id,
        )

    def _emit_timestamp_invalid(
        self,
        member: ArchiveMember,
        member_id: int,
        issue: TimestampIssue,
        *,
        log: logging.Logger | None = logger,
    ) -> None:
        """Report one ``MEMBER_TIMESTAMP_INVALID`` finding, attached to ``member``.

        ``member_id`` is the walk position, as for :meth:`_emit_link_target_unavailable`:
        backends call this while typing the member. ``log=None`` uses the collector's
        own logger.
        """
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
            message=issue.message,
            context=MemberTimestampContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                field=issue.field,
                source=issue.source,
                value_repr=issue.value_repr,
            ),
            member=member,
            attach_to_member=True,
            logger=log,
        )

    def _emit_directory_data_ignored(
        self, member: ArchiveMember, member_id: int, *, reach: str | None = None
    ) -> None:
        """Report one ``MEMBER_DIRECTORY_DATA_IGNORED`` finding, attached to ``member``.

        ``member`` is a ``DIRECTORY`` whose header declares a non-zero size, or whose
        body is larger than an empty one (a declared size of 0 over real bytes; the
        backend decides what an empty body takes, since the Java ``jar`` tool deflates
        one for every directory it writes). No format gives a directory entry content,
        and every official tool creates the directory and drops the bytes silently;
        archivey does the same on extraction but says so (DR-3). A declared size opens
        through ``open()``, and gets a stream from ``stream_members()``, where the
        backend can decode the body (RAR delivers stored data only); a declared size
        of 0 has nothing to read in either. ``reach`` replaces the clause on where a
        declared size can be read, for a backend whose pass could not offer the bytes.
        """
        assert member.size or member.compressed_size, (
            "only a directory with a body is reported"
        )
        if member.size:
            what = f"declares {member.size} bytes of data"
            if reach is None:
                reach = (
                    "open() and stream_members() deliver them where they can be decoded"
                )
        else:
            what = f"declares no data but stores a {member.compressed_size}-byte body"
            reach = "a declared size of 0 leaves nothing to read"
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED,
            message=(
                f"Directory {quoted(member.name)} {what}; extraction creates the "
                f"directory and does not write them ({reach})."
            ),
            context=DirectoryDataContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                size=member.size or 0,
                compressed_size=member.compressed_size,
            ),
            member=member,
            attach_to_member=True,
            logger=logger,
        )

    def _emit_special_file_has_data(
        self, member: ArchiveMember, member_id: int | None
    ) -> None:
        """Report ``MEMBER_SPECIAL_FILE_HAS_DATA`` for a ``FILE`` whose stored type is a
        device, FIFO or socket (``extra["special_file_type"]`` is set), attached to
        ``member``. ``member_id`` is the walk position, as for
        :meth:`_emit_timestamp_invalid`, or ``None`` when neither the caller nor the
        member has one (a re-type in :meth:`_apply_reparse_data`)."""
        code, message, context = special_file_has_data_report(member)
        self._diagnostics_collector.emit(
            code=code,
            message=message,
            context=replace(
                context, archive_name=self._archive_name, member_id=member_id
            ),
            member=member,
            attach_to_member=True,
        )

    def _emit_name_encoding_inferred(
        self,
        member: ArchiveMember,
        member_id: int,
        *,
        inferred_encoding: str,
        passed_over: str,
        message: str,
    ) -> None:
        """Report one ``MEMBER_NAME_ENCODING_INFERRED`` finding, attached to ``member``.

        ``inferred_encoding`` decoded the stored bytes to ``member.name``;
        ``passed_over`` is the encoding the name would otherwise have had (the caller's
        ``encoding=``, or the format's fallback), recorded as ``declared_encoding``.
        ``member_id`` is the walk position, as for :meth:`_emit_timestamp_invalid`.
        """
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED,
            message=message,
            context=NameEncodingContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                raw_name_base64=raw_name_to_base64(member.raw_name),
                inferred_encoding=inferred_encoding,
                declared_encoding=passed_over,
            ),
            member=member,
            attach_to_member=True,
            logger=logger,
        )

    def _watch_unverified_read(
        self,
        stream: BinaryIO,
        member: ArchiveMember,
        *,
        size: int,
        check: Literal[
            "weak_open_check", "confirm_budget_exhausted", "no_password_check"
        ]
        | Callable[[], Literal["weak_open_check", "confirm_budget_exhausted"] | None],
        format_label: str,
        digest: str,
        why: str,
        seek_forfeits: bool = True,
    ) -> BinaryIO:
        """Wrap ``stream`` to report ``ENCRYPTED_MEMBER_UNVERIFIED`` if it is abandoned
        before its ``digest`` (``"checksum"``, ``"integrity check"``) is reached.

        ``why`` says why the password is in doubt. The report runs at close, not
        open: a member's name and id are fixed at listing, so reading them then gives
        the open-time values. ``check`` may be a callable, for a password picked at
        the first read: it says at close which check took it, ``None`` for one
        confirmed (no report).
        """

        def report(reason: str) -> None:
            decided = check() if callable(check) else check
            if decided is None:
                return
            missed = (
                f"gave up its {digest} by seeking"
                if reason == "seek"
                else f"was closed before its {digest} was reached"
            )
            self._diagnostics_collector.emit(
                code=DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED,
                message=(
                    f"Encrypted {format_label} member {quoted(member.name)} {missed}, "
                    f"and {why}: the bytes read may have been decrypted with a wrong "
                    f"password."
                ),
                context=EncryptedVerificationContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=member._member_id,
                    check=decided,
                    reason=reason,
                ),
                member=member,
                logger=integrity_logger,
            )

        def key_in_doubt() -> bool:
            return (check() if callable(check) else check) is not None

        return UnverifiedPasswordReadWatch(
            stream,
            size=size,
            on_unverified=report,
            seek_forfeits=seek_forfeits,
            key_in_doubt=key_in_doubt,
        )

    def _read_link_target_data(
        self,
        member: ArchiveMember,
        open_data: Callable[[], AbstractContextManager[ReadableStream]],
        *,
        is_reparse_point: bool,
    ) -> bytes | None:
        """Read a symlink member's data for its target, never past the cap.

        A member whose declared size is over :data:`MAX_LINK_TARGET_BYTES` is refused
        without opening it: this reports the member and returns ``None``. That is the
        path every over-long ZIP or 7z target takes, because both always declare a size.

        Otherwise the read asks for at most the cap + 1 bytes, and an answer over the
        cap is refused the same way. Where the backend's stream verifies the declared
        size — ZIP always, 7z whenever checksums are verified, the default — a member
        whose data runs past a size under the cap never gets that far: reaching its
        declared size with data left over raises ``CorruptionError`` there, as for any
        other member whose data disagrees with its header. The byte bound is what holds
        where the size is unknown or not verified.

        A Windows reparse buffer is never refused here, because its data may turn out to
        be ordinary file content (see :meth:`_apply_reparse_data`) that stays readable at
        any length. It is read as far as the buffer's own header says it runs — the
        8-byte header, then the payload length it declares, at most 0xFFFF — which is
        everything :func:`parse_reparse_data` looks at. The target it yields is held to
        the cap there.

        Both reads ask for one byte past what they need. On a member that is exactly
        that long, the extra byte reaches end of stream, so its checksum is verified as
        a whole read would. On a reparse buffer, a byte there means the data runs on
        past the buffer, which then does not parse as one.
        """
        if not self._link_data_refused_by_size(
            member, is_reparse_point=is_reparse_point
        ):
            with open_data() as stream:
                data = self._read_bounded_link_data(
                    stream, is_reparse_point=is_reparse_point
                )
            if is_reparse_point or len(data) <= MAX_LINK_TARGET_BYTES:
                return data
        self._emit_link_target_too_long(member)
        return None

    @staticmethod
    def _link_data_refused_by_size(
        member: ArchiveMember, *, is_reparse_point: bool
    ) -> bool:
        """Whether ``_read_link_target_data`` refuses ``member`` without opening it."""
        declared = member.size
        return (
            not is_reparse_point
            and declared is not None
            and declared > MAX_LINK_TARGET_BYTES
        )

    @staticmethod
    def _read_bounded_link_data(
        stream: ReadableStream, *, is_reparse_point: bool
    ) -> bytes:
        """The bytes ``_read_link_target_data`` reads from an opened link member.

        Split out so a backend that reads a link's bytes ahead of its resolution (7z,
        from a shared folder decode) reads exactly what a direct read would, and the
        later resolution over those bytes answers the same.
        """
        if is_reparse_point:
            header = read_exact(stream, REPARSE_HEADER_BYTES)
            return header + read_exact(stream, reparse_payload_length(header) + 1)
        return read_exact(stream, MAX_LINK_TARGET_BYTES + 1)

    def _link_target_from_data(
        self,
        member: ArchiveMember,
        open_data: Callable[[], AbstractContextManager[ReadableStream]],
        *,
        reparse_fallback: MemberType | None,
    ) -> None:
        """Fill ``link_target`` from the member's data (ZIP, 7z).

        ``reparse_fallback`` is ``None`` for a plain symlink. For a Windows reparse
        point it is the ``fallback_type`` of :meth:`_apply_reparse_data`: the data is
        a REPARSE_DATA_BUFFER, which decoded as UTF-8 would be reported as the target.
        """
        # The zero-data reparse point does not appear here:
        # `_settle_empty_reparse_point` settles it while the member is being typed.
        # The read is capped (`_read_link_target_data`): the data is compressed, so an
        # uncapped read let a small archive decode to gigabytes here.
        try:
            data = self._read_link_target_data(
                member, open_data, is_reparse_point=reparse_fallback is not None
            )
        except EncryptionError as exc:
            # A symlink's target is its file data, so without the password there is
            # nothing to decode. Listing has to stay usable without one, so the member
            # keeps its type and the reason travels on the diagnostics channel instead
            # — silence here would make extraction skip the link with no explanation.
            reason, message = self._locked_link_target_report(member, exc)
            self._emit_link_target_unavailable(
                member,
                reason=reason,
                message=message,
                # The archive does carry the target; it is locked, not missing. So this
                # member fails the way the encrypted file next to it does, rather than
                # disappearing from the output under a status that reads as success.
                target_in_archive=True,
            )
            return
        if data is None:
            return
        if reparse_fallback is not None:
            self._apply_reparse_data(member, data, fallback_type=reparse_fallback)
        else:
            member.link_target = data.decode("utf-8", errors="surrogateescape")

    def _locked_link_target_report(
        self, member: ArchiveMember, exc: EncryptionError
    ) -> tuple[str, str]:
        """The ``(reason, message)`` for a link target its encryption kept unread."""
        if is_unverified_data_error(exc):
            # Nothing confirmed the password before the data failed its check: a wrong
            # password or a damaged member, and nothing here can say which.
            return "password_or_damage", (
                f"The symlink target of {quoted(member.name)} failed its integrity "
                f"check; the password may be wrong or the member may be corrupt. "
                f"Leaving link_target unset."
            )
        return "password_required", (
            f"Cannot read the symlink target of {quoted(member.name)} without the "
            f"correct password; leaving link_target unset."
        )

    def _settle_empty_reparse_point(
        self,
        member: ArchiveMember,
        *,
        reparse_fallback: MemberType | None,
        member_id: int,
    ) -> None:
        """Settle, while it is typed, a reparse point the writer stored no data for."""
        if reparse_fallback is not None and member.size == 0:
            # A writer that stores no data for a reparse point has recorded no target
            # for it, and that is knowable from the header alone — no read, and so no
            # dependence on this being a seekable pass. Deciding it here rather than in
            # the link-target hook is what makes streaming agree: under
            # `read_link_targets=False` that hook runs only when extraction reads the
            # link, and a RAR pass runs it at EOF, after extraction has already decided
            # what to do with the member, which left a 7-Zip junction raising instead
            # of taking the recorded outcome. Here it needs no read at all.
            self._apply_reparse_data(
                member, b"", fallback_type=reparse_fallback, member_id=member_id
            )

    def _apply_reparse_data(
        self,
        member: ArchiveMember,
        data: bytes,
        *,
        fallback_type: MemberType,
        member_id: int | None = None,
    ) -> None:
        """Set ``link_target`` (and ``is_junction``) from a Windows reparse buffer.

        This answers the target question outright — it either produces a target or
        records that the archive holds none — so it marks the lookup done. A backend
        that already has the buffer, or already knows there is none, can therefore call
        it while the member is being typed, and ``_resolve_link_target`` will not run
        the hook again later. That matters wherever the hook runs late: at EOF in a
        RAR pass, or under ``read_link_targets=False`` only when the link is read, after
        extraction has decided what to do with the member. A ZIP or 7z pass under the
        default runs it when it reaches the member.

        The reparse tag that separates a junction from a symlink is the first field of
        that buffer, and the buffer is the member's *data*, so this is the same
        listing-from-data path a symlink target already takes — see
        :mod:`archivey.internal.windows_reparse`.

        The attribute bit that gets a member here says it *was* a reparse point on the
        source filesystem. It does not promise the archive carries the buffer, and it
        does not promise the tag named a link at all — Windows sets the same bit for
        deduplication stubs, cloud placeholders and WSL entries, whose data is ordinary
        content. So a member whose data is present but is not a link buffer goes back to
        ``fallback_type`` and keeps that content: the bytes are what we know, the link
        type is what we inferred, and discarding the former for the latter would cost
        the caller a readable member.

        That trade only pays when ``fallback_type`` is a FILE. Re-typing to DIRECTORY
        buys nothing and costs twice over: :meth:`open` refuses a directory, so the data
        this exists to preserve becomes unreachable anyway, and the entry has already
        lost the trailing slash that made it a directory in the first place (the backend
        suppresses that rename's diagnostic because a *link* stored with the directory
        convention is the format's own spelling). A directory-shaped entry therefore
        stays a targetless link, which is what the archive said it was.

        A member with no data at all has nothing to reinterpret and stays a link with no
        target. That is the case every Windows archiver actually produces for a junction:
        7-Zip writes no data for the directory reparse point that every junction is, so
        the target and the tag are both simply gone, and a member whose target we
        invented would be worse than one that says it has none.
        """
        member._link_target_resolved = True
        parsed = parse_reparse_data(data)
        if parsed is not None and parsed.is_junction:
            # The tag is the buffer's first field, so a junction is established as soon
            # as the buffer parses — independently of whether a target came out of it.
            member.extra[EXTRA_IS_JUNCTION] = True
        if parsed is not None and parsed.target:
            # Held to the same cap as a plain target. Measured in UTF-8, the form every
            # other data-stored target arrives in, since the buffer's UTF-16 byte count
            # is not what a POSIX path limit is written against.
            encoded_size = len(parsed.target.encode("utf-8", errors="surrogatepass"))
            if encoded_size > MAX_LINK_TARGET_BYTES:
                self._emit_link_target_too_long(member, member_id=member_id)
                return
            member.link_target = parsed.target
            return

        # `data` may be only the prefix `_read_link_target_data` read, so the message
        # names the size the archive declares for the member instead. Without one, all
        # it can say is that there are at least this many bytes.
        data_size = (
            str(member.size) if member.size is not None else f"at least {len(data)}"
        )
        if parsed is None and data and fallback_type is not MemberType.DIRECTORY:
            member.type = fallback_type
            if (
                fallback_type is MemberType.FILE
                and EXTRA_SPECIAL_FILE_TYPE in member.extra
            ):
                # The entry's mode named a device, FIFO or socket and it was typed a
                # link provisionally, so the backend's own emit (gated on FILE while
                # the member is typed) did not run. It is a data-bearing FILE from
                # here, and the data-model spec asks for the advisory with the key.
                self._emit_special_file_has_data(
                    member,
                    member_id if member_id is not None else member._member_id,
                )
            reason = "reparse_data_unrecognized"
            message = (
                f"{quoted(member.name)} is flagged as a Windows reparse point, but its "
                f"{data_size} bytes of data are not a symlink or junction buffer; "
                f"presenting it as a {fallback_type.value} with that data as its content."
            )
        elif parsed is None and data:
            reason = "reparse_data_unrecognized"
            message = (
                f"{quoted(member.name)} is flagged as a Windows reparse point, but its "
                f"{data_size} bytes of data are not a symlink or junction buffer; "
                f"it is stored as a directory, whose content is not readable either "
                f"way, so it stays a link with no target."
            )
        else:
            if not data:
                detail = "the writer stored no reparse data for it"
                reason = "reparse_data_absent"
            else:
                detail = "its reparse data names no target"
                reason = "reparse_data_nameless"
            message = (
                f"Cannot read the link target of {quoted(member.name)}: {detail}; "
                f"leaving link_target unset."
            )
        # Every branch above is the archive recording no target: no data, a buffer that
        # names nothing, or bytes that are not a link buffer at all. None of them is a
        # target this reader merely failed to reach.
        self._emit_link_target_unavailable(
            member,
            reason=reason,
            message=message,
            target_in_archive=False,
            member_id=member_id,
        )

    def _index_member_name(self, member: ArchiveMember) -> None:
        index = self._listed_by_name
        held = index.get(member.name)
        if held is None:
            index[member.name] = member
        elif isinstance(held, list):
            held.append(member)
        else:
            index[member.name] = [held, member]

    def _unindex_members(self, name: str, gone: AbstractSet[int]) -> None:
        """Take the members whose ``id()`` is in ``gone`` out of ``name``'s entry.

        By identity: a duplicate can compare equal to the member being removed. ``gone``
        is a set so that one pass over a long entry stays linear.
        """
        index = self._listed_by_name
        held = index.get(name)
        if held is None:
            return
        if not isinstance(held, list):
            if id(held) in gone:
                del index[name]
            return
        kept = [m for m in held if id(m) not in gone]
        if len(kept) == len(held):
            return
        if not kept:
            del index[name]
        elif len(kept) == 1:
            index[name] = kept[0]
        else:
            index[name] = kept

    def _listed_named(self, name: str) -> Sequence[ArchiveMember]:
        """The members listed so far under exactly ``name``, in listing order.

        Read-only, and only until the index next changes: for a duplicated name it is
        the index's own list.
        """
        held = self._listed_by_name.get(name)
        if held is None:
            return ()
        if isinstance(held, list):
            return held
        return (held,)

    def _last_by_exact_name(self, name: str) -> ArchiveMember | None:
        held = self._listed_by_name.get(name)
        if isinstance(held, list):
            return held[-1]
        return held

    def _find_link_target(
        self, member: ArchiveMember, *, before_id: int | None = None
    ) -> ArchiveMember | None:
        """The member ``member``'s link target refers to, or ``None`` if not present.

        Resolves the stored target string to an archive-namespace name first (a symlink
        target is relative to the link's own directory — see
        :func:`resolve_link_target_name`), then looks it up in the name index;
        directory members carry a trailing ``/`` in their names, so both forms are
        tried. With ``before_id``, only members listed before that id count.

        A symlink takes the last entry of the bare name, then of the ``/`` spelling.

        A hard link is always bounded by its own id, so a caller passes no other
        ``before_id`` for one. It takes the latest entry listed before itself, across
        both spellings, and never one listed after it, in any format or mode: a hard
        link names a file already archived. ``tar(1)`` and ``unrar`` extract one by linking to what they
        have already written, and ``unrar`` fails a link whose target comes later ("You
        need to unpack the link target first"). The other formats store no hard-link
        record. A backward answer also never changes as a streaming walk lists more
        members, so it can be memoized.
        """
        if not member.link_target:
            return None
        target_name = resolve_link_target_name(
            member.name, member.link_target, member.type
        )
        if target_name is None:
            return None
        hardlink = member.type == MemberType.HARDLINK
        if hardlink:
            assert before_id is None or before_id == member._member_id
            before_id = member._member_id
            if before_id is None:
                return None
        if before_id is None:
            for name in link_target_name_keys(target_name):
                last = self._last_by_exact_name(name)
                if last is not None:
                    return last
            return None
        best: ArchiveMember | None = None
        best_id = -1
        for name in link_target_name_keys(target_name):
            for candidate in reversed(self._listed_named(name)):
                candidate_id = candidate._member_id
                if candidate_id is None or candidate_id >= before_id:
                    continue
                if not hardlink:
                    return candidate
                if candidate_id > best_id:
                    best, best_id = candidate, candidate_id
                break
        return best

    def _hardlink_direct_target(self, member: ArchiveMember) -> ArchiveMember | None:
        """The member a HARDLINK names, before following any link.

        Extraction uses it to tell a hard link to a symlink from one to a file, which
        ``link_target_member`` (the end of the chain) cannot.
        """
        if member.type is not MemberType.HARDLINK:
            return None
        return self._find_link_target(member)

    def _resolve_link(
        self,
        member: ArchiveMember,
        terminals: dict[int, ArchiveMember | None],
    ) -> None:
        """Resolve link_target to the fully dereferenced link_target_member.

        ``terminals`` memoizes, by ``_member_id``, where a walk from each link ends:
        the terminal member, or ``None`` for a cycle or a dead end. A walk depends only
        on the node it is at (the hardlink lookup keys off that node's own id, not the
        member the walk started from), so every link on a path shares the path's
        terminal. Recording it for all of them makes finalizing N chained links O(N)
        instead of O(N²).

        A cycle or dead end does not set ``link_target_member``; it does not clear it
        either, so a value a streaming pass already stamped (resolved against the members
        before this one only) survives. That is bookkeeping, not an error:
        :meth:`_open_with_link_follow` is where a read of an unresolved link raises.
        """
        path: list[int] = []
        on_path: set[int] = set()
        current = member
        terminal: ArchiveMember | None
        while True:
            if not (current.is_link and current.link_target):
                terminal = current
                break
            member_id = current._member_id
            if member_id is None:
                terminal = None
                break
            if member_id in terminals:
                terminal = terminals[member_id]
                break
            if member_id in on_path:
                # Cycle detected; leave link_target_member unset (None).
                terminal = None
                break
            path.append(member_id)
            on_path.add(member_id)
            target = self._find_link_target(current)
            if target is None:
                terminal = None
                break
            current = target

        for member_id in path:
            terminals[member_id] = terminal
        if terminal is not None and terminal is not member:
            member.link_target_member = terminal

    def _finalize_pass_links(self, *, error: ArchiveyError | None = None) -> None:
        """Resolve all links after a forward pass reaches EOF or terminal damage."""
        if self._materialized is not None:
            return
        # Also ends a random-access reader's stream_members() pass (TAR's one-pass
        # walk, and the 7z and solid RAR passes over ``_listed_members()``), which
        # opens no child scope either. Through the election: under CONCURRENT a
        # members() call beside the pass may be publishing, and then this waits for
        # it and publishes nothing.
        if not self._state.begin_materialization():
            return
        try:
            self._finalize_and_publish(error, child_scope=False)
            self._state.complete_materialization()
        except BaseException:
            self._materialized = None
            self._state.fail_materialization()
            raise

    def _link_progressive_member(self, member: ArchiveMember) -> None:
        """Point a link the pass is about to yield at a member the pass already passed.

        Only earlier members count, as if the list ended here: a peek into an upfront
        index can have walked past this member already, and a target found among later
        members is for finalization to set, not this yield.
        """
        if not member.is_link or member.link_target_member is not None:
            return
        member_id = member._member_id
        if member_id is None:
            return
        target = self._find_link_target(member, before_id=member_id)
        if target is not None and target is not member:
            if target.is_link:
                target = target.link_target_member
            if target is not None:
                member.link_target_member = target

    def _begin_forward_pass(self) -> Iterator[ArchiveMember]:
        """Return the shared instance-held progressive pass, creating it if needed."""
        if self._progressive_gen is None:
            self._progressive_gen = _ProgressivePassIterator(self)
        return self._progressive_gen

    def _guard_forward_pass_entry(self, op: str) -> None:
        if self._streaming and self._forward_pass_started:
            raise ArchiveyUsageError(
                f"{op} is not available after a streaming reader's forward pass has "
                f"started. Call members_report() to finish the pass and get the member "
                f"list, or members_report_if_available() for an index-only peek.",
            )

    def _enter_forward_pass(self, op: str) -> None:
        self._guard_forward_pass_entry(op)
        self._forward_pass_started = True

    # --- Public API ---

    def _require_random_access(self, op: str) -> None:
        """Raise ``ArchiveyUsageError`` if ``op`` (a random-access or
        full-materialization operation) is not allowed on this reader.

        A ``streaming=True`` reader is forward-only: only a single pass of
        ``__iter__``/``stream_members`` (or one ``extract_all``) is allowed. This is
        uniform and format-independent — it does **not** depend on whether a backend
        happens to have an index loaded. The message names the route that fits
        ``op``: for member data (``get()``, ``open()``/``read()``), iterate
        :meth:`stream_members` and read each stream as the pass reaches it; for the
        listing (``members()``), use :meth:`members_report`, iterate
        :meth:`stream_members`, or peek with :meth:`members_report_if_available`.
        """
        self._state.require_open(op)
        if self._streaming:
            if op == "members()":
                advice = (
                    "Call members_report() for the member list (it uses up the "
                    "forward pass; raise report.error for complete-or-raise), "
                    "iterate stream_members() and ignore the streams, or call "
                    "members_report_if_available() for an index-only peek."
                )
            else:
                advice = (
                    "Iterate stream_members() and read each member's stream as the "
                    "pass reaches it."
                )
            raise ArchiveyUsageError(
                f"{op} is not available on a streaming (forward-only) reader. {advice}",
            )

    @property
    def format(self) -> ArchiveFormat:
        self._state.require_open("format")
        return self._format

    @property
    def format_info(self) -> FormatInfo | None:
        self._state.require_open("format_info")
        return self._format_info

    @property
    def info(self) -> ArchiveInfo:
        self._state.require_open("info")
        return self._get_archive_info()

    @property
    def cost(self) -> CostReceipt:
        self._state.require_open("cost")
        return self._cost_receipt()

    def _cost_receipt(self) -> CostReceipt:
        """``ArchiveInfo.cost``; overridden as :meth:`_archive_comment` is."""
        return self._get_archive_info().cost

    @property
    def diagnostics(self) -> DiagnosticSummary:
        """Fresh immutable cumulative snapshot of diagnostics for this reader."""
        self._state.require_open("diagnostics")
        return self._diagnostics_collector.snapshot()

    @property
    def compressed_source_size(self) -> int | None:
        """Byte size of the archive's source when cheaply knowable, else ``None``.

        The denominator for extraction's archive-wide decompression-ratio guard (see
        ``safe-extraction``): for zip/7z/rar/compressed-tar the source size *is* the
        compressed size, and for a plain tar or other uncompressed container the
        resulting ~1:1 ratio simply never trips the guard. Cheap only — see
        ``source_byte_size``: path ``stat``, a ``size`` attribute on a seekable source
        or on an archivey member stream (enabling nested archives), a ``try_get_size()``
        index scan, or a ``SEEK_END`` probe restricted to provably O(1) types (never a
        decompressor). Backends record their source in ``self._source``; readers
        without one (directory) or with an unknowable source report ``None``.

        A caller's **non-seekable** stream reports ``None`` even when it has a ``size``
        attribute: that is the caller's claim, and a pipe has no end to check it
        against. An inflated claim would make the static ratio unreachable and, as the
        complement below, switch off the live counter too. A member stream of another
        archive keeps its ``size`` whether it seeks or not
        (``ArchiveSource.seek_is_expensive`` marks it). That ``size`` is the length the
        container declares, and the container is untrusted input as well: a member
        shorter than its declaration is refused by the container's end-of-member check
        only after its payload is decoded, so for a nested archive ``max_extracted_bytes``
        is the bound that holds.
        """
        self._state.require_open("compressed_source_size")
        return self._trusted_source_size()

    def _trusted_source_size(self) -> int | None:
        """The source's size hint when it may be the ratio denominator, else ``None``.

        The one answer ``compressed_source_size`` reports and ``_wrap_compressed_input``
        complements. A seekable source's hint counts, and so does a member stream's
        declared length (``seek_is_expensive``), itself unchecked until the member ends.
        A caller's non-seekable stream's ``size`` does not.
        """
        src = self._source
        if src is None:
            return None
        if src.seekable() or src.seek_is_expensive:
            return src.size_hint
        return None

    @property
    def compressed_bytes_consumed(self) -> int | None:
        """Running count of compressed bytes pulled from the archive's outer source so far,
        or ``None`` when nothing is being counted.

        The **live** denominator for extraction's archive-wide decompression-ratio guard
        (see ``safe-extraction``), used when ``compressed_source_size`` is ``None`` — a
        compressed archive whose source size is not cheaply knowable (a non-seekable pipe,
        with or without a ``size`` attribute, or a seekable stream that is neither a
        whitelisted O(1)-seek type nor ``.size``-advertising). A backend that
        decompresses a *stream* source wraps it in a ``CountingReader`` and records it
        here; readers with a knowable source size (a path, a sizable stream) leave it
        ``None`` and rely on the cheaper static ratio instead.
        """
        self._state.require_open("compressed_bytes_consumed")
        c = self._compressed_input_counter
        return c.bytes_read if c is not None else None

    def _wrap_compressed_input(self, source: BinaryIO) -> BinaryIO:
        """Wrap a stream source **whose byte size is not cheaply knowable** in a
        ``CountingReader`` (recorded for the live decompression-ratio guard) and return the
        wrapper; return the source unchanged for a path or a sizable stream, whose static
        archive-wide ratio applies instead — exactly the complement of
        ``compressed_source_size``, so one of the two denominators is always available for
        a compressed source. A compressed backend that decompresses a stream source calls
        this on the raw source before handing it to the codec layer, so
        ``compressed_bytes_consumed`` tracks what the decompressor pulls.

        For a *seekable* unsizable source the codec layer may seek and re-read (an index
        scan, an accelerator); re-read bytes are counted again, which only ever inflates
        the denominator — the guard gets weaker, never a false positive.
        """
        # Asked of the reader's source the way ``compressed_source_size`` asks it, so the
        # two stay complements; ``source`` may be a view over it.
        known = (
            self._trusted_source_size()
            if self._source is not None
            else source_byte_size(source)
        )
        if known is None:
            counter = CountingReader(source)
            self._compressed_input_counter = counter
            return counter
        return source

    def _codec_input(
        self, source: ArchiveSource, *, track_seeks: bool = False
    ) -> BinaryIO:
        """What a codec decodes from the stream ``source``: :meth:`_wrap_compressed_input`
        of it, with the seek counter (:meth:`_track_source_seeks`) when ``track_seeks``.

        On a source that cannot seek, the codec reads what has arrived
        (:meth:`ArchiveSource.arrived_view`), and each of its reads makes one read of
        the source (:class:`OneReadEachStream`). A codec asks for a 64 KiB feed, and a
        full-count read of it would wait for a writer that keeps a pipe open. Every
        decoder reads until ``b""``, so a feed split at any byte gives the same output
        and the same verdict.
        """
        if source.seekable():
            counted = self._wrap_compressed_input(source)
            return self._track_source_seeks(counted) if track_seeks else counted
        counted = self._wrap_compressed_input(cast("BinaryIO", source.arrived_view()))
        if track_seeks:
            counted = self._track_source_seeks(counted)
        # Outermost, so the codec's buffering takes it as it is and puts no
        # full-count BufferedReader in front of it (ensure_bufferedio).
        return OneReadEachStream(counted)

    def _open_outer_codec_stream(
        self,
        source: ArchiveSource,
        stream_format: StreamFormat | PluginStream,
        streaming: bool,
        *,
        member_streams: MemberStreams,
    ) -> BinaryIO:
        """The decoded bytes of an archive inside a compression stream (a ``.tar.gz``,
        or a sequential plugin format's ``.cpio.xz``): archivey's codec stream over
        ``source``, which the caller closes.

        A file goes to the codec as its path, as for a bare compressed file: the codec
        opens its own handle and may use path-only accelerators, and the static ratio
        applies because the size is known. A stream whose size is not known is counted
        (:meth:`_codec_input`), so the live decompression-ratio guard can see the
        compressed bytes consumed. The codec stream is the whole file, so bytes after
        its end are reported, as bytes after an archive's own end are.

        Listing such an archive decodes all of it, so the decoded stream is held to
        ``decoder_limits.max_ratio`` of the archive's size (:class:`DecodeRatioGuard`)
        in every use, not only in ``extract_all``.
        """
        # Imported here: the codec layer imports reader-side modules at load.
        from archivey.internal.bomb_tracker import DecodeRatioGuard
        from archivey.internal.config import stream_config_from_archivey
        from archivey.internal.streams.codecs import (
            codec_for_stream_format,
            open_codec_stream,
        )

        codec = codec_for_stream_format(stream_format)
        codec_source: str | BinaryIO
        if source.path is not None:
            codec_source = str(source.path)
        else:
            codec_source = self._codec_input(source, track_seeks=True)
        decoded = open_codec_stream(
            codec,
            codec_source,
            config=replace(
                stream_config_from_archivey(
                    self._config,
                    streaming=streaming,
                    seekable=MemberStreams.SEEKABLE in member_streams,
                    usage=self._usage,
                ),
                report_trailing_data=True,
            ),
            stamp=lambda exc: self._stamp_error_context(exc),
            collector=self._diagnostics_collector,
            # Random access reads it only through views. A read seeks the shared
            # handle when it is not already there, and one such seek is enough to
            # mark the stream rewound. A repeated verdict would drop the prefix of the
            # read that reaches the damage; each member stream repeats its own.
            repeat_verdict=streaming,
        )
        limits = self._ratio_limits()
        if limits.max_ratio is None:
            return decoded
        counter = self._compressed_input_counter
        return DecodeRatioGuard(
            decoded,
            limits=limits,
            static_size=self._trusted_source_size(),
            consumed=None if counter is None else lambda: counter.bytes_read,
        )

    def __iter__(self) -> MemberPass[ArchiveMember]:
        return MemberPassImpl(self._iter_pass())

    def _iter_pass(self) -> Generator[ArchiveMember, None, None]:
        self._state.require_open("__iter__")
        if self._streaming:
            token = self._state.acquire_pass("__iter__")
            try:
                self._enter_forward_pass("__iter__")
                for member in self._begin_forward_pass():
                    # Suspended at the yield: this thread runs the caller's loop body,
                    # which is not re-entry (see OperationToken.suspended).
                    self._state.set_suspended(token, True)
                    try:
                        yield member
                    except BaseException:
                        # Not a finally calling resume(): on a reader closed meanwhile
                        # it raises, which would replace the caller's own exception.
                        # The success path unsuspends inside resume().
                        self._state.set_suspended(token, False)
                        raise
                    # close() may have closed the reader while the pass was suspended.
                    self._state.resume(token, "Iterating the reader")
            finally:
                self._state.release_pass(token)
            return
        # Random access: iteration just walks the already-published immutable member
        # snapshot, so it must NOT hold a reader-wide pass across consumption — that would
        # reject the common `for m in reader: reader.open(m)` idiom as overlap. Take a
        # token only around materialization, the one members() takes, then yield the
        # captured snapshot with none held so open()/get() inside the loop are admitted.
        if self._state.concurrent:
            worker = self._state.acquire_worker("__iter__")
            try:
                report = self._materialize_members().report
            finally:
                self._state.release_worker(worker)
        else:
            token = self._state.acquire_pass("__iter__")
            try:
                report = self._materialize_members().report
            finally:
                self._state.release_pass(token)
        yield from report.members
        if report.error is not None:
            raise report.error

    def members(self) -> list[ArchiveMember]:
        self._require_random_access("members()")
        # Under CONCURRENT, first-touch materialization is coordinated via worker tokens
        # so overlapping members()/open()/get() share one build instead of rejecting.
        # Default readers keep an exclusive pass (single-owner materialization).
        if self._state.concurrent:
            token = self._state.acquire_worker("members")
            try:
                report = self._materialize_members().report
                if report.error is not None:
                    raise report.error
                return list(report.members)
            finally:
                self._state.release_worker(token)
        token = self._state.acquire_pass("members")
        try:
            # Return a shallow copy so callers cannot mutate the published cache container.
            report = self._materialize_members().report
            if report.error is not None:
                raise report.error
            return list(report.members)
        finally:
            self._state.release_pass(token)

    def members_report(self) -> MemberListReport:
        self._state.require_open("members_report()")
        if not self._streaming:
            if self._state.concurrent:
                token = self._state.acquire_worker("members_report")
                try:
                    return self._materialize_members().report
                finally:
                    self._state.release_worker(token)
            token = self._state.acquire_pass("members_report")
            try:
                return self._materialize_members().report
            finally:
                self._state.release_pass(token)

        token = self._state.acquire_pass("members_report")
        try:
            published = self._published_within_limits()
            if published is not None:
                return published.report
            self._forward_pass_started = True
            gen = self._begin_forward_pass()
            while True:
                try:
                    next(gen)
                except StopIteration:
                    break
                except CorruptionError:
                    assert self._materialized is not None
                    break
            published = self._published_within_limits()
            assert published is not None
            return published.report
        finally:
            self._state.release_pass(token)

    def members_report_if_available(self) -> MemberListReport | None:
        """Return the member-list report if it is available **without scanning**, else
        ``None``. Safe to call on any reader (including a streaming one).

        Index-only: returns a materialized report after a completed forward pass, or the
        backend's upfront index when ``_MEMBER_LIST_UPFRONT`` is set. It never triggers
        a forward scan, never reads member data, and never consumes the forward pass.
        Link targets stored in member data (e.g. ZIP symlinks) may be unset; use
        :meth:`members` or :meth:`members_report` for a fully-resolved list. The members
        are the reader's own objects, the same ones every other listing method and pass
        returns, so a later ``members()`` fills those link fields in place.

        On an upfront index this drains the reader's one member walk, which reads no
        member data. A walk that ends in terminal archive damage is returned as the
        incomplete report (prefix plus ``error``), not raised. After a streaming pass
        stopped by a listing limit, ``None``, as on a reader with no index.
        """
        if not self._state.concurrent:
            self._state.require_open("members_report_if_available()")
            return self._members_report_if_available()
        # A worker token, as members() takes: close() then waits for the walk below
        # instead of closing the archive under it.
        token = self._state.acquire_worker("members_report_if_available()")
        try:
            return self._members_report_if_available()
        finally:
            self._state.release_worker(token)

    def _members_report_if_available(self) -> MemberListReport | None:
        published = self._published_within_limits()
        if published is not None:
            return published.report
        if not self._MEMBER_LIST_UPFRONT or isinstance(
            self._walk_failure, ResourceLimitError
        ):
            # A streaming pass stopped by a listing limit handed out a prefix it
            # cannot walk again, so there is no report without a scan, as on a
            # reader with no index. Any other failure still raises the poison. On a
            # reader with an upfront index a walk's ResourceLimitError is a listing
            # limit: the walks that raise other kinds (a decoder cap met finding a
            # bit-3 descriptor, from a pipe) belong to readers with no index.
            return None
        self._ensure_walked()
        materialized = self._materialized
        if materialized is not None:
            # Published while this call waited on another thread's materialization.
            return materialized.report
        return MemberListReport(
            members=tuple(self._listed),
            error=self._walk_error,
            diagnostics=self._diagnostics_collector.snapshot(),
        )

    def __contains__(self, member: object) -> bool:
        # Identity membership for ArchiveMembers: O(1), no scan, so it works in any
        # access mode. This method must exist even though it is a convenience — without
        # a __contains__, the `in` operator falls back to iterating __iter__, which
        # would silently consume a streaming reader's single forward pass (and compare
        # members by value). Strings are rejected: name lookup is get().
        self._state.require_open("__contains__")
        if isinstance(member, ArchiveMember):
            return member._archive_id == self._archive_id
        raise TypeError(
            f"'in <ArchiveReader>' tests whether an ArchiveMember belongs to this "
            f"reader (by identity); to look up a member by name use reader.get(name). "
            f"Got {type(member).__name__}.",
        )

    def get(
        self, name: str, default: ArchiveMember | None = None
    ) -> ArchiveMember | None:
        self._require_random_access("get()")
        # Without this a ``bytes`` name answered "absent" for a member that exists (a
        # wrong answer), and an ArchiveMember escaped as ``unhashable type``. ``open()``
        # refuses a ``bytes`` name the same way; it takes a member object, which get()
        # does not, because get() looks up by name.
        if not isinstance(name, str):
            raise _UsageTypeError(
                f"reader.get() takes a member name (str), but got "
                f"{describe_value(name)}."
            )
        token = self._state.acquire_worker("get")
        try:
            materialized = self._materialize_members()
            found = self._last_by_exact_name(name)
            if found is not None:
                return found
            if materialized.report.error is not None:
                raise materialized.report.error
            return default
        finally:
            self._state.release_worker(token)

    def open(self, member: str | ArchiveMember) -> ArchiveStreamImpl:
        """Open member for reading. Follows symlinks.

        Without ``open_archive(concurrent_operations=True)``, at most one member stream may
        be live. With it, concurrent first-touch materialization is coordinated and
        concurrent ``open`` is supported. Positioning requires
        ``open_archive(seekable_members=True)``.
        """
        self._require_random_access("open()/read()")
        token = self._state.acquire_worker("open")
        try:
            materialized = self._materialize_members()
            if isinstance(member, str):
                found = self._last_by_exact_name(member)
                if found is None:
                    if materialized.report.error is not None:
                        raise materialized.report.error
                    raise KeyError(f"Member {member!r} not found")
                member = found
            else:
                # Checked before the identity comparison below, which reads a private
                # attribute: without this, `open(0)` failed as
                # `AttributeError: 'int' object has no attribute '_archive_id'` —
                # a private field name crossing the public boundary in place of an
                # answer. `in` raises TypeError here (a spec'd escape for the operator
                # protocol); this is an ordinary argument, so it takes the usage error.
                if not isinstance(member, ArchiveMember):
                    raise _UsageTypeError(
                        f"reader.open() takes a member name (str) or an ArchiveMember "
                        f"yielded by this reader, but got {describe_value(member)}."
                    )
                # A member object must have been yielded by THIS reader (same identity rule
                # as `member in reader`). Without this check, a member from another archive
                # resolves against the wrong offsets/paths and can silently return the wrong
                # data (e.g. the directory backend would read whatever sits at the same
                # relative path under this reader's root).
                if member._archive_id != self._archive_id:
                    raise _UsageValueError(
                        f"Member {quoted(member.name)} does not belong to this reader; open a "
                        f"member yielded by this reader, or look it up by name with "
                        f"reader.get(name)."
                    )
            # Gate before spawn: ``_lazy_member_stream`` already registers first.
            # Reserve under the lock so two threads cannot both pass, then open,
            # then bind. A refused second open must not build a decompressor /
            # unrar process that is never registered.
            reservation = self._state.reserve_live_stream()
            bound = False
            stream: ArchiveStreamImpl | None = None
            try:
                opened: list[ArchiveMember] = []
                stream = self._open_with_link_follow(
                    member, visited=set(), opened=opened
                )
                self._hold_to_ratio(stream, opened[0])
                # Asked before the bind: from here a raise still closes the stream.
                run = (
                    self._solid_run(opened[0])
                    if self._solid_decoded is not None
                    else None
                )
                registered = self._register_public_stream(stream, token=reservation)
                bound = True
                if run is not None:
                    self._note_solid_open(opened[0], run)
                return registered
            finally:
                if not bound:
                    pending = sys.exception()
                    if stream is not None:
                        try:
                            stream.close()
                        except Exception as close_exc:
                            # Don't replace the in-flight open/register error.
                            if pending is not None:
                                pending.add_note(
                                    "closing the unbound member stream also failed: "
                                    f"{close_exc}"
                                )
                            else:
                                raise
                    if self._state.release_reservation(reservation):
                        # True → last lease dropped. Today this is False: open()
                        # still holds a worker, so the reader lease remains. Honour
                        # the return so a future invariant break actually teardowns.
                        self._maybe_teardown()
        finally:
            self._state.release_worker(token)

    def _resource_usage(self) -> ResourceUsage:
        """How close this reader has come to each reader-lifetime limit so far."""
        return self._usage.snapshot()

    def _solid_run(self, member: ArchiveMember) -> SolidRun | None:
        """Where ``open(member)`` starts decoding, when it decodes a shared run.

        ``None`` (the default) when the open does not decode bytes of other members:
        a member of its own, or a backend that keeps one decoder position across opens
        (compressed TAR, whose backward seeks ``STREAM_REWIND_REDECOMPRESSES``
        reports). A backend whose every open decodes the member's solid run from its
        start (7z folders, solid RAR) returns that run. Must not raise or decode: it
        reads the member's listed position only.
        """
        del member
        return None

    def _note_solid_open(self, member: ArchiveMember, run: SolidRun) -> None:
        """Log once per reader when an ``open()`` decodes again what an earlier did.

        ``run`` is ``member``'s :meth:`_solid_run`, and the open already succeeded, so
        this only counts and logs: it must not raise. The open decoded the run from its
        start through ``run.offset + run.size``. Per run the reader keeps how far opens
        have decoded and how far they discarded (the largest ``offset``). This open
        decodes again the part of its discarded prefix that an earlier open decoded,
        plus the part of its own member an earlier open decoded and discarded. A
        member's own bytes do not count when the same member is read again, since a
        non-solid archive pays that too; the prefix it decodes again does. On the
        first open that decodes anything again the record is INFO on
        ``archivey.backends``: the caller may have chosen the pattern, and
        ``reader.cost`` and the ``open()`` docstring already carry the cost.
        """
        end = run.offset + run.size
        with self._solid_decoded_lock:
            decoded = self._solid_decoded
            if decoded is None:
                return
            decoded_to, discarded_to = decoded.get(run.key, (0, 0))
            again = min(run.offset, decoded_to) + max(
                0, min(end, discarded_to) - run.offset
            )
            if again <= 0:
                decoded[run.key] = (
                    max(decoded_to, end),
                    max(discarded_to, run.offset),
                )
                return
            self._solid_decoded = None
        logger.info(
            "Archive %r is solid: opening %r decoded again %d bytes an earlier open() "
            "on this reader had decoded, because each open() or read() decodes its "
            "member's solid block from the start. Reading many members this way is "
            "quadratic in the block size; stream_members() decodes each block once. "
            "Logged once per reader.",
            self._archive_name or "(unnamed source)",
            member.name,
            again,
        )

    def _open_with_link_follow(
        self,
        member: ArchiveMember,
        visited: set[int],
        opened: list[ArchiveMember] | None = None,
    ) -> ArchiveStreamImpl:
        """Open ``member``, following links hop by hop until a non-link member.

        ``opened``, when given, receives the member whose data the stream reads.

        A loop, not recursion: an archive's chain can be longer than the interpreter's
        recursion limit, and ``RecursionError`` is outside the library's error contract.

        The cycle policy differs from :meth:`_resolve_link` on purpose. That one is
        listing bookkeeping and leaves ``link_target_member`` unset on a cycle or dead
        end; this one is a caller asking for bytes, so it raises
        ``LinkTargetNotFoundError`` (a ``ReadError``). Do not unify them.
        """
        current = member
        while current.type in (MemberType.SYMLINK, MemberType.HARDLINK):
            # Every hop is registered: ``open()`` refuses a member whose ``_archive_id``
            # is not this reader's, ``_register_member`` sets that id together with
            # ``_member_id``, and ``link_target_member`` / ``_find_link_target`` hand
            # back registered members.
            assert current._member_id is not None, current.name
            member_id = current._member_id
            if member_id in visited:
                raise LinkTargetNotFoundError(
                    "Link cycle detected",
                    reason=LinkTargetNotFoundReason.UNRESOLVED,
                    member_name=current.name,
                )
            visited.add(member_id)
            if current.link_target_member is not None:
                current = current.link_target_member
                continue
            if current.link_target is None:
                self._read_link_target_on_request(current)
            if current.link_target is None:
                raise LinkTargetNotFoundError(
                    "Link target is unknown",
                    reason=LinkTargetNotFoundReason.NOT_RECORDED
                    if current.link_target_unrecorded
                    else LinkTargetNotFoundReason.UNREADABLE,
                    member_name=current.name,
                )
            # open() materializes first: a half-walked index must never answer a lookup.
            assert self._materialized is not None
            target = self._find_link_target(current)
            if target is None:
                raise LinkTargetNotFoundError(
                    "Link target not found in archive",
                    reason=LinkTargetNotFoundReason.UNRESOLVED,
                    member_name=current.name,
                    link_target=current.link_target,
                )
            current = target
        # A tombstone and a special entry are refused by type: there is nothing to
        # deliver for them even where a header declares a size. A directory is
        # refused by data: it has none unless its header declares some, and one that
        # does (``MEMBER_DIRECTORY_DATA_IGNORED`` reported it at listing, in ZIP, TAR
        # and RAR) opens here. ``stream_members()`` decides by ``pass_has_data``,
        # which says where the two differ; extraction creates the directory and does
        # not write the bytes. Both messages end in "(not a file)", which ``archivey
        # test`` classifies by.
        if current.type in (MemberType.ANTI, MemberType.OTHER):
            raise _UsageValueError(
                f"Cannot open member {quoted(current.name)}: type is "
                f"{current.type.value!r} (not a file)",
                refused_member_type=current.type,
            )
        if current.type is MemberType.DIRECTORY and not current.size:
            raise _UsageValueError(
                f"Cannot open member {quoted(current.name)}: directory entry "
                "declares no data (not a file)",
                refused_member_type=current.type,
            )
        if opened is not None:
            opened.append(current)
        return self._open_member_handle(current)

    def read(self, member: str | ArchiveMember) -> bytes:
        """Read member data as bytes."""
        with self.open(member) as f:
            return f.read()

    def stream_members(
        self,
        members: MemberSelectorArg = None,
        *,
        file_copy_streams: bool = True,
    ) -> MemberPass[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """Yield (member, stream) pairs. members is a selector filter (no transform).

        The stream is ``None`` for every member :func:`pass_has_data` rejects (see
        there for the one shape where that differs from ``open()``). The yielded
        stream is owned by the iterator: advancing closes/invalidates the
        previous stream before the next pair is produced. It never seeks, on any
        format and whatever ``seekable_members`` says (``_iter_stream_members`` makes
        each handle forward-only); ``tell()`` works.
        """
        if not isinstance(file_copy_streams, bool):
            raise _UsageTypeError(
                "stream_members(file_copy_streams=…) takes True or False, but got "
                f"{describe_value(file_copy_streams)}."
            )
        return MemberPassImpl(
            self._stream_members(
                members, FileCopyPass(streams=file_copy_streams), hold_to_ratio=True
            )
        )

    def _stream_members(
        self,
        members: MemberSelectorArg,
        copies: FileCopyPass,
        *,
        hold_to_ratio: bool = False,
    ) -> Generator[tuple[ArchiveMember, ArchiveStreamImpl | None], None, None]:
        """``stream_members()`` with the file-copy handling given whole.

        The extraction coordinator calls this directly, to pass ``keep_source``, and
        leaves ``hold_to_ratio`` off: its own tracker holds what it writes to the limits
        of the ``extract_all`` call (``_hold_to_ratio``).
        """
        self._state.require_open("stream_members()")
        # Validate here rather than inside the generator: a generator body does not
        # run until the first next(), so a check left there raised at a call site
        # that did not make the mistake.
        selector = normalize_member_selector(members)
        # Report unmatched entries only for a selector built here from the caller's
        # collection. A CollectionSelector passed in is an internal caller's (the
        # extraction coordinator), and that caller reports for itself.
        report = (
            selector
            if isinstance(selector, CollectionSelector) and selector is not members
            else None
        )
        return self._iter_stream_members(
            selector, report, copies, hold_to_ratio=hold_to_ratio
        )

    def _iter_stream_members(
        self,
        selector: Callable[[ArchiveMember], bool] | None,
        report: CollectionSelector | None = None,
        copies: FileCopyPass = DEFAULT_FILE_COPY_PASS,
        *,
        hold_to_ratio: bool = False,
    ) -> Generator[tuple[ArchiveMember, ArchiveStreamImpl | None], None, None]:
        token = self._state.acquire_pass("stream_members")
        current: ArchiveStreamImpl | None = None
        source_closer: Callable[[], None] | None = None
        # The pass's streams hold the live-stream slot together (see
        # ReaderState.admit_pass_streams): admitted once, at the first, and not
        # registered for close() to find.
        admitted = False

        def wind_down() -> None:
            # The pass's pass_closer, run by close() while the pass is suspended at a
            # yield: close the stream the caller may still hold (``current``; nothing
            # else will, as it is not registered), then the backend's pass, whose
            # finally frees what the pass holds (a solid block, an unrar pipe).
            nonlocal current
            stream, current = current, None
            try:
                if stream is not None:
                    stream.close()
            finally:
                if source_closer is not None:
                    source_closer()

        try:
            if self._streaming:
                self._enter_forward_pass("stream_members()")
            source = self._iter_with_data(copies)
            source_closer = _closer_of(source)
            self._state.set_pass_closer(token, wind_down)
            for m, stream in source:
                if current is not None:
                    current.close()
                    current = None
                if stream is not None and not admitted:
                    # Held before the check, so a refusal closes it (never opened, so
                    # the close reads and decodes nothing).
                    current = stream
                    self._state.admit_pass_streams()
                    admitted = True
                    current = None
                if (
                    not copies.streams
                    and stream is not None
                    and m.extra.get(EXTRA_IS_FILE_COPY)
                ):
                    # Never opened, so closing it reads and decodes nothing.
                    stream.close()
                    stream = None
                if selector is None or selector(m):
                    if stream is not None:
                        # One rule for every backend, here rather than in each
                        # _iter_with_data: a pass handle never seeks. A seek would
                        # re-decode behind the pass, and a handle that could seek on
                        # some formats only is a per-format accident callers would
                        # come to rely on. seekable_members=True is for open().
                        stream._make_forward_only()
                        if hold_to_ratio:
                            # A file copy decodes its source's bytes again: held, and
                            # counted once, as that source.
                            copied = m.link_target_member
                            self._hold_to_ratio(
                                stream,
                                copied
                                if copied is not None
                                and m.extra.get(EXTRA_IS_FILE_COPY)
                                else m,
                            )
                    current = stream
                    # Suspended at the yield: this thread runs the caller's loop body,
                    # which is not re-entry (see OperationToken.suspended).
                    self._state.set_suspended(token, True)
                    try:
                        yield m, stream
                    except BaseException:
                        # Not a finally calling resume(): on a reader closed meanwhile
                        # it raises, which would replace the caller's own exception.
                        # The success path unsuspends inside resume().
                        self._state.set_suspended(token, False)
                        raise
                    # close() may have closed the reader while the pass was suspended.
                    self._state.resume(token, "stream_members()")
                elif stream is not None:
                    stream.close()
            # Only a pass that reached the end has offered every member. A caller
            # that stops early never gets here (the generator is closed at a yield).
            # Close the last stream first, so a diagnostic its close emits comes
            # before the unmatched ones.
            if current is not None:
                current.close()
                current = None
            if report is not None:
                report.report_unmatched(self._diagnostics_collector, self._archive_name)
        finally:
            if current is not None:
                current.close()
            # The backend's pass is closed here, not left to be dropped: what it holds
            # (an unrar process for a solid RAR) then ends now, and not only when an
            # interpreter without reference counting (PyPy) collects it. Once close()
            # has begun, its stream-shutdown step closes it instead (below).
            try:
                if source_closer is not None and self._state.lifecycle_is_open():
                    source_closer()
            finally:
                self._state.release_pass(token)
            # A close() interrupted inside its stream-shutdown step handed the step
            # back with the pass wind-down lease still held. Finish it here, so
            # dropping this iterator still reaches teardown without another close().
            # A no-op when close() finished the step, or the reader is still open.
            # A failure here propagates out of the generator's close(), or, when the
            # generator is being collected, goes to sys.unraisablehook.
            if not self._state.lifecycle_is_open():
                self._maybe_teardown(self._finish_stream_shutdown_step())

    def _check_extraction_dest(self, dest: Path) -> None:
        """Refuse a destination this reader's own source would read back.

        No-op here; ``DirectoryReader`` refuses a destination inside its root.
        Called before anything is created.
        """

    def extract_all(
        self,
        dest: str | Path,
        *,
        members: MemberSelectorArg = None,
        filter: MemberFilter | None = None,
        policy: ExtractionPolicy | ExtractionPolicyStr = ExtractionPolicy.STRICT,
        overwrite: OverwritePolicy | OverwritePolicyStr = OverwritePolicy.ERROR,
        on_error: OnError | OnErrorStr = OnError.STOP,
        abort_on: Collection[AbortOn | AbortOnStr] = (),
        on_progress: Callable[[ExtractionProgress], None] | None = None,
        limits: ExtractionLimits | None = None,
        dry_run: bool = False,
    ) -> ExtractionReport:
        """Extract members to dest via the shared ``ExtractionCoordinator``."""
        # At the boundary, not on use: the coordinator tests these with ``is``, so an
        # unrecognised value is not refused there, it silently takes the other branch.
        policy = coerce_enum(
            policy, ExtractionPolicy, call="extract_all()", param="policy="
        )
        overwrite = coerce_enum(
            overwrite, OverwritePolicy, call="extract_all()", param="overwrite="
        )
        on_error = coerce_enum(
            on_error, OnError, call="extract_all()", param="on_error="
        )
        abort_on = coerce_enum_collection(
            abort_on, AbortOn, call="extract_all()", param="abort_on="
        )
        self._state.require_open("extract_all()")
        check_extraction_limits(limits, call="extract_all(limits=…)")
        check_callable(on_progress, call="extract_all(on_progress=…)")
        # ``filter`` is not consulted until the first member is offered, by which point
        # the extraction is under way; a non-callable there reads as
        # ``TypeError: 'int' object is not callable`` with nothing naming the argument.
        check_callable(filter, call="extract_all(filter=…)")
        # ``members=`` is checked before dest is created, for the same reason as
        # filter: a refusal that has already touched the disk is a side effect of a
        # call the caller got wrong. It is normalized here once and only the result is
        # passed on, because ``members`` may be a one-shot iterable that a second read
        # would find empty.
        selector = normalize_member_selector(members)
        dest_path = check_dest(dest, call="extract_all(dest=…)")
        check_path_not_empty(dest_path, call="extract_all()")
        self._check_extraction_dest(Path(dest_path))
        # Check (but do not enter) the single-pass guard here, so a second extract_all
        # on a streaming reader fails with this method's name; the coordinator drives
        # the pass through the public stream_members(), which enters it properly.
        if self._streaming:
            self._guard_forward_pass_entry("extract_all()")
        # Imported here (not at module top) to keep the import graph tidy: extraction.py
        # type-checks against BaseArchiveReader.
        from archivey.internal.extraction import ExtractionCoordinator

        # The reader's open config applies to the whole reader lifetime; only the
        # extraction limits have a per-call override (see archive-reading).
        effective_limits = (
            limits if limits is not None else self._config.extraction_limits
        )
        collector = self._diagnostics_collector
        coordinator = ExtractionCoordinator(
            policy=policy,
            overwrite=overwrite,
            on_error=on_error,
            abort_on=abort_on,
            on_progress=on_progress,
            selector=selector,
            filter=filter,
            limits=effective_limits,
            # The reader's ratio, a deprecated field of its config's extraction limits
            # included, under the call's: a per-call ``limits=`` that sets no ratio
            # field keeps it.
            ratio=self._ratio_limits(),
            dry_run=dry_run,
        )
        token = self._state.acquire_pass("extract_all")
        try:
            # Library-internal member opens (including hardlink recovery) are ungated.
            # The report covers only the emits this call makes, on its own thread:
            # open-phase diagnostics stay on reader.diagnostics, and on a CONCURRENT
            # reader other threads emit into the same collector meanwhile.
            with self._internal_member_opens(), collector.scoped() as scope:
                results = coordinator.run(self, dest_path)
        finally:
            self._state.release_pass(token)
        return ExtractionReport(
            results=tuple(results),
            diagnostics=scope.summary(),
            _dry_run_top_level=coordinator.dry_run_top_level,
            _dry_run_links=coordinator.dry_run_links,
            _dry_run_entries=coordinator.dry_run_entries,
            _resource_usage=self._resource_usage(),
        )

    def close(self) -> None:
        """Close the reader.

        Idempotent. With declared concurrency, blocks until in-flight worker ``open()``
        / ``get()`` / ``members()`` calls return (``read()`` is one only while it opens
        the member), then marks the reader closed. Still-open member streams are then
        closed, matching ``zipfile.ZipFile.close()`` / ``tarfile.TarFile.close()``: a
        member stream does not outlive the reader it came from.

        In both modes, a member stream's own ``read()`` is not a worker call:
        ``close()`` closes the stream under it, and the stream's next ``read()`` raises
        ``ValueError``, as for any closed file. A read already running when the stream
        closes returns what it had or raises the same ``ValueError``, never a damage
        error.

        Without ``CONCURRENT``, ``close()`` still raises if a worker call or reader-wide
        pass is actively executing, and the reader stays open. A ``stream_members()`` or
        streaming iteration pass suspended at a yield does not block it: the reader
        closes, and resuming that iterator raises ``ArchiveyUsageError``. A suspended
        ``stream_members()`` pass is wound down here, before teardown. Teardown runs at
        most once, after the last lease drops.
        """
        if self._closed:
            return
        # Raising on an active pass must leave the reader open -- so member streams are
        # closed only once the transition has actually happened. Its "run teardown now"
        # result is not needed: _maybe_teardown() below asks claim_teardown() directly.
        # Every step below is idempotent on its own (a spent claim refuses), so
        # ``_closed`` is set only at the end, and only once the stream-shutdown step is
        # spent: an interrupt in between, or a peer close() that found the step's
        # holder still working, leaves teardown reachable instead of short-circuited by
        # the check above. The next close() reaches it, and so does the suspended
        # pass's own finally (see _finish_stream_shutdown_step()).
        self._state.mark_reader_closed()
        pending = self._finish_stream_shutdown_step()
        # Unconditional: claim_teardown() refuses while a lease remains or once claimed,
        # so this is a no-op wherever mark_reader_closed() returned False for a good
        # reason. It is not a no-op after a close() interrupted just past the transition:
        # the retry's mark_reader_closed() returns False (lifecycle is no longer OPEN)
        # although nothing tore the archive down. With teardown already claimed, it
        # still raises ``pending``.
        self._maybe_teardown(pending)
        if self._state.stream_shutdown_done():
            # A closed reader updates nothing, so a pass left early or a link never
            # read is as final as it will get.
            _settle_listing(self._listed, links_too=True)
            self._closed = True

    def _finish_stream_shutdown_step(self) -> Exception | None:
        """Wind a suspended pass down and close member streams, if this call may.

        Returns a held ``Exception`` from either, for ``_maybe_teardown()`` to raise.
        Called by ``close()`` and, once the reader is closed, by the ``finally`` of a
        ``stream_members()`` pass: the pass wind-down lease has no other releaser, so
        a pass dropped after an interrupted ``close()`` must still be able to finish
        the step itself.
        """
        # Exactly one caller winds the pass down and closes the streams.
        # mark_reader_closed() returns False both when this thread transitioned with
        # leases outstanding and when a peer had already closed, so it cannot tell the
        # owner from a late caller -- and ArchiveStream.close tests `self.closed` outside
        # its lock, so two concurrent close() calls could otherwise both reach
        # inner.close() on the same stream.
        pending: Exception | None = None
        # This call's claim on the step. The claim is the single store of this ticket in
        # the state, and it is taken inside the try below, so an interrupt anywhere
        # after it reaches the except arm, which hands the claim back. Whoever calls
        # this next -- a later close(), or the pass's own finally -- then retakes it and
        # drops the pass wind-down lease, which only the holder of the claim may drop:
        # a peer sees the claim held and must not drop a lease while the holder's
        # closer runs.
        ticket = object()
        try:
            if self._state.claim_stream_shutdown(ticket):
                # A stream_members() pass suspended at a yield: its wind-down closes
                # the stream the caller holds (not registered, so the stream close
                # below does not reach it), then the backend's pass iterator, whose
                # finally frees the pass's own resources. The transition took a lease with the
                # closer, so no stream close in here can claim teardown; it runs at
                # the caller's _maybe_teardown(), after finish_stream_shutdown() drops
                # the lease. An Exception from the wind-down or the stream shutdown is
                # held and returned for _maybe_teardown() to raise after teardown.
                try:
                    closer = self._state.take_pass_wind_down()
                    if closer is not None:
                        closer()
                except Exception as exc:  # noqa: BLE001 - raised by _maybe_teardown
                    pending = exc
                finally:
                    try:
                        self._close_public_streams()
                    except Exception as exc:  # noqa: BLE001 - raised by _maybe_teardown
                        pending = (
                            exc
                            if pending is None
                            else ExceptionGroup(
                                "winding down the pass and closing member streams "
                                "both failed",
                                [pending, exc],
                            )
                        )
                self._state.finish_stream_shutdown(ticket)
        except BaseException:
            # An interrupt: hand the claim back unless it was spent, then propagate.
            self._state.abandon_stream_shutdown(ticket)
            raise
        return pending

    def _close_public_streams(self) -> None:
        """Close member streams that are still open, in the order they were opened.

        Each close releases that stream's lease, and the last one triggers teardown
        through the ordinary path -- so the source is always closed *after* the streams
        reading through it, never underneath one.
        """
        failures: list[BaseException] = []
        # A snapshot: each close removes its stream from the registry (the lease hook).
        for stream in self._state.live_streams():
            if stream.closed:
                continue
            try:
                stream.close()
            except BaseException as exc:  # noqa: BLE001 - report every failure, not the first
                failures.append(exc)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup(
                "closing member streams during reader close failed", failures
            )

    def __enter__(self) -> Self:
        self._state.require_open("__enter__")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _validate_at_open(self) -> None:
        """Check the source decodes, once ``open_archive`` has set format provenance.

        A no-op by default. A backend that validates at open does it here rather than in
        ``__init__``, so a failure is stamped by :meth:`_stamp_error_context` with the
        provenance ``open_archive`` sets after construction (``format_unconfirmed`` and
        its diagnostic). ``open_archive`` closes the reader if this raises.
        """

    def _stamp_error_context(
        self, exc: ArchiveyError, member_name: str | None = None
    ) -> None:
        """Stamp format/archive/member context onto an ArchiveyError if not already set."""
        if exc.source_format is None:
            exc.source_format = self._format
        if exc.archive_name is None:
            exc.archive_name = self._archive_name
        if exc.member_name is None and member_name is not None:
            exc.member_name = member_name
        provenance = self._format_provenance
        if provenance is None or not isinstance(
            exc, (CorruptionError, ResourceLimitError)
        ):
            return
        evidence = provenance.unconfirmed_evidence
        if evidence is not None:
            self._mark_format_unconfirmed(exc, evidence)

    def io_stats(self) -> IoStats | None:
        """Return I/O counters if measurement is enabled, else ``None``.

        Enable measurement with :func:`archivey.internal.measurement.enable_measurement`
        around the :func:`archivey.open_archive` call. Returns ``None`` when the reader
        was not opened inside an ``enable_measurement()`` context.
        """
        if not self._measure:
            return None
        c_bytes = self._compressed_input_counter
        return IoStats(
            bytes_decompressed=self.bytes_decompressed,
            compressed_bytes_consumed=c_bytes.bytes_read
            if c_bytes is not None
            else None,
            source_seek_count=self.source_seek_count,
        )


class _ProgressivePassIterator(Iterator[ArchiveMember]):
    """Instance-held streaming pass: a cursor over the reader's one member walk.

    A generator would be closed (and its post-loop tail skipped) when a consumer
    breaks out of ``for member in reader``; this iterator survives early exit so
    :meth:`BaseArchiveReader.members_report` can drain the remainder.

    The cursor reads ``_listed`` and pulls from the walk only when it reaches the end
    of what has been walked, so a peek that drained the walk ahead of it hands the pass
    the same objects. It finalizes when *it* steps past the last member of an ended
    walk, not when the walk ends: a pass abandoned after a peek drained the walk
    resolves no links and publishes nothing.
    """

    def __init__(self, reader: BaseArchiveReader) -> None:
        self._reader = reader
        self._pos = 0
        self._finished = False
        self._error: BaseException | None = None

    def __iter__(self) -> _ProgressivePassIterator:
        return self

    def __next__(self) -> ArchiveMember:
        if self._error is not None:
            # The pass previously failed. A plain retry could step past the end of a
            # PARTIAL listing and finalize it as the complete, resolved member cache —
            # members_report() would then silently return a truncated listing after the
            # caller caught the original error. Fail loud and keep the cache unpublished.
            err = ReadError(
                "The archive scan previously failed "
                f"({type(self._error).__name__}); the member list is incomplete and "
                "cannot be resumed. Reopen the archive to retry."
            )
            raise err from self._error
        if self._finished:
            raise StopIteration
        reader = self._reader
        with reader._walk_lock:
            try:
                member = self._step_locked()
            except BaseException as exc:
                # A failed pull poisons the walk as well (``_abandon_walk``); this keeps
                # the pass's own answer the same whichever a retry reaches first.
                self._error = exc
                raise
        if member is None:
            # The cursor stepped past the last member of an ended walk.
            self._finished = True
            error = reader._walk_error
            try:
                reader._finalize_pass_links(error=error)
            except BaseException as exc:
                # Listing-limit refusal (or link finalize failure) must not leave a
                # half-published cache retryable as success via a second StopIteration.
                # Secondary Corruption/Truncated during link finalization after terminal
                # listing damage is swallowed inside _finalize_links so the recovered
                # prefix stays published.
                self._error = exc
                raise
            if error is not None:
                raise error
            raise StopIteration
        return member

    def _step_locked(self) -> ArchiveMember | None:
        """The member at this cursor, pulling up to it; ``None`` past an ended walk.

        Held under the walk lock. Other cursors (a second pass, a listing call under
        ``CONCURRENT``) may have pulled past this one, so the member is read from
        ``_listed`` when it is there. A walk discarded after a failure elsewhere and
        started over replays onto the same objects, so pulling up to this position
        again hands back the members this cursor has already yielded before its next.
        """
        reader = self._reader
        while self._pos >= len(reader._listed):
            if reader._pull_member() is None:
                return None
        member = reader._listed[self._pos]
        self._pos += 1
        reader._link_progressive_member(member)
        return member


class _TranslatedErrorBoundary:
    """``with``-boundary that applies ``_raise_translated`` to an escaping exception.

    A plain ``__exit__`` class (not a ``@contextmanager`` generator) so the exception
    handling is explicit: ``BaseException`` that is not an ``Exception`` always passes
    through untouched; an exception ``_raise_translated`` re-raises *unchanged* (already
    typed, or unrecognized by the translator) propagates as the original — with context
    stamped where applicable — and only a genuinely translated exception replaces it,
    chained via ``from``.
    """

    __slots__ = ("_member_name", "_reader", "_stamp_encryption")

    def __init__(
        self,
        reader: BaseArchiveReader,
        member_name: str | None,
        stamp_encryption: bool,
    ) -> None:
        self._reader = reader
        self._member_name = member_name
        self._stamp_encryption = stamp_encryption

    def __enter__(self) -> None:
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object,
    ) -> bool:
        if exc is None or not isinstance(exc, Exception):
            return False
        try:
            self._reader._raise_translated(
                exc,
                self._member_name,
                stamp_encryption=self._stamp_encryption,
            )
        except BaseException as raised:
            if raised is exc:
                # Already typed (stamped in place) or unrecognized: let the ORIGINAL
                # propagate from the with-body rather than re-raising from here, which
                # would tack an extra frame onto its traceback.
                return False
            raise


class _InternalMemberOpens:
    """``with``-boundary marking library-internal opens, exempt from the live-stream gate.

    A plain ``__enter__``/``__exit__`` class, matching ``_TranslatedErrorBoundary``
    above: this runs on every eager link-data read and every ``extract_all``, so it
    allocates one small object rather than a generator and a context manager per call.
    """

    __slots__ = ("_state",)

    def __init__(self, state: ReaderState) -> None:
        self._state = state

    def __enter__(self) -> None:
        self._state.begin_internal_opens()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self._state.end_internal_opens()
