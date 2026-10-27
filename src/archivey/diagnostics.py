"""Public diagnostic value types — structured advisories as queryable data.

See ``openspec/specs/diagnostics`` (and the ``diagnostics-warnings-as-data`` change)
for the lifecycle, retention, and policy contracts.

Layout of this module:

1. **Codes / disposition** — stable enums callers match on.
2. **Context payloads** — one frozen dataclass per ``kind``; fields are JSON-safe
   scalars so :meth:`Diagnostic.to_dict` needs no per-class serializers.
3. **Records** — :class:`Diagnostic`, :class:`DiagnosticSummary`, policy, reports.
4. **Helpers** — ``validate_code_context``, ``raw_name_to_base64``, ``format_path_name``
   (used when *emitting* diagnostics; end users mostly read the records).
"""

from __future__ import annotations

import base64
import dataclasses
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, Literal, TypeVar

from archivey.exceptions import ArchiveyError, _UsageTypeError, _UsageValueError
from archivey.internal.enum_args import coerce_enum_collection
from archivey.internal.resource_usage import ResourceUsage
from archivey.terminal import escape_control_chars
from archivey.types import ArchiveMember, ExtractionResult

_K = TypeVar("_K")
_V = TypeVar("_V")


def _freeze_mapping(mapping: Mapping[_K, _V] | None) -> Mapping[_K, _V]:
    """Defensive copy into an immutable mapping proxy."""
    if mapping is None:
        return MappingProxyType({})
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class _JsonSafeContext:
    """Shared ``to_dict`` for the flat context dataclasses below.

    Subclasses declare their own fields (this base adds none). Every field is a
    JSON-safe scalar (``str`` / ``int`` / ``None`` / ``Literal``), so
    ``dataclasses.asdict`` is enough — no per-class boilerplate.
    """

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


class DiagnosticCode(StrEnum):
    """Stable machine codes for advisory events.

    The codes in :data:`ARCHIVE_INTEGRITY_CODES` report the archive's own bytes or
    metadata as anomalous, and ``DiagnosticPolicy.STRICT`` raises them. A diagnostic's
    ``context`` carries the details, such as the member and the field involved.
    """

    MEMBER_NAME_NORMALIZED = "member_name_normalized"
    """A member's stored name was changed to give ``name``, for example its
    separators or a ``.`` segment."""
    MEMBER_NAME_ENCODING_INFERRED = "member_name_encoding_inferred"
    """A member's name was decoded with an encoding archivey inferred, not one the
    archive or the caller declared."""
    MEMBER_NAME_BIDI_CONTROL = "member_name_bidi_control"
    """A member's name or link target contains bidi controls, which change the order
    the text displays in and can make an ``.exe`` look like a ``.png``."""
    MEMBER_NAME_ZERO_WIDTH_CHARACTER = "member_name_zero_width_character"
    """A member's name or link target contains a zero-width space, word joiner or
    byte-order mark, so two different names can look the same."""
    MEMBER_NAME_INVISIBLE_CHARACTER = "member_name_invisible_character"
    """A member's name or link target contains another invisible format character,
    such as a zero-width joiner or a soft hyphen. These occur in ordinary names, such
    as in emoji."""
    FORMAT_EXTENSION_CONFLICT = "format_extension_conflict"
    """The file name's extension suggests one format and the content another.
    archivey goes by the content."""
    EXPLICIT_FORMAT_LISTED_EMPTY = "explicit_format_listed_empty"
    """An archive opened with ``format=`` listed no members. The context's
    ``detected_format`` says what detection finds in the content."""
    EXTENSION_FORMAT_UNCONFIRMED = "extension_format_unconfirmed"
    """A format chosen from the file name alone, with nothing in the content to
    confirm it, listed no members or failed to read."""
    PROBE_FORMAT_UNCONFIRMED = "probe_format_unconfirmed"
    """A format found only by decoding a sample of the content failed to read, so the
    file may not be in that format."""
    EMPTY_ARCHIVE = "empty_archive"
    """The listing finished without error and found no members."""
    ENCODING_ARGUMENT_UNUSED = "encoding_argument_unused"
    """``encoding=`` was passed for a format that decodes member names without it
    (7z, a directory, a single-file format)."""
    PASSWORD_ARGUMENT_UNUSED = "password_argument_unused"
    """A password was passed for a format with no encryption (TAR, ISO, a directory,
    a single-file format). A password provider callable is not reported, since such a
    format never calls it."""
    SCAN_DIRECTORY_VANISHED = "scan_directory_vanished"
    """A directory opened as an archive changed while it was read: a subdirectory
    listed earlier was gone."""
    SCAN_ENTRY_VANISHED = "scan_entry_vanished"
    """A directory opened as an archive changed while it was read: an entry listed
    earlier was gone."""
    ARCHIVE_EOF_MARKER_MISSING = "archive_eof_marker_missing"
    """The record that marks the end of the archive is missing or short, such as a
    TAR's two zero blocks or a ZIP's end of central directory record. The archive may
    be truncated."""
    ARCHIVE_TRAILING_DATA = "archive_trailing_data"
    """Bytes other than zeros follow the end of the archive or of the compressed
    stream."""
    ARCHIVE_UNLISTED_DATA = "archive_unlisted_data"
    """A ZIP read from a pipe holds a member its central directory does not list. It
    is left out of the listing, as a read from a file never sees it."""
    MEMBER_TIMESTAMP_INVALID = "member_timestamp_invalid"
    """A stored timestamp could not be used, so that time is left unset."""
    MEMBER_HEADER_RECORD_SKIPPED = "member_header_record_skipped"
    """An optional record in a member's header could not be read and was dropped, so
    the field it would fill is left unset rather than wrong. RAR also reports two
    faults here that drop no record, because they too are header damage a strict
    policy should refuse: bytes in a RAR5 header that belong to no record, and a RAR5
    quick-open record holding FILE header copies that match no header the walk reached.
    The context's ``record`` tells them apart."""
    SYMLINK_TARGET_UNAVAILABLE = "symlink_target_unavailable"
    """A link's target could not be read: it is empty, too long, damaged, or needs a
    codec or package that is missing. The link stays listed with ``link_target``
    unset, and the context's ``reason`` says why."""
    DIGEST_UNVERIFIABLE = "digest_unverifiable"
    """A member's data cannot be checked against a stored checksum, so damage may go
    unnoticed."""
    MEMBER_DIRECTORY_DATA_IGNORED = "member_directory_data_ignored"
    """A directory entry declares data, which extraction does not write. The
    directory is still created."""
    MEMBER_LINK_DATA_IGNORED = "member_link_data_ignored"
    """A TAR symlink or hard link header declares data, which nothing reads. The link
    is listed and extracted as a link."""
    ENCRYPTED_MEMBER_UNVERIFIED = "encrypted_member_unverified"
    """An encrypted member's stream was closed or seeked before its checksum
    confirmed the password, and nothing stronger had confirmed it, so the bytes read
    may come from a wrong password."""
    SEEK_INDEX_DEGRADED = "seek_index_degraded"
    """Building a stream's seek index failed, was skipped or was thinned, so a seek
    may decompress more than usual."""
    STREAM_REWIND_REDECOMPRESSES = "stream_rewind_redecompresses"
    """A backward seek decompressed at least 1 MiB again from an earlier point."""
    MEMBER_SELECTOR_UNMATCHED = "member_selector_unmatched"
    """An entry of ``members=`` matched no member of the archive."""
    MEMBER_SPECIAL_FILE_HAS_DATA = "member_special_file_has_data"
    """An entry stored as a device, FIFO or socket carries data, so it is listed as a
    ``FILE`` with that data, as unzip, 7-Zip and bsdtar extract it."""
    MEMBER_LOCAL_NAME_DIFFERS = "member_local_name_differs"
    """A ZIP member's local header stores another name than its central directory
    entry. The member keeps the central directory's name, as unzip and 7-Zip read it;
    a tool that trusts the local header shows the other one."""
    MEMBER_LOCAL_METHOD_DIFFERS = "member_local_method_differs"
    """A ZIP member's local header names another compression method than its central
    directory entry. The member is decoded by the local header's method, the one a
    read from a pipe uses, and the data is still checked against its CRC-32."""
    MEMBER_LOCAL_CRC_USED = "member_local_crc_used"
    """A ZIP member's central directory entry stores CRC-32 0 and its local header
    another value, which the data is checked against. Adobe AIR writes such files."""
    ARCHIVE_OFFSET_WRAPPED = "archive_offset_wrapped"
    """A ZIP stores an offset past 4 GiB in a 32-bit field without ZIP64, as macOS
    Archive Utility does, and archivey corrected it."""
    MEMBER_SIZE_WRAPPED = "member_size_wrapped"
    """A ZIP member's stored sizes are its real sizes modulo 2³², as macOS Archive
    Utility writes a member over 4 GiB without ZIP64. archivey corrects them, or
    lists ``size`` as ``None`` until a read can tell."""
    MEMBER_TYPE_UNKNOWN = "member_type_unknown"
    """A TAR member has a typeflag archivey does not know. One that declares data is
    listed as a ``FILE``, as GNU tar extracts it; one that declares none stays
    ``OTHER``."""
    # No per-member extraction outcome has a code here. Extraction returns a structured
    # per-item report, so ``ExtractionResult`` is the sole carrier of those facts — see
    # the placement clause in ``openspec/specs/diagnostics``.


#: The string spellings of :class:`DiagnosticCode` a type checker accepts: each value, and
#: its dash form. The runtime also accepts a member's name in any case.
DiagnosticCodeStr = Literal[
    "member_name_normalized",
    "member-name-normalized",
    "member_name_encoding_inferred",
    "member-name-encoding-inferred",
    "member_name_bidi_control",
    "member-name-bidi-control",
    "member_name_zero_width_character",
    "member-name-zero-width-character",
    "member_name_invisible_character",
    "member-name-invisible-character",
    "format_extension_conflict",
    "format-extension-conflict",
    "explicit_format_listed_empty",
    "explicit-format-listed-empty",
    "extension_format_unconfirmed",
    "extension-format-unconfirmed",
    "probe_format_unconfirmed",
    "probe-format-unconfirmed",
    "empty_archive",
    "empty-archive",
    "encoding_argument_unused",
    "encoding-argument-unused",
    "password_argument_unused",
    "password-argument-unused",
    "scan_directory_vanished",
    "scan-directory-vanished",
    "scan_entry_vanished",
    "scan-entry-vanished",
    "archive_eof_marker_missing",
    "archive-eof-marker-missing",
    "archive_trailing_data",
    "archive-trailing-data",
    "archive_unlisted_data",
    "archive-unlisted-data",
    "member_timestamp_invalid",
    "member-timestamp-invalid",
    "member_header_record_skipped",
    "member-header-record-skipped",
    "symlink_target_unavailable",
    "symlink-target-unavailable",
    "digest_unverifiable",
    "digest-unverifiable",
    "encrypted_member_unverified",
    "encrypted-member-unverified",
    "seek_index_degraded",
    "seek-index-degraded",
    "stream_rewind_redecompresses",
    "stream-rewind-redecompresses",
    "member_selector_unmatched",
    "member-selector-unmatched",
    "member_special_file_has_data",
    "member-special-file-has-data",
    "member_local_name_differs",
    "member-local-name-differs",
    "member_local_method_differs",
    "member-local-method-differs",
    "member_local_crc_used",
    "member-local-crc-used",
    "member_directory_data_ignored",
    "member-directory-data-ignored",
    "member_link_data_ignored",
    "member-link-data-ignored",
    "archive_offset_wrapped",
    "archive-offset-wrapped",
    "member_size_wrapped",
    "member-size-wrapped",
    "member_type_unknown",
    "member-type-unknown",
]


@dataclass(frozen=True)
class NameNormalizationContext(_JsonSafeContext):
    """Member path rewritten for display/lookup (separators, ``.``/``..``, etc.)."""

    kind: Literal["name_normalization"] = "name_normalization"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    raw_name_base64: str | None = None
    presented_name: str = ""
    normalized_name: str = ""


@dataclass(frozen=True)
class NameEncodingContext(_JsonSafeContext):
    """Member name bytes decoded with an inferred (not declared) encoding.

    ``inferred_encoding`` decodes ``raw_name_base64`` to ``member_name``.
    ``declared_encoding`` is the encoding the name would otherwise have had: the
    caller's ``encoding=`` or the format's fallback when UTF-8 was inferred, ZIP's
    cp437 default when a configured fallback was used, and ``"utf-8"`` when a ZIP name's
    UTF-8 flag is set over bytes that are not UTF-8. Both encoding fields are empty
    when no decode of the stored bytes produced the name: ISO takes a Rock Ridge name
    that is not UTF-8 from the file's Joliet record instead.
    """

    kind: Literal["name_encoding"] = "name_encoding"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    raw_name_base64: str | None = None
    inferred_encoding: str = ""
    declared_encoding: str = ""


@dataclass(frozen=True)
class MemberNameControlsContext(_JsonSafeContext):
    """Member name or link target carries Unicode format characters a reader cannot see.

    ``category`` says which set they come from, and so which code reports them:

    - ``"bidi"`` (``MEMBER_NAME_BIDI_CONTROL``): bidi formatting controls. A caller can
      tell an *override* (U+202A–202E, U+2066–2069 — the `…gnp.exe` disguise) from a
      *directional mark* (U+061C, U+200E, U+200F, which occur in legitimate Arabic and
      Hebrew filenames) from ``controls``.
    - ``"zero_width"`` (``MEMBER_NAME_ZERO_WIDTH_CHARACTER``): zero-width space U+200B,
      word joiner U+2060 and BOM U+FEFF. They have no use inside a filename and make
      two names that display the same compare different (``invoice.pdf`` beside
      ``invoice<U+200B>.pdf``).
    - ``"invisible"`` (``MEMBER_NAME_INVISIBLE_CHARACTER``): every other character of
      Unicode category Cf, for example zero-width joiner U+200D, non-joiner U+200C,
      soft hyphen U+00AD and the tag characters. These are legitimate in some names:
      ZWJ joins emoji sequences, ZWNJ is part of Persian and Indic spelling, and tag
      characters spell subdivision flags.

    ``controls`` is the comma-joined ``U+XXXX`` spellings in the order they occur, so a
    caller can decide without re-scanning the text.

    ``field`` says which text carries them: ``"name"``, the member's name, or
    ``"link_target"``, the target a link member stores. ``member_name`` and
    ``raw_name_base64`` always identify the member.
    """

    kind: Literal["member_name_controls"] = "member_name_controls"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    raw_name_base64: str | None = None
    controls: str = ""
    field: Literal["name", "link_target"] = "name"
    category: Literal["bidi", "zero_width", "invisible"] = "bidi"


@dataclass(frozen=True)
class UnusedArgumentContext(_JsonSafeContext):
    """An explicit argument the resolved backend cannot act on, accepted anyway.

    Carries no argument *value*: the password variant must never surface candidates
    (``diagnostics`` §"No diagnostic surface SHALL contain passwords"), and the count
    would leak a little of the same thing.
    """

    kind: Literal["unused_argument"] = "unused_argument"
    archive_name: str | None = None
    argument: Literal["encoding", "password"] = "encoding"
    format: str = ""
    reason: str = ""


@dataclass(frozen=True)
class EmptyArchiveContext(_JsonSafeContext):
    """A listing completed without error and contained no members."""

    kind: Literal["empty_archive"] = "empty_archive"
    archive_name: str | None = None
    format: str = ""


@dataclass(frozen=True)
class UnconfirmedFormatContext(_JsonSafeContext):
    """A format claim the archive's bytes did not (or no longer) support.

    Two events share this context:

    * **Empty listing** (``chosen_by="argument"`` / ``"extension"``): listing finished
      with zero members under a format chosen by an override or the filename, not by
      content. ``detected_format`` is what a fresh content detection reports now —
      ``None`` when every content signal declines (the extension fallback's usual case).
    * **Extension-only decode failure** (``chosen_by="extension"``): a read of a format
      chosen by the filename alone raised. ``detected_format`` is ``None``: detection
      had declined the bytes, which is why the filename decided.
    * **Probe-only decode failure** (``chosen_by="content_probe"``): listing succeeded
      (typically one fabricated single-file member) and a later read raised. ``format``
      is the probe's claim; ``detected_format`` is the same claim restated (there is no
      separate re-detection step — the probe *was* content detection).
    """

    kind: Literal["unconfirmed_format"] = "unconfirmed_format"
    archive_name: str | None = None
    format: str = ""
    chosen_by: Literal["argument", "extension", "content_probe"] = "argument"
    detected_format: str | None = None


@dataclass(frozen=True)
class FormatConflictContext(_JsonSafeContext):
    """Extension suggested one format; content detection chose another."""

    kind: Literal["format_conflict"] = "format_conflict"
    source_name: str | None = None
    extension: str | None = None
    extension_format: str = ""
    detected_format: str = ""


@dataclass(frozen=True)
class ScanRaceContext(_JsonSafeContext):
    """Directory-archive entry vanished between listing and open (TOCTOU)."""

    kind: Literal["scan_race"] = "scan_race"
    archive_name: str | None = None
    relative_path: str = ""
    entry_kind: Literal["directory", "entry"] = "entry"


@dataclass(frozen=True)
class ArchiveEofContext(_JsonSafeContext):
    """The end of the archive did not look the way the format says it should.

    These checks share this shape, told apart by ``expected_marker``:

    - ``"two_zero_blocks"`` (``ARCHIVE_EOF_MARKER_MISSING``) — the TAR trailer itself is
      missing (``observed_kind="absent"``), short (``"short"``), or a non-null block
      where a header or the trailer belongs (``"nonzero"``). ``"nonzero"`` is always
      escalated to ``CorruptionError``: a header did not parse and the listing is
      shortened, or the file has no member and is not shown to be a TAR archive.
    - ``"second_zero_block"`` (``ARCHIVE_EOF_MARKER_MISSING``) — the first TAR trailer
      block is zero and ends the members, and the second is a full non-null block.
      Every member is listed; only the marker is damaged. ``observed_kind`` is
      ``"nonzero"`` and both byte counts are 512.
    - ``"end_of_archive_block"`` (``ARCHIVE_EOF_MARKER_MISSING``) — a RAR5 archive, or
      a volume of a RAR5 set, ends without the end-of-archive block its writers always
      put last, so the file was most likely cut at a header boundary. ``format`` is
      ``"rar"``, ``observed_kind`` is ``"absent"`` and both byte counts are 0: the
      block has no fixed size. The same marker with ``observed_kind="nonzero"``
      reports an end-of-archive block that is there but fails its header CRC; the
      members before it are all listed, ``observed_bytes`` is the offset where that
      block starts in its volume, and ``expected_bytes`` is 0. That offset counts
      from the volume's first byte, unlike member offsets, which count across the
      whole set; the message names the volume.
    - ``"end_of_central_directory"`` (``ARCHIVE_EOF_MARKER_MISSING``) — a ZIP end
      record that does not match the archive. ``observed_kind="nonzero"``: the entry
      count it declares (classic, or ZIP64 when stdlib used that record) is not the
      number of entries the central directory holds; ``observed_bytes`` is the
      record's offset and ``expected_bytes`` is 0. ``observed_kind="short"``: the
      archive comment length runs past the end of the file; ``expected_bytes`` is
      the record's declared size (22 plus the comment length) and ``observed_bytes``
      the bytes from the record to the end of the file.
    - ``"zip64_end_of_central_directory"`` (``ARCHIVE_EOF_MARKER_MISSING``) — the ZIP64
      end record a locator announces is missing or does not match it, and the classic
      end record, none of whose fields needs it, is used instead. ``observed_kind`` is
      ``"absent"``, ``observed_bytes`` is the locator's offset and ``expected_bytes``
      is 0.
    - ``"zeros_to_eof"`` (``ARCHIVE_TRAILING_DATA``) — a non-zero byte follows the
      archive's end within the first MiB past it, so the file carries something the
      listing did not account for. ``format`` names where the end was: ``"tar"`` for
      the TAR trailer (complete, or its second block damaged and reported as
      ``"second_zero_block"`` first), ``"7z"`` for the later of a 7z archive's next
      header and its last packed stream, ``"rar"`` for a RAR volume's end-of-archive
      block, ``"iso"`` for the furthest of an ISO image's volume space, the partitions
      its MBR or GPT lists and the GPT backup header, ``"zip"`` for the end of a ZIP's
      end-of-central-directory record and its declared comment. ``observed_bytes`` is
      that byte's offset past the end. RAR emits one per volume, and its offset counts from that
      volume's end block, unlike member offsets, which count across the whole set; the
      message names the volume.
    - ``"end_of_stream"`` (``ARCHIVE_TRAILING_DATA``) — a compressed stream (gzip, xz,
      zstd and the other stream codecs) decoded to its end, and bytes follow that end
      which are neither another stream nor padding the format allows. ``format`` names
      the codec and ``observed_bytes`` is the compressed offset where those bytes start.
    """

    kind: Literal["archive_eof"] = "archive_eof"
    archive_name: str | None = None
    format: str = ""
    expected_marker: str = ""
    expected_bytes: int = 0
    observed_bytes: int = 0
    observed_kind: Literal["absent", "short", "nonzero"] = "absent"


@dataclass(frozen=True)
class UnlistedDataContext(_JsonSafeContext):
    """A member's data that no entry of the archive's index points to.

    A ZIP read from a source that cannot seek finds members by their local headers,
    and learns only from the central directory, after the last one, which of them the
    archive lists. A local entry the directory does not list (an update appended
    without rewriting it, or a planted member) is dropped from the listing, as the
    seekable read never sees it. ``member_name`` and ``member_id`` are what the pass
    gave it before then; ``offset`` is where its local header starts and
    ``compressed_size`` the bytes of data after it.
    """

    kind: Literal["unlisted_data"] = "unlisted_data"
    archive_name: str | None = None
    format: str = ""
    member_name: str = ""
    member_id: int | None = None
    offset: int = 0
    compressed_size: int | None = None


@dataclass(frozen=True)
class MemberTimestampContext(_JsonSafeContext):
    """A stored timestamp field was present but unusable / out of range.

    ``source`` names the representation the value came from, such as ``"dos"``,
    ``"ntfs"``, ``"tar"`` or ISO's ``"directory_record"``. ``field`` names the
    ``ArchiveMember`` attribute the value would have filled (``"modified"``,
    ``"accessed"``, ``"created"`` or ``"ctime"``) in every format; the stored field's
    own name, such as ZIP's ``date_time`` or a PAX ``atime`` record, is in the message.
    ``value_repr`` is the stored value as text.
    """

    kind: Literal["member_timestamp"] = "member_timestamp"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    field: str = ""
    source: str = ""
    value_repr: str = ""


@dataclass(frozen=True)
class MemberHeaderRecordContext(_JsonSafeContext):
    """An optional metadata record inside a member header was unreadable.

    The record was dropped and the member listed without whatever it carried, so the
    field it would have populated is absent rather than wrong. ``record`` names the
    record as the format calls it (a RAR5 extra area's ``hash``, ``time``, ``redir``,
    ``version``; ZIP's Unicode Path extra field, ``unicode_path``, its Unicode Comment
    extra field, ``unicode_comment``, and its Unix owner extra fields, ``unix_owner``;
    ISO's Rock Ridge records, ``rock_ridge``; a TAR device header's ``device_numbers``,
    when its devmajor or devminor field is not a number); ``record_id`` is its numeric
    type where the format has one (0x7075 for ``unicode_path``, 0x6375 for
    ``unicode_comment``, the field's tag for ``unix_owner``), so an unnamed record is
    still identifiable.

    Two RAR5 ``record`` values name no dropped record, and nothing is left unset for
    them. ``"unplaced bytes"`` is bytes between a header's fixed fields and its
    declared extra area, which were skipped. ``"unmatched copies"`` is on the ``QO``
    quick-open service header, whose payload was read whole: some of its cached FILE
    header copies match no header the walk reached, which ``rar`` never writes, so the
    record is damaged or crafted. The listing comes from the headers the walk read, as
    with ``unrar``. ``reason`` says how many copies; ``record_id`` is ``None``.

    A RAR5 member header is attacker-sized, so how many records one member may drop is
    capped and reaching the cap stops the header being read; an ISO Rock Ridge entry
    list stops at its first malformed entry. ``list_truncated`` is true on the one
    diagnostic reporting either cut — it is the *record* list that was cut short, not
    the archive's listing; ``record`` names nothing on that one. Everywhere else it is
    false. ZIP never sets it: a member reports at most one ``unicode_path``, one
    ``unicode_comment`` and one ``unix_owner`` record.

    A RAR5 archive's own ``CMT`` and ``QO`` service headers carry the same records
    and are reported the same way, plus the ``QO`` header's ``"unmatched copies"``
    above, and they are not members: those diagnostics
    carry an empty ``member_name`` and a ``member_id`` of ``None``, and the message
    names the header and what the archive therefore does without. How many such
    damaged headers one archive describes is bounded, so there is one further shape:
    a single diagnostic, in the same empty-``member_name`` shape but naming no header
    and with ``list_truncated`` false, saying how many were left undescribed. The
    ``"unmatched copies"`` diagnostic is never one of those left out.
    """

    kind: Literal["member_header_record"] = "member_header_record"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    record: str = ""
    record_id: int | None = None
    reason: str = ""
    list_truncated: bool = False


@dataclass(frozen=True)
class SymlinkTargetContext(_JsonSafeContext):
    """Symlink/hardlink target could not be resolved inside the archive."""

    kind: Literal["symlink_target"] = "symlink_target"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class DigestContext(_JsonSafeContext):
    """Stored digest present but not verifiable with the available data."""

    kind: Literal["digest"] = "digest"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    algorithm: str = ""
    reason: str = ""


@dataclass(frozen=True)
class DirectoryDataContext(_JsonSafeContext):
    """A directory entry declares member data, which extraction does not write.

    ``size`` is the declared uncompressed size and ``compressed_size`` the stored
    one (``None`` where the format does not record it). The directory is still
    created. A declared size is reachable through ``open()`` / ``read()`` and the
    stream ``stream_members()`` yields for the directory, where the backend can decode
    the body (RAR delivers stored data only), except a bit-3 ZIP directory read from
    a source that cannot seek: its size arrives after its data, so the pass yields
    ``None`` for it and the message says so. A ``size`` of 0 over a non-empty body
    has nothing to read, so ``open()`` refuses it and the pass yields ``None``.
    """

    kind: Literal["directory_data"] = "directory_data"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    size: int = 0
    compressed_size: int | None = None


@dataclass(frozen=True)
class LinkDataContext(_JsonSafeContext):
    """A TAR symlink or hard link header declares data, which nothing delivers.

    ``size`` is the declared byte count. The link is listed and extracted as a link;
    the declared blocks are skipped so the members after them stay listed. Nothing
    reads them: ``open()`` on a link reads its target.
    """

    kind: Literal["link_data"] = "link_data"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    size: int = 0


@dataclass(frozen=True)
class EncryptedVerificationContext(_JsonSafeContext):
    """An encrypted member's stream closed before its digest checked the password.

    ``check`` names what accepted the password: ``"weak_open_check"`` (a per-open
    check weaker than 2⁻³², such as ZipCrypto's check byte or WinZip AES's
    ``pw_verify``), ``"confirm_budget_exhausted"`` (confirmation survived its bounded
    prefix without reaching a checksum) or ``"no_password_check"`` (the member carries
    no password check at all, as RAR3/4 data does, so nothing accepted the password
    before decoding). ``reason`` names why the digest was not reached:
    ``"partial_read"`` (closed before the end) or ``"seek"`` (a seek that jumped past
    the bytes read so far gave up a CRC; a WinZip AES HMAC survives seeks, so for an
    AES member it means only that a failed seek left the position unknown). No
    password or key material is ever carried.

    The code answers a question a member stream cannot answer for itself yet. Retire it
    when member streams report their verification state (``dev-docs/IDEAS.md``,
    "Verification state as data").
    """

    kind: Literal["encrypted_verification"] = "encrypted_verification"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    check: str = ""
    reason: str = ""


@dataclass(frozen=True)
class SeekIndexContext(_JsonSafeContext):
    """Seek index build failed, was skipped, was thinned, or was dropped.

    A failed or skipped build means the stream may redecompress on rewind. A thinned
    table (more entries than the seek-table cap) still works, with points further
    apart, so a seek may decode further than it would otherwise. An index that a decode
    proved wrong is dropped: seeks resume only from points found by decoding, and the
    size is the decoded one (a size query decodes to the end until a decode has).
    """

    kind: Literal["seek_index"] = "seek_index"
    archive_name: str | None = None
    member_name: str | None = None
    member_id: int | None = None
    codec: str = ""
    scan: str = ""
    # The failing exception's class name, "SeekTableThinned" for a thinned table, or
    # "SeekIndexContradicted" (scan "decode_check") for an index a decode proved wrong.
    error_type: str = ""


@dataclass(frozen=True)
class StreamRewindContext(_JsonSafeContext):
    """A backward seek re-decompressed from an earlier offset (no accelerator)."""

    kind: Literal["stream_rewind"] = "stream_rewind"
    archive_name: str | None = None
    member_name: str | None = None
    member_id: int | None = None
    codec: str = ""
    from_offset: int = 0
    to_offset: int = 0
    accelerator: str | None = None


@dataclass(frozen=True)
class SelectorUnmatchedContext(_JsonSafeContext):
    """One ``members=`` selector entry matched no member of the archive.

    ``entry`` is the name the caller passed (``entry_kind="name"``), or the name of
    the ``ArchiveMember`` the caller passed (``entry_kind="member"``). A member entry
    matches by identity, so it is unmatched when it came from another archive or
    another reader, or was built by hand and carries no identity.
    """

    kind: Literal["selector_unmatched"] = "selector_unmatched"
    archive_name: str | None = None
    entry: str = ""
    entry_kind: Literal["name", "member"] = "name"


@dataclass(frozen=True)
class SpecialFileDataContext(_JsonSafeContext):
    """A member whose stored type is a device, FIFO or socket carries data, so it is
    listed as a ``FILE`` (design rule DR-25).

    Info-ZIP's ``zip -FI`` stores a named pipe's content under the pipe's own FIFO mode,
    and unzip, 7-Zip, bsdtar and ``zipfile`` all write such an entry as a regular file,
    so archivey does too: the bytes are the content. ``special_file_type`` is what the
    archive called the entry (the same value as ``extra["special_file_type"]``) and
    ``size`` the bytes it stores. Advisory: nothing is hidden or misread, so it is not
    in :data:`ARCHIVE_INTEGRITY_CODES`.
    """

    kind: Literal["special_file_data"] = "special_file_data"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    special_file_type: str = ""
    size: int | None = None


@dataclass(frozen=True)
class LocalHeaderContext(_JsonSafeContext):
    """A ZIP member's local header disagrees with its central directory entry, and the
    member is read anyway.

    ``field`` says on what, and matches the code. ``"name"``
    (``MEMBER_LOCAL_NAME_DIFFERS``): the local header stores other name bytes
    (``local_raw_name_base64``), such as another code page or ``\\`` for ``/``. The
    member keeps the central directory's name, as unzip and 7-Zip read it; a tool that
    trusts the local header shows another name, so ``STRICT`` refuses the member.
    ``"method"`` (``MEMBER_LOCAL_METHOD_DIFFERS``): the local header names another
    compression method (``local_method``) than the directory (``central_method``). The
    member is decoded by the local method, which sits next to the data and is the one
    a read from a pipe uses, so a file and a pipe read the same bytes; the CRC-32 still
    checks them. A tool that trusts the directory decodes other bytes or fails, so
    ``STRICT`` refuses the member.
    ``"crc32"`` (``MEMBER_LOCAL_CRC_USED``): the central directory stores CRC-32 0 and
    the local header a non-zero value (``local_crc32``). The data is checked against
    the local value, as unzip checks it, and ``hashes`` holds it. Every Adobe AIR
    package stores ``META-INF/AIR/hash`` this way; ``STRICT`` reads it.
    """

    kind: Literal["local_header"] = "local_header"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    field: Literal["name", "method", "crc32"] = "name"
    local_raw_name_base64: str | None = None
    local_crc32: int | None = None
    local_method: int | None = None
    central_method: int | None = None


@dataclass(frozen=True)
class OffsetWrapContext(_JsonSafeContext):
    """An offset the archive stores is short of where its record is by a multiple of
    2³², because the writer stored a 32-bit field past 4 GiB without ZIP64.

    macOS Archive Utility (Finder's Compress, ``ditto -c -k``) writes such ZIPs. The
    reader adds 2³² to an offset that falls below the furthest end of the members before
    it, until it no longer does, and keeps the result only when a local header with the
    member's name starts there; the member's CRC-32 is still checked when it is read.
    ``record`` says which offset was corrected:

    - ``"local_header"`` — a central directory entry's local header offset.
      ``member_name`` and ``member_id`` name the member.
    - ``"central_directory"`` — the end record's offset of the central directory. The
      archive is reported once, with an empty ``member_name`` and a ``member_id`` of
      ``None``.

    ``stored_offset`` is the value in the archive and ``corrected_offset`` the one used,
    both counted as the format counts them (before a self-extractor stub's length is
    added).
    """

    kind: Literal["offset_wrap"] = "offset_wrap"
    archive_name: str | None = None
    format: str = ""
    member_name: str = ""
    member_id: int | None = None
    record: Literal["local_header", "central_directory"] = "local_header"
    stored_offset: int = 0
    corrected_offset: int = 0


@dataclass(frozen=True)
class SizeWrapContext(_JsonSafeContext):
    """A ZIP member's stored sizes are its real sizes modulo 2³², because the writer
    stored 32-bit fields for a member past 4 GiB without ZIP64.

    macOS Archive Utility (Finder's Compress, ``ditto -c -k``) writes such ZIPs. The
    reader corrects sizes only for an entry that carries that writer's fields (version
    made by Unix 2.1, a data descriptor, only the ``0x5855`` extra field) in an archive
    with no ZIP64 records:

    - The compressed size is measured from the layout: the member's data and data
      descriptor end where the next local header starts, or the central directory,
      and that end must be past the stored size's by a multiple of 2³².
    - A stored member's size is its compressed size. A deflated member's size is the
      stored value plus a multiple of 2³² that deflate's ratio allows (at most 1032 to
      1; nothing bounds it from below). When it allows several, the size is unknown
      until a read: ``size`` is ``None`` here and on the
      member, and ``extra["size_mod_2_32"]`` holds the stored value. A read that
      reaches the end checks the length against both, then the CRC-32, and only then
      fills in ``member.size``.

    ``stored_*`` are the values in the archive; ``compressed_size`` and ``size`` the
    ones the member carries.
    """

    kind: Literal["size_wrap"] = "size_wrap"
    archive_name: str | None = None
    format: str = ""
    member_name: str = ""
    member_id: int | None = None
    stored_compressed_size: int = 0
    compressed_size: int = 0
    stored_size: int = 0
    size: int | None = None


@dataclass(frozen=True)
class UnknownMemberTypeContext(_JsonSafeContext):
    """A TAR member header has a typeflag archivey does not know.

    POSIX reserves ``A`` to ``Z`` for vendors and leaves the rest undefined; GNU tar
    extracts any typeflag it does not know as a regular file and warns ("Unknown file
    type"). A header that declares data is listed as a ``FILE`` of that ``size``,
    readable and extracted (design rule DR-25); one that declares none stays ``OTHER``.
    ``stored_type`` is the typeflag byte as a one-character string (the byte as
    Latin-1), the same byte as ``extra["tar.type"]``; ``size`` is the member's
    ``size``, ``None`` for an ``OTHER`` member. Advisory: the bytes are delivered and
    nothing is hidden, so it is not in :data:`ARCHIVE_INTEGRITY_CODES`.
    """

    kind: Literal["unknown_member_type"] = "unknown_member_type"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    stored_type: str = ""
    size: int | None = None


DiagnosticContext = (
    NameNormalizationContext
    | NameEncodingContext
    | MemberNameControlsContext
    | UnusedArgumentContext
    | EmptyArchiveContext
    | UnconfirmedFormatContext
    | FormatConflictContext
    | ScanRaceContext
    | ArchiveEofContext
    | UnlistedDataContext
    | MemberTimestampContext
    | MemberHeaderRecordContext
    | SymlinkTargetContext
    | DigestContext
    | DirectoryDataContext
    | LinkDataContext
    | EncryptedVerificationContext
    | SeekIndexContext
    | StreamRewindContext
    | SelectorUnmatchedContext
    | SpecialFileDataContext
    | LocalHeaderContext
    | OffsetWrapContext
    | SizeWrapContext
    | UnknownMemberTypeContext
)

_CODE_CONTEXT_KINDS: Mapping[DiagnosticCode, str] = MappingProxyType(
    {
        DiagnosticCode.MEMBER_NAME_NORMALIZED: "name_normalization",
        DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED: "name_encoding",
        DiagnosticCode.MEMBER_NAME_BIDI_CONTROL: "member_name_controls",
        DiagnosticCode.MEMBER_NAME_ZERO_WIDTH_CHARACTER: "member_name_controls",
        DiagnosticCode.MEMBER_NAME_INVISIBLE_CHARACTER: "member_name_controls",
        DiagnosticCode.FORMAT_EXTENSION_CONFLICT: "format_conflict",
        DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY: "unconfirmed_format",
        DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED: "unconfirmed_format",
        DiagnosticCode.PROBE_FORMAT_UNCONFIRMED: "unconfirmed_format",
        DiagnosticCode.EMPTY_ARCHIVE: "empty_archive",
        DiagnosticCode.ENCODING_ARGUMENT_UNUSED: "unused_argument",
        DiagnosticCode.PASSWORD_ARGUMENT_UNUSED: "unused_argument",
        DiagnosticCode.SCAN_DIRECTORY_VANISHED: "scan_race",
        DiagnosticCode.SCAN_ENTRY_VANISHED: "scan_race",
        DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING: "archive_eof",
        DiagnosticCode.ARCHIVE_TRAILING_DATA: "archive_eof",
        DiagnosticCode.ARCHIVE_UNLISTED_DATA: "unlisted_data",
        DiagnosticCode.MEMBER_TIMESTAMP_INVALID: "member_timestamp",
        DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED: "member_header_record",
        DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE: "symlink_target",
        DiagnosticCode.DIGEST_UNVERIFIABLE: "digest",
        DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED: "directory_data",
        DiagnosticCode.MEMBER_LINK_DATA_IGNORED: "link_data",
        DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED: "encrypted_verification",
        DiagnosticCode.SEEK_INDEX_DEGRADED: "seek_index",
        DiagnosticCode.STREAM_REWIND_REDECOMPRESSES: "stream_rewind",
        DiagnosticCode.MEMBER_SELECTOR_UNMATCHED: "selector_unmatched",
        DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA: "special_file_data",
        DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS: "local_header",
        DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS: "local_header",
        DiagnosticCode.MEMBER_LOCAL_CRC_USED: "local_header",
        DiagnosticCode.ARCHIVE_OFFSET_WRAPPED: "offset_wrap",
        DiagnosticCode.MEMBER_SIZE_WRAPPED: "size_wrap",
        DiagnosticCode.MEMBER_TYPE_UNKNOWN: "unknown_member_type",
    }
)


ARCHIVE_INTEGRITY_CODES: frozenset[DiagnosticCode] = frozenset(
    {
        DiagnosticCode.MEMBER_NAME_NORMALIZED,
        DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED,
        DiagnosticCode.MEMBER_NAME_BIDI_CONTROL,
        DiagnosticCode.MEMBER_NAME_ZERO_WIDTH_CHARACTER,
        DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED,
        DiagnosticCode.SCAN_DIRECTORY_VANISHED,
        DiagnosticCode.SCAN_ENTRY_VANISHED,
        DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
        DiagnosticCode.ARCHIVE_TRAILING_DATA,
        DiagnosticCode.ARCHIVE_UNLISTED_DATA,
        DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
        DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
        DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE,
        DiagnosticCode.DIGEST_UNVERIFIABLE,
        DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED,
        DiagnosticCode.MEMBER_LINK_DATA_IGNORED,
        DiagnosticCode.SEEK_INDEX_DEGRADED,
        DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS,
        DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS,
    }
)
"""Codes reporting the archive's own bytes or metadata as anomalous.

The ``raise_on`` set of ``DiagnosticPolicy.STRICT``. Fifteen codes are deliberately **out**,
and the reasons are part of the contract rather than an oversight:

- ``EMPTY_ARCHIVE`` — an empty archive is legitimate, and ``diagnostics`` forbids
  treating zero members as an error.
- ``ENCODING_ARGUMENT_UNUSED`` / ``PASSWORD_ARGUMENT_UNUSED`` — argument hygiene. A
  pipeline that speculatively passes a password to every call would otherwise raise on
  every unencrypted archive.
- ``EXPLICIT_FORMAT_LISTED_EMPTY`` — ``format=`` is an override, and an override that
  halts the caller is not an override.
- ``STREAM_REWIND_REDECOMPRESSES`` — reports the caller's access pattern rather than the
  archive, and is most useful as a deliberately targeted tripwire.
- ``ENCRYPTED_MEMBER_UNVERIFIED`` — fires only when the caller abandons a member stream
  before EOF (extraction reads every member to EOF and never fires it). In ``STRICT`` it
  would turn a peek at a ZipCrypto or RAR3/4 encrypted member into
  ``DiagnosticRaisedError``. Revisit when member streams report their verification
  state (``dev-docs/IDEAS.md``, "Verification state as data") and retire this code.
- ``PROBE_FORMAT_UNCONFIRMED`` — a probe-only identification is an advisory about
  what the file *is* (its bytes passed that format's content check), not a finding
  about the archive's own bytes, and it only accompanies a read that already failed
  with a typed error that carries ``format_unconfirmed=True``. A policy that resolves
  it to RAISE still gets that typed error, through ``escalate_as``. Its sibling
  ``EXTENSION_FORMAT_UNCONFIRMED`` is **in** the set: it also fires on an
  extension-only empty listing, a successful open that no byte confirmed.
- ``MEMBER_SELECTOR_UNMATCHED`` — reports the caller's ``members=`` argument, not the
  archive. A job that passes one fixed list of names to many archives would otherwise
  raise on every archive that lacks one of them.
- ``MEMBER_SPECIAL_FILE_HAS_DATA`` — a documented writer option (Info-ZIP ``zip -FI``)
  produces the shape, and the member's bytes are delivered and checked like any file's,
  so nothing is hidden; ``STRICT`` would refuse an ordinary archive (DR-25).
- ``MEMBER_NAME_INVISIBLE_CHARACTER`` — zero-width joiners are part of ordinary emoji
  sequences, non-joiners of Persian and Indic spelling, and tag characters of
  subdivision flags. ``STRICT`` would refuse an archive of legitimately named files.
  Its sibling ``MEMBER_NAME_ZERO_WIDTH_CHARACTER`` is **in** the set: U+200B, U+2060
  and U+FEFF have no use inside a filename.
- ``FORMAT_EXTENSION_CONFLICT`` — reports the file's name, not its bytes: the bytes
  win and the archive reads in full. A tarball saved as ``b.gz`` is an ordinary mistake,
  and ``STRICT`` would refuse a well-formed archive over it. The code is still recorded.
- ``MEMBER_LOCAL_CRC_USED`` — a common packager (Adobe AIR) writes the shape, and the
  data is still checked, against the local header's CRC-32, so nothing is left
  unverified. Its siblings ``MEMBER_LOCAL_NAME_DIFFERS`` and
  ``MEMBER_LOCAL_METHOD_DIFFERS`` are **in** the set: there a tool that trusts the
  other header shows the member under another name, or decodes other bytes.
- ``ARCHIVE_OFFSET_WRAPPED`` — macOS Archive Utility (Finder's Compress) writes a ZIP
  past 4 GiB this way by default and reads it back, and a correction is kept only when
  a local header with the member's name is there, with the CRC-32 still checked.
  ``STRICT`` would refuse an ordinary Mac archive.
- ``MEMBER_SIZE_WRAPPED`` — the same Mac archives: a member past 4 GiB, or a deflated
  one over about 4 MB compressed in an archive of any length, whose size only a read
  can tell. A size is corrected only where the layout or deflate's ratio forces it,
  and an unknown one is ``None``, with the length and CRC-32 checked on a read.
  ``STRICT`` would refuse ordinary Mac archives.
- ``MEMBER_TYPE_UNKNOWN`` — a TAR typeflag archivey does not know. GNU tar extracts
  such a member as a regular file with a warning, and archivey lists its data as a
  ``FILE``, so nothing is hidden. ``STRICT`` would refuse an archive GNU tar extracts.
"""


_INFO_LOG_CODES: frozenset[DiagnosticCode] = frozenset(
    {DiagnosticCode.STREAM_REWIND_REDECOMPRESSES}
)
"""Codes whose log record is INFO rather than WARNING (``logging`` spec).

They report the caller's access pattern, not the archive: the reason
``STREAM_REWIND_REDECOMPRESSES`` is out of :data:`ARCHIVE_INTEGRITY_CODES` too, and the
reason the solid re-decode record on ``archivey.backends`` is INFO (maintainer,
2026-10-23). The policy still collects, counts and raises them like any other code.
"""


# Codes that share a context kind with another code, and the context field that tells
# them apart. The kind alone cannot reject a mismatched pairing for these, so
# ``validate_code_context`` checks the field too. A code added to a shared kind needs a
# row here; ``test_every_shared_kind_code_has_a_discriminator`` fails until it has one.
# A code may accept several values of its field (``ARCHIVE_TRAILING_DATA`` is reported
# after a TAR trailer and after a compressed stream's end); the sets never overlap, so
# the field still tells the codes apart.
_SHARED_KIND_DISCRIMINATORS: Mapping[DiagnosticCode, tuple[str, frozenset[str]]] = (
    MappingProxyType(
        {
            DiagnosticCode.MEMBER_NAME_BIDI_CONTROL: (
                "category",
                frozenset({"bidi"}),
            ),
            DiagnosticCode.MEMBER_NAME_ZERO_WIDTH_CHARACTER: (
                "category",
                frozenset({"zero_width"}),
            ),
            DiagnosticCode.MEMBER_NAME_INVISIBLE_CHARACTER: (
                "category",
                frozenset({"invisible"}),
            ),
            DiagnosticCode.SCAN_DIRECTORY_VANISHED: (
                "entry_kind",
                frozenset({"directory"}),
            ),
            DiagnosticCode.SCAN_ENTRY_VANISHED: ("entry_kind", frozenset({"entry"})),
            DiagnosticCode.ENCODING_ARGUMENT_UNUSED: (
                "argument",
                frozenset({"encoding"}),
            ),
            DiagnosticCode.PASSWORD_ARGUMENT_UNUSED: (
                "argument",
                frozenset({"password"}),
            ),
            DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY: (
                "chosen_by",
                frozenset({"argument"}),
            ),
            DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED: (
                "chosen_by",
                frozenset({"extension"}),
            ),
            DiagnosticCode.PROBE_FORMAT_UNCONFIRMED: (
                "chosen_by",
                frozenset({"content_probe"}),
            ),
            DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING: (
                "expected_marker",
                frozenset(
                    {
                        "two_zero_blocks",
                        "second_zero_block",
                        "end_of_archive_block",
                        "end_of_central_directory",
                        "zip64_end_of_central_directory",
                    }
                ),
            ),
            DiagnosticCode.ARCHIVE_TRAILING_DATA: (
                "expected_marker",
                frozenset({"zeros_to_eof", "end_of_stream"}),
            ),
            DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS: ("field", frozenset({"name"})),
            DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS: (
                "field",
                frozenset({"method"}),
            ),
            DiagnosticCode.MEMBER_LOCAL_CRC_USED: ("field", frozenset({"crc32"})),
        }
    )
)


def validate_code_context(code: DiagnosticCode, context: DiagnosticContext) -> None:
    """Reject unregistered or mismatched code→context pairings.

    Most codes map 1:1 onto a context ``kind`` via ``_CODE_CONTEXT_KINDS``. Codes that
    share a kind (``member_name_controls``, ``scan_race``, ``unused_argument``,
    ``unconfirmed_format``, ``archive_eof``, ``local_header``) are told apart by one
    context field, and every one of them is checked against the value its code
    requires.
    """
    expected = _CODE_CONTEXT_KINDS.get(code)
    if expected is None:
        raise ValueError(f"Unknown diagnostic code: {code!r}")
    if context.kind != expected:
        raise ValueError(
            f"Diagnostic code {code.value!r} requires context kind {expected!r}, "
            f"got {context.kind!r}"
        )
    discriminator = _SHARED_KIND_DISCRIMINATORS.get(code)
    if discriminator is not None:
        field_name, allowed = discriminator
        actual = getattr(context, field_name, None)
        if actual not in allowed:
            required = " or ".join(repr(value) for value in sorted(allowed))
            raise ValueError(
                f"{code.name} requires {field_name}={required}, got {actual!r}"
            )


@dataclass(frozen=True)
class Diagnostic:
    """One immutable advisory occurrence: something archivey noticed and reported
    instead of raising.

    ``message`` and ``context`` carry the same facts for different readers.
    ``message`` is display text, and its control characters are escaped: it includes
    names from the archive, and a name carrying ``\\x1b[2K\\r`` could otherwise
    erase the terminal line reporting it and write something else in its place.
    ``context`` keeps the raw values, for matching on a name or for a structured log
    (see :meth:`to_dict`). :class:`~archivey.ArchiveyError` escapes its ``message``
    and keeps ``member_name`` raw for the same reason.
    """

    # Escaping here rather than trusting the sites that build messages: every one of
    # them today interpolates through terminal.quoted or !r, so the text would be inert
    # either way, but that is a property of the current call sites, not of the type. A
    # future message written as f"...{name}" would pass review looking exactly like its
    # neighbours while emitting raw control bytes, and only for a hostile archive.
    #
    # Escaping runs in __post_init__: on a frozen dataclass that is the hook that covers
    # every construction path. Nothing reconstructs a Diagnostic with
    # dataclasses.replace, which would escape a second time.

    occurrence_id: str
    """A random id, unique to this occurrence."""

    code: DiagnosticCode
    """What kind of event this is."""

    message: str
    """A sentence describing the event, with control characters escaped."""

    context: DiagnosticContext
    """The event's details as typed fields with raw values, such as the archive and
    member names. Its ``kind`` field says which context class it is."""

    def __post_init__(self) -> None:
        # frozen dataclass — the escape has to go in through the back door.
        object.__setattr__(self, "message", escape_control_chars(self.message))

    def to_dict(self) -> dict[str, object]:
        return {
            "occurrence_id": self.occurrence_id,
            "code": self.code.value,
            "message": self.message,
            "context": self.context.to_dict(),
        }


@dataclass(frozen=True)
class DiagnosticSummary:
    """Immutable point-in-time snapshot of diagnostic counts and retained detail."""

    total_count: int
    """Every diagnostic emitted in the summary's scope, ignored ones included."""

    counts: Mapping[DiagnosticCode, int] = field(
        default_factory=lambda: MappingProxyType({})
    )
    """The exact count for each code, ignored ones included."""

    retained: tuple[Diagnostic, ...] = ()
    """The diagnostics kept in full, in the order they were emitted. Ignored codes are
    not kept, and nor is anything past the
    ``ArchiveyConfig.max_retained_diagnostic_references`` budget."""

    dropped_count: int = 0
    """How many of ``total_count`` are not in ``retained``."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "counts", _freeze_mapping(self.counts))

    @staticmethod
    def empty() -> DiagnosticSummary:
        return DiagnosticSummary(total_count=0, counts={}, retained=(), dropped_count=0)


def _coerce_policy_codes(
    value: object, *, call: str, param: str
) -> frozenset[DiagnosticCode]:
    """One ``DiagnosticPolicy`` code set, refusing the two shapes that iterate wrongly."""
    if isinstance(value, Mapping):
        # A dict iterates as its keys, so the removed overrides={code: disposition}
        # spelling would pass and drop every disposition: under ignore= a code the
        # caller wanted raised would be silenced.
        raise _UsageTypeError(
            f"{call} takes a set of DiagnosticCode for {param}, not a mapping. Put the "
            "codes to raise on in raise_on= and the codes to ignore in ignore=."
        )
    if isinstance(value, DiagnosticCode):
        # A StrEnum member is a str, so the shared helper would call it a bare string.
        raise _UsageTypeError(
            f"{call} takes a set of DiagnosticCode for {param}, but got the single "
            f"code DiagnosticCode.{value.name}. Pass a set, e.g. "
            f"{{DiagnosticCode.{value.name}}}."
        )
    return coerce_enum_collection(value, DiagnosticCode, call=call, param=param)


@dataclass(frozen=True, init=False)
class DiagnosticPolicy:
    """Which diagnostic codes to ignore and which to raise; every other code is collected.

    Matching is by code only. Both arguments take any iterable of :class:`DiagnosticCode`
    (or their values as strings), and the fields always hold a ``frozenset``; a code in
    both is refused. A policy is built with set operations on the code sets, for example
    ``DiagnosticPolicy(raise_on=ARCHIVE_INTEGRITY_CODES - {DiagnosticCode.X})``.

    Two ready-made instances:

    - ``DiagnosticPolicy.STRICT`` is ``DiagnosticPolicy(raise_on=ARCHIVE_INTEGRITY_CODES)``:
      RAISE on the codes about the archive's own bytes, COLLECT on everything else. It is
      the recommended strict mode because it is version-stable in the way that matters:
      a patch release may add new codes but adds none to ``ARCHIVE_INTEGRITY_CODES``,
      unless the new code reports damage archivey should already have caught. A minor
      release may add to the set, and each addition is a deliberate decision.
    - ``DiagnosticPolicy.PEDANTIC`` is ``DiagnosticPolicy(raise_on=frozenset(DiagnosticCode))``:
      RAISE on every code, including the argument-hygiene and access-pattern ones.
      ``frozenset(DiagnosticCode)`` is every code of the installed version, so it raises
      on codes added after the caller wrote it.
    """

    STRICT: ClassVar[DiagnosticPolicy]
    PEDANTIC: ClassVar[DiagnosticPolicy]

    ignore: frozenset[DiagnosticCode]
    """Codes that are counted but not kept, logged or passed to ``on_diagnostic``."""

    raise_on: frozenset[DiagnosticCode]
    """Codes that raise :class:`~archivey.DiagnosticRaisedError` once recorded."""

    # A hand-written __init__ (the decorator has init=False) so the parameters can
    # describe what a caller passes while the fields describe what every reader gets
    # back: always a frozenset of members, so set operations work on them.
    def __init__(
        self,
        *,
        ignore: Iterable[DiagnosticCode | DiagnosticCodeStr] | None = None,
        raise_on: Iterable[DiagnosticCode | DiagnosticCodeStr] | None = None,
    ) -> None:
        # Converted, not only checked: the collector and the reader answer by membership
        # in these sets, so a code spelled as its name would be stored and never match.
        call = "DiagnosticPolicy()"
        ignore_parsed = _coerce_policy_codes(ignore, call=call, param="ignore=")
        raise_on_parsed = _coerce_policy_codes(raise_on, call=call, param="raise_on=")
        both = ignore_parsed & raise_on_parsed
        if both:
            # Keyword arguments have no order, so neither can win: keeping either would
            # silently drop what the other asked for.
            names = ", ".join(sorted(code.value for code in both))
            raise _UsageValueError(
                f"{call} got codes in both ignore= and raise_on=: {names}."
            )
        object.__setattr__(self, "ignore", ignore_parsed)
        object.__setattr__(self, "raise_on", raise_on_parsed)


DiagnosticPolicy.STRICT = DiagnosticPolicy(raise_on=ARCHIVE_INTEGRITY_CODES)
DiagnosticPolicy.PEDANTIC = DiagnosticPolicy(raise_on=frozenset(DiagnosticCode))


@dataclass(frozen=True)
class ExtractionReport:
    """Immutable extraction outcome: fixed result tuple plus diagnostic summary.

    ``results`` is a frozen outcome structure. Each :class:`ExtractionResult` is frozen,
    but ``ExtractionResult.member`` refers to the live mutable :class:`ArchiveMember`
    (caller-read-only), whose late-bound metadata and member diagnostics may still be
    filled in place.

    The report iterates, indexes, and sizes as its ``results`` sequence, so the common
    ``for result in reader.extract_all(...)`` / ``len(...)`` / ``report[0]`` idioms keep
    working while ``report.diagnostics`` exposes the call's diagnostic summary. It covers
    that :meth:`ForwardArchiveReader.extract_all` call only; detection and open
    diagnostics stay on ``reader.diagnostics``.
    """

    results: tuple[ExtractionResult, ...]
    """One result per member processed, in the order they were processed."""

    diagnostics: DiagnosticSummary
    """The diagnostics emitted during this ``extract_all()`` call."""

    # A dry run's top-level entries, as (name, is a directory), read from its scratch
    # tree before removing it: what a real run would leave directly under ``dest``.
    # Private, for the CLI's hoist prediction; ``None`` after a real run.
    _dry_run_top_level: tuple[tuple[str, bool], ...] | None = field(
        default=None, repr=False, compare=False
    )
    # A dry run's symlinks, as (path under ``dest`` with ``/`` separators, target),
    # read from the same scratch tree when it held a single top-level entry. ``None``
    # with a single top-level entry means part of the tree could not be read. Private,
    # for the same prediction: the CLI walks them as its hoist walks a real tree.
    _dry_run_links: tuple[tuple[str, str], ...] | None = field(
        default=None, repr=False, compare=False
    )
    # Every entry of the same scratch tree, as (path under ``dest`` with ``/``
    # separators, is a directory and not a symlink), recorded with ``_dry_run_links``
    # and ``None`` when it is. Private, for the same prediction: the CLI checks the
    # hoist's merge against them as its hoist checks a real tree.
    _dry_run_entries: tuple[tuple[str, bool], ...] | None = field(
        default=None, repr=False, compare=False
    )
    # How close the reader came to each reader-lifetime limit, taken when the call
    # ended. Private, for the backup-scan script and ``archivey extract --dry-run``:
    # ``extract_all()`` (the function) closes its reader, so the report is where a
    # caller of it can read the numbers. Public later, if a corpus scan shows which
    # numbers are worth keeping.
    _resource_usage: ResourceUsage | None = field(
        default=None, repr=False, compare=False
    )

    def __iter__(self) -> Iterator[ExtractionResult]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __getitem__(self, index: int) -> ExtractionResult:
        return self.results[index]


@dataclass(frozen=True)
class MemberListReport:
    """Immutable member-list outcome: recovered members plus listing honesty.

    ``error is None`` means ``members`` is a complete archive listing. A non-``None``
    error means the tuple is the recovered prefix and the error is the terminal
    archive-level damage that stopped listing.

    Like :class:`ExtractionReport`, the report iterates, indexes, and sizes as its
    primary sequence so common ``for member in report`` / ``len(report)`` idioms work.
    """

    members: tuple[ArchiveMember, ...]
    """The members listed, all of them when ``error`` is ``None``."""

    error: ArchiveyError | None
    """The damage that stopped the listing, or ``None`` when it completed."""

    diagnostics: DiagnosticSummary
    """The diagnostics emitted while listing."""

    def __iter__(self) -> Iterator[ArchiveMember]:
        return iter(self.members)

    def __len__(self) -> int:
        return len(self.members)

    def __getitem__(self, index: int) -> ArchiveMember:
        return self.members[index]


OnDiagnostic = Callable[[Diagnostic], None]
"""Optional synchronous callback invoked for COLLECT/RAISE diagnostics."""


def raw_name_to_base64(raw_name: bytes | None) -> str | None:
    """Encode raw archive name bytes for a JSON-safe diagnostic context field."""
    if raw_name is None:
        return None
    return base64.b64encode(raw_name).decode("ascii")


def format_path_name(path: str | Path | None) -> str | None:
    """Stringify a source path for diagnostic context without retaining Path objects."""
    if path is None:
        return None
    return str(path)


__all__ = [
    "ARCHIVE_INTEGRITY_CODES",
    "ArchiveEofContext",
    "Diagnostic",
    "DiagnosticCode",
    "DiagnosticCodeStr",
    "DiagnosticContext",
    "DiagnosticPolicy",
    "DiagnosticSummary",
    "DigestContext",
    "DirectoryDataContext",
    "EmptyArchiveContext",
    "EncryptedVerificationContext",
    "ExtractionReport",
    "FormatConflictContext",
    "LinkDataContext",
    "LocalHeaderContext",
    "MemberHeaderRecordContext",
    "MemberListReport",
    "MemberNameControlsContext",
    "MemberTimestampContext",
    "NameEncodingContext",
    "NameNormalizationContext",
    "OffsetWrapContext",
    "OnDiagnostic",
    "ScanRaceContext",
    "SeekIndexContext",
    "SelectorUnmatchedContext",
    "SizeWrapContext",
    "SpecialFileDataContext",
    "StreamRewindContext",
    "SymlinkTargetContext",
    "UnconfirmedFormatContext",
    "UnknownMemberTypeContext",
    "UnlistedDataContext",
    "UnusedArgumentContext",
    "format_path_name",
    "raw_name_to_base64",
    "validate_code_context",
]
