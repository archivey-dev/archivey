"""ZIP backend on the v2 ABC.

Layout this code assumes::

    [ local file header + payload ]*   # PK\\x03\\x04 … name | extra | [data]
    [ central directory ]              # walked lazily as members are listed (INDEXED)
    [ EOCD (+ optional ZIP64) ]        # at EOF: this reader seeks to it

A source that cannot seek is read front to back by ``zip_forward_reader`` instead.

Who does what:

- ``zip_parser`` — the end record, the central directory walk and the local header, as
  plain data. This module builds members from it and owns the handle and its lock.
- Member **data** — slice the local payload, decrypt it if encrypted, and decode via the
  shared codec layer (never ``ZipExtFile``), so accelerators / rewind warnings / CRC
  verification stay uniform.
- Decrypt stages: ZipCrypto (``internal.backends.zipcrypto``, weak 1-byte check) and
  WinZip AES (method 99, ``internal.backends.zip_aes``, real method from extra field
  ``0x9901``). One password ladder for both: a bounded confirm per candidate when
  several are possible (a shared CRC pass for STORED ZipCrypto).
- PKWARE Strong Encryption — refused (``UnsupportedFeatureError``).

Multi-volume sets:

- 7-Zip ``.zip.NNN`` split sets are byte slices of one ordinary ZIP. ``open_archive``
  joins the parts before this backend sees them (``source.volume_count > 1``).
- A lone ``.zip.NNN`` segment whose sibling parts are missing is an incomplete set,
  not a spanned one: ``open_archive`` raises ``TruncatedError`` naming the missing
  parts. The ``UnsupportedFeatureError`` in ``ZipReader.__init__`` is only the
  backstop for a segment that did not pass through that check.
- Spanned sets are rejected with ``UnsupportedFeatureError``; rejoin them with the
  tool that made them (see ``format-zip``): Info-ZIP ``.zNN`` / final ``.zip`` (EOCD
  disk fields) and ZIP64 locator ``disks > 1``.
"""

from __future__ import annotations

import io
import lzma
import stat
import struct
import threading
import zlib
from array import array
from bisect import bisect_right
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from functools import lru_cache
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Literal,
    NamedTuple,
    NoReturn,
    TypeVar,
    cast,
)

from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.cost import (
    AccessCost,
    CostReceipt,
    ListingCost,
    StreamCapability,
)
from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    DigestContext,
    LocalHeaderContext,
    MemberHeaderRecordContext,
    OffsetWrapContext,
    SizeWrapContext,
    raw_name_to_base64,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    EncryptionError,
    ResourceLimitError,
    ResourceUnavailableError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
    exception_detail,
    raw_message_of,
)
from archivey.internal.backends.zip_aes import (
    ZIP_WRONG_PASSWORD_MSG,
    ExtraField,
    WinZipAesInfo,
    aes_record_differences,
    iter_extra_fields,
    local_first,
    open_winzip_aes_member,
    parse_winzip_aes_extra,
    split_extra_fields,
)
from archivey.internal.backends.zip_detect import (
    LOCAL_HEADER_SIGNATURE,
    ZIP_MULTI_VOLUME_MSG,
    is_zip_split_segment_name,
    validate_zip_local_header,
)
from archivey.internal.backends.zip_local_walk import (
    DataDescriptor,
    LocalEntry,
    LocalHeaderWalk,
    local_entry_at,
    missing_end_record_error,
)
from archivey.internal.backends.zip_parser import (
    CENTRAL_HEADER_SIZE,
    EOCD_SIZE,
    MAX_DATA_OFFSET,
    NO_END_RECORD_MSG,
    OFFSET_WRAP,
    ZIP64_LOCATOR_SIZE,
    CentralDirectoryWalk,
    CentralEntry,
    DirectoryOffsetWrapped,
    EndRecord,
    EntryCountMismatch,
    LocalHeader,
    WalkFinding,
    local_header_at,
    locate_end_record,
    read_end_record,
    read_local_header,
    written_by_archive_utility,
)
from archivey.internal.backends.zipcrypto import (
    ZIPCRYPTO_HEADER_LEN,
    ZipCryptoDecryptStream,
    keys_after_header,
    parallel_plaintext_crc32,
    password_matches_check_byte,
)
from archivey.internal.base_reader import BaseArchiveReader, ReadBackend
from archivey.internal.config import StreamConfig, stream_config_from_archivey
from archivey.internal.dataclass_copy import copy_with
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.file_copy_pass import DEFAULT_FILE_COPY_PASS, FileCopyPass
from archivey.internal.hashing import crc32_digest
from archivey.internal.logs import backends as logger
from archivey.internal.naming import (
    emit_member_name_normalized,
    normalize_member_name,
)
from archivey.internal.open_site import OpenSite
from archivey.internal.password import (
    _PasswordCandidates,
    _PasswordCandidatesExhausted,
    unverified_data_error,
    wrong_password_error,
)
from archivey.internal.password_confirm import (
    PASSWORD_CONFIRM_MIN_VERIFIED_BYTES,
    PASSWORD_CONFIRM_PREFIX_BYTES,
    REJECTING_CODECS,
    PasswordConfirmPlan,
    PasswordConfirmVerdict,
    attempt_with_confirm,
    first_crc_match,
    plan_password_confirm,
    run_password_confirm_plan,
)
from archivey.internal.registry import register_reader
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import (
    ArchiveStreamImpl,
    ExceptionTranslator,
    MemberStreamParts,
    RewindWarning,
)
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    decode_lzma_filter_properties,
    open_codec_raw,
    open_codec_stream,
)
from archivey.internal.streams.streamtools import (
    DelegatingStream,
    SharedView,
    SlicingStream,
    is_seekable,
    read_exact,
    source_byte_size,
)
from archivey.internal.streams.verify import VerifyingStream, ask_digest_intact
from archivey.internal.timestamps import (
    TimestampIssue,
    filetime_to_datetime,
    unix32_to_datetime,
)
from archivey.internal.trailing_scan import first_nonzero_offset
from archivey.internal.unix_mode import special_file_type
from archivey.internal.windows_reparse import FILE_ATTRIBUTE_REPARSE_POINT
from archivey.terminal import quoted
from archivey.types import (
    EXTRA_ALTERNATE_RAW_NAME,
    EXTRA_IS_REPARSE_POINT,
    EXTRA_SIZE_MOD_2_32,
    EXTRA_SPECIAL_FILE_TYPE,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    CreateSystem,
    HashAlgorithm,
    MagicSignature,
    MemberExtra,
    MemberStreams,
    MemberType,
)

_new_tuple = tuple.__new__

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from _typeshed import WriteableBuffer

    from archivey.internal.streams.streamtools import ReadableStream

# Decoding of a comment under a set UTF-8 flag its name's bytes do not refute: UTF-8,
# else cp437 (the ZIP appnote default, which maps every byte and therefore never fails).
# An unflagged comment, and one whose name was decoded as unflagged because the bytes
# refute the flag, go through `_decode_unflagged_comment`, which shares the `encoding=`
# / fallback step (`_decode_unflagged_legacy`) with the unflagged-name sniff.
_ZIP_ENCODINGS = ("utf-8", "cp437")

# ZIP general-purpose bit 3: data descriptor follows the member; verification byte is
# then the high byte of the DOS time rather than of the CRC-32.
_ZIP_MASK_USE_DATA_DESCRIPTOR = 0x8
# ZIP general-purpose bit 11: the name and comment are UTF-8.
_ZIP_MASK_UTF8 = 0x800

# ZIP general-purpose bit 0: the member is encrypted.
_ZIP_MASK_ENCRYPTED = 0x1
# ZIP general-purpose bit 1 on an LZMA (method 14) member: the stream ends with an
# end-of-stream marker. When it is clear there is no marker, and APPNOTE 4.4.4 says the
# decoder stops at the declared uncompressed size.
_ZIP_MASK_LZMA_EOS_MARKER = 0x2
# ZIP general-purpose bit 5: the body is PKWARE "compressed patched data", a patch
# against some other file rather than the file itself. Nothing implements it; stdlib
# zipfile refuses it too.
_ZIP_MASK_COMPRESSED_PATCHED_DATA = 0x20
# PKWARE Strong Encryption (APPNOTE §7): general-purpose bit 6 on an encrypted member
# (bit 0 is set with it), with the algorithm in extra field 0x0017. Either marks the
# member; archivey does not implement the algorithm.
_ZIP_MASK_STRONG_ENCRYPTION = 0x40
_ZIP_EXTRA_STRONG_ENCRYPTION = 0x0017
# Info-ZIP Unicode Path extra field: the name as UTF-8, tied to the header's name bytes
# by their CRC-32 (`_unicode_path_name`).
_ZIP_EXTRA_UNICODE_PATH = 0x7075
# Info-ZIP Unicode Comment extra field: a member comment as UTF-8, tied to the
# header's comment bytes by their CRC-32 (`_unicode_comment_text`).
_ZIP_EXTRA_UNICODE_COMMENT = 0x6375
_STRONG_ENCRYPTION_MSG = (
    "PKWARE Strong Encryption is not supported (only ZipCrypto and WinZip AES are)"
)

# ZIP compression-method id -> our codec algorithm. Unknown ids map to UNKNOWN rather than
# raising, matching the open-ended CompressionAlgorithm contract.
_ZIP_COMPRESSION_ALGOS: dict[int, CompressionAlgorithm] = {
    0: CompressionAlgorithm.STORED,
    8: CompressionAlgorithm.DEFLATE,
    9: CompressionAlgorithm.DEFLATE64,
    12: CompressionAlgorithm.BZIP2,
    14: CompressionAlgorithm.LZMA,
    93: CompressionAlgorithm.ZSTD,
    98: CompressionAlgorithm.PPMD,
}

# Shared compression tuples for the common ZIP methods — avoid per-member
# CompressionMethod construction on the open+list hot path (perf review H3/Q1).
_ZIP_COMPRESSION_TUPLES: dict[int, tuple[CompressionMethod, ...]] = {
    method_id: (CompressionMethod(algo=algo),)
    for method_id, algo in _ZIP_COMPRESSION_ALGOS.items()
}
# A method id archivey does not know.
_UNKNOWN_COMPRESSION = (CompressionMethod(algo=CompressionAlgorithm.UNKNOWN),)

# ZIP method id -> shared codec-layer Codec for member decode, after any decrypt stage.
_ZIP_METHOD_CODECS: dict[int, Codec] = {
    0: Codec.STORED,
    8: Codec.DEFLATE,
    9: Codec.DEFLATE64,
    12: Codec.BZIP2,
    14: Codec.LZMA,  # after peeling the ZIP LZMA header (see _open_codec_member)
    93: Codec.ZSTD,
    98: Codec.PPMD,  # after peeling the ZIP PPMd8 header
}

# Compressed size of an *empty* body per method, as ``zipfile`` writes one for a
# directory ``ZipInfo`` given no data (the Java ``jar`` tool deflates every directory's
# empty body: 2 bytes). ``tests/test_zip.py`` checks the table against ``zipfile``.
# The sizes are those of a known, unencrypted method: an encrypted entry's body also
# carries the cipher's framing (12 bytes for ZipCrypto, salt plus verifier plus auth
# code for WinZip AES, under method 99), and DEFLATE64, zstd and PPMd have no 0-byte
# empty frame, so a directory entry in either shape errs toward being reported. No
# writer measured (zip, 7-Zip, zipfile) encrypts or compresses a directory's body.
_ZIP_EMPTY_BODY_SIZES: dict[int, int] = {
    0: 0,  # STORED
    8: 2,  # DEFLATE
    12: 14,  # bzip2
    14: 19,  # LZMA
}


def _zip_directory_stores_data(entry: CentralEntry) -> bool:
    """True when a directory entry's body holds something: a declared size, or a
    compressed body larger than an empty one of its method takes (a declared size of
    0 over a real body is the same hidden payload one header field away). A method
    the table does not know reports any body at all."""
    if entry.file_size > 0:
        return True
    return entry.compressed_size > _ZIP_EMPTY_BODY_SIZES.get(entry.method, 0)


# ZIP create-system values whose entries use "\" as a path separator (DOS/Windows family).
# For these, a stored backslash is a separator; for Unix/other entries it is a literal
# filename character (see the minimal-name-normalization change / archive-data-model spec).
_BACKSLASH_SEPARATOR_SYSTEMS: frozenset[CreateSystem] = frozenset(
    {
        CreateSystem.FAT,
        CreateSystem.OS2_HPFS,
        CreateSystem.WINDOWS_NTFS,
        CreateSystem.VFAT,
    }
)
# ZIP create-system values whose `external_attr` low word is a Win32 DOS attribute word
# (FILE_ATTRIBUTE_*). Deliberately a sibling of _BACKSLASH_SEPARATOR_SYSTEMS rather than
# the same object: the two answer different questions about the same family and are free
# to diverge — a creator could spell paths the DOS way without recording DOS attributes.
_DOS_ATTRIBUTE_SYSTEMS: frozenset[CreateSystem] = frozenset(
    {
        CreateSystem.FAT,
        CreateSystem.OS2_HPFS,
        CreateSystem.WINDOWS_NTFS,
        CreateSystem.VFAT,
    }
)
# Hosts whose stored creation time is a birth time. The same four as
# _DOS_ATTRIBUTE_SYSTEMS today, kept apart on purpose: a host added there for its
# attribute or separator rules is not a birth-time host until someone says so, since
# its creation time would otherwise flow into ``created``.
_ZIP_BIRTH_TIME_HOSTS: frozenset[CreateSystem] = frozenset(
    {
        CreateSystem.FAT,
        CreateSystem.OS2_HPFS,
        CreateSystem.WINDOWS_NTFS,
        CreateSystem.VFAT,
    }
)
_CREATE_SYSTEM_BY_VALUE: dict[int, CreateSystem] = {
    member.value: member for member in CreateSystem
}
# _BACKSLASH_SEPARATOR_SYSTEMS by host byte: an enum member hashes in Python, an int
# in C, and the listing asks once per member.
_BACKSLASH_SEPARATOR_HOSTS: frozenset[int] = frozenset(
    system.value for system in _BACKSLASH_SEPARATOR_SYSTEMS
)


# Raised when a member read finds the reader's handle gone.
_CLOSED_ARCHIVE_MESSAGE = "Attempt to use ZIP archive that was already closed"


# A password candidate that passed the header check but then failed the member's own
# checks; shared by the compressed and the STORED confirmation paths.
_CANDIDATE_FAILED_MSG = (
    "Password candidate failed integrity validation for this ZIP member"
)


class _CandidateFailures:
    """What the candidates of one confirm run failed with, for the error raised when
    none wins (``ZipReader._finish_password_attempt``).

    ``ambiguous`` holds the one failure to report, ``limits`` the first decoder limit a
    ZipCrypto candidate's decrypted codec settings tripped.
    """

    def __init__(self) -> None:
        self.ambiguous: list[EncryptionError] = []
        self.limits: list[ResourceLimitError] = []

    def failed(self, cause: Exception | None) -> EncryptionError:
        """The error that rejects one candidate whose data failed its checks."""
        failure = EncryptionError(_CANDIDATE_FAILED_MSG)
        if cause is not None:
            failure.__cause__ = cause
        if not self.ambiguous:
            self.ambiguous.append(failure)
        elif isinstance(cause, TruncatedError) and not isinstance(
            self.ambiguous[0].__cause__, TruncatedError
        ):
            # Prefer a truncation any candidate met over the first failure, so the
            # verdict does not follow key order. For a STORED member the length is
            # the ciphertext's and settles it; for a compressed one the decoded
            # length depends on the key, so this is a heuristic there.
            self.ambiguous[0] = failure
        return failure

    def limit_failed(self, exc: ResourceLimitError) -> EncryptionError:
        """The error that rejects a ZipCrypto candidate whose decrypted codec settings
        are over a decoder limit: it may be a wrong key that passed the check byte."""
        if not self.limits:
            self.limits.append(exc)
        failure = EncryptionError(
            "Password candidate decrypted codec settings over a decoder limit for "
            "this ZIP member"
        )
        failure.__cause__ = exc
        return failure


def _closed_archive_error() -> ArchiveyUsageError:
    """The handle under a live reader was closed — a lifecycle fault, not damage.

    Deliberately not a ``CorruptionError``: the archive bytes are fine, so reporting
    damage sends the caller hunting a bad file. This is the underlying-handle variant of
    using a reader after ``close()``, which already raises ``ArchiveyUsageError``.
    """
    return ArchiveyUsageError(_CLOSED_ARCHIVE_MESSAGE)


# Raw exceptions a ZIP member open can raise before the codec layer takes over (local
# header parse, raw payload view, decrypt-stage header, codec open) that
# _translate_exception maps to typed ArchiveyErrors. Declared once so those catch sites
# cannot drift apart.
_ZIP_MEMBER_READ_ERRORS: tuple[type[Exception], ...] = (
    io.UnsupportedOperation,
    lzma.LZMAError,
    ValueError,
)
# The same, plus the typed errors the parser raises for a damaged local header and the
# overlap guard raises, so a member open stamps them with the member's name.
_LOCAL_HEADER_ERRORS: tuple[type[Exception], ...] = (
    ArchiveyError,
    *_ZIP_MEMBER_READ_ERRORS,
)
#: WinZip AES: the real method sits in the 0x9901 extra field.
_WINZIP_AES_METHOD = 99
#: The code each ``LocalHeaderContext.field`` reports under.
_LOCAL_HEADER_CODES: dict[str, DiagnosticCode] = {
    "name": DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS,
    "method": DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS,
    "crc32": DiagnosticCode.MEMBER_LOCAL_CRC_USED,
}


def _decode_with_fallback(data: bytes) -> str:
    for encoding in _ZIP_ENCODINGS:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise AssertionError("unreachable: cp437 decodes every byte")


_T = TypeVar("_T")

# Methods whose decoder rejects random input (the confirm ladder's codec rung, for
# ZipCrypto and WinZip AES alike): a wrong key dies inside the plaintext prefix, so
# confirmation stops there rather than walk a large member to its CRC or HMAC. Derived
# from REJECTING_CODECS, which the tests re-measure; STORED and PPMd are not in it and
# walk to the CRC or HMAC. The compressed-input half of the budget needs no cap of its
# own here: DEFLATE, Deflate64, LZMA and Zstandard are stream codecs, and bzip2
# produces output after one block, whose compressed size its format bounds.
_ZIP_REJECTING_METHODS = frozenset(
    method for method, codec in _ZIP_METHOD_CODECS.items() if codec in REJECTING_CODECS
)


def _is_candidate_integrity_failure(
    exc: BaseException, *, payload_complete: Callable[[], bool]
) -> bool:
    """Whether ``exc`` can be caused by a wrong key that passed the cheap check.

    A wrong key decrypts to garbage, which the codec rejects or the CRC check at EOF
    catches (``CorruptionError``). A decoder that runs out of garbage before the
    declared size says ``TruncatedError`` too, so that counts when the member's whole
    payload is in the file (``payload_complete()``, asked only then: it costs a seek);
    otherwise the file really is short.
    The local header is not encrypted, so a damaged one is never the key's doing: it
    raises before decryption starts.
    """
    # TruncatedError is a CorruptionError subclass, so it must be tested first.
    if isinstance(exc, TruncatedError):
        return payload_complete()
    return isinstance(exc, CorruptionError)


#: A lone ZipCrypto password passed the one-byte check, and the data then failed its
#: integrity check. Either the password is wrong (one in 256 wrong ones pass that byte)
#: or the member is damaged; nothing in the archive can tell the two apart.
_UNCONFIRMED_PASSWORD_FAILURE = (
    "The data failed its integrity check with this password; the password may be "
    "wrong (ZipCrypto checks only one byte of it before decrypting), or the encrypted "
    "member may be corrupt"
)


#: ZIP methods whose codec settings sit inside the member's data: the LZMA properties
#: (method 14) and the PPMd order and memory (method 98). Under ZipCrypto they are
#: encrypted, so a wrong password that passes the one-byte check decrypts them to
#: garbage, and a garbage dictionary or memory size trips ``max_decoder_memory``.
_ZIP_KEYED_SETTINGS_METHODS = frozenset({14, 98})

# PPMd8 restore method 2 (freeze): 7-Zip says "Unsupported Method". 0 and 1 decode;
# anything above 2 is a "Data Error".
_ZIP_PPMD_RESTORE_UNSUPPORTED = 2

_UNCONFIRMED_RESOURCE_LIMIT_NOTE = (
    "Under ZipCrypto the password may be wrong: it checks only one byte of the "
    "password before decrypting, and these codec settings are part of the encrypted "
    "data, so a wrong password decrypts them to an arbitrary size."
)


def _unconfirmed_resource_limit(error: ResourceLimitError) -> ResourceLimitError:
    """``error``, from codec settings an unconfirmed ZipCrypto key decrypted, with a note.

    Still a ``ResourceLimitError``: when the size is real (the password was right), a
    caller who raises ``DecoderLimits.max_decoder_memory`` gets a working read.
    """
    return ResourceLimitError(
        f"{raw_message_of(error)} {_UNCONFIRMED_RESOURCE_LIMIT_NOTE}"
    )


@dataclass(frozen=True)
class _ZipCipher:
    """An encrypted member's scheme, and the method and codec its plaintext uses.

    ZipCrypto (``is_aes`` False): a one-byte key check, no MAC, and a stage that seeks
    only by decrypting again from the start. WinZip AES: a two-byte key check and an
    HMAC over the whole ciphertext, which survives seeks.
    """

    stage: Callable[[bytes], BinaryIO]
    method: int
    codec: Codec
    #: The CRC-32 a candidate's plaintext must match: the member's CRC-32 digest
    #: (:func:`_member_crc_anchor`). ``None`` when the member has none, as for AE-2
    #: (the HMAC is its check) and a directory whose CRC field is 0.
    crc_anchor: int | None
    is_aes: bool

    @property
    def keyed_settings(self) -> bool:
        """Whether a wrong key can decrypt the codec settings to an arbitrary size."""
        return not self.is_aes and self.method in _ZIP_KEYED_SETTINGS_METHODS


class _UnconfirmedZipCryptoStream(DelegatingStream):
    """A ZipCrypto member opened with one password that only its check byte vouched for.

    A wrong password shows up here as a CRC mismatch at the end of the member, or a
    decoder error part way into a compressed one. Both would otherwise read as a
    damaged archive, so they are reported the way the multi-password path reports the
    same ambiguity: as an ``EncryptionError`` that names both causes. The inner stream
    is the decoded member with its CRC verifier, so both arrive as ``ArchiveyError``
    (see :func:`_is_candidate_integrity_failure`).
    """

    # Translates errors and changes no byte: the verification level looks through.
    forwards_verification = True

    def __init__(
        self, inner: BinaryIO, *, payload_complete: Callable[[], bool]
    ) -> None:
        self._payload_complete = payload_complete
        super().__init__(inner)

    def read(self, n: int = -1, /) -> bytes:
        try:
            return super().read(n)
        except Exception as exc:  # noqa: BLE001 - classified, then re-raised
            self._reraise(exc)

    def readinto(self, b: WriteableBuffer, /) -> int:
        # Overridden too, so the zero-copy passthrough stays on and still translates.
        try:
            return super().readinto(b)
        except Exception as exc:  # noqa: BLE001 - classified, then re-raised
            self._reraise(exc)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        # A forward seek decrypts and decodes what it skips.
        try:
            return super().seek(offset, whence)
        except Exception as exc:  # noqa: BLE001 - classified, then re-raised
            self._reraise(exc)

    def _digest_intact(self) -> bool | None:
        # The password watch above asks after a seek whether the CRC can still run.
        return ask_digest_intact(self._inner)

    def _reraise(self, exc: Exception) -> NoReturn:
        if _is_candidate_integrity_failure(
            exc, payload_complete=self._payload_complete
        ):
            raise unverified_data_error(_UNCONFIRMED_PASSWORD_FAILURE) from exc
        raise exc


def _zip_timestamps(
    entry: CentralEntry, member_name: str, fields: Sequence[ExtraField]
) -> tuple[
    datetime | None,
    datetime | None,
    datetime | None,
    datetime | None,
    list[TimestampIssue],
    tuple[int, ...],
]:
    """Return ``(modified, accessed, ntfs_ctime, ut_ctime, issues, used_tags)`` for a
    member, ``used_tags`` being the extra fields a time the member keeps came from:
    a field whose every time a higher layer replaced is not among them.

    Sources, lowest to highest precedence (each layer overrides only the times it
    actually carries):

    1. The DOS ``date_time``: a 2-second-granularity local wall-clock modification time
       (naive ``datetime``; ``None`` for the "no timestamp" sentinel year 1980).
    2. An NTFS extra field (0x000A): three 64-bit FILETIMEs (modification, access,
       creation) in 100 ns UTC ticks since 1601; zero means "not set". Written by
       Windows tools (e.g. 7-Zip).
    3. A PKWARE Unix (0x000D) or Info-ZIP old Unix (0x5855) extra field: access then
       modification time, each a 32-bit Unix time in UTC, then (local header only)
       the owner ids. macOS ditto and Archive Utility write only 0x5855. As unzip 6.00
       reads it (measured, dev-docs/formats/zip.md §6 Decisions), it is ignored in a blob that
       holds an Extended Timestamp, or after an Info-ZIP Unix type 2 or new Unix field
       (0x7855, 0x7875), the rule ``_zip_owner`` applies to its ids; of several, the
       last one long enough for both times counts.
    4. An Extended Timestamp extra field (0x5455): real Unix timestamps, its flags byte
       signaling which of modification/access/"creation" follow (in that order), each a
       signed 32-bit Unix time interpreted as UTC. The central directory typically
       carries only the modification time even when the flags advertise more.

    The two "creation" times come back raw, apart from each other: ``ntfs_ctime``
    from the NTFS field and ``ut_ctime`` from the Extended Timestamp's third time.
    Whether either is a birth time depends on the writer, not the field, so the caller
    decides (``_zip_created``).

    ``member_name`` names the member in the issue messages; ``fields`` is
    ``entry.extra`` split (``split_extra_fields``).
    """
    issues: list[TimestampIssue] = []
    date_time = entry.date_time
    if date_time == (1980, 0, 0, 0, 0, 0):
        modified: datetime | None = None
    else:
        try:
            modified = datetime(*date_time)
        except ValueError:
            issues.append(
                TimestampIssue(
                    field="mtime",
                    source="dos",
                    value_repr=repr(date_time),
                    message=(
                        f"Invalid ZIP date_time for {quoted(member_name)}: "
                        f"{date_time!r}"
                    ),
                )
            )
            modified = None
    accessed: datetime | None = None
    ntfs_ctime: datetime | None = None
    ut_ctime: datetime | None = None

    # One scan collecting the timestamp extra fields, applied afterwards in precedence
    # order (NTFS, then Unix, then Extended Timestamp) regardless of their order in the
    # blob. Empty extra is the common case (zipfile.writestr / many tools) — skip it.
    ntfs_field: bytes | None = None
    ut_field: bytes | None = None
    unix_field: ExtraField | None = None
    newer_unix = False
    # The extra field each time came from, None for the DOS stamp or no time.
    modified_from: int | None = None
    accessed_from: int | None = None
    if not fields:
        return modified, accessed, ntfs_ctime, ut_ctime, issues, ()
    # A cut-short field is read for what it carries: the NTFS and UT walks below
    # check every read against the field's actual length.
    for field in fields:
        tag = field.tag
        if tag == 0x000A and ntfs_field is None:
            ntfs_field = field.data
        elif tag == 0x5455 and field.data and ut_field is None:
            ut_field = field.data
        elif tag in (_OWNER_TAG_INFOZIP_NEW_UNIX, _OWNER_TAG_INFOZIP_UNIX2):
            newer_unix = True
        elif (
            tag in (_OWNER_TAG_PKWARE_UNIX, _OWNER_TAG_INFOZIP_OLD_UNIX)
            and len(field.data) >= _UNIX_TIMES_LEN
            and not newer_unix
        ):
            unix_field = field

    if ntfs_field is not None:
        # Layout: 4 reserved bytes, then (tag, size) attributes; tag 1 carries the three
        # FILETIMEs. Malformed/short fields are skipped rather than failing the listing.
        cursor = 4
        while cursor + 4 <= len(ntfs_field):
            attr_tag, attr_size = struct.unpack_from("<HH", ntfs_field, cursor)
            cursor += 4
            if (
                attr_tag == 0x0001
                and attr_size >= 24
                and cursor + 24 <= len(ntfs_field)
            ):
                mtime, atime, ctime = struct.unpack_from("<QQQ", ntfs_field, cursor)
                for value, field_name in (
                    (mtime, "mtime"),
                    (atime, "atime"),
                    (ctime, "ctime"),
                ):
                    dt, issue = filetime_to_datetime(
                        value, member_name, field=field_name
                    )
                    if issue is not None:
                        issues.append(issue)
                    if dt is None:
                        continue
                    if field_name == "mtime":
                        modified, modified_from = dt, 0x000A
                    elif field_name == "atime":
                        accessed, accessed_from = dt, 0x000A
                    else:
                        ntfs_ctime = dt
                break
            cursor += attr_size

    if unix_field is not None and ut_field is None:
        # Signed, as the Extended Timestamp's times are read below.
        atime, mtime = struct.unpack_from("<ii", unix_field.data)
        accessed = unix32_to_datetime(atime)
        modified = unix32_to_datetime(mtime)
        accessed_from = modified_from = unix_field.tag

    if ut_field is not None:
        flags = ut_field[0]
        cursor = 1
        for bit, ut_name in ((0x01, "mtime"), (0x02, "atime"), (0x04, "ctime")):
            if flags & bit and cursor + 4 <= len(ut_field):
                ts = int.from_bytes(
                    ut_field[cursor : cursor + 4], "little", signed=True
                )
                cursor += 4
                # A signed 32-bit field: a pre-1970 date is legitimate, and every
                # value it can hold is a valid datetime on every platform.
                when = unix32_to_datetime(ts)
                if bit == 0x01:
                    modified, modified_from = when, 0x5455
                elif bit == 0x02:
                    accessed, accessed_from = when, 0x5455
                else:
                    ut_ctime = when

    # A field counts as read only for a time it still gives once every layer has run;
    # the creation slot takes the Extended Timestamp's time over the NTFS one
    # (``_zip_created``).
    creation_from = (
        0x5455 if ut_ctime is not None else 0x000A if ntfs_ctime is not None else None
    )
    used: tuple[int, ...] = ()
    for tag in (modified_from, accessed_from, creation_from):
        if tag is not None and tag not in used:
            used += (tag,)
    return modified, accessed, ntfs_ctime, ut_ctime, issues, used


# Extra fields that record a Unix owner: Info-ZIP's "new Unix" field (variable-width
# ids), its "Unix type 2" (16-bit ids), PKWARE's Unix field and Info-ZIP's old "Unix"
# field (both 16-bit ids after two times, the same layout). ``_zip_owner`` reads them
# as unzip 6.00 does.
_OWNER_TAG_INFOZIP_NEW_UNIX = 0x7875
_OWNER_TAG_INFOZIP_UNIX2 = 0x7855
_OWNER_TAG_PKWARE_UNIX = 0x000D
_OWNER_TAG_INFOZIP_OLD_UNIX = 0x5855
# The id widths unzip reads from the new Unix field; Info-ZIP writes 4 bytes.
_NEW_UNIX_ID_SIZES = frozenset((2, 4, 8))
# The two times every PKWARE or old Info-ZIP Unix field starts with; the ids follow.
_UNIX_TIMES_LEN = 8


class _ZipOwner(NamedTuple):
    """What a member's owner extra fields give.

    ``ids`` is ``(uid, gid)``, or ``None``; ``tag`` is the field they came from.
    ``fault`` is ``(tag, reason)`` when there are no ids because a field was damaged;
    the reader drops it and reports that.
    """

    ids: tuple[int, int] | None
    fault: tuple[int, str] | None = None
    tag: int | None = None


_NO_OWNER = _ZipOwner(None)


def _zip_owner(fields: Sequence[ExtraField]) -> _ZipOwner:
    """The owner ids an extra field's ``fields`` record, read as unzip 6.00 reads them.

    The fields are read in blob order (measured with ``unzip -X`` as root, see
    dev-docs/formats/zip.md §6):

    - A ``0x7875`` or ``0x7855`` decides the owner afresh, readable or not: the ids are
      its own, or none. A ``0x7855`` after a ``0x7875`` is ignored.
    - A PKWARE or old Info-ZIP field is ignored after either of them. Otherwise one
      that holds ids replaces the earlier ids, and one that does not changes nothing.

    Not damage, so not reported: a field holding only what its central directory copy
    holds (an empty ``0x7855``, a PKWARE or old Info-ZIP field with its two times only;
    those hold their ids in local headers only, which listing does not read), and a
    ``0x7875`` of a version other than 1. Either still decides as above. No ZIP field
    records the owner's names.
    """
    if not fields:
        return _NO_OWNER
    ids: tuple[int, int] | None = None
    ids_tag: int | None = None
    fault: tuple[int, str] | None = None
    # 0: no newer field seen; 1: a 0x7855; 2: a 0x7875.
    newer = 0
    # Once a 0x7875 is seen the last one decides, so its owner is the answer as is.
    newest: _ZipOwner | None = None
    for field in fields:
        tag = field.tag
        data = field.data
        if tag == _OWNER_TAG_INFOZIP_NEW_UNIX:
            newer = 2
            newest = (
                _cached_new_unix_owner(data, field.complete)
                if len(data) <= _NEW_UNIX_CACHED_LEN
                else _new_unix_owner(data, field.complete)
            )
        elif tag == _OWNER_TAG_INFOZIP_UNIX2:
            if newer == 2:
                continue
            newer = 1
            ids = None
            if not field.complete:
                fault = (tag, "cut_short")
            elif len(data) == 4:
                ids, fault, ids_tag = struct.unpack_from("<HH", data), None, tag
            else:
                fault = (tag, "wrong_size") if data else None
        elif tag in (_OWNER_TAG_PKWARE_UNIX, _OWNER_TAG_INFOZIP_OLD_UNIX):
            if newer:
                continue
            if field.complete and len(data) >= _UNIX_TIMES_LEN + 4:
                ids, fault = struct.unpack_from("<HH", data, _UNIX_TIMES_LEN), None
                ids_tag = tag
            elif ids is None and (not field.complete or len(data) != _UNIX_TIMES_LEN):
                fault = (tag, "cut_short" if not field.complete else "too_short")
    if newest is not None:
        return newest
    if ids is not None:
        return _ZipOwner((ids[0], ids[1]), tag=ids_tag)
    return _NO_OWNER if fault is None else _ZipOwner(None, fault)


def _new_unix_owner(data: bytes, complete: bool) -> _ZipOwner:
    """The ids in an Info-ZIP new Unix field (``0x7875``) holding ``data``.

    Layout: version (1), uid size, uid, gid size, gid, each id little-endian.
    """
    tag = _OWNER_TAG_INFOZIP_NEW_UNIX
    if not complete:
        return _ZipOwner(None, (tag, "cut_short"))
    if not data:
        return _ZipOwner(None, (tag, "too_short"))
    if data[0] != 1:
        return _NO_OWNER
    if len(data) < 3:
        return _ZipOwner(None, (tag, "too_short"))
    uid_size = data[1]
    gid_at = 2 + uid_size
    if gid_at >= len(data):
        return _ZipOwner(None, (tag, "too_short"))
    gid_size = data[gid_at]
    end = gid_at + 1 + gid_size
    if end > len(data):
        return _ZipOwner(None, (tag, "too_short"))
    if uid_size not in _NEW_UNIX_ID_SIZES or gid_size not in _NEW_UNIX_ID_SIZES:
        return _ZipOwner(None, (tag, "id_size"))
    uid = int.from_bytes(data[2:gid_at], "little")
    gid = int.from_bytes(data[gid_at + 1 : end], "little")
    return _ZipOwner((uid, gid), tag=tag)


# The members of one archive mostly share an owner, so mostly share the field's bytes.
# Only fields a writer could produce are cached (19 bytes at most: version, two sizes,
# two 8-byte ids): hashing a long hostile field costs more than parsing it, and the
# cache would keep its bytes for the life of the process.
_NEW_UNIX_CACHED_LEN = 19
_cached_new_unix_owner = lru_cache(maxsize=64)(_new_unix_owner)


# Fields that are part of the ZIP structure rather than a record about the member: the
# ZIP64 sizes (applied by the parser), WinZip AES and PKWARE Strong Encryption. They
# never appear among the unparsed fields.
_STRUCTURAL_EXTRA_TAGS = frozenset((0x0001, 0x9901, _ZIP_EXTRA_STRONG_ENCRYPTION))


def _unparsed_extra_fields(
    fields: Sequence[ExtraField], used_tags: Collection[int]
) -> dict[int, bytes] | None:
    """The central extra fields archivey took nothing from, by tag, or ``None``.

    ``used_tags`` names the fields a value was taken from. A field archivey knows
    but took nothing from (malformed, or a Unicode Path field about another name) is
    unparsed too, so a caller can see what was ignored. Of several fields with one
    tag, the first is kept; a tag any copy of which was used is left out.
    """
    unparsed: dict[int, bytes] | None = None
    for field in fields:
        tag = field.tag
        if tag in _STRUCTURAL_EXTRA_TAGS or tag in used_tags:
            continue
        if unparsed is None:
            unparsed = {tag: field.data}
        else:
            unparsed.setdefault(tag, field.data)
    return unparsed


def _zip_created(
    create_system: CreateSystem,
    ntfs_ctime: datetime | None,
    ut_ctime: datetime | None,
) -> tuple[datetime | None, datetime | None]:
    """Split a member's stored creation time into ``(created, ctime)``.

    The writer's host decides what the time means, not the field that carries it: on
    Linux and macOS, 7-Zip and p7zip fill the NTFS creation FILETIME from st_ctime and
    libarchive fills the Extended Timestamp's third time from it; on Windows the same
    writers store the birth time. A FAT, OS/2, NTFS or VFAT host stores a birth time.
    Any other host, unknown included, has its time reported as ``ctime``
    and ``created`` left None, as RAR does for an unknown ``host_os``. Measured per writer
    and OS in dev-docs/investigations/writer-timestamp-slots.md.

    One measured writer loses a birth time this way: libarchive on Windows stamps host
    3 but stores the birth time. It lands in ``ctime``, so ``created`` can
    miss a birth time but never holds st_ctime.

    The Extended Timestamp wins when both are present, the same precedence
    ``_zip_timestamps`` gives it for the other times.
    """
    stored = ut_ctime if ut_ctime is not None else ntfs_ctime
    if stored is None:
        return None, None
    if create_system in _ZIP_BIRTH_TIME_HOSTS:
        return stored, None
    return None, stored


def _zip_timestamp_field(create_system: CreateSystem, slot: str) -> str:
    """The ``ArchiveMember`` field a stored time slot would have filled.

    The creation slot is ``created`` or ``ctime`` by host, as in :func:`_zip_created`.
    That field may still hold a value from a lower-precedence layer, such as the DOS
    stamp under a bad NTFS modification time.
    """
    if slot == "ctime":
        return "created" if create_system in _ZIP_BIRTH_TIME_HOSTS else "ctime"
    return {"mtime": "modified", "atime": "accessed"}[slot]


@dataclass(slots=True)
class _ZipLocator:
    """What a listed member keeps for reading its data, as ``member._raw``.

    Not the ``CentralEntry``: its extra field and comment would stay alive for every
    member, for data that is read only while listing. Read-only by convention, not
    ``frozen``, for the construction cost (as ``CentralEntry``).
    """

    #: Position in the central directory; tells same-offset entries apart.
    index: int
    #: Absolute position of the local header.
    header_offset: int
    compressed_size: int
    file_size: int
    crc: int
    flags: int
    method: int
    #: The DOS time word: its high byte is the ZipCrypto check byte under bit 3.
    dos_time: int
    #: The central directory's name bytes. ``_checked_local_header`` compares the local
    #: header's with them and reports a difference (``_report_local_name``).
    name: bytes
    #: The WinZip AES record (strength, real method) for method 99; ``None`` when
    #: absent or malformed.
    aes: WinZipAesInfo | None
    strong_encryption: bool
    #: For an entry flagged as a Windows reparse point, the type it reverts to when
    #: its data is not a link buffer (:func:`_reparse_fallback_type`).
    reparse_fallback: MemberType | None
    #: For a member whose size is unknown until a read (:func:`_wrapped_size`): the
    #: stored size and the bounds its real size lies in. ``None`` otherwise.
    size_unknown: _UnknownSize | None = None
    #: Per-open scratch: where the data starts, once an open has read and checked the
    #: local header (:meth:`ZipReader._with_local_method`), so the open reads it once.
    #: Listing never fills it, so it is ``None`` on every listed member. An open works
    #: on a ``replace()`` copy carrying it, so a write to the listed locator
    #: (``_apply_descriptor``) reaches an open only when it comes first: listing
    #: writes stay ahead of every open.
    data_start: int | None = None


#: Deflate's largest expansion: a 258-byte match costs at least two bits.
_DEFLATE_MAX_RATIO = 1032
#: ZIP compression methods macOS Archive Utility writes: stored and deflated.
_ARCHIVE_UTILITY_METHODS = frozenset({0, 8})


class _UnknownSize(NamedTuple):
    """What a read checks a member's length against when the archive stores its size
    modulo 2³² alone (:func:`_wrapped_size`)."""

    stored: int
    #: Deflate's upper bound on the size: 1032 times the compressed size.
    high: int

    def check(self, length: int) -> None:
        """Refuse a length the stored size or deflate's ratio rules out."""
        if length % OFFSET_WRAP != self.stored or length > self.high:
            raise CorruptionError(
                f"Decompressed content ended after {length} bytes, which the stored "
                f"size of {self.stored} modulo 2**32 and the compressed size rule out."
            )


def _wrapped_size(entry: CentralEntry) -> tuple[int | None, _UnknownSize | None]:
    """The size of a member of a macOS Archive Utility ZIP, whose sizes past 4 GiB the
    archive stores modulo 2³², and its bounds when that leaves it unknown.

    The real size is the stored one plus a multiple of 2³². A stored member's is its
    compressed size, which the walk measured from the layout, when the two agree
    modulo 2³². A deflated member's is at most 1032 times its compressed size (a
    258-byte match takes two bits at the least). When the stored value is the only
    multiple under that, it is the size. When more fit, the size is unknown: ``None``,
    with the bound a read checks the length against. No lower bound narrows them:
    one that real encoders keep (incompressible data shrinks little) does not hold
    for every valid stream, since empty stored blocks pad one without bound, and a
    size picked on it could be 4 GiB too large. A stored value over the bound (a
    damaged entry) stays, and the read fails on it as before.
    """
    stored = entry.file_size
    compressed = entry.compressed_size
    if entry.method == 0:
        if compressed % OFFSET_WRAP == stored:
            return compressed, None
        return stored, None
    high = compressed * _DEFLATE_MAX_RATIO
    if stored + OFFSET_WRAP <= high:
        return None, _UnknownSize(stored, high)
    return stored, None


def _local_crc_stands_in(
    central: CentralEntry, local_flags: int, local_crc: int
) -> bool:
    """Whether a local header's CRC-32 replaces its directory entry's 0.

    The directory stores 0 over some data and the local header a non-zero value that
    no data descriptor defers (bit 3 clear). 0 is the CRC-32 of no data, so an empty
    member's 0 needs nothing, and a listing reads no local header for one. unzip checks
    the data against the local value and archivey does too, reporting
    ``MEMBER_LOCAL_CRC_USED``. Adobe AIR's packager writes ``META-INF/AIR/hash``
    this way: it fills the local header after the directory entry was made.
    """
    return (
        central.crc == 0
        and central.file_size > 0
        and local_crc != 0
        and not local_flags & _ZIP_MASK_USE_DATA_DESCRIPTOR
    )


def _stored_text(name: bytes) -> str:
    """Stored name bytes as message text: UTF-8, with any other byte kept as a lone
    surrogate for the message's own escaping to show."""
    return name.decode("utf-8", "surrogateescape")


def _bound_offset(offset: int) -> int:
    """``offset`` clamped into a signed 64-bit range that keeps its order.

    A local-header offset past ``MAX_DATA_OFFSET`` or below 0 is refused when its
    member opens; as a bound for its neighbours only its order matters, and
    ``MAX_DATA_OFFSET`` is the largest value the array holds.
    """
    return min(max(offset, -1), MAX_DATA_OFFSET)


@dataclass(frozen=True, slots=True)
class _PastDamage:
    """The members a walk over the local headers found past a damaged directory
    (``ZipReader._past_damage``)."""

    walked: _WalkedMembers
    #: The directory's offsets, then those of the members past the damage.
    offsets: array[int]
    #: The overlap guard's offsets, one per member as ``offsets`` is: -1, which bounds
    #: nothing, for a directory entry that points at no local header.
    bounds: array[int]
    #: Each member past the damage's position in ``walked``.
    positions: list[int]
    #: The id of the member whose data the walk could not get past, if listed.
    cut: int | None


class _DataBounds:
    """Where each member's data must end, for the overlap guard.

    The next local header above the member's own, or the central directory for the
    last one. stdlib sets the same bound as ``ZipInfo._end_offset``. Two entries over
    one local header: the first in directory order reads and each later one is an
    overlap, because many directory entries over one local header is the
    overlapping-entry amplification shape (DR-9a). stdlib warns and reads both from
    3.12.10, 3.13.3 and 3.14.

    A walk that stops early at ``max_members`` gives the offsets of the entries before
    the stop. Every walk stops at the same entry, so those are every member ever handed
    out; no member past the stop opens. The bound only loosens for a listed member
    whose next header is past the stop: its data may then run over entries that never
    open, so no byte still reads as two members' data. A walk that stops at damage
    gives those offsets and then the ones the local headers hold past it
    (``ZipReader._past_damage``), one per member that listing hands out, but -1 for a
    directory entry that points at no local header: it reads nothing, and bounds
    nothing. The index pass stops at the entry the listing stops at, so the two
    give the same bounds.
    """

    __slots__ = ("_cd_start", "_first_at", "_sorted")

    def __init__(self, offsets: array[int], *, cd_start: int) -> None:
        self._sorted = array("q", sorted(offsets))
        self._cd_start = cd_start
        ordered = self._sorted
        shared = {
            ordered[i] for i in range(1, len(ordered)) if ordered[i] == ordered[i - 1]
        }
        # For each shared offset, the first entry over it: the one that reads.
        self._first_at: dict[int, int] = {}
        if shared:
            for index, offset in enumerate(offsets):
                if offset in shared:
                    self._first_at.setdefault(offset, index)

    def end_for(self, loc: _ZipLocator) -> int:
        offset = _bound_offset(loc.header_offset)
        first = self._first_at.get(offset)
        if first is not None and first != loc.index:
            return offset
        ordered = self._sorted
        above = bisect_right(ordered, offset)
        return ordered[above] if above < len(ordered) else self._cd_start


def _max_members_error(
    max_members: int, counted: str = "ZIP central directory holds"
) -> ResourceLimitError:
    """``counted`` names what crossed the limit: the directory, or the local headers a
    forward walk met before any directory."""
    return ResourceLimitError(
        f"Listing limit reached: max_members={max_members} ({counted} more than "
        f"{max_members} entries)"
    )


#: Also the receipt for a seekable source read through its directory. An end record
#: behind more trailing bytes than its search reads is found by a walk over every local
#: header at open, reading the data of each bit-3 member (``_walk_past_members``). A ZIP
#: with no end record at all is listed from the local headers that walk found, and its
#: listing ends by raising the walk's error. Both stay ``INDEXED``: the walk finds the
#: index or salvages a damaged archive (``ListingCost`` says why neither changes it).
_ZIP_COST = CostReceipt(
    listing_cost=ListingCost.INDEXED,
    access_cost=AccessCost.DIRECT,
    stream_capability=StreamCapability.SEEKABLE,
    solid_block_count=None,
)


class _DecodedName(NamedTuple):
    """A ZIP entry's name as archivey reads it, before normalization. A tuple, not a
    dataclass: one is built per member on the listing hot path. The ASCII fast path
    in ``_decode_member_name`` builds it positionally; ``test_zip_native_reader``
    pins the field order."""

    text: str
    """The decoded name; ``member.name`` is this, normalized."""
    raw_name: bytes
    """The bytes ``text`` was decoded from."""
    alternate_raw_name: bytes | None
    """The header's bytes, when the Unicode Path field named the entry instead."""
    inferred_encoding: str | None
    """The codec that produced ``text`` when it is not the one the name would
    otherwise have had (a sniff's choice over the default, or the codec used for a
    name whose UTF-8 flag the bytes refute), for the diagnostic."""
    declared_encoding: str | None
    """``"utf-8"`` when the UTF-8 flag is set over bytes that are not UTF-8, so the
    name and its comment decode as unflagged ones; ``None`` otherwise."""
    unicode_extra_fault: str | None
    """Why a malformed Unicode Path field was dropped, for the diagnostic."""
    unicode_path_used: bool
    """Whether the Unicode Path field named the entry."""


def _stored_as_directory(name: str, create_system: CreateSystem) -> bool:
    """Whether a decoded ZIP name ends in a separator, which marks a directory entry.

    The test reads archivey's own decoded name with archivey's own separator rule
    (``\\`` is one only for DOS/Windows-origin entries), never ``ZipInfo.is_dir()``:
    that reads stdlib's rewritten ``filename``, which differs by host (``os.sep``
    becomes ``/`` on Windows, and a trailing ``\\`` counts there) and by Python version
    (3.12+ substitutes the Unicode Path field's name), so one entry would change type
    from one machine to the next.
    """
    return name.endswith("/") or (
        create_system in _BACKSLASH_SEPARATOR_SYSTEMS and name.endswith("\\")
    )


def _is_flagged_reparse_point(external_attr: int, create_system: CreateSystem) -> bool:
    """Whether a DOS/Windows creator set ``FILE_ATTRIBUTE_REPARSE_POINT`` on the entry."""
    return create_system in _DOS_ATTRIBUTE_SYSTEMS and bool(
        external_attr & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _reparse_fallback_type(
    external_attr: int, create_system: CreateSystem, *, stored_as_directory: bool
) -> MemberType | None:
    """For an entry flagged as a Windows reparse point (handbook §2.2.1), the type it
    reverts to when its data is not a link buffer; ``None`` for any other entry.

    The bit lives in the low (DOS attribute) word of ``external_attr``, and only a
    DOS/Windows creator puts a Win32 attribute word there. Every other creator writes
    whatever its own platform records — a Unix creator's authority is the mode in the
    high word — so bit ``0x400`` outside :data:`_DOS_ATTRIBUTE_SYSTEMS` is somebody
    else's bit and is not read.

    "Flagged as" is the whole claim: the bit says the entry was a reparse point on the
    source filesystem, not that the archive carries the reparse buffer or that the tag
    named a link. What the data turns out to be decides that, in
    ``BaseArchiveReader._apply_reparse_data``.

    ``stored_as_directory`` was decided under the separator family
    (:data:`_BACKSLASH_SEPARATOR_SYSTEMS`, in :func:`_stored_as_directory`), not this
    function's attribute family. The two hold the same hosts today; nothing here relies
    on that.
    """
    if not _is_flagged_reparse_point(external_attr, create_system):
        return None
    return MemberType.DIRECTORY if stored_as_directory else MemberType.FILE


class _WalkedMembers:
    """What the walk over the local headers found (``ZipReader._walk_past_members``).

    For a ZIP with no end record, the members it found are listed from their local
    headers and then ``error`` is raised, as a read from a pipe lists and raises
    (``ZipReader._iter_walked``). Kept in arrays, a few bytes a member, since the
    walk may meet up to ``max_members`` of them.
    """

    __slots__ = (
        "after",
        "compressed_sizes",
        "crcs",
        "cut",
        "error",
        "file_sizes",
        "members_end",
        "offsets",
    )

    def __init__(self) -> None:
        #: Each member's local header offset, in file order.
        self.offsets: array[int] = array("q")
        #: A bit-3 member's CRC and sizes, from its data descriptor; 0 for any other.
        self.crcs: array[int] = array("L")
        self.compressed_sizes: array[int] = array("q")
        #: Unsigned: an 8-byte descriptor's uncompressed size is whatever it states,
        #: up to 2**64 - 1, and a read checks the data against it.
        self.file_sizes: array[int] = array("Q")
        #: Where the last member the walk passed whole ends.
        self.members_end = 0
        #: Where that is, for a message: "after member #n".
        self.after = ""
        #: The member whose data or descriptor the walk could not get past: listed
        #: last, and its read raises ``error``.
        self.cut: int | None = None
        #: Why the walk stopped short of the directory; ``None`` when it reached
        #: bytes that are no local header.
        self.error: ArchiveyError | None = None

    def add(self, offset: int, descriptor: DataDescriptor | None) -> None:
        self.offsets.append(_bound_offset(offset))
        if descriptor is None:
            self.crcs.append(0)
            self.compressed_sizes.append(0)
            self.file_sizes.append(0)
        else:
            self.crcs.append(descriptor.crc)
            self.compressed_sizes.append(descriptor.compressed_size)
            self.file_sizes.append(descriptor.file_size)


def _central_from_local(entry: LocalEntry) -> CentralEntry:
    """A central-entry view of what ``entry``'s local header says.

    The fields only the directory holds are zero: no host, no attributes, no comment.
    It feeds the name and time decoders, which read the same fields from either."""
    header = entry.header
    return CentralEntry(
        index=entry.index,
        version_made_by=0,
        version_needed=header.version_needed,
        flags=header.flags,
        method=header.method,
        dos_time=header.dos_time,
        dos_date=header.dos_date,
        crc=header.crc,
        compressed_size=header.compressed_size,
        file_size=header.file_size,
        header_offset=entry.offset,
        disk_start=0,
        internal_attr=0,
        external_attr=0,
        name=header.name,
        extra=header.extra,
        comment=b"",
    )


class ZipReader(BaseArchiveReader):
    """Reads a ZIP archive: the central directory and local headers through
    ``zip_parser``, member data through archivey's decrypt stages and codec layer."""

    _MEMBER_LIST_UPFRONT = True
    _LINK_TARGETS_IN_DATA = True

    def __init__(
        self,
        source: ArchiveSource,
        streaming: bool,
        passwords: _PasswordCandidates | None,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
        start_offset: int = 0,
    ) -> None:
        super().__init__(
            ArchiveFormat.ZIP,
            streaming,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
        self._source = source
        self._passwords = passwords or _PasswordCandidates()
        self._encoding = encoding
        self._stream_config = stream_config_from_archivey(
            self._config,
            streaming=streaming,
            seekable=MemberStreams.SEEKABLE in member_streams,
            usage=self._usage,
        )
        # What every member's decoder config shares, built once rather than per member.
        # The member's compressed size is the codec's input exactly, so a byte after
        # the codec's end of stream is CorruptionError (DR-3; 7-Zip: "There are some
        # data after the end of the payload data", an error in ZIP). That covers a
        # declared size short of an LZMA or PPMd stream too: the rest of the stream is
        # input left after the size (``DataAfterEndError``).
        self._member_decoder_config = replace(
            self._stream_config,
            refuse_input_after_end=True,
            collector=self._diagnostics_collector,
        )
        # One handle and one lock for everything that reads the archive: the directory
        # walk, local headers, and every member's SharedView. A read holds the lock for
        # one seek and read, so independent members still decode in parallel; closing
        # the archive takes the same lock (_close_archive). Re-entrant, as stdlib's
        # ZipFile lock was: a source whose read closes the archive (a callback that
        # tears the reader down) re-enters it on the same thread.
        self._lock = threading.RLock()
        self._fp: BinaryIO | None = None
        # >1 when the source is a joined volume set. 7-Zip's ``-v`` on a ZIP is a raw
        # byte split, so the join is an ordinary ZIP and the count is reported rather
        # than acted on. The source states it, so no wrapper between the boundary and
        # here can hide it.
        self._volume_count: int = source.volume_count
        # The members a walk over the local headers found, when the archive has no end
        # record: listed from there (``_iter_walked``). ``None`` for every other read.
        self._salvage: _WalkedMembers | None = None
        # The walk over the local headers, once made: by the tail search at open, or
        # for a directory damaged part way, whose members after the damage are listed
        # from it (``_past_damage``). Read and set under ``_past_damage_lock``.
        self._local_walk: _WalkedMembers | None = None
        self._past_damage_lock = threading.Lock()
        # What the listing listed past the damage, for ``_open_member``.
        self._past_damage_found: _PastDamage | None = None
        # Members whose local header named them differently, already reported once
        # (``_report_local_name``). Under the reader's lock.
        self._local_names_reported: set[int] = set()
        # The same for a local header naming another method (``_report_local_method``).
        self._local_methods_reported: set[int] = set()
        self._refuse_lone_split_segment()
        self._open_index(source, start_offset)

    def _refuse_lone_split_segment(self) -> None:
        """Refuse a split-set segment read alone."""
        # A split-set segment read alone. A joined set arrives here still carrying
        # part one's name, so the name alone does not decide it: what is refused is a
        # segment that was *not* rejoined. Numbered ``.zip.NNN`` incompleteness is
        # ``TruncatedError`` in ``open_archive``; this backstop is Info-ZIP's spanned
        # ``.zNN`` (and any ``.zip.NNN`` that skipped that refuse).
        if self._volume_count == 1 and is_zip_split_segment_name(self._archive_name):
            raise UnsupportedFeatureError(
                ZIP_MULTI_VOLUME_MSG,
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )

    def _open_index(self, source: ArchiveSource, start_offset: int) -> None:
        """Find the end record and get ready to walk the central directory.

        :class:`~archivey.internal.backends.zip_forward_reader.ZipForwardReader`
        replaces this for a source that cannot seek.
        """
        if not source.seekable():
            raise StreamNotSeekableError(
                "ZIP archives cannot be read from a non-seekable source: the central "
                "directory lives at the end of the file.",
                archive_name=self._archive_name,
            )
        # The counter and the slice over the source close nothing of the caller's;
        # the base closes the source itself after ``_close_archive``.
        handle = self._track_source_seeks(source)
        if start_offset:
            # The parser adjusts past a stub on its own (``EndRecord.base``), but
            # "adjust past whatever precedes the end record" is not the same promise
            # as "the archive starts here": a stub carrying its own record-shaped
            # bytes would move the answer. Slicing makes the payload the whole world,
            # which is what start_offset means.
            handle = SlicingStream(handle, start=start_offset)
        self._fp = handle
        file_size = handle.seek(0, io.SEEK_END)
        # Every header offset the listing walk has read, for the overlap guard; then
        # the guard's sorted bounds once the walk is complete (``_data_bounds``).
        self._index_lock = threading.Lock()
        self._bounds: _DataBounds | None = None
        self._member_count: int | None = None
        self._count_known = False
        try:
            found, stopped = locate_end_record(
                self._read_at, file_size, members_end=self._walk_past_members
            )
            walked = self._local_walk
            if found is None and walked is not None:
                if walked.error is None:
                    # The walk got past the members, so the step ran from there.
                    assert stopped is not None
                    walked.error = self._missing_end_record(walked, stopped, file_size)
                if walked.offsets:
                    self._list_walked_members(walked)
                    return
                raise walked.error
            if found is None:
                raise CorruptionError(NO_END_RECORD_MSG)
            try:
                self._end: EndRecord = read_end_record(self._read_at, file_size, found)
            except CorruptionError as exc:
                # End records that cannot be used (a damaged ZIP64 record after a
                # saturated classic one, a directory that would start before the
                # file): the members are what the local headers hold, as from a pipe.
                if self._list_after_bad_end_records(exc, walked):
                    return
                raise
        except ArchiveyError as exc:
            if isinstance(exc, CorruptionError):
                # The type is kept (a cut archive stays TruncatedError); the prefix says
                # where it failed.
                opened = type(exc)(f"Could not open ZIP archive: {raw_message_of(exc)}")
                self._stamp_error_context(opened)
                raise opened from exc
            self._stamp_error_context(exc)
            raise
        self._refuse_declared_count_over_limit()
        self._report_zip64_damage()
        self._report_trailing_data()

    def _list_after_bad_end_records(
        self, error: CorruptionError, walked: _WalkedMembers | None
    ) -> bool:
        """List the members the local headers hold, then raise ``error``, for end
        records ``read_end_record`` refused; ``False`` when the walk finds no member,
        and ``error`` is raised at open. A walk that stops first (a cut, a limit)
        raises its own error, as the pipe read meets it first. ``walked`` is the walk
        the tail search already made, reused; the headers are walked here only when
        it made none."""
        if walked is None:
            walked = self._local_walk = self._walk_local_headers()
        if walked.error is None:
            walked.error = error
        if not walked.offsets:
            return False
        self._list_walked_members(walked)
        return True

    def _missing_end_record(
        self, walked: _WalkedMembers, stopped: int, file_size: int
    ) -> ArchiveyError:
        """Why no end record follows the members the walk passed, in the words a read
        from a pipe uses (``missing_end_record_error``); ``stopped`` is where the step
        over the directory after them stopped."""
        return missing_end_record_error(
            self._read_at,
            walked.members_end,
            walked.after,
            stopped,
            whole=True,
            file_size=file_size,
        ) or CorruptionError(NO_END_RECORD_MSG)

    def _list_walked_members(self, walked: _WalkedMembers) -> None:
        """Get ready to list the members the walk found, for a ZIP with no end record:
        what the local headers hold is listed, then the walk's error is raised, as a
        cut TAR lists and raises. The end record stands in for none: no directory, no
        comment, no trailing bytes. The overlap guard's bounds are the walk's offsets,
        ending where the members it passed whole end; the count is unknown."""
        self._salvage = walked
        members_end = walked.members_end
        self._end = EndRecord(
            eocd_offset=members_end,
            zip64=False,
            entries_declared=0,
            cd_size=0,
            cd_offset=members_end,
            base=0,
            comment=b"",
            comment_declared=0,
            trailing=0,
        )
        self._bounds = _DataBounds(walked.offsets, cd_start=members_end)
        self._count_known = True

    def _walk_past_members(self) -> int | None:
        """Where the members end, found by walking their local headers from the start
        (``_walk_local_headers``), for an end record the tail search does not find
        behind more trailing bytes than its window holds. ``None`` when the walk does
        not get past the members. The tail search's step, at open: the walk is kept
        in ``_local_walk``, for ``_open_index`` to list when no end record follows or
        the one found cannot be used, and for a damaged directory's listing to go on
        from (``_past_damage``)."""
        walked = self._local_walk = self._walk_local_headers()
        return walked.members_end if walked.error is None else None

    def _walk_local_headers(self) -> _WalkedMembers:
        """Walk the members' local headers from the start: their offsets and
        descriptors, where they end and why the walk stopped.

        The walk is the one a read from a pipe makes, with no data decoded: a member
        whose local header states its size is seeked over, and a bit-3 member's data
        is scanned for its descriptor, so the walk reads at most the source once, as a
        pipe read does. Each local header is charged against ``max_members`` before
        its data is passed, as the pipe read charges it: past the limit the walk
        stops there and the archive opens. A pass that lists as it goes (streaming,
        from a file or a pipe) then yields the members before the limit and raises
        it; a random-access listing raises it with nothing listed, since there only
        damage keeps the members before it (``_materialize_members``). Made at most
        once per reader (``_local_walk``): by the tail search, for end records
        ``read_end_record`` refused when the search found them without it, or for a
        directory damaged part way.
        """
        max_members = self._config.listing_limits.max_members
        walked = _WalkedMembers()
        with self._lock:
            fp = self._fp
            if fp is None:
                raise _closed_archive_error()
            fp.seek(0)
            walk = LocalHeaderWalk(fp)
            while True:
                members_end = walk.source.offset
                walked.members_end = members_end
                try:
                    entry = walk.next_entry()
                except ArchiveyError as exc:
                    walked.error = exc
                    return walked
                if entry is None:
                    walked.after = walk.where()
                    return walked
                if max_members is not None and len(walked.offsets) >= max_members:
                    # Kept like any other stop: the archive opens, and its listing
                    # raises the limit, as at a directory entry past it.
                    walked.error = _max_members_error(
                        max_members, "ZIP local headers name"
                    )
                    return walked
                try:
                    descriptor = walk.skip_member(entry)
                except ArchiveyError as exc:
                    walked.add(entry.offset, None)
                    walked.cut = entry.index
                    walked.error = exc
                    return walked
                walked.add(entry.offset, descriptor)

    def _read_at(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes at absolute ``offset``, under the reader's lock.

        The parser's ``ReadAt``. The handle's position is not restored: every reader of
        the shared handle seeks before it reads (``SharedView`` asks ``tell()``).
        """
        with self._lock:
            fp = self._fp
            if fp is None:
                raise _closed_archive_error()
            fp.seek(offset)
            return read_exact(fp, n)

    def _refuse_declared_count_over_limit(self) -> None:
        """Refuse an end record declaring more entries than ``max_members``, as soon
        as it is read: at open from a file, at the end of a forward pass.

        Only when the directory is large enough to hold that many (46 bytes each): a
        count it cannot hold is a wrong field, which the walk reports as a count
        mismatch, and the walk charges the entries really there (DR-15b).
        """
        max_members = self._config.listing_limits.max_members
        end = self._end
        if (
            max_members is not None
            and end.entries_declared > max_members
            and end.cd_size >= end.entries_declared * CENTRAL_HEADER_SIZE
        ):
            error = ResourceLimitError(
                f"Listing limit reached: max_members={max_members} (ZIP end record "
                f"declares {end.entries_declared} entries)"
            )
            self._stamp_error_context(error)
            raise error

    def _report_zip64_damage(self) -> None:
        """Report ZIP64 records the classic end record stood in for
        (``EndRecord.zip64_damage``): it holds every value, none saturated, so the
        archive is listed from it."""
        end = self._end
        if end.zip64_damage is None:
            return
        # Set only after a whole ZIP64 locator was read right before the classic
        # record, from a file or a pipe's tail alike.
        locator_offset = end.eocd_offset - ZIP64_LOCATOR_SIZE
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
            message=(
                f"{end.zip64_damage}; the ZIP end record holds every value, so it is "
                "used instead."
            ),
            context=ArchiveEofContext(
                archive_name=self._archive_name,
                format="zip",
                expected_marker="zip64_end_of_central_directory",
                expected_bytes=0,
                observed_bytes=locator_offset,
                observed_kind="absent",
            ),
            logger=logger,
        )

    def _report_trailing_data(self) -> None:
        """Report a non-zero byte after the end record and its declared comment.

        ``ARCHIVE_TRAILING_DATA`` with ``expected_marker="zeros_to_eof"``, as after a
        TAR trailer or a 7z archive's end: a warning by default, refused under
        ``DiagnosticPolicy.STRICT`` (DR-3). Zero padding is silent, and the scan
        stops at ``MAX_TRAILING_SCAN`` bytes past the comment. 7-Zip warns on the same
        input; Info-ZIP ``unzip`` says nothing.
        """
        end = self._end
        if end.trailing == 0:
            return
        tail = SharedView(
            cast("BinaryIO", self._fp),
            start=end.eocd_offset + EOCD_SIZE + end.comment_declared,
            length=end.trailing,
            lock=self._lock,
        )
        try:
            found = first_nonzero_offset(tail)
        finally:
            tail.close()
        if found is not None:
            self._emit_trailing_data(found)

    def _emit_trailing_data(self, found: int) -> None:
        """Report a non-zero byte ``found`` bytes past the end record's comment; the
        seekable read and the forward walk both find it."""
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_TRAILING_DATA,
            message=(
                "ZIP archive continues past its end: a non-zero byte appears "
                f"{found} bytes after the end of central directory record and its "
                "comment. The listing does not account for it (this file may hold "
                "something appended to the archive)."
            ),
            context=ArchiveEofContext(
                archive_name=self._archive_name,
                format="zip",
                expected_marker="zeros_to_eof",
                expected_bytes=0,
                observed_bytes=found,
                observed_kind="nonzero",
            ),
            logger=logger,
        )

    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, io.UnsupportedOperation):
            if "seek" in str(exc):
                return StreamNotSeekableError("ZIP archives require a seekable source")
            # Any other unsupported operation says nothing about the archive. Without
            # this return it would reach the ValueError arm below (a subclass) and be
            # reported as corruption.
            return None
        if isinstance(exc, lzma.LZMAError):
            # No known path raises one here: the method-14 properties are typed by
            # decode_lzma_filter_properties (_zip_lzma_params) and the codec layer
            # types the decoder's own errors. Kept so a new one reads as corruption,
            # which the password ladder counts as a failed candidate under ZipCrypto.
            return CorruptionError(
                f"Error decompressing ZIP member: {exception_detail(exc)}"
            )
        if isinstance(exc, ValueError):
            # A raw ValueError from a member read is a malformed structure some layer
            # did not type. A closed handle is *not* corruption and never reaches this
            # arm: the shared boundary (BaseArchiveReader._raise_translated) maps a
            # closed source ahead of this translator (ArchiveyUsageError is
            # deliberately not an ArchiveyError, so it cannot be returned from here).
            return CorruptionError(
                f"Corrupt ZIP member structure: {exception_detail(exc)}"
            )
        if isinstance(exc, EOFError):
            # Short input, from any decoder a member read reaches. The codec layer maps
            # its own EOFError and no ZIP path is known to raise a bare one now; this
            # translator sees every exception a member stream raises, so a new source
            # still reads as truncation rather than escaping untyped.
            return TruncatedError(f"Truncated ZIP member data: {exception_detail(exc)}")
        return None

    def _iter_members(self) -> Iterator[ArchiveMember]:
        """Walk the central directory, yielding each member as its entry is parsed.

        ``ListingLimits`` therefore see members as they are read. The walk records
        each header offset for the overlap guard, and charges ``max_members`` itself,
        in every mode, because the offsets are held in every mode: it raises before
        building one member more than the limit. Damage raises after the
        members before it, as a cut TAR does, and after the members the local headers
        hold past it (``_past_damage``); the end-record findings come after the last
        member. A ZIP with no end record has no directory to walk: its members
        come from the local headers the walk at open found (``_iter_walked``).
        """
        walked = self._salvage
        if walked is not None:
            yield from self._iter_walked(walked)
            return
        walk = self._directory_walk()
        offsets: array[int] = array("q")
        max_members = self._config.listing_limits.max_members
        try:
            for entry in walk:
                # The position is passed down because it is the id `_register_member`
                # stamps, so a diagnostic raised while typing can name the member
                # before it has an id.
                index = entry.index
                if max_members is not None and index >= max_members:
                    raise _max_members_error(max_members)
                member = self._to_member(entry, index)
                offset = entry.header_offset
                # ``_bound_offset`` only for an offset out of its range (rare).
                offsets.append(
                    offset if 0 <= offset <= MAX_DATA_OFFSET else _bound_offset(offset)
                )
                yield member
        except CorruptionError as damage:
            # A directory damaged part way: the members after the damage are the
            # ones the local headers hold, as a read from a pipe lists them, then
            # the damage is raised (``_past_damage``).
            past = self._past_damage_found = self._past_damage(offsets)
            self._set_bounds(past.bounds, count=None)
            for index, offset in enumerate(past.offsets):
                if index < len(offsets):
                    continue
                yield self._member_past_damage(past, index, offset)
            raise self._error_past_damage(past, damage)
        except (UnsupportedFeatureError, ResourceLimitError):
            # The members before the stop keep their bound, from the offsets the walk
            # read (``_DataBounds``).
            self._set_bounds(offsets, count=None)
            raise
        self._set_bounds(offsets, count=walk.entries_read)
        self._drop_local_walk()
        # The end record and the central directory disagree. Info-ZIP unzip and 7-Zip
        # list and test every member, then report the damage; so does this, once the
        # members are out, and a strict policy refuses the archive.
        for finding in walk.findings:
            self._emit_walk_finding(finding)

    def _past_damage(self, listed: array[int]) -> _PastDamage:
        """The members past a directory damaged after the entries at ``listed``.

        The local headers are walked once per reader, as for a ZIP with no end record
        (``_local_walk``); a member the directory already listed, by offset, is not
        listed again. ``offsets`` holds the directory's offsets, then the new ones in
        file order, so a member's id is its position there and the overlap guard
        bounds every member listed (``_DataBounds``). The listing and the index pass
        stop at the same entry, so both build the same members past the damage.
        """
        with self._past_damage_lock:
            walked = self._local_walk
            if walked is None:
                walked = self._local_walk = self._walk_local_headers()
        seen = set(listed)
        found = set(walked.offsets)
        offsets = array("q", listed)
        # The walk steps over each member's data by the size its own local header
        # states, so a real header it did not reach (inside another member's data,
        # or past where it stopped) is read for: it keeps bounding its neighbours,
        # and two entries over it stay an overlap.
        bounds = array(
            "q",
            (
                offset if offset in found or self._holds_local_header(offset) else -1
                for offset in listed
            ),
        )
        positions: list[int] = []
        cut: int | None = None
        for position, offset in enumerate(walked.offsets):
            if offset in seen:
                continue
            if position == walked.cut:
                cut = len(offsets)
            positions.append(position)
            offsets.append(offset)
            bounds.append(offset)
        return _PastDamage(walked, offsets, bounds, positions, cut)

    def _holds_local_header(self, offset: int) -> bool:
        """Whether a local header's signature starts at ``offset``. Every local header
        comes before the directory, so an offset at or past it is not read: a source
        on disk cannot seek to every offset a directory entry can state."""
        return (
            0 <= offset < self._end.cd_start
            and self._read_at(offset, 4) == LOCAL_HEADER_SIGNATURE
        )

    def _drop_local_walk(self) -> None:
        """Free the walk over the local headers: the directory was walked whole, so
        no listing goes on past damage from it."""
        with self._past_damage_lock:
            self._local_walk = None

    def _member_past_damage(
        self, past: _PastDamage, index: int, offset: int
    ) -> ArchiveMember:
        """The member at ``offset`` past the damage, built from its local header as
        ``_iter_walked`` builds one."""
        entry = local_entry_at(self._read_at, index, offset)
        member = self._local_member(entry, index)
        if entry.deferred and index != past.cut:
            position = past.positions[index - (len(past.offsets) - len(past.positions))]
            self._apply_descriptor(member, past.walked, position)
        return member

    def _error_past_damage(
        self, past: _PastDamage, damage: CorruptionError
    ) -> ArchiveyError:
        """What the listing raises after the members past the damage: the directory's
        damage, so the listing's error stays a ``CorruptionError`` and keeps the
        members listed. A limit the walk over the local headers met is raised
        instead, as at a directory entry past it. Any other error that stopped the
        walk is either about the member whose data it could not get past, whose read
        raises it (``_open_member``), or a local header it could not read (one whose
        name or extra field runs past the end), past which nothing more is listed."""
        if isinstance(past.walked.error, ResourceLimitError):
            return self._walked_error(past.walked, None)
        return damage

    def _iter_walked(self, walked: _WalkedMembers) -> Iterator[ArchiveMember]:
        """The members of a ZIP with no end record, from the local headers the walk at
        open found, then the error that ended the walk (``_list_walked_members``).

        Each member is built as a read from a pipe builds it before the directory
        arrives (``_local_member``), with a bit-3 member's CRC and sizes from its data
        descriptor; nothing the directory alone holds is guessed. A member whose data
        the walk could not get past is listed last, as the pipe lists it, and its
        read raises the walk's error (``_open_member``).
        """
        cut = walked.cut
        name: str | None = None
        for index, offset in enumerate(walked.offsets):
            entry = local_entry_at(self._read_at, index, offset)
            member = self._local_member(entry, index)
            if entry.deferred and index != cut:
                self._apply_descriptor(member, walked, index)
            name = member.name
            yield member
        raise self._walked_error(walked, name if cut is not None else None)

    def _walked_error(
        self, walked: _WalkedMembers, member_name: str | None, *, corrupt: bool = False
    ) -> ArchiveyError:
        """A fresh copy of the error that ended the walk, stamped: the listing raises
        it once per walk, and a cut member's read raises it too. ``corrupt`` makes a
        ``TruncatedError`` a ``CorruptionError``, for a source known not to be cut."""
        error = walked.error
        assert error is not None
        kind = type(error)
        if corrupt and isinstance(error, TruncatedError):
            kind = CorruptionError
        fresh = kind(raw_message_of(error))
        self._stamp_error_context(fresh, member_name)
        return fresh

    @staticmethod
    def _apply_descriptor(
        member: ArchiveMember, walked: _WalkedMembers, index: int
    ) -> None:
        """Give a bit-3 member the CRC and sizes its data descriptor holds, which a
        read checks the data against, as the directory's would be."""
        crc = walked.crcs[index]
        compressed_size = walked.compressed_sizes[index]
        file_size = walked.file_sizes[index]
        loc = cast("_ZipLocator", member._raw)
        loc.crc = crc
        loc.compressed_size = compressed_size
        loc.file_size = file_size
        member.compressed_size = compressed_size
        member.size = file_size
        if _crc_is_digest(member.type, file_size, crc, loc.aes):
            member.hashes = {HashAlgorithm.CRC32: crc32_digest(crc)}

    def _directory_walk(self) -> CentralDirectoryWalk:
        """A walk over the directory that reads the name of the local header an offset
        in the directory points at wherever a length or offset field may be wrong: a
        corrected offset, an entry no central header follows, and the first header a
        signature inside an entry's fields chains to."""
        read_at = self._read_at
        # The last header read, by offset: the walk asks for a header's name and then
        # for where its data starts, and the two share one read.
        last: list[tuple[int, tuple[bytes, int] | None]] = []

        def probe(offset: int) -> tuple[bytes, int] | None:
            if not last or last[0][0] != offset:
                last[:] = [(offset, local_header_at(read_at, offset))]
            return last[0][1]

        def name_at(offset: int) -> bytes | None:
            found = probe(offset)
            return None if found is None else found[0]

        def data_start_at(offset: int) -> int | None:
            found = probe(offset)
            return None if found is None else found[1]

        return CentralDirectoryWalk(
            read_at,
            self._end,
            local_name_at=name_at,
            local_data_start_at=data_start_at,
        )

    def _emit_walk_finding(self, finding: WalkFinding) -> None:
        """One disagreement between the end record and the central directory."""
        end = self._end
        archive_name = self._archive_name
        if isinstance(finding, DirectoryOffsetWrapped):
            self._diagnostics_collector.emit(
                code=DiagnosticCode.ARCHIVE_OFFSET_WRAPPED,
                message=(
                    f"ZIP end record stores the central directory's offset as "
                    f"{finding.stored}, but the directory is at {finding.corrected}: "
                    "the archive was written past 4 GiB without ZIP64, and its offsets "
                    "were corrected."
                ),
                context=OffsetWrapContext(
                    archive_name=archive_name,
                    format="zip",
                    record="central_directory",
                    stored_offset=finding.stored,
                    corrected_offset=finding.corrected,
                ),
                logger=logger,
            )
            return
        if isinstance(finding, EntryCountMismatch):
            record = "ZIP64 end of central directory" if finding.zip64 else "end record"
            message = (
                f"ZIP {record} declares {finding.declared} entries, but the central "
                f"directory holds {finding.read}."
            )
            context = ArchiveEofContext(
                archive_name=archive_name,
                format="zip",
                expected_marker="end_of_central_directory",
                expected_bytes=0,
                observed_bytes=end.eocd_offset,
                observed_kind="nonzero",
            )
        else:
            message = (
                f"ZIP archive comment is declared as {finding.declared} bytes, but the "
                f"file ends {finding.available} bytes after the end record; the "
                "comment is cut short."
            )
            context = ArchiveEofContext(
                archive_name=archive_name,
                format="zip",
                expected_marker="end_of_central_directory",
                expected_bytes=EOCD_SIZE + finding.declared,
                observed_bytes=EOCD_SIZE + finding.available,
                observed_kind="short",
            )
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
            message=message,
            context=context,
            logger=logger,
        )

    def _iter_with_data(
        self, copies: FileCopyPass = DEFAULT_FILE_COPY_PASS
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """Read the whole directory before the first member's data, then go forward.

        The directory is read once and member data in file order after it, so the
        only backward move after the tail reads is the seek to the first local header,
        and the overlap guard's bounds are known before any member opens. The walk
        reads the directory one chunk at a time, so pulling it alongside the data
        would go back to the tail between members. The listing is final before the
        first yield, ``is_current`` included. A source that cannot seek is read by
        ``ZipForwardReader``, which overrides this.
        """
        if self._streaming:
            self._walk_ahead()
        yield from super()._iter_with_data(copies)

    def _emit_offset_wrapped(
        self, member: ArchiveMember, entry: CentralEntry, index: int
    ) -> None:
        """``ARCHIVE_OFFSET_WRAPPED`` for a member whose local header offset the walk
        corrected (``CentralDirectoryWalk``)."""
        # Both offsets as the directory counts them, without the stub's length.
        stored = entry.stored_offset
        corrected = stored + entry.offset_correction
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_OFFSET_WRAPPED,
            message=(
                f"ZIP member {quoted(member.name)} stores its local header offset as "
                f"{stored}, but the header is at {corrected}: the archive was written "
                "past 4 GiB without ZIP64, and the offset was corrected."
            ),
            context=OffsetWrapContext(
                archive_name=self._archive_name,
                format="zip",
                member_name=member.name,
                member_id=index,
                record="local_header",
                stored_offset=stored,
                corrected_offset=corrected,
            ),
            member=member,
            attach_to_member=True,
            logger=logger,
        )

    def _emit_size_wrapped(
        self, member: ArchiveMember, entry: CentralEntry, index: int
    ) -> None:
        """``MEMBER_SIZE_WRAPPED`` for a member of a macOS Archive Utility ZIP whose
        compressed size the walk measured, or whose size :func:`_wrapped_size` moved or
        left unknown."""
        stored_compressed = entry.compressed_size - entry.compressed_size_correction
        size = member.size
        stored = (
            f"ZIP member {quoted(member.name)} stores {stored_compressed} bytes "
            f"decoding to {entry.file_size}"
        )
        if size is None:
            # Nothing was found wrapped: the writer keeps only the low 32 bits, and
            # the compressed size allows a size past 4 GiB, whatever the archive's.
            message = (
                f"{stored}; macOS Archive Utility stores sizes modulo 2**32 and "
                f"{entry.compressed_size} bytes of deflate can decode to more than "
                "4 GiB, so the size is unknown until a read counts it."
            )
        else:
            message = (
                f"{stored}, but it holds {entry.compressed_size} bytes and decodes "
                f"to {size}: the archive was written past 4 GiB without ZIP64."
            )
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_SIZE_WRAPPED,
            message=message,
            context=SizeWrapContext(
                archive_name=self._archive_name,
                format="zip",
                member_name=member.name,
                member_id=index,
                stored_compressed_size=stored_compressed,
                compressed_size=entry.compressed_size,
                stored_size=entry.file_size,
                size=size,
            ),
            member=member,
            attach_to_member=True,
            logger=logger,
        )

    def _set_bounds(self, offsets: array[int], *, count: int | None) -> None:
        """Record the offsets a listing walk read, and what it says of the count.

        ``count`` is ``None`` for a walk that ended in damage or at ``max_members``: the
        count is then known to be unknowable. The index pass's early stop sets the same
        state directly (``_index_pass``).
        """
        with self._index_lock:
            if self._bounds is None:
                self._bounds = _DataBounds(offsets, cd_start=self._end.cd_start)
            if not self._count_known:
                self._member_count = count
                self._count_known = True

    def _data_bounds(self) -> _DataBounds:
        """The overlap guard's bounds, walking the directory once more if needed.

        After a listing that ran to the end (or to damage, or to ``max_members``) the
        bounds are already known, and every member open comes after one: random access
        lists before it opens, and a streaming pass walks ahead (``_iter_with_data``).
        Otherwise, when ``member_count`` is asked for first, an **index pass** reads the
        directory's entries again, builds no members and keeps only the offsets and the
        count. It stops where the listing
        walk stops, at damage or at ``max_members``, and keeps the offsets before that
        point (``_DataBounds``).
        """
        bounds = self._bounds
        if bounds is not None:
            return bounds
        with self._index_lock:
            if self._bounds is None:
                self._index_pass()
            assert self._bounds is not None
            return self._bounds

    def _index_pass(self) -> None:
        """Walk the directory for its offsets and count alone (``_data_bounds``).

        Called under ``_index_lock``.
        """
        max_members = self._config.listing_limits.max_members
        walk = self._directory_walk()
        offsets: array[int] = array("q")
        try:
            for entry in walk:
                if max_members is not None and entry.index >= max_members:
                    # The listing raises the limit itself, at the same entry.
                    break
                offsets.append(_bound_offset(entry.header_offset))
            else:
                self._bounds = _DataBounds(offsets, cd_start=self._end.cd_start)
                self._member_count = walk.entries_read
                self._count_known = True
                self._drop_local_walk()
                return
        except CorruptionError:
            # The listing raises the damage itself, at the same entry, after the
            # members the local headers hold past it.
            offsets = self._past_damage(offsets).bounds
        except UnsupportedFeatureError:
            # The listing raises it itself, at the same entry.
            pass
        # Stopped early: the bounds are the entries' before the stop, as after a listing
        # that met it; the count is unknown.
        self._bounds = _DataBounds(offsets, cd_start=self._end.cd_start)
        self._count_known = True

    def _known_member_count(self) -> int | None:
        """Entries a complete walk read; ``None`` when the walk fails or stops at
        ``max_members`` (DR-1: absence over a wrong value)."""
        if not self._count_known:
            self._data_bounds()
        # Under the lock: another thread's pass may have set the bounds and not yet the
        # count, and it sets both under the lock.
        with self._index_lock:
            return self._member_count

    def _sniff_unflagged_name(
        self, raw_name: bytes, cp437_decoded: str
    ) -> tuple[str, str | None]:
        """Decode an unflagged ZIP name: prefer valid UTF-8, else the caller's
        ``encoding=``, else the configured legacy fallback (default cp437).

        Returns ``(name, inferred_encoding)`` where ``inferred_encoding`` is the encoding
        archivey chose over the one the name would otherwise have had (for the
        diagnostic), else ``None``. The caller's ``encoding=`` is not an inference, so it
        gives ``None``. UTF-8 is self-validating, so a clean decode is strong evidence the bytes
        are UTF-8; legacy bytes that are coincidentally valid UTF-8 are the documented
        residual risk. Pure ASCII (and any other bytes that decode identically under
        UTF-8 and cp437) is not an override — both encodings agree, so no diagnostic.
        """
        try:
            utf8_decoded = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            text, codec = self._decode_unflagged_legacy(raw_name, lambda: cp437_decoded)
            # The caller's encoding= is not an inference, nor is the cp437 default.
            return text, None if codec in (self._encoding, "cp437") else codec
        if utf8_decoded == cp437_decoded:
            return utf8_decoded, None
        return utf8_decoded, "utf-8"

    def _decode_unflagged_legacy(
        self, raw: bytes, cp437_decoded: Callable[[], str]
    ) -> tuple[str, str]:
        """Decode unflagged bytes that are not valid UTF-8: the caller's ``encoding=``,
        else the configured legacy fallback (default cp437).

        ``cp437_decoded`` is called only when the cp437 reading is the answer. Returns
        ``(text, codec)``: ``codec`` is the caller's ``encoding=``, the configured
        fallback or ``"cp437"``, whichever decoded ``text``. A byte the chosen codec
        does not define survives as a lone surrogate.
        """
        if self._encoding is not None:
            try:
                return (
                    raw.decode(self._encoding, errors="surrogateescape"),
                    self._encoding,
                )
            except UnicodeError:
                # A codec that refuses the surrogateescape handler outright
                # (``idna``): fall through to the configured fallback.
                pass
        fallback = self._config.zip_unflagged_fallback_encoding
        if fallback.lower().replace("-", "").replace("_", "") in {
            "cp437",
            "437",
            "ibm437",
        }:
            return cp437_decoded(), "cp437"
        try:
            return raw.decode(fallback, errors="surrogateescape"), fallback
        except (LookupError, UnicodeError):
            # An unknown fallback encoding name, or a codec that refuses the
            # surrogateescape handler outright (``idna``): keep the cp437 decode
            # rather than fail.
            return cp437_decoded(), "cp437"

    def _decode_unflagged_comment(self, raw: bytes) -> str:
        """Decode a comment with no UTF-8 flag, or one whose name's bytes refute the flag,
        the way an unflagged name is decoded.

        A comment is not a name, so no ``member_name_encoding_inferred`` is reported.
        As for a name, ASCII skips the sniff (UTF-8 and cp437 agree on it), and the
        cp437 decode runs only when it is the answer.
        """
        if raw.isascii():
            return raw.decode("ascii")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return self._decode_unflagged_legacy(raw, lambda: raw.decode("cp437"))[0]

    def _decode_member_name(
        self, entry: CentralEntry, fields: Sequence[ExtraField] | None = None
    ) -> _DecodedName:
        """The entry's name as archivey reads it: the source of ``member.name`` and of
        the directory marker. It reports nothing, so the end-record findings can name
        an entry the listing already decoded. ``fields`` is ``entry.extra`` split, for
        a caller that has split it already."""
        raw_name = entry.name
        is_utf8_flagged = bool(entry.flags & _ZIP_MASK_UTF8)
        if raw_name.isascii():
            # The common case, decided without the steps below: ASCII reads the same
            # under every codec, so only a Unicode Path field can rename it.
            if not is_utf8_flagged and entry.extra:
                if fields is None:
                    fields = split_extra_fields(entry.extra)
                has_unicode_path = any(
                    field.tag == _ZIP_EXTRA_UNICODE_PATH for field in fields
                )
            else:
                has_unicode_path = False
            if not has_unicode_path:
                # Positional, in _DecodedName's order (pinned by a test). The pragma:
                # a NamedTuple is a tuple.
                # pyrefly: ignore[bad-specialization]
                return _new_tuple(
                    _DecodedName,
                    (raw_name.decode("ascii"), raw_name, None, None, None, None, False),
                )
        if is_utf8_flagged:
            try:
                decoded = raw_name.decode("utf-8")
            except UnicodeDecodeError:
                # The flag says UTF-8 and the bytes are not (a code-page name under a
                # wrong flag): decoded the way an unflagged name that is not UTF-8 is,
                # and reported (format-zip spec). The Unicode Path field stays unread,
                # as for any flagged name.
                text, codec = self._decode_unflagged_legacy(
                    raw_name, lambda: raw_name.decode("cp437")
                )
                return _DecodedName(
                    text=text,
                    raw_name=raw_name,
                    alternate_raw_name=None,
                    inferred_encoding=codec,
                    declared_encoding="utf-8",
                    unicode_extra_fault=None,
                    unicode_path_used=False,
                )
        else:
            decoded = raw_name.decode("cp437")
        name_source = decoded
        # An unflagged name with an Info-ZIP Unicode Path extra field (0x7075) whose CRC
        # matches the stored bytes is named by the field, ahead of the sniff and of an
        # explicit encoding=, as 7-Zip, Info-ZIP unzip and stdlib zipfile 3.12+ do. The
        # field's UTF-8 bytes become raw_name, so name stays raw_name decoded, and the
        # header's bytes are kept in extra. The field is authoritative, not a guess, so
        # no member_name_encoding_inferred diagnostic is emitted for a name taken from
        # it; the header's spelling stays visible as extra["alternate_raw_name"].
        # A malformed field is dropped with a MEMBER_HEADER_RECORD_SKIPPED diagnostic
        # and the name decoded as if it were absent (`_unicode_path_name`). Only the
        # central directory's field is read: the listing comes from there, and the
        # local header's name is only checked against the central one.
        alternate_raw_name: bytes | None = None
        unicode_name: bytes | None = None
        unicode_extra_fault: str | None = None
        if not is_utf8_flagged and entry.extra:
            if fields is None:
                fields = split_extra_fields(entry.extra)
            unicode_path = _unicode_path_name(fields, raw_name)
            unicode_name = unicode_path.name
            unicode_extra_fault = unicode_path.fault
            if unicode_name is not None:
                name_source = unicode_name.decode("utf-8")
                if unicode_name != raw_name:
                    alternate_raw_name, raw_name = raw_name, unicode_name
        # Many tools write UTF-8 names without setting the UTF-8 flag (APPNOTE says cp437),
        # so cp437 would yield mojibake. With no authoritative signal (flag clear and no
        # Unicode Path field), prefer UTF-8 when the stored bytes are valid UTF-8, else
        # the caller's encoding= or a configurable legacy fallback. A set flag over valid
        # UTF-8 is honored as-is (one the bytes refute returned above). ASCII bytes
        # decode identically under UTF-8 and cp437 — skip the sniff.
        inferred_encoding: str | None = None
        if not is_utf8_flagged and unicode_name is None and not raw_name.isascii():
            name_source, inferred_encoding = self._sniff_unflagged_name(
                raw_name, decoded
            )
        return _DecodedName(
            text=name_source,
            raw_name=raw_name,
            alternate_raw_name=alternate_raw_name,
            inferred_encoding=inferred_encoding,
            declared_encoding=None,
            unicode_extra_fault=unicode_extra_fault,
            unicode_path_used=unicode_name is not None,
        )

    def _directory_data_reach(self, entry: CentralEntry) -> str | None:
        """Where the data of the directory ``entry`` describes can be read, for the
        ``MEMBER_DIRECTORY_DATA_IGNORED`` message, or ``None`` for the shared wording.

        ``None`` here: this reader lists from the central directory before any pass,
        so a pass knows the size and yields the bytes. The pipe reader overrides it.
        """
        return None

    def _to_member(self, entry: CentralEntry, index: int) -> ArchiveMember:
        external_attr = entry.external_attr
        full_mode = external_attr >> 16
        # CentralEntry.create_system, inlined: a property call per member is measurable
        # on a 20 000-entry listing.
        host = entry.version_made_by >> 8
        is_unix = host == 3
        # Permission bits only; None when no usable Unix mode was stored. A Unix host
        # with a zero high word stored DOS attribute bits at most, which unzip 6.00
        # also reads as "no Unix mode" (it falls back to the DOS bits), so the entry
        # gets no mode rather than 000.
        mode = stat.S_IMODE(full_mode) if (full_mode and is_unix) else None

        create_system = _CREATE_SYSTEM_BY_VALUE.get(host, CreateSystem.UNKNOWN)
        # Split once: the name, the times, the owner and the leftovers all read it.
        fields = split_extra_fields(entry.extra)
        decoded_name = self._decode_member_name(entry, fields)
        name_source = decoded_name.text
        raw_name = decoded_name.raw_name
        stored_as_directory = _stored_as_directory(name_source, create_system)

        # A Windows reparse point (symlink or junction) is marked by a DOS attribute
        # bit in the low word, and 7-Zip's `-snl` is the only common writer that sets
        # it. Checked before the directory marker: a directory reparse point carries
        # both and is a link, not a directory — its trailing "/" is then dropped by
        # normalize_member_name, which is how 7z already presents the same member.
        # The type is provisional: the data decides, in `_apply_reparse_data`, whether
        # the entry really holds a link buffer, and a member that does not goes back to
        # `reparse_fallback`.
        reparse_fallback = (
            _reparse_fallback_type(
                external_attr, create_system, stored_as_directory=stored_as_directory
            )
            if external_attr & FILE_ATTRIBUTE_REPARSE_POINT
            else None
        )
        is_reparse_point = reparse_fallback is not None

        special = special_file_type(full_mode) if is_unix else None
        if is_reparse_point:
            member_type = MemberType.SYMLINK
        elif stored_as_directory:
            member_type = MemberType.DIRECTORY
        elif is_unix and stat.S_ISLNK(full_mode):
            member_type = MemberType.SYMLINK
        elif special is not None and entry.file_size == 0:
            # A device, FIFO or socket with no data. unzip writes these as empty regular
            # files, but every format types them OTHER, so extraction refuses them
            # everywhere. With data the entry is a FILE: ``zip -FI`` stores a named
            # pipe's content under the pipe's FIFO mode, and every extractor writes the
            # bytes (DR-25). ``extra["special_file_type"]`` keeps the stored type.
            member_type = MemberType.OTHER
        else:
            member_type = MemberType.FILE
        # Convert "\\" to "/" only for DOS/Windows-origin entries (where it is a separator);
        # a Unix (or other) entry keeps a backslash as a literal filename character.
        backslash_is_separator = host in _BACKSLASH_SEPARATOR_HOSTS
        name = normalize_member_name(
            name_source, member_type, backslash_is_separator=backslash_is_separator
        )

        method = entry.method
        aes_info = parse_winzip_aes_extra(entry.extra) if method == 99 else None
        if aes_info is not None:
            # Method 99 is a wrapper; surface the underlying compression algorithm.
            algo = _ZIP_COMPRESSION_ALGOS.get(
                aes_info.actual_method, CompressionAlgorithm.UNKNOWN
            )
            compression: tuple[CompressionMethod, ...] = (CompressionMethod(algo=algo),)
        else:
            compression = _ZIP_COMPRESSION_TUPLES.get(method, _UNKNOWN_COMPRESSION)

        modified, accessed, ntfs_ctime, ut_ctime, ts_issues, time_tags = (
            _zip_timestamps(entry, name, fields)
        )
        created, ctime = _zip_created(create_system, ntfs_ctime, ut_ctime)
        # Surface the central-directory CRC-32 as a stored digest (archive-data-model:
        # HashAlgorithm.CRC32 → 4 big-endian bytes), so a dedupe pass can key on it
        # without decompressing (VISION "hashes without decompression"). Only for
        # members with data: FILE and SYMLINK, and a directory whose header declares
        # some (``open()`` delivers it, so the read is digest-checked like a file's).
        # A directory's CRC field is 0 by convention, so a zero there over declared
        # data is no digest, not a failing one: the member gets no crc32. Whether that
        # leaves the read unchecked depends on the entry's other checks: a WinZip AES
        # member (method 99, AE-1 and AE-2 alike) carries an HMAC over its bytes, so
        # only an entry whose CRC was its only check reports ``DIGEST_UNVERIFIABLE``
        # below (design principle 1: say so instead of implying the bytes were checked;
        # DR-4: CorruptionError is for damage). AE-2 stores CRC 0 by design and relies
        # on the HMAC — never surface a fake crc32 for it.
        hashes: dict[HashAlgorithm, bytes] = {}
        is_ae2 = aes_info is not None and aes_info.is_ae2
        crc = entry.crc
        # A central CRC-32 of 0 over a file is 0 for its data only once in 2**32;
        # the local header may hold the real value (``_local_crc_stands_in``).
        local_crc = (
            self._local_crc_for(entry)
            if crc == 0
            and entry.file_size > 0
            and not is_ae2
            and member_type in (MemberType.FILE, MemberType.SYMLINK)
            else None
        )
        if local_crc is not None:
            crc = local_crc
        directory_data = member_type is MemberType.DIRECTORY and entry.file_size > 0
        directory_zero_crc = directory_data and entry.crc == 0
        directory_without_anchor = directory_zero_crc and aes_info is None
        if _crc_is_digest(member_type, entry.file_size, entry.crc, aes_info):
            hashes = {HashAlgorithm.CRC32: crc32_digest(crc)}
        extra = MemberExtra({"zip.compress_type": method})
        if special is not None:
            # Whatever the type decided above, the key records what the mode said, so
            # a reparse point that settles or re-types to FILE keeps it (DR-25).
            extra[EXTRA_SPECIAL_FILE_TYPE] = special
        if decoded_name.alternate_raw_name is not None:
            extra[EXTRA_ALTERNATE_RAW_NAME] = decoded_name.alternate_raw_name
        if is_reparse_point:
            # From the attribute bit alone, so it is known while listing and stays true
            # even when the data turns out not to be a link buffer and the member is
            # re-typed. `is_junction` needs the tag inside that data, and is set later.
            extra[EXTRA_IS_REPARSE_POINT] = True
        if aes_info is not None:
            extra["zip.aes_vendor_version"] = aes_info.vendor_version
            extra["zip.aes_strength"] = aes_info.strength
            extra["zip.aes_actual_method"] = aes_info.actual_method
        size: int | None = entry.file_size
        size_unknown: _UnknownSize | None = None
        size_wrapped = False
        if (
            entry.method in _ARCHIVE_UTILITY_METHODS
            and not self._end.zip64
            and written_by_archive_utility(entry)
        ):
            size, size_unknown = _wrapped_size(entry)
            if size_unknown is not None and not hashes:
                # An unknown size is filled in only once a read's CRC-32 matches;
                # with none to check, the stored size stays.
                size, size_unknown = entry.file_size, None
            size_wrapped = size != entry.file_size or bool(
                entry.compressed_size_correction
            )
            if size_unknown is not None:
                extra[EXTRA_SIZE_MOD_2_32] = entry.file_size
        # Skip defaulted None/False kwargs on the listing hot path (perf review L2).
        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=raw_name,
            size=size,
            compressed_size=entry.compressed_size,
            compression=compression,
            hashes=hashes,
            extra=extra,
            # What reading the data needs, so _open_member needs no name/id lookup
            # table; not the entry, whose extra field and comment would stay alive.
            _raw=_ZipLocator(
                index=index,
                header_offset=entry.header_offset,
                compressed_size=entry.compressed_size,
                file_size=entry.file_size if size is None else size,
                crc=crc,
                flags=entry.flags,
                method=method,
                dos_time=entry.dos_time,
                name=entry.name,
                aes=aes_info,
                # The bit test repeats the callee's first line, to skip the call for
                # an unencrypted member; it must stay a necessary condition there.
                strong_encryption=bool(entry.flags & _ZIP_MASK_ENCRYPTED)
                and _uses_strong_encryption(entry.flags, entry.extra),
                reparse_fallback=reparse_fallback,
                size_unknown=size_unknown,
            ),
        )
        if size_unknown is not None:
            # A verified full read fills ``size`` in (``fill_size``): not final yet.
            member._size_unread = True
        if modified is not None:
            member.modified = modified
        if accessed is not None:
            member.accessed = accessed
        if created is not None:
            member.created = created
        if ctime is not None:
            member.ctime = ctime
        if mode is not None:
            member.mode = mode
        owner = _zip_owner(fields)
        if owner.ids is not None:
            member.uid, member.gid = owner.ids
        unicode_comment = _NO_UNICODE_PATH
        if entry.comment:
            # APPNOTE puts the member comment under the name's UTF-8 flag, so a flag
            # the name's bytes refute is not trusted for the comment either.
            if entry.flags & _ZIP_MASK_UTF8 and decoded_name.declared_encoding is None:
                member.comment = _decode_with_fallback(entry.comment)
            else:
                # A comment with bit 11 clear and an Info-ZIP Unicode Comment field
                # (0x6375) whose CRC matches the stored bytes takes the field's text,
                # ahead of the sniff and of encoding=, as 7-Zip does. The rule is the
                # Unicode Path field's for a name: the field is read only when bit 11 is
                # clear, so a flag the name refutes leaves both fields unread, as 7-Zip
                # 23.01 does. A malformed field is dropped and reported below.
                if entry.extra and not entry.flags & _ZIP_MASK_UTF8:
                    unicode_comment = _unicode_comment_text(fields, entry.comment)
                member.comment = (
                    unicode_comment.name.decode("utf-8")
                    if unicode_comment.name is not None
                    else self._decode_unflagged_comment(entry.comment)
                )
        if entry.extra:
            used_tags = list(time_tags)
            if owner.tag is not None:
                used_tags.append(owner.tag)
            if decoded_name.unicode_path_used:
                used_tags.append(_ZIP_EXTRA_UNICODE_PATH)
            if unicode_comment.name is not None:
                used_tags.append(_ZIP_EXTRA_UNICODE_COMMENT)
            unparsed = _unparsed_extra_fields(fields, used_tags)
            if unparsed is not None:
                extra["zip.extra_fields"] = unparsed
        if _is_encrypted_entry(entry.flags, method):
            member.is_encrypted = True
        member.create_system = create_system
        # Each report below names the member by its position in the walk, because
        # registration has not stamped `_member_id` yet and stamps that same position.
        inferred_encoding = decoded_name.inferred_encoding
        declared_encoding = decoded_name.declared_encoding
        if inferred_encoding is not None and declared_encoding is not None:
            self._emit_name_encoding_inferred(
                member,
                index,
                inferred_encoding=inferred_encoding,
                passed_over=declared_encoding,
                message=(
                    f"ZIP member name decoded as {inferred_encoding!r}: its UTF-8 flag "
                    f"is set but the name is not valid UTF-8: {quoted(member.name)}"
                ),
            )
        elif inferred_encoding is not None:
            # The codec the name would otherwise have had: for a UTF-8 reading, the
            # caller's encoding= or the configured fallback; for a configured fallback,
            # the cp437 APPNOTE default.
            passed_over = (
                (self._encoding or self._config.zip_unflagged_fallback_encoding)
                if inferred_encoding == "utf-8"
                else "cp437"
            )
            self._emit_name_encoding_inferred(
                member,
                index,
                inferred_encoding=inferred_encoding,
                passed_over=passed_over,
                message=(
                    f"ZIP member name decoded as {inferred_encoding!r} rather than "
                    f"{passed_over!r} (UTF-8 flag not set): {quoted(member.name)}"
                ),
            )
        unicode_extra_fault = decoded_name.unicode_extra_fault
        if unicode_extra_fault is not None:
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=(
                    f"The Unicode Path extra field (0x7075) of ZIP member "
                    f"{quoted(member.name)} is malformed and was dropped "
                    f"({unicode_extra_fault}); the name was decoded from the header."
                ),
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    record="unicode_path",
                    record_id=_ZIP_EXTRA_UNICODE_PATH,
                    reason=unicode_extra_fault,
                ),
                member=member,
                attach_to_member=True,
                logger=logger,
            )
        if unicode_comment.fault is not None:
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=(
                    f"The Unicode Comment extra field (0x6375) of ZIP member "
                    f"{quoted(member.name)} is malformed and was dropped "
                    f"({unicode_comment.fault}); the comment was decoded from the "
                    f"header."
                ),
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    record="unicode_comment",
                    record_id=_ZIP_EXTRA_UNICODE_COMMENT,
                    reason=unicode_comment.fault,
                ),
                member=member,
                attach_to_member=True,
                logger=logger,
            )
        if owner.fault is not None:
            owner_tag, owner_fault = owner.fault
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=(
                    f"The Unix owner extra field (0x{owner_tag:04x}) of ZIP member "
                    f"{quoted(member.name)} is malformed and was dropped "
                    f"({owner_fault}); the member has no owner ids."
                ),
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    record="unix_owner",
                    record_id=owner_tag,
                    reason=owner_fault,
                ),
                member=member,
                attach_to_member=True,
                logger=logger,
            )
        # member.name is still ``name``: this is the callee's own early return, kept
        # here to skip the call for the common unchanged name.
        if name != name_source:
            emit_member_name_normalized(
                self._diagnostics_collector,
                member=member,
                # The decoded name before normalization, from whichever source named
                # it; the cp437 text a sniff or the Unicode Path field replaced is not
                # a normalization.
                presented_name=name_source,
                archive_name=self._archive_name,
                member_id=index,
                # A directory reparse point is stored with the directory convention's
                # trailing "/" and is still a link, so normalization drops the slash.
                # Only this backend knows that, so only this backend says so.
                link_stored_as_directory=is_reparse_point and stored_as_directory,
            )
        if is_reparse_point:
            self._settle_empty_reparse_point(
                member, reparse_fallback=reparse_fallback, member_id=index
            )
        if entry.offset_correction:
            self._emit_offset_wrapped(member, entry, index)
        if size_wrapped:
            self._emit_size_wrapped(member, entry, index)
        if member.type is MemberType.DIRECTORY and _zip_directory_stores_data(entry):
            # APPNOTE 4.3.8 gives a directory no data; unzip, 7-Zip and bsdtar create
            # the directory and drop the bytes silently. Say so; a read delivers them.
            self._emit_directory_data_ignored(
                member, index, reach=self._directory_data_reach(entry)
            )
            if directory_without_anchor:
                self._diagnostics_collector.emit(
                    code=DiagnosticCode.DIGEST_UNVERIFIABLE,
                    message=(
                        f"Directory {quoted(member.name)} declares {entry.file_size} "
                        "bytes of data but its CRC-32 field is 0, a directory's "
                        "conventional value; the bytes a read delivers are not "
                        "checked against any digest."
                    ),
                    context=DigestContext(
                        archive_name=self._archive_name,
                        member_name=member.name,
                        member_id=index,
                        algorithm="crc32",
                        reason="no_integrity_anchor",
                    ),
                    member=member,
                    attach_to_member=True,
                    logger=logger,
                )
        if special is not None and member.type is MemberType.FILE:
            # The gate is kept in the shape the 7z reader needs, where a reparse point
            # with a special mode can settle or re-type to FILE. In ZIP the two
            # attribute families cannot coexist: the mode is read only from a Unix
            # creator and the reparse bit only from a DOS/Windows one, so a member
            # with `special` set is never a reparse point and `member.type` is
            # `member_type` here.
            self._emit_special_file_has_data(member, index)
        for issue in ts_issues:
            field = _zip_timestamp_field(create_system, issue.field)
            self._emit_timestamp_invalid(member, index, replace(issue, field=field))
        if local_crc is not None:
            self._emit_local_header_differs(
                member,
                index,
                field="crc32",
                local_crc32=local_crc,
                message=(
                    f"ZIP member {quoted(member.name)}: its central directory entry "
                    f"stores CRC-32 0 and its local header {local_crc:08x}; the data "
                    "is checked against the local header's value, as unzip checks it."
                ),
            )
        return member

    def _local_crc_for(self, entry: CentralEntry) -> int | None:
        """The CRC-32 the local header of ``entry`` holds, when it replaces the
        directory's 0 (``_local_crc_stands_in``); else ``None``.

        Read only for a file or link, not WinZip AE-2, whose central CRC-32 is 0 over
        some data, so a listing reads no local header for any other entry. A local
        header that cannot be read gives ``None``: reading the member reports it
        (``_checked_local_header``).
        """
        if not 0 <= entry.header_offset < self._end.cd_start:
            return None
        try:
            header = read_local_header(self._read_at, entry.header_offset)
        except ArchiveyError:
            return None
        if not _local_crc_stands_in(entry, header.flags, header.crc):
            return None
        return header.crc

    def _emit_local_header_differs(
        self,
        member: ArchiveMember,
        member_id: int,
        *,
        field: Literal["name", "method", "crc32"],
        message: str,
        local_name: bytes | None = None,
        local_crc32: int | None = None,
        local_method: int | None = None,
        central_method: int | None = None,
    ) -> None:
        self._diagnostics_collector.emit(
            code=_LOCAL_HEADER_CODES[field],
            message=message,
            context=LocalHeaderContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                field=field,
                local_raw_name_base64=raw_name_to_base64(local_name),
                local_crc32=local_crc32,
                local_method=local_method,
                central_method=central_method,
            ),
            member=member,
            attach_to_member=True,
            logger=logger,
        )

    def _report_local_name(
        self, loc: _ZipLocator, member: ArchiveMember, local_name: bytes
    ) -> None:
        """Report that the local header of ``member`` names it ``local_name``.

        Read anyway, by the directory's name: archivey takes every field from the
        directory, so the local copy decides nothing. Reported on the member's first
        open only, so a password ladder that reads the header once per candidate
        counts it once; a policy that raises on the code raises on every open.

        Only a file or a link reports it. Reporting a directory from a pipe would
        break extraction parity under a policy that raises on the code, because
        extraction from a file never reads a directory's data and so never reaches
        its local header.
        """
        if member.type not in (MemberType.FILE, MemberType.SYMLINK):
            return
        code = DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS
        with self._lock:
            first = loc.index not in self._local_names_reported
            self._local_names_reported.add(loc.index)
        if not first and code not in self._diagnostics_collector.policy.raise_on:
            return
        self._emit_local_header_differs(
            member,
            loc.index,
            field="name",
            local_name=local_name,
            message=(
                f"ZIP member {quoted(member.name)}: its local header stores the name "
                f"{quoted(_stored_text(local_name))}; the central directory's name "
                "is used, as unzip and 7-Zip use it."
            ),
        )

    def _report_local_method(
        self, loc: _ZipLocator, member: ArchiveMember, local_method: int
    ) -> None:
        """Report that the local header of ``member`` names ``local_method``, which the
        member is decoded by (:meth:`_with_local_method`).

        Reported on the member's first open only, and by a file or link only, as
        :meth:`_report_local_name` is and for the same reasons.
        """
        if member.type not in (MemberType.FILE, MemberType.SYMLINK):
            return
        code = DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS
        with self._lock:
            first = loc.index not in self._local_methods_reported
            self._local_methods_reported.add(loc.index)
        if not first and code not in self._diagnostics_collector.policy.raise_on:
            return
        self._emit_local_header_differs(
            member,
            loc.index,
            field="method",
            local_method=local_method,
            central_method=loc.method,
            message=(
                f"ZIP member {quoted(member.name)}: its local header names compression "
                f"method {local_method} and its central directory entry method "
                f"{loc.method}; the local header's method is used, as a read from a "
                "pipe uses it."
            ),
        )

    def _local_member(self, entry: LocalEntry, index: int) -> ArchiveMember:
        """The member as its local header describes it, until the directory arrives.

        No field the directory alone holds is guessed: ``mode``, ``create_system`` and
        ``comment`` are ``None``, and the type is ``FILE`` or ``DIRECTORY`` from the
        name.

        ``uid`` and ``gid`` are ``None`` too, although the local header has its own
        extra field and Info-ZIP writers put the owner there. ``zip`` writes ``0x7875``
        in both headers; the 16-bit ``0x7855`` and ``0x5855`` hold the ids in the local
        header only, and their directory copies are empty or hold the times alone. A
        file read takes the owner from the directory alone, so a local-only ``0x7855``
        gives it no owner, and the pass must end with the directory's owner too. Left
        ``None`` here, the owner reaches extraction the way the mode does: extraction
        places the member only once the directory is read, with the directory's owner.
        Yielding the local ids instead would give the pass an owner no file read
        gives. A ZIP with no directory has no owner from either read.

        A backslash is a literal character until the host says otherwise, except at the
        end of the name, which makes the member a ``DIRECTORY`` until then: a DOS or
        Windows writer marks its folders that way, and the pass stages no bytes for
        what is usually a folder. A member the host then makes a file with data is not
        placed: it fails, its data never staged, where a file read writes it. Nothing is
        reported here: on a pipe the directory's version of the member reports what it
        finds, once. A ZIP with no directory lists this member as it stands
        (``_iter_walked``), and reports nothing for it either, as the pipe read reports
        nothing when no directory arrives; the listing then raises.
        """
        header = entry.header
        central = _central_from_local(entry)
        fields = split_extra_fields(central.extra)
        decoded_name = self._decode_member_name(central, fields)
        stored_as_directory = decoded_name.text.endswith(("/", "\\"))
        member_type = MemberType.DIRECTORY if stored_as_directory else MemberType.FILE
        name = normalize_member_name(
            decoded_name.text, member_type, backslash_is_separator=False
        )
        method = header.method
        aes_info = parse_winzip_aes_extra(header.extra) if method == 99 else None
        if aes_info is not None:
            algo = _ZIP_COMPRESSION_ALGOS.get(
                aes_info.actual_method, CompressionAlgorithm.UNKNOWN
            )
            compression: tuple[CompressionMethod, ...] = (CompressionMethod(algo=algo),)
        else:
            compression = _ZIP_COMPRESSION_TUPLES.get(method, _UNKNOWN_COMPRESSION)
        modified, accessed, ntfs_ctime, ut_ctime, _issues, _tags = _zip_timestamps(
            central, name, fields
        )
        created, ctime = _zip_created(CreateSystem.UNKNOWN, ntfs_ctime, ut_ctime)
        deferred = entry.deferred
        hashes = (
            {HashAlgorithm.CRC32: crc32_digest(header.crc)}
            if not deferred
            and _crc_is_digest(member_type, header.file_size, header.crc, aes_info)
            else {}
        )
        return ArchiveMember(
            type=member_type,
            name=name,
            raw_name=decoded_name.raw_name,
            size=None if deferred else header.file_size,
            compressed_size=None if deferred else header.compressed_size,
            compression=compression,
            hashes=hashes,
            extra=MemberExtra({"zip.compress_type": method}),
            modified=modified,
            accessed=accessed,
            created=created,
            ctime=ctime,
            is_encrypted=_is_encrypted_entry(header.flags, method),
            _raw=_ZipLocator(
                index=index,
                header_offset=entry.offset,
                compressed_size=header.compressed_size,
                file_size=header.file_size,
                crc=header.crc,
                flags=header.flags,
                method=method,
                dos_time=header.dos_time,
                name=header.name,
                aes=aes_info,
                strong_encryption=_uses_strong_encryption(header.flags, header.extra),
                reparse_fallback=None,
            ),
        )

    def _read_zipcrypto_header(
        self, raw: BinaryIO, loc: _ZipLocator, member_name: str
    ) -> bytes:
        """Read the 12-byte ZipCrypto header from the start of ``raw``, the payload.

        A declared size too small for the header is an impossible header,
        ``CorruptionError``, as for WinZip AES. The STORED confirm pass is gated above
        this size, so only the decrypt stage reaches that check. A payload the file cuts short is
        ``TruncatedError`` on every password path. ``raw`` is left open, positioned at
        the ciphertext body.
        """
        if loc.compressed_size < ZIPCRYPTO_HEADER_LEN:
            impossible = CorruptionError(
                "ZipCrypto member too short for its encryption header "
                f"({loc.compressed_size} < {ZIPCRYPTO_HEADER_LEN})",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
            self._stamp_error_context(impossible, member_name)
            raise impossible
        try:
            header = read_exact(raw, ZIPCRYPTO_HEADER_LEN)
        except _ZIP_MEMBER_READ_ERRORS as exc:
            self._reraise_member_error(exc, member_name)
        if len(header) != ZIPCRYPTO_HEADER_LEN:
            truncated = TruncatedError(
                "Truncated ZipCrypto header",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
            self._stamp_error_context(truncated, member_name)
            raise truncated
        return header

    def _local_data_region(
        self, loc: _ZipLocator, member: ArchiveMember
    ) -> tuple[int, int]:
        """Return ``(data_start, compressed_size)`` for ``loc`` from its local header
        (:meth:`_checked_local_header`), unless the open has read it already."""
        length = max(0, loc.compressed_size)
        if loc.data_start is not None:
            return loc.data_start, length
        return self._checked_local_header(loc, member).data_start, length

    def _checked_local_header(
        self, loc: _ZipLocator, member: ArchiveMember
    ) -> LocalHeader:
        """The local header of ``loc``, once the checks below let it through.

        The parser reads the fixed 30-byte header plus the local name and extra (the
        central extra can differ) and refuses a bad signature, a cut header and an
        offset past ``MAX_DATA_OFFSET``. This refuses a payload that runs into the
        next local header or the directory: the overlap guard. Then, on a payload
        the guard lets through, a local name whose bytes differ from the central
        directory's is reported (``_report_local_name``), and the member reads by
        the directory's name.
        """
        if loc.header_offset < 0:
            raise CorruptionError(self._front_cut_message(loc.header_offset))
        if loc.header_offset >= self._end.cd_start:
            # Every local header comes before the directory, as ``_holds_local_header``
            # says; not sought, since a source on disk cannot seek to every offset a
            # directory entry can state. For a ZIP with no end record the directory
            # starts where the walk stopped, at the cut member, whose read
            # ``_open_member`` has already refused with the walk's error.
            raise CorruptionError(f"Absurd local-header offset: {loc.header_offset}")
        try:
            header = read_local_header(self._read_at, loc.header_offset)
        except TruncatedError as exc:
            # The directory after every local header is in the file, so a local header
            # the file cuts short sits at a wrong offset: damage, not a cut archive.
            raise CorruptionError(raw_message_of(exc)) from exc
        # stdlib ZipFile.open's guard, with archivey's own bounds: a member whose
        # compressed payload extends past the next entry's start is a zip bomb. It
        # comes before the name check: a second directory entry over an earlier
        # entry's local header almost always names another member, and the overlap
        # refusal must not report that the read goes ahead by the directory's name.
        length = max(0, loc.compressed_size)
        if header.data_start + length > self._data_bounds().end_for(loc):
            raise CorruptionError(
                f"Overlapped entries: {quoted(_stored_text(loc.name))} "
                "(possible zip bomb)"
            )
        if header.name != loc.name:
            self._report_local_name(loc, member, header.name)
        return header

    def _with_local_method(
        self, loc: _ZipLocator, member: ArchiveMember
    ) -> _ZipLocator:
        """``loc`` with the compression method its local header names, and the data
        start it gives, so the open reads that header once.

        The local header sits next to the data, and a read from a pipe decodes by it,
        having nothing else; a file read does the same, so both read the same bytes,
        which the CRC-32 still checks. A method that differs from the directory's is
        reported (``MEMBER_LOCAL_METHOD_DIFFERS``, which ``STRICT`` refuses: a tool that
        trusts the directory decodes other bytes or fails). WinZip AES (method 99) on
        one side only is refused: its record is read from the central extra field, so
        the two headers disagree on how the data is encrypted. So is AES on both sides
        when the two AES records differ in any field (version, strength or real
        method), or one side's record is missing or unparseable
        (``aes_record_differences``): the pass decodes by the local record, this read
        by the central one.

        The local header is read and checked here, ahead of the codec and password
        refusals in the open, on purpose: the check holds the overlap guard against a
        zip bomb, so a member whose header fails it raises that ``CorruptionError``
        even when its method is unsupported or no password was given.
        """
        try:
            header = self._checked_local_header(loc, member)
        except _LOCAL_HEADER_ERRORS as exc:
            self._reraise_member_error(exc, member.name)
        local_method = header.method
        if local_method == loc.method == _WINZIP_AES_METHOD:
            differ = aes_record_differences(
                parse_winzip_aes_extra(header.extra), loc.aes
            )
            if differ:
                raise CorruptionError(
                    f"ZIP member {quoted(member.name)}: its local header and its "
                    "central directory entry disagree on its encryption "
                    f"({', '.join(differ)}{local_first(differ)}), so the two headers describe "
                    "different data",
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.ZIP,
                )
        if local_method == loc.method:
            return copy_with(loc, data_start=header.data_start)
        if _WINZIP_AES_METHOD in (local_method, loc.method):
            raise CorruptionError(
                f"ZIP member {quoted(member.name)}: its local header names compression "
                f"method {local_method} and its central directory entry method "
                f"{loc.method}, so the two headers disagree on its encryption",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        self._report_local_method(loc, member, local_method)
        return copy_with(loc, method=local_method, data_start=header.data_start)

    def _front_cut_message(self, header_offset: int) -> str:
        """The refusal for a local header the directory puts before byte 0.

        Every offset is a stored value, never negative, plus ``EndRecord.base``, so
        ``-base`` is at least every member's own shortfall and is the size of a front
        cut when the directory's own offset field is sound. A directory offset or size
        field that is too large gives the same shape with nothing missing, which is why
        the message says "seems".
        """
        missing = max(-self._end.base, -header_offset)
        detail = (
            ""
            if missing == -header_offset
            else f"; this member's local header would start {-header_offset} bytes "
            "before the start of the file"
        )
        return (
            f"The archive seems to be missing at least its first {missing} bytes: "
            "its central directory puts local headers before the start of the file"
            f"{detail}"
        )

    def _check_open(self) -> None:
        if self._fp is None:
            raise _closed_archive_error()

    def _raw_member_stream(self, loc: _ZipLocator, member: ArchiveMember) -> BinaryIO:
        """Locked :class:`SharedView` over the member's raw compressed payload."""
        data_start, length = self._local_data_region(loc, member)
        fp = self._fp
        if fp is None:
            raise _closed_archive_error()
        return SharedView(
            fp,
            start=data_start,
            length=length,
            lock=self._lock,
            check_open=self._check_open,
        )

    def _zip_lzma_params(self, raw: BinaryIO, *, keyed: bool) -> CodecParams:
        """Peel the ZIP method-14 LZMA header and return RAW LZMA1 :class:`CodecParams`.

        ``keyed`` marks a header a ZipCrypto key decrypted (see
        :attr:`_ZipCipher.keyed_settings`): an lc/lp liblzma cannot decode may then be
        a wrong key's garbage, so it stays a ``CorruptionError`` the password ladder
        counts as a failed candidate.
        """
        # version (2) + properties size (2) + properties
        header = read_exact(raw, 4)
        if len(header) != 4:
            raise TruncatedError(
                "Truncated ZIP LZMA header",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        props_size = struct.unpack_from("<H", header, 2)[0]
        if props_size > 256:
            raise CorruptionError(
                f"Absurd ZIP LZMA properties size: {props_size}",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        props = read_exact(raw, props_size)
        if len(props) != props_size:
            raise TruncatedError(
                "Truncated ZIP LZMA properties",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        try:
            lzma_filter = decode_lzma_filter_properties(
                lzma.FILTER_LZMA1, props, what="ZIP LZMA member"
            )
        except UnsupportedFeatureError as exc:
            # 7-Zip writes and reads lc + lp over 4 (``-mm=LZMA:lc=8``); liblzma
            # cannot decode it, so the archive is valid and unreadable here. When
            # keyed, every ZipCrypto open path re-raises this CorruptionError as the
            # password-or-damage EncryptionError, so its "not supported" wording is
            # only ever read as that error's ``__cause__``.
            error_type = CorruptionError if keyed else UnsupportedFeatureError
            raise error_type(
                raw_message_of(exc),
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            ) from exc
        return CodecParams(filters=[lzma_filter])

    def _zip_ppmd_params(self, raw: BinaryIO, *, keyed: bool) -> CodecParams:
        """Peel the ZIP method-98 2-byte PPMd8 header into :class:`CodecParams`.

        ``keyed`` as in :meth:`_zip_lzma_params`: under ZipCrypto an unsupported
        restore method may be a wrong key's garbage, so it reads as corruption.
        """
        header = read_exact(raw, 2)
        if len(header) != 2:
            raise TruncatedError(
                "Truncated ZIP PPMd header",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        word = struct.unpack("<H", header)[0]
        order = (word & 0xF) + 1
        mem_mb = ((word >> 4) & 0xFF) + 1
        restore = (word >> 12) & 0xF
        if order < 2 or order > 64 or mem_mb < 1:
            raise CorruptionError(
                f"Invalid ZIP PPMd header parameters: order={order} mem_mb={mem_mb}",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        # PPMd8 restore methods: 0 restart, 1 cut off, 2 freeze. 7-Zip builds without
        # freeze and reports it as an unsupported method; anything above 2 is its
        # data error. pyppmd must not be handed these either: it is built without
        # PPMD8_FREEZE_SUPPORT yet accepts any value silently, so a 2 (or a 3 to 15)
        # passed on decodes to wrong bytes once a large member fills the model,
        # rather than failing.
        if restore > _ZIP_PPMD_RESTORE_UNSUPPORTED or (
            restore == _ZIP_PPMD_RESTORE_UNSUPPORTED and keyed
        ):
            raise CorruptionError(
                f"Invalid ZIP PPMd header parameters: restore method {restore}",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        if restore == _ZIP_PPMD_RESTORE_UNSUPPORTED:
            raise UnsupportedFeatureError(
                f"ZIP PPMd restore method {restore} is not supported",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        return CodecParams(
            ppmd_order=order,
            ppmd_mem_size=mem_mb * 1024 * 1024,
            ppmd_restore_method=restore,
        )

    def _member_codec(
        self, method: int, member_name: str, *, suffix: str = ""
    ) -> Codec:
        codec = _ZIP_METHOD_CODECS.get(method)
        if codec is None:
            raise UnsupportedFeatureError(
                f"Unsupported ZIP compression method {method}{suffix}"
                "; a damaged header reads the same way",
                archive_name=self._archive_name,
                member_name=member_name,
                source_format=ArchiveFormat.ZIP,
            )
        return codec

    def _decode_body(
        self,
        loc: _ZipLocator,
        member: ArchiveMember,
        body: BinaryIO,
        *,
        method: int,
        codec: Codec,
        sequential_body: bool = False,
        keyed_settings: bool = False,
    ) -> ArchiveStreamImpl:
        """Decode a member body through the shared codec layer.

        ``body`` is the member's data as the codec sees it: the raw payload of an
        unencrypted member, or the plaintext out of a decrypt stage. Every encrypted
        member decodes here; an unencrypted one decodes in :meth:`_open_codec_member`,
        with the same config. Failures raise as ``ArchiveyError``.

        ``sequential_body`` marks a body that seeks only by re-reading from its start
        (the ZipCrypto stage). ``AUTO`` accelerators then stay off: they read their
        input at scattered offsets, and every step back would decrypt the member again.
        ``keyed_settings`` marks codec settings a ZipCrypto key decrypted
        (:attr:`_ZipCipher.keyed_settings`).
        """
        return self._open_decoder(
            loc,
            member,
            body,
            method=method,
            codec=codec,
            sequential_body=sequential_body,
            keyed_settings=keyed_settings,
            open_codec=lambda config, params: open_codec_stream(
                codec,
                body,
                config=config,
                params=params,
                seekable=self._stream_config.seekable,
                collector=self._diagnostics_collector,
            ),
        )

    def _open_decoder(
        self,
        loc: _ZipLocator,
        member: ArchiveMember,
        body: BinaryIO,
        *,
        method: int,
        codec: Codec,
        sequential_body: bool,
        keyed_settings: bool,
        open_codec: Callable[[StreamConfig, CodecParams], _T],
    ) -> _T:
        """Read the codec header and build the config ``codec`` opens with.

        ``open_codec`` opens it. ``body`` is closed if anything here fails.
        """
        try:
            try:
                params = self._member_codec_params(
                    loc, body, method=method, size=member.size, keyed=keyed_settings
                )
            except ArchiveyError as exc:
                # A codec header refused where it is read (malformed, cut short, or
                # a setting archivey cannot decode): stamped with the member, as a
                # raw decoder error from the same member would be.
                self._reraise_member_error(exc, member.name)
            return open_codec(
                self._member_config(body, member, codec, sequential_body), params
            )
        except BaseException as exc:
            body.close()
            if isinstance(exc, _ZIP_MEMBER_READ_ERRORS):
                self._reraise_member_error(exc, member.name)
            raise

    def _member_config(
        self,
        body: BinaryIO,
        member: ArchiveMember,
        codec: Codec,
        sequential_body: bool,
    ) -> StreamConfig:
        """The decoder config for one member: one copy of the reader's, or none.

        Each copy of this dataclass costs a few microseconds, and a reader makes one
        per member it opens.
        """
        base = self._member_decoder_config
        if codec is Codec.STORED:
            # ``StoredCodec`` reads nothing from its config, and the codec openers do
            # no config work for a stored stream source.
            return base
        changes: dict[str, Any] = {"expected_decompressed_size": member.size}
        # The codec opener fills the input size from ``body`` as it finds it, in a
        # copy of its own. Filled here instead while ``body`` is still at its start,
        # where the opener would read the same value from the same object. A codec
        # header read (LZMA, PPMd) moves it, and the opener then measures the view
        # it puts over the rest.
        body_seekable = is_seekable(body)
        if not body_seekable or body.tell() == 0:
            input_size = source_byte_size(body)
            if input_size is not None:
                changes["compressed_input_size"] = input_size
        # What ``open_codec``'s own config pass would set, by its rules
        # (``registry._decoder_config``, which points back here), so it finds nothing to
        # change and makes no second copy.
        if body_seekable != base.source_seekable:
            changes["source_seekable"] = body_seekable
        if base.seekable and not body_seekable:
            changes["seekable"] = False
        if sequential_body:
            changes["use_rapidgzip"] = _sequential_accelerator(base.use_rapidgzip)
            changes["use_indexed_bzip2"] = _sequential_accelerator(
                base.use_indexed_bzip2
            )
        return copy_with(base, **changes)

    def _member_codec_params(
        self,
        loc: _ZipLocator,
        body: BinaryIO,
        *,
        method: int,
        size: int | None,
        keyed: bool,
    ) -> CodecParams:
        """Read the member's codec header, if its method has one, into :class:`CodecParams`.

        ``keyed`` as in :meth:`_zip_lzma_params`.
        """
        if method == 14:  # ZIP LZMA
            params = self._zip_lzma_params(body, keyed=keyed)
            # Without the EOS-marker flag the stream has no end marker (APPNOTE
            # 4.4.4): the declared size is where it ends, so the decoder stops
            # there. With the flag set it stays unbounded, and an over-long or
            # short stream is caught by the size check on the member stream.
            if (
                not loc.flags & _ZIP_MASK_LZMA_EOS_MARKER
                and size is not None
                and size >= 0
            ):
                params = replace(params, unpack_size=size)
            return params
        if method == 98:  # ZIP PPMd8
            params = self._zip_ppmd_params(body, keyed=keyed)
            # Bound PPMd decode to the member size when known (defensive; PPMd8
            # usually has an end mark, but max_length still matches py7zr practice).
            if size is not None and size >= 0:
                params = replace(params, unpack_size=size)
            return params
        if method == 12:  # ZIP bzip2
            # A member is one bzip2 stream, as 7-Zip, Info-ZIP and stdlib zipfile
            # read it: a further stream after its end is input the member does not
            # use, refused like any other (``refuse_input_after_end``), with the
            # accelerator on or off (dev-docs/formats/zip.md §2.3). A Zstd member
            # (93) reads every frame instead, as a .zst file and a 7z coder do: RFC
            # 8878 defines Zstd data as one or more frames.
            return CodecParams(single_stream=True)
        return CodecParams()

    def _verified_member_parts(
        self,
        decoded: BinaryIO,
        member: ArchiveMember,
        *,
        translate: ExceptionTranslator | None = None,
        rewind_warning: RewindWarning | None = None,
        seekable: bool | None = None,
    ) -> MemberStreamParts:
        """The member's parts, with the stored CRC and size fused in.

        ``translate``, ``rewind_warning`` and ``seekable`` go to
        :meth:`_member_parts`, for a ``decoded`` that is a bare codec stream
        rather than an ``ArchiveStream`` (:meth:`_open_codec_member`).
        """
        hashes = member.hashes
        size = member.size
        if hashes or size is not None:
            loc = member._raw
            unknown = (
                loc.size_unknown
                if size is None and isinstance(loc, _ZipLocator)
                else None
            )
            # A size the archive leaves unknown: the length is checked against what
            # it stores, and filled in once the CRC-32 matches, on the listed member
            # (a ``replace()`` copy stands for it but is never filled).
            fill = None if unknown is None else self._own_member(member)
            return self._member_parts(
                decoded,
                member.name,
                size=size,
                expected_hashes=hashes,
                expected_size=size,
                verify_member=member if fill is None else fill,
                end_check=None if unknown is None else unknown.check,
                fill_size=fill is not None,
                translate=translate,
                rewind_warning=rewind_warning,
                seekable=seekable,
            )
        # A listed member carries a size, or a digest when its size is unknown (with
        # no CRC-32, ``_to_member`` keeps the stored size); only a caller's own
        # copy rebuilt with ``replace(size=None, hashes={})`` gets here, and is then
        # not verified.
        return self._member_parts(
            decoded,
            member.name,
            size=size,
            translate=translate,
            rewind_warning=rewind_warning,
            seekable=seekable,
        )

    def _open_codec_member(
        self, loc: _ZipLocator, member: ArchiveMember
    ) -> MemberStreamParts:
        """Decode an unencrypted ZIP member through the shared codec layer.

        The codec opens bare (``open_codec_raw``), and the member stream carries its
        translator and rewind warning, so the member has one ``ArchiveStream``.
        :meth:`_decode_body` instead builds the codec's own stream, which the member
        stream then collapses away. An encrypted member keeps that, because its
        password checks read the decoded body before the member stream exists.
        """
        codec = self._member_codec(loc.method, member.name)
        body = self._open_raw_payload(loc, member)
        opened = self._open_decoder(
            loc,
            member,
            body,
            method=loc.method,
            codec=codec,
            sequential_body=False,
            keyed_settings=False,
            open_codec=lambda config, params: open_codec_raw(
                codec, body, config=config, params=params
            ),
        )
        # What the codec's own stream, built with ``seekable=`` the config's seek
        # demand, would have answered: seekable only with that demand set and a
        # decoder that can seek, and with a rewind warning only under that demand.
        seek_demand = self._stream_config.seekable
        return self._verified_member_parts(
            opened.stream,
            member,
            translate=opened.translate,
            rewind_warning=opened.rewind_warning if seek_demand else None,
            seekable=(
                self._seek_declared() and seek_demand and is_seekable(opened.stream)
            ),
        )

    def _payload_is_complete(self, loc: _ZipLocator, member: ArchiveMember) -> bool:
        """Whether the file holds every byte of ``loc``'s declared payload."""
        try:
            data_start, length = self._local_data_region(loc, member)
        except _LOCAL_HEADER_ERRORS as exc:
            self._reraise_member_error(exc, member.name)
        with self._lock:
            fp = self._fp
            if fp is None:
                raise _closed_archive_error()
            return data_start + length <= fp.seek(0, io.SEEK_END)

    def _open_raw_payload(self, loc: _ZipLocator, member: ArchiveMember) -> BinaryIO:
        """:meth:`_raw_member_stream`, with a damaged local header raised translated."""
        try:
            return self._raw_member_stream(loc, member)
        except _LOCAL_HEADER_ERRORS as exc:
            self._reraise_member_error(exc, member.name)

    def _zipcrypto_stage(
        self, loc: _ZipLocator, member: ArchiveMember
    ) -> Callable[[bytes], BinaryIO]:
        """Return ``stage(password)``: the member's plaintext under ZipCrypto.

        ``stage`` checks the header's check byte (the cheap key check, 2⁻⁸) and raises
        the wrong-password ``EncryptionError`` when it does not match.
        """
        check_byte = _zipcrypto_check_byte(loc)

        def stage(password: bytes) -> BinaryIO:
            raw = self._open_raw_payload(loc, member)
            try:
                header = self._read_zipcrypto_header(raw, loc, member.name)
            except BaseException:
                raw.close()
                raise
            keys, check = keys_after_header(password, header)
            if check != check_byte:
                raw.close()
                raise wrong_password_error(ZIP_WRONG_PASSWORD_MSG)
            return ZipCryptoDecryptStream(
                raw, keys, length=max(0, loc.compressed_size - ZIPCRYPTO_HEADER_LEN)
            )

        return stage

    def _winzip_aes_stage(
        self, loc: _ZipLocator, aes: WinZipAesInfo, member: ArchiveMember
    ) -> Callable[[bytes], BinaryIO]:
        """Return ``stage(password)``: the member's plaintext under WinZip AES.

        ``stage`` checks the two-byte ``pw_verify`` (the cheap key check, 2⁻¹⁶); the
        HMAC runs when a read reaches the end of the ciphertext.
        """

        def stage(password: bytes) -> BinaryIO:
            raw = self._open_raw_payload(loc, member)
            try:
                return open_winzip_aes_member(
                    raw,
                    aes=aes,
                    password=password,
                    compress_size=loc.compressed_size,
                )
            except ArchiveyError as exc:
                raw.close()
                self._stamp_error_context(exc, member.name)
                raise
            except BaseException:
                raw.close()
                raise

        return stage

    def _open_encrypted_member(
        self, loc: _ZipLocator, member: ArchiveMember
    ) -> MemberStreamParts:
        """Open a ZipCrypto or WinZip AES member: decrypt stage, then the codec layer.

        Both schemes share one password ladder (``password_confirm``). Their cheap key
        checks (ZipCrypto's check byte, 2⁻⁸; WinZip AES's ``pw_verify``, 2⁻¹⁶) admit
        some wrong passwords, so:

        - **One possible password:** accept it on the cheap check. The CRC (or HMAC)
          at EOF is the real test, and a stream abandoned before it reports
          ``ENCRYPTED_MEMBER_UNVERIFIED``.
        - **Several, STORED ZipCrypto with a CRC-32 digest, at least**
          :data:`~archivey.internal.password_confirm.PASSWORD_CONFIRM_MIN_VERIFIED_BYTES`
          **long:** nothing but the whole-member CRC can tell them apart; one shared
          ciphertext pass decides (:meth:`_open_stored_confirmed`). A smaller member's
          CRC cannot confirm a password, and a member with no digest has none to
          match, so either takes the bounded confirm below.
        - **Several, otherwise:** each candidate runs a bounded confirm: the CRC when
          the member has a CRC-32 digest and it is in reach, codec rejection for a
          codec that rejects random input, and for WinZip AES the HMAC, which covers
          the whole member.

        The CRC a candidate is matched against is the member's CRC-32 digest
        (:func:`_member_crc_anchor`), the one its read is verified against, not the
        header's field.
        """
        if loc.method == 99:
            aes = loc.aes
            if aes is None:
                raise UnsupportedFeatureError(
                    "ZIP compression method 99 without a valid WinZip AES (0x9901) "
                    "extra field",
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.ZIP,
                )
            cipher = _ZipCipher(
                method=aes.actual_method,
                codec=self._member_codec(
                    aes.actual_method, member.name, suffix=" under WinZip AES"
                ),
                stage=self._winzip_aes_stage(loc, aes, member),
                crc_anchor=_member_crc_anchor(member),
                is_aes=True,
            )
        else:
            cipher = _ZipCipher(
                method=loc.method,
                codec=self._member_codec(loc.method, member.name),
                stage=self._zipcrypto_stage(loc, member),
                crc_anchor=_member_crc_anchor(member),
                is_aes=False,
            )

        def decode_body(body: BinaryIO) -> ArchiveStreamImpl:
            return self._decode_body(
                loc,
                member,
                body,
                method=cipher.method,
                codec=cipher.codec,
                sequential_body=not cipher.is_aes,
                keyed_settings=cipher.keyed_settings,
            )

        def payload_complete() -> bool:
            return self._payload_is_complete(loc, member)

        if not self._passwords.is_ambiguous():
            return self._open_encrypted_unconfirmed(
                loc, member, cipher, decode_body, payload_complete=payload_complete
            )
        if (
            not cipher.is_aes
            and cipher.method == 0  # STORED
            and cipher.crc_anchor is not None
            and min(loc.file_size, loc.compressed_size - ZIPCRYPTO_HEADER_LEN)
            >= PASSWORD_CONFIRM_MIN_VERIFIED_BYTES
        ):
            # A CRC over fewer bytes can reject a candidate but not confirm one, so a
            # smaller member takes the bounded confirm below, which never promotes it.
            # Both sizes are the archive's word: the declared plaintext and the body
            # the CRC pass will read. ``_open_stored_confirmed`` also checks the bytes
            # the pass actually covered, for a file that ends early. A member with no
            # CRC-32 digest has nothing for that pass to match, and takes the
            # bounded confirm too.
            winner = self._open_stored_confirmed(loc, member, cipher.crc_anchor)
            decoded = decode_body(cipher.stage(winner))
            return self._verified_member_parts(decoded, member)
        return self._open_encrypted_confirmed(
            loc, member, cipher, decode_body, payload_complete=payload_complete
        )

    def _open_encrypted_unconfirmed(
        self,
        loc: _ZipLocator,
        member: ArchiveMember,
        cipher: _ZipCipher,
        decode_body: Callable[[BinaryIO], ArchiveStreamImpl],
        *,
        payload_complete: Callable[[], bool],
    ) -> MemberStreamParts:
        """Open with the one possible password, accepted on its cheap key check."""
        stage = cipher.stage
        if cipher.is_aes:
            try:
                decoded: BinaryIO = self._finish_password_attempt(
                    member,
                    lambda: self._passwords.attempt(
                        member, lambda password: decode_body(stage(password))
                    ),
                    ambiguous_holder=None,
                )
            except _ZIP_MEMBER_READ_ERRORS as exc:
                self._reraise_member_error(exc, member.name)
            decoded = self._watch_unverified(
                decoded, loc, member, cipher, check="weak_open_check"
            )
            return self._verified_member_parts(decoded, member)

        size = member.size
        hashes = member.hashes

        def decrypt(password: bytes) -> BinaryIO:
            body = stage(password)
            try:
                decoded = decode_body(body)
            except ResourceUnavailableError:
                # The system ran short (no decoder child, say): not the settings.
                raise
            except ResourceLimitError as exc:
                # The LZMA or PPMd settings decrypted to a size over the cap. The
                # password may be wrong, but the size may be real: say both, and keep
                # the type a caller can act on by raising the cap.
                if not cipher.keyed_settings:
                    raise
                noted = _unconfirmed_resource_limit(exc)
                self._stamp_error_context(noted, member.name)
                raise noted from exc
            except ArchiveyError as exc:
                # The LZMA or PPMd header decrypted to nonsense: the same ambiguity
                # as a failure further in.
                if not _is_candidate_integrity_failure(
                    exc, payload_complete=payload_complete
                ):
                    raise
                raise unverified_data_error(_UNCONFIRMED_PASSWORD_FAILURE) from exc
            # The verifier sits inside the translation, so a CRC mismatch is reported
            # as the ambiguity it is rather than as plain corruption.
            return _UnconfirmedZipCryptoStream(
                VerifyingStream(
                    decoded,
                    hashes,
                    expected_size=size,
                    collector=self._diagnostics_collector,
                    member=member,
                    archive_name=self._archive_name,
                ),
                payload_complete=payload_complete,
            )

        stream = self._finish_password_attempt(
            member,
            lambda: self._passwords.attempt(member, decrypt),
            ambiguous_holder=None,
        )
        # Only the check byte vouched for this password; the CRC at EOF is the check.
        stream = self._watch_unverified(
            stream, loc, member, cipher, check="weak_open_check"
        )
        return self._member_parts(stream, member.name, size=size)

    def _open_encrypted_confirmed(
        self,
        loc: _ZipLocator,
        member: ArchiveMember,
        cipher: _ZipCipher,
        decode_body: Callable[[BinaryIO], ArchiveStreamImpl],
        *,
        payload_complete: Callable[[], bool],
    ) -> MemberStreamParts:
        """Pick among several possible passwords with a bounded confirm per candidate."""
        # The central directory's size, which the plan trusts;
        # the fused verifier on the caller's stream checks it at EOF.
        size = loc.file_size
        stage = cipher.stage
        crc_anchor = cipher.crc_anchor
        codec_rejects = cipher.method in _ZIP_REJECTING_METHODS
        # One substream, the member itself: its CRC is the anchor when the member fits
        # the prefix, and codec rejection decides a larger one.
        plan = plan_password_confirm(
            [(size, crc_anchor)],
            None,
            budget=PASSWORD_CONFIRM_PREFIX_BYTES,
            codec_rejects=codec_rejects,
        )
        # WinZip AES authenticates the whole ciphertext, so reading a member to its end
        # confirms the password (an 80-bit HMAC) whether or not it has a CRC. Take that
        # walk wherever a CRC walk would be taken: the member fits the budget, or its
        # codec cannot reject a wrong key on its own.
        reads_to_hmac = (
            cipher.is_aes
            and not plan.confirms
            and (size <= PASSWORD_CONFIRM_PREFIX_BYTES or not codec_rejects)
        )
        if reads_to_hmac:
            plan = PasswordConfirmPlan(
                ((size, crc_anchor),),
                None,
                confirms=True,
                bounded=size <= PASSWORD_CONFIRM_PREFIX_BYTES,
            )
        # A ZipCrypto candidate whose decrypted codec settings tripped a decoder
        # limit counts as failing (it may be a wrong key that passed the one-byte
        # check), and that limit is what is raised when no candidate succeeds.
        # WinZip AES keeps propagating the limit: its 16-bit pw_verify and the HMAC
        # make a garbage size from a wrong key negligible.
        failures = _CandidateFailures()
        candidate_failed = failures.failed

        # The walk to the member's end: its CRC, or for WinZip AES the HMAC. Run for
        # each candidate that survived the bounded plan when several did, since only
        # the end can tell them apart. ``None`` when the bounded plan already is it.
        full_plan: PasswordConfirmPlan | None = None
        if (
            not plan.confirms
            and size > PASSWORD_CONFIRM_PREFIX_BYTES
            and (crc_anchor is not None or cipher.is_aes)
        ):
            full_plan = PasswordConfirmPlan(
                ((size, crc_anchor),), None, confirms=True, bounded=False
            )

        def run_plan(
            password: bytes, walk: PasswordConfirmPlan, walk_to_hmac: bool
        ) -> tuple[bytes, PasswordConfirmVerdict]:
            # A damaged local header, a short encryption header and a failed cheap
            # check all raise from the stage, before anything below can mistake them
            # for a wrong key's garbage.
            body = stage(password)
            probe: ArchiveStreamImpl | None = None
            ended_early: TruncatedError | None = None
            try:
                try:
                    probe = decode_body(body)
                except ResourceUnavailableError:
                    # A shortage, not what the decrypted settings asked for: it must
                    # not become a candidate failure below.
                    raise
                except ResourceLimitError as exc:
                    if not cipher.keyed_settings:
                        raise
                    raise failures.limit_failed(exc) from exc
                verdict = run_password_confirm_plan(probe, walk)
                if verdict is not PasswordConfirmVerdict.REJECTED and walk_to_hmac:
                    # The read that finds the end is the one that checks the HMAC.
                    if probe.read(1):
                        verdict = PasswordConfirmVerdict.REJECTED
                elif verdict is PasswordConfirmVerdict.REJECTED and cipher.is_aes:
                    # The plan rejects a short read without saying so. For WinZip AES
                    # that is the data ending before its declared size, the damage the
                    # one-password path reports as TruncatedError; say so here too.
                    got = probe.tell()
                    if got < size and not probe.read(1):
                        ended_early = TruncatedError(
                            f"Decompressed content ended after {got} of {size} "
                            f"expected bytes."
                        )
            except ArchiveyError as exc:
                if not _is_candidate_integrity_failure(
                    exc, payload_complete=payload_complete
                ):
                    raise
                raise candidate_failed(exc) from exc
            finally:
                if probe is not None:
                    probe.close()
            if verdict is PasswordConfirmVerdict.REJECTED:
                raise candidate_failed(ended_early)
            return password, verdict

        def bounded_check(password: bytes) -> tuple[bytes, PasswordConfirmVerdict]:
            return run_plan(password, plan, reads_to_hmac)

        def full_check(password: bytes) -> tuple[bytes, PasswordConfirmVerdict]:
            assert full_plan is not None
            return run_plan(password, full_plan, cipher.is_aes)

        password, verdict = self._finish_password_attempt(
            member,
            lambda: attempt_with_confirm(
                self._passwords,
                member,
                bounded_check,
                None if full_plan is None else full_check,
            ),
            ambiguous_holder=failures.ambiguous,
            failure_is_damage=cipher.is_aes,
            limit_holder=failures.limits,
        )
        # Fresh stream for the caller: nothing decoded by a probe is handed out.
        try:
            decoded = decode_body(stage(password))
        except _ZIP_MEMBER_READ_ERRORS as exc:
            self._reraise_member_error(exc, member.name)
        stream: BinaryIO = decoded
        if verdict is not PasswordConfirmVerdict.CONFIRMED:
            stream = self._watch_unverified(
                decoded, loc, member, cipher, check="confirm_budget_exhausted"
            )
        return self._verified_member_parts(stream, member)

    def _reraise_member_error(self, exc: Exception, member_name: str) -> NoReturn:
        """Translate a raw member-read error, stamp it with member context, and raise.

        Thin wrapper over the shared base boundary: an ``EncryptionError`` is raised
        without member stamping (it carries its own message and must not be
        reclassified). Shared by the member-open and compressed-confirm decrypt paths
        so their translate/stamp/raise tail stays identical.

        A closed source (``I/O operation on closed file``) is mapped by the shared base
        boundary for every format; the reader's own closed handle raises
        ``ArchiveyUsageError`` where it is found (``_closed_archive_error``).
        """
        self._raise_translated(exc, member_name, stamp_encryption=False)

    def _open_stored_confirmed(
        self, loc: _ZipLocator, member: ArchiveMember, expected_crc: int
    ) -> bytes:
        """Resolve the password for a STORED ZipCrypto member, in four phases.

        A STORED member has no decompressor to reject a wrong key, and ZipCrypto's 1-byte
        header check admits ~1/256 of wrong passwords, so a full CRC pass over the member's
        plaintext is the only way to disambiguate. The caller sends only a member that
        has a CRC-32 digest, passed as ``expected_crc`` (:func:`_member_crc_anchor`),
        and whose declared sizes clear ``PASSWORD_CONFIRM_MIN_VERIFIED_BYTES``; a CRC
        match over fewer bytes than that (a file that ends early) confirms nothing here
        either.
        To keep that pass single and bounded:

        1. **Collect survivors** — run every static candidate through the cheap 1-byte
           check; keep the ~1/256 that pass.
        2. **Disambiguate** — one shared ciphertext pass computes every survivor's plaintext
           CRC-32 in constant memory; the first to match ``expected_crc`` wins.
        3. **Provider fallback** — if no static candidate won, ask the provider one password
           at a time (cheap check, then a per-candidate CRC pass), until one wins or it stops.
        4. **Resolve outcome** — return the winner, which the caller opens fresh;
           otherwise raise the most specific error (integrity-ambiguous /
           password-required / wrong-password).
        """
        ambiguous_failure: EncryptionError | None = None
        check_byte = _zipcrypto_check_byte(loc)

        # The same validated view every member open reads through: the local
        # header's name, data offset and overlap are checked before any pass runs.
        # One view serves the header read and every CRC pass; each pass rewinds it.
        raw = self._open_raw_payload(loc, member)
        try:
            header = self._read_zipcrypto_header(raw, loc, member.name)

            def weak_ok(password: bytes) -> bool:
                return password_matches_check_byte(password, header, check_byte)

            def disambiguate(survivors: list[bytes]) -> bytes | None:
                nonlocal ambiguous_failure
                if not survivors:
                    return None
                # No decompressor to reject garbage: one shared ciphertext pass computes
                # every survivor's plaintext CRC-32 in constant memory.
                try:
                    raw.seek(ZIPCRYPTO_HEADER_LEN)  # every pass starts at the body
                    crcs = parallel_plaintext_crc32(survivors, header, raw)
                    covered = raw.tell() - ZIPCRYPTO_HEADER_LEN
                except _ZIP_MEMBER_READ_ERRORS as exc:
                    self._reraise_member_error(exc, member.name)
                # A CRC over fewer bytes than the floor cannot confirm a password.
                winner = (
                    first_crc_match(expected_crc, crcs)
                    if covered >= PASSWORD_CONFIRM_MIN_VERIFIED_BYTES
                    else None
                )
                if winner is None:
                    failure = EncryptionError(_CANDIDATE_FAILED_MSG)
                    if ambiguous_failure is None:
                        ambiguous_failure = failure
                return winner

            # Phase 1 — collect the static candidates that pass the cheap 1-byte check.
            tried: set[bytes] = set()
            survivors: list[bytes] = []
            for password in self._passwords.iter_candidates():
                tried.add(password)
                if weak_ok(password):
                    survivors.append(password)

            # Phase 2 — one shared CRC pass over the survivors.
            winner = disambiguate(survivors)

            # Phase 3 — provider fallback through ``iter_provider_answers``.
            # The nested generator keeps ``except EncryptionError`` on the
            # provider call. ``disambiguate`` reports a member-read failure
            # through ``_reraise_member_error``, and that path does not stamp
            # an ``EncryptionError`` (``stamp_encryption=False``). A ``try``
            # around the ``for`` would stamp one raised while checking the
            # answer. Each yielded answer is added to ``tried`` because phase 4
            # reads that set: empty means "password required", and any answer
            # already tried means "wrong password".
            if winner is None:

                def provider_answers() -> Iterator[bytes]:
                    try:
                        yield from self._passwords.iter_provider_answers(member, tried)
                    except EncryptionError as exc:
                        self._stamp_error_context(exc, member.name)
                        raise

                for password in provider_answers():
                    tried.add(password)
                    if weak_ok(password):
                        winner = disambiguate([password])
                        if winner is not None:
                            break
        finally:
            raw.close()

        # Phase 4 — resolve the outcome (winner, else the most specific error).
        if winner is not None:
            self._passwords.record_success(winner)
            return winner

        if ambiguous_failure is not None:
            self._raise_unverified_candidates(member, ambiguous_failure)

        # A provider that exists but returned None without yielding a candidate
        # must not read as "wrong password" (cli-product P7 / #131 D8 residue).
        if not tried:
            required = EncryptionError("Password required to read this ZIP member")
            self._stamp_error_context(required, member.name)
            raise required
        wrong = wrong_password_error(ZIP_WRONG_PASSWORD_MSG)
        self._stamp_error_context(wrong, member.name)
        raise wrong

    def _raise_unverified_candidates(
        self, member: ArchiveMember, failure: EncryptionError
    ) -> NoReturn:
        """Raise that every candidate failed integrity: wrong password(s) or damage."""
        ambiguous = unverified_data_error(
            "No password candidate produced integrity-verified data for "
            "this ZIP member; the password(s) may be wrong, or "
            "the encrypted member may be corrupt"
        )
        self._stamp_error_context(ambiguous, member.name)
        raise ambiguous from failure

    def _watch_unverified(
        self,
        stream: BinaryIO,
        loc: _ZipLocator,
        member: ArchiveMember,
        cipher: _ZipCipher,
        *,
        check: Literal["weak_open_check", "confirm_budget_exhausted"],
    ) -> BinaryIO:
        """Report ``ENCRYPTED_MEMBER_UNVERIFIED`` if ``stream`` is abandoned before EOF.

        For a password that a check weaker than the member's digest accepted: a wrong
        ZipCrypto password that passes the check byte decrypts to readable garbage,
        and only the CRC at EOF notices. A read that skips bytes after a seek pauses the
        check except under WinZip AES: its HMAC survives seeks, so only a read reaching
        the end counts.
        """
        return self._watch_unverified_read(
            stream,
            member,
            size=loc.file_size,
            check=check,
            format_label="ZIP",
            digest="integrity check",
            why="the password was accepted on a weaker check",
            seek_forfeits=not cipher.is_aes,
        )

    def _finish_password_attempt(
        self,
        member: ArchiveMember,
        attempt: Callable[[], _T],
        *,
        ambiguous_holder: list[EncryptionError] | None,
        failure_is_damage: bool = False,
        limit_holder: list[ResourceLimitError] | None = None,
    ) -> _T:
        """Run ``attempt`` over the passwords, and name what exhausting them means.

        ``attempt`` is the candidate loop: ``_PasswordCandidates.attempt`` for the one
        possible password, :func:`~archivey.internal.password_confirm.attempt_with_confirm`
        for several.

        ``failure_is_damage`` is for WinZip AES: a candidate that failed integrity had
        already passed the 16-bit ``pw_verify``, which a wrong password passes once in
        65 536, so a member every such candidate fails on is far more likely damaged.
        It raises the damage the member has, as the one-password path does:
        ``TruncatedError`` when any candidate found the data ending early (exact for
        a STORED member, whose length no key changes; a heuristic for a compressed
        one), ``CorruptionError`` for anything else (an HMAC mismatch, a codec
        rejection). ZipCrypto's 8-bit check
        leaves the ambiguous ``EncryptionError``.

        ``limit_holder`` holds the first ``ResourceLimitError`` a ZipCrypto candidate's
        decrypted codec settings raised. When it holds one, exhausting the candidates
        raises it, with the note that the password may be wrong, ahead of every other
        outcome: raising the limit may be all a right password needs.
        """
        try:
            return attempt()
        except _PasswordCandidatesExhausted as exc:
            if limit_holder:
                noted = _unconfirmed_resource_limit(limit_holder[0])
                self._stamp_error_context(noted, member.name)
                raise noted from limit_holder[0]
            ambiguous_failure = ambiguous_holder[0] if ambiguous_holder else None
            if ambiguous_failure is not None and failure_is_damage:
                damage_type: type[ArchiveyError] = (
                    TruncatedError
                    if isinstance(ambiguous_failure.__cause__, TruncatedError)
                    else CorruptionError
                )
                damaged = damage_type(
                    "Every password candidate that passed the WinZip AES password "
                    "check failed integrity validation for this ZIP member; the "
                    "member is most likely damaged"
                )
                self._stamp_error_context(damaged, member.name)
                raise damaged from ambiguous_failure
            if ambiguous_failure is not None:
                self._raise_unverified_candidates(member, ambiguous_failure)
            if exc.last_error is not None:
                last_error = exc.last_error
                self._stamp_error_context(last_error, member.name)
                raise last_error from last_error.__cause__
            required = EncryptionError(raw_message_of(exc))
            self._stamp_error_context(required, member.name)
            raise required from None
        except EncryptionError as exc:
            self._stamp_error_context(exc, member.name)
            raise

    def _ensure_link_target(self, member: ArchiveMember) -> None:
        if member.type != MemberType.SYMLINK or member.link_target is not None:
            return
        loc = member._raw
        assert isinstance(loc, _ZipLocator), "ZIP member is missing its locator"
        if loc.strong_encryption:
            # No password opens it here, so the target is out of reach, not missing.
            self._emit_link_target_unavailable(
                member,
                reason="target_data_encrypted",
                message=(
                    f"The symlink target of {quoted(member.name)} is encrypted with "
                    f"PKWARE Strong Encryption, which archivey does not support; "
                    f"leaving link_target unset."
                ),
                target_in_archive=True,
            )
            return
        # A symlink's target is its (possibly encrypted) file data. A missing/wrong
        # password, or data that fails its check under an unconfirmed ZipCrypto
        # password, leaves link_target unset (following the link later fails with
        # LinkTargetNotFoundError). Damage, a method this reader does not decode, or an
        # optional library the data needs that is not installed propagates, and listing
        # reports the link targetless (`_report_unreadable_link_target`); open and
        # extraction raise it.
        self._link_target_from_data(
            member,
            self._link_target_opener(member),
            reparse_fallback=loc.reparse_fallback,
        )

    def _link_target_opener(
        self, member: ArchiveMember
    ) -> Callable[[], AbstractContextManager[ReadableStream]]:
        """How ``_ensure_link_target`` opens a link's data: the member itself here; the
        bytes the pass kept in a forward walk."""
        return lambda: self._open_member_handle(member)

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        # The member carries its own locator (`_raw`), so data access needs no name/id
        # map, and a duplicate member name can't resolve to the wrong entry.
        loc = member._raw
        assert isinstance(loc, _ZipLocator), "ZIP member is missing its locator"
        past = self._past_damage_found
        if past is not None and loc.index == past.cut:
            # The walk past a damaged directory could not get past this member's
            # data. The end record follows it, so the file is not cut: a local header
            # that runs past the end is corruption (``corrupt``).
            raise self._walked_error(past.walked, member.name, corrupt=True)
        walked = self._salvage
        if walked is not None and loc.index == walked.cut:
            # The walk could not get past this member's data: a read fails where the
            # walk did, as from a pipe.
            raise self._walked_error(walked, member.name)
        if loc.strong_encryption:
            raise UnsupportedFeatureError(
                _STRONG_ENCRYPTION_MSG,
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        if loc.flags & _ZIP_MASK_COMPRESSED_PATCHED_DATA:
            # The body is a patch against another file, not this member's content.
            # Decoding it as the content would return the patch bytes, and a stored CRC
            # that covers those bytes would not catch it. No guessed output: refuse.
            raise UnsupportedFeatureError(
                "ZIP compressed patched data (general-purpose bit 5) is not supported",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        loc = self._with_local_method(loc, member)
        # Every member reads as raw payload -> decrypt stage (if encrypted) -> codec
        # layer -> fused CRC/size verify.
        if _is_encrypted_entry(loc.flags, loc.method):
            return self._open_encrypted_member(loc, member)
        return self._open_codec_member(loc, member)

    def _archive_comment(self) -> str | None:
        comment = self._end.comment
        # The archive comment has no UTF-8 flag of its own.
        return self._decode_unflagged_comment(comment) if comment else None

    def _cost_receipt(self) -> CostReceipt:
        return _ZIP_COST

    def _get_archive_info(self) -> ArchiveInfo:
        info_extra = ArchiveInfoExtra({"zip.volume_count": self._volume_count})
        return ArchiveInfo(
            format=ArchiveFormat.ZIP,
            format_version=None,
            is_solid=False,  # ZIP is never solid: each member has an independent offset
            member_count=self._known_member_count(),
            comment=self._archive_comment(),
            is_encrypted=False,  # ZIP has per-member encryption, not header-level
            # True for a rejoined 7-Zip `.zip.NNN` set: it arrived as several files,
            # which is what a caller checking this wants to know. It says nothing
            # about the ZIP structure — the join is a plain single-disk archive.
            is_multivolume=self._volume_count > 1,
            cost=_ZIP_COST,
            extra=info_extra,
        )

    def _close_archive(self) -> None:
        # Wait out an in-flight read before the handle goes; a later read then fails
        # its SharedView check_open with the closed-archive error. The base closes the
        # source; the wrappers over it (seek counter, slice) are closed here.
        with self._lock:
            fp, self._fp = self._fp, None
        if fp is not None and fp is not self._source:
            fp.close()


class _UnicodePath(NamedTuple):
    """What the first Info-ZIP Unicode extra field of a name or comment says: the
    Unicode Path field (0x7075) or the Unicode Comment field (0x6375).

    ``name`` is the UTF-8 text when the field gives it. ``fault`` says why a field that
    should have given it could not, when it is malformed rather than merely not about
    these bytes; the reader drops it and reports that.
    """

    name: bytes | None = None
    fault: str | None = None


_NO_UNICODE_PATH = _UnicodePath()


def _unicode_path_name(
    fields: Sequence[ExtraField], stored_name: bytes
) -> _UnicodePath:
    """Read the Info-ZIP Unicode Path extra field (0x7075) of a name, if any."""
    return _info_zip_unicode_field(
        fields, _ZIP_EXTRA_UNICODE_PATH, stored_name, what="name"
    )


def _unicode_comment_text(
    fields: Sequence[ExtraField], stored_comment: bytes
) -> _UnicodePath:
    """Read the Info-ZIP Unicode Comment extra field (0x6375) of a member comment."""
    return _info_zip_unicode_field(
        fields, _ZIP_EXTRA_UNICODE_COMMENT, stored_comment, what="comment"
    )


def _info_zip_unicode_field(
    fields: Sequence[ExtraField], tag: int, stored: bytes, *, what: str
) -> _UnicodePath:
    """Read the first Info-ZIP Unicode extra field ``tag`` about ``stored``.

    Both fields (0x7075 for a name, 0x6375 for a member comment) are version 1, a
    CRC-32 of the header's bytes, then the text as UTF-8. The CRC ties the field to
    ``stored``, so a tool that changed the name or comment without updating the field
    leaves a stale field that does not match. Only the first such field counts, as in
    7-Zip. A stale field and an unknown version are not about these bytes and are
    ignored like any unknown record. A field too short for its version and CRC, one
    the extra field's end cuts short, or one whose CRC matches but whose text is empty
    or not UTF-8, is malformed: it gives nothing, and the caller reports it as a
    dropped record. ``what`` names the text in the fault (``name`` or ``comment``).
    """
    for extra_field in fields:
        if extra_field.tag != tag:
            continue
        field = extra_field.data
        if len(field) < 5:
            return _UnicodePath(
                fault=f"{len(field)} bytes, shorter than its version and {what} CRC"
            )
        if field[0] != 1 or struct.unpack_from("<I", field, 1)[0] != zlib.crc32(stored):
            return _NO_UNICODE_PATH
        if not extra_field.complete:
            return _UnicodePath(
                fault="its CRC matches but the extra field ends inside it"
            )
        text = field[5:]
        if not text:
            return _UnicodePath(fault=f"its CRC matches but it holds no {what}")
        try:
            text.decode("utf-8")
        except UnicodeDecodeError:
            return _UnicodePath(
                fault=f"its CRC matches but its {what} is not valid UTF-8"
            )
        return _UnicodePath(name=text)
    return _NO_UNICODE_PATH


def _is_encrypted_entry(flags: int, method: int) -> bool:
    """True when the entry's data is encrypted: bit 0, or method 99 (WinZip AES).

    Writers set bit 0 on WinZip AES members too, but method 99 alone means the data
    is encrypted, so listing and opening both ask this one predicate.
    """
    return bool(flags & _ZIP_MASK_ENCRYPTED) or method == 99


def _uses_strong_encryption(flags: int, extra: bytes) -> bool:
    """True for a PKWARE Strong Encryption member (APPNOTE §7)."""
    # The listing tests this bit before calling, to skip the call.
    if not flags & _ZIP_MASK_ENCRYPTED:
        return False
    if flags & _ZIP_MASK_STRONG_ENCRYPTION:
        return True
    return any(
        field.tag == _ZIP_EXTRA_STRONG_ENCRYPTION for field in iter_extra_fields(extra)
    )


def _crc_is_digest(
    member_type: MemberType, file_size: int, crc: int, aes: WinZipAesInfo | None
) -> bool:
    """Whether a member's CRC-32 field is a digest of its data, to list in
    ``hashes``: for a file or symlink, and for a directory that declares data
    unless the field is 0, a directory's conventional value. Never for AE-2, which
    stores 0 by design and relies on its HMAC. The seekable reader's three
    producers of ``hashes[CRC32]`` take it from here: the central directory's
    members, the local headers' and a data descriptor's update, so the read is
    checked, and several passwords anchored, alike on each.

    The pipe pass (``zip_forward_reader``) keeps its own rule for a bit-3 member:
    it verifies as it lists, so it lists a descriptor's CRC only once the CRC it
    computed matched, and a directory gets none until the central directory
    arrives (``format-zip`` spec, "Two shapes read differently from a pipe"). A
    pass that reads a directory's data checks it by this rule all the same
    (``_PassData._crc_is_digest``)."""
    if aes is not None and aes.is_ae2:
        return False
    if member_type is MemberType.DIRECTORY:
        return file_size > 0 and crc != 0
    return member_type in (MemberType.FILE, MemberType.SYMLINK)


def _member_crc_anchor(member: ArchiveMember) -> int | None:
    """The CRC-32 that tells a right password from a wrong one, or ``None``.

    The member's CRC-32 digest, the one its read is checked against, and not the
    header's CRC field: that field is no digest for an AE-2 member, which stores 0
    by design, nor for a directory whose field is 0 over declared data
    (:func:`_crc_is_digest`). Anchoring on it would reject the right password
    with several candidates where one password reads the member (DR-5).
    """
    digest = member.hashes.get(HashAlgorithm.CRC32)
    return None if digest is None else int.from_bytes(digest, "big")


def _zipcrypto_check_byte(loc: _ZipLocator) -> int:
    """The byte a ZipCrypto header's last plaintext byte must equal.

    The CRC's high byte, or under bit 3 (a data descriptor follows, so the CRC was not
    known when the header was written) the DOS time's.
    """
    if loc.flags & _ZIP_MASK_USE_DATA_DESCRIPTOR:
        return (loc.dos_time >> 8) & 0xFF
    return (loc.crc >> 24) & 0xFF


def _sequential_accelerator(mode: AcceleratorMode) -> AcceleratorMode:
    """``AUTO`` off, for a codec input that is expensive to read out of order.

    ``ON`` stays on: the caller asked for the accelerator by name. Over a ZipCrypto
    stage its scattered reads each restart decryption from the member's start, so the
    cost grows with the square of the member size.
    """
    return AcceleratorMode.OFF if mode is AcceleratorMode.AUTO else mode


class ZipReadBackend(ReadBackend):
    """Backend factory for ZIP archives."""

    FORMATS: tuple[ArchiveFormat, ...] = (ArchiveFormat.ZIP,)
    EXTENSIONS: Mapping[str, ArchiveFormat] = {
        ".zip": ArchiveFormat.ZIP,
        ".jar": ArchiveFormat.ZIP,
        ".pyz": ArchiveFormat.ZIP,
        ".whl": ArchiveFormat.ZIP,
        ".apk": ArchiveFormat.ZIP,
        ".cbz": ArchiveFormat.ZIP,
    }
    MAGIC: tuple[MagicSignature, ...] = (
        MagicSignature(
            0, b"\x50\x4b\x03\x04", ArchiveFormat.ZIP
        ),  # standard local header
        MagicSignature(
            0, b"\x50\x4b\x05\x06", ArchiveFormat.ZIP
        ),  # empty archive (EOCD)
        MagicSignature(0, b"\x50\x4b\x07\x08", ArchiveFormat.ZIP),  # spanned marker
        # APPNOTE 8.5.4: PKZIP may write PK00 ahead of the first local header of a set
        # that ended up as one segment. 7-Zip and unzip read it as an ordinary ZIP.
        MagicSignature(0, b"PK00PK\x03\x04", ArchiveFormat.ZIP),
    )
    # Local header only. The no-span marker needs no needle of its own: the local-header
    # search finds it at offset 4. The other two ZIP magics are not useful search
    # targets inside a stub window: PK\x05\x06 would precede a local header only for an
    # empty archive, and PK\x07\x08 is the spanning marker (7-Zip's -sfx -v keeps the
    # stub as a standalone executable, not concatenated with the volumes). Neither
    # carries fields SFX_HIT_VALIDATOR can cheaply confirm — see formats/zip.md §2.1.
    SFX_MAGIC: tuple[MagicSignature, ...] = (
        MagicSignature(0, b"\x50\x4b\x03\x04", ArchiveFormat.ZIP),
    )
    SFX_HIT_VALIDATOR = staticmethod(validate_zip_local_header)
    # A pipe is read forward over the local headers (`ZipForwardReader`), and the
    # members are updated from the central directory at the end of the pass.
    SUPPORTS_STREAMING_NON_SEEKABLE = True
    SUPPORTS_PASSWORD = True  # per-member ZipCrypto/AES encryption
    USES_ENCODING = True  # decodes unflagged names that are not valid UTF-8

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
    ) -> ZipReader:
        # `format` is always ZIP here (single-format backend); accepted for the uniform
        # ReadBackend signature.
        reader_cls = ZipReader
        if not source.seekable():
            # Only streaming=True gets here with such a source (open_archive refuses
            # random access on one). Imported here: that module builds on this one.
            from archivey.internal.backends.zip_forward_reader import (
                ZipForwardReader,
            )

            reader_cls = ZipForwardReader
        return reader_cls(
            source,
            streaming,
            passwords,
            encoding,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
            start_offset=start_offset,
        )


register_reader(ZipReadBackend)
