"""ZIP read front to back with no seek: a pipe, a socket, a remote object read once.

Layout this reader walks (``zip_local_walk``)::

    [ local file header · data · data descriptor? ] × n   # member by member
    [ central directory ] [ end records ]                  # after the last member

Each member is yielded with what its local header says, and its data is read through
the walk as the caller reads it. The fields only the central directory holds (mode,
host, comment, the types those decide) arrive after the last member, so the members
already yielded are updated in place then, before the pass ends; until then each has
``member_state_final`` false. ``openspec/changes/native-zip-reader/design.md``
§"Streaming: a forward walk over local headers" is the contract.

A seekable source never comes here: :class:`~archivey.internal.backends.zip_reader.ZipReader`
reads its directory first.
"""

from __future__ import annotations

import heapq
import io
import sys
import zlib
from array import array
from collections.abc import Callable, Generator, Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import fields, replace
from typing import BinaryIO, Literal, cast

from archivey.config import ListingLimits
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.diagnostics import DiagnosticCode, UnlistedDataContext
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    ResourceLimitError,
    ResourceUnavailableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.zip_aes import (
    _HMAC_LEN,
    FORWARD_READ,
    ZIP_WRONG_PASSWORD_MSG,
    WinZipAesForwardStream,
    WinZipAesInfo,
    aes_record_differences,
    local_first,
    open_winzip_aes_forward,
    open_winzip_aes_member,
    parse_winzip_aes_extra,
)
from archivey.internal.backends.zip_local_walk import (
    _CODEC_RETAIN,
    DataDescriptor,
    ForwardTail,
    LocalEntry,
    LocalHeaderWalk,
    MemberData,
    descriptor_by_crc,
)
from archivey.internal.backends.zip_parser import (
    CENTRAL_HEADER_SIZE,
    EOCD_SEARCH_WINDOW,
    CentralDirectoryWalk,
    CentralEntry,
    EndRecord,
    written_by_archive_utility,
)
from archivey.internal.backends.zip_reader import (
    _STRONG_ENCRYPTION_MSG,
    _UNCONFIRMED_PASSWORD_FAILURE,
    _WINZIP_AES_METHOD,
    _ZIP_KEYED_SETTINGS_METHODS,
    _ZIP_MASK_COMPRESSED_PATCHED_DATA,
    _ZIP_MASK_LZMA_EOS_MARKER,
    _ZIP_MASK_USE_DATA_DESCRIPTOR,
    _ZIP_REJECTING_METHODS,
    ZipReader,
    _bound_offset,
    _CandidateFailures,
    _is_candidate_integrity_failure,
    _is_encrypted_entry,
    _local_crc_stands_in,
    _max_members_error,
    _unconfirmed_resource_limit,
    _zipcrypto_check_byte,
    _ZipLocator,
)
from archivey.internal.backends.zipcrypto import (
    ZIPCRYPTO_HEADER_LEN,
    ZipCryptoDecryptStream,
    keys_after_header,
)
from archivey.internal.base_reader import (
    MAX_LINK_TARGET_BYTES,
    _apply_last_entry_wins_is_current,
    pass_has_data,
)
from archivey.internal.file_copy_pass import DEFAULT_FILE_COPY_PASS, FileCopyPass
from archivey.internal.hashing import crc32_digest
from archivey.internal.listing_limits import member_metadata_bytes
from archivey.internal.logs import backends as logger
from archivey.internal.password import unverified_data_error, wrong_password_error
from archivey.internal.password_confirm import (
    PASSWORD_CONFIRM_CHUNK_BYTES,
    PASSWORD_CONFIRM_MAX_INPUT_BYTES,
    PASSWORD_CONFIRM_MIN_VERIFIED_BYTES,
    PASSWORD_CONFIRM_PREFIX_BYTES,
    PasswordConfirmPlan,
    PasswordConfirmVerdict,
    attempt_with_confirm,
    plan_password_confirm,
    run_password_confirm_plan,
)
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.streams.codecs import open_codec_stream
from archivey.internal.streams.decompressor_stream import DataAfterEndError
from archivey.internal.streams.streamtools import (
    OneReadEachStream,
    ReadableStream,
    read_exact,
)
from archivey.internal.streams.streamtools.base import ReadOnlyIOStream
from archivey.internal.trailing_scan import first_nonzero_offset
from archivey.internal.windows_reparse import (
    REPARSE_HEADER_BYTES,
    parse_reparse_data,
    reparse_payload_length,
)
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    HashAlgorithm,
    MemberType,
)

# Read size when the pass reads through data nobody asked for.
_DRAIN_CHUNK = 1 << 16
#: A watch size no read reaches, for a stream whose check runs only at EOF.
_NO_END_BEFORE_EOF = sys.maxsize
#: The most ciphertext kept for an encrypted member that may be a link: twice the
#: target's cap, room for the encryption header, the AES code and a codec's framing.
#: Not a limit on what is read: a longer sized member (deflate padded with empty
#: blocks) is decrypted as the pass drains it instead under ``read_link_targets``, at
#: the cost of one key derivation, so it bounds only the bytes held until the
#: directory arrives.
_MAX_KEPT_CIPHERTEXT = 2 * MAX_LINK_TARGET_BYTES

#: Why a member's kept data was dropped (``ZipForwardReader._hold``): the pass held
#: ``max_metadata_bytes`` of short members' data, and this member's was the longest.
_DROPPED = "dropped"
#: What a link's read is given for data the pass knows is no reparse buffer but did
#: not keep (``ZipForwardReader._link_target_opener``).
_NOT_A_REPARSE_BUFFER = b"\0"
#: The data a member read with several possible passwords keeps to confirm one on
#: (``_PassData._confirm_password``): the compressed input a bounded confirm may take
#: (``PASSWORD_CONFIRM_MAX_INPUT_BYTES``), and room for the encryption header.
#: At most ``_CODEC_RETAIN``: a bit-3 codec member's spool can run past its data, and
#: the walk finds its descriptor among the last ``_CODEC_RETAIN`` bytes handed out
#: (a test pins it).
_CONFIRM_SPOOL = PASSWORD_CONFIRM_MAX_INPUT_BYTES + 64
#: How much of a bit-3 WinZip AES codec member's ciphertext stays out of its HMAC
#: until the descriptor says where the data ended: the walk finds the descriptor
#: among the last ``_CODEC_RETAIN`` bytes handed out and one read more, so the
#: codec's layers cannot have read further past the end than that, plus the code.
#: About 4 MiB, held on top of the walk's own window over the same bytes, so a bit-3
#: AES codec member costs twice ``_CODEC_RETAIN`` while it is read.
_AES_HOLD_BACK = _CODEC_RETAIN + FORWARD_READ + _HMAC_LEN

# A forward pass decides nothing by seeking back, and reads each member's data once.
_ZIP_FORWARD_COST = CostReceipt(
    listing_cost=ListingCost.REQUIRES_SCANNING,  # members are found by their headers
    access_cost=AccessCost.DIRECT,  # each member's data is independent
    stream_capability=StreamCapability.FORWARD_ONLY,
    solid_block_count=None,
)

# Fields the end of the pass leaves as they are: the reader's identity stamps, and
# what the base settles itself (``is_current`` when the walk ends, links when the
# listing resolves them).
_KEPT_ON_UPDATE = frozenset(
    {
        "_member_id",
        "_archive_id",
        "_diagnostics",
        "_listing_pending",
        "_link_target_unread",
        "is_current",
        "link_target_member",
    }
)


def _contradicts(descriptor: tuple[int, int, int], central: CentralEntry) -> bool:
    """Whether a data descriptor's CRC or sizes differ from the directory entry's.

    A 4-byte descriptor holds the size modulo 2**32 (its compressed size was matched
    in full). So does the directory entry of a member past 4 GiB that macOS Archive
    Utility wrote, whose compressed size the walk measured
    (``CentralDirectoryWalk``)."""
    crc, compressed_size, file_size = descriptor
    sizes = (central.file_size, central.file_size & 0xFFFF_FFFF)
    return (
        crc != central.crc
        or compressed_size != central.compressed_size
        or (
            file_size not in sizes
            and not (
                file_size & 0xFFFF_FFFF == central.file_size
                and written_by_archive_utility(central)
            )
        )
    )


def _header_disagreements(
    local: _ZipLocator, central: CentralEntry, *, crc_used: bool
) -> list[str]:
    """The fields a member's local header (its pass-time ``_raw``) and ``central``
    disagree on, out of those that decide what a read yields.

    The pass reads a member's data as its local header describes it; a file read reads
    it as the directory does. The CRC and sizes count only when the local header holds
    them (no bit 3): a data descriptor's are checked by :func:`_contradicts`. The CRC
    counts only when a read checks it (``crc_used``: not WinZip AE-2). The method does
    not count: the data the pass decoded matched the CRC and size the directory gives,
    and a file read decodes by the local method too, reporting
    ``MEMBER_LOCAL_METHOD_DIFFERS`` as the pass does. WinZip AES (method 99) on one side
    only counts, as a file read refuses it: the two headers disagree on the encryption.
    So do two AES records that differ in any field, or a missing or unparseable record
    on one side (:func:`aes_record_differences`): the pass decoded by the local record, and a file
    read refuses the member.
    """
    flags, crc = local.flags, local.crc
    compressed_size, file_size = local.compressed_size, local.file_size
    differ = []
    if local.method != central.method and _WINZIP_AES_METHOD in (
        local.method,
        central.method,
    ):
        differ.append(f"compression method {local.method} against {central.method}")
    elif local.method == central.method == _WINZIP_AES_METHOD:
        differ.extend(
            aes_record_differences(local.aes, parse_winzip_aes_extra(central.extra))
        )
    encrypted = _is_encrypted_entry(flags, local.method)
    if encrypted != _is_encrypted_entry(central.flags, central.method):
        differ.append(
            "encrypted in the local header, not in the directory"
            if encrypted
            else "encrypted in the directory, not in the local header"
        )
    if not flags & _ZIP_MASK_USE_DATA_DESCRIPTOR:
        # A central CRC-32 of 0 over data against a local value is no
        # contradiction, whatever the member's type: a file or link takes the local
        # value (``_local_crc_for``), and a directory keeps no digest
        # (``DIGEST_UNVERIFIABLE``), as from a file, which never compares the two.
        if (
            crc_used
            and crc != central.crc
            and not _local_crc_stands_in(central, flags, crc)
        ):
            differ.append(f"CRC-32 {crc:08x} against {central.crc:08x}")
        if compressed_size != central.compressed_size:
            differ.append(
                f"{compressed_size} bytes stored against {central.compressed_size}"
            )
        if file_size != central.file_size:
            differ.append(f"{file_size} bytes against {central.file_size}")
    return differ


def _header_error(member: ArchiveMember, differ: list[str]) -> CorruptionError:
    return CorruptionError(
        f"ZIP member {quoted(member.name)}: its local header and its central "
        f"directory entry disagree ({', '.join(differ)}{local_first(differ)}); the data the "
        "stream held for it was read as the local header describes it, and a read "
        "that follows the directory reads it differently",
        member_name=member.name,
        source_format=ArchiveFormat.ZIP,
    )


def _descriptor_error(
    member: ArchiveMember, descriptor: tuple[int, int, int], central: CentralEntry
) -> CorruptionError:
    crc, compressed_size, file_size = descriptor
    return CorruptionError(
        f"ZIP member {quoted(member.name)}: the data descriptor after its data "
        f"(CRC-32 {crc:08x}, {compressed_size} bytes stored, {file_size} bytes) "
        f"differs from its central directory entry (CRC-32 {central.crc:08x}, "
        f"{central.compressed_size} bytes stored, {central.file_size} bytes); the "
        "bytes the stream held for it are not the data the directory describes",
        member_name=member.name,
        source_format=ArchiveFormat.ZIP,
    )


def _missing_error(
    member: ArchiveMember, offset: int, rejected: ArchiveyError | None = None
) -> CorruptionError:
    """The failure of a directory entry with no local entry: none at ``offset``, or
    one there that did not parse (``rejected``, chained as the cause)."""
    if rejected is None:
        return CorruptionError(
            f"ZIP central directory entry {quoted(member.name)} points to offset "
            f"{offset}, where the stream held no local header",
            member_name=member.name,
            source_format=ArchiveFormat.ZIP,
        )
    error = CorruptionError(
        f"ZIP central directory entry {quoted(member.name)} points to offset "
        f"{offset}, where the local header did not parse: {rejected.message}",
        member_name=member.name,
        source_format=ArchiveFormat.ZIP,
    )
    error.__cause__ = rejected
    return error


def _without_frames(exc: ArchiveyError) -> ArchiveyError:
    """``exc`` and the errors it was raised from (``__cause__``, the reader's own
    translation chain) with no traceback, to keep for a report: a traceback keeps
    its frames and their locals alive. Each one's ``__context__`` link is dropped,
    not followed: it may be an exception the caller was handling when it drove the
    pass, whose traceback is the caller's."""
    visited: set[int] = set()
    link: BaseException | None = exc
    while link is not None and id(link) not in visited:
        visited.add(id(link))
        link.__traceback__ = None
        link.__context__ = None
        link = link.__cause__
    return exc


def _declared_reparse_buffer(header: bytes) -> int:
    """The length of a Windows reparse buffer starting with ``header``: the header
    and the payload a link tag declares. The file read reads one byte more
    (``_read_bounded_link_data``)."""
    return REPARSE_HEADER_BYTES + reparse_payload_length(header)


#: The most of a reparse buffer the pass keeps for a member it cannot yet tell is one:
#: a symlink buffer as Windows lays it out (header, name offsets, flags), with both
#: names at the target cap in UTF-16 and their terminators. A target a longer buffer
#: holds is padded or over the cap; Windows itself holds at most 16 KiB.
_MAX_REPARSE_PREFIX = REPARSE_HEADER_BYTES + 12 + 2 * (2 * MAX_LINK_TARGET_BYTES + 2)


def _tail_bound(limits: ListingLimits) -> int | None:
    """How many bytes after the members a pass holds to find the directory in.

    The most a directory within the listing limits takes (each entry's fixed header
    and its text), then four end-record search windows (64 KiB and 22 bytes each) for
    what may follow it: the end record with its comment and any bytes after them
    (the window the record is searched in), a digital signature record, a ZIP64 end
    record's extensible data, and one more for bytes between the last member and the
    directory. Past it the pass keeps the last that many bytes, for an archive that
    ends the stream, and, when a directory or end record follows the members right
    away, the first that many too, for one followed by other bytes. A directory or
    ZIP64 end record further from both is a ``ResourceLimitError``. At the default
    limits the bound is about 76 MiB, so a pass holds up to about 152 MiB here, and
    a copy of the kept tail for a moment when it joins it. ``None`` when a limit is
    off.
    """
    if limits.max_members is None or limits.max_metadata_bytes is None:
        return None
    return (
        limits.max_members * CENTRAL_HEADER_SIZE
        + limits.max_metadata_bytes
        + 4 * EOCD_SEARCH_WINDOW
    )


class _PassData:
    """One member's data in a forward pass, read once, checked when it ends.

    The caller's stream and the pass itself (when it moves on to the next header) read
    through the same object, so every byte is decoded once. When the data ends, its
    CRC and size are checked against the local header, or for a bit-3 member against
    the data descriptor that follows, and a bit-3 member's sizes and CRC are filled in
    on the member.

    A member whose data could be a symlink's target (at most
    :data:`MAX_LINK_TARGET_BYTES` decoded bytes) keeps them: the directory, which says
    whether it is a link, comes after the data. An encrypted one nobody read keeps its
    ciphertext instead (:class:`_KeptCiphertext`). Longer data keeps the start a
    Windows reparse buffer's parse reads (:attr:`reparse_prefix`), at most
    :data:`_MAX_REPARSE_PREFIX` and one byte.
    """

    def __init__(
        self,
        reader: ZipForwardReader,
        entry: LocalEntry,
        member: ArchiveMember,
        data: MemberData,
    ) -> None:
        self._reader = reader
        self.entry = entry
        self.member = member
        self._data = data
        self._decoded: BinaryIO | None = None
        #: Decrypted with the one possible password, which only ZipCrypto's one-byte
        #: check vouched for: a failed integrity check may be a wrong password.
        self._unconfirmed = False
        #: The stream ended inside the data (not a wrong key's short output).
        self._cut_short = False
        #: What an encrypted member's read raised, or why the start of data over the
        #: target cap was not kept (``reparse_prefix``), for its link target's read.
        self._failure: ArchiveyError | None = None
        #: The length of a reparse buffer the data declares over
        #: ``_MAX_REPARSE_PREFIX``, which the pass did not keep.
        self._overlong_buffer: int | None = None
        #: Encrypted data over the target cap that nobody read: the pass neither
        #: decrypts it nor keeps its ciphertext.
        self._unread_encrypted = False
        #: What opening the decoded stream raised: it runs once, as the decrypt
        #: stage reads its header from the data (a second try would read past it).
        self._open_error: ArchiveyError | None = None
        #: An encrypted member's ciphertext, kept by ``drain`` for a link target.
        self._kept: _KeptCiphertext | None = None
        #: ``drain`` read past an encrypted bit-3 member too long to be a link
        #: target without keeping it.
        self._too_long = False
        #: A bit-3 WinZip AES codec member's decrypt stage, which authenticates once
        #: the descriptor says where the data ended (``_finish``).
        self._aes_pass: WinZipAesForwardStream | None = None
        #: Which weaker check the password was taken on, for the report when the
        #: caller's stream closes before the end; ``None`` once a confirm settled it.
        self._check: Literal["weak_open_check", "confirm_budget_exhausted"] | None = (
            "weak_open_check"
        )
        #: The kept first bytes of the data and the rest, as the confirm's winner
        #: reads them (``_confirm_password``).
        self._replay: _Replay | None = None
        #: Decoding kept ciphertext for a link target: the walk has settled it.
        self._from_kept = isinstance(data, _KeptData)
        self._crc = 0
        self._size = 0
        self._capture: bytearray | None = bytearray()
        # Once the data is over the target cap: how much of its start the capture
        # keeps, for a Windows reparse buffer (``_declared_reparse_buffer``).
        self._prefix_want: int | None = None
        #: The data has ended and been checked, or the pass has moved past it.
        self.done = False
        #: The data was decoded to its end and checked (``_finish``). ``done`` without
        #: it means the decode failed part way, ``abandon`` stopped the pass, or, for
        #: a bit-3 member, the data runs on past the reparse prefix. The pass decodes
        #: one byte past the prefix (``_wants_decoded``), so data that ends there is
        #: checked, and longer data is passed by the scan unchecked
        #: (``reparse_prefix``), as the file read's bounded read stops at the prefix
        #: and gives the target.
        self._checked = False
        #: The walk has moved on: the caller's stream reads nothing more.
        self.passed = False
        #: Set when the caller read up to the end and every check passed.
        self.verified = False

    @property
    def captured(self) -> bytes | None:
        """The member's whole decoded data, when it is short enough to be a link
        target and was read to its end; else ``None``."""
        if not self.verified or self._capture is None or self._prefix_want is not None:
            return None
        return bytes(self._capture)

    @property
    def reparse_prefix(self) -> bytes | None:
        """The start of data over the target cap, as far as a Windows reparse buffer's
        parse reads it, when it was decoded that far; else ``None``.

        A link buffer's target may sit anywhere in its declared payload, up to 64 KiB,
        and data whose tag is no link's goes back to being a file whatever follows, so
        the file read reads no more than this (``_read_bounded_link_data``). Whether the
        member is a reparse point at all is only known from the directory, so the pass
        keeps no buffer longer than ``_MAX_REPARSE_PREFIX`` (``uncaptured`` says so).
        """
        capture = self._capture
        want = self._prefix_want
        if capture is None or want is None:
            return None
        if self._deferred():
            # The file read reads this prefix (the buffer and one byte) and reaches
            # the end only when the data is no longer. The pass decodes one byte past
            # the prefix (``_wants_decoded``), since only a decode that returns
            # nothing tells bit-3 data it has ended; both stop at the same place. A
            # decode that failed part way was not checked (``_checked``).
            ended = self.verified or (self._checked and self._size <= want)
        else:
            ended = self.verified or self._size >= self.entry.header.file_size
        if ended and not self.verified:
            # Read to its end and failed its check, as the file read's byte past the
            # buffer finds.
            return None
        # Data shorter than the buffer declares is all there is to parse.
        if len(capture) < want and not ended:
            return None
        return bytes(capture)

    def _over_cap(self) -> bool:
        """The local header states a size over the target cap."""
        return (
            not self._deferred() and self.entry.header.file_size > MAX_LINK_TARGET_BYTES
        )

    def _keep(self, chunk: bytes) -> None:
        """Add ``chunk``, just decoded, to what the pass keeps of the data."""
        capture = self._capture
        if capture is None:
            return
        want = self._prefix_want
        if want is None:
            if self._over_cap():
                if self._size < REPARSE_HEADER_BYTES:
                    capture += chunk
                    return
            elif self._size <= MAX_LINK_TARGET_BYTES:
                capture += chunk
                return
            # Over the cap: only a reparse buffer's start stays. Its header is in
            # what was kept and this chunk.
            head = bytes(capture[:REPARSE_HEADER_BYTES])
            head += chunk[: REPARSE_HEADER_BYTES - len(head)]
            declared = _declared_reparse_buffer(head)
            if declared > _MAX_REPARSE_PREFIX:
                # The member's own bytes say how much the pass keeps of every such
                # member until the directory comes, so no more than a target within
                # the cap needs. The length alone is kept: the message is built only
                # if the directory makes the member a link.
                self._capture = None
                self._overlong_buffer = declared
                return
            want = self._prefix_want = declared + 1
            del capture[want:]
        room = want - len(capture)
        if room > 0:
            capture += chunk[:room]

    def _wants_prefix(self) -> int:
        """How many more decoded bytes the capture wants, to tell a target or a reparse
        buffer's start."""
        capture = self._capture
        if capture is None:
            return 0
        if self._prefix_want is not None:
            return max(0, self._prefix_want - len(capture))
        if self._deferred():
            # No size to go by: the data is within the target cap only if it ends
            # by the byte past it.
            return max(0, MAX_LINK_TARGET_BYTES + 1 - self._size)
        # ``drain`` asks a sized member only of data over the cap.
        return max(0, REPARSE_HEADER_BYTES - self._size)

    def _wants_decoded(self) -> int:
        """How many more decoded bytes ``drain`` takes of bit-3 codec data: what the
        capture wants, then one byte past a reparse prefix. The prefix is the buffer
        and one byte, all the file read reads; it checks data no longer than that
        (``reparse_prefix``). Bit-3 data has no size, so the pass learns that it ended
        there only from a decode past the prefix that returns nothing."""
        want = self._wants_prefix()
        if want or self._capture is None or self._prefix_want is None:
            return want
        return max(0, self._prefix_want + 1 - self._size)

    def _deferred(self) -> bool:
        return self.entry.deferred

    def _runs_on(self) -> bool:
        """The data has no end of its own: only the codec finds it (bit 3). Kept
        ciphertext ends where the walk's scan found the data's end."""
        return self._deferred() and self._method() != 0 and not self._from_kept

    def _method(self) -> int:
        """The compression method, under WinZip AES the one its extra field names."""
        aes = cast("_ZipLocator", self.member._raw).aes
        return self.entry.header.method if aes is None else aes.actual_method

    def _open_decoded(self) -> BinaryIO:
        if self._decoded is not None:
            return self._decoded
        if self._open_error is not None:
            raise self._open_error
        try:
            self._decoded = self._open_decoded_once()
        except ArchiveyError as exc:
            self._open_error = exc
            raise
        return self._decoded

    def _open_decoded_once(self) -> BinaryIO:
        member = self.member
        header = self.entry.header
        reader = self._reader
        if header.flags & _ZIP_MASK_COMPRESSED_PATCHED_DATA:
            raise UnsupportedFeatureError(
                "ZIP compressed patched data (general-purpose bit 5) is not supported",
                archive_name=reader._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        loc = member._raw
        assert isinstance(loc, _ZipLocator)
        method = self._method()
        deferred = self._deferred()
        if deferred and method == 14 and not header.flags & _ZIP_MASK_LZMA_EOS_MARKER:
            raise UnsupportedFeatureError(
                "A ZIP LZMA member with no end-of-stream marker and its sizes in a "
                "data descriptor cannot be read from a source that cannot seek: "
                "nothing marks where its data ends",
                archive_name=reader._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        if _is_encrypted_entry(header.flags, header.method):
            keyed = loc.aes is None and method in _ZIP_KEYED_SETTINGS_METHODS
            return self._decrypted(
                loc, lambda source: self._decode(loc, source, keyed=keyed)
            )
        return self._decode(loc, self._data, keyed=False)

    def _decode(
        self,
        loc: _ZipLocator,
        source: BinaryIO,
        *,
        keyed: bool,
        note_limit: bool = True,
    ) -> BinaryIO:
        """``source`` (the member's data, decrypted) through its codec.

        ``keyed``: ZipCrypto decrypted the codec's settings, so settings a wrong key
        could produce read as corruption, and a decoder limit they trip may be a
        wrong password's doing. ``note_limit``: say so on that limit's error; a
        candidate's probe leaves it raw, for the attempt to note once.
        """
        member = self.member
        header = self.entry.header
        reader = self._reader
        method = self._method()
        deferred = self._deferred()
        if method == 0:
            return source
        codec = reader._member_codec(
            method,
            member.name,
            suffix=" under WinZip AES" if loc.aes is not None else "",
        )
        size = None if deferred else header.file_size
        # A sized member's data is its codec's input exactly, so a byte after the
        # codec's end is refused as from a file (DR-3). A bit-3 member's data runs on
        # into the descriptor, so there the same refusal is how its end is found.
        config = replace(
            reader._stream_config,
            expected_decompressed_size=size,
            refuse_input_after_end=True,
            seekable=False,
        )
        try:
            params = reader._member_codec_params(
                loc, source, method=method, size=size, keyed=keyed
            )
        except ResourceLimitError as exc:
            # The LZMA or PPMd settings a ZipCrypto key decrypted ask for more than
            # the cap: the password may be wrong, or the size real (as from a file).
            # Only the settings are read here, no decoder is built, so this is never
            # a ResourceUnavailableError, which the decode below lets through.
            if not keyed or not note_limit:
                raise
            noted = _unconfirmed_resource_limit(exc)
            reader._stamp_error_context(noted, member.name)
            raise noted from exc
        if deferred and method == 98:
            # PPMd holds a sized member's input until it is all in; a bit-3 member
            # has no size to wait for, so it is fed in pieces, in a child process.
            params = replace(params, input_runs_on=True)
        if deferred:
            # The data reads ahead in small steps (``MemberData._read_ahead``),
            # which a ``BufferedReader`` in front of the decoder would fill.
            source = OneReadEachStream(source)
        return open_codec_stream(
            codec,
            source,
            config=config,
            params=params,
            seekable=False,
            collector=reader._diagnostics_collector,
        )

    def _decrypted(
        self, loc: _ZipLocator, decode: Callable[[BinaryIO], BinaryIO]
    ) -> BinaryIO:
        """The member's decoded data (``decode`` over its plaintext), decrypted from its
        data as the pass reads it.

        One possible password is taken on its cheap check (ZipCrypto's check byte,
        WinZip AES's ``pw_verify``), as from a file; the CRC or the HMAC at the end is
        the real test (``_unconfirmed``). Several are judged by a bounded confirm on
        the first bytes of the data, which the pass keeps to replay to the winner
        (``_confirm_password``). Its header is read once, so a second candidate could
        not start over without them.

        A bit-3 member's data has no size to decrypt by. A STORED one's ends where
        the walk's scan finds its descriptor, on the ciphertext, as does a codec
        one's kept by ``drain``; a codec one's read from the walk where the decrypted
        codec ends, and the AES code is checked once the descriptor says where that
        was (``_finish``).
        """
        reader = self._reader
        member = self.member
        if loc.strong_encryption:
            raise UnsupportedFeatureError(
                _STRONG_ENCRYPTION_MSG,
                archive_name=reader._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        if loc.aes is None and self.entry.header.method == 99:
            raise UnsupportedFeatureError(
                "ZIP compression method 99 without a valid WinZip AES (0x9901) "
                "extra field",
                archive_name=reader._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        raw = _CutShortWatch(self._data, self)
        if reader._passwords.is_ambiguous():
            return self._confirm_password(loc, raw, decode)
        decrypted = reader._finish_password_attempt(
            member,
            lambda: reader._passwords.attempt(
                member, lambda password: self._stage(loc, raw, password)
            ),
            ambiguous_holder=None,
        )
        self._unconfirmed = loc.aes is None
        self._check = "weak_open_check"
        return decode(decrypted)

    def _stage(
        self,
        loc: _ZipLocator,
        raw: BinaryIO,
        password: bytes,
        *,
        probe: bool = False,
        ends_with_data: bool | None = None,
    ) -> BinaryIO:
        """The decrypt stage over ``raw`` for ``password``; raises the wrong-password
        ``EncryptionError`` when its cheap check fails.

        ``probe``: a confirm's trial, which leaves this member's state alone.
        ``ends_with_data``: ``raw`` ends where the data does (by default, unless the
        data runs on into what follows it).
        """
        reader = self._reader
        member = self.member
        header = self.entry.header
        deferred = self._deferred()
        if ends_with_data is None:
            # A bit-3 STORED member's data, or kept ciphertext, ends where its
            # ciphertext does.
            ends_with_data = not self._runs_on()
        aes = loc.aes
        if aes is not None:
            if not deferred:
                return open_winzip_aes_member(
                    raw,
                    aes=aes,
                    password=password,
                    compress_size=header.compressed_size,
                )
            forward = open_winzip_aes_forward(
                raw,
                aes=aes,
                password=password,
                hold_back=None if ends_with_data else _AES_HOLD_BACK,
            )
            if not ends_with_data and not probe:
                self._aes_pass = forward
            return forward
        # Inside the attempt, so a missing password is reported first, as from a
        # file.
        if not deferred and header.compressed_size < ZIPCRYPTO_HEADER_LEN:
            raise CorruptionError(
                "ZipCrypto member too short for its encryption header "
                f"({header.compressed_size} < {ZIPCRYPTO_HEADER_LEN})",
                archive_name=reader._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        head = read_exact(raw, ZIPCRYPTO_HEADER_LEN)
        if len(head) != ZIPCRYPTO_HEADER_LEN:
            # Only a bit-3 member gets here: a sized one's data raises
            # TruncatedError itself when the stream ends inside it. A codec one's
            # data runs on to the end of the stream; a STORED one's scan found the
            # descriptor first, so the data is whole and short.
            if not ends_with_data:
                raise TruncatedError(
                    "ZIP stream ends inside the encryption header of "
                    f"member {quoted(member.name)}",
                    archive_name=reader._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.ZIP,
                )
            raise CorruptionError(
                "ZipCrypto member too short for its encryption header "
                f"({len(head)} < {ZIPCRYPTO_HEADER_LEN})",
                archive_name=reader._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.ZIP,
            )
        keys, check = keys_after_header(password, head)
        if check != _zipcrypto_check_byte(loc):
            raise wrong_password_error(ZIP_WRONG_PASSWORD_MSG)
        # The length bounds seeks only, and nothing seeks a pass.
        length = max(0, header.compressed_size - ZIPCRYPTO_HEADER_LEN)
        return ZipCryptoDecryptStream(raw, keys, length=length)

    def _confirm_password(
        self,
        loc: _ZipLocator,
        raw: BinaryIO,
        decode: Callable[[BinaryIO], BinaryIO],
    ) -> BinaryIO:
        """Pick among several possible passwords, as the file read does, on the data's
        first ``_CONFIRM_SPOOL`` bytes.

        Each candidate that passes its cheap check decrypts and decodes those bytes
        (``_probe``): a CRC or HMAC reached in them confirms it, a codec's rejection or
        a mismatch rejects it, and anything else leaves it inconclusive. The data goes
        by once, so the walk to the end the file read takes to tell several
        inconclusive candidates apart is not available: the first of them wins, and
        its CRC or HMAC at the end is the test, as for one password. The kept bytes
        are replayed in front of the rest of the data for the winner.
        """
        reader = self._reader
        member = self.member
        spool = read_exact(raw, _CONFIRM_SPOOL)
        # The data ended inside the kept bytes: they are all of it.
        whole = self._ends_in(spool, raw)
        failures = _CandidateFailures()
        survivors = 0

        def probe(password: bytes) -> tuple[bytes, PasswordConfirmVerdict]:
            nonlocal survivors
            verdict = self._probe(loc, spool, whole, password, failures)
            survivors += 1
            return password, verdict

        password, verdict = reader._finish_password_attempt(
            member,
            lambda: attempt_with_confirm(reader._passwords, member, probe, None),
            ambiguous_holder=failures.ambiguous,
            failure_is_damage=loc.aes is not None,
            limit_holder=failures.limits,
        )
        confirmed = verdict is PasswordConfirmVerdict.CONFIRMED
        # As the file read: a lone survivor over a codec is the only key the data can
        # be under, so a failure further in is the codec's or the CRC's to report. A
        # STORED member's CRC is its only test, so its failure stays ambiguous, as
        # does the failure of the first of several survivors, which may be the wrong
        # one.
        self._unconfirmed = (
            loc.aes is None and not confirmed and (survivors > 1 or self._method() == 0)
        )
        self._check = None if confirmed else "confirm_budget_exhausted"
        self._replay = _Replay(spool, raw)
        return decode(self._stage(loc, self._replay, password))

    def _ends_in(self, spool: bytes, raw: BinaryIO) -> bool:
        """Whether the member's data ended inside ``spool``, read from ``raw``."""
        if len(spool) < _CONFIRM_SPOOL:
            # A short read is the data's end, except for a bit-3 codec member, whose
            # data runs on: there it is the stream's.
            return not self._runs_on()
        if self._deferred():
            return False
        return len(spool) >= self.entry.header.compressed_size

    def _probe(
        self,
        loc: _ZipLocator,
        spool: bytes,
        whole: bool,
        password: bytes,
        failures: _CandidateFailures,
    ) -> PasswordConfirmVerdict:
        """Judge one candidate on the kept bytes; never ``REJECTED``, which raises
        the error that rejects the candidate instead."""
        view = _SpoolView(spool)
        # The kept bytes stop short of the data's end, or of the stream's.
        partial = not whole and len(spool) == _CONFIRM_SPOOL

        def ran_out() -> bool:
            # A read reached the kept bytes' end before the data's: what ended
            # there is not the key's doing.
            return view.ended and partial

        aes = loc.aes
        keyed = aes is None and self._method() in _ZIP_KEYED_SETTINGS_METHODS
        # A wrong key raises its EncryptionError from the stage, before anything
        # below can mistake a damaged header for garbage.
        body = self._stage(loc, view, password, probe=True, ends_with_data=whole)
        decoded: BinaryIO | None = None
        ended_early: TruncatedError | None = None
        try:
            try:
                decoded = self._decode(loc, body, keyed=keyed, note_limit=False)
            except ResourceUnavailableError:
                # A shortage, not what the decrypted settings asked for: it must not
                # become a candidate failure below.
                raise
            except ResourceLimitError as exc:
                if not keyed:
                    raise
                raise failures.limit_failed(exc) from exc
            if self._deferred():
                verdict = self._judge_deferred(
                    decoded, body, view, spool, whole, ran_out
                )
            else:
                verdict = self._judge_sized(decoded, aes, ran_out)
                if verdict is PasswordConfirmVerdict.REJECTED and aes is not None:
                    # As the file read says it: a WinZip AES member's data ending
                    # before its declared size is the damage the one-password path
                    # reports as TruncatedError.
                    got = decoded.tell()
                    size = self.entry.header.file_size
                    if got < size and not decoded.read(1):
                        ended_early = TruncatedError(
                            f"Decompressed content ended after {got} of {size} "
                            "expected bytes."
                        )
        except EncryptionError:
            raise
        except ArchiveyError as exc:
            if ran_out():
                return PasswordConfirmVerdict.INCONCLUSIVE
            # As the member's own read judges it: a stream cut inside the data is
            # damage, whichever key read it.
            if not _is_candidate_integrity_failure(
                exc, payload_complete=lambda: not self._cut_short
            ):
                raise
            raise failures.failed(exc) from exc
        finally:
            if decoded is not None:
                decoded.close()
            else:
                body.close()
        if verdict is PasswordConfirmVerdict.REJECTED:
            raise failures.failed(ended_early)
        return verdict

    def _judge_sized(
        self,
        decoded: BinaryIO,
        aes: WinZipAesInfo | None,
        ran_out: Callable[[], bool],
    ) -> PasswordConfirmVerdict:
        """The file read's plan for a member whose local header states its size and
        CRC: the CRC when it is within the budget, else the codec's rejection; under
        WinZip AES the code at the end when the plan would walk there anyway."""
        header = self.entry.header
        size = header.file_size
        if aes is None and self._method() == 0:
            # As the file read's CRC pass over a STORED member: the body the
            # header's compressed size holds, whatever size it declares.
            size = max(0, header.compressed_size - ZIPCRYPTO_HEADER_LEN)
        anchor = None if self._ae2() else header.crc
        rejects = self._method() in _ZIP_REJECTING_METHODS
        plan = plan_password_confirm(
            [(size, anchor)],
            None,
            budget=PASSWORD_CONFIRM_PREFIX_BYTES,
            codec_rejects=rejects,
        )
        to_hmac = (
            aes is not None
            and not plan.confirms
            and (size <= PASSWORD_CONFIRM_PREFIX_BYTES or not rejects)
        )
        if to_hmac:
            plan = PasswordConfirmPlan(
                ((size, anchor),), None, confirms=True, bounded=False
            )
        verdict = run_password_confirm_plan(decoded, plan, input_exhausted=ran_out)
        if to_hmac and verdict is PasswordConfirmVerdict.CONFIRMED and decoded.read(1):
            # The read that finds the end is the one that checks the code.
            return PasswordConfirmVerdict.REJECTED
        return verdict

    def _judge_deferred(
        self,
        decoded: BinaryIO,
        body: BinaryIO,
        view: _SpoolView,
        spool: bytes,
        whole: bool,
        ran_out: Callable[[], bool],
    ) -> PasswordConfirmVerdict:
        """A bit-3 member's size and CRC follow its data, so only a member that ends
        inside the kept bytes can be confirmed: by the AES code when the stage ends
        with the data, or after a codec's end by the descriptor in the kept bytes
        that states the decoded size (and CRC, but for AE-2), which says where the
        code is; else by the descriptor's CRC, the one the walk found there (a
        STORED member's scan, kept ciphertext) or, after a codec's end, one in the
        kept bytes that states the decoded CRC and size. Otherwise the codec's
        rejection is the one signal, as for a sized member past the budget."""
        aes = cast("_ZipLocator", self.member._raw).aes
        crc = 0
        got = 0
        budget = PASSWORD_CONFIRM_PREFIX_BYTES
        codec_ended = False
        while got <= budget:
            try:
                chunk = decoded.read(
                    min(PASSWORD_CONFIRM_CHUNK_BYTES, budget + 1 - got)
                )
            except DataAfterEndError:
                # The codec ended and its input goes on: the descriptor is next.
                codec_ended = True
                break
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
            got += len(chunk)
        # The codec's own end stands even when its read-ahead reached the kept
        # bytes' end.
        if got > budget or (ran_out() and not codec_ended):
            return PasswordConfirmVerdict.INCONCLUSIVE
        if aes is not None and whole:
            # The stage ends with the data, and the read that found the end checked
            # the code.
            return PasswordConfirmVerdict.CONFIRMED
        if aes is not None:
            # An AE-2 member's descriptor stores no CRC: zero.
            found = descriptor_by_crc(
                spool,
                crc=0 if self._ae2() else crc,
                file_size=got,
                base=0,
                zip64=self.entry.zip64,
                at_end=False,
            )
            if found is None:
                return PasswordConfirmVerdict.INCONCLUSIVE
            at, descriptor = found
            assert isinstance(body, WinZipAesForwardStream)
            try:
                body.authenticate_end(
                    descriptor.compressed_size, spool[view.consumed : at]
                )
            except CorruptionError:
                return PasswordConfirmVerdict.REJECTED
            return PasswordConfirmVerdict.CONFIRMED
        if self._ae2() or got < PASSWORD_CONFIRM_MIN_VERIFIED_BYTES:
            # No CRC, or one over too few bytes to confirm.
            return PasswordConfirmVerdict.INCONCLUSIVE
        if whole:
            descriptor = self._data.found_descriptor
            if descriptor is None:
                return PasswordConfirmVerdict.INCONCLUSIVE
            if crc != descriptor.crc:
                return PasswordConfirmVerdict.REJECTED
            return PasswordConfirmVerdict.CONFIRMED
        # A codec ended inside the kept bytes, which run on past the data. A wrong
        # key's garbage that a codec ends early states no descriptor after it.
        found = descriptor_by_crc(
            spool,
            crc=crc,
            file_size=got,
            base=0,
            zip64=self.entry.zip64,
            at_end=False,
        )
        if found is None:
            return PasswordConfirmVerdict.INCONCLUSIVE
        return PasswordConfirmVerdict.CONFIRMED

    def read(self, n: int) -> bytes:
        """Up to ``n`` decoded bytes; ``b""`` once the data has ended and checked.

        The read that reaches the end raises ``CorruptionError`` when the data fails
        its CRC or size check, or for a ZipCrypto member the password may be wrong,
        the ``EncryptionError`` that says so, as from a file."""
        try:
            chunk = self._read_chunk(n)
            if not chunk and not self.done:
                self._finish(raise_mismatch=True)
        except ArchiveyError as exc:
            failure = self._as_read_failure(exc)
            if self._encrypted():
                self._failure = failure
            if failure is exc:
                raise
            raise failure from exc
        return chunk

    def _encrypted(self) -> bool:
        header = self.entry.header
        return _is_encrypted_entry(header.flags, header.method)

    def _as_read_failure(self, exc: ArchiveyError) -> ArchiveyError:
        """``exc`` as the caller sees it: under ZipCrypto, a failed integrity check
        may be a wrong password, and the error says so, as from a file."""
        if self._unconfirmed and _is_candidate_integrity_failure(
            exc, payload_complete=lambda: not self._cut_short
        ):
            failure = unverified_data_error(_UNCONFIRMED_PASSWORD_FAILURE)
            failure.__cause__ = exc
            return failure
        return exc

    def _read_chunk(self, n: int) -> bytes:
        """Up to ``n`` decoded bytes, or ``b""`` once the codec or the data ends."""
        if self.done or n == 0:
            return b""
        assert n > 0, "callers ask for a number of bytes"
        decoded = self._open_decoded()
        declared = None if self._deferred() else self.entry.header.file_size
        if declared is not None:
            # Nothing past the declared size and one byte is decoded: that byte is
            # the overrun, refused as the file read refuses it. The raise below
            # keeps ``_size`` at or under ``declared``, so this asks for one at least.
            n = min(n, declared + 1 - self._size)
        try:
            chunk = decoded.read(n)
        except DataAfterEndError:
            if not self._deferred():
                raise
            # The codec ended and its input goes on: the descriptor is next.
            chunk = b""
        if declared is not None and self._size + len(chunk) > declared:
            # The file read's verifier words it (``streams/verify.py``); the
            # ``_fixtures()`` table in ``test_zip_pipe_encrypted.py`` compares them.
            raise CorruptionError(
                f"Decompressed content exceeds its declared size of {declared} bytes."
            )
        if chunk:
            self._crc = zlib.crc32(chunk, self._crc)
            self._size += len(chunk)
            self._keep(chunk)
        return chunk

    def _finish(self, *, raise_mismatch: bool) -> CorruptionError | None:
        """Settle the data and check what was read against the header or descriptor.

        A mismatch is the caller's to see when the caller read the data; data the
        pass read past on its own is not checked for the caller, as a skipped member
        is not in the seekable read, and only loses its kept bytes. Returns the
        mismatch it did not raise.
        """
        self.done = True
        self._checked = True
        self._close_decoded()
        header = self.entry.header
        data = self._data
        member = self.member
        error: CorruptionError | None = None
        if self._deferred():
            if self._method() == 0:
                descriptor = data.settle()
            else:
                # An AE-2 member's descriptor stores no CRC: zero.
                crc = 0 if self._ae2() else self._crc
                descriptor = data.settle(crc=crc, file_size=self._size)
            assert descriptor is not None
            if self._aes_pass is not None:
                try:
                    # The data's bytes the stage did not read: what is left of the
                    # kept ones, then what the descriptor's search read past.
                    replayed = b"" if self._replay is None else self._replay.unread
                    self._aes_pass.authenticate_end(
                        descriptor.compressed_size, replayed + data.passed_over
                    )
                except CorruptionError as exc:
                    error = exc
            crc, file_size = descriptor.crc, descriptor.file_size
            # A kept member is decoded for its link target after the directory has
            # updated it: stamping the descriptor's view now would overwrite the
            # directory's, and ``drain`` already noted this descriptor.
            if not self._from_kept:
                self._reader._note_descriptor(self.entry, descriptor)
                # The descriptor dates the end from its own position, so its
                # compressed size is the member's, past any byte the codec's layers
                # read ahead.
                member.compressed_size = descriptor.compressed_size
                member.size = self._size
                if (
                    crc == self._crc
                    and not self._ae2()
                    and member.type is not MemberType.DIRECTORY
                ):
                    member.hashes = {HashAlgorithm.CRC32: crc32_digest(crc)}
        else:
            data.settle()
            crc, file_size = header.crc, header.file_size
        # A 4-byte descriptor holds the size modulo 2**32.
        size_ok = file_size == self._size or (
            self._deferred() and file_size == self._size & 0xFFFF_FFFF
        )
        # A failed AES code comes first: the data is not what was written.
        if error is None and not size_ok:
            # In the words a read through the size check gives (streams/verify.py).
            if self._size < file_size:
                error = TruncatedError(
                    f"Decompressed content ended after {self._size} of "
                    f"{file_size} expected bytes."
                )
            else:
                error = CorruptionError(
                    "Decompressed content exceeds its declared size of "
                    f"{file_size} bytes."
                )
        elif error is None and crc != self._crc and self._crc_is_digest(crc, file_size):
            error = CorruptionError(
                f"CRC-32 mismatch in ZIP member {quoted(member.name)}: stored "
                f"{crc:08x}, computed {self._crc:08x}"
            )
        if error is None:
            self.verified = True
        elif raise_mismatch:
            raise error
        return error

    def _crc_is_digest(self, crc: int, file_size: int) -> bool:
        """Whether the stored ``crc`` checks the data, by the file read's rule for a
        directory (``zip_reader._crc_is_digest``).

        Not for WinZip AE-2, which stores no CRC. For a directory, only when it
        declares data (``file_size`` above 0) under a non-zero field: 0 is a
        directory's conventional value, so the file read lists no digest for it and
        reports ``DIGEST_UNVERIFIABLE``, and a pass that reads the directory's data
        delivers it unchecked too (DR-5). Any other member's stored CRC is checked.
        """
        if self._ae2():
            return False
        if self.member.type is MemberType.DIRECTORY:
            return file_size > 0 and crc != 0
        return True

    def _ae2(self) -> bool:
        """A WinZip AE-2 member stores no CRC: its HMAC is the check."""
        aes = cast("_ZipLocator", self.member._raw).aes
        return aes is not None and aes.is_ae2

    def _close_decoded(self) -> None:
        decoded, self._decoded = self._decoded, None
        if decoded is not None and decoded is not self._data:
            decoded.close()

    def drain(self) -> None:
        """Read past what is left of the data, so the walk can go on.

        A member whose local header states its size is skipped without decoding, unless
        it is short enough to be a link target: the directory may yet make it one, and
        its target is these bytes. Of a longer one only the start a Windows reparse
        buffer's parse reads is decoded (``reparse_prefix``), unless it is encrypted and
        nobody read it (no key is derived for it, and its target's read says so). When
        the prefix reaches the data's end its CRC is checked, as the file read's byte
        past the buffer checks it. As with data within the cap, ``read_link_targets``
        off does not stop that decode: no key is derived and no provider asked, and a
        file read still reads the target when asked. That costs every such member a
        decoder, which a file read does not pay for a member it does not read: about
        0.1 ms, and for PPMd, whose decoder holds a sized member's input until it is all
        in, that input up to ``DecoderLimits``' in-process bound, past which a child
        process starts. That decode is only for the target, so its failure loses the bytes and
        nothing else, as a member nobody reads costs nothing from a file. An encrypted
        one keeps its ciphertext instead, decrypted only if the directory makes it a
        link (``_KeptCiphertext``): no key is derived for a member nobody asked for,
        unless its ciphertext is over ``_MAX_KEPT_CIPHERTEXT``, and then it is decoded
        here, its failure kept for the target's read. That decryption, unlike the
        reparse prefix, happens only under ``read_link_targets``, which allows reading a
        target nobody asked for, and asking a password provider for it: the member may
        turn out to be no link, which only a padded codec stream makes this long.

        A bit-3 STORED member is read to its end, which its scan finds. A bit-3 codec
        member is decoded no further than the byte past the target cap, then the
        reparse prefix the file read reads (the buffer and one byte) and one byte past
        it (``_wants_decoded``). Its codec finds its end only by decoding all of it,
        which no limit bounds, so where the decode stops short of that end, and where
        it fails, the walk's scan finds the end on the stored bytes, with no key
        (``_scan_rest``). An encrypted one, STORED or nobody read
        it, is not decoded: the scan finds its end on the ciphertext, and its
        ciphertext is kept as a sized one's is, if it is short enough to be a link's.
        One the caller opened is decoded with the key it was opened with.
        """
        if self.done:
            return
        header = self.entry.header
        encrypted = _is_encrypted_entry(header.flags, header.method)
        deferred = self._deferred()
        unopened = self._decoded is None and self._open_error is None
        if (
            deferred
            and encrypted
            and self._decoded is None
            and self._reader._walker.scan_starts_at_data_start(self._data)
        ):
            # A decrypt stage that failed to open (no password, or none passed its
            # check) read only the data's first bytes, which the scan puts back: the
            # member is passed over as one nobody read, as from a file. The
            # ciphertext kept then serves a member nobody read; one whose read
            # failed reports that failure instead (``uncaptured``).
            unopened = True
        # The data's end is found without decoding it: by its size, or for encrypted
        # bit-3 data by the scan, on the ciphertext.
        ends_undecoded = not deferred or (
            encrypted and (self._method() == 0 or unopened)
        )
        if deferred and ends_undecoded and self._method() != 0:
            self._data = self._reader._walker.scan_member_data(self._data)
        kept: bytes | None = None
        over_cap = False
        if deferred:
            skip = False
            if ends_undecoded and unopened:
                # Keep what a link target could be, and one byte more to tell.
                kept = read_exact(self._data, _MAX_KEPT_CIPHERTEXT + 1)
                skip = True
        else:
            skip = over_cap = header.file_size > MAX_LINK_TARGET_BYTES
            if (
                encrypted
                and not skip
                and unopened
                and header.compressed_size <= _MAX_KEPT_CIPHERTEXT
            ):
                # No key derived yet, and none is derived for a member nobody read
                # unless the directory makes it a link.
                kept = read_exact(self._data, header.compressed_size)
                skip = True
            elif (
                encrypted
                and not skip
                and unopened
                and not self._reader._config.read_link_targets
            ):
                # Decoding it here is reading a target nobody asked for, which
                # ``read_link_targets`` off rules out, with any password: no key
                # derived and no provider asked.
                self._failure = EncryptionError(
                    f"The pass did not decrypt {quoted(self.member.name)}: nobody "
                    f"read it, its ciphertext is over the {_MAX_KEPT_CIPHERTEXT} "
                    "bytes the pass keeps for a symlink target, and "
                    "read_link_targets is off"
                )
                skip = True
        if not skip and deferred and encrypted and self._failure is not None:
            # The caller's read failed inside the data.
            skip = self._scan_rest()
        if not skip:
            try:
                if self._runs_on():
                    # Decoding a bit-3 codec member to its end is the only way its
                    # codec finds it, at a cost nothing bounds: a bzip2 member of
                    # 900 bytes decodes to 1 GiB. Only what the capture wants, and
                    # the byte past it, is decoded (``_wants_decoded``); the scan
                    # finds where the rest ends.
                    while (want := self._wants_decoded()) and self._read_chunk(want):
                        pass
                    # With bytes still wanted the codec ended first, and the data is
                    # checked below as a read to its end is.
                    if not want:
                        skip = self._scan_rest()
                else:
                    while self._read_chunk(_DRAIN_CHUNK):
                        pass
            except ArchiveyError as exc:
                failure = self._as_read_failure(exc) if encrypted else exc
                # Only bit-3 data is decoded to find its end.
                if not ends_undecoded and not self._scan_rest():
                    # As the member's own read words it.
                    if failure is exc:
                        raise
                    raise failure from exc
                if encrypted:
                    self._failure = failure
                skip = True
        if over_cap and encrypted and unopened:
            # No key is derived for it, and the pass keeps no ciphertext of data
            # that decodes past the target cap: the reason, for its target's report.
            self._capture = None
            self._unread_encrypted = True
        elif over_cap:
            # Data over the target cap that nobody read to its end: its start, which
            # decides a reparse point's type and target once the directory makes it
            # one, as a file read reads it (``reparse_prefix``).
            try:
                while (want := self._wants_prefix()) and self._read_chunk(want):
                    pass
            except ArchiveyError as exc:
                self._capture = None
                self._failure = self._as_read_failure(exc) if encrypted else exc
            else:
                if self._size >= header.file_size:
                    # The start is all the data, as for most reparse buffers: the
                    # file read's byte past the buffer reaches the end and checks it.
                    self._finish_prefix(encrypted=encrypted)
                    return
        if skip:
            self.done = True
            if self._prefix_want is None:
                self._capture = None
            self._close_decoded()
            descriptor = self._data.settle()
            if descriptor is not None:
                self._reader._note_descriptor(self.entry, descriptor)
            if kept is not None and len(kept) <= _MAX_KEPT_CIPHERTEXT:
                self._kept = _KeptCiphertext(self.entry, kept, descriptor)
            elif kept is not None:
                self._too_long = True
            return
        if not self.done:
            error = self._finish(raise_mismatch=False)
            if self._unconfirmed and not self.verified:
                self._failure = unverified_data_error(_UNCONFIRMED_PASSWORD_FAILURE)
            elif encrypted and error is not None:
                self._failure = error

    def _finish_prefix(self, *, encrypted: bool) -> None:
        """Check data whose reparse prefix reached its end; a mismatch loses the
        prefix and is kept for the target's read."""
        error = self._finish(raise_mismatch=False)
        failure: ArchiveyError | None = None
        if self._unconfirmed and not self.verified:
            failure = unverified_data_error(_UNCONFIRMED_PASSWORD_FAILURE)
        elif error is not None:
            failure = self._as_read_failure(error) if encrypted else error
        if failure is not None:
            self._capture = None
            self._failure = failure

    def _scan_rest(self) -> bool:
        """Find the end of a bit-3 codec member by the walk's scan on its stored bytes,
        so the walk goes on as it does past an encrypted one nobody read: one whose
        decode failed, or one decoded as far as the capture wants and no further.

        After a failed decode the file read fails the member alone. The data is
        damaged, or a wrong key that passed its check byte decoded garbage; either way
        the codec's end is not the data's. The scan starts at the last bytes the walk
        kept (``LocalHeaderWalk.scan_member_data``). False for STORED data, which the
        walk already scans."""
        if self._method() == 0:
            return False
        self._close_decoded()
        self._data = self._reader._walker.scan_member_data(self._data)
        return True

    @property
    def uncaptured(
        self,
    ) -> str | int | ArchiveyError | _KeptCiphertext | _UnverifiedData | None:
        """Why a drained member's bytes were not kept, when not for their length:
        what the read of an encrypted member raised, its kept ciphertext, the length
        of a reparse buffer over ``_MAX_REPARSE_PREFIX``, or ``"damaged"``, with the
        data when all of it was kept (``_UnverifiedData``; see
        ``ZipForwardReader._link_target_opener``).
        """
        if self._failure is not None:
            return self._failure
        if self._overlong_buffer is not None:
            return self._overlong_buffer
        if self._unread_encrypted:
            return "encrypted"
        if self._kept is not None:
            return self._kept
        if self._too_long:
            return None
        header = self.entry.header
        if not self.verified and (
            self._deferred()
            or header.file_size <= MAX_LINK_TARGET_BYTES
            or self._size >= header.file_size
        ):
            capture = self._capture
            if capture is not None and self._prefix_want is None:
                return _UnverifiedData(bytes(capture))
            return "damaged"
        return None

    def abandon(self) -> None:
        """Release the decoder of a pass that will not read on."""
        self.done = True
        self._close_decoded()


class _UnverifiedData:
    """A member's whole decoded data, within the target cap, that failed its check.

    Kept because a file read of a Windows reparse buffer stops one byte past the
    buffer: when the data runs on past that, the file read never meets the failed
    check, and the data is no link buffer, so the member is a file
    (``ZipForwardReader._link_target_opener``). Any other link reports the damage.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data

    def __len__(self) -> int:
        return len(self.data)


#: What ``ZipForwardReader._hold`` leaves for dropped data that is no reparse buffer
#: as a file read reads one: the header, the payload it declares and one byte
#: (``_file_read_parses_no_buffer``). A reparse point's answer is then decided without
#: the bytes: the parse rejects the data, so the member is a file, or a
#: directory-shaped link with no target, as from a file
#: (``ZipForwardReader._link_target_opener``). Any other link has lost its data as the
#: reason each maps to says: dropped, or damaged for data that failed its check.
_DROPPED_NO_BUFFER = "dropped, no buffer"
_DAMAGED_NO_BUFFER = "damaged, no buffer"
_NO_BUFFER_REASONS = {_DROPPED_NO_BUFFER: _DROPPED, _DAMAGED_NO_BUFFER: "damaged"}


def _file_read_parses_no_buffer(data: bytes, *, check_failed: bool) -> bool:
    """Whether a file read of a reparse point holding ``data`` finds no link buffer.

    The file read reads the header, the payload it declares and one byte. Without
    ``check_failed``, ``data`` is what ``_captured`` holds: the whole data, which
    passed its check, or the start a file read reads of longer data
    (``_PassData.reparse_prefix``, which keeps none of data that ended within it and
    failed its check). Either way it holds every byte the file read parses, so that
    parse decides, verified or not. With ``check_failed``, ``data`` is the whole data
    of a member that failed its check (``_UnverifiedData``): it is no buffer only when
    it runs on past that read, which then never meets the failed check, and the parse
    rejects data longer than the buffer it declares; data ending within that read is
    damage instead.
    """
    reach = REPARSE_HEADER_BYTES + reparse_payload_length(data) + 1
    if check_failed:
        return len(data) > reach
    return parse_reparse_data(data[:reach]) is None


class _KeptCiphertext:
    """An encrypted member's ciphertext, kept as the pass read past it, so its link
    target is decrypted only once the directory says it is a link: a member nobody
    asked for costs no key derivation, as from a file."""

    def __init__(
        self, entry: LocalEntry, data: bytes, descriptor: DataDescriptor | None
    ) -> None:
        self.entry = entry
        self.data = data
        #: What followed a bit-3 member's data, which the walk read past it.
        self.descriptor = descriptor

    def __len__(self) -> int:
        return len(self.data)

    def decode(self, reader: ZipForwardReader, member: ArchiveMember) -> bytes:
        """The plaintext, up to one byte past the target cap, read as the caller's
        stream reads it: the same password attempt, codec and checks, so a failure is
        the one a read raises."""
        decoder = _PassData(reader, self.entry, member, _KeptData(self))
        out = bytearray()
        # One byte past the cap, as ``_read_link_target_data`` reads: a target that
        # long is refused there, and a shorter one reaches its end and its checks.
        while (left := MAX_LINK_TARGET_BYTES + 1 - len(out)) > 0 and (
            chunk := decoder.read(left)
        ):
            out += chunk
        return bytes(out)


class _KeptData(MemberData):
    """Kept ciphertext, read as the member's data from the walk would be."""

    def __init__(self, kept: _KeptCiphertext) -> None:  # noqa: PLW0231 - no walk
        ReadOnlyIOStream.__init__(self)
        self.entry = kept.entry
        self.consumed = 0
        self.passed_over = b""
        self._settled = False
        self._kept = kept.data
        self._descriptor = kept.descriptor

    def _read_some(self, size: int) -> bytes:
        chunk = self._kept[self.consumed : self.consumed + size]
        self.consumed += len(chunk)
        return chunk

    @property
    def found_descriptor(self) -> DataDescriptor | None:
        return self._descriptor

    def settle(
        self,
        used: int | None = None,
        *,
        crc: int | None = None,
        file_size: int | None = None,
    ) -> DataDescriptor | None:
        # Nothing after it to read past: the walk did, and kept the descriptor.
        self._settled = True
        return self._descriptor


class _SpoolView(ReadOnlyIOStream):
    """The kept first bytes of a member's data, as one confirm trial reads them.
    ``ended`` is set once a read found their end."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._data = data
        self._pos = 0
        self.ended = False

    @property
    def consumed(self) -> int:
        """How many of the kept bytes the trial has read."""
        return self._pos

    def read(self, n: int = -1, /) -> bytes:
        end = len(self._data) if n < 0 else self._pos + n
        chunk = self._data[self._pos : end]
        self._pos += len(chunk)
        if n != 0 and self._pos >= len(self._data) and (n < 0 or len(chunk) < n):
            self.ended = True
        return chunk


class _Replay(ReadOnlyIOStream):
    """The kept first bytes of a member's data, then the rest from ``source``: the
    data as the confirm's winner reads it. Closing it leaves ``source`` open."""

    def __init__(self, kept: bytes, source: BinaryIO) -> None:
        super().__init__()
        self._kept = kept
        self._pos = 0
        self._source = source

    @property
    def unread(self) -> bytes:
        """The kept bytes not read yet."""
        return self._kept[self._pos :]

    def read(self, n: int = -1, /) -> bytes:
        if self._pos < len(self._kept):
            end = len(self._kept) if n < 0 else self._pos + n
            chunk = self._kept[self._pos : end]
            self._pos += len(chunk)
            if n < 0 or len(chunk) < n:
                # Run on into the source, so a short read still means the end.
                return chunk + self._source.read(-1 if n < 0 else n - len(chunk))
            return chunk
        return self._source.read(n)


class _CutShortWatch(ReadOnlyIOStream):
    """The member's data as a decrypt stage reads it, noting on its ``_PassData``
    when the stream ends inside it: that ``TruncatedError`` is the archive's, not a
    wrong key's. Closing it leaves the data open, for the walk to settle."""

    def __init__(self, data: MemberData, owner: _PassData) -> None:
        super().__init__()
        self._data = data
        self._owner = owner

    def read(self, n: int = -1, /) -> bytes:
        try:
            chunk = self._data.read(n)
        except TruncatedError:
            self._owner._cut_short = True
            raise
        if (
            not chunk
            and n != 0
            and self._owner._runs_on()
            and not self._data.read_end_record
        ):
            # A bit-3 codec member's data runs on into what follows it, so its end
            # is the stream's: cut, unless the archive's end record went by first,
            # as the walk judges a descriptor it does not find.
            self._owner._cut_short = True
        return chunk


class _PassStream(ReadOnlyIOStream):
    """The caller's view of the member a forward pass is at.

    Good until the walk moves on to the next header, as a streaming TAR member's is.
    """

    def __init__(self, data: _PassData) -> None:
        super().__init__()
        self._pass_data = data

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("read from a closed ZIP member stream")
        data = self._pass_data
        if data.passed:
            raise ValueError(
                "ZIP member data is no longer readable: the walk has moved on"
            )
        if n is None or n < 0:
            chunks = []
            while chunk := data.read(_DRAIN_CHUNK):
                chunks.append(chunk)
            return b"".join(chunks)
        return data.read(n)


class ZipForwardReader(ZipReader):
    """Reads a ZIP front to back through its local headers (``LocalHeaderWalk``).

    Only ``streaming=True`` reaches it, on a source that cannot seek.
    """

    # The member list exists only once the walk has passed every member.
    _MEMBER_LIST_UPFRONT = False
    _REVISES_YIELDED_MEMBERS = True

    def _open_index(self, source: ArchiveSource, start_offset: int) -> None:
        self._fp = None
        self._walker = LocalHeaderWalk(source, offset=0, find_start=True)
        if start_offset:
            # The detector found a stub: read past it, so the walk starts at the
            # first local header and its offsets stay those of the file.
            skipped = self._walker.source.skip(start_offset)
            if skipped < start_offset:
                raise TruncatedError(
                    "ZIP stream ends inside the stub in front of the archive",
                    archive_name=self._archive_name,
                    source_format=ArchiveFormat.ZIP,
                )
        self._pass_data: _PassData | None = None
        # Local header offset -> why the header the directory names there, in the
        # bytes kept after the walk, did not parse (``_walk_held_members``): the
        # error alone, its frames dropped. Cleared on a pass that completes, with
        # the other maps of the walk; a pass that raises leaves them on the reader.
        self._rejected_headers: dict[int, ArchiveyError] = {}
        # How many local headers the walk has met: the next member's index, and
        # what ``max_members`` is charged on. Reset where the walk starts
        # (``_iter_members``).
        self._local_count = 0
        # Local header offset -> the member built from it, for the directory to
        # update in place at the end.
        self._by_offset: dict[int, ArchiveMember] = {}
        # Every local header offset the walk met, which the directory must account
        # for. ``max_members`` bounds its length, as it bounds the seekable read's offsets,
        # though a set costs some 60 bytes an offset against their array's 8, for a
        # lookup per directory entry.
        self._local_offsets: set[int] = set()
        # Local header offset -> where its data starts, for the bit-3 headers with the
        # ``UX`` extra field macOS Archive Utility writes: the directory walk measures
        # their compressed sizes past 4 GiB from them (``CentralDirectoryWalk``).
        self._mac_data_starts: dict[int, int] = {}
        # Member id -> its whole data, when short enough to be a link target, or the
        # start a Windows reparse buffer's parse reads of longer data
        # (``_PassData.reparse_prefix``), until the directory says which members are
        # links. Bounded with the kept ciphertext by ``_hold``, not charged to the
        # listing: most of it is files' data, which a file read does not keep.
        self._captured: dict[int, bytes] = {}
        # What ``_captured``, the kept ciphertext and the data held as
        # ``_UnverifiedData`` hold, in bytes, and a heap of (-length, member id) over
        # them, so ``_hold`` drops the longest first.
        self._kept_bytes = 0
        self._kept_heap: list[tuple[int, int]] = []
        # Member id -> why its data is not in ``_captured``, when not for its length
        # (``_PassData.uncaptured``), so a link's missing target says why. Two values
        # carry bytes rather than a reason: the kept ciphertext and the data that failed
        # its check (``_UnverifiedData``). ``_hold`` replaces what it drops with
        # ``_DROPPED``, ``"damaged"`` or one of ``_NO_BUFFER_REASONS``.
        self._uncaptured: dict[
            int, str | int | ArchiveyError | _KeptCiphertext | _UnverifiedData
        ] = {}
        # Local header offset -> what the data descriptor after a bit-3 member's data
        # said (CRC, compressed size, size), for the directory to confirm at the end.
        self._descriptors: dict[int, tuple[int, int, int]] = {}
        # The kept members in the directory's order, once it has been read.
        self._directory_order: list[ArchiveMember] | None = None
        self._end_record: EndRecord | None = None
        self._entries_read: int | None = None
        # The first header is parsed at open, so a stream that is no ZIP fails here
        # (DR-15b), as a TAR's does.
        try:
            self._first_entry: LocalEntry | None = self._walker.next_entry()
        except ArchiveyError as exc:
            self._stamp_error_context(exc)
            raise

    # -- the walk ----------------------------------------------------------------

    def _iter_members(self) -> Iterator[ArchiveMember]:
        walker = self._walker
        self._local_count = 0
        entry = self._first_entry
        self._first_entry = None
        while True:
            if self._local_count:
                self._leave_member()
                with self._translated_errors():
                    entry = walker.next_entry()
            if entry is None:
                break
            yield self._begin_member(entry)
        yield from self._read_directory()

    def _begin_member(self, entry: LocalEntry) -> ArchiveMember:
        """The member ``entry`` describes, its data open on the walk at it."""
        max_members = self._config.listing_limits.max_members
        index = self._local_count
        if max_members is not None and index >= max_members:
            error = _max_members_error(max_members, "ZIP local headers name")
            self._stamp_error_context(error)
            raise error
        member = self._local_member(entry, index)
        aes = cast("_ZipLocator", member._raw).aes
        self._pass_data = _PassData(
            self,
            entry,
            member,
            self._walker.member_data(
                entry,
                encrypted=_is_encrypted_entry(entry.header.flags, entry.header.method),
                # WinZip AES names the real method in its extra field.
                stored=None if aes is None else aes.actual_method == 0,
            ),
        )
        self._by_offset[entry.offset] = member
        self._local_offsets.add(entry.offset)
        if entry.deferred and entry.header.extra[:2] == b"UX":
            self._mac_data_starts[entry.offset] = entry.header.data_start
        self._local_count = index + 1
        return member

    def _walk_held_members(
        self, tail: ForwardTail, offsets: Iterable[int]
    ) -> Iterator[ArchiveMember]:
        """Yield the members the directory places after the walk's end, read from
        the bytes the pass kept there.

        The walk ends at the first bytes after a member that are no local header:
        the directory, or bytes between two members (a gap a writer left, a stray
        data descriptor), or a first archive's directory with a second archive
        after it (``cat a.zip b.zip``). A file read seeks to each offset the
        directory names, so the pass reads each such member from the kept bytes
        the same way, at those offsets only: no local header the directory does
        not name is read there. A directory entry whose local header the bound
        dropped is ``ResourceLimitError``, as a directory there is
        (``ForwardTail.end_record``): higher limits keep those bytes.

        Each entry is read from its offset to its data's end, or as far as its
        local header got before it failed to parse, and nothing keeps that short
        of the end of the stream, so entries whose bytes overlap would read the
        kept bytes once each. Every byte each attempt reads is counted, however it
        ends, and once the count reaches the bytes held, the next entry is
        ``CorruptionError`` before it is read: entries a writer laid out apart never
        take that much, so their bytes overlap, and no limit would relieve it.
        Together the attempts read the kept bytes at most twice. A local header
        that is there and does not parse fails its entry at the end of the pass,
        with the parse error as the reason (``_rejected_headers``).

        The directory walk has run by then, so its callbacks never see these
        members: ``local_name_at`` cannot correct a held member's offset wrapped
        past 4 GiB, and ``local_data_start_at`` gives no data start for a held
        bit-3 member with the macOS ``UX`` field. Both need an archive over 4 GiB
        with bytes in front of the member; the member then fails as missing, or
        its size is the directory's 32-bit one.
        """
        main = self._walker
        budget = len(tail.head) + len(tail.data)
        consumed = 0
        try:
            # Among the members' data, which the walk read as such, or past the end
            # of the stream, no local header is there to read.
            held_offsets = {
                offset for offset in offsets if tail.members_end <= offset < tail.size
            }
            for offset in sorted(held_offsets - self._local_offsets):
                if consumed >= budget:
                    raise CorruptionError(
                        "ZIP central directory places entries after the members a "
                        f"forward read walked ({tail.after}) whose bytes overlap: "
                        f"reading them has taken the {budget} bytes held there, "
                        "and entries a writer laid out apart never do",
                        archive_name=self._archive_name,
                        source_format=ArchiveFormat.ZIP,
                    )
                held = tail.held_from(offset)
                if held is None:
                    raise ResourceLimitError(
                        "ZIP central directory places a local header at stream "
                        f"offset {offset}, past the members a forward read walked "
                        f"({tail.after}), and the {tail.size - offset} bytes from "
                        "there to the end of the stream are more than it holds "
                        "within the listing limits",
                        archive_name=self._archive_name,
                        source_format=ArchiveFormat.ZIP,
                    )
                self._walker = LocalHeaderWalk(
                    held, offset=offset, find_start=False, index=self._local_count
                )
                try:
                    try:
                        with self._translated_errors():
                            entry = self._walker.next_entry()
                    except ArchiveyError as exc:
                        # A local header there that does not parse: the entry fails
                        # at the end of the pass, with this as the reason.
                        self._rejected_headers[offset] = _without_frames(exc)
                        continue
                    if entry is None:
                        # Other bytes: the entry fails as missing, as from a file.
                        continue
                    yield self._begin_member(entry)
                    self._leave_member()
                finally:
                    # Every byte this attempt read counts, however it ended.
                    consumed += self._walker.source.offset - offset
        finally:
            self._walker = main

    def _leave_member(self) -> None:
        """Read past the data of the member the walk is at, before the next header."""
        current = self._pass_data
        if current is None:
            return
        current.passed = True
        member = current.member
        try:
            with self._translated_errors(member.name):
                current.drain()
        except BaseException:
            # The walk ends here: release the decoder (a PPMd child process).
            current.abandon()
            raise
        finally:
            self._pass_data = None
        captured = current.captured
        if captured is None:
            captured = current.reparse_prefix
        assert member._member_id is not None
        if captured is not None:
            self._captured[member._member_id] = captured
            self._hold(member._member_id, len(captured))
        elif (why := current.uncaptured) is not None:
            self._uncaptured[member._member_id] = why
            if isinstance(why, _KeptCiphertext | _UnverifiedData):
                self._hold(member._member_id, len(why))

    def _hold(self, member_id: int, length: int) -> None:
        """Count ``length`` bytes just kept for ``member_id`` against the most the pass
        keeps for link targets, and drop the longest kept data while over it.

        Every member short enough to be a link keeps its data until the directory says
        which members are links, so an archive of many small files keeps most of its
        data. The pass holds at most ``max_metadata_bytes`` of it (none is charged to
        the listing, which a file read's never holds), on top of what the listing
        holds. Real link targets are paths, far shorter than most files, so the
        longest data goes first: a link loses its target only behind
        ``max_metadata_bytes`` of kept data no longer than its own, and is then listed
        without one (``_ensure_link_target``).

        A drop keeps no bytes. It leaves the reason, and for data that a reparse
        buffer's parse would reject as the file read reads it, that verdict
        (``_NO_BUFFER_REASONS``), so a reparse point whose data the bound dropped is
        still re-typed as from a file. The verdict costs one parse of at most the
        dropped data, at the drop, and nothing held: the verdict is a constant
        reason string, as the plain reason is.
        """
        budget = self._config.listing_limits.max_metadata_bytes
        if budget is None:
            return
        self._kept_bytes += length
        heap = self._kept_heap
        heapq.heappush(heap, (-length, member_id))
        while self._kept_bytes > budget:
            negative, dropped = heapq.heappop(heap)
            self._kept_bytes += negative
            kept = self._captured.pop(dropped, None)
            was = self._uncaptured.get(dropped)
            # Data that failed its check stays damaged without its bytes, for a link
            # that is no reparse point; kept ciphertext is not decoded to decide.
            if isinstance(was, _UnverifiedData):
                no_buffer = _file_read_parses_no_buffer(was.data, check_failed=True)
                why = _DAMAGED_NO_BUFFER if no_buffer else "damaged"
            else:
                no_buffer = kept is not None and _file_read_parses_no_buffer(
                    kept, check_failed=False
                )
                why = _DROPPED_NO_BUFFER if no_buffer else _DROPPED
            self._uncaptured[dropped] = why

    # -- the directory -------------------------------------------------------------

    def _read_directory(self) -> Iterator[ArchiveMember]:
        """Read the directory and end records, and update the members in place.

        The bytes after the last member are kept up to ``_tail_bound`` (``read_rest``)
        and parsed with the seekable read's code: ``find_end_record`` picks the end
        record a file read picks, and ``CentralDirectoryWalk`` reads the directory it
        names, so the pass lists what a file read lists and reports the same
        disagreements between the end record and the directory, except where
        ``ForwardTail.end_record`` refuses a record the pass cannot see (passed, or
        past the bound) or lets the classic end record stand in for a ZIP64 record
        among the members' data. Each local entry is matched to its directory
        entry by offset. The directory is authoritative: a member it describes is
        rebuilt from it, as the seekable read builds it, and the yielded object takes
        every field of that build. The entries are charged against ``max_members``
        as they are read, as the seekable read's directory walk charges them.

        The entries are held until every one has been read. Their names, extra fields
        and comments are weighed against ``max_metadata_bytes`` as they arrive
        (``_charge_held_directory``).

        A local entry no directory entry points to is dropped from the listing and
        reported (``ARCHIVE_UNLISTED_DATA``). Of two members with the same name, the
        later in the directory is current (``_listed_in_index_order``). A member whose
        local header names it differently takes the directory's name and is reported
        (``MEMBER_LOCAL_NAME_DIFFERS``), as a file read reports it when it reads that
        local header. A member whose data descriptor or local header the directory
        contradicts fails (``_failed_at_end``): the pass raises for the first, after a
        directory entry with no local entry and two entries for one local entry.
        """
        limits = self._config.listing_limits
        max_members = limits.max_members
        max_meta = limits.max_metadata_bytes
        with self._translated_errors():
            tail = self._walker.read_rest(_tail_bound(limits))
            end = tail.end_record()
        self._end_record = self._end = end
        # Weighed now that it is known, as a file read weighs it before the first
        # member.
        self._account_archive_comment()
        self._refuse_declared_count_over_limit()
        self._report_zip64_damage()
        by_offset = self._by_offset

        def local_name_at(offset: int) -> bytes | None:
            # The pass has every local header it met. The walk asks for the name of
            # the one an offset in the directory points at wherever a length or
            # offset field may be wrong: a corrected offset, an entry no central
            # header follows, and the first header a signature inside an entry's
            # fields chains to (an offset no local header has to back).
            member = by_offset.get(offset)
            return None if member is None else cast("_ZipLocator", member._raw).name

        walk = CentralDirectoryWalk(
            tail.read_at,
            end,
            local_name_at=local_name_at,
            local_data_start_at=self._mac_data_starts.get,
        )
        # Every entry's local header offset, in directory order, and the entries.
        offsets = array("q")
        entries: list[CentralEntry] = []
        held = 0
        # Damage part way through the directory: the entries before it update their
        # members, the members after it keep their local headers, and the damage is
        # raised at the end, as the seekable read lists past it (``_past_damage``).
        damage: CorruptionError | None = None
        try:
            with self._translated_errors():
                for central in walk:
                    if max_members is not None and len(offsets) >= max_members:
                        raise _max_members_error(max_members)
                    # Clamped as the seekable read's are: one past what the array
                    # holds points at no local header either, and fails as missing.
                    offsets.append(_bound_offset(central.header_offset))
                    held += (
                        len(central.name) + len(central.extra) + len(central.comment)
                    )
                    if max_meta is not None and held > max_meta:
                        self._charge_held_directory(held)
                    entries.append(central)
        except CorruptionError as exc:
            damage = exc
        yield from self._walk_held_members(tail, offsets)
        # A walk that met damage read no count.
        self._entries_read = None if damage is not None else walk.entries_read
        local_offsets = self._local_offsets
        updates: list[tuple[ArchiveMember, CentralEntry]] = []
        # Members whose local header named them differently, by member id: the name
        # the local header gave.
        renamed: dict[int, bytes] = {}
        remethoded: dict[int, int] = {}
        matched: set[int] = set()
        order: list[ArchiveMember] = []
        # Entries pointing at a local header an earlier entry already took (by
        # position in the directory).
        shared: list[int] = []
        failed: list[tuple[int, ArchiveMember, CorruptionError]] = []
        # Listed and missing members in the directory's order, for is_current.
        placed: list[ArchiveMember] = []
        any_missing = False
        for position, offset in enumerate(offsets):
            if offset not in local_offsets:
                missing = self._missing_member(entries[position], len(failed))
                failed.append(
                    (
                        position,
                        missing,
                        _missing_error(
                            missing,
                            entries[position].header_offset,
                            self._rejected_headers.get(offset),
                        ),
                    )
                )
                placed.append(missing)
                any_missing = True
                continue
            if offset in matched:
                shared.append(position)
                continue
            matched.add(offset)
            member = by_offset[offset]
            order.append(member)
            placed.append(member)
            central = entries[position]
            local_name = cast("_ZipLocator", member._raw).name
            if central.name != local_name:
                # Reported once the member has the directory's name, below.
                assert member._member_id is not None
                renamed[member._member_id] = local_name
            local_method = cast("_ZipLocator", member._raw).method
            if central.method != local_method:
                assert member._member_id is not None
                remethoded[member._member_id] = local_method
            updates.append((member, central))
            # ``_raw`` still holds the local header's fields: the directory replaces
            # it only in ``_update_from_directory``, after this loop.
            local = cast("_ZipLocator", member._raw)
            differ = _header_disagreements(
                local, central, crc_used=local.aes is None or not local.aes.is_ae2
            )
            descriptor = self._descriptors.get(offset)
            if differ:
                failed.append((position, member, _header_error(member, differ)))
            elif descriptor is not None and _contradicts(descriptor, central):
                failed.append(
                    (position, member, _descriptor_error(member, descriptor, central))
                )
        unlisted = sorted(local_offsets - matched)
        if damage is not None:
            # Past the damage, the members keep their local headers, in file order
            # after the directory's, as the seekable read lists them; they take part
            # in which copy of a name is current.
            kept = [by_offset[offset] for offset in unlisted]
            order.extend(kept)
            placed.extend(kept)
            unlisted = []
        for member, central in updates:
            self._update_from_directory(member, central)
            local_name = renamed.get(cast("int", member._member_id))
            if local_name is not None:
                # A file or link only, as from a file (``_report_local_name``).
                self._report_local_name(
                    cast("_ZipLocator", member._raw), member, local_name
                )
            local_method = remethoded.get(cast("int", member._member_id))
            if local_method is not None and _WINZIP_AES_METHOD not in (
                local_method,
                central.method,
            ):
                # The pass decoded by the local method, as a file read does
                # (``_with_local_method``); a file or link only, as from a file. A
                # file read reports once its local-header checks pass and before it
                # decodes, so it reports a member whose data then fails on a CRC-32
                # or size the directory contradicts, and so does the pass, which
                # fails that member at the end. It reports nothing for a member those
                # checks refuse: WinZip AES on one side, skipped here, and a central
                # compressed size the overlap guard refuses, not skipped. The pass
                # would have to rebuild the guard's bound (the next local header or
                # the directory, per member) to tell those apart, so it reports
                # them: a crafted-only difference (DR-5a), in the spec and zip.md.
                self._report_local_method(
                    cast("_ZipLocator", member._raw), member, local_method
                )
        if any_missing:
            # A missing entry has a name too, and takes part in last-entry-wins as the
            # seekable read's listing does: a listed copy it follows is not current.
            # The stamp over the listed members alone (``_end_walk``) leaves a member
            # made not current here as it is.
            _apply_last_entry_wins_is_current(placed)
        self._directory_order = order
        self._failed_at_end = [(member, error) for _, member, error in failed]
        # Only a link's bytes are read again, for its target; of data over the
        # target cap, only a Windows reparse point's start. This frees memory and
        # guards nothing: a plain symlink over the cap is refused by its size before
        # its bytes are asked for. ``size`` is the central entry's by now; the
        # ``None`` arm is for the type.
        links = {
            member._member_id
            for member, _ in updates
            if member.type is MemberType.SYMLINK
            and (
                cast("_ZipLocator", member._raw).reparse_fallback is not None
                or member.size is None
                or member.size <= MAX_LINK_TARGET_BYTES
            )
        }
        self._captured = {
            member_id: data
            for member_id, data in self._captured.items()
            if member_id in links
        }
        self._uncaptured = {
            member_id: why
            for member_id, why in self._uncaptured.items()
            if member_id in links
        }
        self._kept_heap = []
        self._kept_bytes = 0
        self._report_unlisted(unlisted)
        for finding in () if damage is not None else walk.findings:
            self._emit_walk_finding(finding)
        # The kept bytes end where the stream does, so the last ``trailing`` of them
        # follow the end record and its declared comment.
        trailing = tail.data[len(tail.data) - end.trailing :]
        found = first_nonzero_offset(io.BytesIO(trailing))
        if found is not None:
            self._emit_trailing_data(found)
        self._by_offset = {}
        self._local_offsets = set()
        self._mac_data_starts = {}
        self._descriptors = {}
        self._rejected_headers = {}
        if damage is not None:
            # The listing's error, as from a file; a member that fails a check of its
            # own fails at the end of the pass (``_failed_at_end``).
            raise damage
        if shared:
            first = shared[0]
            raise CorruptionError(
                f"ZIP central directory entry {self._directory_entry_label(entries, first)} "
                f"points to the local header at offset {offsets[first]}, "
                f"which an earlier entry already describes ({len(shared)} such entries); "
                "a source that cannot seek reads that data once, for one member",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.ZIP,
            )
        if failed:
            _, _, error = failed[0]
            raise error

    def _local_crc_for(self, entry: CentralEntry) -> int | None:
        """The seekable read's :meth:`ZipReader._local_crc_for`, from the local header
        the pass met at ``entry``'s offset rather than a read of it."""
        member = self._by_offset.get(_bound_offset(entry.header_offset))
        if member is None:
            return None
        local = cast("_ZipLocator", member._raw)
        if not _local_crc_stands_in(entry, local.flags, local.crc):
            return None
        return local.crc

    def _directory_data_reach(self, entry: CentralEntry) -> str | None:
        """A directory whose local header defers its sizes to a data descriptor (bit
        3) has no size when a pass reaches it, so the pass yields no stream and its
        data goes past unread: say so instead of promising a stream. The message is
        emitted on any listing, a pass or not, so it says what a pass does. Only a
        seekable source, which a reader lists from its central directory first,
        offers those bytes."""
        member = self._by_offset.get(_bound_offset(entry.header_offset))
        if member is None:
            return None
        local = cast("_ZipLocator", member._raw)
        if not local.flags & _ZIP_MASK_USE_DATA_DESCRIPTOR:
            return None
        return (
            "its data descriptor comes after them, so stream_members() over a source "
            "that cannot seek yields no stream for it; open() delivers them from a "
            "seekable source"
        )

    def _missing_member(self, central: CentralEntry, nth: int) -> ArchiveMember:
        """The member a directory entry with no local entry describes, for the end of
        the pass to fail (``_failed_at_end``).

        The pass never yielded it and the listing does not keep it; its id follows
        those the walk gave out, so it is told apart from every listed member. Its
        name counts for which copy is current (``_read_directory``).
        """
        member = self._to_member(central, self._walk_position + nth)
        member._member_id = self._walk_position + nth
        member._archive_id = self._archive_id
        return member

    def _report_unlisted(self, offsets: list[int]) -> None:
        """Drop the members at ``offsets`` from the listing, and report each.

        No directory entry lists them, so the seekable read never sees them: an update
        appended to the archive without rewriting its directory, or a member planted
        between two others. Data outside any member is a warning (DR-3). The report is
        the signal: the object the pass yielded keeps its fields (``is_current``
        among them), and only leaves the listing.

        A dropped member's metadata stays charged to the listing limits: the pass
        held it while it walked, as it holds any member, and refunding it would let
        planted entries cost nothing. So a pipe read can go over the limits on
        entries a file read never sees (DR-5a).
        """
        if not offsets:
            return
        by_offset = self._by_offset
        dropped = [by_offset[offset] for offset in offsets if offset in by_offset]
        if dropped:
            self._drop_listed(dropped)
        for offset in offsets:
            member = by_offset.get(offset)
            name = "" if member is None else member.name
            what = "a local entry" if member is None else f"member {quoted(name)}"
            self._diagnostics_collector.emit(
                code=DiagnosticCode.ARCHIVE_UNLISTED_DATA,
                message=(
                    f"ZIP stream holds {what} at offset {offset} that the central "
                    "directory does not list; it is left out, as reading the "
                    "archive from a file leaves it out (the archive may carry "
                    "something added to it without its directory being rewritten)."
                ),
                context=UnlistedDataContext(
                    archive_name=self._archive_name,
                    format="zip",
                    member_name=name,
                    member_id=None if member is None else member._member_id,
                    offset=offset,
                    compressed_size=None if member is None else member.compressed_size,
                ),
                logger=logger,
            )

    def _note_descriptor(self, entry: LocalEntry, descriptor: DataDescriptor) -> None:
        """Keep what a bit-3 member's data descriptor said, for the directory to
        confirm (``_read_directory``)."""
        self._descriptors[entry.offset] = (
            descriptor.crc,
            descriptor.compressed_size,
            descriptor.file_size,
        )

    def _listed_in_index_order(self) -> list[ArchiveMember]:
        """The kept members in the directory's order, once it has been read.

        The walk's order before then."""
        order = self._directory_order
        if order is None:
            return self._listed
        return order

    def _directory_entry_label(self, entries: list[CentralEntry], position: int) -> str:
        """The entry's name, quoted."""
        return quoted(self._decode_member_name(entries[position]).text)

    def _charge_held_directory(self, held: int) -> None:
        """Stop holding directory entries: their text passed ``max_metadata_bytes``.

        The seekable read builds a member from each entry as it reads it and weighs
        that; a forward pass holds the entries until the last is read, to match each
        to a local header, and the held text is what it weighs instead. It is charged
        to the listing, which it would have become, so the pass raises
        ``ResourceLimitError`` here.
        """
        self._listing_tracker.account_retained_bytes(held)
        raise AssertionError("held directory text over the cap passed the tracker")

    def _update_from_directory(
        self, member: ArchiveMember, central: CentralEntry
    ) -> None:
        """Give ``member`` the fields the seekable read builds from ``central``."""
        member_id = member._member_id
        assert member_id is not None
        old_name = member.name
        weighed = member_metadata_bytes(member)
        # What the pass counted, and the digest it matched (``_PassData._finish``).
        counted, counted_hashes = member.size, member.hashes
        fresh = self._to_member(central, member_id)
        for f in fields(ArchiveMember):
            if f.name in _KEPT_ON_UPDATE:
                continue
            setattr(member, f.name, getattr(fresh, f.name))
        self._keep_counted_size(member, counted, counted_hashes)
        member._diagnostics = member._diagnostics + fresh._diagnostics
        # The directory adds what no local header holds (a comment, its own extra
        # field); the limits weigh it when the pass is published, as they weigh the
        # seekable read's members when it lists them.
        self._listing_tracker.account_retained_bytes(
            member_metadata_bytes(member) - weighed, enforce=False
        )
        if member.name != old_name:
            self._reindex_name(member, old_name)
        if (
            member.type is MemberType.SYMLINK
            and member.link_target is None
            and not member._link_target_resolved
        ):
            member._link_target_unread = True

    def _keep_counted_size(
        self,
        member: ArchiveMember,
        counted: int | None,
        counted_hashes: Mapping[HashAlgorithm, bytes],
    ) -> None:
        """Give a member whose size the directory leaves unknown (a macOS Archive
        Utility ZIP past 4 GiB, ``_wrapped_size``) the size the pass counted, when the
        pass decoded it to the end with the directory's CRC-32 and the count fits what
        the directory stores, as a file read fills it in."""
        loc = member._raw
        if (
            member.size is not None
            or counted is None
            or not counted_hashes
            or counted_hashes != member.hashes
            or not isinstance(loc, _ZipLocator)
            or loc.size_unknown is None
        ):
            return
        try:
            loc.size_unknown.check(counted)
        except CorruptionError:
            return
        member.size = counted
        member._size_unread = False

    def _reindex_name(self, member: ArchiveMember, old_name: str) -> None:
        # By identity, though an equality scan would also find ``member``: its new
        # name is already set, so no other entry under ``old_name`` equals it.
        self._unindex_members(old_name, {id(member)})
        self._index_member_name(member)

    # -- data ----------------------------------------------------------------------

    def _iter_with_data(
        self, copies: FileCopyPass = DEFAULT_FILE_COPY_PASS
    ) -> Iterator[tuple[ArchiveMember, ArchiveStream | None]]:
        # close_previous=False: moving to the next header reads past the previous
        # member's data, and its stream reads nothing after that.

        def _open(member: ArchiveMember) -> ArchiveStream | None:
            if not pass_has_data(member):
                return None
            return self._open_member(member)

        yield from self._drive_pass_streams(
            self._begin_forward_pass(), open_member=_open, close_previous=False
        )

    def _open_member(self, member: ArchiveMember) -> ArchiveStream:
        current = self._pass_data
        if current is None or current.member is not member:
            raise ValueError(
                f"ZIP member {quoted(member.name)} is not the one the walk is at; "
                "a source that cannot seek is read once, member by member"
            )
        stream: BinaryIO = _PassStream(current)
        header = current.entry.header
        if _is_encrypted_entry(header.flags, header.method):
            # Only a cheap check vouched for the password, unless a confirm settled
            # it: ``_PassData._check``, known once the first read picked it, so read
            # at close. The
            # pass runs the CRC or the HMAC on the read after the last byte, not on
            # the one reaching the member's size, so no size is handed to the watch:
            # only reaching the end counts. Seeks would forfeit the check, but
            # nothing seeks a pass.
            stream = self._watch_unverified_read(
                stream,
                member,
                size=_NO_END_BEFORE_EOF,
                check=lambda: current._check,
                format_label="ZIP",
                digest="integrity check",
                why="the password was accepted on a weaker check",
            )
        return self._wrap_member_stream(stream, member.name, size=member.size)

    def _ensure_link_target(self, member: ArchiveMember) -> None:
        member_id = member._member_id
        why = None if member_id is None else self._uncaptured.get(member_id)
        if (
            isinstance(why, str)
            and why in _NO_BUFFER_REASONS
            and cast("_ZipLocator", member._raw).reparse_fallback is None
        ):
            why = _NO_BUFFER_REASONS[why]
        if (
            member.type is not MemberType.SYMLINK
            or member.link_target is not None
            or why != _DROPPED
        ):
            super()._ensure_link_target(member)
            return
        # ``_hold`` dropped the data to stay within the bound. The archive is not
        # damaged and a file read lists the target, so the link is listed without
        # one and says why, as for any target the read cannot reach; the rest of
        # the listing stands.
        budget = self._config.listing_limits.max_metadata_bytes
        assert budget is not None, "data is dropped only under a budget"
        self._emit_link_target_unavailable(
            member,
            reason="target_data_dropped",
            message=(
                f"The symlink target of {quoted(member.name)} was not kept: reading "
                "from a stream that cannot seek, the pass holds at most "
                f"max_metadata_bytes={budget} of the data of members short enough "
                "to be links until the directory says which are, and dropped this "
                "member's data as the longest; leaving link_target unset."
            ),
            target_in_archive=True,
        )

    def _link_target_opener(
        self, member: ArchiveMember
    ) -> Callable[[], AbstractContextManager[ReadableStream]]:
        """The bytes the pass kept for the link (``_leave_member``); without them, the
        error that says why, so the target is reported as the file read reports it."""
        member_id = member._member_id
        assert member_id is not None
        captured = self._captured.get(member_id)
        why = self._uncaptured.get(member_id)
        if (
            captured is None
            and isinstance(why, int)
            and member.size is not None
            and member.size > why
        ):
            # The pass kept nothing of a buffer over its bound, but the member's data
            # runs on past the buffer its header declares, so it is no link buffer
            # (``parse_reparse_data``) and the file read makes it a file. One byte, too
            # short for any buffer's header, gets the same answer from the same parse.
            # The report names the member's size from the directory (checked above),
            # not this byte's.
            captured = _NOT_A_REPARSE_BUFFER
        if isinstance(why, str) and why in _NO_BUFFER_REASONS:
            # ``_hold`` dropped the data, having found it no buffer as the file read
            # reads one: the same stand-in gets the same answer.
            if cast("_ZipLocator", member._raw).reparse_fallback is not None:
                captured = _NOT_A_REPARSE_BUFFER
            why = _NO_BUFFER_REASONS[why]
        if isinstance(why, _UnverifiedData):
            if cast("_ZipLocator", member._raw).reparse_fallback is not None:
                # What the file read reads of a reparse buffer: the header, the
                # payload it declares and one byte. Data longer than that is never
                # read to its failed check there, and parses as no buffer.
                data = why.data
                reach = REPARSE_HEADER_BYTES + reparse_payload_length(data) + 1
                if len(data) > reach:
                    captured = data[:reach]
            why = "damaged"

        def missing() -> ArchiveyError:
            if isinstance(why, ArchiveyError):
                return why
            cap = MAX_LINK_TARGET_BYTES
            if why == "encrypted":
                # Not an EncryptionError, which reports a missing password: the pass
                # did not try one.
                return CorruptionError(
                    f"The pass did not decrypt {quoted(member.name)}: nobody read it, "
                    f"and it decodes to more than the {cap}-byte symlink target cap, "
                    "past which the pass keeps no ciphertext"
                )
            if why == "damaged":
                return CorruptionError(
                    f"The data of symlink {quoted(member.name)} failed its check as "
                    "the pass read it"
                )
            if isinstance(why, int):
                # A target report takes a CorruptionError: the pass cannot read what
                # the file read would.
                return CorruptionError(
                    f"The data of {quoted(member.name)} starts with a reparse buffer "
                    f"of {why} bytes, over the {_MAX_REPARSE_PREFIX} the pass keeps "
                    "of one before the directory says it is a link"
                )
            return CorruptionError(
                f"The symlink target of {quoted(member.name)} was not kept as the "
                f"pass read its data: it is over {cap} bytes"
            )

        @contextmanager
        def open_data() -> Generator[ReadableStream, None, None]:
            if captured is not None:
                yield io.BytesIO(captured)
            elif isinstance(why, _KeptCiphertext):
                with self._translated_errors(member.name):
                    plain = why.decode(self, member)
                yield io.BytesIO(plain)
            else:
                raise missing()

        return open_data

    # -- what the caller sees ------------------------------------------------------

    def _account_archive_comment(self) -> None:
        # The walk starts before the end record is read: ``_read_directory`` weighs
        # the comment once it is. The base call at the start of the walk has to be
        # suppressed, not passed through with no comment: the tracker latches the
        # comment as counted on its first call, even for ``None``, so the later one
        # would weigh nothing.
        if self._end_record is not None:
            super()._account_archive_comment()

    def _archive_comment(self) -> str | None:
        end = self._end_record
        if end is None or not end.comment:
            return None
        return self._decode_unflagged_comment(end.comment)

    def _known_member_count(self) -> int | None:
        return self._entries_read

    def _cost_receipt(self) -> CostReceipt:
        return _ZIP_FORWARD_COST

    def _get_archive_info(self) -> ArchiveInfo:
        return ArchiveInfo(
            format=ArchiveFormat.ZIP,
            format_version=None,
            is_solid=False,
            member_count=self._known_member_count(),
            comment=self._archive_comment(),
            is_encrypted=False,
            is_multivolume=self._volume_count > 1,
            cost=_ZIP_FORWARD_COST,
            extra=ArchiveInfoExtra({"zip.volume_count": self._volume_count}),
        )

    def _close_archive(self) -> None:
        current, self._pass_data = self._pass_data, None
        if current is not None:
            current.abandon()


__all__ = ["ZipForwardReader"]
