"""Native RAR metadata parser (RAR 1.5 / 2.x / 3.x through RAR5).

Parses archive headers into :class:`RarArchive` / :class:`RarMemberInfo` without
decompressing member data and without importing ``rarfile``. Header encryption uses
:mod:`archivey.internal.streams.crypto` (never ``cryptography`` directly).

On-disk layout this module walks::

    [ optional SFX stub ][ magic ]
        RAR 1.5–3.x:  b"Rar!\\x1a\\x07\\x00"      → RarArchive.version == 4
        RAR5:         b"Rar!\\x1a\\x07\\x01\\x00"  → RarArchive.version == 5
    [ block sequence … until ENDARC ]
        RAR3 family: MARK / MAIN / FILE / … / ENDARC
          each: CRC16 | type | flags | header_size | [body] | [packed add_size]
        RAR5: vint-framed MAIN / FILE / SERVICE / ENCRYPTION / ENDARC
          optional encryption block before encrypted headers
          optional MAIN locator extra → QO SERVICE (FILE header copies after the members)
    FILE rows point at packed bytes after the header (``data_offset``).
    When a stored unencrypted QO is reachable from the locator, listing parses
    those copies, seeks back to after MAIN, and walks. A FILE whose offset is
    in QO is emitted from the copy and skipped (consecutive cached spans chain
    in memory, then one seek). ``CMT`` after MAIN is a normal SERVICE on that
    walk. FILE after QO is kept.

``RarArchive.version`` uses **4 for the whole RAR3-on-disk family** (1.5/2.x/3.x) and
**5 for RAR5** — not "RAR 4.x product version". Multi-volume sets are merged by
:func:`parse_rar_volumes` (split sizes/CRC; offsets rebased for
:class:`~archivey.internal.volumes.ConcatenatedFile`). Member **payload** decode is
``unrar`` via :mod:`.rar_unrar` / :mod:`.rar_reader`.

RAR3 SHA-1 / string-to-key and Unicode filename decompression are adapted from
``rarfile`` 4.3 (https://github.com/markokr/rarfile), Copyright (c) 2005-2024
Marko Kreen, used under the ISC License (see the notice at the bottom of this file).
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import io
import itertools
import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import pbkdf2_hmac
from typing import BinaryIO, NamedTuple, Protocol

from archivey.config import ListingLimits
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    raw_message_of,
)
from archivey.internal.config import KeyDerivationBudget
from archivey.internal.listing_limits import metadata_limit_error, text_bytes
from archivey.internal.password import wrong_password_error
from archivey.internal.sfx import SFX_MAX, describe_scan_miss, scan_for_magic
from archivey.internal.streams.crypto import AesParams, open_aes_decrypt_stage
from archivey.internal.streams.streamtools import read_exact
from archivey.internal.timestamps import (
    TimestampIssue,
    filetime_to_datetime,
    unix32_to_datetime,
)
from archivey.internal.trailing_scan import first_nonzero_offset
from archivey.internal.windows_reparse import normalize_windows_link_target
from archivey.terminal import quoted


class _Readable(Protocol):
    """Header-walk surface: sequential ``read`` plus a ciphertext ``tell``.

    Both the archive ``BinaryIO`` and :class:`_HeaderDecryptStream` provide this.
    It is not ``BinaryIO``: the decrypt stream is not an ``IOBase`` (no
    ``readinto`` / ``close`` / ``writable``), and the walk never seeks it —
    packed-data skips go through the underlying ``source`` so AES-CBC state is
    not asked to reposition. streamtools bases either close the inner stream
    or have no ciphertext ``tell``.
    """

    def read(self, n: int = -1, /) -> bytes: ...
    def tell(self) -> int: ...


# ---------------------------------------------------------------------------
# Magics / limits
# ---------------------------------------------------------------------------

RAR_ID = b"Rar!\x1a\x07\x00"
RAR5_ID = b"Rar!\x1a\x07\x01\x00"
_RAR_MAX_PASSWORD = 127
_RAR_MAX_KDF_SHIFT = 24
# RAR3's fixed key-derivation cost: 16 x 0x4000 SHA-1 rounds in ``_rar3_s2k``.
_RAR3_KDF_ROUNDS = 16 * 0x4000
_RAR5_MAX_HEADER = 2 * 1024 * 1024
# Most FILE extras are a handful of records (encryption, hash, time, version,
# redir, owner). Each skipped record is one retained tuple plus one diagnostic,
# and ``max_members`` cannot see that — it is one member. After this many the
# extra area is junk and the walk stops. Structural, not a ListingLimits
# field: a caller cannot usefully raise a "more skipped extras" budget.
_MAX_SKIPPED_HEADER_RECORDS = 16
# The ``record`` of the ``skipped_header_records`` entry for bytes between a RAR5
# header's fixed fields and its declared extra area. They are not a record, so the
# reader words that diagnostic on its own.
RAR5_UNPLACED_BYTES = "unplaced bytes"
# The ``record`` of the entry on the ``QO`` service header for its FILE copies whose
# ``header_offset`` a clean walk never reached (:func:`_qo_unmatched_copies`). Not a
# dropped record either: the QO payload parsed whole, and the reader words this
# diagnostic on its own. At most one per volume and it retains nothing
# attacker-sized, so :data:`_MAX_DAMAGED_SERVICE_HEADERS` does not count it.
RAR5_QO_UNMATCHED_COPIES = "unmatched copies"
# RAR 1.5-4 service header holding the preceding file's Unix owner (``rar -ow``),
# and the ``reason`` of the ``skipped_header_records`` entry for one whose data holds
# no NUL, which ``unrar`` applies no owner from.
RAR3_UOW_NAME = "UOW"
RAR3_UOW_NO_NUL = "no NUL in its owner data"
# SERVICE headers (``CMT``, ``QO``) are not members, so ``max_members`` never
# counts them and a damaged one is retained for the reader to report. Both halves
# of that are attacker-controlled: a 3.4 MB archive of nothing but damaged SERVICE
# headers retained 80 MB before this cap. Counting them as members instead would
# refuse an archive ``unrar`` lists, which is the opposite of this walk's posture,
# so they get their own cap and the overflow is reported as a count. Structural
# for the same reason as the cap above. It counts only headers whose walk did not
# finish: the overflow message says so, and a ``QO`` unmatched-copies entry is not one.
_MAX_DAMAGED_SERVICE_HEADERS = 16
# BytesIO/file seek offsets must fit in a C ssize_t; hostile RAR5 vints can exceed that.
_MAX_SEEK = (1 << 63) - 1
# Same default as ListingLimits.max_members. None is the explicit UNLIMITED opt-out.
_DEFAULT_MAX_MEMBERS = ListingLimits().max_members
_DEFAULT_MAX_METADATA_BYTES = ListingLimits().max_metadata_bytes

# RAR3 block types
_RAR3_MARK = 0x72
_RAR3_MAIN = 0x73
_RAR3_FILE = 0x74
_RAR3_OLD_COMMENT = 0x75
_RAR3_SUB = 0x7A
_RAR3_ENDARC = 0x7B

# RAR3 MAIN flags
_RAR3_MAIN_VOLUME = 0x0001
_RAR3_MAIN_COMMENT = 0x0002
_RAR3_MAIN_SOLID = 0x0008
_RAR3_MAIN_NEW_NUMBERING = 0x0010
_RAR3_MAIN_PASSWORD = 0x0080
_RAR3_MAIN_ENCRYPTVER = 0x0200

# RAR3 FILE flags
_RAR3_FILE_SPLIT_BEFORE = 0x0001
_RAR3_FILE_SPLIT_AFTER = 0x0002
_RAR3_FILE_PASSWORD = 0x0004
_RAR3_FILE_COMMENT = 0x0008
_RAR3_FILE_SOLID = 0x0010
_RAR3_FILE_DIRECTORY = 0x00E0
_RAR3_FILE_LARGE = 0x0100
_RAR3_FILE_UNICODE = 0x0200


def _utf8_over_encoding(raw: bytes, encoding: str | None) -> bool:
    """Whether :func:`_decode_rar3_8bit_name` took the UTF-8 reading of ``raw`` where
    the caller's ``encoding`` would have given a different name."""
    if encoding is None or raw.isascii():
        return False
    try:
        utf8 = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    try:
        return raw.decode(encoding, errors="surrogateescape") != utf8
    except UnicodeError:
        # A codec that refuses surrogateescape (``idna``) would not have named it.
        return False


_RAR3_FILE_SALT = 0x0400
_RAR3_FILE_VERSION = 0x0800
_RAR3_FILE_EXTTIME = 0x1000
_RAR3_LONG_BLOCK = 0x8000

_RAR3_OS_UNIX = 3
# MS-DOS, OS/2 and Win32: hosts whose RAR writers store an 8-bit name in the OEM
# code page (see ``_decode_rar3_8bit_name``).
_RAR3_OEM_HOSTS = frozenset({0, 1, 2})
_RAR3_M0 = 0x30

# RAR5 block types / flags
_RAR5_MAIN = 1
_RAR5_FILE = 2
_RAR5_SERVICE = 3
_RAR5_ENCRYPTION = 4
_RAR5_ENDARC = 5

_RAR5_FLAG_EXTRA = 0x01
_RAR5_FLAG_DATA = 0x02
_RAR5_FLAG_SPLIT_BEFORE = 0x08
_RAR5_FLAG_SPLIT_AFTER = 0x10

_RAR5_MAIN_ISVOL = 0x01
_RAR5_MAIN_HAS_VOLNR = 0x02
_RAR5_MAIN_SOLID = 0x04

_RAR5_FILE_ISDIR = 0x01
_RAR5_FILE_HAS_MTIME = 0x02
_RAR5_FILE_HAS_CRC32 = 0x04

_RAR5_COMPR_SOLID = 0x40

# Dictionary sizes. RAR3 keeps a 3-bit exponent in FILE flags bits 5-7 over a 64 KiB
# base (the value 7 marks a directory instead), so the format's largest is 4 MiB.
# RAR5 keeps it in compression-info bits 10-14 over a 128 KiB base. Algorithm 0
# (RAR 5.0) reads only the low 4 bits of it, so its largest is 4 GiB. Algorithm 1
# (RAR 7.0) reads all 5 bits and adds bits 15-19 in 1/32 steps of the power of two.
# The masks follow RARLAB unrar 7.00, the program whose allocation this sizes.
_RAR3_DICT_BASE = 0x10000
# The same three bits as ``_RAR3_FILE_DIRECTORY``: all ones is the directory marker.
_RAR3_DICT_MASK = 0x00E0
_RAR3_DICT_SHIFT = 5
_RAR5_DICT_BASE = 0x20000
_RAR5_DICT_SHIFT = 10
_RAR5_ALGO_MASK = 0x3F
_RAR5_ALGO_RAR50 = 0
# The newest RAR5 compression-info version ``unrar`` 7.00 decodes (1: RAR 7.0).
_RAR5_ALGO_NEWEST = 1
# The ``UNP_VER`` range ``unrar`` 7.00 accepts for RAR 1.5-4 compressed data.
_RAR3_UNP_VER_OLDEST = 13
_RAR3_UNP_VER_NEWEST = 29

_RAR5_ENC_HAS_CHECKVAL = 0x01
_RAR5_XENC_CHECKVAL = 0x01
_RAR5_XENC_TWEAKED = 0x02
_RAR5_XENC_AES256 = 0

_RAR5_XFILE_ENCRYPTION = 1
_RAR5_XFILE_HASH = 2
_RAR5_XFILE_TIME = 3
_RAR5_XFILE_VERSION = 4
_RAR5_XFILE_REDIR = 5
_RAR5_XFILE_OWNER = 6

# Names for the FHEXTRA record types, for the diagnostic raised when one of them
# is malformed and dropped. The numeric type travels with it, so a record this
# map does not name is still identifiable.
_RAR5_XNAMES: dict[int, str] = {
    _RAR5_XFILE_ENCRYPTION: "encryption",
    _RAR5_XFILE_HASH: "hash",
    _RAR5_XFILE_TIME: "time",
    _RAR5_XFILE_VERSION: "version",
    _RAR5_XFILE_REDIR: "redir",
    _RAR5_XFILE_OWNER: "owner",
}

_RAR5_MHEXTRA_LOCATOR = 1
_RAR5_MHEXTRA_LOCATOR_QLIST = 0x01
_RAR5_QO_NAME = "QO"
_RAR5_CMT_NAME = "CMT"
# Stored QO is copies of FILE headers (~50–200 B each; measured 55 B/member on
# `rar a -m0 -qo+`, RAR 7.00). 16 MiB covers roughly 300k members — below the
# 1 048 576 parser ceiling, so a very large archive silently falls back to the
# FILE walk (same listing, more seeks). The cap is a read-into-memory bound so a
# hostile packed-size cannot force a 2 GiB read.
_RAR5_QO_PAYLOAD_MAX = 16 * 1024 * 1024

_RAR5_XTIME_UNIXTIME = 0x01
_RAR5_XTIME_HAS_MTIME = 0x02
_RAR5_XTIME_HAS_CTIME = 0x04
_RAR5_XTIME_HAS_ATIME = 0x08
_RAR5_XTIME_UNIXTIME_NS = 0x10

_RAR5_XHASH_BLAKE2SP = 0

# FHEXTRA_UOWNER flags: which of the four owner fields follow, in this order.
_RAR5_XOWNER_UNAME = 0x01
_RAR5_XOWNER_GNAME = 0x02
_RAR5_XOWNER_UID = 0x04
_RAR5_XOWNER_GID = 0x08

_RAR5_XREDIR_UNIX_SYMLINK = 1
_RAR5_XREDIR_WINDOWS_SYMLINK = 2
_RAR5_XREDIR_WINDOWS_JUNCTION = 3
_RAR5_XREDIR_HARD_LINK = 4
_RAR5_XREDIR_FILE_COPY = 5

_RAR5_ENDARC_NEXT_VOLUME = 0x01

_RAR3_ENDARC_NEXT_VOLUME = 0x0001
_RAR3_ENDARC_DATACRC = 0x0002
# RAR 3.0 and later record the volume's 0-based number in its end block (RARLAB
# ``EARC_VOLNUMBER``); RAR 1.5 / 2.x do not.
_RAR3_ENDARC_VOLNUMBER = 0x0008
# 7-byte common header, then optional data CRC (4), volume number (2) and the
# reserved space RAR 2.x writers leave (7).
_RAR3_ENDARC_MAX_HEADER = 7 + 4 + 2 + 7

_RAR5_OS_WINDOWS = 0
_RAR5_OS_UNIX = 1

_S_BLK_HDR = struct.Struct("<HBHH")
_S_FILE_HDR = struct.Struct("<LLBLLBBHL")
_S_COMMENT_HDR = struct.Struct("<HBBH")
_S_LONG = struct.Struct("<L")
_S_SHORT = struct.Struct("<H")

# Bit 0 of a RAR 2.9-4 SERVICE header's attribute field (unrar's
# ``SUBHEAD_FLAGS_CMT_UNICODE``): the ``CMT`` payload is UTF-16LE. Without it unrar
# reads the payload as 8-bit text up to the first NUL (``Archive::ReadCommentData``).
_RAR3_SUBHEAD_CMT_UNICODE = 0x01

# The largest comment RARLAB ``rar`` writes and ``unrar`` shows: ``rar`` cuts a
# longer comment file to this size. A compressed RAR 2.9-4 ``CMT`` that declares
# more, or whose packed data is larger (``rar`` compresses a comment only when that
# makes it smaller), is dropped before its bytes are read or its decode is run. A
# stored ``CMT`` is not capped: its bytes are the text, and ``max_metadata_bytes``
# weighs all of them.
RAR3_MAX_COMMENT_SIZE = 0x40000


def rar3_main_crc_end(flags: int) -> int:
    """Exclusive end of MAIN-header CRC coverage, from the start of the block.

    Shared with the SFX hit validator so a flag-walk change cannot silently
    desync detection from the parser.
    """
    pos = _S_BLK_HDR.size
    if flags & _RAR3_LONG_BLOCK:
        pos += 4
    pos += 6
    if flags & _RAR3_MAIN_ENCRYPTVER:
        pos += 1
    return pos


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RarEncryptionInfo:
    algo: int
    flags: int
    kdf_count: int
    salt: bytes
    iv: bytes | None  # file-level has IV; header enc block may not
    check_value: bytes | None


@dataclass(slots=True)
class _Rar3Comment:
    """Compressed RAR 1.5-4 comment awaiting ``unrar`` in the reader layer.

    Two sources make one: a RAR 1.5-2.x COMMENT subblock (``crc16`` only) and a
    compressed RAR 2.9-4 ``CMT`` SERVICE header, which carries a full ``crc32`` and
    can hold UTF-16LE text (``utf16``, from ``_RAR3_SUBHEAD_CMT_UNICODE``).
    """

    packed: bytes
    unpacked_size: int
    extract_version: int
    compress_type: int
    flags: int
    crc16: int
    crc32: int | None = None
    utf16: bool = False


class RarOwner(NamedTuple):
    """A RAR5 owner record: names and numeric ids, each optional."""

    uname: str | None
    gname: str | None
    uid: int | None
    gid: int | None


@dataclass(slots=True)
class RarMemberInfo:
    filename: str
    orig_filename: bytes | None
    file_size: int
    compress_size: int
    # RAR3: the stored method byte as written, which a crafted header can set to
    # any value. RAR5: 0x30 plus its 3-bit method field (0x30..0x37).
    compress_type: int
    crc32: int | None
    blake2sp_hash: bytes | None
    mtime: datetime | None  # RAR4 naive; RAR5 aware UTC
    ctime: datetime | None  # same tz; Unix RARLAB writer stores st_ctime, not birth
    atime: datetime | None  # same tz; RAR5 0x03 HAS_ATIME / RAR3 EXTTIME after ctime
    mode: int | None
    host_os: int | None
    flags: int
    file_redir: tuple[int, int, str] | None  # type, flags, target
    file_encryption: RarEncryptionInfo | None
    header_offset: int
    header_size: int
    data_offset: int
    extract_version: int | None
    file_solid: bool
    is_directory: bool
    is_symlink: bool  # RAR4 unix mode or RAR5 redir symlink types
    is_hardlink_or_copy: bool  # RAR5 HARD_LINK or FILE_COPY: no data stream of its own
    is_encrypted: bool
    volume_index: int
    split_before: bool
    split_after: bool
    comment: str | _Rar3Comment | None = None
    spanned_volumes: bool = False
    # Where each part's packed bytes sit, as ``(data_offset, size)`` in the
    # concatenated volume space, for a member merged across volumes; empty for a
    # member in one part. ``data_offset`` and ``compress_size`` stay the first part's
    # offset and the total. Each part continues the one before it
    # (:func:`_merge_split_member`), and the merged member keeps the first part's
    # ``split_before`` and the last part's ``split_after``: with both clear the list
    # is the whole member. ``split_before`` set means the first part is in a volume
    # outside the set; the parser refuses that only when the continuation is the
    # first volume's first member. ``split_after`` set means the last part was not
    # found (an end block that claimed no next volume).
    data_parts: list[tuple[int, int]] = field(default_factory=list)
    # The dictionary (sliding window) size the header declares, in bytes; 0 for a
    # directory (on RAR5, one that is not also a link: its flag is kept apart from
    # the dictionary bits). A stored member declares one too, and no decoder uses
    # it. The header chooses this number: it is not bounded by the member's size,
    # and the reader checks it against ``DecoderLimits.max_decoder_memory`` before
    # a decompressor runs.
    dictionary_size: int = 0
    # RAR5 only: the compression-info version field (bits 0-5). ``None`` for RAR
    # 1.5-4, whose version is ``extract_version``.
    rar5_algorithm_version: int | None = None
    # A RAR3/4 encrypted member's own 8-byte salt (``FILE_SALT``); its data key and IV
    # are derived from the password and this salt. ``None`` for RAR5, whose salt is in
    # ``file_encryption``, and for a RAR3 member that stores none.
    rar3_salt: bytes | None = None
    # WinRAR ``-ver`` history: RAR5 FHEXTRA_VERSION vint, or RAR3 ``FILE_VERSION``
    # (``;n`` stripped from ``filename``). ``None`` / ``0`` = live revision.
    file_version: int | None = None
    # A RAR3 name whose Unicode field decoded, as decoded: what ``unrar`` compares
    # a ``-n`` mask against, once ``unrar_member_view`` splits a valid pair into
    # its two units. ``filename`` can differ from it
    # (``_fix_rar3_astral_truncation``). ``None`` for RAR5 and for a RAR3 name
    # ``unrar`` reads from the 8-bit field.
    rar3_unicode_name: str | None = None
    # A RAR 1.5-4 8-bit name, with no Unicode flag, that decoded as UTF-8 where the
    # caller's ``encoding=`` would have given a different name.
    rar3_utf8_over_encoding: bool = False
    # RAR5 FHEXTRA records that were malformed and dropped, and a RAR 1.5-4 ``UOW``
    # header after the member with no owner in it, as ``(record_name, record_type,
    # reason)``. Empty for every well-formed archive, and the shared empty tuple
    # keeps that case at one slot rather than an object: the listing bound is
    # expressed in members, so per-member retained bytes are load-bearing. Capped at
    # ``_MAX_SKIPPED_HEADER_RECORDS`` so a crafted extra area cannot retain one tuple
    # per attacker byte, and at one ``UOW`` entry per member. The reader turns each
    # entry into a ``MEMBER_HEADER_RECORD_SKIPPED`` diagnostic.
    skipped_header_records: tuple[tuple[str, int | None, str], ...] = ()
    # Why the extra-area walk gave up with area still unread, in the words the
    # diagnostic uses, or ``None`` when the header was read to the end. The list
    # above is then what was read rather than all there was. There is no count of
    # the rest: counting it would mean walking it, which is the cost the cap avoids.
    header_walk_stop_reason: str | None = None
    # Stored times that were present but invalid, and so left ``None``. The reader
    # turns each into a ``MEMBER_TIMESTAMP_INVALID`` diagnostic. Empty (the shared
    # tuple) for every well-formed header.
    timestamp_issues: tuple[TimestampIssue, ...] = ()
    # The owner ``rar -ow`` stores: ``(uname, gname, uid, gid)``, each ``None`` when
    # the record leaves it out. RAR5 reads it from the file header's owner record;
    # RAR 1.5-4 from the ``UOW`` service header after the file, which the walk
    # attaches to the member before it. ``None`` when there is no owner record.
    owner: RarOwner | None = None

    @property
    def skipped_header_records_truncated(self) -> bool:
        """True when the extra-area walk gave up with area still unread."""
        return self.header_walk_stop_reason is not None

    @property
    def encryption_unknown(self) -> bool:
        """True when the header stopped before encryption could be ruled out.

        The extra-area walk gave up with area still unread, and no encryption
        record had been seen — so an unread record may be the one that says this
        member is ciphertext. Distinct from :attr:`is_encrypted`, which is what
        the header actually said, because the two are acted on differently: a
        member that is *known* encrypted is presented with its parameters and
        needs a password, while one that is merely unknown is presented as
        encrypted (a wrong answer here is worse than a missing one) but asserts
        nothing about the archive it sits in.
        """
        return self.skipped_header_records_truncated and not self.is_encrypted

    def needs_password(self) -> bool:
        return self.is_encrypted

    def is_payload_file(self) -> bool:
        """True if ``unrar p`` emits this member's bytes (regular file, not dir/link/redir)."""
        return not (self.is_directory or self.is_symlink or self.is_hardlink_or_copy)

    def is_file_copy(self) -> bool:
        """True for a RAR5 ``FILE_COPY`` redirect (``rar -oi``, "file reference").

        A regular file whose bytes are those of an earlier member, stored once. Unlike a
        hard link it is extracted as an independent file, so it is presented as one.
        """
        redir = self.file_redir
        return (
            redir is not None
            and redir[0] == _RAR5_XREDIR_FILE_COPY
            and not self.is_directory
        )

    @property
    def is_stored(self) -> bool:
        """Whether the member's data is stored (method M0), not compressed.

        ``compress_type`` is normalised to the RAR3 method byte for both formats
        (``_RAR3_M0`` plus the RAR5 method), so this holds for RAR4 and RAR5 alike.
        """
        return self.compress_type == _RAR3_M0

    def unknown_compression_version(self) -> str | None:
        """The compression version this member declares and ``unrar`` cannot decode.

        ``None`` when the data can be decoded, or is stored: a stored member is
        copied whatever version it declares. Otherwise a short description of the
        version, for a message. The bounds are ``unrar`` 7.00's, measured: RAR5
        compression-info versions 0 (RAR 5.0) and 1 (RAR 7.0), and RAR 1.5-4
        ``UNP_VER`` 13 to 29. Outside them ``unrar`` reports "Unknown method" and
        "You may need a newer version of RAR" and writes nothing.
        """
        if self.is_stored:
            return None
        if self.rar5_algorithm_version is not None:
            if self.rar5_algorithm_version > _RAR5_ALGO_NEWEST:
                return f"RAR5 compression version {self.rar5_algorithm_version}"
            return None
        version = self.extract_version
        if version is not None and not (
            _RAR3_UNP_VER_OLDEST <= version <= _RAR3_UNP_VER_NEWEST
        ):
            return f"RAR compression version {version}"
        return None

    def is_file_version_history(self) -> bool:
        """True for a prior ``-ver`` revision (presented as ``path;n``)."""
        return self.file_version is not None and self.file_version != 0


@dataclass(slots=True, frozen=True)
class DamagedServiceHeader:
    """A SERVICE header whose extra-area walk dropped a record or gave up, or a ``QO``
    header whose FILE copies matched no header a clean walk reached
    (:data:`RAR5_QO_UNMATCHED_COPIES`).

    Not a :class:`RarMemberInfo`: a service header is not a member, nothing lists
    it, and keeping the whole parse of one both says otherwise and retains far more
    than the reader reads. These three fields are what the reader reports.
    """

    #: ``CMT``, ``QO`` — the header's own name, not a member name.
    name: str
    skipped_header_records: tuple[tuple[str, int | None, str], ...]
    header_walk_stop_reason: str | None


@dataclass(slots=True)
class RarArchive:
    version: int  # 4 = RAR3-on-disk family (1.5/2/3); 5 = RAR5 (not "RAR 4.x")
    is_solid: bool
    has_header_encryption: bool
    comment: str | _Rar3Comment | None
    members: _MemberList
    sfx_offset: int
    is_volume: bool
    needs_next_volume: bool = False
    #: A RAR 1.5-2.x volume set named ``name.rar``, ``name.r00``, ``name.r01`` …: the
    #: RAR3 main header lacks the new-numbering flag. ``False`` for RAR5 and for
    #: ``name.partN.rar`` sets. Taken from volume 1.
    old_volume_naming: bool = False
    #: SERVICE headers (``CMT``, ``QO``) whose extra-area walk dropped a record or
    #: gave up, in file order, at most ``_MAX_DAMAGED_SERVICE_HEADERS`` of them, plus
    #: at most one ``QO`` entry per volume for copies that matched no header the walk
    #: reached, which the cap does not count.
    #: They are not members, so nothing lists them and the reader's per-member
    #: diagnostics never see them — yet the same leniency applies to their headers,
    #: and the argument that leniency is not silent rests on a diagnostic being
    #: emitted. The reader emits from this at open.
    damaged_service_headers: list[DamagedServiceHeader] = field(default_factory=list)
    #: How many damaged SERVICE headers the cap above kept out of that list. The
    #: reader reports the count, so hitting the cap is itself never silent.
    damaged_service_headers_omitted: int = 0
    #: Set when the walk ended because the file was cut: a block's packed data ran past
    #: the end of the file, or the file ends part-way into a header. For an encrypted
    #: header that covers a cut in its salt or IV, or before its first whole cipher
    #: block. A cut after that block is set here only once the password is proven: in
    #: RAR5 by a password check value, in RAR 1.5-4 by an earlier encrypted header
    #: whose CRC16 matched. Before that it reads like a wrong key, so the walk raises
    #: ``EncryptionError`` at open and lists nothing: inside the first encrypted RAR
    #: 1.5-4 header, or any header of a RAR5 archive with no check value. A file that
    #: ends exactly at a header boundary is not cut. The members listed are a prefix.
    #: The reader lists them and then reports this as ``TruncatedError``, as TAR does
    #: for a member whose data runs past the end. The walk cannot tell it at open, so
    #: raising here would lose the prefix a caller can still read. A cut before the walk
    #: has read the main header leaves ``is_solid``, ``is_volume`` and
    #: ``old_volume_naming`` at their ``False`` defaults, and ``has_header_encryption``
    #: too when the cut is before the header that sets it: those values are not data.
    truncated: str | None = None
    #: Set when the walk ended at a member header whose CRC failed, after the main
    #: header. The members of that volume listed are the ones before it; no later
    #: member of that volume is listed. The reader lists them and then reports this
    #: as ``CorruptionError`` (DR-2), as TAR does for a damaged header after its
    #: first member. The walk does not go past the damaged header: its size is not
    #: data, so the next header's position is unknown. ``unrar`` searches for it;
    #: archivey does not. Not set for a damaged main header, which still raises at
    #: open, nor where the header password is unproven: there a CRC mismatch reads
    #: the same as a wrong key, so the walk raises the wrong-password
    #: ``EncryptionError``. In a set, ``needs_next_volume`` is still set by a member
    #: header before the damage (CRC intact) whose data continues, and the walk
    #: follows it: the next volume's first header is at its own offset 0, so the
    #: damaged header's size is not needed to find it. Its members are listed and the
    #: error follows the whole listing, as for a missing middle volume (DR-2).
    #: The first damaged volume's text is kept.
    damaged: str | None = None
    #: 0-based indices of the RAR5 volumes whose block walk reached end of file
    #: without an end-of-archive block. RAR5 writers always close a volume with one,
    #: so its absence means the file was cut at a header boundary — bytes that would
    #: otherwise list as a complete archive. The reader reports it as
    #: ``ARCHIVE_EOF_MARKER_MISSING`` after the members. Not set when
    #: ``truncated`` already reports the cut, nor for RAR 1.5-4, whose writers
    #: may omit the block.
    end_block_missing_volumes: list[int] = field(default_factory=list)
    #: 0-based volume index -> byte offset, within that volume, where its end-of-archive
    #: block starts (its salt or IV first, when headers are encrypted), for the volumes
    #: whose end block failed its header CRC. A header whose CRC failed is taken for the
    #: end block only if all three hold: its type reads as the end block, it has an end
    #: block's shape (no data area, a header no larger than an end block's), and nothing
    #: but zero padding follows it in the volume, as far as the 1 MiB trailing scan
    #: looks. One flipped byte cannot make a FILE header pass the shape; a MAIN header
    #: with no extra or data area can, and is then kept out only by the blocks after it
    #: (see ``dev-docs/formats/rar.md``). Anything else stays a ``CorruptionError``. The
    #: block sits after the last member, so the walk keeps the members before it and
    #: stops there; the reader reports the damage as ``ARCHIVE_EOF_MARKER_MISSING``
    #: after the members, and a strict policy refuses. The block's flags are not data
    #: once its CRC fails, so its next-volume flag is not read: ``needs_next_volume`` is
    #: then set only by a member header (CRC intact) whose data continues, as for a
    #: volume with no end block. Both formats. Never set where the header password is
    #: unproven: there a CRC mismatch reads the same as a wrong key, so the walk raises
    #: the wrong-password ``EncryptionError`` instead.
    end_block_damaged_volumes: dict[int, int] = field(default_factory=dict)
    #: 0-based volume index -> offset, counted from the end of that volume's
    #: end-of-archive block, of the first non-zero byte within
    #: :data:`~archivey.internal.trailing_scan.MAX_TRAILING_SCAN` bytes after it.
    #: Only for a volume whose end block was read intact: a damaged one is taken for
    #: the end block only when nothing but zeros follows it. The reader reports each as
    #: ``ARCHIVE_TRAILING_DATA`` after the members. Zero padding is not recorded.
    trailing_data_volumes: dict[int, int] = field(default_factory=dict)
    #: RAR 1.5-4 only: an encrypted header of this volume, or of an earlier volume
    #: of the set, decrypted with a matching CRC16, which proves the header password.
    #: :func:`parse_rar_volumes` passes it to the next volume's walk, since a set has
    #: one password, and merges it like the other fields: on the merged archive it
    #: is set when any volume proved the password.
    password_proven: bool = False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_rar_archive(
    source: BinaryIO,
    *,
    password: str | bytes | None = None,
    use_qo: bool = True,
    max_members: int | None = _DEFAULT_MAX_MEMBERS,
    max_metadata_bytes: int | None = _DEFAULT_MAX_METADATA_BYTES,
    kdf_cache: RarKdfCache | None = None,
    name_encoding: str | None = None,
) -> RarArchive:
    """Parse from current position (archive start). Source must be seekable.

    ``use_qo=False`` forces the FILE-header walk even when MAIN's locator
    points at a usable QO. Tests compare the two listings; production always
    leaves the default.

    ``max_members`` is ``ListingLimits.max_members`` from the reader config
    (``None`` = ``ListingLimits.UNLIMITED``). Omitting it uses the same default
    as ``ListingLimits()``; pass ``None`` to lift the bound. RAR has no
    header-size analogue, so ``None`` can walk until memory is exhausted.

    ``kdf_cache`` holds the header-key derivations. ``RarReader`` passes its own,
    so a member's PswCheck reuses the header's; without one the parse makes a
    fresh cache.

    ``name_encoding`` is the caller's ``encoding=``, for RAR 1.5-4 names stored
    as 8-bit bytes that are not valid UTF-8 (``_decode_rar3_8bit_name``). RAR5
    names are UTF-8.
    """
    return _parse_rar_volume(
        source,
        password=password,
        kdf_cache=kdf_cache if kdf_cache is not None else RarKdfCache(),
        volume_index=0,
        use_qo=use_qo,
        max_members=max_members,
        max_metadata_bytes=max_metadata_bytes,
        name_encoding=name_encoding,
    )


def parse_rar_volumes(
    volumes: Sequence[BinaryIO],
    *,
    password: str | bytes | None = None,
    use_qo: bool = True,
    max_members: int | None = _DEFAULT_MAX_MEMBERS,
    max_metadata_bytes: int | None = _DEFAULT_MAX_METADATA_BYTES,
    kdf_cache: RarKdfCache | None = None,
    name_encoding: str | None = None,
    volume_numbers: Sequence[int] | None = None,
) -> RarArchive:
    """Parse an ordered multi-volume RAR set, merging split members across volumes.

    Each volume is an independent seekable stream positioned at its start. Member
    ``header_offset`` / ``data_offset`` values are adjusted to a concatenated byte
    space (volume 0 at 0, volume 1 after volume 0's size, …) so a
    :class:`~archivey.internal.volumes.ConcatenatedFile` can serve stored reads.

    ``max_members`` is the same listing budget as :func:`parse_rar_archive`.
    Each volume is capped independently, and the merged table is capped again
    so two volumes that are each under the budget cannot together exceed it.

    Every volume shares one ``kdf_cache`` (the caller's, or a fresh one): each
    volume of a header-encrypted set carries its own encryption record, normally
    with the same salt, and would otherwise derive the same keys again.

    ``volume_numbers`` gives each volume's 1-based position in its set, when the
    set has gaps (volume 1 missing, or one in the middle); omitted, the volumes are
    ``1..N``. Ruled 2026-10-06: everything in the volumes present is listed, and
    the listing then ends with ``TruncatedError`` naming the missing volumes
    (``RarArchive.truncated``). Across a gap nothing is merged: the member that ran
    into it keeps ``split_after``, and a continuation that opens the volume after
    it is listed on its own with ``split_before`` (unrar warns "You need to start
    extraction from a previous volume" for it). Either flag left on a merged member
    means part of its data is missing, which is what the reader refuses on.
    """
    if not volumes:
        raise ValueError("at least one RAR volume is required")
    if volume_numbers is None:
        volume_numbers = range(1, len(volumes) + 1)
    if (
        len(volume_numbers) != len(volumes)
        or any(
            later <= earlier for earlier, later in itertools.pairwise(volume_numbers)
        )
        or volume_numbers[0] < 1
    ):
        raise ValueError("volume numbers must be increasing, from 1 up")
    if kdf_cache is None:
        kdf_cache = RarKdfCache()

    merged: RarArchive | None = None
    base_offset = 0
    password_proven = False
    missing: list[int] = list(range(1, volume_numbers[0]))
    previous = volume_numbers[0] - 1
    for volume, number in zip(volumes, volume_numbers):
        gap = number != previous + 1
        if gap and previous:
            missing.extend(range(previous + 1, number))
        previous = number
        # The walk's byte offsets are within this volume, not the concatenated space
        # the member offsets below use, so a message that gives one names the volume.
        where = (
            f" (volume {number} of the set; the offset is within that volume)"
            if len(volumes) > 1
            else ""
        )
        try:
            part = _parse_rar_volume(
                volume,
                password=password,
                kdf_cache=kdf_cache,
                volume_index=number - 1,
                use_qo=use_qo,
                max_members=max_members,
                max_metadata_bytes=max_metadata_bytes,
                name_encoding=name_encoding,
                password_proven=password_proven,
            )
        except EncryptionError as exc:
            if not where or not getattr(exc, _OFFSET_IN_VOLUME, False):
                raise
            # Still the wrong-password error, so a password list moves on.
            located = wrong_password_error(exc.raw_message + where)
            raise located.with_traceback(exc.__traceback__) from exc.__cause__
        password_proven = part.password_proven

        for member in part.members:
            member.header_offset += base_offset
            member.data_offset += base_offset
            member.data_parts = [
                (offset + base_offset, size) for offset, size in member.data_parts
            ]
        if where:
            if part.truncated is not None:
                part.truncated += where
            if part.damaged is not None:
                part.damaged += where

        if merged is None:
            merged = part
        else:
            if part.version != merged.version:
                raise CorruptionError(
                    f"RAR volume version mismatch: {merged.version} vs {part.version}"
                )
            merged.is_solid = merged.is_solid or part.is_solid
            merged.has_header_encryption = (
                merged.has_header_encryption or part.has_header_encryption
            )
            if part.comment and not merged.comment:
                merged.comment = part.comment
            merged.is_volume = True
            # Damaged SERVICE headers are per volume and the merge is field by
            # field, so leaving this out made a damaged header past volume 1
            # silent — the archive opened clean and nothing said a header could
            # not be finished. The cap applies to the merged list for the same
            # reason it applies to one volume's, and passes QO unmatched-copies
            # entries through as it does there.
            for damaged in part.damaged_service_headers:
                if not _append_damaged_service_header(
                    merged.damaged_service_headers, damaged
                ):
                    merged.damaged_service_headers_omitted += 1
            merged.damaged_service_headers_omitted += (
                part.damaged_service_headers_omitted
            )
            merged.truncated = merged.truncated or part.truncated
            merged.damaged = merged.damaged or part.damaged
            merged.password_proven = merged.password_proven or part.password_proven
            merged.end_block_missing_volumes.extend(part.end_block_missing_volumes)
            merged.end_block_damaged_volumes.update(part.end_block_damaged_volumes)
            merged.trailing_data_volumes.update(part.trailing_data_volumes)
            for position, member in enumerate(part.members):
                if gap and position == 0:
                    # Its earlier parts are in the missing volume: listed on its
                    # own, never folded into the member before the gap.
                    _append_member(
                        merged.members,
                        member,
                        max_members=max_members,
                        max_metadata_bytes=max_metadata_bytes,
                    )
                else:
                    _emit_file_member(
                        merged.members,
                        member,
                        max_members=max_members,
                        max_metadata_bytes=max_metadata_bytes,
                    )

        # Size of this volume for absolute offset adjustment.
        pos = volume.tell()
        end = volume.seek(0, 2)
        volume.seek(pos)
        base_offset += end

        merged.needs_next_volume = part.needs_next_volume
        if not part.needs_next_volume:
            # Archive is complete; ignore trailing unused volume paths if any were listed.
            break

    assert merged is not None
    mark_missing_next_volume(merged, volumes_read=previous, missing=missing)
    return merged


def mark_missing_next_volume(
    archive: RarArchive, *, volumes_read: int, missing: Sequence[int] = ()
) -> None:
    """Record the volumes a set is missing as a truncation.

    ``volumes_read`` is the number of the last volume read, and ``missing`` the
    numbers before it that were not there (volume 1, or a gap). The last volume
    read saying another follows adds the one after it. The members of the volumes
    present are kept and the listing ends with ``TruncatedError``, the same
    channel as a cut single file: ``unrar`` lists and tests the members it has and
    fails only on the ones that run into a missing volume. Those keep
    ``split_after`` or ``split_before``, which is what the reader refuses their
    data on. A cut the walk already recorded is the earlier fault and keeps its
    own message.
    """
    if archive.truncated is not None:
        return
    reasons: list[str] = []
    if missing:
        listed = ", ".join(str(number) for number in missing[:10])
        if len(missing) > 10:
            listed += f" and {len(missing) - 10} more"
        noun, verb = ("volume", "is") if len(missing) == 1 else ("volumes", "are")
        reasons.append(f"{noun} {listed} {verb} missing")
    if archive.needs_next_volume:
        reasons.append(
            "end of archive expects another volume "
            f"(volume {volumes_read + 1} is missing)"
        )
    if reasons:
        archive.truncated = "Incomplete RAR multi-volume set: " + "; ".join(reasons)


def _append_damaged_service_header(
    headers: list[DamagedServiceHeader],
    source: RarMemberInfo | DamagedServiceHeader,
) -> bool:
    """Retain a damaged SERVICE header, or report that the cap turned it away.

    Takes the parsed header from the walk or the already-narrowed record from
    another volume, and narrows it here rather than at the call sites, so nothing
    is built for a header the cap is about to turn away. The caller counts what
    this refuses: nothing is dropped silently, because the reader reports the
    count alongside the headers it does describe. A ``QO`` unmatched-copies entry
    is always kept and never counted: the overflow message says each counted
    header was not read to the end, which is not true of it.
    """
    if len(headers) >= _MAX_DAMAGED_SERVICE_HEADERS and not _is_qo_unmatched_copies(
        source
    ):
        return False
    headers.append(
        source
        if isinstance(source, DamagedServiceHeader)
        else DamagedServiceHeader(
            name=source.filename,
            skipped_header_records=source.skipped_header_records,
            header_walk_stop_reason=source.header_walk_stop_reason,
        )
    )
    return True


def _is_qo_unmatched_copies(source: RarMemberInfo | DamagedServiceHeader) -> bool:
    return isinstance(source, DamagedServiceHeader) and any(
        record == RAR5_QO_UNMATCHED_COPIES
        for record, _, _ in source.skipped_header_records
    )


# The two RAR5 redirect types that are Windows reparse points. RAR is the one format
# that records the kind in a header field rather than in the member's data, which is
# why it can flag both while listing and never has to read anything.
_RAR5_XREDIR_REPARSE_POINTS = frozenset(
    {_RAR5_XREDIR_WINDOWS_SYMLINK, _RAR5_XREDIR_WINDOWS_JUNCTION}
)


def _rar5_redirect_target(file_redir: tuple[int, int, str]) -> str:
    """The ``link_target`` of a RAR5 redirect record.

    A Windows symlink or junction stores a Windows path, so it is normalized the way a
    ZIP or 7z reparse buffer is (``\\??\\C:\\x`` gives ``C:/x``, ``..\\up`` gives
    ``../up``). Every ``\\`` becomes ``/``, as unrar's ``DosSlashToUnix`` does on
    POSIX. Dropping the ``\\??\\`` prefix is archivey's own step, and extraction then
    refuses a drive or UNC result. Measured on unrar 7.00 on Linux
    (``dev-docs/formats/rar.md``): it refuses the prefixed spellings too, by a
    different route, and it creates a stored, unprefixed ``C:\\abs\\y`` as the
    relative link ``C:/abs/y``, which archivey refuses. It also refuses ``..\\up\\x``,
    which archivey refuses only when the target leaves the destination. A Unix
    symlink, a hard link and a file copy keep the stored string: in those a backslash
    can be part of a name.
    """
    redir_type, _flags, target = file_redir
    if redir_type in _RAR5_XREDIR_REPARSE_POINTS:
        return normalize_windows_link_target(target)
    return target


class _MemberList(list[RarMemberInfo]):
    """A member list that keeps the running metadata weight of what it holds.

    Every walk, the QO run and the cross-volume merge build one, and
    :func:`_append_member` adds to its weight, so each list is held to
    ``max_metadata_bytes`` the way its length is held to ``max_members``.
    """

    __slots__ = ("metadata_bytes",)

    def __init__(self) -> None:
        super().__init__()
        self.metadata_bytes = 0


def comment_metadata_bytes(comment: str | _Rar3Comment | None) -> int:
    """A comment's weight before it is decoded.

    A compressed RAR 1.5-4 comment counts the larger of its declared size and its
    packed bytes. The declared size bounds the decode (``decompress_rar3_blob``
    discards output of any other length); the packed bytes are what the listing
    holds until then, and a header can declare a 1-byte text over 256 KiB of them.
    """
    if isinstance(comment, _Rar3Comment):
        return max(comment.unpacked_size, len(comment.packed))
    return text_bytes(comment)


def header_metadata_bytes(member: RarMemberInfo) -> int:
    """What the header gave ``member`` that the listing keeps, by the weights
    registration uses (``listing_limits``), applied to the stored values.

    The name counts twice, as ``name`` and ``raw_name`` do. It is the stored name:
    registration weighs the normalized one, which can be shorter (``a/./b`` lists as
    ``a/b``), so a name normalization shortens weighs a little more here. A RAR5 name
    has no stored bytes of its own, and its length stands for its UTF-8 bytes, which
    are at least that many. The owner's user and group names (RAR5 owner record,
    RAR 1.5-4 ``UOW`` header) count as ``uname`` and ``gname`` do. The comment
    counts per :func:`comment_metadata_bytes`.
    """
    filename = member.filename
    raw = member.orig_filename
    total = text_bytes(filename) + (len(raw) if raw is not None else len(filename))
    if member.file_redir is not None:
        total += text_bytes(_rar5_redirect_target(member.file_redir))
    if member.owner is not None:
        total += text_bytes(member.owner.uname) + text_bytes(member.owner.gname)
    return total + comment_metadata_bytes(member.comment)


def _append_member(
    members: _MemberList,
    member: RarMemberInfo,
    *,
    max_members: int | None,
    max_metadata_bytes: int | None,
) -> None:
    # ``None`` is ListingLimits.UNLIMITED: no count bound. RAR walks sequentially
    # and has no header-size analogue, so UNLIMITED can allocate until OOM.
    # Refuse the member that would make len == max_members + 1 — same bound as
    # ListingLimitTracker._check_members (count > max_members after increment).
    if max_members is not None and len(members) >= max_members:
        raise ResourceLimitError(
            f"Listing limit reached: max_members={max_members} "
            f"(registered {len(members) + 1} members)"
        )
    # The names a header walk keeps are held to the metadata budget here, as they
    # arrive, not only when the members are registered after the whole walk: a
    # volume's headers have no size bound of their own (RAR5 caps one header at
    # 2 MiB, RAR 1.5-4 a name at 64 KiB), so ``max_members`` long names would
    # otherwise all be in memory first. A split member's later parts merge into
    # the first and are not weighed again. Under ``None`` nothing reads the total.
    if max_metadata_bytes is not None:
        _charge_metadata(
            members,
            header_metadata_bytes(member),
            max_metadata_bytes,
            count=len(members) + 1,
        )
    members.append(member)


def _charge_metadata(
    members: _MemberList, nbytes: int, max_metadata_bytes: int, *, count: int
) -> None:
    """Add ``nbytes`` to ``members``' running weight, refusing past the budget.

    The message is built only on refusal: this runs once per member of the walk.
    """
    total = members.metadata_bytes + nbytes
    if total > max_metadata_bytes:
        raise metadata_limit_error(
            max_metadata_bytes, f"RAR headers of {count} members hold {total} bytes"
        )
    members.metadata_bytes = total


def _parse_rar_volume(
    source: BinaryIO,
    *,
    password: str | bytes | None,
    kdf_cache: RarKdfCache,
    volume_index: int,
    use_qo: bool = True,
    max_members: int | None,
    max_metadata_bytes: int | None,
    name_encoding: str | None = None,
    password_proven: bool = False,
) -> RarArchive:
    """Parse one volume — one seekable source — into a :class:`RarArchive`.

    ``parse_rar_archive`` calls this for a single-file archive (volume index 0).
    ``parse_rar_volumes`` calls it once per volume and merges split members.
    ``volume_index`` is the 0-based position in that set, not a RAR format
    version: RAR3-on-disk is ``archive.version == 4``, RAR5 is ``5``.
    A ``split_before`` member on the first volume is refused ("Need first
    volume") rather than listed as a fragment.
    ``password_proven`` carries an earlier RAR 1.5-4 volume's proof of the header
    password into this volume's walk (:attr:`RarArchive.password_proven`).
    """
    start = source.tell()
    version, sfx_offset = _find_sfx_header(source, start)
    source.seek(start + sfx_offset)
    try:
        if version == 5:
            archive = _parse_rar5(
                source,
                password=password,
                kdf_cache=kdf_cache,
                sfx_offset=sfx_offset,
                volume_index=volume_index,
                use_qo=use_qo,
                max_members=max_members,
                max_metadata_bytes=max_metadata_bytes,
            )
        else:
            archive = _parse_rar3(
                source,
                password=password,
                kdf_cache=kdf_cache,
                sfx_offset=sfx_offset,
                volume_index=volume_index,
                max_members=max_members,
                max_metadata_bytes=max_metadata_bytes,
                name_encoding=name_encoding,
                password_proven=password_proven,
            )
    except _PRIVATE_WALK_ERRORS as exc:
        raise _public_walk_error(exc) from None
    # RAR5 normally refuses a later volume earlier, from MAIN's volume number;
    # this check covers RAR 1.5-4, which records none, and a RAR5 MAIN without one.
    # The emit rule appends a split_before member only to an empty list, so
    # members[0] is the only place a continuation can show on volume 1.
    if volume_index == 0 and archive.members and archive.members[0].split_before:
        raise UnsupportedFeatureError("Need first volume of multi-volume RAR archive")
    return archive


# ---------------------------------------------------------------------------
# SFX detection
# ---------------------------------------------------------------------------


def _find_sfx_header(source: BinaryIO, start: int) -> tuple[int, int]:
    """Return ``(version, offset_from_start)`` for RAR4 (version 4) or RAR5.

    Scanning both ids rather than their shared ``Rar!\x1a\x07`` prefix lets the shared
    scanner resolve the version by which id matched first, so a stub containing the bare
    prefix (without a valid version byte) no longer needs a rescan loop here. A
    candidate that fails :func:`~archivey.internal.backends.rar_detect.validate_rar_main_header`
    is skipped while a later ``VALID`` hit is sought; if none validate, the first
    identified candidate is used so a damaged payload still reaches the parser.
    """
    source.seek(start)
    # Fast path: magic at current position.
    head = read_exact(source, len(RAR5_ID))
    if head.startswith(RAR5_ID):
        return 5, 0
    if head.startswith(RAR_ID):
        return 4, 0

    source.seek(start)
    # Imported here: rar_detect imports this module for the ids / CRC helpers.
    from archivey.internal.backends.rar_detect import validate_rar_main_header

    scan = scan_for_magic(
        source,
        (RAR5_ID, RAR_ID),
        limit=SFX_MAX,
        validator=validate_rar_main_header,
    )
    if scan.hit is not None:
        return (5 if scan.hit.needle == RAR5_ID else 4), scan.hit.candidate_origin

    raise CorruptionError(
        "Not a RAR archive: " + describe_scan_miss(scan, limit=SFX_MAX)
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _crc32(data: bytes | memoryview) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _require_exact(stream: BinaryIO, n: int, what: str) -> bytes:
    if n < 0 or n > _MAX_SEEK:
        raise CorruptionError(f"Invalid {what} length: {n}")
    try:
        data = read_exact(stream, n)
    except OverflowError as exc:
        raise CorruptionError(f"Invalid {what} length: {n}") from exc
    if len(data) != n:
        raise CorruptionError(f"Unexpected EOF while reading {what}")
    return data


def _read_comment(
    stream: BinaryIO, n: int, what: str, max_metadata_bytes: int | None
) -> bytes:
    """A comment's ``n`` packed bytes, refused before the read when ``n`` alone is
    over ``max_metadata_bytes``.

    The walks call it only for a span inside the file (:func:`_span_in_file`), so a
    cut comment is reported as a cut and the read gets every byte it asks for. A
    stored comment has no size cap of its own, and its packed bytes are what the
    read holds, so they are weighed here, before the cost is paid (DR-9). The later
    total weighs the comment too: for a member's comment, the ``_charge_metadata``
    call in :func:`_parse_rar3`'s ``file_solid`` arm, which charges it to the member
    it attaches to; for the archive comment, ``RarReader._check_header_metadata_budget``.
    This check weighs the packed bytes and that total weighs the decoded text
    (:func:`comment_metadata_bytes`), so this one is stricter wherever the text is
    smaller than its packed bytes: a UTF-16LE comment, about half as many characters
    as it packs, and one whose text stops at a NUL. Those bytes are held all the
    same, as a compressed comment's packed bytes are weighed.
    """
    if max_metadata_bytes is not None and n > max_metadata_bytes:
        raise metadata_limit_error(max_metadata_bytes, f"a RAR comment packs {n} bytes")
    return _require_exact(stream, n, what)


def _packed_span_end(data_offset: int, add_size: int) -> int:
    """First byte after a packed-data region, or CorruptionError on a hostile span."""
    if data_offset < 0 or add_size < 0:
        raise CorruptionError(
            f"Invalid RAR packed-data span: offset={data_offset}, size={add_size}"
        )
    if add_size > _MAX_SEEK - data_offset:
        raise CorruptionError(
            f"RAR packed size {add_size} at offset {data_offset} exceeds the seekable range"
        )
    return data_offset + add_size


def _seek_to(source: BinaryIO, pos: int) -> None:
    if pos < 0 or pos > _MAX_SEEK:
        raise CorruptionError(f"Invalid RAR seek offset: {pos}")
    try:
        source.seek(pos)
    except (OverflowError, OSError) as exc:
        raise CorruptionError(f"RAR packed-data seek failed at offset {pos}") from exc


def _scan_after_end_block(source: BinaryIO, end: int) -> int | None:
    """Where the first non-zero byte after an end block at ``end`` lies, if any.

    ``end`` is where the block's bytes stop in the volume: past any data area it
    declares, as every other block ends, and past its AES padding when headers are
    encrypted, as the walk's ``data_offset`` is a ciphertext offset. The read position
    is left at ``end``. See ``RarArchive.trailing_data_volumes``.
    """
    _seek_to(source, end)
    try:
        return first_nonzero_offset(source)
    finally:
        source.seek(end)


def _only_zeros_after(source: BinaryIO, pos: int) -> bool:
    """Whether nothing but zero padding follows ``pos``; the read position is kept.

    The same test an intact end block's tail gets, with the same 1 MiB bound, so a
    damaged end block on a volume ``rar`` padded with zeros is still recognised as one.
    """
    here = source.tell()
    try:
        return _scan_after_end_block(source, pos) is None
    finally:
        source.seek(here)


def _rar3_end_block_shaped(flags: int, header_size: int) -> bool:
    """Whether a RAR 1.5-4 header has an end block's shape, whatever its CRC.

    An end block has no data area, so no ``LONG_BLOCK`` flag, and its header is 7
    bytes plus at most a data CRC (4), a volume number (2) and 7 reserved bytes:
    20 at most. A FILE header's fixed fields are 25 bytes past the 7-byte common
    header, so even one with ``LONG_BLOCK`` clear is larger than that.
    """
    return not flags & _RAR3_LONG_BLOCK and header_size <= _RAR3_ENDARC_MAX_HEADER


def _rar3_end_block_volume_number(
    hdata: bytes, flags: int, header_size: int
) -> int | None:
    """The 0-based volume number a RAR 1.5-4 end block records, or ``None``.

    It follows the 7-byte common header and the optional data CRC. RAR 3.0 and
    later write it on every volume; RAR 1.5 / 2.x, and a header too short to hold
    it, give ``None``.
    """
    if not flags & _RAR3_ENDARC_VOLNUMBER:
        return None
    pos = 7 + (4 if flags & _RAR3_ENDARC_DATACRC else 0)
    if pos + 2 > header_size:
        return None
    return int.from_bytes(hdata[pos : pos + 2], "little")


def _rar5_end_block_shaped(hdata: bytes, pos: int) -> bool:
    """Whether a RAR5 header from ``pos`` (its type field) has an end block's shape.

    That is the type, block flags with neither an extra nor a data area, then the
    end-of-archive flags, and nothing after them. A FILE or service header declares
    a data area. A MAIN header with no extra and no data area passes this; the blocks
    that follow it in any archive with members keep it out (see
    ``dev-docs/formats/rar.md``).
    """
    try:
        _type, pos = load_vint(hdata, pos)
        block_flags, pos = load_vint(hdata, pos)
        if block_flags & (_RAR5_FLAG_EXTRA | _RAR5_FLAG_DATA):
            return False
        _end_flags, pos = load_vint(hdata, pos)
    except CorruptionError:
        return False
    return pos == len(hdata)


def _data_past_end(source: BinaryIO) -> str | None:
    """Why the walk reached end of file inside a block's packed data, or ``None``.

    Called where the walk found no further header. A clean end sits exactly at the
    end of the file; a skip over packed data that the file does not hold leaves the
    position past it, and the read there is empty as well.
    """
    pos = source.tell()
    end = source.seek(0, io.SEEK_END)
    source.seek(pos)
    if pos <= end:
        return None
    return (
        f"RAR archive is truncated: the last block's packed data ends at byte {pos}, "
        f"past the end of the file ({end} bytes)"
    )


def _span_in_file(source: BinaryIO, data_offset: int, size: int) -> bool:
    """Whether the ``size`` bytes at ``data_offset`` all lie inside the file.

    The read position is kept. A comment whose data runs past the end is not read:
    the walk skips its span as it skips any packed data, and the next header read
    finds the cut (:func:`_data_past_end`), so the members before it still list.
    """
    end = _packed_span_end(data_offset, size)
    here = source.tell()
    file_end = source.seek(0, io.SEEK_END)
    source.seek(here)
    return end <= file_end


def _encrypted_header_cut(start: int) -> str:
    """Why the walk stopped at an encrypted header that the file holds only part of.

    Each encrypted header is a salt (RAR3) or IV (RAR5) and then whole 16-byte
    ciphertext blocks, so a file that ends anywhere after its first byte and before
    its last cannot be a clean end: the writer never stops part-way.
    """
    return f"RAR archive is truncated: {_ends_inside_encrypted_header(start)}"


# Set on a raised error whose message gives a byte offset within one volume, so that
# ``parse_rar_volumes`` can name the volume, as it does for the returned strings.
_OFFSET_IN_VOLUME = "_archivey_rar_offset_in_volume"


def _ends_inside_encrypted_header(start: int) -> str:
    """The clause that places a cut in an encrypted header, shared by the proven cut
    and the unproven wrong-password message so the two say it the same way."""
    return f"the file ends inside the encrypted header that starts at byte {start}"


class _RarHeaderCrcError(CorruptionError):
    """A header failed its CRC; private signal for the walk.

    With plain headers or a proven password, the walks catch it by this type after
    the main header and list the members before the damaged header
    (``RarArchive.damaged``). Any other :class:`CorruptionError` raised in the same
    place, such as an invalid header size, still fails the open, and so does this
    one in the main header.
    """


def _damaged_header(exc: CorruptionError, start: int) -> str:
    """The ``RarArchive.damaged`` text for a member header that failed its CRC."""
    return (
        f"{exc}; the header starts at byte {start}, "
        "and no later member of that volume is listed"
    )


class _RarEndBlockCrcError(CorruptionError):
    """A RAR5 header shaped as an end block failed its CRC; private signal for the walk.

    :func:`_read_rar5_block` raises this in place of the generic CRC error when the
    header's type reads as the end block and its shape is an end block's (see
    :func:`_rar5_end_block_shaped`). The walk keeps the members before it only if
    nothing but zeros follows ``data_offset``, as far as the 1 MiB trailing scan
    looks (:func:`_only_zeros_after`), and the header password is proven or headers
    are plain. Behind an unproven header password the walk's earlier check raises
    the wrong-password :class:`EncryptionError` instead. With a proven key or plain
    headers, a non-zero byte within that scan is handled as ``generic``, the error
    a header of any other type would have raised. The end-of-archive flags are not
    used.
    """

    def __init__(self, header_offset: int, data_offset: int) -> None:
        super().__init__(
            f"RAR5 end-of-archive header CRC mismatch at offset {header_offset}"
        )
        self.data_offset = data_offset
        self.generic = _RarHeaderCrcError(
            f"RAR5 header CRC mismatch at offset {header_offset}"
        )


class _RarHeaderCutError(TruncatedError):
    """The file ended before the bytes a header declares; private signal for the walk.

    The RAR3 and RAR5 header readers raise this, and only this, at their "file ended
    early" points. The plain walks catch it by this type and list the members before
    the header, so any other :class:`TruncatedError` raised inside the same ``try``
    still fails the open. Callers catching ``TruncatedError`` are unaffected.
    """


_PRIVATE_WALK_ERRORS = (_RarHeaderCrcError, _RarEndBlockCrcError, _RarHeaderCutError)


def _public_walk_error(exc: CorruptionError) -> CorruptionError:
    """The public exception for a private walk signal that the walk re-raised.

    The private types are for the walks to catch by type. One that escapes them (a
    damaged main header, say) leaves the parser as its public base class, so callers
    and ``type(exc).__name__`` never see a private name (DR-13). The traceback of the
    original raise is kept.
    """
    public = TruncatedError if isinstance(exc, TruncatedError) else CorruptionError
    return public(exc.raw_message).with_traceback(exc.__traceback__)


def _plain_header_cut(start: int) -> str:
    """Why the walk stopped at a plain header that the file holds only part of.

    The header readers raise :class:`_RarHeaderCutError` only when the file ends
    before the bytes the header declares; a declared size that is invalid stays a
    :class:`CorruptionError`. The first byte was present, so this is not a clean end.
    """
    return (
        f"RAR archive is truncated: the file ends inside the header that starts at "
        f"byte {start}"
    )


def _no_header(source: BinaryIO, start: int, *, encrypted_cut: bool) -> str | None:
    """Why the walk found no header at ``start``, or ``None`` for a clean end.

    ``encrypted_cut``: part of a salt/IV, or a whole one with no ciphertext behind it,
    was read. That is a cut, and needs no password to tell.
    """
    if encrypted_cut:
        return _encrypted_header_cut(start)
    return _data_past_end(source)


def _header_failure(
    exc: CorruptionError,
    header_fd: _Readable,
    start: int,
    *,
    proven: bool,
    version: str,
) -> str | None:
    """Classify a header read that failed; ``None`` means re-raise ``exc``.

    Neither format has a verifier for every header: a wrong key decrypts a garbage
    header that fails its size or CRC checks, so in an encrypted header that is an
    :class:`EncryptionError` and password candidates keep iterating. Once the key is
    proven (a matching CRC16 in RAR3, a check value in RAR5), a failure there is
    damage, and one that ran out of ciphertext is a cut. Unproven, a garbage size
    reads to the end of the file as well, so that stays a wrong password; when the
    read did run out, the message also names a cut or a damaged header, because
    with the right password one of those is the cause (damage can garble the size
    just as a wrong key does) and nothing here can tell them apart. A plain
    header the file holds only part of is a cut: unrar lists the members before it
    and reports an unexpected end of archive.

    :raises EncryptionError: (from :func:`wrong_password_error`) for a failure in an
        encrypted header while the password is unproven.
    """
    if isinstance(header_fd, _HeaderDecryptStream):
        if not proven:
            message = f"Failed to decrypt {version} headers (wrong password?)"
            if header_fd.hit_eof:
                # A wrong key's garbage size runs to the end of a small archive as
                # well, so the cut is the second reading, not the first; a damaged
                # header garbles the size the same way, so it is named too.
                message += (
                    "; if the password is right, "
                    f"{_ends_inside_encrypted_header(start)}, "
                    "or that header is damaged"
                )
                error = wrong_password_error(message)
                # The offset is within this volume; ``parse_rar_volumes`` names it.
                setattr(error, _OFFSET_IN_VOLUME, True)
                raise error from exc
            raise wrong_password_error(message) from exc
        if header_fd.hit_eof:
            return _encrypted_header_cut(start)
    elif isinstance(exc, _RarHeaderCutError):
        return _plain_header_cut(start)
    return None


def _check_rar3_crc(
    header_crc: int,
    data: bytes,
    what: str,
    *,
    encrypted: bool,
    proven: bool,
) -> bool:
    """Check a RAR3 header's CRC16 and return the updated password proof.

    RAR3 has no header password verifier: a mismatch in an encrypted header is a wrong
    password until a match has proven the key.
    """
    calc = _crc32(data) & 0xFFFF
    if header_crc != calc:
        if encrypted and not proven:
            raise wrong_password_error(
                "Failed to decrypt RAR3 headers (wrong password?)"
            )
        raise _RarHeaderCrcError(
            f"RAR3 {what} header CRC mismatch: expected {header_crc:#x}, got {calc:#x}"
        )
    return proven or encrypted


def _seek_after_packed(source: BinaryIO, data_offset: int, add_size: int) -> None:
    """Skip past a packed-data region, translating hostile sizes to CorruptionError."""
    _seek_to(source, _packed_span_end(data_offset, add_size))


def load_vint(buf: bytes | bytearray | memoryview, pos: int) -> tuple[int, int]:
    # Hot path: most RAR5 vints are a single byte (< 0x80). Avoid the multi-byte
    # loop and ``min()`` on every call (listing many-member archives).
    length = len(buf)
    if pos >= length:
        raise CorruptionError("Invalid RAR5 variable-length integer")
    b = buf[pos]
    if b < 0x80:
        return b, pos + 1
    limit = pos + 11
    limit = min(limit, length)
    res = b & 0x7F
    ofs = 7
    pos += 1
    while pos < limit:
        b = buf[pos]
        res += (b & 0x7F) << ofs
        pos += 1
        ofs += 7
        if b < 0x80:
            return res, pos
    raise CorruptionError("Invalid RAR5 variable-length integer")


def _load_byte(buf: bytes | bytearray | memoryview, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise CorruptionError("Unexpected EOF while reading byte")
    return buf[pos], pos + 1


def _load_le32(buf: bytes | bytearray | memoryview, pos: int) -> tuple[int, int]:
    end = pos + 4
    if end > len(buf):
        raise CorruptionError("Unexpected EOF while reading le32")
    return _S_LONG.unpack_from(buf, pos)[0], end


def _load_bytes(
    buf: bytes | bytearray | memoryview, num: int, pos: int
) -> tuple[bytes, int]:
    end = pos + num
    if end > len(buf):
        raise CorruptionError("Unexpected EOF while reading bytes")
    return bytes(buf[pos:end]), end


def _load_vstr(buf: bytes | bytearray | memoryview, pos: int) -> tuple[bytes, int]:
    slen, pos = load_vint(buf, pos)
    return _load_bytes(buf, slen, pos)


def _parse_dos_time(stamp: int) -> datetime | None:
    """A DOS date/time word as a naive datetime, or ``None`` when it names no date.

    Zero is the unset value, as in ZIP. Any other word that is not a real date (month
    13, day 0, 25 o'clock) is also ``None``; the caller reports it through
    :func:`_dos_time_issue`. It is not clamped to a nearby date, because a clamped
    date is a fabricated one that nothing downstream could tell from a real one.
    """
    if stamp == 0:
        return None
    sec = (stamp & 0x1F) * 2
    stamp >>= 5
    minute = stamp & 0x3F
    stamp >>= 6
    hour = stamp & 0x1F
    stamp >>= 5
    day = stamp & 0x1F
    stamp >>= 5
    month = stamp & 0x0F
    stamp >>= 4
    year = (stamp & 0x7F) + 1980
    try:
        return datetime(year, month, day, hour, minute, sec)
    except ValueError:
        return None


def _dos_time_issue(stamp: int, field: str, filename: str) -> TimestampIssue:
    """The report for a nonzero DOS word :func:`_parse_dos_time` could not use."""
    return TimestampIssue(
        field=field,
        source="dos",
        value_repr=f"0x{stamp:08x}",
        message=f"Invalid RAR DOS timestamp for {quoted(filename)}: 0x{stamp:08x}",
    )


def _load_unixtime(
    buf: bytes | bytearray | memoryview, pos: int
) -> tuple[datetime, int]:
    secs, pos = _load_le32(buf, pos)
    return unix32_to_datetime(secs), pos


def _load_windowstime(
    buf: bytes | bytearray | memoryview,
    pos: int,
    *,
    filename: str = "",
    field: str = "mtime",
    issues: list[TimestampIssue] | None = None,
) -> tuple[datetime | None, int]:
    lo, pos = _load_le32(buf, pos)
    hi, pos = _load_le32(buf, pos)
    ticks = (hi << 32) | lo
    # Shared FILETIME helper. ticks=0 → None is that helper's ZIP unset
    # rule, accepted for RAR (do not revive 1601-01-01). An out-of-range value
    # is ``None`` plus an issue, which the reader reports; listing continues.
    dt, issue = filetime_to_datetime(ticks, filename, field=field)
    if issue is not None and issues is not None:
        issues.append(issue)
    return dt, pos


_NO_UNICODE_FORM = (
    "Wrong password: it has no Unicode form, so it cannot be a RAR password"
)


def _normalize_password_utf8(password: str | bytes) -> bytes:
    """RAR5 password normalization: UTF-16LE truncate → UTF-8.

    The truncation counts UTF-16 code units, so a password whose last kept unit is
    the first half of a surrogate pair has no UTF-8 form. That is typed like the
    ``bytes`` case in :func:`_normalize_password_utf16le`: a wrong candidate.
    """
    wstr = _normalize_password_utf16le(password)
    try:
        return wstr.decode("utf-16le").encode("utf8")
    except UnicodeError:
        raise wrong_password_error(_NO_UNICODE_FORM) from None


def _normalize_password_utf16le(password: str | bytes) -> bytes:
    """The password as RAR hashes it: UTF-16LE, truncated to the format's maximum.

    A ``bytes`` candidate that is not UTF-8 has no Unicode form, so it cannot be any
    RAR password: it is a wrong password, and the candidate loop moves on to the next
    one, as the member path already does.
    """
    try:
        pwd = password.decode("utf8") if isinstance(password, bytes) else password
        wstr = pwd.encode("utf-16le")
    except UnicodeError:
        raise wrong_password_error(_NO_UNICODE_FORM) from None
    return wstr[: _RAR_MAX_PASSWORD * 2]


def decode_rar3_cmt_text(raw: bytes, *, utf16: bool, encoding: str | None) -> str:
    """Decode the unpacked text of a RAR 1.5-4 comment.

    Two sources reach it: a RAR 2.9-4 ``CMT`` SERVICE header, and a RAR 1.5-2.x
    old-style COMMENT subblock (always 8-bit, so ``utf16`` is false).
    ``utf16`` is ``_RAR3_SUBHEAD_CMT_UNICODE`` from a ``CMT`` header's attribute field.
    With it, unrar converts ``CmtSize / 2`` units, so an odd trailing byte is
    dropped rather than shown as U+FFFD, and the text is cut at the first NUL
    *character*: ASCII text in UTF-16LE is full of NUL bytes. A unit without its
    partner stays as that unit (``surrogatepass``), as it does in a RAR3 Unicode name.
    Without it, the payload is 8-bit text (:func:`_decode_comment_text`).
    """
    if not utf16:
        return _decode_comment_text(raw, encoding=encoding)
    even = raw[: len(raw) - len(raw) % 2]
    return even.decode("utf-16le", "surrogatepass").split("\0", 1)[0]


def _decode_comment_text(raw: bytes, *, encoding: str | None) -> str:
    """Decode an 8-bit RAR 1.5-4 comment the way ``unrar`` reads it.

    The text ends at the first NUL, because ``unrar`` hands the bytes to a C-string
    conversion (``DoGetComment``, ``Archive::ReadCommentData``). What is left is
    UTF-8 if it is valid, else the caller's ``encoding=``, else windows-1252. A byte
    the code page cannot decode (five are undefined in windows-1252) survives as a lone
    surrogate, as it does in a name. The order and the error handler are the ones
    ``_decode_rar3_8bit_name`` uses for a name, and the ones a ZIP comment uses; keep
    them in step. Only the last fallback differs from a name's: ``unrar`` reads a
    comment as windows-1252 whatever the host OS.

    A RAR 1.5-4 comment is 8-bit text whose code page is not recorded. It is never
    guessed as UTF-16LE: almost any even-length byte string decodes that way, so
    ``caf\xe9 ok!`` came out as CJK. The one UTF-16LE comment is a RAR 2.9-4 ``CMT``
    SERVICE header with ``_RAR3_SUBHEAD_CMT_UNICODE`` set, decoded on its own path.
    """
    text = raw.split(b"\0", 1)[0]
    try:
        return text.decode("utf8")
    except UnicodeDecodeError:
        pass
    if encoding is not None:
        try:
            return text.decode(encoding, "surrogateescape")
        except UnicodeError:
            # A codec that refuses the bytes or the handler outright (``utf-32`` on a
            # length that is not a multiple of four, ``idna``): decode as without
            # ``encoding=``.
            pass
    return text.decode("windows-1252", "surrogateescape")


def _decode_rar3_8bit_name(raw: bytes, *, host_os: int, encoding: str | None) -> str:
    """Decode a RAR 1.5-4 name stored as 8-bit bytes, whose code page is not recorded.

    Strict UTF-8 is tried first, with or without the header's Unicode flag, because
    ``rar`` on Unix stores the locale's bytes, which today are UTF-8. The caller's
    ``encoding=`` applies only to bytes that are not valid UTF-8, as it does for a
    TAR name or a ZIP name without the UTF-8 flag. Without it, such bytes are in the
    writer's code page. WinRAR on DOS, OS/2 and Windows writes the OEM code page,
    which is how Windows ``unrar`` reads the name back (``ArcCharToWide`` with
    ``ACTW_OEM``), so cp437 is used for those hosts. For a Unix or other host it is
    the locale's single-byte charset, and windows-1252 is used.
    ``dev-docs/formats/rar.md`` §7 has the evidence. UTF-16LE is never tried: almost
    any even-length byte string decodes as UTF-16LE, and a RAR3 UTF-16 name is stored
    in its own encoded field.

    A codec ``open_archive`` accepted can still fail on these bytes (``idna``, which
    has no ``surrogateescape``); the name then decodes as it would without one.
    ``_decode_comment_text`` decodes an 8-bit comment in the same order; keep the two
    in step.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if encoding is not None:
        try:
            return raw.decode(encoding, errors="surrogateescape")
        except UnicodeError:
            pass
    fallback = "cp437" if host_os in _RAR3_OEM_HOSTS else "windows-1252"
    # windows-1252 leaves five bytes undefined; surrogateescape keeps each one distinct.
    return raw.decode(fallback, "surrogateescape")


def _add_skipped_uow(
    member: RarMemberInfo, records: tuple[tuple[str, int | None, str], ...]
) -> None:
    """Record a dropped RAR 1.5-4 ``UOW`` header on the file it follows.

    Kept only while the member has no owner, so the report ("listed without one")
    is true whenever it is there: a writer puts one ``UOW`` after a file, and with
    several, ``unrar`` applies the owner of any that names one. A stack of headers
    with no owner retains one entry.
    """
    if (
        records
        and member.owner is None
        and not any(r[0] == RAR3_UOW_NAME for r in member.skipped_header_records)
    ):
        member.skipped_header_records += records[:1]


def _set_uow_owner(member: RarMemberInfo, owner: RarOwner) -> None:
    """Give ``member`` the owner a ``UOW`` header names, dropping any report of an
    earlier ``UOW`` header that named none (see :func:`_add_skipped_uow`)."""
    member.owner = owner
    if member.skipped_header_records:
        member.skipped_header_records = tuple(
            r for r in member.skipped_header_records if r[0] != RAR3_UOW_NAME
        )


def _merge_split_member(old: RarMemberInfo, new: RarMemberInfo) -> None:
    """Collapse a SPLIT_AFTER continuation into the first part (rarfile-style).

    A genuine continuation repeats the same file name and follows a part that was itself
    marked SPLIT_AFTER. Reject a continuation that names a different file or follows a
    non-split member, so a crafted split_before flag cannot silently fold an unrelated
    member's size/CRC into the previous one (and hide it from the listing).
    """
    if not old.split_after or old.filename != new.filename:
        raise CorruptionError(
            "Mismatched RAR split continuation: "
            f"{quoted(new.filename)} does not continue {quoted(old.filename)}"
        )
    # A volume holds at most one part of a member: a continuation is the first file
    # header of the next volume. A walk merges within one volume only when the volume
    # repeats a continuation, and every repeat would add a retained part (and later a
    # view) that ``max_members`` does not count: 200 000 one-byte parts in a 6.8 MB
    # archive held 26 MB after open and peaked at 153 MB on the read. Refused, so
    # the parts of a member stay bounded by the volumes the caller passed.
    # ``old.volume_index`` stays the volume the member started in: a merge inside
    # one volume's walk compares two members of that volume, and every merge across
    # volumes compares against an earlier one, so ``==`` is the whole test.
    if new.volume_index == old.volume_index:
        raise CorruptionError(
            f"RAR split continuation of {quoted(new.filename)} is in the same "
            "volume as the part it continues"
        )
    if not old.data_parts:
        old.data_parts.append((old.data_offset, old.compress_size))
    old.data_parts.append((new.data_offset, new.compress_size))
    old.compress_size += new.compress_size
    if new.crc32 is not None:
        old.crc32 = new.crc32
    if new.blake2sp_hash is not None:
        old.blake2sp_hash = new.blake2sp_hash
    # The digests above are the last part's, and so is the record that says how to
    # check them: RAR5 sets the tweaked-checksum flag (``ConvertHashToMAC``) only on
    # the part that carries the whole file's digest, under that part's salt.
    if new.file_encryption is not None:
        old.file_encryption = new.file_encryption
    # RAR 1.5-4 writes a member's UOW header after its last part.
    if new.owner is not None:
        _set_uow_owner(old, new.owner)
    _add_skipped_uow(
        old, tuple(r for r in new.skipped_header_records if r[0] == RAR3_UOW_NAME)
    )
    old.split_after = new.split_after
    old.spanned_volumes = True


# ---------------------------------------------------------------------------
# Header decrypt stream (AES-CBC via crypto module)
# ---------------------------------------------------------------------------


class _HeaderDecryptStream:
    """Decrypt one encrypted RAR header with AES-CBC.

    Each encrypted header is its own CBC message: RAR3 prefixes an 8-byte salt,
    RAR5 a 16-byte IV, then ciphertext padded to 16-byte blocks. ``read`` returns
    plaintext; leftover bytes in ``_buf`` are the unread tail of the last
    decrypted block. Mid-header, that tail is still-owed plaintext. After the
    walk has consumed ``header_size``, it is AES padding — not bytes this header
    still owes. Either way ``tell`` is the ciphertext cursor (see below).

    ``tell`` is the underlying **ciphertext** cursor, including unread leftover.
    After a full header read, ``data_offset`` needs that position so the next
    salt/IV (or packed data) starts on a block boundary. Subtracting
    ``len(_buf)`` would report the logical plaintext offset and land inside the
    padding; the next header then decrypts as garbage.

    There is no ``seek``. CBC *can* reposition (``AesDecryptStream`` restarts
    from the preceding ciphertext block as IV), but the parser never needs it:
    after the header is consumed this wrapper is discarded and packed-data
    skips go through ``source``. ``tell`` is the ciphertext cursor rather than
    a plaintext offset. Do not prefetch plaintext and rewind — that is why
    :func:`_read_rar5_block` reads the size vint byte-at-a-time.

    Not :class:`~archivey.internal.streams.crypto.AesDecryptStream`. That 7z
    wrapper has ``owns_inner`` (both streams borrow) and a plaintext
    ``tell``/``seek``. What still blocks folding this class in is the header
    walk: ``header_fd`` is either the raw handle or this stream, and
    ``tell()`` means archive offset for both arms; and this wrapper sits
    mid-file unbounded, so a seeking decrypt stream would reposition the
    shared archive handle. The decrypt *stage* is shared; the pull stream is
    not.

    ``read`` rejects unbounded ``n < 0``. It has no per-read size cap: the
    caller already bounds the ask. RAR5 refuses ``hdrlen > _RAR5_MAX_HEADER``
    (2 MiB) before the body ``read_exact``; RAR3 ``header_size`` is a 16-bit
    field (max 65 535). A tighter 8 KiB cap here used to reject a well-formed
    header as ``wrong password?``.
    """

    def __init__(self, source: BinaryIO, key: bytes, iv: bytes) -> None:
        self._source = source
        self._stage = open_aes_decrypt_stage(AesParams(key=key, iv=iv))
        self._buf = bytearray()
        #: Set once a read found fewer than 16 ciphertext bytes left. Whether that
        #: means the file was cut inside this header is the caller's to judge: an
        #: unproved key decrypts a garbage header size that reads to the end of
        #: the file as well.
        self.hit_eof = False

    def tell(self) -> int:
        # Ciphertext position, not plaintext-consumed. Leftover ``_buf`` is the
        # unread tail of the last decrypted block (still-owed mid-header; AES
        # padding after ``header_size``). See the class docstring. Measured:
        # every FILE header on ``encrypted_header__.rar`` /
        # ``encrypted_header__rar4.rar`` has ``header_size % 16 != 0``, and
        # ``tell() - len(_buf)`` fails the parse.
        return self._source.tell()

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            raise CorruptionError("Unbounded read on encrypted RAR header stream")
        if n <= len(self._buf):
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out
        out = bytearray(self._buf)
        self._buf.clear()
        need = n - len(out)
        while need > 0:
            # AES-CBC advances one whole block at a time: a short read must be gathered,
            # not treated as EOF, or the remaining ciphertext decrypts against the wrong
            # IV and every later header looks corrupt.
            enc = read_exact(self._source, 16)
            if len(enc) < 16:
                self.hit_eof = True
                break
            dec = self._stage.update(enc)
            if need >= len(dec):
                out.extend(dec)
                need -= len(dec)
            else:
                out.extend(dec[:need])
                self._buf.extend(dec[need:])
                need = 0
        return bytes(out)


# ---------------------------------------------------------------------------
# RAR3 SHA-1 / string-to-key (ported from rarfile 4.3)
# ---------------------------------------------------------------------------


class _Rar3Sha1:
    """SHA-1 plus the WinRAR 3.x KDF buffer-mutation bug.

    WinRAR's SHA-1 runs the message schedule in place on its 64-byte block
    buffer, then writes the expanded words back little-endian. ``hashlib.sha1``
    does not mutate its input, so the digest of *this* ``update`` is correct —
    and then, when ``data`` is a ``bytearray`` containing a complete SHA-1 block
    at a block boundary (``dpos`` skips the already-absorbed prefix), this class
    applies the same in-place corruption so the *next* ``update`` of a reused
    seed matches WinRAR.

    RAR3 string-to-key hashes the same ``password + salt`` seed 0x4000×16
    times. Mutation is not "the first time the seed crosses 64 bytes": it
    fires only when this ``update`` contains a complete SHA-1 block at a
    hasher block boundary (``dpos + 64 <= len(data)``). A 65-byte seed never
    satisfies that, even though ``len(data) > 64``; a 128-byte seed does on
    the first call. Seed ≤ 64 bytes (including the 8-byte salt) never enters
    ``_corrupt``. Ported from ``rarfile`` 4.3 ``Rar3Sha1``; there is no
    non-buggy caller.
    """

    _BLK_BE = struct.Struct(b">16L")
    _BLK_LE = struct.Struct(b"<16L")
    block_size = 64

    def __init__(self) -> None:
        self._md = hashlib.sha1()
        self._nbytes = 0

    def update(self, data: bytes | bytearray) -> None:
        self._md.update(data)
        bufpos = self._nbytes & 63
        self._nbytes += len(data)
        if len(data) > 64:
            # Unrar's hash_process memcpy's the first ``64 - bufpos`` bytes
            # into its own ``ctx->buffer`` and transforms *there*, so the
            # caller's prefix is never rewritten. That includes ``bufpos ==
            # 0``: a whole first block is copied internally, not "no prefix".
            # Only later ``hash_transform(state, &data[i])`` calls mutate the
            # caller's buffer in place. ``dpos`` is that first in-place block.
            dpos = self.block_size - bufpos
            while dpos + self.block_size <= len(data):
                self._corrupt(data, dpos)
                dpos += self.block_size

    def digest(self) -> bytes:
        return self._md.digest()

    def _corrupt(self, data: bytes | bytearray, dpos: int) -> None:
        if not isinstance(data, bytearray):
            raise TypeError(
                "_Rar3Sha1 needs a mutable seed: the WinRAR KDF mutates its "
                "block buffer in place, and a bytes seed silently derives a "
                "different key."
            )
        ws = list(self._BLK_BE.unpack_from(data, dpos))
        for t in range(16, 80):
            tmp = (
                ws[(t - 3) & 15]
                ^ ws[(t - 8) & 15]
                ^ ws[(t - 14) & 15]
                ^ ws[(t - 16) & 15]
            )
            ws[t & 15] = ((tmp << 1) | (tmp >> 31)) & 0xFFFFFFFF
        self._BLK_LE.pack_into(data, dpos, *ws)


def _rar3_s2k(password: str | bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derive AES-128 key + IV for RAR3 header/file encryption.

    Uses :class:`_Rar3Sha1` so a long ``password + salt`` seed is mutated between
    rounds the way WinRAR's SHA-1 mutates its block buffer.
    """
    return _rar3_key_iv(_normalize_password_utf16le(password), salt)


def _rar3_key_iv(wstr: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """:func:`_rar3_s2k` for a password already in UTF-16LE."""
    seed = bytearray(wstr + salt)
    h = _Rar3Sha1()
    iv = bytearray()
    for i in range(16):
        for j in range(0x4000):
            cnt = struct.pack("<L", i * 0x4000 + j)
            h.update(seed)
            h.update(cnt[:3])
            if j == 0:
                iv.append(h.digest()[19])
    key_be = h.digest()[:16]
    key_le = struct.pack("<LLLL", *struct.unpack(">LLLL", key_be))
    return key_le, bytes(iv)


def _rar5_s2k(password: str | bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256 for RAR5 (returns 32-byte AES-256 key material)."""
    return _rar5_pbkdf2(_normalize_password_utf8(password), salt, iterations)


def _rar5_pbkdf2(ustr: bytes, salt: bytes, iterations: int) -> bytes:
    """:func:`_rar5_s2k` for a password already normalized to UTF-8."""
    return pbkdf2_hmac("sha256", ustr, salt, iterations, dklen=32)


class RarKdfCache:
    """RAR key derivations, each behind a per-instance ``functools.cache``.

    RAR5's cost is the archive's choice: ``2**kdf_count`` PBKDF2 rounds, accepted up
    to ``2**24`` (about 3-4 s each). RAR3's is a fixed 2**18-round SHA-1 loop that
    runs in Python. RARLAB writes one salt per archiving run, so every volume of a
    header-encrypted set repeats the same derivation; without a cache each volume
    paid it again.

    The caches are built in ``__init__``, not with ``@functools.cache`` on a method:
    that one cache would live on the class, keyed on ``self``, and keep every reader,
    password and key alive until the process exits. ``RarReader`` holds one instance
    for its lifetime and passes it to every parse and member-side derivation, so the
    keys go when the reader does. :func:`parse_rar_archive` and
    :func:`parse_rar_volumes` run without a reader, which is why the cache is an
    object passed in; they make a fresh one per call when none is.

    The methods only normalize the password before the cache lookup: the reader
    passes ``bytes`` on the header walk and ``str`` on member reads, and both must
    hit one entry. Keyed by the normalized password, the salt and (RAR5) the round
    count, so a wrong candidate never answers for a right one and the three RAR5
    outputs (AES key, HashKey, PswCheck at ``+0``/``+16``/``+32`` rounds) stay
    distinct.

    UnRAR takes all three from one PBKDF2 chain, reading its state at each offset.
    Here each is a separate ``hashlib`` run, because ``pbkdf2_hmac`` returns only
    the end of the chain. A Python loop that walks the chain once and keeps all
    three measured about 40% slower than two ``hashlib`` runs (0.78 s against
    0.55 s at ``2**20`` rounds, Python 3.13), so each output is charged as its own
    derivation: a ``-p`` read through ``unrar`` pays PswCheck and HashKey, a stored
    member archivey decrypts itself pays the AES key as well, and a header-encrypted
    walk pays the header key and PswCheck.

    The caches have no size bound, and need none: an entry is added only on a miss,
    and a miss runs the derivation the caller was about to run anyway, at the
    archive's declared cost. Entries cannot grow faster than the CPU work that
    produces them, so an archive that varies its salts gains no amplification over
    the per-derivation cost it already had. Two threads racing on one entry may both
    derive it, which costs time but never a wrong key. Neither this class nor the
    cache wrappers has a ``repr`` that shows passwords or keys.

    Each miss is charged to ``budget``
    (:attr:`~archivey.config.DecoderLimits.max_key_derivation_rounds`) before it
    runs: RAR5 at its PBKDF2 round count, RAR3 at its fixed ``2**18``. The charge
    sits inside the cached function, which ``functools.cache`` calls only on a miss,
    so a hit costs nothing. Without a budget the cache charges one built from the
    default limits.
    """

    __slots__ = ("_rar3", "_rar5")

    def __init__(self, *, budget: KeyDerivationBudget | None = None) -> None:
        charge = budget if budget is not None else KeyDerivationBudget()

        def rar5(ustr: bytes, salt: bytes, iterations: int) -> bytes:
            charge.spend(iterations, what="RAR5 key derivation")
            return _rar5_pbkdf2(ustr, salt, iterations)

        def rar3(wstr: bytes, salt: bytes) -> tuple[bytes, bytes]:
            charge.spend(_RAR3_KDF_ROUNDS, what="RAR3 key derivation")
            return _rar3_key_iv(wstr, salt)

        self._rar5 = functools.cache(rar5)
        self._rar3 = functools.cache(rar3)

    def rar5(self, password: str | bytes, salt: bytes, iterations: int) -> bytes:
        """:func:`_rar5_s2k`, derived once per distinct input."""
        return self._rar5(_normalize_password_utf8(password), salt, iterations)

    def rar3(self, password: str | bytes, salt: bytes) -> tuple[bytes, bytes]:
        """:func:`_rar3_s2k`, derived once per distinct input."""
        return self._rar3(_normalize_password_utf16le(password), salt)


def rar5_hash_key(
    password: str | bytes,
    salt: bytes,
    kdf_count_shift: int,
    *,
    kdf_cache: RarKdfCache | None = None,
) -> bytes:
    """Derive the RAR5 HashKey used by ``ConvertHashToMAC`` (PBKDF2 at ``(1<<kdf)+16``).

    The AES key is at ``1 << kdf_count``, HashKey at ``+16``, and PswCheck at ``+32``
    (UnRAR ``crypt5.cpp``).
    """
    if kdf_count_shift > _RAR_MAX_KDF_SHIFT:
        raise CorruptionError(f"RAR5 kdf_count too large: {kdf_count_shift}")
    derive = kdf_cache.rar5 if kdf_cache is not None else _rar5_s2k
    return derive(password, salt, (1 << kdf_count_shift) + 16)


def rar5_data_key(
    password: str | bytes,
    salt: bytes,
    kdf_count_shift: int,
    *,
    kdf_cache: RarKdfCache | None = None,
) -> bytes:
    """Derive the RAR5 AES-256 key for one member's data (PBKDF2 at ``1 << kdf``).

    The same derivation as the header key; :func:`rar5_hash_key` has the offsets of the
    other two outputs.
    """
    if kdf_count_shift > _RAR_MAX_KDF_SHIFT:
        raise CorruptionError(f"RAR5 kdf_count too large: {kdf_count_shift}")
    derive = kdf_cache.rar5 if kdf_cache is not None else _rar5_s2k
    return derive(password, salt, 1 << kdf_count_shift)


def convert_crc_to_mac(crc: int, hash_key: bytes) -> int:
    """RAR5 ``ConvertHashToMAC`` for CRC32: XOR-fold of ``HMAC-SHA256(HashKey, crc_le4)``."""
    digest = hmac.new(
        hash_key, (crc & 0xFFFFFFFF).to_bytes(4, "little"), hashlib.sha256
    ).digest()
    result = 0
    for (word,) in struct.iter_unpack("<I", digest):
        result ^= word
    return result & 0xFFFFFFFF


def convert_blake2sp_to_mac(digest: bytes, hash_key: bytes) -> bytes:
    """RAR5 ``ConvertHashToMAC`` for BLAKE2sp: ``HMAC-SHA256(HashKey, digest32)``."""
    if len(digest) != 32:
        raise ValueError(f"BLAKE2sp digest must be 32 bytes, got {len(digest)}")
    return hmac.new(hash_key, digest, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# RAR3 Unicode filename decompressor (ported from rarfile)
# ---------------------------------------------------------------------------


def _decode_rar3_unicode_name(std_name: bytes, encdata: bytes) -> str | None:
    """Decode a RAR3 compressed Unicode name, or None if it is corrupt.

    RAR 2.9-4 store a file name as two fields separated by a NUL: an 8-bit name
    in the local/OEM charset, then a compressed UTF-16 name. The compressed form
    is a *delta against the 8-bit name*, which is why both are needed: they are
    position-aligned, character i of the Unicode name against byte i of the
    8-bit one, so ``pos`` indexes the output and ``std_name`` at the same time.

    ``encdata[0]`` is the high UTF-16 byte shared by most of the name. The rest
    is a stream of 2-bit opcodes, four per flags byte, MSB first:

      0  next byte is a low byte, high byte 0        (ASCII / Latin-1)
      1  next byte is a low byte, high byte ``hi``
      2  next two bytes are the low and high bytes   (anything else)
      3  run: the next k characters equal the 8-bit name's, optionally shifted
         by a correction byte. k is 2..129, so one opcode byte can emit 129
         code units.

    Bounded by construction: a t=0/1/2 unit costs an encoding byte and a run
    unit costs a ``std_name`` byte, so the output cannot exceed
    ``len(std_name) + len(encdata)``. (``encdata[0]`` is ``hi`` and any output
    needs a flags byte, so the live length is strictly less; there is no
    runtime cap because it cannot fire.) Overrunning either field means the
    name is corrupt: return None and let the caller fall back to the 8-bit
    field.

    Without that stop, an empty 8-bit field plus RLE-heavy ``encdata`` spent
    ~11 s of CPU at the ``uint16`` ``name_size`` ceiling (~6.7e6 code units,
    13.5 MB, discarded before any member existed). The memory was always
    bounded by ``name_size``; the CPU was not, other than the file size.
    (unrar encname.cpp, EncodeFileName::Decode; ported via rarfile.)
    """
    out = bytearray()
    pos = 0  # output character index AND index into std_name - aligned
    try:
        hi = encdata[0]
        encpos = 1
        flagbits = 0
        flags = 0
        while encpos < len(encdata):
            if flagbits == 0:
                flags = encdata[encpos]
                encpos += 1
                flagbits = 8
            flagbits -= 2
            t = (flags >> flagbits) & 3
            if t == 0:
                out += bytes((encdata[encpos], 0))
                encpos += 1
                pos += 1
            elif t == 1:
                out += bytes((encdata[encpos], hi))
                encpos += 1
                pos += 1
            elif t == 2:
                lo, c_hi = encdata[encpos], encdata[encpos + 1]
                encpos += 2
                out += bytes((lo, c_hi))
                pos += 1
            else:
                n = encdata[encpos]
                encpos += 1
                # ``n & 0x80`` selects the high-byte=hi / correction path even
                # when the correction byte is 0. Folding that into
                # ``if correction:`` would emit high-byte 0 instead of ``hi``.
                if n & 0x80:
                    correction = encdata[encpos]
                    encpos += 1
                    k = (n & 0x7F) + 2
                    run = std_name[pos : pos + k]
                    if len(run) != k:
                        raise IndexError
                    block = bytearray(2 * k)
                    if correction:
                        block[0::2] = bytes((b + correction) & 0xFF for b in run)
                    else:
                        block[0::2] = run
                    block[1::2] = bytes((hi,)) * k
                else:
                    k = n + 2
                    run = std_name[pos : pos + k]
                    if len(run) != k:
                        raise IndexError
                    block = bytearray(2 * k)
                    block[0::2] = run
                out += block
                pos += k
    except IndexError:
        return None
    # surrogatepass: the field is UTF-16 code units, and NTFS lets a name hold a
    # surrogate without its partner. The unit stays in the name, as the 7z reader
    # keeps it; extraction decides what reaches disk. ``out`` has an even length, so
    # the decode cannot fail, and a valid pair still decodes as one character.
    return out.decode("utf-16le", "surrogatepass")


def _fix_rar3_astral_truncation(unicode_name: str, std_name: bytes) -> str:
    """Recover non-BMP (astral) characters truncated by the RAR3 Unicode name compressor.

    *Astral* is the usual Unicode term for a code point above the Basic
    Multilingual Plane — U+10000 and up, stored as a UTF-16 surrogate pair.

    RAR 2.9–4 encode filenames as compressed UTF-16, which cannot represent those
    characters: an emoji like ``😀`` (U+1F600) is stored as a single truncated
    code unit (U+F600, in the Private Use Area) instead of a surrogate pair. The
    legacy 8-bit name field carries the same name — commonly as UTF-8 — so where
    the decompressed name shows a surrogate/PUA code unit exactly ``0x10000``
    below the 8-bit name's character, prefer the 8-bit decoding. (Workaround
    ported from the v1 reader's ``get_non_corrupted_filename``.)
    """
    try:
        utf8_name = std_name.decode("utf-8")
    except UnicodeDecodeError:
        return unicode_name
    if utf8_name == unicode_name:
        return unicode_name
    for u16c, u8c in zip(unicode_name, utf8_name):
        u16 = ord(u16c)
        if (0xD800 <= u16 <= 0xDFFF or 0xE000 <= u16 <= 0xF8FF) and ord(
            u8c
        ) == u16 + 0x10000:
            return utf8_name
    return unicode_name


def _parse_rar3_old_comment_subblocks(
    hdata: bytes, pos: int, *, encoding: str | None
) -> str | _Rar3Comment | None:
    """Read a RAR 1.5/2.x COMMENT subblock appended to a MAIN or FILE header.

    The enclosing header's CRC ends before these subblocks, despite its
    ``header_size`` including them. Keep malformed trailing subblocks ignorable:
    older archives were previously listed after skipping this region entirely.
    """
    comment: str | _Rar3Comment | None = None
    while pos + _S_BLK_HDR.size <= len(hdata):
        _, block_type, flags, block_size = _S_BLK_HDR.unpack_from(hdata, pos)
        next_pos = pos + block_size
        pos += _S_BLK_HDR.size
        if block_size < _S_BLK_HDR.size or next_pos > len(hdata):
            break
        if block_type == _RAR3_OLD_COMMENT and pos + _S_COMMENT_HDR.size <= next_pos:
            unpacked_size, extract_version, compress_type, crc16 = (
                _S_COMMENT_HDR.unpack_from(hdata, pos)
            )
            packed = hdata[pos + _S_COMMENT_HDR.size : next_pos]
            if flags & (_RAR3_FILE_PASSWORD | _RAR3_FILE_SALT):
                # An encrypted comment is a known limitation, stored or compressed:
                # no available writer produces one, so no decode path could be
                # tested. A stored one would otherwise be taken as plaintext.
                comment = None
            elif compress_type == _RAR3_M0:
                if _crc32(packed) & 0xFFFF == crc16:
                    comment = _decode_comment_text(packed, encoding=encoding)
            else:
                comment = _Rar3Comment(
                    packed=packed,
                    unpacked_size=unpacked_size,
                    extract_version=extract_version,
                    compress_type=compress_type,
                    flags=flags,
                    crc16=crc16,
                )
        pos = next_pos
    return comment


# ---------------------------------------------------------------------------
# RAR3 / RAR4 parser
# ---------------------------------------------------------------------------


def _parse_rar3(
    source: BinaryIO,
    *,
    password: str | bytes | None,
    kdf_cache: RarKdfCache,
    sfx_offset: int,
    volume_index: int = 0,
    max_members: int | None,
    max_metadata_bytes: int | None,
    name_encoding: str | None = None,
    password_proven: bool = False,
) -> RarArchive:
    _require_exact(source, len(RAR_ID), "RAR3 signature")

    is_solid = False
    is_volume = False
    old_volume_naming = False
    has_header_encryption = False
    comment: str | _Rar3Comment | None = None
    members = _MemberList()
    needs_next_volume = False
    truncated: str | None = None
    damaged: str | None = None
    main_seen = False
    end_block_damaged_at: int | None = None
    trailing_at: int | None = None
    # Set once an encrypted header decrypted with a matching CRC16, in this volume or
    # an earlier one of the set (the caller passes that in). The walk treats a
    # mismatch as proof of a wrong password, so a match proves the password the same
    # way. From then on a header that fails is damage or a cut, not a wrong password.
    # Each header has its own salt, so the proof says nothing about a later salt: a
    # damaged one decrypts a garbage header, which is reported as damage too.

    while True:
        header_fd: _Readable = source
        block_encrypted = has_header_encryption
        header_start = source.tell()
        if has_header_encryption:
            assert password is not None  # MAIN raised without one
            # Nothing here depends on the password being right: the salt read and the
            # key derivation fail the same way for every candidate, so their errors
            # (a spent derivation budget) propagate as they are. A wrong password
            # shows up later, when the decrypted header does not parse or its CRC16
            # does not match. A salt the file holds only part of is a cut, reported
            # after the members listed.
            # No salt at all is a clean end, as in a plain walk: RAR 1.5-4 writers may
            # omit ENDARC, and unrar lists such a file and exits 0 (rar.md §1).
            salt = read_exact(source, 8)
            if len(salt) < 8:
                truncated = _no_header(source, header_start, encrypted_cut=bool(salt))
                break
            header_fd = _rar3_decrypt_header(source, salt, password, kdf_cache)

        try:
            header_offset = header_fd.tell()
            buf = read_exact(header_fd, _S_BLK_HDR.size)
            if not buf:
                truncated = _no_header(
                    source, header_start, encrypted_cut=block_encrypted
                )
                break
            if len(buf) < _S_BLK_HDR.size:
                raise _RarHeaderCutError(
                    "Unexpected EOF while reading RAR3 block header"
                )

            header_crc, block_type, flags, header_size = _S_BLK_HDR.unpack_from(buf)
            if header_size < _S_BLK_HDR.size:
                raise CorruptionError(f"Invalid RAR3 header size: {header_size}")
            if header_size > _S_BLK_HDR.size:
                rest = read_exact(header_fd, header_size - _S_BLK_HDR.size)
                if len(rest) != header_size - _S_BLK_HDR.size:
                    raise _RarHeaderCutError(
                        "Unexpected EOF while reading RAR3 header body"
                    )
                hdata = buf + rest
            else:
                hdata = buf
        except CorruptionError as exc:
            # ``header_fd`` is the decrypt stream exactly when ``block_encrypted``.
            truncated = _header_failure(
                exc, header_fd, header_start, proven=password_proven, version="RAR3"
            )
            if truncated is None:
                raise
            break
        # HeaderDecryptStream.tell() reports the underlying ciphertext position
        # (including AES block padding), which is the correct data_offset.
        data_offset = header_fd.tell()

        pos = _S_BLK_HDR.size
        if flags & _RAR3_LONG_BLOCK:
            add_size, pos = _load_le32(hdata, pos)
        else:
            add_size = 0

        if block_type == _RAR3_MARK:
            _seek_after_packed(source, data_offset, add_size)
            continue

        if block_type == _RAR3_MAIN:
            crc_pos = rar3_main_crc_end(flags)
            is_solid = bool(flags & _RAR3_MAIN_SOLID)
            is_volume = bool(flags & _RAR3_MAIN_VOLUME)
            old_volume_naming = is_volume and not flags & _RAR3_MAIN_NEW_NUMBERING
            if flags & _RAR3_MAIN_PASSWORD:
                has_header_encryption = True
                if password is None:
                    raise EncryptionError(
                        "RAR archive has encrypted headers but no password was provided"
                    )
            password_proven = _check_rar3_crc(
                header_crc,
                hdata[2:crc_pos],
                "MAIN",
                encrypted=block_encrypted,
                proven=password_proven,
            )
            main_seen = True
            if flags & _RAR3_MAIN_COMMENT:
                comment = _parse_rar3_old_comment_subblocks(
                    hdata, crc_pos, encoding=name_encoding
                )
            _seek_after_packed(source, data_offset, add_size)
            continue

        if block_type == _RAR3_ENDARC:
            # The type was read from the same unverified bytes, so a MAIN or FILE
            # header with one flipped byte reads as ENDARC too. Only a header shaped
            # as an end block, with nothing but zeros after it, is one. Damage after
            # the last member keeps the listing, and the flags, the next-volume flag among
            # them, are not read. unrar lists such an archive and tests every member
            # OK, then reports one error. An unproven key still reads as a wrong
            # password, through _check_rar3_crc.
            if (
                header_crc != _crc32(hdata[2:header_size]) & 0xFFFF
                and (password_proven or not block_encrypted)
                and _rar3_end_block_shaped(flags, header_size)
                and _only_zeros_after(source, data_offset)
            ):
                end_block_damaged_at = header_start
                break
            try:
                password_proven = _check_rar3_crc(
                    header_crc,
                    hdata[2:header_size],
                    "ENDARC",
                    encrypted=block_encrypted,
                    proven=password_proven,
                )
            except _RarHeaderCrcError as exc:
                # Not an end block, so a header whose type byte is damaged.
                if not main_seen:
                    raise
                damaged = _damaged_header(exc, header_start)
                break
            needs_next_volume = bool(flags & _RAR3_ENDARC_NEXT_VOLUME)
            volume_number = _rar3_end_block_volume_number(hdata, flags, header_size)
            if volume_index == 0 and is_volume and volume_number:
                # A later volume whose first member starts on its boundary: no
                # member continues from an earlier volume, so only this number
                # tells it from volume 1 (RAR5 reads MAIN's instead).
                raise UnsupportedFeatureError(
                    "Need first volume of multi-volume RAR archive"
                )
            trailing_at = _scan_after_end_block(
                source, _packed_span_end(data_offset, add_size)
            )
            break

        if block_type in (_RAR3_FILE, _RAR3_SUB):
            # FILE header re-reads pack_size as first field when LONG_BLOCK was set.
            file_pos = pos - 4 if (flags & _RAR3_LONG_BLOCK) else pos
            member: RarMemberInfo | None = None
            try:
                member, crc_pos = _parse_rar3_file_header(
                    hdata,
                    file_pos,
                    flags=flags,
                    header_offset=header_offset,
                    header_size=header_size,
                    data_offset=data_offset,
                    volume_index=volume_index,
                    is_service=(block_type == _RAR3_SUB),
                    name_encoding=name_encoding,
                )
            except CorruptionError:
                # The fields are parsed before the CRC can be checked, since they
                # say how many bytes it covers. A field that does not parse in a
                # header whose CRC also fails is the same damage as a bad CRC.
                # Once the fields failed, the true end of the CRC is unknown, so
                # this checks the whole header: a deliberate approximation. It is
                # exact except for a FILE_COMMENT header, whose CRC stops before
                # the comment, so there the check cannot match and invalid fields
                # under a valid CRC read as damage too. Either way it is a
                # CorruptionError; only its timing differs (after the listing,
                # not at open), and reaching it needs a crafted CRC.
                if header_crc == _crc32(hdata[2:header_size]) & 0xFFFF:
                    raise
                crc_pos = header_size
            try:
                password_proven = _check_rar3_crc(
                    header_crc,
                    hdata[2:crc_pos],
                    "FILE",
                    encrypted=block_encrypted,
                    proven=password_proven,
                )
            except _RarHeaderCrcError as exc:
                if not main_seen:
                    raise
                damaged = _damaged_header(exc, header_start)
                break
            # A parse error leaves it unset only with a CRC that fails, raised above.
            assert member is not None

            # The data size is PACK_SIZE (with HIGH_PACK_SIZE for a >4 GiB member),
            # whatever LONG_BLOCK says, as unrar reads it. ``add_size`` is the same
            # low 32 bits when LONG_BLOCK is set and 0 when it is clear, and skipping
            # 0 parsed a member's data as more headers, listing members unrar does
            # not have.
            packed_size = member.compress_size
            if block_type == _RAR3_FILE:
                # RAR 1.5 / 2.x use the same block layout as RAR3 for headers we
                # care about; member data is always left to RARLAB ``unrar``.
                # Do not reject extract_version ≤ 20 — that also false-positives
                # modern RAR3 archives whose stored/small members advertise
                # unp_ver=20.
                # File-version history rows (FILE_VERSION) are kept as members.
                if flags & _RAR3_FILE_COMMENT:
                    member.comment = _parse_rar3_old_comment_subblocks(
                        hdata, crc_pos, encoding=name_encoding
                    )
                if _emit_file_member(
                    members,
                    member,
                    max_members=max_members,
                    max_metadata_bytes=max_metadata_bytes,
                ):
                    needs_next_volume = True
            elif (
                block_type == _RAR3_SUB and member.filename == RAR3_UOW_NAME and members
            ):
                # ``rar -ow`` writes a UOW header right after the file it describes.
                # The file was weighed when it was appended, so the names are here.
                owner = member.owner
                if owner is None:
                    _add_skipped_uow(members[-1], member.skipped_header_records)
                else:
                    _set_uow_owner(members[-1], owner)
                    if max_metadata_bytes is not None:
                        _charge_metadata(
                            members,
                            text_bytes(owner.uname) + text_bytes(owner.gname),
                            max_metadata_bytes,
                            count=len(members),
                        )
            elif (
                block_type == _RAR3_SUB
                and member.filename == "CMT"
                and not member.is_encrypted
                and not member.split_before
                and not member.split_after
                and packed_size > 0
                and (
                    member.is_stored
                    or (
                        member.file_size <= RAR3_MAX_COMMENT_SIZE
                        and packed_size <= RAR3_MAX_COMMENT_SIZE
                    )
                )
                and _span_in_file(source, data_offset, packed_size)
            ):
                # The span the walk skips below, so no byte is read both as
                # comment data and as a later header, which let a stack of small
                # CMT headers each re-read the rest of the archive.
                source.seek(data_offset)
                raw = _read_comment(
                    source, packed_size, "RAR3 comment", max_metadata_bytes
                )
                utf16 = bool(
                    member.mode is not None and member.mode & _RAR3_SUBHEAD_CMT_UNICODE
                )
                cmt: str | _Rar3Comment
                if member.is_stored:
                    cmt = decode_rar3_cmt_text(raw, utf16=utf16, encoding=name_encoding)
                else:
                    # Compressed: ``unrar`` decodes it in the reader layer, as it
                    # does a compressed RAR 1.5-2.x comment, once the listing
                    # budget has weighed the declared size.
                    # A RAR3 FILE or SUB header always carries FILE_CRC.
                    assert member.crc32 is not None
                    cmt = _Rar3Comment(
                        packed=raw,
                        unpacked_size=member.file_size,
                        extract_version=member.extract_version or 0,
                        compress_type=member.compress_type,
                        flags=member.flags,
                        crc16=member.crc32 & 0xFFFF,
                        crc32=member.crc32,
                        utf16=utf16,
                    )
                if member.file_solid and members:
                    # The member was weighed when it was appended, before this
                    # comment arrived, so the comment is weighed here.
                    members[-1].comment = cmt
                    if max_metadata_bytes is not None:
                        _charge_metadata(
                            members,
                            comment_metadata_bytes(cmt),
                            max_metadata_bytes,
                            count=len(members),
                        )
                else:
                    comment = cmt

            _seek_after_packed(source, data_offset, packed_size)
            continue

        # Unknown / skippable block
        _seek_after_packed(source, data_offset, add_size)

    return RarArchive(
        version=4,
        is_solid=is_solid,
        has_header_encryption=has_header_encryption,
        comment=comment,
        members=members,
        sfx_offset=sfx_offset,
        is_volume=is_volume,
        needs_next_volume=needs_next_volume,
        old_volume_naming=old_volume_naming,
        truncated=truncated,
        damaged=damaged,
        end_block_damaged_volumes=(
            {volume_index: end_block_damaged_at}
            if end_block_damaged_at is not None
            else {}
        ),
        trailing_data_volumes=(
            {volume_index: trailing_at} if trailing_at is not None else {}
        ),
        password_proven=password_proven,
    )


def _rar3_decrypt_header(
    source: BinaryIO, salt: bytes, password: str | bytes, kdf_cache: RarKdfCache
) -> _HeaderDecryptStream:
    key, iv = kdf_cache.rar3(password, salt)
    return _HeaderDecryptStream(source, key, iv)


def _parse_rar3_file_header(
    hdata: bytes,
    pos: int,
    *,
    flags: int,
    header_offset: int,
    header_size: int,
    data_offset: int,
    volume_index: int,
    is_service: bool,
    name_encoding: str | None = None,
) -> tuple[RarMemberInfo, int]:
    if pos + _S_FILE_HDR.size > len(hdata):
        raise CorruptionError("Truncated RAR3 file header")
    fld = _S_FILE_HDR.unpack_from(hdata, pos)
    pos += _S_FILE_HDR.size

    compress_size = fld[0]
    file_size = fld[1]
    host_os = fld[2]
    crc32 = fld[3]
    dos_stamp = fld[4]
    extract_version = fld[5]  # UNP_VER as stored; not clamped to 15/20/29/50
    compress_type = fld[6]
    name_size = fld[7]
    mode = fld[8]

    mtime: datetime | None = _parse_dos_time(dos_stamp)

    if flags & _RAR3_FILE_LARGE:
        h1, pos = _load_le32(hdata, pos)
        h2, pos = _load_le32(hdata, pos)
        compress_size |= h1 << 32
        file_size |= h2 << 32

    name, pos = _load_bytes(hdata, name_size, pos)
    name_end = pos
    orig_filename: bytes | None
    unicode_name: str | None = None
    utf8_over_encoding = False
    if flags & _RAR3_FILE_UNICODE and b"\0" in name:
        nul = name.find(b"\0")
        orig_filename = name[:nul]
        decoded = _decode_rar3_unicode_name(orig_filename, name[nul + 1 :])
        if not decoded:
            # ``unrar`` falls back to the 8-bit field on an empty decode too.
            filename = _decode_rar3_8bit_name(
                orig_filename, host_os=host_os, encoding=name_encoding
            )
            utf8_over_encoding = _utf8_over_encoding(orig_filename, name_encoding)
        else:
            unicode_name = decoded
            filename = _fix_rar3_astral_truncation(decoded, orig_filename)
    else:
        orig_filename = name
        filename = _decode_rar3_8bit_name(name, host_os=host_os, encoding=name_encoding)
        # The Unicode flag declares UTF-8, so a UTF-8 reading there is not inferred.
        if not flags & _RAR3_FILE_UNICODE:
            utf8_over_encoding = _utf8_over_encoding(name, name_encoding)

    filename = filename.replace("\\", "/").rstrip("/")
    is_directory = (flags & _RAR3_FILE_DIRECTORY) == _RAR3_FILE_DIRECTORY
    is_symlink = (
        not is_service
        and host_os == _RAR3_OS_UNIX
        and mode is not None
        and (mode & 0xF000) == 0xA000
    )
    file_version: int | None = None
    if flags & _RAR3_FILE_VERSION:
        filename, file_version = _rar3_split_file_version(filename)
    if is_directory:
        filename = filename + "/"

    rar3_salt: bytes | None = None
    if flags & _RAR3_FILE_SALT:
        rar3_salt, pos = _load_bytes(hdata, 8, pos)

    timestamp_issues: list[TimestampIssue] = []
    if mtime is None and dos_stamp != 0:
        timestamp_issues.append(_dos_time_issue(dos_stamp, "mtime", filename))
    ctime: datetime | None = None
    atime: datetime | None = None
    if flags & _RAR3_FILE_EXTTIME:
        # An EXTTIME mtime only refines the header's DOS word, so it is ``None``
        # exactly when that word was: it adds no report of its own.
        mtime, ctime, atime, pos = _parse_rar3_ext_time(
            hdata, pos, mtime, filename=filename, issues=timestamp_issues
        )
    # else: keep DOS mtime (spec: RAR4 naive wall-clock)

    # CRC covers through the file-header fields; old comment subblocks (if any) follow.
    crc_pos = pos if not is_service else header_size

    member = RarMemberInfo(
        filename=filename,
        orig_filename=orig_filename,
        rar3_unicode_name=unicode_name,
        rar3_utf8_over_encoding=utf8_over_encoding,
        file_size=file_size,
        compress_size=compress_size,
        compress_type=compress_type,
        crc32=crc32,
        blake2sp_hash=None,
        mtime=None if is_service else mtime,
        ctime=None if is_service else ctime,
        atime=None if is_service else atime,
        timestamp_issues=()
        if is_service or not timestamp_issues
        else tuple(timestamp_issues),
        mode=mode,
        host_os=host_os,
        flags=flags,
        file_redir=None,
        file_encryption=None,
        header_offset=header_offset,
        header_size=header_size,
        data_offset=data_offset,
        extract_version=extract_version,
        file_solid=bool(flags & _RAR3_FILE_SOLID),
        is_directory=is_directory and not is_symlink,
        is_symlink=is_symlink,
        is_hardlink_or_copy=False,
        is_encrypted=bool(flags & _RAR3_FILE_PASSWORD),
        volume_index=volume_index,
        split_before=bool(flags & _RAR3_FILE_SPLIT_BEFORE),
        split_after=bool(flags & _RAR3_FILE_SPLIT_AFTER),
        file_version=file_version,
        # The raw flag, not the narrowed field: a directory-flagged symlink's bits are
        # the directory marker, not a dictionary size.
        dictionary_size=0
        if is_directory
        else _RAR3_DICT_BASE << ((flags & _RAR3_DICT_MASK) >> _RAR3_DICT_SHIFT),
        rar3_salt=rar3_salt,
    )
    if is_service and filename == RAR3_UOW_NAME:
        # A service header's own data sits between the name and the salt: ``unrar``'s
        # ``ReadHeader15`` reads it right after the name, as the header's remaining
        # size less the salt, and reads the salt after it. The generic parse above
        # reads a salt from right after the name instead, which only a salted
        # service header with data would notice.
        sub_end = header_size - (8 if flags & _RAR3_FILE_SALT else 0)
        member.owner = _parse_rar3_uow(hdata[name_end:sub_end])
        if member.owner is None:
            member.skipped_header_records = ((RAR3_UOW_NAME, None, RAR3_UOW_NO_NUL),)
    return member, crc_pos


def _parse_rar3_uow(data: bytes) -> RarOwner | None:
    """The owner a RAR 1.5-4 ``UOW`` service header records: the user name and the
    group name, each ended by a NUL or the data's end, as ``unrar``'s
    ``ExtractUnixOwner30`` reads them. With no NUL ``unrar`` applies no owner, and
    neither is one listed; the walk reports that header as a dropped record, as
    RAR5 reports an owner record too short for its flags. RAR 3-6 stores names
    only. Names decode as RAR5's do.
    """
    user, nul, rest = data.partition(b"\0")
    if not nul:
        return None
    group = rest.partition(b"\0")[0]
    return RarOwner(
        user.decode("utf8", "surrogateescape") or None,
        group.decode("utf8", "surrogateescape") or None,
        None,
        None,
    )


# Ten digits hold any 32-bit number; a longer run is not treated as a version.
_RAR3_MAX_VERSION_DIGITS = 10


def _rar3_split_file_version(filename: str) -> tuple[str, int | None]:
    """Split a RAR3 ``path;n`` version suffix into ``(path, n)``.

    RAR3 stores the version in the header name when ``FILE_VERSION`` is set.
    Returns ``(filename, None)`` when no trailing decimal ``;n`` is present.

    Only ASCII digits count, at most :data:`_RAR3_MAX_VERSION_DIGITS` of them.
    ``str.isdigit`` also accepts ``²`` and other Unicode digits that ``int`` then
    rejects, and ``int`` refuses a string of more than 4300 digits. Either would
    raise a bare ``ValueError`` out of ``open_archive``. A suffix that fails the
    test stays part of the name, as ``unrar vt -ver`` also shows it.
    """
    stem, sep, ver = filename.rpartition(";")
    if (
        not sep
        or not 0 < len(ver) <= _RAR3_MAX_VERSION_DIGITS
        or not ver.isascii()
        or not ver.isdigit()
    ):
        return filename, None
    return stem, int(ver)


def _parse_rar3_ext_time(
    data: bytes,
    pos: int,
    dos_mtime: datetime | None,
    *,
    filename: str = "",
    issues: list[TimestampIssue] | None = None,
) -> tuple[datetime | None, datetime | None, datetime | None, int]:
    """Parse RAR3 EXTTIME. Returns ``(mtime, ctime, atime, pos)``.

    Nibble order is UnRAR / rarfile, not a guess: flags>>12 mtime (refines the
    header DOS stamp), >>8 ctime, >>4 atime, low nibble arctime. arctime has no
    ``ArchiveMember`` field and is walked only so the cursor stays aligned.

    Without the mtime nibble's present bit, ``dos_mtime`` is returned unchanged.
    """
    flags = 0
    if pos + 2 <= len(data):
        flags = _S_SHORT.unpack_from(data, pos)[0]
        pos += 2

    mtime = dos_mtime
    if flags >> 12 & 8:
        mtime, pos = _parse_rar3_xtime(
            flags >> 12, data, pos, dos_mtime, base_in_header=True
        )
    ctime, pos = _parse_rar3_xtime(
        flags >> 8, data, pos, None, field=("ctime", filename, issues)
    )
    atime, pos = _parse_rar3_xtime(
        flags >> 4, data, pos, None, field=("atime", filename, issues)
    )
    # arctime is walked for the cursor only, so a bad one has no field to report.
    _, pos = _parse_rar3_xtime(flags, data, pos, None)
    return mtime, ctime, atime, pos


def _parse_rar3_xtime(
    flag: int,
    data: bytes,
    pos: int,
    basetime: datetime | None,
    *,
    base_in_header: bool = False,
    field: tuple[str, str, list[TimestampIssue] | None] | None = None,
) -> tuple[datetime | None, int]:
    """One EXTTIME slot: ``(time, pos)``.

    The mtime slot refines the header's DOS word (``base_in_header``, with that
    word's value as ``basetime``); every other slot stores its own DOS word first.
    ``field`` is ``(name, filename, issues)`` for a slot whose invalid word is
    reported. The remainder bytes are consumed either way, so the cursor stays
    aligned when the base time is invalid.
    """
    if not (flag & 8):
        return None, pos
    if not base_in_header:
        if pos + 4 > len(data):
            return None, pos
        stamp, pos = _load_le32(data, pos)
        basetime = _parse_dos_time(stamp)
        if basetime is None and stamp != 0 and field is not None:
            name, filename, issues = field
            if issues is not None:
                issues.append(_dos_time_issue(stamp, name, filename))

    rem = 0
    cnt = flag & 3
    for _ in range(cnt):
        if pos >= len(data):
            break
        b, pos = _load_byte(data, pos)
        rem = (b << 16) | (rem >> 8)

    if basetime is None:
        return None, pos
    if flag & 4 and basetime.second < 59:
        basetime = basetime.replace(second=basetime.second + 1)

    # Convert 100ns units to microseconds (rarfile uses nsdatetime; we keep µs).
    usec = (rem * 100) // 1000
    try:
        return basetime.replace(microsecond=min(usec, 999999)), pos
    except ValueError:
        return basetime, pos


@dataclass(slots=True)
class _Rar5HdrEnc:
    algo: int
    flags: int
    kdf_count: int
    salt: bytes
    check_value: bytes | None


def _rar5_locator_qopen_abs(
    hdata: bytes, extra_size: int, header_offset: int
) -> int | None:
    """Absolute offset of the QO SERVICE header from MAIN extra 0x01, or None.

    Locator field 0 means the reserved vint had no room for the real offset
    (technote: ignore). The stored value is the distance from MAIN to QO.
    """
    if extra_size <= 0:
        return None
    extra_start = len(hdata) - extra_size
    if extra_start < 0:
        return None
    pos = extra_start
    while pos < len(hdata) - 1:
        try:
            xsize, pos = load_vint(hdata, pos)
        except CorruptionError:
            break
        if xsize < 1 or pos + xsize > len(hdata):
            # Same rule as the FILE extra walk: one byte is the smallest legal
            # record, so a declared size of zero is a broken size rather than an
            # empty record. Stopping matters here for cost rather than
            # correctness — a zero-size record advances one byte and raises, so
            # falling through would walk a crafted MAIN extra one byte and one
            # exception at a time. Giving up costs only quick open, which is what
            # every other exit from this walk costs too.
            break
        xdata, pos = _load_bytes(hdata, xsize, pos)
        try:
            xtype, xp = load_vint(xdata, 0)
        except CorruptionError:
            continue
        if xtype != _RAR5_MHEXTRA_LOCATOR:
            continue
        try:
            flags, xp = load_vint(xdata, xp)
            if not (flags & _RAR5_MHEXTRA_LOCATOR_QLIST):
                return None
            offset, xp = load_vint(xdata, xp)
        except CorruptionError:
            return None
        if offset == 0:
            return None
        abs_off = header_offset + offset
        if abs_off < 0 or abs_off > _MAX_SEEK:
            return None
        return abs_off
    return None


def _is_stored_rar5_cmt(member: RarMemberInfo) -> bool:
    # ``encryption_unknown`` refuses for the same reason ``is_encrypted`` does:
    # this gate slices the payload straight out of the archive and decodes it as
    # text, so a header that stopped before it could rule encryption out would
    # put ciphertext in ``ArchiveInfo.comment``. Losing the comment is a missing
    # answer; that would be a wrong one.
    return (
        member.filename == _RAR5_CMT_NAME
        and member.is_stored
        and not member.split_before
        and not member.split_after
        and member.compress_size > 0
        and not member.is_encrypted
        and not member.encryption_unknown
    )


def _decode_rar5_cmt_bytes(raw: bytes) -> str:
    """Decode a RAR5 comment: UTF-8 by the format, cut at the first NUL.

    A byte that is not valid UTF-8 survives as a lone surrogate, as it does in a RAR5
    name (``surrogateescape``), so the comment keeps every stored byte. RARLAB ``rar``
    never writes one; only a crafted comment has it.
    """
    return raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")


def _parse_rar5_qo_payload(
    payload: bytes,
    qo_header_offset: int,
    volume_index: int,
    *,
    max_members: int | None,
    max_metadata_bytes: int | None,
) -> list[RarMemberInfo] | None:
    """Parse QO cache structures into FILE members, or None if unusable."""
    members = _MemberList()
    pos = 0
    n = len(payload)
    # Trailing zeros: AES/size overprovisioning. Stop before them; do not try
    # to parse a CRC=0 record out of the pad.
    data_end = len(payload.rstrip(b"\0"))
    while pos < data_end:
        if n - pos < 5:
            return None
        try:
            crc, pos = _load_le32(payload, pos)
            body_size, pos_after_size = load_vint(payload, pos)
        except CorruptionError:
            return None
        size_bytes = payload[pos:pos_after_size]
        pos = pos_after_size
        if body_size <= 0 or body_size > _RAR5_MAX_HEADER or pos + body_size > n:
            return None
        body = payload[pos : pos + body_size]
        pos += body_size
        if _crc32(size_bytes + body) != crc:
            return None
        try:
            bp = 0
            # UnRAR reads this flags vint and does not act on it.
            _flags, bp = load_vint(body, bp)
            offset_from_qo, bp = load_vint(body, bp)
            data_size, bp = load_vint(body, bp)
        except CorruptionError:
            return None
        if data_size < 0 or bp + data_size > len(body):
            return None
        cached = body[bp : bp + data_size]
        if offset_from_qo <= 0 or offset_from_qo > qo_header_offset:
            return None
        original_offset = qo_header_offset - offset_from_qo
        bio = io.BytesIO(cached)
        try:
            parsed = _read_rar5_block(bio)
        except CorruptionError:
            return None
        if parsed is None:
            return None
        (
            block_type,
            block_flags,
            hdata,
            hpos,
            header_offset_rel,
            header_size,
            data_offset_rel,
            add_size,
            extra_size,
        ) = parsed
        if block_type != _RAR5_FILE:
            continue
        try:
            member = _parse_rar5_file_block(
                hdata,
                hpos,
                block_flags=block_flags,
                extra_size=extra_size,
                header_offset=original_offset + header_offset_rel,
                header_size=header_size,
                data_offset=original_offset + data_offset_rel,
                add_size=add_size,
                volume_index=volume_index,
            )
        except CorruptionError:
            return None
        _append_member(
            members,
            member,
            max_members=max_members,
            max_metadata_bytes=max_metadata_bytes,
        )
    if not members:
        return None
    return members


def _qo_spans_consistent(
    members: list[RarMemberInfo], *, min_offset: int, qopen_abs: int
) -> bool:
    """True if QO-derived packed spans do not overlap and end before QO."""
    prev_end = min_offset
    for member in sorted(members, key=lambda m: m.header_offset):
        if member.header_offset < prev_end:
            return False
        prev_end = _packed_end(member)
    return prev_end <= qopen_abs


def _try_list_via_rar5_qo(
    source: BinaryIO,
    *,
    qopen_abs: int,
    volume_index: int,
    min_file_offset: int,
    max_members: int | None,
    max_metadata_bytes: int | None,
) -> tuple[list[RarMemberInfo], int] | None:
    """Seek to QO and parse FILE copies.

    On success the file pointer is at the end of QO's packed span (also
    returned). The caller seeks back to after MAIN and walks, skipping FILE
    offsets present in the copies. None means the caller should walk FILE
    headers with an empty skip map.
    """
    try:
        source.seek(qopen_abs)
    except (OSError, OverflowError):
        return None
    try:
        parsed = _read_rar5_block(source)
        if parsed is None:
            return None
        (
            block_type,
            block_flags,
            hdata,
            pos,
            header_offset,
            header_size,
            data_offset,
            add_size,
            extra_size,
        ) = parsed
        if block_type != _RAR5_SERVICE:
            return None
        member = _parse_rar5_file_block(
            hdata,
            pos,
            block_flags=block_flags,
            extra_size=extra_size,
            header_offset=header_offset,
            header_size=header_size,
            data_offset=data_offset,
            add_size=add_size,
            volume_index=volume_index,
        )
        if (
            member.filename != _RAR5_QO_NAME
            or not member.is_stored
            or member.is_encrypted
            # Same slice-and-parse hazard as the CMT gate above: an unsettled
            # header would have this parse a member table out of bytes that may
            # be ciphertext. Refusing costs the quick open, and the FILE walk
            # answers the same question from the headers themselves.
            or member.encryption_unknown
            or member.split_before
            or member.split_after
            or member.file_size <= 0
            or member.file_size != member.compress_size
            or member.file_size > _RAR5_QO_PAYLOAD_MAX
        ):
            return None
        source.seek(data_offset)
        payload = _require_exact(source, member.file_size, "RAR5 QO")
        qo_members = _parse_rar5_qo_payload(
            payload,
            header_offset,
            volume_index,
            max_members=max_members,
            max_metadata_bytes=max_metadata_bytes,
        )
        if qo_members is None:
            return None
        if not _qo_spans_consistent(
            qo_members, min_offset=min_file_offset, qopen_abs=qopen_abs
        ):
            return None
        _seek_after_packed(source, data_offset, add_size)
        return qo_members, source.tell()
    # ResourceLimitError must propagate: an over-limit QO is not "unusable".
    except (CorruptionError, OSError, OverflowError):
        return None


def _emit_file_member(
    members: _MemberList,
    member: RarMemberInfo,
    *,
    max_members: int | None,
    max_metadata_bytes: int | None,
) -> bool:
    """Merge a ``split_before`` FILE into the previous member, else append it.

    Both header walks, the QO run and the cross-volume merge use this one rule. A
    continuation is appended only when ``members`` is empty: in a header walk that is
    the first member of a volume, which :func:`_parse_rar_volume` refuses on volume 1.
    Returns ``split_after``.
    """
    if member.split_before and members:
        _merge_split_member(members[-1], member)
    else:
        _append_member(
            members,
            member,
            max_members=max_members,
            max_metadata_bytes=max_metadata_bytes,
        )
    return member.split_after


def _packed_end(member: RarMemberInfo) -> int:
    return member.data_offset + member.compress_size


def _emit_and_skip_qo_run(
    source: BinaryIO,
    *,
    qo_by_off: dict[int, RarMemberInfo],
    members: _MemberList,
    seen_file_offsets: set[int],
    max_members: int | None,
    max_metadata_bytes: int | None,
) -> bool | None:
    """If ``tell()`` is a QO FILE, emit the consecutive cached run and seek past it.

    Returns ``None`` when ``tell()`` is not a QO FILE (caller parses the block).
    Otherwise returns whether any emitted member has ``split_after``.
    """
    pos = source.tell()
    if pos not in qo_by_off:
        return None
    run: list[RarMemberInfo] = []
    visited: set[int] = set()
    while pos in qo_by_off:
        if pos in visited:
            return None
        visited.add(pos)
        member = qo_by_off[pos]
        run.append(member)
        nxt = _packed_end(member)
        if nxt <= pos:
            return None
        pos = nxt
    needs_next = False
    for member in run:
        if _emit_file_member(
            members,
            member,
            max_members=max_members,
            max_metadata_bytes=max_metadata_bytes,
        ):
            needs_next = True
    seen_file_offsets.update(m.header_offset for m in run)
    _seek_to(source, pos)
    return needs_next


def _qo_unmatched_copies(
    qo_by_off: dict[int, RarMemberInfo], seen_file_offsets: set[int]
) -> DamagedServiceHeader | None:
    """The ``QO`` header's report of copies a clean walk never reached, or ``None``.

    Listing follows the walk: a copy is used only when the walk lands on its
    ``header_offset``, as ``unrar`` substitutes a copy only for a FILE header it
    reaches, so an unmatched copy is not a member and the listing is unchanged.
    ``rar`` writes one copy per FILE header it caches, so a copy that matches none is
    a damaged or crafted record, which a strict policy should be able to refuse. It
    rides on the ``MEMBER_HEADER_RECORD_SKIPPED`` channel of a damaged service header.
    The caller asks only after a clean end. A walk that was cut or stopped at a
    damaged header leaves copies unreached for that reason alone. A damaged end block
    stops nothing, but it already makes the archive corrupt, and a claim that the QO
    record is crafted would then rest on a walk whose last header failed its check.
    """
    count = sum(1 for offset in qo_by_off if offset not in seen_file_offsets)
    if not count:
        return None
    noun = "copy" if count == 1 else "copies"
    return DamagedServiceHeader(
        name=_RAR5_QO_NAME,
        skipped_header_records=(
            (
                RAR5_QO_UNMATCHED_COPIES,
                None,
                f"{count} FILE header {noun} that matched no header the walk reached",
            ),
        ),
        header_walk_stop_reason=None,
    )


def _parse_rar5(
    source: BinaryIO,
    *,
    password: str | bytes | None,
    kdf_cache: RarKdfCache,
    sfx_offset: int,
    volume_index: int = 0,
    use_qo: bool = True,
    max_members: int | None,
    max_metadata_bytes: int | None,
) -> RarArchive:
    _require_exact(source, len(RAR5_ID), "RAR5 signature")

    is_solid = False
    is_volume = False
    comment: str | None = None
    members = _MemberList()
    hdr_enc: _Rar5HdrEnc | None = None
    # Whether a check value positively confirmed the header password; see
    # _header_failure and _check_rar5_password.
    password_proven = False
    needs_next_volume = False
    seen_file_offsets: set[int] = set()
    qo_by_off: dict[int, RarMemberInfo] = {}
    damaged_service_headers: list[DamagedServiceHeader] = []
    damaged_service_headers_omitted = 0
    truncated: str | None = None
    damaged: str | None = None
    main_seen = False
    end_block_seen = False
    end_block_damaged_at: int | None = None
    trailing_at: int | None = None
    # Only the first MAIN of a volume is asked for the quick-open table. unrar
    # accepts a repeated MAIN, and each try reads a QO payload of up to
    # _RAR5_QO_PAYLOAD_MAX, so trying on every MAIN would let a 17-byte header buy
    # that read again.
    qo_tried = not use_qo

    while True:
        header_fd: _Readable = source
        header_start = source.tell()
        if hdr_enc is not None:
            assert password is not None  # the ENCRYPTION block raised without one
            # See the RAR3 walk: the IV read and key derivation do not depend on the
            # password, so their errors are not a wrong password. No IV at all is the
            # walk's end, as for a plain header; part of one is a cut.
            iv = read_exact(source, 16)
            if len(iv) < 16:
                truncated = _no_header(source, header_start, encrypted_cut=bool(iv))
                break
            header_fd = _rar5_decrypt_header(source, iv, hdr_enc, password, kdf_cache)

        skipped = _emit_and_skip_qo_run(
            source,
            qo_by_off=qo_by_off,
            members=members,
            seen_file_offsets=seen_file_offsets,
            max_members=max_members,
            max_metadata_bytes=max_metadata_bytes,
        )
        if skipped is not None:
            if skipped:
                needs_next_volume = True
            continue

        try:
            parsed = _read_rar5_block(header_fd)
        except CorruptionError as exc:
            # A plain cut includes one inside the CRC or the size vint.
            truncated = _header_failure(
                exc, header_fd, header_start, proven=password_proven, version="RAR5"
            )
            if truncated is not None:
                break
            if isinstance(exc, _RarEndBlockCrcError):
                # As in the RAR3 walk: only a block with nothing but zeros after it is
                # the end block. Damage after the last member keeps the listing, and
                # the block's next-volume flag is not read.
                if _only_zeros_after(source, exc.data_offset):
                    end_block_seen = True
                    end_block_damaged_at = header_start
                    break
                if not main_seen:
                    raise exc.generic from None
                # Not an end block, so a member header whose type byte is damaged.
                damaged = _damaged_header(exc.generic, header_start)
                break
            if isinstance(exc, _RarHeaderCrcError) and main_seen:
                damaged = _damaged_header(exc, header_start)
                break
            raise
        if parsed is None:
            truncated = _no_header(
                source, header_start, encrypted_cut=hdr_enc is not None
            )
            break
        (
            block_type,
            block_flags,
            hdata,
            pos,
            header_offset,
            header_size,
            data_offset,
            add_size,
            extra_size,
        ) = parsed

        if block_type == _RAR5_MAIN:
            main_flags, pos = load_vint(hdata, pos)
            if main_flags & _RAR5_MAIN_HAS_VOLNR:
                volnr, pos = load_vint(hdata, pos)
                # RAR5: first volume omits the field (implicit 0); later volumes
                # store 1 for the second volume, 2 for the third, …
                if volume_index == 0 and volnr != 0:
                    raise UnsupportedFeatureError(
                        "Need first volume of multi-volume RAR archive"
                    )
                if volume_index > 0 and volnr != volume_index:
                    raise TruncatedError(
                        f"Out-of-order RAR volume: expected volume index "
                        f"{volume_index}, got {volnr}"
                    )
            elif volume_index > 0:
                raise TruncatedError(
                    f"Out-of-order RAR volume: expected volume index {volume_index}, "
                    f"got first-volume header"
                )
            is_solid = bool(main_flags & _RAR5_MAIN_SOLID)
            is_volume = bool(main_flags & _RAR5_MAIN_ISVOL)
            main_seen = True
            _seek_after_packed(source, data_offset, add_size)
            # Header-encrypted QO stores IV+ciphertext header copies and
            # file-encrypts the QO payload; reconstructed data_offset then
            # misses AES padding. Treat that QO as unreadable (FILE walk).
            if hdr_enc is None and not qo_tried:
                qo_tried = True
                qopen_abs = _rar5_locator_qopen_abs(hdata, extra_size, header_offset)
                if qopen_abs is not None:
                    resume_pos = source.tell()
                    listed = _try_list_via_rar5_qo(
                        source,
                        qopen_abs=qopen_abs,
                        volume_index=volume_index,
                        min_file_offset=resume_pos,
                        max_members=max_members,
                        max_metadata_bytes=max_metadata_bytes,
                    )
                    if listed is not None:
                        qo_members, _qo_end = listed
                        qo_by_off = {m.header_offset: m for m in qo_members}
                        # Back to after MAIN. CMT is a normal SERVICE on the
                        # walk; a FILE in the skip map is emitted from the copy.
                        _seek_to(source, resume_pos)
                        continue
                    _seek_to(source, resume_pos)
            continue

        if block_type == _RAR5_ENCRYPTION:
            algo, pos = load_vint(hdata, pos)
            enc_flags, pos = load_vint(hdata, pos)
            kdf_count, pos = _load_byte(hdata, pos)
            salt, pos = _load_bytes(hdata, 16, pos)
            check_value = None
            if enc_flags & _RAR5_ENC_HAS_CHECKVAL:
                check_value, pos = _load_bytes(hdata, 12, pos)
            if algo != _RAR5_XENC_AES256:
                raise UnsupportedFeatureError(
                    f"Unsupported RAR5 header encryption cipher: {algo}"
                )
            if password is None:
                raise EncryptionError(
                    "RAR archive has encrypted headers but no password was provided"
                )
            if check_value is not None:
                password_proven = _check_rar5_password(
                    check_value, kdf_count, salt, password, kdf_cache=kdf_cache
                )
            hdr_enc = _Rar5HdrEnc(
                algo=algo,
                flags=enc_flags,
                kdf_count=kdf_count,
                salt=salt,
                check_value=check_value,
            )
            _seek_after_packed(source, data_offset, add_size)
            continue

        if block_type == _RAR5_ENDARC:
            endarc_flags, _ = load_vint(hdata, pos)
            needs_next_volume = bool(endarc_flags & _RAR5_ENDARC_NEXT_VOLUME)
            end_block_seen = True
            trailing_at = _scan_after_end_block(
                source, _packed_span_end(data_offset, add_size)
            )
            break

        if block_type in (_RAR5_FILE, _RAR5_SERVICE):
            member = _parse_rar5_file_block(
                hdata,
                pos,
                block_flags=block_flags,
                extra_size=extra_size,
                header_offset=header_offset,
                header_size=header_size,
                data_offset=data_offset,
                add_size=add_size,
                volume_index=volume_index,
            )
            if block_type == _RAR5_FILE:
                # File-version history rows (extra 0x04) are kept as members.
                # QO copies are emitted in `_emit_and_skip_qo_run` before this
                # read; this branch is holes, FILE after QO, and the no-QO walk.
                if member.header_offset not in seen_file_offsets:
                    if _emit_file_member(
                        members,
                        member,
                        max_members=max_members,
                        max_metadata_bytes=max_metadata_bytes,
                    ):
                        needs_next_volume = True
                    seen_file_offsets.add(member.header_offset)
            elif block_type == _RAR5_SERVICE:
                if (
                    member.skipped_header_records or member.header_walk_stop_reason
                ) and not _append_damaged_service_header(
                    damaged_service_headers, member
                ):
                    damaged_service_headers_omitted += 1
                if _is_stored_rar5_cmt(member) and _span_in_file(
                    source, data_offset, member.compress_size
                ):
                    source.seek(data_offset)
                    # The packed size, as for any stored payload: the unpacked one
                    # is only a claim, and bytes past the packed span belong to the
                    # next header.
                    raw = _read_comment(
                        source,
                        member.compress_size,
                        "RAR5 comment",
                        max_metadata_bytes,
                    )
                    comment = _decode_rar5_cmt_bytes(raw)
            _seek_after_packed(source, data_offset, add_size)
            continue

        # Unknown block — skip data area.
        _seek_after_packed(source, data_offset, add_size)

    # A cut or a damaged header stops the walk early, so copies past it are unreached
    # for that reason alone; both break out of the loop before ``end_block_seen`` is
    # set, so that flag alone withholds the report for them. A damaged end block
    # stops nothing, but the archive is already corrupt and the QO claim would rest
    # on a header whose CRC failed, so it is withheld there too. The entry bypasses
    # the cap (_is_qo_unmatched_copies).
    if end_block_seen and end_block_damaged_at is None:
        unmatched = _qo_unmatched_copies(qo_by_off, seen_file_offsets)
        if unmatched is not None:
            damaged_service_headers.append(unmatched)

    return RarArchive(
        version=5,
        is_solid=is_solid,
        has_header_encryption=hdr_enc is not None,
        comment=comment,
        members=members,
        sfx_offset=sfx_offset,
        is_volume=is_volume,
        needs_next_volume=needs_next_volume,
        damaged_service_headers=damaged_service_headers,
        damaged_service_headers_omitted=damaged_service_headers_omitted,
        truncated=truncated,
        damaged=damaged,
        end_block_missing_volumes=(
            [volume_index]
            if not end_block_seen and truncated is None and damaged is None
            else []
        ),
        end_block_damaged_volumes=(
            {volume_index: end_block_damaged_at}
            if end_block_damaged_at is not None
            else {}
        ),
        trailing_data_volumes=(
            {volume_index: trailing_at} if trailing_at is not None else {}
        ),
    )


def _read_rar5_block(
    fd: _Readable,
) -> tuple[int, int, bytes, int, int, int, int, int, int] | None:
    """Read one RAR5 block.

    Returns
    ``(type, flags, hdata, pos_after_common, header_offset, header_size,
    data_offset, add_size, extra_size)`` or ``None`` at EOF.

    Reads the size vint byte-at-a-time rather than prefetching a large window and
    seeking back: :class:`_HeaderDecryptStream` has no ``seek``, and its ``tell``
    is the ciphertext cursor. Leftover ``_buf`` is not rewind room — mid-header
    it is still-owed plaintext; after ``header_size`` it is AES padding.
    """
    header_offset = fd.tell()
    preload = 4 + 1
    head = bytearray(read_exact(fd, preload))
    if not head:
        return None
    if len(head) < preload:
        raise _RarHeaderCutError("Unexpected EOF while reading RAR5 header")
    # The header-size vint starts at byte 4 (after the 4-byte CRC). A vint is at most
    # 10 bytes; cap the continuation so a crafted run of 0x80 bytes cannot drive an
    # unbounded, O(n^2) byte-at-a-time read of the source before ``load_vint``'s own
    # 11-byte guard (which only runs *after* this loop) would reject it.
    while head[-1] & 0x80:
        if len(head) - 4 >= 10:
            raise CorruptionError(
                "Invalid RAR5 header size (variable-length integer too long)"
            )
        b = fd.read(1)
        if not b:
            raise _RarHeaderCutError("Unexpected EOF while reading RAR5 header size")
        head += b
    start_bytes = bytes(head)
    header_crc, pos = _load_le32(start_bytes, 0)
    hdrlen, pos = load_vint(start_bytes, pos)
    if hdrlen > _RAR5_MAX_HEADER:
        raise CorruptionError(f"RAR5 header too large: {hdrlen}")
    header_size = pos + hdrlen
    hdata = start_bytes + read_exact(fd, header_size - len(start_bytes))
    if len(hdata) != header_size:
        raise _RarHeaderCutError("Unexpected EOF while reading RAR5 header body")
    # Ciphertext cursor, including AES block padding. Same invariant as the
    # RAR3 walk: this is where packed data (or the next header's IV) starts.
    data_offset = fd.tell()

    if header_crc != _crc32(memoryview(hdata)[4:]):
        try:
            damaged_type, _ = load_vint(hdata, pos)
        except CorruptionError:
            damaged_type = None
        if damaged_type == _RAR5_ENDARC and _rar5_end_block_shaped(hdata, pos):
            raise _RarEndBlockCrcError(header_offset, data_offset)
        raise _RarHeaderCrcError(f"RAR5 header CRC mismatch at offset {header_offset}")

    block_type, pos = load_vint(hdata, pos)
    block_flags, pos = load_vint(hdata, pos)
    extra_size = 0
    add_size = 0
    if block_flags & _RAR5_FLAG_EXTRA:
        extra_size, pos = load_vint(hdata, pos)
    if block_flags & _RAR5_FLAG_DATA:
        add_size, pos = load_vint(hdata, pos)
    return (
        block_type,
        block_flags,
        hdata,
        pos,
        header_offset,
        header_size,
        data_offset,
        add_size,
        extra_size,
    )


def _rar5_decrypt_header(
    source: BinaryIO,
    iv: bytes,
    hdr_enc: _Rar5HdrEnc,
    password: str | bytes,
    kdf_cache: RarKdfCache,
) -> _HeaderDecryptStream:
    if hdr_enc.kdf_count > _RAR_MAX_KDF_SHIFT:
        raise CorruptionError(f"RAR5 kdf_count too large: {hdr_enc.kdf_count}")
    key = kdf_cache.rar5(password, hdr_enc.salt, 1 << hdr_enc.kdf_count)
    return _HeaderDecryptStream(source, key, iv)


def _check_rar5_password(
    check_value: bytes,
    kdf_count_shift: int,
    salt: bytes,
    password: str | bytes,
    *,
    kdf_cache: RarKdfCache | None = None,
) -> bool:
    """Verify the RAR5 header password against the check value.

    Returns ``True`` when the check value positively confirms the password (so a later
    header failure is genuine corruption, not a wrong password); ``False`` when the
    check value is unusable/absent (no verifier — a later failure is indistinguishable
    from a wrong password). Raises :class:`EncryptionError` when the password is
    provably wrong.
    """
    if len(check_value) != 12:
        return False
    if kdf_count_shift > _RAR_MAX_KDF_SHIFT:
        raise CorruptionError(f"RAR5 kdf_count too large: {kdf_count_shift}")
    hdr_check = check_value[:8]
    hdr_sum = check_value[8:]
    if not hmac.compare_digest(hashlib.sha256(hdr_check).digest()[:4], hdr_sum):
        return False
    kdf_count = (1 << kdf_count_shift) + 32
    derive = kdf_cache.rar5 if kdf_cache is not None else _rar5_s2k
    pwd_hash = derive(password, salt, kdf_count)
    pwd_check = bytearray(8)
    for i, v in enumerate(pwd_hash):
        pwd_check[i & 7] ^= v
    if not hmac.compare_digest(bytes(pwd_check), hdr_check):
        raise wrong_password_error("Wrong password for RAR5 header encryption")
    return True


def _rar5_dictionary_size(compress_info: int) -> int:
    """The dictionary size a RAR5 compression-info field declares, in bytes."""
    rar50 = (compress_info & _RAR5_ALGO_MASK) == _RAR5_ALGO_RAR50
    exponent = (compress_info >> _RAR5_DICT_SHIFT) & (0x0F if rar50 else 0x1F)
    size = _RAR5_DICT_BASE << exponent
    if not rar50:
        size += size // 32 * ((compress_info >> 15) & 0x1F)
    return size


def _parse_rar5_file_block(
    hdata: bytes,
    pos: int,
    *,
    block_flags: int,
    extra_size: int,
    header_offset: int,
    header_size: int,
    data_offset: int,
    add_size: int,
    volume_index: int,
) -> RarMemberInfo:
    file_flags, pos = load_vint(hdata, pos)
    file_size, pos = load_vint(hdata, pos)
    mode, pos = load_vint(hdata, pos)

    mtime: datetime | None = None
    crc32: int | None = None
    if file_flags & _RAR5_FILE_HAS_MTIME:
        mtime, pos = _load_unixtime(hdata, pos)
    if file_flags & _RAR5_FILE_HAS_CRC32:
        crc32, pos = _load_le32(hdata, pos)

    compress_info, pos = load_vint(hdata, pos)
    host_os_raw, pos = load_vint(hdata, pos)
    orig_filename, pos = _load_vstr(hdata, pos)
    # surrogateescape, not replace: two names that differ only in bytes that are not
    # UTF-8 stay two names, as they do in TAR, and the extraction name policy escapes
    # those bytes (O7). unrar is addressed from ``orig_filename``, not from this.
    filename = orig_filename.decode("utf8", "surrogateescape").rstrip("/")

    host_os = 2 if host_os_raw == _RAR5_OS_WINDOWS else 3  # RAR_OS_WIN32 / UNIX
    compress_type = _RAR3_M0 + ((compress_info >> 7) & 7)
    file_solid = bool(compress_info & _RAR5_COMPR_SOLID)
    is_directory = bool(file_flags & _RAR5_FILE_ISDIR)
    split_before = bool(block_flags & _RAR5_FLAG_SPLIT_BEFORE)
    split_after = bool(block_flags & _RAR5_FLAG_SPLIT_AFTER)

    blake2sp_hash: bytes | None = None
    file_redir: tuple[int, int, str] | None = None
    file_encryption: RarEncryptionInfo | None = None
    file_version: int | None = None
    owner: RarOwner | None = None
    flags = 0
    ctime: datetime | None = None
    atime: datetime | None = None
    skipped_records: list[tuple[str, int | None, str]] = []
    timestamp_issues: list[TimestampIssue] = []
    # Why the walk stopped, or ``None`` if it ran to the end. Four exits reach it
    # and they are not the same fault, so the diagnostic must not name one of them
    # for all four: a single zero-size record is not "more than sixteen malformed".
    stop_reason: str | None = None
    unplaced_bytes = 0

    if extra_size:
        # The extra area is the header's last ``extra_size`` bytes, wherever the
        # fixed fields end — the same rule as the MAIN locator walk, and the one
        # ``unrar`` applies (``ProcessExtra50``). Walking on from the end of the
        # name instead reads the wrong bytes as records whenever the two disagree.
        extra_start = len(hdata) - extra_size
        if extra_start <= 0:
            # ``unrar`` 7.00 checks ``ExtraSize >= HeadSize`` when it reads the
            # size and reports "Corrupt header": an extra area that does not fit
            # in its own header is not one a walk can place. Both sizes count the
            # whole header, its CRC and size vint included, which is ``hdata``;
            # the oracle rows at ``len(hdata) - 1`` and ``len(hdata)`` pin it.
            raise CorruptionError(
                f"RAR5 header at offset {header_offset} declares an extra area of "
                f"{extra_size} bytes in a {len(hdata)}-byte header"
            )
        if extra_start < pos:
            # The area would overlap the fields already read. ``unrar`` ignores
            # the extras then and lists the member from its fixed fields. Do the
            # same, but through the stop reason: an unread area may hold the
            # encryption record, so the member is ``encryption_unknown`` rather
            # than silently plaintext.
            stop_reason = "its extra area overlaps the header's fixed fields"
            pos = len(hdata)
        else:
            # A writer leaves no room here: the fixed fields end where the extra
            # area starts. ``unrar`` skips any bytes in between without a word and
            # lists the member, and so does this walk; but bytes no writer puts
            # there mean the header is damaged or crafted, which is what the
            # diagnostic (and a strict policy) is for. Should a later RAR add a
            # fixed field this parser does not read, this fires on every such
            # header and is the place to teach it.
            unplaced_bytes = extra_start - pos
            pos = extra_start
        # Walk extras until near end (allow 1 byte of padding like rarfile).
        while pos < len(hdata) - 1:
            if len(skipped_records) >= _MAX_SKIPPED_HEADER_RECORDS:
                # Still inside the loop, so bytes remain; a member whose last
                # skipped record is also its last extra never gets here.
                stop_reason = (
                    f"more than {_MAX_SKIPPED_HEADER_RECORDS} of its extra "
                    f"records were malformed"
                )
                break
            try:
                xsize, pos = load_vint(hdata, pos)
            except CorruptionError as exc:
                # ``load_vint`` does not advance ``pos`` on failure, so the
                # next record has no boundary. Stop, and say so.
                skipped_records.append(("unknown", None, raw_message_of(exc)))
                stop_reason = "an extra record's size could not be read"
                break
            if xsize < 1:
                # A record's body opens with its type vint, so one byte is the
                # smallest legal record: a type with no payload, which is what an
                # unimplemented record looks like. A declared size of zero names
                # nothing, so the size vint is wrong and the offset it puts the
                # next record at is wrong with it. It is also one attacker byte
                # per record, which is what made a crafted extra area expensive
                # rather than merely damaged. ``unrar`` 7.00 does carry on here
                # and gets a wrong answer for it — one such record in front of an
                # encrypted member and ``unrar l`` reports it as plaintext — so
                # the oracle that justifies the leniency above does not reach
                # this case.
                skipped_records.append(
                    ("unknown", None, "extra record declares a size of zero")
                )
                stop_reason = "an extra record declared a size of zero"
                break
            if pos + xsize > len(hdata):
                skipped_records.append(
                    ("unknown", None, "extra record overruns the extra area")
                )
                stop_reason = "an extra record overran the extra area"
                break
            xdata, pos = _load_bytes(hdata, xsize, pos)
            try:
                xtype, xpos = load_vint(xdata, 0)
            except CorruptionError as exc:
                # A body of the declared length whose type vint has no terminating
                # byte. The framing is intact — the next record's offset is known —
                # so this is a dropped record like any other, not a reason to stop.
                # Two attacker bytes apiece, which is what the cap at the loop head
                # keeps from becoming one retained tuple per extra byte.
                skipped_records.append(("unknown", None, raw_message_of(exc)))
                continue
            try:
                if xtype == _RAR5_XFILE_TIME:
                    mtime, ctime, atime = _parse_rar5_xtime(
                        xdata,
                        xpos,
                        mtime,
                        ctime,
                        atime,
                        filename=filename,
                        issues=timestamp_issues,
                    )
                elif xtype == _RAR5_XFILE_ENCRYPTION:
                    # Deliberately *not* skippable. Dropping this record would
                    # leave ``file_encryption`` unset and the member would list as
                    # plaintext, which is a wrong answer rather than a missing one
                    # — the failure class this library treats as the worst. A
                    # member whose encryption parameters cannot be read is not a
                    # member that can be presented at all.
                    file_encryption = _parse_rar5_file_encryption(xdata, xpos)
                    flags |= _RAR3_FILE_PASSWORD
                elif xtype == _RAR5_XFILE_HASH:
                    hash_type, xpos = load_vint(xdata, xpos)
                    if hash_type == _RAR5_XHASH_BLAKE2SP:
                        blake2sp_hash, xpos = _load_bytes(xdata, 32, xpos)
                elif xtype == _RAR5_XFILE_REDIR:
                    redir_type, xpos = load_vint(xdata, xpos)
                    redir_flags, xpos = load_vint(xdata, xpos)
                    redir_name, xpos = _load_vstr(xdata, xpos)
                    file_redir = (
                        redir_type,
                        redir_flags,
                        redir_name.decode("utf8", "surrogateescape"),
                    )
                elif xtype == _RAR5_XFILE_VERSION:
                    _vflags, xpos = load_vint(xdata, xpos)
                    file_version, xpos = load_vint(xdata, xpos)
                elif xtype == _RAR5_XFILE_OWNER:
                    owner = _parse_rar5_owner(xdata, xpos)
                # SERVICE / unknown: ignore
            except CorruptionError as exc:
                if xtype == _RAR5_XFILE_ENCRYPTION:
                    raise
                # Drop this record and keep the member. The walk already ignores a
                # record type it does not know; a *known* type it cannot parse is
                # the same amount of missing information, and refusing the archive
                # over it loses every member that parsed. ``unrar`` 7.00 lists such
                # an archive. The caller surfaces this as a diagnostic, which under
                # a strict policy raises — so strictness stays available without
                # being the default. Whatever the record would have set keeps the
                # value it had; nothing half-written is committed, because each
                # branch assigns only on its own last statement.
                skipped_records.append(
                    (_RAR5_XNAMES.get(xtype, "unknown"), xtype, raw_message_of(exc))
                )

    if unplaced_bytes:
        # Added after the walk so the cap on malformed records counts records
        # only, and first because the bytes come first in the header.
        skipped_records.insert(
            0,
            (
                RAR5_UNPLACED_BYTES,
                None,
                (
                    f"{unplaced_bytes} bytes between its fixed fields and its "
                    "declared extra area"
                ),
            ),
        )

    is_symlink = False
    is_hardlink_or_copy = False
    if file_redir is not None:
        rtype = file_redir[0]
        if rtype in (
            _RAR5_XREDIR_UNIX_SYMLINK,
            _RAR5_XREDIR_WINDOWS_SYMLINK,
            _RAR5_XREDIR_WINDOWS_JUNCTION,
        ):
            is_symlink = True
        elif rtype in (_RAR5_XREDIR_HARD_LINK, _RAR5_XREDIR_FILE_COPY):
            is_hardlink_or_copy = True

    if is_directory and not is_symlink:
        filename = filename + "/"

    return RarMemberInfo(
        filename=filename,
        orig_filename=orig_filename,
        file_size=file_size,
        compress_size=add_size,
        compress_type=compress_type,
        crc32=crc32,
        blake2sp_hash=blake2sp_hash,
        mtime=mtime,
        ctime=ctime,
        atime=atime,
        mode=mode,
        host_os=host_os,
        flags=flags,
        file_redir=file_redir,
        file_encryption=file_encryption,
        header_offset=header_offset,
        header_size=header_size,
        data_offset=data_offset,
        extract_version=50,
        file_solid=file_solid,
        is_directory=is_directory and not is_symlink,
        is_symlink=is_symlink,
        is_hardlink_or_copy=is_hardlink_or_copy,
        # What the header actually said, and only that. A member whose walk
        # stopped before the encryption record could be ruled out is not
        # "not encrypted" — it is *unknown*, which is ``encryption_unknown``
        # rather than this flag. Keeping the two apart is what stops one
        # damaged member from reporting a whole plaintext archive as encrypted.
        is_encrypted=file_encryption is not None,
        volume_index=volume_index,
        split_before=split_before,
        split_after=split_after,
        file_version=file_version,
        owner=owner,
        # RAR5 keeps the directory flag apart from the dictionary bits, so a
        # directory-flagged link reports what its compression info declares.
        dictionary_size=0
        if is_directory and not is_symlink
        else _rar5_dictionary_size(compress_info),
        rar5_algorithm_version=compress_info & _RAR5_ALGO_MASK,
        skipped_header_records=tuple(skipped_records),
        header_walk_stop_reason=stop_reason,
        timestamp_issues=tuple(timestamp_issues) if timestamp_issues else (),
    )


def _parse_rar5_owner(xdata: bytes, pos: int) -> RarOwner:
    """The fields of a RAR5 owner record (``FHEXTRA_UOWNER``) after its type vint.

    Flags, then each field its flag announces, in order: user name and group name
    (vint length, bytes), user id and group id (vints). Names are decoded as UTF-8,
    with any other byte kept as a lone surrogate, as for link targets.
    """
    flags, pos = load_vint(xdata, pos)
    uname = gname = None
    uid = gid = None
    if flags & _RAR5_XOWNER_UNAME:
        raw, pos = _load_vstr(xdata, pos)
        uname = raw.decode("utf8", "surrogateescape")
    if flags & _RAR5_XOWNER_GNAME:
        raw, pos = _load_vstr(xdata, pos)
        gname = raw.decode("utf8", "surrogateescape")
    if flags & _RAR5_XOWNER_UID:
        uid, pos = load_vint(xdata, pos)
    if flags & _RAR5_XOWNER_GID:
        gid, pos = load_vint(xdata, pos)
    return RarOwner(uname, gname, uid, gid)


def _apply_rar5_unix_ns(
    xdata: bytes, pos: int, dt: datetime | None, *, present: bool
) -> tuple[datetime | None, int]:
    """Consume a unix-ns extra when the corresponding HAS_* flag is set.

    The nsec word is present whenever HAS_* is set, even if the timestamp
    itself failed to decode — skip it and the later fields desync.
    """
    if not present:
        return dt, pos
    if pos + 4 > len(xdata):
        # Truncated ns word: keep whatever decoded, do not abort the listing.
        return dt, pos
    nsec, pos = _load_le32(xdata, pos)
    if dt is None:
        return None, pos
    try:
        return dt.replace(microsecond=min(nsec // 1000, 999999)), pos
    except ValueError:
        return dt, pos


def _parse_rar5_xtime(
    xdata: bytes,
    pos: int,
    current_mtime: datetime | None,
    current_ctime: datetime | None = None,
    current_atime: datetime | None = None,
    *,
    filename: str = "",
    issues: list[TimestampIssue] | None = None,
) -> tuple[datetime | None, datetime | None, datetime | None]:
    """Apply one RAR5 time extra. A FILETIME out of ``datetime``'s range is
    ``None`` and, when ``issues`` is given, is recorded there."""
    tflags, pos = load_vint(xdata, pos)

    def ldr(field: str, at: int) -> tuple[datetime | None, int]:
        if tflags & _RAR5_XTIME_UNIXTIME:
            return _load_unixtime(xdata, at)
        return _load_windowstime(
            xdata, at, filename=filename, field=field, issues=issues
        )

    mtime = current_mtime
    ctime = current_ctime
    atime = current_atime
    if tflags & _RAR5_XTIME_HAS_MTIME:
        mtime, pos = ldr("mtime", pos)
    if tflags & _RAR5_XTIME_HAS_CTIME:
        ctime, pos = ldr("ctime", pos)
    if tflags & _RAR5_XTIME_HAS_ATIME:
        atime, pos = ldr("atime", pos)
    if tflags & _RAR5_XTIME_UNIXTIME_NS:
        mtime, pos = _apply_rar5_unix_ns(
            xdata, pos, mtime, present=bool(tflags & _RAR5_XTIME_HAS_MTIME)
        )
        ctime, pos = _apply_rar5_unix_ns(
            xdata, pos, ctime, present=bool(tflags & _RAR5_XTIME_HAS_CTIME)
        )
        atime, pos = _apply_rar5_unix_ns(
            xdata, pos, atime, present=bool(tflags & _RAR5_XTIME_HAS_ATIME)
        )
    return mtime, ctime, atime


def _parse_rar5_file_encryption(xdata: bytes, pos: int) -> RarEncryptionInfo:
    algo, pos = load_vint(xdata, pos)
    flags, pos = load_vint(xdata, pos)
    kdf_count, pos = _load_byte(xdata, pos)
    salt, pos = _load_bytes(xdata, 16, pos)
    iv, pos = _load_bytes(xdata, 16, pos)
    check_value = None
    if flags & _RAR5_XENC_CHECKVAL:
        check_value, pos = _load_bytes(xdata, 12, pos)
    return RarEncryptionInfo(
        algo=algo,
        flags=flags,
        kdf_count=kdf_count,
        salt=salt,
        iv=iv,
        check_value=check_value,
    )


# ---------------------------------------------------------------------------
# ISC License notice for algorithms adapted from rarfile
# (RAR3 SHA-1 / string-to-key and Unicode filename decompression above)
# ---------------------------------------------------------------------------
#
# Copyright (c) 2005-2024 Marko Kreen <markokr@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
