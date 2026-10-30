"""Native RAR reader backend.

Module split:

- :mod:`.rar_parser` — metadata, offsets, encryption headers, multi-volume merge
- :mod:`.rar_unrar` — spawn RARLAB ``unrar p`` (password on stdin; ``-n./member``)
- :mod:`.rar_unar` — the refusals and pipe layout when the caller selects ``unar``
  (``ArchiveyConfig.rar_decompressor``); the process itself is
  :mod:`archivey.internal.external.unar`
- this module — ``BaseArchiveReader``: list from the parser; member **data** via unrar,
  or via ``unar`` when selected (same shapes, entries named by index instead of mask)

Data-open shapes:

- Solid archive → one ``unrar p`` ALL-pipe + :class:`SolidBlockReader` demux
- Stored, unencrypted, every part found → direct sliced view (no ``unrar``),
  whatever the solid flag; a split member's part views are joined
- Stored, encrypted with AES (RAR 2.9 and later), in one part → the direct view
  decrypted here (no ``unrar``), when ``cryptography`` is installed
- ``RarDecompressor.NONE`` → only those direct views; every other read is refused
- Other non-solid → per-member named ``unrar p -n./…`` opens
- Stream / non-path sources may be materialized to a temp ``.rar`` so ``unrar``
  can open a real path (and resolve sibling volumes)

WinRAR ``-ver`` history members are presented as ``path;n`` (see
:func:`_presented_filename`). Passwords feed three places: header parse, ``unrar``,
and RAR5 ConvertHashToMAC when checksums are tweaked.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import shutil
import subprocess
import tempfile
import threading
import zlib
from collections.abc import Callable, Generator, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Literal, NamedTuple, assert_never

from archivey.config import ArchiveyConfig, RarDecompressor, SpoolLimits
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    DigestContext,
    MemberHeaderRecordContext,
    UnknownMemberTypeContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    LinkTargetNotFoundError,
    LinkTargetNotFoundReason,
    PackageNotInstalledError,
    ReadError,
    ResourceLimitError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
    raw_message_of,
)
from archivey.internal.backends.rar_copy_sources import FileCopySources
from archivey.internal.backends.rar_detect import validate_rar_main_header
from archivey.internal.backends.rar_parser import (
    _RAR3_M0,
    _RAR5_XENC_AES256,
    _RAR5_XREDIR_REPARSE_POINTS,
    RAR3_UOW_NAME,
    RAR5_ID,
    RAR5_QO_UNMATCHED_COPIES,
    RAR5_UNPLACED_BYTES,
    RAR_ID,
    DamagedServiceHeader,
    RarArchive,
    RarEncryptionInfo,
    RarKdfCache,
    RarMemberInfo,
    RarOwner,
    _check_rar5_password,
    _Rar3Comment,
    _rar5_redirect_target,
    comment_metadata_bytes,
    convert_blake2sp_to_mac,
    convert_crc_to_mac,
    decode_rar3_cmt_text,
    header_metadata_bytes,
    mark_missing_next_volume,
    parse_rar_archive,
    parse_rar_volumes,
    rar5_data_key,
    rar5_hash_key,
)
from archivey.internal.backends.rar_unar import (
    REFUSE_NON_ASCII_PASSWORD,
    UNAR_PURPOSE,
    UnarRarPolicy,
    solid_after_unknown_compression,
    solid_after_unknown_compression_reason,
    unar_dictionary_costs,
    uses_no_dictionary,
)
from archivey.internal.backends.rar_unrar import (
    UNAR_BY_POSITION_HINT,
    UnrarMask,
    UnrarMaskRefusal,
    UnrarNameRefusal,
    decompress_rar3_blob,
    find_rarlab_unrar,
    open_unrar_p,
    plan_unrar_mask,
    rarlab_unrar_missing,
    unrar_dot_rule,
    unrar_dot_rule_can_matter,
    unrar_mask_keys,
    unrar_mask_selects,
    unrar_member_view,
    unrar_selection_keys,
)
from archivey.internal.base_reader import (
    MAX_LINK_TARGET_BYTES,
    BaseArchiveReader,
    ReadBackend,
    SolidRun,
    pass_has_data,
)
from archivey.internal.config import KeyDerivationBudget, check_decoder_memory
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.external.cli import ProcessOutputStream, signal_exit_error
from archivey.internal.external.unar import (
    UnarOutputStream,
    find_unar,
    open_unar_stdout,
    unar_password_supported,
)
from archivey.internal.file_copy_pass import DEFAULT_FILE_COPY_PASS, FileCopyPass
from archivey.internal.hashing import crc32_digest
from archivey.internal.listing_limits import check_metadata_budget
from archivey.internal.logs import backends as logger, integrity as integrity_logger
from archivey.internal.naming import (
    emit_member_name_normalized,
    normalize_member_name,
    resolve_link_target_name,
)
from archivey.internal.open_site import OpenSite
from archivey.internal.password import (
    _PasswordCandidates,
    _PasswordCandidatesExhausted,
    mark_unverified_data,
    wrong_password_error,
)
from archivey.internal.password_confirm import (
    PASSWORD_CONFIRM_CHUNK_BYTES,
    PASSWORD_CONFIRM_MIN_VERIFIED_BYTES,
    PASSWORD_CONFIRM_PREFIX_BYTES,
    PasswordConfirmPlan,
    PasswordConfirmVerdict,
    attempt_with_confirm,
    plan_password_confirm,
    run_password_confirm_plan,
)
from archivey.internal.registry import register_reader
from archivey.internal.source import ArchiveSource
from archivey.internal.spool import SpoolBudget
from archivey.internal.streams.archive_stream import (
    ArchiveStreamImpl,
    MemberStreamParts,
    RewindWarning,
)
from archivey.internal.streams.crypto import (
    AES_BLOCK_SIZE,
    CRYPTO_REQUIREMENT,
    AesParams,
    _crypto_available,
    open_aes_decrypt_stage,
    open_aes_decrypt_stream,
)
from archivey.internal.streams.respawn import RespawnStream
from archivey.internal.streams.streamtools import (
    SharedSource,
    SlicingStream,
    SolidBlockReader,
    is_seekable,
    skip_forward,
)
from archivey.internal.streams.verify import build_member_verifier
from archivey.internal.unix_mode import special_file_type
from archivey.internal.volumes import (
    ConcatenatedFile,
    JoinedViews,
    discover_volume_siblings,
    next_rar_volume_name,
    rar_volume_name,
    rar_volume_number,
)
from archivey.terminal import quoted
from archivey.types import (
    EXTRA_IS_FILE_COPY,
    EXTRA_IS_JUNCTION,
    EXTRA_IS_REPARSE_POINT,
    EXTRA_RAR_EXTRACT_VERSION,
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
    MissingComponent,
    SpecialFileType,
)


def _single_disk_copy_note(program: str) -> str:
    return (
        f"Reading a member that {program} has to read, such as a compressed one, will "
        f"copy the whole archive to disk so {program} can read it."
    )


def _stream_volumes_disk_copy_note(program: str) -> str:
    return (
        f"Reading a member that {program} has to read, such as a compressed one, will "
        f"copy every volume to a temp directory so {program} can read them."
    )


def _resolve_decompressor(choice: RarDecompressor) -> RarDecompressor:
    """The program ``AUTO`` stands for: ``unrar`` when usable, else ``unar``.

    Neither found resolves to ``UNRAR``, so a data read raises the ``unrar``
    refusal it always has. Probing costs one identification run per binary per
    process, and a ``unar`` that identifies costs a second: a decode of a small RAR5
    archive written to a temp directory (``unar_rar5_probe_failure``). Each run is
    bounded by ``cli.PROBE_TIMEOUT_SECONDS``, so one ``unar`` can take up to twice
    that. The finders cache the answers.
    """
    if choice is not RarDecompressor.AUTO:
        return choice
    try:
        find_rarlab_unrar()
    except PackageNotInstalledError:
        pass
    else:
        return RarDecompressor.UNRAR
    try:
        find_unar(purpose=UNAR_PURPOSE)
    except PackageNotInstalledError:
        return RarDecompressor.UNRAR
    return RarDecompressor.UNAR


_NO_DECOMPRESSOR_NOTE = (
    "ArchiveyConfig.rar_decompressor is 'none', so no external program reads RAR "
    "member data. Reading a compressed member, an encrypted member archivey cannot "
    "decrypt itself, or a member split across volumes with a part missing, will be "
    "refused."
)


AUTO_CHOSE_UNAR_NOTE = (
    "RAR member data is read with unar because no RARLAB unrar or rar 6.0 or later was "
    "found. unar "
    "reads fewer archives than unrar, and a password is passed on its command line, "
    "where other local users can see it. Install unrar, or set "
    "ArchiveyConfig.rar_decompressor to 'unrar', to avoid both."
)


# unar 1.10 reads an old-style set as far as ``.z99`` and no further: ``lsar``
# reports 901 volumes for a longer set, and the member is then short.
_UNAR_MAX_OLD_STYLE_VOLUMES = 901

# Why a RAR cannot come from a pipe. The block headers are at the front, but the header
# walk seeks past each member's packed data (and to the RAR5 quick-open record), and
# unrar reads members from a file on disk.
_NON_SEEKABLE_REASON = (
    "the header walk seeks past each member's data, and unrar reads members from a "
    "file on disk"
)


def _gapped_volume_numbers(paths: list[Path]) -> list[int] | None:
    """Each volume's number in its set, when the names leave a gap; else ``None``.

    Discovery returns the volumes present in order (``discover_volume_siblings``).
    A set whose names number it ``1..N`` needs no numbers; one missing volume 1 or
    a middle volume does, so the parse checks each volume against its own number and
    the reader knows where the gaps are. Names that do not number the set, or not
    in increasing order, leave it as given.
    """
    numbers = [rar_volume_number(path.name) for path in paths]
    if any(number is None for number in numbers):
        return None
    known = [number for number in numbers if number is not None]
    if any(later <= earlier for earlier, later in itertools.pairwise(known)):
        return None
    if known == list(range(1, len(known) + 1)):
        return None
    return known


def _unrar_finds_exactly(
    paths: list[Path], *, is_volume: bool, old_numbering: bool
) -> bool:
    """Whether unrar, given ``paths[0]``, walks exactly ``paths`` by name.

    unrar looks for each next volume by name beside the one before, under the
    scheme volume 1's MAIN header names (``old_numbering``), not under the names
    the files carry: an old-scheme set renamed ``x.part1.rar``, ``x.part2.rar`` is
    continued from ``x.part1.r00``. So each next name is predicted from that flag,
    and must be the next given file. Past the last one, no file may answer to the
    next name, nor to the old-scheme name unrar retries when that one is missing
    (``OldSchemeTested`` in unrar's ``volume.cpp``: ``x.part2.rar`` is followed by
    ``x.part2.r00``), or unrar could read it as a further volume. Before the last
    one, a missing predicted name fails ``samefile``, so the retry cannot pick a
    given file there unnoticed. A name the prediction does not cover counts as not
    found, and the set is staged.
    """
    if not is_volume:
        # unrar never looks for another file beside a non-volume archive.
        return len(paths) == 1
    try:
        current = paths[0]
        for index in range(1, len(paths) + 1):
            name = next_rar_volume_name(current.name, old_numbering=old_numbering)
            if name is None:
                return False
            candidate = current.parent / name
            if index == len(paths):
                retry = next_rar_volume_name(current.name, old_numbering=True)
                return not os.path.lexists(candidate) and (
                    retry is not None and not os.path.lexists(current.parent / retry)
                )
            if not os.path.samefile(candidate, paths[index]):
                return False
            current = candidate
    except (OSError, ValueError):
        # ValueError: a predicted name the filesystem cannot encode (a lone
        # surrogate, the name after an extension of U+D7FF and "99", on POSIX)
        # cannot exist, so unrar cannot find it either.
        return False
    return True


def _data_is_in_one_place(info: RarMemberInfo) -> bool:
    """Whether the member's packed data is one run starting at ``data_offset``.

    A part of a split member has a split flag set. Once the parser merges the parts,
    the member keeps the first part's ``data_offset`` and the total packed size, and
    ``spanned_volumes`` marks it: a read from ``data_offset`` would run past the first
    volume's part into the next header.
    """
    return not (info.split_before or info.split_after or info.spanned_volumes)


def _data_is_reachable(info: RarMemberInfo) -> bool:
    """Whether every packed byte of the member can be sliced out of the sources.

    Either one run (:func:`_data_is_in_one_place`) or every part of a member merged
    across volumes: ``data_parts``, with no part expected before the first or after
    the last.
    """
    return _data_is_in_one_place(info) or (
        bool(info.data_parts) and not info.split_before and not info.split_after
    )


def _link_file(src: Path, dest: Path) -> None:
    """Make ``dest`` name ``src``'s bytes without copying them: a symlink, else a
    hard link. Raises ``OSError`` when neither is possible."""
    try:
        dest.symlink_to(src)
    except (OSError, NotImplementedError):
        os.link(src, dest)


def _stream_copy_refused_note(program: str, reason: str) -> str:
    return (
        f"Reading a member that {program} has to read, such as a compressed one, will "
        f"be refused: {program} reads only files, and {reason}. Members archivey "
        f"reads without {program}, such as stored, unencrypted ones, can still be "
        f"read."
    )


def _rar_stream_copy_cost_notes(
    source: ArchiveSource,
    limits: SpoolLimits,
    copy_size: int | None,
    program: str,
) -> tuple[str, ...]:
    """Open-time caveat when member data needs a filesystem path for the decompressor.

    A file source, or a joined set of files, gets no note here; the one file source that
    is copied, a prefixed file read with ``unar``, is known only after the parse and is
    noted then (see ``RarReader.__init__``). Both stream shapes get the same predictive
    caveat: the copy happens on the first read the decompressor has to serve, not at
    open. Keyed from the source's facts so a mixed set, whose file parts
    ``_materialize_stream_volumes`` copies alongside the streams, is labelled as the
    streams it contains. ``program`` names the decompressor in the note.

    The caveat names the spool limit, so the caller reads the worst case at open.
    When the limit already decides the outcome — ``max_bytes=0``, or ``copy_size``
    (the copy's size, when known at open) over the limit — it says the read will be
    refused rather than promise a copy that cannot happen.
    """
    if source.path is not None:
        return ()
    if source.joined is not None:
        if source.volume_paths:
            return ()
        note = _stream_volumes_disk_copy_note(program)
        what = "every volume"
    else:
        note = _single_disk_copy_note(program)
        what = "the archive"
    return _bounded_copy_notes(
        note, what, "a stream source", limits, copy_size, program
    )


def _bounded_copy_notes(
    note: str,
    what: str,
    source_kind: str,
    limits: SpoolLimits,
    copy_size: int | None,
    program: str,
) -> tuple[str, ...]:
    """``note`` with the spool limit in force, or the refusal the limit decides at open.

    ``what`` names what is copied and ``source_kind`` what it is copied from, in the
    refusal's wording.
    """
    limit = limits.max_bytes
    if limit is None:
        return (f"{note} The copy has no size limit (SpoolLimits.max_bytes=None).",)
    if limit == 0:
        reason = f"SpoolLimits.max_bytes=0 allows no copy of {source_kind}"
        return (_stream_copy_refused_note(program, reason),)
    if copy_size is not None and copy_size > limit:
        reason = (
            f"a copy of {what} would be {copy_size} bytes, over "
            f"SpoolLimits.max_bytes={limit}"
        )
        return (_stream_copy_refused_note(program, reason),)
    return (
        (
            f"{note} An archive over SpoolLimits.max_bytes={limit} is refused instead "
            f"of copied."
        ),
    )


# rarfile / RAR host_os values (parser maps RAR5 Windows→2, Unix→3).
_RAR_HOST_OS_TO_CREATE_SYSTEM: dict[int, CreateSystem] = {
    0: CreateSystem.FAT,
    1: CreateSystem.OS2_HPFS,
    2: CreateSystem.WINDOWS_NTFS,
    3: CreateSystem.UNIX,
    4: CreateSystem.MACINTOSH,
    5: CreateSystem.BEOS,
}

# RAR host_os values used directly below; the same numbers key
# _RAR_HOST_OS_TO_CREATE_SYSTEM above (the parser maps RAR5 Windows->2, Unix->3).
_RAR_HOST_OS_WIN32 = 2
_RAR_HOST_OS_UNIX = 3
# Hosts whose creation-time slot is a birth time: MS-DOS, OS/2, Win32, Mac OS, BeOS.
# Listed, not derived from the map above: a host added there is not a birth-time host
# until someone says so, since its slot would otherwise flow into ``created``.
_RAR_BIRTH_TIME_HOSTS = frozenset({0, 1, _RAR_HOST_OS_WIN32, 4, 5})

# The extract version of a RAR3/4 member whose data is AES-128 encrypted (RAR 2.9 and
# later). Earlier versions used RAR 2.0's own cipher, which archivey does not decrypt.
_RAR3_AES_EXTRACT_VERSION = 29
_RAR_METHOD_MAX = 0x35  # RAR M5
_RAR_ENCDATA_FLAG_TWEAKED_CHECKSUMS = 0x02
_RAR5_XREDIR_WINDOWS_JUNCTION = 3


# Read step for the confirmation pass over a cut-short member's stored bytes
# (``RarReader._confirm_unsettled_plaintext``). Matches the verifier's own drain
# step; the pass is bounded by the member, which is bounded by the source.
_CONFIRM_CHUNK_BYTES = 64 * 1024

# Shared CompressionMethod tuples — many-member listing hits the same method byte
# (typically store / M1–M5) thousands of times; avoid per-member allocations.
# M0 is STORED; M1–M5 are CompressionAlgorithm.RAR with level = method - 0x30.
_STORED_COMPRESSION: tuple[CompressionMethod, ...] = (
    CompressionMethod(algo=CompressionAlgorithm.STORED),
)
_COMPRESSION_BY_METHOD: dict[int, tuple[CompressionMethod, ...]] = {
    _RAR3_M0: _STORED_COMPRESSION,
    **{
        method: (
            CompressionMethod(
                algo=CompressionAlgorithm.RAR,
                level=method - _RAR3_M0,
            ),
        )
        for method in range(_RAR3_M0 + 1, _RAR_METHOD_MAX + 1)
    },
}


class _DictionaryCost(NamedTuple):
    """What one read costs in dictionary memory, and which header the cost came from.

    ``count`` is compared against ``DecoderLimits.max_decoder_memory``. ``declared``
    is the dictionary behind ``count``, and ``declarer`` the archive index of the
    member whose header declared it. ``declarer`` is -1, and ``declared`` 0, when no
    header is behind the count: a member that uses no dictionary outside a solid
    ``unrar`` walk, or one ahead of every member that does. A count of 0 does not
    imply -1 (an empty compressed member is its own declarer). Both are for the
    refusal message: under ``unrar`` the count can be smaller than ``declared``, and
    in a solid archive, a shared mask or a pass the declarer can be another member.
    Compare two costs with :func:`_larger_cost`, not ``max``.
    """

    count: int
    declared: int
    declarer: int


_NO_DICTIONARY = _DictionaryCost(0, 0, -1)


def _larger_cost(a: _DictionaryCost, b: _DictionaryCost) -> _DictionaryCost:
    """The larger count, with the declaration behind that count."""
    return b if b.count > a.count else a


def _unrar_dictionary_costs(archive: RarArchive) -> list[_DictionaryCost]:
    """The dictionary bytes RARLAB ``unrar`` can touch to decode each member, in order.

    Measured with ``unrar`` 7.00 (``dev-docs/formats/rar.md`` §7). ``unrar`` sizes a
    nonsolid member's window to the smaller of its declared dictionary and its
    unpacked size, and the pages fill only as output is written. A 64 KiB member
    that declares 4 GiB stays near 8 MiB resident. In a solid archive the window
    only grows: ``unrar`` keeps the largest dictionary declared by any member it
    has decoded. It decodes every earlier member, across solid streams too. A
    member that starts a new stream still paid about 300 MiB for the 1 GiB window
    and 300 MB of data ahead of it. So the count for a solid member is the smaller
    of the largest dictionary declared up to and including it and the unpacked
    bytes of those members.

    The unpacked size is a header value, as the dictionary is. When it is too
    small, the reader's own size check stops reading at that size, and ``unrar``
    then blocks on the full pipe. So the bytes written, and so the pages touched,
    stay near the declared size. A stored member, a directory and a redirect use
    no dictionary (:func:`uses_no_dictionary`) and add nothing to the window or
    to the decoded bytes. In a nonsolid archive they count 0. In a solid one they
    count the window built ahead of them, because ``unrar`` decodes every earlier
    member to reach them: measured, a stored 64 KiB member behind a 300 MB member
    declaring 1 GiB took 314 MiB resident. The walk keys on the archive's MAIN
    solid flag, as ``unrar`` does: with it set and the member's own solid flag
    clear, the read still took 314 MiB; with it clear and the member's flag set,
    ``unrar`` decoded nothing ahead (47 MiB, the parent's own). ``rar -s`` writes
    both flags on every member after the first. The reader slices a stored member
    itself whatever its solid flag, unless it is encrypted or its encryption is
    unsettled: such a member reaches ``unrar`` by name and is charged its entry
    here. Any other stored member reaches ``unrar`` only inside a solid pass.
    A RAR3 symlink does count: its target is compressed data. That is why this walk
    does not use ``is_payload_file()`` as :meth:`RarReader._solid_prefix` does.
    """
    costs: list[_DictionaryCost] = []
    window = decoded = 0
    declarer = -1
    for index, info in enumerate(archive.members):
        if not archive.is_solid:
            costs.append(
                _NO_DICTIONARY
                if uses_no_dictionary(info)
                else _DictionaryCost(
                    min(info.dictionary_size, info.file_size),
                    info.dictionary_size,
                    index,
                )
            )
            continue
        if not uses_no_dictionary(info):
            if info.dictionary_size > window or declarer < 0:
                window, declarer = info.dictionary_size, index
            decoded += info.file_size
        costs.append(_DictionaryCost(min(window, decoded), window, declarer))
    return costs


def _member_stream_size(member: ArchiveMember) -> int:
    """Unpacked size for a RAR payload member.

    RAR headers always store ``file_size`` as ``int``, and every payload member
    (``RarMemberInfo.is_payload_file()``) lists it as ``size``. A non-payload member
    may not: an unknown RAR5 redirect is ``OTHER`` with no ``size``, so callers filter
    on ``is_payload_file()`` before summing. ``ArchiveMember.size`` is optional because
    other formats have streaming entries; folding ``None`` into ``0`` here would treat
    "unknown length" as "empty". A payload member without a declared size is a
    programming error.
    """
    size = member.size
    if size is None:
        raise AssertionError("RAR payload members always declare an unpacked size")
    return size


def _presented_filename(info: RarMemberInfo) -> str:
    """Archive path, or WinRAR/``unrar`` ``path;n`` for file-version history."""
    if info.is_file_version_history():
        assert info.file_version is not None
        return f"{info.filename};{info.file_version}"
    return info.filename


def _password_as_str(password: bytes | str | None) -> str | None:
    if password is None or password == b"" or password == "":
        return None
    if isinstance(password, bytes):
        return password.decode("utf-8", errors="surrogateescape")
    return password


def _compression_for(info: RarMemberInfo) -> tuple[CompressionMethod, ...]:
    cached = _COMPRESSION_BY_METHOD.get(info.compress_type)
    if cached is not None:
        return cached
    # Outside M0–M5: UNKNOWN with no level. ``level`` is the M1–M5 method-byte
    # offset (1–5), not ``method - 0x30`` for an arbitrary byte.
    return (CompressionMethod(algo=CompressionAlgorithm.UNKNOWN),)


_UNDECODABLE_WITH_CANDIDATE = (
    "This RAR member did not decode with the password: it may be wrong, or the "
    "member may be damaged"
)
_UNDECODABLE_WITH_ANY_CANDIDATE = (
    "This RAR member did not decode with any of the passwords: they may all be "
    "wrong, or the member may be damaged"
)


def _undecodable_with_candidate() -> EncryptionError:
    """The failure of a RAR3/4 candidate judged by decoding, which cannot tell why.

    RAR3/4 has no password check, so a wrong key and damage the right key decodes
    into look the same: garbage the decoder refuses, output that ends early, or a CRC
    mismatch. Not marked as a wrong password, so exhaustion does not claim one.
    """
    return EncryptionError(_UNDECODABLE_WITH_CANDIDATE)


def _crc_is_tweaked(info: RarMemberInfo) -> bool:
    enc = info.file_encryption
    if enc is None:
        return False
    return bool(enc.flags & _RAR_ENCDATA_FLAG_TWEAKED_CHECKSUMS)


def _member_hashes(info: RarMemberInfo) -> dict[HashAlgorithm, bytes]:
    """Plaintext digests safe for member verification without a HashKey.

    When ``RAR5_XENC_TWEAKED`` / ``HASHMAC`` (0x02) is set, the stored CRC32 and
    BLAKE2sp are key-tweaked (``ConvertHashToMAC``) and must not be compared to the
    plaintext digest. Those values are stashed in ``member.extra`` and verified via
    forward-transform when a password is available (see
    :meth:`RarReader._tweaked_verify_spec`).

    A **RAR5 redirect** member (symlink, hard link, file copy) surfaces no digest at all.
    It keeps its target in a header field and stores *no data stream*, so its CRC32 field
    covers zero bytes — and ``crc32(b"") == 0``, which RARLAB duly writes. That value is
    correct about nothing: every RAR5 symlink in existence carries ``0x00000000``, so it
    neither describes the member (``size`` is the target's length while the digest covers
    0 bytes) nor distinguishes one link from another. Reporting it would make
    ``member.hashes`` mean something different in RAR than in every other format, against
    the no-surprises rule — and the founding "hashes without decompression" use case
    reads exactly this field.

    **RAR4 is deliberately unaffected**, and the difference is why this keys on the
    redirect rather than on the member type: RAR3/4 store a symlink's target *as the
    member's data*, so ``compress_size`` is the target length and the CRC32 is a real
    digest of it — the same thing ZIP and 7z record. Dropping that would lose a
    meaningful value.
    """
    hashes: dict[HashAlgorithm, bytes] = {}
    if info.file_redir is not None:
        return hashes
    tweaked = _crc_is_tweaked(info)
    if info.crc32 is not None and not tweaked:
        hashes[HashAlgorithm.CRC32] = crc32_digest(info.crc32)
    if info.blake2sp_hash is not None and not tweaked:
        hashes[HashAlgorithm.BLAKE2SP] = info.blake2sp_hash
    return hashes


def _rar_special_file_type(info: RarMemberInfo) -> SpecialFileType | None:
    """The stored special type (device, FIFO, socket) of a Unix-host entry, or ``None``."""
    if info.host_os != _RAR_HOST_OS_UNIX or info.mode is None:
        return None
    return special_file_type(info.mode)


def _rar_member_extra_and_link(
    info: RarMemberInfo,
) -> tuple[MemberExtra, str | None]:
    """Build ``ArchiveMember.extra`` and the link target (or a file copy's source)."""
    extra = MemberExtra()
    link_target: str | None = None
    special = _rar_special_file_type(info)
    if special is not None:
        # Whatever type ``_member_type`` gives the entry (a file copy is a FILE even
        # though it carries a redirect), the key records what the mode said (DR-25).
        extra[EXTRA_SPECIAL_FILE_TYPE] = special
    if info.file_redir is not None and not info.has_unknown_redirect():
        link_target = _rar5_redirect_target(info.file_redir)
        if info.is_file_copy():
            extra[EXTRA_IS_FILE_COPY] = True
        if info.file_redir[0] in _RAR5_XREDIR_REPARSE_POINTS:
            extra[EXTRA_IS_REPARSE_POINT] = True
        if info.file_redir[0] == _RAR5_XREDIR_WINDOWS_JUNCTION:
            extra[EXTRA_IS_JUNCTION] = True
    # Pure; re-derived here rather than threaded through the ``_to_member`` split
    # (``is_current`` and the tweaked-digest diagnostic each call the same
    # predicates independently).
    if info.is_file_version_history():
        assert info.file_version is not None
        extra["rar.file_version"] = info.file_version
    if info.extract_version is not None:
        extra[EXTRA_RAR_EXTRACT_VERSION] = info.extract_version
    if _crc_is_tweaked(info):
        # Stored digests are key-tweaked; keep them out of ``hashes`` (see
        # ``_member_hashes``) but expose the raw values for callers / forward-verify.
        if info.crc32 is not None:
            extra["rar.tweaked_crc32"] = info.crc32
        if info.blake2sp_hash is not None:
            extra["rar.tweaked_blake2sp"] = info.blake2sp_hash
    return extra, link_target


def _rar_created(info: RarMemberInfo) -> datetime | None:
    """The member's birth time: the creation slot, when ``host_os`` stores one there.

    A Unix writer (RAR3 Unix; the parser maps RAR5 Unix to 3) fills the slot from
    st_ctime, which ``created`` never holds. Win32 and the other RAR3 hosts store a
    birth time. An unknown ``host_os`` says neither, so it gets None too.
    """
    if info.host_os in _RAR_BIRTH_TIME_HOSTS:
        return info.ctime
    return None


def _rar_ctime(info: RarMemberInfo) -> datetime | None:
    """The creation slot when it is not ``created``: a Unix or unknown ``host_os``."""
    if info.host_os in _RAR_BIRTH_TIME_HOSTS:
        return None
    return info.ctime


def _timestamp_field_name(info: RarMemberInfo, slot: str) -> str:
    """The ``ArchiveMember`` field a parser time slot would have filled.

    The creation slot is ``created`` or ``ctime`` by ``host_os``, as in
    :func:`_rar_created`. That field may still hold a value from another record, such
    as a later valid RAR5 time record.
    """
    if slot == "ctime":
        return "created" if info.host_os in _RAR_BIRTH_TIME_HOSTS else "ctime"
    return {"mtime": "modified", "atime": "accessed"}[slot]


def _tweaked_hash_key(
    enc: RarEncryptionInfo, password: str, kdf_cache: RarKdfCache
) -> bytes | None:
    """Return HashKey for ``password``, or ``None`` when the password is provably wrong.

    A present PswCheck that rejects ``password`` returns ``None`` so callers skip
    forward-transform verification (a wrong HashKey would false-``CorruptionError``
    good plaintext). When the check is absent or unusable, the HashKey is still
    derived — matching the password ``unrar`` will receive.
    """
    if enc.check_value is not None:
        try:
            _check_rar5_password(
                enc.check_value,
                enc.kdf_count,
                enc.salt,
                password,
                kdf_cache=kdf_cache,
            )
        except EncryptionError:
            return None
    return rar5_hash_key(password, enc.salt, enc.kdf_count, kdf_cache=kdf_cache)


def _psw_check_usable(enc: RarEncryptionInfo) -> bool:
    """Whether ``enc`` carries a PswCheck that can tell a right password from a wrong one.

    Mirrors the shape test :func:`rar_parser._check_rar5_password` applies before it
    derives a key: twelve bytes whose last four are the SHA-256 prefix of the first
    eight. RAR4 records and a damaged check have none, and a candidate cannot be
    judged before ``unrar`` runs. It does not mirror that function's ``kdf_count``
    bound: a usable check with an out-of-range cost still reaches the check, which
    raises ``CorruptionError`` for the member rather than deriving at that cost.
    """
    check = enc.check_value
    return (
        check is not None
        and len(check) == 12
        and hashlib.sha256(check[:8]).digest()[:4] == check[8:]
    )


class _UnrarCannotAddress(Exception):
    """``unrar`` cannot address a member by name; ``error`` is the refusal to raise.

    Raised by :meth:`RarReader._unrar_spawner_by_name` so that a read under ``AUTO``
    can hand the member to ``unar``, which names entries by index, before it raises.
    """

    def __init__(self, error: UnsupportedFeatureError) -> None:
        super().__init__(error)
        self.error = error


@dataclass(slots=True)
class _UnrarNames:
    """Every payload member's name as ``unrar`` reads it, to size an ``-n`` skip.

    Built once per reader, the first time a member is read through ``unrar``, so
    each later read looks its mask up rather than walking every member.
    """

    # By position in the member list: the name ``unrar_member_view`` gives, or
    # ``None`` for a member that is not a payload file or whose name this host
    # cannot reproduce.
    views: list[str | None]
    # ``id(member)`` to its position.
    positions: dict[int, int]
    # ``unrar_selection_keys`` of each known view, to its payload positions.
    by_key: dict[str, list[int]]
    # Payload positions whose view is ``None``, ascending.
    unknown: list[int]


@contextmanager
def _close_on_error(owned: BinaryIO) -> Generator[None, None, None]:
    """Close ``owned`` if the block raises.

    ``owned`` is the stream built before the block; what the block builds on top of it
    is not closed, so wrap each new outermost stream in its own block.
    """
    try:
        yield
    except BaseException:
        owned.close()
        raise


class _UnrarOwnedStream(ProcessOutputStream):
    """Stdout wrapper that terminates the owning ``unrar`` process on close.

    On close it maps ``unrar``'s exit code (RARLAB) to a typed error so a corrupt,
    truncated, or wrong-password member surfaces honestly instead of a silent short
    read. When *we* terminate the process (early close / teardown) the return code
    is negative and no error is raised. A signal that ends ``unrar`` after it closed
    its output came from elsewhere (or was a crash), and maps to
    ``ResourceLimitError`` / ``ReadError`` (:func:`signal_exit_error`), never to a
    truncation the digest check would otherwise report. ``named_member``
    distinguishes a per-member open (``-n`` mask) — where "no files matched" (code 10)
    means the member could not be read — from the solid ALL-pipe, where an empty match
    is not an error.

    ``has_verifiable_hash`` suppresses the corruption/no-match mapping (codes 2/3/10):
    when the member carries a CRC32/BLAKE2sp that archivey verifies itself, that check
    is authoritative, and some legacy archives (e.g. RAR 1.5) make ``unrar`` report a
    spurious CRC error (exit 3) while emitting correct, verified data. A wrong-password
    exit (11) always maps — it means no usable data regardless of any stored hash.

    RAR4 often reports exit 3 (CRC) instead of 11 for a missing/wrong password, with
    empty stdout. After verify's short-before-digest preference that would otherwise
    surface only as ``TruncatedError`` (0 of N) while ``has_verifiable_hash`` suppresses
    the CRC exit. When the member is encrypted and we read zero plaintext bytes, map
    exit 2/3 to ``EncryptionError``.

    Exit mapping runs on the **empty/completing read** when the process has already
    exited (ADR 0014 eager-finalize parity), so ``archive.read()`` / a completing
    ``read()`` see ``EncryptionError`` on the read path rather than only from
    ``close()``. ``close()`` still maps if the empty-read path never ran (early stop).
    """

    def __init__(
        self,
        stdout: BinaryIO,
        proc: subprocess.Popen[bytes],
        *,
        named_member: bool = False,
        has_verifiable_hash: bool = False,
        encrypted: bool = False,
    ) -> None:
        self._named_member = named_member
        self._has_verifiable_hash = has_verifiable_hash
        self._encrypted = encrypted
        self._saw_eof = False
        super().__init__(stdout, proc)

    def _at_eof(self) -> None:
        self._saw_eof = True
        super()._at_eof()

    def tell(self, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        # The inner is a pipe, whose tell() raises ESPIPE. Every byte goes through
        # read() (readinto_passthrough is off), so the count is the position.
        return self._bytes_read

    def _raise_for_returncode(self, rc: int) -> None:
        """Map an unrar exit code to an archivey error, or return quietly."""
        # RARLAB unrar exit codes: 11 bad password, 3 CRC/corrupt data, 2 fatal
        # error, 10 no files matched. Codes 0 (success) and 1 (warning) pass.
        if rc < 0:
            # A signal. Before end of file it is archivey's doing: close stopped a
            # program that was still writing, or the pipe it closed ended it. After
            # end of file something else ended unrar (the out-of-memory killer, an
            # operator) or it crashed; either way the pipe was cut short, and the
            # digest check below would call that a truncated archive.
            if self._saw_eof:
                raise signal_exit_error("unrar", rc)
            return
        if rc == 255 and self._saw_eof:
            # ``USER_BREAK``: unrar catches SIGINT and SIGTERM and exits 255, so a
            # stop from outside arrives as this code rather than as a signal.
            raise ReadError(
                "unrar was stopped from outside (exit 255, user break) while reading "
                "data; the archive may be valid, so try reading it again."
            )
        if rc == 11:
            raise EncryptionError("Incorrect RAR password or encrypted member")
        # RAR4 wrong/missing password: often exit 3 + empty stdout, not exit 11.
        # Ambiguity: a genuinely corrupt (not password-related) encrypted member that
        # also yields empty stdout + exit 2/3 is mislabeled EncryptionError here. We
        # accept that bias — for an encrypted member producing zero plaintext, "wrong
        # password" is the far more common cause and the actionable one (a caller
        # cannot distinguish, or make progress, without the correct password anyway).
        # unrar exposes no reliable signal to separate the two; narrow this if one
        # appears.
        if self._encrypted and self._bytes_read == 0 and rc in (2, 3):
            raise EncryptionError("Incorrect RAR password or encrypted member")
        if self._has_verifiable_hash:
            # archivey verifies this member's CRC32/BLAKE2sp itself; that check is
            # authoritative, so ignore unrar's (sometimes spurious) corruption codes.
            return
        if rc in (2, 3):
            raise CorruptionError(
                f"unrar reported a fatal or CRC error (exit {rc}) reading member data"
            )
        if rc == 10 and self._named_member:
            raise CorruptionError(
                "unrar found no matching member (exit 10); the member could not be read"
            )


def _bounded_member_pipe(inner: BinaryIO, *, prefix: int, size: int) -> BinaryIO:
    """Own an ``unrar`` pipe, skip a glob-match prefix, then EOF at ``size``.

    ``unrar -n./name-with-wildcards`` concatenates every matching member with no
    headers. The parsed member list tells us how many unpacked bytes sit before
    the target; after that we must stop, or the fused overrun probe would see the
    next match as extra payload.

    The skip is eager at construction. A seekable wrapper respawns lazily on the
    next ``read()``, so this factory — and the skip — runs then, not inside
    ``seek()``. ``seek(0, SEEK_END); seek(0)`` before any read still costs
    nothing: ``RespawnStream._inner_pos`` stays 0 and no new pipe is built.

    The bound itself is a non-seekable :class:`SlicingStream` (same shape as the
    7z folder-pipe member slice). ``SharedView`` is the locked re-seek door and
    requires a seekable source; the inner here is a subprocess pipe.
    """
    try:
        assert not is_seekable(inner), (
            "bounded member pipe requires a non-seekable unrar stdout"
        )
        if prefix:
            skip_forward(inner, prefix)
        return SlicingStream(inner, length=size, owns_inner=True)
    except EOFError as exc:
        inner.close()
        raise TruncatedError(
            "unrar pipe ended before the requested glob-matched member"
        ) from exc
    except BaseException:
        inner.close()
        raise


def _open_unar_blob_pipe(path: Path) -> tuple[subprocess.Popen[bytes], BinaryIO]:
    """``unar`` for the one-entry archive :func:`decompress_rar3_blob` builds."""
    return open_unar_stdout(path, [0], purpose=UNAR_PURPOSE)


# What a service header's payload would have answered, for the diagnostic that
# reports one whose walk stopped: the payload is then refused, because a header
# nobody finished reading may be hiding the record that says it is ciphertext.
_SERVICE_PAYLOAD_LOST = {
    "CMT": "the archive comment",
    "QO": "the quick-open index",
}


# A member with no owner record: all four owner fields ``None``.
_NO_OWNER = RarOwner(None, None, None, None)


class RarReader(BaseArchiveReader):
    """Reads RAR archives: native metadata parse + RARLAB ``unrar`` for data."""

    # The header walk (listing_cost REQUIRES_SCANNING) runs inside open_archive, so the
    # table exists before members() and the report peek can return it.
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
        *,
        volume_count: int = 1,
        start_offset: int = 0,
    ) -> None:
        super().__init__(
            ArchiveFormat.RAR,
            streaming,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
        # Applied to RAR 1.5-4 names stored as 8-bit bytes; RAR5 names are UTF-8.
        self._encoding = encoding
        self._source = source
        self._passwords = passwords or _PasswordCandidates()
        # The candidate each RAR5 encryption record's PswCheck accepted, keyed by the
        # record's salt, KDF cost and check. RAR writes one salt per archiving run,
        # so this is usually one derivation per archive rather than one per member.
        self._checked_passwords: dict[tuple[bytes, int, bytes], bytes] = {}
        # Every RAR key this reader derives: the header parse, each PswCheck and each
        # tweaked-digest HashKey. An ``-hp`` archive's members repeat the header's
        # salt, so their PswCheck is the header's own derivation.
        kdf_budget = KeyDerivationBudget(self._config.decoder_limits)
        self._usage.watch_key_derivation(kdf_budget)
        self._kdf_cache = RarKdfCache(budget=kdf_budget)
        # The first member whose PswCheck can judge a candidate, found once on first
        # use; ``False`` until looked for, ``None`` when there is none.
        self._archive_check_member: ArchiveMember | None | Literal[False] = False
        # Likewise :meth:`_unchecked_reference_member`, with the same sentinel.
        self._unchecked_reference: ArchiveMember | None | Literal[False] = False
        # The password a RAR3/4 candidate list resolved to, by ``id`` of the member it
        # was judged on (:meth:`_unchecked_data_password`), and the members it was
        # confirmed against, whose read then needs no unverified-read report.
        self._unchecked_passwords: dict[int, bytes] = {}
        self._unchecked_confirmed: set[int] = set()
        self._unrar_names_cache: _UnrarNames | None = None
        self._volume_count = max(source.volume_count, volume_count)
        self._temp_path: Path | None = None
        self._temp_dir: Path | None = None
        self._owned_concat: ConcatenatedFile | None = None
        self._archive_path: Path | None = None
        # unar's private directory (``_unar_archive_path``) and the path in it that
        # unar is handed. The directory is removed on close.
        self._unar_dir: Path | None = None
        self._unar_path: Path | None = None
        # The unar policy and dictionary costs for members unrar cannot address,
        # built on the first such read under AUTO (:meth:`_unar_for_unaddressable`).
        # ``False`` until then, as for ``_archive_check_member``; ``None`` once no
        # accepted unar was found.
        self._unar_fallback: (
            tuple[UnarRarPolicy, dict[int, _DictionaryCost]] | None | Literal[False]
        ) = False
        self._unar_fallback_lock = threading.Lock()
        # Guards the check-then-write in ``_ensure_archive_path``: two concurrent
        # compressed opens used to both see ``None`` and both copy, and close
        # only removed the winner.
        self._materialize_lock = threading.Lock()
        # The one spool allowance for this reader's copies, made on the first copy
        # (``_spool_budget``) and kept, so a refused copy is not retried.
        self._spool: SpoolBudget | None = None
        self._volume_paths: list[Path] = []
        # Each discovered volume's 1-based number in its set, read from its name,
        # when the set has a gap: volume 1 missing, or one in the middle. ``None``
        # for a set numbered 1..N, which is every set but those. See
        # ``_segment_start``.
        self._volume_numbers: list[int] | None = None
        # A lone path whose name numbers it as a later volume (``x.part3.rar``).
        self._lone_volume_number: int | None = None
        # Stream volumes, kept unmaterialized until unrar actually needs files.
        self._stream_volume_items: list[Path | BinaryIO] = []
        # Volume files (explicit or discovered) that unrar would not find by name from
        # the first one (_choose_unrar_volume_paths), linked into a temp directory on
        # the first read that needs it.
        self._stage_volume_paths = False
        self._volume0_parse_origin = 0  # set after sibling discovery when origin > 0
        # The data program, with ``AUTO`` resolved once for the life of this reader.
        self._decompressor = _resolve_decompressor(self._config.rar_decompressor)

        if not source.seekable():
            raise StreamNotSeekableError(
                f"RAR archives require a seekable source: {_NON_SEEKABLE_REASON}.",
                archive_name=archive_name,
                source_format=ArchiveFormat.RAR,
            )

        # Where the RAR proper starts inside ``source``: detection's payload_offset
        # for a self-extracting file, 0 otherwise. The parser scan skips invalid
        # decoys the same way detection does (then falls back to the first
        # identified candidate if none validate), but pinning volume 1 to that
        # origin still avoids a second scan, and still matters for a CRC-valid
        # decoy that would win as first-VALID. ConcatenatedFile + parser ``tell()``
        # offsets are file-absolute (each volume contributes its full size, stub
        # included), so stored reads must not also shift by ``_origin`` — that is
        # why a discovered multi-volume set zeroes it after copying it to
        # ``_volume0_parse_origin``.
        self._origin = start_offset
        self._shared = self._open_shared_source(source)
        if self._origin and self._volume_set_size() > 1:
            self._volume0_parse_origin = self._origin
            self._origin = 0
        # Open-time caveat from source shape, not from later materialization
        # (CostReceipt is a static snapshot; see access-mode-and-cost). With no
        # program nothing is ever copied, so there is no copy to warn about.
        self._cost_notes = (
            ()
            if self._decompressor is RarDecompressor.NONE
            else _rar_stream_copy_cost_notes(
                source,
                self._config.spool_limits,
                self._spool_copy_size(),
                self._decompressor_name(),
            )
        )
        if (
            self._config.rar_decompressor is RarDecompressor.AUTO
            and self._decompressor is RarDecompressor.UNAR
        ):
            self._cost_notes = (AUTO_CHOSE_UNAR_NOTE, *self._cost_notes)
        self._archive, self._unrar_password = self._parse_archive()
        self._choose_unrar_volume_paths()
        # unrar only consults the password when something is actually encrypted, so
        # a spawn for a plain archive is not given one: nothing is decrypted with it,
        # and handing a secret to a subprocess that ignores it buys nothing. This is
        # also what ``get_archive_info`` reports as ``is_encrypted``: one predicate,
        # so what the caller is told and what reaches the subprocess cannot drift.
        #
        # ``info.is_encrypted`` here is the definite answer, not the fail-closed one
        # the member is presented with: a member whose header was cut short says
        # nothing about the archive around it. Reading the presented flag instead
        # would let one damaged member report a wholly plaintext archive as
        # encrypted, hand the caller's password to every ``unrar`` spawn for it, and
        # relabel an ordinary empty read as a wrong password.
        self._archive_has_encryption = self._archive.has_header_encryption or any(
            info.is_encrypted for info in self._archive.members
        )
        # Members a solid decode reaches only through an encrypted (or possibly
        # encrypted) one: everything after the first such member. Read by
        # ``_member_needs_password``.
        self._behind_encryption: set[int] = set()
        if self._archive.is_solid:
            seen_encrypted = False
            for info in self._archive.members:
                if seen_encrypted:
                    self._behind_encryption.add(id(info))
                seen_encrypted = (
                    seen_encrypted or info.is_encrypted or info.encryption_unknown
                )
        if self._in_set:
            self._volume_count = max(self._volume_count, self._volume_set_size() or 1)
        # Each compressed member's solid run under unar (``_unar_solid_runs``).
        self._unar_runs: dict[int, SolidRun] | None = None
        # Built once from the parse, and only when the caller chose unar: it holds the
        # refusals and the pipe layout, and none of it applies to unrar.
        self._unar_policy: UnarRarPolicy | None = (
            UnarRarPolicy(self._archive)
            if self._decompressor is RarDecompressor.UNAR
            else None
        )
        # Members an unknown-version member ahead of them keeps from being decoded:
        # by any program in its solid stream, by ``unrar`` in the rest of a solid
        # archive. Keyed by ``id`` of the parsed member.
        self._solid_after_unknown = solid_after_unknown_compression(self._archive)
        if (
            self._unar_policy is not None
            and source.path is not None
            and self._volume_set_size() <= 1
            and self._origin + self._archive.sfx_offset > 0
        ):
            # ``_unar_archive_path`` copies a prefixed file from where the RAR starts,
            # within the spool limit; the size is known, so the note can say whether
            # the copy will be refused.
            self._cost_notes = (
                *self._cost_notes,
                *_bounded_copy_notes(
                    _single_disk_copy_note("unar"),
                    "the archive",
                    "a prefixed archive for unar",
                    self._config.spool_limits,
                    self._unar_copy_size(),
                    "unar",
                ),
            )
        self._check_header_metadata_budget()
        self._archive.comment = self._resolve_rar3_comment(self._archive.comment)
        for info in self._archive.members:
            info.comment = self._resolve_rar3_comment(info.comment)
        self._members = [
            self._to_member(info, index)
            for index, info in enumerate(self._archive.members)
        ]
        self._resolve_file_copies()
        # Not ``not _can_direct_read``: a member whose header stopped before its
        # encryption record can still be served by ``_confirm_unsettled_plaintext``,
        # and a file copy's refusal comes from its source, which is in this walk too.
        if self._decompressor is RarDecompressor.NONE and any(
            member.is_file
            and not info.is_file_copy()
            and (
                not self._is_directly_sliceable(info)
                or (
                    info.is_encrypted
                    and not (self._natively_decryptable(info) and _crypto_available())
                )
            )
            for member, info in zip(self._members, self._archive.members, strict=True)
        ):
            self._cost_notes = (*self._cost_notes, _NO_DECOMPRESSOR_NOTE)
        # The dictionary memory each member's read costs under the program that will
        # run it, keyed by ``id(member)``, checked against
        # ``DecoderLimits.max_decoder_memory`` before that program starts. The two
        # programs allocate differently, so each has a rule. Under ``NONE`` nothing runs
        # and nothing consults this.
        if self._unar_policy is not None:
            self._dictionary_costs = self._unar_dictionary_cost_map()
        else:
            self._dictionary_costs = {
                id(member): cost
                for member, cost in zip(
                    self._members, _unrar_dictionary_costs(self._archive), strict=True
                )
            }
        # SERVICE headers (``CMT``, ``QO``) are not members, so the walk above never
        # reaches them, and a damaged one would otherwise report nothing under any
        # policy.
        self._emit_service_header_diagnostics()

    def _open_shared_source(self, source: ArchiveSource) -> SharedSource:
        """Build SharedSource, discovering/materializing volumes as needed."""
        wrap = self._seek_handle_wrapper()
        path = source.path
        if path is not None:
            siblings = discover_volume_siblings(path)
            if siblings is not None and len(siblings) > 1:
                # The source reads volume 1 only; ``unrar`` walks the set on disk, and
                # the header walk reads across it through a join this reader builds.
                # That join is the one source-level object a backend still opens and
                # closes itself, because the boundary hands RAR volume 1's path.
                self._volume_paths = siblings
                self._volume_count = len(siblings)
                self._archive_path = siblings[0]
                self._volume_numbers = _gapped_volume_numbers(siblings)
                concat = ConcatenatedFile(siblings)
                self._owned_concat = concat
                return SharedSource(concat, wrap_handle=wrap)
            self._volume_paths = [path]
            self._archive_path = path
            number = rar_volume_number(path.name)
            if number is not None and number > 1:
                # Possibly a later volume with none of its set beside it; only the
                # parse can tell (``_parse_archive``).
                self._lone_volume_number = number
            return SharedSource(source, wrap_handle=wrap)

        joined = source.joined
        if isinstance(joined, ConcatenatedFile):
            paths = source.volume_paths
            if paths:
                # An explicit list of volume files is used as given, in the order
                # given. Whether unrar may read them in place is decided after the
                # parse (_choose_unrar_volume_paths).
                self._volume_paths = paths
                self._volume_count = len(paths)
                self._archive_path = paths[0]
                return SharedSource(source, wrap_handle=wrap)
            # Stream volumes: parse from the originals; copy for unrar only when
            # a member actually needs one (_ensure_archive_path).
            items = joined.volume_items
            self._stream_volume_items = items
            self._volume_count = len(items)
            return SharedSource(source, wrap_handle=wrap)

        # Single non-path stream — materialize later when unrar is needed.
        return SharedSource(source, wrap_handle=wrap)

    def _choose_unrar_volume_paths(self) -> None:
        """Stage the volume files unless unrar, handed the first, reads exactly them.

        unrar finds later volumes by name beside the first, under the naming scheme
        the MAIN header names, which can differ from the one the files carry or
        the one sibling discovery matched. Unless that walk finds exactly the files
        parsed here, unrar is pointed at links to them under the set's own names
        instead (:meth:`_stage_explicit_volumes`, on the first read that needs
        unrar), so it cannot read a file this reader never parsed, or miss one it
        did.
        """
        if self._archive_path is None or self._stage_volume_paths:
            return
        if self._volume_numbers is None and _unrar_finds_exactly(
            self._volume_paths,
            is_volume=self._archive.is_volume,
            old_numbering=self._archive.old_volume_naming,
        ):
            return
        self._archive_path = None
        self._stage_volume_paths = True

    def _volume_numbers_or_default(self) -> list[int]:
        """Each volume's number in its set: ``_volume_numbers``, or ``1..N``."""
        if self._volume_numbers is not None:
            return self._volume_numbers
        return list(range(1, len(self._volume_paths) + 1))

    def _segment_start(self, info: RarMemberInfo) -> int | None:
        """The first volume of the unbroken run that holds this member's header.

        ``None`` for a set with no gap. ``unrar`` finds later volumes by name from
        the one it is given and stops at the first that is missing, so a member
        past a gap is read from the first volume after that gap; that is how
        ``unrar`` itself reads such a set, opened there (measured on 7.00).
        """
        numbers = self._volume_numbers
        if numbers is None:
            return None
        number = info.volume_index + 1
        start = number
        present = set(numbers)
        while start - 1 in present:
            start -= 1
        return start

    def _missing_data_error(
        self, member: ArchiveMember, info: RarMemberInfo
    ) -> TruncatedError | None:
        """Why this member's data cannot be read for a missing volume, or ``None``.

        Decided from the listing, before any decompressor runs. A member that runs
        into a missing volume, or starts in one, has part of its data missing
        (``split_after`` / ``split_before`` left on after the merge). In a solid
        archive a member past a gap needs the solid stream that ran through the
        missing volume; ``unrar`` reports checksum errors for those.
        """
        if info.split_after:
            detail = "continues into a volume that is missing from the set"
        elif info.split_before:
            detail = "starts in a volume that is missing from the set"
        elif (
            self._archive.is_solid
            and (start := self._segment_start(info)) is not None
            and start > 1
        ):
            detail = (
                "is in a solid archive past a missing volume, and its data depends "
                "on the solid stream that ran through it"
            )
        else:
            return None
        return TruncatedError(
            f"RAR member {quoted(member.name)} {detail}.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _cut_data_error(
        self, member: ArchiveMember, info: RarMemberInfo
    ) -> TruncatedError | None:
        """Why a program cannot read this member: the file ends inside its packed data.

        Decided from the listing, as :meth:`_missing_data_error` is. The callers ask
        only for a member a program would decode, and that set differs between them.
        :meth:`_open_member` asks after it has sliced a stored plaintext member and
        decrypted a stored encrypted one itself; both read up to the cut and then
        raise. The solid pass asks for every member it does not slice directly, so
        there a stored encrypted member is refused before any byte. ``unrar`` cannot
        say why it failed on such a member. It exits 3, which for an encrypted member
        that wrote nothing is also its RAR4 answer to a wrong password, and the bytes
        it writes for the gap can fail the digest as corruption before its exit code
        is read. ``None`` when the source size is not known.
        """
        size = self._shared.size
        if size is None:
            return None
        if info.data_parts:
            offset, part_size = info.data_parts[-1]
            end = offset + part_size
        elif _data_is_in_one_place(info):
            end = info.data_offset + info.compress_size
        else:
            return None
        if end <= size:
            return None
        if self._volume_set_size() > 1:
            # Offsets in a volume set are in the volumes laid end to end, which
            # locate nothing in any one file.
            where = "its packed data runs past the end of the set's volumes"
        else:
            where = (
                f"its packed data ends at byte {end}, past the end of the file "
                f"({size} bytes)"
            )
        return TruncatedError(
            f"RAR member {quoted(member.name)} is cut short: {where}.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _unrar_path_for(self, info: RarMemberInfo) -> Path:
        """The volume ``unrar`` is pointed at to read this member.

        Volume 1, or the staged first volume, for a set with no gap. Past a gap it
        is the first volume of the member's run, under the staged names, which keep
        each volume's own number so ``unrar`` stops at the next gap.
        """
        path = self._ensure_archive_path()
        start = self._segment_start(info)
        numbers = self._volume_numbers
        if start is None or numbers is None or start == numbers[0]:
            return path
        return path.parent / rar_volume_name(
            "archive", start, old_numbering=self._archive.old_volume_naming
        )

    def _volume_set_size(self) -> int:
        """Volumes in this set, whether or not they are files yet."""
        return max(len(self._volume_paths), len(self._stream_volume_items))

    def _materialize_stream_volumes(self) -> None:
        """Write ordered volumes into a temp dir under the names the set's own scheme uses.

        ``name.partN.rar``, or ``name.rar``, ``name.r00``, ``name.r01`` … for a RAR
        1.5-2.x set without the new-numbering flag. ``unrar`` and ``unar`` both look
        for the next volume only under the scheme the header names: an old-style set
        written as ``partN`` reads as volume 1 alone.

        Called from :meth:`_ensure_archive_path`, on the first read ``unrar``
        has to serve — not from ``__init__``. Listing a stream-volume set never
        reaches this, so a caller that only lists writes nothing.

        Stream items are copied through a :class:`SharedSource` view rather than
        read directly, so the copy takes the same lock every other read of these
        volumes takes. ``Path`` items are copied by the filesystem: they are not
        shared state. Assignments to ``_archive_path`` / ``_volume_paths`` /
        ``_temp_dir`` are a different lock: the caller
        (:meth:`_ensure_archive_path`) holds ``_materialize_lock`` across this
        method so two concurrent opens cannot each copy and leave the loser's
        directory behind on ``close()``.
        """
        items = self._stream_volume_items
        ranges = self._stream_volume_ranges()
        budget = self._spool_budget("every volume of the stream source")
        # The whole set is one copy, so the limit weighs the total. The joined source
        # already knows every volume's size, so an oversized set is refused here,
        # before the temp directory exists.
        budget.check_total(self._spool_copy_size())
        temp_dir = Path(tempfile.mkdtemp(prefix="archivey-rar-vol-"))
        self._temp_dir = temp_dir
        stem = "archive"
        if self._archive_name:
            stem = Path(self._archive_name).stem or stem
        paths: list[Path] = []
        try:
            for index, item in enumerate(items, start=1):
                dest = temp_dir / rar_volume_name(
                    stem, index, old_numbering=self._archive.old_volume_naming
                )
                # A file volume goes through the budget too, not ``shutil.copy2``:
                # its size was read when the set was joined, and a file that grew
                # since then must not carry the copy past the limit.
                if isinstance(item, Path):
                    with item.open("rb") as src, dest.open("wb") as out:
                        budget.copy(src, out)
                else:
                    start, size = ranges[index - 1]
                    view = self._shared.view(start, size)
                    try:
                        with dest.open("wb") as out:
                            budget.copy(view, out)
                    finally:
                        view.close()
                paths.append(dest)
        except BaseException:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self._temp_dir = None
            raise
        self._volume_paths = paths
        self._archive_path = paths[0]

    def _stage_explicit_volumes(self) -> None:
        """Link the parsed volume files into a temp dir under the set's own names.

        The files may sit in different directories, or carry names that unrar's
        rule for this set (:func:`_unrar_finds_exactly`) does not continue, and
        unrar finds each later volume by name beside the one before. Each file is
        linked (:meth:`_link_volumes`) rather than copied; only a file the system will
        not link is copied, and only those copies are charged to ``SpoolLimits``.
        Called under ``_materialize_lock`` from :meth:`_ensure_archive_path`.
        """
        temp_dir = Path(tempfile.mkdtemp(prefix="archivey-rar-vol-"))
        self._temp_dir = temp_dir
        names = [
            temp_dir
            / rar_volume_name(
                "archive", number, old_numbering=self._archive.old_volume_naming
            )
            for number in self._volume_numbers_or_default()
        ]
        try:
            self._link_volumes(
                self._volume_paths,
                names,
                "each volume the system would not link beside the others",
            )
        except BaseException:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self._temp_dir = None
            raise
        self._archive_path = names[0]

    def _decompressor_name(self) -> str:
        """The data program as the open-time notes name it."""
        if self._decompressor is RarDecompressor.UNAR:
            return "unar"
        return "RARLAB unrar or rar"

    def _spool_budget(self, what: str | None) -> SpoolBudget:
        """This reader's spool budget, made on first use and kept for its lifetime.

        One budget per reader, not per attempt: a copy that was refused, or failed
        part-way, is not given a fresh allowance by the next read. Called under
        ``_materialize_lock``. ``what`` names the copy in the refusal; the first call
        that passes one fixes it (``None`` is a file-copy source kept by a solid pass,
        :meth:`_try_spool`, which never refuses). Neither link fallback follows a
        stream source's copy on one reader. Only a path source's files are ever linked
        for ``unar``. For unrar, :meth:`_ensure_archive_path` either copies stream
        volumes or stages explicit volume files, never both.
        """
        program = (
            "unar" if self._decompressor is RarDecompressor.UNAR else "RARLAB unrar"
        )
        if self._spool is None:
            remedy: dict[str, str] = {}
            source = self._source
            if source is None:
                pass
            elif source.path is not None:
                # A file copied for unar: from where a prefixed RAR starts, or because
                # it could not be linked into unar's private directory. unrar reads
                # a path where it is.
                remedy["remedy"] = (
                    "Set ArchiveyConfig.rar_decompressor to 'unrar', which reads an "
                    "archive file in place, or raise the limit (None removes it)."
                )
            elif source.volume_paths and self._decompressor is RarDecompressor.UNAR:
                # unar reads every set from its private directory, so where the
                # caller keeps the files does not matter; unrar can read them there.
                remedy["remedy"] = (
                    "Set ArchiveyConfig.rar_decompressor to 'unrar', which reads "
                    "volumes in place when they sit in one directory under their "
                    "set's names, or raise the limit (None removes it)."
                )
            elif source.volume_paths:
                # Explicit volume files that could not be linked side by side.
                remedy["remedy"] = (
                    "Put the volumes in one directory under their set's names, where "
                    "they are read in place, or raise the limit (None removes it)."
                )
            self._spool = SpoolBudget(
                self._config.spool_limits,
                what=None,
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
                **remedy,
            )
            self._usage.watch_spool(self._spool)
        if what is not None:
            self._spool.describe(
                f"reading this member needs {program}, which reads only files, "
                f"so {what} must be copied to a temporary location"
            )
        return self._spool

    def _try_spool(self, size: int) -> bool:
        """Charge ``size`` bytes of a kept file-copy source to the spool budget, if they fit.

        ``False`` when they do not: the copy then reads its source as it would without
        the solid pass (:meth:`_open_file_copy`), and the budget is left open.
        """
        with self._materialize_lock:
            return self._spool_budget(None).try_reserve(size)

    def _release_spool(self, size: int) -> None:
        """Give back what :meth:`_try_spool` charged, once the kept file is deleted."""
        with self._materialize_lock:
            assert self._spool is not None
            self._spool.release(size)

    def _unar_copy_size(self) -> int | None:
        """Bytes :meth:`_unar_archive_path` copies from where the RAR starts, if known."""
        size = self._shared.size
        if size is None:
            return None
        return max(size - self._origin - self._archive.sfx_offset, 0)

    def _spool_copy_size(self) -> int | None:
        """Bytes the copy for ``unrar`` would write, or ``None`` when not known.

        Stream volumes copy every volume whole, and the joined source measured each
        one. A single stream copies from the origin to the end of the source.
        """
        if self._stream_volume_items:
            return sum(size for _, size in self._stream_volume_ranges())
        source_size = self._shared.size
        if source_size is None:
            return None
        return max(source_size - self._origin, 0)

    def _stream_volume_ranges(self) -> list[tuple[int, int]]:
        """``(start, size)`` per volume in the concatenated space this reader reads."""
        assert self._source is not None
        joined = self._source.joined
        assert isinstance(joined, ConcatenatedFile), (
            "stream volumes only come from a joined source"
        )
        return joined.volume_ranges

    def _parse_archive(self) -> tuple[RarArchive, str | None]:
        max_members = self._config.listing_limits.max_members
        max_metadata_bytes = self._config.listing_limits.max_metadata_bytes

        def parse(password: bytes | None) -> RarArchive:
            if len(self._volume_paths) > 1:
                handles: list[BinaryIO] = []
                try:
                    for index, path in enumerate(self._volume_paths):
                        handle = path.open("rb")
                        if index == 0 and self._volume0_parse_origin:
                            handle.seek(self._volume0_parse_origin)
                        handles.append(handle)
                    return parse_rar_volumes(
                        handles,
                        password=password,
                        max_members=max_members,
                        max_metadata_bytes=max_metadata_bytes,
                        kdf_cache=self._kdf_cache,
                        name_encoding=self._encoding,
                        volume_numbers=self._volume_numbers,
                    )
                finally:
                    for handle in handles:
                        handle.close()

            if len(self._stream_volume_items) > 1:
                # Stream volumes, not yet copied anywhere. The header walk needs
                # each volume as its own stream positioned at its start, which
                # the concatenation cannot be, so mint one bounded view per
                # volume over the same source. Views are non-owning and take the
                # shared lock, so nothing here touches the caller's streams.
                views: list[BinaryIO] = []
                try:
                    for index, (start, size) in enumerate(self._stream_volume_ranges()):
                        view = self._shared.view(start, size)
                        views.append(view)
                        if index == 0 and self._volume0_parse_origin:
                            view.seek(self._volume0_parse_origin)
                    return parse_rar_volumes(
                        views,
                        password=password,
                        max_members=max_members,
                        max_metadata_bytes=max_metadata_bytes,
                        kdf_cache=self._kdf_cache,
                        name_encoding=self._encoding,
                    )
                finally:
                    for view in views:
                        view.close()

            # Single volume: a path source, or a lone stream. Nothing is copied
            # on this path any more — a stream volume *set* is handled above, from
            # views over the originals, and the copy waits for a member read.
            if self._volume_paths:
                with self._volume_paths[0].open("rb") as handle:
                    handle.seek(self._origin)
                    try:
                        archive = parse_rar_archive(
                            handle,
                            password=password,
                            max_members=max_members,
                            max_metadata_bytes=max_metadata_bytes,
                            kdf_cache=self._kdf_cache,
                            name_encoding=self._encoding,
                        )
                    except UnsupportedFeatureError:
                        # "Need first volume": a later volume alone. Its name says
                        # which one, so it is read as a set missing the others.
                        if self._lone_volume_number is None:
                            raise
                        self._volume_numbers = [self._lone_volume_number]
                        handle.seek(self._origin)
                        return parse_rar_volumes(
                            [handle],
                            password=password,
                            max_members=max_members,
                            max_metadata_bytes=max_metadata_bytes,
                            kdf_cache=self._kdf_cache,
                            name_encoding=self._encoding,
                            volume_numbers=self._volume_numbers,
                        )
                    return archive

            view = self._shared.view(0)
            try:
                view.seek(self._origin)
                archive = parse_rar_archive(
                    view,
                    password=password,
                    max_members=max_members,
                    max_metadata_bytes=max_metadata_bytes,
                    kdf_cache=self._kdf_cache,
                    name_encoding=self._encoding,
                )
                if archive.is_volume and not archive.needs_next_volume:
                    # A lone volume that says nothing follows it is a later
                    # volume, or the only one, of a set. One that says another
                    # follows is volume 1 here: the parse refuses a later volume
                    # from its volume number (RAR5 MAIN, RAR 3.0+ end block) or a
                    # first member that continues an earlier one. Only a RAR 1.5 /
                    # 2.x later volume whose first member starts on its boundary
                    # records neither, and lists as volume 1 of an incomplete set.
                    raise TruncatedError(
                        "Incomplete RAR multi-volume set: additional volumes required"
                    )
                return archive
            finally:
                view.close()

        try:
            try:
                archive = parse(None)
            except EncryptionError:
                if not self._passwords.has_passwords():
                    raise
                archive = self._passwords.attempt(None, parse)
            # A set whose last volume present says another follows: list what the
            # volumes hold, then raise (``_iter_members``), as for a cut file.
            mark_missing_next_volume(
                archive,
                volumes_read=(
                    self._volume_numbers[-1]
                    if self._volume_numbers
                    else max(self._volume_set_size(), 1)
                ),
            )
            # _first_candidate_str is the first configured candidate when
            # headers parsed without a password (data-only encryption; a wrong
            # guess is rejected by PswCheck or unrar exit 11). After
            # attempt(), record_success has moved the working password to
            # the front of _known_good, so the same call is the password that
            # worked. core.py mints a fresh _PasswordCandidates per
            # open_archive, so _known_good is not shared across archives.
            return archive, self._first_candidate_str()
        except _PasswordCandidatesExhausted as exc:
            message = (
                exc.last_error.message
                if exc.last_error is not None
                else "Password required to decrypt RAR headers"
            )
            raise EncryptionError(message) from exc

    def _unrar_data_password(self) -> str | None:
        """The password to hand an ``unrar`` spawn, or ``None`` when none is needed.

        ``_first_candidate_str`` returns a configured candidate whenever the caller
        supplied one, encrypted archive or not. Passing that on made every ``unrar``
        spawn carry a password the archive has no use for — which is how a password
        that cannot be handed to ``unrar`` at all (see
        :func:`rar_unrar._password_stdin_bytes`) stopped a plain archive from opening.

        The gate is the whole archive rather than the member being read, and
        deliberately so: on a solid archive a plain member's block can sit behind an
        encrypted one, so ``unrar`` may need the password to reach a member that is
        not itself encrypted. An archive with nothing encrypted anywhere needs it on
        no path at all, which is the case worth cutting.
        """
        return self._unrar_password if self._archive_has_encryption else None

    def _first_candidate_str(self) -> str | None:
        """Password to hand unrar / ConvertHashToMAC, or ``None``.

        Relies on ``_PasswordCandidates.iter_candidates`` yielding
        ``_known_good`` first. After a successful ``attempt()``, that front
        item is the password that worked, not the originally first candidate.
        """
        for password in self._passwords.iter_candidates():
            return _password_as_str(password)
        return None

    def _checked_password(
        self,
        enc: RarEncryptionInfo,
        member: ArchiveMember | None,
        *,
        ask_provider: bool,
    ) -> bytes | None:
        """The candidate ``enc``'s PswCheck accepts, found by trying them in order.

        ``enc`` must pass :func:`_psw_check_usable`. With ``ask_provider`` this is the
        ordinary per-unit attempt (known-good, then the list, then the provider) and
        exhaustion raises ``_PasswordCandidatesExhausted``. Without it, only the
        concrete candidates are tried and ``None`` means none matched: a caller that
        must not prompt (building a digest check for a member nobody read yet) still
        gets the right password when the caller listed it, just not first.
        """
        assert enc.check_value is not None
        check_value = enc.check_value
        key = (enc.salt, enc.kdf_count, check_value)
        found = self._checked_passwords.get(key)
        if found is not None:
            return found

        def check(password: bytes) -> bytes:
            try:
                _check_rar5_password(
                    check_value,
                    enc.kdf_count,
                    enc.salt,
                    _password_as_str(password) or "",
                    kdf_cache=self._kdf_cache,
                )
            except (EncryptionError, UnicodeError):
                raise wrong_password_error(
                    "Wrong password for this RAR member"
                ) from None
            return password

        if ask_provider:
            found = self._passwords.attempt(member, check)
        else:
            for password in self._passwords.iter_candidates():
                try:
                    found = check(password)
                except EncryptionError:
                    continue
                break
            if found is None:
                return None
        self._checked_passwords[key] = found
        return found

    def _member_needs_password(self, raw: RarMemberInfo) -> bool:
        """Whether a spawn reading only this member has any use for a password.

        It does when the headers are encrypted (the program cannot list without it),
        when the member is encrypted or its encryption is unknown, and in a solid
        archive when an encrypted member comes before it: the decode runs through
        that member's data first. Otherwise no password is handed over, so the
        caller's password reaches ``unrar`` or ``unar`` only for a read that uses it.
        """
        return (
            self._archive.has_header_encryption
            or raw.is_encrypted
            or raw.encryption_unknown
            or id(raw) in self._behind_encryption
        )

    def _member_data_password(self, member: ArchiveMember) -> str | None:
        """The password to hand the ``unrar`` or ``unar`` spawn that reads ``member``.

        ``None`` for a member that needs none (:meth:`_member_needs_password`).
        ``unrar`` takes one password and cannot try a list, so a candidate list is
        resolved here. A RAR5 member carries a PswCheck, so its password is picked
        per member, before ``unrar`` runs. A plain member of a solid archive behind
        an encrypted one needs that member's password. An encrypted member without a
        usable check (RAR3/4) is judged by decoding it
        (:meth:`_unchecked_data_password`).
        """
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if not self._member_needs_password(raw):
            return None
        enc = raw.file_encryption
        if enc is not None and _psw_check_usable(enc):
            return self._checked_data_password(enc, member)
        if self._archive.is_solid:
            return self._archive_data_password()
        if raw.is_encrypted:
            return self._unchecked_data_password(member)
        return self._unrar_data_password()

    def _archive_data_password(self) -> str | None:
        """The password for an ``unrar`` spawn that decodes the whole archive.

        Taken from the first member whose PswCheck can judge a candidate; the pass
        spawn and a solid archive's plain members read through it. With no such
        member (RAR3/4), a candidate list is judged on one encrypted member: in a
        solid archive the first, which the solid stream decodes first anyway; in a
        non-solid one the smallest, the cheapest to decode.
        """
        if self._passwords.has_passwords():
            member = self._archive_check_member
            if member is False:
                member = next(
                    (
                        candidate
                        for candidate in self._members
                        if isinstance(candidate._raw, RarMemberInfo)
                        and candidate._raw.file_encryption is not None
                        and _psw_check_usable(candidate._raw.file_encryption)
                    ),
                    None,
                )
                self._archive_check_member = member
            if member is not None:
                raw = member._raw
                assert isinstance(raw, RarMemberInfo)
                assert raw.file_encryption is not None
                return self._checked_data_password(raw.file_encryption, member)
            reference = self._unchecked_reference_member()
            if reference is not None:
                return self._unchecked_data_password(reference, for_archive=True)
        return self._unrar_data_password()

    def _unchecked_reference_member(self) -> ArchiveMember | None:
        """The encrypted member a RAR3/4 candidate list is judged on for the archive."""
        if self._unchecked_reference is False:
            self._unchecked_reference = self._find_unchecked_reference_member()
        return self._unchecked_reference

    def _find_unchecked_reference_member(self) -> ArchiveMember | None:
        encrypted = [
            member
            for member in self._members
            if isinstance(member._raw, RarMemberInfo)
            and member._raw.is_encrypted
            and member._raw.is_payload_file()
            and member.is_file
            and _member_stream_size(member) > 0
            # A member whose data is cut or in a missing volume fails to decode
            # with every candidate, so it cannot judge them.
            and self._cut_data_error(member, member._raw) is None
            and self._missing_data_error(member, member._raw) is None
        ]
        if not encrypted:
            return None
        if self._archive.is_solid:
            return encrypted[0]
        return min(encrypted, key=_member_stream_size)

    def _unchecked_data_password(
        self, reference: ArchiveMember, *, for_archive: bool = False
    ) -> str | None:
        """The candidate that decodes ``reference``, an encrypted member with no check.

        RAR3/4 records no password check value, so a candidate is judged by decoding
        (:func:`~archivey.internal.password_confirm.attempt_with_confirm`): a bounded
        probe of the first :data:`PASSWORD_CONFIRM_PREFIX_BYTES` of output, which the
        decoder fails for about two wrong keys in three (one in two when solid), and
        when several candidates survive it, a full decode checked against the
        member's CRC. A stored member has no decoder to object, so its check is the
        CRC over a native decryption (:meth:`_stored_check`).

        Only a list is judged this way. One password goes to ``unrar`` unjudged, as
        before: the CRC at the member's end is its check. So does the header
        password of an ``-hp`` archive, which decrypting the headers already proved.

        ``for_archive`` says ``reference`` only stands in for the archive (the solid
        pass reads every member through one spawn). If ``reference`` itself cannot be
        decoded on its own (``unrar`` cannot be handed its name), the list is then not
        judged, as before, rather than refusing a read that does not need it.
        """
        if (
            not self._passwords.has_passwords()
            or not self._passwords.is_ambiguous()
            or self._archive.has_header_encryption
        ):
            return self._unrar_data_password()
        found = self._unchecked_passwords.get(id(reference))
        if found is None:
            try:
                probe, full_check = self._unchecked_password_checks(reference)
            except UnsupportedFeatureError:
                if not for_archive:
                    raise
                return self._unrar_data_password()
            try:
                found, verdict = attempt_with_confirm(
                    self._passwords, reference, probe, full_check
                )
            except _PasswordCandidatesExhausted as exc:
                undecodable = (
                    exc.last_error is not None
                    and raw_message_of(exc.last_error) == _UNDECODABLE_WITH_CANDIDATE
                )
                error = EncryptionError(
                    _UNDECODABLE_WITH_ANY_CANDIDATE
                    if undecodable
                    else raw_message_of(exc),
                    archive_name=self._archive_name,
                    member_name=reference.name,
                    source_format=ArchiveFormat.RAR,
                )
                if undecodable:
                    # Wrong password or damage: nothing here can tell which.
                    mark_unverified_data(error)
                raise error from exc
            self._unchecked_passwords[id(reference)] = found
            if verdict is PasswordConfirmVerdict.CONFIRMED:
                self._unchecked_confirmed.add(id(reference))
        return _password_as_str(found)

    def _unchecked_password_checks(
        self, member: ArchiveMember
    ) -> tuple[
        Callable[[bytes], tuple[bytes, PasswordConfirmVerdict]],
        Callable[[bytes], tuple[bytes, PasswordConfirmVerdict]] | None,
    ]:
        """The bounded probe and the full check for one encrypted RAR3/4 member."""
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if self._stored_natively_checkable(raw):
            return (lambda password: self._stored_check(raw, password)), None

        size = _member_stream_size(member)
        crc = raw.crc32 if not _crc_is_tweaked(raw) else None
        # Unlike the read path, a tweaked digest does not count here: it can only be
        # verified once a password is chosen, so for such a member unrar's exit code is
        # the only CRC signal the probe gets, and suppressing it would leave none.
        has_hash = bool(member.hashes)
        if self._unar_policy is not None:
            unar_spawn = self._unar_spawner(member, raw, self._unar_policy)

            def spawn(password: str | None) -> BinaryIO:
                return unar_spawn(password)

        else:
            unrar_spawn = self._unrar_spawner(member, raw)

            def spawn(password: str | None) -> BinaryIO:
                return unrar_spawn(password, has_hash)

        def decode_check(
            password: bytes, plan: PasswordConfirmPlan
        ) -> tuple[bytes, PasswordConfirmVerdict]:
            stream = spawn(_password_as_str(password))
            try:
                verdict = run_password_confirm_plan(stream, plan)
            except (
                UnsupportedFeatureError,
                PackageNotInstalledError,
                ResourceLimitError,
            ):
                raise
            except EncryptionError as exc:
                # The program itself said the password is wrong.
                raise wrong_password_error(
                    "Wrong password for this RAR member"
                ) from exc
            except ArchiveyError as exc:
                # The decoder objected, the output ended early, or a CRC mismatched.
                # A wrong key does that, and so does damage the right key decodes
                # into; the attempt still moves on, but its message must not claim
                # which one it was.
                raise _undecodable_with_candidate() from exc
            finally:
                # Stops the program when the plan ended before its output did; only
                # what was read above is judged.
                stream.close()
            if verdict is PasswordConfirmVerdict.REJECTED:
                raise _undecodable_with_candidate()
            return password, verdict

        bounded = plan_password_confirm(
            [(size, crc)],
            None,
            budget=PASSWORD_CONFIRM_PREFIX_BYTES,
            # A wrong RAR3/4 key fails the decoder within the prefix for only about
            # two in three candidates (dev-docs/formats/rar.md §2.2), so surviving it
            # is evidence, never proof; the stored case is handled natively above.
            codec_rejects=not raw.is_stored,
        )
        full: PasswordConfirmPlan | None = None
        if not bounded.confirms and crc is not None:
            full = plan_password_confirm(
                [(size, crc)],
                None,
                budget=PASSWORD_CONFIRM_PREFIX_BYTES,
                codec_rejects=False,
            )
            if full == bounded or not full.confirms:
                full = None
        full_plan = full
        return (
            lambda password: decode_check(password, bounded),
            None
            if full_plan is None
            else (lambda password: decode_check(password, full_plan)),
        )

    def _natively_decryptable(self, raw: RarMemberInfo) -> bool:
        """Whether this is a stored, encrypted member archivey can decrypt itself.

        A stored member's packed bytes are its content once decrypted, so no decoder is
        needed. RAR 2.9 to 4 encrypt them with AES-128-CBC under a key and IV the
        password and the member's 8-byte salt give; RAR5 with AES-256-CBC under a key
        from the password and the member's salt, and the IV in its encryption record.
        Either way the ciphertext is the plaintext padded to whole 16-byte blocks, so
        the two sizes must agree with that. Only a member in one part qualifies: each
        part of a split member has its own encryption record. Whether ``cryptography``
        is installed is not part of this answer (:meth:`_decrypts_natively`).
        """
        if not (
            raw.is_encrypted
            and raw.is_stored
            and not raw.encryption_unknown
            and not raw.data_parts
            and _data_is_in_one_place(raw)
            and raw.compress_size % AES_BLOCK_SIZE == 0
            and raw.file_size <= raw.compress_size < raw.file_size + AES_BLOCK_SIZE
        ):
            return False
        if self._archive.version == 5:
            enc = raw.file_encryption
            return (
                enc is not None
                and enc.algo == _RAR5_XENC_AES256
                and enc.iv is not None
                and len(enc.iv) == AES_BLOCK_SIZE
            )
        return (
            raw.rar3_salt is not None
            and raw.extract_version is not None
            and raw.extract_version >= _RAR3_AES_EXTRACT_VERSION
        )

    def _decrypts_natively(self, raw: RarMemberInfo) -> bool:
        """Whether a read of ``raw`` decrypts it here instead of running a program.

        Without ``cryptography``, a program reads it when one is selected. Under
        ``NONE`` there is none, so the read is still taken here, where it raises
        ``PackageNotInstalledError`` naming ``cryptography``.
        """
        return self._natively_decryptable(raw) and (
            _crypto_available() or self._decompressor is RarDecompressor.NONE
        )

    def _stored_data_cipher(
        self, raw: RarMemberInfo, password: str | bytes
    ) -> AesParams:
        """The AES key and IV for a :meth:`_natively_decryptable` member's data."""
        if self._archive.version == 5:
            enc = raw.file_encryption
            assert enc is not None and enc.iv is not None
            key = rar5_data_key(
                password, enc.salt, enc.kdf_count, kdf_cache=self._kdf_cache
            )
            return AesParams(key=key, iv=enc.iv)
        assert raw.rar3_salt is not None
        key, iv = self._kdf_cache.rar3(password, raw.rar3_salt)
        return AesParams(key=key, iv=iv)

    def _stored_natively_checkable(self, raw: RarMemberInfo) -> bool:
        """Whether a candidate password for ``raw`` can be judged by decrypting it here.

        The judge is the member's CRC32 over the decrypted bytes
        (:meth:`_stored_check`); a member that records none goes to the decoder probe,
        as does every member when ``cryptography`` is not installed.
        """
        return (
            self._natively_decryptable(raw)
            and _crypto_available()
            and raw.crc32 is not None
        )

    def _stored_check(
        self, raw: RarMemberInfo, password: bytes
    ) -> tuple[bytes, PasswordConfirmVerdict]:
        """Judge ``password`` by the CRC of a stored member it decrypts.

        Every wrong key decrypts a stored member to bytes of the right length, so only
        the CRC can tell them apart; this pass is the full check, with no ``unrar``.
        A RAR5 CRC the writer tweaked (``ConvertHashToMAC``) is compared after the same
        transform under this password's HashKey. Memory is one chunk.
        """
        if not self._stored_crc_matches(raw, password):
            raise _undecodable_with_candidate()
        verdict = (
            PasswordConfirmVerdict.CONFIRMED
            if raw.file_size >= PASSWORD_CONFIRM_MIN_VERIFIED_BYTES
            else PasswordConfirmVerdict.INCONCLUSIVE
        )
        return password, verdict

    def _stored_crc_matches(self, raw: RarMemberInfo, password: str | bytes) -> bool:
        """Whether ``password`` decrypts a stored member to bytes its CRC32 matches."""
        assert raw.crc32 is not None
        stage = open_aes_decrypt_stage(self._stored_data_cipher(raw, password))
        view = self._direct_view(raw, raw.compress_size)
        crc = 0
        remaining = raw.file_size
        try:
            while remaining > 0:
                chunk = view.read(PASSWORD_CONFIRM_CHUNK_BYTES)
                if not chunk:
                    raise TruncatedError(
                        "The stored RAR member's data ended before its declared size"
                    )
                plain = stage.update(chunk)[:remaining]
                crc = zlib.crc32(plain, crc)
                remaining -= len(plain)
        finally:
            view.close()
        if _crc_is_tweaked(raw):
            enc = raw.file_encryption
            assert enc is not None
            crc = convert_crc_to_mac(
                crc,
                rar5_hash_key(
                    password, enc.salt, enc.kdf_count, kdf_cache=self._kdf_cache
                ),
            )
        return crc == raw.crc32 & 0xFFFFFFFF

    def _checked_data_password(
        self, enc: RarEncryptionInfo, member: ArchiveMember
    ) -> str | None:
        if not self._passwords.has_passwords():
            # Nothing to try: unrar reports the missing password itself, as before.
            return None
        try:
            found = self._checked_password(enc, member, ask_provider=True)
        except _PasswordCandidatesExhausted as exc:
            raise EncryptionError(
                raw_message_of(exc),
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            ) from exc
        assert found is not None
        return _password_as_str(found)

    def _ensure_archive_path(self) -> Path:
        """Return a filesystem path ``unrar`` can open (materialize streams once).

        Concurrent compressed ``open()`` calls share one copy: the check-then-write
        is under ``_materialize_lock``, and ``_close_archive`` takes the same lock
        so it cannot unlink while a copy is still landing, or miss the loser's
        directory if two copies raced.
        """
        if self._archive_path is not None:
            return self._archive_path
        with self._materialize_lock:
            if self._archive_path is not None:
                return self._archive_path
            if self._stream_volume_items:
                # Stream volumes: unrar needs sibling files on disk, so the whole set
                # is written, not just the volume holding this member. Nothing before
                # this point needed them — the listing was parsed from the originals.
                self._materialize_stream_volumes()
                assert self._archive_path is not None
                return self._archive_path
            if self._stage_volume_paths:
                self._stage_explicit_volumes()
                assert self._archive_path is not None
                return self._archive_path
            # Single stream source: write one temp .rar for unrar.
            budget = self._spool_budget("the whole stream source")
            # Checked before mkstemp, so a refused archive leaves no temp file. With
            # no size known this still refuses a retry after an earlier refusal.
            budget.check_total(self._spool_copy_size())
            path = self._spool_from(self._origin, budget)
            self._temp_path = path
            self._archive_path = path
            return path

    def _spool_from(
        self,
        start: int,
        budget: SpoolBudget,
        *,
        directory: Path | None = None,
    ) -> Path:
        """Copy the source from ``start`` to a new temp ``.rar``; the caller owns it.

        ``budget`` bounds the copy: a stream source's for ``unrar``, and a single
        archive's for ``unar`` (a stream, or a prefixed path). The caller checks the
        known total against it first. ``directory`` is where the file is made, the
        system temp directory if omitted.
        """
        fd, name = tempfile.mkstemp(suffix=".rar", dir=directory)
        path = Path(name)
        try:
            with os.fdopen(fd, "wb") as out:
                # From ``start``, so the temp holds the RAR alone and a program that
                # does not look past a prefix sees a plain RAR at byte 0. ``unrar``
                # skips a stub itself, so its path source is passed as is and only
                # a stream comes here; ``unar`` also sends a prefixed path source.
                view = self._shared.view(start)
                try:
                    # The budget stops the copy at the limit when the size checked
                    # before was not known, or was wrong. It reads in 1 MiB chunks,
                    # which keeps the SharedView lock acquisitions few.
                    budget.copy(view, out)
                finally:
                    view.close()
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path

    def _unar_path_refusal(self) -> str | None:
        """Why ``unar`` cannot be handed this archive, or ``None`` when it can.

        Decided from the volume set alone, so it is the same for every member.
        """
        if self._volume_set_size() > 1 and (
            self._volume0_parse_origin or self._archive.sfx_offset
        ):
            return (
                "unar does not find a RAR after a prefix, and a prefixed multi-volume "
                "set is not copied for it. Set ArchiveyConfig.rar_decompressor to "
                "'unrar' to read it with RARLAB unrar."
            )
        if (
            self._archive.old_volume_naming
            and self._volume_set_size() > _UNAR_MAX_OLD_STYLE_VOLUMES
        ):
            return (
                f"unar reads at most {_UNAR_MAX_OLD_STYLE_VOLUMES} volumes of an "
                "old-style (.rar, .r00 ...) set and reports the rest as a damaged "
                "member. Set ArchiveyConfig.rar_decompressor to 'unrar' to read it "
                "with RARLAB unrar."
            )
        return None

    def _unar_dictionary_cost_map(self) -> dict[int, _DictionaryCost]:
        """Each member's dictionary cost under ``unar``, keyed by ``id(member)``.

        Under ``unar`` the count is the declared size (see
        :func:`unar_dictionary_costs`), so both fields carry it.
        """
        return {
            id(member): _DictionaryCost(count, count, declarer)
            for member, (count, declarer) in zip(
                self._members, unar_dictionary_costs(self._archive), strict=True
            )
        }

    def _unar_for_unaddressable(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> tuple[UnarRarPolicy, _DictionaryCost] | None:
        """The ``unar`` policy and dictionary cost for a member ``unrar`` cannot name.

        ``unar`` names entries by index, so no refusal about addressing a member by name
        (each one :class:`_UnrarCannotAddress` carries) applies to it. ``AUTO``
        therefore reads such a member with an accepted ``unar`` when one is installed,
        where it would otherwise refuse it. ``None`` keeps the ``unrar`` refusal when:

        - the caller chose ``unrar`` explicitly, or no accepted ``unar`` was found;
        - the read needs a password (:meth:`_member_needs_password`): ``unar`` takes
          it on its command line, where other local users can see it. A plaintext
          member of a non-solid archive, or one no encrypted member precedes in a
          solid one, needs none, and ``unar`` gets none;
        - ``unar`` would need a copy of the archive made for it alone: a prefix before
          the RAR (no open-time note under ``unrar``), or a stream source (a second
          copy against the ``SpoolLimits`` budget the open-time note described as
          one). A file source is linked into ``unar``'s directory, and copied only
          where the system allows no link, as for a chosen ``unar``;
        - ``unar`` refuses the member or the archive too.
        """
        if (
            self._config.rar_decompressor is not RarDecompressor.AUTO
            or self._decompressor is not RarDecompressor.UNRAR
            or self._member_needs_password(raw)
            or not self._volume_paths
            or self._origin + self._archive.sfx_offset != 0
            or self._unar_path_refusal() is not None
        ):
            return None
        # Not under _materialize_lock: find_unar runs a probe with a timeout (and on
        # a first call decodes a test archive), which must not hold up the copies.
        with self._unar_fallback_lock:
            if self._unar_fallback is False:
                try:
                    find_unar(purpose=UNAR_PURPOSE)
                except PackageNotInstalledError:
                    self._unar_fallback = None
                else:
                    self._unar_fallback = (
                        UnarRarPolicy(self._archive),
                        self._unar_dictionary_cost_map(),
                    )
            fallback = self._unar_fallback
        if fallback is None or fallback[0].member_refusal(raw) is not None:
            return None
        policy, costs = fallback
        return policy, costs[id(member)]

    def _unar_archive_path(self, member: ArchiveMember | None) -> Path:
        """A path ``unar`` can open, in a directory that holds this archive alone.

        ``unar`` picks a volume set by file name: handed ``report2024.rar`` beside
        ``report2023.rar``, it reads the pair as one set and returns the neighbour's
        data. So ``unar`` never gets the caller's path. It gets a private directory
        holding exactly the volumes archivey found, under the names
        :func:`rar_volume_name` gives them; a single archive is ``archive.rar``
        there, with no name another file could continue.

        Each volume is linked, not copied (:func:`_link_file`). Where the system
        allows neither link, the volumes that could not be linked are copied through
        the reader's spool budget: their total is checked before the first byte, so a
        limit below it refuses the read and leaves no directory behind. That copy has
        no open-time cost note, because whether a link works is known only when it is
        tried; the notes cover only the copies known at open (a stream source, and a
        prefixed path source).

        A single stream source has no file to link, so it is copied once straight
        into that directory, within the spool budget.

        ``unar`` also does not look for a RAR after a prefix, whether that is an SFX
        stub or anything else; it reports an unknown format and writes nothing. A
        single prefixed archive is therefore copied once into that directory from
        where the RAR starts: the detected origin plus any stub the parser skipped
        past. A prefixed multi-volume set is refused: every volume would need
        copying under its sibling name, and ``unrar`` reads that set in place.
        """
        start = self._origin + self._archive.sfx_offset
        refusal = self._unar_path_refusal()
        if refusal is not None:
            raise self._unar_refused(member, refusal)
        if self._unar_path is not None:
            return self._unar_path
        if start == 0 and self._stream_volume_items:
            # Stream volumes are already written to a directory of their own, holding
            # the set and nothing else.
            return self._ensure_archive_path()
        # A path source's files are linked. A single stream source has none: it is
        # copied once, straight into the private directory, by the branch below, so
        # no temp copy of it is made first and then copied again.
        volumes = self._volume_paths if start == 0 else []
        with self._materialize_lock:
            if self._unar_path is not None:
                return self._unar_path
            budget = None
            if not volumes:
                # Bounded like any other copy, and checked before the directory
                # exists when the size is known, as it is for a path.
                budget = self._spool_budget("the archive from where the RAR starts")
                budget.check_total(self._unar_copy_size())
            temp_dir = Path(tempfile.mkdtemp(prefix="archivey-unar-"))
            try:
                if budget is not None:
                    target = temp_dir / "archive.rar"
                    self._spool_from(start, budget, directory=temp_dir).replace(target)
                    self._unar_path = target
                else:
                    self._unar_path = self._link_volumes_for_unar(volumes, temp_dir)
            except BaseException:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise
            self._unar_dir = temp_dir
            return self._unar_path

    def _link_volumes_for_unar(self, volumes: list[Path], temp_dir: Path) -> Path:
        """Put ``volumes`` in ``temp_dir`` for ``unar``; return volume 1's path there.

        A lone archive is ``archive.rar``; a set takes its own naming scheme. A volume
        the system will not link is copied, within the spool budget (see
        :meth:`_unar_archive_path`).
        """
        if len(volumes) == 1:
            names = ["archive.rar"]
        else:
            old_numbering = self._archive.old_volume_naming
            names = [
                rar_volume_name("archive", number, old_numbering=old_numbering)
                for number in self._volume_numbers_or_default()
            ]
        self._link_volumes(
            volumes,
            [temp_dir / name for name in names],
            "each volume the system would not link into a private directory",
        )
        return temp_dir / names[0]

    def _link_volumes(self, volumes: list[Path], dests: list[Path], what: str) -> None:
        """Link each of ``volumes`` to its ``dests`` path; copy the ones that will not link.

        Only the copies are charged to the spool budget, and their total is checked
        before the first byte, so a limit below it refuses the read with nothing
        copied. The caller removes the directory on failure.
        """
        unlinked: list[tuple[Path, Path]] = []
        for volume, dest in zip(volumes, dests, strict=True):
            try:
                _link_file(volume.absolute(), dest)
            except OSError:
                unlinked.append((volume, dest))
        if unlinked:
            budget = self._spool_budget(what)
            budget.check_total(sum(volume.stat().st_size for volume, _ in unlinked))
            for volume, dest in unlinked:
                with volume.open("rb") as src, dest.open("wb") as out:
                    budget.copy(src, out)

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield from self._members
        if self._archive.truncated is not None:
            # Terminal damage after the prefix, so the listing keeps what the file
            # holds and reports the rest as missing (``members_report().error``).
            # Raised before the end-block diagnostics below: under a strict policy
            # emitting them first would replace this with a DiagnosticRaisedError
            # about lesser damage. A set can also have a damaged header (the walk
            # follows a split member past one): one error is raised, so its message
            # names both.
            message = self._archive.truncated
            if self._archive.damaged is not None:
                message += f"; also {self._archive.damaged}"
            raise TruncatedError(
                message,
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )
        if self._archive.damaged is not None:
            # A member header failed its CRC after these members: the same terminal
            # damage after the prefix, reported as corruption rather than a cut.
            raise CorruptionError(
                self._archive.damaged,
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )
        self._emit_end_block_missing()
        self._emit_end_block_damaged()
        self._emit_trailing_data()

    @property
    def _in_set(self) -> bool:
        """Whether this archive is a volume set, which decides how diagnostics name it."""
        return self._archive.is_volume or self._volume_count > 1

    def _emit_end_block_damaged(self) -> None:
        """Report each volume whose end-of-archive block failed its header CRC.

        The block sits after the last member, so the listing keeps every member and
        they read normally; this is reported after them, once per damaged block,
        and a ``RAISE`` disposition refuses after delivery. ``observed_bytes`` is
        where the block starts in its volume. The walk did not follow the damaged
        block's next-volume flag, so a set continued past that volume only where a
        member's own header said its data continues.
        """
        for index, offset in sorted(self._archive.end_block_damaged_volumes.items()):
            if self._in_set:
                detail = (
                    f"the end-of-archive block of volume {index + 1}, at byte "
                    f"{offset}, fails its header CRC. Its flags were not used, so "
                    f"its next-volume flag was not followed."
                )
            else:
                detail = (
                    f"the end-of-archive block at byte {offset} fails its header CRC."
                )
            self._diagnostics_collector.emit(
                code=DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
                message=f"RAR archive is damaged after its last member: {detail}",
                context=ArchiveEofContext(
                    archive_name=self._archive_name,
                    format="rar",
                    expected_marker="end_of_archive_block",
                    expected_bytes=0,
                    observed_bytes=offset,
                    observed_kind="nonzero",
                ),
                logger=logger,
            )

    def _emit_trailing_data(self) -> None:
        """Report each volume with a non-zero byte after its end-of-archive block.

        ``ARCHIVE_TRAILING_DATA`` with ``expected_marker="zeros_to_eof"``, as after a
        TAR trailer or a 7z next header: a warning by default, refused under
        ``DiagnosticPolicy.STRICT`` (DR-3), once per volume. Zero padding is silent,
        since ``rar`` pads volumes with zeros. ``unrar`` says nothing about these
        bytes; 7-Zip warns "There are data after the end of archive" for any tail,
        zeros included. ``observed_bytes`` counts from the end of that volume's end
        block.
        """
        for index, offset in sorted(self._archive.trailing_data_volumes.items()):
            where = f"volume {index + 1} of the set" if self._in_set else "RAR archive"
            self._diagnostics_collector.emit(
                code=DiagnosticCode.ARCHIVE_TRAILING_DATA,
                message=(
                    f"{where[0].upper()}{where[1:]} continues past its end-of-archive "
                    f"block: a non-zero byte appears {offset} bytes after it. The "
                    "listing does not account for it (this file may hold something "
                    "appended to the archive)."
                ),
                context=ArchiveEofContext(
                    archive_name=self._archive_name,
                    format="rar",
                    expected_marker="zeros_to_eof",
                    expected_bytes=0,
                    observed_bytes=offset,
                    observed_kind="nonzero",
                ),
                logger=logger,
            )

    def _emit_end_block_missing(self) -> None:
        """Report RAR5 volumes that end without their end-of-archive block.

        RAR5 writers always close a volume with that block, so a walk that reaches
        end of file without it most likely stopped at a cut on a header boundary: the
        bytes list as a shorter, complete-looking archive. Emitted once, after the
        members, the way TAR reports a missing trailer, so the listing still
        completes and a ``RAISE`` disposition refuses it after delivery.
        """
        missing = self._archive.end_block_missing_volumes
        if not missing:
            return
        if self._in_set:
            where = "volume(s) " + ", ".join(str(index + 1) for index in missing)
        else:
            where = "the archive"
        self._diagnostics_collector.emit(
            code=DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
            message=(
                f"RAR archive may be truncated: {where} ended without the "
                f"end-of-archive block RAR5 writers always write."
            ),
            context=ArchiveEofContext(
                archive_name=self._archive_name,
                format="rar",
                expected_marker="end_of_archive_block",
                expected_bytes=0,
                observed_bytes=0,
                observed_kind="absent",
            ),
            logger=logger,
        )

    def _check_header_metadata_budget(self) -> None:
        """Refuse names and comments whose weight, together, exceeds the metadata budget.

        The header walk has already held each member list to ``max_metadata_bytes``
        as it was built (``rar_parser._append_member``), which bounds the memory of
        the walk. This check is the total for the archive as it will be listed: it
        weighs every member of the final list again (``header_metadata_bytes``) and
        adds the archive comment, before any comment is decoded. It recomputes rather
        than reading the walk's running total because that total is kept per list and
        a comment or owner can reach a member after it was weighed: a RAR 1.5-4
        ``CMT`` or ``UOW`` service header attaches its comment or owner to the member
        before it (``_parse_rar3``), and a split member's parts merge after each
        volume weighed its own list.

        Each compressed comment expands to up to 64 KiB (256 KiB for a RAR 2.9-4
        ``CMT`` header), and ``max_members`` alone lets one archive carry a million
        of them. The header declares every ``unpacked_size`` up front, so the total
        is checked before anything is decoded, and a refused archive spawns no
        ``unrar`` at all. The declared size is a real bound on the decode, not a
        trusted attacker number: ``decompress_rar3_blob`` reads at most
        ``unpacked_size + 1`` bytes from ``unrar`` and discards a result of any other
        length. A comment whose packed bytes are more than its declared size counts
        those instead, since the listing holds them until the decode
        (``comment_metadata_bytes``).

        This bounds comment **bytes**, not the number of ``unrar`` spawns: comments
        that each declare a few bytes still cost one process apiece. Decoding every
        comment in a single ``unrar`` call is tracked separately.

        Refusing, rather than dropping the remaining comments to ``None`` the way an
        undecodable comment is dropped, is the maintainer's ruling (#353, finding F12):
        ``max_metadata_bytes`` means retained metadata on every format, and an over-budget
        listing raises on all of them.
        """
        total = comment_metadata_bytes(self._archive.comment) + sum(
            header_metadata_bytes(info) for info in self._archive.members
        )
        check_metadata_budget(
            self._config.listing_limits,
            total,
            detail=f"RAR names and comments hold or declare {total} bytes",
        )

    def _resolve_rar3_comment(self, comment: str | _Rar3Comment | None) -> str | None:
        """Return a decoded compressed comment, dropping unavailable/invalid payloads.

        The comment is a RAR 1.5-2.x COMMENT subblock or a compressed RAR 2.9-4
        ``CMT`` SERVICE header (:class:`_Rar3Comment`).
        """
        if not isinstance(comment, _Rar3Comment):
            return comment
        if self._decompressor is RarDecompressor.NONE:
            # Decoding it would run a program, which the caller ruled out.
            return None
        # The selected program decodes the comment, ``unar`` included, without the
        # member refusals of ``UnarRarPolicy``: the CRC16 check below catches any wrong
        # or missing output, and a comment that fails it is dropped either way.
        # ``unar`` 1.10.1 decodes the RAR 1.5 comments of ``rar15-comment.rar``
        # correctly, though it returns nothing for that archive's first member.
        try:
            unpacked = decompress_rar3_blob(
                open_pipe=None if self._unar_policy is None else _open_unar_blob_pipe,
                extract_version=comment.extract_version,
                compress_type=comment.compress_type,
                packed=comment.packed,
                unpacked_size=comment.unpacked_size,
                flags=comment.flags,
                crc16=comment.crc16,
            )
        except (
            OSError,
            PackageNotInstalledError,
            subprocess.SubprocessError,
        ):
            # An undecodable comment degrades to None rather than sinking the
            # listing.
            return None
        if unpacked is None:
            return None
        if comment.crc32 is not None:
            if zlib.crc32(unpacked) != comment.crc32:
                return None
        elif zlib.crc32(unpacked) & 0xFFFF != comment.crc16:
            return None
        return decode_rar3_cmt_text(
            unpacked, utf16=comment.utf16, encoding=self._encoding
        )

    def _to_member(self, info: RarMemberInfo, index: int) -> ArchiveMember:
        """Type one member. ``index`` is its position in the walk, the id registration
        stamps, so the diagnostics raised here can name it before it has one."""
        member_type = self._member_type(info)
        version_history = info.is_file_version_history()
        presented = _presented_filename(info)
        member_comment = info.comment
        assert not isinstance(member_comment, _Rar3Comment)
        name = normalize_member_name(
            presented,
            member_type,
            backslash_is_separator=True,
        )
        # raw_name keeps archive-stored path bytes (RAR5 has no ``;n`` in header;
        # RAR3 may store ``path;n`` bytes — we do not rewrite them).
        raw_name = (
            info.orig_filename
            if info.orig_filename is not None
            else info.filename.encode("utf-8", errors="surrogateescape")
        )
        extra, link_target = _rar_member_extra_and_link(info)
        host_os = info.host_os
        create_system = (
            _RAR_HOST_OS_TO_CREATE_SYSTEM.get(host_os, CreateSystem.UNKNOWN)
            if host_os is not None
            else CreateSystem.UNKNOWN
        )
        mode: int | None = None
        windows_attrs: int | None = None
        if info.mode is not None:
            # RAR5 stores attr as a vint (hostile values can exceed C unsigned long).
            # Unix: ArchiveMember.mode is the low 12 permission bits, what
            # stat.S_IMODE keeps; masked directly, as TAR does, since S_IMODE refuses
            # a value wider than its C type with OverflowError.
            # Win32: FILE_ATTRIBUTE_* is a 32-bit field.
            if host_os == _RAR_HOST_OS_UNIX:
                mode = info.mode & 0o7777
            elif host_os == _RAR_HOST_OS_WIN32:
                windows_attrs = info.mode & 0xFFFFFFFF

        owner = info.owner if info.owner is not None else _NO_OWNER
        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=raw_name,
            # An unknown redirect's size field is its target's length. A symlink keeps
            # that as its size, as every format lists a link; an unknown redirect is
            # not a link and holds no data, so it has no size (DR-25's OTHER).
            size=None if info.has_unknown_redirect() else info.file_size,
            compressed_size=info.compress_size,
            modified=info.mtime,
            accessed=info.atime,
            created=_rar_created(info),
            ctime=_rar_ctime(info),
            mode=mode,
            uid=owner.uid,
            gid=owner.gid,
            uname=owner.uname,
            gname=owner.gname,
            compression=_compression_for(info),
            # Fails closed: a member whose header stopped before the encryption
            # record could be ruled out is presented as encrypted. Answering
            # "not encrypted" from a header nobody finished reading is a wrong
            # answer rather than a missing one, which is the class this library
            # ranks worst. ``ArchiveInfo.is_encrypted`` deliberately does *not*
            # follow: see ``_archive_has_encryption``.
            is_encrypted=info.is_encrypted or info.encryption_unknown,
            is_current=not version_history,
            create_system=create_system,
            windows_attrs=windows_attrs,
            hashes=_member_hashes(info),
            link_target=link_target,
            comment=member_comment,
            extra=extra,
            _raw=info,
        )
        self._emit_member_diagnostics(info, member, presented, index)
        return member

    def _emit_member_diagnostics(
        self, info: RarMemberInfo, member: ArchiveMember, presented: str, index: int
    ) -> None:
        """Name-normalization, dropped-header-record, invalid-timestamp and
        tweaked-digest diagnostics.

        All attach onto ``member`` (``attach_to_member=True``) and can raise
        under a strict collector, so this must run before ``_to_member`` returns.
        """
        emit_member_name_normalized(
            self._diagnostics_collector,
            member=member,
            presented_name=presented,
            archive_name=self._archive_name,
            member_id=index,
        )
        self._emit_header_record_diagnostics(info, member.name, member, index)
        if info.is_directory and (member.size or member.compressed_size):
            # rar writes directories with no data and unrar skips any it finds (its
            # directory branch returns before the data). Say so; a read delivers it.
            self._emit_directory_data_ignored(member, index)
        if EXTRA_SPECIAL_FILE_TYPE in member.extra and member.type is MemberType.FILE:
            self._emit_special_file_has_data(member, index)
        if info.has_unknown_redirect():
            self._emit_unknown_redirect(info, member, index)
        if info.rar3_utf8_over_encoding:
            assert self._encoding is not None
            self._emit_name_encoding_inferred(
                member,
                index,
                inferred_encoding="utf-8",
                passed_over=self._encoding,
                message=(
                    f"RAR member name decoded as 'utf-8' rather than "
                    f"{self._encoding!r} (the stored bytes are valid UTF-8): "
                    f"{quoted(member.name)}"
                ),
            )
        for issue in info.timestamp_issues:
            field = _timestamp_field_name(info, issue.field)
            self._emit_timestamp_invalid(member, index, replace(issue, field=field))
        # Pure; same predicate ``_rar_member_extra_and_link`` uses for extra keys.
        if not _crc_is_tweaked(info) or self._unrar_password is not None:
            return
        # No password → cannot forward-transform; surface as unverifiable digests.
        for algo, present in (
            (HashAlgorithm.CRC32, info.crc32 is not None),
            (HashAlgorithm.BLAKE2SP, info.blake2sp_hash is not None),
        ):
            if not present:
                continue
            self._diagnostics_collector.emit(
                code=DiagnosticCode.DIGEST_UNVERIFIABLE,
                message=(
                    f"Cannot verify tweaked RAR5 {algo} without a password "
                    f"(ConvertHashToMAC); skipping integrity check for it."
                ),
                context=DigestContext(
                    archive_name=self._archive_name,
                    member_name=member.name,
                    member_id=index,
                    algorithm=algo.value,
                    reason="tweaked_checksum",
                ),
                member=member,
                attach_to_member=True,
                logger=integrity_logger,
            )

    def _resolve_file_copies(self) -> None:
        """Point each RAR5 file copy's ``link_target_member`` at its source.

        The source is the latest member before the copy whose name the stored target
        names (read as a hard link's target is: archive-root relative), and it must be a
        ``FILE``. A target that ``..``-escapes the archive root names no source
        (``within_root``): extraction writes a copy from its source's bytes and does not
        refuse it for a refused source, as it refuses a hard link. ``rar`` always writes
        the source first, and ``unrar`` copies from a file it has already extracted, so
        only earlier members count; that also rules out a copy of itself and any cycle.
        A source that is itself a copy stands for its own source, so a chain collapses
        to the one member that holds the bytes. A copy left unresolved stays listed and
        raises ``LinkTargetNotFoundError`` when read (:meth:`_open_file_copy`).
        """
        latest: dict[str, ArchiveMember] = {}
        for member in self._members:
            raw = member._raw
            assert isinstance(raw, RarMemberInfo)
            if raw.is_file_copy() and member.link_target:
                target_name = resolve_link_target_name(
                    member.name,
                    member.link_target,
                    MemberType.HARDLINK,
                    within_root=True,
                )
                source = latest.get(target_name) if target_name is not None else None
                if source is not None and source.type is MemberType.FILE:
                    source_raw = source._raw
                    assert isinstance(source_raw, RarMemberInfo)
                    member.link_target_member = (
                        source.link_target_member
                        if source_raw.is_file_copy()
                        else source
                    )
            latest[member.name] = member

    def _open_file_copy(
        self,
        member: ArchiveMember,
        kept: Callable[[ArchiveMember], BinaryIO | None] | None = None,
    ) -> MemberStreamParts:
        """Serve a RAR5 file copy from its source member.

        A copy carries no data stream: ``unrar p`` emits nothing for it in a full run
        and ``unar`` emits nothing at all, so the bytes are the source's, read and
        verified as the source. The copy's own CRC32 covers zero bytes
        (``_member_hashes``); its declared size must match the source's, or the copy
        would read as a different length than it lists.

        A solid pass passes ``kept``, which returns the source's bytes as the pass
        decoded them (:class:`FileCopySources`), or ``None`` when it did not keep
        them; only then is the source opened by name, which decodes the solid stream
        again up to it.
        """
        source = member.link_target_member
        if source is None:
            raise LinkTargetNotFoundError(
                "The source of this RAR file copy is not an earlier file member of "
                "the archive",
                reason=LinkTargetNotFoundReason.UNRESOLVED,
                archive_name=self._archive_name,
                member_name=member.name,
                link_target=member.link_target,
            )
        if source.size != member.size:
            raise CorruptionError(
                f"This RAR file copy declares {member.size} bytes but its source "
                f"{quoted(source.name)} declares {source.size}.",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            )
        stream = kept(source) if kept is not None else None
        if stream is None:
            return self._open_member(source)
        # Checked as the source's bytes from the pipe are; not counted as decoded
        # output, since the pass already counted them once.
        hashes, vsize, transforms, verify_member = self._payload_verify_args(source)
        return self._member_parts(
            self._watch_unverified(stream, source),
            member.name,
            size=member.size,
            track_output=False,
            expected_hashes=hashes,
            expected_size=vsize,
            digest_transforms=transforms,
            verify_member=verify_member,
        )

    def _file_copy_sources(self, copies: FileCopyPass) -> FileCopySources | None:
        """What a solid pass keeps for its file copies, or ``None`` when it keeps nothing:
        it has no copies, or it yields none of their streams."""
        if not copies.streams:
            return None
        sources = {
            id(source): source
            for m in self._members
            if isinstance(m._raw, RarMemberInfo)
            and m._raw.is_file_copy()
            and (source := m.link_target_member) is not None
        }
        if not sources:
            return None
        keep_source = copies.keep_source
        return FileCopySources(
            frozenset(sources),
            self._try_spool,
            self._release_spool,
            keep=None if keep_source is None else lambda key: keep_source(sources[key]),
        )

    def _pass_file_copy_stream(
        self,
        member: ArchiveMember,
        sources: FileCopySources | None,
        advance_past: Callable[[int], object],
        pass_costs: dict[int, _DictionaryCost],
    ) -> ArchiveStreamImpl:
        """A solid pass's lazy stream for a file copy, served from its kept source."""

        def kept(source: ArchiveMember) -> BinaryIO | None:
            if sources is None:
                return None
            # Reaching the source may start the pass's process or decode through
            # it, so the source's dictionary is checked as its own read would be.
            cost = pass_costs.get(id(source))
            if cost is not None:
                self._check_dictionary_memory(source, cost)
            return sources.open(id(source), advance_past)

        # Not registered: the pass holds the live-stream slot for all of its streams
        # (``_iter_stream_members``).
        return self._wrap_member_stream(
            member.name,
            lambda: self._open_file_copy(member, kept),
            size=member.size,
            # ``_open_file_copy`` returns parts; see _lazy_member_stream.
            track_output=False,
            seekable=self._seek_declared(),
        )

    @staticmethod
    def _member_type(info: RarMemberInfo) -> MemberType:
        if info.has_unknown_redirect():
            # ``unrar`` creates nothing for it, under the directory flag too, and its
            # pipe carries no bytes for it.
            return MemberType.OTHER
        if info.is_directory:
            return MemberType.DIRECTORY
        if info.is_file_copy():
            # Extracted as an independent file, as ``unrar`` does, not as a link.
            return MemberType.FILE
        if info.is_hardlink_or_copy:
            return MemberType.HARDLINK
        if info.is_symlink:
            return MemberType.SYMLINK
        if _rar_special_file_type(info) is not None and info.file_size == 0:
            # A device, FIFO or socket with no data, typed OTHER as in every format.
            # rar itself skips these when archiving; only a hand-built header carries
            # one. With data the entry is a FILE, its bytes the content (DR-25);
            # ``extra["special_file_type"]`` keeps the stored type either way.
            return MemberType.OTHER
        return MemberType.FILE

    def _iter_with_data(
        self, copies: FileCopyPass = DEFAULT_FILE_COPY_PASS
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        if not self._archive.is_solid or self._decompressor is RarDecompressor.NONE:
            # Nonsolid: default lazy per-member named opens (never ALL-pipe demux).
            # With no program, each member is read directly or refused on its own.
            yield from super()._iter_with_data(copies)
            return
        if self._unar_policy is not None:
            yield from self._iter_solid_with_unar(self._unar_policy, copies)
            return

        # Bare ``unrar p`` omits ``-ver`` history from the ALL pipe; pass ``-ver``
        # when any versioned payload FILE is present so demux stays aligned.
        version_control = any(
            isinstance(m._raw, RarMemberInfo)
            and m._raw.is_payload_file()
            and m._raw.is_file_version_history()
            for m in self._members
        )

        def _spawn() -> BinaryIO:
            password = self._archive_data_password()
            path = self._ensure_archive_path()
            proc, stdout = open_unrar_p(
                path,
                password=password,
                version_control=version_control,
                rar5=self._archive.version == 5,
            )
            # Each payload member in the pipe is verified individually (CRC/BLAKE2sp
            # and declared length via fused ArchiveStream verify), so the pipe-level
            # unrar exit code is redundant for corruption and is suppressed here to
            # avoid legacy-format false positives; wrong-password (11) still maps,
            # and so does RAR4's wrong-password exit 2/3 with nothing emitted,
            # which is why the pipe is told whether the archive is encrypted.
            return _UnrarOwnedStream(
                stdout,
                proc,
                has_verifiable_hash=True,
                encrypted=self._archive_has_encryption,
            )

        pipe_offset = 0

        def _plan(
            member: ArchiveMember, raw: RarMemberInfo, size: int, _: bool
        ) -> int | Callable[[], BinaryIO] | None:
            unknown_version = raw.unknown_compression_version()
            if unknown_version is not None:
                # ``unrar p`` writes nothing for it ("Unknown method") and raises
                # on its first read.
                def _refused() -> BinaryIO:
                    raise self._unknown_compression_error(member, unknown_version)

                return _refused
            if id(raw) in self._solid_after_unknown:
                # ``unrar p`` stopped at the unknown member, so the pipe holds
                # nothing for this one. Served as ``open()`` serves it: read by
                # archivey when stored, refused as unsupported otherwise.
                return None
            # ``unrar p`` writes every other payload member, in listing order.
            nonlocal pipe_offset
            member_offset = pipe_offset
            pipe_offset += size
            return member_offset

        yield from self._drive_solid_pass(copies, _spawn, _plan)

    def _drive_solid_pass(
        self,
        copies: FileCopyPass,
        spawn: Callable[[], BinaryIO],
        plan: Callable[
            [ArchiveMember, RarMemberInfo, int, bool],
            int | Callable[[], BinaryIO] | None,
        ],
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """The solid pass over one process's output, demultiplexed by offset.

        ``spawn`` starts the process and returns its output stream. ``plan`` gets each
        payload member, its stream size and whether it has a digest to check, and
        returns the member's offset in that output, an ``open_fn`` that serves it
        some other way, or ``None`` to serve it exactly as ``open()`` does (a member
        the output does not hold). A plain ``int | Callable | None`` is enough for
        that answer; no slot type is needed.

        ``plan`` may keep a running cursor (the ``unrar`` pass does). This driver
        calls it once for every payload member that gets past the earlier branches,
        in listing order. It never calls it for a file copy, a non-payload member,
        or a member that runs into a missing volume (only the last member present
        can, so skipping it shifts no later offset). The rule a cursor-keeping
        ``plan`` must keep is that it advances the cursor only for a member the
        output carries, and answers ``None`` (or an ``open_fn``) without advancing
        it for one the output does not; advancing it for such a member would shift
        every later offset.
        """
        solid: SolidBlockReader | None = None
        sources = self._file_copy_sources(copies)
        pass_costs = self._pass_dictionary_costs()

        def _pipe() -> SolidBlockReader:
            """Spawn the process on the first read into the pass, not at pass start.

            A caller that iterates the pass without reading any member — listing a
            solid RAR through ``stream_members``, or an extraction whose selector
            matches nothing — never spawns a process and is never asked for a
            password. The stream-source copy lives here too, so that caller also
            writes nothing.
            """
            nonlocal solid
            if solid is None:
                owned = spawn()
                with _close_on_error(owned):
                    tracked = self._track_decompressed(owned)
                with _close_on_error(tracked):
                    solid = SolidBlockReader(
                        tracked if sources is None else sources.tee(tracked)
                    )
            return solid

        def _open(member: ArchiveMember) -> ArchiveStreamImpl | None:
            # Read straight from the archive (RAR3/4 stores the target as plain
            # member data), not through the pipe, so its offsets do not move.
            self._read_pass_link_target(member)
            raw = member._raw
            assert isinstance(raw, RarMemberInfo)
            if raw.is_file_copy():
                # Not in the pipe; served from its source's bytes, kept as the pipe
                # passed them, so the solid stream is not decoded again for it.
                return self._pass_file_copy_stream(
                    member,
                    sources,
                    lambda end: _pipe().open_member(end, 0),
                    pass_costs,
                )
            if member.type is MemberType.DIRECTORY:
                # ``unrar p`` writes nothing for a directory, so declared directory
                # data is not in the pipe and takes no offset in it. It is served
                # as ``open()`` serves it: sliced from the archive when stored and
                # unencrypted, refused on the first read otherwise.
                return (
                    self._lazy_member_stream(member, register=False)
                    if pass_has_data(member)
                    else None
                )
            if not raw.is_payload_file() or not member.is_file:
                return None
            size = _member_stream_size(member)
            hashes, vsize, transforms, verify_member = self._payload_verify_args(member)
            slot: int | Callable[[], BinaryIO]
            missing = self._missing_data_error(member, raw)
            if missing is not None:
                # Every member from the first missing volume on is refused here,
                # and the output ends at that volume, so leaving them out of
                # ``plan`` shifts no offset a member before it is read at.
                def _refused() -> BinaryIO:
                    error = self._missing_data_error(member, raw)
                    assert error is not None
                    raise error

                slot = _refused
            else:
                planned = plan(member, raw, size, bool(hashes))
                if planned is None:
                    return self._lazy_member_stream(member, register=False)
                slot = planned
                # The pass has no native-decrypt or unsettled-plaintext branch: every
                # member it does not slice directly and ``plan`` does not hand back
                # to ``open()`` (above) is served from the program's output, stored
                # encrypted ones included. So for the members that reach here this
                # one test is the whole of "a member a program would decode".
                # ``plan`` still runs for a cut member, so the offsets of any member
                # listed after it do not move.
                if (
                    not self._can_direct_read(raw)
                    and self._cut_data_error(member, raw) is not None
                ):

                    def _cut() -> BinaryIO:
                        error = self._cut_data_error(member, raw)
                        assert error is not None
                        raise error

                    slot = _cut
            open_fn: Callable[[], BinaryIO]
            if isinstance(slot, int):
                offset = slot
                if sources is not None and sources.is_source(id(member)):
                    sources.register(id(member), offset, size)
                cost = pass_costs[id(member)]

                def open_fn() -> BinaryIO:
                    # Checked on the first read, as the spawn is: a pass that skips
                    # this member is not refused for it. Verify is fused into the
                    # outer ArchiveStream, so a never-opened handle skips verify on
                    # close (no solid positioning, and no process, for unread members).
                    self._check_dictionary_memory(member, cost)
                    return self._watch_unverified(
                        _pipe().open_member(offset, size, lazy=True), member
                    )

            else:
                open_fn = slot
            # Not registered, as the base class's pass streams are not: the pass holds
            # the live-stream slot for all of them (``_iter_stream_members``).
            return self._wrap_member_stream(
                member.name,
                open_fn,
                size=member.size,
                track_output=False,
                seekable=False,
                expected_hashes=hashes,
                expected_size=vsize,
                digest_transforms=transforms,
                verify_member=verify_member,
            )

        def _cleanup() -> None:
            try:
                if solid is not None:
                    solid.close()
            finally:
                if sources is not None:
                    sources.close()

        yield from self._drive_pass_streams(
            self._listed_members(),
            open_member=_open,
            close_previous=True,
            cleanup=_cleanup,
        )

    def _translate_exception(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, EOFError):
            return TruncatedError("RAR solid stream ended before the requested member")
        return None

    def _tweaked_verify_spec(
        self, info: RarMemberInfo
    ) -> (
        tuple[
            dict[HashAlgorithm, bytes],
            dict[HashAlgorithm, Callable[[bytes], bytes]],
        ]
        | None
    ):
        """Build ``(expected, digest_transforms)`` for tweaked RAR5 checksums.

        Returns ``None`` when checksums are not tweaked, no password is available, or
        the password is provably wrong (PswCheck). Expected values are the *stored*
        (already tweaked) digests; transforms apply ``ConvertHashToMAC`` to the
        plaintext digest before compare.
        """
        if not _crc_is_tweaked(info):
            return None
        enc = info.file_encryption
        if enc is None:
            return None
        if _psw_check_usable(enc):
            # The candidate the check accepts, not the first one: the first may be
            # another member's password, and its HashKey would fail good data.
            # Never prompts; a provider's answer is here once a read asked for it.
            checked = self._checked_password(enc, None, ask_provider=False)
            if checked is None:
                return None
            hash_key = rar5_hash_key(
                _password_as_str(checked) or "",
                enc.salt,
                enc.kdf_count,
                kdf_cache=self._kdf_cache,
            )
        else:
            password = self._unrar_password
            if password is None:
                return None
            hash_key = _tweaked_hash_key(enc, password, self._kdf_cache)
            if hash_key is None:
                return None
        expected: dict[HashAlgorithm, bytes] = {}
        transforms: dict[HashAlgorithm, Callable[[bytes], bytes]] = {}
        if info.crc32 is not None:
            expected[HashAlgorithm.CRC32] = crc32_digest(info.crc32)
            transforms[HashAlgorithm.CRC32] = lambda digest, hk=hash_key: crc32_digest(
                convert_crc_to_mac(int.from_bytes(digest, "big"), hk)
            )
        if info.blake2sp_hash is not None:
            expected[HashAlgorithm.BLAKE2SP] = info.blake2sp_hash
            transforms[HashAlgorithm.BLAKE2SP] = lambda digest, hk=hash_key: (
                convert_blake2sp_to_mac(digest, hk)
            )
        if not expected:
            return None
        return expected, transforms

    def _emit_unknown_redirect(
        self, info: RarMemberInfo, member: ArchiveMember, member_id: int
    ) -> None:
        """Report ``MEMBER_TYPE_UNKNOWN`` for a RAR5 redirect of a type this reader
        does not know. ``unrar`` warns too ("Unknown extra field") and skips it."""
        assert info.file_redir is not None
        stored_type = str(info.file_redir[0])
        self._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_TYPE_UNKNOWN,
            message=(
                f"RAR member {quoted(member.name)} is a redirect of the unknown type "
                f"{stored_type}: it holds no data, so it is listed as OTHER and not "
                "extracted, as unrar skips it."
            ),
            context=UnknownMemberTypeContext(
                archive_name=self._archive_name,
                member_name=member.name,
                member_id=member_id,
                stored_type=stored_type,
                size=member.size,
            ),
            member=member,
            attach_to_member=True,
        )

    def _emit_header_record_diagnostics(
        self,
        info: RarMemberInfo | DamagedServiceHeader,
        name: str,
        member: ArchiveMember | None,
        member_id: int | None = None,
    ) -> None:
        """Report what a RAR5 extra-area walk dropped, and why it stopped, a
        RAR 1.5-4 ``UOW`` owner header that held no owner, and a ``QO`` header whose
        FILE copies matched no header the walk reached.

        ``member`` is ``None`` for a SERVICE header (``CMT``, ``QO``), which is not
        a listed member and so has nothing to attach to. It still comes through
        here: the same leniency applies to its header, and the argument for
        dropping a record rather than refusing the archive is that the diagnostic
        is emitted and ``ARCHIVE_INTEGRITY_CODES`` makes a strict policy refuse.
        A service header that said nothing was the one place that argument did not
        hold.

        The two cases do not get the same words. A member's is about a member that
        was listed; a service header's is about a header that is in no listing, and
        what a reader wants to know is which of the archive's own answers went
        missing with it. Sharing the wording named ``CMT`` as a member the caller
        could then not find, and never mentioned the comment it had withheld. The
        context follows the same split: ``member_name`` is empty and ``member_id``
        is ``None`` for a service header, because there is no member to name. For a
        member, ``member_id`` is its position in the walk, the id registration stamps.
        """
        attach = member is not None
        context_name = name if member is not None else ""
        for record, record_id, reason in info.skipped_header_records:
            named = record if record_id is None else f"{record} ({record_id})"
            if record == RAR5_UNPLACED_BYTES:
                message = (
                    f"This RAR5 member's header has {reason}, which no writer "
                    "leaves; they were not read, as unrar does not read them."
                    if member is not None
                    else f"This archive's {name} service header has {reason}, "
                    "which no writer leaves; they were not read."
                )
            elif record == RAR5_QO_UNMATCHED_COPIES:
                message = (
                    f"This archive's {name} quick-open service header holds "
                    f"{reason}. rar writes no copy that matches no header, so this "
                    "record is damaged or crafted. The listing comes from the "
                    "headers the walk read, which is what unrar lists too."
                )
            elif record == RAR3_UOW_NAME:
                message = (
                    f"This member's RAR 1.5-4 UOW owner header has {reason}, so "
                    "unrar applies no owner from it; the member is listed without one."
                )
            elif member is not None:
                message = (
                    f"RAR5 extra record {named} is malformed and was dropped "
                    f"({reason}); the member is listed without what it carried."
                )
            else:
                message = (
                    f"RAR5 extra record {named} in this archive's {name} "
                    f"service header is malformed and was dropped ({reason}); "
                    f"the header was read without what it carried."
                )
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=message,
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=context_name,
                    member_id=member_id,
                    record=record,
                    record_id=record_id,
                    reason=reason,
                ),
                member=member,
                attach_to_member=attach,
                logger=logger,
            )
        stop_reason = info.header_walk_stop_reason
        if stop_reason is not None:
            # One diagnostic saying the header was abandoned, rather than one per
            # record past the cap — emitting per record is the cost the cap exists
            # to avoid. Without this a caller sees the capped list and cannot tell
            # it is the whole story. ``list_truncated`` is what they read.
            #
            # The reason comes from the walk because four different faults end it
            # and only one of them is the cap. It is also the only thing that
            # explains why the member may be reported encrypted when nothing in
            # its listing says so, so naming a fault that did not happen costs
            # more here than it would on an ordinary skip.
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=(
                    f"This RAR5 member's header was not read to the end because "
                    f"{stop_reason}; it is listed from what was read before that."
                    if member is not None
                    else f"This archive's {name} service header was not read to "
                    f"the end because {stop_reason}, so {_SERVICE_PAYLOAD_LOST.get(name, 'its payload')} "
                    f"was not used."
                ),
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name=context_name,
                    member_id=member_id,
                    record="",
                    record_id=None,
                    reason=stop_reason,
                    list_truncated=True,
                ),
                member=member,
                attach_to_member=attach,
                logger=logger,
            )

    def _emit_service_header_diagnostics(self) -> None:
        """Report the SERVICE headers (``CMT``, ``QO``) whose walk did not finish,
        and a ``QO`` header whose copies matched no header the walk reached.

        Emitted after the members, so the two kinds are not interleaved in file
        order: a strict policy raises at emit time, so it refuses on a member's
        fault first even where the damaged service header came earlier in the file
        — a ``CMT`` sits right after MAIN, so that is the usual layout. Real file
        order would need each header's offset, which ``DamagedServiceHeader``
        deliberately does not keep.

        The parser caps how many unfinished headers it keeps, so the count of the
        rest is reported too: a cap that silently swallowed the remainder would reopen the hole this
        reporting exists to close.
        """
        for damaged in self._archive.damaged_service_headers:
            self._emit_header_record_diagnostics(damaged, damaged.name, None)
        omitted = self._archive.damaged_service_headers_omitted
        if omitted:
            self._diagnostics_collector.emit(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                message=(
                    f"{omitted} further RAR5 service header(s) in this archive "
                    f"were not read to the end and are not described "
                    f"individually; an archive with this many damaged service "
                    f"headers is crafted rather than merely damaged."
                ),
                context=MemberHeaderRecordContext(
                    archive_name=self._archive_name,
                    member_name="",
                    member_id=None,
                    record="",
                    record_id=None,
                    reason="too many damaged service headers to describe",
                    # Not ``list_truncated``: that flag marks the diagnostic
                    # reporting that one header's own record list was cut short,
                    # and this one is behind no header at all. What was cut short
                    # here is the list of headers, which the message says.
                    list_truncated=False,
                ),
                logger=logger,
            )

    def _payload_verify_args(
        self, member: ArchiveMember
    ) -> tuple[
        Mapping[HashAlgorithm, bytes] | None,
        int | None,
        Mapping[HashAlgorithm, Callable[[bytes], bytes]] | None,
        ArchiveMember | None,
    ]:
        """Return ``(hashes, size, transforms, member)`` for fused verify, or Nones.

        Verify every member's declared length (and any CRC32/BLAKE2sp) as it is
        read. Tweaked RAR5 digests (HASHMAC) use ConvertHashToMAC transforms when
        a password is available.
        """
        expected: Mapping[HashAlgorithm, bytes] = member.hashes
        transforms: Mapping[HashAlgorithm, Callable[[bytes], bytes]] | None = None
        raw = member._raw
        if isinstance(raw, RarMemberInfo):
            tweaked = self._tweaked_verify_spec(raw)
            if tweaked is not None:
                expected, transforms = tweaked
        if member.size is None and not expected:
            return None, None, None, None
        return expected, member.size, transforms, member

    def _payload_parts(
        self,
        inner: BinaryIO,
        member: ArchiveMember,
        *,
        track_output: bool = True,
        rewind_warning: RewindWarning | None = None,
    ) -> MemberStreamParts:
        hashes, size, transforms, verify_member = self._payload_verify_args(member)
        return self._member_parts(
            inner,
            member.name,
            size=member.size,
            track_output=track_output,
            expected_hashes=hashes,
            expected_size=size,
            digest_transforms=transforms,
            verify_member=verify_member,
            rewind_warning=rewind_warning,
        )

    def _is_directly_sliceable(self, info: RarMemberInfo) -> bool:
        """Everything the direct read needs except an answer about encryption.

        Split out so ``_open_member`` can tell a member that genuinely needs
        ``unrar`` from one whose bytes are sitting right there and are held back
        only because the header never settled whether they are ciphertext.
        """
        # The member's own solid flag does not matter here: a stored member's bytes
        # are plaintext where they sit, even inside a solid stream (``rar -s -ms``),
        # and its parts, when split across volumes, are joined in order.
        return info.is_stored and _data_is_reachable(info)

    def _can_direct_read(self, info: RarMemberInfo) -> bool:
        # ``encryption_unknown`` is excluded here rather than refused: slicing the
        # stored bytes and handing them straight back would present ciphertext as
        # plaintext if the unread record was the encryption record, so that member
        # goes through ``_confirm_unsettled_plaintext`` first (see ``_open_member``).
        return (
            self._is_directly_sliceable(info)
            and not info.is_encrypted
            and not info.encryption_unknown
        )

    def _confirm_unsettled_plaintext(
        self, info: RarMemberInfo, member: ArchiveMember
    ) -> None:
        """Prove a cut-short member's stored bytes are plaintext, or raise.

        The member's header stopped before its extra records were read to the end,
        so nothing in it says whether the data is encrypted — and routing to
        ``unrar`` would not settle it either. Measured on unrar 7.00, it reads the
        same damaged header and reaches the same wrong conclusion (``unrar l`` drops
        the encrypted marker); what it actually does is refuse when a digest that
        survived the damage fails against the bytes, and hand them back unverified
        when none survived. Archivey applies the same digest test and refuses the
        second case, which is the maintainer's ruling (see ``format-rar``).

        Which digest survives is the writer's choice, not ours: RAR5 keeps CRC32 in
        the fixed FILE header and BLAKE2sp in the extra area, so a cut area destroys
        one and leaves the other. A surviving digest is a real discriminator because
        an encrypted member's stored digests are key-tweaked (``ConvertHashToMAC``)
        whenever the writer sets that flag, and are the *plaintext* digest when it
        does not — ciphertext matches neither.

        The check runs **before** any byte is handed back, like the ZIP ZipCrypto
        stored path (``_open_stored_confirmed``): both face a member whose framing
        cannot reject wrong bytes incrementally, and a caller that stops reading
        early would otherwise never reach the end-of-stream verdict. The extra pass
        costs one read of an already-damaged member and never touches the happy path.
        """
        hashes, size, transforms, _ = self._payload_verify_args(member)
        # ``member=`` is deliberately omitted: this is a confirmation pass, and any
        # diagnostic it emitted would be attached to the member a second time by the
        # real read that follows.
        verifier = (
            build_member_verifier(
                hashes,
                expected_size=size,
                collector=self._diagnostics_collector,
                archive_name=self._archive_name,
                digest_transforms=transforms,
            )
            if hashes
            else None
        )
        # Two ways to have nothing to go on, and they end the same: the cut took the
        # only digest with it, or the one it left is an algorithm this installation
        # cannot compute. The second matters because such a verifier is dropped
        # silently and would then confirm the member by finding no fault at all.
        if verifier is None or not verifier.expected_algorithms:
            raise CorruptionError(
                "This RAR5 member's header stopped before its extra records were "
                "read to the end, so whether the member is encrypted is unknown, "
                "and no usable checksum survived the damage to tell its stored "
                "bytes from ciphertext. Reading it would risk returning encrypted "
                "bytes as file content.",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            )
        view = self._direct_view(info)
        try:
            while verifier.read(view, _CONFIRM_CHUNK_BYTES):
                pass
        # TruncatedError is a CorruptionError subclass: this clause must stay first.
        except TruncatedError as exc:
            # A member whose bytes end short of its declared size is a truncated
            # member, whatever its header said, and relabelling that as a verdict
            # about encryption would name a cause that did not happen. This pass
            # is interpreting one outcome — the digest — and has nothing to add
            # to the others, so they travel as they would on an ordinary read.
            #
            # Stamped because this pass raises from the open path rather than from
            # a member read, which is where the reader's own boundary would have
            # filled these in: without it the same truncation named the archive
            # and the member on an intact header and named neither on a cut-short
            # one.
            self._stamp_error_context(exc, member.name)
            raise
        except CorruptionError as exc:
            # What is left is the digest verdict. The verifier's other
            # ``CorruptionError`` is an over-run, which cannot happen here: the
            # view is bounded to the member's declared size, so the probe past
            # the end reads ``b""`` however much archive follows.
            raise CorruptionError(
                "This RAR5 member's header stopped before its extra records were "
                "read to the end, so whether the member is encrypted is unknown, "
                "and its stored bytes do not match the checksum that survived the "
                "damage: they are either encrypted or corrupt.",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            ) from exc
        finally:
            view.close()

    def _direct_view(self, info: RarMemberInfo, length: int | None = None) -> BinaryIO:
        # Never past the packed span: whatever the unpacked size claims, the bytes
        # after ``compress_size`` belong to the next header, not to this member.
        # ``_open_member`` refuses a plaintext stored member whose two sizes differ
        # before it gets here. The clamp covers the caller that check does not reach,
        # the unsettled-plaintext path (``_confirm_unsettled_plaintext`` and the read
        # after it): there a member declaring more than it packs ends short, and the
        # size check reports it as truncated.
        size = min(info.file_size, info.compress_size) if length is None else length
        if not info.data_parts:
            return self._shared.view(info.data_offset, size)
        # A member split across volumes: its parts, in order, then cut to ``size``.
        views: list[BinaryIO] = []
        remaining = size
        for offset, part_size in info.data_parts:
            if remaining <= 0:
                break
            take = min(part_size, remaining)
            views.append(self._shared.view(offset, take))
            remaining -= take
        if not views:
            return self._shared.view(info.data_offset, 0)
        return JoinedViews(views)

    def _ensure_link_target(self, member: ArchiveMember) -> None:
        if member.type != MemberType.SYMLINK or member.link_target is not None:
            return
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if raw.file_redir is not None:
            member.link_target = _rar5_redirect_target(raw.file_redir)
            return
        # RAR4: symlink target stored as M0 member data (even when file_solid).
        if (
            raw.is_stored
            and not raw.is_encrypted
            and not raw.encryption_unknown
            # Either size: a header where only one is zero is damage, refused below,
            # not an archive that recorded no target.
            and (raw.file_size > 0 or raw.compress_size > 0)
            and _data_is_reachable(raw)
        ):
            # As for the member read, neither a solid flag nor a split holds the
            # target back: a stored target needs no decoder, and split parts are
            # joined in order. ``encryption_unknown`` needs no arm in
            # the reason chain below: only the RAR5 extra-area walk sets it, and a
            # RAR5 symlink has ``file_redir`` and returned above.
            #
            # A stored target is its packed bytes, so the two sizes must agree, as
            # ``_open_member`` requires of any stored member. A header that declares
            # more would have the read take the next header, and whatever follows
            # it, as the target. This comes before the cap below, so a header whose
            # sizes disagree is reported as damage rather than as an oversized target
            # it does not hold.
            if raw.file_size != raw.compress_size:
                raise CorruptionError(
                    "The stored symlink target's declared size "
                    f"({raw.file_size} bytes) does not match its packed size "
                    f"({raw.compress_size} bytes)",
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.RAR,
                )
            # Stored, so the read is the header's own size and cannot amplify; it is
            # still held to the cap every data-stored target is, and an oversized one
            # is refused before any of it is read.
            if raw.file_size > MAX_LINK_TARGET_BYTES:
                self._emit_link_target_too_long(member)
                return
            view = self._direct_view(raw, raw.file_size)
            try:
                data = view.read()
            finally:
                view.close()
            # The header's data CRC32 covers these bytes, and the header CRC does not,
            # so past the size check above this is the only check a damaged target
            # meets. Held to it as ZIP and 7z hold theirs: a mismatch raises, and the
            # listing, or a pass when it reaches the link, lists the link targetless
            # (`_report_unreadable_link_target`) while open/extract re-raise.
            # A short read is caught by the same comparison. Encrypted members never
            # reach here, so the CRC is never a RAR5 key-tweaked one.
            if raw.crc32 is not None and zlib.crc32(data) != raw.crc32:
                raise CorruptionError(
                    "The stored symlink target does not match its CRC32 checksum",
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.RAR,
                )
            member.link_target = data.decode("utf-8", errors="surrogateescape")
            return
        if raw.is_encrypted and self._natively_decryptable(raw) and _crypto_available():
            # Stored and encrypted: decrypted here as ``open()`` would, so with the
            # password the target lists as it does from a plain archive, and without
            # it the link is reported as locked (``password_required``), as in ZIP and
            # 7z. The read is capped like any data-stored target. A target with both
            # sizes zero passes ``_natively_decryptable``, decrypts to no bytes and is
            # reported by the shared empty-target check (``target_empty``), not by
            # the ``no_target_data`` arm below.
            self._link_target_from_data(
                member,
                lambda: self._member_stream(
                    self._open_encrypted_link_target(member, raw)
                ),
                reparse_fallback=None,
            )
            return
        # Encrypted / compressed target without usable direct bytes: leave unset. The
        # reason still has to reach the caller — `SYMLINK_TARGET_UNAVAILABLE` is in
        # `ARCHIVE_INTEGRITY_CODES`, so a strict policy refuses the archive, and a
        # lenient one gets a diagnostic instead of a link whose absence is unexplained.
        #
        # Only the last of these is the archive recording no target; the other three
        # are targets this direct read cannot reach, and the member keeps the
        # per-member failure it had before `LINK_TARGET_UNAVAILABLE` existed. The
        # encrypted one is a target archivey cannot decrypt itself (compressed, split,
        # RAR 2.0's cipher, or no ``cryptography``) rather than a missing password, so
        # it does not claim that a password would help.
        if raw.is_encrypted:
            reason = "target_data_encrypted"
            if self._natively_decryptable(raw):
                detail = "its data is encrypted and cryptography is not installed"
            else:
                detail = "its data is encrypted in a form archivey does not decrypt"
            in_archive = True
        elif not _data_is_reachable(raw):
            reason = "target_data_split_across_volumes"
            detail = "its data is split across volumes and not every part was found"
            in_archive = True
        elif not raw.is_stored:
            reason = "target_data_compressed"
            detail = "its data is compressed rather than stored"
            in_archive = True
        else:
            reason = "no_target_data"
            detail = "it carries no data"
            in_archive = False
        self._emit_link_target_unavailable(
            member,
            reason=reason,
            message=(
                f"Cannot read the symlink target of {quoted(member.name)} because {detail}; "
                f"leaving link_target unset."
            ),
            target_in_archive=in_archive,
        )
        return

    def _unrar_names(self) -> _UnrarNames:
        names = self._unrar_names_cache
        if names is not None:
            return names
        rar5 = self._archive.version == 5
        views: list[str | None] = []
        positions: dict[int, int] = {}
        by_key: dict[str, list[int]] = {}
        unknown: list[int] = []
        for position, member in enumerate(self._members):
            positions[id(member)] = position
            raw = member._raw
            if not isinstance(raw, RarMemberInfo) or not raw.is_payload_file():
                views.append(None)
                continue
            view = unrar_member_view(
                rar5=rar5,
                stored=raw.orig_filename,
                rar3_unicode_name=raw.rar3_unicode_name,
                host_os=raw.host_os,
                file_version=raw.file_version,
            )
            views.append(view)
            if view is None:
                unknown.append(position)
                continue
            for key in unrar_selection_keys(view):
                by_key.setdefault(key, []).append(position)
        names = _UnrarNames(views, positions, by_key, unknown)
        self._unrar_names_cache = names
        return names

    def _unrar_selection(
        self, target: ArchiveMember, mask_view: str, *, version_control: bool
    ) -> tuple[int, bool, _DictionaryCost]:
        """Where ``target``'s bytes start in the ``unrar -n`` pipe, and what the run needs.

        ``unrar p`` emits every payload member the mask selects, concatenated in
        archive order with no headers: a glob, a duplicate name, two names ``unrar``
        cuts or converts to the same text, a mask that names a directory prefix of
        another member. The first value is the unpacked size of the members before
        the target; the second is True when any other member is selected, so the read
        must stop at the target's size. History rows are left out unless
        ``version_control`` is set, as ``unrar`` leaves them out without ``-ver``.

        The third value is the largest :attr:`_dictionary_costs` entry among the
        target and the selected members before it. ``unrar`` decodes each of those
        in full, so in a nonsolid archive each earlier match sizes its own window.
        In a solid archive the target's own count already covers them. A match after
        the target does not count: the read stops at the target's end, and that
        member's window fills only as ``unrar`` writes to the pipe.

        When the selection up to the target depends on whether this ``unrar`` lets a
        ``.`` in the mask match nothing, it asks the binary once
        (:func:`unrar_dot_rule`, cached per binary path and stat identity), so this
        step may spawn ``unrar`` on an embedded archive.

        Raises :class:`_UnrarCannotAddress` when the answer is not known, so that
        ``AUTO`` can hand the member to ``unar``: the mask does not select the
        target itself, an earlier member's name cannot be read the way ``unrar``
        reads it on this host, or the dot-rule probe gave no answer. Raises
        ``PackageNotInstalledError`` from :func:`find_rarlab_unrar` when it has to
        probe and no ``unrar`` is found.
        """
        names = self._unrar_names()
        target_position = names.positions[id(target)]
        keys = unrar_mask_keys(mask_view)
        candidates: Iterable[int]
        if keys is None:
            candidates = range(len(self._members))
        else:
            found: set[int] = set()
            for key in keys:
                found.update(names.by_key.get(key, ()))
            candidates = sorted(found)
        considered: list[int] = []
        for position in candidates:
            if names.views[position] is None:
                continue
            raw = self._members[position]._raw
            assert isinstance(raw, RarMemberInfo)
            if raw.is_file_version_history() and not version_control:
                continue
            considered.append(position)
        # unrar 7.30 beta 2 dropped the rule that lets a "." in the mask match
        # nothing (:func:`unrar_dot_rule`). Without it a mask selects a subset of
        # what it selects with it (the rule only ever adds a match), so the second
        # pass needs only the first one's result. Ask the binary which rule it has
        # only when the two disagree up to the target: a member after it changes
        # neither the skip nor the cost, and counting it in ``others`` under either
        # rule only bounds the read, which is safe.
        with_dot_rule = self._unrar_selected(mask_view, considered, dot_rule=True)
        selected = with_dot_rule
        if unrar_dot_rule_can_matter(mask_view):
            without_dot_rule = self._unrar_selected(
                mask_view, with_dot_rule, dot_rule=False
            )
            up_to_target = [p for p in with_dot_rule if p <= target_position]
            if up_to_target != [p for p in without_dot_rule if p <= target_position]:
                dot_rule = unrar_dot_rule()
                if dot_rule is None:
                    # The binary on PATH is the trouble, not the archive, so AUTO
                    # may still read the member with unar (DR-11).
                    raise _UnrarCannotAddress(
                        self._unrar_name_refused(
                            target,
                            "the members unrar selects with this mask depend on how "
                            "it matches a '.', and this unrar did not answer the "
                            "probe for it",
                        )
                    )
                if not dot_rule:
                    selected = without_dot_rule
        prefix = 0
        others = False
        selects_target = False
        cost = self._dictionary_costs[id(target)]
        for position in selected:
            if position == target_position:
                selects_target = True
                continue
            others = True
            if position < target_position:
                earlier = self._members[position]
                prefix += _member_stream_size(earlier)
                cost = _larger_cost(cost, self._dictionary_costs[id(earlier)])
        # The target drops out when it matched only through a dot rule this binary
        # lacks, or when archivey's port of unrar's matcher and unrar disagree.
        # Neither refusal below is about the archive: unar names entries by index,
        # so AUTO may still read the member with it (DR-11).
        if not selects_target:
            raise _UnrarCannotAddress(
                self._unrar_name_refused(
                    target,
                    "the name unrar reads for it cannot be given back to unrar as a "
                    "mask",
                )
            )
        for position in names.unknown:
            raw = self._members[position]._raw
            assert isinstance(raw, RarMemberInfo)
            if raw.is_file_version_history() and not version_control:
                continue
            if position < target_position:
                raise _UnrarCannotAddress(
                    self._unrar_name_refused(
                        target,
                        "an earlier member's name cannot be read the way unrar reads "
                        "it on this system, so the bytes unrar may send before this "
                        "member cannot be sized",
                    )
                )
            others = True
        return prefix, others, cost

    def _unrar_selected(
        self, mask_view: str, candidates: list[int], *, dot_rule: bool
    ) -> list[int]:
        """The positions among ``candidates`` that the mask selects under ``dot_rule``."""
        views = self._unrar_names().views
        selected: list[int] = []
        for position in candidates:
            view = views[position]
            assert view is not None, "_unrar_selection drops members with no view"
            if unrar_mask_selects(mask_view, view, dot_rule=dot_rule):
                selected.append(position)
        return selected

    def _unrar_name_refused(
        self, member: ArchiveMember, reason: str
    ) -> UnsupportedFeatureError:
        return UnsupportedFeatureError(
            f"RAR member {quoted(member.name)} cannot be read through unrar: "
            f"{reason}. {UNAR_BY_POSITION_HINT}",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _solid_run(self, member: ArchiveMember) -> SolidRun | None:
        # Each open() of a solid member runs a fresh process. Through its include
        # mask, unrar decodes the archive from its first payload member. unar decodes
        # only the member's solid stream, which starts at a compressed member without
        # the solid flag, and skips stored members (``unar_dictionary_costs``). The
        # rare unar read of a name unrar cannot address under AUTO is counted as
        # unrar's.
        raw = member._raw
        if (
            not self._archive.is_solid
            or not isinstance(raw, RarMemberInfo)
            or not raw.is_payload_file()
            or raw.is_file_copy()
            or self._can_direct_read(raw)
            or self._decrypts_natively(raw)
        ):
            return None
        if self._unar_policy is None:
            return SolidRun(
                None, self._solid_prefix(member), _member_stream_size(member)
            )
        if uses_no_dictionary(raw):
            return None
        return self._unar_solid_runs().get(id(member))

    def _unar_solid_runs(self) -> dict[int, SolidRun]:
        """Each compressed member's :class:`SolidRun` under ``unar``, by ``id``.

        The key is the archive index of the member that starts the solid stream, and
        the offset counts the earlier compressed entries of that stream. Streams are
        cut on :func:`uses_no_dictionary` alone, as ``unar_dictionary_costs`` cuts
        them, so a compressed entry that is not a payload file (a RAR3/4 symlink
        target) still starts a stream and counts toward the offset. Built once.
        """
        runs = self._unar_runs
        if runs is not None:
            return runs
        runs = {}
        start = -1
        offset = 0
        for index, member in enumerate(self._members):
            raw = member._raw
            if not isinstance(raw, RarMemberInfo) or uses_no_dictionary(raw):
                continue
            if not raw.file_solid or start < 0:
                start, offset = index, 0
            size = raw.file_size
            if raw.is_payload_file():
                runs[id(member)] = SolidRun(start, offset, size)
            offset += size
        self._unar_runs = runs
        return runs

    def _solid_prefix(self, target: ArchiveMember) -> int:
        """Unpacked bytes of earlier payload members in a solid archive.

        A named ``unrar p`` or an ``unar -i`` run for a solid member re-decodes this
        prefix even though the pipe only emits the requested member. Zero when the
        archive is not solid — then the run starts at this member and the
        member-stream ``tell()`` is the whole re-decode cost.

        History rows are counted even without ``-ver``. That is not an oversight
        relative to :meth:`_unrar_selection`, which skips them unless
        ``version_control``: ``-ver`` controls what unrar *emits*, not what it
        *decodes*, and a solid chain must decompress history to reach later
        members. This value is a ``RewindWarning.min_redecode_bytes`` floor, not
        a pipe offset.
        """
        if not self._archive.is_solid:
            return 0
        prefix = 0
        for member in self._members:
            raw = member._raw
            if not isinstance(raw, RarMemberInfo) or not raw.is_payload_file():
                continue
            if member is target:
                return prefix
            prefix += _member_stream_size(member)
        # Same payload-only walk as glob skip; _open_member is payload-only.
        raise AssertionError(
            "solid prefix target missing from the payload walk; uses member identity"
        )

    def _unknown_compression_error(
        self, member: ArchiveMember, version: str
    ) -> UnsupportedFeatureError:
        """The refusal for a member compressed with a version ``unrar`` cannot decode.

        ``unrar`` reports "Unknown method" and writes nothing for such a member,
        which used to surface as a truncation. The data is not short: it is in a
        format newer than the decoder, so this is ``UnsupportedFeatureError``, as
        for lzip version 0. Raised before any process is spawned, for both
        decompressors (see :meth:`RarMemberInfo.unknown_compression_version`).
        """
        return UnsupportedFeatureError(
            f"RAR member {quoted(member.name)} is compressed with {version}, which "
            "neither RAR decompressor archivey runs is known to decode (unrar 7.00 "
            'reports "Unknown method"), so switching decompressors does not help; it '
            "may need a newer version of RAR.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _solid_after_unknown_error(
        self, member: ArchiveMember, raw: RarMemberInfo, *, masked_unrar: bool
    ) -> UnsupportedFeatureError | None:
        """The refusal for a member that an unknown-version member ahead of it keeps
        from being decoded, or ``None``.

        When that member is in its solid stream, no program decodes it: decoding it
        means decoding that member first. With ``masked_unrar``, the read is the
        ``unrar`` one, addressed through an include mask, and a member in a later
        solid stream is refused too: with a mask, ``unrar`` decodes a solid archive
        from its start, stops at that member and writes nothing more
        (:func:`solid_after_unknown_compression`). Either used to surface as a
        truncation. Like :meth:`_unknown_compression_error`, this is
        ``UnsupportedFeatureError``, raised before any process is spawned.
        """
        block = self._solid_after_unknown.get(id(raw))
        if block is None or not (block.same_stream or masked_unrar):
            return None
        return UnsupportedFeatureError(
            f"RAR member {quoted(member.name)} cannot be decoded: "
            + solid_after_unknown_compression_reason(block),
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _check_dictionary_memory(
        self,
        member: ArchiveMember,
        cost: _DictionaryCost,
        *,
        program: str | None = None,
    ) -> None:
        """Refuse a read whose decompressor would allocate over ``max_decoder_memory``.

        ``cost`` comes from :attr:`_dictionary_costs`, from :meth:`_unrar_selection`
        for a named ``unrar`` read, or from :meth:`_pass_dictionary_costs` for a
        solid pass. Runs before the program is spawned and before a stream source is
        copied to disk for it.

        The message names the member whose header declared the dictionary, only when
        the member read does not declare that size itself, and says when the count is
        capped below it, so a caller can find both numbers. A declarer that shares the
        read member's name is named by its archive index instead.
        """
        if program is None:
            program = "unar" if self._unar_policy is not None else "unrar"
        counted_from = None
        if cost.declarer >= 0:
            source = self._members[cost.declarer]
            raw = member._raw
            # The member read declaring the same size is named in place of the
            # member that happened to declare it first.
            own = source is member or (
                isinstance(raw, RarMemberInfo) and raw.dictionary_size == cost.declared
            )
            if own:
                owner = "its own header"
            elif source.name == member.name:
                owner = (
                    "the header of an earlier entry with the same name "
                    f"(archive index {cost.declarer}, counting from 0)"
                )
            else:
                owner = f"the header of member {quoted(source.name)}"
            if cost.count < cost.declared:
                counted_from = (
                    f"the {cost.declared}-byte dictionary {owner} declares, capped at "
                    "the unpacked bytes the read decodes"
                )
            elif not own:
                counted_from = f"the dictionary {owner} declares"
        check_decoder_memory(
            cost.count,
            limits=self._config.decoder_limits,
            what=f"the RAR dictionary {program} needs for member {quoted(member.name)}",
            counted_from=counted_from,
            usage=self._usage,
        )

    def _pass_dictionary_costs(self) -> dict[int, _DictionaryCost]:
        """:attr:`_dictionary_costs` for one process that decodes the archive in order.

        A solid pass runs one process over every member, so a member's read also
        pays for the largest window an earlier member needed. ``unar`` starts a new
        dictionary for each solid stream, but the process's peak is still the
        largest one so far.
        """
        costs: dict[int, _DictionaryCost] = {}
        peak = _NO_DICTIONARY
        for member in self._members:
            peak = _larger_cost(peak, self._dictionary_costs[id(member)])
            costs[id(member)] = peak
        return costs

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if raw.is_file_copy():
            return self._open_file_copy(member)
        missing = self._missing_data_error(member, raw)
        if missing is not None:
            raise missing
        unknown_version = raw.unknown_compression_version()
        if unknown_version is not None:
            raise self._unknown_compression_error(member, unknown_version)

        if raw.is_directory and not (
            self._can_direct_read(raw)
            or (raw.encryption_unknown and self._is_directly_sliceable(raw))
        ):
            # unrar emits nothing for a directory entry (``extract.cpp`` returns from
            # the directory branch before any data), so only the directory data
            # archivey slices itself can be delivered: stored and not encrypted (or
            # stored with the encryption question still open, which the digest check
            # below settles). Compressed or encrypted data would reach unrar and
            # come back empty, so it is refused here, as unsupported, not corrupt.
            raise UnsupportedFeatureError(
                f"Directory {quoted(member.name)} declares data that archivey cannot "
                "deliver: unrar does not decode data stored under a directory entry, "
                "so only stored (uncompressed), unencrypted directory data can be read.",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            )
        if self._can_direct_read(raw):
            if raw.compress_size != raw.file_size:
                # A plaintext stored member packs exactly its own bytes; only encryption
                # (padding to the AES block) makes the two sizes differ, and encrypted
                # members never take this path. ``unrar`` trusts the packed size here,
                # the size check trusts the unpacked one, and neither is the member.
                raise CorruptionError(
                    f"This stored RAR member declares {raw.file_size} bytes but packs "
                    f"{raw.compress_size}; a stored member's two sizes must match.",
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.RAR,
                )
            inner: BinaryIO = self._direct_view(raw)
            return self._payload_parts(inner, member)

        if raw.encryption_unknown and self._is_directly_sliceable(raw):
            # This member's bytes are stored and sitting right there; the only thing
            # holding back the slice is that its header stopped before the encryption
            # record, so nothing read so far says whether they are plaintext. A digest
            # that survived the damage can still say, and needs no ``unrar``; when none
            # did, this raises. See ``_confirm_unsettled_plaintext``.
            self._confirm_unsettled_plaintext(raw, member)
            return self._payload_parts(self._direct_view(raw), member)

        if self._decrypts_natively(raw):
            return self._open_decrypted_stored(member, raw)

        cut = self._cut_data_error(member, raw)
        if cut is not None:
            raise cut

        # Only here, on the way to a program: archivey's own reads above do not
        # decode the members before this one. A member of a later solid stream is
        # refused only once the read is known to be ``unrar``'s
        # (:meth:`_open_member_with_program`).
        after_unknown = self._solid_after_unknown_error(member, raw, masked_unrar=False)
        if after_unknown is not None:
            raise after_unknown

        if self._decompressor is RarDecompressor.NONE:
            raise self._no_decompressor_refused(member, raw)

        if not self._natively_decryptable(raw):
            return self._open_member_with_program(member, raw)
        # A stored encrypted member ``cryptography`` would have decrypted here: a
        # missing program is then not the only way to read it, so the error says so.
        try:
            return self._open_member_with_program(member, raw)
        except PackageNotInstalledError as exc:
            raise PackageNotInstalledError(
                f"{raw_message_of(exc)} Or install {CRYPTO_REQUIREMENT.name} "
                f"({CRYPTO_REQUIREMENT.install_hint}): archivey then decrypts this "
                "stored member itself.",
                missing=(*exc.missing, CRYPTO_REQUIREMENT),
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            ) from exc

    def _open_decrypted_stored(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> MemberStreamParts:
        """Serve a :meth:`_natively_decryptable` member by decrypting its stored bytes.

        The password is picked as for an ``unrar`` read: a RAR5 PswCheck rejects a
        wrong one here, and a RAR3/4 candidate list is judged by the CRC over a
        decryption (:meth:`_stored_check`). A single RAR3/4 password goes unjudged,
        as it does to ``unrar``; the digest check at the end of the read is its test,
        and :meth:`_watch_unverified` reports a read abandoned before it. The stream
        seeks: CBC restarts from any block, given the block before it.
        """
        if not _crypto_available():
            raise PackageNotInstalledError(
                CRYPTO_REQUIREMENT.message("decrypting a stored RAR member"),
                missing=(CRYPTO_REQUIREMENT,),
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            )
        params = self._stored_data_cipher(raw, self._stored_data_password(member, raw))
        view = self._direct_view(raw, raw.compress_size)
        with _close_on_error(view):
            plain = open_aes_decrypt_stream(view, params, owns_inner=True)
        with _close_on_error(plain):
            # The ciphertext is padded to whole blocks; the member ends at its
            # unpacked size, and the padding after it is not content.
            trimmed: BinaryIO = SlicingStream(
                plain, length=raw.file_size, owns_inner=True, probe_source_size=False
            )
        with _close_on_error(trimmed):
            watched = self._watch_unverified(trimmed, member)
        with _close_on_error(watched):
            return self._payload_parts(watched, member)

    def _stored_data_password(self, member: ArchiveMember, raw: RarMemberInfo) -> str:
        """The password :meth:`_open_decrypted_stored` decrypts ``member`` with."""
        enc = raw.file_encryption
        password: str | None
        if enc is not None and _psw_check_usable(enc):
            password = self._checked_data_password(enc, member)
        elif self._stored_natively_checkable(raw):
            password = self._unchecked_data_password(member)
        else:
            password = self._unrar_data_password()
        if password is None:
            raise EncryptionError(
                "Password required to read this encrypted member",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            )
        return password

    def _open_encrypted_link_target(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> MemberStreamParts:
        """Open a RAR 2.9-4 symlink's encrypted, stored target for listing.

        RAR 2.9-4 records no password check, so one password goes to the read
        unjudged, and a wrong one decrypts to bytes of the right length. The target
        is small, so its CRC is checked first: a mismatch, or a candidate list whose
        every entry fails it, is a wrong password or damage, which nothing here can
        tell apart, and is reported as such
        (:meth:`_locked_link_target_report`) rather than as a damaged target.
        """
        # A candidate list whose every entry fails the same CRC arrives marked.
        password = self._stored_data_password(member, raw)
        if raw.crc32 is not None and not self._stored_crc_matches(raw, password):
            error = EncryptionError(
                "The decrypted symlink target does not match its CRC32 checksum",
                archive_name=self._archive_name,
                member_name=member.name,
                source_format=ArchiveFormat.RAR,
            )
            mark_unverified_data(error)
            raise error
        return self._open_decrypted_stored(member, raw)

    def _open_member_with_program(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> MemberStreamParts:
        """Serve ``member`` through ``unrar``, or ``unar`` when it is selected."""
        if self._unar_policy is not None:
            return self._open_member_with_unar(member, raw, self._unar_policy)

        try:
            spawner = self._unrar_spawner_by_name(member, raw)
        except _UnrarCannotAddress as refusal:
            fallback = self._unar_for_unaddressable(member, raw)
            if fallback is None:
                raise refusal.error from None
            policy, cost = fallback
            return self._open_member_with_unar(
                member, raw, policy, dictionary_cost=cost
            )
        # ``unrar`` it is, through an include mask. Nothing has been spawned for the
        # read yet; the selection step may have run the dot-rule probe once.
        after_unknown = self._solid_after_unknown_error(member, raw, masked_unrar=True)
        if after_unknown is not None:
            raise after_unknown
        # Picked before anything is copied for ``unrar``: a RAR5 PswCheck rejects a
        # wrong candidate without spooling a stream source to disk. A RAR3/4 candidate
        # list is judged by running ``unrar``, so that one does copy.
        data_password = self._member_data_password(member)
        # Prefer our fused digest check (including tweaked ConvertHashToMAC) over
        # unrar's exit code for corruption; wrong-password (11) still maps. After the
        # password: the tweaked check needs the one the member's PswCheck accepted.
        has_hash = bool(member.hashes) or self._tweaked_verify_spec(raw) is not None
        return self._open_spawned_member(
            member, lambda: spawner(data_password, has_hash)
        )

    def _unrar_spawner(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> Callable[[str | None, bool], BinaryIO]:
        """Check what ``unrar p`` needs to read ``member``; return its spawner.

        Every refusal is decided here from the parsed member table, plus at most one
        cached run of the dot-rule probe (:func:`unrar_dot_rule`) when the members a
        mask selects depend on it; the read itself spawns nothing here.
        The spawner takes the password and whether the member has a digest archivey
        checks itself, and copies a stream source to disk on its first call.
        """
        try:
            return self._unrar_spawner_by_name(member, raw)
        except _UnrarCannotAddress as refusal:
            raise refusal.error from None

    def _unrar_spawner_by_name(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> Callable[[str | None, bool], BinaryIO]:
        """:meth:`_unrar_spawner`, with the refusals about naming the member raised as
        :class:`_UnrarCannotAddress`: a name ``unrar`` cannot be given, a name whose
        mask also selects earlier members with data, glob or not
        (``rar_allow_glob_member_concatenation``), a mask that does not select the
        member, an earlier name ``unrar`` reads differently on this host, or a selection
        that depends on a dot rule the binary did not report.
        """
        # unrar addresses the member by name (``path`` or ``path;n``) through a ``-n``
        # include mask (see open_unrar_p); a history row needs ``-ver``. The mask is
        # built from the name as unrar reads it, which is not always the presented
        # ``member.name``: unrar cuts a RAR5 name at its first byte that is not
        # UTF-8, an 8-bit RAR3 name goes to unrar as its stored bytes (on
        # Windows, as unrar's own OEM reading of them), and a RAR3 Unicode name
        # sends each surrogate unit as ``?``.
        version_control = raw.is_file_version_history()
        names = self._unrar_names()
        mask = plan_unrar_mask(
            view=names.views[names.positions[id(member)]],
            stored=raw.orig_filename,
            presented=_presented_filename(raw),
            stored_is_8bit=self._archive.version == 4 and raw.rar3_unicode_name is None,
            surrogates_as_wildcards=raw.rar3_unicode_name is not None,
        )
        if isinstance(mask, UnrarNameRefusal):
            raise _UnrarCannotAddress(self._unrar_name_refused(member, mask.reason))
        if isinstance(mask, UnrarMaskRefusal):
            raise _UnrarCannotAddress(
                UnsupportedFeatureError(
                    mask.reason,
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.RAR,
                )
            )
        if not isinstance(mask, UnrarMask):
            assert_never(mask)
        glob_prefix, shares_mask, dictionary_cost = self._unrar_selection(
            member, mask.mask_view, version_control=version_control
        )
        if glob_prefix and not self._config.rar_allow_glob_member_concatenation:
            # unrar decompresses every earlier match before the target and emits
            # them concatenated. The skip below returns the right bytes, but the
            # decode has already happened and ExtractionLimits do not reach
            # open()/read(). On a nonsolid archive that extra decode is
            # unadvertised and unbounded in the earlier member's size.
            #
            # On a solid archive it is neither. Those members are inside the
            # solid prefix the read pays anyway, so what the mask adds is only
            # the *emit* -- unrar pipes us bytes we then discard. That extra is
            # a bounded transfer cost, roughly 1 ms/MB
            # (dev-docs/formats/rar.md §6), not new work.
            #
            # Refused on both shapes anyway. Maintainer decision (davitf, #372,
            # 2026-09-20): always reject, for internal consistency and so the
            # config flag keeps a single meaning. Two arguments he raised cut
            # the other way and are recorded in rar.md section 7 as a question
            # to revisit: an attacker can simply make the archive solid to
            # sidestep the sharp case, and an out-of-order read of any solid
            # archive already decodes everything ahead of it, glob or not. The
            # names are almost always constructed (davitf, 2026-09-19), with
            # the config flag as the escape hatch.
            # A glob name matching nothing else has `glob_prefix == 0` and
            # never reaches this -- which also means this is **not** a guard
            # against a hostile mask as such: a name built to make a matcher
            # backtrack, with no sibling it can match, has a zero prefix and
            # still goes to unrar. That is bounded separately, by narrowing
            # the mask itself. This bounds the payload, not the match.
            #
            # A mask with no glob that still selects earlier members (a duplicate
            # name, or two names unrar reads the same way) costs the same decode and
            # is refused the same way (maintainer decision, 2026-10-29). Under AUTO
            # both go to unar, which selects by index, when it can read the member.
            #
            # The predicate is deliberately `_unrar_selection`'s own answer and
            # not a second walk: which siblings match is decided by the mask
            # actually handed to unrar, which that function owns. Recomputing it
            # from the presented name here would refuse archives that read fine
            # under the mask unrar is given.
            why = (
                "is an include mask that also matches"
                if mask.is_glob
                else "also selects"
            )
            if self._archive.is_solid:
                message = (
                    f"Reading RAR member {quoted(member.name)} is refused: its "
                    f"name, as unrar is given it, {why} earlier members. Names "
                    "like this are almost always constructed. Set "
                    "ArchiveyConfig.rar_allow_glob_member_concatenation=True "
                    "to read it anyway."
                )
            else:
                message = (
                    f"Reading RAR member {quoted(member.name)} would decompress "
                    f"{glob_prefix} bytes of earlier members first: its name, as "
                    f"unrar is given it, {why} them. Set "
                    "ArchiveyConfig.rar_allow_glob_member_concatenation=True to "
                    "read it anyway."
                )
            raise _UnrarCannotAddress(
                UnsupportedFeatureError(
                    message,
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.RAR,
                )
            )

        # Counts the other members the mask selects too (a duplicate name is enough),
        # because unrar decodes each of them before the target.
        self._check_dictionary_memory(member, dictionary_cost)

        # Only on spawn: every refusal above is decided from the parsed member table
        # (plus, at most, the dot-rule probe, which reads an embedded archive and
        # not this one), so a stream source must not be spooled to disk to reach one.
        def _spawn(data_password: str | None, has_hash: bool) -> BinaryIO:
            path = self._unrar_path_for(raw)
            proc, stdout = open_unrar_p(
                path,
                password=data_password,
                member=mask.argument,
                version_control=version_control,
                rar5=self._archive.version == 5,
            )
            owned = _UnrarOwnedStream(
                stdout,
                proc,
                named_member=True,
                has_verifiable_hash=has_hash,
                encrypted=raw.is_encrypted,
            )
            # _bounded_member_pipe already closed ``tracked`` (and so ``owned``) if the
            # prefix skip failed; close is idempotent.
            with _close_on_error(owned):
                tracked = self._track_decompressed(owned)
                if mask.is_glob or shares_mask:
                    return _bounded_member_pipe(
                        tracked,
                        prefix=glob_prefix,
                        size=_member_stream_size(member),
                    )
                return tracked

        return _spawn

    def _open_spawned_member(
        self, member: ArchiveMember, spawn: Callable[[], BinaryIO]
    ) -> MemberStreamParts:
        """Wrap one member's decompressor pipe: respawn on rewind, verify, count.

        ``spawn`` starts the process and returns a stream that owns it, already
        counted by ``_track_decompressed``. The same wrapping serves ``unrar`` and
        ``unar``.
        """
        # Spawn now so PackageNotInstalledError / a missing stdout pipe surface at
        # open(), and so a spawn-count right after open() is 1 (the live-stream
        # gate's "refused second open does not spawn" pin). Password and
        # corruption still map on the completing read — the exit status is only
        # known after the process ends. The boundary maps a stream source closed
        # before its first spool to disk, as every format's member open does.
        with self._translated_errors(member.name):
            inner = spawn()
        try:
            rewind: RewindWarning | None = None
            if self._seek_declared():
                inner = RespawnStream(
                    spawn,
                    inner,
                    size=_member_stream_size(member),
                    what="unrar output",
                )
                rewind = RewindWarning(
                    codec_name="rar",
                    suggest_install=False,
                    min_redecode_bytes=self._solid_prefix(member),
                )
            inner = self._watch_unverified(inner, member)
            # Folder/pipe output already counted; avoid double-counting at the member wrap.
            # Fused verify in _payload_parts bounds/checks declared size + digests.
            return self._payload_parts(
                inner, member, track_output=False, rewind_warning=rewind
            )
        except BaseException:
            inner.close()
            raise

    def _watch_unverified(self, stream: BinaryIO, member: ArchiveMember) -> BinaryIO:
        """Wrap ``stream`` to report an abandoned read of a member no check vouched for.

        RAR3/4 file data has no password check value, so ``unrar`` decodes with
        whatever password it is given, and only the CRC at the member's end tells a
        wrong key. Before that it can stream the wrong key's bytes: always for a stored
        member, and for about three wrong passwords in ten on a compressed one
        (unrar 7.00, dev-docs/formats/rar.md §2.2). A caller who reads a prefix and
        closes never reaches the CRC, so the close reports it. A RAR5 record's 64-bit
        PswCheck vouches for the password, and so does a header-encrypted archive's
        header decryption, which the password passed CRC by CRC; neither is watched.

        The test is the parser's ``is_encrypted``, not the member's wider
        ``encrypted`` (which adds ``encryption_unknown``), on purpose. A member whose
        extra-area walk stopped before its encryption record never meets a key: a
        stored one is proved plaintext by ``_confirm_unsettled_plaintext`` or
        refused, and ``unrar`` reads the same damaged header, so it never sees the
        encryption marker and derives no key. There is no wrong-key prefix to report.
        """
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if not raw.is_encrypted or self._archive.has_header_encryption:
            return stream
        enc = raw.file_encryption
        if enc is not None and _psw_check_usable(enc):
            return stream
        if id(member) in self._unchecked_confirmed:
            # The candidate list was settled by this member's own CRC.
            return stream
        return self._watch_unverified_read(
            stream,
            member,
            size=_member_stream_size(member),
            check="no_password_check",
            format_label="RAR",
            digest="checksum",
            why="it carries no password check",
        )

    def _unar_password(
        self, member: ArchiveMember | None, password: str | None
    ) -> str | None:
        """``password`` if ``unar`` can use it; refuse one it cannot."""
        if password is not None and not unar_password_supported(password):
            raise self._unar_refused(member, REFUSE_NON_ASCII_PASSWORD)
        return password

    def _no_decompressor_refused(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> UnsupportedFeatureError:
        """The refusal for a member only an external program can read, under ``NONE``."""
        if not raw.is_stored:
            why = "it is compressed"
        elif raw.is_encrypted:
            # Stored but not ``_natively_decryptable``: split across volumes, or the
            # RAR 2.0 cipher, or sizes or a record the AES decryption cannot use.
            why = "it is encrypted in a form archivey does not decrypt itself"
        else:
            # A stored member whose parts were not all found: a split member missing
            # its other volumes. Its parts are joined natively when they are present.
            why = "it is split across volumes and not every part was found"
        return UnsupportedFeatureError(
            f"Cannot read RAR member {quoted(member.name)}: {why}, and only an external "
            "program (unrar or unar) can read it. ArchiveyConfig.rar_decompressor is "
            "'none', which rules them out. Set it to 'unrar' to read the member.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _unar_refused(
        self, member: ArchiveMember | None, reason: str
    ) -> UnsupportedFeatureError:
        if member is None:
            return UnsupportedFeatureError(
                f"Cannot read RAR member data: {reason}",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )
        return UnsupportedFeatureError(
            f"Cannot read RAR member {quoted(member.name)}: {reason}",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _open_member_with_unar(
        self,
        member: ArchiveMember,
        raw: RarMemberInfo,
        policy: UnarRarPolicy,
        *,
        dictionary_cost: _DictionaryCost | None = None,
    ) -> MemberStreamParts:
        """Serve one member from ``unar -i <index>``.

        The member is named by its entry index, not by its stored name, so none of the
        ``unrar`` include-mask handling applies: no sibling can match, and a glob name
        costs nothing extra. The refusals are the ones ``unar`` needs instead
        (:class:`UnarRarPolicy`), decided from the parse before anything is spooled or
        spawned.
        """
        return self._open_spawned_member(
            member,
            self._unar_member_spawner(
                member, raw, policy, dictionary_cost=dictionary_cost
            ),
        )

    def _unar_member_spawner(
        self,
        member: ArchiveMember,
        raw: RarMemberInfo,
        policy: UnarRarPolicy,
        *,
        dictionary_cost: _DictionaryCost | None = None,
    ) -> Callable[[], BinaryIO]:
        """Check what ``unar -i <index>`` needs for this member; return its spawner."""
        spawn = self._unar_spawner(member, raw, policy, dictionary_cost=dictionary_cost)
        # Picked the way the ``unrar`` path picks it, before anything is copied: a
        # RAR5 PswCheck rejects a wrong candidate here, without spawning ``unar``.
        data_password = self._unar_password(member, self._member_data_password(member))
        return lambda: spawn(data_password)

    def _unar_spawner(
        self,
        member: ArchiveMember,
        raw: RarMemberInfo,
        policy: UnarRarPolicy,
        *,
        dictionary_cost: _DictionaryCost | None = None,
    ) -> Callable[[str | None], BinaryIO]:
        """The refusals and dictionary check for ``unar -i <index>``; a spawner by password.

        ``dictionary_cost`` is given for a member read with ``unar`` while ``unrar``
        is this reader's program (:meth:`_unar_for_unaddressable`), whose
        :attr:`_dictionary_costs` follow ``unrar``'s rule.
        """
        refusal = policy.member_refusal(raw)
        if refusal is not None:
            raise self._unar_refused(member, refusal)
        self._check_dictionary_memory(
            member,
            self._dictionary_costs[id(member)]
            if dictionary_cost is None
            else dictionary_cost,
            program="unar",
        )
        # ``unar`` answers a wrong password with no output and exit 0.
        empty_means_wrong_password = (
            raw.is_encrypted and _member_stream_size(member) > 0
        )
        index = policy.entry_index(raw)

        def _spawn(data_password: str | None) -> BinaryIO:
            data_password = self._unar_password(member, data_password)
            # The stored CRC32 or BLAKE2sp, when present, is checked; an encrypted
            # RAR5 member's tweaked digest needs the password picked by the caller.
            has_digest = (
                bool(member.hashes) or self._tweaked_verify_spec(raw) is not None
            )
            path = self._unar_archive_path(member)
            proc, stdout = open_unar_stdout(
                path, [index], purpose=UNAR_PURPOSE, password=data_password
            )
            owned = UnarOutputStream(
                stdout,
                proc,
                has_verifiable_digest=has_digest,
                empty_means_wrong_password=empty_means_wrong_password,
            )
            with _close_on_error(owned):
                return self._track_decompressed(owned)

        return _spawn

    def _iter_solid_with_unar(
        self, policy: UnarRarPolicy, copies: FileCopyPass
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        """The solid pass over one all-entries ``unar`` run.

        Driven by :meth:`_drive_solid_pass`, as the ``unrar`` pass is: one process, spawned
        on the first read, demultiplexed by :class:`SolidBlockReader`. The offsets come
        from :meth:`UnarRarPolicy.solid_pass_offset` because ``unar`` emits a different
        set of entries than ``unrar p`` (history rows always, RAR3/4 symlink targets
        too), or only the entries the policy names. A refused member raises on its first
        read, so a pass that only lists, or skips it, is not refused.

        A member with no digest to check is not served from this run: it gets its own
        ``unar -i <index>`` run, as :meth:`_open_member_with_unar` would give it. When
        ``unar`` 1.10.1 drops a member from this run (exit 0), the bytes at that
        member's offset are the next members' or stale window bytes, often enough of
        them to pass the size check; only a digest tells them from the member's. A run
        of one entry writes that entry exactly or not at all, which the size check
        catches.
        """

        def _spawn() -> BinaryIO:
            password = self._unar_password(None, self._archive_data_password())
            path = self._unar_archive_path(None)
            proc, stdout = open_unar_stdout(
                path,
                policy.solid_pass_indexes,
                purpose=UNAR_PURPOSE,
                password=password,
            )
            # Every member read from this pipe is checked against its declared
            # size and its stored CRC32 or BLAKE2sp; a member without one is read
            # by its own run instead (``_plan``). unar 1.10.1 drops a compressed
            # RAR5 member when a Huffman lookup peeks past its packed data, exit 0
            # (``scripts/find_unar_probe_member.py``); the bytes
            # then read in its place are later members' or stale window bytes,
            # which the digest catches and the size check often does not. The
            # exit status adds nothing. A wrong password gives no output at all,
            # reported as such when a password was needed.
            return UnarOutputStream(
                stdout,
                proc,
                has_verifiable_digest=True,
                empty_means_wrong_password=(
                    self._archive_has_encryption and policy.solid_pass_emits_data()
                ),
            )

        def _refuse(member: ArchiveMember, reason: str) -> BinaryIO:
            raise self._unar_refused(member, reason)

        def _plan(
            member: ArchiveMember, raw: RarMemberInfo, size: int, has_digest: bool
        ) -> int | Callable[[], BinaryIO] | None:
            block = self._solid_after_unknown.get(id(raw))
            if block is not None and block.same_stream:
                # Left out of the run (``member_refusal``) and served as ``open()``
                # serves it, as in the ``unrar`` pass. A member of a later stream
                # is in the run: ``unar`` reads it.
                return None
            refusal = policy.solid_pass_refusal(raw)
            if refusal is not None:
                return lambda: _refuse(member, refusal)
            if not has_digest:
                # No digest would catch misplaced bytes from the shared run (above).
                return lambda: self._watch_unverified(
                    self._unar_member_spawner(member, raw, policy)(), member
                )
            return policy.solid_pass_offset(raw)

        yield from self._drive_solid_pass(copies, _spawn, _plan)

    def _get_archive_info(self) -> ArchiveInfo:
        is_solid = self._archive.is_solid
        cost = CostReceipt(
            # A header-to-header walk at open; a RAR5 quick-open record saves the
            # seeks, not the parse.
            listing_cost=ListingCost.REQUIRES_SCANNING,
            access_cost=AccessCost.SOLID if is_solid else AccessCost.DIRECT,
            stream_capability=StreamCapability.SEEKABLE,
            # RAR solid is one continuous compression context; block count is unknown.
            solid_block_count=None,
            notes=self._cost_notes,
        )
        is_multivolume = (
            self._archive.is_volume
            or self._volume_count > 1
            or self._volume_set_size() > 1
        )
        archive_comment = self._archive.comment
        assert not isinstance(archive_comment, _Rar3Comment)
        info_extra = ArchiveInfoExtra(
            {"rar.volume_count": max(self._volume_count, self._volume_set_size())}
        )
        return ArchiveInfo(
            format=ArchiveFormat.RAR,
            format_version=str(self._archive.version),
            is_solid=is_solid,
            member_count=len(self._members),
            comment=archive_comment,
            is_encrypted=self._archive_has_encryption,
            is_multivolume=is_multivolume,
            cost=cost,
            extra=info_extra,
        )

    def _close_archive(self) -> None:
        with self._materialize_lock:
            self._shared.close()
            if self._owned_concat is not None:
                try:
                    self._owned_concat.close()
                except OSError:
                    pass
                self._owned_concat = None
            if self._temp_path is not None:
                try:
                    self._temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._temp_path = None
            if self._unar_dir is not None:
                # Links, or copies where links are unavailable: removing them leaves
                # the caller's files alone.
                shutil.rmtree(self._unar_dir, ignore_errors=True)
                self._unar_dir = None
                self._unar_path = None
            if self._temp_dir is not None:
                # Single-stream copy (_ensure_archive_path) owns _temp_path;
                # stream volumes (_materialize_stream_volumes) own _temp_dir.
                # unlink vs rmtree, so _close_archive unwinds them separately.
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                self._temp_dir = None


class RarReadBackend(ReadBackend):
    """Backend factory for RAR archives."""

    FORMATS: tuple[ArchiveFormat, ...] = (ArchiveFormat.RAR,)
    EXTENSIONS: Mapping[str, ArchiveFormat] = {
        ".rar": ArchiveFormat.RAR,
        ".cbr": ArchiveFormat.RAR,
    }
    MAGIC: tuple[MagicSignature, ...] = (
        MagicSignature(0, RAR5_ID, ArchiveFormat.RAR),
        MagicSignature(0, RAR_ID, ArchiveFormat.RAR),
    )
    # Both ids, so the scan resolves RAR4 vs RAR5 by which one comes first rather than
    # matching their shared `Rar!\x1a\x07` prefix and re-reading to disambiguate.
    SFX_MAGIC: tuple[MagicSignature, ...] = MAGIC
    SFX_HIT_VALIDATOR = staticmethod(validate_rar_main_header)
    SFX_PARSER_SCANS = True
    SUPPORTS_PASSWORD = True
    USES_ENCODING = True  # for RAR 1.5-4 names stored as 8-bit bytes
    SUPPORTS_STREAMING_NON_SEEKABLE = False
    NON_SEEKABLE_REASON = _NON_SEEKABLE_REASON
    OPTIONAL_DEPENDENCY = None

    @classmethod
    def missing_programs(cls) -> tuple[MissingComponent, ...]:
        # Independent of ``rar_decompressor``: the query takes no config, so it answers
        # for the default ``AUTO``, which uses unrar when one is usable.
        return rarlab_unrar_missing()

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
    ) -> RarReader:
        del format
        return RarReader(
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


register_reader(RarReadBackend)
