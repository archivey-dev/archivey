"""RAR policy for the ``unar`` data path: what ``unar`` may read, and where its bytes land.

The process layer is :mod:`archivey.internal.external.unar` and knows nothing about RAR.
This module holds the RAR facts that decide how :mod:`.rar_reader` uses it, all taken
from the native parse before any process starts:

- **Entry indexes.** ``unar -i`` addresses an entry by its position in ``lsar``'s list,
  which for RAR is one entry per FILE header in archive order, a file split across
  volumes counted once. That is the order of :attr:`RarArchive.members`.
- **What an all-entries run emits.** ``unar -o -`` with no index writes each entry's
  unpacked bytes in archive order. That differs from ``unrar p``: every file-version
  history row is included (``unrar`` needs ``-ver``), a RAR3/4 symlink emits its stored
  target, and a directory or a RAR5 redirect emits nothing.
- **Dictionary cost.** What ``unar`` allocates for a member's dictionary, checked
  against ``DecoderLimits.max_decoder_memory`` before it runs
  (:func:`unar_dictionary_costs`).
- **Refusals.** The reads ``unar`` 1.10 is known to get wrong. Each is refused with
  ``UnsupportedFeatureError`` before ``unar`` runs, because ``unar`` reports several of
  them with exit 0. RAR5 encryption is read, with the password on ``unar``'s command
  line (see :mod:`archivey.internal.external.unar`).

Measurements: ``dev-docs/investigations/alternative-rar-decompressors.md`` and
``scripts/exploration/rar_decompressor_matrix.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from archivey.internal.backends.rar_parser import RarArchive, RarMemberInfo
from archivey.terminal import quoted

# Compression versions below 2.0 are decoded by a separate RAR 1.5 algorithm, which
# only matters when the data is compressed.
_FIRST_UNAR_SAFE_EXTRACT_VERSION = 20

UNAR_PURPOSE = (
    "to read RAR member data with ArchiveyConfig.rar_decompressor set to 'unar'"
)

_USE_UNRAR = (
    "Set ArchiveyConfig.rar_decompressor to 'unrar' to read it with RARLAB unrar."
)

REFUSE_RAR4_ENCRYPTED = (
    "unar 1.10 returns no data, and reports success, for encrypted RAR 2.x-4.x data "
    "even with the right password. " + _USE_UNRAR
)
REFUSE_RAR4_AFTER_ENCRYPTED = (
    "This member continues a solid stream that holds encrypted data, and unar 1.10 "
    "returns no data, and reports success, for encrypted RAR 2.x-4.x data even with "
    "the right password. " + _USE_UNRAR
)
REFUSE_NON_ASCII_PASSWORD = (
    "unar 1.10 does not decrypt with a password that is not ASCII. " + _USE_UNRAR
)
REFUSE_HEADER_ENCRYPTED_VOLUMES = (
    "unar 1.10.8 returns no data, and reports success, for a multi-volume RAR5 set "
    "with encrypted headers, even with the right password. " + _USE_UNRAR
)
REFUSE_RAR15 = (
    "unar 1.10 returns no data, and reports success, for a member compressed with the "
    "RAR 1.5 algorithm. " + _USE_UNRAR
)
# Worded for the member, not for ``unar``: the bounds were measured on ``unrar``
# 7.00 only, and refusing on them is the conservative direction for ``unar`` too.
# Same words as ``RarReader._unknown_compression_error``.
REFUSE_UNKNOWN_COMPRESSION = (
    "it is compressed with {version}, which neither RAR decompressor archivey runs "
    'is known to decode (unrar 7.00 reports "Unknown method"), so switching '
    "decompressors does not help; it may need a newer version of RAR."
)
REFUSE_RAR5_SOLID_AFTER_EMPTY = (
    "unar 1.10 crashes, or reports success with no data, on a RAR5 solid archive when a "
    "member with data follows an empty file, a directory or a link. " + _USE_UNRAR
)


# The most entries one solid pass names on the ``unar`` command line. The bound that
# applies is ``ARG_MAX``, which covers argv and the environment together: 256 KiB on
# older macOS, 1 MiB on current macOS, 2 MiB on Linux. 4000 indexes of up to six
# digits cost under 60 KB, counting each string's terminator and its argv pointer,
# which leaves most of the smallest of those for the environment, the fixed argv and
# a long archive path. ``unar`` is not packaged for Windows, so its 32 767-character
# command line is not the constraint. Only a pass with a refused member names entries
# at all; the cap is in the ``format-rar`` spec and in ``docs/formats.md``.
MAX_SELECTED_ENTRIES = 4000

REFUSE_TOO_MANY_SELECTED = (
    f"this archive has a member that unar cannot read, so a single unar run must name "
    f"each readable member, and it can name at most {MAX_SELECTED_ENTRIES}. Open this "
    "member on its own instead. " + _USE_UNRAR
)


def unar_entry_index(archive: RarArchive) -> dict[int, int]:
    """``id(member info)`` to its ``unar -i`` index."""
    return {id(info): index for index, info in enumerate(archive.members)}


def _carries_no_data(info: RarMemberInfo) -> bool:
    """A directory or a RAR5 redirect: the entry has a header and no data to decode.

    A RAR3 symlink is not one of these: its target is stored as compressed data.
    """
    return info.is_directory or info.file_redir is not None or info.is_hardlink_or_copy


def _carries_no_solid_data(info: RarMemberInfo) -> bool:
    return _carries_no_data(info) or info.file_size == 0


def uses_no_dictionary(info: RarMemberInfo) -> bool:
    """Whether decoding this entry leaves the dictionary untouched, for both programs.

    An entry with no data decodes nothing, and a stored member is copied. The
    ``file_size`` a hardlink, copy or redirect declares is not decoded, so it must
    not count. An empty compressed member still counts: its declared dictionary may
    start a stream.
    """
    return _carries_no_data(info) or info.is_stored


def unar_emitted_size(info: RarMemberInfo) -> int:
    """Bytes ``unar -o -`` writes for this entry in an all-entries run."""
    if _carries_no_data(info):
        return 0
    return info.file_size


def unar_pipe_offsets(archive: RarArchive) -> dict[int, int]:
    """``id(member info)`` to where its bytes start in an all-entries ``unar`` run."""
    offsets: dict[int, int] = {}
    position = 0
    for info in archive.members:
        offsets[id(info)] = position
        position += unar_emitted_size(info)
    return offsets


def unar_dictionary_costs(archive: RarArchive) -> list[tuple[int, int]]:
    """The dictionary bytes ``unar`` allocates to decode each member, in archive order.

    Measured with ``unar`` 1.10.1: it maps the declared dictionary when it starts a
    stream and writes to every page of it, whatever the member's size. A 64 KiB
    member declaring 1 GiB peaks at about 1 GiB resident, and a solid pair of 64 KiB
    members declaring 4 GiB at about 4 GiB. The count is the declared size. It is not
    capped at the data, which is where the ``unrar`` rule differs.

    In a solid archive ``unar`` keeps one dictionary for a solid stream, which starts
    at a compressed member without the solid flag. The count for a member is the
    largest dictionary declared in its stream up to and including it. Measured, only
    the first member's declaration is allocated, so the largest is an upper bound. A
    member that starts a new stream does not pay for the one before it: reading it
    alone stayed near 20 MiB after a 1 GiB stream ahead of it. A stored member, a
    directory and a redirect use no dictionary (:func:`uses_no_dictionary`), so they
    count 0 and neither start nor end a stream. For a stored member of a solid
    archive that is measured too: ``unar -i`` read a stored 64 KiB member behind a
    300 MB member declaring 1 GiB at 41 MiB resident, where reading the 300 MB
    member took 1044 MiB. ``unar`` does not decode the stream ahead of it.

    Each entry is ``(count, declarer)``: the bytes, and the archive index of the
    member whose header declared that dictionary, or -1 for a count of 0.
    """
    costs: list[tuple[int, int]] = []
    stream = 0
    declarer = -1
    for index, info in enumerate(archive.members):
        if uses_no_dictionary(info):
            costs.append((0, -1))
            continue
        if not info.file_solid:
            stream, declarer = 0, -1
        if info.dictionary_size > stream or declarer < 0:
            stream, declarer = info.dictionary_size, index
        costs.append((stream, declarer))
    return costs


def _rar5_solid_after_empty(archive: RarArchive) -> set[int]:
    """``id``s of RAR5 solid members that ``unar`` 1.10 does not decode.

    Measured with ``unar`` 1.10.1 (SIGSEGV) and XADMaster 1.10.8 (exit 0, no data): a
    member with data that comes after an empty file or a directory in a RAR5 solid
    archive. An empty entry *last* is harmless, and so is anything before it. Links are
    included on the same grounds as directories (no data in the solid stream), without
    a failing sample: a link before data in a solid RAR5 archive is untested, and this
    refuses rather than guesses. RAR3/4 solid archives decoded correctly in every
    shape measured, so they are not refused; the size and digest check on every member
    is the net there.
    """
    if archive.version != 5 or not archive.is_solid:
        return set()
    refused: set[int] = set()
    seen_empty = False
    for info in archive.members:
        if seen_empty and not _carries_no_solid_data(info):
            refused.add(id(info))
        if _carries_no_solid_data(info):
            seen_empty = True
    return refused


def _rar4_solid_after_encrypted(archive: RarArchive) -> set[int]:
    """``id``s of RAR 2.x-4.x members whose solid stream holds encrypted data before them.

    To decode such a member, ``unar`` decodes the solid stream from its start, and
    that includes the encrypted data it returns nothing for. The streams are the ones
    :func:`unar_dictionary_costs` walks: a member that uses the dictionary without the
    solid flag starts one, and a stored member or an entry without data neither starts
    nor continues one. An encrypted member is refused on its own already.
    """
    if archive.version == 5:
        return set()
    refused: set[int] = set()
    tainted = False
    for info in archive.members:
        if uses_no_dictionary(info):
            continue
        if not info.file_solid:
            tainted = False
        if _needs_password(archive, info):
            tainted = True
        elif tainted:
            refused.add(id(info))
    return refused


@dataclass(frozen=True)
class SolidAfterUnknown:
    """Why a member after an unknown-version member is not decoded.

    ``blocker`` is the unknown-version member. ``same_stream`` says whether the
    member shares its solid stream, so that no decoder can rebuild the window it
    needs; when ``False``, only ``unrar``'s masked read is blocked
    (:func:`solid_after_unknown_compression`).
    """

    blocker: RarMemberInfo
    same_stream: bool


def solid_after_unknown_compression(
    archive: RarArchive,
) -> dict[int, SolidAfterUnknown]:
    """``id``s of the payload members that an unknown-version member ahead of them
    keeps from being decoded, each mapped to why.

    No decoder archivey runs decodes that member
    (:meth:`RarMemberInfo.unknown_compression_version`), so no decoder rebuilds the
    window a later member of **its solid stream** needs (``same_stream``). The streams
    are the ones :func:`unar_dictionary_costs` walks, by each member's solid flag, so
    this part does not depend on the archive's solid bit. That much holds for both
    programs, and it is all ``unar`` is refused: it addresses an entry by index and
    does not decode the stream ahead of a member that starts a new one. Measured
    with ``unar`` 1.10.1 on ``solid_groups__.rar`` (``rar -s2``) with ``a.txt``'s data
    garbled: ``b.txt`` fails and ``c.txt`` and ``d.txt`` read whole.

    ``unrar`` 7.00 is blocked further. It reports "Unknown method" and stops, so
    ``unrar p`` writes nothing for any later member, and a read addressed with an
    include mask (``-n``, as archivey addresses a member) decodes a solid archive from
    its start. So in an archive whose main header has the solid bit, every payload
    member after the first unknown-version one fails under ``unrar``, even one in a
    later solid group (``same_stream`` ``False``). The archive bit is the gate
    because ``unrar`` keys that on it, not on the members' flags: on the same
    archive with the bit cleared, ``unrar p -n./c.txt`` reads ``c.txt``. Only a
    file name given as an argument, which archivey does not use, skips to the group.

    A member a program does not decode (stored and read by archivey itself) is not
    affected, so callers check this only on the way to a program.
    """
    blocked: dict[int, SolidAfterUnknown] = {}
    first: RarMemberInfo | None = None
    in_stream: RarMemberInfo | None = None
    for info in archive.members:
        # Every member, as ``unar_dictionary_costs`` walks them: a compressed RAR
        # 2.x-4.x symlink is no payload file but stores its target as compressed data,
        # so it starts, continues or blocks a stream like any other. A stored member
        # neither starts nor continues one; only ``unrar``'s masked read reaches it.
        decoded = not uses_no_dictionary(info)
        if decoded and not info.file_solid:
            in_stream = None
        # Only payload members are read, so only they are recorded.
        if info.is_payload_file():
            if decoded and in_stream is not None:
                blocked[id(info)] = SolidAfterUnknown(in_stream, same_stream=True)
            elif first is not None and archive.is_solid:
                blocked[id(info)] = SolidAfterUnknown(first, same_stream=False)
        if decoded and info.unknown_compression_version() is not None:
            # Refused on its own first; recorded as the blocker of what follows.
            first = first or info
            in_stream = in_stream or info
    return blocked


def solid_after_unknown_compression_reason(block: SolidAfterUnknown) -> str:
    """Why a member that ``block`` names cannot be decoded.

    For a member of the blocker's own solid stream it is worded like
    :data:`REFUSE_UNKNOWN_COMPRESSION`, for the same reason: the bound is the
    decoder's, not one program's. For a member of a later stream the bound is how
    archivey runs ``unrar``, and the text says so. The reader's refusal uses it too.
    """
    blocker = block.blocker
    version = blocker.unknown_compression_version()
    assert version is not None
    if block.same_stream:
        return (
            f"it comes after {quoted(blocker.filename)} in its solid stream, and "
            f"decoding it means decoding that member first. That member is "
            f"compressed with {version}, which neither RAR decompressor archivey "
            'runs is known to decode (unrar 7.00 reports "Unknown method" and stops '
            "there), so switching decompressors does not help; it may need a newer "
            "version of RAR."
        )
    return (
        f"it comes after {quoted(blocker.filename)} in this solid archive, which is "
        f"compressed with {version}. This member is not in that member's solid "
        "stream and does not need it decoded, but archivey asks unrar for one member "
        "through an "
        "include mask, and unrar then decodes the solid archive from its start and "
        'stops at that member ("Unknown method"). unar reads it: set '
        "ArchiveyConfig.rar_decompressor to 'unar'."
    )


def _needs_password(archive: RarArchive, info: RarMemberInfo) -> bool:
    return archive.has_header_encryption or info.is_encrypted or info.encryption_unknown


def _rar4_encrypted(archive: RarArchive, info: RarMemberInfo) -> bool:
    return archive.version != 5 and _needs_password(archive, info)


def _archive_refusal(archive: RarArchive) -> str | None:
    """Why no solid pass over this archive can use ``unar``, or ``None``."""
    if archive.version != 5 and (
        archive.has_header_encryption
        or any(_needs_password(archive, info) for info in archive.members)
    ):
        return REFUSE_RAR4_ENCRYPTED
    # Measured on the Homebrew bottle (XADMaster 1.10.8) with ``tinyvol_hp``: no data,
    # exit 0. Debian's 1.10.1 reads the same set; the version is not told apart.
    if archive.version == 5 and archive.has_header_encryption and archive.is_volume:
        return REFUSE_HEADER_ENCRYPTED_VOLUMES
    return None


class UnarRarPolicy:
    """The refusals and pipe layout for one parsed archive, computed once."""

    def __init__(self, archive: RarArchive) -> None:
        self._archive = archive
        self._index = unar_entry_index(archive)
        self._solid_after_empty = _rar5_solid_after_empty(archive)
        self._solid_after_encrypted = _rar4_solid_after_encrypted(archive)
        # Only the blocker's own stream: ``unar`` reads a later one (see the function).
        self._solid_after_unknown = {
            key: block
            for key, block in solid_after_unknown_compression(archive).items()
            if block.same_stream
        }
        self._archive_refusal = _archive_refusal(archive)
        self._pass_refusals: dict[int, str] = {}
        self._pass_indexes: list[int] | None = None
        self._pass_offsets: dict[int, int] = {}
        if self._archive_refusal is None:
            self._plan_solid_pass()

    def _plan_solid_pass(self) -> None:
        """Choose the one ``unar`` run a solid pass reads, and where each member lands.

        With nothing refused, the run selects every entry and the offsets follow
        :func:`unar_emitted_size`. With a refused member, the run names only the
        readable payload members by index. The refused member must stay out of the run,
        not only out of the demux: ``unar`` 1.10.1 crashes on it, and the crash loses
        output of *earlier* members that ``unar`` had buffered but not yet written.
        """
        payload = [info for info in self._archive.members if info.is_payload_file()]
        for info in payload:
            reason = self.member_refusal(info)
            if reason is not None:
                self._pass_refusals[id(info)] = reason
        if not self._pass_refusals:
            self._pass_offsets = unar_pipe_offsets(self._archive)
            return
        selected: list[RarMemberInfo] = []
        for info in payload:
            if id(info) in self._pass_refusals:
                continue
            if len(selected) == MAX_SELECTED_ENTRIES:
                self._pass_refusals[id(info)] = REFUSE_TOO_MANY_SELECTED
                continue
            selected.append(info)
        position = 0
        for info in selected:
            self._pass_offsets[id(info)] = position
            position += info.file_size
        self._pass_indexes = [self._index[id(info)] for info in selected]

    def entry_index(self, info: RarMemberInfo) -> int:
        return self._index[id(info)]

    def member_refusal(self, info: RarMemberInfo) -> str | None:
        """Why ``unar`` must not read this member on its own, or ``None``."""
        version = info.unknown_compression_version()
        if version is not None:
            return REFUSE_UNKNOWN_COMPRESSION.format(version=version)
        block = self._solid_after_unknown.get(id(info))
        if block is not None:
            return solid_after_unknown_compression_reason(block)
        if _rar4_encrypted(self._archive, info):
            return REFUSE_RAR4_ENCRYPTED
        if id(info) in self._solid_after_encrypted:
            return REFUSE_RAR4_AFTER_ENCRYPTED
        if self._archive_refusal == REFUSE_HEADER_ENCRYPTED_VOLUMES:
            return self._archive_refusal
        if (
            info.extract_version is not None
            and info.extract_version < _FIRST_UNAR_SAFE_EXTRACT_VERSION
            and not info.is_stored
        ):
            return REFUSE_RAR15
        if id(info) in self._solid_after_empty:
            return REFUSE_RAR5_SOLID_AFTER_EMPTY
        return None

    @property
    def solid_pass_indexes(self) -> list[int] | None:
        """The ``unar -i`` selection for a solid pass; ``None`` selects every entry."""
        return self._pass_indexes

    def solid_pass_refusal(self, info: RarMemberInfo) -> str | None:
        """Why this payload member cannot come out of the solid pass's run, or ``None``.

        In a RAR 2.x-4.x archive, one encrypted member anywhere refuses the whole run:
        ``unar`` would have to decode it to reach any later member of the solid stream.
        """
        if self._archive_refusal is not None:
            return self._archive_refusal
        return self._pass_refusals.get(id(info))

    def solid_pass_emits_data(self) -> bool:
        """Whether the solid pass's run writes at least one byte when it decrypts."""
        if self._pass_indexes is not None:
            return any(
                info.file_size > 0
                for info in self._archive.members
                if id(info) in self._pass_offsets
            )
        return any(unar_emitted_size(info) > 0 for info in self._archive.members)

    def solid_pass_offset(self, info: RarMemberInfo) -> int:
        """Where this readable payload member starts in the solid pass's run."""
        return self._pass_offsets[id(info)]
