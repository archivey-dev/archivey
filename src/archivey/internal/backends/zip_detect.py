"""Cheap ZIP local-header identity check for the SFX scan.

Four bytes of ``PK\\x03\\x04`` in a stub are not a ZIP. The cued scan calls
:func:`validate_zip_local_header` with a candidate-relative view; EOCD plus
central-directory confirmation is the tail probe's job, not this check.

Also: :func:`is_zip_split_segment_name` — Info-ZIP ``.zNN`` and 7-Zip
``name.zip.NNN`` split naming. Info-ZIP names are refused in ``open_archive``
before format detection (middle/last parts typically have no magic at offset 0).
A lone ``.zip.NNN`` is an incomplete numbered set (``TruncatedError``) instead;
this helper still matches both so the ZIP reader can refuse a spanned ``.zNN``
that reached it unjoined. See ``internal/volumes.py`` for the byte-slice join.
Info-ZIP's spanned sets are never joined.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable
from pathlib import PurePath

from archivey.internal.sfx import HitOutcome

# Shared rejoin-first message for every ZIP split/spanned refuse path
# (``open_archive`` early name check and the ZIP reader).
ZIP_MULTI_VOLUME_MSG = "Multi-volume (split/spanned) ZIP archives are not supported."

# Info-ZIP/WinZip ``name.z01``…``name.zNN`` (and ``.z100``+ when the set exceeds
# 99 parts); 7-Zip ``name.zip.001``…``name.zip.00N``. The final Info-ZIP ``.zip``
# part is caught via EOCD disk fields instead. ``\Z``, not ``$``: ``$`` also matches
# before a final newline, which would read ``name.z01\n`` as a split part.
_ZIP_SPLIT_SEGMENT_RE = re.compile(
    r"\.(?:z[0-9]{2,}|zip\.[0-9]{3,})\Z", re.IGNORECASE | re.ASCII
)


def is_zip_split_segment_name(archive_name: str | None) -> bool:
    """True when ``archive_name`` is an Info-ZIP ``.zNN`` or 7-Zip ``.zip.NNN`` part.

    Callers must pair this with "was the set joined?" before refusing: a joined set
    keeps part one's name, so the name alone no longer decides the answer.
    """
    if not archive_name:
        return False
    # PurePath so Windows ``\\`` and POSIX ``/`` both yield the final segment.
    return _ZIP_SPLIT_SEGMENT_RE.search(PurePath(archive_name).name) is not None


LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
LOCAL_HEADER_SIZE = 30

# APPNOTE 6.3.10 tops out at version 6.3 (63). 1.0 (10) is the floor any writer
# produces; 0 is the zero-padded-stub decoy. 99 is a slack ceiling so a slightly
# newer writer is not mistaken for a decoy; random bytes after ``PK\\x03\\x04``
# (e.g. ``0x90`` filler) land well above it.
_VERSION_NEEDED_MIN = 10
_VERSION_NEEDED_MAX = 99

# Unused / PKWARE-reserved general-purpose flag bits: 7–10, 12, 14, 15.
_GP_RESERVED_MASK = 0xD780

# APPNOTE compression-method ids plus WinZip AES (99). Unknown ids fail the
# cheap check; a method this library cannot decode can still identify as ZIP.
_KNOWN_METHODS = frozenset(
    {
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        8,
        9,
        10,
        12,
        14,
        16,
        18,
        19,
        20,  # pre-reassignment zstd; APPNOTE keeps it, 93 is the current id
        93,
        94,  # MP3, written by WinZip for .mp3 members
        95,
        96,
        97,
        98,
        99,
    }
)


def validate_zip_local_header(
    peek_more: Callable[[int], bytes],
    remaining: int | None,
) -> HitOutcome:
    """Return whether a candidate origin looks like a ZIP local file header.

    ``peek_more(n)`` is a view relative to the candidate, not the source.
    ``remaining`` is provable bytes from the candidate to source EOF, or
    ``None`` if unknown. A truncated header, reserved flags, an unknown
    method, or name/extra lengths that overrun the source is
    :attr:`HitOutcome.NOT_THIS_FORMAT` — identity never held. This check
    does not return :attr:`HitOutcome.DAMAGED`.

    When ``remaining`` is known, name/extra existence is a length compare,
    so the check does not read up to 128 KiB of name and extra. When
    ``remaining`` is unknown, the check peeks them, and a short peek (the
    source ended, or the budget clamped the view) is ``NOT_THIS_FORMAT``.
    """
    header = peek_more(LOCAL_HEADER_SIZE)
    if len(header) < LOCAL_HEADER_SIZE or header[:4] != LOCAL_HEADER_SIGNATURE:
        return HitOutcome.NOT_THIS_FORMAT
    (
        version_needed,
        flags,
        method,
        _time,
        _date,
        _crc,
        _csize,
        _usize,
        name_len,
        extra_len,
    ) = struct.unpack_from("<HHHHHIIIHH", header, 4)
    if version_needed < _VERSION_NEEDED_MIN or version_needed > _VERSION_NEEDED_MAX:
        return HitOutcome.NOT_THIS_FORMAT
    if flags & _GP_RESERVED_MASK:
        return HitOutcome.NOT_THIS_FORMAT
    if method not in _KNOWN_METHODS:
        return HitOutcome.NOT_THIS_FORMAT
    # A local header always names its member. Combined with the version floor, this
    # rejects ``PK\\x03\\x04`` plus zero-fill — the usual ELF/PE stub padding.
    if name_len == 0:
        return HitOutcome.NOT_THIS_FORMAT
    needed = LOCAL_HEADER_SIZE + name_len + extra_len
    if remaining is not None:
        if needed > remaining:
            return HitOutcome.NOT_THIS_FORMAT
        return HitOutcome.VALID
    rest = peek_more(needed)
    if len(rest) < needed:
        return HitOutcome.NOT_THIS_FORMAT
    return HitOutcome.VALID
