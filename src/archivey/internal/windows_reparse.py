"""Parsing for the Windows ``REPARSE_DATA_BUFFER`` that archivers store as member data.

A Windows symlink and an NTFS junction are both *reparse points*, and the file
attribute that marks them (``FILE_ATTRIBUTE_REPARSE_POINT``) is the same for both.
What separates them is the **reparse tag**, and the tag does not live in any archive
header: it is the first field of the reparse data buffer, which archivers store as
the member's *content*. So a junction is recognised the same way a symlink target is
read — from the member's data — which is why both backends do this from
``_ensure_link_target`` rather than while listing.

Measured against archives built on a Windows runner (see
``tests/fixtures/external/README.md``): 7-Zip stores this buffer for a **file**
reparse point, and stores **nothing** for a directory one. A junction is always a
directory reparse point, so 7-Zip's output never carries a junction's tag or its
target — the parser below is correct and simply never sees one from that writer.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = [
    "FILE_ATTRIBUTE_REPARSE_POINT",
    "IO_REPARSE_TAG_MOUNT_POINT",
    "IO_REPARSE_TAG_SYMLINK",
    "REPARSE_HEADER_BYTES",
    "ReparsePoint",
    "normalize_windows_link_target",
    "parse_reparse_data",
    "reparse_payload_length",
]

# winnt.h: the attribute bit shared by every reparse point, symlink and junction alike.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# winnt.h reparse tags. Only these two name a link a filesystem user would recognise;
# every other tag (deduplication, cloud placeholders, WSL sockets, …) describes a file
# whose content is not a link target at all, so the parser declines them.
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003  # junction
IO_REPARSE_TAG_SYMLINK = 0xA000000C

# REPARSE_DATA_BUFFER: ULONG ReparseTag, USHORT ReparseDataLength, USHORT Reserved.
_HEADER = struct.Struct("<IHH")
# A caller reads this much first, then the payload length it declares
# (`reparse_payload_length`), which the 16-bit field keeps to 0xFFFF.
REPARSE_HEADER_BYTES = _HEADER.size
# Both tags' payloads open with the same four offsets, in bytes, into PathBuffer.
_NAMES = struct.Struct("<HHHH")
# A SYMLINK payload has an extra ULONG Flags before PathBuffer; MOUNT_POINT has none.
_SYMLINK_FLAGS_SIZE = 4

# The NT object-manager prefix on a substitute name ("\??\C:\dir"), and the Win32
# long-path one ("\\?\C:\dir"), after ``\`` has become ``/``. Each is how Windows
# names the target and is meaningless as a path, so it is stripped. RAR 5.1 and later
# store a Windows link's target with ``/`` separators, so ``/??/`` is also how the
# prefix arrives from a RAR5 redirect record (unrar ``ExtractUnixLink50``).
_NT_PREFIXES = ("/??/", "//?/")
# What follows that prefix for a network target: "\??\UNC\server\share" names
# "\\server\share". Stripping the prefix alone would leave "UNC/server/share", a
# relative path to a directory called UNC.
_NT_UNC_PREFIX = "UNC/"


@dataclass(frozen=True)
class ReparsePoint:
    """A parsed reparse data buffer."""

    tag: int
    """The raw ``IO_REPARSE_TAG_*`` value."""

    target: str
    """Where the link points, with ``\\`` converted to ``/``.

    A reparse path buffer is always a Windows path, so a backslash in it is always a
    separator — unlike a stored member name, where it can be a literal character (see
    :func:`~archivey.internal.naming.resolve_link_target_name`). May be ``""`` when the
    writer stored a buffer with both names empty.
    """

    is_junction: bool
    """True for ``IO_REPARSE_TAG_MOUNT_POINT``."""


def normalize_windows_link_target(target: str) -> str:
    """A Windows link target as a ``/``-separated path, without the NT prefix.

    For the target of a Windows symlink or junction: a reparse buffer's name (ZIP, 7z)
    or a RAR5 redirect of type 2 or 3. Every ``\\`` becomes ``/``, as unrar's
    ``DosSlashToUnix`` does, because a Windows path never holds a literal backslash.
    Then a leading ``\\??\\`` or ``\\\\?\\`` is removed, and ``UNC\\`` after it
    becomes ``//``: ``\\??\\C:\\Windows`` gives ``C:/Windows`` and
    ``\\??\\UNC\\srv\\share`` gives ``//srv/share``. An absolute result is kept as
    it is; extraction refuses it (``filters.check_universal``).

    A POSIX symlink target must not come here: there ``\\`` is an ordinary character.
    """
    target = target.replace("\\", "/")
    for prefix in _NT_PREFIXES:
        if target.startswith(prefix):
            target = target[len(prefix) :]
            if target[: len(_NT_UNC_PREFIX)].upper() == _NT_UNC_PREFIX:
                target = "//" + target[len(_NT_UNC_PREFIX) :]
            break
    return target


def _decode_path(buffer: bytes, offset: int, length: int) -> str:
    if length <= 0 or offset < 0 or offset + length > len(buffer):
        return ""
    # A name length is a byte count over UTF-16 code units, so an odd one is malformed,
    # not merely truncated — and `errors=` does not cover it: a trailing half code unit
    # raises whatever the handler is, `surrogatepass` included. Declining it keeps a
    # crafted archive from raising `UnicodeDecodeError` out of `members()`, and matches
    # what the out-of-bounds guard above already does with a length that does not
    # describe the bytes present. Decoding the even prefix instead would report a
    # truncated path as if the archive had named it.
    if length % 2:
        return ""
    # surrogatepass, not surrogateescape: the source is UTF-16 code units, and Windows
    # permits unpaired surrogates in a path. Replacing them would silently rewrite a
    # target; passing them through keeps the round trip honest.
    return buffer[offset : offset + length].decode("utf-16-le", errors="surrogatepass")


def reparse_payload_length(header: bytes) -> int:
    """Payload bytes a buffer opening with ``header`` declares; 0 if it is not a link one.

    ``header`` is the first :data:`REPARSE_HEADER_BYTES` of the member's data. Reading
    this many more gives :func:`parse_reparse_data` everything it looks at — a real
    symlink buffer is around a hundred bytes — so a reader never decodes more of a
    member than the buffer itself claims to be. A header that is short, or whose tag is
    not a symlink or a junction, declares nothing the parser would use.
    """
    if len(header) < _HEADER.size:
        return 0
    tag, data_length, _reserved = _HEADER.unpack_from(header, 0)
    if tag not in (IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK):
        return 0
    return data_length


def parse_reparse_data(data: bytes) -> ReparsePoint | None:
    """Parse a ``REPARSE_DATA_BUFFER``, or return ``None`` when ``data`` is not one.

    ``None`` means "this is not a link buffer I understand": too short to hold the
    header and the name offsets, a declared payload length shorter than those offsets,
    data that runs on past the declared payload, or a tag that is not a symlink or a
    junction. What a reader does with ``None`` is
    decided in :meth:`~archivey.internal.base_reader.BaseArchiveReader._apply_reparse_data`.

    A truncated buffer, whose declared payload length runs past the end of ``data``,
    parses the bytes that are there: a name that falls outside them decodes as ``""``,
    so the result is a link with no target rather than ``None``.
    """
    if len(data) < _HEADER.size:
        return None
    tag, data_length, _reserved = _HEADER.unpack_from(data, 0)
    if tag not in (IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK):
        return None

    payload = data[_HEADER.size :]
    if len(payload) > data_length:
        # Data that runs on past the buffer the header declares is not that buffer:
        # Windows returns exactly the header and ReparseDataLength bytes. Reading it as
        # a link would leave the bytes after the buffer, and the member's checksum,
        # unread, so a damaged target would list as if it were whole.
        return None
    # The payload is now at most the length declared, and shorter only when the buffer
    # is truncated, which parses what is there rather than raising.
    if len(payload) < _NAMES.size:
        return None

    subst_offset, subst_length, print_offset, print_length = _NAMES.unpack_from(
        payload, 0
    )
    paths_at = _NAMES.size + (
        _SYMLINK_FLAGS_SIZE if tag == IO_REPARSE_TAG_SYMLINK else 0
    )
    paths = payload[paths_at:]

    # PrintName is the form Windows shows the user and is already free of the NT
    # prefix; SubstituteName is the authoritative one and is what a junction always
    # fills in, so it is the fallback rather than the other way round.
    target = _decode_path(paths, print_offset, print_length)
    if not target:
        target = _decode_path(paths, subst_offset, subst_length)

    return ReparsePoint(
        tag=tag,
        target=normalize_windows_link_target(target),
        is_junction=tag == IO_REPARSE_TAG_MOUNT_POINT,
    )
