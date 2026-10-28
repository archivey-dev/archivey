"""Paths past Windows' ``MAX_PATH`` for the filesystem calls extraction makes.

Win32 refuses a path of 260 characters or more (248 for a directory it creates) unless
the machine sets ``LongPathsEnabled``, and reports it as a missing path. An archive that
extracts in full on POSIX then fails on Windows partway down a deep tree. A path in the
extended form, ``\\\\?\\C:\\...`` (``\\\\?\\UNC\\server\\share\\...`` for a network
path), has no such limit, so on Windows every filesystem call the extraction makes
under the destination takes its path through :func:`long_path`.

The extended form is for the call only. Results, errors and diagnostics name a path
as the caller would write it: :func:`plain` strips the prefix from what a call hands
back (``os.path.realpath``, an ``OSError``'s file names). The path-safety checks compare
those plain paths with the destination root.

Only a path at or past :data:`_SHORT_LIMIT` characters, once absolute, gets the prefix.
A shorter one is passed as given, so its behaviour is the one Windows has always had.
Win32 normalizes a path before the prefix is added (``ntpath.abspath``, which on Windows
is ``GetFullPathNameW``): separators, ``.`` and ``..`` components, and trailing dots and
spaces on a component are treated as for a short path, so the extended form names the
file the short form would.
"""

from __future__ import annotations

import ntpath
import os

# A module attribute, not ``os.name`` at each use, so a test can take the Windows path
# on POSIX.
_ENABLED = os.name == "nt"

# Below MAX_PATH (260) and CreateDirectory's 248 with room to spare: extraction adds a
# temporary name of up to 46 characters (``.archivey-tmp-`` and a uuid4) to a directory
# that passed through here.
_SHORT_LIMIT = 200

_EXTENDED = "\\\\?\\"
_EXTENDED_UNC = "\\\\?\\UNC\\"
_DEVICE = "\\\\.\\"

# What :func:`plain` strips: each extended prefix, and what it stands for.
_PREFIXES: tuple[tuple[str, str], ...] = ((_EXTENDED_UNC, "\\\\"), (_EXTENDED, ""))


def long_path(path: str | os.PathLike[str]) -> str | os.PathLike[str]:
    """``path`` for a filesystem call: in the extended form on Windows when it is long,
    else ``path`` itself."""
    if not _ENABLED:
        return path
    return extended(os.fspath(path))


def extended(path: str) -> str:
    """``path`` in the extended form when it is :data:`_SHORT_LIMIT` characters or more
    once absolute; else ``path`` unchanged. A path already in the extended form or the
    device namespace (``\\\\.\\``) is unchanged too."""
    if path.startswith((_EXTENDED, _DEVICE)):
        return path
    # Normalizing cannot lengthen an absolute path, so a short one needs no
    # ``GetFullPathNameW`` to be measured.
    if ntpath.isabs(path) and len(path) < _SHORT_LIMIT:
        return path
    full = ntpath.abspath(path)
    if len(full) < _SHORT_LIMIT or full.startswith((_EXTENDED, _DEVICE)):
        return path
    if full.startswith("\\\\"):
        return _EXTENDED_UNC + full[2:]
    return _EXTENDED + full


def plain(path: str) -> str:
    """``path`` without an extended prefix: how the caller would write it."""
    for prefix, replacement in _PREFIXES:
        if path.startswith(prefix):
            return replacement + path[len(prefix) :]
    return path
