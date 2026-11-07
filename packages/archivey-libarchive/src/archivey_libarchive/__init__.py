"""Formats archivey reads through the system libarchive: today LHA (``.lzh``,
``.lha``).

Call :func:`register` once, before opening archives::

    import archivey
    import archivey_libarchive

    archivey_libarchive.register()
    with archivey.open_archive("old.lzh") as archive:
        ...

libarchive runs in a child process unless ``process_isolation`` is
``ProcessIsolation.NONE``, since it is C code reading untrusted bytes.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from archivey_libarchive._libarchive import LibraryUnavailable, version_string

if TYPE_CHECKING:
    from archivey_libarchive._formats import LHA, LibarchiveContainer

__all__ = [
    "LHA",
    "LibarchiveContainer",
    "LibraryUnavailable",
    "libarchive_version",
    "register",
]

_lock = threading.Lock()
_registered = False


def register() -> None:
    """Make archivey read the formats this package adds, in this process. A second
    call does nothing."""
    global _registered
    from archivey.formats import register_format
    from archivey_libarchive._formats import HANDLERS

    with _lock:
        if _registered:
            return
        for handler in HANDLERS:
            register_format(handler)
        _registered = True


def libarchive_version() -> str:
    """The version of the libarchive this package loads, such as
    ``"libarchive 3.7.2"``. Raises :class:`LibraryUnavailable` when there is none."""
    return version_string()


def __getattr__(name: str) -> object:
    # The child process imports this package for its worker, which must not import
    # archivey: the archivey names load on first use.
    if name in ("LHA", "LibarchiveContainer"):
        from archivey_libarchive import _formats

        return getattr(_formats, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
