"""ctypes bindings to the system libarchive, for reading only.

Standard library only: the child process imports this module and nothing of archivey.
A :class:`Session` reads one archive in one format, pulling its bytes through a
callback, so it reads a pipe as well as a file.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import threading
from collections.abc import Callable
from typing import Any

ARCHIVE_EOF = 1
ARCHIVE_OK = 0
ARCHIVE_RETRY = -10
ARCHIVE_WARN = -20
ARCHIVE_FAILED = -25
ARCHIVE_FATAL = -30

AE_IFMT = 0o170000
AE_IFREG = 0o100000
AE_IFLNK = 0o120000
AE_IFDIR = 0o040000

# The oldest libarchive this package is tested with. 3.6 is the oldest still shipped by
# a supported Linux distribution (Debian 12 has 3.6.2).
MIN_VERSION = 3_006_000

# The formats this package reads, by the name of their libarchive support call. Not
# WARC: libarchive 3.7.2 appends four NUL bytes to every record's data (``bsdtar -xO``
# shows them), and a record read to its listed size leaves the next one misread.
FORMATS = ("lha",)

_READ_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
)

_lock = threading.Lock()
_lib: ctypes.CDLL | None = None
_load_error: str | None = None


class LibarchiveError(Exception):
    """A libarchive call failed: its return code, errno and message."""

    def __init__(self, code: int, errno: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.errno = errno
        self.message = message


class LibraryUnavailable(Exception):
    """The system libarchive could not be loaded, or is too old."""


def _declare(lib: ctypes.CDLL) -> None:
    vp, cp, i, i64 = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int64
    sigs: dict[str, tuple[Any, list[Any]]] = {
        "archive_version_number": (i, []),
        "archive_version_string": (cp, []),
        "archive_read_new": (vp, []),
        "archive_read_free": (i, [vp]),
        "archive_read_open": (i, [vp, vp, vp, _READ_CALLBACK, vp]),
        "archive_read_next_header": (i, [vp, ctypes.POINTER(vp)]),
        "archive_read_data": (ctypes.c_ssize_t, [vp, vp, ctypes.c_size_t]),
        "archive_read_data_skip": (i, [vp]),
        "archive_read_support_filter_none": (i, [vp]),
        "archive_error_string": (cp, [vp]),
        "archive_errno": (i, [vp]),
        "archive_entry_pathname": (cp, [vp]),
        "archive_entry_symlink": (cp, [vp]),
        "archive_entry_hardlink": (cp, [vp]),
        "archive_entry_uname": (cp, [vp]),
        "archive_entry_gname": (cp, [vp]),
        "archive_entry_filetype": (ctypes.c_uint, [vp]),
        "archive_entry_perm": (ctypes.c_uint, [vp]),
        "archive_entry_size": (i64, [vp]),
        "archive_entry_size_is_set": (i, [vp]),
        "archive_entry_mtime": (ctypes.c_long, [vp]),
        "archive_entry_mtime_nsec": (ctypes.c_long, [vp]),
        "archive_entry_mtime_is_set": (i, [vp]),
        "archive_entry_uid": (i64, [vp]),
        "archive_entry_gid": (i64, [vp]),
        "archive_entry_is_encrypted": (i, [vp]),
    }
    for name in FORMATS:
        sigs[f"archive_read_support_format_{name}"] = (i, [vp])
    for name, (restype, argtypes) in sigs.items():
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = argtypes


def load() -> ctypes.CDLL:
    """The system libarchive, loaded once. ``LIBARCHIVE`` names a file to load instead
    of the one ``ctypes.util.find_library`` finds. Raises :class:`LibraryUnavailable`."""
    global _lib, _load_error
    with _lock:
        if _lib is not None:
            return _lib
        if _load_error is not None:
            raise LibraryUnavailable(_load_error)
        path = os.environ.get("LIBARCHIVE") or ctypes.util.find_library("archive")
        try:
            if path is None:
                raise OSError("no libarchive found on the library search path")
            lib = ctypes.CDLL(path)
            _declare(lib)
            version = lib.archive_version_number()
            if version < MIN_VERSION:
                raise OSError(
                    f"libarchive {lib.archive_version_string().decode()} is older than "
                    "3.6.0"
                )
        except (OSError, AttributeError) as exc:
            _load_error = f"the system libarchive cannot be used: {exc}"
            raise LibraryUnavailable(_load_error) from None
        _lib = lib
        return lib


def version_string() -> str:
    return load().archive_version_string().decode("ascii", "replace")


def _text(value: bytes | None) -> str:
    return "" if value is None else value.decode("utf-8", "replace")


class Session:
    """One archive read in one format, forward only.

    ``read_input(n)`` returns up to ``n`` more bytes of the archive, ``b""`` at its end.
    Errors raise :class:`LibarchiveError`, including a warning on a data read: libarchive
    reports a CRC mismatch at the end of a member's data as ``ARCHIVE_WARN``.
    """

    CHUNK = 64 << 10

    def __init__(self, fmt: str, read_input: Callable[[int], bytes]) -> None:
        if fmt not in FORMATS:
            raise ValueError(f"unknown format {fmt}")
        self._lib = load()
        self._read_input = read_input
        self._buffer = ctypes.create_string_buffer(0)
        self._callback_error: BaseException | None = None
        # Kept on the instance: libarchive calls it until the archive is freed.
        self._callback = _READ_CALLBACK(self._on_read)
        self._entry = ctypes.c_void_p()
        self._archive = self._lib.archive_read_new()
        if not self._archive:
            raise MemoryError("archive_read_new failed")
        try:
            self._check(
                getattr(self._lib, f"archive_read_support_format_{fmt}")(self._archive)
            )
            self._check(self._lib.archive_read_support_filter_none(self._archive))
            self._check(
                self._lib.archive_read_open(
                    self._archive, None, None, self._callback, None
                )
            )
        except BaseException:
            self.close()
            raise

    def _on_read(self, _archive: int, _client: int, buffer: Any) -> int:
        try:
            data = self._read_input(self.CHUNK)
        except BaseException as exc:  # noqa: BLE001 - re-raised once libarchive returns
            self._callback_error = exc
            return -1
        self._buffer = ctypes.create_string_buffer(data, len(data))
        buffer[0] = ctypes.cast(self._buffer, ctypes.c_void_p)
        return len(data)

    def _error(self, code: int) -> LibarchiveError:
        if self._callback_error is not None:
            exc, self._callback_error = self._callback_error, None
            raise exc
        return LibarchiveError(
            code,
            self._lib.archive_errno(self._archive),
            _text(self._lib.archive_error_string(self._archive)) or "libarchive error",
        )

    def _check(self, code: int) -> int:
        if code < ARCHIVE_OK:
            raise self._error(code)
        return code

    def next_header(self) -> dict[str, object] | None:
        """The next entry's fields, or ``None`` at the end of the archive. A warning
        that left the entry readable (a name that could not be converted) comes back
        as ``"warning"``."""
        code = self._lib.archive_read_next_header(
            self._archive, ctypes.byref(self._entry)
        )
        if code == ARCHIVE_EOF:
            if self._callback_error is not None:
                raise self._error(code)
            return None
        warning = None
        if code == ARCHIVE_WARN:
            warning = self._error(code).message
        elif code < ARCHIVE_OK:
            raise self._error(code)
        lib, entry = self._lib, self._entry
        return {
            "path": lib.archive_entry_pathname(entry),
            "symlink": lib.archive_entry_symlink(entry),
            "hardlink": lib.archive_entry_hardlink(entry),
            "uname": lib.archive_entry_uname(entry),
            "gname": lib.archive_entry_gname(entry),
            "filetype": lib.archive_entry_filetype(entry) & AE_IFMT,
            "perm": lib.archive_entry_perm(entry),
            "size": lib.archive_entry_size(entry)
            if lib.archive_entry_size_is_set(entry)
            else None,
            "mtime": lib.archive_entry_mtime(entry)
            if lib.archive_entry_mtime_is_set(entry)
            else None,
            "mtime_nsec": lib.archive_entry_mtime_nsec(entry),
            "uid": lib.archive_entry_uid(entry),
            "gid": lib.archive_entry_gid(entry),
            "encrypted": bool(lib.archive_entry_is_encrypted(entry) > 0),
            "warning": warning,
        }

    def read(self, n: int) -> bytes:
        """Up to ``n`` bytes of the current entry's data; ``b""`` at its end."""
        buf = ctypes.create_string_buffer(n)
        got = self._lib.archive_read_data(self._archive, buf, n)
        if got < 0:
            raise self._error(got)
        return buf.raw[:got]

    def skip(self) -> None:
        self._check(self._lib.archive_read_data_skip(self._archive))

    def close(self) -> None:
        if self._archive:
            self._lib.archive_read_free(self._archive)
            self._archive = None
