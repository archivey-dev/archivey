"""Set a file's birth time, on the systems that let a program set it.

Windows sets it with ``SetFileTime`` and macOS with ``setattrlist`` (``ATTR_CMN_CRTIME``).
Linux has no call that sets it: the kernel stamps ``statx``'s ``btime`` itself. Python
has no wrapper for either call, so both go through :mod:`ctypes`.

Extraction calls :func:`set_birth_time` after ``os.utime``, best effort as the rest of
a member's metadata: a failure leaves the time the file was written.
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND = timedelta(microseconds=1)


def _microseconds_since(epoch: datetime, when: datetime) -> int:
    """Whole microseconds from ``epoch`` to ``when``, exactly: a ``timestamp()`` float
    times 10**7 or 10**9 is past the integers a float holds exactly. A naive ``when``
    is local time, as ``datetime.timestamp()`` reads it."""
    if when.tzinfo is None:
        when = when.astimezone()
    return (when - epoch) // _MICROSECOND


def _windows_setter() -> Callable[[str | int, datetime], bool] | None:
    # Checked here, not only by the caller, so a type checker on another system
    # skips the Windows-only names below.
    if sys.platform != "win32":
        return None
    from ctypes import wintypes

    # pyrefly: ignore[missing-attribute]  # Windows-only; pyrefly ignores the guard
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class FILETIME(ctypes.Structure):
        _fields_ = (
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        )

    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    set_file_time = kernel32.SetFileTime
    set_file_time.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    )
    set_file_time.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    invalid = wintypes.HANDLE(-1).value
    file_write_attributes = 0x0100
    share_all = 0x1 | 0x2 | 0x4
    open_existing = 3
    # A directory opens only with backup semantics; a reparse point is changed itself.
    flags = 0x02000000 | 0x00200000

    def set_windows(target: str | int, when: datetime) -> bool:
        ticks = _microseconds_since(_FILETIME_EPOCH, when) * 10
        if not 0 <= ticks < 1 << 63:
            return False
        stamp = FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)
        if isinstance(target, int):
            # Extraction hands a descriptor only for a folder where os.chown takes
            # one, which never happens on Windows; and a descriptor opened read-only
            # gives a handle SetFileTime refuses. So a descriptor is not set.
            return False
        handle = create_file(
            target, file_write_attributes, share_all, None, open_existing, flags, None
        )
        if handle in (None, invalid):
            return False
        try:
            return bool(set_file_time(handle, ctypes.byref(stamp), None, None))
        finally:
            close_handle(handle)

    return set_windows


def _macos_setter() -> Callable[[str | int, datetime], bool] | None:
    libc = ctypes.CDLL(None, use_errno=True)

    class AttrList(ctypes.Structure):
        _fields_ = (
            ("bitmapcount", ctypes.c_ushort),
            ("reserved", ctypes.c_uint16),
            ("commonattr", ctypes.c_uint32),
            ("volattr", ctypes.c_uint32),
            ("dirattr", ctypes.c_uint32),
            ("fileattr", ctypes.c_uint32),
            ("forkattr", ctypes.c_uint32),
        )

    class TimeSpec(ctypes.Structure):
        _fields_ = (("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long))

    attr_bit_map_count = 5
    attr_cmn_crtime = 0x00000200
    fsopt_nofollow = 0x00000001
    setattrlist = libc.setattrlist
    setattrlist.argtypes = (
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
    )
    setattrlist.restype = ctypes.c_int
    fsetattrlist = libc.fsetattrlist
    fsetattrlist.argtypes = (
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
    )
    fsetattrlist.restype = ctypes.c_int

    def set_macos(target: str | int, when: datetime) -> bool:
        attrs = AttrList(attr_bit_map_count, 0, attr_cmn_crtime, 0, 0, 0, 0)
        ns = _microseconds_since(_UNIX_EPOCH, when) * 1000
        stamp = TimeSpec(*divmod(ns, 1_000_000_000))
        size = ctypes.sizeof(stamp)
        if isinstance(target, int):
            result = fsetattrlist(
                target, ctypes.byref(attrs), ctypes.byref(stamp), size, 0
            )
        else:
            result = setattrlist(
                os.fsencode(target),
                ctypes.byref(attrs),
                ctypes.byref(stamp),
                size,
                fsopt_nofollow,
            )
        return result == 0

    return set_macos


def _platform_setter() -> Callable[[str | int, datetime], bool] | None:
    try:
        if sys.platform == "win32":
            return _windows_setter()
        if sys.platform == "darwin":
            return _macos_setter()
    except (OSError, AttributeError):
        pass
    return None


_SETTER = _platform_setter()


def can_set_birth_time() -> bool:
    """Whether this system lets :func:`set_birth_time` set anything."""
    return _SETTER is not None


def set_birth_time(target: str | int, when: datetime) -> bool:
    """Set the birth time of the file at ``target`` (a path, or on macOS a descriptor)
    to ``when``, without following a symlink; return whether it was set.

    A naive ``when`` is local time, as ``os.utime`` takes ``datetime.timestamp()``.
    Never raises for a refused or out-of-range time: it returns ``False``.
    """
    if _SETTER is None:
        return False
    try:
        return _SETTER(target, when)
    except (OSError, ValueError, OverflowError):
        return False
