"""ctypes bindings to the system libarchive, for reading only.

Standard library only: the child process imports this module and nothing of archivey.
A :class:`Session` reads one archive in one format, pulling its bytes through a
callback, so it reads a pipe as well as a file.
"""

from __future__ import annotations

import codecs
import contextlib
import ctypes
import ctypes.util
import os
import re
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
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


_TEXT_FIELDS = ("pathname", "symlink", "hardlink", "uname", "gname")


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
        "archive_read_set_format_option": (i, [vp, cp, cp, cp]),
        "archive_read_header_position": (i64, [vp]),
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
    for field in _TEXT_FIELDS:
        sigs[f"archive_entry_{field}"] = (cp, [vp])
        sigs[f"archive_entry_{field}_utf8"] = (cp, [vp])
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


# ── Locale ──────────────────────────────────────────────────────────────────────────
#
# libarchive turns names into wide characters through the C library's current locale,
# so under ``LC_ALL=C`` a CP932 name cannot be converted at all. Each call into
# libarchive runs with a UTF-8 LC_CTYPE set for its own thread only (``uselocale``),
# which leaves the rest of the process, and an in-process caller, as they were.

_LC_CTYPE_MASK = 1 << 1 if sys.platform == "darwin" else 1 << 0
_UTF8_LOCALES = (b"C.UTF-8", b"C.utf8", b"en_US.UTF-8", b"UTF-8")
_utf8_locale: int | None = None
_locale_looked_up = False


def _thread_locale() -> tuple[Any, int | None]:
    """The C library's ``uselocale`` and a UTF-8 LC_CTYPE locale, or ``None`` where
    there is none (the calls then run in the process locale)."""
    global _utf8_locale, _locale_looked_up
    libc = _libc()
    with _lock:
        if not _locale_looked_up:
            _locale_looked_up = True
            if libc is not None:
                for name in _UTF8_LOCALES:
                    loc = libc.newlocale(_LC_CTYPE_MASK, name, None)
                    if loc:
                        _utf8_locale = loc
                        break
    return libc, _utf8_locale


_libc_handle: Any = None


def _libc() -> Any:
    global _libc_handle
    if _libc_handle is None:
        try:
            libc = ctypes.CDLL(None)
            libc.newlocale.restype = ctypes.c_void_p
            libc.newlocale.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p]
            libc.uselocale.restype = ctypes.c_void_p
            libc.uselocale.argtypes = [ctypes.c_void_p]
        except (OSError, AttributeError):
            libc = False
        _libc_handle = libc
    return _libc_handle or None


@contextlib.contextmanager
def _utf8() -> Iterator[None]:
    libc, loc = _thread_locale()
    if loc is None:
        yield
        return
    old = libc.uselocale(loc)
    try:
        yield
    finally:
        libc.uselocale(old)


# ── Header bytes ─────────────────────────────────────────────────────────────────────

_CHARSET = re.compile(rb"[A-Za-z0-9._:-]{1,40}")


def charset_name(encoding: str) -> bytes:
    """The iconv name libarchive takes for a Python codec name (``latin-1`` becomes
    ``ISO8859-1``). Raises ``LookupError`` for an unknown codec."""
    name = codecs.lookup(encoding).name.upper().replace("_", "-").encode("ascii")
    if not _CHARSET.fullmatch(name):
        raise LookupError(encoding)
    return name


# An LHA header, at every level, has its method id at offset 2 and its level at 20.
_LHA_METHOD = re.compile(rb"-l[hz][0-9a-z]-")
_KEEP_INPUT = 4 * (64 << 10)


# Extended header records that set the Unix mode, and the owner, as libarchive's LHA
# reader takes them: (type, data size).
_MODE_RECORDS = frozenset({(0x50, 2), (0x7F, 16), (0xFF, 20)})
_OWNER_RECORDS = frozenset({(0x51, 4), (0x7F, 16), (0xFF, 20)})


def _lha_records(
    at: Callable[[int, int], bytes], level: int, base: bytes
) -> set[tuple[int, int]] | None:
    """The (type, data size) of each extended header record, walked as libarchive
    walks them; ``None`` when the bytes run out first."""
    if level == 1:
        start, width = base[0], 2  # header size - 2, then records
    elif level == 2:
        start, width = 24, 2
    else:
        start, width = 28, 4
    records: set[tuple[int, int]] = set()
    pos = start
    for _ in range(1 << 12):
        field = at(pos, width)
        if len(field) < width:
            return None
        size = int.from_bytes(field, "little")
        if size == 0:
            return records
        if size <= width:
            return None
        kind = at(pos + width, 1)
        if not kind:
            return None
        records.add((kind[0], size - width - 1))
        pos += size
    return None


def _lha_header_fields(at: Callable[[int, int], bytes]) -> dict[str, object]:
    """What the plugin needs from an LHA header that libarchive does not say: its
    level, for levels 0 and 1 the DOS time, and whether the header stores a Unix mode
    and owner (libarchive makes up 0666 or 0777, and uid and gid 0, when it does
    not). ``at(offset, n)`` reads the header's bytes."""
    header = at(0, 24)
    level = header[20]
    fields: dict[str, object] = {"lha_level": level}
    if level in (0, 1):
        fields["lha_dos_time"] = int.from_bytes(header[15:19], "little")
    if level == 0:
        # LHa for UNIX's 12-byte extension: 'U', a version, mtime, mode, uid, gid.
        size, namelen = header[0] + 2, header[21]
        unix = size - 24 - namelen == 12 and at(24 + namelen, 1) == b"U"
        fields["lha_mode_stored"] = fields["lha_owner_stored"] = unix
        return fields
    records = _lha_records(at, level, header)
    if records is not None:
        fields["lha_mode_stored"] = bool(records & _MODE_RECORDS)
        fields["lha_owner_stored"] = bool(records & _OWNER_RECORDS)
    return fields


def _dos_mktime(stamp: int) -> int | None:
    """What libarchive's ``lha_dos_time`` returns for a DOS time: ``mktime`` of its
    fields in this process's time zone, or ``None`` when ``mktime`` refuses them."""
    t, d = stamp & 0xFFFF, stamp >> 16
    fields = (
        ((d >> 9) & 0x7F) + 1980,
        (d >> 5) & 0x0F,
        d & 0x1F,
        (t >> 11) & 0x1F,
        (t >> 5) & 0x3F,
        (t << 1) & 0x3E,
        0,
        0,
        -1,
    )
    try:
        return int(time.mktime(fields))
    except (OverflowError, ValueError):
        return None


class Session:
    """One archive read in one format, forward only.

    ``read_input(n)`` returns up to ``n`` more bytes of the archive, ``b""`` at its end.
    Errors raise :class:`LibarchiveError`, including a warning on a data read: libarchive
    reports a CRC mismatch at the end of a member's data as ``ARCHIVE_WARN``.
    """

    CHUNK = 64 << 10

    def __init__(
        self,
        fmt: str,
        read_input: Callable[[int], bytes],
        hdrcharset: str | None = None,
    ) -> None:
        if fmt not in FORMATS:
            raise ValueError(f"unknown format {fmt}")
        self._fmt = fmt
        self._lib = load()
        self._read_input = read_input
        # The last input chunks, by offset, to read a header's own bytes back.
        self._window: deque[tuple[int, bytes]] = deque()
        self._window_bytes = 0
        self._fed = 0
        self._buffer = ctypes.create_string_buffer(0)
        self._callback_error: BaseException | None = None
        # Kept on the instance: libarchive calls it until the archive is freed.
        self._callback = _READ_CALLBACK(self._on_read)
        self._entry = ctypes.c_void_p()
        self._archive = self._lib.archive_read_new()
        if not self._archive:
            raise MemoryError("archive_read_new failed")
        try:
            with _utf8():
                self._open(fmt, hdrcharset)
        except BaseException:
            self.close()
            raise

    def _open(self, fmt: str, hdrcharset: str | None) -> None:
        lib, archive = self._lib, self._archive
        self._check(getattr(lib, f"archive_read_support_format_{fmt}")(archive))
        self._check(lib.archive_read_support_filter_none(archive))
        if hdrcharset is not None:
            try:
                charset = charset_name(hdrcharset)
            except LookupError:
                charset = None
            if charset is None or lib.archive_read_set_format_option(
                archive, fmt.encode(), b"hdrcharset", charset
            ):
                raise LibarchiveError(
                    ARCHIVE_FAILED,
                    0,
                    f"names in {hdrcharset!r} are not supported by this libarchive",
                )
        self._check(lib.archive_read_open(archive, None, None, self._callback, None))

    def _on_read(self, _archive: int, _client: int, buffer: Any) -> int:
        try:
            data = self._read_input(self.CHUNK)
        except BaseException as exc:  # noqa: BLE001 - re-raised once libarchive returns
            self._callback_error = exc
            return -1
        self._buffer = ctypes.create_string_buffer(data, len(data))
        buffer[0] = ctypes.cast(self._buffer, ctypes.c_void_p)
        if data:
            self._window.append((self._fed, data))
            self._window_bytes += len(data)
            self._fed += len(data)
            while self._window_bytes - len(self._window[0][1]) >= _KEEP_INPUT:
                self._window_bytes -= len(self._window.popleft()[1])
        return len(data)

    def _input_at(self, pos: int, n: int) -> bytes:
        """Up to ``n`` input bytes from offset ``pos``, as far as the window holds."""
        out = bytearray()
        for start, data in self._window:
            want = pos + len(out)
            if start + len(data) <= want:
                continue
            if start > want:
                break
            out += data[want - start : want - start + n - len(out)]
            if len(out) >= n:
                break
        return bytes(out)

    def _lha_header(self) -> dict[str, object]:
        """The current LHA header's level, attribute and DOS time, from its bytes.

        libarchive gives the header's position; when the bytes there are not a header
        (junk it skipped before the first one), the first method id after it in the
        input window marks it. Empty when the window holds no header there."""
        pos = self._lib.archive_read_header_position(self._archive)
        header = self._input_at(pos, 24)
        if len(header) < 24 or not _LHA_METHOD.fullmatch(header, 2, 7):
            ahead = self._input_at(pos, _KEEP_INPUT)
            match = _LHA_METHOD.search(ahead, 2)
            if match is None:
                return {}
            pos += match.start() - 2
            header = self._input_at(pos, 24)
        if len(header) < 24 or header[20] > 3:
            return {}
        start = pos
        return _lha_header_fields(lambda offset, n: self._input_at(start + offset, n))

    def _error(self, code: int) -> LibarchiveError:
        if self._callback_error is not None:
            exc, self._callback_error = self._callback_error, None
            raise exc
        message = _text(self._lib.archive_error_string(self._archive))
        if not message and self._fmt == "lha":
            # A level-0 or level-1 name in neither UTF-8 nor CP932 fails libarchive's
            # conversion with no message.
            message = (
                "libarchive refused an entry header without saying why; a name in "
                "neither UTF-8 nor CP932 needs encoding="
            )
        return LibarchiveError(
            code, self._lib.archive_errno(self._archive), message or "libarchive error"
        )

    def _check(self, code: int) -> int:
        if code < ARCHIVE_OK:
            raise self._error(code)
        return code

    def next_header(self) -> dict[str, object] | None:
        """The next entry's fields, or ``None`` at the end of the archive. A warning
        that left the entry readable (a name that could not be converted) comes back
        as ``"warning"``."""
        with _utf8():
            return self._next_header()

    def _text_field(self, field: str) -> bytes | None:
        lib, entry = self._lib, self._entry
        value = getattr(lib, f"archive_entry_{field}_utf8")(entry)
        if value is None:
            # No UTF-8 form: the bytes as libarchive holds them.
            value = getattr(lib, f"archive_entry_{field}")(entry)
        return value

    def _next_header(self) -> dict[str, object] | None:
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
        fields: dict[str, object] = {
            "path": self._text_field("pathname"),
            "symlink": self._text_field("symlink"),
            "hardlink": self._text_field("hardlink"),
            "uname": self._text_field("uname"),
            "gname": self._text_field("gname"),
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
        if self._fmt == "lha":
            fields.update(self._lha_header())
            dos = fields.get("lha_dos_time")
            # libarchive's mtime is the DOS time read in this process's time zone,
            # unless a Unix or Windows time in the header replaced it.
            fields["mtime_is_dos"] = isinstance(dos, int) and fields["mtime"] == (
                _dos_mktime(dos)
            )
        return fields

    def read(self, n: int) -> bytes:
        """Up to ``n`` bytes of the current entry's data; ``b""`` at its end."""
        buf = ctypes.create_string_buffer(n)
        with _utf8():
            got = self._lib.archive_read_data(self._archive, buf, n)
        if got < 0:
            raise self._error(got)
        return buf.raw[:got]

    def skip(self) -> None:
        with _utf8():
            self._check(self._lib.archive_read_data_skip(self._archive))

    def close(self) -> None:
        if self._archive:
            self._lib.archive_read_free(self._archive)
            self._archive = None
