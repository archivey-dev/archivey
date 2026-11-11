"""CLI wrapper around RARLAB ``unrar`` / ``rar`` for member **payload** bytes.

No RAR structure knowledge beyond argv safety — metadata/listing is
:mod:`.rar_parser`. Locates a RARLAB decompressor on ``PATH`` (``unrar`` first,
then the trialware writer ``rar``; not ``unrar-free`` / ``unar`` / ``7z``), or on
Windows in WinRAR's Program Files folder, and
spawns ``<binary> p`` with the password on stdin (bare ``-p``, secret not in
argv) and optional ``-n./member`` include masks. Never ``x`` / extract-to-disk.

:mod:`.rar_reader` calls :func:`open_unrar_p` for every member read and solid pass
that runs ``unrar``, and :func:`decompress_rar3_blob` for a compressed RAR 1.5-4
comment. :func:`find_rarlab_unrar` is the 6.0 banner probe: :func:`open_unrar_p`
runs it before each spawn, :mod:`.rar_reader` runs it to resolve
``RarDecompressor.AUTO``, and ``format_availability`` runs it through
:func:`rarlab_unrar_missing`.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from archivey.exceptions import (
    PackageNotInstalledError,
    ReadError,
    ResourceUnavailableError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.rar_parser import (
    _RAR3_FILE,
    _RAR3_FILE_PASSWORD,
    _RAR3_FILE_SALT,
    _RAR3_LONG_BLOCK,
    _RAR3_M0,
    _RAR3_MAIN,
    _S_BLK_HDR,
    _S_FILE_HDR,
    RAR3_MAX_COMMENT_SIZE,
    RAR_ID,
    _normalize_password_utf8,
    _normalize_password_utf16le,
)
from archivey.internal.external.cli import (
    spawn_for_stdout,
    stat_identity,
    terminate_process,
)
from archivey.terminal import display_path, quoted
from archivey.types import MissingComponent

# Inclusive major.minor floor. ``-n`` glob demux and ``-ver`` were checked
# against RARLAB unrar 6.02, 6.12, 6.24, and 7.00 (RAR data tests plus
# ``scripts/investigations/exploration/rar_unrar_input_matrix.py``). On 7.00, ``rar p``
# matched ``unrar p`` on the argv archivey actually spawns. 5.91 passed those
# tests too, but hangs on an anonymous-fd multi-volume probe that 6.12+
# exits 3 on — a path archivey does not use. Floor is 6.0 so Debian 12 /
# Ubuntu 22.04 apt packages work; 5.x is still refused. Parsed from the
# identification banner, not from a second spawn.
_UNRAR_VERSION_FLOOR: tuple[int, int] = (6, 0)
# Prefer the freeware reader. The writer is the same vendor's decompressor
# under a different PATH name (Ubuntu ``apt install rar`` Suggests ``unrar``
# and does not put ``unrar`` on PATH).
_RARLAB_BINARY_NAMES: tuple[str, ...] = ("unrar", "rar")
# On Windows, WinRAR's installer puts both programs in its own folder and does not
# add that folder to PATH, so the finder also looks there when PATH has no usable
# program. The variables name the 64-bit and the 32-bit Program Files folders;
# writing there needs administrator rights.
_ON_WINDOWS = sys.platform == "win32"
_WINRAR_EXE_NAMES: tuple[str, ...] = ("UnRAR.exe", "Rar.exe")
_WINDOWS_PROGRAM_FILES_VARS: tuple[str, ...] = (
    "ProgramW6432",
    "ProgramFiles",
    "ProgramFiles(x86)",
)
# Bound the digit runs: an unbounded run then ``int()`` raises ``ValueError``
# past CPython's 4300-digit limit, and that must not cross ``open_archive``.
# ``[0-9]`` and ``[ \t]``, not ``\d`` and ``\s``: those match Unicode digits and
# spaces, and ``\s`` also a newline, which would pair a token with a version on the
# next line (``tests/test_src_regex_ascii.py`` holds the rule).
# ``(?<![A-Za-z])`` so ``RAR`` does not match inside ``UNRAR``.
_UNRAR_VERSION_RE = re.compile(r"(?<![A-Za-z])UNRAR[ \t]+([0-9]{1,4})\.([0-9]{1,4})")
_RAR_VERSION_RE = re.compile(r"(?<![A-Za-z])RAR[ \t]+([0-9]{1,4})\.([0-9]{1,4})")
_UNRAR_TOKEN_RE = re.compile(r"(?<![A-Za-z])UNRAR(?![A-Za-z])")
_RAR_TOKEN_RE = re.compile(r"(?<![A-Za-z])RAR(?![A-Za-z])")


@dataclass(frozen=True, slots=True)
class _UnrarBanner:
    """RARLAB verdict and major.minor from one identification banner."""

    is_rarlab: bool
    version: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class _UnrarProbe:
    """Banner verdict for one resolved decompressor path, plus the stat identity
    that lets a later call skip the subprocess.

    Keyed on the absolute candidate, not on ``PATH``. ``shutil.which`` re-runs
    every call, so a newly installed binary is visible without editing ``PATH``.
    The finder walks ``unrar`` then ``rar``; one cache entry per resolved
    absolute path it has probed (on a stable ``PATH``, at most one per name).
    Entries persist for the process lifetime so a lookalike ``unrar`` plus a
    usable ``rar`` does not re-probe both on every member read.
    The lookup does not key cwd or ``PATHEXT`` (Windows ``which`` consults both).
    ``version`` is parsed from the same banner as ``is_rarlab`` — a genuine
    RARLAB binary that is too old (or unparseable) stays ``is_rarlab=True``.
    ``timed_out`` marks a binary that ran and printed no banner within
    ``_PROBE_TIMEOUT_SECONDS``; it is ``is_rarlab=False`` and the refusal names it.
    """

    unrar_path: str
    is_rarlab: bool
    version: tuple[int, int] | None
    st_dev: int
    st_ino: int
    st_mtime_ns: int
    st_size: int
    timed_out: bool = False


# Keyed by absolute path. A durable "not RARLAB" answer stores
# ``is_rarlab=False`` so a lookalike costs one process, not one per attempted
# read. A too-old (or unparseable) RARLAB banner stores ``is_rarlab=True`` and
# is still refused. A probe that timed out stores ``is_rarlab=False`` with
# ``timed_out=True``: the binary ran and did not answer, and re-probing would
# cost the full timeout on every member read. That makes a one-off slow start
# permanent for the process unless the binary changes on disk; the refusal
# names the binary and the timeout on every lookup, so the cause stays visible.
# A ``which`` miss and a probe that could not *run* the binary (``OSError``,
# e.g. ``EMFILE``) are not stored.
_cached_unrar: dict[str, _UnrarProbe] = {}

# Seconds the identification probe may run. A binary that has not printed its
# banner by then is cached as not RARLAB (see ``_cached_unrar``).
_PROBE_TIMEOUT_SECONDS: float = 10

# ``rar`` / ``unrar`` prepend ``switches=`` from ``~/.rarrc`` / ``~/.unrarrc``.
# Archivey builds a complete argv; ``-cfg-`` keeps those files from injecting
# ``-idq`` (empty identification banner) or ``-x`` (empty ``p`` pipe).
_RAR_DISABLE_CONFIG = "-cfg-"

# Appended to every refusal of a member unrar cannot be pointed at. unar
# addresses entries by index, so none of those reasons apply to it.
UNAR_BY_POSITION_HINT = (
    "Set ArchiveyConfig.rar_decompressor to 'unar' to read it by position instead."
)

_NOT_INSTALLED_MSG = (
    "RARLAB unrar or rar is required to read RAR member data, but neither was found "
    "on PATH or, on Windows, in WinRAR's folder under Program Files (or the one found "
    "is not a RARLAB binary). Install RARLAB unrar or rar 6.0 or later and put it on "
    "PATH; unrar-free, 7z and 7zz are not substitutes. With "
    "ArchiveyConfig.rar_decompressor 'auto' or 'unar', a unar 1.10 or later that "
    "passes archivey's RAR5 check reads most RAR data too; Debian and Ubuntu packages "
    "before 1.10.8+ds1-10 fail that check and are not used."
)


def _parse_unrar_banner(text: str) -> _UnrarBanner:
    """Classify a banner already captured by the identification probe.

    RARLAB ``unrar`` prints ``UNRAR x.yy … Alexander Roshal``. The trialware
    writer prints ``RAR x.yy … Alexander Roshal`` (often with ``Trial version``).
    A ``RAR`` token must not match inside ``UNRAR``.
    """
    if "Alexander Roshal" not in text and "RARLAB" not in text:
        return _UnrarBanner(is_rarlab=False, version=None)
    if _UNRAR_TOKEN_RE.search(text) is None and _RAR_TOKEN_RE.search(text) is None:
        return _UnrarBanner(is_rarlab=False, version=None)
    match = _UNRAR_VERSION_RE.search(text) or _RAR_VERSION_RE.search(text)
    if match is None:
        return _UnrarBanner(is_rarlab=True, version=None)
    return _UnrarBanner(
        is_rarlab=True,
        version=(int(match.group(1)), int(match.group(2))),
    )


def _is_rarlab_unrar(path: str) -> _UnrarBanner:
    """Spawn ``path`` once and parse the RARLAB banner plus major.minor.

    ``OSError`` / ``SubprocessError`` (could not run it) propagate so the
    caller can avoid caching a transient failure as "not RARLAB".
    """
    completed = subprocess.run(
        [path, _RAR_DISABLE_CONFIG],
        capture_output=True,
        timeout=_PROBE_TIMEOUT_SECONDS,
        check=False,
    )
    banner = (completed.stdout or b"") + (completed.stderr or b"")
    text = banner.decode("utf-8", errors="replace")
    return _parse_unrar_banner(text)


def _describe_floor_refusal(path: str, version: tuple[int, int] | None) -> str:
    """One binary's part of :func:`_unrar_floor_message`: why it was turned down."""
    shown = display_path(path)
    if version is None:
        return f"the version of {shown} could not be parsed from its banner"
    return f"{shown} reports version {version[0]}.{version[1]}"


def _unrar_floor_message(
    refusals: list[tuple[str, tuple[int, int] | None]], *, pinned: bool = False
) -> str:
    floor = f"{_UNRAR_VERSION_FLOOR[0]}.{_UNRAR_VERSION_FLOOR[1]}"
    found = "; ".join(
        _describe_floor_refusal(path, version) for path, version in refusals
    )
    fix = (
        "archivey does not look on PATH when ArchiveyConfig.unrar_path is set; point "
        f"it at RARLAB unrar or rar {floor} or later."
        if pinned
        else f"Install RARLAB unrar or rar {floor} or later."
    )
    return (
        f"RARLAB unrar or rar {floor} or later is required to read RAR member data, "
        f"but {found}. {fix}"
    )


def _unrar_timeout_message(paths: list[str], *, pinned: bool = False) -> str:
    shown = " and ".join(display_path(path) for path in paths)
    them = "it" if len(paths) == 1 else "them"
    where = " at ArchiveyConfig.unrar_path" if pinned else ""
    fix = (
        "point ArchiveyConfig.unrar_path at a working RARLAB unrar or rar"
        if pinned
        else "put a working RARLAB unrar or rar on PATH"
    )
    return (
        f"RARLAB unrar or rar is required to read RAR member data. Found {shown}"
        f"{where}, but the identification probe got no answer from {them} within "
        f"{_PROBE_TIMEOUT_SECONDS:g} seconds. archivey does not probe an unchanged "
        f"binary again in this process; fix or replace it, or {fix}."
    )


def _pinned_unrar_missing_message(program: str) -> str:
    return (
        f"RARLAB unrar or rar is required to read RAR member data, but "
        f"ArchiveyConfig.unrar_path names {display_path(program)}, which could not be "
        "run, or is not a RARLAB binary. archivey does not look on PATH when "
        "unrar_path is set. Point it at RARLAB unrar or rar 6.0 or later."
    )


def _stat_identity(
    path: str, message: str = _NOT_INSTALLED_MSG
) -> tuple[int, int, int, int]:
    """``(st_dev, st_ino, st_mtime_ns, st_size)``, or ``PackageNotInstalledError``.

    Same syscall ``Path.is_file()`` would make; wrapping keeps the finder's
    contract (never a raw ``OSError``) and is the identity a swapped binary
    cannot keep.
    """
    try:
        return stat_identity(path)
    except OSError as exc:
        raise _unrar_missing(message) from exc


def _unrar_missing(message: str) -> PackageNotInstalledError:
    """The refusal when no usable RARLAB program is found, with ``unrar`` as its
    missing component; ``message`` is also the component's install hint."""
    return PackageNotInstalledError(
        message, missing=(MissingComponent("unrar", message),)
    )


def _banner_meets_floor(banner: _UnrarBanner) -> bool:
    """Whether a banner is RARLAB's and reports a version at or above the floor."""
    return (
        banner.is_rarlab
        and banner.version is not None
        and banner.version >= _UNRAR_VERSION_FLOOR
    )


def rarlab_unrar_missing(program: str | None = None) -> tuple[MissingComponent, ...]:
    """What ``format_availability(RAR)`` names when no usable RARLAB program is found.

    Without one, RAR still opens and lists, and stored members read natively, so the
    format is PARTIAL. The install hint is the refusal :func:`find_rarlab_unrar`
    raises, so the query and a member read give the same advice: nothing on ``PATH``,
    a lookalike, a RARLAB binary under the 6.0 floor, or one that did not answer the
    probe. The hint names ``unar`` as a way to read most RAR data, but finding one does
    not make RAR FULL: it is a bounded fallback that reads fewer archives.
    """
    try:
        find_rarlab_unrar(program)
    except PackageNotInstalledError as exc:
        return exc.missing
    return ()


def winrar_install_candidates() -> list[str]:
    """``UnRAR.exe`` then ``Rar.exe`` in each Program Files ``WinRAR`` folder that has them.

    Empty off Windows. Only files that exist are listed; the caller still probes
    each one's banner, as it does a ``PATH`` hit.
    """
    if not _ON_WINDOWS:
        return []
    folders: list[str] = []
    for var in _WINDOWS_PROGRAM_FILES_VARS:
        base = os.environ.get(var)
        if base:
            folders.append(os.path.join(base, "WinRAR"))
    found: list[str] = []
    seen: set[str] = set()
    for exe in _WINRAR_EXE_NAMES:
        for folder in folders:
            candidate = os.path.abspath(os.path.join(folder, exe))
            key = os.path.normcase(candidate)
            if key in seen:
                continue
            seen.add(key)
            if os.path.isfile(candidate):
                found.append(candidate)
    return found


def _rarlab_candidates(path_env: str) -> Iterator[str]:
    """Absolute paths to probe, best first: ``unrar`` then ``rar`` on ``PATH``, then
    :func:`winrar_install_candidates`.

    Lazy, so the WinRAR folders are looked at only when no ``PATH`` hit is usable.
    A path already yielded is not yielded again.
    """
    seen: set[str] = set()

    def _first_time(candidate: str) -> bool:
        key = os.path.normcase(candidate)
        if key in seen:
            return False
        seen.add(key)
        return True

    for name in _RARLAB_BINARY_NAMES:
        hit = shutil.which(name, path=path_env)
        if hit is not None:
            candidate = os.path.abspath(hit)
            if _first_time(candidate):
                yield candidate
    for candidate in winrar_install_candidates():
        if _first_time(candidate):
            yield candidate


def _unrar_candidates(program: str | None) -> Iterator[str]:
    """The binaries to try, in order: ``program`` alone when the caller pinned one
    (``ArchiveyConfig.unrar_path``), else :func:`_rarlab_candidates`."""
    if program is not None:
        return iter([program])
    # Sample PATH once and pass it to ``which`` so a concurrent ``os.environ``
    # rewrite cannot stamp a new lookup with the old key.
    return _rarlab_candidates(os.environ.get("PATH", ""))


def find_rarlab_unrar(program: str | None = None) -> str:
    """Return path to RARLAB ``unrar`` or ``rar`` 6.0+, or raise PackageNotInstalledError.

    ``unrar`` wins when both names resolve to a usable binary. A lookalike or
    too-old ``unrar`` does not hide a usable ``rar``. ``PATH`` comes first; on
    Windows, WinRAR's own folder is tried after it (:func:`winrar_install_candidates`).
    A ``which`` miss is never cached. Spawn sites still only run ``p`` (see
    :func:`open_unrar_p`).

    ``program`` is ``ArchiveyConfig.unrar_path``: when set, it is the only binary
    tried, neither ``PATH`` nor the WinRAR folder is searched, and it is held to the
    same identification and version floor.
    """
    pinned = program is not None
    not_installed = (
        _pinned_unrar_missing_message(program)
        if program is not None
        else _NOT_INSTALLED_MSG
    )
    floor_refusals: list[tuple[str, tuple[int, int] | None]] = []
    timed_out: list[str] = []
    run_cause: BaseException | None = None

    def _note_floor(path: str, version: tuple[int, int] | None) -> None:
        if any(existing == path for existing, _ in floor_refusals):
            return
        floor_refusals.append((path, version))

    for candidate in _unrar_candidates(program):
        try:
            identity = _stat_identity(candidate, not_installed)
        except PackageNotInstalledError as exc:
            run_cause = exc.__cause__ if exc.__cause__ is not None else exc
            continue

        cached = _cached_unrar.get(candidate)
        if (
            cached is not None
            and (cached.st_dev, cached.st_ino, cached.st_mtime_ns, cached.st_size)
            == identity
        ):
            if _banner_meets_floor(
                _UnrarBanner(is_rarlab=cached.is_rarlab, version=cached.version)
            ):
                return candidate
            if cached.is_rarlab:
                _note_floor(candidate, cached.version)
            elif cached.timed_out and candidate not in timed_out:
                timed_out.append(candidate)
            continue

        probe_timed_out = False
        try:
            banner = _is_rarlab_unrar(candidate)
        except subprocess.TimeoutExpired as exc:
            # The binary ran and did not answer. Unlike a spawn failure, remember
            # it: otherwise every member read pays the probe timeout again. A
            # replaced binary changes the stat identity and is probed afresh.
            run_cause = exc
            probe_timed_out = True
            banner = _UnrarBanner(is_rarlab=False, version=None)
            timed_out.append(candidate)
        except (OSError, subprocess.SubprocessError) as exc:
            run_cause = exc
            continue

        st_dev, st_ino, st_mtime_ns, st_size = identity
        _cached_unrar[candidate] = _UnrarProbe(
            unrar_path=candidate,
            is_rarlab=banner.is_rarlab,
            version=banner.version,
            st_dev=st_dev,
            st_ino=st_ino,
            st_mtime_ns=st_mtime_ns,
            st_size=st_size,
            timed_out=probe_timed_out,
        )
        if _banner_meets_floor(banner):
            return candidate
        if banner.is_rarlab:
            _note_floor(candidate, banner.version)

    if floor_refusals:
        raise _unrar_missing(_unrar_floor_message(floor_refusals, pinned=pinned))
    if timed_out:
        message = _unrar_timeout_message(timed_out, pinned=pinned)
        if run_cause is not None:
            raise _unrar_missing(message) from run_cause
        raise _unrar_missing(message)
    if run_cause is not None:
        raise _unrar_missing(not_installed) from run_cause
    raise _unrar_missing(not_installed)


def _password_arg(password: str | bytes | None) -> str:
    """Return the ``unrar`` password switch.

    Empty/absent → ``-p-`` (no password). Otherwise bare ``-p``; the password itself
    is written to the child's stdin (see :func:`open_unrar_p`) so it never appears in
    ``argv`` / ``/proc/<pid>/cmdline``.
    """
    if password is None or password == b"" or password == "":
        return "-p-"
    return "-p"


def _password_stdin_bytes(password: str | bytes, *, rar5: bool) -> bytes:
    """Encode a password for ``unrar``'s stdin, refusing one it would silently cut.

    What is sent is the password the native path hashes
    (:func:`rar_parser._normalize_password_utf16le`): its first 127 UTF-16 code
    units, written as UTF-8. ``unrar`` truncates as well (measured on 7.00: a RAR5 archive whose
    password is 127 characters decrypts with 100 000 more appended), but its
    ``wchar_t`` is not UTF-16 on every platform, so its count may differ once a
    character outside the BMP is involved; it is handed the already-truncated
    string so the two paths cannot disagree. The truncation also
    bounds what goes into the pipe to a few hundred bytes, far below any pipe
    buffer, so :func:`open_unrar_p` can write it all before reading stdout without
    a deadlock. A password with no Unicode form raises the wrong-password
    ``EncryptionError`` the native path raises for it.

    A password whose 127-unit cut falls inside a surrogate pair has no UTF-8 form to
    write, and dropping or completing the lone half would change it. What that means
    depends on ``rar5``. RAR5 hashes UTF-8, so such a password cannot be the real one:
    it is the wrong-password ``EncryptionError`` the native RAR5 path raises. RAR 1.5-4
    hashes the UTF-16LE units directly, so the native path accepts exactly this
    password and a header CRC can prove it right; here the limit is ``unrar``'s stdin,
    not the password, so it is an ``UnsupportedFeatureError``.

    ``unrar`` reads the password as a single line that ends at the first newline or
    NUL, and discards the rest. Measured against RARLAB ``rar`` 7.00: an archive
    whose password is ``ab`` decrypts when ``"ab\\nXX"`` is supplied, and a RAR4
    member whose password is ``password`` decrypts with ``"password\\x00zz"``.
    That is a wrong password accepted, and nothing downstream can tell. The native
    header path (:func:`rar_parser._rar3_s2k` / :func:`~rar_parser._rar5_s2k`)
    hashes past a newline or NUL, so the same argument would also mean two
    different things on the two paths. Refuse it instead of clamping it.
    """
    if rar5:
        raw = _normalize_password_utf8(password)
    else:
        wstr = _normalize_password_utf16le(password)
        try:
            raw = wstr.decode("utf-16le").encode("utf-8")
        except UnicodeDecodeError:
            raise UnsupportedFeatureError(
                "This password cannot be passed to unrar: RAR uses only its first 127 "
                "UTF-16 code units, that limit falls inside a character, and unrar "
                "reads the password from stdin as text, which cannot carry half a "
                "character."
            ) from None
    if b"\n" in raw or b"\r" in raw:
        raise UnsupportedFeatureError(
            "A password containing a line break cannot be passed to unrar: it reads "
            "the password as one line and would silently use only the part before "
            "the break."
        )
    if b"\0" in raw:
        raise UnsupportedFeatureError(
            "A password containing a NUL character cannot be passed to unrar: it "
            "would silently use only the part before the NUL."
        )
    return raw


def _member_include_switch(member: str) -> str | bytes:
    """Build a safe ``unrar`` include-mask switch for one member name.

    A hostile archive can name a member like a switch (``-inul``) or an ``@listfile``
    argument; passed positionally those are mis-parsed by ``unrar`` (a switch, or a
    read of an attacker-chosen local file). Passing the name as the value of the ``-n``
    include-mask switch, prefixed with ``./``, neutralizes both: the leading ``-`` is
    not a switch (it is inside ``-n``) and the leading ``@`` is not a listfile (the
    value starts with ``.``). ``./`` also anchors the mask to the exact archive path
    rather than matching the basename at any depth.

    The reader sends only names with no ``*`` or ``?``: a placeholder (``m0``) in a
    synthetic archive, or a plain name that selects one member of the original
    (``RarReader._plain_mask``).
    """
    if sys.platform != "win32":
        # UTF-8 whatever this process's filesystem encoding is: the child runs
        # under a UTF-8 locale (:func:`_unrar_env`) and decodes argv with it.
        return b"-n./" + member.encode("utf-8")
    return "-n./" + member


# Locale names that select UTF-8, tried in order for unrar's environment. glibc
# 2.35+ and musl have ``C.UTF-8`` built in; older Debian-family systems ship
# ``C.utf8``; macOS has ``en_US.UTF-8``.
_UTF8_LOCALE_NAMES: tuple[str, ...] = ("C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8")
# ``LC_ALL_MASK`` for ``newlocale``: every category bit. glibc refuses bits it does
# not define, so the value is per C library; musl ignores bits past its own.
_LC_ALL_MASK_LINUX = 8127
_LC_ALL_MASK_BSD = 63
_utf8_locale_lock = threading.Lock()
_utf8_locale_probed = False
_utf8_locale: str | None = None


def _probe_utf8_locale() -> str | None:
    """The first of :data:`_UTF8_LOCALE_NAMES` the C library can load, or ``None``.

    Asked with ``newlocale``, which builds a locale object without touching this
    process's own locale, so the probe is thread-safe and spawns nothing.
    """
    if sys.platform.startswith("linux"):
        mask = _LC_ALL_MASK_LINUX
    elif sys.platform == "darwin" or "bsd" in sys.platform:
        mask = _LC_ALL_MASK_BSD
    else:
        return None
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        newlocale = libc.newlocale
        freelocale = libc.freelocale
    except (ImportError, OSError, AttributeError):
        return None
    newlocale.restype = ctypes.c_void_p
    newlocale.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)
    freelocale.argtypes = (ctypes.c_void_p,)
    for name in _UTF8_LOCALE_NAMES:
        handle = newlocale(mask, name.encode("ascii"), None)
        if handle:
            freelocale(handle)
            return name
    return None


def _utf8_locale_name() -> str | None:
    """:func:`_probe_utf8_locale`, run once per process."""
    global _utf8_locale, _utf8_locale_probed
    with _utf8_locale_lock:
        if not _utf8_locale_probed:
            _utf8_locale = _probe_utf8_locale()
            _utf8_locale_probed = True
        return _utf8_locale


def _unrar_env() -> dict[str, str] | None:
    """The environment for an ``unrar`` child, or ``None`` to inherit this one.

    ``unrar`` converts a Unicode member name and an argv mask to and from multibyte
    text through the C locale. Under ``LC_ALL=C`` (cron, CI, containers) a
    non-ASCII RAR5 name then never matches its own mask, and the read is reported
    truncated. ``LC_ALL`` names a UTF-8 locale instead, which is how the mask is
    encoded. Windows has no such conversion on this path and keeps its environment.
    """
    if sys.platform == "win32":
        return None
    name = _utf8_locale_name()
    if name is None:
        return None
    return {**os.environ, "LC_ALL": name}


_NUL_REFUSAL = (
    "its stored name contains a NUL character, which cannot be passed to a subprocess"
)


def unrar_mask_carries_non_ascii() -> bool:
    """Whether a non-ASCII mask reaches ``unrar`` as the text it was built from.

    On Windows argv is Unicode. On POSIX the mask goes out as UTF-8 and ``unrar``
    reads it through the C locale, so it needs a UTF-8 locale (:func:`_unrar_env`);
    without one a non-ASCII mask never matches its own member.
    """
    return sys.platform == "win32" or _utf8_locale_name() is not None


def unrar_matches_names_as_windows() -> bool:
    """Whether ``unrar`` changes and compares names the way its Windows build does.

    Windows ``unrar`` converts a Unix-host name to NFC (``ConvertToPrecomposed`` in
    ``arcread.cpp``) before it compares it with a mask, and does not convert the
    mask. It compares the directory part of a mask with ``CompareStringW``, which
    ignores some code points (U+00AD, U+200B, ...) and treats canonically
    equivalent sequences as equal. ``rar_reader._plain_unrar_masks`` takes out of
    the plain set every name that is not NFC, and, when any name in the archive has
    a directory that is not printable ASCII, every name with a directory.
    """
    return sys.platform == "win32"


def unrar_expands_wildcards(path: str | Path) -> bool:
    """Whether ``unrar`` reads ``path``, given as the archive, as a wildcard mask.

    ``unrar`` expands ``*`` and ``?`` in an archive name, and ``--`` does not stop
    that: ``rep*.rar`` also opens a ``rep-a.rar`` beside it, and a FIFO that the
    mask matches blocks the open forever. Those are the only two wildcard
    characters (``IsWildcard`` in unrar's ``pathfn.cpp``; ``[`` is literal). On
    Windows it skips the ``\\\\?\\`` long-path prefix before it looks, and a
    Windows name cannot hold either character, so only that prefix is exempt.
    """
    text = str(path)
    if sys.platform == "win32" and text.startswith("\\\\?\\"):
        text = text[4:]
    return "*" in text or "?" in text


# The longest archive path that ``unrar`` is trusted to keep whole: UTF-16 code units
# on Windows, and on POSIX also bytes of the name as it reaches the filesystem. unrar
# 6.x copies the archive argument into ``wchar ArcName[NM]`` with NM 2048
# (``cmddata.cpp`` and ``extract.cpp``, unrarsrc 6.2.12), and ``wchar_t`` is UTF-16 on
# Windows. On POSIX ``File::Open`` converts the name back to bytes in ``char
# NameA[NM]`` (``WideToChar``, ``file.cpp``), so a non-ASCII path is cut at 2047
# bytes, which can be far fewer characters (measured on 6.24: a CJK path of 708 units
# and 2068 bytes opened a file at its 2046-byte prefix). Either way unrar opens
# whatever file the cut path names. Half of NM leaves margin for a path unrar makes
# absolute or derives a next volume name from.
_UNRAR_ARCHIVE_PATH_MAX = 1024


# The longest member name, in UTF-16 code units, that ``unrar`` keeps whole when it
# compares it with a ``-n`` mask. ``unrar`` cuts a stored name to a fixed buffer, but
# the mask is the full argument, so a longer name matches no mask, and two names that
# share the kept prefix match one. 6.x keeps NM - 1 = 2047 ``wchar_t`` units of the
# name and of each mask (``FileName[NM]`` in ``headers.hpp``, ``CurMask[NM]`` in
# ``cmdfilter.cpp``, unrarsrc 6.2.12), and the mask carries a ``./`` prefix, so 2045
# units of name fit. 7.00 keeps 65 536 characters of both (measured on Linux: a
# 65 536-character name read alone through ``-n./<name>``, a 65 537-character one
# matched nothing), but the mask must also reach it as one argument: a Windows
# command line holds 32 767 units in all, and Linux refuses one argument over 128 KiB
# (``MAX_ARG_STRLEN``) with E2BIG. 16 384 units leave the rest of the Windows command
# line half of it, and are at most 49 152 bytes of UTF-8. ``wchar_t`` is UTF-16 on
# Windows, so the count is in UTF-16 units, which is never fewer than code points.
_UNRAR6_PLAIN_NAME_MAX = 2047 - len("./")
_UNRAR7_PLAIN_NAME_MAX = 16384


def unrar_plain_name_max(program: str | None = None) -> int:
    """The longest name, in UTF-16 units, a mask on the ``unrar`` that reads next
    selects whole (see ``_UNRAR6_PLAIN_NAME_MAX``).

    Taken from the banner version :func:`find_rarlab_unrar` probed for ``program``
    (``ArchiveyConfig.unrar_path``, or ``None`` to search). When no usable
    ``unrar`` is found, or its version did not parse, the 6.x bound applies: it is
    the smaller one, and the read that follows fails on the missing program anyway.
    """
    try:
        path = find_rarlab_unrar(program)
    except PackageNotInstalledError:
        return _UNRAR6_PLAIN_NAME_MAX
    probe = _cached_unrar.get(path)
    if probe is not None and probe.version is not None and probe.version >= (7, 0):
        return _UNRAR7_PLAIN_NAME_MAX
    return _UNRAR6_PLAIN_NAME_MAX


def unrar_may_cut_archive_path(path: str | Path) -> bool:
    """Whether ``path`` is too long to hand to ``unrar`` as the archive.

    Measured as an absolute path, so a short relative path in a deep working
    directory counts at its full length: in UTF-16 units, and on POSIX also in the
    bytes ``os.fsencode`` gives, which is what ``unrar`` 6.x cuts there.
    """
    text = os.path.abspath(path)
    size = len(text.encode("utf-16-le", "surrogatepass")) // 2
    if sys.platform != "win32":
        size = max(size, len(os.fsencode(text)))
    return size > _UNRAR_ARCHIVE_PATH_MAX


def _unrar_archive_argument(archive_path: str | Path) -> tuple[str, str | None]:
    """The archive argument for ``unrar``, and the directory to start it in.

    A path that ``unrar`` would expand (:func:`unrar_expands_wildcards`) or cut
    (:func:`unrar_may_cut_archive_path`) reaches here only as a file archivey made:
    the reader stages a caller's path of either kind under a fixed name. Its
    directory, the system temp directory or one made in it, is what holds the
    ``*``, ``?`` or the length, so ``unrar`` is started in that directory and given
    the file's name alone. No part of the directory then reaches ``unrar``'s argv,
    and ``unrar`` finds the next volume of a staged set beside that name. ``unrar p``
    writes only to stdout, so the working directory changes no output location.

    Windows names cannot hold ``*`` or ``?``, so there only the length applies, and
    a working directory that long is past what ``CreateProcess`` takes: that is
    refused, never handed to ``unrar`` to cut.
    """
    path = str(archive_path)
    if not (unrar_expands_wildcards(path) or unrar_may_cut_archive_path(path)):
        return path, None
    directory, name = os.path.split(os.path.abspath(path))
    if not name or unrar_expands_wildcards(name):
        # The reader stages every such name; reaching here is a bug upstream.
        raise ReadError(
            f"the archive {display_path(path)} cannot be handed to unrar: its name "
            "holds a wildcard character"
        )
    if sys.platform == "win32":
        raise ResourceUnavailableError(
            f"unrar cannot read {display_path(path)}: the temporary directory's path "
            f"is longer than {_UNRAR_ARCHIVE_PATH_MAX} characters. Set TMP or TEMP to "
            "a shorter directory."
        )
    return name, directory


def unrar_member_refusal(member: str) -> str | None:
    """Why ``member`` is not a mask the reader sends, or ``None`` when it is one.

    The reader sends only names with no NUL, ``*`` or ``?`` that encode as UTF-8,
    and non-ASCII ones only where :func:`unrar_mask_carries_non_ascii`: a
    placeholder in a synthetic archive, or a plain name of the original archive.
    Anything else is a bug upstream, refused here rather than handed to ``unrar``.
    """
    try:
        member.encode("utf-8")
    except UnicodeEncodeError:
        return "its name is not one archivey passes to unrar as a mask"
    if any(char in member for char in "\0*?") or (
        not member.isascii() and not unrar_mask_carries_non_ascii()
    ):
        return "its name is not one archivey passes to unrar as a mask"
    return None


def decompress_rar3_blob(
    *,
    open_pipe: Callable[[Path], tuple[subprocess.Popen[bytes], BinaryIO]] | None = None,
    extract_version: int,
    compress_type: int,
    packed: bytes,
    unpacked_size: int,
    flags: int,
    crc16: int,
) -> bytes | None:
    """Decode a non-file RAR3 payload by wrapping it in a temporary RAR.

    RAR3 old-style comments hold compressed bytes inside a header, and a RAR 2.9-4
    ``CMT`` SERVICE header holds them in a block ``unrar p`` does not pipe; neither
    is a FILE block that ``unrar`` can address. A minimal one-file archive lets the
    existing RARLAB process decode that one blob. This is deliberately limited
    to metadata blobs; it does not change stream-source member reads.

    ``unrar`` can report a CRC error for the synthetic FILE because old comment
    blocks retain only a CRC16. The caller validates the comment's CRC (the CRC16,
    or a ``CMT`` header's CRC32) against the returned bytes, which is the integrity
    check the on-disk comment provides.

    ``open_pipe`` spawns the decompressor on the synthetic archive and returns
    ``(proc, stdout)`` for its only member; ``None`` means :func:`open_unrar_p`.

    An encrypted comment (the PASSWORD or SALT flag) returns ``None`` before any
    archive is built. The parser already drops one
    (``_parse_rar3_old_comment_subblocks``), so this is a second guard for direct
    callers. No available writer produces such a comment, so a decode path for it
    could not be tested.
    The synthetic FILE header sets only the flag it needs (a long block): it writes
    no salt, so it must not claim one, and it copies no other bit of the comment's
    flag word.
    """
    if unpacked_size < 0 or unpacked_size > RAR3_MAX_COMMENT_SIZE:
        return None
    if flags & (_RAR3_FILE_PASSWORD | _RAR3_FILE_SALT):
        return None
    if compress_type == _RAR3_M0:
        return packed if len(packed) == unpacked_size else None

    file_flags = _RAR3_LONG_BLOCK
    filename = b"data"
    file_body = (
        _S_FILE_HDR.pack(
            len(packed),
            unpacked_size,
            0,  # MS-DOS
            crc16,
            0,
            extract_version,
            compress_type,
            len(filename),
            0x20,  # DOS archive attribute
        )
        + filename
    )
    file_without_crc = (
        struct.pack("<BHH", _RAR3_FILE, file_flags, _S_BLK_HDR.size + len(file_body))
        + file_body
    )
    file_header = (
        struct.pack("<H", zlib.crc32(file_without_crc) & 0xFFFF) + file_without_crc
    )

    main_body = b"\0" * 6
    main_without_crc = (
        struct.pack("<BHH", _RAR3_MAIN, 0, _S_BLK_HDR.size + len(main_body)) + main_body
    )
    main_header = (
        struct.pack("<H", zlib.crc32(main_without_crc) & 0xFFFF) + main_without_crc
    )

    fd, name = tempfile.mkstemp(suffix=".rar")
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as archive:
            archive.write(RAR_ID + main_header + file_header + packed)
        proc, stdout = (open_pipe or open_unrar_p)(path)
        try:
            # A comment's declared unpacked length is at most
            # ``RAR3_MAX_COMMENT_SIZE``. Bound the process output so a malformed
            # blob cannot turn archive listing into an unbounded metadata read.
            data = stdout.read(unpacked_size + 1)
            if len(data) != unpacked_size:
                return None
            return data
        finally:
            try:
                stdout.close()
            finally:
                if proc.poll() is None:
                    terminate_process(proc)
    finally:
        path.unlink(missing_ok=True)


def open_unrar_p(
    archive_path: str | Path,
    *,
    password: str | bytes | None = None,
    member: str | None = None,
    version_control: bool = False,
    rar5: bool = False,
    program: str | None = None,
) -> tuple[subprocess.Popen[bytes], BinaryIO]:
    """Spawn ``<unrar|rar> p -inul -cfg- [-ver] [-p|-p-] [-n./member] -- archive``.

    ``program`` is ``ArchiveyConfig.unrar_path`` (see :func:`find_rarlab_unrar`).

    ``version_control`` adds ``-ver`` so the pipe includes WinRAR file-version history
    payloads (needed for solid demux when versioned FILE rows are present, and for a
    named open of a ``path;n`` history member — the ``-n`` mask excludes history rows
    unless ``-ver`` is set).

    A named ``member`` is passed as a ``-n./`` include mask, never positionally, so a
    hostile member name cannot inject an ``unrar`` switch or ``@listfile`` argument
    (see :func:`_member_include_switch`). The child runs under a UTF-8 locale
    (:func:`_unrar_env`). ``None`` means no ``-n`` mask, so every payload member is
    piped: the solid pass wants that, and a named read must never pass it.

    When a non-empty ``password`` is given, the switch is bare ``-p`` and the password
    (plus a trailing newline) is written to the child's stdin — ``unrar`` reads it from
    stdin when redirected, keeping the secret out of ``argv``. A password containing a
    line break or a NUL is refused rather than sent, because ``unrar`` would read only
    the part before it, and a longer one is cut to the 127 UTF-16 units RAR hashes —
    see :func:`_password_stdin_bytes`, which also needs ``rar5`` (true for a RAR5
    archive) to tell a wrong password from one ``unrar``'s stdin cannot carry; the
    default gives the refusal, which claims nothing about the password. That bound is what lets the whole password be
    written before stdout is read: it always fits in the pipe buffer, so the write
    cannot block on a child that is itself blocked writing a full stdout.

    Reading ``stdout`` has no time bound. A read waits for as long as the child
    takes to produce bytes, and nothing here stops a child that stalls. A solid
    archive can legitimately produce no bytes for a long time while ``unrar``
    decodes the members before the target, so an idle timeout would refuse valid
    work. The only timeouts in this module are the version probe and the teardown
    in :func:`~archivey.internal.external.cli.terminate_process`.

    Returns ``(proc, stdout)``. Caller must terminate/wait/close.
    """
    unrar = find_rarlab_unrar(program)
    cmd: list[str | bytes] = [unrar, "p", "-inul", _RAR_DISABLE_CONFIG]
    if version_control:
        cmd.append("-ver")
    pass_arg = _password_arg(password)
    cmd.append(pass_arg)
    if member is not None:
        # subprocess raises a bare ValueError for a NUL in any argument.
        refusal = unrar_member_refusal(member)
        if refusal is not None:
            raise UnsupportedFeatureError(
                f"RAR member {quoted(member)} cannot be read through unrar: {refusal}."
            )
        cmd.append(_member_include_switch(member))
    # ``--`` ends switch parsing, so an archive path starting with ``-`` (a
    # caller's ``-inul.rar``) is read as the archive and not as a switch. An
    # ``@`` prefix needs no guard: unrar reads the first non-switch argument as
    # the archive, and only later file-name arguments as listfiles.
    cmd.append("--")
    archive_arg, cwd = _unrar_archive_argument(archive_path)
    cmd.append(archive_arg)
    feed_password = pass_arg == "-p"
    # Encode before spawning: _password_stdin_bytes refuses a password unrar would
    # silently cut, and raising after Popen would leave the child and its pipes behind.
    stdin_bytes: bytes | None = None
    if feed_password:
        assert password is not None and password != b"" and password != ""
        stdin_bytes = _password_stdin_bytes(password, rar5=rar5)
    proc, stdout = spawn_for_stdout(
        cmd,
        name="unrar",
        not_started=_NOT_INSTALLED_MSG,
        stdin=subprocess.PIPE if feed_password else subprocess.DEVNULL,
        env=_unrar_env(),
        cwd=cwd,
    )
    if stdin_bytes is not None:
        assert proc.stdin is not None
        try:
            proc.stdin.write(stdin_bytes + b"\n")
            proc.stdin.close()
        except BrokenPipeError:
            # unrar exited before consuming the password; surface via exit-code mapping.
            pass
        except BaseException:
            # Any other failure leaves the caller without ``proc``, so nothing else
            # would ever reap it.
            try:
                stdout.close()
            finally:
                terminate_process(proc)
            raise
    return proc, stdout
