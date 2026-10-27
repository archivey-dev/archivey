"""CLI wrapper around RARLAB ``unrar`` / ``rar`` for member **payload** bytes.

No RAR structure knowledge beyond argv safety — metadata/listing is
:mod:`.rar_parser`. Locates a RARLAB decompressor on ``PATH`` (``unrar`` first,
then the trialware writer ``rar``; not ``unrar-free`` / ``unar`` / ``7z``) and
spawns ``<binary> p`` with the password on stdin (bare ``-p``, secret not in
argv) and optional ``-n./member`` include masks. Never ``x`` / extract-to-disk.
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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from archivey.exceptions import (
    PackageNotInstalledError,
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
# ``scripts/exploration/rar_unrar_input_matrix.py``). On 7.00, ``rar p``
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
    "on PATH (or the unrar/rar on PATH is not a RARLAB binary). Install RARLAB unrar "
    "or rar 6.0 or later; unrar-free, 7z and 7zz are not substitutes. With "
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
    shown = display_path(path)
    if version is None:
        return f"the version of {shown} could not be parsed from its banner"
    return f"{shown} reports version {version[0]}.{version[1]}"


def _unrar_floor_message(
    refusals: list[tuple[str, tuple[int, int] | None]],
) -> str:
    floor = f"{_UNRAR_VERSION_FLOOR[0]}.{_UNRAR_VERSION_FLOOR[1]}"
    found = "; ".join(
        _describe_floor_refusal(path, version) for path, version in refusals
    )
    return (
        f"RARLAB unrar or rar {floor} or later is required to read RAR member data, "
        f"but {found}. Install RARLAB unrar or rar {floor} or later."
    )


def _unrar_timeout_message(paths: list[str]) -> str:
    shown = " and ".join(display_path(path) for path in paths)
    them = "it" if len(paths) == 1 else "them"
    return (
        f"RARLAB unrar or rar is required to read RAR member data. Found {shown} on "
        f"PATH, but the identification probe got no answer from {them} within "
        f"{_PROBE_TIMEOUT_SECONDS:g} seconds. archivey does not probe an unchanged "
        "binary again in this process; fix or replace it, or put a working RARLAB "
        "unrar or rar on PATH."
    )


def _stat_identity(path: str) -> tuple[int, int, int, int]:
    """``(st_dev, st_ino, st_mtime_ns, st_size)``, or ``PackageNotInstalledError``.

    Same syscall ``Path.is_file()`` would make; wrapping keeps the finder's
    contract (never a raw ``OSError``) and is the identity a swapped binary
    cannot keep.
    """
    try:
        return stat_identity(path)
    except OSError as exc:
        raise PackageNotInstalledError(_NOT_INSTALLED_MSG) from exc


def _banner_meets_floor(banner: _UnrarBanner) -> bool:
    return (
        banner.is_rarlab
        and banner.version is not None
        and banner.version >= _UNRAR_VERSION_FLOOR
    )


def rarlab_unrar_missing() -> tuple[MissingComponent, ...]:
    """What ``format_availability(RAR)`` names when no usable RARLAB program is found.

    Without one, RAR still opens and lists, and stored members read natively, so the
    format is PARTIAL. The install hint is the refusal :func:`find_rarlab_unrar`
    raises, so the query and a member read give the same advice: nothing on ``PATH``,
    a lookalike, a RARLAB binary under the 6.0 floor, or one that did not answer the
    probe. The hint names ``unar`` as a way to read most RAR data, but finding one does
    not make RAR FULL: it is a bounded fallback that reads fewer archives.
    """
    try:
        find_rarlab_unrar()
    except PackageNotInstalledError as exc:
        return (MissingComponent("unrar", str(exc)),)
    return ()


def find_rarlab_unrar() -> str:
    """Return path to RARLAB ``unrar`` or ``rar`` 6.0+, or raise PackageNotInstalledError.

    ``unrar`` wins when both names resolve to a usable binary. A lookalike or
    too-old ``unrar`` does not hide a usable ``rar``. A ``which`` miss is never
    cached. Spawn sites still only run ``p`` (see :func:`open_unrar_p`).
    """
    path_env = os.environ.get("PATH", "")
    # Sample PATH once and pass it to ``which`` so a concurrent ``os.environ``
    # rewrite cannot stamp a new lookup with the old key.
    floor_refusals: list[tuple[str, tuple[int, int] | None]] = []
    timed_out: list[str] = []
    run_cause: BaseException | None = None

    def _note_floor(path: str, version: tuple[int, int] | None) -> None:
        if any(existing == path for existing, _ in floor_refusals):
            return
        floor_refusals.append((path, version))

    for name in _RARLAB_BINARY_NAMES:
        candidate = shutil.which(name, path=path_env)
        if candidate is None:
            continue
        candidate = os.path.abspath(candidate)

        try:
            identity = _stat_identity(candidate)
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
        raise PackageNotInstalledError(_unrar_floor_message(floor_refusals))
    if timed_out:
        message = _unrar_timeout_message(timed_out)
        if run_cause is not None:
            raise PackageNotInstalledError(message) from run_cause
        raise PackageNotInstalledError(message)
    if run_cause is not None:
        raise PackageNotInstalledError(_NOT_INSTALLED_MSG) from run_cause
    raise PackageNotInstalledError(_NOT_INSTALLED_MSG)


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


def _unrar_mask_for(member: str) -> str:
    """The ``-n`` mask archivey sends for a member name: every ``*`` narrowed to ``?``.

    A member whose stored name contains ``*`` or ``?`` is itself a glob once it is
    handed to ``unrar -n``, so the pipe carries every sibling the name happens to
    match and archivey has to size a skip past them. Sending the name verbatim makes
    that mask a hostile one: ``unrar`` 7.00's own matcher backtracks exponentially on
    a name that alternates ``*`` with literals, and no archivey-side change reaches
    a cost paid inside the subprocess.

    Substituting ``?`` for ``*`` removes it. ``?`` matches exactly one character, so
    the mask is fixed-length and still matches the member itself (same length, a
    ``?`` wherever the name had a ``*``). With no ``*`` left there is nothing for
    either matcher to backtrack on. ``dev-docs/formats/rar.md`` §6 has the numbers.

    Whatever this returns is the mask ``unrar`` actually sees, so the skip in
    ``RarReader._unrar_selection`` is sized against this string and not against
    the presented name. The siblings it selects are mostly a subset of what the
    ``*`` mask selected, but not always: unrar's DOS extension rule lets ``*.``
    refuse ``..`` where ``?.`` selects it.
    """
    return member.replace("*", "?")


def _member_include_switch(member: str | bytes) -> str | bytes:
    """Build a safe ``unrar`` include-mask switch for one member name.

    ``member`` is ``bytes`` for a name ``unrar`` must be given as stored (an 8-bit
    RAR3 name, see :func:`unrar_member_argument`); ``*`` is narrowed to ``?`` in
    it the same way, which is one byte for one byte.

    A hostile archive can name a member like a switch (``-inul``) or an ``@listfile``
    argument; passed positionally those are mis-parsed by ``unrar`` (a switch, or a
    read of an attacker-chosen local file). Passing the name as the value of the ``-n``
    include-mask switch, prefixed with ``./``, neutralizes both: the leading ``-`` is
    not a switch (it is inside ``-n``) and the leading ``@`` is not a listfile (the
    value starts with ``.``). For a name **without** wildcards, ``./`` also anchors
    the mask to the exact archive path rather than matching the basename at any
    depth.

    ``unrar`` masks treat ``*`` and ``?`` as wildcards with no escape (``[]`` are
    literal, ``\\`` does not escape). A name whose globs are confined to the
    basename and that contains no backslash is still passed as a mask, via
    :func:`_unrar_mask_for`, which narrows ``*`` to ``?``. Any mask can select
    more than its own member (a duplicate name, a glob, a name ``unrar`` cuts
    short), so ``RarReader._open_member`` skips the others using the parsed
    member list and :func:`unrar_mask_selects`. A glob in a directory component,
    or a backslash in the mask (on Windows, in the stored name), raises
    ``UnsupportedFeatureError`` instead (see :func:`plan_unrar_mask`).
    """
    if isinstance(member, bytes):
        return b"-n./" + member.replace(b"*", b"?")
    if sys.platform != "win32":
        # UTF-8 whatever this process's filesystem encoding is: the child runs
        # under a UTF-8 locale (:func:`_unrar_env`) and decodes argv with it.
        return b"-n./" + _unrar_mask_for(member).encode("utf-8")
    return "-n./" + _unrar_mask_for(member)


def unrar_member_argument(
    view: str | None,
    stored: bytes | None,
    *,
    stored_is_8bit: bool,
    surrogates_as_wildcards: bool = False,
) -> str | bytes | None:
    """The name to build ``unrar``'s ``-n`` mask from: text, the stored bytes, or none.

    ``view`` is the member's name as ``unrar`` reads it (:func:`unrar_member_view`).
    That is the text to match, and it is not always the name archivey presents: a
    RAR5 name that is not valid UTF-8 is cut at its first bad byte, and a RAR3
    Unicode name keeps the code unit its writer truncated. A trailing separator is
    dropped, since a mask ending in one selects whole directories.

    ``unrar`` turns a mask from argv into characters with the same conversion it
    applies to an 8-bit RAR3 name (one without a Unicode field) read from the
    header. Handing it the stored bytes therefore matches in every locale; measured
    on 7.00 under ``C``, ``POSIX`` and ``C.UTF-8`` with ``caf\\xe9.txt``. Windows
    argv is Unicode, not bytes, so there the view (the OEM reading of the bytes,
    :func:`_windows_unrar_8bit_name`) is the mask.

    ``None`` means there is no mask to give; :func:`unrar_member_refusal` turns
    that into a reason. Backslashes are separators in RAR3's stored bytes and
    ``/`` in the mask; the bytes follow the name.

    ``surrogates_as_wildcards`` is for a RAR 1.5-4 Unicode name. Its view holds
    UTF-16 code units. On POSIX the mask goes out as UTF-8 bytes, and ``unrar``'s
    ``mbstowcs`` rejects a surrogate's UTF-8 form, so each unit becomes ``?``, which
    matches exactly one unit. The mask can then select other members too, which the
    reader handles like any glob's siblings. Windows argv is UTF-16 and carries a
    valid pair as it is, so there the view is the mask (a lone unit is refused by
    :func:`unrar_member_refusal`).
    """
    if stored_is_8bit and stored is not None and sys.platform != "win32":
        return stored.replace(b"\\", b"/").rstrip(b"/")
    if view is None:
        return None
    if surrogates_as_wildcards and sys.platform != "win32":
        view = "".join("?" if "\ud800" <= c <= "\udfff" else c for c in view)
    if sys.platform == "win32":
        view = view.replace("\\", "/")
    return view.rstrip("/")


def _windows_unrar_8bit_name(stored: bytes) -> str | None:
    """An 8-bit RAR3 name as Windows ``unrar`` sees it; ``None`` if it cannot tell.

    ``unrar`` 7.00 (``ArcCharToWide`` with ``ACTW_OEM``) converts the stored bytes
    with ``OemToCharBuffA`` and then ``MultiByteToWideChar(CP_ACP, 0, …)``. Both use
    the system code pages, which the child shares, so making the same two calls
    with the same flags here gives the text its mask must match. Under OEM 437 the
    ``\\xe9`` of ``caf\\xe9s.txt`` is ``Θ``, not the ``é`` archivey presents
    (Windows CI).

    The calls are made through ``ctypes`` rather than Python's ``mbcs`` codec
    because either step can be lossy: ``OemToCharBuffA`` best-fits a character the
    ANSI code page lacks, and ``MultiByteToWideChar`` with no flags maps an
    undefined byte to the code page's default character, where the codec would
    raise or substitute ``U+FFFD``. Reproducing the loss exactly is what keeps the
    mask on ``unrar``'s own name. Two names the loss makes equal are then read by
    position, as duplicate names are.
    """
    if stored.isascii():
        return stored.decode("ascii")
    if sys.platform == "win32":
        import ctypes

        buffer = ctypes.create_string_buffer(stored, len(stored))
        ctypes.windll.user32.OemToCharBuffA(buffer, buffer, len(stored))
        # ``OemToExt`` cuts the converted name at its first NUL.
        ansi = buffer.raw.split(b"\0", 1)[0]
        multi_byte_to_wide_char = ctypes.windll.kernel32.MultiByteToWideChar
        size = multi_byte_to_wide_char(0, 0, ansi, len(ansi), None, 0)
        if size > 0:
            wide = ctypes.create_unicode_buffer(size)
            if multi_byte_to_wide_char(0, 0, ansi, len(ansi), wide, size) == size:
                return wide[:size]
    return None


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


def unrar_member_refusal(member: str | bytes | None) -> str | None:
    """Why ``unrar`` cannot be given ``member`` as a mask, or ``None`` when it can.

    ``None`` is an 8-bit RAR3 name Windows ``unrar`` cannot be matched against
    (:func:`_windows_unrar_8bit_name`). A NUL cannot be in any process argument.
    A non-ASCII text name needs the UTF-8 locale :func:`_unrar_env` sets, and
    without one it would read as truncated. Stored bytes need no locale
    (:func:`unrar_member_argument`).
    """
    if member is None:
        return (
            "its stored name could not be converted through this system's OEM and "
            "ANSI code pages, which is how unrar reads it"
        )
    has_nul = b"\0" in member if isinstance(member, bytes) else "\0" in member
    if has_nul:
        return _NUL_REFUSAL
    if isinstance(member, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in member):
        # unrar decodes an encoded surrogate in a RAR5 name, but no argv encoding
        # can carry one back to it. (On POSIX a RAR 1.5-4 name's units are sent as
        # ``?``, see :func:`unrar_member_argument`, so only RAR5 reaches this there.)
        return (
            "unrar reads its name with a UTF-16 surrogate in it, which cannot be "
            "passed back to unrar as a mask"
        )
    if (
        isinstance(member, str)
        and not member.isascii()
        and sys.platform != "win32"
        and _utf8_locale_name() is None
    ):
        return (
            "its name is not ASCII, and no UTF-8 locale was found to pass it to "
            "unrar in"
        )
    return None


def _unrar_glob_demux_ok(presented: str) -> bool:
    """True when archivey will demux this glob name from an ``unrar -n`` pipe.

    Only a glob confined to the basename, with no backslash. A glob in a
    directory component lets ``?`` match a separator, and ``\\`` is a separator
    to Windows ``unrar`` and a literal on Linux. :func:`unrar_mask_selects`
    follows both, but they are untested against Windows ``unrar``, so those names
    stay ``UnsupportedFeatureError``.
    """
    if "\\" in presented:
        return False
    parent, sep, _base = presented.rpartition("/")
    if not sep:
        return True
    return "*" not in parent and "?" not in parent


def _surrogate_in_directory_part(view: str) -> bool:
    """True when a directory component of ``view`` holds a UTF-16 surrogate unit."""
    directory = view.replace("\\", "/").rstrip("/").rpartition("/")[0]
    return any("\ud800" <= char <= "\udfff" for char in directory)


@dataclass(frozen=True, slots=True)
class UnrarMask:
    """A member's ``-n`` mask: the :func:`open_unrar_p` argument and unrar's reading."""

    argument: str | bytes
    mask_view: str
    is_glob: bool


@dataclass(frozen=True, slots=True)
class UnrarNameRefusal:
    """No ``-n`` mask can be given for the member's name.

    ``reason`` is a lowercase clause with no final period, such as "its stored name
    contains a NUL character, ...", for ``RarReader._unrar_name_refused`` to insert.
    """

    reason: str


@dataclass(frozen=True, slots=True)
class UnrarMaskRefusal:
    """A mask exists, but which members ``unrar`` selects with it is not predictable.

    ``reason`` is the complete ``UnsupportedFeatureError`` message.
    """

    reason: str


def plan_unrar_mask(
    *,
    view: str | None,
    stored: bytes | None,
    presented: str,
    stored_is_8bit: bool,
    surrogates_as_wildcards: bool,
) -> UnrarMask | UnrarNameRefusal | UnrarMaskRefusal:
    """The ``-n`` mask that reads one member through ``unrar``, or why there is none.

    ``view`` is the name as ``unrar`` reads it (:func:`unrar_member_view`), ``stored``
    the header's name bytes, and ``presented`` the name archivey shows.
    ``stored_is_8bit`` marks a RAR3 name with no Unicode field, which goes to
    ``unrar`` as its stored bytes, and ``surrogates_as_wildcards`` a RAR3 name with
    one, whose surrogate units go as ``?`` (both :func:`unrar_member_argument`).
    """
    argument = unrar_member_argument(
        view,
        stored,
        stored_is_8bit=stored_is_8bit,
        surrogates_as_wildcards=surrogates_as_wildcards,
    )
    reason = unrar_member_refusal(argument)
    if reason is not None:
        return UnrarNameRefusal(reason)
    assert argument is not None  # unrar_member_refusal refuses None
    if (
        surrogates_as_wildcards
        and sys.platform != "win32"
        and view is not None
        and _surrogate_in_directory_part(view)
    ):
        # Sent as ``?``, that unit would make a directory glob, which the check
        # below refuses with a reason about backslashes and globs.
        return UnrarNameRefusal(
            "a directory in its name holds a UTF-16 surrogate unit, which can "
            "reach unrar only as a glob in that directory, and archivey cannot "
            "size what a directory glob selects"
        )
    if "\0" in presented or (stored is not None and b"\0" in stored):
        # unrar cuts the name at the NUL; the name is refused rather than read
        # through the part before it.
        return UnrarNameRefusal(_NUL_REFUSAL)
    mask_view = unrar_mask_view(argument)
    if mask_view is None or not unrar_mask_is_usable(mask_view):
        return UnrarNameRefusal(
            "unrar reads its name as empty, or as a path with no name in it"
            if view is not None
            else "its name cannot be read the way unrar reads it on this system",
        )
    is_glob = "?" in mask_view
    # ``\\`` in the mask is a separator to Windows unrar and a literal on
    # POSIX, so the same ``-n./`` mask selects a different set; Windows CI
    # read nothing for ``a\\b_TGT.txt``. On POSIX a RAR5 Windows-host
    # ``\\`` is read as ``_`` (measured in test_rar_unrar_names.py), which
    # the mask already reflects. On Windows every RAR5 ``\\`` becomes ``_``
    # by the unrar source, which is unmeasured there, so a stored backslash
    # is still refused on Windows.
    if (
        "\\" in mask_view
        or (sys.platform == "win32" and "\\" in presented)
        or (is_glob and not _unrar_glob_demux_ok(mask_view[2:]))
    ):
        return UnrarMaskRefusal(
            "RAR member names that unrar reads with a backslash, or with a "
            "glob in a directory component, cannot be read through unrar: "
            "Windows unrar treats a backslash as a separator, and a "
            "directory glob selects members archivey cannot size. "
            + UNAR_BY_POSITION_HINT,
        )
    return UnrarMask(argument=argument, mask_view=mask_view, is_glob=is_glob)


# --- how unrar reads a member name, and which members a -n mask selects -------
#
# A named read gets every payload member whose name the ``-n`` mask selects,
# concatenated in archive order. Sizing the skip past the earlier ones needs the
# same answer unrar computes, so the functions below reproduce, from the unrar 7
# sources, the steps between the stored header bytes and that answer:
# ``UtfToWide`` / ``CharToWide`` (the name as wide text), ``ConvertFileHeader``
# (separators and per-platform substitutions), ``ConvertPath`` (leading ``./``,
# ``../`` and drive prefixes dropped, on the name and on the mask), and
# ``CmpName`` with ``MATCH_WILDSUBPATH`` (the comparison). Each step is checked
# against unrar 7.00 by ``tests/test_rar_unrar_names.py``. Where a step cannot be
# reproduced here, the view is ``None`` and the caller refuses the read.

# ``MAXPATHSIZE``: a RAR5 name is read to at most this many bytes.
_UNRAR_MAX_NAME_BYTES = 0x10000
# ``MappedStringMark`` and ``MapAreaStart`` in unrar's ``CharToWideMap``.
_UNRAR_MAPPED_MARK = "\ufffe"
_UNRAR_MAP_AREA = 0xE000
# RAR 1.5-4 hosts ``unrar`` treats as Unix (``HSYS_UNIX``): Unix and BeOS. MS-DOS,
# OS/2, Win32 and Mac OS are ``HSYS_WINDOWS``.
_RAR3_HSYS_UNIX = frozenset({3, 5})
_RAR3_HSYS_WINDOWS = frozenset({0, 1, 2, 4})
# ``rar_parser`` maps a RAR5 host to these RAR3-style values.
_RAR5_HOST_WINDOWS = 2
_RAR5_HOST_UNIX = 3


def _unrar_utf_to_wide(data: bytes) -> str:
    """``UtfToWide`` as ``unrar`` 7 applies it to a RAR5 name.

    It is looser than Python's UTF-8 codec. It stops at a NUL byte and at the
    first malformed sequence, keeping what came before (``b"ab\\xffcd"`` is
    ``"ab"``). It accepts overlong forms (``b"\\xc1\\x81"`` is ``"A"``) and encoded
    surrogates, and it drops a four-byte sequence above U+10FFFF without stopping.
    """
    data = data[:_UNRAR_MAX_NAME_BYTES]
    if b"\0" not in data:
        try:
            # Every sequence Python's codec accepts, unrar decodes the same way.
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    size = len(data)

    def continuation(at: int) -> int | None:
        byte = data[at] if at < size else 0
        return byte & 0x3F if byte & 0xC0 == 0x80 else None

    out: list[str] = []
    pos = 0
    while pos < size and data[pos] != 0:
        lead = data[pos]
        pos += 1
        if lead < 0x80:
            code = lead
        else:
            if lead >> 5 == 6:
                count, code = 1, lead & 0x1F
            elif lead >> 4 == 14:
                count, code = 2, lead & 0x0F
            elif lead >> 3 == 30:
                count, code = 3, lead & 0x07
            else:
                break
            tail = [continuation(pos + index) for index in range(count)]
            if None in tail:
                break
            for bits in tail:
                assert bits is not None
                code = code << 6 | bits
            pos += count
            if code > 0x10FFFF:
                continue
        out.append(chr(code))
    return "".join(out)


def _glibc_utf8_width(data: bytes, pos: int) -> int | None:
    """Length of the UTF-8 sequence glibc's ``mbrtowc`` accepts at ``pos``, or ``None``.

    Python's strict codec accepts exactly the same sequences up to U+10FFFF. glibc
    also accepts longer forms above it, which Python does not decode; for those
    this returns ``-1`` so the caller can give up rather than guess.
    """
    lead = data[pos]
    if lead < 0x80:
        return 1
    for width in (2, 3, 4):
        try:
            if len(data[pos : pos + width].decode("utf-8")) == 1:
                return width
        except UnicodeDecodeError:
            continue
    # glibc decodes up to U+7FFFFFFF: F4 90.. to F7 as four bytes, F8-FB as five
    # and FC-FD as six, each refusing an overlong form. A four-byte lead that gets
    # here is never overlong (F0-F3 forms are either decoded above or invalid).
    if 0xF4 <= lead <= 0xF7:
        width, value, least = 4, lead & 0x07, 0
    elif 0xF8 <= lead <= 0xFB:
        width, value, least = 5, lead & 0x03, 0x200000
    elif lead in (0xFC, 0xFD):
        width, value, least = 6, lead & 0x01, 0x4000000
    else:
        return None
    tail = data[pos + 1 : pos + width]
    if len(tail) != width - 1 or any(b & 0xC0 != 0x80 for b in tail):
        return None
    for byte in tail:
        value = value << 6 | byte & 0x3F
    # An overlong form is rejected like any invalid byte, and unrar maps it.
    return -1 if value >= least else None


def _unrar_posix_char_to_wide(data: bytes) -> str | None:
    """``CharToWide`` with ``CharToWideMap`` under the UTF-8 locale unrar runs in.

    Valid UTF-8 decodes as such. When any byte does not, every byte that does not
    is mapped to U+E000 plus its value, and U+FFFE marks the string once, just
    before the first mapped byte. ``unrar lb`` on Linux shows ``caf\\xe9.txt`` as
    ``"caf\\ufffe\\ue0e9.txt"``.
    """
    if _utf8_locale_name() is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    out: list[str] = []
    mapped = False
    pos = 0
    while pos < len(data):
        width = _glibc_utf8_width(data, pos)
        if width == -1:
            return None
        if width is None:
            if not mapped:
                out.append(_UNRAR_MAPPED_MARK)
                mapped = True
            out.append(chr(_UNRAR_MAP_AREA + data[pos]))
            pos += 1
            continue
        out.append(data[pos : pos + width].decode("utf-8"))
        pos += width
    return "".join(out)


def unrar_char_to_wide(data: bytes) -> str | None:
    """An 8-bit name, or an ``-n`` mask given as bytes, as ``unrar`` reads it.

    This is ``ArcCharToWide`` with ``ACTW_OEM`` for a RAR 1.5-4 name, and the argv
    conversion for a mask; both go through the same ``CharToWide``, so stored bytes
    given as the mask read back as the name does. ``None`` when this host's
    conversion cannot be reproduced.
    """
    data = data.split(b"\0", 1)[0]
    if data.isascii():
        return data.decode("ascii")
    if sys.platform == "win32":
        return _windows_unrar_8bit_name(data)
    if sys.platform == "darwin":
        # unrar's macOS build converts with ``UtfToWide`` rather than the locale.
        return _unrar_utf_to_wide(data)
    return _unrar_posix_char_to_wide(data)


def _windows_precomposed(text: str) -> str:
    """``ConvertToPrecomposed``: ``FoldStringW(MAP_PRECOMPOSED)``, unchanged on failure."""
    if text.isascii():
        return text
    if sys.platform == "win32":
        import ctypes

        fold_string = ctypes.windll.kernel32.FoldStringW
        map_precomposed = 0x20
        size = fold_string(map_precomposed, text, -1, None, 0)
        if size > 0:
            buffer = ctypes.create_unicode_buffer(size)
            if fold_string(map_precomposed, text, -1, buffer, size) != 0:
                return buffer.value
    return text


def unrar_member_view(
    *,
    rar5: bool,
    stored: bytes | None,
    rar3_unicode_name: str | None,
    host_os: int | None,
    file_version: int | None,
) -> str | None:
    """A member's name as ``unrar`` compares it with an ``-n`` mask, or ``None``.

    ``stored`` is the header's name bytes (for RAR 1.5-4, the 8-bit field);
    ``rar3_unicode_name`` is the decoded Unicode field when there is one. The
    separator is ``/``, or ``\\`` on Windows. ``None`` means this host's reading
    of the name cannot be reproduced (:func:`unrar_char_to_wide`).
    """
    if stored is None:
        return None
    if rar5:
        text: str | None = _unrar_utf_to_wide(stored)
        if file_version:
            # FHEXTRA_VERSION appends ``;n`` after the name is decoded.
            text = f"{text};{file_version}"
        hsys_unix = host_os == _RAR5_HOST_UNIX
        hsys_windows = host_os == _RAR5_HOST_WINDOWS
    else:
        # unrar keeps a RAR 1.5-4 Unicode name as UTF-16 code units, one ``wchar_t``
        # each, so a valid pair is two characters to its matcher (measured on 7.00:
        # ``-n./pair??.txt`` selects ``pair`` U+1F600 ``.txt``, ``-n./pair?.txt``
        # does not).
        text = (
            _as_utf16_units(rar3_unicode_name)
            if rar3_unicode_name
            else unrar_char_to_wide(stored)
        )
        hsys_unix = host_os in _RAR3_HSYS_UNIX
        hsys_windows = host_os in _RAR3_HSYS_WINDOWS
    if text is None:
        return None
    windows = sys.platform == "win32"
    # ``TruncateAtZero`` runs last, but no step before it moves a NUL.
    text = text.split("\0", 1)[0]
    if windows and hsys_unix:
        text = _windows_precomposed(text)
    if rar5 and (windows or hsys_windows):
        text = text.replace("\\", "_")
    if windows:
        text = text.replace(":", "_")
    if not rar5:
        text = text.replace("\\", "/")
    return text.replace("/", "\\") if windows else text


def unrar_mask_view(mask: str | bytes) -> str | None:
    """The ``-n`` value (``./`` plus ``mask``) as ``unrar`` reads it from argv."""
    if isinstance(mask, bytes):
        text = unrar_char_to_wide(mask.replace(b"*", b"?"))
        return None if text is None else "./" + text
    return "./" + _unrar_mask_for(mask)


def _unrar_is_div(char: str) -> bool:
    if sys.platform == "win32":
        return char in ("\\", "/")
    return char == "/"


def _unrar_convert_path_offset(text: str) -> int:
    """``ConvertPath``: where the name starts once leading path parts are dropped.

    Drops everything up to the last ``/../`` (or a trailing ``/..``), then any run
    of ``./``, ``../`` and, on Windows, drive and UNC prefixes. ``../ab`` and
    ``ab`` are therefore the same name to ``unrar``.
    """
    size = len(text)
    windows = sys.platform == "win32"
    if (
        not text
        or text[0] not in ("./\\" if windows else "./")
        and not (windows and size > 1 and text[1] == ":")
        and "/.." not in text
        and not (windows and "\\.." in text)
    ):
        # Nothing to drop, which is every ordinary name.
        return 0

    def at(index: int) -> str:
        return text[index] if index < size else "\0"

    dest = 0
    for index in range(size):
        if (
            _unrar_is_div(text[index])
            and at(index + 1) == "."
            and at(index + 2) == "."
            and (_unrar_is_div(at(index + 3)) or at(index + 3) == "\0")
        ):
            dest = index + 3 if at(index + 3) == "\0" else index + 4
    while dest < size:
        index = dest
        if windows and index + 1 < size and text[index + 1] == ":":
            index += 2
        if _unrar_is_div(at(index)) and _unrar_is_div(at(index + 1)):
            slashes = 0
            for scan in range(index + 2, size):
                if _unrar_is_div(text[scan]):
                    slashes += 1
                    if slashes == 2:
                        index = scan + 1
                        break
        for scan in range(index, size):
            if _unrar_is_div(text[scan]):
                index = scan + 1
            elif text[scan] != ".":
                break
        if index == dest:
            break
        dest = index
    return dest


def _unrar_name_pos(text: str) -> int:
    """``GetNamePos``: where the last path component starts."""
    for index in range(len(text) - 1, -1, -1):
        if _unrar_is_div(text[index]):
            return index + 1
    # ``IsDriveLetter``: an ASCII letter (``etoupperw`` folds only ASCII), then
    # ``:``. ``ConvertPath`` checks only the colon, and
    # ``_unrar_convert_path_offset`` follows it there.
    if (
        sys.platform == "win32"
        and len(text) > 1
        and text[0].isascii()
        and text[0].isalpha()
        and text[1] == ":"
    ):
        return 2
    return 0


def _unrar_fold(char: str) -> str:
    """``touppercw``: identity on Unix; one character's upper case on Windows."""
    if sys.platform != "win32":
        return char
    upper = char.upper()
    return upper if len(upper) == 1 else char


def _unrar_fold_all(text: str) -> str:
    if sys.platform != "win32":
        return text
    return "".join(_unrar_fold(char) for char in text)


def _unrar_same(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    if sys.platform != "win32":
        return left == right
    return all(_unrar_fold(a) == _unrar_fold(b) for a, b in zip(left, right))


def _unrar_match(pattern: str, string: str) -> bool:
    """unrar's ``match()`` for a pattern with ``?`` as its only wildcard.

    ``?`` takes exactly one character. A ``.`` in the pattern may also stand for
    nothing where the string ends or has a ``\\``, so the mask ``a.`` selects the
    member ``a``. With no ``*`` there is nothing to backtrack over, so this is a
    single walk.
    """
    p = s = 0
    while True:
        s_char = _unrar_fold(string[s]) if s < len(string) else "\0"
        p_char = _unrar_fold(pattern[p]) if p < len(pattern) else "\0"
        p += 1
        if p_char == "\0":
            return s_char == "\0"
        if p_char == "?":
            if s_char == "\0":
                return False
        elif p_char == "*":
            raise AssertionError(
                "unrar mask still contains '*'; build it with _unrar_mask_for"
            )
        elif p_char != s_char:
            if p_char == "." and s_char in ("\0", "\\", "."):
                continue
            return False
        s += 1


def _unrar_is_wild(text: str) -> bool:
    return "*" in text or "?" in text


def _unrar_cmp_name(wild: str, name: str) -> bool:
    """``CmpName(wild, name, MATCH_WILDSUBPATH)``."""
    name_pos = _unrar_name_pos(name)
    wild_pos = _unrar_name_pos(wild)
    # A mask selects everything below the path it names: ``ab`` selects ``ab/x``,
    # and, because both separators are tested on every platform, ``ab\\x``.
    if _unrar_same(name[: len(wild)], wild) and (
        len(name) == len(wild) or name[len(wild)] in ("\\", "/")
    ):
        return True
    if _unrar_is_wild(wild[:wild_pos]):
        return _unrar_match(wild, name)
    if _unrar_is_wild(wild):
        if wild_pos > 0 and not _unrar_same(name[:wild_pos], wild[:wild_pos]):
            return False
    elif wild_pos != name_pos or not _unrar_same(name[:wild_pos], wild[:wild_pos]):
        return False
    return _unrar_match(wild[wild_pos:], name[name_pos:])


def unrar_mask_selects(mask_view: str, name_view: str) -> bool:
    """True when ``unrar p -n<mask_view>`` emits a file member named ``name_view``.

    ``CommandData::CheckArgs`` for a file: both strings go through ``ConvertPath``
    and are compared with ``CmpName``. A mask ending in a separator selects
    whole directories and is never built here. A name that ``ConvertPath``
    reduces to nothing (``./``, ``../``) is never selected, though ``CmpName``
    alone would let the mask ``...`` match it: ``unrar p -n...`` emits only the
    members named ``...``.
    """
    if sys.platform == "win32":
        # Both sides as Windows unrar holds them: ``CheckArgs`` turns ``/`` into
        # ``\\`` in the mask and ``ConvertFileHeader`` does so in the name. A view
        # from :func:`unrar_member_view` already has ``\\``; a name given with
        # ``/`` would otherwise differ in its directory part.
        mask_view = mask_view.replace("/", "\\")
        name_view = name_view.replace("/", "\\")
    if mask_view and _unrar_is_div(mask_view[-1]):
        raise AssertionError("a mask ending in a separator is never passed to unrar")
    mask = mask_view[_unrar_convert_path_offset(mask_view) :]
    name = name_view[_unrar_convert_path_offset(name_view) :]
    if not name:
        return False
    if sys.platform == "win32":
        mask, name = _as_utf16_units(mask), _as_utf16_units(name)
    return _unrar_cmp_name(mask, name)


def _as_utf16_units(text: str) -> str:
    """``text`` with each character above U+FFFF as its two UTF-16 code units.

    Windows ``wchar_t`` is a code unit, so there ``?`` takes half of such a
    character.
    """
    if all(ord(char) <= 0xFFFF for char in text):
        return text
    # Not a UTF-16 round trip: Python's decoder joins a valid pair back into one
    # character.
    out: list[str] = []
    for char in text:
        code = ord(char) - 0x10000
        if code < 0:
            out.append(char)
        else:
            out += (chr(0xD800 + (code >> 10)), chr(0xDC00 + (code & 0x3FF)))
    return "".join(out)


def unrar_mask_is_usable(mask_view: str) -> bool:
    """True when the mask names something once ``unrar`` drops its leading parts.

    An empty remainder or one ending in a separator selects every member, or
    whole directories, instead of one name.
    """
    if sys.platform == "win32":
        mask_view = mask_view.replace("/", "\\")
    rest = mask_view[_unrar_convert_path_offset(mask_view) :]
    return bool(rest) and not _unrar_is_div(rest[-1])


def unrar_selection_keys(view: str) -> tuple[str, ...]:
    """Keys under which a member must be indexed so an exact mask can find it.

    An exact mask (no ``?``) selects a name only when, after ``ConvertPath``, it
    equals the name up to trailing dots, or equals the part of the name before
    one of its separators. The keys are those strings, folded on Windows. The
    index is a filter: :func:`unrar_mask_selects` still decides.
    """
    if sys.platform == "win32":
        view = view.replace("/", "\\")  # as in :func:`unrar_mask_selects`
    name = view[_unrar_convert_path_offset(view) :]
    folded = _unrar_fold_all(name)
    keys = {folded.rstrip(".")}
    for separator in ("/", "\\"):
        index = folded.find(separator)
        while index != -1:
            keys.add(folded[:index])
            index = folded.find(separator, index + 1)
    return tuple(keys)


def unrar_mask_keys(mask_view: str) -> tuple[str, ...] | None:
    """Keys to look an exact mask up by (:func:`unrar_selection_keys`), or ``None``.

    ``None`` for a mask with ``?``, which has to be tested against every member.
    """
    if sys.platform == "win32":
        mask_view = mask_view.replace("/", "\\")
    mask = mask_view[_unrar_convert_path_offset(mask_view) :]
    if _unrar_is_wild(mask):
        return None
    folded = _unrar_fold_all(mask)
    return (folded, folded.rstrip("."))


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
    member: str | bytes | None = None,
    version_control: bool = False,
    rar5: bool = False,
) -> tuple[subprocess.Popen[bytes], BinaryIO]:
    """Spawn ``<unrar|rar> p -inul -cfg- [-ver] [-p|-p-] [-n./member] -- archive``.

    ``version_control`` adds ``-ver`` so the pipe includes WinRAR file-version history
    payloads (needed for solid demux when versioned FILE rows are present, and for a
    named open of a ``path;n`` history member — the ``-n`` mask excludes history rows
    unless ``-ver`` is set).

    A named ``member`` is passed as a ``-n./`` include mask, never positionally, so a
    hostile member name cannot inject an ``unrar`` switch or ``@listfile`` argument
    (see :func:`_member_include_switch`). It is ``bytes`` for a name given to
    ``unrar`` as stored (:func:`unrar_member_argument`). The child runs under a
    UTF-8 locale (:func:`_unrar_env`). ``None`` means no ``-n`` mask, so every
    payload member is piped: the solid pass wants that, and a named read must never
    pass it.

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
    unrar = find_rarlab_unrar()
    cmd: list[str | bytes] = [unrar, "p", "-inul", _RAR_DISABLE_CONFIG]
    if version_control:
        cmd.append("-ver")
    pass_arg = _password_arg(password)
    cmd.append(pass_arg)
    if member is not None:
        # subprocess raises a bare ValueError for a NUL in any argument.
        refusal = unrar_member_refusal(member)
        if refusal is not None:
            shown = quoted(
                member.decode("utf-8", "surrogateescape")
                if isinstance(member, bytes)
                else member
            )
            raise UnsupportedFeatureError(
                f"RAR member {shown} cannot be read through unrar: {refusal}."
            )
        cmd.append(_member_include_switch(member))
    # ``--`` ends switch parsing, so an archive path starting with ``-`` (a
    # caller's ``-inul.rar``) is read as the archive and not as a switch. An
    # ``@`` prefix needs no guard: unrar reads the first non-switch argument as
    # the archive, and only later file-name arguments as listfiles.
    cmd.append("--")
    cmd.append(str(archive_path))
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
