"""Universal path-safety checks and policy permission transforms for extraction.

Two independent stages sit in front of every on-disk write (see ``safe-extraction``):

* :func:`check_universal` — the non-bypassable path/link/special-file constraints,
  enforced under **every** :class:`ExtractionPolicy` (including ``TRUSTED``). Run on the
  **final** member, after the policy transform and the caller's filter, so a filter can
  rename an unsafe member to a safe one; whatever it returns is checked.
* :func:`reroot_absolute` — under ``STANDARD`` and ``TRUSTED``, an absolute name is
  moved inside the destination by dropping its root, as tar, unzip and 7-Zip do.
  ``STRICT`` does not re-root, so ``check_universal`` refuses the member there.
* the policy transforms in :data:`POLICY_TRANSFORMS` — permission/ownership normalization
  applied to a transient copy of the member, selected by the active policy.

The post-``os.symlink`` re-resolution check (the third defense-in-depth layer) lives in
the coordinator, next to the ``os.symlink`` call it guards.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import string
import sys
import unicodedata
from collections.abc import Callable
from pathlib import Path

from archivey.exceptions import ExtractionError, FilterRejectionError
from archivey.internal.long_paths import long_path, plain
from archivey.internal.naming import BIDI_REORDERING_CONTROLS
from archivey.types import ArchiveMember, ExtractionPolicy, MemberType

# Split a member name into path components on either separator; a ".." component after
# this split is a traversal attempt regardless of which separator the archive used.
_SEP_SPLIT = re.compile(r"[\\/]")
# The same split, keeping each separator as its own list item, for a rewrite that has to
# put the name back together exactly as it was apart from the segments it changed.
_SEP_KEEP_SPLIT = re.compile(r"([\\/])")


def _map_segments(name: str, fn: Callable[[str], str]) -> str:
    """``name`` with ``fn`` applied to each segment between separators (``/`` or
    ``\\``); the separators are kept exactly as they are."""
    return "".join(
        part if part in ("/", "\\") else fn(part)
        for part in _SEP_KEEP_SPLIT.split(name)
    )


def _has_drive_letter(name: str) -> bool:
    """Whether ``name`` starts with a Windows drive letter: a single ASCII letter
    followed by ``:`` (``C:\\``, ``C:/x``, ``C:foo``).

    ASCII only, on purpose. ``str.isalpha()`` is Unicode-wide and would classify
    ``Ä:foo`` — an ordinary POSIX filename — as a Windows drive path. That would make
    TRUSTED refuse it as an absolute name, and every policy refuse a symlink to it.
    """
    return len(name) >= 2 and name[0] in string.ascii_letters and name[1] == ":"


def _is_absolute(name: str) -> bool:
    """Whether ``name`` is an absolute path: a POSIX root, a UNC share, or a drive letter."""
    if name.startswith(("/", "\\")):
        return True  # POSIX root or UNC / rooted-backslash
    return _has_drive_letter(name)


def _has_windows_root(target: str) -> bool:
    """Whether ``target`` starts with a drive letter (``C:``, ``C:/x``, ``C:x``) or a UNC
    root (two separators, ``//server/share`` or ``\\\\server\\share``).

    A single leading ``\\`` (``\\foo``) is not a Windows root here; see the comment
    in :func:`check_universal`.
    """
    if target[:1] in ("/", "\\") and target[1:2] in ("/", "\\"):
        return True
    return _has_drive_letter(target)


def is_rooted(name: str) -> bool:
    """Whether ``name`` starts at a filesystem root: a leading ``/`` or ``\\`` (POSIX
    root, UNC share) or a drive letter followed by a separator (``C:/``, ``C:\\``).

    Narrower than :func:`_is_absolute`, on purpose. A drive-relative ``C:x`` is also an
    ordinary POSIX name (``a:b``), so it has no root to drop: rewriting it to ``x``
    would put the member where another member named ``x`` belongs. It stays refused.
    """
    if name[:1] in ("/", "\\"):
        return True
    return _is_absolute(name) and name[2:3] in ("/", "\\")


def strip_absolute_root(name: str) -> str:
    """``name`` with its root removed: every leading ``/`` and ``\\`` and a drive letter
    followed by a separator, repeatedly, so ``C:\\x``, ``//host/share/x`` and ``/C:/x``
    all lose their whole root. A name that is nothing but a root becomes ``"."``. A name
    that is not rooted (see :func:`is_rooted`), ``C:x`` included, is returned as is.

    ``C:/`` is dropped on every OS, as bsdtar does, so a member extracts to the same
    place wherever it is extracted. GNU tar keeps it as a literal directory on POSIX.
    """
    stripped = name
    while is_rooted(stripped):
        if stripped[:1] in ("/", "\\"):
            stripped = stripped.lstrip("/\\")
        else:  # a drive letter and its separator; the next pass strips the separator
            stripped = stripped[2:]
    return stripped or "."


def reroot_absolute(member: ArchiveMember) -> ArchiveMember:
    """Move an absolute ``member`` inside the destination by dropping its root.

    ``/etc/x`` extracts as ``etc/x``, which is what GNU tar, bsdtar, unzip, 7-Zip and
    Python's ``tarfile`` ``data`` filter all do. Only the root goes: a ``..`` component
    is left in place for :func:`check_universal` to refuse.

    Link targets are left as stored. A symlink's target is a filesystem path, and an
    absolute one is refused as an escape. A hardlink's target is a member name:
    extraction links to the member it names, which is re-rooted on its own turn
    (``tar -P`` stores ``/a`` and a hardlink naming ``/a``), and the target string
    never becomes a path. A caller filter therefore sees the target as stored.

    Only a rooted name is re-rooted (:func:`is_rooted`); a drive-relative ``C:x`` is
    left for :func:`check_universal` to refuse.

    Returns ``member`` itself when there is nothing to change.
    """
    if not is_rooted(member.name):
        return member
    return member.replace(name=strip_absolute_root(member.name))


def _within(path: Path, root: Path) -> bool:
    return path.is_relative_to(root)


# Windows' code for a path whose links do not resolve (``ERROR_CANT_RESOLVE_FILENAME``),
# its equivalent of ``ELOOP``.
_ERROR_CANT_RESOLVE_FILENAME = 1921


def resolve_or_raise_on_loop(path: Path) -> Path:
    """``path`` with every symlink on the way followed, raising ``OSError`` when that
    cannot be done exactly: ``ELOOP`` for a symlink loop, on every Python version, and
    the error itself when a component exists but cannot be looked at.

    A missing component is kept as a name, as ``os.path.realpath`` does, and so is a
    component under a file (``ENOTDIR``), which no path lookup can go through either.
    Any other error is raised, because ``realpath`` would keep that component as a
    name too and carry on with the rest of the path, while the kernel may still follow
    it. ``ENAMETOOLONG`` is the one that matters: a chain of links whose expansion is
    longer than ``PATH_MAX`` cannot be looked up as one string, but the kernel follows
    it one link at a time, so a check that kept the long name would see a path inside
    the destination where the kernel goes outside (CVE-2025-4517 in ``tarfile``).
    Python's own fix, ``realpath(strict=ALLOW_MISSING)``, is missing from older
    patch releases and also raises for ``ENOTDIR``, so the walk is done here on POSIX.

    On Windows ``Path.resolve()`` is used, as the platform resolves links itself:
    before Python 3.13 it raised ``RuntimeError`` on a loop, from 3.13 it returns a
    path that still contains the looping link. The ``RuntimeError`` is turned into an
    ``OSError`` and a ``stat`` finds the loop on 3.13+. Windows reports a loop as
    ``ERROR_CANT_RESOLVE_FILENAME``, which Python maps to ``EINVAL``, so it is raised
    as ``ELOOP``, with the platform's own error on the chain as ``__cause__``. A path
    past ``MAX_PATH`` is resolved in the extended form (``long_paths``), so a link
    deep in the tree is followed as it is for a short path, and the result is given
    without the prefix, for comparison with a plain root.

    Either way the error names ``path``, and callers catch ``OSError`` alone.
    """
    if os.name == "nt":
        return _resolve_with_pathlib(path)
    # Joined with the working directory, not ``os.path.abspath``, which would drop a
    # ``name/..`` pair before ``name`` is looked at.
    return Path(_realpath_posix(os.path.join(os.getcwd(), path), str(path)))


# Links followed in one resolution before it counts as a loop: Linux's own limit
# (``MAXSYMLINKS``), so a chain the kernel follows is followed here too. The dry run's
# ``_MAX_LINK_HOPS`` and the CLI hoist's walk use the same bound for the same reason;
# ``link_watch._MAX_FOLLOWS`` is 64 on purpose, as a walk that records dependencies must
# go past every kernel's limit.
_MAX_LINK_FOLLOWS = 40


def _realpath_posix(path: str, asked: str) -> str:
    """``os.path.realpath(path)`` that raises instead of guessing (see
    :func:`resolve_or_raise_on_loop`). ``path`` is absolute; ``asked`` is the path
    the caller passed, for the error."""
    rest = path.split("/")[::-1]
    resolved = ""
    follows = 0
    while rest:
        name = rest.pop()
        if name in ("", "."):
            continue
        if name == "..":
            resolved = resolved[: resolved.rfind("/")]
            continue
        candidate = f"{resolved}/{name}"
        try:
            # Every filesystem call under the destination goes through ``long_path``
            # (identity on POSIX; ``test_filesystem_calls_take_the_long_path_form``
            # checks the routing). Safe here because no candidate holds a ``..``.
            mode = os.lstat(long_path(candidate)).st_mode
        except (FileNotFoundError, NotADirectoryError):
            resolved = candidate
            continue
        except OSError as exc:
            raise OSError(exc.errno, exc.strerror, asked) from exc
        if not stat.S_ISLNK(mode):
            resolved = candidate
            continue
        follows += 1
        if follows > _MAX_LINK_FOLLOWS:
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), asked)
        try:
            target = os.readlink(long_path(candidate))
        except OSError as exc:
            raise OSError(exc.errno, exc.strerror, asked) from exc
        if target.startswith("/"):
            resolved = ""
        rest.extend(target.split("/")[::-1])
    return resolved or "/"


def _resolve_with_pathlib(path: Path) -> Path:
    """The Windows half of :func:`resolve_or_raise_on_loop`."""
    try:
        resolved = Path(plain(os.fspath(Path(long_path(path)).resolve())))
    except RuntimeError as exc:
        raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), str(path)) from exc
    try:
        Path(long_path(resolved)).stat()
    except OSError as exc:
        if exc.errno == errno.ELOOP or (
            getattr(exc, "winerror", None) == _ERROR_CANT_RESOLVE_FILENAME
        ):
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), str(path)) from exc
    return resolved


SYMLINK_ESCAPES = "Symlink target escapes destination"
SYMLINK_LOOPS = "Symlink target is part of a symlink loop"


def link_resolution_problem(path: Path, root: Path) -> str | None:
    """Why ``path`` does not resolve to a place inside ``root``, or ``None`` when it
    does: ``SYMLINK_LOOPS`` for a loop on the way, else ``SYMLINK_ESCAPES``. A path
    that cannot be resolved for another reason counts as an escape, as it does in the
    check after a link is created. Both are refused the same way; only the message
    differs. A loop cannot be resolved at all, so there is no inside or outside to
    compare: the loop message wins even when the target might have led outside."""
    try:
        resolved = resolve_or_raise_on_loop(path)
    except OSError as exc:
        return SYMLINK_LOOPS if exc.errno == errno.ELOOP else SYMLINK_ESCAPES
    return None if _within(resolved, root) else SYMLINK_ESCAPES


def _check_path_string(
    value: str, *, member_name: str, what: str, link_target: str | None = None
) -> None:
    """Refuse a string that cannot name a filesystem path: a NUL, which the OS
    truncates on, or a character the platform filesystem encoding cannot represent.
    ``what`` is ``"member name"`` or ``"link target"``, for the message."""
    if "\x00" in value:
        raise FilterRejectionError(
            f"Null byte in {what}", member_name=member_name, link_target=link_target
        )
    try:
        os.fsencode(value)
    except UnicodeEncodeError as exc:
        raise FilterRejectionError(
            f"{what.capitalize()} cannot be encoded for the filesystem",
            member_name=member_name,
            link_target=link_target,
        ) from exc


def _reject_bidi_override(value: str, *, member_name: str, what: str) -> None:
    """Refuse a bidi override/isolate in a string that is about to become a path.

    Only the *reordering* controls (U+202A–202E, U+2066–2069): they open a span and
    reorder the surrounding text, which is what makes ``evil<RLO>gnp.exe`` display as a
    ``.png``. The three directional marks are deliberately absent from
    ``BIDI_REORDERING_CONTROLS`` — they reorder nothing and occur in legitimate Arabic
    and Hebrew filenames. Listing still presents either kind as stored, with
    ``MEMBER_NAME_BIDI_CONTROL``; this is only about writing one to a filesystem a
    person will read back.

    ASCII cannot contain them — skip the scan on the common path.
    """
    if value.isascii():
        return
    found = [char for char in value if char in BIDI_REORDERING_CONTROLS]
    if not found:
        return
    spelled = ", ".join(f"U+{ord(char):04X}" for char in found)
    raise FilterRejectionError(
        f"Bidirectional override ({spelled}) in {what}: {value!r}. It would display "
        f"as a different name than it is; extract it under a name you choose.",
        member_name=member_name,
    )


# A lone surrogate that is not a surrogateescape byte (U+DC80-U+DCFF). A 7z name holds
# UTF-16 code units and keeps one when its partner is missing (``surrogatepass``).
_LONE_SURROGATE = re.compile("[\ud800-\udc7f\udd00-\udfff]")


def _surrogate_as_bytes(match: re.Match[str]) -> str:
    return (
        match.group()
        .encode("utf-8", "surrogatepass")
        .decode("utf-8", "surrogateescape")
    )


def _lone_surrogates_as_bytes(text: str) -> str:
    """``text`` with each lone surrogate outside U+DC80-U+DCFF as its UTF-8 bytes.

    U+D800 becomes ``ed a0 80`` (``surrogatepass``), returned as surrogateescape
    characters, so ``os.fsencode`` gives exactly those bytes and the O7 escape sees
    three undecodable bytes. U+DC80-U+DCFF is left alone: in a ``str`` it already
    means one undecodable byte, for every format.
    """
    if _LONE_SURROGATE.search(text) is None:
        return text
    return _LONE_SURROGATE.sub(_surrogate_as_bytes, text)


def disk_spelling(text: str) -> str:
    """``text`` as ``os`` calls need it to write the name 7-Zip writes.

    On POSIX, each lone surrogate outside the surrogateescape range becomes its UTF-8
    form (:func:`_lone_surrogates_as_bytes`): U+D800 becomes the bytes ``ed a0 80``,
    which is what 7-Zip 23.01 writes on Linux. Without this, ``os.fsencode`` raises
    ``UnicodeEncodeError``. Under ``STRICT`` and ``STANDARD`` the name policy has
    already escaped such a name, so this changes a member name only under
    ``TRUSTED``; it changes a link target under every policy. A link to a member whose
    name the policy escaped therefore dangles, as it does for undecodable bytes.

    U+DC80-U+DCFF is left alone: in a ``str`` it means one undecodable byte, for every
    format, and ``os.fsencode`` writes that byte. A 7z name with a lone unit in that
    range is therefore written as the byte, not as 7-Zip's three-byte form.

    On Windows the text is returned unchanged: the filesystem takes the code units.
    """
    if sys.platform == "win32":
        return text
    return _lone_surrogates_as_bytes(text)


def disk_spelled(member: ArchiveMember) -> ArchiveMember:
    """``member`` with its name and link target in :func:`disk_spelling`.

    The same member when nothing changes. The extraction coordinator gives this to
    the path checks and to the write, but not to the name policy: the policy escapes a
    lone surrogate itself, the same way on every OS, and the disk spelling differs
    between POSIX and Windows.
    """
    name = disk_spelling(member.name)
    target = member.link_target
    disk_target = disk_spelling(target) if target is not None else None
    if name == member.name and disk_target == target:
        return member
    return member.replace(name=name, link_target=disk_target)


def check_universal(
    member: ArchiveMember,
    dest: Path,
    *,
    link_target_on_disk: Callable[[str], str] | None = None,
    show_os_error: Callable[[OSError], None] | None = None,
) -> None:
    """Enforce the non-bypassable universal path-safety constraints on ``member``.

    ``dest`` is the extraction root. Raises :class:`FilterRejectionError` on the first
    violation (an escaping path, an escaping symlink, a special file); returns ``None``
    when the member is safe to extract. Raises :class:`ExtractionError` when the member's
    parent directory cannot be resolved in the destination (a symlink loop already on
    disk): that is a failure, not a block. Applied to the member about to be written, after
    the policy transform and any caller filter, regardless of the active policy.

    ``link_target_on_disk`` is given by a dry run only. It maps a link target to the
    one the link is created with in the scratch tree, so an absolute target is checked
    where it points there.

    ``show_os_error``, when given, points an ``OSError``'s file names at the paths the
    caller sees, in place, before the error's text goes into a message. It expects
    the error's file names to be built from the ``dest`` given here, which the
    coordinator has already resolved. The coordinator gives it: it removes the
    long-path prefix, and under a dry run it names dest, not the scratch directory.

    Everything here meets one of two criteria. Either the *write itself* is dangerous
    or impossible — escaping the destination, a NUL the OS truncates on, a device
    node — or the *outcome would differ by OS*: a symlink target with a Windows drive
    or UNC root escapes on Windows and is an ordinary relative name on POSIX, so it is
    refused everywhere (maintainer ruling, 2026-10-06). A name that is merely
    *deceptive to read* meets neither and is policy-keyed instead; see
    ``apply_name_policy`` and ADR 0017.

    A HARDLINK's target string is not checked here. It names an earlier member of the
    archive, and the link is made to the file that member was written to, so the
    string never becomes a path, and a NUL or an unencodable character in it reaches
    no OS call. The coordinator refuses the link instead when it refuses the member
    the link gets its bytes from (``ExtractionCoordinator._source_refused``).
    """
    name = member.name

    # (1) String checks on member.name. Names are faithful (meaning-preserving
    # normalization keeps a leading "/" and every ".."), so the danger is visible directly
    # on member.name — no separate raw_name inspection is needed. Any ".." component is
    # rejected (escaping and internal alike): a well-formed archive has no reason to carry
    # one. An absolute name reaching here was not re-rooted: STRICT, or a filter that
    # returned one (see reroot_absolute).
    # A name the platform filesystem encoding cannot represent can never be
    # materialized under dest, and it would otherwise crash the parent-resolution
    # below with a raw UnicodeEncodeError. The extraction coordinator passes the
    # member through ``disk_spelled`` first, so a lone surrogate reaches here as
    # bytes on POSIX; a caller of this function that does not still gets a
    # rejection. (Windows' surrogatepass encoding represents lone surrogates.)
    _check_path_string(name, member_name=name, what="member name")
    if _is_absolute(name):
        raise FilterRejectionError("Absolute path not allowed", member_name=name)
    if ".." in _SEP_SPLIT.split(name):
        raise FilterRejectionError(
            "Path traversal ('..') in member name", member_name=name
        )

    rel = name.rstrip("/")
    if member.type != MemberType.DIRECTORY and rel in ("", "."):
        raise FilterRejectionError(
            "Member name refers to the extraction root",
            member_name=name,
        )

    if member.type == MemberType.OTHER:
        raise FilterRejectionError(
            "Special file (device/FIFO/socket) not allowed",
            member_name=name,
        )

    # Pre-extraction path computation: the destination's PARENT directory must resolve
    # within the root. We resolve the parent, not the full path — the final component may
    # be a pre-existing (possibly hostile) symlink that the OverwritePolicy will unlink
    # rather than follow, so following it here would wrongly reject a REPLACE. Combined
    # with the no-".." name check above, a parent inside the root guarantees the member
    # lands inside the root. A symlinked *parent* that escapes is still caught.
    is_root = rel in ("", ".")  # "" / "." is the root dir member itself
    try:
        dest_root = resolve_or_raise_on_loop(dest)
        # The root member has no parent to place, so only other members are checked.
        if not is_root:
            parent = resolve_or_raise_on_loop((dest_root / rel).parent)
            if not _within(parent, dest_root):
                raise FilterRejectionError(
                    "Member resolves outside the destination root",
                    member_name=name,
                )
    except OSError as exc:
        # A path in dest or below it that the resolver cannot follow exactly: a symlink
        # loop the destination already had (links this run creates never loop: one that
        # would is removed as an escape), or a component it cannot look at, such as a
        # directory it may not search or a link chain past PATH_MAX
        # (``resolve_or_raise_on_loop``). The member cannot be placed, and that is the
        # destination's state, not a policy decision.
        if show_os_error is not None:
            show_os_error(exc)
        cause = (
            "a symlink loop"
            if exc.errno == errno.ELOOP
            else "a path that cannot be looked up"
        )
        raise ExtractionError(
            f"A path in the destination does not resolve ({cause}): {exc}",
            member_name=name,
        ) from exc

    # Symlink-target escape at planning time (the authoritative check is re-run
    # post-creation in the coordinator). The target is relative to the link's own
    # directory; an absolute target makes the join absolute, so it passes only when it
    # names a path inside dest.
    target = member.link_target
    if target is not None and member.type == MemberType.SYMLINK:
        # Same string-level guards as for names: a NUL or an unencodable target
        # cannot name a filesystem path, and would crash the resolves below with a
        # raw ValueError / UnicodeEncodeError instead of a typed rejection.
        _check_path_string(
            target, member_name=name, what="link target", link_target=target
        )
        # A drive or UNC target leaves the destination on Windows and is a relative
        # name on POSIX. It is refused on every OS so that one archive extracts the
        # same way everywhere (maintainer ruling, 2026-10-06); unrar 7.00 on POSIX
        # refuses the `\??\`-prefixed spellings too.
        if _has_windows_root(target):
            raise FilterRejectionError(
                "Symlink target is a Windows drive or UNC path",
                member_name=name,
                link_target=member.link_target,
            )
        # Named exception: a target rooted by a single `\` (`\foo`) is left alone.
        # Windows resolves it to the drive root and refuses it as an escape, but on
        # POSIX a backslash is an ordinary filename character, so `\foo` is a
        # legitimate relative link there. Refusing it would block an archive that is
        # valid on POSIX, and ADR 0013 rules that extracting beats refusing. Only
        # TRUSTED keeps that `\` literal: STRICT and STANDARD write a TAR `\` as `/`,
        # so `link_target_on_disk` below turns `\foo` into `/foo`, an escape.
        if link_target_on_disk is not None:
            target = link_target_on_disk(target)
        problem = link_resolution_problem((dest_root / name).parent / target, dest_root)
        if problem is not None:
            raise FilterRejectionError(
                problem,
                member_name=name,
                link_target=member.link_target,
            )


# --- Policy permission transforms (applied to a transient copy) ---------------------

_HIGH_BITS = 0o7000  # setuid | setgid | sticky


def _carries_file_mode(member: ArchiveMember) -> bool:
    """Whether ``member``'s mode can end up on a regular file the extraction writes."""
    return member.type in (MemberType.FILE, MemberType.HARDLINK)


def transform_strict(member: ArchiveMember) -> ArchiveMember:
    """STRICT: drop ownership, strip high bits and group/other write, dirs at 755.

    A file's stored mode is *masked* with ``0o755``, never raised to it: ``0o660``
    (``umask 007``, a group-shared file) becomes ``0o640``, not ``0o644``. The policy
    that distrusts the archive must not be the one that opens a file up to other users.
    When the owner has an execute bit, the stored execute bits are kept, as GNU tar,
    unzip, 7-Zip, unar and ``tarfile``'s ``data`` filter keep them: a script extracted
    from a release tarball must still run. Setuid, setgid and sticky are stripped
    (both masks, ``0o755`` and ``0o644``, clear them). As in the ``data`` filter, and
    unlike the other four tools, a file whose owner has no execute bit loses the
    group and other execute bits too, so ``0o011`` is written ``0o000``. The filter's
    other step, adding owner read and write, is left out: it would widen the mode.

    A hardlink's mode is treated as a file's: a link materialized as a copy (the source
    was not selected, or it sits on another device) is written with it.
    """
    new: dict[str, object] = {
        "uid": None,
        "gid": None,
        "uname": None,
        "gname": None,
    }
    if member.is_dir:
        new["mode"] = 0o755
    elif _carries_file_mode(member):
        mode = member.mode
        if mode is None:
            new["mode"] = 0o644
        else:
            new["mode"] = mode & 0o755 if mode & 0o100 else mode & 0o644
    return member.replace(**new)


def transform_standard(member: ArchiveMember) -> ArchiveMember:
    """STANDARD: strip setuid/setgid/sticky, keep execute and ownership.

    Hardlinks are treated as files, for the reason given on ``transform_strict``.
    """
    new: dict[str, object] = {}
    if member.is_dir:
        new["mode"] = 0o755 if member.mode is None else (member.mode & ~_HIGH_BITS)
    elif _carries_file_mode(member):
        new["mode"] = 0o644 if member.mode is None else (member.mode & ~_HIGH_BITS)
    return member.replace(**new)


def transform_trusted(member: ArchiveMember) -> ArchiveMember:
    """TRUSTED: apply stored metadata as-is (a fresh copy, no changes)."""
    return member.replace()


POLICY_TRANSFORMS: dict[ExtractionPolicy, Callable[[ArchiveMember], ArchiveMember]] = {
    ExtractionPolicy.STRICT: transform_strict,
    ExtractionPolicy.STANDARD: transform_standard,
    ExtractionPolicy.TRUSTED: transform_trusted,
}


# --- Cross-platform portable-name policy (safe-extraction O3/O4/O7) ------------------
#
# These rules are keyed on ``ExtractionPolicy`` and applied to the FINAL member name (after
# the policy permission transform and any user filter). They make destination-name handling
# deterministic on every OS: ``STRICT`` is portable-by-default, ``STANDARD`` is portable but
# not paranoid, ``TRUSTED`` defers to the local OS (no name rejection or rewrite). See
# ``dev-docs/decisions/0013-cross-platform-name-safety-policies.md``.

# Windows reserved device names (case-insensitive, with or without an extension). Matched
# against the first dot-separated component of each path segment — ``NUL`` and ``NUL.txt``
# both mangle on Win32. Win32 also reads the superscript digits ¹²³ as ports
# (``COM¹``), and ``CONIN$``/``CONOUT$`` open the console's input and output.
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{port}{n}" for port in ("COM", "LPT") for n in [*"123456789", *"¹²³"]}
)


def _is_reserved_segment(segment: str) -> bool:
    """Whether ``segment`` names a Windows reserved device: its first dot-separated
    component, stripped of surrounding whitespace the way Win32 strips it."""
    return segment.partition(".")[0].strip().upper() in _RESERVED_NAMES


# Characters Win32 refuses in a file name (WinError 123), besides ``:``, which is
# rejected as an NTFS stream separator, ``\\`` and ``/``, which are separators, and
# NUL, which no OS writes. The O7 escape writes each one as ``%XX`` on every OS.
_WINDOWS_INVALID_CHARS = frozenset('<>"|?*') | frozenset(map(chr, range(0x01, 0x20)))


def _needs_escape(c: str) -> bool:
    return "\udc80" <= c <= "\udcff" or c in _WINDOWS_INVALID_CHARS


def _sanitize_portable_name(name: str) -> str:
    """O7: rewrite a name that a filesystem cannot store to a deterministic portable
    spelling. Two kinds of character are escaped as ``%XX`` (uppercase hex):

    - each surrogateescape char ``U+DC80``–``U+DCFF`` (a raw byte 0x80–0xFF that did
      not decode as UTF-8), as the byte;
    - each character Windows refuses in a name, ``<>"|?*`` and the controls
      0x01–0x1F, as its code point (``a?b`` → ``a%3Fb``). POSIX could write them, but
      then the same archive gives a different tree on Windows.

    In a name that has either, a literal ``%`` becomes ``%25``, so a *rewritten* name
    unescapes back to its bytes.

    Only names that actually carry such characters are rewritten — valid Unicode
    (including NFC/NFD forms) is representable on every filesystem and is returned
    unchanged; its cross-platform folding is the collision-tracking concern, not a
    representability one.

    A lone surrogate outside U+DC80-U+DCFF (a 7z name can keep one) is not a byte,
    and this function leaves it alone. ``apply_name_policy`` first spells it as its
    UTF-8 bytes, so it arrives here as three of them and ``hi\\ud800`` is written
    ``hi%ED%A0%80`` on every OS. ``TRUSTED`` skips both steps and writes 7-Zip's bytes
    (``disk_spelling``).

    The escaping is therefore reversible within a rewritten name, not across names: a
    stored ``%FF`` is returned verbatim and a raw ``0xFF`` byte is also written ``%FF``.
    The name alone cannot tell the two apart; ``ExtractionResult.presented_name`` can:
    after this rewrite it differs from the written name in the escaped bytes, and
    ``ExtractionResult.rewrites`` holds ``NameRewrite.PORTABLE_NAME``. A set
    ``presented_name`` alone is not enough, since an absolute-name re-root sets it
    too. The collision map sees both spellings as one key, so the second is resolved
    by the ``OverwritePolicy`` rather than silently overwriting the first.
    """
    if not any(_needs_escape(c) for c in name):
        return name
    out: list[str] = []
    for c in name:
        if "\udc80" <= c <= "\udcff":
            out.append(f"%{ord(c) - 0xDC00:02X}")
        elif c in _WINDOWS_INVALID_CHARS:
            out.append(f"%{ord(c):02X}")
        elif c == "%":
            out.append("%25")
        else:
            out.append(c)
    return "".join(out)


def _strip_trailing_dot_space(name: str) -> str:
    """O3: strip a trailing dot/space from each path segment — the portable spelling Win32
    itself produces (``stuff_etc.`` → ``stuff_etc``). Deterministic on every OS, so the
    result is identical everywhere and the O2 collision map catches any name it now clashes
    with. A segment that is *entirely* dots/spaces has no portable spelling and is rejected
    (an all-dots segment like ``...`` cannot round-trip and would collapse a path).

    A segment ends at either separator, ``/`` or ``\\``, as it does for ``_SEP_SPLIT``
    and ``collision_key``: a TAR name keeps ``\\`` as a literal character, and Windows
    then writes it as a separator, so ``foo. \\bar`` must lose its trailing space too.
    The separators themselves are kept as they are; only the segments change."""

    def strip(part: str) -> str:
        # Empty (from a leading/trailing/`//` separator) and the path-navigation spellings
        # "." / ".." are structural, not trailing-dot hazards — pass them through untouched
        # ("." is the never-empty root from normalize_member_name; ".." is caught earlier by
        # check_universal). Stripping them would wrongly collapse the segment to empty.
        if part in ("", ".", ".."):
            return part
        stripped = part.rstrip(". ")
        if stripped == "":
            raise FilterRejectionError(
                f"Path segment is entirely dots/spaces: {part!r}", member_name=name
            )
        return stripped

    return _map_segments(name, strip)


def _reject_unsafe_segments(
    path: str, *, member_name: str, where: str, link_target: str | None = None
) -> None:
    """Refuse a Windows-reserved device name or a ``:`` in any segment of ``path``.

    Both are unsafe (device capture, NTFS alternate data stream), not merely awkward,
    so ``STRICT`` and ``STANDARD`` refuse them on every platform.
    """
    for segment in _SEP_SPLIT.split(path):
        if not segment:
            continue
        if _is_reserved_segment(segment):
            raise FilterRejectionError(
                f"Windows-reserved device name in {where}: {segment!r}",
                member_name=member_name,
                link_target=link_target,
            )
        if ":" in segment:
            raise FilterRejectionError(
                f"Colon in {where} segment (NTFS alternate data stream): {segment!r}",
                member_name=member_name,
                link_target=link_target,
            )


def apply_name_policy(member: ArchiveMember, policy: ExtractionPolicy) -> ArchiveMember:
    """Enforce the portable-name policy on ``member``'s final name.

    ``TRUSTED`` returns the member unchanged (faithful bytes, defer to the local OS).
    ``STRICT``/``STANDARD`` **reject** only the unsafe name shapes — Windows-reserved device
    names, ``:`` (NTFS alternate data stream), and bidi overrides, in the name and in a
    symlink's target, and a name segment of only dots and spaces, which Win32 would merge
    into its parent — and **rewrite** the merely-non-portable ones: ``STRICT`` strips
    trailing dots/spaces (O3), and both levels write a ``\\`` as ``/`` (in a link target
    too) and escape bytes that are not UTF-8 and the characters Windows refuses,
    ``<>"|?*`` and 0x01-0x1F (O7). A lone surrogate outside U+DC80-U+DCFF is escaped too,
    as its UTF-8 bytes
    (``hi\\ud800`` → ``hi%ED%A0%80``), so the result is the same on every OS;
    ``TRUSTED`` writes 7-Zip's bytes instead. Rewriting (not rejecting) a
    legitimate-but-awkward name keeps extraction working; refusal is reserved for
    structures that cannot be safely written. Raises :class:`FilterRejectionError` (so the
    coordinator records ``BLOCKED``) on a rejected name; otherwise returns ``member`` or a
    rewritten ``.replace()`` copy.
    """
    if policy is ExtractionPolicy.TRUSTED:
        return member

    name = member.name

    # Bidi overrides are policy-keyed, not universal (ADR 0017). Unlike everything in
    # ``check_universal``, the *write* is completely safe: the file lands inside the
    # destination under exactly its stored bytes. What is unsafe is the name a person
    # reads back afterwards, which is a presentation problem, and presentation is the
    # axis this function owns. Running here rather than in ``check_universal`` also means
    # a caller filter that renames the member rescues it — renaming a deceptive name is
    # precisely the fix — and that ``TRUSTED`` returns above without reaching this.
    _reject_bidi_override(name, member_name=name, what="member name")
    if member.type in (MemberType.SYMLINK, MemberType.HARDLINK) and member.link_target:
        # A target carrying an override is the same disguise with an extra hop: the
        # listing shows a plausible target and the link on disk points at something that
        # reads differently.
        _reject_bidi_override(
            member.link_target, member_name=name, what=f"link target of {name!r}"
        )
    _reject_unsafe_segments(name, member_name=name, where="path")
    if member.type is MemberType.SYMLINK and member.link_target:
        # On Windows a link to ``t:stream`` names an alternate data stream of ``t``, and
        # one to ``NUL`` names the device, so a target segment is held to the rule a
        # name segment is. A hardlink target names a member, whose name is checked.
        _reject_unsafe_segments(
            member.link_target,
            member_name=name,
            where="link target",
            link_target=member.link_target,
        )

    # A trailing dot/space is silently stripped by Win32 — a legitimate macOS/Linux name
    # (e.g. a folder ending in '.'), not an attack. STRICT rewrites it to the portable
    # spelling so extraction succeeds and is identical on every OS; STANDARD/TRUSTED keep it
    # faithful. The O2 collision map catches any clash the rewrite creates. A segment of
    # only dots and spaces has no spelling Win32 keeps (``a/.../b`` would merge into
    # ``a/b``), so STANDARD refuses it as STRICT does.
    stripped = _strip_trailing_dot_space(name)  # refuses an all-dots segment under both
    if policy is ExtractionPolicy.STRICT:
        name = stripped
    # A TAR name keeps ``\`` as a literal character, and Windows writes it as a
    # separator. Writing it as ``/`` everywhere gives the tree Windows would create, on
    # every OS. The collision key already treats the two separators as one.
    name = name.replace("\\", "/")
    name = _sanitize_portable_name(_lone_surrogates_as_bytes(name))
    changes: dict[str, object] = {}
    if name != member.name:
        changes["name"] = name
    target = member.link_target
    if (
        member.type in (MemberType.SYMLINK, MemberType.HARDLINK)
        and target is not None
        and "\\" in target
    ):
        # Every name is written with "/" for "\", so a target spelled with "\" names
        # a path that has "/" on disk (no member can be written with a "\" under this
        # policy). Rewriting it keeps a symlink to another member live on POSIX, as it
        # is on Windows, where the coordinator writes each "/" as "\" again. The
        # rewritten target is also what the universal check sees. A hard link still
        # resolves by the member the reader matched to its stored target, not by this
        # string.
        changes["link_target"] = target.replace("\\", "/")
    return member.replace(**changes) if changes else member


# --- sanitize_names: a ready-made caller filter ---------------------------------------


def _collapse_dotdot(name: str) -> str:
    """``name`` with every ``..`` resolved lexically and none left over.

    ``a/../b`` becomes ``b``, as the filesystem the archive came from would read it. A
    ``..`` with nothing left to climb out of is dropped, so ``../x`` becomes ``x``, which
    is what unzip and 7-Zip do. The separators between the kept segments stay as stored:
    a TAR name keeps ``\\`` as an ordinary character on POSIX.
    """
    parts = _SEP_KEEP_SPLIT.split(name)
    if ".." not in parts:
        return name
    kept: list[str] = []  # alternating segment, separator, segment, ...
    for index in range(0, len(parts), 2):
        segment = parts[index]
        separator = parts[index + 1] if index + 1 < len(parts) else ""
        if segment == "..":
            # Drop the segment this one climbs out of, with its separator. An empty
            # or "." segment is not a directory to climb out of, so it goes too and
            # the ".." carries on to the real segment before it (a\.\..\b is b).
            while kept and kept[-2] in ("", "."):
                del kept[-2:]
            if kept:
                del kept[-2:]
            continue
        kept += [segment, separator]
    joined = "".join(kept)
    return joined.lstrip("/\\") or "."


def _sanitize_segment(segment: str) -> str:
    """A path segment made writable on Windows: ``:`` becomes ``_`` and a reserved
    device name gets ``_`` after its stem (``CON.txt`` → ``CON_.txt``)."""
    segment = segment.replace(":", "_")
    if _is_reserved_segment(segment):
        stem, dot, rest = segment.partition(".")
        return stem + "_" + dot + rest
    return segment


def _sanitize_characters(name: str) -> str:
    """``name`` without bidi override/isolate characters and with each NUL as ``_``."""
    if not name.isascii():
        name = "".join(c for c in name if c not in BIDI_REORDERING_CONTROLS)
    return name.replace("\x00", "_")


def _sanitize_path(name: str) -> str:
    """Every ``sanitize_names`` rewrite of a member name."""
    name = _sanitize_characters(name)
    # Only a rooted name loses its root. A drive-relative "a:b" is kept, and the
    # segment rewrite below turns its colon into "_".
    name = _collapse_dotdot(strip_absolute_root(name))
    return _map_segments(name, _sanitize_segment)


def _sanitize_symlink_target(target: str) -> str:
    """The ``sanitize_names`` rewrite of a symlink target: characters and segments only.

    The root and every ``..`` are kept, because a symlink target is a filesystem path
    relative to the link, and ``../sibling`` or ``/etc/x`` mean what they say; one that
    escapes is refused by extraction. A target that has a Windows drive or UNC root
    once its characters are cleaned gets no segment rewrite, so extraction still
    refuses it: rewriting ``C:/x`` to ``C_/x`` would make a different link rather than
    a safe spelling of the same one. Its characters are still cleaned, so a bidi
    override hidden before the drive letter does not survive the filter.
    """
    cleaned = _sanitize_characters(target)
    if _has_windows_root(cleaned):
        return cleaned
    return _map_segments(cleaned, _sanitize_segment)


def sanitize_names(member: ArchiveMember) -> ArchiveMember:
    """Rewrite a member's name so that extraction writes it instead of refusing it.

    Pass it as ``filter=`` to ``extract_all()`` (or call it from your own filter) to
    extract every member that has a safe place to go under a rewritten name, instead of
    refusing the members with an unsafe one. It changes:

    - a rooted name (``/etc/x``, ``C:\\x``, ``\\\\host\\share\\x``): the root
      is dropped, so the member lands at ``etc/x`` inside the destination. ``STANDARD``
      and ``TRUSTED`` already do this; under ``STRICT`` it happens only with this filter.
    - a ``..`` component: resolved against the segment before it (``a/../b`` → ``b``),
      and dropped when there is none (``../x`` → ``x``).
    - a bidirectional override or isolate character: removed.
    - a Windows-reserved device name (``CON``, ``NUL.txt``) or a ``:`` in a segment:
      ``_`` is added after the reserved stem (``CON_``, ``NUL_.txt``) and ``:`` becomes
      ``_``.
    - a NUL character: becomes ``_``.

    A hardlink's target is left as stored: it names a member, not a path.

    A symlink's target gets the character and segment rewrites only (``file:stream`` →
    ``file_stream``, ``sub/NUL`` → ``sub/NUL_``), so a link to a rewritten member points
    at the name that was written. Its root and its ``..`` components are kept: it is a
    path on the filesystem, and one that points outside the destination is still
    refused. A symlink target with a Windows drive or UNC root (``C:/x``,
    ``//host/share``) gets the character rewrites only, and is still refused.

    A symlink target the archive stores as member data and that is read only after
    this filter has run (``ArchiveyConfig.read_link_targets=False``, or a streaming
    pass) gets the same rewrite: ``extract_all`` calls the filter again once the
    target is read.

    Two members can end up with the same name (``a/../x`` and ``x``). The second is then
    handled by the ``overwrite`` option like any other clash. The result's
    ``member.name`` keeps the stored name and ``path`` shows where it was written.

    Returns ``member`` unchanged when nothing needed rewriting.
    """
    changes: dict[str, object] = {}
    name = _sanitize_path(member.name)
    if name != member.name:
        changes["name"] = name
    target = member.link_target
    if target is not None and member.type is MemberType.SYMLINK:
        new_target = _sanitize_symlink_target(target)
        if new_target != target:
            changes["link_target"] = new_target
    return member.replace(**changes) if changes else member


def collision_key(name: str, policy: ExtractionPolicy) -> str:
    """The per-run duplicate-detection key for a member's relative ``name`` (O2).

    ``STRICT``/``STANDARD`` fold case and Unicode normalization so ``README``/``readme`` and
    NFC/NFD ``café`` collide on every platform; ``TRUSTED`` keys on the exact name (defer to
    the local OS). Separators are normalized so ``a/b`` and ``a\\b`` share a key.

    A trailing dot or space on a segment is dropped from the key too: Win32 trims it, so
    ``foo.`` and ``foo`` are one file on Windows. ``STRICT`` has already rewritten the name;
    ``STANDARD`` keeps it, and without this the second member would silently replace the
    first on Windows and land beside it elsewhere. A segment with nothing else left keeps
    its spelling: ``.``, ``..``, and a segment of only dots and spaces, which
    ``apply_name_policy`` refuses under both policies but which reaches ``_physical_key``
    under ``TRUSTED`` (it keys as ``STANDARD``).
    """
    rel = name.replace("\\", "/").rstrip("/")
    if policy is ExtractionPolicy.TRUSTED:
        return rel
    folded = unicodedata.normalize("NFC", rel).casefold()
    if not folded.endswith((".", " ")) and "./" not in folded and " /" not in folded:
        return folded
    return "/".join(segment.rstrip(". ") or segment for segment in folded.split("/"))
