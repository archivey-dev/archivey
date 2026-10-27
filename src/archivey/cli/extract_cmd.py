"""``extract`` / ``x`` verb."""

from __future__ import annotations

import contextlib
import os
import re
import stat
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath
from typing import TextIO

from archivey import (
    AbortOn,
    ExtractionPolicy,
    ExtractionProgress,
    ExtractionReport,
    ExtractionResult,
    ExtractionStatus,
    NameRewrite,
    OnError,
    OverwritePolicy,
)
from archivey.cli.choices import from_cli_choice
from archivey.cli.common import (
    open_for_cli,
    outer_format_for,
    reject_empty_path,
)
from archivey.cli.exit_codes import EXIT_FAIL, EXIT_OK, EXIT_POLICY
from archivey.cli.filters import MemberSelection
from archivey.cli.format import escape_member_name, escape_path, format_error_detail
from archivey.cli.logging_config import member_skips_reported_elsewhere
from archivey.cli.password import resolve_password
from archivey.cli.progress import ProgressCallback, make_progress_callback
from archivey.config import ArchiveyConfig, PasswordInput
from archivey.exceptions import ArchiveyError
from archivey.paths import numbered_name
from archivey.reader import ForwardArchiveReader
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    ContainerFormat,
    MemberType,
)


def _archive_stem(path: Path, *, format: ArchiveFormat) -> str:
    """Stem used for the smart enclosing directory.

    Prefer the format's canonical extension (covers ``.tar.Z``, ``.tzst``, …); fall
    back to stripping a final suffix and a remaining ``.tar``. Never return empty,
    ``.`` or ``..``: the result becomes a destination path, so an empty stem (a file
    named exactly ``.tar.gz``) or ``.`` (``..zip``) would splatter into the cwd, and
    ``..`` (``...zip``, ``...tar.gz``) would write into the parent directory. Those
    names give ``"archive"`` instead.
    """
    name = path.name
    ext = format.file_extension()
    if ext:
        suffix = f".{ext}"
        if name.lower().endswith(suffix.lower()):
            return _safe_stem(name[: -len(suffix)])
    stem, suffix = _split_suffix(name)
    if suffix:
        stem, suffix = _split_suffix(stem)
        if suffix.lower() != ".tar":
            stem += suffix
    return _safe_stem(stem)


def _split_suffix(name: str) -> tuple[str, str]:
    """Split ``name`` into stem and final suffix, the same on every Python version.

    ``pathlib`` changed in 3.14 to skip all leading dots before looking for a suffix
    (``Path("...bin").suffix`` is ``".bin"`` up to 3.13 and ``""`` from 3.14), so it
    would name the wrapper folder differently by interpreter. This keeps the 3.11-3.13
    rule: a suffix starts at the last dot, which is not the first or last character.
    """
    i = name.rfind(".")
    if 0 < i < len(name) - 1:
        return name[:i], name[i:]
    return name, ""


def _safe_stem(stem: str) -> str:
    """``stem``, or ``"archive"`` when it is not a usable single-segment name."""
    return "archive" if stem in ("", ".", "..") else stem


def _top_level_names(members: list[ArchiveMember]) -> set[str]:
    tops: set[str] = set()
    for member in members:
        name = member.name.strip("/")
        if not name:
            continue
        tops.add(name.split("/", 1)[0])
    return tops


def _enclosing_dir(archive: Path, *, format: ArchiveFormat) -> Path:
    """The wrapper folder named after the archive: a name nothing has yet (D1).

    The CLI picks this folder on the user's behalf, so it is always one this run
    creates. Anything already at the stem name (a directory, a file, a symlink,
    dangling or live) makes the name taken under every overwrite policy, and the
    next free ``stem (N)`` is used. A user who wants to extract into an existing
    directory, or through a link, names it with ``-d``. Probes use ``lexists`` so a
    dangling link counts as present, matching :func:`_free_name`.
    """
    dest = Path(_archive_stem(archive, format=format))
    if not os.path.lexists(dest):
        return dest
    return _free_name(dest, is_dir=True)


def smart_dest(
    archive: Path,
    *,
    format: ArchiveFormat,
    members: list[ArchiveMember],
) -> Path:
    """Anti-tarbomb dest from an indexed member list (tops may already be filtered)."""
    if format.container == ContainerFormat.RAW_STREAM:
        return Path(".")
    tops = _top_level_names(members)
    if len(tops) <= 1:
        return Path(".")
    return _enclosing_dir(archive, format=format)


@dataclass(frozen=True)
class _SmartDestPlan:
    """Where to extract, and whether a post-extract single-root hoist may run."""

    target: Path
    may_hoist: bool


def resolve_smart_dest(
    reader: ForwardArchiveReader,
    archive: Path,
    *,
    pred: Callable[[ArchiveMember], bool] | None,
) -> _SmartDestPlan:
    """Choose the default dest without forcing a streaming metadata pass (D1).

    - Single-file / raw-stream → cwd.
    - Indexed archive → tops on the **filtered** member set (wrap / cwd). A single
      top whose name exists in the cwd, or that extraction may write under another
      spelling (:func:`_written_as_stored`), is extracted into a new wrapper and
      hoisted, as below, so the operator's entry is never replaced.
    - No cheap index (tar, an archive read from a pipe, …) → always a new
      ``./<stem>/``, then :func:`maybe_hoist_single_root` may lift a single
      extracted top entry to cwd.
    """
    fmt = reader.format
    if fmt.container == ContainerFormat.RAW_STREAM:
        return _SmartDestPlan(Path("."), may_hoist=False)

    indexed = reader.members_report_if_available()
    if indexed is None:
        # The wrapper is always new, so its content is all this run's.
        return _SmartDestPlan(_enclosing_dir(archive, format=fmt), may_hoist=True)

    members = [m for m in indexed if pred is None or pred(m)]
    target = smart_dest(archive, format=fmt, members=members)
    tops = _top_level_names(members)
    if target == Path(".") and any(_may_land_on_existing(top) for top in tops):
        # The single root's name is taken in the cwd, or extraction may write it under
        # another spelling that is. Extracting straight into the cwd would apply
        # ``--overwrite`` to the operator's entries there; the hoist never replaces or
        # deletes one, and judges from what is on disk, so extract into a new wrapper
        # and hoist.
        return _SmartDestPlan(_enclosing_dir(archive, format=fmt), may_hoist=True)
    return _SmartDestPlan(target, may_hoist=False)


# Characters the library's name policy does not write as stored: it escapes them as
# ``%XX``, writes ``\`` as ``/``, or refuses the member (``:``).
_REWRITTEN_CHARS = frozenset('<>:"|?*\\')


def _written_as_stored(name: str) -> bool:
    """Whether extraction surely writes the top-level ``name`` under that spelling.

    A conservative stand-in for the library's name policy, which the CLI cannot
    import: ``False`` for anything that policy may rewrite (a trailing dot or space,
    a character Windows refuses, a control or other non-printable character, a byte
    that is not UTF-8), and for some names it writes as stored too."""
    return (
        name.isprintable()
        and not name.endswith((".", " "))
        and _REWRITTEN_CHARS.isdisjoint(name)
    )


def _may_land_on_existing(name: str) -> bool:
    """Whether extracting the top-level ``name`` into the cwd may land on an entry
    already there, under its own spelling or one the name policy may write instead.

    For a name not written as stored (:func:`_written_as_stored`), each cwd entry is
    compared with the name after undoing what the policy may do to it. Both sides are
    taken as the UTF-8 bytes the policy escapes (:func:`_utf8`), the entry's ``%XX``
    escapes are turned back into the bytes they stand for (``%25`` into ``%``), a ``\\``
    ends the top level, as it is written as ``/``, and trailing dots and spaces are
    dropped from both sides. The entry is also compared as it is, for a ``%`` the policy
    left alone. An entry that matches only when case is ignored counts when the cwd
    folds case (:func:`_cwd_folds_case`). The comparison is loose on purpose: a false
    match only sends the archive through the wrapper, while a missed one lets
    ``--overwrite`` touch the operator's entry."""
    if os.path.lexists(name):
        return True
    if _written_as_stored(name):
        return False
    stem = _canonical(_utf8(name.split("\\", 1)[0])).rstrip(". ")
    try:
        entries = os.listdir(".")
    except OSError:
        return True  # the cwd could not be listed: take the safe route
    for entry in entries:
        raw = _utf8(entry)
        for spelling in {_canonical(raw), _canonical(_ESCAPE.sub(_byte, raw))}:
            spelling = spelling.rstrip(". ")
            if spelling == stem or (
                spelling.casefold() == stem.casefold() and _cwd_folds_case(entry)
            ):
                return True
    return False


_ESCAPE = re.compile(rb"%([0-9A-Fa-f]{2})")


def _byte(match: re.Match[bytes]) -> bytes:
    return bytes([int(match[1], 16)])


def _utf8(name: str) -> bytes:
    """``name`` as the UTF-8 bytes the name policy escapes: a surrogate in
    U+DC80-U+DCFF stands for the byte it was read from (``surrogateescape``), and any
    other lone surrogate is encoded as its own three bytes (``surrogatepass``)."""
    return b"".join(
        ch.encode(
            "utf-8",
            "surrogateescape" if "\udc80" <= ch <= "\udcff" else "surrogatepass",
        )
        for ch in name
    )


def _canonical(raw: bytes) -> str:
    """``raw`` read back as a name, so two spellings of the same bytes compare equal."""
    return raw.decode("utf-8", "surrogateescape")


def _cwd_folds_case(entry: str) -> bool:
    """Whether the cwd entry ``entry`` is also found under its case flipped, as on a
    case-insensitive filesystem. Errs towards ``True`` when both spellings exist."""
    flipped = entry.swapcase()
    return flipped != entry and os.path.lexists(flipped)


@dataclass
class _HoistResult:
    """Outcome of :func:`maybe_hoist_single_root` for reporting and exit code."""

    # Where the content is: the wrapper when not hoisted. Read only by
    # :func:`maybe_hoist_single_root`, for its own closing line.
    target: Path
    # Terminal-safe summary destination when the hoist decided it; ``None`` leaves it
    # to :func:`_summary_dest_label`.
    dest_label: str | None = None
    ok: bool = True  # False → collision/failure; caller exits nonzero
    renamed: int = 0
    # What the move did to each entry, so the report can name each member where it is
    # now; ``None`` when nothing moved.
    moves: _Moves | None = None


@dataclass(frozen=True)
class _Moves:
    """Where the hoist put each entry it moved out of the wrapper.

    ``names`` maps an entry's name in the wrapper (``/``-separated) to its name in the
    wrapper's parent after the move. A name that is not a key moved with its nearest
    ancestor that is. ``left_in`` names where the remainder is when the hoist stopped
    part-way: the wrapper, or the aside directory when the wrapper's name could not
    be taken back. A name under no key is still in that directory.
    """

    names: dict[str, str]
    left_in: str | None = None

    def place(self, relative: str) -> str:
        """``relative``'s name after the move."""
        parts = relative.split("/")
        for end in range(len(parts), 0, -1):
            moved = self.names.get("/".join(parts[:end]))
            if moved is not None:
                return "/".join([moved, *parts[end:]])
        if self.left_in is not None:
            return f"{self.left_in}/{relative}"
        return relative

    @classmethod
    def of(
        cls,
        moved: dict[str, Path],
        left_in: Path,
        *,
        stopped: bool = False,
    ) -> _Moves:
        """What the hoist recorded in ``moved``, named from ``left_in``'s parent.

        ``left_in`` is the directory that holds whatever did not move: the wrapper,
        or the aside directory when the wrapper's name could not be taken back. Both
        share one parent. ``stopped`` when the merge did not finish.
        """
        return cls(
            {
                name: path.relative_to(left_in.parent).as_posix()
                for name, path in moved.items()
            },
            left_in.name if stopped else None,
        )


def _step_back(side: Path, wrapper: Path) -> Path:
    """Rename ``side`` back to ``wrapper``; return where the remainder now is.

    Only while ``wrapper`` is free: under ``--overwrite rename`` the merge can give a
    member that name, and a rename onto an empty directory would replace it. When
    the rename does not happen, the remainder stays in ``side``, which is returned.
    """
    if os.path.lexists(wrapper):
        return side
    try:
        side.rename(wrapper)
    except OSError:
        return side
    return wrapper


class _HoistConflict(Exception):
    """A collision the hoist does not resolve. Only ``rename`` settles a collision."""

    def __init__(self, dest: Path) -> None:
        super().__init__(str(dest))
        self.dest = dest


def _free_name(dest: Path, *, is_dir: bool) -> Path:
    """First ``name (N)`` free on disk, spelled as extraction spells its renames."""
    n = 1
    while True:
        candidate = dest.parent / numbered_name(dest.name, n, is_dir=is_dir)
        if not os.path.lexists(candidate):
            return candidate
        n += 1


def _same_entry(a: Path, b: Path) -> bool:
    """Whether ``a`` and ``b`` name the same entry on disk, which the spelling cannot
    tell on a case-insensitive filesystem (``FILE`` and ``file``). False when either
    cannot be stat'ed, as when nothing is at it."""
    try:
        return os.path.samestat(os.lstat(a), os.lstat(b))
    except OSError:
        return False


def _off_dest(side: Path, wrapper: Path, dest: Path) -> Path:
    """Rename the aside directory ``side`` to the next ``<wrapper> (N)`` when it is the
    entry at ``dest``; return where it is.

    The root's stored name can be the aside name (``foo.tar`` holding ``foo (1)/``),
    and on a case-insensitive filesystem a different spelling (``FOO (1)/``) is the
    same entry too, so the filesystem decides, not the string. The next name was free
    while ``side`` held ``dest``, so it is never ``dest``.
    """
    if not _same_entry(side, dest):
        return side
    free = _free_name(wrapper, is_dir=True)
    side.rename(free)
    return free


def _open_up(path: Path) -> int | None:
    """Give the directory at ``path`` owner read, write and search permission for a
    move; return the mode to put back, or ``None`` when nothing was changed (it is
    not a directory, or already has them).

    Extraction applies a directory's stored mode when the run ends, so a hoisted
    directory can be ``0o555``. Moving entries out of it needs write permission on
    it, and so does moving it to another parent, because its ``..`` entry changes.
    Without this, a non-root user's hoist failed where tar would have extracted.
    """
    st = os.lstat(path)
    mode = stat.S_IMODE(st.st_mode)
    if not stat.S_ISDIR(st.st_mode) or mode & stat.S_IRWXU == stat.S_IRWXU:
        return None
    os.chmod(path, mode | stat.S_IRWXU)
    return mode


def _put_back(path: Path, mode: int | None) -> None:
    """Restore the mode :func:`_open_up` changed, at the directory's current path."""
    if mode is not None:
        with contextlib.suppress(OSError):
            os.chmod(path, mode)


def _rename(src: Path, dest: Path) -> None:
    """``os.rename``, for a directory too that lacks owner write (:func:`_open_up`).
    The directory keeps its mode."""
    mode = _open_up(src)
    try:
        os.rename(src, dest)
    except BaseException:
        _put_back(src, mode)
        raise
    _put_back(dest, mode)


def _merge_move(
    src: Path,
    dest: Path,
    overwrite: OverwritePolicy,
    result: _HoistResult,
    err: TextIO,
    name: str,
    moved: dict[str, Path],
) -> Path:
    """Move ``src`` to ``dest``, merging directories into existing directories. A
    file or symlink collision is resolved only under RENAME, which moves ours to a
    free name, as extracting directly into ``dest``'s parent does. The hoist neither
    replaces the operator's entry nor throws away ours, so every other policy
    resolves nothing (:func:`_policy_resolves`). Symlinks are moved as links and
    never descended into (on either side). A collision the policy cannot resolve
    raises :class:`_HoistConflict`; the caller checks the whole merge with
    :func:`_first_clash` before calling this, so that happens only when the cwd
    changed in between.

    ``name`` is ``src``'s name in the wrapper. Each entry moved or merged is recorded
    in ``moved`` under its name in the wrapper, with the path it took. A merged
    directory is recorded once all of it has moved, so a name under one the merge
    stopped in is still in the wrapper.

    Returns where ``src`` landed: ``dest``, or the free name a rename chose."""
    if not os.path.lexists(dest):
        _rename(src, dest)
        moved[name] = dest
        return dest
    src_is_dir = src.is_dir() and not src.is_symlink()
    dest_is_dir = dest.is_dir() and not dest.is_symlink()
    if src_is_dir and dest_is_dir:
        # ``dest`` keeps its own mode, as a directory that was already there does
        # when extracting into it, and the line is the one extraction prints then.
        # ``src`` holds the archive's mode as extraction applied it, which is the
        # mode the library compares for ``-d .``: the member's, as the platform
        # stores it (on Windows only the read-only attribute, ``0o777`` or
        # ``0o555``; see ``_dir_mode_as_stored``).
        kept = stat.S_IMODE(os.stat(dest).st_mode)
        if kept != stat.S_IMODE(os.lstat(src).st_mode):
            print(
                f"kept existing directory's mode {kept:04o}: {escape_path(dest)}",
                file=err,
            )
        # ``src`` is opened up only to empty it.
        mode = _open_up(src)
        try:
            for entry in sorted(src.iterdir()):
                _merge_move(
                    entry,
                    dest / entry.name,
                    overwrite,
                    result,
                    err,
                    f"{name}/{entry.name}",
                    moved,
                )
            moved[name] = dest
            src.rmdir()
        except BaseException:
            _put_back(src, mode)
            raise
        return dest
    if not _policy_resolves(overwrite):
        # The hoist checked the whole merge first (:func:`_first_clash`), so this is
        # reached only when the cwd changed after that check. Stop; the caller keeps
        # the remainder under the wrapper and exits nonzero.
        raise _HoistConflict(dest)
    free = _free_name(dest, is_dir=src_is_dir)
    _rename(src, free)
    moved[name] = free
    result.renamed += 1
    print(
        f"renamed: {escape_path(dest)} -> {escape_path(free)}",
        file=err,
    )
    return free


def _policy_resolves(overwrite: OverwritePolicy) -> bool:
    """Whether :func:`_merge_move` resolves a collision: only ``rename`` does, by
    moving ours to a free name. ``replace`` and ``skip`` would replace the operator's
    entry or throw ours away, and the hoist, which the operator did not ask for, does
    neither: the content stays in the wrapper instead. Two directories merge, so they
    are no collision and are not asked about here."""
    return overwrite is OverwritePolicy.RENAME


def _first_clash(
    relative: str,
    src_is_dir: bool,
    dest: Path,
    overwrite: OverwritePolicy,
    listing: Callable[[str], list[tuple[str, bool]]],
) -> Path | None:
    """The first path where merging the entry at ``relative`` into ``dest`` would meet
    a collision ``overwrite`` cannot resolve (:func:`_policy_resolves`), or ``None``.

    The same walk as :func:`_merge_move`, without moving anything: directories merge,
    so only their contents can clash. ``listing`` gives the entries of the directory
    at a ``/``-separated path in the wrapper, as (name, is a directory and not a
    symlink), sorted as the merge visits them."""
    if not os.path.lexists(dest):
        return None
    dest_is_dir = dest.is_dir() and not dest.is_symlink()
    if src_is_dir and dest_is_dir:
        for name, is_dir in listing(relative):
            clash = _first_clash(
                f"{relative}/{name}", is_dir, dest / name, overwrite, listing
            )
            if clash is not None:
                return clash
        return None
    # So under ``rename`` this walk never finds a clash. It still runs: listing the
    # tree first makes an unlistable directory fail the hoist with nothing moved,
    # rather than part-way through the merge.
    if _policy_resolves(overwrite):
        return None
    return dest


def _disk_listing(wrapper: Path) -> Callable[[str], list[tuple[str, bool]]]:
    """:func:`_first_clash`'s ``listing`` for the tree extracted into ``wrapper``.

    A directory extracted without owner read or search permission is opened up to be
    listed and then given its mode back, as the merge opens it up to empty it."""

    def listing(relative: str) -> list[tuple[str, bool]]:
        path = wrapper / relative
        mode = _open_up(path)
        try:
            return [
                (entry.name, entry.is_dir() and not entry.is_symlink())
                for entry in sorted(path.iterdir())
            ]
        finally:
            _put_back(path, mode)

    return listing


def _recorded_listing(
    entries: tuple[tuple[str, bool], ...],
) -> Callable[[str], list[tuple[str, bool]]]:
    """:func:`_first_clash`'s ``listing`` for a dry run, from the entries its scratch
    tree held (``ExtractionReport._dry_run_entries``)."""
    children: dict[str, list[tuple[str, bool]]] = {}
    for path, is_dir in entries:
        parent, _, name = path.rpartition("/")
        children.setdefault(parent, []).append((name, is_dir))
    for listed in children.values():
        listed.sort()
    return lambda relative: children.get(relative, [])


_MAX_LINK_HOPS = 40  # the Linux ``MAXSYMLINKS``


def _is_absolute_target(target: str) -> bool:
    """Whether a symlink target is absolute, on either separator (a drive letter
    counts)."""
    return target[:1] in ("/", "\\") or target[1:2] == ":"


def _readlink_on_disk(path: PurePath) -> str | None:
    """``path``'s target when it is a symlink on disk, else ``None``."""
    return os.readlink(path) if Path(path).is_symlink() else None


def _walk_stays_inside(
    start: PurePath,
    target: str,
    root: PurePath,
    hops: list[int],
    readlink: Callable[[PurePath], str | None] = _readlink_on_disk,
) -> PurePath | None:
    """Follow ``target`` from the directory ``start`` one component at a time, through
    any symlink on the way, and return where it ends; ``None`` when a step leaves
    ``root`` or reaches ``root``'s parent. ``hops`` is the symlink budget left, shared
    by the nested walks. ``readlink`` says whether a path is a symlink and where it
    points: the disk by default, a dry run's record of its scratch tree otherwise."""
    if _is_absolute_target(target):
        return None
    current = start
    for part in target.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if current == root:
                return None
            current = current.parent
            continue
        step = current / part
        try:
            inner = readlink(step)
        except OSError:
            return None
        if inner is not None:
            hops[0] -= 1
            if hops[0] < 0:
                return None
            landed = _walk_stays_inside(current, inner, root, hops, readlink)
            if landed is None:
                return None
            current = landed
        else:
            current = step
    return current


def _disk_links(root: Path) -> Iterator[tuple[PurePath, str]]:
    """Each symlink under ``root`` with its target, listed from disk as it is read."""
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_symlink():
                    yield Path(entry.path), os.readlink(entry.path)
                elif entry.is_dir():
                    pending.append(Path(entry.path))


def _links_stay_inside(
    root: PurePath,
    links: Iterable[tuple[PurePath, str]],
    readlink: Callable[[PurePath], str | None] = _readlink_on_disk,
) -> bool:
    """Whether every symlink under ``root`` reaches its target without leaving ``root``.

    The hoist moves ``root`` one level up after extraction checked its links against
    the wrapper. A link whose path stays inside ``root`` at every step means the same
    thing after the move, because the whole tree moves together. A step above ``root``
    is where the move changes the meaning: ``wrapper/top/k ->
    ../../.ssh/authorized_keys`` stays inside the wrapper when the archive is named
    ``.ssh.tar``, and names the operator's own ``.ssh`` once ``top`` is moved up. Even
    one step up into the wrapper and back down can land on a name the working directory
    has and the wrapper did not, so that blocks too.

    The walk follows each symlink on the way, so a chain cannot hide a climb, and an
    absolute target always blocks. A path that ends at nothing is walked by name. A
    directory that cannot be listed blocks too: what is under it was not checked.

    ``links`` is every symlink under ``root`` with its target, and ``readlink`` answers
    each step from the same source. An ``OSError`` raised while ``links`` is listed
    blocks: so a disk listing must be passed unconsumed, not as a list built first.
    """
    try:
        return all(
            _walk_stays_inside(path.parent, target, root, [_MAX_LINK_HOPS], readlink)
            is not None
            for path, target in links
        )
    except OSError:
        # A directory the walk cannot list could hold anything: keep the tree
        # where it is rather than move what was not looked at.
        return False


def _disk_links_stay_inside(root: Path) -> bool:
    """:func:`_links_stay_inside` for a tree on disk, listed and read as it is walked."""
    return _links_stay_inside(root, _disk_links(root))


def _recorded_links_stay_inside(top: str, links: tuple[tuple[str, str], ...]) -> bool:
    """:func:`_links_stay_inside` for a dry run, over the symlinks its scratch tree
    held (``ExtractionReport._dry_run_links``) rather than a tree on disk: the same
    walk, with a path a symlink exactly when the record lists it."""
    targets: dict[PurePath, str] = {
        PurePosixPath(name): target for name, target in links
    }
    root = PurePosixPath(top)
    under = ((path, t) for path, t in targets.items() if root in path.parents)
    return _links_stay_inside(root, under, targets.get)


def _keep_reason(is_symlink: bool, links_leave: Callable[[], bool]) -> str | None:
    """Why the hoist leaves the wrapper's single entry in place, or ``None`` to move it.

    ``links_leave`` says whether a symlink in the entry may leave it on the way to its
    target, which includes a tree that could not be fully walked
    (:func:`_links_stay_inside`); it runs only when nothing earlier settled it.
    """
    if is_symlink:
        # A link's relative target is read from its own directory, which the move
        # changes from the wrapper to the working directory: `b -> passwd` would then
        # name the operator's own `passwd`, and `b -> ../etc/passwd` one outside it.
        return "its only entry is a symlink, which the move would repoint"
    if links_leave():
        return (
            "it may hold a symlink that points outside it, which a move would repoint"
        )
    return None


def maybe_hoist_single_root(
    wrapper: Path,
    *,
    overwrite: OverwritePolicy,
    err: TextIO,
) -> _HoistResult:
    """If ``wrapper`` holds exactly one top-level entry, lift it to cwd (R4/D1).

    The entry stays in the wrapper, and a line says why, for the reasons
    :func:`_keep_reason` gives.

    Recovers unar-style single-root reuse (and filter-aware D1 for streaming) after an
    always-wrap extract, without a pre-extract metadata pass. Directories merge into
    existing ones, and under ``rename`` the final layout matches extracting directly
    into the wrapper's parent (:func:`_merge_move`). The hoist is a convenience, not a
    promise: it never replaces or deletes anything in the cwd, so when the merge would
    meet a collision that ``rename`` does not settle (any collision under ``error``,
    ``skip`` or ``replace``, :func:`_policy_resolves`), nothing is moved, a ``kept in``
    line names the first such path, and the run still succeeds with the content in the
    wrapper. A destination that is the wrapper itself (``FILE`` in ``file/`` on a
    case-insensitive filesystem) is not a collision, because the wrapper moves aside
    before the merge. When the sole root shares the wrapper's own name, spelled the same
    (``src.tar.gz`` containing ``src/``), the child is flattened in place — the wrapper
    *becomes* the root, so no collision logic applies to it. A root whose name differs
    only in case is merged like any other.
    """
    if wrapper == Path(".") or wrapper.is_symlink() or not wrapper.is_dir():
        return _HoistResult(wrapper)
    try:
        children = list(wrapper.iterdir())
    except OSError:
        return _HoistResult(wrapper)
    if len(children) != 1:
        return _HoistResult(wrapper)
    child = children[0]
    reason = _keep_reason(
        child.is_symlink(),
        lambda: child.is_dir() and not _disk_links_stay_inside(child),
    )
    dest = wrapper.parent / child.name
    # The sole root shares the wrapper's name, spelled the same, so the wrapper is
    # removed and the root takes its place under that name; otherwise the root is
    # merged into the cwd. Strings, not paths: Windows paths compare equal across
    # case, and a root spelled ``PLAIN`` in ``plain/`` must land at ``./PLAIN``.
    in_place = dest.name == wrapper.name
    # On a case-insensitive filesystem a root spelled ``FILE`` in ``file/`` has the
    # wrapper itself at ``dest``. That is not the operator's data: the wrapper moves
    # aside before the merge, so the check skips it, as the dry run does.
    if reason is None and not in_place and not _same_entry(dest, wrapper):
        try:
            clash = _first_clash(
                child.name,
                child.is_dir() and not child.is_symlink(),
                dest,
                overwrite,
                _disk_listing(wrapper),
            )
        except OSError as exc:
            # The ``archivey: `` prefix: see main._parse_and_dispatch.
            print(f"archivey: hoist failed: {format_error_detail(exc)}", file=err)
            print(f"files left in {escape_path(wrapper)}/", file=err)
            return _HoistResult(wrapper, ok=False)
        if clash is not None:
            reason = f"{escape_path(clash)} already exists"
    if reason is not None:
        print(f"kept in {escape_path(wrapper)}/: {reason}", file=err)
        return _HoistResult(wrapper)
    result = _HoistResult(dest)
    moved: dict[str, Path] = {}
    # Where the remainder is when the hoist stops: the wrapper, unless restoring it
    # failed and the remainder stayed in the aside directory.
    left_in = wrapper
    try:
        if in_place:
            if child.is_dir() and not child.is_symlink():
                # Flatten: wrapper/src/* → wrapper/*. The wrapper held only this
                # child, so the moves cannot collide. The wrapper takes the child's
                # place, so it takes the child's mode and times too.
                st = os.stat(child)
                mode = _open_up(child)
                try:
                    for entry in sorted(child.iterdir()):
                        up = wrapper / entry.name
                        _rename(entry, up)
                        # Recorded for a failure part-way: an entry already moved is
                        # named where it is, and ``left_in`` covers only the rest.
                        moved[f"{child.name}/{entry.name}"] = up
                    child.rmdir()
                except BaseException:
                    _put_back(child, mode)
                    raise
                with contextlib.suppress(OSError):  # best-effort, as in extraction
                    os.chmod(wrapper, stat.S_IMODE(st.st_mode))
                    os.utime(wrapper, ns=(st.st_atime_ns, st.st_mtime_ns))
            else:
                # Sole non-dir entry named like the wrapper: step the wrapper
                # aside so the entry can take its place.
                side = _free_name(wrapper, is_dir=True)
                wrapper.rename(side)
                try:
                    (side / child.name).rename(dest)
                    try:
                        side.rmdir()
                    except BaseException:
                        # The entry holds the wrapper's name now; it goes back inside
                        # ``side`` first, so ``side`` can take that name again below.
                        try:
                            dest.rename(side / child.name)
                        except OSError:
                            # It stays at its final name: report it there.
                            moved[child.name] = dest
                        raise
                except BaseException:
                    # Leave the entry where the messages say it is: in the wrapper.
                    left_in = _step_back(side, wrapper)
                    raise
        else:
            # The wrapper took the first free name for the archive's stem, which can
            # be the free name a rename of the root would take (``foo`` exists, so
            # ``foo.tar`` extracts into ``foo (1)`` and its root ``foo`` must be
            # renamed). Step it aside so the merge sees the cwd a direct extraction
            # sees. The aside name is ``<wrapper> (N)``, which no rename of the root
            # spells, as the root's name differs from the wrapper's here. The root's
            # stored name can still be that name, and the merge would then move the
            # root into the wrapper itself, so :func:`_off_dest` moves it on.
            side = _free_name(wrapper, is_dir=True)
            wrapper.rename(side)
            try:
                side = _off_dest(side, wrapper, dest)
                landed = _merge_move(
                    side / child.name, dest, overwrite, result, err, child.name, moved
                )
                side.rmdir()
            except BaseException:
                # Leave the remainder where the messages say it is.
                left_in = _step_back(side, wrapper)
                raise
            result.moves = _Moves.of(moved, wrapper)
            result.target = landed
    except _HoistConflict as conflict:
        print(
            f"Destination already exists: {escape_path(conflict.dest)}",
            file=err,
        )
        print(
            f"hoist stopped; remaining files left in {escape_path(left_in)}/",
            file=err,
        )
        return _HoistResult(
            left_in,
            ok=False,
            renamed=result.renamed,
            moves=_Moves.of(moved, left_in, stopped=True),
        )
    except OSError as exc:
        # The ``archivey: `` prefix: see main._parse_and_dispatch.
        print(f"archivey: hoist failed: {format_error_detail(exc)}", file=err)
        print(f"files left in {escape_path(left_in)}/", file=err)
        return _HoistResult(
            left_in,
            ok=False,
            renamed=result.renamed,
            moves=_Moves.of(moved, left_in, stopped=True),
        )
    if result.moves is None:
        result.moves = _Moves({child.name: child.name})  # in place: name unchanged
    is_dir = result.target.is_dir() and not result.target.is_symlink()
    # The target is the sole root's own name, which the archive chose.
    label = f"{escape_path(result.target)}{'/' if is_dir else ''}"
    result.dest_label = label
    if in_place:
        # src.tar → src/ containing src/: the wrapper is gone, the name unchanged.
        print(f"removed wrapper; content at {label}", file=err)
    else:
        print(f"moved to {label}", file=err)
    return result


def predict_hoist(
    wrapper: Path,
    report: ExtractionReport,
    *,
    overwrite: OverwritePolicy,
    err: TextIO,
) -> _HoistResult:
    """What :func:`maybe_hoist_single_root` would do after a real run, for a dry run.

    A dry run writes nothing, so there is no wrapper to look into. Its scratch tree is
    the next best thing: the run created the same directories, links and (empty) files
    there, and the report carries the entries it left at the top. A single entry is
    lifted to the wrapper's parent under its own name, as the hoist lifts it. Where that
    name exists already, the hoist would merge into it: the collisions the overwrite
    policy resolves are not listed, but one it cannot resolve keeps the entry in the
    wrapper, as it does in the hoist (:func:`_first_clash`, over the entries the scratch
    tree held). The entry also stays in the wrapper for the hoist's other reasons, judged
    from the symlinks the scratch tree held, and a line says why.
    """
    tops = _dry_run_top_level(report)
    if len(tops) != 1:
        return _HoistResult(wrapper)
    ((name, is_dir),) = tops
    links = report._dry_run_links
    # ``links`` is ``None`` when part of the scratch tree could not be read, and the
    # hoist keeps a tree it cannot fully walk.
    reason = _keep_reason(
        links is not None and any(path == name for path, _ in links),
        lambda: (
            links is None or (is_dir and not _recorded_links_stay_inside(name, links))
        ),
    )
    dest = wrapper.parent / name
    in_place = name == wrapper.name  # by spelling, as in the hoist
    entries = report._dry_run_entries
    # ``lexists`` first: with nothing at ``dest`` there is no merge, so the entries
    # are not indexed.
    if (
        reason is None
        and not in_place
        and entries is not None
        and os.path.lexists(dest)
    ):
        try:
            clash = _first_clash(
                name, is_dir, dest, overwrite, _recorded_listing(entries)
            )
        except OSError:
            clash = None  # the real run's check meets the same error and says so
        if clash is not None:
            reason = f"{escape_path(clash)} already exists"
    if reason is not None:
        print(f"would keep in {escape_path(wrapper)}/: {reason}", file=err)
        return _HoistResult(wrapper)
    if (
        not in_place
        and os.path.lexists(dest)
        and not (is_dir and dest.is_dir() and not dest.is_symlink())
    ):
        # Not a merge: the check above let it through, so ``rename`` moves the root
        # to the first free name, as the real hoist's ``_merge_move`` does. That
        # rename is a collision the policy resolves, so it gets no line of its own.
        dest = _free_name(dest, is_dir=is_dir)
    label = f"{escape_path(dest)}{'/' if is_dir else ''}"
    if in_place:
        print(f"would remove wrapper; content at {label}", file=err)
    elif os.path.lexists(dest):
        print(
            f"would move to {label}, which exists already: "
            "collisions with its contents follow --overwrite",
            file=err,
        )
    else:
        print(f"would move to {label}", file=err)
    # ``dest`` is where the root lands, a rename's free name included, as the real
    # hoist records it.
    return _HoistResult(dest, dest_label=label, moves=_Moves({name: dest.name}))


def _summary_dest_label(
    target: Path, report: ExtractionReport, *, dry_run: bool = False
) -> str:
    """Closing summary destination; prefer the single extracted top when dest is cwd.

    The single top is the name the run wrote, which a rename can move off the member's
    own name: naming the member's would point at the operator's file. Returned
    terminal-safe: the top, the operator's ``-d`` and a wrapper named after the archive
    file can all carry control bytes, and this is the last line the operator reads.

    A dry run wrote nothing to look at, so it answers from what its scratch tree held,
    which is what a real run's extracted results hold: the target is a directory the
    run would create, and the single top's kind is the one the scratch tree gave it."""
    if target != Path("."):
        if dry_run or target.is_dir():
            return f"{escape_path(target)}/"
        return escape_path(target)
    if dry_run:
        tops = dict(_dry_run_top_level(report))
    else:
        written = (
            _relative_name(r.path, target) or r.member.name.strip("/")
            for r in report
            if r.status is ExtractionStatus.EXTRACTED
        )
        # The kind is read from disk below, once there is a single top.
        tops = dict.fromkeys({name.split("/", 1)[0] for name in written} - {""}, False)
    if len(tops) != 1:
        return "."
    ((only, is_dir),) = tops.items()
    if not dry_run:
        on_disk = Path(only)
        is_dir = on_disk.is_dir() and not on_disk.is_symlink()
    return f"{escape_member_name(only)}/" if is_dir else escape_member_name(only)


def _dry_run_top_level(report: ExtractionReport) -> tuple[tuple[str, bool], ...]:
    """A dry run's top-level entries, from the report's private field.

    The one place the CLI reads a private library name; the ``cli`` spec's public-API
    requirement records it as an exception. A dry run writes nothing, so nothing else
    can say what a real run would leave at the top of ``dest``."""
    return report._dry_run_top_level or ()


def _follows_renamed_dir(
    requested: Path, path: Path, renamed_dirs: dict[Path, Path]
) -> bool:
    """Whether ``requested`` -> ``path`` only moved with its nearest renamed ancestor
    directory: the same tail under that directory's written name."""
    for ancestor in requested.parents:
        renamed_to = renamed_dirs.get(ancestor)
        if renamed_to is not None:
            return path == renamed_to / requested.relative_to(ancestor)
    return False


def _implied_dir_rename(requested: Path, path: Path) -> tuple[Path, Path] | None:
    """The directory rename that ``requested`` -> ``path`` only followed, or ``None``:
    the one ancestor whose name differs, with the same tail below it.

    A parent the archive implies but does not store has no result of its own, so
    when the library renames it (``foo/x`` -> ``foo (1)/x``) only its members show
    the rename."""
    if len(requested.parts) != len(path.parts):
        return None
    for i, (asked, written) in enumerate(zip(requested.parts, path.parts)):
        if asked != written:
            if i == len(requested.parts) - 1:
                return None  # the member's own name: its own rename
            if requested.parts[i + 1 :] != path.parts[i + 1 :]:
                return None
            return Path(*requested.parts[: i + 1]), Path(*path.parts[: i + 1])
    return None


def _report_extraction(
    report: ExtractionReport,
    *,
    target: Path,
    verbose: bool,
    err: TextIO,
    extra_renamed: int = 0,
    dest_label: str | None = None,
    moves: _Moves | None = None,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Print rename notices + a closing summary from the library report (F3/D2).

    Per-member paths are named relative to ``target``, the directory extracted into.
    ``moves`` is what the hoist did to the entries it moved out of ``target``
    (:class:`_Moves`): a path under one is named where the move put it, relative to
    ``target``'s parent.

    ``extra_renamed`` folds in collisions the post-extract hoist renamed (the library
    report covers only the wrapper extraction, which is collision-free by
    construction). ``dest_label`` is the hoist's own
    account of where the content landed, which the report — written before the hoist
    moved anything — cannot know.

    Under ``dry_run`` the per-member lines are the same, since they say what the
    extraction decided, and the summary says that nothing was written. Its destination
    is the target as named: the disk cannot say more, because nothing landed there.

    Returns ``(blocked_count, failed_count)`` for exit-code selection (Q1).
    """
    extracted = 0
    renamed = extra_renamed
    skipped = 0
    blocked = 0
    failed = 0
    rerooted = 0
    # Every directory rename in the run: requested path -> written path. A member
    # inside a renamed directory follows it (``dd/f`` -> ``dd (1)/f``) and so also
    # reports ``requested_path != path``; that is the directory's one rename, not a new
    # one. Collected before the walk, as the result that carries the rename is not
    # always first: with the directory stored twice, it is the later copy, after the
    # members written between the two.
    renamed_dirs = {
        r.requested_path: r.path
        for r in report.results
        if r.member.type is MemberType.DIRECTORY
        and r.requested_path is not None
        and r.path is not None
        and r.requested_path != r.path
    }
    # A renamed directory the archive only implies has no result: take its rename
    # from the members that followed it, and print it once, at the first of them.
    implied_dirs: dict[Path, Path] = {}
    for r in report.results:
        if (
            r.status is ExtractionStatus.EXTRACTED
            and r.requested_path is not None
            and r.path is not None
            and not r.member.is_anti
            and not _follows_renamed_dir(r.requested_path, r.path, renamed_dirs)
        ):
            implied = _implied_dir_rename(r.requested_path, r.path)
            if implied is not None:
                asked, written = implied
                implied_dirs.setdefault(asked, written)
    renamed_dirs.update(implied_dirs)

    def shown(path: Path | None) -> str:
        """``path`` as the line names it."""
        return escape_member_name(_relative_name(path, target, moves))

    for result in report:
        status = result.status
        if status is ExtractionStatus.EXTRACTED:
            extracted += 1
            was_renamed = (
                result.requested_path is not None
                and result.path is not None
                and result.requested_path != result.path
                # An anti-item deletes; where it deleted is not a rename.
                and not result.member.is_anti
                and not _follows_renamed_dir(
                    result.requested_path, result.path, renamed_dirs
                )
            )
            if (
                result.requested_path is not None
                and implied_dirs
                and not result.member.is_anti
            ):
                for ancestor in result.requested_path.parents:
                    if ancestor in renamed_dirs:
                        renamed_to = implied_dirs.pop(ancestor, None)
                        if renamed_to is not None:
                            renamed += 1
                            print(
                                f"renamed: {shown(ancestor)} -> {shown(renamed_to)}",
                                file=err,
                            )
                        break
            landed = shown(result.path)
            if was_renamed:
                renamed += 1
                # Renames change where data lives — always report them.
                print(
                    f"renamed: {shown(result.requested_path)} -> {landed}",
                    file=err,
                )
            elif verbose and not _hoist_renamed(result.path, target, moves):
                # A member the hoist renamed has the hoist's ``renamed:`` line instead,
                # as a member that extraction renamed has its own.
                print(
                    f"extracted: {escape_member_name(result.member.name)}",
                    file=err,
                )
            if result.kept_mode is not None:
                # The directory was already there: it kept its own mode, not the
                # archive's. Reported because the tree differs from the archive.
                print(
                    f"kept existing directory's mode {result.kept_mode:04o}: "
                    f"{landed or '.'}",
                    file=err,
                )
            # A portable rewrite is a different event from a collision rename: the member
            # landed where it asked to, under a different spelling. Always reported, for
            # the same reason as a rename — the on-disk name is not the archive's.
            # A re-root is the exception: a ``tar -P`` backup re-roots every member, so
            # re-roots are counted and reported once, as GNU tar does, and listed per
            # member only under --verbose. A portable rewrite on top of a re-root goes
            # with it: the result carries one ``presented_name`` for both, so the
            # verbose line shows both under the re-root's label.
            if result.presented_name is not None:
                rerooted_name = NameRewrite.REROOTED in result.rewrites
                if rerooted_name:
                    rerooted += 1
                if not rerooted_name or verbose:
                    # ``presented_name`` is the full relative name, so the arrow's other
                    # side must be too: a basename would print ``dir/foo. -> foo`` and
                    # invent a destination the member never had.
                    label = "re-rooted" if rerooted_name else "name rewritten"
                    print(
                        f"{label}: {escape_member_name(result.presented_name)} -> "
                        f"{landed}",
                        file=err,
                    )
        elif status is ExtractionStatus.OVERWRITTEN:
            # Written, then clobbered by a later member. Not counted as extracted: its
            # content is not what is on disk. Always reported — data was lost.
            skipped += 1
            where = _escaped_where(result, target, moves)
            print(f"overwritten: {where}", file=err)
        elif status is ExtractionStatus.NOT_OVERWRITTEN:
            skipped += 1
            # Overwrite-skips change outcomes under --overwrite skip; always note.
            where = _escaped_where(result, target, moves)
            print(f"not overwritten: {where}", file=err)
        elif status is ExtractionStatus.LINK_TARGET_UNAVAILABLE:
            skipped += 1
            # The archive described a link it never recorded a target for, so there was
            # nothing to write. Always reported: the tree the user gets is missing an
            # entry the listing showed them.
            where = _escaped_where(result, target, moves)
            print(f"link target unavailable: {where}", file=err)
        elif status is ExtractionStatus.SUPERSEDED:
            skipped += 1  # count superseded entries alongside skipped in summary
            if verbose:
                print(
                    f"superseded: {escape_member_name(result.member.name)}",
                    file=err,
                )
        elif status is ExtractionStatus.BLOCKED:
            blocked += 1
            detail = (
                f": {format_error_detail(result.error)}"
                if result.error is not None
                else ""
            )
            print(
                f"blocked: {escape_member_name(result.member.name)}{detail}",
                file=err,
            )
        elif status is ExtractionStatus.FAILED:
            failed += 1
            detail = (
                f": {format_error_detail(result.error)}"
                if result.error is not None
                else ""
            )
            print(
                f"failed: {escape_member_name(result.member.name)}{detail}",
                file=err,
            )

    if rerooted:
        print(
            f"re-rooted {rerooted} absolute member name{'s' if rerooted != 1 else ''}"
            " inside the destination",
            file=err,
        )
    if dry_run:
        # Only a dry run: its product is the report, so how close the archive came to
        # the limits is what the caller ran it for. Before the summary, which stays last.
        usage = _usage_line(report)
        if usage is not None:
            print(usage, file=err)
    if dest_label is None:
        dest_label = _summary_dest_label(target, report, dry_run=dry_run)
    print(
        f"{'dry run, nothing written: ' if dry_run else ''}"
        f"{extracted} extracted, {renamed} renamed, {skipped} skipped"
        f"{f', {blocked} blocked' if blocked else ''}"
        f"{f', {failed} failed' if failed else ''}"
        f" → {dest_label}",
        file=err,
    )
    return blocked, failed


def _usage_line(report: ExtractionReport) -> str | None:
    """A dry run's closing account of how close the archive came to the reader limits.

    Read from the report's private resource-usage record, which exists to tune the
    limits: the largest decoder allocation archivey checked (xz, LZMA Alone and zstd
    leave theirs to their library), the key-derivation rounds' total, the spool peak and
    the last listing walk's totals. Each part appears only when it is not zero, and with
    no part there is no line; byte counts are exact, to compare with the limit fields.
    """
    usage = report._resource_usage
    if usage is None:
        return None
    parts: list[str] = []
    if usage.decoder_memory:
        what = escape_member_name(usage.decoder_memory_what)
        parts.append(f"decoder memory {usage.decoder_memory} bytes ({what})")
    if usage.key_derivation_rounds:
        parts.append(f"{usage.key_derivation_rounds} key-derivation rounds")
    if usage.spool_bytes:
        parts.append(f"spool {usage.spool_bytes} bytes")
    if usage.listed_members or usage.listing_metadata_bytes:
        members = usage.listed_members
        parts.append(
            f"listing {members} member{'s' if members != 1 else ''}, "
            f"{usage.listing_metadata_bytes} metadata bytes"
        )
    if not parts:
        return None
    return "peak use of the reader limits: " + "; ".join(parts)


def _escaped_where(result: ExtractionResult, target: Path, moves: _Moves | None) -> str:
    """The destination to report for a member that did not keep it, terminal-safe.

    ``requested_path`` is built from the member's own name. STRICT and STANDARD write the
    controls 0x01-0x1F as ``%XX``, but other non-printable characters (DEL, the C1
    controls, U+2028) pass through, and TRUSTED writes every name as stored. Printing it
    raw is the line-spoofing vector ``escape_member_name`` exists to close, so both the
    path and the name fallback go through it.

    Rendered relative to the extraction root first, matching ``name rewritten:``. That is
    not only for brevity: ``escape_member_name`` escapes backslashes, so handing it a
    native Windows path would double every separator (``C:\\Users\\...``). The relative
    name is ``/``-separated, so a backslash surviving into it is a real character in a
    member name — which is exactly what should be escaped."""
    if result.requested_path is not None:
        return escape_member_name(_relative_name(result.requested_path, target, moves))
    return escape_member_name(result.member.name)


def _relative_name(
    path: PurePath | None,
    target: PurePath,
    moves: _Moves | None = None,
) -> str:
    """The on-disk name relative to the extraction root, for reporting.

    With ``moves``, a name the hoist moved out of ``target`` is given where the move
    put it, relative to ``target``'s parent (:meth:`_Moves.place`). Falls back to the full path,
    still ``/``-separated, when the member landed outside ``target``, and to ``""`` when
    nothing was written."""
    if path is None:
        return ""
    try:
        relative = path.relative_to(target).as_posix()
    except ValueError:
        return path.as_posix()
    if moves is not None:
        return moves.place(relative)
    return relative


def _in_target(path: PurePath | None, target: PurePath) -> str | None:
    """``path`` relative to ``target``, ``/``-separated; ``None`` when nothing was
    written or the entry is not under ``target``, so no hoist moved it."""
    if path is None:
        return None
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return None


def _hoist_renamed(
    path: PurePath | None, target: PurePath, moves: _Moves | None
) -> bool:
    """Whether the hoist moved the entry at ``path`` itself to a new name. An entry
    inside a renamed directory only follows it, as in :func:`_follows_renamed_dir`.
    ``False`` when no hoist ran (``moves`` is ``None``) or nothing was written."""
    relative = _in_target(path, target)
    if relative is None or moves is None:
        return False
    return moves.names.get(relative, relative) != relative


def _missing_dirs(target: Path) -> list[Path]:
    """``target`` and those of its parents that do not exist yet, deepest first."""
    missing: list[Path] = []
    path = target
    while not os.path.lexists(path) and path != path.parent:
        missing.append(path)
        path = path.parent
    return missing


def _remove_empty_dirs(paths: list[Path]) -> None:
    """Remove each directory in ``paths``, deepest first, while it is empty."""
    for path in paths:
        try:
            path.rmdir()
        except OSError:
            return


def _exit_for_outcomes(*, blocked: int, failed: int, hoist_ok: bool) -> int:
    """Map extract outcomes to exit codes (Q8 Option A): FAILED→1, policy-only BLOCKED→3."""
    if not hoist_ok or failed:
        return EXIT_FAIL
    if blocked:
        return EXIT_POLICY
    return EXIT_OK


def run_extract(
    *,
    archive: str,
    dest: str | None,
    patterns: list[str],
    exclude: list[str],
    policy: str,
    overwrite: str,
    password: str | None,
    track_io: bool,
    config: ArchiveyConfig | None = None,
    hide_progress: bool,
    verbose: bool,
    stop_on_error: bool = False,
    abort_on: list[str] | None = None,
    dry_run: bool = False,
    outer: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    del out  # extract reports to stderr; files go to the filesystem
    # On the strings, before Path() turns "" into ".". The stdin token "-" is
    # refused by open_for_cli below.
    reject_empty_path(archive, arg="archive")
    if dest is not None:
        reject_empty_path(dest, arg="--dest")
    err = err if err is not None else sys.stderr
    pwd: PasswordInput = resolve_password(password)
    selection = MemberSelection(patterns, exclude)
    pred = selection.predicate
    policy_enum = from_cli_choice(ExtractionPolicy, policy)
    overwrite_enum = from_cli_choice(OverwritePolicy, overwrite)
    on_error = OnError.STOP if stop_on_error else OnError.CONTINUE
    abort_on_enum = frozenset(from_cli_choice(AbortOn, item) for item in abort_on or ())
    archive_path = Path(archive)
    # --outer opens the compression layer as a one-file archive: its member is the
    # tar of a .tar.gz, so the extraction writes that file, as gunzip -k would.
    fmt = (
        outer_format_for(archive, patterns, exclude, config=config, verb="extract")
        if outer
        else None
    )

    with open_for_cli(
        archive_path,
        password=pwd,
        track_io=track_io,
        config=config,
        err=err,
        format=fmt,
    ) as reader:
        # A complete free index settles the patterns before anything is written.
        # Without one, or with one that ends in damage, the extraction's own pass
        # offers each member to them, and they are judged after it: a separate pass
        # would decompress the archive a second time.
        indexed = reader.members_report_if_available() if pred is not None else None
        if indexed is not None:
            selection.settle_from(indexed, err=err, dest_hint=True)
            if selection.settled and selection.selects_nothing:
                return EXIT_FAIL

        may_hoist = False
        if dest is not None:
            target = Path(dest)
        else:
            plan = resolve_smart_dest(
                reader,
                archive_path,
                pred=pred,
            )
            target = plan.target
            may_hoist = plan.may_hoist
            if target != Path("."):
                verb = "would extract" if dry_run else "extracting"
                print(f"{verb} into {escape_path(target)}/", file=err)

        base_progress: ProgressCallback | None = make_progress_callback(
            hide_progress=hide_progress, stream=err
        )
        # Under STOP, extract_all raises without returning a report — track how
        # many members were extracted / blocked before the stop via progress (Q1.5).
        members_extracted = 0
        members_blocked = 0

        # The directories the extraction may create; removed again when it turns
        # out the patterns selected nothing.
        missing_dirs = _missing_dirs(target)

        def on_progress(progress: ExtractionProgress) -> None:
            nonlocal members_extracted, members_blocked
            members_extracted = progress.members_extracted
            members_blocked = progress.members_blocked
            if base_progress is not None:
                base_progress(progress)

        try:
            try:
                with member_skips_reported_elsewhere():
                    report = reader.extract_all(
                        target,
                        members=pred,
                        policy=policy_enum,
                        overwrite=overwrite_enum,
                        on_error=on_error,
                        abort_on=abort_on_enum,
                        on_progress=on_progress,
                        dry_run=dry_run,
                    )
            except BrokenPipeError:
                # The progress bar's stream lost its reader. That must reach
                # main(), which exits 141 with no message; the handler below would
                # report it as a failed extraction and exit 1.
                raise
            except (ArchiveyError, OSError) as exc:
                # STOP-path member failure / always-stop (bomb guards,
                # DiagnosticRaisedError): report what was already written, then
                # the stop notice. Exit 1 always on abort (Q8 Option A): exit 3
                # is reserved for a *completed* run with policy blocks and safe
                # members on disk (blocks never abort under STOP). The
                # ``archivey: `` prefix: see main._parse_and_dispatch.
                # Under CONTINUE this line can repeat the detail of the
                # ``WARNING: Skipping …`` line printed just above it, which ``test``
                # suppresses. That is kept on purpose: the warning says a member was
                # skipped, this line says why the run ended, and ``extract`` has no
                # failure counter, so nothing is counted twice.
                print(f"archivey: {format_error_detail(exc)}", file=err)
                parts: list[str] = []
                if members_extracted:
                    parts.append(f"{members_extracted} member(s) extracted")
                if members_blocked:
                    parts.append(f"{members_blocked} blocked")
                if parts:
                    print(f"{', '.join(parts)} before the stop", file=err)
                print(
                    "extraction stopped; remaining members were not extracted",
                    file=err,
                )
                if dry_run:
                    print("dry run: nothing was written", file=err)
                return EXIT_FAIL
            if pred is not None and not selection.settled:
                if len(report) == 0 and selection.selects_nothing:
                    # Removed before the warning, whose -d hint looks for a directory
                    # named like the pattern.
                    _remove_empty_dirs(missing_dirs)
                    selection.report(err=err, dest_hint=True)
                    return EXIT_FAIL
                selection.report(err=err, dest_hint=True)
            hoist = _HoistResult(target)
            if may_hoist and dry_run:
                # The hoist moves what the extraction wrote; a dry run wrote nothing.
                hoist = predict_hoist(target, report, overwrite=overwrite_enum, err=err)
            elif may_hoist:
                hoist = maybe_hoist_single_root(
                    target, overwrite=overwrite_enum, err=err
                )
            blocked, failed = _report_extraction(
                report,
                target=target,
                verbose=verbose,
                err=err,
                extra_renamed=hoist.renamed,
                dest_label=hoist.dest_label,
                moves=hoist.moves,
                dry_run=dry_run,
            )
            return _exit_for_outcomes(blocked=blocked, failed=failed, hoist_ok=hoist.ok)
        finally:
            if base_progress is not None:
                base_progress.close()
