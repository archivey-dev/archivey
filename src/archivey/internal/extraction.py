"""The extraction coordinator.

``ExtractionCoordinator`` is a **pull-based sink**: it drives the reader
(``members_report_if_available()``, ``_iter_with_data()``, ``compressed_source_size``) and
selects an algorithm, rather than a push-model helper that buffers deferred link state.
Per member it runs the universal safety check on the original, applies the policy
transform (and optional user filter) to a transient copy, and writes FILE / DIR / SYMLINK
/ HARDLINK, tracking bomb limits and per-member results.

Hardlinks (TAR ordering guarantees the source precedes its links) are resolved by one
**core** algorithm: a sequential forward pass with a conditional second pass. When a
filter/selector orphans a selected link (its source excluded), a re-readable (seekable)
source is recovered in a single second pass; a forward-only source is unrecoverable and
fails per ``OnError``. See ``safe-extraction`` / ``format-tar`` for the normative spec.

The optional *planned single pass* optimization (staging an excluded source during the
first pass when a free member list exists) is deliberately not implemented here — it is an
optimization over this core, not a correctness requirement.
"""

from __future__ import annotations

import bisect
import contextlib
import errno
import io
import os
import posixpath
import stat
import tempfile
import uuid
from collections.abc import Callable, Collection, Generator, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Protocol, assert_never, cast

from archivey.config import ExtractionLimits
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    DiagnosticRaisedError,
    ExtractionError,
    FilterRejectionError,
    LinkTargetNotFoundError,
    LinkTargetNotFoundReason,
    NameCollisionError,
    NameRewrittenError,
    _UsageTypeError,
    exception_detail,
)
from archivey.internal.bomb_tracker import (
    AlwaysStopResourceLimitError,
    BombTracker,
)
from archivey.internal.dry_run import DryRun, scratch_for
from archivey.internal.file_copy_pass import FileCopyPass
from archivey.internal.filters import (
    POLICY_TRANSFORMS,
    SYMLINK_ESCAPES,
    SYMLINK_LOOPS,
    apply_name_policy,
    check_universal,
    collision_key,
    disk_spelled,
    reroot_absolute,
    resolve_or_raise_on_loop,
)
from archivey.internal.link_watch import LinkWatch
from archivey.internal.logs import extraction as logger
from archivey.internal.long_paths import long_path, plain
from archivey.internal.selection import CollectionSelector
from archivey.paths import numbered_name
from archivey.terminal import display_path, quoted
from archivey.types import (
    EXTRA_IS_FILE_COPY,
    AbortOn,
    ArchiveMember,
    ExtractionPolicy,
    ExtractionProgress,
    ExtractionResult,
    ExtractionStatus,
    MemberFilter,
    MemberType,
    NameRewrite,
    OnError,
    OverwritePolicy,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

    from archivey.internal.base_reader import BaseArchiveReader
    from archivey.internal.streams.archive_stream import ArchiveStream


_CHUNK = 1024 * 1024  # 1 MiB copy chunk

# Prefix of the temp files atomic FILE writes stage in the destination directory
# (mkstemp appends a random suffix), and of the staging directory of a pass that stages
# its members (``_write_staged``: a ZIP from a pipe). Python-level failures remove
# them; a removal the filesystem refuses (logged) or a hard kill (SIGKILL, power loss)
# can leave one: leftover ``.archivey-tmp-*`` files and directories in an extraction
# destination are archivey's and are safe to delete once no extraction is running
# there (a staging directory holds a running pipe extraction's only copy of its
# data). Documented in docs/extracting.md; keep the value and that doc in sync.
_TMP_PREFIX = ".archivey-tmp-"

# A module attribute, not ``os.name`` at each use, so a test can take the Windows path
# on POSIX.
_WINDOWS = os.name == "nt"

# Whether ``os.symlink`` makes two kinds of link, one for a file target and one for a
# directory target (``target_is_directory``). Windows does, and a link of the wrong kind
# does not work: a file link to a directory cannot be entered. POSIX has one kind.
# Separate from ``_WINDOWS`` so a test can take this route alone on POSIX.
_DIRECTORY_LINKS = _WINDOWS


def _dir_mode_as_stored(mode: int) -> int:
    """The mode ``os.stat`` reports for a directory after ``os.chmod(path, mode)``.

    On Windows a mode carries only the read-only attribute, taken from the owner-write
    bit, and ``os.stat`` reports a directory as ``0o777`` or, read-only, ``0o555``.
    Comparing the member's mode as given would report every existing directory as
    having kept its mode there (``0o755`` against ``0o777``) when applying the
    member's would have changed nothing."""
    if not _WINDOWS:
        return mode
    return 0o777 if mode & stat.S_IWUSR else 0o555


# Win32 error codes matched on ``OSError.winerror``, which exists only on Windows.
_ERROR_PATH_NOT_FOUND = 3
_ERROR_INVALID_NAME = 123
_ERROR_FILENAME_EXCED_RANGE = 206
_ERROR_TOO_MANY_LINKS = 1142
_ERROR_PRIVILEGE_NOT_HELD = 1314


def _link_refused_here(exc: OSError) -> bool:
    """Whether ``os.link`` failed for a reason another path, or a copy, avoids.

    ``EXDEV``: the path is on another device. Or the file is at its link-count limit
    (``_at_link_limit``).
    """
    return exc.errno == errno.EXDEV or _at_link_limit(exc)


def _at_link_limit(exc: OSError) -> bool:
    """Whether ``os.link`` failed because the file already has as many names as the
    filesystem allows.

    ``EMLINK`` (Windows: ``winerror`` 1142, ``ERROR_TOO_MANY_LINKS``). NTFS allows 1024
    names for one file, the first name included, against 65000 on ext4. Without a copy,
    an archive POSIX extracts in full would fail on Windows at the 1025th name. A copy
    holds the same bytes.
    """
    return exc.errno == errno.EMLINK or (
        getattr(exc, "winerror", None) == _ERROR_TOO_MANY_LINKS
    )


def _symlink_problem(link_path: Path, target: str, dest_root: Path) -> str | None:
    """Why the symlink at ``link_path`` does not resolve inside ``dest_root`` now, or
    ``None`` when it does.

    Resolved through the real filesystem, so links on the way are followed. A link
    that cannot be resolved is refused: fail safe rather than crash. A symlink loop
    (found on every Python version by ``resolve_or_raise_on_loop``) is refused with
    its own message; anything else with the escape message. A loop cannot be
    resolved at all, so the loop message wins even when the target might have led
    outside ``dest_root``.
    """
    try:
        resolved = resolve_or_raise_on_loop(link_path.parent / target)
    except OSError as exc:
        return SYMLINK_LOOPS if exc.errno == errno.ELOOP else SYMLINK_ESCAPES
    if resolved == dest_root or resolved.is_relative_to(dest_root):
        return None
    return SYMLINK_ESCAPES


def _typed_os_error(
    exc: ArchiveyError | OSError, member_name: str
) -> ArchiveyError | OSError:
    """``exc``, or an ``ExtractionError`` when the archive's own name caused it.

    Two errors are properties of the name the archive chose, not of the filesystem's
    state: ``EILSEQ`` (bytes a UTF-8-only filesystem such as APFS refuses) and
    ``ENAMETOOLONG`` (a component, whole path or symlink target longer than the
    filesystem allows; the portable rewrite's ``%XX`` escapes can push a name over).
    Windows reports the same two as ``winerror`` 123 (``ERROR_INVALID_NAME``) and 206
    (``ERROR_FILENAME_EXCED_RANGE``), with errnos (``EINVAL``, ``ENOENT``) too broad to
    match on, so the Windows code is checked instead. Either can come from a link
    target as well as the name, so the messages name both. Windows also raises 1314
    (``ERROR_PRIVILEGE_NOT_HELD``) for a symlink when the process may not create one,
    which every symlink member hits the same way. The code is matched for any member,
    and today a symlink is the only write archivey makes on Windows that needs a
    privilege, so the message names symlinks as the likely cause rather than as the
    call that failed. They become a typed per-member failure. Every other ``OSError``
    stays as it is.

    A path of ``MAX_PATH`` (260) characters or more that a call took without the
    extended prefix fails with ``winerror`` 3 (``ERROR_PATH_NOT_FOUND``) unless the
    machine enables long paths. The coordinator gives such a path the prefix
    (``long_paths``), so this is the rest: a call it does not route, or a component
    longer than the filesystem allows. It is typed as too long only when the path in
    the error is that long and not in the extended form; a short missing path stays
    the ``FileNotFoundError`` it is.
    """
    if not isinstance(exc, OSError):
        return exc
    # ``winerror`` exists only on Windows; elsewhere it is None.
    winerror = getattr(exc, "winerror", None)
    if winerror == _ERROR_PATH_NOT_FOUND and _past_max_path(exc):
        winerror = _ERROR_FILENAME_EXCED_RANGE
    if exc.errno == errno.EILSEQ or winerror == _ERROR_INVALID_NAME:
        message = (
            "Member name or link target cannot be represented on the destination "
            "filesystem"
        )
    elif exc.errno == errno.ENAMETOOLONG or winerror == _ERROR_FILENAME_EXCED_RANGE:
        message = (
            "Member name or link target is too long for the destination filesystem"
        )
    elif winerror == _ERROR_PRIVILEGE_NOT_HELD:
        message = (
            "This process does not hold a privilege the write needs; on Windows, "
            "creating a symlink needs Developer Mode or an elevated process"
        )
    else:
        return exc
    error = ExtractionError(message, member_name=member_name)
    error.__cause__ = exc
    return error


# Win32's limit on a path without the extended prefix, the terminating NUL included.
_MAX_PATH = 260


def _past_max_path(exc: OSError) -> bool:
    """Whether a file name in ``exc`` is too long for Win32 without the extended
    prefix."""
    for name in (exc.filename, exc.filename2):
        if isinstance(name, str) and len(name) >= _MAX_PATH - 1 and plain(name) == name:
            return True
    return False


def _plain_os_error(exc: OSError) -> None:
    """Name the paths in ``exc`` without the extended prefix, in place."""
    for attr in ("filename", "filename2"):
        value = getattr(exc, attr, None)
        if isinstance(value, str):
            setattr(exc, attr, plain(value))


def _is_regular_file(path: Path) -> bool:
    """Whether ``path`` is a regular file itself, not a symlink to one."""
    try:
        return stat.S_ISREG(os.lstat(long_path(path)).st_mode)
    except OSError:
        return False


def _file_identity(st: os.stat_result) -> tuple[int, int, int, int]:
    """What says a file is still the one this run wrote: its inode, size and mtime."""
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _open_new_file(path: Path, mode: int) -> int:
    """Create ``path``, which must not exist, for writing; return the open fd.

    ``mode`` is the creation mode, so the umask applies to it as it does to any new
    file. The flags are ``mkstemp``'s: ``O_EXCL`` fails loudly on a name that appeared
    underneath us, ``O_NOFOLLOW`` refuses a symlink planted there, and ``O_BINARY`` /
    ``O_NOINHERIT`` matter on Windows only.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for extra in ("O_NOFOLLOW", "O_BINARY", "O_NOINHERIT"):
        flags |= getattr(os, extra, 0)
    return os.open(long_path(path), flags, mode)


class _AbortExtraction(Exception):
    """Internal carrier for an ``abort_on`` trigger fired deep in the write path.

    The public error it wraps (``NameCollisionError`` / ``NameRewrittenError``) is an
    ``ExtractionError``, so raising it directly would be caught by the per-member
    handlers and turned into a ``FAILED`` result — the opposite of an abort. This
    carrier is a plain ``Exception``, so it passes those handlers untouched (their
    ``finally`` clauses still close streams) and ``run()`` unwraps it at the top.
    """

    def __init__(self, error: ArchiveyError) -> None:
        super().__init__(str(error))
        self.error = error


class _PassedData(io.RawIOBase):
    """Stands in for a member's data that a forward pass has already passed: reading
    it raises ``error``. The write runs up to its first read, so the overwrite policy
    decides as it would with the data there (a member it would not write does not
    fail)."""

    def __init__(self, error: ArchiveyError | OSError) -> None:
        super().__init__()
        self._error = error

    def readable(self) -> bool:
        return True

    def readinto(self, b: WriteableBuffer, /) -> int:
        raise self._error


def _passed_data(error: ArchiveyError | OSError) -> BinaryIO:
    """A ``_PassedData`` that raises ``error``, as the member stream it stands in for."""
    return cast("BinaryIO", _PassedData(error))


def _report_stored_spelling(
    exc: ArchiveyError, on_disk: ArchiveMember, member: ArchiveMember
) -> None:
    """Rename ``exc`` from the spelling ``on_disk`` back to ``member``'s names.

    A check runs on the spelling that reaches disk, but an error names the member as
    it was before that spelling, so one skip does not print two names for one member.
    Each of the name and the link target moves back when the two members spell it
    differently. Two callers: after ``disk_spelled``, which writes a lone surrogate as
    its UTF-8 bytes (under ``STRICT`` and ``STANDARD`` the name policy has already
    escaped the name, so there only the link target changes back); and after the name
    policy's rewrite, where the name, the target or both can change back.
    """
    if exc.member_name == on_disk.name:
        exc.member_name = member.name
    if exc.link_target is not None and exc.link_target == on_disk.link_target:
        exc.link_target = member.link_target


def _final_members_only(
    selector: Callable[[ArchiveMember], bool],
) -> Callable[[ArchiveMember], bool]:
    """``selector`` for the members the walk will not change, and yes for the rest,
    which the pass selects provisionally (``_provisionally_selected``) and placement
    for good (``_stage_then_place``)."""

    def select(member: ArchiveMember) -> bool:
        return not member.member_state_final or selector(member)

    return select


def _provisionally_selected(
    selector: Callable[[ArchiveMember], bool], member: ArchiveMember
) -> bool:
    """Whether the pass stages a member the walk can still change, before placement
    selects it for good (``_stage_then_place``).

    A ``members=`` collection matches any name the member can end up with, so the
    data of every member it may select is staged while the stream holds it, and
    nothing is recorded as matched yet. A predicate is asked about the member as it
    is now; the data of a member it leaves out is not staged, and cannot be placed
    later.
    """
    if isinstance(selector, CollectionSelector):
        return selector.would_select(member, _possible_names(member.name))
    return selector(member)


def _possible_names(name: str) -> set[str]:
    """The names a member the walk has yet to settle can end with: a ZIP's
    directory can make ``\\`` a separator (a DOS host) and a provisional directory
    a file or a link, which drops the trailing ``/``."""
    names = {name, name.replace("\\", "/")}
    return names | {n[:-1] for n in names if n.endswith("/")}


def _until_listing_damage(
    reader: BaseArchiveReader,
    pairs: Iterator[tuple[ArchiveMember, ArchiveStream | None]],
    found: list[CorruptionError],
) -> Generator[tuple[ArchiveMember, ArchiveStream | None], None, None]:
    """``pairs``, ending quietly when the listing's own damage ends them.

    That damage is appended to ``found`` for the caller to raise once the members
    before it are done. Only the reader's walk error counts: any other error the
    pass raises propagates at once, as before. An error from the loop body never
    reaches this generator.
    """
    try:
        yield from pairs
    except CorruptionError as exc:
        if exc is not reader._walk_error:
            raise
        found.append(exc)


class _Closable(Protocol):
    def close(self) -> None: ...


@contextlib.contextmanager
def _closing_pass(passing: _Closable) -> Generator[None, None, None]:
    """Close ``passing`` on the way out, without letting a failed close hide an error.

    Closing the pass closes its open member stream, which can raise (an ``unrar``
    exit status maps to a typed error). With an error already leaving the loop, that
    error is the one the caller catches; the close failure rides on it as a note. On a
    clean exit, a close failure raises as itself.
    """
    try:
        yield
    except BaseException as exc:
        try:
            passing.close()
        except Exception as close_exc:  # noqa: BLE001  # kept as a note, not raised
            exc.add_note(
                "Closing the member pass also failed: "
                + exception_detail(close_exc, with_type=True)
            )
        raise
    passing.close()


@dataclass
class _Orphan:
    """A selected hardlink whose source was not yet on disk, awaiting the second pass.

    ``transformed`` is the policy/filter-transformed copy from the first pass: it supplies
    the on-disk identity (mode, timestamps) when the source's content is materialized at
    this link's path (see the ``safe-extraction`` "copy supplies the identity" rule).
    ``spelled_from`` is ``transformed`` before its disk spelling, when that differs, so
    an error names it as the first pass would (``_MemberState.spelled_from``).
    """

    result_index: int
    original: ArchiveMember
    transformed: ArchiveMember
    dest_path: Path
    source: ArchiveMember
    spelled_from: ArchiveMember | None = None


@dataclass
class _Staging:
    """A member a pass that stages its members met, or one the walk lists that the
    stream never held (``missing``), on its way to placement (``_stage_then_place``).

    ``final``: the member was final when yielded, so the walk's selection already
    took it. ``staged``: its data in the staging directory, and ``staged_bytes`` what
    the bomb limits counted for it. ``error``: the failure that stopped its staging.
    ``refused``: its local header's name was refused, so nothing was staged.
    ``reported``: the pass reported it to ``on_progress``. ``reversed``: it is the
    current copy of its name, though the stream holds another copy after it.
    """

    member: ArchiveMember
    final: bool
    staged: Path | None = None
    staged_bytes: int = 0
    error: ArchiveyError | OSError | None = None
    refused: bool = False
    missing: CorruptionError | None = None
    reported: bool = True
    reversed: bool = False


@dataclass(frozen=True)
class _Claim:
    """A destination claimed by a member written this run, with the index of that
    member's result. A later ``REPLACE`` onto the destination revises that result to
    ``OVERWRITTEN``.

    ``physical`` is where the claimed file was when it was claimed, with every parent
    resolved. The key is taken from it, and a collision is routed to it. ``path`` can
    run through a symlink the archive later repoints, so it can stop naming that file.
    """

    path: Path
    result_index: int
    physical: Path


@dataclass
class _RunState:
    """One ``run()``'s state: where it writes, what it has written, its tallies.

    ``_run`` builds a new one per run, so nothing carries over from an earlier run.
    """

    # The destination as given, and resolved.
    dest: Path
    dest_root: Path
    tracker: BombTracker
    reader: BaseArchiveReader
    # The symlinks this run created and the paths each one's resolution depends on,
    # so a later member that changes such a path gets them rechecked.
    links: LinkWatch
    # Progress totals; see ``_run``.
    members_total: int | None = None
    total_estimate: int | None = None
    results: list[ExtractionResult] = field(default_factory=list)
    # Running counts of EXTRACTED and BLOCKED results, kept here rather than in the
    # pass loop because a REPLACE collision, a link recheck or a streaming pass's
    # superseded copy revises an *earlier* member's result and must correct the
    # tally with it (progress reports tallies of results, not of writes attempted).
    members_extracted: int = 0
    members_blocked: int = 0
    # Result index -> output bytes counted for it, for each member that reached
    # ``tracker.start_member``: what a streaming take-back refunds.
    counted: dict[int, int] = field(default_factory=dict)
    # Source member id -> the on-disk paths holding that source's content.
    source_paths: dict[int, list[Path]] = field(default_factory=dict)
    # The entries this run has written under ``dest``.
    written_paths: set[Path] = field(default_factory=set)
    # O2 collision map: casefold(NFC(relpath)) key (exact under TRUSTED) -> the claim
    # (written path + claiming member's result index). Tracks non-directory members
    # written THIS run so a second member resolving to the same key is a deterministic
    # collision on every OS (not a platform-dependent silent merge), and so a REPLACE
    # resolution can revise the earlier member's result. See _write_member /
    # dev-docs/decisions/0013.
    collision_map: dict[str, _Claim] = field(default_factory=dict)
    # The key each claimed path was claimed under (see ``_claim``).
    claim_keys: dict[Path, str] = field(default_factory=dict)
    # Claimed files by identity, (st_dev, st_ino) -> the path claimed, for a name the
    # filesystem makes a second name of one (``_alias_claim``). Filled lazily: a path
    # waits in ``unindexed_claims`` until the first lookup after it was claimed.
    claim_ids: dict[tuple[int, int], Path] = field(default_factory=dict)
    unindexed_claims: list[Path] = field(default_factory=list)
    # RENAME: the last ``N`` tried per collision key of the requested name, so the
    # next member colliding on that key resumes after it instead of rescanning from
    # ``(1)``. Cleared whenever a claim is released (a freed name may be the first
    # free one again).
    rename_next: dict[str, int] = field(default_factory=dict)
    # Directories RENAME wrote under a derived name: the path the member asked for ->
    # the path it was written to. Members inside such a directory follow it there
    # (``_follow_renamed_dirs``).
    renamed_dirs: dict[Path, Path] = field(default_factory=dict)
    # Directories this run wrote: collision key of the written path -> indices of the
    # EXTRACTED results that report it. Not collision claims (directories merge, so
    # they never go in the collision map), but keyed the same way, so a directory
    # reached through the archive's own symlink or by a case variant is one entry.
    # Kept so a REPLACE that removes an empty directory this run wrote can revise
    # that result to OVERWRITTEN.
    written_dirs: dict[str, list[int]] = field(default_factory=dict)
    # Hardlinks whose source was not on disk yet, for the second pass.
    orphans: list[_Orphan] = field(default_factory=list)
    # Superseded copies the filesystem refused to remove, by archive name, as in
    # ``_MemberState.parked``: the next member of that name parks them again.
    unremoved: dict[str, dict[Path, int]] = field(default_factory=dict)
    # Directories ``_makedirs`` created this run, as parents of what it wrote.
    created_dirs: set[Path] = field(default_factory=set)
    # Every directory this run wrote or created, by ``_physical_key`` -> where each one
    # physically is (``_physical_path``), so a member that names one under another
    # spelling is not taken for the caller's (``_is_run_directory``).
    run_dirs: dict[str, set[Path]] = field(default_factory=dict)
    # Directory members whose ownership, mode and times wait for the end of the run
    # (``_apply_directory_metadata``): ``_physical_key`` -> where the directory physically
    # is -> the directory's identity on disk (device, inode) when it was written, the
    # number of ``/`` in that physical path relative to the root (so a deeper
    # directory sorts first), and the transformed member. In each key, in the order
    # they were last written. Keyed by place, not identity: some filesystems report
    # inode 0 for every entry (``_Identity.of`` in the directory reader). By the
    # physical path, not the spelled one: two spellings through a symlink of the
    # archive's share one entry, and the metadata pass opens the directory through
    # shallower directories only, which it has not changed yet. Under a casefolded
    # key, so a removal by a case variant finds the entry (``_drop_pending_dir``).
    pending_dirs: dict[str, dict[Path, tuple[tuple[int, int], int, ArchiveMember]]] = (
        field(default_factory=dict)
    )
    # ``_physical_rel``'s resolved parents, as spelled -> relative to the root with a
    # trailing ``/``. Only a symlink created, replaced or removed changes a
    # resolution, so each of those clears it (``_note_link_change`` and
    # ``_resolutions_changed``).
    resolved_parents: dict[str, str] = field(default_factory=dict)
    # ``_hardlink_chain_end``'s memo: a hard link's ``_member_id`` -> the first
    # member on its chain that is not a HARDLINK, or ``None``.
    hardlink_ends: dict[int, ArchiveMember | None] = field(default_factory=dict)
    # Member id -> the index of the result recorded for it, so a hard link can read
    # what this run did with its source (``_source_refused``).
    result_ids: dict[int, int] = field(default_factory=dict)
    # ``_source_refused``'s memo for hard-link sources this run recorded no result
    # for (a selector or filter excluded them): member id -> whether the policy would
    # refuse it.
    refusals: dict[int, bool] = field(default_factory=dict)
    # Where the platform has two kinds of symlink (``_DIRECTORY_LINKS``): each symlink
    # this run created -> the target it was created with and whether it was made a
    # directory link, so the end of the run can remake one whose target turned out
    # the other kind (``_settle_link_kinds``).
    link_kinds: dict[Path, tuple[str, bool]] = field(default_factory=dict)
    # The archive's listing, when the run has one for free, and its names folded and
    # sorted with the set of directory members' names (``_listed_directory``, built on
    # first use).
    listed: list[ArchiveMember] | None = None
    listed_names: tuple[list[str], set[str]] | None = None
    # The stored target of each tracked symlink whose target was written differently
    # (a disk spelling, Windows separators, a dry run's scratch path), by result
    # index, so a recheck error names it as listed.
    stored_targets: dict[int, str] = field(default_factory=dict)
    # RAR file copies (``_open_written_source``). ``streaming_now`` is ``id()`` of
    # the member whose stream is being written; a file-copy source arriving then is
    # not kept by the pass (``_keep_copy_source``), and goes in ``declined``. Only
    # a declined source's file gets its identity recorded after the write
    # (``_file_identity``), by its member id and path, so a later member written
    # to the same path never vouches for it, and no other file costs a stat. A
    # copy is then copied from that file if it still matches.
    streaming_now: int | None = None
    declined: set[int] = field(default_factory=set)
    # The staging directory of a pass whose members can change once its walk ends
    # (a ZIP from a pipe, whose central directory comes last;
    # ``_REVISES_YIELDED_MEMBERS``): the pass writes each member's data there, and the
    # members are placed from it once the walk has ended (``_stage_then_place``).
    # Created on the first staged member; removed when the run ends.
    staging: Path | None = None
    written_files: dict[tuple[int, Path], tuple[int, int, int, int]] = field(
        default_factory=dict
    )


@dataclass
class _MemberState:
    """What the member being handled shares with its write path, in both directions.

    The pass builds a new one per member, and the second pass one per link, so
    nothing carries over.
    """

    # The destination the member asked for, published so the per-member error
    # handler can record it on a FAILED/BLOCKED result. A collision resolved by ERROR
    # raises out of the write, which is exactly the case where the spec still requires
    # ``requested_path`` set with ``path=None``; it has to carry the collision too.
    requested_path: Path | None = None
    collided_with: Path | None = None
    # Set by ``_transform`` when reading a link's target showed the member is not a
    # link after all, so the pass yielded it with no data stream.
    retyped: bool = False
    # Set by ``_transform`` to the member before ``disk_spelled`` when the disk
    # spelling differs, so an error raised while writing can name it as listed.
    spelled_from: ArchiveMember | None = None
    # Set by ``_prepare_destination`` when it removes an existing entry to make room.
    # Only the non-atomic paths (DIR / SYMLINK / HARDLINK) do that — a FILE write
    # lands via os.replace and never destroys the destination up front — so this is
    # how the write path knows a failure afterwards left a hole rather than the old
    # content.
    removed_existing: bool = False
    # Intra-member progress emit while copying a FILE (None when on_progress is unset
    # or the member has no streamed body).
    emit_progress: Callable[[], None] | None = None
    # The member's data as the pass staged it (``_stage_then_place``): a FILE written
    # from it lands by renaming it (``_write_file_atomic``), and its bytes were
    # counted when it was staged.
    staged: Path | None = None
    # A streaming pass's earlier copies of this member's name, left in place while it
    # is handled so it can replace one atomically: path -> index of the superseded
    # result. See ``_park_earlier_copies``.
    parked: dict[Path, int] = field(default_factory=dict)


class ExtractionCoordinator:
    """Drives a single forward pass over a reader's members, writing them safely to disk."""

    def __init__(
        self,
        *,
        policy: ExtractionPolicy = ExtractionPolicy.STRICT,
        overwrite: OverwritePolicy = OverwritePolicy.ERROR,
        on_error: OnError = OnError.STOP,
        on_progress: Callable[[ExtractionProgress], None] | None = None,
        selector: Callable[[ArchiveMember], bool] | None = None,
        filter: MemberFilter | None = None,
        limits: ExtractionLimits | None = None,
        abort_on: Collection[AbortOn] = (),
        dry_run: bool = False,
    ) -> None:
        self._policy = policy
        self._dry_run = dry_run
        self._overwrite = overwrite
        self._on_error = on_error
        self._abort_on = frozenset(abort_on)
        self._on_progress = on_progress
        # A predicate, never the caller's raw ``members=``: that argument may be a
        # one-shot iterable, so only the public entry point reads it, and the caller
        # passes the normalized result here.
        self._selector = selector
        self._filter = filter
        self._limits = limits if limits is not None else ExtractionLimits()
        # Built by each ``run()``. A test that drives a helper directly installs its
        # own.
        self._state: _RunState
        # The state of the member being handled; each pass replaces it per member.
        self._current = _MemberState()
        # Set for the length of a dry run; ``None`` on a real run.
        self._dry: DryRun | None = None
        # Set by a dry run, from its scratch tree; see ExtractionReport.
        self.dry_run_top_level: tuple[tuple[str, bool], ...] | None = None
        self.dry_run_links: tuple[tuple[str, str], ...] | None = None
        self.dry_run_entries: tuple[tuple[str, bool], ...] | None = None

    # --- entry point ---------------------------------------------------------------

    def run(
        self, reader: BaseArchiveReader, dest: str | Path
    ) -> list[ExtractionResult]:
        """Extract into ``dest``; under ``dry_run``, into a private scratch directory.

        A dry run is the same pass, not a model of it. Directories, symlinks and
        hardlinks are created for real under the scratch directory, so every check that
        consults the filesystem (a parent resolved through an earlier member's symlink,
        a link escape, a collision) behaves as it would in ``dest``. Each FILE body is
        read, decompressed, verified and counted against the limits, then discarded:
        the file itself is created empty. ``dest`` itself is checked the way a real run
        checks it and is never created or written to. What it holds already is copied
        into the scratch directory, entry by entry, as the pass reaches it
        (``DryRun.bring_in``): the entry at each component of a member's path, link
        target or hardlink source, the names a RENAME would try in its place, and one
        entry of a directory the path names. A file is copied as an empty file with
        its mode, a directory with its mode, a symlink with its target. So the
        overwrite policy, a caller's file or symlink in the way, a RENAME's free name
        and a REPLACE's emptiness check are met as in ``dest``. What that costs is a
        listing of each directory of ``dest`` the pass enters, read once, and a copy of
        each entry it names, not of everything ``dest`` holds. Paths in the results and
        in errors are reported under ``dest``, and the scratch directory is removed
        before this returns or raises. What a completed pass made directly under the
        scratch copy of ``dest``, by the run's own record of what it wrote, created or
        extracted, is kept in ``dry_run_top_level``.

        Where the scratch tree cannot stand in for ``dest``, the run says less than a
        real one would. The copy of a directory of ``dest`` always has its owner's
        read, write and search bits, so a directory there that the caller cannot
        write to, or that the run cannot list, is not refused as a real run refuses
        it, and a member that keeps such a directory's mode reports those bits too; a
        directory that cannot be listed is copied as empty, and an entry that cannot
        be copied is left out. A symlink of ``dest`` that the OS will not create in
        the scratch tree (Windows without the privilege) is copied as an empty file. A
        link target that leaves ``dest`` is resolved outside the scratch tree, so one
        that comes back into ``dest`` through a symlink outside it, or climbs above
        the directory that holds it, is refused where a real run could accept it; an
        absolute target is matched by the leading part of it that resolves to
        ``dest`` (``DryRun.target_on_disk``) and is not affected. And everything is
        written to one filesystem, so a hardlink never falls back to a copy: the bytes
        such a copy counts against ``max_extracted_bytes`` in a ``dest`` that spans a
        mount point are not counted.
        """
        dest = Path(dest)
        if not self._dry_run:
            try:
                return self._run(reader, dest)
            except OSError as exc:
                _plain_os_error(exc)
                raise
        with scratch_for(dest) as dry:
            self._dry = dry
            try:
                results = self._run(reader, dry.scratch_given)
            except OSError as exc:
                dry.rebase_os_error(exc)
                raise
            finally:
                self._dry = None
            # What the run made, from its own record of it: an entry copied in from
            # dest counts only when it is one of these (``DryRun.record``).
            state = self._state
            record = dry.record(
                (
                    *state.written_paths,
                    *state.created_dirs,
                    *(
                        r.path
                        for r in results
                        if r.status is ExtractionStatus.EXTRACTED and r.path is not None
                    ),
                )
            )
            self.dry_run_top_level = record.top_level
            self.dry_run_entries = record.entries
            self.dry_run_links = record.links
            return [dry.rebase_result(result) for result in results]

    @property
    def _on_disk(self) -> Callable[[str], str] | None:
        """``check_universal``'s ``link_target_on_disk``: set on a dry run only."""
        return self._dry.target_on_disk if self._dry is not None else None

    def _link_target_on_disk(self, target: str) -> str:
        """The target a link is created with (see ``DryRun.target_on_disk``).

        On Windows each ``/`` is written as ``\\`` first. A symlink's target is stored
        as given, and Windows resolves it with ``\\`` as the only separator, so
        ``sub/file`` would dangle there while it resolves on POSIX. Windows cannot hold
        ``/`` in a name, so the character can only mean a separator. Git for Windows
        and Node write link targets the same way.
        """
        if _WINDOWS:
            target = target.replace("/", "\\")
        return target if self._dry is None else self._dry.target_on_disk(target)

    def _shown(self, path: Path) -> Path:
        """``path`` as the caller sees it (see ``DryRun.shown``)."""
        return path if self._dry is None else self._dry.shown(path)

    def _rebase_os_error(self, exc: OSError) -> None:
        """Point a filesystem error at the paths the caller sees, in place: without the
        long-path prefix, and under a dry run at the caller's dest."""
        _plain_os_error(exc)
        if self._dry is not None:
            self._dry.rebase_os_error(exc)

    def _rebase_resolved_os_error(self, exc: OSError) -> None:
        """``_rebase_os_error`` for an error that names a path built from
        ``dest_root``, the resolved dest: a real run names it so, and a dry run shows
        it under the resolved dest too."""
        _plain_os_error(exc)
        if self._dry is not None:
            self._dry.rebase_os_error(exc, resolved=True)

    def _run(self, reader: BaseArchiveReader, dest: Path) -> list[ExtractionResult]:
        tracker = BombTracker(
            self._limits.max_extracted_bytes,
            self._limits.max_ratio,
            self._limits.ratio_activation_threshold,
            self._limits.max_entries,
            source=reader,
            live_ratio_activation_threshold=(
                self._limits.live_ratio_activation_threshold
            ),
        )

        selector = self._selector

        # Progress totals cover what this call will actually attempt: when a member list
        # is free (an upfront index) and a selector is given, totals count only the
        # selected members — so members_done can reach members_total and the byte
        # estimate matches the selected output. The user `filter` runs only during
        # extraction and cannot be pre-applied, so members it skips still count as
        # processed below. Streaming readers with no free list report None totals.
        members_report = reader.members_report_if_available()
        all_members = list(members_report) if members_report is not None else None
        # A free list that ends in damage holds only the members before it. What it
        # says no selected entry matches is not known, and the pass has to reach the
        # damage to raise it (see _run_pass).
        listing_damaged = (
            members_report is not None and members_report.error is not None
        )
        if all_members is not None and selector is not None:
            all_members = [m for m in all_members if selector(m)]
        # A members= collection whose entries all went through the free list is
        # settled now: report the entries that matched nothing before anything is
        # written or created, so a RAISE disposition refuses the call with nothing on
        # disk.
        # Without a free list the answer is known only at the end of the pass, or,
        # for a pass that stages its members, once its walk has ended and before any
        # member is placed (``_stage_then_place``).
        unmatched_pending: CollectionSelector | None = None
        # A pass that stages its members never has a free list here (its reader lists
        # nothing up front, and ``extract_all`` refuses a streaming reader whose pass
        # has started), so ``_stage_then_place`` is its only reporter: the report is
        # made once.
        assert not (reader._REVISES_YIELDED_MEMBERS and all_members is not None)
        if isinstance(selector, CollectionSelector):
            if all_members is not None and not listing_damaged:
                selector.report_unmatched(
                    reader._diagnostics_collector, reader._archive_name
                )
            elif not reader._REVISES_YIELDED_MEMBERS:
                unmatched_pending = selector
        # Created only after that report, so a refusal leaves no directory behind.
        created_root = self._ensure_dest_root(dest)
        dest_root = resolve_or_raise_on_loop(dest)
        members_total = len(all_members) if all_members is not None else None
        self._state = _RunState(
            dest=dest,
            dest_root=dest_root,
            reader=reader,
            tracker=tracker,
            members_total=members_total,
            total_estimate=self._estimate_total_bytes(all_members),
            created_dirs={dest} if created_root else set(),
            # Rechecks share the entry-count bound: a hostile archive can make each
            # member recheck every link so far, and max_entries is what bounds members.
            links=LinkWatch(dest_root, self._limits.max_entries),
            listed=all_members if _DIRECTORY_LINKS else None,
        )

        # Extract-prep: every pass enforces ListingLimits as it lists, so this only
        # decides when the listing happens. Most random-access readers list everything
        # first, so nothing is written from an archive over the limits; TAR and every
        # streaming reader list as members arrive in the one pass
        # (_list_before_extraction).
        reader._list_before_extraction()

        # The pass is driven through the public stream_members(), which applies the
        # selection (skipped members never surface here — they are invisible to progress
        # and results, matching the totals above). When the totals pre-filtered the free
        # member list, that list is reused as an identity selector, so a user predicate
        # runs once per member (on the index) rather than once per pre-filter plus once
        # per yield; a stateful predicate still sees each member a single time. Without
        # a free list the predicate itself is passed through.
        #
        # Every pass the coordinator drives hands stream_members() a CollectionSelector
        # built here, with no bookkeeping. A selector that stream_members() builds from a
        # collection reports its own unmatched entries, and a collection built here is
        # the coordinator's, not the caller's (the hardlink second pass does the same).
        stream_selector = (
            None
            if selector is None
            else CollectionSelector(list(all_members), record=False)
            if all_members is not None
            else selector
        )

        # Explicit selection with a free member list: once every selected member has
        # been seen, stop the forward pass. Solid backends otherwise keep walking the
        # rest of the archive (and would skip-decode unread tails if positioning were
        # eager). Predicate selectors and streaming backends have no finite remaining
        # count, so they still drain.
        selected_total = (
            members_total
            if selector is not None
            and members_total is not None
            and not listing_damaged
            else None
        )

        try:
            self._run_pass(reader, stream_selector, selected_total)
        except _AbortExtraction as abort:
            # An abort_on trigger fired: no report is returned, and output already
            # written for earlier members stays on disk (same as OnError.STOP). A pass
            # that stages its members (a ZIP read from a pipe) has placed none of them
            # before its walk ends, so a stop then leaves nothing of the run in the
            # destination. Nothing partial exists for the triggering member — every
            # trigger fires before its write begins, and FILE writes land atomically
            # in any case.
            raise abort.error from None
        finally:
            # Also when the run stops early; first, while the destination root is
            # still writable (its own deferred metadata comes last).
            if self._state.staging is not None:
                self._remove_staging()
            # Links first: remaking one changes its directory, whose times come next.
            self._settle_link_kinds()
            # The directories the run did write end with their stored metadata, as
            # the ones of a completed run do.
            self._apply_directory_metadata()

        if unmatched_pending is not None:
            unmatched_pending.report_unmatched(
                reader._diagnostics_collector, reader._archive_name
            )
        return self._state.results

    def _run_pass(
        self,
        reader: BaseArchiveReader,
        stream_selector: Callable[[ArchiveMember], bool] | None,
        selected_total: int | None,
    ) -> None:
        """The forward pass and the orphan second pass, appending into the results.

        Split out of ``run()`` only so an ``abort_on`` trigger raised anywhere inside it
        has one place to unwind to; the results are filled in place because an abort
        discards them rather than returning them.
        """
        state = self._state
        copies = FileCopyPass(keep_source=self._keep_copy_source)
        # Damage that ends the listing ends this loop, not the pass: the members listed
        # before it are all written, including the hardlinks the second pass below
        # completes, and then it is raised. A hardlink only points back, so every
        # source the second pass needs is in that prefix.
        # Each pass is closed on the way out, so an error out of the loop body closes
        # the open member stream (and any unrar child) at once. CPython would close
        # an unnamed pass as soon as the error left the loop; PyPy closes a dropped
        # one only when it is collected. Binding the pass to ``pairs`` is safe only
        # because ``_closing_pass`` closes it: without that, a caller holding the
        # traceback would keep it (and the unrar child) alive on CPython too.
        listing_damage: list[CorruptionError] = []
        if reader._REVISES_YIELDED_MEMBERS:
            self._stage_then_place(reader, stream_selector, copies, listing_damage)
        else:
            members_done = 0
            # Archive name -> result index of the latest member of that name that
            # went on to be written (or tried). Random access stamps last-entry-wins
            # before the pass, so a shadowed copy reaches the SUPERSEDED branch of
            # ``_handle_member`` and is never recorded here. A streaming pass learns
            # of the later copy only when it arrives; see ``_park_earlier_copies``.
            current_by_name: dict[str, int] = {}
            pairs = _until_listing_damage(
                reader, reader._stream_members(stream_selector, copies), listing_damage
            )
            with _closing_pass(pairs):
                for original, stream in pairs:
                    self._handle_member(
                        original,
                        stream,
                        current_by_name=current_by_name,
                        members_done=members_done,
                    )
                    members_done += 1
                    if selected_total is not None and members_done >= selected_total:
                        break

        # Core second pass: resolve orphaned hardlinks whose (re-readable) source was
        # excluded. Only populated for a seekable source; forward-only orphans already
        # failed at the link during the main pass.
        if state.orphans:
            self._resolve_orphans(reader)
        if listing_damage:
            raise listing_damage[0]

    def _handle_member(
        self,
        original: ArchiveMember,
        stream: BinaryIO | None,
        *,
        current_by_name: dict[str, int] | None,
        members_done: int,
        staged: Path | None = None,
        fail_with: ArchiveyError | OSError | None = None,
        report: bool = True,
    ) -> int | None:
        """Handle one member of a pass: the filter, the policy checks, the overwrite
        policy and the write, recording its result. Return the index of that result,
        or ``None`` when no result was recorded (the filter dropped the member).

        ``current_by_name`` is the pass's record of the latest written member of each
        name (``_run_pass``), or ``None`` where every member's ``is_current`` is final,
        so no earlier copy is ever taken back (``_park_earlier_copies``).
        ``members_done`` is the number of members handled before this one. ``staged``
        is the member's data as a pass staged it (``_stage_then_place``): its bytes and
        its entry were counted then, so they are not counted again. ``fail_with`` fails
        a member the pass knows is bad, once the filter and the checks have let it
        through, for a type that reads no ``stream``. ``report=False`` makes no
        progress report for it.
        """
        state = self._state
        results = state.results
        tracker = state.tracker
        member_started = False
        recorded_index: int | None = None
        presented_name: str | None = None
        rewrites: frozenset[NameRewrite] = frozenset()
        current = self._current = _MemberState(staged=staged)

        def record(_error: object, failed: ExtractionResult) -> bool:
            nonlocal recorded_index
            if results and results[-1].member is failed.member:
                recorded_index = len(results) - 1
                self._set_result(recorded_index, failed)
            else:
                recorded_index = self._append_result(failed)
            return False

        def cleanup() -> None:
            self._close(stream)
            if current.parked:
                self._drop_parked_copies(original.name, recorded_index)

        with self._handling(
            original, kind=original.type.value, record=record, cleanup=cleanup
        ):
            if current_by_name is not None:
                self._park_earlier_copies(
                    original.name, current_by_name.pop(original.name, None)
                )
            # User filter sees every selected member (including non-current); the
            # is_current skip is hardwired after the filter and does not force a write
            # even if the filter returns the member.
            transformed, presented_name, rewrites = self._transform(original)
            if transformed is None:
                # Filter returned None: caller-elected exclusion — no ExtractionResult
                # (same as a selector exclusion). Still counts as processed for progress.
                pass
            elif not original.is_current:
                recorded_index = self._append_result(
                    ExtractionResult(original, None, ExtractionStatus.SUPERSEDED, None)
                )
            else:
                result_index = recorded_index = self._append_result(
                    ExtractionResult(original, None, ExtractionStatus.FAILED, None)
                )
                if current_by_name is not None:
                    current_by_name[original.name] = result_index
                if fail_with is not None and transformed.type is not MemberType.FILE:
                    raise fail_with
                if not original.is_anti and staged is None:
                    # Counted only now, once the selector, the filter and the
                    # universal check have accepted the member: a member skipped or
                    # rejected before this does not count toward max_entries.
                    tracker.start_member(original)
                    member_started = True
                    if self._on_progress is not None and report:
                        # Capture members_done for intra-member reports: members fully
                        # completed *before* this one. The outcome tallies are read
                        # live: they change only when a member completes, except that
                        # this member's REPLACE can revise an earlier result first.
                        done_so_far = members_done
                        member = original

                        def emit_progress() -> None:
                            self._report_progress(
                                member, done_so_far, tracker.member_bytes
                            )

                        current.emit_progress = emit_progress

                written = self._write_member(
                    original, transformed, stream, result_index
                )
                self._set_result(result_index, written)

        if member_started and recorded_index is not None:
            state.counted[recorded_index] = tracker.member_bytes

        # A portable rewrite is recorded on whatever result this member ended up with,
        # including a BLOCKED/FAILED one: the rewrite happened before the outcome.
        if presented_name is not None and recorded_index is not None:
            self._set_result(
                recorded_index,
                replace(
                    results[recorded_index],
                    presented_name=presented_name,
                    rewrites=rewrites,
                ),
            )

        if report:
            self._report_progress(
                original,
                members_done + 1,
                tracker.member_bytes if member_started else 0,
            )
        return recorded_index

    # --- a pass that stages its members ----------------------------------------------

    def _stage_then_place(
        self,
        reader: BaseArchiveReader,
        selector: Callable[[ArchiveMember], bool] | None,
        copies: FileCopyPass,
        listing_damage: list[CorruptionError],
    ) -> None:
        """The pass of a reader whose walk changes the members it yielded once it ends
        (``_REVISES_YIELDED_MEMBERS``: a ZIP from a pipe learns each member's type,
        mode, host and current copy only from the central directory, after the last
        member). ``safe-extraction``, "A ZIP extracted from a non-seekable source is
        settled at the end of the pass", is the contract.

        During the walk each member the selection may take is staged
        (``_stage_member``): its data goes into one private directory under the
        destination, and nothing else is written there. Once the walk has ended, the
        members are placed in listing order by ``_handle_member``, as a pass over the
        same archive from a file handles them, each FILE landing from its staged file
        by a rename.
        """
        # A member the walk can still rename or retype is selected on what it
        # becomes, so the reader yields it whatever the selection says now.
        walk_selector = None if selector is None else _final_members_only(selector)
        staging: list[_Staging] = []
        members_done = 0
        pairs = _until_listing_damage(
            reader, reader._stream_members(walk_selector, copies), listing_damage
        )
        with _closing_pass(pairs):
            for original, stream in pairs:
                # A member already final when yielded was selected by ``walk_selector``.
                entry = _Staging(original, final=original.member_state_final)
                staging.append(entry)
                if (
                    not entry.final
                    and selector is not None
                    and not _provisionally_selected(selector, original)
                ):
                    # The selection is made again on what the member becomes, at
                    # placement. Its data is not staged, and it is not counted as
                    # handled.
                    entry.reported = False
                    self._close(stream)
                    continue
                self._stage_member(entry, stream, len(staging) - 1, members_done)
                members_done += 1

        if listing_damage and any(
            listing_damage[0] is error for _, error in reader._failed_at_end
        ):
            # The walk raised for a member placement deals with: its result carries
            # the failure, unless a seekable read of the same bytes would not have
            # read the member's data either (the selection or the filter left it out,
            # the directory makes it not current, or an outcome decided before any
            # of its data was read). Then nothing reports it, as from a file.
            listing_damage.clear()

        # A current copy of a name the stream holds again later: the directory
        # reverses the two copies' order (``_placement_data``).
        later: set[str] = set()
        for entry in reversed(staging):
            name = entry.member.name
            entry.reversed = name in later and entry.member.is_current
            later.add(name)
        # The selection, made for good on what each member became. A member the walk
        # took out of the listing is not placed.
        failing = {id(member): error for member, error in reader._failed_at_end}
        yielded = {id(entry.member) for entry in staging}
        placing: list[_Staging] = []
        for entry in staging:
            member = entry.member
            if member._member_id in reader._dropped_listed or (
                not entry.final and selector is not None and not selector(member)
            ):
                self._unstage(entry, placed=False)
                continue
            placing.append(entry)
        # A member the directory lists and the stream never held.
        for member, error in reader._failed_at_end:
            if id(member) in yielded:
                continue
            if selector is not None and not selector(member):
                continue
            placing.append(_Staging(member, final=True, missing=error, reported=False))
        if isinstance(selector, CollectionSelector) and not listing_damage:
            # Every member has been offered to the selection, before any is placed,
            # as when the member list is free (``_run``).
            selector.report_unmatched(
                reader._diagnostics_collector, reader._archive_name
            )

        for entry in placing:
            self._place_member(entry, failing, members_done)
            if not entry.reported:
                members_done += 1
        if placing:
            # The outcome tallies count placed results only: one report gives them,
            # once placement ends.
            last = placing[-1]
            self._report_progress(last.member, members_done, last.staged_bytes)

    def _place_member(
        self,
        entry: _Staging,
        failing: dict[int, CorruptionError],
        members_done: int,
    ) -> None:
        """Place ``entry``'s member once the walk has ended (``_stage_then_place``), and
        drop what is left of its staged data."""
        stream, fail_with = self._placement_data(entry, failing)
        index: int | None = None
        try:
            index = self._handle_member(
                entry.member,
                stream,
                current_by_name=None,
                members_done=members_done,
                staged=entry.staged if stream is None else None,
                fail_with=fail_with,
                report=False,
            )
        finally:
            results = self._state.results
            placed = index is not None and results[index].status in (
                ExtractionStatus.EXTRACTED,
                ExtractionStatus.OVERWRITTEN,
            )
            self._unstage(entry, placed=placed)

    def _stage_member(
        self, entry: _Staging, stream: BinaryIO | None, position: int, members_done: int
    ) -> None:
        """Stage ``entry``'s member while the pass holds its data, and report it to
        ``on_progress``.

        The universal path-safety checks and the name policy run first, on the
        member as its local header names it (``_check_local_name``). A member they
        refuse is not staged; the refusal stops the run at once where ``abort_on``
        or ``OnError.STOP`` stops on it, and waits for placement otherwise. A FILE
        with data is then written to the staging directory, counted toward the bomb
        limits as any write is. A failure while it is written stops an
        ``OnError.STOP`` run at once, and is otherwise kept for placement, as is a
        refusal. A directory or an empty file stages nothing.
        """
        tracker = self._state.tracker
        original = entry.member
        started = False

        def record(error: ArchiveyError | OSError, failed: ExtractionResult) -> bool:
            if started:
                entry.error = error
            else:
                entry.refused = True
            # A failure under STOP, or a block under ``AbortOn.BLOCKED_MEMBER``, stops
            # the run now (``_stop_or_log``); anything else waits for placement, which
            # records and logs it.
            if failed.status is ExtractionStatus.FAILED:
                return not self._stops_on_failure()
            return AbortOn.BLOCKED_MEMBER not in self._abort_on

        def cleanup() -> None:
            self._close(stream)

        self._current = _MemberState()
        with self._handling(
            original, kind=original.type.value, record=record, cleanup=cleanup
        ):
            self._check_local_name(original)
            if (
                original.type is MemberType.FILE
                and original.size != 0
                and not original.is_anti
            ):
                tracker.start_member(original)
                started = True
                emit: Callable[[], None] | None = None
                if self._on_progress is not None:

                    def emit() -> None:
                        self._report_progress(
                            original, members_done, tracker.member_bytes
                        )

                try:
                    entry.staged = self._write_staged(stream, position, emit)
                except BaseException:
                    tracker.refund(tracker.member_bytes)
                    raise
                entry.staged_bytes = tracker.member_bytes
        self._report_progress(original, members_done + 1, entry.staged_bytes)

    def _check_local_name(self, original: ArchiveMember) -> None:
        """Run the universal checks and the name policy on ``original`` as its local
        header names it, before its data is staged (``_stage_member``).

        Raises the refusal, or ``NameRewrittenError`` (through ``_AbortExtraction``)
        under ``AbortOn.NAME_SANITIZED``. The directory can still make ``\\`` a
        separator (a DOS host), so a member is refused only when every name it can end
        with is refused, and aborted on for a rewrite only when every such name is
        rewritten. The caller's filter does not run: it runs once, at placement."""
        names = [original.name]
        separated = original.name.replace("\\", "/")
        if separated != original.name:
            names.append(separated)
        refusal: ExtractionError | None = None
        rewrite: NameRewrittenError | None = None
        for name in names:
            candidate = (
                original if name == original.name else original.replace(name=name)
            )
            try:
                found = self._local_name_rewrite(candidate)
            except ExtractionError as exc:
                refusal = refusal or exc
                continue
            if found is None:
                return
            rewrite = rewrite or found
        if rewrite is not None:
            raise _AbortExtraction(rewrite)
        assert refusal is not None
        raise refusal

    def _local_name_rewrite(self, member: ArchiveMember) -> NameRewrittenError | None:
        """The checks of ``_check_local_name`` on one name: raise its refusal, or
        return the error ``AbortOn.NAME_SANITIZED`` would stop on (``None`` when it
        would not), as ``_transform`` decides them without a filter."""
        transformed = POLICY_TRANSFORMS[self._policy](member)
        rerooted_from: str | None = None
        if self._policy is not ExtractionPolicy.STRICT:
            rerooted = reroot_absolute(transformed)
            if rerooted.name != transformed.name:
                rerooted_from = transformed.name
            transformed = rerooted
        dest_root = self._state.dest_root
        self._check_universal(transformed, dest_root)
        portable = apply_name_policy(transformed, self._policy)
        if portable is not transformed:
            try:
                self._check_universal(portable, dest_root)
            except ExtractionError as exc:
                _report_stored_spelling(exc, portable, transformed)
                raise
        if AbortOn.NAME_SANITIZED not in self._abort_on:
            return None
        if rerooted_from is not None:
            return NameRewrittenError(
                f"Absolute name re-rooted: {quoted(rerooted_from)} -> "
                f"{quoted(transformed.name)}",
                member_name=member.name,
            )
        if portable.name != transformed.name:
            return NameRewrittenError(
                f"Name rewritten for portability: {quoted(transformed.name)} -> "
                f"{quoted(portable.name)}",
                member_name=member.name,
            )
        return None

    def _write_staged(
        self,
        stream: BinaryIO | None,
        position: int,
        emit_progress: Callable[[], None] | None,
    ) -> Path:
        """Write a member's data from ``stream`` to the staging directory, under its
        position in the pass, and return where; on any failure nothing of it stays.

        The directory is ``.archivey-tmp-`` and a random suffix, directly under the
        destination, created private on the first call. Each file is created at the
        ordinary creation mode, which a placed file without a stored mode keeps
        (``_write_file_atomic``). A dry run creates the file empty, as it creates
        every file."""
        state = self._state
        if state.staging is None:
            staging = self._temp_sibling(state.dest)
            os.mkdir(long_path(staging), 0o700)
            state.staging = staging
        # Every check that could still skip the member has passed, so a member whose
        # recorded size is already over the ratio is refused before its data is read.
        state.tracker.check_recorded_size()
        path = state.staging / str(position)
        fd = _open_new_file(path, 0o666)
        try:
            with os.fdopen(fd, "wb") as dst:
                self._copy_to_fileobj(
                    stream,
                    dst if self._dry is None else self._dry.sink,
                    state.tracker,
                    emit_progress=emit_progress,
                )
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(long_path(path))
            raise
        return path

    def _placement_data(
        self, entry: _Staging, failing: dict[int, CorruptionError]
    ) -> tuple[BinaryIO | None, ArchiveyError | OSError | None]:
        """The data ``_handle_member`` places ``entry``'s member from, and the error
        that fails it where it reads none, as ``(stream, fail_with)``. A ``None``
        stream with a staged file means the staged file.

        The data stands in for what a pass over the same archive from a file reads.
        A stream that raises (``_PassedData``) raises only when the write reads it,
        so the overwrite policy decides first:

        - A member with no local entry raises the walk's error where it reads data.
        - Any other member the end of the walk fails (``_failed_at_end``) raises the
          walk's error, whatever its type and whatever it staged.
        - The current copy of a name the stream holds again after it (the directory
          reverses the two copies' order) raises ``CorruptionError`` unless it is
          empty, as the archive contradicts itself.
        - A member whose staging failed raises that failure; a link among them fails
          with it too, as its target came from the data that failed.
        - A member with a staged file is placed from it.
        - A member that needs no bytes (a directory, a link, an empty file) needs no
          data.
        - Any other member's data went by unstaged: its local header's name was
          refused, or the selection left it out during the pass.
        """
        member = entry.member
        is_file = member.type is MemberType.FILE
        missing = entry.missing
        if missing is not None:
            return (_passed_data(missing) if is_file else None), None
        failed = failing.get(id(member))
        if failed is not None:
            return (_passed_data(failed) if is_file else None), failed
        if entry.reversed and is_file and member.size != 0:
            return (
                _passed_data(
                    CorruptionError(
                        f"The archive's directory makes {quoted(member.name)} the "
                        "current copy of its name, though the stream holds a later "
                        "copy",
                        member_name=member.name,
                    )
                ),
                None,
            )
        if entry.error is not None:
            if is_file:
                return _passed_data(entry.error), None
            return None, entry.error if member.type is MemberType.SYMLINK else None
        if entry.staged is not None or not is_file:
            return None, None
        if member.size == 0:
            return io.BytesIO(), None
        why = (
            "its local header's name was refused"
            if entry.refused
            else "the archive's directory changed the member"
        )
        return (
            _passed_data(
                ExtractionError(
                    f"The data of {quoted(member.name)} was passed before {why}, "
                    "and was not kept",
                    member_name=member.name,
                )
            ),
            None,
        )

    def _unstage(self, entry: _Staging, *, placed: bool) -> None:
        """Remove ``entry``'s staged file if it is still there, and stop counting what
        the bomb limits counted for it: its bytes, and its entry too unless its member
        was ``placed`` (a link placed without its data). The archive-wide ratio keeps
        its bytes: they were decoded."""
        staged = entry.staged
        if staged is None:
            return
        entry.staged = None
        if not os.path.lexists(long_path(staged)):
            # Landed: it is the member's file now.
            return
        self._state.tracker.refund(entry.staged_bytes, entry=not placed)
        with contextlib.suppress(OSError):
            os.chmod(long_path(staged), stat.S_IREAD | stat.S_IWRITE)
        with contextlib.suppress(OSError):
            os.unlink(long_path(staged))

    def _remove_staging(self) -> None:
        """Remove the staging directory and whatever is left in it, when the run ends.
        Each entry is made writable first, as a stored mode can leave a staged file
        read-only, which Windows refuses to remove. A removal the filesystem refuses
        leaves the directory, with a warning naming it: it is safe to delete."""
        state = self._state
        staging = state.staging
        if staging is None:
            return
        state.staging = None
        root = long_path(staging)
        try:
            with os.scandir(root) as entries:
                names = [entry.name for entry in entries]
            for name in names:
                path = os.path.join(root, name)
                with contextlib.suppress(OSError):
                    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
                os.unlink(path)
            os.rmdir(root)
        except OSError as exc:
            self._rebase_os_error(exc)
            logger.warning(
                "Could not remove %r, where the members were staged before the "
                "archive's directory was read: %s",
                str(self._shown(staging)),
                exc,
            )

    def _park_earlier_copies(self, name: str, earlier: int | None) -> None:
        """Park every earlier non-directory copy of ``name`` still on disk for the
        member of that name now being handled (streaming only): result ``earlier``,
        taken back now, and any an earlier take-back could not remove, unless another
        member has since replaced it under its own claim. A superseded directory is
        never parked; see ``_supersede_written_copy``.

        Random access never writes a shadowed copy; a streaming pass finds out only
        when the later copy arrives. A parked path counts as free (``_occupied``,
        ``_prepare_destination``), so the member replaces it atomically under any
        overwrite policy, and ``_drop_parked_copies`` removes the rest afterwards.
        """
        state = self._state
        parked = self._current.parked
        for path, index in state.unremoved.pop(name, {}).items():
            claim = state.collision_map.get(self._claimed_key(path))
            if claim is not None and claim.path == path and claim.result_index == index:
                parked[path] = index
                self._release_claim(path)
        if earlier is not None:
            self._supersede_written_copy(earlier)

    def _supersede_written_copy(self, index: int) -> None:
        """Take back an earlier copy of a name the archive holds again (streaming only).

        The earlier result becomes ``SUPERSEDED`` here, before the later copy is
        filtered: random access supersedes it whatever then happens to the later copy.
        Its file is parked (see ``_park_earlier_copies``). Its claim, its place in the
        hardlink source lists and its bomb-limit counts are released now. A hardlink
        already made to it is its own directory entry and stays, and its bytes stay
        counted against the byte cap while it holds them. A directory is removed now if
        it is empty; one that other members were written into stays, as their parent,
        as it would in random access. An orphaned hardlink waiting on the second pass
        is dropped with the result it would fill. An error recorded on the earlier
        result is dropped with it: random access never tried that copy.
        """
        self._take_back_written(index)
        prior = self._state.results[index]
        self._set_result(
            index,
            ExtractionResult(
                prior.member,
                None,
                ExtractionStatus.SUPERSEDED,
                None,
                presented_name=prior.presented_name,
                rewrites=prior.rewrites,
            ),
        )

    def _take_back_written(self, index: int) -> None:
        """Undo what result ``index`` put on disk and counted, for a member a streaming
        pass wrote and must now handle otherwise (``_supersede_written_copy``); the
        caller records its new result.

        A file is parked in ``_current``, a directory removed when empty, and the
        claim, hardlink-source entries and bomb-limit counts are released.
        """
        state = self._state
        prior = state.results[index]
        path = prior.path
        # Whether another directory entry still holds the earlier copy's content: a
        # hardlink made to it before the later copy arrived.
        content_kept = False
        if (
            prior.status is ExtractionStatus.EXTRACTED
            and path is not None
            and path in state.written_paths
        ):
            self._release_claim(path)
            content_kept = self._forget_source_path(path)
            on_disk = long_path(path)
            if os.path.isdir(on_disk) and not os.path.islink(on_disk):
                # Random access never writes the superseded copy, so its metadata
                # is not applied, whether or not the directory stays as a parent.
                self._drop_pending_dir(path)
                with contextlib.suppress(OSError):  # not empty: members live under it
                    os.rmdir(on_disk)
                    state.written_paths.discard(path)
            else:
                state.written_paths.discard(path)
                self._current.parked[path] = index
        if index in state.counted:
            member_bytes = state.counted.pop(index)
            state.tracker.refund(0 if content_kept else member_bytes)
        state.orphans[:] = [o for o in state.orphans if o.result_index != index]

    def _drop_parked_copies(self, name: str, result_index: int | None) -> None:
        """Remove each parked copy of ``name`` unless the member just handled, recorded
        at ``result_index``, landed on it.

        A removal the filesystem refuses is logged, not raised: this runs in a
        ``finally``, where raising would replace the member's own error. The entry is
        then still the run's own, so it goes back into ``written_paths`` (an anti-item
        can still delete it) and into the collision map (a different name on the same
        key still collides with it), and is held in ``unremoved`` for the next member
        of the same name. Its claim points at its ``SUPERSEDED`` result, which
        ``_mark_overwritten`` leaves as it is.
        """
        state = self._state
        parked, self._current.parked = self._current.parked, {}
        latest = state.results[result_index] if result_index is not None else None
        # Only a path the member wrote: an anti-item also reports EXTRACTED at its
        # name, but writes nothing there.
        landed = (
            latest.path
            if latest is not None
            and latest.status is ExtractionStatus.EXTRACTED
            and latest.path in state.written_paths
            else None
        )
        for path, index in parked.items():
            if path == landed:
                continue
            if os.path.islink(long_path(path)):
                self._note_link_change(path)
            try:
                with self._readonly_cleared(path, ours=True):
                    os.unlink(long_path(path))
            except FileNotFoundError:
                state.written_paths.discard(path)
            except OSError as exc:
                self._rebase_os_error(exc)
                logger.warning(
                    "Could not remove superseded %r: %s", str(self._shown(path)), exc
                )
                state.written_paths.add(path)
                self._claim(path, index)
                state.unremoved.setdefault(name, {})[path] = index
            else:
                state.written_paths.discard(path)

    def _is_callers_entry(self, path: Path, st: os.stat_result) -> bool:
        """Whether the entry at ``path`` (``st`` its ``lstat``) was there before this
        run, rather than written or created by it."""
        state = self._state
        if path in state.written_paths or path in state.created_dirs:
            return False
        return not (stat.S_ISDIR(st.st_mode) and self._is_run_directory(path, st))

    def _occupied(self, path: Path) -> bool:
        """Whether ``path`` holds an entry, not counting a parked superseded copy."""
        return path not in self._current.parked and os.path.lexists(long_path(path))

    # --- selection / transform -----------------------------------------------------

    def _as_written(
        self, original: ArchiveMember, transformed: ArchiveMember
    ) -> ArchiveMember:
        """``transformed``, or the SYMLINK it is written as when ``original`` is a hard
        link to a symlink member, through any number of hard links.

        A hard link to a symlink is a second name for the symlink itself, which is what
        GNU tar creates. So the member is written as a symlink with the same target, read
        from its own directory, and goes through the same checks as any symlink. It runs
        after the caller's filter, which sees the HARDLINK the archive lists, and only
        when the filter kept it a HARDLINK.
        """
        if (
            original.type is not MemberType.HARDLINK
            or transformed.type is not MemberType.HARDLINK
        ):
            return transformed
        direct = self._hardlink_chain_end(self._state.reader, original)
        if (
            direct is None
            or direct.type is not MemberType.SYMLINK
            or direct.link_target is None
        ):
            return transformed
        return transformed.replace(
            type=MemberType.SYMLINK,
            link_target=direct.link_target,
            link_target_member=direct.link_target_member,
        )

    def _hardlink_chain_end(
        self, reader: BaseArchiveReader, member: ArchiveMember
    ) -> ArchiveMember | None:
        """The first member that is not a HARDLINK on ``member``'s hard-link chain, or
        ``None`` for a cycle or a dead end.

        Memoized by ``_member_id`` for every link on the walked path, as
        ``BaseArchiveReader._resolve_link`` does, so a chain of N hard links costs O(N)
        lookups in total rather than O(N²). A lookup depends only on the node it starts
        at, so the links on one path share its end, and no answer changes during the
        run: ``_hardlink_direct_target`` only looks backward.
        """
        ends = self._state.hardlink_ends
        path: list[int] = []
        on_path: set[int] = set()
        end: ArchiveMember | None
        current = member
        while True:
            if current.type is not MemberType.HARDLINK:
                end = current
                break
            member_id = current._member_id
            if member_id is None:
                end = None
                break
            if member_id in ends:
                end = ends[member_id]
                break
            if member_id in on_path:
                end = None
                break
            path.append(member_id)
            on_path.add(member_id)
            target = reader._hardlink_direct_target(current)
            if target is None:
                end = None
                break
            current = target
        for member_id in path:
            ends[member_id] = end
        return end

    def _transform(
        self, original: ArchiveMember
    ) -> tuple[ArchiveMember | None, str | None, frozenset[NameRewrite]]:
        """Policy transform and user filter on a transient copy, then the universal check
        on the result.

        Returns ``(member_to_write, presented_name, rewrites)`` — the member is ``None``
        if the user filter skipped it, ``presented_name`` is the full name before a
        safety rewrite (the absolute-name re-root or the portable-name policy) when one
        reaches disk, else ``None``, and ``rewrites`` names each safety rewrite that
        reached disk (empty exactly when ``presented_name`` is ``None``). Raises a
        ``FilterRejectionError`` on a universal violation."""
        transformed = POLICY_TRANSFORMS[self._policy](original)
        # The re-root comes before the filter so the filter sees the name that would be
        # written, as it already sees the policy's permission changes, and a filter
        # need not strip roots itself under STANDARD or TRUSTED. Whether the re-root
        # counts as a rewrite is decided after the filter, like the portable one: a
        # member the filter drops or renames never reaches disk under the re-rooted name.
        rerooted_from: str | None = None
        if self._policy is not ExtractionPolicy.STRICT:
            rerooted = reroot_absolute(transformed)
            if rerooted.name != transformed.name:
                rerooted_from = transformed.name
            transformed = rerooted
        rerooted_name = transformed.name
        # The filter runs before the universal check, so it sees every member, the
        # unsafe ones included, and can rename one to something safe. Whatever it
        # returns is what gets checked and written.
        if self._filter is not None:
            # The filter is told, as a predicate is, when the walk can still change
            # the member (``member_state_final``): it may see the member again.
            transformed._listing_pending = original._listing_pending
            filtered = self._filter(transformed)
            if filtered is None:
                return None, None, frozenset()
            if not isinstance(filtered, ArchiveMember):
                # A caller bug, so a TypeError that ends the call rather than a
                # per-member result; it names what came back, which the attribute
                # error from the first use of it did not.
                raise _UsageTypeError(
                    f"filter= must return an ArchiveMember or None, not "
                    f"{type(filtered).__name__} (for member {quoted(original.name)})"
                )
            transformed = filtered
            if transformed.name != rerooted_name:
                rerooted_from = None  # the filter chose this name; it is not a rewrite
        transformed = self._as_written(original, transformed)
        # Read after `_as_written`: a hard link to a symlink is now the SYMLINK it is
        # a second name for, which copies no bytes and gets the symlink checks below.
        kept_hardlink = (
            original.type is MemberType.HARDLINK
            and transformed.type is MemberType.HARDLINK
        )
        dest_root = self._state.dest_root
        # The checks run on the name that reaches disk; the name policy below runs on
        # the stored one, so its escape of a lone surrogate is the same on every OS.
        self._check_universal(transformed, dest_root)
        if kept_hardlink and self._source_refused(original):
            raise FilterRejectionError(
                "Hardlink target was refused",
                member_name=original.name,
                link_target=original.link_target,
            )
        reader = self._state.reader
        if self._needs_target_read(original, transformed):
            # A symlink whose target the format keeps in member data and nothing has
            # read yet (`read_link_targets=False`), or one whose read failed and was
            # reported as damaged, which leaves it unresolved: this read raises the
            # fault again and fails the member. The selector and the filter have now
            # both accepted it, with `link_target=None`, so reading it here is the
            # read the caller asked for (`archive-reading`, "Link targets stored as
            # member data are read only when configured").
            reader._read_link_target_on_request(original)
            if original.type is not MemberType.SYMLINK:
                # The data showed the member is not a link: a reparse-flagged member
                # whose data is no reparse buffer, re-typed to its fallback as listing
                # would have. Everything above decided on a member that did not exist,
                # so decide again on the real one, the filter included.
                self._current.retyped = True
                return self._transform(original)
            if original.link_target is not None:
                # The filter decided on a link with no target. Decide again with the
                # target, so a filter that rewrites targets (`sanitize_names`) sees
                # it, and the link gets the outcome it gets when listing read the
                # target. The target is now set, so this runs once.
                return self._transform(original)
        # Portable-name policy on the FINAL name — after the user filter, so a filter rename
        # is checked too, and TRUSTED keeps faithful bytes. Reserved names, ':' and a segment
        # of only dots/spaces are rejected; a trailing dot/space (STRICT) or
        # non-representable byte is rewritten to a portable spelling, recorded on the
        # result so the rename is not silent.
        if rerooted_from is not None and AbortOn.NAME_SANITIZED in self._abort_on:
            raise _AbortExtraction(
                NameRewrittenError(
                    f"Absolute name re-rooted: {quoted(rerooted_from)} -> "
                    f"{quoted(transformed.name)}",
                    member_name=original.name,
                )
            )
        portable = apply_name_policy(transformed, self._policy)
        if portable is not transformed:
            # The rewrite can change which directories the path passes through: a
            # "\\" becomes a separator, and "foo. /x" becomes "foo/x". The parent
            # checked above is then not the parent written to, so check again. A
            # symlink "foo" that leaves the destination is refused here.
            try:
                self._check_universal(portable, dest_root)
            except ExtractionError as exc:
                _report_stored_spelling(exc, portable, transformed)
                raise
        on_disk = disk_spelled(portable)
        if on_disk is not portable:
            self._current.spelled_from = portable
        reroot_rewrite = (
            frozenset({NameRewrite.REROOTED})
            if rerooted_from is not None
            else frozenset()
        )
        if portable.name == transformed.name:
            return on_disk, rerooted_from, reroot_rewrite
        # The pre-rewrite spelling is the caller filter's output when there is one, which
        # is why it cannot be reconstructed from ``member.name`` and ``path`` alone.
        if AbortOn.NAME_SANITIZED in self._abort_on:
            raise _AbortExtraction(
                NameRewrittenError(
                    f"Name rewritten for portability: {quoted(transformed.name)} -> "
                    f"{quoted(portable.name)}",
                    member_name=original.name,
                )
            )
        # After a re-root, the stored name is the one the caller will recognise.
        return (
            on_disk,
            rerooted_from or transformed.name,
            reroot_rewrite | {NameRewrite.PORTABLE_NAME},
        )

    def _source_refused(self, link: ArchiveMember) -> bool:
        """Whether the member a HARDLINK gets its bytes from was refused, so the link
        is refused too.

        A hard link's target is a member name, never a path, so it gets no path check
        of its own (``check_universal``); but the second pass can write a refused
        source's bytes under the link's name. So a link is refused when its source is,
        in both access modes and at every policy.

        The source is ``link_target_member``, the end of the link chain (symlinks
        included). A refused link in the middle of the chain does not refuse this one,
        which does not use that link's name. A chain that ends at a SYMLINK refuses
        nothing: that symlink has no target (``_as_written`` wrote the link as any
        symlink that has one), the link copies no bytes, and ``_write_hardlink`` fails
        it as a link to a non-file. Hard links point only backward, so this run has
        already reached the source. When it recorded a result for it, ``BLOCKED`` is a
        refusal and anything else is not: the caller's filter decides through the name
        it gave the source. A source with no result was left out by the selector or the
        filter, and the policy's own steps run on it as listed (``_policy_refuses``).
        The caller's filter does not run on it, since a member the selector left out
        was never meant to reach the filter. A refused source's links are refused; any
        other source left out is recovered by the second pass, or fails the link on a
        forward-only stream (``_write_hardlink``).
        """
        state = self._state
        source = link.link_target_member
        if source is None or source._member_id is None:
            # No source: `_write_hardlink` fails the link as not found.
            return False
        if source.type is MemberType.SYMLINK:
            # A targetless symlink: no bytes to refuse.
            return False
        member_id = source._member_id
        index = state.result_ids.get(member_id)
        if index is not None:
            return state.results[index].status is ExtractionStatus.BLOCKED
        refused = state.refusals.get(member_id)
        if refused is None:
            # Memoized, so N links to one excluded source run its checks once.
            refused = state.refusals[member_id] = self._policy_refuses(source)
        return refused

    def _policy_refuses(self, member: ArchiveMember) -> bool:
        """Whether this run's policy would refuse ``member`` as listed, without the
        caller's filter: the absolute-name re-root, the universal checks and the name
        policy, as ``_transform`` runs them. Only a ``FilterRejectionError`` is a
        refusal; a member whose parent cannot be resolved has failed, not been refused.
        ``member`` is the end of a link chain and not a link itself, which
        ``_as_written`` never rewrites, so this skips that step. The check goes
        through ``_check_universal``, so a dry run copies in what dest holds along
        the very name it checks, which a link's own target does not name when the
        link names another link."""
        candidate = member
        if self._policy is not ExtractionPolicy.STRICT:
            candidate = reroot_absolute(candidate)
        try:
            self._check_universal(candidate, self._state.dest_root)
            apply_name_policy(candidate, self._policy)
        except FilterRejectionError:
            return True
        except ExtractionError:
            return False
        return False

    def _check_universal(self, member: ArchiveMember, dest_root: Path) -> None:
        """``check_universal`` on the disk spelling, reporting the stored names.

        Every name that reaches disk is checked here first, so a dry run copies in
        what dest holds along it here (``DryRun.bring_in``), before anything of the
        pass looks at the scratch tree there."""
        on_disk = disk_spelled(member)
        if self._dry is not None:
            self._dry.bring_in(on_disk)
        try:
            check_universal(
                on_disk,
                dest_root,
                link_target_on_disk=self._on_disk,
                show_os_error=self._rebase_resolved_os_error,
            )
        except ExtractionError as exc:
            if on_disk is not member:
                _report_stored_spelling(exc, on_disk, member)
            raise

    @staticmethod
    def _needs_target_read(original: ArchiveMember, transformed: ArchiveMember) -> bool:
        """Whether a link about to be written still needs its target read.

        Only a current symlink the caller's filter left targetless and whose target
        nobody has looked for yet: a superseded member is not written, and a target the
        filter supplied is the one to write.
        """
        return (
            original.type is MemberType.SYMLINK
            and original.is_current
            and original.link_target is None
            and not original._link_target_resolved
            and transformed.link_target is None
        )

    # --- per-member write ----------------------------------------------------------

    def _write_member(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        stream: BinaryIO | None,
        result_index: int,
    ) -> ExtractionResult:
        requested = self._state.dest / transformed.name
        self._current.requested_path = requested
        target = self._follow_renamed_dirs(
            requested, is_dir=transformed.type == MemberType.DIRECTORY
        )

        if original.is_anti:
            return replace(
                self._apply_anti_item(original, target), requested_path=requested
            )

        dest_path, prior, collided_with = self._resolve_collision(
            original, transformed, target
        )
        # Stashed for the failure handler: an ERROR-policy collision becomes a FAILED
        # result built there, and it has to carry the collision too.
        self._current.collided_with = collided_with

        try:
            result = self._dispatch_write(
                original, transformed, stream, dest_path, result_index
            )
        except (ArchiveyError, OSError):
            # A write that failed after clearing the destination (only the non-atomic
            # landings clear it first) has still removed the earlier member's content,
            # so that member's result must stop reporting it EXTRACTED. This member's
            # own result is recorded by the caller's handler.
            if self._current.removed_existing:
                self._mark_overwritten(prior)
            raise

        return self._settle_placement(
            result,
            requested=requested,
            target=target,
            prior=prior,
            collided_with=collided_with,
            transformed=transformed,
            result_index=result_index,
        )

    def _settle_placement(
        self,
        result: ExtractionResult,
        *,
        requested: Path,
        target: Path,
        prior: _Claim | None,
        collided_with: Path | None,
        transformed: ArchiveMember,
        result_index: int,
    ) -> ExtractionResult:
        """``result`` with its collision recorded, once the claims and earlier results
        it affects are updated. Both passes; the caller records what it returns.

        ``requested`` is the path the member asked for, ``target`` the path collision
        resolution started from: ``requested`` moved under a renamed directory
        (``_follow_renamed_dirs``), or ``requested`` itself."""
        # Record the intended destination. A REPLACE merge into a prior path is not a
        # rename, so it reports the actual (merged) path; every other outcome reports the
        # member's own intended destination, so RENAME shows up as requested_path != path.
        if prior is not None and result.status is ExtractionStatus.EXTRACTED:
            result = replace(
                result, requested_path=result.path, collided_with=collided_with
            )
        else:
            result = replace(
                result, requested_path=requested, collided_with=collided_with
            )

        # A REPLACE that actually landed leaves the earlier member's content gone. Revise
        # that member's already-recorded result to OVERWRITTEN so the merge is visible in
        # ``results`` instead of two members both reporting EXTRACTED at one path.
        if result.status is ExtractionStatus.EXTRACTED:
            self._mark_overwritten(prior)
            if transformed.type == MemberType.DIRECTORY and result.path is not None:
                self._state.written_dirs.setdefault(
                    self._collision_key(result.path), []
                ).append(result_index)
                # Written under a derived name rather than merged into a prior path:
                # members inside it follow it there.
                if prior is None and result.path != target:
                    self._state.renamed_dirs[requested] = result.path

        self._register_collision_key(transformed, result, result_index)
        return result

    def _dispatch_write(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        stream: BinaryIO | None,
        dest_path: Path,
        result_index: int,
    ) -> ExtractionResult:
        written_paths = self._state.written_paths
        if transformed.type == MemberType.DIRECTORY:
            existed = self._occupied(dest_path)
            callers = self._is_callers_directory(dest_path)
            if not self._make_room_for_parents(
                transformed, dest_path
            ) or not self._prepare_destination(transformed, dest_path):
                return ExtractionResult(
                    original, None, ExtractionStatus.NOT_OVERWRITTEN, None
                )
            try:
                self._makedirs(dest_path, transformed)
            except FileExistsError as exc:
                # A non-directory took the name after the existence check, as for the
                # other landings (``_taken_after_check``). Only this call: a parent
                # that turned into a file is not this member's name being taken.
                if not self._taken_after_check(dest_path, atomic=False):
                    raise
                raise self._already_exists(dest_path, transformed) from exc
            kept_mode: int | None = None
            if callers:
                # A directory the caller already had, the destination root included
                # (a `./` member): it keeps its own mode and times. Applying the
                # member's would widen a private 0o700 directory to the policy's
                # 0o755, or to a world-writable 0o777 under STANDARD. GNU tar has
                # the same rule as --no-overwrite-dir.
                wanted = self._effective_mode(transformed)
                current = stat.S_IMODE(os.stat(long_path(dest_path)).st_mode)
                if wanted is not None and _dir_mode_as_stored(wanted) != current:
                    kept_mode = current
            else:
                self._defer_directory_metadata(dest_path, transformed)
            if not existed:
                written_paths.add(dest_path)
                self._note_run_directory(dest_path)
            return ExtractionResult(
                original,
                dest_path,
                ExtractionStatus.EXTRACTED,
                None,
                kept_mode=kept_mode,
            )

        if transformed.type == MemberType.SYMLINK:
            result = self._write_symlink(original, transformed, dest_path)
        elif transformed.type == MemberType.HARDLINK:
            result = self._write_hardlink(
                original, transformed, dest_path, result_index
            )
        elif transformed.type == MemberType.FILE:
            result = self._write_file(original, transformed, stream, dest_path)
        else:
            # MemberType.OTHER is rejected by check_universal; nothing else should
            # reach here.
            raise ExtractionError(
                f"Unsupported member type {transformed.type!r}",
                member_name=transformed.name,
            )
        if result.status is ExtractionStatus.EXTRACTED and result.path is not None:
            written_paths.add(result.path)
            if (
                transformed.type == MemberType.SYMLINK
                and transformed.link_target is not None
            ):
                on_disk = self._link_target_on_disk(transformed.link_target)
                self._state.links.track(result.path, on_disk, result_index)
                if on_disk != transformed.link_target:
                    # An error names the target as stored, not with the separators
                    # or dry-run path written to disk.
                    self._state.stored_targets[result_index] = transformed.link_target
                spelled_from = self._current.spelled_from
                if spelled_from is not None and spelled_from.link_target is not None:
                    self._state.stored_targets[result_index] = spelled_from.link_target
        return result

    def _make_room(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        dest_path: Path,
        *,
        atomic: bool,
    ) -> ExtractionResult | None:
        """Apply the OverwritePolicy at ``dest_path`` and create its parents; the
        result if the policy declines, else ``None``. A check that skips the member
        comes first, so it cannot remove an entry under ``OverwritePolicy.REPLACE``.
        A parent the caller holds as a non-directory is handled first, as an explicit
        directory entry there would be (``_make_room_for_parents``). That keeps the
        rule across both calls: the parent's own skip check runs before it removes
        anything, and once it has replaced the parent nothing is left at
        ``dest_path`` for ``_prepare_destination`` to skip."""
        if not self._make_room_for_parents(
            transformed, dest_path
        ) or not self._prepare_destination(transformed, dest_path, atomic=atomic):
            return ExtractionResult(
                original, None, ExtractionStatus.NOT_OVERWRITTEN, None
            )
        self._makedirs(dest_path.parent, transformed)
        return None

    def _resolve_collision(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        requested: Path,
    ) -> tuple[Path, _Claim | None, Path | None]:
        """Resolve an O2 name collision, returning
        ``(dest_path, redirected_from, collided_with)``.

        ``redirected_from`` is the prior claim when this member was routed onto an
        already-written destination (so the caller can revise that member's result), and
        ``None`` otherwise — including under RENAME, which writes somewhere fresh.

        ``collided_with`` is the prior path whenever a collision *event* occurred, which
        is the wider set: RENAME collides and then avoids the destination, so it reports
        a path here while reporting no redirection. A collision event is a claim held by
        this run, outside TRUSTED. A pre-existing on-disk obstacle is not one, and
        reports ``None``.

        Directories are structural (parents recur, entries merge) and are never claimed
        in the map, so a directory member landing on a real directory merges into it.
        A non-directory member landing on a directory this run wrote or created as a
        parent still collides with it (``_run_directory_at``): ``collided_with`` and the
        abort apply, and the policy then meets the directory as it would any other.
        One landing on an entry that is not a real directory (a file or a symlink) goes
        through the same resolution as any other member: under every policy it collides
        with a claim this run holds there, so ``collided_with``, the abort and a REPLACE
        revision of the earlier member work as they do for files. Under RENAME it gets a
        ``name (N)`` too, as removing that entry would lose it, and the members inside it
        follow it there (``_follow_renamed_dirs``). For a tracked member whose key is
        already claimed THIS run, a collision is deterministic on every OS: route
        ERROR/SKIP/REPLACE to the prior path so the existing OverwritePolicy machinery
        handles it uniformly, or derive a fresh ``name (N)`` under RENAME. TRUSTED keys
        on the exact name and defers to the local OS (no collision *event*, but RENAME
        still uses the map to avoid re-deriving names). Shared by the main pass and the
        orphan second pass so deferred hardlinks honour the map too.

        Under RENAME, a parent of ``requested`` that the caller holds as a file or a
        symlink first moves ``requested`` under a derived name for that parent
        (``_rename_callers_parent``).
        """
        if self._overwrite is OverwritePolicy.RENAME:
            requested = self._rename_callers_parent(requested)
        if transformed.type == MemberType.DIRECTORY and not self._blocks_directory(
            requested
        ):
            return requested, None, None
        prior = self._state.collision_map.get(self._collision_key(requested))
        if prior is None and self._policy is not ExtractionPolicy.TRUSTED:
            # TRUSTED reports no collision event (``collided`` below), so an alias
            # found there would change nothing; the guard saves its ``lstat``.
            prior = self._alias_claim(requested)
        collided = (
            prior.path
            if prior is not None and self._policy is not ExtractionPolicy.TRUSTED
            else None
        )
        if (
            collided is None
            and transformed.type != MemberType.DIRECTORY
            and self._policy is not ExtractionPolicy.TRUSTED
        ):
            collided = self._run_directory_at(requested)
        if collided is not None:
            self._check_collision_abort(original, collided, directory=prior is None)
        if self._overwrite is OverwritePolicy.RENAME:
            if prior is not None or self._occupied(requested):
                is_dir = transformed.type == MemberType.DIRECTORY
                free = self._derive_free_name(requested, is_dir=is_dir)
                return free, None, collided
            return requested, None, None
        if prior is not None and collided is not None:
            return prior.physical, prior, collided
        # A directory of this run (``collided``, set) is met where it is, by name.
        return requested, None, collided

    def _run_directory_at(self, path: Path) -> Path | None:
        """The directory this run wrote or created as a parent at ``path``, under any
        spelling that reaches it (``_is_run_directory``), or ``None``.

        Returned as the directory member's result reports it when one wrote it, so a
        caller joins ``collided_with`` to that result by path; a directory the run
        only created as a parent has no result, and is returned as ``path``."""
        state = self._state
        # Every directory the run created on disk is in ``run_dirs``: a run that made
        # none under this key pays no ``lstat``. A directory that was already in
        # ``dest`` is not there, even when a DIRECTORY member of this run merged into
        # it and reports it: it is the caller's, so landing on it is no collision.
        if not state.run_dirs.get(self._physical_key(path)):
            return None
        try:
            st = os.lstat(long_path(path))
        except (OSError, ValueError):
            return None
        if not stat.S_ISDIR(st.st_mode) or not self._is_run_directory(path, st):
            return None
        # The key is casefolded, so on a case-sensitive filesystem it can also cover
        # another directory (``X/`` beside ``x/``): only the same directory counts.
        for index in reversed(state.written_dirs.get(self._collision_key(path), ())):
            written = state.results[index].path
            if written is None:
                continue
            if written == path:
                return written
            with contextlib.suppress(OSError, ValueError):
                if os.path.samestat(st, os.lstat(long_path(written))):
                    return written
        return path

    def _callers_parent(self, path: Path) -> Path | None:
        """The parent of ``path`` under the destination that the caller holds as an
        entry that is not a directory (a file, or a symlink that does not resolve to
        a directory), or ``None``. Only the nearest to the destination can exist: the
        directories below it are not there yet.

        The member implies that parent as a directory, and it meets OverwritePolicy as
        an explicit directory entry would (``_make_room_for_parents``). One the run
        wrote is not the caller's: ``_makedirs`` fails the member with an error that
        names it."""
        dest = self._state.dest
        parent = path.parent
        if (
            parent == dest
            or parent in self._state.created_dirs
            or os.path.isdir(long_path(parent))
        ):
            # The common case: a directory this run made (``created_dirs`` drops
            # one the run removes), else one stat.
            return None
        try:
            parts = parent.relative_to(dest).parts
        except ValueError:
            return None
        probe = dest
        for part in parts:
            probe = probe / part
            try:
                st = os.lstat(long_path(probe))
            except (OSError, ValueError):
                return None
            if stat.S_ISDIR(st.st_mode) or (
                stat.S_ISLNK(st.st_mode) and os.path.isdir(long_path(probe))
            ):
                continue
            if probe in self._current.parked or not self._is_callers_entry(probe, st):
                return None
            return probe
        return None

    def _rename_callers_parent(self, requested: Path) -> Path:
        """``requested`` moved under a derived name for its parent that the caller
        holds as a non-directory (``_callers_parent``), as RENAME writes an explicit
        directory entry there: ``foo/x`` -> ``foo (1)/x``. The later members inside
        it follow it (``_follow_renamed_dirs``), so the name is derived once."""
        blocked = self._callers_parent(requested)
        if blocked is None:
            return requested
        renamed_dirs = self._state.renamed_dirs
        renamed = renamed_dirs.get(blocked)
        if renamed is None:
            renamed = renamed_dirs[blocked] = self._derive_free_name(
                blocked, is_dir=True
            )
        return renamed / requested.relative_to(blocked)

    def _make_room_for_parents(self, member: ArchiveMember, path: Path) -> bool:
        """Apply OverwritePolicy to a parent of ``path`` that the caller holds as a
        non-directory (``_callers_parent``), as for an explicit directory entry
        there: ERROR raises, SKIP returns False, REPLACE removes the entry and returns
        True. RENAME moved ``path`` away from it already
        (``_rename_callers_parent``)."""
        blocked = self._callers_parent(path)
        if blocked is None:
            return True
        return self._prepare_destination(member, blocked)

    def _blocks_directory(self, path: Path) -> bool:
        """Whether ``path`` holds an entry that is not a real directory: a file or a
        symlink (to a directory too, as it is never written through), which a directory
        member cannot merge into."""
        if not self._occupied(path):
            return False
        try:
            return not stat.S_ISDIR(os.lstat(long_path(path)).st_mode)
        except (OSError, ValueError):
            return False

    def _follow_renamed_dirs(self, requested: Path, *, is_dir: bool) -> Path:
        """``requested`` moved under the derived name of the nearest directory RENAME
        wrote elsewhere (``dd/f`` -> ``dd (1)/f``), or unchanged when none contains it.

        Only a directory member also matches itself: a second ``dd/`` merges into
        ``dd (1)/`` as directories always merge, which a streaming pass needs because
        the first copy is still in place, superseded, when the second arrives. A file
        that only shares the renamed directory's name is not inside it, and resolves
        its own collision from the name it asked for (``dd (2)``, not ``dd (1) (1)``)."""
        renamed_dirs = self._state.renamed_dirs
        if not renamed_dirs:
            return requested
        candidates = (requested, *requested.parents) if is_dir else requested.parents
        for ancestor in candidates:
            renamed = renamed_dirs.get(ancestor)
            if renamed is not None:
                return renamed / requested.relative_to(ancestor)
        return requested

    @contextlib.contextmanager
    def _handling(
        self,
        member: ArchiveMember,
        *,
        kind: str,
        record: Callable[[ArchiveyError | OSError, ExtractionResult], bool],
        cleanup: Callable[[], None] | None = None,
    ) -> Generator[None, None, None]:
        """Run the work on ``member`` in either pass, and deal with its failure.

        A per-member failure (``ArchiveyError`` or ``OSError``) is named as listed,
        typed (``_classify``) and handed to ``record`` with the result it gives
        ``member``, for the caller to record. The run then stops on it or logs it
        (``_stop_or_log``), unless ``record`` returns True: the caller stops on it
        later. The always-stop errors pass through. Whatever the outcome, ``cleanup``
        runs, and then the links the work may have moved are rechecked
        (``_recheck_links``). Unless the run is stopping on the failure, an error from
        the recheck ends the run; a stopping run ends on the member's error and drops
        the recheck's. A ``_handling`` is never entered inside another, so nothing
        catches that error.
        """
        current = self._current
        link_error: ArchiveyError | None = None
        try:
            yield
        except (AlwaysStopResourceLimitError, DiagnosticRaisedError):
            raise
        except (ArchiveyError, OSError) as exc:
            spelled_from = current.spelled_from
            if isinstance(exc, ArchiveyError) and spelled_from is not None:
                _report_stored_spelling(exc, disk_spelled(spelled_from), spelled_from)
            error, status = self._classify(exc, member.name)
            failed = ExtractionResult(
                member,
                None,
                status,
                error,
                requested_path=current.requested_path,
                collided_with=current.collided_with,
            )
            if not record(error, failed):
                self._stop_or_log(exc, error, status, kind=kind, name=member.name)
        finally:
            if cleanup is not None:
                cleanup()
            link_error = self._recheck_links()
        if link_error is not None:
            raise link_error

    def _stops_on_failure(self) -> bool:
        """Whether ``OnError`` halts on a member failure.

        Exhaustive on purpose: an ``OnError`` member this does not name raises instead
        of being treated as ``CONTINUE``, which would swallow its failures.
        """
        if self._on_error is OnError.STOP:
            return True
        if self._on_error is OnError.CONTINUE:
            return False
        assert_never(self._on_error)

    def _classify(
        self, exc: ArchiveyError | OSError, member_name: str
    ) -> tuple[ArchiveyError | OSError, ExtractionStatus]:
        """The error to record for a member's failed work, and its status.

        EILSEQ and ENAMETOOLONG (and their Windows codes) come from the archive's name,
        not the filesystem's state, so they become typed failures, as does Windows
        refusing a symlink for want of privilege: see ``_typed_os_error``.
        """
        # Typed first: whether a path was too long is read from the path the call took.
        error = _typed_os_error(exc, member_name)
        if isinstance(exc, OSError):
            # Before it is recorded or logged: a dry run's error names dest. The typed
            # error keeps ``exc`` as its cause, so this reaches that too.
            self._rebase_os_error(exc)
        if isinstance(error, FilterRejectionError):
            return error, ExtractionStatus.BLOCKED
        return error, ExtractionStatus.FAILED

    def _stop_or_log(
        self,
        exc: ArchiveyError | OSError,
        error: ArchiveyError | OSError,
        status: ExtractionStatus,
        *,
        kind: str,
        name: str,
    ) -> None:
        """Raise ``error`` (``exc`` as caught) if the run stops on it, else log it."""
        # OnError governs failures only. A BLOCKED stops the run only under the
        # fail-closed AbortOn.BLOCKED_MEMBER opt-in, under either OnError value; its
        # recorded result is discarded with the rest of the report.
        if (self._stops_on_failure() and status is ExtractionStatus.FAILED) or (
            status is ExtractionStatus.BLOCKED
            and AbortOn.BLOCKED_MEMBER in self._abort_on
        ):
            if error is exc:
                raise error
            raise error from exc
        # No diagnostic: the recorded result is the whole record of this outcome (the
        # placement clause in ``diagnostics``).
        # archivey/cli/logging_config.py matches this format string literally.
        logger.warning("Skipping %s %r: %s", kind, name, error)

    def _check_collision_abort(
        self, original: ArchiveMember, collided: Path, *, directory: bool
    ) -> None:
        """Abort on a collision event with ``collided`` if the caller asked to be
        stopped by one. ``directory`` says that ``collided`` is a directory this run
        made (``_run_directory_at``), which no member may have written: one created
        only as a parent is at the name the aborting member asked for.

        Fires on **every** non-TRUSTED collision whatever resolution follows — replaced,
        skipped, errored or renamed — because the trigger is the collision itself, not its
        outcome. Without the opt-in a collision is not an error: OverwritePolicy resolves
        it and both members' results record what happened.
        """
        if AbortOn.NAME_COLLISION not in self._abort_on:
            return
        what = "a directory this run created at" if directory else "already-written"
        raise _AbortExtraction(
            NameCollisionError(
                f"Name collision with {what} {display_path(self._shown(collided))}",
                member_name=original.name,
            )
        )

    def _register_collision_key(
        self, transformed: ArchiveMember, result: ExtractionResult, result_index: int
    ) -> None:
        """Claim the key for an actually-written non-directory member so later members (in
        this pass and the orphan second pass) collide against it.

        The claim carries ``result_index`` so a later REPLACE onto this destination can
        revise this member's result to OVERWRITTEN. Re-claiming a key transfers it: after
        a replacement, a third member colliding revises the second, not the first."""
        if (
            transformed.type != MemberType.DIRECTORY
            and result.status is ExtractionStatus.EXTRACTED
            and result.path is not None
        ):
            self._claim(result.path, result_index)

    def _rel_name(self, path: Path) -> str:
        """``path`` relative to the extraction root, as written, for messages."""
        return path.relative_to(self._state.dest).as_posix()

    def _claim(self, path: Path, index: int) -> None:
        """Claim ``path`` for result ``index``, keyed on where it physically is now.

        The key is remembered per path, so releasing the claim later finds it even after
        a symlink in ``path`` was repointed and ``path`` resolves somewhere else."""
        key = self._collision_key(path)
        self._state.collision_map[key] = _Claim(path, index, self._physical_path(path))
        self._state.claim_keys[path] = key
        self._state.unindexed_claims.append(path)

    def _alias_claim(self, path: Path) -> _Claim | None:
        """The claim on the file at ``path`` when ``path`` is another name the
        filesystem gives a file this run wrote under its own name; else ``None``.

        An 8.3 short name (``LONGFI~1.TXT`` for ``longfilename.txt``) is such a name on
        Windows, on a volume that makes them; so is a spelling that NTFS's upcase table
        folds and ``casefold`` does not. The collision key does not see it, so without
        this the member would meet the file as one already there: refused under
        ``ERROR``, and under ``REPLACE`` written over the earlier member while that
        member's result still says ``EXTRACTED``. Matched by identity
        (``st_dev``, ``st_ino``) with the files this run claimed, so it goes through
        the same collision handling as a case variant does. A filesystem that reports
        inode 0 cannot be matched, and an entry there stays one already there.

        Only a name that holds an entry and has no claim of its own gets here, so a
        run into an empty destination costs nothing. Each claimed path is looked at
        once, on the first lookup after it was claimed; a hit is checked against the
        claimed path again, as that path may hold a newer file by now.
        """
        if not self._occupied(path):
            return None
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return None
        if st.st_ino == 0:
            return None
        state = self._state
        for claimed in state.unindexed_claims:
            with contextlib.suppress(OSError):
                cst = os.lstat(long_path(claimed))
                state.claim_ids[cst.st_dev, cst.st_ino] = claimed
        state.unindexed_claims.clear()
        claimed = state.claim_ids.get((st.st_dev, st.st_ino))
        if claimed is None or claimed == path:
            return None
        claim = state.collision_map.get(self._claimed_key(claimed))
        if claim is None or claim.path != claimed:
            return None
        try:
            if not os.path.samestat(st, os.lstat(long_path(claimed))):
                return None
        except OSError:
            return None
        return claim

    def _claimed_key(self, path: Path) -> str:
        """The key ``path`` was claimed under, or its current key if it was not."""
        key = self._state.claim_keys.get(path)
        return key if key is not None else self._collision_key(path)

    def _physical_rel(self, path: Path) -> str | None:
        """Where ``path`` is, relative to the destination root and ``/``-separated, with
        its parent resolved; ``None`` when that parent does not resolve inside the root.

        It runs several times per member, so it works on strings and caches each
        parent's answer until a symlink changes (``_resolutions_changed``)."""
        parent, name = os.path.split(os.fspath(path))
        resolved_parents = self._state.resolved_parents
        rel_parent = resolved_parents.get(parent)
        if rel_parent is None:
            root = os.fspath(self._state.dest_root)
            try:
                resolved = os.fspath(resolve_or_raise_on_loop(Path(parent)))
            except OSError:
                return None
            prefix = root if root.endswith(os.sep) else root + os.sep
            if os.path.normcase(resolved) == os.path.normcase(root):
                rel_parent = ""
            elif os.path.normcase(resolved).startswith(os.path.normcase(prefix)):
                rel_parent = resolved[len(prefix) :].replace(os.sep, "/") + "/"
            else:
                return None
            resolved_parents[parent] = rel_parent
        return rel_parent + name

    def _physical_path(self, path: Path) -> Path:
        """Where ``path`` is, under the destination as given, with its parent
        resolved (``_physical_rel``); ``path`` itself when that parent does not resolve
        inside the root."""
        rel = self._physical_rel(path)
        return self._state.dest / rel if rel is not None else path

    def _collision_key(self, path: Path) -> str:
        """The collision-map key of the entry at ``path``: where it physically is.

        The parent is resolved, so two members that reach one file by different names
        collide: ``s/f`` through the archive's own ``s -> d`` is ``d/f``. The final
        component is not followed, as a member's own destination never is. A parent
        that does not resolve inside the destination (it was checked when the member
        was accepted, so only a later change can do that) falls back to the name as
        written.
        """
        rel = self._physical_rel(path)
        if rel is None:
            rel = self._rel_name(path)
        return collision_key(rel, self._policy)

    def _physical_key(self, path: Path) -> str:
        """The key of the directory at ``path`` in ``run_dirs`` and ``pending_dirs``:
        where it physically is, with case and Unicode normalization folded and a trailing
        dot or space trimmed under every policy.

        ``_collision_key`` folds only under ``STRICT`` and ``STANDARD``, because it
        decides which member's result a name reaches. These two maps ask whether a
        directory is one this run made, which does not depend on how the archive spelled
        it: on a case-insensitive filesystem ``D/`` and ``d/`` are one directory under
        ``TRUSTED`` too, as ``d.`` and ``d`` are on Windows. Where the folded key covers
        two directories (``X/`` beside ``x/`` on a case-sensitive filesystem), the readers
        tell them apart on disk.
        """
        rel = self._physical_rel(path)
        if rel is None:
            rel = self._rel_name(path)
        return collision_key(rel, ExtractionPolicy.STANDARD)

    def _derive_free_name(self, requested: Path, *, is_dir: bool) -> Path:
        """The first ``name (N)`` (N = 1, 2, …) free both in the collision map and on disk.

        :func:`~archivey.paths.numbered_name` spells each candidate (``photo.jpg`` →
        ``photo (1).jpg``), the same spelling the CLI's single-root hoist uses.

        The search resumes after the last ``N`` this run handed out for the same
        collision key, rather than starting at 1 each time: restarting made ``k``
        members colliding on one key cost ``k²`` probes, which a hostile archive of
        case-variant names turns into hours. The counter records names handed out, not
        names taken, so a member renamed and then failing to write leaves a gap in the
        numbering (``(1)`` unused, next member gets ``(2)``). The result is still
        deterministic, which is what the spec asks. ``_release_claim`` resets the
        counters, so a name freed by an anti-item is found again."""
        parent = requested.parent
        rename_next = self._state.rename_next
        counter_key = self._collision_key(requested)
        n = rename_next.get(counter_key, 1)
        while True:
            candidate = parent / numbered_name(requested.name, n, is_dir=is_dir)
            candidate_key = self._collision_key(candidate)
            if candidate_key not in self._state.collision_map and not self._occupied(
                candidate
            ):
                rename_next[counter_key] = n + 1
                return candidate
            n += 1

    def _apply_anti_item(
        self, original: ArchiveMember, dest_path: Path
    ) -> ExtractionResult:
        """Delete what an earlier member of this run wrote at the anti-item's name.

        An exact path this run wrote wins. Otherwise the name is looked up through the
        collision map, so it matches the way every other collision does: under STRICT
        and STANDARD, an anti-item ``readme`` deletes the ``README`` this run wrote,
        which on a case-insensitive filesystem is the file it names. TRUSTED keys on the
        exact name, so there it is exact. Directories are not in the map, so a directory
        matches only by its exact path. Nothing is deleted that this run did not write.
        """
        written_paths = self._state.written_paths
        if dest_path not in written_paths:
            claim = self._state.collision_map.get(self._collision_key(dest_path))
            if claim is not None and claim.path in written_paths:
                dest_path = claim.path
        if dest_path not in written_paths:
            return ExtractionResult(
                original, dest_path, ExtractionStatus.EXTRACTED, None
            )
        try:
            st = os.lstat(long_path(dest_path))
        except FileNotFoundError:
            written_paths.discard(dest_path)
            self._release_claim(dest_path)
            return ExtractionResult(
                original, dest_path, ExtractionStatus.EXTRACTED, None
            )
        with self._readonly_cleared(dest_path):
            if stat.S_ISDIR(st.st_mode):
                os.rmdir(long_path(dest_path))
                # Its member's metadata has no directory left to go on.
                self._drop_pending_dir(dest_path)
            else:
                os.unlink(long_path(dest_path))
            if stat.S_ISLNK(st.st_mode):
                self._note_link_change(dest_path)
        written_paths.discard(dest_path)
        self._release_claim(dest_path)
        self._forget_source_path(dest_path)
        return ExtractionResult(original, dest_path, ExtractionStatus.EXTRACTED, None)

    def _release_claim(self, path: Path) -> None:
        """Drop the collision claim on ``path`` once its content is gone.

        ``written_paths`` and ``collision_map`` both track what this run put on disk, so
        an anti-item delete has to clear both or the map keeps advertising a claim for
        content that no longer exists — which a later same-key member would see as a
        collision, aborting under ``AbortOn.NAME_COLLISION`` against an empty destination
        or revising an already-deleted member to ``OVERWRITTEN``."""
        key = self._claimed_key(path)
        collision_map = self._state.collision_map
        claim = collision_map.get(key)
        if claim is not None and claim.path == path:
            del collision_map[key]
            # A freed name can be the first free one for a later RENAME again.
            self._state.rename_next.clear()

    def _write_file(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        stream: BinaryIO | None,
        dest_path: Path,
    ) -> ExtractionResult:
        state = self._state
        declined = self._make_room(original, transformed, dest_path, atomic=True)
        if declined is not None:
            return declined
        staged = self._current.staged
        if stream is None and staged is None and self._current.retyped:
            # The pass yielded this member as a link, with no data stream, before its
            # data showed it is a file. Random access opens it now. A forward-only pass
            # is already past that data, so the content is out of reach: fail the member
            # rather than write an empty file for one the archive carries in full.
            reader = state.reader
            if reader._streaming:
                raise ExtractionError(
                    f"{quoted(original.name)} is flagged as a link but its data is a "
                    "file's content, which a streaming pass cannot go back for",
                    member_name=original.name,
                )
            with contextlib.closing(reader._lazy_member_stream(original)) as reopened:
                self._write_file_atomic(reopened, dest_path, transformed)
        elif (
            written_source := self._open_written_source(original, dest_path)
        ) is not None:
            # A file copy whose source this run wrote: its bytes come from that file,
            # and ``stream`` is closed unread, so nothing decodes the source again.
            # Read with no digest check, because none is needed: the source's write
            # read its stream to the end through the source's digest and size checks,
            # and a write that failed them recorded no identity to copy from.
            with written_source:
                self._write_file_atomic(written_source, dest_path, transformed)
        else:
            state.streaming_now = id(original) if stream is not None else None
            try:
                self._write_file_atomic(stream, dest_path, transformed, staged=staged)
            finally:
                state.streaming_now = None
        if self._dry is None and id(original) in state.declined:
            # A file that cannot be looked at now is simply not copied from.
            with contextlib.suppress(OSError):
                state.written_files[original.member_id, dest_path] = _file_identity(
                    os.stat(long_path(dest_path), follow_symlinks=False)
                )

        # Record this FILE's path under the ORIGINAL member id so later hardlinks whose
        # link_target_member is this member can os.link against it.
        state.source_paths.setdefault(original.member_id, []).append(dest_path)
        return ExtractionResult(original, dest_path, ExtractionStatus.EXTRACTED, None)

    def _keep_copy_source(self, source: ArchiveMember) -> bool:
        """Whether the pass keeps a RAR file copy's source for its copies.

        Asked when the source's first byte is decoded. Not when this run is writing the
        source from its stream: the copies then come from the file written
        (``_open_written_source``). A dry run writes empty files, so it keeps every
        source.
        """
        if self._dry is not None or id(source) != self._state.streaming_now:
            return True
        self._state.declined.add(id(source))
        return False

    def _open_written_source(
        self, original: ArchiveMember, dest_path: Path
    ) -> BinaryIO | None:
        """The file this run wrote for a RAR file copy's source, opened, or ``None``.

        ``None`` when ``original`` is not a file copy, its source was not written (a
        selector or filter dropped it, its write failed, or a later member of its name
        took its place), its sizes disagree, or the file no longer is the one written:
        another inode, size or modification time than ``written_files`` recorded for
        the source's own write (a later member written to the same path does not
        count). The check is made on the opened file, so a swap between check and read
        is caught too. The caller then reads the copy's own stream, which serves the source's
        bytes from the pass or decodes them again.
        """
        source = original.link_target_member
        if (
            self._dry is not None
            or source is None
            or not original.extra.get(EXTRA_IS_FILE_COPY)
            or source.size != original.size
        ):
            return None
        for path in self._state.source_paths.get(source.member_id, ()):
            expected = self._state.written_files.get((source.member_id, path))
            # Never the copy's own destination: the atomic write would replace the
            # file it is reading.
            if expected is None or path == dest_path:
                continue
            try:
                f = open(long_path(path), "rb")  # noqa: SIM115 - returned open
            except OSError:
                continue
            try:
                found = _file_identity(os.fstat(f.fileno()))
            except OSError:
                found = None
            if found is not None and found == expected and found[2] == original.size:
                return f
            f.close()
        return None

    def _write_symlink(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        dest_path: Path,
    ) -> ExtractionResult:
        target = transformed.link_target
        if target is None and original.link_target_unrecorded:
            # The archive says this is a link and records nowhere for it to point — a
            # 7-Zip-written directory symlink or junction, or a reparse buffer naming
            # nothing. There is nothing to write, and nothing here went wrong, so this
            # is a LINK_TARGET_UNAVAILABLE result rather than a per-member failure that
            # OnError.STOP would turn into an aborted extraction.
            # Checked before _make_room so a member we are not going to
            # write cannot unlink an existing destination under OverwritePolicy.REPLACE.
            return ExtractionResult(
                original, None, ExtractionStatus.LINK_TARGET_UNAVAILABLE, None
            )

        if target is None:
            # Unset for any other reason, which always means the archive records a
            # target this read could not produce. A data-stored target has been looked
            # for by now, either while listing or by `_transform` on request, so it is
            # out of reach: compressed, split across volumes, encrypted, or refused as
            # too long. The status above would claim success while dropping a member
            # the archive describes in full, so this is a per-member failure. The
            # reason is the backend's to report:
            # `BaseArchiveReader._emit_link_target_unavailable`.
            raise LinkTargetNotFoundError(
                "Symlink has no target",
                reason=LinkTargetNotFoundReason.UNREADABLE,
                member_name=transformed.name,
            )

        declined = self._make_room(original, transformed, dest_path, atomic=False)
        if declined is not None:
            return declined
        # A symlink is target-independent: create it even if the target was filtered out,
        # appears later, or lies outside the archive — it may dangle. Only the escape
        # check below constrains it. An os.symlink failure (unsupported FS) propagates as
        # a per-member OnError failure; no copy-the-target fallback. A dry run creates
        # an absolute target that names dest pointing into its scratch copy instead.
        on_disk = self._link_target_on_disk(target)
        try:
            if _DIRECTORY_LINKS:
                is_dir = self._link_to_directory(dest_path, target, on_disk)
                os.symlink(on_disk, long_path(dest_path), target_is_directory=is_dir)
                self._state.link_kinds[dest_path] = (on_disk, is_dir)
            else:
                os.symlink(on_disk, long_path(dest_path))
        except FileExistsError as exc:
            # The name was taken after the existence check, as for a FILE or HARDLINK
            # landing (``_swap_into_place``).
            if not self._taken_after_check(dest_path, atomic=False):
                raise
            raise self._already_exists(dest_path, transformed) from exc
        self._resolutions_changed()

        # Resolve the link now that it exists, through the real filesystem, and remove
        # it if it escapes. check_universal checked the target against the tree as it
        # was; an earlier member's symlink on the target's path can still lead out
        # (`sub -> /tmp/evil`, then `sub/link -> x`). This cannot move before
        # os.symlink: until the link exists there is nothing to resolve, and resolving
        # the bare target string only repeats check_universal. A link that cannot be
        # resolved, a loop included on every Python version, counts as an escape: fail
        # safe rather than crash. This is the third layer of the `safe-extraction`
        # spec's "Symlink Escape Re-Validated at Extraction Time".
        # A later member can still change what this link resolves to; the caller
        # records the link in ``links`` for that.
        problem = _symlink_problem(dest_path, on_disk, self._state.dest_root)
        if problem is not None:
            try:
                os.unlink(long_path(dest_path))
            except OSError:
                pass
            self._resolutions_changed()
            raise FilterRejectionError(
                problem,
                member_name=transformed.name,
                link_target=target,
            )

        return ExtractionResult(original, dest_path, ExtractionStatus.EXTRACTED, None)

    def _link_to_directory(self, dest_path: Path, target: str, on_disk: str) -> bool:
        """Whether the symlink at ``dest_path`` is made a directory link, where the
        platform has two kinds (``_DIRECTORY_LINKS``).

        Yes when its target is a directory now, or when the archive's listing shows
        the target is one (``_listed_directory``). A target the run has not written
        yet and the listing cannot place, as in a streaming pass, gets a file link;
        ``_settle_link_kinds`` remakes it once the run is done if it turned out a
        directory.
        """
        if os.path.isdir(long_path(os.path.join(dest_path.parent, on_disk))):
            return True
        return self._listed_directory(dest_path, target)

    def _listed_directory(self, dest_path: Path, target: str) -> bool:
        """Whether the archive's listing shows the target of a symlink at ``dest_path``
        is a directory: a directory member, or a name other members are inside.

        Matched by name, lexically from the link's place under the destination, and
        casefolded, as Windows matches names. A target that leaves the destination, or
        is absolute, is not placed. A name the policy or a filter writes elsewhere is
        missed and left to ``_settle_link_kinds``.
        """
        state = self._state
        if state.listed is None:
            return False
        if state.listed_names is None:
            # One string per member: an ancestor is found by a prefix search, so no
            # string is built for each directory a deep name passes through.
            names: list[str] = []
            dirs: set[str] = set()
            for member in state.listed:
                name = posixpath.normpath(member.name.replace("\\", "/").strip("/"))
                folded = name.casefold()
                names.append(folded)
                if member.type == MemberType.DIRECTORY:
                    dirs.add(folded)
            names.sort()
            state.listed_names = (names, dirs)
        try:
            rel_parent = dest_path.parent.relative_to(state.dest).as_posix()
        except ValueError:
            return False
        spelled = target.replace("\\", "/")
        if spelled.startswith("/"):
            return False
        named = posixpath.normpath(posixpath.join(rel_parent, spelled))
        if named == ".." or named.startswith("../"):
            return False
        folded = named.casefold()
        names, dirs = state.listed_names
        if folded in dirs:
            return True
        inside = folded + "/"
        at = bisect.bisect_left(names, inside)
        return at < len(names) and names[at].startswith(inside)

    def _settle_link_kinds(self) -> None:
        """Remake each symlink this run made of the wrong kind for what its target is
        now: a file link to a directory, or a directory link to anything else. Where
        the platform has one kind (POSIX), there is nothing to do.

        Only a link still at its path with the target it was made with is remade, so
        nothing a later member put there is touched. The new link is made under a
        temporary name and renamed into place. A failure is logged and leaves the
        link as it was, as metadata is best-effort.
        """
        state = self._state
        kinds, state.link_kinds = state.link_kinds, {}
        for path, (on_disk, is_dir) in kinds.items():
            if path not in state.written_paths:
                continue
            try:
                # Windows hands back an absolute target with the extended
                # prefix: compared plain, as it was created.
                if plain(os.readlink(long_path(path))) != on_disk:
                    continue
            except OSError:
                continue
            wanted = os.path.isdir(long_path(os.path.join(path.parent, on_disk)))
            if wanted == is_dir:
                continue
            tmp = self._temp_sibling(path.parent)
            try:
                os.symlink(on_disk, long_path(tmp), target_is_directory=wanted)
            except OSError as exc:
                self._rebase_os_error(exc)
                logger.warning(
                    "Could not remake symlink %r for its target: %s",
                    str(self._shown(path)),
                    exc,
                )
                continue
            try:
                # Not os.replace: Windows will not replace a directory link by name.
                os.unlink(long_path(path))
                try:
                    os.rename(long_path(tmp), long_path(path))
                except OSError:
                    # Put the link back as it was.
                    with contextlib.suppress(OSError):
                        os.symlink(on_disk, long_path(path), target_is_directory=is_dir)
                    raise
            except OSError as exc:
                self._rebase_os_error(exc)
                logger.warning(
                    "Could not remake symlink %r for its target: %s",
                    str(self._shown(path)),
                    exc,
                )
                with contextlib.suppress(OSError):
                    os.unlink(long_path(tmp))

    def _write_hardlink(
        self,
        original: ArchiveMember,
        transformed: ArchiveMember,
        dest_path: Path,
        result_index: int,
    ) -> ExtractionResult:
        source = original.link_target_member
        if source is None:
            raise LinkTargetNotFoundError(
                "Hardlink target not found",
                reason=LinkTargetNotFoundReason.UNRESOLVED,
                member_name=transformed.name,
                link_target=original.link_target,
            )
        if source.type is not MemberType.FILE:
            # `link_target_member` is the end of the link chain, so anything but a
            # file here (a directory, a device) cannot share an inode. A hard link to
            # a symlink whose target is known never gets here: `_as_written` writes it
            # as a symlink. Only a FILE source is recorded in `source_paths`, so the
            # branches below would report this source as excluded.
            reason = (
                "a directory, and a hard link to a directory cannot be created"
                if source.type is MemberType.DIRECTORY
                else f"a {source.type.value}, not a regular file"
            )
            raise ExtractionError(
                f"Hardlink target {quoted(source.name)} is {reason}",
                member_name=transformed.name,
                link_target=source.name,
            )

        if source.member_id in self._state.source_paths:
            # Taken before ``_make_room``: under REPLACE a link can land on one of its
            # own source's paths, which ``_make_room`` then forgets.
            candidates = list(self._state.source_paths[source.member_id])
            declined = self._make_room(original, transformed, dest_path, atomic=True)
            if declined is not None:
                return declined
            self._place_link(source.member_id, candidates, dest_path, transformed)
            return ExtractionResult(
                original, dest_path, ExtractionStatus.EXTRACTED, None
            )

        # Source not on disk yet: either it was excluded by the selector/filter, or (in a
        # crafted/non-TAR-ordered archive) it simply appears later in archive order. The
        # second pass distinguishes the two: a source written later in this same pass is
        # just linked against; a truly excluded one is re-read and materialized.
        if self._state.reader._streaming:
            # Forward-only: the source's bytes already streamed past — unrecoverable. Per
            # spec this is a per-member ExtractionError handled by OnError.
            raise ExtractionError(
                "Hardlink source was excluded or replaced by a later member, and "
                "cannot be recovered on a forward-only stream",
                link_target=source.name,
                member_name=transformed.name,
            )
        # Re-readable: resolve in the second pass.
        self._state.orphans.append(
            _Orphan(
                result_index,
                original,
                transformed,
                dest_path,
                source,
                spelled_from=self._current.spelled_from,
            )
        )
        return ExtractionResult(original, None, ExtractionStatus.FAILED, None)

    # --- orphan (second pass) ------------------------------------------------------

    def _resolve_orphans(self, reader: BaseArchiveReader) -> None:
        orphans_by_source: dict[int, list[_Orphan]] = {}
        for orphan in self._state.orphans:
            orphans_by_source.setdefault(orphan.source.member_id, []).append(orphan)

        # A source that was written LATER in the first pass (a link preceding its source in
        # archive order) is already on disk: just link against it — re-reading its bytes
        # here would create an independent inode and double-count against the bomb limits.
        needed: set[int] = set()
        for source_id, group in orphans_by_source.items():
            if source_id in self._state.source_paths:
                self._link_orphan_group(group, source_id)
            else:
                needed.add(source_id)
        if not needed:
            return

        # One second forward pass over the (re-readable) source; write each needed source's
        # content to the first writable link path and os.link the rest. Driven through the
        # public stream_members() with the needed sources as an identity selector, so
        # unneeded members are never surfaced (or opened — the streams are lazy).
        # Built here for the same reason as the first pass's identity selector:
        # these entries are the coordinator's, so an unmatched one is not reported
        # as MEMBER_SELECTOR_UNMATCHED.
        needed_sources = CollectionSelector(
            [orphans_by_source[source_id][0].source for source_id in needed],
            record=False,
        )
        # Closed on the way out, so an error out of the loop body closes the open
        # member stream (and any unrar child) now, not when the pass is collected.
        passing = reader.stream_members(needed_sources)
        with _closing_pass(passing):
            for member, stream in passing:
                group = orphans_by_source[member.member_id]
                try:
                    remaining = self._materialize_orphan_source(member, stream, group)
                finally:
                    self._close(stream)
                # Each link after the one that took the content is its own attempt: its
                # failure is that link's, not the source's.
                self._link_orphan_group(remaining, member.member_id)
                needed.discard(member.member_id)
                if not needed:
                    break  # every orphaned source is materialized; stop opening members

        # Any orphan whose source never reappeared (should not happen for a re-readable
        # source) is a per-member failure.
        for source_id in needed:
            group = orphans_by_source[source_id]
            name = group[0].source.name
            err = ExtractionError(
                "Hardlink source was not found on the second pass", member_name=name
            )
            self._record_failure_group(group, err)
            self._stop_or_log(
                err,
                err,
                ExtractionStatus.FAILED,
                kind="orphaned hardlink source",
                name=name,
            )

    def _record_failure_group(
        self, group: list[_Orphan], error: ArchiveyError | OSError
    ) -> None:
        """Record one failed hardlink source as N FAILED results sharing a group id.

        The id is opaque and process-local (``uuid4().hex``): callers compare it for
        equality to join a group and nothing more. Both fields are set together, so a
        partial fill can never look like a group."""
        group_id = uuid.uuid4().hex
        group_size = len(group)
        for orphan in group:
            self._revise_result(
                orphan.result_index,
                ExtractionResult(
                    orphan.original,
                    None,
                    ExtractionStatus.FAILED,
                    error,
                    failure_group_id=group_id,
                    failure_group_size=group_size,
                ),
            )

    def _revise_result(self, index: int, new: ExtractionResult) -> None:
        """Overwrite a recorded result, carrying forward first-pass facts it omits.

        The second pass rebuilds a result from scratch, but two facts were decided in
        the first pass (before the member was deferred) and are still true: the name
        rewrite, and the ``requested_path`` the member asked for. The rewrite is two
        fields, ``presented_name`` and the ``rewrites`` that produced it, so neither is
        carried without the other. A rebuild that does not supply them must not erase
        them — results are the sole record, so a dropped field is a fact lost rather
        than a fact reported elsewhere.
        Unlike ``_set_result`` it moves no progress tally: ``_report_progress`` is
        called only from the main member loop, which has finished by the second pass.
        """
        results = self._state.results
        prior = results[index]
        if prior.presented_name is not None and new.presented_name is None:
            new = replace(
                new, presented_name=prior.presented_name, rewrites=prior.rewrites
            )
        if prior.requested_path is not None and new.requested_path is None:
            new = replace(new, requested_path=prior.requested_path)
        results[index] = new

    def _append_result(self, new: ExtractionResult) -> int:
        """Record ``new`` as the next result, tallied, and return its index."""
        self._tally(None, new.status)
        self._state.results.append(new)
        index = len(self._state.results) - 1
        member_id = new.member._member_id
        if member_id is not None:
            self._state.result_ids[member_id] = index
        return index

    def _set_result(self, index: int, new: ExtractionResult) -> None:
        """Replace recorded result ``index`` with ``new``. The progress tallies count
        the results, so they follow the change; a report already sent is not resent."""
        results = self._state.results
        self._tally(results[index].status, new.status)
        results[index] = new

    def _tally(
        self, old: ExtractionStatus | None, new: ExtractionStatus | None
    ) -> None:
        for status, step in ((old, -1), (new, 1)):
            if status is ExtractionStatus.EXTRACTED:
                self._state.members_extracted += step
            elif status is ExtractionStatus.BLOCKED:
                self._state.members_blocked += step

    def _materialize_orphan_source(
        self,
        source_member: ArchiveMember,
        stream: BinaryIO | None,
        group: list[_Orphan],
    ) -> list[_Orphan]:
        """Write the source's content at the first link of ``group`` that takes it, and
        return the links after that one, for the caller to link against it. None remain
        when no link took the content: every link was skipped or failed on its own, or
        the source itself failed."""
        # Count the recovered source bytes toward the cumulative/ratio guards too.
        self._state.tracker.start_member(source_member)

        # The excluded source's content is written to the FIRST link whose destination the
        # OverwritePolicy allows writing, never to the source's own name. A link the
        # policy declines (SKIP over an existing entry), or one that fails before the
        # copy of the source's bytes begins (ERROR over an existing entry, a REPLACE
        # that cannot remove what is there, a temp file its directory refuses), records
        # that outcome as its own, and the content moves on to the next link.
        for index, orphan in enumerate(group):
            placed = self._materialize_at(source_member, stream, group, index)
            if placed is None:
                # The source failed: every link from this one on is in its group.
                return []
            if placed:
                return group[index + 1 :]
        return []

    def _materialize_at(
        self,
        source_member: ArchiveMember,
        stream: BinaryIO | None,
        group: list[_Orphan],
        index: int,
    ) -> bool | None:
        """Try to write the source's content at link ``group[index]``, as one step of
        ``_materialize_orphan_source``: True when it took the content, False when the
        link was declined or failed on its own, ``None`` when the source failed.

        The content is written atomically (temp + ``os.replace``), same as a normal
        FILE, so a failure while re-reading does not clobber an existing entry. The
        link's transformed copy supplies the on-disk mode and timestamps: hardlinks
        share one inode, so the metadata goes on the file that carries the content. The
        destination is O2-collision-resolved against the map the main pass built (a
        deferred link's key may have been claimed after it was orphaned).

        Two kinds of failure are the source's, and fail this link and every later
        one as one group: the refusal of the source's recorded size
        (``check_recorded_size``), which every link would meet, and any failure from
        the moment the copy into the link's temp file begins, as the source's bytes
        are then being read and cannot be offered to another link. Every other
        failure (collision resolution, ``_make_room``, creating the temp file) is
        this link's own, as for any other link (``_link_orphan``)."""
        orphan = group[index]
        current = self._current = _MemberState(
            requested_path=orphan.dest_path, spelled_from=orphan.spelled_from
        )
        # True while a failure is the source's (see the docstring).
        source_step = False
        source_error: ArchiveyError | OSError | None = None

        def record(error: ArchiveyError | OSError, failed: ExtractionResult) -> bool:
            nonlocal source_error
            # Nothing the second pass runs raises FilterRejectionError.
            assert failed.status is ExtractionStatus.FAILED
            if not source_step:
                # This link's own failure, not a source fan-out: no group id.
                self._revise_result(orphan.result_index, failed)
                return False
            # One failed source, N failed links: the fan-out is recorded on the
            # results themselves, so a caller can tell N separate failures from one
            # failure seen N times without joining against a diagnostic. Earlier
            # links keep their own results.
            self._record_failure_group(group[index:], error)
            source_error = error
            return True  # stopped on or logged below, under the source's name

        def copy_begins() -> None:
            nonlocal source_step
            source_step = True

        placed = False
        with self._handling(orphan.original, kind="hardlink", record=record):
            resolved, prior, collided_with = self._resolve_collision(
                orphan.original, orphan.transformed, orphan.dest_path
            )
            current.collided_with = collided_with
            result = self._make_room(
                orphan.original, orphan.transformed, resolved, atomic=True
            )
            if result is None:
                # ``_write_file_atomic`` runs this check again. Running it here first
                # lets its refusal count as the source's failure.
                source_step = True
                self._state.tracker.check_recorded_size()
                source_step = False
                self._write_file_atomic(
                    stream, resolved, orphan.transformed, copy_begins=copy_begins
                )
                self._state.written_paths.add(resolved)
                self._state.source_paths.setdefault(source_member.member_id, []).append(
                    resolved
                )
                result = ExtractionResult(
                    orphan.original, resolved, ExtractionStatus.EXTRACTED, None
                )
            result = self._settle_placement(
                result,
                requested=orphan.dest_path,
                target=orphan.dest_path,
                prior=prior,
                collided_with=collided_with,
                transformed=orphan.transformed,
                result_index=orphan.result_index,
            )
            self._revise_result(orphan.result_index, result)
            placed = result.status is ExtractionStatus.EXTRACTED
        if source_error is not None:
            self._stop_or_log(
                source_error,
                source_error,
                ExtractionStatus.FAILED,
                kind="orphaned hardlink source",
                name=source_member.name,
            )
            return None
        return placed

    def _link_orphan_group(self, group: list[_Orphan], source_id: int) -> None:
        """Link each orphan in ``group`` against the source content already on disk
        (recorded under ``source_id``), applying the OverwritePolicy per link (O2 collisions
        resolved against the map) and recording per-link results; failures follow
        ``OnError``. A link can replace a symlink or a directory, so the symlinks it
        may have moved are rechecked after each one, whatever its outcome."""
        for orphan in group:
            self._link_orphan(orphan, source_id)

    def _link_orphan(self, orphan: _Orphan, source_id: int) -> None:
        """One link of ``_link_orphan_group``."""
        current = self._current = _MemberState(
            requested_path=orphan.dest_path, spelled_from=orphan.spelled_from
        )

        def record(_error: object, failed: ExtractionResult) -> bool:
            # Nothing the second pass runs raises FilterRejectionError.
            assert failed.status is ExtractionStatus.FAILED
            # A single link's failure, not a source fan-out: no group id.
            self._revise_result(orphan.result_index, failed)
            return False

        with self._handling(orphan.original, kind="hardlink", record=record):
            resolved, prior, collided_with = self._resolve_collision(
                orphan.original, orphan.transformed, orphan.dest_path
            )
            current.collided_with = collided_with
            # Taken before ``_make_room``, as in ``_write_hardlink``. An earlier link
            # of the group that failed after its ``_make_room`` can have taken the
            # last path; ``_place_link`` then fails this link as well. No archive
            # reaches that alone: the earlier link has to fail in ``os.link`` or
            # ``os.replace``, which needs the filesystem to change under the run.
            candidates = list(self._state.source_paths.get(source_id, ()))
            result = self._make_room(
                orphan.original, orphan.transformed, resolved, atomic=True
            )
            if result is None:
                self._place_link(source_id, candidates, resolved, orphan.transformed)
                self._state.written_paths.add(resolved)
                result = ExtractionResult(
                    orphan.original, resolved, ExtractionStatus.EXTRACTED, None
                )
            result = self._settle_placement(
                result,
                requested=orphan.dest_path,
                target=orphan.dest_path,
                prior=prior,
                collided_with=collided_with,
                transformed=orphan.transformed,
                result_index=orphan.result_index,
            )
            self._revise_result(orphan.result_index, result)

    @contextlib.contextmanager
    def _readonly_cleared(
        self, path: Path, *, ours: bool = False
    ) -> Generator[None, None, None]:
        """Let the block replace or remove ``path`` on Windows when this run wrote it
        read-only. ``ours`` says the caller knows this run wrote it (a parked copy
        already taken out of ``parked``).

        Windows refuses to replace or unlink a file, or remove a directory, with the
        read-only attribute (``WinError 5``), which a stored mode without write
        permission (``0o444``, ``0o555``) sets; POSIX checks only the parent directory.
        So a later member of the same name replaced the entry on POSIX and failed on
        Windows. The attribute is cleared only on a regular file or a directory this run
        wrote (or parked), or a directory it created as a parent that a later member made
        read-only: a read-only entry the caller already had stays protected, as on
        Windows before. A run applies directory modes only when it ends
        (``_apply_directory_metadata``), so a directory it wrote is read-only during
        the run only when something else made it so; the directory case is kept for
        that. The attribute belongs to the file, not the name, so it is
        put back on the other names of a file (hard links this run made) once the block
        is done, and on ``path`` itself if the block fails.
        """
        state = self._state
        st: os.stat_result | None = None
        if _WINDOWS and (
            ours
            or path in state.written_paths
            or path in state.created_dirs
            or path in self._current.parked
        ):
            with contextlib.suppress(OSError):
                st = os.lstat(long_path(path))
        if (
            st is None
            or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode))
            or st.st_mode & stat.S_IWRITE
        ):
            yield
            return
        others: list[Path] = []
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            identity = (st.st_dev, st.st_ino)
            for paths in state.source_paths.values():
                for other in paths:
                    with contextlib.suppress(OSError):
                        ost = os.lstat(long_path(other))
                        if other != path and (ost.st_dev, ost.st_ino) == identity:
                            others.append(other)
        os.chmod(long_path(path), st.st_mode | stat.S_IWRITE)
        try:
            yield
        except BaseException:
            with contextlib.suppress(OSError):
                # Still the same file: the block failed.
                os.chmod(long_path(path), st.st_mode)
            raise
        for other in others:
            with contextlib.suppress(OSError):
                os.chmod(long_path(other), st.st_mode)

    def _forget_source_path(self, path: Path) -> bool:
        """Stop offering ``path`` as a hardlink source: something else is going there.
        Returns whether another path still holds the content it held.

        ``source_paths`` records where each source member's content was written, and a
        later hardlink to that member is made against it. Once another member replaces
        the entry at that path, it holds that member's content (or is a symlink that
        ``os.link`` would follow), so a link made against it would get the wrong bytes.
        A source left with no path is re-read by the second pass where the source is
        seekable, as an excluded one is.
        """
        source_paths = self._state.source_paths
        content_kept = False
        for source_id, paths in list(source_paths.items()):
            if path in paths:
                paths.remove(path)
                if paths:
                    content_kept = True
                else:
                    del source_paths[source_id]
        return content_kept

    def _resolutions_changed(self) -> None:
        """Forget the cached parent resolutions: a symlink was created or removed."""
        self._state.resolved_parents.clear()

    def _note_link_change(self, path: Path) -> None:
        """Report a symlink or directory at ``path`` replaced or removed this member."""
        self._resolutions_changed()
        self._state.links.note_change(path)

    def _recheck_links(self) -> ArchiveyError | None:
        """Remove the links this run created that the member just handled made escape.

        Called once per member, before the next one is handled, so no later member
        (or a progress callback) sees an escaping link. A removed link's result
        becomes ``BLOCKED`` in place (``_set_result``).

        It runs in a ``finally``, so it returns the error that must end the run
        instead of raising it, which would replace the member's own error: the
        recheck bound running out, or ``AbortOn.BLOCKED_MEMBER`` with a link removed.
        """
        state = self._state
        links = state.links
        if not links.has_changes:
            return None
        dest_root = state.dest_root
        # The recheck asks a yes/no question; the reason is kept here, per link path,
        # so a loop a later member closed is named as a loop. ``recheck`` reports a
        # link as escaped only when this callback refused it, so every escaped link
        # has an entry: indexed, so a broken invariant raises instead of mislabelling.
        problems: dict[Path, str] = {}

        def escapes(path: Path, target: str) -> bool:
            if self._dry is not None:
                # The link can now resolve through entries of dest that the scratch
                # tree does not hold yet; a real run meets them in dest. A copy made
                # here needs no new recheck of other links: each link copies in all
                # it resolves through here, before its own check.
                self._dry.bring_in_link(path, target)
            problem = _symlink_problem(path, target, dest_root)
            if problem is not None:
                problems[path] = problem
            return problem is not None

        outcome = links.recheck(escapes)
        removed = [
            (
                link,
                (
                    f"{problems[link.path]}: a later member changed "
                    "a path it resolves through"
                ),
            )
            for link in outcome.escaped
        ] + [
            (link, "Symlink removed unchecked: the recheck limit was reached")
            for link in outcome.unchecked
        ]
        if removed:
            self._resolutions_changed()
        first: FilterRejectionError | None = None
        for link, message in removed:
            prior = state.results[link.result_index]
            error = FilterRejectionError(
                message,
                member_name=prior.member.name,
                link_target=state.stored_targets.get(link.result_index, link.target),
            )
            first = first or error
            state.written_paths.discard(link.dest_path)
            self._release_claim(link.dest_path)
            if prior.status is ExtractionStatus.EXTRACTED:
                self._set_result(
                    link.result_index,
                    replace(
                        prior, path=None, status=ExtractionStatus.BLOCKED, error=error
                    ),
                )
            logger.warning("Removed symlink %r: %s", prior.member.name, error)
        if outcome.unchecked:
            return AlwaysStopResourceLimitError(
                f"Symlink recheck limit reached: max_entries={self._limits.max_entries}"
            )
        if first is not None and AbortOn.BLOCKED_MEMBER in self._abort_on:
            return first
        return None

    def _mark_overwritten(self, prior: _Claim | None) -> None:
        """Revise a clobbered member's result to OVERWRITTEN: its content is gone.

        Called once the caller knows the earlier member lost its destination — either
        because a later REPLACE landed on it, or because a REPLACE cleared it and then
        failed. Shared by the main pass and the orphan second pass: a deferred hardlink
        can be the member that replaces an earlier write just as a first-pass member
        can."""
        if prior is None or self._overwrite is not OverwritePolicy.REPLACE:
            return
        self._revise_to_overwritten(prior.result_index)

    def _revise_removed_directory(self, removed: Path) -> None:
        """Revise the directory results this run wrote at ``removed`` to OVERWRITTEN.

        Looked up by collision key, so a result that reached the same directory through
        a symlink or a case variant is found. A casefolded key can also cover a
        different directory on a case-sensitive filesystem (``X/`` beside ``x/``), so a
        result is revised only when its own path is gone; the others stay recorded."""
        key = self._collision_key(removed)
        indices = self._state.written_dirs.pop(key, None)
        if not indices:
            return
        kept: list[int] = []
        for index in indices:
            path = self._state.results[index].path
            if path is not None and os.path.lexists(long_path(path)):
                kept.append(index)
            else:
                self._revise_to_overwritten(index)
        if kept:
            self._state.written_dirs[key] = kept

    def _revise_to_overwritten(self, index: int) -> None:
        """Revise result ``index`` to OVERWRITTEN, keeping where it had written."""
        clobbered = self._state.results[index]
        if clobbered.status is ExtractionStatus.SUPERSEDED:
            # A superseded copy still on disk (a file the filesystem would not remove, or
            # a directory other members were written into): it keeps its status.
            return
        # The clobbered member was tallied as EXTRACTED when it completed, and is
        # no longer: ``_set_result`` moves the tally, or the final report would claim
        # more extracted members than ``results`` contains.
        self._set_result(
            index,
            replace(
                clobbered,
                path=None,
                status=ExtractionStatus.OVERWRITTEN,
                requested_path=(
                    clobbered.requested_path
                    if clobbered.requested_path is not None
                    else clobbered.path
                ),
            ),
        )

    # --- filesystem helpers --------------------------------------------------------

    def _ensure_dest_root(self, dest: Path) -> bool:
        """Ensure ``dest`` is a directory to extract into, creating it if absent; under
        ``dry_run``, only refuse a ``dest`` a real run would refuse
        (``DryRun.check_creatable``). Returns whether this call created it, or under
        ``dry_run`` whether a real run would have.

        A dest that resolves to a directory — a real directory or a symlink pointing at
        one — is reused, and members land inside the resolved target (``run`` resolves
        ``dest`` before writing). This matches ``tar -C``/``unzip -d`` and leaves the
        caller's symlink in place; the dest root is trusted (unlike archive-internal
        symlinks, which are never written through).

        A dest that exists as anything else — a regular file, a symlink to a file, a
        dangling symlink — is a hard error regardless of ``OverwritePolicy``: we never
        delete it. Extraction is not an invitation to remove a path the caller pointed at
        by mistake (e.g. a CLI given a file argument where a directory was meant).
        """
        named = dest if self._dry is None else self._dry.shown_dest
        # A real directory or a symlink resolving to one: reuse / follow.
        if os.path.isdir(long_path(named)):
            return False
        # ``lexists`` (not ``exists``) so a dangling symlink is caught here rather than
        # surfacing as a raw FileExistsError from ``mkdir`` below.
        if os.path.lexists(long_path(named)):
            raise ExtractionError(
                f"Destination exists and is not a directory: {display_path(named)}"
            )
        if self._dry is not None:
            self._dry.check_creatable()
        else:
            os.makedirs(long_path(dest), exist_ok=True)
        return True

    def _makedirs(self, path: Path, member: ArchiveMember) -> None:
        """``os.makedirs(path, exist_ok=True)`` for ``member``, typed when the archive
        itself is in the way.

        A file member ``d`` followed by ``d/f`` (or a directory ``d/y``) cannot both be
        extracted, and the conflict is in the archive, not in the filesystem. So when
        creating the directories fails and one of the components is a non-directory
        that this run wrote, the member gets an ``ExtractionError`` that names that
        component, a per-member failure like any other. A non-directory that was in
        ``dest`` before the run met ``OverwritePolicy`` before this
        (``_make_room_for_parents``), so any other failure is the filesystem's, and
        propagates unchanged.
        """
        # The components that do not exist yet: this run creates them, so a directory
        # member naming one later is not the caller's (``_is_callers_directory``).
        missing: list[Path] = []
        probe = path
        while probe != probe.parent and not os.path.lexists(long_path(probe)):
            missing.append(probe)
            probe = probe.parent
        try:
            os.makedirs(long_path(path), exist_ok=True)
        except (FileExistsError, NotADirectoryError, FileNotFoundError) as exc:
            # FileNotFoundError too: Windows can report a directory created under a file
            # as a missing path. Nearest the root first, because that component is the
            # one that stops the rest.
            for component in (*reversed(path.parents), path):
                if component in self._state.written_paths and not os.path.isdir(
                    long_path(component)
                ):
                    raise ExtractionError(
                        f"Cannot create {quoted(member.name)}: "
                        f"{quoted(self._rel_name(component))} is a "
                        "non-directory already extracted from this archive",
                        member_name=member.name,
                    ) from exc
            raise
        self._state.created_dirs.update(missing)
        for component in missing:
            self._note_run_directory(component)

    def _is_callers_directory(self, path: Path) -> bool:
        """Whether ``path`` is a directory that was there before this run: the
        destination root unless this run created it, or a directory this run neither
        wrote nor created (``_is_run_directory``). The root is decided by name, as it
        may be the caller's symlink to a directory."""
        state = self._state
        if path == state.dest:
            return path not in state.created_dirs
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return False
        return stat.S_ISDIR(st.st_mode) and not self._is_run_directory(path, st)

    def _note_run_directory(self, path: Path) -> None:
        """Record that this run wrote or created the directory at ``path``."""
        self._state.run_dirs.setdefault(self._physical_key(path), set()).add(
            self._physical_path(path)
        )

    def _is_run_directory(self, path: Path, st: os.stat_result) -> bool:
        """Whether the directory at ``path`` (``st`` its ``lstat``) is one this run
        wrote or created, under any spelling: through a symlink the archive created
        (the same physical path), or a case variant on a case-insensitive filesystem
        under every policy (one recorded under the same ``_physical_key`` that is the
        same directory). Where
        the filesystem reports inode 0, a case variant cannot be told from another
        directory and is taken for the caller's, which keeps its mode."""
        recorded = self._state.run_dirs.get(self._physical_key(path))
        if not recorded:
            return False
        if self._physical_path(path) in recorded:
            return True
        if st.st_ino == 0:
            return False
        for other in recorded:
            try:
                if os.path.samestat(st, os.lstat(long_path(other))):
                    return True
            except OSError:
                continue
        return False

    def _prepare_destination(
        self, member: ArchiveMember, dest_path: Path, *, atomic: bool = False
    ) -> bool:
        """Apply the OverwritePolicy. Returns True to proceed with creation, False to
        skip (SKIP over an existing entry). Raises ExtractionError under ERROR when the
        entry exists, and under REPLACE or RENAME when it is a directory that is not
        empty. Uses lstat semantics so a dangling symlink counts as existing.

        ``atomic=True`` is used for FILE and HARDLINK writes, which land via
        ``os.replace()`` over the destination (see ``_write_file_atomic`` /
        ``_place_link``): under REPLACE this leaves an existing **file or symlink** in
        place for that atomic swap (so the old data survives until the new entry is fully
        built, and a symlink is replaced, never written through), removing only an
        existing empty **directory** first — ``os.replace`` cannot overwrite a directory.
        ``atomic=False`` (DIR / SYMLINK) keeps the plain unlink-then-create: a symlink
        must be created at its final name for the escape re-validation's cycle check, and
        a directory cannot be renamed over a file at all."""
        try:
            st = os.lstat(long_path(dest_path))
        except (OSError, ValueError):  # the same errors ``os.path.lexists`` absorbs
            return True
        existing = st.st_mode
        # Replacing a symlink or a directory can move where an earlier link resolves;
        # the member's handler rechecks the links once the member is done.
        moves_links = stat.S_ISLNK(existing) or stat.S_ISDIR(existing)
        # A parked copy of this name (``_park_earlier_copies``) skips the policy: the
        # member replaces it under any policy, as random access would never have
        # written it.
        parked = dest_path in self._current.parked
        if not parked:
            # A real directory recreated as a directory is fine under any policy.
            if member.type == MemberType.DIRECTORY and stat.S_ISDIR(existing):
                return True
            if self._overwrite is OverwritePolicy.ERROR:
                raise self._already_exists(dest_path, member)
            if self._overwrite is OverwritePolicy.SKIP:
                return False
            if (
                self._overwrite is not OverwritePolicy.REPLACE
                and self._overwrite is not OverwritePolicy.RENAME
            ):
                # What follows destroys the existing entry, so a policy nobody taught
                # this chain must not inherit it: an unknown member stops here.
                assert_never(self._overwrite)
            # REPLACE (RENAME members are pre-resolved to a free path, a directory
            # member too when a file or symlink holds its name, so they reach an
            # existing entry here only if it appeared after that check): never
            # write-through a symlink. For an atomic FILE write, os.replace handles a
            # file/symlink target atomically, so only a real directory must be removed
            # up front. Otherwise unlink a symlink/file (bytes never follow the link). A
            # directory is removed only when it is empty.
            if stat.S_ISDIR(existing):
                # Only an empty directory is removed, as GNU tar does without
                # --recursive-unlink. Removing a tree takes the members this run wrote
                # into it, which would then still report EXTRACTED, and the caller's
                # own files when the directory was already there.
                with os.scandir(long_path(dest_path)) as entries:
                    if next(entries, None) is not None:
                        raise ExtractionError(
                            f"Destination is a directory that is not empty: "
                            f"{display_path(self._shown(dest_path))}",
                            member_name=member.name,
                        )
                self._note_link_change(dest_path)
                with self._readonly_cleared(dest_path):
                    os.rmdir(long_path(dest_path))
                # Its member's metadata has no directory left to go on.
                self._drop_pending_dir(dest_path)
                self._current.removed_existing = True
                # A directory member of this run that wrote it no longer has it, so its
                # result is revised (directories are never claimed, so there is no
                # claim to hand over; ``_resolve_collision`` set this member's
                # ``collided_with`` from ``_run_directory_at``). Only under REPLACE:
                # RENAME reaches this arm only after a filesystem race, with nothing of
                # this run's here, and OVERWRITTEN is a REPLACE outcome.
                if self._overwrite is OverwritePolicy.REPLACE:
                    self._revise_removed_directory(dest_path)
                self._forget_source_path(dest_path)
                return True
        # Reached by a parked copy of this name (never a directory), and by REPLACE or
        # RENAME over an existing file or symlink.
        if moves_links:
            self._note_link_change(dest_path)
        if not atomic:
            with self._readonly_cleared(dest_path):
                os.unlink(long_path(dest_path))
            # A parked copy's result is already SUPERSEDED: nothing to revise.
            if not parked:
                self._current.removed_existing = True
        self._forget_source_path(dest_path)
        return True

    def _write_file_atomic(
        self,
        stream: BinaryIO | None,
        dest_path: Path,
        member: ArchiveMember,
        *,
        staged: Path | None = None,
        copy_begins: Callable[[], None] | None = None,
    ) -> None:
        """Write a FILE by streaming into a temp sibling, applying ``member``'s metadata,
        then ``os.replace()``-ing it onto ``dest_path`` — atomic, so a mid-stream failure
        never truncates or removes an existing destination (only the temp is discarded),
        and the target name never appears half-written. The temp lives in the destination
        directory so the rename stays on one filesystem. When the orphan pass materializes
        an unselected hardlink source, ``member`` is the *link's* transformed copy, so the
        file carrying the content gets the link's (policy-capped) mode, not the source's.

        Under TRUSTED, a member with no stored mode gets the mode an ordinary file
        creation would, ``0o666`` less the umask, rather than ``mkstemp``'s private
        ``0o600``. Nothing chmods it afterwards, so the temp's creation mode is the file's
        final mode. STRICT and STANDARD give a mode-less member their own default instead
        (see ``_effective_mode``), so this arm is TRUSTED's alone.

        ``staged`` is the member's data as a pass staged it (``_stage_then_place``),
        created at the ordinary creation mode. It gets ``member``'s metadata and lands
        by the same swap, and ``stream`` is not read: nothing is copied, and nothing is
        counted again, since its bytes were counted when it was staged. Where the swap
        cannot rename it (another filesystem mounted inside the destination), it is
        copied, uncounted, as any stream is.

        ``copy_begins`` is called once the temp file exists, just before the first
        read of ``stream``: the orphan pass blames a failure from then on on the
        source, not the link (``_materialize_at``). A staged write copies nothing, so
        the two are never passed together."""
        assert copy_begins is None or staged is None
        if staged is not None:
            self._land_staged(staged, dest_path, member)
            return
        # Every check that could still skip the member has passed, so a member whose
        # recorded size is already over the ratio is refused before any temp file
        # exists.
        self._state.tracker.check_recorded_size()
        if self._effective_mode(member) is None:
            tmp = self._temp_sibling(dest_path.parent)
            fd = _open_new_file(tmp, 0o666)
        else:
            # mkstemp hands back an already-open fd; write straight into it (no
            # close+reopen). Its 0o600 keeps the content private until the chmod below.
            fd, tmp_name = tempfile.mkstemp(
                dir=long_path(dest_path.parent), prefix=_TMP_PREFIX
            )
            tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as dst:
                if copy_begins is not None:
                    copy_begins()
                # A dry run reads and verifies the body like a real one; only the bytes
                # go nowhere, and the file is left empty.
                self._copy_to_fileobj(
                    stream,
                    dst if self._dry is None else self._dry.sink,
                    self._state.tracker,
                    emit_progress=self._current.emit_progress,
                )
            self._apply_metadata(tmp, member)
            self._swap_into_place(tmp, dest_path, member)
        except BaseException:
            # os.replace consumes the temp on success; on any earlier failure remove it so
            # no .archivey-tmp-* file is left behind (the existing destination is untouched).
            try:
                os.unlink(long_path(tmp))
            except FileNotFoundError:
                pass
            except OSError as exc:
                self._rebase_os_error(exc)
                logger.warning(
                    "Could not remove %r, staged for %r: %s",
                    str(self._shown(tmp)),
                    member.name,
                    exc,
                )
            raise

    def _land_staged(
        self, staged: Path, dest_path: Path, member: ArchiveMember
    ) -> None:
        """Land the staged file ``staged`` on ``dest_path`` (``_write_file_atomic``)."""
        self._apply_metadata(staged, member)
        try:
            self._swap_into_place(staged, dest_path, member)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
        else:
            return
        tmp = self._temp_sibling(dest_path.parent)
        try:
            with (
                open(long_path(staged), "rb") as src,
                os.fdopen(_open_new_file(tmp, 0o600), "wb") as dst,
            ):
                self._copy_to_fileobj(src, dst, None)
            self._apply_metadata(tmp, member)
            if self._effective_mode(member) is None:
                os.chmod(
                    long_path(tmp), stat.S_IMODE(os.stat(long_path(staged)).st_mode)
                )
            self._swap_into_place(tmp, dest_path, member)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(long_path(tmp))
            raise
        with contextlib.suppress(OSError):
            os.unlink(long_path(staged))

    @staticmethod
    def _copy_to_fileobj(
        stream: BinaryIO | None,
        dst: BinaryIO,
        tracker: BombTracker | None,
        emit_progress: Callable[[], None] | None = None,
    ) -> None:
        """Copy ``stream`` into the already-open ``dst`` in chunks, counting each toward the
        bomb tracker. Cleanup of a partial ``dst`` on failure is the caller's job.

        When ``emit_progress`` is set, it is invoked after each full ``_CHUNK`` so callers
        can report intra-member progress (~1 callback/MiB). Short final chunks are left to
        the coordinator's terminal per-member report so sub-chunk members keep a single
        callback. Pass ``None`` (the default) for the zero-cost path.
        """
        if stream is None:
            # A backend bug, not an empty file: a zero-byte FILE still has a stream.
            # Both FILE write paths come through here, so this fails the member in
            # either pass rather than writing an empty file.
            raise ExtractionError(
                "FILE member has no data stream to extract (backend returned stream=None)"
            )
        while True:
            chunk = stream.read(_CHUNK)
            if not chunk:
                break
            if tracker is not None:
                tracker.count(len(chunk))
            dst.write(chunk)
            # Full chunks only: the terminal report covers the final (possibly short) chunk
            # so a sub-chunk member still gets exactly one callback.
            if emit_progress is not None and len(chunk) == _CHUNK:
                emit_progress()

    def _place_link(
        self,
        source_id: int,
        candidates: list[Path],
        new_path: Path,
        member: ArchiveMember,
    ) -> None:
        """Create ``new_path`` as a hardlink to the source's content, trying
        ``candidates`` (the source's recorded on-disk paths, taken before
        ``_make_room`` cleared ``new_path``) newest first; when none takes the link for
        a reason of its own (see ``_link_refused_here``), copy from an existing path.
        Records ``new_path`` under ``source_id`` so a later same-device link can reuse
        it — which is what keeps a fan-out across one device boundary to a single copy
        per device rather than one per link, and a fan-out past the link-count limit to
        one copy per full file. When ``new_path`` already named the source's file, it
        is not recorded twice: the name existed, so ``_prepare_destination`` dropped it
        from the list (``_forget_source_path``) before this method ran.

        The first path at the link-count limit ends the search with a copy. The paths
        recorded before it are older names of the same file, of a file that filled up
        before it, or of a copy on another device, which could not take this link
        either (``EMLINK`` means the destination is on the full file's device). So
        trying each would fail too, and would cost a failed call per recorded path for
        every later link: quadratic in the number of links an archive declares. A file
        that dropped below the limit since (a later member replaced one of its names) is
        not tried again, which costs at most an extra copy.

        The copy is a real write of the source's full size, so it goes through
        ``tracker`` and counts toward ``max_extracted_bytes``; a link adds no bytes.
        It is written into a new file, not ``shutil.copy2``'d, so it carries this
        member's metadata alone, never the source file's mode.

        The link is built at a temp sibling and ``os.replace``d into place, the same way
        a FILE write lands: ``os.link`` needs a free name, so the alternative is to
        unlink an existing destination first and leave a hole if the link then fails.
        ``os.replace`` moves the link itself and never follows the entry it replaces, so
        a destination symlink is replaced rather than written through."""
        if new_path in candidates and _is_regular_file(new_path):
            # The link landed on a path that already holds its source's content (a
            # case-folded name under REPLACE). The callers' ``_make_room`` ran with
            # ``atomic=True``, which leaves an existing file for the swap rather than
            # unlinking it, so the file is still in place and there is nothing to link.
            self._state.source_paths.setdefault(source_id, []).append(new_path)
            return
        # Each path was a regular file this run wrote, and ``_forget_source_path``
        # drops one once another member replaces it. ``candidates`` was taken before
        # the callers' ``_make_room``, so the one path that can be stale here is
        # ``new_path``: the early return above takes it while it is a regular file,
        # and the check below skips it when it is not. Checked again here because
        # ``os.link`` follows a symlink (``follow_symlinks=False`` is not available on
        # every platform): a link made through one would name a file this run did not
        # write. Checked one path at a time as the loop reaches it, so the common case,
        # where the newest path links, checks one path however many links name it.
        tmp = self._temp_sibling(new_path.parent)
        try:
            copied = False
            linked = False
            at_link_limit = False
            copy_from: Path | None = None
            for candidate in reversed(candidates):
                if not _is_regular_file(candidate):
                    continue
                if copy_from is None:
                    copy_from = candidate
                try:
                    os.link(long_path(candidate), long_path(tmp))
                except OSError as exc:
                    if not _link_refused_here(exc):
                        raise
                    if _at_link_limit(exc):
                        at_link_limit = True
                        break
                    continue
                linked = True
                break
            if not linked:
                if copy_from is None:
                    raise ExtractionError(
                        "Hardlink source is no longer on disk as a regular file",
                        member_name=member.name,
                    )
                # No usable path took a link: fall back to a copy.
                # Created private when a mode follows (as mkstemp would), at the ordinary
                # creation mode when none does, the same as a FILE write.
                create_mode = (
                    0o600 if self._effective_mode(member) is not None else 0o666
                )
                with (
                    open(long_path(copy_from), "rb") as src,
                    os.fdopen(_open_new_file(tmp, create_mode), "wb") as dst,
                ):
                    while chunk := src.read(_CHUNK):
                        self._state.tracker.count_copy(
                            len(chunk), at_link_limit=at_link_limit
                        )
                        dst.write(chunk)
                copied = True
            if copied:
                # Applied before the swap, so the final name never appears with the
                # source's metadata instead of this member's.
                self._apply_metadata(tmp, member)
            self._swap_into_place(tmp, new_path, member)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(long_path(tmp))
            raise
        self._state.source_paths.setdefault(source_id, []).append(new_path)

    def _already_exists(self, dest: Path, member: ArchiveMember) -> ExtractionError:
        """The error ``OverwritePolicy.ERROR`` raises for an entry at ``dest``, from the
        existence check and from a landing that finds the name taken after it."""
        return ExtractionError(
            f"Destination already exists: {display_path(self._shown(dest))}",
            member_name=member.name,
        )

    def _taken_after_check(self, dest: Path, *, atomic: bool) -> bool:
        """Whether, under ``OverwritePolicy.ERROR``, ``dest`` is now taken by something
        that was not there at the existence check: another writer into the same folder,
        such as a second extraction. Asked by every landing whose creation refuses a
        taken name: the ``os.replace`` of a FILE or HARDLINK (``atomic``), and the
        ``os.symlink`` of a SYMLINK and the ``os.makedirs`` of a DIRECTORY.

        Under ERROR the check lets a member through only to a free name, to a copy this
        run parked (``_park_earlier_copies``), or, for a DIRECTORY member, to an existing
        directory. An atomic landing replaces a parked copy where it stands, so that
        copy does not count (``_occupied``); the other landings removed it in
        ``_prepare_destination``. ``os.makedirs(exist_ok=True)`` never raises for an
        existing directory, so a ``FileExistsError`` there means a non-directory. So
        anything a landing is refused over appeared after the check. Under the other
        policies a landing that fails this way is not handled: its error goes out as it
        is."""
        if self._overwrite is not OverwritePolicy.ERROR:
            return False
        return self._occupied(dest) if atomic else os.path.lexists(long_path(dest))

    def _swap_into_place(self, tmp: Path, dest: Path, member: ArchiveMember) -> None:
        """Move the staged temp ``tmp`` onto ``dest`` with ``os.replace``, the last step
        of every atomic write (``_write_file_atomic``, ``_place_link``).

        POSIX ``rename(2)`` does nothing, and reports success, when ``tmp`` and ``dest``
        are already names of the same file. That happens when ``_place_link`` links a
        file onto another of its own names (a hard link listed twice, or one REPLACE
        routes onto a link to the same file). ``dest`` then already names the right
        file, so only the temp name is left, and it is removed here. After a real
        rename the temp name is gone and the unlink finds nothing. The unlink covers
        Windows either way.

        Any error from the unlink is ignored: ``os.replace`` has already put the member
        in place, and a temp name left behind is a stray the docs call safe to delete,
        not a failed write. The unlink stays inside the ``_readonly_cleared`` block. On
        Windows that block's exit puts the read-only attribute back on the other names of
        ``dest``'s file, and in the same-file case the temp is one of them, so an unlink
        after the block would fail.

        A rename refused onto an entry that appeared after the existence check is, under
        ERROR, the clash that check reports, and raises its error
        (``_taken_after_check``). Windows refuses it with access denied (seen with two
        extractions into one folder); POSIX refuses it in a sticky directory when someone
        else owns the entry, and otherwise replaces it."""
        with self._readonly_cleared(dest):
            try:
                os.replace(long_path(tmp), long_path(dest))
            except PermissionError as exc:
                if not self._taken_after_check(dest, atomic=True):
                    raise
                raise self._already_exists(dest, member) from exc
            with contextlib.suppress(OSError):
                os.unlink(long_path(tmp))

    @staticmethod
    def _temp_sibling(parent: Path) -> Path:
        """A free ``.archivey-tmp-*`` name in ``parent`` for an atomic swap.

        Unlike ``_write_file_atomic`` this cannot use ``mkstemp``: ``os.link`` needs a
        name that does *not* exist. The destination is trusted at rest (see the threat
        model), and ``os.link`` / ``os.replace`` fail loudly on a name that appeared
        underneath us, so a uuid4 name is enough."""
        while True:
            candidate = parent / f"{_TMP_PREFIX}{uuid.uuid4().hex}"
            if not os.path.lexists(long_path(candidate)):
                return candidate

    def _defer_directory_metadata(self, path: Path, member: ArchiveMember) -> None:
        """Keep ``member``'s ownership, mode and times for the directory just made at
        ``path`` until the run ends (``_apply_directory_metadata``).

        Applied at once, a stored mode without owner write or search permission
        (``0o555``, ``0o644``) refused every member inside the directory to a non-root
        user, and each entry written inside moved the directory's mtime. GNU tar,
        bsdtar and Python's ``tarfile`` defer them the same way.
        """
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return
        physical = self._physical_path(path)
        depth = self._rel_name(physical).count("/")
        pending = self._state.pending_dirs.setdefault(self._physical_key(path), {})
        # Moved to the end, so where two spellings reach one directory (a case
        # variant), the member written last is applied last.
        pending.pop(physical, None)
        pending[physical] = ((st.st_dev, st.st_ino), depth, member)

    def _drop_pending_dir(self, path: Path) -> None:
        """Drop the deferred metadata of the directory at ``path``, which is being
        removed, under whichever spelling it was written.

        Found by ``_physical_key``, under every policy: the entry at the same physical
        path is dropped, and so is one under a case variant that is gone from disk. A
        casefolded key also covers another directory on a
        case-sensitive filesystem (``X/`` beside ``x/``); that one is still there, and
        keeps its entry."""
        key = self._physical_key(path)
        pending = self._state.pending_dirs.get(key)
        if not pending:
            return
        physical = self._physical_path(path)
        for other in list(pending):
            if other == physical or not os.path.lexists(long_path(other)):
                del pending[other]
        if not pending:
            del self._state.pending_dirs[key]

    def _apply_directory_metadata(self) -> None:
        """Apply the deferred directory metadata (``_defer_directory_metadata``),
        deepest first, so a parent's mode never stops the run from reaching a
        directory inside it. Best-effort, as ``_apply_metadata`` is.

        A directory is changed only when the entry at its path is still the directory
        this run made: a later member may have replaced it, with a symlink to another
        directory for example. Each ``os.rmdir`` this run makes also drops the entry
        recorded at that path, which matters where a filesystem reports inode 0 and
        this check cannot tell two directories apart. Where the platform can, the
        directory is opened without following a symlink and changed through that
        descriptor, so nothing put at the path after the check is changed either.
        Elsewhere (Windows), or when the directory cannot be opened (a umask without
        owner read), the check is an ``lstat`` and the change goes by path.
        """
        pending = self._state.pending_dirs
        # Windows has no ``os.chown`` and takes no descriptor here.
        by_fd = hasattr(os, "chown") and all(
            f in os.supports_fd for f in (os.chmod, os.utime, os.chown)
        )
        flags = os.O_RDONLY
        for extra in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
            flags |= getattr(os, extra, 0)

        def is_ours(st: os.stat_result, identity: tuple[int, int]) -> bool:
            return stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == identity

        entries = [item for by_key in pending.values() for item in by_key.items()]
        for path, (identity, _depth, member) in sorted(
            entries, key=lambda item: item[1][1], reverse=True
        ):
            if by_fd:
                try:
                    fd = os.open(long_path(path), flags)
                except PermissionError:
                    pass
                except OSError:
                    continue
                else:
                    try:
                        if is_ours(os.fstat(fd), identity):
                            self._apply_metadata(fd, member)
                    finally:
                        os.close(fd)
                    continue
            try:
                if is_ours(os.lstat(long_path(path)), identity):
                    self._apply_metadata(path, member)
            except OSError:
                pass
        pending.clear()

    def _effective_mode(self, member: ArchiveMember) -> int | None:
        """The mode to give what ``member`` writes; ``None`` means the creation default.

        The policy transforms fill in a missing mode, but a user filter runs after them
        and may hand back ``mode=None``. STRICT and STANDARD still owe their documented
        default then (file ``0o644``, dir ``0o755``), not whatever the umask leaves.
        Only TRUSTED means "as stored", and a member that stored nothing gets the
        creation default.
        """
        if member.mode is not None or self._policy is ExtractionPolicy.TRUSTED:
            return member.mode
        return 0o755 if member.is_dir else 0o644

    def _apply_metadata(self, path: Path | int, member: ArchiveMember) -> None:
        """Best-effort ownership / mode / mtime. Failures are swallowed (best-effort).
        ``path`` may be an open descriptor, where the platform takes one.

        Ownership goes first: Linux ``chown`` clears setuid/setgid on a non-directory
        even when root calls it, so a ``chmod`` before it would lose exactly the bits
        TRUSTED promises to keep. GNU tar orders the two the same way for this reason.
        """
        target = path if isinstance(path, int) else long_path(path)
        # Ownership only under TRUSTED as root (STRICT/STANDARD never chown). A
        # negative id is skipped (-1 means "leave unchanged" to chown), and one past
        # uid_t raises OverflowError before any syscall: both are archive content.
        if (
            self._policy is ExtractionPolicy.TRUSTED
            and member.uid is not None
            and member.gid is not None
            and member.uid >= 0
            and member.gid >= 0
            and hasattr(os, "geteuid")
            and os.geteuid() == 0
        ):
            try:
                os.chown(target, member.uid, member.gid)
            except (OSError, OverflowError):
                pass
        mode = self._effective_mode(member)
        if mode is not None:
            try:
                os.chmod(target, mode)
            except OSError:
                pass
        if member.modified is not None:
            try:
                ts = member.modified.timestamp()
                os.utime(target, (ts, ts))
            except (OSError, ValueError, OverflowError):
                pass

    # --- progress / misc -----------------------------------------------------------

    def _estimate_total_bytes(
        self, all_members: list[ArchiveMember] | None
    ) -> int | None:
        if all_members is None:
            return None
        if any(m.is_file and m.size is None for m in all_members):
            return None
        return sum(m.size or 0 for m in all_members if m.is_file)

    def _report_progress(
        self, member: ArchiveMember, members_done: int, member_bytes_written: int
    ) -> None:
        if self._on_progress is None:
            return
        state = self._state
        self._on_progress(
            ExtractionProgress(
                member=member,
                bytes_written=state.tracker.total_bytes,
                total_bytes_estimated=state.total_estimate,
                members_done=members_done,
                members_total=state.members_total,
                member_bytes_written=member_bytes_written,
                members_extracted=state.members_extracted,
                members_blocked=state.members_blocked,
            )
        )

    @staticmethod
    def _close(stream: BinaryIO | None) -> None:
        """Close a member stream once its result is recorded.

        Best-effort: the member's result already stands, and every content verdict fired
        from a read (ADR 0014), so a close failure has no result left to change. An
        interrupt still propagates.
        """
        if stream is not None:
            try:
                stream.close()
            except Exception:  # noqa: BLE001, S110 - teardown hygiene; the result is recorded
                pass
