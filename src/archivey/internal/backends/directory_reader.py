"""Directory pseudo-backend: presents a filesystem directory as an ArchiveReader.

Uniformity principle (`format-directory`): this reader is never more lenient than
archive readers. Declared member-stream capabilities (`MemberStreams.CONCURRENT` /
`SEEKABLE`) gate concurrent opens and seekability here exactly as for ZIP/TAR/ISO —
the directory backend exists to keep archive-vs-directory code uniform, not to offer a
more permissive escape hatch.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import NamedTuple

from archivey.config import ArchiveyConfig
from archivey.cost import (
    AccessCost,
    CostReceipt,
    ListingCost,
    StreamCapability,
)
from archivey.diagnostics import DiagnosticCode, ScanRaceContext
from archivey.exceptions import ExtractionError
from archivey.internal.base_reader import (
    BaseArchiveReader,
    ReadBackend,
    reject_start_offset,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.filters import resolve_or_raise_on_loop
from archivey.internal.logs import backends as logger
from archivey.internal.open_site import OpenSite
from archivey.internal.password import _PasswordCandidates
from archivey.internal.registry import register_reader
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.timestamps import unix_to_datetime
from archivey.internal.windows_reparse import FILE_ATTRIBUTE_REPARSE_POINT
from archivey.terminal import display_path, quoted
from archivey.types import (
    EXTRA_IS_JUNCTION,
    EXTRA_IS_REPARSE_POINT,
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    MagicSignature,
    MemberExtra,
    MemberStreams,
    MemberType,
)


def _link_extra(member_type: MemberType, is_junction: bool) -> MemberExtra:
    """The junction / reparse-point keys for a live filesystem entry.

    On Windows a symlink *is* a reparse point — there is no other kind — so the flag
    follows from the platform rather than from anything stored. Elsewhere a symlink is
    a POSIX one and neither key applies, junctions included: `os.DirEntry.is_junction`
    only reports true on Windows.
    """
    extra = MemberExtra()
    if is_junction:
        extra[EXTRA_IS_JUNCTION] = True
    if member_type == MemberType.SYMLINK and os.name == "nt":
        extra[EXTRA_IS_REPARSE_POINT] = True
    return extra


# `os.DirEntry.stat` on Windows serves the data scandir already has, in which st_ino,
# st_dev and st_nlink are always zero.
_STAT_LACKS_IDENTITY = os.name == "nt"


def _identity_stat(path: str) -> os.stat_result:
    """A fresh ``lstat`` of ``path``, for the file identity scandir's data lacks.

    A seam for tests: they replace it to simulate Windows without patching ``os.stat``.
    """
    return os.stat(path, follow_symlinks=False)


# POSIX platforms with `O_NOFOLLOW` and `dir_fd` support open members component by
# component; Windows has neither and relies on the identity check.
_HAS_NOFOLLOW = hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
# The walk scans each subdirectory through a descriptor opened with `O_NOFOLLOW` (by
# path, or component by component with `openat` when the listing has no identity to
# check), lists it with `os.scandir(fd)` and reads links in it with `readlinkat`. Where
# any of those is missing it scans by path.
_SCAN_BY_FD = (
    _HAS_NOFOLLOW and os.scandir in os.supports_fd and os.readlink in os.supports_dir_fd
)


class _Identity(NamedTuple):
    """An entry's ``(st_dev, st_ino)`` from the listing.

    A FILE member carries it in its ``_raw``; the walk keeps one per subdirectory it
    has yet to scan.
    """

    dev: int
    ino: int

    @classmethod
    def of(cls, st: os.stat_result) -> _Identity | None:
        """``st``'s identity, or ``None`` for ``st_ino`` 0, which is no identity.

        Windows' scandir data, some FUSE and network mounts report 0 for every file.
        """
        return cls(st.st_dev, st.st_ino) if st.st_ino else None


def _file_attributes(path: str) -> int:
    """Windows' ``st_file_attributes`` of ``path`` itself (0 elsewhere).

    A seam for tests, like `_identity_stat`: the reparse-point refusal can be reached
    on POSIX only by replacing this.
    """
    return getattr(os.lstat(path), "st_file_attributes", 0)


def _changed_since_listing(name: str, what: str, action: str = "reading") -> OSError:
    """The refusal for a member whose path no longer holds the file the walk listed.

    The message is left unescaped: it is a plain OSError, and the print site escapes a
    non-archivey exception once (`cli/format.py`'s ``format_error_detail``), so the
    name is delimited with ``quoted``, as `_format_os_error` in `cli/main.py` does.
    """
    return OSError(
        errno.ESTALE,
        f"{quoted(name)} {what} since the directory was listed; not {action} it",
    )


def _is_junction(entry: os.DirEntry[str]) -> bool:
    """True if a scandir entry is a Windows NTFS junction.

    ``os.DirEntry.is_junction()`` only exists on Python 3.12+; on older interpreters
    (and on every non-Windows platform, where junctions don't exist) this returns False.
    """
    is_junction = getattr(entry, "is_junction", None)
    return bool(is_junction()) if is_junction is not None else False


class DirectoryReader(BaseArchiveReader):
    """Reads a filesystem directory as an archive."""

    # A filesystem directory has no O(1) upfront index: enumerating members is an
    # os.scandir walk (a scan). So this is False (like plain TAR) — members_report_if_available()
    # returns None rather than triggering an uncached walk on every call, and the walk only runs
    # once under the materialization election (which also removes the free-threaded cache race on
    # _uname_cache/_gname_cache). See format-directory.
    _MEMBER_LIST_UPFRONT = False

    def __init__(
        self,
        root: Path,
        streaming: bool,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
    ) -> None:
        super().__init__(
            ArchiveFormat.DIRECTORY,
            streaming,
            archive_name,
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
        self._root = root
        # uid/gid -> name caches: most entries in a tree share an owner/group, and
        # pwd/grp lookups hit the system database (nss) on every call, so we memoize.
        self._uname_cache: dict[int, str | None] = {}
        self._gname_cache: dict[int, str | None] = {}

    def _check_extraction_dest(self, dest: Path) -> None:
        # Extracting a tree into a directory inside it reads its own output: a
        # streaming walk descends into what it just wrote (`copy/copy/copy/...`)
        # until a path is too long, and a listing taken later includes it. `cp -r`
        # refuses the same request.
        #
        # A dest that does not resolve is left to the shared path, so it fails as on
        # every other backend: under a symlink loop, mkdir raises OSError (ELOOP); a
        # dest that is itself a looping link exists and is not a directory, so it is
        # refused with ExtractionError. A source root that does not resolve skips the
        # check too, and the walk fails on it a moment later. So neither case writes
        # members into the source, but in the second the dest directory itself may
        # already be created inside the source, as it was with 3.13's resolve().
        try:
            root = resolve_or_raise_on_loop(self._root)
            target = resolve_or_raise_on_loop(dest)
        except OSError:
            return
        if target == root or target.is_relative_to(root):
            raise ExtractionError(
                f"Cannot extract a directory into itself: {display_path(dest)} is "
                f"inside the source {display_path(self._root)}"
            )

    def _iter_members(self) -> Iterator[ArchiveMember]:
        # An explicit stack rather than recursion: a tree deeper than the interpreter's
        # recursion limit (easy to produce by extracting an archive of `a/a/a/…/f`)
        # must list like any other, and a member is yielded straight to the caller
        # instead of being passed up one generator frame per level of depth.
        #
        # Order is a depth-first preorder: at each level the non-directory entries
        # (sorted by name), then each subdirectory's own member followed by its whole
        # subtree. Subdirectories are pushed in reverse so they pop in name order.
        #
        # `first_names` maps a multiply-linked file's (st_dev, st_ino) to the first name
        # the walk gave it, so later names list as HARDLINK members pointing there, the
        # way a tar records them. It lives for one walk: each pass decides afresh.
        pending: list[tuple[ArchiveMember, Path, _Identity | None]] = []
        first_names: dict[tuple[int, int], str] = {}
        yield from self._scan_level(self._root, "", None, pending, first_names)
        while pending:
            member, path, identity = pending.pop()
            yield member
            yield from self._scan_level(
                path, member.name, identity, pending, first_names
            )

    def _scan_level(
        self,
        directory: Path,
        rel_prefix: str,
        expected: _Identity | None,
        pending: list[tuple[ArchiveMember, Path, _Identity | None]],
        first_names: dict[tuple[int, int], str],
    ) -> Iterator[ArchiveMember]:
        """Yield one directory's non-directory entries; push its subdirectories.

        The subdirectories go onto ``pending`` (the walk's stack, see `_iter_members`)
        in reverse name order, so the caller pops them in name order. They are pushed
        only when this generator is exhausted: a caller that stops early (``break``,
        ``islice``, a peek with ``next``) leaves them off the stack and silently loses
        those subtrees, so drain it before reading ``pending``.

        ``expected`` is the subdirectory's identity from its parent's scan (``None``
        for the root, and where the filesystem reports ``st_ino`` 0). Another process can
        swap a listed subdirectory for a symlink out of the root before the walk gets
        to it, and scanning that path would list the target's entries as members
        (threat-model O21). So where the platform allows it the subdirectory is opened
        with ``O_NOFOLLOW`` and scanned through that descriptor, and a descriptor that
        is not the listed directory is refused with ``OSError(ESTALE)``, as a read of a
        replaced file is, and so is a symlink in its place.
        """
        # os.scandir yields DirEntry objects whose stat() is cached, so we avoid a
        # separate os.stat()/os.lstat() syscall per entry.
        #
        # Errors: a live filesystem can change under the walk, so an entry (or a whole
        # subdirectory) that vanished between being listed and being inspected is
        # skipped with a warning — a race, not an error. Every other OSError (permission
        # denied, I/O failure) propagates unchanged: silently dropping entries would
        # present an incomplete listing as complete (see the design authority in
        # `openspec/project.md` — no silent guesses — and `error-handling`'s rule that
        # genuine I/O errors are never swallowed or reclassified).
        try:
            dir_fd = self._open_listed_directory(directory, rel_prefix, expected)
            try:
                with os.scandir(directory if dir_fd is None else dir_fd) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except BaseException:
                if dir_fd is not None:
                    os.close(dir_fd)
                raise
        except FileNotFoundError:
            relative = rel_prefix.rstrip("/") or "."
            self._diagnostics_collector.emit(
                code=DiagnosticCode.SCAN_DIRECTORY_VANISHED,
                message=f"Directory vanished during scan, skipping: {quoted(str(directory))}",
                context=ScanRaceContext(
                    archive_name=self._archive_name,
                    relative_path=relative,
                    entry_kind="directory",
                ),
                logger=logger,
            )
            return

        # Entries scanned through a descriptor are inspected through it too (`lstat`
        # and `readlink` relative to it), so they come from the directory that was
        # checked, whatever happens to its path meanwhile. So `dir_fd` must stay open
        # until the last entry is inspected: `os.scandir(fd)` dups the descriptor for
        # its own iterator, and closing that iterator leaves `dir_fd` open, but each
        # `DirEntry` resolves `stat()` through `dir_fd` itself. Closed any earlier, an
        # entry's `stat()` fails with `EBADF`, or runs in whatever directory reused the
        # number.
        try:
            yield from self._scan_entries(
                entries, directory, dir_fd, rel_prefix, pending, first_names
            )
        finally:
            if dir_fd is not None:
                os.close(dir_fd)

    def _scan_entries(
        self,
        entries: list[os.DirEntry[str]],
        directory: Path,
        dir_fd: int | None,
        rel_prefix: str,
        pending: list[tuple[ArchiveMember, Path, _Identity | None]],
        first_names: dict[tuple[int, int], str],
    ) -> Iterator[ArchiveMember]:
        """The body of `_scan_level`, for one directory's sorted entries."""
        # Emit all non-directory entries at this level now; the subdirectories are
        # collected and handed to the walk's stack, so a directory's own files come
        # before anything inside its children.
        subdirs: list[tuple[ArchiveMember, Path, _Identity | None]] = []
        for entry in entries:
            rel_path = rel_prefix + entry.name
            # Scanned through a descriptor, `entry.path` is the bare name.
            entry_path = os.path.join(directory, entry.name)
            # `stat` and `readlink` race the same window on the same entry — listed by
            # scandir, gone before we inspect it — so both sit inside the one guard.
            #
            # The type comes from that `lstat`, not from scandir's snapshot, so an entry
            # replaced in the window (a symlink swapped for a file) is typed as what is
            # there now and `readlink` only runs on something that is a link. Only the
            # junction test still reads the entry: a junction's reparse tag is not in
            # `st_mode`, which reports it as a directory. On Windows `DirEntry.stat`
            # serves scandir's own data without a syscall; the identity stat below
            # refreshes it for entries scandir saw as regular files, so there the
            # window narrows for those only, and a directory or link replaced in it
            # still fails.
            try:
                st = entry.stat(follow_symlinks=False)
                if _STAT_LACKS_IDENTITY and stat.S_ISREG(st.st_mode):
                    st = self._stat_with_identity(entry_path, st)
                is_symlink = stat.S_ISLNK(st.st_mode)
                is_junction = not is_symlink and _is_junction(entry)
                link_target = (
                    self._read_link_target(entry_path, entry.name, dir_fd)
                    if is_symlink or is_junction
                    else None
                )
            except FileNotFoundError:
                self._diagnostics_collector.emit(
                    code=DiagnosticCode.SCAN_ENTRY_VANISHED,
                    message=f"Entry vanished during scan, skipping: {quoted(entry_path)}",
                    context=ScanRaceContext(
                        archive_name=self._archive_name,
                        relative_path=rel_path,
                        entry_kind="entry",
                    ),
                    logger=logger,
                )
                continue

            if is_symlink:
                yield self._make_member(rel_path, st, MemberType.SYMLINK, link_target)
            elif is_junction:
                # A Windows NTFS junction points at a directory but is a reparse point,
                # not a real subtree to walk — surface it as a symlink-like leaf (flagged
                # via extra[EXTRA_IS_JUNCTION]) and do NOT recurse through it.
                yield self._make_member(
                    rel_path,
                    st,
                    MemberType.SYMLINK,
                    link_target,
                    is_junction=True,
                )
            elif stat.S_ISDIR(st.st_mode):
                member = self._make_member(
                    rel_path + "/", st, MemberType.DIRECTORY, None
                )
                subdirs.append((member, Path(entry_path), _Identity.of(st)))
            elif stat.S_ISREG(st.st_mode):
                first_name = None
                identity = _Identity.of(st)
                # Grouping files with no identity would link unrelated ones.
                if st.st_nlink > 1 and identity is not None:
                    first_name = first_names.setdefault(identity, rel_path)
                if first_name is not None and first_name != rel_path:
                    yield self._make_member(
                        rel_path, st, MemberType.HARDLINK, first_name
                    )
                else:
                    # The listing's identity rides on the member (`_raw`), so opening it
                    # can refuse whatever was put at that path since (threat-model O21).
                    yield self._make_member(
                        rel_path, st, MemberType.FILE, None, identity=identity
                    )
            else:
                yield self._make_member(rel_path, st, MemberType.OTHER, None)

        pending.extend(reversed(subdirs))

    def _open_listed_directory(
        self, directory: Path, rel_prefix: str, expected: _Identity | None
    ) -> int | None:
        """A descriptor on the directory the listing saw at ``directory``, or ``None``.

        ``None`` means the level is scanned by path: the root (``rel_prefix`` is
        empty; the caller chose it, and it may be a symlink), or a platform without
        the calls the descriptor walk needs (`_SCAN_BY_FD`). Otherwise nothing on the
        way is followed. With the listing's identity, the path is opened with
        ``O_NOFOLLOW | O_DIRECTORY``, so a symlink put in its place fails, and the
        handle must be the listed directory: a directory above it swapped for a
        symlink resolves the path elsewhere, which the identity catches. A directory
        listed with no identity (``st_ino`` 0: some FUSE and network mounts) has
        nothing to compare, so it is opened one component at a time from the root
        instead, each with ``O_NOFOLLOW``, and a symlink anywhere on the path fails.
        So is a path too long to open whole (``ENAMETOOLONG``, deeper than
        ``PATH_MAX``), which then still gets the identity check. The walk opens the
        last component ``O_DIRECTORY`` too, and with no identity that is the only
        refusal of a non-directory swapped in.

        A symlink in the way fails in the kernel (``ENOTDIR`` on Linux, ``ELOOP``
        elsewhere); that is reported like a replaced directory, with the kernel's
        error as the cause. Every other ``OSError`` propagates unchanged, in
        particular ``FileNotFoundError``, which `_scan_level` reports as a vanished
        directory.
        """
        if not _SCAN_BY_FD or not rel_prefix:
            return None
        name = rel_prefix.rstrip("/")
        try:
            if expected is None:
                return self._open_nofollow(name, _O_DIRECTORY)
            try:
                fd = os.open(
                    directory,
                    os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
            except OSError as exc:
                if exc.errno != errno.ENAMETOOLONG:
                    raise
                # Past PATH_MAX the whole path cannot be opened; walk it one component
                # at a time instead, as reading a member does. The identity check
                # below still applies.
                fd = self._open_nofollow(name, _O_DIRECTORY)
        except OSError as exc:
            if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                raise _changed_since_listing(name, "was replaced", "scanning") from exc
            raise
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != expected:
                raise _changed_since_listing(name, "was replaced", "scanning")
        except BaseException:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def _stat_with_identity(path: str, cached: os.stat_result) -> os.stat_result:
        """Windows only: re-stat a regular file for st_ino, st_dev and st_nlink.

        Hardlink detection needs them and scandir's data has them all zero. The fresh
        stat takes a path where scandir needed none, so a path past ``MAX_PATH``
        without long-path support can fail here with ``FileNotFoundError`` for a file
        that exists. That is not a vanished entry: keep scandir's data, which lists it
        as a plain ``FILE``, as before hardlinks were detected. A file that really did
        vanish in this window lists the same way, as it did then; opening it fails
        later. Any other ``OSError`` propagates like every genuine error in the walk.
        """
        try:
            return _identity_stat(path)
        except FileNotFoundError:
            return cached

    @staticmethod
    def _read_link_target(path: str, name: str, dir_fd: int | None) -> str:
        """The symlink/junction target, with separators normalized like member names.

        ``name`` is read relative to ``dir_fd`` when the level was scanned through one,
        and ``path`` is read otherwise.

        On Windows ``os.readlink`` returns the target with ``\\`` separators; convert
        them to ``/`` so link targets live in the same namespace as member names (where
        the separator conversion is likewise applied only for Windows-origin paths — on
        POSIX a backslash is a literal filename character and is kept).
        """
        target = (
            os.readlink(path) if dir_fd is None else os.readlink(name, dir_fd=dir_fd)
        )
        if os.name == "nt":
            target = target.replace("\\", "/")
        return target

    def _make_member(
        self,
        name: str,
        st: os.stat_result,
        member_type: MemberType,
        link_target: str | None,
        is_junction: bool = False,
        identity: _Identity | None = None,
    ) -> ArchiveMember:
        # `name` is built from live filesystem entries (already "/"-separated, no
        # "."/".."/leading-slash components), so it is normalize_member_name()-clean by
        # construction — unlike names decoded from an archive, which every real backend
        # must route through that helper.
        #
        # Timestamps are guarded like every backend's (see internal/timestamps.py): a
        # network/FUSE filesystem can report a value outside datetime's range, which
        # lists as None rather than sinking the whole walk. A pre-1970 value is a real
        # date on every platform.
        modified = unix_to_datetime(st.st_mtime)
        accessed = unix_to_datetime(st.st_atime)
        # st_birthtime is the true creation time but only exists on some platforms
        # (macOS/BSD, Windows; never Linux); st_ctime is metadata-change time on
        # Unix, NOT creation, so we never use it for `created`. Hence the getattr.
        birthtime = getattr(st, "st_birthtime", None)
        created = unix_to_datetime(birthtime) if birthtime is not None else None
        # On Windows st_ctime was the creation time before 3.12 (deprecated since),
        # so it is only an inode change time elsewhere.
        ctime = unix_to_datetime(st.st_ctime) if os.name != "nt" else None

        # os.stat_result always defines st_uid/st_gid (both 0 on Windows), so no
        # getattr guard is needed.
        uid = st.st_uid
        gid = st.st_gid

        size = st.st_size if member_type == MemberType.FILE else None

        return ArchiveMember(
            type=member_type,
            name=name,
            raw_name=name.encode("utf-8", errors="surrogateescape"),
            size=size,
            compressed_size=size,  # no compression
            modified=modified,
            accessed=accessed,
            created=created,
            ctime=ctime,
            mode=stat.S_IMODE(st.st_mode),
            uid=uid,
            gid=gid,
            uname=self._lookup_uname(uid),
            gname=self._lookup_gname(gid),
            link_target=link_target,
            extra=_link_extra(member_type, is_junction),
            _raw=identity,
        )

    def _lookup_uname(self, uid: int) -> str | None:
        if uid not in self._uname_cache:
            try:
                import pwd

                self._uname_cache[uid] = pwd.getpwuid(uid).pw_name
            except (ImportError, KeyError):
                self._uname_cache[uid] = None
        return self._uname_cache[uid]

    def _lookup_gname(self, gid: int) -> str | None:
        if gid not in self._gname_cache:
            try:
                import grp

                self._gname_cache[gid] = grp.getgrgid(gid).gr_name
            except (ImportError, KeyError):
                self._gname_cache[gid] = None
        return self._gname_cache[gid]

    def _open_member(self, member: ArchiveMember) -> ArchiveStream:
        # Wrapped like every backend's member stream (the uniform-handle contract): the
        # directory backend has no translator (a genuine OSError propagates unchanged,
        # and the refusals `_open_listed_file` raises for a member that no longer
        # matches the listing are OSError too: a backend serving raw bytes through no
        # decoding library does not wrap OSError, per the error-handling spec), but the
        # caller still gets the same ArchiveStream handle type — with its `size`
        # advertisement — as for any other format.
        identity = member._raw if isinstance(member._raw, _Identity) else None
        raw = os.fdopen(
            self._open_listed_file(member.name, member.size, identity), "rb"
        )
        return self._wrap_member_stream(raw, member.name, size=member.size)

    def _open_listed_file(
        self, name: str, listed_size: int | None, expected: _Identity | None
    ) -> int:
        """A read-only descriptor on the file the listing saw at ``name``, or ``OSError``.

        Another process may change the tree between the walk and this open, and a read
        must not leave the root (threat-model O21). So nothing on the way is followed:
        on POSIX each directory component is opened with ``O_NOFOLLOW`` relative to its
        parent, and the file itself with ``O_NOFOLLOW | O_NONBLOCK`` (a FIFO swapped in
        must not block the open). The handle must then be a regular file, and the same
        ``(st_dev, st_ino)`` the listing recorded when it had one. A symlink in the path
        fails with ``ELOOP`` from the kernel; anything else that changed fails with
        ``ESTALE``, as does a file whose size is no longer the listed one (a listed size
        of 0 is exempt: procfs and sysfs list 0 for files that have content). A member
        listed with no identity (``st_ino`` 0) is checked on type and size alone.
        Windows has no ``O_NOFOLLOW``, so there the identity check carries it, with a
        reparse-point check on the path when the listing had no identity.
        """
        path = os.path.join(self._root, name)
        if _HAS_NOFOLLOW:
            fd = self._open_nofollow(name, os.O_NONBLOCK)
        else:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise _changed_since_listing(name, "is no longer a regular file")
            if _HAS_NOFOLLOW:
                # O_NONBLOCK was only for the open (a FIFO must not block it); drop it
                # before the descriptor is read through a buffered reader.
                os.set_blocking(fd, True)
            if expected is not None and (st.st_dev, st.st_ino) != expected:
                raise _changed_since_listing(name, "was replaced")
            # The listed size is part of what was listed, not advisory: a caller treating
            # the listing as a manifest must not read bytes it never described (chosen
            # over a diagnostic in PR #501; directory.md §6).
            if listed_size and st.st_size != listed_size:
                raise _changed_since_listing(
                    name, f"changed size ({listed_size} to {st.st_size} bytes)"
                )
            if (
                expected is None
                and not _HAS_NOFOLLOW
                and _file_attributes(path) & FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise _changed_since_listing(name, "is now a reparse point")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _open_nofollow(self, name: str, leaf_flags: int) -> int:
        """POSIX: open ``name`` under the root one component at a time, following nothing.

        The root is opened without ``O_NOFOLLOW``: the caller chose it, and it may be
        a symlink. Each directory on the way is opened ``O_DIRECTORY | O_NOFOLLOW``,
        and the last component ``O_NOFOLLOW | leaf_flags``: ``O_DIRECTORY`` for a
        directory to scan, ``O_NONBLOCK`` for a member to read.
        """
        *dirs, leaf = name.split("/")
        fd = os.open(self._root, os.O_RDONLY | _O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in dirs:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = next_fd
            return os.open(
                leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | leaf_flags, dir_fd=fd
            )
        finally:
            os.close(fd)

    def _get_archive_info(self) -> ArchiveInfo:
        cost = CostReceipt(
            # A directory has no O(1) index; listing walks the tree header-to-header
            # (an os.scandir walk) without decompressing, exactly like a plain TAR.
            listing_cost=ListingCost.REQUIRES_SCANNING,
            access_cost=AccessCost.DIRECT,
            stream_capability=StreamCapability.SEEKABLE,
            solid_block_count=None,
        )
        return ArchiveInfo(
            format=ArchiveFormat.DIRECTORY,
            format_version=None,
            is_solid=False,
            member_count=None,  # unknown until walked
            comment=None,
            is_encrypted=False,
            is_multivolume=False,
            cost=cost,
        )

    def _close_archive(self) -> None:
        pass  # nothing to close for filesystem directory


class DirectoryReadBackend(ReadBackend):
    """Backend factory for directory pseudo-archives."""

    FORMATS: tuple[ArchiveFormat, ...] = (ArchiveFormat.DIRECTORY,)
    EXTENSIONS: Mapping[str, ArchiveFormat] = {}
    MAGIC: tuple[MagicSignature, ...] = ()

    def open_read(
        self,
        source: ArchiveSource,
        format: ArchiveFormat,
        streaming: bool,
        passwords: _PasswordCandidates | None,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        collector: DiagnosticCollector | None = None,
        member_streams: MemberStreams = MemberStreams(0),
        open_site: OpenSite | None = None,
        start_offset: int = 0,
    ) -> DirectoryReader:
        reject_start_offset(start_offset, format, archive_name)
        # `format` is always DIRECTORY here (single-format backend); accepted for the
        # uniform ReadBackend signature. Password rejection is central (SUPPORTS_PASSWORD).
        if not source.is_directory or source.path is None:
            raise TypeError("Directory backend requires a directory path source")
        reader = DirectoryReader(
            source.path,
            streaming,
            archive_name or str(source.path),
            config,
            collector=collector,
            member_streams=member_streams,
            open_site=open_site,
        )
        # Recorded like every other backend's, so the reader's teardown closes it. A
        # directory source holds nothing open; this keeps one close path, not two.
        reader._source = source
        return reader


# Self-register at import time
register_reader(DirectoryReadBackend)
