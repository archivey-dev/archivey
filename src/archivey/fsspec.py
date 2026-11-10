"""An archive as a read-only ``fsspec`` file system: the ``archivey://`` protocol.

:class:`ArchiveyFileSystem` shows the members of any archive archivey reads as files and
directories, so ``pandas.read_csv("archivey://data/t.csv::s3://bucket/a.7z")`` reads one
member of a remote 7z without downloading the rest. The base package registers the
protocol through fsspec's ``fsspec.specs`` entry point, so fsspec finds it without an
``import archivey``.

This module imports fsspec, and it is the only archivey module that does: without
fsspec installed, importing it raises ``ModuleNotFoundError``. No archivey extra
installs fsspec; every package that reads a remote store (``s3fs``, ``gcsfs``,
``adlfs``) depends on it.
"""

from __future__ import annotations

import os
import posixpath
import tempfile
import threading
import weakref
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Literal, Self, cast

import fsspec
from fsspec.archive import AbstractArchiveFileSystem
from fsspec.core import OpenFile

from archivey.core import open_archive
from archivey.diagnostics import DiagnosticCode, PathRefusedContext
from archivey.exceptions import FilterRejectionError
from archivey.internal.enum_args import coerce_enum
from archivey.internal.extraction import hardlink_chain_end
from archivey.internal.filters import (
    check_universal,
    collision_key,
    extraction_view,
    resolve_or_raise_on_loop,
)
from archivey.internal.overrides import override
from archivey.terminal import quoted
from archivey.types import ArchiveMember, ExtractionPolicy, MemberType

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig, PasswordInput
    from archivey.formats import ArchiveFormat
    from archivey.internal.base_reader import BaseArchiveReader
    from archivey.reader import ArchiveReader, ArchiveStream
    from archivey.types import ExtractionPolicyStr

__all__ = ["ArchiveyFileSystem"]

# What a path resolves through before it counts as a loop: Linux's ``SYMLOOP_MAX``.
_MAX_SYMLINK_HOPS = 40

_Kind = Literal["dir", "file", "link"]


@dataclass(frozen=True)
class _Refusal:
    reason: str


_LOOP = _Refusal("it resolves through a symlink loop")


class _Tree:
    """The paths extraction writes into an empty destination, member by member.

    Paths are exact, as on a case-sensitive disk: a directory, a parent and a link's
    target are found by name. Only files and links also claim the policy's
    ``collision_key``, as extraction's collision map does, and the first to claim a
    key keeps it. A path is resolved as the destination resolves it once the members
    before it are written: a component that is a symlink the archive made is
    followed, so ``l/y`` under ``l -> d`` is written as ``d/y``.
    """

    def __init__(self, policy: ExtractionPolicy) -> None:
        self._policy = policy
        self._kinds: dict[str, _Kind] = {}  # a path -> what is written there
        self._targets: dict[str, str] = {}  # a link's path -> its target text
        self._claimed: set[str] = set()  # the collision keys of files and links

    def place(self, name: str, view: ArchiveMember) -> str | _Refusal:
        """Claim ``name`` and return the path it is written at, or say why extraction
        would not write it."""
        parent_name, _, last = name.rpartition("/")
        parent = self._resolve(parent_name)
        if isinstance(parent, _Refusal):
            return parent
        path = f"{parent}/{last}" if parent else last
        kind: _Kind = (
            "dir"
            if view.type is MemberType.DIRECTORY
            else "link"
            if view.type is MemberType.SYMLINK
            else "file"
        )
        existing = self._kinds.get(path)
        key = collision_key(path, self._policy)
        if kind == "dir":
            if existing == "dir":
                return path  # a directory listed again
            if existing is not None:
                return _Refusal("its name collides with a member written before it")
        elif existing is not None or key in self._claimed:
            return _Refusal("its name collides with a member written before it")
        self._kinds[path] = kind
        if kind == "link":
            target = view.link_target or ""
            self._targets[path] = target
            # A link that leads out through a link made before it is refused before
            # anything is written. One that loops is found only once it is made, so
            # it is removed, and the parents made for it stay.
            problem = self._resolve(posixpath.join(parent, target), final=True)
            if isinstance(problem, _Refusal):
                del self._kinds[path], self._targets[path]
                if problem is _LOOP:
                    self._make_parents(parent)
                return problem
        if kind != "dir":
            self._claimed.add(key)
        self._make_parents(parent)
        return path

    def _make_parents(self, parent: str) -> None:
        """Claim the directories extraction makes on the way to a member, resolved
        already."""
        parts = parent.split("/") if parent else []
        for depth in range(1, len(parts) + 1):
            self._kinds.setdefault("/".join(parts[:depth]), "dir")

    def written_path(self, name: str) -> str | None:
        """Where ``name`` leads on the disk extraction writes, every symlink on the
        way followed, the last one too: a path that need not exist, or ``None`` for
        a loop or a way out."""
        resolved = self._resolve(name, final=True)
        return None if isinstance(resolved, _Refusal) else resolved

    def link_destination(self, path: str) -> str | None:
        """Where the link written at ``path`` leads once every member is written, as
        the destination resolves its target text, or ``None``."""
        target = self._targets.get(path)
        if target is None:
            return None
        return self.written_path(posixpath.join(posixpath.dirname(path), target))

    def directories(self) -> list[str]:
        """Every directory extraction makes: those a member names and those made as
        parents, including a looping link's, which extraction makes before it
        removes the link."""
        return [path for path, kind in self._kinds.items() if kind == "dir"]

    def _resolve(self, name: str, *, final: bool = False) -> str | _Refusal:
        """The path the directory ``name`` resolves to.

        A missing component of the name is a directory extraction creates. A file, or
        a link that leads to no directory, ends the walk: extraction cannot create a
        path under it. With ``final``, ``name`` is a link's target, which may lead
        anywhere inside the destination: only a loop and a way out are refused.
        """
        # Each component, and whether it came from a link's target.
        pending = [(part, False) for part in name.split("/")]
        out: list[str] = []
        hops = 0
        while pending:
            part, from_link = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                # ``check_universal`` refused a ``..`` name and a target whose text
                # leaves the destination; this is a way out through a link.
                if not out:
                    return _Refusal("it resolves outside the destination")
                out.pop()
                continue
            out.append(part)
            current = "/".join(out)
            kind = self._kinds.get(current)
            if kind == "link":
                hops += 1
                if hops > _MAX_SYMLINK_HOPS:
                    return _LOOP
                out.pop()
                # The target is relative to the link's parent, which ``out`` now is.
                target = self._targets[current]
                pending[:0] = [(p, True) for p in target.split("/")]
                continue
            if final:
                continue
            if kind == "file":
                return _Refusal("a parent of it is a file")
            if kind is None and from_link:
                return _Refusal(
                    "a parent of it is a symlink that leads to no directory"
                )
        return "/".join(out)


class ArchiveyFileSystem(AbstractArchiveFileSystem):
    """A read-only ``fsspec`` file system over one archive, protocol ``archivey``.

    ``fo`` is the archive: an fsspec URL (``"s3://bucket/a.7z"``), an
    ``fsspec.core.OpenFile``, a local path, or a binary file object. A ``str`` goes
    through ``fsspec.open(fo, protocol=target_protocol, **target_options)``, so
    chained URLs (``archivey://member::s3://bucket/a.7z``) work, and so, unlike a
    ``str`` given to :func:`~archivey.open_archive`, a ``str`` here reaches whatever
    protocol it names. Build the file system from a trusted ``fo`` and pass a member
    name from a caller as the path of ``open()``, never formatted into a URL:
    fsspec splits a URL on ``::``, so a name in one can add a protocol of its own.

    The archive is opened once, with ``seekable_members=True`` and
    ``concurrent_operations=True``, and the reader is :attr:`reader`. ``format``,
    ``password``, ``encoding`` and ``config`` are :func:`~archivey.open_archive`'s.

    **The tree is what extraction writes.** Each path is the relative path
    ``reader.extract_all(dest, policy=policy)`` gives the member, into an empty
    ``dest``, and the tree leaves out what that extraction would not write: a member
    the policy refuses (a ``..`` segment, an absolute name under ``STRICT``, a name the
    policy will not write, a symlink whose target leaves the destination), a hard link
    to a refused member, a member whose name collides with one before it (the
    policy's collision key: ``README`` and ``readme`` collide under ``STRICT`` and
    ``STANDARD``), a path under a file, and a symlink that loops or leads out through
    another link. Each is a ``MEMBER_PATH_REFUSED`` diagnostic on
    ``fs.reader.diagnostics``. A duplicate name shows its current entry. A member
    under one of the archive's own symlinks is listed where extraction writes it,
    through the link: ``l/y`` under ``l -> d`` is ``d/y``, and a path under a link that
    leads to no directory is refused. Paths are compared as on a case-sensitive
    disk; only files and links collide by the policy's key. Not modelled: what a
    non-empty destination decides (``overwrite=``, existing files), what the
    destination's file system cannot hold (a reserved name under ``TRUSTED`` on
    Windows, case folded by the disk, a link Windows keeps because it collapses
    ``..`` before following links), a link that a later member makes lead out, and
    ``filter=``. A hard link to a symlink is that
    symlink, with its target read from the hard link's own directory, as
    extraction (and GNU tar) write it.

    A symlink's target text is resolved among the written paths, as the destination
    resolves it once every member is written: the symlink is listed as what it
    reaches there, with ``"islink": True`` and ``"destination"`` in its ``info()``,
    and opens it. A name extraction did not write is not reached, even when the
    archive stored a member under it, and a symlink that reaches nothing written is
    listed as ``"other"``; opening it raises ``FileNotFoundError``. A symlink to a
    directory lists that directory's entries under its own name (``ls("s")``, and
    ``s/f`` under ``s -> d`` is ``d/f``); ``walk``, ``find`` and ``glob`` list it
    and do not descend into it, as ``os.walk`` does, since it can lead back above
    itself. A hard link is listed only when extraction makes it: its source is a
    file listed before it. A hard link to a symlink is that symlink, with the
    symlink's target as its ``"destination"``.

    The instance owns its reader: :meth:`close`, or leaving a ``with`` block, closes it,
    and so does collecting the instance. A member stream from ``open()`` keeps the
    instance alive until the stream closes. ``cachable`` is ``False``: fsspec's
    instance cache would keep every reader open for the life of the process.

    The file system pickles as its constructor arguments and opens the archive again
    when unpickled, as dask needs to send it to a worker. A file-object ``fo`` cannot
    be sent that way, and pickling raises ``TypeError``.
    """

    protocol = "archivey"
    root_marker = ""
    cachable = False

    def __init__(
        self,
        fo: str | os.PathLike[str] | OpenFile | BinaryIO = "",
        *,
        target_protocol: str | None = None,
        target_options: dict[str, Any] | None = None,
        format: ArchiveFormat | str | None = None,  # open_archive's name
        password: PasswordInput = None,
        encoding: str | None = None,
        config: ArchiveyConfig | None = None,
        policy: ExtractionPolicy | ExtractionPolicyStr = ExtractionPolicy.STRICT,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.policy = coerce_enum(
            policy, ExtractionPolicy, call="ArchiveyFileSystem()", param="policy="
        )
        self.fo = fo
        source: OpenFile | os.PathLike[str] | BinaryIO
        if isinstance(fo, str):
            source = cast(
                "OpenFile",
                fsspec.open(
                    fo, mode="rb", protocol=target_protocol, **(target_options or {})
                ),
            )
        else:
            source = fo
        reader = open_archive(
            cast("Any", source),
            format=cast("Any", format),
            password=password,
            encoding=encoding,
            config=config,
            seekable_members=True,
            concurrent_operations=True,
        )
        self.reader: ArchiveReader = reader
        # Closes the reader when the instance is collected. The callback holds the
        # reader, never ``self``, so it does not keep the instance alive.
        self._finalizer = weakref.finalize(self, reader.close)
        self.dir_cache: dict[str, dict[str, Any]] | None = None
        self._dirs_lock = threading.Lock()
        self._children: dict[str, list[str]] = {}
        # A symlink, or a hard link to one, by path: the member its target reaches
        # among the written paths, ``None`` when it reaches no file.
        self._read_as: dict[str, ArchiveMember | None] = {}
        self._tree: _Tree | None = None

    @classmethod
    @override
    def _strip_protocol(cls, path: str) -> str:
        # Paths are relative to the archive's root. fsspec's own annotation allows a
        # list, for a list of paths; a path is one string here.
        return cast("str", super()._strip_protocol(path)).lstrip("/")

    def close(self) -> None:
        """Close the reader. The file system lists and opens nothing after this."""
        self._finalizer()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @override
    def __reduce__(self) -> tuple[Any, ...]:
        if not isinstance(self.fo, (str, os.PathLike, OpenFile)):
            raise TypeError(
                "an ArchiveyFileSystem built from a file object cannot be pickled: "
                "it pickles as its constructor arguments, and a file object cannot be "
                "sent to another process; build it from a URL, a path or an OpenFile"
            )
        return super().__reduce__()

    def _get_dirs(self) -> None:
        if self.dir_cache is not None:
            return
        # Two threads can list at once (``concurrent_operations=True``): one builds the
        # tree and reports each refusal once.
        with self._dirs_lock:
            if self.dir_cache is None:
                self.dir_cache = self._build_tree()

    @override
    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[Any]:
        """fsspec's archive ``ls``, from an index of each directory's entries."""
        self._get_dirs()
        dir_cache = cast("dict[str, dict[str, Any]]", self.dir_cache)
        path = self._strip_protocol(path).rstrip("/")
        names = self._children.get(path)
        written = self._written_path(path) if names is None and path else None
        if written is not None and written != path and written in self._children:
            # A directory reached through a symlink: its entries, named under
            # ``path``, as ``os.listdir`` lists a symlink to a directory.
            entries = [
                self._aliased(dir_cache[name], written, path)
                for name in self._children[written]
            ]
        elif names is not None:
            entries = [dir_cache[name] for name in names]
        elif not path:
            entries = []  # an archive with nothing in its tree
        else:
            # Nothing is under ``path``: a file lists as itself, an empty directory
            # as nothing, and ``info`` raises FileNotFoundError for a missing one.
            info = self.info(path)
            entries = [] if info["type"] == "directory" else [info]
        entries.sort(key=lambda entry: entry["name"])
        return entries if detail else [entry["name"] for entry in entries]

    @override
    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """fsspec's archive ``info``, and a path through one of the archive's
        symlinks to a directory: ``s/f`` under ``s -> d`` is ``d/f``'s entry, named
        ``s/f``."""
        try:
            return super().info(path, **kwargs)
        except FileNotFoundError:
            stripped = self._strip_protocol(path).rstrip("/")
            written = self._written_parent(stripped)
            dir_cache = cast("dict[str, dict[str, Any]]", self.dir_cache)
            if written is None or written == stripped or written not in dir_cache:
                raise
            return self._aliased(dir_cache[written], written, stripped)

    def _written_path(self, path: str) -> str | None:
        """Where ``path`` leads among the written paths, its symlinks followed."""
        self._get_dirs()
        tree = self._tree
        return tree.written_path(path) if tree is not None and path else path

    def _written_parent(self, path: str) -> str | None:
        """``path`` with its parent's symlinks followed and its last component kept,
        as ``lstat`` finds it: ``l/s`` under ``l -> d`` is ``d/s``, a link itself."""
        parent, _, last = path.rpartition("/")
        if not parent:
            return path
        written = self._written_path(parent)
        return None if written is None else f"{written}/{last}" if written else last

    @staticmethod
    def _aliased(entry: dict[str, Any], written: str, path: str) -> dict[str, Any]:
        """``entry``, whose path starts with ``written``, named under ``path``."""
        return {**entry, "name": path + entry["name"][len(written) :]}

    @override
    def walk(  # pyrefly: ignore[bad-override]
        self,
        path: str,
        maxdepth: int | None = None,
        topdown: bool = True,
        on_error: Any = "omit",
        **kwargs: Any,
    ) -> Iterator[tuple[str, Any, Any]]:
        """fsspec's ``walk``, with a stack in place of recursion.

        One member name sets the tree's depth, and fsspec's ``walk`` recurses once a
        level, so ``find``, ``glob`` and ``du`` would raise ``RecursionError`` on an
        archive with a deeply nested name. The order, ``maxdepth``, ``topdown`` (a
        caller may prune ``dirs`` in place) and ``on_error`` are fsspec's.
        """
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        detail = kwargs.pop("detail", False)
        # Each entry: a directory still to list with the depth it has left, or, for a
        # bottom-up walk, a listed one to yield once everything under it has been.
        stack: list[tuple[str, int | None, tuple[str, Any, Any] | None]] = [
            (self._strip_protocol(path), maxdepth, None)
        ]
        while stack:
            top, depth, ready = stack.pop()
            if ready is not None:
                yield ready
                continue
            try:
                listing = self.ls(top, detail=True, **kwargs)
            except OSError as exc:
                if on_error == "raise":
                    raise
                if callable(on_error):
                    on_error(exc)
                continue
            full_dirs: dict[str, str] = {}
            dirs: dict[str, Any] = {}
            files: dict[str, Any] = {}
            for info in listing:
                pathname = info["name"].rstrip("/")
                name = pathname.rsplit("/", 1)[-1]
                if info["type"] == "directory" and pathname != top:
                    # A symlink to a directory is listed, not followed, as
                    # ``os.walk`` does: it can lead back to a directory above it.
                    if not info.get("islink"):
                        full_dirs[name] = pathname
                    dirs[name] = info
                elif pathname == top:
                    files[""] = info
                else:
                    files[name] = info
            shown_dirs: Any = dirs if detail else list(dirs)
            shown_files: Any = files if detail else list(files)
            if topdown:
                yield top, shown_dirs, shown_files
            else:
                stack.append((top, None, (top, shown_dirs, shown_files)))
            if depth is not None:
                depth -= 1
                if depth < 1:
                    continue
            # Reversed, so the first directory is listed next, as recursion would.
            for name in reversed(list(shown_dirs)):
                if name in full_dirs:
                    stack.append((full_dirs[name], depth, None))

    def _build_tree(self) -> dict[str, dict[str, Any]]:
        files: dict[str, dict[str, Any]] = {}
        tree = _Tree(self.policy)
        refused_ids: set[int] = set()
        hardlink_ends: dict[int, ArchiveMember | None] = {}
        # An empty directory as the destination: nothing is written to it, so the
        # symlink checks of ``check_universal`` resolve every path by its name alone.
        # A path through a link the archive made is resolved by ``_Tree``.
        with tempfile.TemporaryDirectory(prefix="archivey-fsspec-") as tmp:
            root = resolve_or_raise_on_loop(Path(tmp))
            for member in self.reader.members():
                if not member.is_current:
                    continue
                try:
                    view = self._view(member, root, refused_ids, hardlink_ends)
                except FilterRejectionError as exc:
                    refused_ids.add(member.member_id)
                    self._report_refused(member, exc.raw_message)
                    continue
                name = view.name.rstrip("/")
                if not name or name == ".":
                    continue
                placed = tree.place(name, view)
                if isinstance(placed, _Refusal):
                    # Not a refused source: extraction refuses a hard link only for
                    # a source the policy refused, and makes one whose source lost
                    # its name to a member before it from that source's bytes.
                    self._report_refused(member, placed.reason)
                    continue
                files[placed] = self._entry(placed, member, view)
        dir_cache: dict[str, dict[str, Any]] = {
            name: {"name": name, "size": 0, "type": "directory"}
            for name in tree.directories()
        }
        # Every parent of every path, built in a loop: a name nested a thousand deep
        # is within the metadata budget, and a recursive walk would overflow the stack.
        for name in files:
            parent = posixpath.dirname(name)
            while parent and parent not in dir_cache:
                dir_cache[parent] = {"name": parent, "size": 0, "type": "directory"}
                parent = posixpath.dirname(parent)
        dir_cache.update(files)
        self._resolve_links(tree, dir_cache)
        self._tree = tree
        # Each directory's entries, so ``ls`` reads one directory's worth, not the
        # whole tree: fsspec's own ``ls`` scans every path, which makes a full walk
        # quadratic in the member count. Set before ``dir_cache``, which marks the
        # tree as built.
        children: dict[str, list[str]] = {}
        for name in dir_cache:
            children.setdefault(posixpath.dirname(name), []).append(name)
        self._children = children
        return dir_cache

    def _resolve_links(self, tree: _Tree, dir_cache: dict[str, dict[str, Any]]) -> None:
        """Give each symlink entry the type, size and bytes of what its target text
        reaches among the written paths, as the destination resolves it once every
        member is written: a later member, a name re-rooted or renamed by the
        policy, a path through another link. A name extraction did not write is not
        reached, even when the archive holds a member of that name."""
        for name, entry in dir_cache.items():
            if not entry.get("islink") or name not in tree._targets:
                continue  # not a symlink as written: a hard link to a file
            dest = tree.link_destination(name)
            reached = dir_cache.get(dest) if dest is not None else None
            read_as: ArchiveMember | None = None
            if reached is None or reached["type"] == "other":
                entry.update(type="other", size=None)
            elif reached["type"] == "directory":
                entry.update(type="directory", size=0)
            else:
                entry.update(type="file", size=reached["size"])
                read_as = self._read_as.get(dest, reached["member"]) if dest else None
            self._read_as[name] = read_as

    def _view(
        self,
        member: ArchiveMember,
        root: Path,
        refused_ids: set[int],
        hardlink_ends: dict[int, ArchiveMember | None],
    ) -> ArchiveMember:
        """``member`` as extraction writes it, or ``FilterRejectionError``."""
        view = extraction_view(member, self.policy)
        if view.type is MemberType.HARDLINK:
            # A hard link to a symlink is a second name for the symlink, written as a
            # symlink with its target, as extraction's ``_as_written`` does (and GNU
            # tar). Its target text is then read from the hard link's own directory
            # (``_resolve_links``), so it can lead elsewhere than the symlink's does.
            reader = cast("BaseArchiveReader", self.reader)
            direct = hardlink_chain_end(reader, member, hardlink_ends)
            if (
                direct is not None
                and direct.type is MemberType.SYMLINK
                and direct.link_target is not None
            ):
                view = view.replace(
                    type=MemberType.SYMLINK,
                    link_target=direct.link_target,
                    link_target_member=None,
                )
        if view.type is MemberType.SYMLINK:
            # Where its target points: a target that leaves the destination is refused
            # whatever the destination is.
            check_universal(view, root, dest_resolved=True)
        elif view.type is MemberType.HARDLINK:
            # Extraction links to the file an earlier member was written to: with no
            # such member (none of that name, or only a later one, as hard links point
            # backward) or one that is not a file, it writes nothing.
            source = member.link_target_member
            if source is None or source.type is not MemberType.FILE:
                raise FilterRejectionError(
                    "Hardlink target not found"
                    if source is None
                    else "Hardlink target is not a file",
                    member_name=member.name,
                    link_target=member.link_target,
                )
            if source.member_id in refused_ids:
                raise FilterRejectionError(
                    "Hardlink target was refused",
                    member_name=member.name,
                    link_target=member.link_target,
                )
        return view

    def _entry(
        self, name: str, member: ArchiveMember, view: ArchiveMember
    ) -> dict[str, Any]:
        islink = member.type in (MemberType.SYMLINK, MemberType.HARDLINK)
        # ``link_target_member`` is the end of the link chain; a cycle or a target
        # that is no member leaves it ``None``, and a chain that ends at a symlink
        # with no target ends at that symlink. ``view`` is the member as written: a
        # hard link to a symlink is that symlink, with its target.
        target = view.link_target_member if islink else member
        entry: dict[str, Any] = {"name": name}
        if target is None or target.type in (
            MemberType.OTHER,
            MemberType.SYMLINK,
            MemberType.HARDLINK,
        ):
            entry.update(type="other", size=None)
        elif target.type is MemberType.DIRECTORY:
            entry.update(type="directory", size=0)
        else:
            entry.update(type="file", size=target.size)
        if islink:
            entry.update(islink=True, destination=view.link_target)
        modified = member.modified_utc()
        if modified is not None:
            entry["mtime"] = modified.timestamp()
        entry["member"] = member
        return entry

    def _report_refused(self, member: ArchiveMember, reason: str) -> None:
        reader = cast("BaseArchiveReader", self.reader)
        reader._diagnostics_collector.emit(
            code=DiagnosticCode.MEMBER_PATH_REFUSED,
            message=(
                f"{quoted(member.name)} is not in the archivey:// tree: extraction "
                f"under the {self.policy.value} policy would not write it ({reason})"
            ),
            context=PathRefusedContext(
                archive_name=reader._archive_name,
                member_name=member.name,
                member_id=member.member_id,
                policy=self.policy.value,
                reason=reason,
            ),
            member=member,
        )

    # fsspec annotates ``_open`` as returning its own buffered file; any binary file
    # object is what callers of ``open`` get, and a member stream is one.
    @override
    def _open(  # pyrefly: ignore[bad-override]
        self,
        path: str,
        mode: str = "rb",
        block_size: int | None = None,
        autocommit: bool = True,
        cache_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ArchiveStream:
        if mode != "rb":
            raise NotImplementedError(
                f"the archivey file system is read-only; mode {mode!r} is not 'rb'"
            )
        path = self._strip_protocol(path)
        info: dict[str, Any] = self.info(path)
        if info["type"] == "directory":
            raise IsADirectoryError(path)
        if info["type"] != "file":
            raise FileNotFoundError(path)
        written = self._written_parent(path.rstrip("/")) or path
        member = self._read_as.get(written, info["member"])
        if member is None:
            raise FileNotFoundError(path)
        stream = self.reader.open(member)
        # The stream keeps this file system, and through it the reader, alive while
        # the caller holds only the stream (``fsspec.open(url).open()``).
        stream._archivey_fs = self  # pyrefly: ignore[missing-attribute]  # ty: ignore[unresolved-attribute]
        return stream

    # Every write method of AbstractFileSystem, refused as fsspec's other read-only
    # file systems refuse them.
    def _read_only(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("the archivey file system is read-only")

    mkdir = makedirs = rmdir = _read_only
    pipe_file = put_file = cp_file = mv = _read_only
    rm_file = rm = _rm = touch = _read_only
