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


class _Node:
    """One path in the tree: a component and the directory it is in.

    A node holds its own component and not its full path, so a name nested D deep
    costs D nodes, not D paths of up to D components each: the tree's memory is linear
    in the length of the names, whatever their depth.
    """

    __slots__ = (
        "children",
        "entry",
        "key",
        "kind",
        "leads_to",
        "leads_to_final",
        "parent",
        "part",
        "read_as",
        "target",
    )

    def __init__(self, parent: _Node | None, part: str, kind: _Kind) -> None:
        self.parent = parent
        self.part = part
        self.kind = kind
        # A directory's entries by component; a file and a link have none.
        self.children: dict[str, _Node] | None = {} if kind == "dir" else None
        self.target: str | None = None  # a symlink's target text
        # The member's ``info()``, without its ``"name"``; ``None`` for a directory
        # that no member names.
        self.entry: dict[str, Any] | None = None
        # A symlink's file: the member its target reaches, ``None`` for no file.
        self.read_as: ArchiveMember | None = None
        # A directory's collision key, as the start of a longer path's key.
        self.key: _KeyNode | None = None
        # A link's walk, kept: the node its target leads to and the links followed
        # on the way, as a parent and as the end of a path (``_Tree._follow``).
        self.leads_to: tuple[_Node, int] | None = None
        self.leads_to_final: tuple[_Node, int] | None = None

    def child(self, part: str) -> _Node | None:
        return self.children.get(part) if self.children else None


class _KeyNode:
    """One segment of a collision key, in a tree of the keys that files and links
    claim."""

    __slots__ = ("children", "claimed", "parent", "segment")

    def __init__(self, parent: _KeyNode | None, segment: str) -> None:
        self.parent = parent
        self.segment = segment
        # Made with the first segment under this one: most keys end a path.
        self.children: dict[str, _KeyNode] | None = None
        self.claimed = False

    def walk(self, segments: list[str]) -> _KeyNode:
        node = self
        for segment in segments:
            if node.children is None:
                node.children = {}
            next_node = node.children.get(segment)
            if next_node is None:
                next_node = node.children[segment] = _KeyNode(node, segment)
            node = next_node
        return node


# Where a resolve ends: the deepest node the path reaches, and the components after it
# that no member made, which extraction creates as directories.
_Spot = tuple[_Node, list[str]]


class _Tree:
    """The paths extraction writes into an empty destination, member by member.

    Paths are exact, as on a case-sensitive disk: a directory, a parent and a link's
    target are found by name. Only files and links also claim the policy's
    ``collision_key``, as extraction's collision map does, and the first to claim a
    key keeps it. A path is resolved as the destination resolves it once the members
    before it are written: a component that is a symlink the archive made is
    followed, so ``l/y`` under ``l -> d`` is written as ``d/y``.

    No path string is built while the tree is built or resolved: a resolve step moves
    to a child or to a parent node, so its cost does not grow with the depth.
    """

    def __init__(self, policy: ExtractionPolicy) -> None:
        self._policy = policy
        self.root = _Node(None, "", "dir")
        self.root.key = _KeyNode(None, "")
        self.links: list[_Node] = []  # every symlink as written
        # The links whose final walk was kept since the last ``place`` began.
        self._kept_final: list[_Node] = []

    def place(self, name: str, view: ArchiveMember) -> _Node | _Refusal:
        """Claim ``name`` and return the node it is written at, or say why extraction
        would not write it."""
        parent_name, _, last = name.rpartition("/")
        spot = self._resolve(self.root, parent_name)
        if isinstance(spot, _Refusal):
            return spot
        parent, missing = spot
        kind: _Kind = (
            "dir"
            if view.type is MemberType.DIRECTORY
            else "link"
            if view.type is MemberType.SYMLINK
            else "file"
        )
        existing = None if missing else parent.child(last)
        claim: _KeyNode | None = None
        if kind == "dir":
            if existing is not None and existing.kind == "dir":
                return existing  # a directory listed again
            if existing is not None:
                return _Refusal("its name collides with a member written before it")
        else:
            claim = self._claim_key(parent, missing, last)
            if existing is not None or claim.claimed:
                return _Refusal("its name collides with a member written before it")
        made: list[_Node] = []
        for part in missing:
            parent = self._add(parent, part, "dir")
            made.append(parent)
        node = self._add(parent, last, kind)
        if kind == "link":
            target = view.link_target or ""
            node.target = target
            # A link that leads out through a link made before it is refused before
            # anything is written. One that loops is found only once it is made, so
            # it is removed, and the parents made for it stay.
            self._kept_final.clear()
            problem = self._resolve(self._start(parent, target), target, final=True)
            if isinstance(problem, _Refusal):
                for kept in self._kept_final:
                    kept.leads_to_final = None
                self._remove(node)
                if problem is not _LOOP:
                    for made_dir in reversed(made):
                        self._remove(made_dir)
                return problem
            self.links.append(node)
        if claim is not None:
            claim.claimed = True
        return node

    @staticmethod
    def _add(parent: _Node, part: str, kind: _Kind) -> _Node:
        node = _Node(parent, part, kind)
        cast("dict[str, _Node]", parent.children)[part] = node
        return node

    @staticmethod
    def _remove(node: _Node) -> None:
        parent = cast("_Node", node.parent)
        del cast("dict[str, _Node]", parent.children)[node.part]

    def _start(self, parent: _Node, target: str) -> _Node:
        """Where a link's target text starts, as ``posixpath.join(parent, target)``
        reads it: an absolute target starts at the root."""
        return self.root if target.startswith("/") else parent

    def _claim_key(self, parent: _Node, missing: list[str], last: str) -> _KeyNode:
        """The key node of ``collision_key`` of the path ``parent/missing.../last``.

        ``collision_key`` folds each segment on its own, so a path's key is its
        directory's key followed by the key of the rest. It drops separators only at
        the end of the whole path: a last component of only backslashes drops them,
        and then the empty segments before it.
        """
        key = self._dir_key(parent)
        for part in missing:
            key = key.walk(self._segments(part))
        rest = collision_key(last, self._policy)
        if rest:
            return key.walk(rest.split("/"))
        while key.parent is not None and not key.segment:
            key = key.parent
        return key

    def _dir_key(self, node: _Node) -> _KeyNode:
        """The key of a directory's path as the start of a longer path's key, kept
        on the directory once found."""
        chain: list[_Node] = []
        while node.key is None:
            chain.append(node)
            node = cast("_Node", node.parent)
        key = node.key
        for item in reversed(chain):
            key = item.key = key.walk(self._segments(item.part))
        return key

    def _segments(self, part: str) -> list[str]:
        """The key of the component ``part`` inside a longer path, split at ``/``.

        ``collision_key`` reads a backslash as a separator, so one component can give
        several segments. The ``/x`` keeps a trailing one, which ``collision_key``
        drops only at the end of the whole path, and is cut off again.
        """
        return collision_key(part + "/x", self._policy)[:-2].split("/")

    def lookup(self, path: str) -> _Node | None:
        """The node at exactly ``path``, with no symlink followed: a component that is
        a link ends the walk, since nothing is written under a link's own path."""
        node = self.root
        if path:
            for part in path.split("/"):
                child = node.child(part)
                if child is None:
                    return None
                node = child
        return node

    def written(self, name: str) -> _Node | None:
        """The node ``name`` leads to on the disk extraction writes, every symlink on
        the way followed, the last one too; ``None`` for a loop, a way out, or a path
        that nothing wrote."""
        spot = self._resolve(self.root, name, final=True)
        if isinstance(spot, _Refusal) or spot[1]:
            return None
        return spot[0]

    def link_destination(self, link: _Node) -> _Spot | None:
        """Where ``link`` leads once every member is written, as the destination
        resolves its target text, or ``None`` for a loop or a way out."""
        target = cast("str", link.target)
        parent = cast("_Node", link.parent)
        spot = self._resolve(self._start(parent, target), target, final=True)
        return None if isinstance(spot, _Refusal) else spot

    def _resolve(
        self, start: _Node, name: str, *, final: bool = False
    ) -> _Spot | _Refusal:
        """Where the directory ``name`` resolves to, from the directory ``start``.

        A missing component of the name is a directory extraction creates. A file, or
        a link that leads to no directory, ends the walk: extraction cannot create a
        path under it. With ``final``, ``name`` is a link's target, which may lead
        anywhere inside the destination: only a loop and a way out are refused.
        """
        walked = self._walk(start, name, final=final, from_link=False, hops=0)
        if isinstance(walked, _Refusal):
            return walked
        return walked.node, walked.missing

    def _walk(
        self, start: _Node, name: str, *, final: bool, from_link: bool, hops: int
    ) -> _Walk | _Refusal:
        """``_resolve``'s walk of ``name`` from ``start``, with ``hops`` links followed
        before it. ``from_link`` says ``name`` is a link's target."""
        node = start
        missing: list[str] = []
        steady = True
        for part in name.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                # ``check_universal`` refused a ``..`` name and a target whose text
                # leaves the destination; this is a way out through a link.
                if missing:
                    missing.pop()
                elif node.parent is None:
                    return _Refusal("it resolves outside the destination")
                else:
                    node = node.parent
                continue
            child = None if missing else node.child(part)
            if child is None:
                if from_link and not final:
                    return _Refusal(
                        "a parent of it is a symlink that leads to no directory"
                    )
                missing.append(part)
                steady = False
                continue
            if child.kind == "link":
                # The target is relative to the link's parent, which ``node`` is.
                followed = self._follow(child, node, final=final, hops=hops)
                if isinstance(followed, _Refusal):
                    return followed
                node, missing = followed.node, list(followed.missing)
                hops = followed.hops
                steady = steady and followed.steady
                continue
            if child.kind == "file" and not final:
                return _Refusal("a parent of it is a file")
            node = child
        return _Walk(node, missing, hops, steady)

    def _follow(
        self, link: _Node, parent: _Node, *, final: bool, hops: int
    ) -> _Walk | _Refusal:
        """Follow ``link``, in ``parent``, as one more hop after ``hops``.

        The end of a link's target is kept on the link once the walk to it met no
        missing component, so a link that many paths go through is walked once: a
        component added later cannot change such a walk. A walk without ``final``
        runs only before a member's nodes are added; one with ``final`` can run
        through a link and parents that ``place`` then removes, so ``place`` drops
        what was kept then (``_kept_final``).
        """
        hops += 1
        if hops > _MAX_SYMLINK_HOPS:
            return _LOOP
        kept = link.leads_to_final if final else link.leads_to
        if kept is not None:
            node, used = kept
            if hops + used > _MAX_SYMLINK_HOPS:
                return _LOOP  # where the walk itself would have stopped
            return _Walk(node, [], hops + used, True)
        walked = self._walk(
            parent, cast("str", link.target), final=final, from_link=True, hops=hops
        )
        if isinstance(walked, _Refusal) or not walked.steady:
            return walked
        if final:
            link.leads_to_final = (walked.node, walked.hops - hops)
            self._kept_final.append(link)
        else:
            link.leads_to = (walked.node, walked.hops - hops)
        return walked


@dataclass
class _Walk:
    """Where a walk ends, with the links followed so far and whether every component
    on the way existed (``steady``)."""

    node: _Node
    missing: list[str]
    hops: int
    steady: bool


def _info(node: _Node, name: str) -> dict[str, Any]:
    """The ``info()`` of ``node``, named ``name``."""
    if node.entry is None:
        return {"name": name, "size": 0, "type": "directory"}
    return {"name": name, **node.entry}


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
    and so does collecting the instance. After :meth:`close`, listing and opening raise
    ``ArchiveyUsageError``, whether or not anything was listed before it. A member
    stream from ``open()`` keeps the instance alive until the stream closes.
    ``cachable`` is ``False``: fsspec's instance cache would keep every reader open for
    the life of the process.

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
        # The tree extraction writes, built at the first listing; ``close`` drops it.
        self._tree: _Tree | None = None
        self._tree_lock = threading.Lock()

    @classmethod
    @override
    def _strip_protocol(cls, path: str) -> str:
        # Paths are relative to the archive's root. fsspec's own annotation allows a
        # list, for a list of paths; a path is one string here.
        return cast("str", super()._strip_protocol(path)).lstrip("/")

    def close(self) -> None:
        """Close the reader and drop the tree. After this, a call that lists or opens
        raises ``ArchiveyUsageError``, as the closed reader does."""
        # Under the lock, so a listing that builds the tree now either finishes
        # first or finds the reader closed, and no tree is kept after the close.
        with self._tree_lock:
            self._finalizer()
            self._tree = None

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

    def _get_tree(self) -> _Tree:
        tree = self._tree
        if tree is not None:
            return tree
        # Two threads can list at once (``concurrent_operations=True``): one builds the
        # tree and reports each refusal once. After ``close``, ``members()`` raises.
        with self._tree_lock:
            if self._tree is None:
                self._tree = self._build_tree()
            return self._tree

    @override
    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[Any]:
        """fsspec's archive ``ls``, from the entries of one directory."""
        tree = self._get_tree()
        path = self._strip_protocol(path).rstrip("/")
        node = self._listed_dir(tree, path)
        if node is not None:
            entries = self._entries(node, path)
        elif not path:
            entries = []  # an archive with nothing in its tree
        else:
            # Nothing is under ``path``: a file lists as itself, an empty directory
            # as nothing, and ``info`` raises FileNotFoundError for a missing one.
            info = self.info(path)
            entries = [] if info["type"] == "directory" else [info]
        return entries if detail else [entry["name"] for entry in entries]

    @staticmethod
    def _listed_dir(tree: _Tree, path: str) -> _Node | None:
        """The directory whose entries ``ls(path)`` lists, or ``None`` when nothing
        is under ``path``. A directory reached through a symlink lists its entries
        under ``path``, as ``os.listdir`` lists a symlink to a directory."""
        node = tree.lookup(path)
        if path and (node is None or not node.children):
            node = tree.written(path)
        return node if node is not None and node.children else None

    @staticmethod
    def _entries(node: _Node, path: str) -> list[dict[str, Any]]:
        """The ``info()`` of each entry of the directory ``node``, named under
        ``path``, sorted by name."""
        prefix = f"{path}/" if path else ""
        entries = [
            _info(child, prefix + part) for part, child in (node.children or {}).items()
        ]
        entries.sort(key=lambda entry: entry["name"])
        return entries

    @override
    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """fsspec's archive ``info``, and a path through one of the archive's
        symlinks to a directory: ``s/f`` under ``s -> d`` is ``d/f``'s entry, named
        ``s/f``."""
        path = self._strip_protocol(path)
        return _info(self._find(path), path.rstrip("/"))

    def _find(self, path: str) -> _Node:
        """The node ``info(path)`` describes, or ``FileNotFoundError``."""
        tree = self._get_tree()
        if not path:
            if tree.root.children:
                return tree.root
            raise FileNotFoundError(path)  # an archive with nothing in its tree
        node = tree.lookup(path)
        if node is not None:
            return node
        # ``path`` with its parent's symlinks followed and its last component kept,
        # as ``lstat`` finds it: ``l/s`` under ``l -> d`` is ``d/s``, a link itself.
        stripped = path.rstrip("/")
        parent, _, last = stripped.rpartition("/")
        written = tree.written(parent) if parent else None
        found = written.child(last) if written is not None else None
        if found is None or found is tree.lookup(stripped):
            # Found with no symlink followed means ``path`` ends with ``/``: fsspec's
            # archive ``info`` finds ``d`` by its exact name only, and so does this.
            raise FileNotFoundError(path)
        return found

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
        archive with a deeply nested name. A directory under the first is listed from
        its node, not found again by its path, so a walk down a deep name does not
        cost the square of its depth. The order, ``maxdepth``, ``topdown`` (a caller
        may prune ``dirs`` in place) and ``on_error`` are fsspec's.
        """
        if maxdepth is not None and maxdepth < 1:
            raise ValueError("maxdepth must be at least 1")
        detail = kwargs.pop("detail", False)
        # Each entry: a directory still to list with the depth it has left and its
        # node (``None`` for the first), or, for a bottom-up walk, a listed one to
        # yield once everything under it has been.
        Item = tuple[str, int | None, "_Node | None", "tuple[str, Any, Any] | None"]
        stack: list[Item] = [(self._strip_protocol(path), maxdepth, None, None)]
        while stack:
            top, depth, node, ready = stack.pop()
            if ready is not None:
                yield ready
                continue
            if node is not None:
                listing = self._entries(node, top)
            else:
                try:
                    listing = self.ls(top, detail=True, **kwargs)
                except OSError as exc:
                    if on_error == "raise":
                        raise
                    if callable(on_error):
                        on_error(exc)
                    continue
                node = self._listed_dir(self._get_tree(), top.rstrip("/"))
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
                stack.append((top, None, None, (top, shown_dirs, shown_files)))
            if depth is not None:
                depth -= 1
                if depth < 1:
                    continue
            # Reversed, so the first directory is listed next, as recursion would.
            for name in reversed(list(shown_dirs)):
                if name in full_dirs:
                    child = cast("_Node", node).child(name)
                    stack.append((full_dirs[name], depth, child, None))

    def _build_tree(self) -> _Tree:
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
                placed.entry = self._entry(member, view)
        self._resolve_links(tree)
        return tree

    @staticmethod
    def _resolve_links(tree: _Tree) -> None:
        """Give each symlink entry the type, size and bytes of what its target text
        reaches among the written paths, as the destination resolves it once every
        member is written: a later member, a name re-rooted or renamed by the
        policy, a path through another link. A name extraction did not write is not
        reached, even when the archive holds a member of that name."""
        for link in tree.links:
            entry = cast("dict[str, Any]", link.entry)
            spot = tree.link_destination(link)
            # The end of a resolve is never a link: the last one is followed too.
            reached = spot[0] if spot is not None and not spot[1] else None
            if reached is None:
                entry.update(type="other", size=None)
                continue
            reached_entry = reached.entry or {"type": "directory"}
            if reached is tree.root or reached_entry["type"] == "directory":
                entry.update(type="directory", size=0)
            elif reached_entry["type"] == "other":
                entry.update(type="other", size=None)
            else:
                entry.update(type="file", size=reached_entry["size"])
                link.read_as = reached_entry["member"]

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

    @staticmethod
    def _entry(member: ArchiveMember, view: ArchiveMember) -> dict[str, Any]:
        """The member's ``info()``, without the ``"name"``, which is the path it is
        reached by."""
        islink = member.type in (MemberType.SYMLINK, MemberType.HARDLINK)
        # ``link_target_member`` is the end of the link chain; a cycle or a target
        # that is no member leaves it ``None``, and a chain that ends at a symlink
        # with no target ends at that symlink. ``view`` is the member as written: a
        # hard link to a symlink is that symlink, with its target.
        target = view.link_target_member if islink else member
        entry: dict[str, Any] = {}
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
        node = self._find(path)
        info = _info(node, path)
        if info["type"] == "directory":
            raise IsADirectoryError(path)
        if info["type"] != "file":
            raise FileNotFoundError(path)
        # A symlink opens the member its target reaches.
        member = node.read_as if node.target is not None else info["member"]
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
