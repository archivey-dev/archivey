"""Which destination paths each extracted symlink depends on, and rechecking on change.

A symlink is checked against the live tree when it is created, but a later member can
change what it resolves to. ``l -> a/../secret`` resolves inside the destination while
``a`` does not exist, because a ``..`` after a missing component is taken lexically.
Once a later member creates ``a -> .``, ``l`` resolves outside (threat model O22).

:class:`LinkWatch` records, for every link the extraction creates, the destination
paths its resolution looked at: every component the walk ``lstat``-ed, whether it
existed or not, including the components of every link the walk followed on the way.
Only the state of those paths decides where the link resolves. When a member changes
one of them, the coordinator calls :meth:`LinkWatch.recheck` before the next member is
handled, and the links that now escape are removed.

Only two kinds of change can move a resolution, so they are the only changes reported:

- a symlink appears at a path, and
- a symlink or a directory is removed or replaced. Removing a symlink turns the
  component back into a plain name, and removing a directory removes the links in it.

A regular file or a directory created where nothing was does not move a resolution:
``..`` after a missing component and after a plain one both go to the same parent.

The recorded set is closed under prefixes, as far as the link's own directory: every
path the walk visits is reached by appending one component to a path it visited
before, to an ancestor of the link, or to the destination root (an absolute target
re-enters there). So a change at ``d`` is enough to find every link whose walk went
through ``d/x``: it went through ``d`` too. A change to an ancestor of the link itself
needs no entry, because removing that ancestor removes the link.

The dependency index keys paths by component, normalized to NFC and case-folded. On a
case-sensitive filesystem a change can then reach a link that did not depend on it;
the recheck finds nothing, and costs one resolution. The opposite mistake would miss
an escape on a case-insensitive one. That argument covers the index only: the map from
a path to the link recorded there is keyed on the exact path, because there a false
match forgets a link instead of rechecking one.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from archivey.internal.filters import resolve_or_raise_on_loop
from archivey.internal.long_paths import long_path, plain

# More symlink follows than any supported kernel allows in one resolution (Linux 40,
# macOS and FreeBSD 32, Windows 63 reparse points). A walk stops there: the OS
# refuses the path with ELOOP, so what lies further cannot be reached through it. A
# later change that shortens the chain happens at a link inside the first 64 hops,
# which the walk did record.
_MAX_FOLLOWS = 64

_SPLIT = re.compile(r"[\\/]") if os.sep == "\\" else re.compile("/")

Key = tuple[str, ...]


def _key(name: str) -> str:
    """One path component as the dependency index keys it: NFC, case-folded (see the
    module docstring)."""
    return unicodedata.normalize("NFC", name).casefold()


class _Node:
    """One destination path in the dependency index, and the links that visited it."""

    __slots__ = ("children", "dependents")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        # A dict used as an ordered set, so rechecks run in a reproducible order.
        self.dependents: dict[WatchedLink, None] = {}

    def child(self, name: str) -> _Node:
        key = _key(name)
        node = self.children.get(key)
        if node is None:
            node = self.children[key] = _Node()
        return node


@dataclass(eq=False)
class WatchedLink:
    """A symlink this extraction created, with what its resolution depended on.

    ``path`` is where the link physically is (its parent resolved), so a change to a
    symlink on the way to it (``s -> sub``, then ``s/l``) does not lose it.
    ``dest_path`` is the path its result reports, and ``result_index`` the result
    to revise if the link is removed. ``identity`` is the link's ``(st_dev, st_ino)``,
    to tell it from a link another member put at the same path later.
    """

    path: Path
    target: str
    dest_path: Path
    result_index: int
    identity: tuple[int, int]
    nodes: list[_Node] = field(default_factory=list)


@dataclass
class RecheckOutcome:
    """The links :meth:`LinkWatch.recheck` removed, for the caller to report."""

    escaped: list[WatchedLink] = field(default_factory=list)
    """Links that now resolve outside the destination, removed."""

    unchecked: list[WatchedLink] = field(default_factory=list)
    """Links removed without being resolved, because the budget ran out."""


class LinkWatch:
    """The dependency index for one extraction run. Not thread-safe."""

    def __init__(self, dest_root: Path, budget: int | None) -> None:
        # Folded like the index, so a walk that reaches the root by another spelling
        # (``/TMP/out`` on a case-insensitive filesystem) still knows it is inside.
        self._root_parts = tuple(_key(part) for part in dest_root.parts)
        self._root = _Node()
        # The link recorded at each physical path. Keyed on the exact path, unlike the
        # index: two links whose names differ only by case or normalization are two
        # entries on a filesystem that keeps them apart, and forgetting one when the
        # other is recorded would leave it unwatched.
        self._by_path: dict[Path, WatchedLink] = {}
        self._changed: dict[Path, None] = {}
        # Rechecks left before the run must stop (``None``: no bound). Each change can
        # recheck every link that depends on it, so a path changed many times with
        # many links behind it costs links x changes resolutions. The caller gives it
        # ``ExtractionLimits.max_entries``.
        self._budget = budget

    # --- recording ---------------------------------------------------------------

    def track(self, dest_path: Path, target: str, result_index: int) -> None:
        """Record a symlink just created at ``dest_path`` and report it as a change."""
        path = self._physical(dest_path)
        if self._folded_key(path) is None:
            return
        try:
            st = os.lstat(long_path(path))
        except OSError:
            return
        previous = self._by_path.pop(path, None)
        if previous is not None:
            self._unregister(previous)
        link = WatchedLink(
            path, target, dest_path, result_index, (st.st_dev, st.st_ino)
        )
        self._register(link)
        self._by_path[path] = link
        self._changed[path] = None

    def note_change(self, dest_path: Path) -> None:
        """Report that the entry at ``dest_path`` was, or is about to be, replaced or
        removed. The caller reports only symlinks and directories (see the module
        docstring)."""
        self._changed[self._physical(dest_path)] = None

    @property
    def has_changes(self) -> bool:
        return bool(self._changed)

    # --- rechecking --------------------------------------------------------------

    def recheck(self, escapes: Callable[[Path, str], bool]) -> RecheckOutcome:
        """Recheck every link that depends on a path changed since the last call.

        ``escapes(path, target)`` is the authoritative containment check for a link at
        ``path``. A link that escapes is unlinked here, and its removal is itself a
        change: a link that resolved through it is rechecked in turn. A link that
        still passes gets its dependencies recorded again, since the walk may now take
        another route. Once the budget is spent, every link still waiting is removed
        without being resolved, so none of them can be left escaping, and the caller
        stops the run.
        """
        # Insertion-ordered set: a link queued twice before its recheck is rechecked
        # once, and one queued again after it is rechecked again.
        queue: dict[WatchedLink, None] = {}
        changed, self._changed = self._changed, {}
        for path in changed:
            self._enqueue_dependents(path, queue)
        outcome = RecheckOutcome()
        while queue:
            link = next(iter(queue))
            del queue[link]
            if not self._is_live(link):
                self._forget(link)
                continue
            self._unregister(link)
            if self._budget is not None and self._budget <= 0:
                outcome.unchecked.append(link)
            else:
                if self._budget is not None:
                    self._budget -= 1
                if not escapes(link.path, link.target):
                    self._register(link)
                    continue
                outcome.escaped.append(link)
            try:
                os.unlink(link.path)
            except OSError:
                # The same as a link that escapes when it is created: the result
                # still says BLOCKED, and the caller logs it.
                pass
            self._forget(link)
            self._enqueue_dependents(link.path, queue)
        return outcome

    def _enqueue_dependents(self, path: Path, queue: dict[WatchedLink, None]) -> None:
        """Queue every link whose last walk visited ``path``, the changed path, and
        forget the link recorded at ``path`` if the change replaced it."""
        key = self._folded_key(path)
        if key is None:
            return
        # The link recorded at this path, if the change replaced or removed it.
        own = self._by_path.get(path)
        if own is not None and not self._is_live(own):
            self._forget(own)
        node = self._root
        for part in key:
            child = node.children.get(part)
            if child is None:
                return
            node = child
        for link in node.dependents:
            queue[link] = None

    @staticmethod
    def _is_live(link: WatchedLink) -> bool:
        """Whether the link recorded here is still the entry at its path.

        By identity where the filesystem has inode numbers, and by target on the FUSE
        and network mounts that report 0 for every file. A link this run creates at
        the same path later replaces the record in ``track``, so this only has to
        tell a link apart from whatever else a later member put there.
        """
        try:
            st = os.lstat(long_path(link.path))
            if not stat.S_ISLNK(st.st_mode):
                return False
            if link.identity[1]:
                return (st.st_dev, st.st_ino) == link.identity
            # Plain: Windows returns an absolute target with the extended prefix.
            return plain(os.readlink(long_path(link.path))) == link.target
        except OSError:
            return False

    def _forget(self, link: WatchedLink) -> None:
        self._unregister(link)
        if self._by_path.get(link.path) is link:
            del self._by_path[link.path]

    def _register(self, link: WatchedLink) -> None:
        link.nodes = self._walk(link.path, link.target)
        for node in link.nodes:
            node.dependents[link] = None

    @staticmethod
    def _unregister(link: WatchedLink) -> None:
        for node in link.nodes:
            node.dependents.pop(link, None)
        link.nodes = []

    # --- the walk ----------------------------------------------------------------

    def _walk(self, link: Path, target: str) -> list[_Node]:
        """The index nodes of every destination path that resolving ``target`` from
        ``link``'s directory ``lstat``-s.

        It follows ``os.path.realpath``: a missing component is kept as a name, a
        ``..`` drops the last component of the path resolved so far, and a symlink is
        replaced by its target, read from the directory it is in. The walk continues
        outside the destination, because a path can leave the root and come back in
        through it by name, but only paths inside it are recorded: nothing this
        extraction does can change the others.
        """
        n = len(self._root_parts)
        cur = list(link.parent.parts)
        # Index nodes for ``cur`` from the root down, or ``None`` while ``cur`` is not
        # inside the destination.
        nodes = self._nodes_for(cur)
        pending: list[str] = []
        visited: dict[int, _Node] = {}
        follows = 0

        def push(target: str) -> None:
            """Queue ``target``, read from ``cur``: the link's own target first, then
            each followed link's target, by the same rule."""
            nonlocal cur, nodes
            if PurePath(target).anchor:
                # Absolute, or on Windows drive- or root-relative. Joined the way
                # pathlib joins it, which is what the creation check resolves, so the
                # walk restarts from the anchor and ``..`` components survive.
                joined = PurePath(*cur).joinpath(target)
                # POSIX leaves a leading ``//`` to the implementation; Linux and macOS
                # read it as ``/``, and the root comparison needs the same spelling.
                cur = ["/" if joined.anchor == "//" else joined.anchor]
                nodes = self._nodes_for(cur)
                pending.extend(reversed(joined.parts[1:]))
            else:
                pending.extend(_components(target))

        push(target)
        while pending:
            comp = pending.pop()
            if comp in ("", "."):
                continue
            if comp == "..":
                if len(cur) > 1:  # ``..`` at the filesystem root stays there
                    cur.pop()
                    if nodes is not None:
                        nodes.pop()
                        if not nodes:
                            nodes = None
                continue
            cur.append(comp)
            if nodes is not None:
                node = nodes[-1].child(comp)
                nodes.append(node)
                visited[id(node)] = node
            elif len(cur) == n and self._under_root(cur):
                nodes = [self._root]
            path = os.path.join(*cur)
            try:
                if not stat.S_ISLNK(os.lstat(long_path(path)).st_mode):
                    continue
                link_target = plain(os.readlink(long_path(path)))
            except OSError:
                # Missing, or unreadable: kept as a name, as realpath does.
                continue
            follows += 1
            if follows > _MAX_FOLLOWS:
                break
            # The target is read from the directory the link is in.
            cur.pop()
            if nodes is not None:
                nodes.pop()
                if not nodes:
                    nodes = None
            push(link_target)
        return list(visited.values())

    def _nodes_for(self, parts: list[str]) -> list[_Node] | None:
        """The index nodes from the root down to the path ``parts``, created where
        missing, or ``None`` when that path is not inside the destination."""
        n = len(self._root_parts)
        if not self._under_root(parts):
            return None
        nodes = [self._root]
        for part in parts[n:]:
            nodes.append(nodes[-1].child(part))
        return nodes

    # --- paths -------------------------------------------------------------------

    def _under_root(self, parts: Sequence[str]) -> bool:
        """Whether ``parts`` is the destination root or a path under it."""
        n = len(self._root_parts)
        return len(parts) >= n and all(
            _key(part) == root for part, root in zip(parts, self._root_parts)
        )

    def _folded_key(self, path: Path) -> Key | None:
        """``path``'s index key: its components under the root, folded."""
        parts = path.parts
        n = len(self._root_parts)
        if not self._under_root(parts) or len(parts) == n:
            return None
        return tuple(_key(part) for part in parts[n:])

    @staticmethod
    def _physical(path: Path) -> Path:
        """``path`` with its parent resolved: where the entry physically is."""
        try:
            return resolve_or_raise_on_loop(path.parent) / path.name
        except OSError:
            return path


def _components(target: str) -> list[str]:
    """``target``'s components in reverse, so the walk pops them in order."""
    return _SPLIT.split(target)[::-1]
