"""Which paths each symlink's resolution looked up, to find the symlinks a change moves.

A symlink is checked when it is made, but a later symlink can change where its target
lands: ``l -> a/x`` names ``a/x`` until a later ``a -> /`` sends it elsewhere.
Rechecking every symlink on every change costs links x changes resolutions. A
:class:`DependencyIndex` records, for each symlink, the paths its last resolution looked
up, so a change at a path rechecks only the symlinks that looked it up.

Two users share it, each with its own walk and its own keys:

- extraction's :class:`~archivey.internal.link_watch.LinkWatch`, which walks the
  destination with ``lstat`` and keys components NFC-normalized and case-folded, and
- ``open_nested``'s borders (``nested_borders.LinkTree``), which walk an inner archive's
  symlinks in memory and key segments as the extraction collision key folds them.

A walk records every path it appends a component to. So the recorded set of a link is
closed under prefixes from where the walk starts: a change at ``d`` finds every link
whose walk went through ``d/x``, because the walk went through ``d`` too.

Nodes exist only while a link records them, or a descendant of them. :meth:`forget`
removes the nodes it leaves empty, so the index holds one node per path that a live
link's last resolution looked up. Without that, a path changed many times leaves the
nodes of every abandoned route behind, and memory grows with the rechecks instead of
with the links.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Generic, TypeVar

L = TypeVar("L")


class IndexNode(Generic[L]):
    """One path in the index: its children by key, and the links that looked it up."""

    __slots__ = ("children", "dependents", "key", "parent")

    def __init__(self, parent: IndexNode[L] | None, key: str) -> None:
        self.parent = parent
        self.key = key
        self.children: dict[str, IndexNode[L]] = {}
        # A dict used as an ordered set, so rechecks run in a reproducible order.
        self.dependents: dict[L, None] = {}

    def child(self, key: str) -> IndexNode[L]:
        """The child at ``key``, created if missing. ``key`` is already folded."""
        node = self.children.get(key)
        if node is None:
            node = self.children[key] = IndexNode(self, key)
        return node


class DependencyIndex(Generic[L]):
    """The paths each link's last resolution looked up. Not thread-safe.

    The caller walks, creating nodes with :meth:`IndexNode.child` from :attr:`root`,
    and hands the nodes it looked up to :meth:`record`. Keys are whatever the caller
    folds a component to; two components that fold alike are one path here.
    """

    def __init__(self) -> None:
        self.root: IndexNode[L] = IndexNode(None, "")
        self._visits: dict[L, list[IndexNode[L]]] = {}

    def path(self, keys: Sequence[str]) -> list[IndexNode[L]]:
        """The nodes from the root down to ``keys``, created where missing. A walk
        that starts below the root starts from the last of them; :meth:`record` or
        :meth:`prune` removes the ones no link looks up."""
        nodes = [self.root]
        for key in keys:
            nodes.append(nodes[-1].child(key))
        return nodes

    def record(self, link: L, nodes: Iterable[IndexNode[L]]) -> None:
        """Record ``link`` as looking up ``nodes``, replacing what it recorded
        before."""
        kept: dict[int, IndexNode[L]] = {}
        for node in nodes:
            if id(node) not in kept:
                kept[id(node)] = node
                node.dependents[link] = None
        # The old nodes are let go only now: pruning them first could detach a node
        # the new walk is about to record.
        old = self._visits.pop(link, ())
        if kept:
            self._visits[link] = list(kept.values())
        for node in old:
            if id(node) not in kept:
                node.dependents.pop(link, None)
                self.prune(node)

    def forget(self, link: L) -> None:
        """Take ``link`` out of the index, and the nodes it leaves empty with it."""
        nodes = self._visits.pop(link, None)
        if nodes is None:
            return
        for node in nodes:
            node.dependents.pop(link, None)
        for node in nodes:
            self.prune(node)

    def prune(self, node: IndexNode[L]) -> None:
        """Remove ``node`` and its ancestors while they have no dependents and no
        children."""
        while (
            node.parent is not None
            and not node.dependents
            and not node.children
            and node.parent.children.get(node.key) is node
        ):
            del node.parent.children[node.key]
            node = node.parent

    def dependents(self, keys: Sequence[str]) -> list[L]:
        """The links whose last resolution looked up the path ``keys``."""
        node = self.root
        for key in keys:
            child = node.children.get(key)
            if child is None:
                return []
            node = child
        return list(node.dependents)
