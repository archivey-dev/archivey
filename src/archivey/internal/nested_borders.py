"""Borders inside one listing: ``ReaderContext.open_nested(under=, keep_out=)``.

A reader that joins several inner archives into one listing draws borders between
them that extraction knows nothing of. A ``.deb`` lists its control tar under
``DEBIAN/`` and its data tar at the root, and a data member must not reach
``DEBIAN/``: it would replace a control file in the listing and on disk. A macOS
package lists each payload under its own folder. Extraction keeps every member inside
the destination, but these borders are inside it, so the reader names them and core
checks each inner member against them as the inner reader yields it, before the
outer listing holds it.

- ``under``: the inner members are listed under a folder, and each one, and each
  hard link's target, must extract inside it under every policy and filter, spelled
  exactly as the folder is (``extracted_segments``). A folder is one directory on
  every filesystem only when spelled alike: ``../debian/x`` is outside ``DEBIAN/`` on
  Linux.
- ``keep_out``: folders no inner member may reach under any spelling that extraction
  or a filesystem makes one with them (``collision_key``), through the inner
  archive's own symlinks too (:class:`LinkTree`).

Under either, a member under a symlink of the inner archive is refused, and so is a
symlink at the path of a directory or of another symlink: where such a member lands
depends on which members a caller extracts and on the overwrite policy, so no
listing-time check could hold.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from archivey.exceptions import ArchiveyUsageError, CorruptionError, ResourceLimitError
from archivey.internal.dependency_index import DependencyIndex, IndexNode
from archivey.internal.filters import (
    collision_key,
    extracted_segments,
    is_rooted,
    strip_absolute_root,
)
from archivey.terminal import quoted
from archivey.types import ArchiveFormat, ArchiveMember, ExtractionPolicy, MemberType

if TYPE_CHECKING:
    from archivey.formats import MemberSpan

# Both separators split a path, as in ``extracted_top_segment``.
_SEPARATORS = re.compile(r"[\\/]")
# How many symlinks one path may pass through, as Linux allows (ELOOP after 40). A
# path that needs more is left where the last one put it: no system resolves it.
_MAX_SYMLINK_STEPS = 40


def _fold(segment: str) -> str:
    """A segment as ``extracted_top_key`` folds one: two that fold alike can be one
    directory."""
    return collision_key(segment, ExtractionPolicy.STANDARD)


def _segments(path: str) -> list[str]:
    """The segments of ``path`` without its root, ``""`` and ``"."`` dropped."""
    return [
        s for s in _SEPARATORS.split(strip_absolute_root(path)) if s not in ("", ".")
    ]


class _Link:
    """A recorded symlink: what resolving its target needs."""

    __slots__ = ("directory", "rooted", "target", "text")

    def __init__(self, directory: list[str], text: str) -> None:
        # The folded segments of the symlink's directory, its target's segments,
        # whether the target is rooted, and the target as stored: a hard link to the
        # symlink extracts as a symlink with this text.
        self.directory = directory
        self.target = _segments(text)
        self.rooted = is_rooted(text)
        self.text = text


class _Node:
    """A path of the tree, in a trie of an inner archive's symlinks and
    directories: the children by folded name, the symlink when this path is one,
    and whether it is a directory."""

    __slots__ = ("children", "directory", "link")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.link: _Link | None = None
        # Whether a directory member, or the parent of a member, landed here.
        self.directory = False


class LinkTree:
    """An inner archive's symlinks and directories, to say where a path lands.

    A member extracts through the symlinks its archive made before it, so
    ``foo -> DEBIAN`` then ``foo/control`` writes ``DEBIAN/control``. Each path is
    resolved one segment at a time: ``..`` climbs, as ``sanitize_names`` resolves it,
    and a segment that names a symlink is replaced by its target, read from the
    symlink's own directory, or from the root of the listing when the target is
    rooted.
    Names are compared folded, as a case-insensitive filesystem would. The walk of
    a path costs one dictionary step per segment, and at most
    ``_MAX_SYMLINK_STEPS`` targets are followed.

    The check has to hold for every selection of members a caller extracts, not only for
    the whole archive, so the caller keeps every path's meaning independent of the
    selection: a member under a symlink of the archive is refused (``locate``), and so is a
    symlink at the path of a directory or of another symlink, and a directory at a
    symlink's path. Then a symlink left out of a selection leaves nothing at its path,
    and a path through it fails on disk instead of landing elsewhere. A file at a
    symlink's path replaces the symlink only when both are extracted, so the tree keeps
    the symlink: a path through a file fails too. A hard link to a symlink, through any
    number of hard links, extracts as a symlink with the same target text, read from the
    hard link's directory, so the tree records it as one. To see a directory that only a
    member's parent makes, the trie holds a node for every directory, not only for the
    symlinks.

    A symlink stays on disk, so a later symlink can change where an earlier one's
    target lands: ``x -> y/DEBIAN/control``, then ``y -> .``. As extraction's
    ``LinkWatch`` does, the tree keeps a :class:`DependencyIndex` of the paths each
    symlink's target resolution looked up, and ``add_symlink`` resolves again the
    targets of the symlinks that looked up the new symlink's path, and only those.

    Two kinds of work grow faster than the archive, and both count against ``budget``
    (``ListingLimits.max_members``), one per path step, with ``ResourceLimitError``
    once it is spent:

    - Every step taken inside a target the walk follows, in any resolution. Each
      of 40 follows can push a long target again, and every symlink that routes
      through it walks it again, so N short symlinks through 40 long ones cost
      N x 40 x their length. A walk over the resolved path's own segments is free,
      so an ordinary ``libfoo.so -> libfoo.so.1`` costs nothing.
    - Every step of a recheck. Each later symlink can redirect every earlier one,
      so the rechecks can cost links x links resolutions.

    The unit is a step, not a resolution as in ``LinkWatch``: one resolution here
    can follow 40 symlinks, so a count of resolutions would allow 40 times the
    work.
    """

    def __init__(self, budget: int | None, zones: list[list[str]]) -> None:
        # The folded segments of each folder the members are kept out of.
        self._zones = zones
        self._root = _Node()
        self._index: DependencyIndex[_Link] = DependencyIndex()
        # Steps left (None: no bound), and the limit they came from.
        self._budget = budget
        self._limit = budget
        # Steps over the resolved paths' own segments, which only a recheck pays.
        self._own_steps = 0

    def resolve(
        self, path: str, *, follow_last: bool, base: list[str] | None = None
    ) -> list[str]:
        """The folded segments of where ``path`` lands, read from ``base`` (folded
        segments of a directory; the root when ``None``).

        With ``follow_last`` false, the last segment is not followed, as for a
        member's own name. This only reads the tree."""
        return self._resolve(_segments(path), follow_last, base, None)

    def _resolve(
        self,
        segments: list[str],
        follow_last: bool,
        base: list[str] | None,
        link: _Link | None,
    ) -> list[str]:
        """``resolve`` of ``segments``. With ``link``, the paths the walk looked up
        are recorded in the dependency index as ``link``'s."""
        index = self._index
        pending = list(reversed(segments))  # popped from the end
        out = list(base) if base else []
        nodes = self._walk(out)
        # The index nodes along ``out``, while recording, and those the walk started
        # from, which ``record`` does not keep unless the walk looked them up.
        indexed = index.path(out) if link is not None else []
        starts = [indexed[-1]] if indexed else []
        visited: list[IndexNode[_Link]] = []
        follows = 0
        # The pending segments that are the path's own: the bottom of the stack,
        # under every target a follow pushed.
        own = len(pending)
        while pending:
            if len(pending) <= own:
                own -= 1
                self._own_steps += 1
            else:
                self._spend(1)
            segment = pending.pop()
            if segment == "..":
                if out:
                    out.pop()
                    nodes.pop()
                    if indexed:
                        indexed.pop()
                continue
            key = _fold(segment)
            parent = nodes[-1]
            node = parent.children.get(key) if parent is not None else None
            if indexed:
                visited.append(indexed[-1].child(key))
            if (
                node is not None
                and node.link is not None
                and (pending or follow_last)
                and follows < _MAX_SYMLINK_STEPS
            ):
                follows += 1
                followed = node.link
                pending.extend(reversed(followed.target))
                if followed.rooted:
                    out = []
                elif out != followed.directory:
                    out = list(followed.directory)
                else:
                    continue
                nodes = self._walk(out)
                if indexed:
                    indexed = index.path(out)
                    starts.append(indexed[-1])
                continue
            out.append(key)
            nodes.append(node)
            if indexed:
                indexed.append(visited[-1])
        if link is not None:
            index.record(link, visited)
            for start in starts:
                index.prune(start)
        return out

    def _walk(self, folded: list[str]) -> list[_Node | None]:
        """The trie nodes along ``folded``, from the root."""
        nodes: list[_Node | None] = [self._root]
        for key in folded:
            parent = nodes[-1]
            nodes.append(parent.children.get(key) if parent is not None else None)
        return nodes

    def in_zone(self, folded: list[str]) -> bool:
        """Whether the folded path ``folded`` is in, or is, a kept-out folder."""
        return any(folded[: len(zone)] == zone for zone in self._zones)

    def _lands_in_zone(self, link: _Link) -> bool:
        """Whether ``link``'s target lands in a kept-out folder now, the paths it
        looks up recorded afresh."""
        base = None if link.rooted else link.directory
        return self.in_zone(self._resolve(link.target, True, base, link))

    def _parent(self, where: list[str]) -> _Node:
        """The trie node of ``where``'s parent, created with its own parents where
        missing, and marked a directory: extraction creates it."""
        node = self._root
        for key in where[:-1]:
            node = node.children.setdefault(key, _Node())
        node.directory = True
        return node

    def locate(self, path: str) -> tuple[list[str], bool]:
        """The folded segments of ``path`` with its ``..`` taken lexically, as
        ``sanitize_names`` takes them, and whether a segment before the last names
        a symlink of the tree. When none does, extraction writes the member at that
        path, whichever members were selected."""
        out: list[str] = []
        nodes: list[_Node | None] = [self._root]
        crossed = False
        for segment in _segments(path):
            if segment == "..":
                if out:
                    out.pop()
                    nodes.pop()
                continue
            parent = nodes[-1]
            if parent is not None and parent.link is not None:
                crossed = True
            key = _fold(segment)
            out.append(key)
            nodes.append(parent.children.get(key) if parent is not None else None)
        return out, crossed

    def lands_in_zone_lexically(self, where: list[str], target: str) -> bool:
        """Whether ``target``, read from the directory of the symlink at ``where``
        with every ``..`` taken lexically and no symlink followed, lands in a
        kept-out folder. A read of the symlink resolves its target this way
        (``resolve_link_target_name``)."""
        # Built in place: a copy per segment would make one long target cost
        # the square of its length.
        out = [] if is_rooted(target) else list(where[:-1])
        for segment in _segments(target):
            if segment == "..":
                if out:
                    out.pop()
            else:
                out.append(_fold(segment))
        return self.in_zone(out)

    def has_symlink(self, where: list[str]) -> bool:
        """Whether the tree holds a symlink at ``where``."""
        return self.symlink_text(where) is not None

    def symlink_text(self, where: list[str]) -> str | None:
        """The stored target of the symlink at ``where``, or ``None`` when the tree
        holds none there."""
        node = self._find(where)
        return None if node is None or node.link is None else node.link.text

    def is_directory(self, where: list[str]) -> bool:
        """Whether a directory member, or a parent of a member, landed at ``where``."""
        node = self._find(where)
        return node is not None and node.directory

    def _find(self, where: list[str]) -> _Node | None:
        node = self._root
        for key in where:
            child = node.children.get(key)
            if child is None:
                return None
            node = child
        return node

    def add_symlink(self, where: list[str], target: str) -> bool:
        """Record a symlink at ``where`` (``locate`` of its name) and say whether a
        symlink's target lands in a kept-out folder: this one's, or an earlier one's that
        this one redirects. The caller refuses a symlink where the tree holds a
        directory or a symlink first."""
        if not where:
            return self.in_zone(self.resolve(target, follow_last=True))
        node = self._parent(where).children.setdefault(where[-1], _Node())
        # The symlinks whose targets looked up this path: a symlink here moves them.
        affected = self._index.dependents(where)
        link = _Link(where[:-1], target)
        node.link = link
        return self._lands_in_zone(link) or self._recheck(affected)

    def add_directory(self, where: list[str]) -> bool:
        """Record a directory member at ``where`` and say whether the tree holds a
        symlink there, which the caller refuses."""
        if not where:
            return False
        node = self._parent(where).children.setdefault(where[-1], _Node())
        if node.link is not None:
            return True
        node.directory = True
        return False

    def add_entry(self, where: list[str]) -> None:
        """Record a member that is neither a directory nor a symlink (a file, a hard
        link to one, a device) at ``where``: its parent is a directory. A hard link
        to a symlink extracts as a symlink, and goes to ``add_symlink``.

        A symlink at ``where`` stays in the tree. Extraction replaces it with the
        member when both are extracted, and then a path through ``where`` names no
        directory; it stays when the member is not selected. The tree keeps the one
        view under which such a path resolves."""
        if where:
            self._parent(where)

    def _spend(self, steps: int) -> None:
        """Charge ``steps`` path steps to the budget."""
        if self._budget is None:
            return
        self._budget -= steps
        if self._budget < 0:
            raise ResourceLimitError(
                f"Symlink resolution limit reached: max_members={self._limit} (the "
                "symlinks of an inner archive follow each other, or later ones "
                "redirect earlier ones, and resolving them took more path steps "
                "than that)"
            )

    def _recheck(self, affected: list[_Link]) -> bool:
        """Resolve ``affected`` again, the symlinks whose targets looked up a path
        that changed, and say whether one of them lands in a kept-out folder now. Every
        step counts against the budget: the followed ones as they are taken, the
        target's own ones here, at least one per recheck."""
        for earlier in affected:
            before = self._own_steps
            if self._lands_in_zone(earlier):
                return True
            self._spend(max(1, self._own_steps - before))
        return False


def _folder(folder: str, what: str) -> list[str]:
    """The segments of a folder ``under`` or ``keep_out`` names, as stored."""
    if not isinstance(folder, str):
        raise ArchiveyUsageError(
            f"ReaderContext.open_nested({what}=) takes folder names as str, not "
            f"{type(folder).__name__}"
        )
    segments = [s for s in _SEPARATORS.split(folder) if s not in ("", ".")]
    if not segments or is_rooted(folder) or ".." in segments:
        raise ArchiveyUsageError(
            f"ReaderContext.open_nested({what}=) takes a folder relative to the "
            f"listing's root, with no '..', not {quoted(folder)}"
        )
    return segments


class Borders:
    """The borders one ``open_nested`` call draws, checked span by span."""

    def __init__(
        self,
        inner: ArchiveFormat,
        under: str | None,
        keep_out: Iterable[str],
        budget: int | None,
    ) -> None:
        self._what = f"Inner {inner.display_name} archive"
        self._under = None if under is None else _folder(under, "under")
        self._prefix = "" if self._under is None else "/".join(self._under) + "/"
        if isinstance(keep_out, str):
            # A str is iterable too, a character at a time.
            raise ArchiveyUsageError(
                "ReaderContext.open_nested(keep_out=) takes a collection of folder "
                "names, not one str"
            )
        kept = [_folder(folder, "keep_out") for folder in keep_out]
        self._zone_names = ", ".join("/".join(segments) + "/" for segments in kept)
        self._tree = LinkTree(budget, [[_fold(s) for s in zone] for zone in kept])

    @property
    def active(self) -> bool:
        return self._under is not None or bool(self._zone_names)

    def check(self, span: MemberSpan) -> MemberSpan:
        """``span`` with its member renamed under the folder, refused with
        ``CorruptionError`` when it crosses a border."""
        member = span.member
        if self._under is not None:
            inner = member.name
            member.name = self._prefix if inner in (".", "./") else self._prefix + inner
            self._check_inside(member, member.name, "a member")
            if member.type is MemberType.HARDLINK and member.link_target:
                # archivey normalizes the prefixed target as it does names.
                member.link_target = self._prefix + member.link_target
                self._check_inside(member, member.link_target, "a hard link to a path")
        self._check_tree(span)
        return span

    def _check_inside(self, member: ArchiveMember, path: str, what: str) -> None:
        assert self._under is not None
        if extracted_segments(path)[: len(self._under)] != self._under:
            raise CorruptionError(
                f"{self._what} has {what} outside {self._prefix}, the folder it is "
                "listed under",
                member_name=member.name,
                link_target=member.link_target,
            )

    def _in_zone(self, path: str) -> bool:
        """Whether ``path`` extracts into a kept-out folder, no symlink followed."""
        return self._tree.in_zone([_fold(s) for s in extracted_segments(path)])

    def _check_tree(self, span: MemberSpan) -> None:
        member = span.member
        tree = self._tree
        where, crossed = tree.locate(member.name)
        if self._in_zone(member.name) or tree.in_zone(
            tree.resolve(member.name, follow_last=False) if crossed else where
        ):
            raise CorruptionError(
                f"{self._what} has a member that extracts into {self._zone_names}, "
                "a folder kept apart from it",
                member_name=member.name,
            )
        if crossed:
            raise CorruptionError(
                f"{self._what} has a member under a symlink it made; extraction "
                "writes it through the symlink, or into a directory there when the "
                "symlink is not extracted, so where it lands depends on the members "
                "selected",
                member_name=member.name,
            )
        if (
            member.type is MemberType.HARDLINK
            and member.link_target
            and (
                self._in_zone(member.link_target)
                or tree.in_zone(tree.resolve(member.link_target, follow_last=True))
            )
        ):
            raise CorruptionError(
                f"{self._what} has a hard link to a path in {self._zone_names}, a "
                "folder kept apart from it",
                member_name=member.name,
                link_target=member.link_target,
            )
        # Extraction makes a hard link to a symlink a symlink with the same target
        # text, read from the hard link's own directory.
        text = (
            member.link_target
            if member.type is MemberType.SYMLINK
            else tree.symlink_text(tree.locate(member.link_target)[0])
            if member.type is MemberType.HARDLINK and member.link_target
            else None
        )
        if text is not None:
            if tree.is_directory(where) or tree.has_symlink(where):
                raise self._shared_path(member.name)
            if tree.lands_in_zone_lexically(where, text) or tree.add_symlink(
                where, text
            ):
                raise CorruptionError(
                    f"{self._what} has a symlink to a path in {self._zone_names}, a "
                    "folder kept apart from it"
                    + (
                        ""
                        if member.type is MemberType.SYMLINK
                        else f" (a hard link to a symlink, extracted as -> {quoted(text)})"
                    ),
                    member_name=member.name,
                    link_target=member.link_target,
                )
        elif member.type is MemberType.DIRECTORY:
            if tree.add_directory(where):
                raise self._shared_path(member.name)
        elif member.type is not MemberType.SYMLINK:
            tree.add_entry(where)

    def _shared_path(self, name: str) -> CorruptionError:
        return CorruptionError(
            f"{self._what} has a symlink at the path of a directory or of another "
            "symlink; which one ends up on disk depends on the overwrite policy and "
            "on the members selected, so where the later members land cannot be "
            "checked",
            member_name=name,
        )


def bordered(spans: Iterator[MemberSpan], borders: Borders) -> Iterator[MemberSpan]:
    """``spans``, each checked against ``borders`` before it is yielded."""
    try:
        for span in spans:
            yield borders.check(span)
    finally:
        close = getattr(spans, "close", None)
        if close is not None:
            close()
