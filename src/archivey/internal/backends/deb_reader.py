"""The Debian package reader: a ``.deb`` read as the files it installs.

A ``.deb`` is an ar archive of three members, in this order::

    debian-binary        "2.0\\n": the package format version
    control.tar[.gz|.xz|.zst]          the maintainer files: control, md5sums, scripts
    data.tar[.gz|.xz|.zst|.bz2|.lzma]  the files the package installs

The listing is what ``dpkg-deb -R`` unpacks: the data tar's members under their own
names, and the control tar's under ``DEBIAN/``. ``debian-binary`` is not listed; opening
the file with ``format=ArchiveFormat.AR`` gives the three ar members instead. Both tars
are read through :meth:`ReaderContext.open_nested`, in the one forward pass, so a
``.deb`` reads from a pipe.

As ``dpkg-deb`` does, the walk refuses a version other than ``2.x``, skips members
whose name starts with ``_`` before the data tar, refuses any other member there, and
stops after the data tar. It also keeps the two tars apart, as ``dpkg-deb -R`` does: a
data-tar member that can extract to ``DEBIAN`` or under it, in any spelling or through a
data-tar symlink, is refused, and so is a control-tar member that extracts outside
``DEBIAN/``, a hard link in either tar whose target crosses to the other, and a data-tar
symlink whose target lands in ``DEBIAN``, at once or once a later symlink moves it.
``dpkg-deb -R`` unpacks the data tar first, then fails on a ``DEBIAN`` path the data tar
made, and GNU tar refuses a ``..`` name. ``DEBIAN/md5sums`` lists an MD5 per installed
file: the walk holds it (it is part of the control tar, so it arrives first) and gives
each data file its digest in ``ArchiveMember.hashes``, which a read then checks. A line
that is not an MD5 and a name is skipped, as ``dpkg --verify`` skips it.

Handbook page: ``dev-docs/formats/deb.md``.
"""

from __future__ import annotations

import io
import itertools
import re
from collections.abc import Generator, Iterator
from typing import BinaryIO

from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.dependency_index import DependencyIndex, IndexNode
from archivey.internal.filters import (
    collision_key,
    extracted_top_key,
    extracted_top_segment,
    is_rooted,
    strip_absolute_root,
)
from archivey.internal.format_adapter import HeldInnerData, register_builtin_format
from archivey.internal.overrides import override
from archivey.internal.salvage import WalkSalvage
from archivey.internal.streams.callers_source import from_source_callback
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ContainerFormat,
    ExtractionPolicy,
    HashAlgorithm,
    MemberType,
    StreamFormat,
)

AR_MAGIC = b"!<arch>\n"
HEADER_SIZE = 60
VERSION_MEMBER = b"debian-binary"
# The first member's name field, as dpkg-deb (no slash) and GNU ar (a slash) write it.
MAGIC = (
    AR_MAGIC + VERSION_MEMBER.ljust(16),
    AR_MAGIC + (VERSION_MEMBER + b"/").ljust(16),
)
CONTROL_DIR = "DEBIAN/"
# The first path segment of CONTROL_DIR. A control member must extract under exactly
# this segment; a data member must not extract under any spelling of it (_CONTROL_KEY).
_CONTROL_TOP = CONTROL_DIR.rstrip("/")
_CONTROL_KEY = extracted_top_key(_CONTROL_TOP)
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
    """A path of the data tree, in a trie of the data tar's symlinks and
    directories: the children by folded name, the symlink when this path is one,
    and whether it is a directory."""

    __slots__ = ("children", "directory", "link")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.link: _Link | None = None
        # Whether a directory member, or the parent of a member, landed here.
        self.directory = False


class _DataTree:
    """The data tar's symlinks and directories, to say where a path lands.

    A data member extracts through the symlinks the data tar made before it, so
    ``foo -> DEBIAN`` then ``foo/control`` writes ``DEBIAN/control``. Each path is
    resolved one segment at a time: ``..`` climbs, as ``sanitize_names`` resolves it,
    and a segment that names a symlink is replaced by its target, read from the
    symlink's own directory, or from the package root when the target is rooted.
    Names are compared folded, as a case-insensitive filesystem would. The walk of
    a path costs one dictionary step per segment, and at most
    ``_MAX_SYMLINK_STEPS`` targets are followed.

    The check has to hold for every selection of members a caller extracts, not only for
    the whole tar, so the caller keeps every path's meaning independent of the
    selection: a member under a symlink of the tar is refused (``locate``), and so is a
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

    Two kinds of work grow faster than the tar, and both count against ``budget``
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

    def __init__(self, budget: int | None) -> None:
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
        segments of a directory; the package root when ``None``).

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

    def _lands_in_control(self, link: _Link) -> bool:
        """Whether ``link``'s target lands in ``DEBIAN`` now, the paths it looks up
        recorded afresh."""
        base = None if link.rooted else link.directory
        return self._resolve(link.target, True, base, link)[:1] == [_CONTROL_KEY]

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

    def lands_in_control_lexically(self, where: list[str], target: str) -> bool:
        """Whether ``target``, read from the directory of the symlink at ``where``
        with every ``..`` taken lexically and no symlink followed, lands in
        ``DEBIAN``. A read of the symlink resolves its target this way
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
        return out[:1] == [_CONTROL_KEY]

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
        symlink's target lands in ``DEBIAN``: this one's, or an earlier one's that
        this one redirects. The caller refuses a symlink where the tree holds a
        directory or a symlink first."""
        if not where:
            return self.resolve(target, follow_last=True)[:1] == [_CONTROL_KEY]
        node = self._parent(where).children.setdefault(where[-1], _Node())
        # The symlinks whose targets looked up this path: a symlink here moves them.
        affected = self._index.dependents(where)
        link = _Link(where[:-1], target)
        node.link = link
        return self._lands_in_control(link) or self._recheck(affected)

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
                "symlinks of the Debian package data tar follow each other, or later "
                "ones redirect earlier ones, and resolving them took more path steps "
                "than that)"
            )

    def _recheck(self, affected: list[_Link]) -> bool:
        """Resolve ``affected`` again, the symlinks whose targets looked up a path
        that changed, and say whether one of them lands in ``DEBIAN`` now. Every
        step counts against the budget: the followed ones as they are taken, the
        target's own ones here, at least one per recheck."""
        for earlier in affected:
            before = self._own_steps
            if self._lands_in_control(earlier):
                return True
            self._spend(max(1, self._own_steps - before))
        return False


# dpkg-deb accepts these compressions for each tar.
_CONTROL_STREAMS = {
    b"": StreamFormat.UNCOMPRESSED,
    b".gz": StreamFormat.GZIP,
    b".xz": StreamFormat.XZ,
    b".zst": StreamFormat.ZSTD,
}
_DATA_STREAMS = {
    **_CONTROL_STREAMS,
    b".bz2": StreamFormat.BZIP2,
    b".lzma": StreamFormat.LZMA_ALONE,
}
# The control file's fields the archive info carries (as deb.package and so on).
_FIELDS = (b"package", b"version", b"architecture")
_HEX = frozenset(b"0123456789abcdefABCDEF")
# The digits of an unsupported major version an error message shows.
_VERSION_SHOWN = 20
# What one md5sums entry holds beyond its name's characters (_str_bytes), as 64-bit
# CPython measures it: the name's str header (40 to 56 bytes), the 16-byte digest object
# (49) and the entry's share of the dict, a 24-byte slot, its index and the spare room a
# dict keeps (31 bytes an entry over 500 000 entries, up to 60 just after the dict
# grows). A constant, not sys.getsizeof(), which PyPy does not implement.
_MD5_ENTRY = 56 + 49 + 48


def _str_bytes(text: str) -> int:
    """The bytes CPython stores for ``text``'s characters: 1, 2 or 4 a character, as
    its widest character needs. One emoji makes a long name 4 bytes a character, and
    one undecodable byte (a lone surrogate) 2."""
    if text.isascii():
        return len(text)
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        pass
    else:
        return len(text)
    # In UTF-16 a character above U+FFFF takes 4 bytes, and every other one 2.
    if len(text.encode("utf-16-le", "surrogatepass")) > 2 * len(text):
        return 4 * len(text)
    return 2 * len(text)


def _ar_confirmed(salvage: WalkSalvage, after: int) -> bool:
    """The ar reader's confirmation of a found header (``ar_confirmed``)."""
    # Imported here, as in ``DebReader._search``.
    from archivey.internal.backends.ar_reader import ar_confirmed

    return ar_confirmed(salvage, after)


def _tar_format(
    name: bytes, kind: bytes, streams: dict[bytes, StreamFormat]
) -> ArchiveFormat | None:
    """The format of ``control.tar.xz`` and its kin, or None for another name."""
    stem = kind + b".tar"
    if not name.startswith(stem):
        return None
    stream = streams.get(name[len(stem) :])
    return None if stream is None else ArchiveFormat(ContainerFormat.TAR, stream)


class DebReader(SequentialReader):
    """Walks a ``.deb``: its two tars, through the nested-archive hook."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._version: str | None = None
        self._fields: dict[bytes, str] = {}
        self._md5: dict[str, bytes] = {}

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        # What the walk has seen so far: in a streaming pass the fields arrive with the
        # control tar.
        fields = self._fields
        extra = ArchiveInfoExtra()
        if b"package" in fields:
            extra["deb.package"] = fields[b"package"]
        if b"version" in fields:
            extra["deb.version"] = fields[b"version"]
        if b"architecture" in fields:
            extra["deb.architecture"] = fields[b"architecture"]
        return ReaderArchiveInfo(
            is_solid=True, format_version=self._version, extra=extra
        )

    @override
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        magic = stream.read(len(AR_MAGIC))
        if magic != AR_MAGIC:
            if AR_MAGIC.startswith(magic):
                raise TruncatedError("Debian package ends inside its ar magic")
            raise CorruptionError("No ar magic at offset 0")
        name, size = self._header(stream)
        if name != VERSION_MEMBER:
            raise CorruptionError(
                "Debian package does not start with its debian-binary member"
            )
        # dpkg-deb allocates whatever size the header gives; archivey counts it
        # against max_metadata_bytes before reading it, like the control files.
        self._count(size, "debian-binary member")
        self._read_version(stream.read_exact(size))
        stream.read(size & 1)
        # Salvage (``open_archive(salvage=True)``): where an ar header after
        # debian-binary is damaged, the walk searches on for the next ar header, as
        # the ar reader does, and lists the tar it finds; the pass ends in the first
        # damage. The tars themselves are read as they are.
        salvage = self._context._salvage(stream) if self._context._salvage else None
        damage: CorruptionError | None = None
        search_from: int | None = None
        control = False
        while True:
            # Whether the search found this header, or the walk walked on to it.
            searched = search_from is not None
            if search_from is not None:
                assert salvage is not None and damage is not None
                hit = self._search(salvage, stream, search_from)
                search_from = None
                if hit is None:
                    raise salvage.ending(damage)
                offset, name, size = hit
            else:
                offset = stream.offset
                try:
                    name, size = self._header(stream)
                except CorruptionError as err:
                    if salvage is None or not salvage.is_damage(err):
                        raise
                    damage = damage or err
                    search_from = offset
                    continue
            confirmed = True
            if damage is not None:
                # Past the damage, a member claims its data only when the header
                # after it passes too, or the package ends there.
                assert salvage is not None
                if not searched and not salvage.holds(offset + HEADER_SIZE + size):
                    # Data that runs past the layer's end, as ``_search`` refuses for
                    # a found header: not listed, since reading it would end the pass
                    # in TruncatedError. The search goes on past this header.
                    search_from = salvage.after(offset)
                    continue
                confirmed = _ar_confirmed(
                    salvage, offset + HEADER_SIZE + size + (size & 1)
                )
                if not confirmed:
                    # The search goes on inside its data, past this header.
                    search_from = salvage.after(offset)
            if name.startswith(b"_"):
                stream.skip(size)
                stream.read(size & 1)
                continue
            fmt = None if control else _tar_format(name, b"control", _CONTROL_STREAMS)
            if fmt is not None:
                # Only a control tar the walk counts (``confirmed``) is the package's:
                # its fields, its md5sums and the end of the search for one. One
                # nothing confirms is listed and changes nothing else, so a later
                # control tar is still read.
                spans = self._opened(
                    self._control(stream.take(size), fmt, settles=confirmed), damage
                )
                if spans is None:
                    # Past the damage, a control tar that does not open is not one:
                    # the search goes on past its header.
                    assert salvage is not None
                    search_from = salvage.after(offset)
                    continue
                whole = yield from self._found(
                    salvage if damage else None, spans, offset, confirmed, searched
                )
                control = control or confirmed
                if not whole:
                    # The control tar failed after listing members: the search goes
                    # on past its header, for the data tar.
                    assert salvage is not None
                    search_from = salvage.after(offset)
                    continue
                stream.read(size & 1)
                continue
            fmt = _tar_format(name, b"data", _DATA_STREAMS)
            if fmt is None:
                if damage is not None:
                    # A header past the damage that is not a package member: the
                    # search goes on past it.
                    assert salvage is not None
                    search_from = salvage.after(offset)
                    continue
                if not control:
                    raise CorruptionError(
                        "Debian package has no control.tar member after debian-binary"
                    )
                raise CorruptionError(
                    "Debian package has an unexpected member before its data.tar"
                )
            if not control and damage is None:
                raise CorruptionError(
                    "Debian package has no control.tar member after debian-binary"
                )
            spans = self._opened(self._data(stream.take(size), fmt), damage)
            if spans is None:
                # Past the damage, a data tar that does not open is not one: the
                # search goes on past its header, as for a control tar.
                assert salvage is not None
                search_from = salvage.after(offset)
                continue
            yield from self._found(
                salvage if damage else None, spans, offset, confirmed, searched
            )
            # dpkg-deb reads no further: members after the data tar are not part of
            # the package.
            if salvage is not None:
                if damage is not None:
                    raise salvage.ending(damage)
                salvage.state.finish()
            return

    @staticmethod
    def _opened(
        spans: Iterator[MemberSpan], damage: CorruptionError | None
    ) -> Iterator[MemberSpan] | None:
        """``spans`` with its first member read, or ``None`` when the tar is past
        ``damage`` and reading its first member raises ``CorruptionError``.

        The salvage search checks little of an ar header (a name, a size, a date), so
        a header past the damage can name a tar whose payload is not one. Such a tar
        lists nothing and is not the package's: the walk searches on, and the pass
        ends in the first damage. Before any damage, or once the tar has listed a
        member, its error is the package's and is raised.
        """
        if damage is None:
            return spans
        try:
            first = next(spans)
        except StopIteration:
            return iter(())
        except CorruptionError as exc:
            if from_source_callback(exc):
                raise
            return None
        return itertools.chain((first,), spans)

    @staticmethod
    def _found(
        salvage: WalkSalvage | None,
        spans: Iterator[MemberSpan],
        offset: int,
        confirmed: bool,
        searched: bool,
    ) -> Generator[MemberSpan, None, bool]:
        """``spans``, each member flagged with ``MEMBER_FOUND_BY_SCAN`` when
        ``salvage`` is given: the tar's ar header at ``offset`` is past damage, found
        by the search (``searched``) or walked on to.

        Returns whether the tar listed to its end. Past damage, a tar that raises
        ``CorruptionError`` after its first member ends there and returns ``False``:
        the pass still ends in the first damage, the package's own error. Before
        damage, and for an exception ``on_source_read`` raised, the error is raised.
        """
        try:
            for span in spans:
                if salvage is not None:
                    salvage.found(
                        span.member,
                        offset=offset,
                        confirmed=confirmed,
                        searched=searched,
                    )
                yield span
        except CorruptionError as exc:
            if salvage is None or not salvage.is_damage(exc):
                raise
            return False
        return True

    def _search(
        self, salvage: WalkSalvage, stream: ForwardStream, start: int
    ) -> tuple[int, bytes, int] | None:
        """The next ar header the salvage search finds from ``start`` whose data
        the package holds, with its offset, name and size; the stream is moved to
        its data. ``None`` when none is found."""
        while True:
            # Imported here: importing the ar reader registers AR, and the order the
            # formats register in is the order detection tries them.
            from archivey.internal.backends.ar_reader import AR_HEADER_SEARCH

            result = salvage.search(AR_HEADER_SEARCH, start=start)
            if result.found is None:
                return None
            at = result.found
            salvage.seek(at)
            try:
                name, size = self._header(stream)
            except CorruptionError as exc:
                if not salvage.is_damage(exc):
                    raise
                start = at
                continue
            if not salvage.holds(at + HEADER_SIZE + size):
                start = at
                continue
            return at, name, size

    def _header(self, stream: ForwardStream) -> tuple[bytes, int]:
        """The next ar member's name and size."""
        offset = stream.offset
        raw = stream.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            raise TruncatedError(
                f"Debian package ends {len(raw)} bytes into the ar header at offset "
                f"{offset}"
            )
        if raw[58:] != b"`\n":
            raise CorruptionError(f"No ar member header at offset {offset}")
        text = raw[48:58].strip(b" ")
        if not text.isdigit():
            raise CorruptionError(
                f"ar header at offset {offset}: the size field is not a number"
            )
        # dpkg-deb writes short names only; GNU ar ends them with a slash.
        return raw[:16].rstrip(b" ").removesuffix(b"/"), int(text)

    def _read_version(self, data: bytes) -> None:
        version = data.split(b"\n", 1)[0].strip()
        major, dot, _minor = version.partition(b".")
        if not (major.isdigit() and dot):
            raise CorruptionError("Debian package has no format version")
        # The digits are compared as bytes: int() refuses more than 4300 digits with
        # a ValueError, and the member may hold millions.
        digits = major.lstrip(b"0") or b"0"
        if digits != b"2":
            shown = digits[:_VERSION_SHOWN].decode("ascii")
            if len(digits) > _VERSION_SHOWN:
                shown += f"... ({len(digits)} digits)"
            raise UnsupportedFeatureError(
                f"Debian package format version {shown}: archivey reads 2.x, "
                "as dpkg-deb does"
            )
        self._version = version.decode("ascii", "replace")

    def _control(
        self, data: BinaryIO, fmt: ArchiveFormat, *, settles: bool = True
    ) -> Iterator[MemberSpan]:
        """The control tar's members, under ``DEBIAN/``.

        ``control`` and ``md5sums`` are read whole on the way, for the archive info and
        the data files' digests, so their spans are served from those held bytes.
        Not when ``settles`` is false (a tar past damage that nothing confirms): its
        members are listed as they are, and it holds and charges nothing. A
        member whose prefixed name extracts outside ``DEBIAN/`` (``../usr/x``) is
        refused, and so is a hard link whose prefixed target does.
        """
        context = self._context
        for span in context.open_nested(data, fmt):
            member = span.member
            inner = member.name
            member.name = CONTROL_DIR if inner == "." else CONTROL_DIR + inner
            if extracted_top_segment(member.name) != _CONTROL_TOP:
                raise CorruptionError(
                    "Debian package control tar has a member outside DEBIAN/, the "
                    "directory of the control files; dpkg-deb refuses the package",
                    member_name=member.name,
                )
            if member.type is MemberType.HARDLINK and member.link_target:
                # archivey normalizes the prefixed target as it does names.
                member.link_target = CONTROL_DIR + member.link_target
                if extracted_top_segment(member.link_target) != _CONTROL_TOP:
                    raise CorruptionError(
                        "Debian package control tar has a hard link to a path outside "
                        "DEBIAN/; dpkg-deb refuses the package",
                        member_name=member.name,
                        link_target=member.link_target,
                    )
            if (
                settles
                and member.type is MemberType.FILE
                and inner in ("control", "md5sums")
            ):
                held = self._hold(span, inner)
                if inner == "control":
                    self._read_control(held)
                else:
                    self._read_md5sums(held)
                span = span._replace(data=HeldInnerData(held))
            yield span

    def _data(self, data: BinaryIO, fmt: ArchiveFormat) -> Iterator[MemberSpan]:
        """The data tar's members, each file with its digest from ``md5sums``.

        A member that can extract to ``DEBIAN`` or under it, under any spelling that
        extraction or the filesystem makes one with it, is refused, and so is a hard
        link whose target can. The test is stricter than ``dpkg-deb -R``, which GNU
        tar on Linux reads byte for byte: ``usr\\..\\DEBIAN/x`` (``sanitize_names``
        and Windows read the backslashes as separators), ``C:/DEBIAN/x`` (extraction
        drops a drive root on every OS), ``DEBIAN./x`` and ``DEBIAN /x`` (``STRICT``
        and Win32 trim the dot or space) and ``debian/x`` (one directory with
        ``DEBIAN/`` on a case-insensitive filesystem). The control side stays exact:
        folding there would accept ``../debian/x``, which is data on Linux.

        The control files are listed under ``DEBIAN/``, so a data copy of
        ``DEBIAN/control`` would replace the real control file in the listing and in
        extraction, and a hard link would read a control file's bytes.

        The same holds through the data tar's symlinks (``_DataTree``): a symlink whose
        target lands in ``DEBIAN`` is refused (``foo -> DEBIAN``,
        ``usr/l -> ../DEBIAN``, ``x -> /DEBIAN/control``), and so is a member or a
        hard-link target that lands there through an earlier symlink (``d -> .``, then
        ``d/DEBIAN/control``). A later symlink that sends an earlier one's target there
        is refused too (``x -> y/DEBIAN/control``, then ``y -> .`` refuses ``y``), and
        so is one whose target lands there lexically, as a read of the symlink resolves
        it (``x -> y/../DEBIAN/control``). So that this holds for every selection of
        members, a member under a data symlink is refused, and so is a symlink at the
        path of a directory or another symlink (``_DataTree``). A hard link to a symlink
        is checked as the symlink extraction makes of it (``q/h`` linked to
        ``a/b/x -> ../DEBIAN`` names ``DEBIAN``). Otherwise extraction writes through
        the symlink into a control file, and a read of the symlink returns one.
        ``dpkg-deb -R`` unpacks the data tar first, so there such a symlink names
        nothing; refusing it is stricter, as the spellings above are.
        """
        context = self._context
        tree = _DataTree(context.config.listing_limits.max_members)
        for span in context.open_nested(data, fmt):
            member = span.member
            where, crossed = tree.locate(member.name)
            if extracted_top_key(member.name) == _CONTROL_KEY or (
                tree.resolve(member.name, follow_last=False) if crossed else where
            )[:1] == [_CONTROL_KEY]:
                raise CorruptionError(
                    "Debian package data tar has a member that extracts into DEBIAN/, "
                    "the directory of the control files",
                    member_name=member.name,
                )
            if crossed:
                raise CorruptionError(
                    "Debian package data tar has a member under a symlink it made; "
                    "extraction writes it through the symlink, or into a directory "
                    "there when the symlink is not extracted, so where it lands, "
                    "DEBIAN/ included, depends on the members selected",
                    member_name=member.name,
                )
            if (
                member.type is MemberType.HARDLINK
                and member.link_target
                and (
                    extracted_top_key(member.link_target) == _CONTROL_KEY
                    or tree.resolve(member.link_target, follow_last=True)[:1]
                    == [_CONTROL_KEY]
                )
            ):
                raise CorruptionError(
                    "Debian package data tar has a hard link to a path in DEBIAN/, "
                    "the directory of the control files",
                    member_name=member.name,
                    link_target=member.link_target,
                )
            # Extraction makes a hard link to a symlink a symlink with the same
            # target text, read from the hard link's own directory.
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
                if tree.lands_in_control_lexically(where, text) or tree.add_symlink(
                    where, text
                ):
                    raise CorruptionError(
                        "Debian package data tar has a symlink to a path in DEBIAN/, "
                        "the directory of the control files"
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
            if member.type is MemberType.FILE:
                digest = self._md5.get(member.name)
                if digest is not None:
                    member.hashes = {**member.hashes, HashAlgorithm.MD5: digest}
            yield span

    @staticmethod
    def _shared_path(name: str) -> CorruptionError:
        return CorruptionError(
            "Debian package data tar has a symlink at the path of a directory or of "
            "another symlink; which one ends up on disk depends on the overwrite "
            "policy and on the members selected, so where the later members land, "
            "DEBIAN/ included, cannot be checked",
            member_name=name,
        )

    def _hold(self, span: MemberSpan, name: str) -> bytes:
        """A control file's bytes, read whole, against ``max_metadata_bytes``."""
        # ``name`` is "control" or "md5sums", never a name from elsewhere.
        self._count(span.member.size or 0, f"control file {name}")
        return span.data.read() if span.data is not None else b""

    def _count(self, size: int, what: str) -> None:
        """Charge ``size`` more held bytes to the listing, refusing before they are
        read. ``debian-binary``, ``control`` and ``md5sums`` are held whole, and
        their sizes come from the package. Each entry of the digest map is charged
        too, as it is added, at an estimate of what it holds. A walk started over to
        reach member data charges nothing: the listing walk did."""
        self._context.charge_metadata(size, what=f"the Debian package {what}")

    def _read_control(self, data: bytes) -> None:
        """The first paragraph's Package, Version and Architecture fields."""
        for line in data.split(b"\n"):
            if not line.strip():
                break
            field, colon, value = line.partition(b":")
            key = field.strip().lower()
            if colon and key in _FIELDS and not line[:1].isspace():
                self._fields[key] = value.strip().decode("utf-8", "replace")

    def _read_md5sums(self, data: bytes) -> None:
        """``<32 hex digits> <name>`` per line, the name relative to the root.

        The lines are read one at a time, not split into a list, and each entry the
        map keeps is charged to ``max_metadata_bytes`` before it is added: the file's
        own bytes were charged when it was held, and the map holds about three times
        as much again for short ASCII names, more for names stored wider."""
        context = self._context
        md5 = self._md5
        for line in io.BytesIO(data):
            digest, _space, name = line.removesuffix(b"\n").partition(b" ")
            # md5sum writes two spaces, the second a " " (text) or "*" (binary) mark.
            name = name[1:] if name[:1] in (b" ", b"*") else name
            if len(digest) != 32 or not set(digest) <= _HEX or not name:
                continue
            path = context.normalize_name(context.decode_name(name), MemberType.FILE)
            if path not in md5:
                self._count(_str_bytes(path) + _MD5_ENTRY, "md5sums entries")
            md5[path] = bytes.fromhex(digest.decode("ascii"))


class DebHandler(SequentialFormatHandler):
    """Debian binary packages: ``.deb``, and the installer's ``.udeb`` and debug
    symbols' ``.ddeb``, which share the layout."""

    format = ArchiveFormat.DEB
    extensions = (".deb", ".udeb", ".ddeb")
    magic = tuple(Magic(0, m) for m in MAGIC)
    uses_encoding = True

    @override
    def open_sequential(self, context: ReaderContext) -> DebReader:
        return DebReader(context)


DebReadBackend = register_builtin_format(DebHandler, SUPPORTS_SALVAGE=True)
