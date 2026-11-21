"""Apple disk images (``.dmg``): UDIF images holding HFS+ or HFSX volumes, written
against ``archivey.formats``.

Three layers, one module each (design ``openspec/changes/dmg-reader``):

1. :mod:`.udif`: the ``koly`` block, the property list and the run tables, and the
   virtual disk they describe, decoded run by run on demand.
2. :mod:`.disk_partitions`: where the filesystems are on that disk (GPT, Apple
   partition map, the run tables' ranges, or the whole disk), and which filesystem a
   range holds, by its signature.
3. :mod:`.hfsplus`: an HFS+ volume's catalog, attributes, hard links and transparent
   compression.

This module ties them together. :class:`DmgReader` opens the image and each HFS+
volume (a fixed amount of work, design §7), and lists the catalog at the first listing:
one volume's files at the archive root, or, when the image holds several, each volume's
files under a top-level directory named after the volume (D1).

An image whose only filesystem is APFS, and an encrypted image, are refused by name
until the parts of the plan that read them land.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple

from archivey.diagnostics import (
    ArchiveStructureContext,
    DiagnosticCode,
    MemberHeaderRecordContext,
    UnlistedDataContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    IndexedFormatHandler,
    IndexedReader,
    MemberData,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    block_stream,
)
from archivey.internal.backends import disk_partitions as partitions, hfsplus
from archivey.internal.backends.udif import (
    MAGIC,
    TRAILER,
    UdifImage,
    UdifSource,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ArchiveMember,
    MagicSignature,
    MemberType,
    TrailerSignature,
)

# An encrypted image (``hdiutil create -encryption``) starts with the ``encrcdsa`` (v2)
# header; a pre-10.5 one ends with ``cdsaencr`` (v1). Neither has a readable ``koly``
# block, so both are named here and refused (design §6B.1).
ENCRYPTED_V2 = b"encrcdsa"
ENCRYPTED_V1 = b"cdsaencr"
ENCRYPTED_MESSAGE = (
    "The file is an encrypted DMG disk image. Reading encrypted DMGs is not supported "
    "yet."
)

# The names macOS gives a volume it mounts with no usable name (``/Volumes/Untitled``).
_UNTITLED = "Untitled"


class FileData(NamedTuple):
    """Where a file's bytes are: its record in a volume, or why it cannot be read."""

    volume: int
    cnid: int  # the file whose forks hold the data (a hard link's inode)
    record: bytes  # its catalog file record
    decmpfs: hfsplus.Attribute | None  # its com.apple.decmpfs, when compressed
    refusal: tuple[type[ArchiveyError], str] | None = None


def volume_names(labels: list[str]) -> list[str]:
    """The top-level directory names for several volumes (D1): the label, ``Untitled``
    when it is empty, ``.`` or ``..``, and a name already taken (exactly, or but for
    case) gets `` 1``, `` 2``, ... as macOS names its mount points."""
    taken: set[str] = set()
    names = []
    for label in labels:
        base = label.replace("/", ":")
        if base in ("", ".", ".."):
            base = _UNTITLED
        name, n = base, 0
        while name in taken or name.casefold() in {t.casefold() for t in taken}:
            n += 1
            name = f"{base} {n}"
        taken.add(name)
        names.append(name)
    return names


class _Volume(NamedTuple):
    volume: hfsplus.HfsVolume
    candidate: partitions.Candidate


class DmgReader(IndexedReader[FileData | None]):
    """One open UDIF image."""

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._context = context
        _refuse_encrypted(source)
        self._image = image = UdifImage(source, context)
        layout = partitions.layout(image, image.report_structure)
        self._scheme = layout.scheme
        candidates = layout.candidates or [partitions.whole_disk(image)]
        found: list[tuple[partitions.Candidate, str | None]] = []
        for candidate in candidates:
            filesystem = partitions.probe(image, candidate)
            found.append((candidate, filesystem))
            self._check_name(candidate, filesystem)
        hfs = [c for c, fs in found if fs in (partitions.HFS, partitions.HFSX)]
        if not hfs:
            _refuse_unreadable(found)
        if layout.source == "map":
            for candidate in hfs:
                self._check_start(candidate)
        for candidate, filesystem in found:
            if filesystem in (partitions.HFS, partitions.HFSX):
                continue
            if filesystem is None and candidate.no_content:
                continue
            what = (
                "an APFS container, which archivey does not read yet"
                if filesystem == partitions.APFS
                else "an HFS volume, which archivey does not read"
                if filesystem == partitions.HFS_WRAPPER
                else "no filesystem archivey reads"
            )
            context.report(
                DiagnosticCode.ARCHIVE_UNLISTED_DATA,
                (
                    f"The DMG partition {quoted(candidate.label)} ({candidate.length} bytes "
                    f"at disk offset {candidate.start}) holds {what}. It is not listed."
                ),
                UnlistedDataContext(
                    format="dmg",
                    member_name=candidate.label,
                    offset=candidate.start,
                    compressed_size=candidate.length,
                ),
            )
        self._volumes = [
            _Volume(hfsplus.HfsVolume(UdifSource(image, c.start, c.length), context), c)
            for c in hfs
        ]
        image.end_open()
        self._names: list[str] | None = None

    # ── Open ─────────────────────────────────────────────────────────────────────────

    def _check_name(
        self, candidate: partitions.Candidate, filesystem: str | None
    ) -> None:
        """Report a map type or run table name that says another filesystem than the
        partition holds. The signature decides; the name only describes."""
        hint = candidate.hint
        if not hint:
            return
        holds = (
            partitions.APFS
            if filesystem == partitions.APFS
            else (
                partitions.HFS
                if filesystem
                in (partitions.HFS, partitions.HFSX, partitions.HFS_WRAPPER)
                else None
            )
        )
        if holds == hint:
            return
        self._image.report_structure(
            "partition_name",
            (
                f"The DMG partition {quoted(candidate.label)} at disk offset "
                f"{candidate.start} is named as {hint}, and holds "
                f"{filesystem or 'no filesystem archivey reads'}; its contents decide."
            ),
            candidate.start,
        )

    def _check_start(self, candidate: partitions.Candidate) -> None:
        """Report a partition the map places elsewhere than the run table named for
        the same filesystem that overlaps it. The map's range is read."""
        end = candidate.start + candidate.length
        for table in self._image.tables:
            start = table.first_sector * partitions.SECTOR
            table_end = start + table.sector_count * partitions.SECTOR
            if start == candidate.start or partitions.hint_from_name(table.name) != (
                partitions.HFS
            ):
                continue
            if start < end and candidate.start < table_end:
                self._image.report_structure(
                    "partition_start",
                    (
                        f"The DMG partition map places {quoted(candidate.label)} at disk "
                        f"offset {candidate.start}, and the run table {quoted(table.name)} "
                        f"at {start}; the map's range is read."
                    ),
                    candidate.start,
                )
                return

    # ── Listing ──────────────────────────────────────────────────────────────────────

    def _volume_names(self) -> list[str]:
        """Each volume's top-level directory, or ``""`` for the one volume of an image
        that holds one. Read at the first listing (the names are in the catalogs)."""
        if self._names is None:
            if len(self._volumes) == 1:
                self._names = [""]
            else:
                self._names = volume_names([self._label(v) for v in self._volumes])
        return self._names

    @staticmethod
    def _label(volume: _Volume) -> str:
        try:
            return volume.volume.volume_name()
        except ArchiveyError:
            return ""  # the listing reaches the same damage and raises it

    @override
    def iter_members(self) -> Iterator[MemberRecord[FileData | None]]:
        """Every member of every volume, in partition order, each volume in catalog
        order (parent folder id, then name). A damaged catalog node stops that volume's
        listing; the other volumes are listed, then the first error is raised."""
        failure: ArchiveyError | None = None
        names = self._volume_names()
        for index, (volume, _) in enumerate(self._volumes):
            walk = _VolumeWalk(self._context, volume, index, names[index])
            yield from walk.members()
            if failure is None:
                failure = walk.failure
        if failure is not None:
            raise failure

    @override
    def open_member(
        self, member: ArchiveMember, locator: FileData | None
    ) -> MemberData:
        # archivey opens only a FILE: a hard link reaches the member it names.
        assert locator is not None, member.name
        if locator.refusal is not None:
            error, message = locator.refusal
            raise error(message)
        volume = self._volumes[locator.volume].volume
        cnid, record = locator.cnid, locator.record
        if locator.decmpfs is not None:
            value = hfsplus.attribute_value(volume, cnid, locator.decmpfs)
            header = hfsplus.parse_decmpfs(value)
            read_chunk = hfsplus.decmpfs_reader(
                volume, self._context, cnid, header, hfsplus.resource_fork(record)
            )
            stream = block_stream(header.size, hfsplus.DECMPFS_CHUNK, read_chunk)
            return MemberData(stream, bounded=True)
        fork = hfsplus.data_fork(record)
        read = volume.fork_reader(cnid, hfsplus.DATA_FORK, fork)
        piece = hfsplus.READ_PIECE

        def read_piece(i: int) -> bytes:
            return read(i * piece, min(piece, fork.size - i * piece))

        return MemberData(block_stream(fork.size, piece, read_piece), bounded=True)

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        labels = [self._label(v) for v in self._volumes]
        first = self._volumes[0].volume
        extra = ArchiveInfoExtra(
            {
                "dmg.filesystem": "HFSX" if first.hfsx else "HFS+",
                "dmg.partition_scheme": self._scheme,
                "dmg.run_codecs": sorted(self._image.run_codecs),
                "dmg.volumes": labels,
                "dmg.code_signature": self._image.code_signature,
            }
        )
        if len(labels) == 1:
            extra["dmg.volume_name"] = labels[0]
        return ReaderArchiveInfo(
            format_version="UDIF 4",  # the koly signature holds version 4
            extra=extra,
        )


def _refuse_encrypted(source: ReaderSource) -> None:
    head = source.read_at(0, len(ENCRYPTED_V2))
    size = source.size
    tail = (
        source.read_at(size - len(ENCRYPTED_V1), len(ENCRYPTED_V1))
        if size is not None and size >= len(ENCRYPTED_V1)
        else b""
    )
    if head == ENCRYPTED_V2:
        raise UnsupportedFeatureError(ENCRYPTED_MESSAGE)
    if tail == ENCRYPTED_V1:
        raise UnsupportedFeatureError(
            "The file is an encrypted DMG disk image in the version 1 (cdsaencr) "
            "layout, which archivey does not read."
        )


def _refuse_unreadable(found: list[tuple[partitions.Candidate, str | None]]) -> None:
    """No HFS+ volume: refuse, naming what the image holds instead."""
    kinds = {fs for _, fs in found}
    if partitions.HFS_WRAPPER in kinds:
        raise UnsupportedFeatureError(
            "HFS (standard) volumes, and HFS+ volumes inside an HFS wrapper, are not "
            "supported"
        )
    if partitions.APFS in kinds:
        raise UnsupportedFeatureError("APFS disk images are not supported yet")
    labels = ", ".join(repr(c.label) for c, _ in found) or "none"
    raise UnsupportedFeatureError(
        f"The DMG disk image holds no HFS+ or APFS filesystem. Its partitions: {labels}."
    )


class _VolumeWalk:
    """The listing of one HFS+ volume: two passes over its catalog (``hfsplus``), the
    attributes, and the members made from them."""

    def __init__(
        self, context: ReaderContext, volume: hfsplus.HfsVolume, index: int, top: str
    ) -> None:
        self._context = context
        self._volume = volume
        self._index = index
        self._top = top
        self.failure: ArchiveyError | None = None
        # A hard link's inode: the path of the first member that names it.
        self._linked: dict[int, str] = {}

    def _charge(self, nbytes: int, what: str) -> None:
        self._context.charge_metadata(nbytes, what=what)

    def members(self) -> Iterator[MemberRecord[FileData | None]]:
        volume = self._volume
        catalog, failure = hfsplus.read_catalog(volume, self._charge)
        attrs, bad, attr_failure = hfsplus.read_attributes(volume, self._charge)
        self._attrs = attrs
        self._bad = bad
        self._catalog = catalog
        self._paths: dict[int, str | None] = {hfsplus.ROOT_FOLDER: ""}
        self._hidden: dict[int, bool] = {hfsplus.ROOT_FOLDER: False}
        self._looped: set[int] = set()
        orphans = 0
        try:
            for entry in hfsplus.catalog_entries(volume):
                made = self._member(entry)
                if made is None:
                    continue
                if isinstance(made, _Orphan):
                    orphans += 1
                    continue
                yield made
        except ArchiveyError as exc:
            failure = exc
        if failure is None and self._looped:
            first = min(self._looped)
            failure = CorruptionError(
                f"the HFS+ folder {first}'s parent chain loops or is deeper than "
                f"{hfsplus.MAX_DEPTH}, so {orphans} records of the catalog are not "
                "listed"
            )
        elif failure is None and orphans:
            failure = CorruptionError(
                f"{orphans} records of the HFS+ catalog are in folders the catalog "
                "does not hold"
            )
        self.failure = failure or attr_failure

    def _is_hidden(self, cnid: int) -> bool:
        """Whether folder ``cnid`` is a hidden folder or inside one. Its parent chain
        reaches the root: ``folder_path`` checked it."""
        chain = []
        at = cnid
        while at not in self._hidden:
            if at in self._catalog.hidden:
                self._hidden[at] = True
                break
            chain.append(at)
            at = self._catalog.folders[at][0]
        hidden = self._hidden[at]
        for each in chain:
            self._hidden[each] = hidden
        return hidden

    def _member(
        self, entry: hfsplus.Entry
    ) -> MemberRecord[FileData | None] | None | _Orphan:
        folder = hfsplus.is_folder(entry)
        if folder and entry.cnid == hfsplus.ROOT_FOLDER:
            if not self._top:
                return None
            return self._folder_member(entry, self._top)
        if folder and entry.cnid in self._catalog.hidden:
            return None
        parent = hfsplus.folder_path(
            self._catalog.folders, self._paths, entry.parent, self._looped
        )
        if parent is None:
            return _ORPHAN
        if self._is_hidden(entry.parent):
            return None
        if (
            not folder
            and entry.parent == hfsplus.ROOT_FOLDER
            and self._is_journal(entry)
        ):
            return None
        within = f"{parent}/{entry.name}" if parent else entry.name
        path = f"{self._top}/{within}" if self._top else within
        if folder:
            return self._folder_member(entry, path)
        return self._file_member(entry, path)

    def _is_journal(self, entry: hfsplus.Entry) -> bool:
        blocks = self._volume.journal_blocks
        if blocks is None or entry.name not in hfsplus.JOURNAL_FILES:
            return False
        fork = hfsplus.data_fork(entry.record)
        first = fork.extents[0][0] if fork.extents else None
        want = blocks[0] if entry.name == ".journal" else blocks[1]
        return first == want

    def _base(self, path: str, info: hfsplus.FileInfo) -> ArchiveMember:
        member = ArchiveMember(
            type=MemberType.FILE,
            name=path,
            mode=info.mode & 0o7777 if info.mode else None,
            uid=info.uid,
            gid=info.gid,
        )
        if info.modified is not None:
            self._context.set_unix_time(
                member, "modified", info.modified, source="hfs+"
            )
        if info.created is not None:
            self._context.set_unix_time(member, "created", info.created, source="hfs+")
        return member

    def _folder_member(
        self, entry: hfsplus.Entry, path: str
    ) -> MemberRecord[FileData | None]:
        member = self._base(path, hfsplus.file_info(entry.record))
        member.type = MemberType.DIRECTORY
        self._add_xattrs(member, entry.cnid, compressed=False)
        return MemberRecord(member, None)

    def _file_member(
        self, entry: hfsplus.Entry, path: str
    ) -> MemberRecord[FileData | None]:
        info = hfsplus.file_info(entry.record)
        kind, special = hfsplus.file_kind(info)
        if kind == hfsplus.FILE_LINK:
            return self._link_member(entry, path, info)
        member = self._base(path, info)
        if kind == hfsplus.DIRECTORY_LINK:
            self._add_xattrs(member, entry.cnid, compressed=False)
            member.size = 0
            return MemberRecord(
                member,
                self._refused(
                    entry,
                    UnsupportedFeatureError,
                    f"{quoted(path)} is an HFS+ directory hard link, which archivey does not "
                    "read",
                ),
            )
        if hfsplus.finder_symlink_disagrees(info):
            self._context.report(
                DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT,
                (
                    f"The HFS+ file {quoted(path)} has a mode that says "
                    f"{'symlink' if kind == hfsplus.SYMLINK else 'not a symlink'} and "
                    "Finder information that says otherwise; the mode decides."
                ),
                ArchiveStructureContext(
                    format="dmg", structure="member_type", offset=entry.cnid
                ),
                member=member,
            )
        if kind == hfsplus.SYMLINK:
            member.type = MemberType.SYMLINK
            self._add_xattrs(member, entry.cnid, compressed=False)
            self._read_target(member, entry)
            return MemberRecord(member, None)
        if kind == hfsplus.SPECIAL:
            member.type = MemberType.OTHER
            member.extra["special_file_type"] = special
            self._add_xattrs(member, entry.cnid, compressed=False)
            return MemberRecord(member, None)
        return MemberRecord(member, self._file_data(member, entry))

    def _link_member(
        self, entry: hfsplus.Entry, path: str, link_info: hfsplus.FileInfo
    ) -> MemberRecord[FileData | None]:
        """A file hard link: the first path to its inode is the file, each later one
        a ``HARDLINK`` to that path (links point backward only)."""
        link_id = link_info.special
        inode = self._catalog.inodes.get(link_id)
        if inode is None:
            member = self._base(path, link_info)
            member.size = 0
            self._add_xattrs(member, entry.cnid, compressed=False)
            return MemberRecord(
                member,
                self._refused(
                    entry,
                    CorruptionError,
                    f"the HFS+ hard link {quoted(path)} names inode {link_id}, which the "
                    "volume's private folder does not hold",
                ),
            )
        member = self._base(path, hfsplus.file_info(inode.record))
        first = self._linked.get(link_id)
        if first is not None:
            member.type = MemberType.HARDLINK
            member.link_target = first
            # The attributes are the inode's, which every path to it shares.
            self._add_xattrs(member, inode.cnid, compressed=False)
            return MemberRecord(member, None)
        self._linked[link_id] = path
        self._charge(len(path) + 32, "the HFS+ hard links")
        return MemberRecord(member, self._file_data(member, inode))

    def _refused(
        self, entry: hfsplus.Entry, error: type[ArchiveyError], message: str
    ) -> FileData:
        return FileData(self._index, entry.cnid, entry.record, None, (error, message))

    def _file_data(self, member: ArchiveMember, entry: hfsplus.Entry) -> FileData:
        """Where ``member``'s bytes are: the data fork of ``entry`` (the file, or a
        hard link's inode), or its decmpfs data. Sets the size."""
        info = hfsplus.file_info(entry.record)
        compressed = bool(info.owner_flags & hfsplus.UF_COMPRESSED)
        self._add_xattrs(member, entry.cnid, compressed=compressed)
        if not compressed:
            member.size = hfsplus.data_fork(entry.record).size
            rsrc = hfsplus.resource_fork(entry.record).size
            if rsrc:
                member.extra["dmg.resource_fork_size"] = rsrc
            return FileData(self._index, entry.cnid, entry.record, None)
        attribute = self._attrs.get(entry.cnid, {}).get(hfsplus.DECMPFS)
        problem = None
        size = 0
        if attribute is None:
            problem = (
                "has the compressed flag and no com.apple.decmpfs attribute"
                if entry.cnid not in self._bad
                else "has a com.apple.decmpfs attribute that cannot be read"
            )
        else:
            head = attribute.value
            if attribute.fork is not None:
                try:
                    head = hfsplus.attribute_value(self._volume, entry.cnid, attribute)
                except ArchiveyError as exc:
                    problem = (
                        f"has a com.apple.decmpfs attribute that cannot be read ({exc})"
                    )
            if head is not None and problem is None:
                try:
                    size = hfsplus.parse_decmpfs(head).size
                except ArchiveyError as exc:
                    problem = f"has a damaged com.apple.decmpfs attribute ({exc})"
        if problem is not None:
            member.size = 0
            return self._refused(
                entry, CorruptionError, f"the HFS+ file {quoted(member.name)} {problem}"
            )
        member.size = size
        return FileData(self._index, entry.cnid, entry.record, attribute)

    def _read_target(self, member: ArchiveMember, entry: hfsplus.Entry) -> None:
        """A symlink's target: its data fork, at most ``SYMLINK_MAX`` bytes."""
        fork = hfsplus.data_fork(entry.record)
        if fork.size > hfsplus.SYMLINK_MAX:
            self._context.link_target_unavailable(
                member,
                reason="too_long",
                message=(
                    f"The HFS+ symlink {quoted(member.name)} stores a {fork.size}-byte target, "
                    f"more than the {hfsplus.SYMLINK_MAX} bytes macOS allows."
                ),
                target_in_archive=True,
            )
            return
        try:
            read = self._volume.fork_reader(entry.cnid, hfsplus.DATA_FORK, fork)
            raw = read(0, fork.size)
        except ArchiveyError as exc:
            self._context.link_target_unavailable(
                member,
                reason="damaged",
                message=(
                    f"The target of the HFS+ symlink {quoted(member.name)} cannot be "
                    f"read: {exc}"
                ),
                target_in_archive=True,
            )
            return
        member.link_target = self._context.decode_name(raw)

    def _add_xattrs(
        self, member: ArchiveMember, cnid: int, *, compressed: bool
    ) -> None:
        """D2: the extended attributes' names and small values, and the resource
        fork's size, in ``extra``. A compressed file's decmpfs attribute and resource
        fork hold its data, so they are not listed."""
        if cnid in self._bad:
            self._context.report(
                DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                (
                    f"An extended attribute record of the HFS+ file {quoted(member.name)} "
                    "cannot be read; the member is listed without it."
                ),
                MemberHeaderRecordContext(record="xattr", reason="damaged record"),
                member=member,
            )
        found = self._attrs.get(cnid)
        if found:
            xattrs = {
                name: (attr.value if attr.fork is None else None)
                for name, attr in found.items()
                if not (compressed and name == hfsplus.DECMPFS)
            }
            for name, value in list(xattrs.items()):
                if value is not None and len(value) > hfsplus.XATTR_VALUE_MAX:
                    xattrs[name] = None
            if xattrs:
                member.extra["dmg.xattrs"] = xattrs


class _Orphan:
    """A catalog record whose folder the catalog does not hold."""


_ORPHAN = _Orphan()


class DmgHandler(IndexedFormatHandler):
    """UDIF disk images (``.dmg``) holding HFS+ or HFSX volumes."""

    format = ArchiveFormat.DMG
    # No ``.dmg`` extension: many files named so are raw disks or renamed zips. The
    # ``koly`` block is the claim, not the name.
    extensions = ()
    non_seekable_reason = (
        "its run tables are at the end of the image and the filesystem metadata can "
        "be anywhere in it"
    )
    # The ``koly`` and encryption signatures go to ``register_builtin_format``: the
    # trailers are past what a handler's ``magic`` can say.
    magic = ()
    uses_encoding = False

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> DmgReader:
        return DmgReader(source, context)


DmgReadBackend = register_builtin_format(
    DmgHandler,
    MAGIC=(*MAGIC, MagicSignature(0, ENCRYPTED_V2, ArchiveFormat.DMG)),
    TRAILER=(
        *TRAILER,
        TrailerSignature(len(ENCRYPTED_V1), ENCRYPTED_V1, ArchiveFormat.DMG),
    ),
)
