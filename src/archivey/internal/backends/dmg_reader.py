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

import struct
import zlib
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any, NamedTuple

from archivey.diagnostics import (
    ArchiveStructureContext,
    DiagnosticCode,
    MemberHeaderRecordContext,
    UnlistedDataContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    ResourceUnavailableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    IndexedFormatHandler,
    IndexedReader,
    MemberData,
    MemberRecord,
    NeedsPassword,
    PasswordConfirmVerdict,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    TimeField,
    block_stream,
)
from archivey.internal.backends import (
    apfs,
    disk_partitions as partitions,
    dmg_encrypted,
    hfsplus,
)
from archivey.internal.backends.udif import (
    MAGIC,
    TRAILER,
    UdifImage,
    UdifSource,
    crc32_value,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.internal.streams.callers_source import from_source_callback
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ArchiveMember,
    MagicSignature,
    MemberType,
    TrailerSignature,
)

if TYPE_CHECKING:
    from archivey.formats import _SpanningCheck

# An encrypted image (``hdiutil create -encryption``) starts with the ``encrcdsa`` (v2)
# header (``dmg_encrypted``); a pre-10.5 one ends with ``cdsaencr`` (v1), which is
# refused by name (design §6B.1).
ENCRYPTED_V2 = dmg_encrypted.SIGNATURE
ENCRYPTED_V1 = b"cdsaencr"

# The names macOS gives a volume it mounts with no usable name (``/Volumes/Untitled``).
_UNTITLED = "Untitled"


class FileData(NamedTuple):
    """Where a file's bytes are: its record in a volume, or why it cannot be read."""

    volume: int
    cnid: int  # the file whose forks hold the data (a hard link's inode)
    record: bytes  # its catalog file record
    decmpfs: hfsplus.Attribute | None  # its com.apple.decmpfs, when compressed
    refusal: tuple[type[ArchiveyError], str] | None = None


class ApfsData(NamedTuple):
    """Where an APFS file's bytes are: its inode in a volume, or why it cannot be
    read."""

    volume: int
    oid: int
    compressed: bool
    refusal: tuple[type[ArchiveyError], str] | None = None


Locator = FileData | ApfsData | None


def volume_names(labels: list[str]) -> list[str]:
    """The top-level directory names for several volumes (D1): the label, ``Untitled``
    when it is empty, ``.`` or ``..``, and a name already taken (exactly, or but for
    case) gets `` 1``, `` 2``, ... as macOS names its mount points.

    Linear in the number of labels: ``taken`` holds the names casefolded, and
    ``tried`` the last suffix used for each casefolded base. Every suffix up to it is
    taken (names are only added), so the next probe starts after it."""
    taken: set[str] = set()
    tried: dict[str, int] = {}
    names = []
    for label in labels:
        base = label.replace("/", ":")
        if base in ("", ".", ".."):
            base = _UNTITLED
        name = base
        if name.casefold() in taken:
            key = base.casefold()
            n = tried.get(key, 0)
            while True:
                n += 1
                name = f"{base} {n}"
                if name.casefold() not in taken:
                    break
            tried[key] = n
        taken.add(name.casefold())
        names.append(name)
    return names


class _NotRun(NamedTuple):
    """A table the checksum pass could not check, and why (a limit, a refused
    codec): not damage, but nothing proves the files it covers."""

    cause: ArchiveyError


class _Volume(NamedTuple):
    volume: hfsplus.HfsVolume
    candidate: partitions.Candidate


class _Container(NamedTuple):
    container: apfs.ApfsContainer
    candidate: partitions.Candidate


class _Unit(NamedTuple):
    """One volume the listing walks: an HFS+ volume, or one volume of an APFS
    container."""

    hfs: hfsplus.HfsVolume | None
    apfs: apfs.ApfsVolume | None
    candidate: partitions.Candidate
    part: int  # its index in ``DmgReader._parts``


_READABLE = (partitions.HFS, partitions.HFSX, partitions.APFS)


class DmgReader(IndexedReader[FileData | ApfsData | None]):
    """One open UDIF image."""

    def __init__(
        self,
        source: ReaderSource,
        context: ReaderContext,
        *,
        encryption: str | None = None,
    ) -> None:
        """``source`` is the UDIF image: the file, or for an encrypted image its
        decrypted view, with ``encryption`` naming the cipher (``"AES-128"``)."""
        self._context = context
        self._encryption = encryption
        self._encrypted = encryption is not None
        self._image = image = UdifImage(source, context)
        layout = partitions.layout(image, image.report_structure)
        self._scheme = layout.scheme
        candidates = layout.candidates or [partitions.whole_disk(image)]
        found: list[tuple[partitions.Candidate, str | None]] = []
        for candidate in candidates:
            filesystem = partitions.probe(image, candidate)
            found.append((candidate, filesystem))
            self._check_name(candidate, filesystem)
        readable = [(c, fs) for c, fs in found if fs in _READABLE]
        if not readable:
            _refuse_unreadable(found)
        if layout.source == "map":
            for candidate, filesystem in readable:
                self._check_start(
                    candidate,
                    partitions.APFS
                    if filesystem == partitions.APFS
                    else partitions.HFS,
                )
        for candidate, filesystem in found:
            if filesystem in _READABLE:
                continue
            if filesystem is None and candidate.no_content:
                continue
            what = (
                "an HFS volume, which archivey does not read"
                if filesystem == partitions.HFS_WRAPPER
                else "no filesystem archivey reads"
            )
            self._report_unlisted(candidate, candidate.label, what)
        self._parts: list[_Volume | _Container] = []
        # A damaged APFS container beside other volumes does not stop the open: the
        # other volumes are listed, then its error is raised (DR-2).
        self._open_failure: ArchiveyError | None = None
        first_error: ArchiveyError | None = None
        for candidate, filesystem in readable:
            view = UdifSource(image, candidate.start, candidate.length)
            if filesystem != partitions.APFS:
                self._parts.append(_Volume(hfsplus.HfsVolume(view, context), candidate))
                continue
            try:
                container = apfs.ApfsContainer(
                    view, context, self._apfs_report(candidate)
                )
            except (CorruptionError, TruncatedError, UnsupportedFeatureError) as exc:
                if len(readable) == 1:
                    raise
                first_error = first_error or exc
                if isinstance(exc, UnsupportedFeatureError):
                    self._report_unlisted(
                        candidate,
                        candidate.label,
                        f"an APFS container archivey does not read ({exc})",
                    )
                else:
                    self._open_failure = self._open_failure or exc
                continue
            self._parts.append(_Container(container, candidate))
        if not self._parts:
            assert first_error is not None
            raise first_error
        image.end_open()
        self._units: list[_Unit] | None = None
        self._load_failure: ArchiveyError | None = None
        self._fatal: ArchiveyError | None = None
        self._trees: dict[int, apfs.FsTree] = {}
        self._kept = 0
        self._names: list[str] | None = None
        # The volumes whose whole partition the run tables' CRC-32s cover (design
        # §7.2): their files are CHECKSUM, which ``verify_all()``'s pass proves.
        self._checked = [
            image.crc_covers(p.candidate.start, p.candidate.length) for p in self._parts
        ]
        # Each checked volume's check, made again at each listing.
        self._checks: dict[int, _SpanningCheck] = {}
        # What the pass found, kept for every later ``verify_all()``: for each table
        # (by index in ``image.tables``) the error, or ``None`` when it matched; and
        # the image-wide one (data fork, master checksum).
        self._table_results: dict[int, CorruptionError | _NotRun | None] | None = None
        self._image_result: CorruptionError | None = None
        if any(self._checked) and context._spanning_pass is not None:
            context._spanning_pass(self._check_partitions)

    # ── Open ─────────────────────────────────────────────────────────────────────────

    def _report_unlisted(
        self, candidate: partitions.Candidate, name: str, what: str
    ) -> None:
        self._context.report(
            DiagnosticCode.ARCHIVE_UNLISTED_DATA,
            (
                f"The DMG partition {quoted(candidate.label)} ({candidate.length} bytes "
                f"at disk offset {candidate.start}) holds {what}. It is not listed."
            ),
            UnlistedDataContext(
                format="dmg",
                member_name=name,
                offset=candidate.start,
                compressed_size=candidate.length,
            ),
        )

    def _apfs_report(
        self, candidate: partitions.Candidate
    ) -> Callable[[str, str, int], None]:
        def report(structure: str, message: str, offset: int) -> None:
            self._image.report_structure(structure, message, candidate.start + offset)

        return report

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

    def _check_start(self, candidate: partitions.Candidate, hint: str) -> None:
        """Report a partition the map places elsewhere than the run table named for
        the same filesystem that overlaps it. The map's range is read."""
        end = candidate.start + candidate.length
        for table in self._image.tables:
            start = table.first_sector * partitions.SECTOR
            table_end = start + table.sector_count * partitions.SECTOR
            if (
                start == candidate.start
                or partitions.hint_from_name(table.name) != hint
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

    # ── The volumes ──────────────────────────────────────────────────────────────────

    def _keep(self, nbytes: int, what: str) -> None:
        """Count what the APFS reading keeps for the life of the archive (object maps
        and filesystem trees, which member reads need) against
        ``max_metadata_bytes``, with what the listing holds and, for an archive read
        inside another, what the outer levels hold: ``charge_metadata`` lasts only
        for a listing. Without the adapter's hook, the kept bytes are bounded
        alone."""
        keep = self._context._keep_metadata
        if keep is not None:
            keep(nbytes, what)
            return
        self._kept += nbytes
        budget = self._context.config.listing_limits.max_metadata_bytes
        if budget is not None and self._kept > budget:
            raise ResourceLimitError(
                f"Listing limit reached: max_metadata_bytes={budget} ({what} and what "
                f"was read before it hold {self._kept} bytes)"
            )

    def _load(self) -> list[_Unit]:
        """The volumes to list, in partition order: each HFS+ volume, and each volume
        of each APFS container, whose checkpoint and volume superblocks are read here,
        at the first need. A container or volume that cannot be read is reported or
        remembered as the listing's error."""
        if self._units is not None:
            return self._units
        if self._fatal is not None:
            raise self._fatal
        units: list[_Unit] = []
        refused: list[str] = []
        failure: ArchiveyError | None = self._open_failure
        image = self._image
        for at, part in enumerate(self._parts):
            if isinstance(part, _Volume):
                units.append(_Unit(part.volume, None, part.candidate, at))
                continue
            try:
                volumes, refusals, lost = part.container.load(
                    lambda: image.budget(
                        apfs.SCAN_BUDGET, "scanning the APFS checkpoint area"
                    ),
                    self._keep,
                )
            except ArchiveyError as exc:
                failure = failure or exc
                continue
            units.extend(_Unit(None, v, part.candidate, at) for v in volumes)
            for each in refusals:
                refused.append(each.reason)
                self._report_unlisted(
                    part.candidate,
                    each.name,
                    f"{each.reason} named {quoted(each.name)}",
                )
            if lost and failure is None:
                failure = CorruptionError(
                    f"{len(lost)} volumes of the APFS container cannot be read: {lost[0]}"
                )
        if not units:
            if refused and failure is None:
                more = f" and {len(refused) - 1} more" if len(refused) > 1 else ""
                failure = UnsupportedFeatureError(
                    f"The DMG disk image holds no volume archivey reads: it holds "
                    f"{refused[0]}{more}"
                )
            assert failure is not None
            # Kept, so a later call raises it again without a second scan and
            # without reporting each refused volume again.
            self._fatal = failure
            raise failure
        self._units = units
        self._load_failure = failure
        return units

    def _tree(self, index: int) -> apfs.FsTree:
        tree = self._trees.get(index)
        if tree is None:
            volume = self._load()[index].apfs
            assert volume is not None
            tree = self._trees[index] = volume.walk()
        return tree

    # ── Listing ──────────────────────────────────────────────────────────────────────

    def _volume_names(self) -> list[str]:
        """Each volume's top-level directory, or ``""`` for the one volume of an image
        that holds one. Read at the first listing (the names are in the catalogs)."""
        if self._names is None:
            units = self._load()
            if len(units) == 1:
                self._names = [""]
            else:
                self._names = volume_names([self._label(u) for u in units])
        return self._names

    @staticmethod
    def _label(unit: _Unit) -> str:
        if unit.apfs is not None:
            return unit.apfs.name
        assert unit.hfs is not None
        try:
            return unit.hfs.volume_name()
        except ArchiveyError:
            return ""  # the listing reaches the same damage and raises it

    @override
    def iter_members(self) -> Iterator[MemberRecord[Locator]]:
        """Every member of every volume, in partition order, each HFS+ volume in
        catalog order (parent folder id, then name), each APFS volume a directory at a
        time from the root. Damage in one volume stops or thins that volume's listing;
        the other volumes are listed, then the first error is raised."""
        units = self._load()
        names = self._volume_names()
        failure = self._load_failure
        spanning = self._context._spanning_check
        check = None
        for index, unit in enumerate(units):
            walk: _VolumeWalk | _ApfsWalk
            if unit.hfs is not None:
                walk = _VolumeWalk(self._context, unit.hfs, index, names[index])
            else:
                assert unit.apfs is not None
                walk = _ApfsWalk(
                    self._context, unit.apfs, self._tree(index), index, names[index]
                )
            # One check per partition, made at its first volume: the volumes of an
            # APFS container share it.
            if index == 0 or units[index - 1].part != unit.part:
                check = None
                if self._checked[unit.part] and spanning is not None:
                    check = self._checks[unit.part] = spanning(
                        ("dmg partition", unit.part)
                    )
            for record in walk.members():
                # A file whose read is refused proves nothing, whatever the CRC says.
                if check is not None and (
                    record.locator is not None and record.locator.refusal is None
                ):
                    check.cover(record.member)
                if self._encrypted:
                    record.member.is_encrypted = True
                yield record
            if failure is None:
                failure = walk.failure
        if failure is not None:
            raise failure

    @override
    def open_member(
        self, member: ArchiveMember, locator: FileData | ApfsData | None
    ) -> MemberData:
        # archivey opens only a FILE: a hard link reaches the member it names.
        assert locator is not None, member.name
        if locator.refusal is not None:
            error, message = locator.refusal
            raise error(message)
        if isinstance(locator, ApfsData):
            return self._open_apfs(locator)
        volume = self._load()[locator.volume].hfs
        assert volume is not None
        cnid, record = locator.cnid, locator.record
        if locator.decmpfs is not None:
            value = hfsplus.attribute_value(volume, cnid, locator.decmpfs)
            header = hfsplus.parse_decmpfs(value)
            rsrc = hfsplus.resource_fork(record)
            read_chunk = hfsplus.decmpfs_reader(
                self._context,
                cnid,
                header,
                rsrc.size,
                lambda: volume.fork_reader(cnid, hfsplus.RESOURCE_FORK, rsrc),
            )
            stream = block_stream(header.size, hfsplus.DECMPFS_CHUNK, read_chunk)
            return MemberData(stream, bounded=True)
        fork = hfsplus.data_fork(record)
        read = volume.fork_reader(cnid, hfsplus.DATA_FORK, fork)
        piece = hfsplus.READ_PIECE

        def read_piece(i: int) -> bytes:
            return read(i * piece, min(piece, fork.size - i * piece))

        return MemberData(block_stream(fork.size, piece, read_piece), bounded=True)

    def _open_apfs(self, locator: ApfsData) -> MemberData:
        volume = self._load()[locator.volume].apfs
        assert volume is not None
        tree = self._tree(locator.volume)
        inode = tree.inodes[locator.oid]
        what = f"APFS file {locator.oid}"
        if not locator.compressed:
            read, _ = apfs.stream_reader(volume, tree, inode.stream, inode.size, what)
            stream = block_stream(
                inode.size, apfs.READ_PIECE, apfs.read_pieces(inode.size, read)
            )
            return MemberData(stream, bounded=True)
        xattrs = tree.xattrs.get(locator.oid, {})
        header = hfsplus.parse_decmpfs(
            apfs.xattr_value(
                volume,
                tree,
                xattrs[apfs.DECMPFS_XATTR],
                hfsplus.DECMPFS_KEEP,
                f"the com.apple.decmpfs attribute of {what}",
            )
        )
        rsrc = xattrs.get(apfs.RESOURCE_FORK_XATTR)

        def open_fork() -> Callable[[int, int], bytes]:
            assert rsrc is not None
            if rsrc.value is not None:
                return _bytes_reader(rsrc.value, what)
            read, _ = apfs.stream_reader(
                volume, tree, rsrc.stream, rsrc.size, f"the resource fork of {what}"
            )
            return read

        read_chunk = hfsplus.decmpfs_reader(
            self._context,
            locator.oid,
            header,
            rsrc.size if rsrc is not None else 0,
            open_fork,
        )
        stream = block_stream(header.size, hfsplus.DECMPFS_CHUNK, read_chunk)
        return MemberData(stream, bounded=True)

    # ── The checksum pass (design §7.2) ──────────────────────────────────────────────

    def _check_partitions(self) -> None:
        """``verify_all()``'s pass: check each CRC-32 table that overlaps a checked
        volume's partition, whole, once; then pass or fail each volume's check. One
        table that overlaps two partitions fails both.

        The runs the pass decodes or reads (compressed and raw: several runs may
        point at the same stored bytes) are held to the archive-wide ratio
        (``DecoderLimits.max_ratio`` against the file's size), on their own total:
        member reads have their own. Past it, the pass stops, and the checks it did
        not finish did not run (``SpanningCheck.did_not_run``), as for a codec the
        policy refuses: no damage was found, but nothing proves those files either.
        """
        image = self._image
        over = {
            index: image.tables_over(v.candidate.start, v.candidate.length)
            for index, v in enumerate(self._parts)
            if self._checked[index]
        }
        results = self._table_results
        if results is None:
            results = dict[int, CorruptionError | _NotRun | None]()
            draw = self._pass_draw()
            stopped: ArchiveyError | None = None
            for table_indexes in over.values():
                for t in table_indexes:
                    if t in results:
                        continue
                    if stopped is not None:
                        results[t] = _NotRun(stopped)
                        continue
                    results[t] = result = self._check_table(t, draw)
                    if isinstance(result, _NotRun) and isinstance(
                        result.cause, ResourceLimitError
                    ):
                        stopped = result.cause
            self._image_result = self._check_image()
            self._table_results = results
        for index, table_indexes in over.items():
            check = self._checks.get(index)
            if check is None:
                continue  # not listed yet: nothing covered
            found = [results[t] for t in table_indexes if results[t] is not None]
            if self._image_result is not None:
                found.append(self._image_result)
            failure = next((r for r in found if isinstance(r, CorruptionError)), None)
            if failure is not None:
                error = check.failed(failure.raw_message)
                error.__cause__ = failure.__cause__
            elif found:
                not_run = found[0]
                assert isinstance(not_run, _NotRun)
                check.did_not_run(not_run.cause)
            else:
                check.passed()

    def _pass_draw(self) -> Callable[[int], None]:
        # Imported here, as the readers that hold member reads to the ratio do.
        from archivey.internal.bomb_tracker import refuse_past_archive_ratio

        config = self._context.config
        size = self._image.file_size
        total = 0

        def draw(n: int) -> None:
            nonlocal total
            total += n
            refuse_past_archive_ratio(
                total,
                limits=config.decoder_limits,
                static_size=size,
                consumed=None,
                counted="runs the DMG checksum pass read",
            )

        return draw

    def _check_table(
        self, t: int, draw: Callable[[int], None]
    ) -> CorruptionError | _NotRun | None:
        """Table ``t``'s CRC-32: ``None`` when it matches, the damage when it does not
        or a run does not decode, or why it could not be checked."""
        table = self._image.tables[t]
        try:
            crc = self._image.table_crc(table, draw)
        except CorruptionError as exc:
            if from_source_callback(exc):
                raise
            error = CorruptionError(
                f"the DMG run table {quoted(table.name)} could not be checked: "
                f"{exc.raw_message}"
            )
            error.__cause__ = exc
            return error
        except (UnsupportedFeatureError, ResourceLimitError) as exc:
            if isinstance(exc, ResourceUnavailableError) or from_source_callback(exc):
                raise
            return _NotRun(exc)
        if crc != table.checksum:
            return CorruptionError(
                f"the DMG run table {quoted(table.name)} (disk sectors "
                f"{table.first_sector} to {table.first_sector + table.sector_count}) "
                f"decodes to CRC-32 0x{crc:08x}, not the 0x{table.checksum:08x} it "
                "stores"
            )
        return None

    def _check_image(self) -> CorruptionError | None:
        """The ``koly`` block's checksums, when they are CRC-32s: the data fork's (its
        stored bytes, read once more) and the master checksum (a CRC-32 of the tables'
        CRC-32s in property-list order, checked only when every table has one)."""
        image = self._image
        koly = image.koly
        master = crc32_value(koly.master_checksum)
        checksums = image.plist_checksums
        if master is not None and all(c is not None for c in checksums):
            got = zlib.crc32(b"".join(struct.pack(">I", c) for c in checksums))
            if got != master:
                return CorruptionError(
                    f"the UDIF master checksum is 0x{master:08x}, and the run tables' "
                    f"CRC-32s give 0x{got:08x}"
                )
        stored = crc32_value(koly.data_checksum)
        if stored is not None:
            got = image.data_fork_crc()
            if got != stored:
                return CorruptionError(
                    f"the UDIF data fork ({koly.data_fork_length} bytes at offset "
                    f"{koly.data_fork_offset}) has CRC-32 0x{got:08x}, not the "
                    f"0x{stored:08x} the koly block stores"
                )
        return None

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        try:
            units = self._load()
        except ArchiveyError:
            units = []
        labels = [self._label(u) for u in units]
        apfs_names = [u.apfs.name for u in units if u.apfs is not None]
        if units:
            first = units[0]
            filesystem = (
                "APFS"
                if first.apfs is not None
                else "HFSX"
                if first.hfs is not None and first.hfs.hfsx
                else "HFS+"
            )
        else:
            filesystem = "APFS" if isinstance(self._parts[0], _Container) else "HFS+"
        extra = ArchiveInfoExtra(
            {
                "dmg.filesystem": filesystem,
                "dmg.partition_scheme": self._scheme,
                "dmg.run_codecs": sorted(self._image.run_codecs),
                "dmg.volumes": labels,
                "dmg.code_signature": self._image.code_signature,
            }
        )
        if apfs_names:
            extra["dmg.apfs_volumes"] = apfs_names
        if self._encryption is not None:
            extra["dmg.encryption"] = self._encryption
        if len(labels) == 1:
            extra["dmg.volume_name"] = labels[0]
        return ReaderArchiveInfo(
            format_version="UDIF 4",  # the koly signature holds version 4
            is_encrypted=self._encrypted,
            extra=extra,
        )


def _bytes_reader(data: bytes, what: str) -> Callable[[int, int], bytes]:
    def read(offset: int, n: int) -> bytes:
        if offset + n > len(data):
            raise TruncatedError(
                f"the resource fork of {what} ends at byte {len(data)}, before byte "
                f"{offset + n}"
            )
        return data[offset : offset + n]

    return read


def _refuse_version_1(source: ReaderSource) -> None:
    size = source.size
    if size is None or size < len(ENCRYPTED_V1):
        return
    if source.read_at(size - len(ENCRYPTED_V1), len(ENCRYPTED_V1)) == ENCRYPTED_V1:
        raise UnsupportedFeatureError(
            "The file is an encrypted DMG disk image in the version 1 (cdsaencr) "
            "layout, which archivey does not read."
        )


def _open_encrypted(
    source: ReaderSource, context: ReaderContext
) -> NeedsPassword[dmg_encrypted.ImageKeys, IndexedReader[Any]]:
    """The password request for an ``encrcdsa`` image; its ``then`` opens the
    decrypted image (design §6B)."""
    header = dmg_encrypted.read_header(source)
    unlocker = dmg_encrypted.Unlocker(source, header, context)

    def then(
        keys: dmg_encrypted.ImageKeys, verdict: PasswordConfirmVerdict
    ) -> DmgReader:
        if not keys.has_koly:
            raise UnsupportedFeatureError(
                "The encrypted DMG disk image has no koly block at the end of its "
                "decrypted data: it holds a read-write (raw disk) image, which "
                "archivey does not read, or its last block is damaged."
            )
        image = dmg_encrypted.EncryptedDmgSource(source, header, keys, unlocker.backend)
        return DmgReader(image, context, encryption=f"AES-{header.key_size * 8}")

    return NeedsPassword("the disk image", unlocker.check, then=then)


def _refuse_unreadable(found: list[tuple[partitions.Candidate, str | None]]) -> None:
    """No HFS+ volume: refuse, naming what the image holds instead."""
    kinds = {fs for _, fs in found}
    if partitions.HFS_WRAPPER in kinds:
        raise UnsupportedFeatureError(
            "HFS (standard) volumes, and HFS+ volumes inside an HFS wrapper, are not "
            "supported"
        )
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

    def members(self) -> Iterator[MemberRecord[Locator]]:
        volume = self._volume
        catalog, failure = hfsplus.read_catalog(volume, self._charge)
        if catalog.bad_threads:
            first = catalog.bad_threads[0]
            count = len(catalog.bad_threads)
            folders = (
                "1 HFS+ folder has" if count == 1 else f"{count} HFS+ folders have"
            )
            self._context.report(
                DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT,
                f"{folders} a thread record that is missing, unreadable, or names "
                f"another parent or name (the first is folder {first}); the folder "
                "records decide the paths.",
                ArchiveStructureContext(
                    format="dmg", structure="folder_thread", offset=first
                ),
            )
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
                f"the HFS+ folder {first}'s parent chain loops, so {orphans} "
                "records of the catalog are not listed"
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

    def _member(self, entry: hfsplus.Entry) -> MemberRecord[Locator] | None | _Orphan:
        folder = hfsplus.is_folder(entry)
        if folder and entry.cnid == hfsplus.ROOT_FOLDER:
            if not self._top:
                return None
            return self._folder_member(entry, self._top)
        if folder and entry.cnid in self._catalog.hidden:
            return None
        parent = hfsplus.folder_path(
            self._catalog.folders, self._paths, entry.parent, self._looped, self._charge
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

    def _folder_member(self, entry: hfsplus.Entry, path: str) -> MemberRecord[Locator]:
        member = self._base(path, hfsplus.file_info(entry.record))
        member.type = MemberType.DIRECTORY
        self._add_xattrs(member, entry.cnid, compressed=False)
        return MemberRecord(member, None)

    def _file_member(self, entry: hfsplus.Entry, path: str) -> MemberRecord[Locator]:
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
    ) -> MemberRecord[Locator]:
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
            # The attributes are the inode's, which every path to it shares, and
            # so is what is hidden.
            flags = hfsplus.file_info(inode.record).owner_flags
            compressed = bool(flags & hfsplus.UF_COMPRESSED)
            self._add_xattrs(member, inode.cnid, compressed=compressed)
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


_S_IFMT = 0o170000
_S_IFDIR = 0o040000
_S_IFREG = 0o100000
_S_IFLNK = 0o120000


class _ApfsWalk:
    """The listing of one APFS volume: its filesystem tree, walked a directory at a
    time from the root, each directory's entries in name order (design §6A.6)."""

    def __init__(
        self,
        context: ReaderContext,
        volume: apfs.ApfsVolume,
        tree: apfs.FsTree,
        index: int,
        top: str,
    ) -> None:
        self._context = context
        self._volume = volume
        self._tree = tree
        self._index = index
        self._top = top
        self.failure: ArchiveyError | None = None

    def members(self) -> Iterator[MemberRecord[Locator]]:
        tree = self._tree
        name = self._volume.name
        lost = 0
        problems: list[str] = []
        root = tree.inodes.get(apfs.ROOT_DIRECTORY)
        if self._top:
            member = (
                self._base(self._top, root)
                if root is not None
                else ArchiveMember(type=MemberType.FILE, name=self._top)
            )
            member.type = MemberType.DIRECTORY
            yield MemberRecord(member, None)
        if root is None and not tree.damage:
            problems.append("its root directory has no inode")
        # The first path of each file reached, for the hard links after it.
        first: dict[int, str] = {}
        directories = {apfs.ROOT_DIRECTORY}
        stack: list[tuple[int, str]] = [(apfs.ROOT_DIRECTORY, "")]
        while stack:
            parent, prefix = stack.pop()
            below: list[tuple[int, str]] = []
            for child in sorted(tree.children.get(parent, ()), key=lambda c: c.name):
                entry = self._context.decode_name(child.name)
                if "/" in entry or entry in ("", ".", ".."):
                    problems.append(f"a directory record names {quoted(entry)}")
                    continue
                within = prefix + entry
                path = f"{self._top}/{within}" if self._top else within
                inode = tree.inodes.get(child.file_id)
                if inode is None:
                    if tree.damaged(child.file_id, apfs.INODE) is not None:
                        lost += 1
                    else:
                        problems.append(
                            f"the entry {quoted(path)} names inode {child.file_id}, "
                            "which the volume does not hold"
                        )
                    continue
                kind = inode.mode & _S_IFMT
                if kind >> 12 != child.kind:
                    self._report_type(path, child.file_id, inode.mode, child.kind)
                    if not kind:
                        kind = child.kind << 12
                if kind == _S_IFDIR:
                    if child.file_id in directories:
                        problems.append(
                            f"the directory {quoted(path)} is reached a second time"
                        )
                        continue
                    directories.add(child.file_id)
                    member = self._base(path, inode)
                    member.type = MemberType.DIRECTORY
                    self._add_xattrs(member, child.file_id, compressed=False)
                    yield MemberRecord(member, None)
                    below.append((child.file_id, within + "/"))
                    continue
                made = self._entry(path, child.file_id, inode, kind, first)
                if made is None:
                    lost += 1
                    continue
                yield made
            stack.extend(reversed(below))
        self._check_link_counts(first)
        orphans = sum(
            len(entries)
            for parent, entries in tree.children.items()
            if parent not in directories and parent not in apfs.UNREACHED_DIRECTORIES
        )
        if orphans:
            problems.append(
                f"{orphans} directory records are in directories the volume does not "
                "reach from its root"
            )
        if tree.damage:
            first_bad = tree.damage[0]
            unlisted = f"; {lost} members are not listed" if lost else ""
            also = f"; also, {problems[0]}" if problems else ""
            self.failure = CorruptionError(
                f"{len(tree.damage)} nodes of the filesystem tree of the APFS volume "
                f"{quoted(name)} cannot be used (block {first_bad.address}: "
                f"{first_bad.reason}){unlisted}{also}"
            )
        elif problems:
            self.failure = CorruptionError(
                f"the APFS volume {quoted(name)} is damaged: {problems[0]}"
                + (f" ({len(problems) - 1} more problems)" if len(problems) > 1 else "")
            )

    def _check_link_counts(self, first: dict[int, str]) -> None:
        """Report a listed file whose sibling-link records (one per hard-link name)
        disagree with its inode's link count (design §6A.5): reported, not refused,
        since the directory records decide what is listed. A file with one name has
        no sibling links; a count in a damaged range is not checked."""
        tree = self._tree
        for oid, path in first.items():
            inode = tree.inodes[oid]
            names = tree.siblings.get(oid, 0)
            if (names or inode.nlink > 1) and names != inode.nlink:
                if tree.damaged(oid, apfs.SIBLING_LINK) is not None:
                    continue
                self._context.report(
                    DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT,
                    (
                        f"The APFS file {quoted(path)} has {names} hard-link records "
                        f"and its inode says {inode.nlink} links; the directory "
                        "records decide what is listed."
                    ),
                    ArchiveStructureContext(
                        format="dmg", structure="link_count", offset=oid
                    ),
                )

    def _report_type(self, path: str, oid: int, mode: int, kind: int) -> None:
        self._context.report(
            DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT,
            (
                f"The APFS directory entry {quoted(path)} says type {kind}, and its "
                f"inode's mode 0o{mode:o} says otherwise; the mode decides."
            ),
            ArchiveStructureContext(format="dmg", structure="member_type", offset=oid),
        )

    def _base(self, path: str, inode: apfs.Inode) -> ArchiveMember:
        member = ArchiveMember(
            type=MemberType.FILE,
            name=path,
            mode=inode.mode & 0o7777,
            uid=inode.uid,
            gid=inode.gid,
        )
        times: tuple[tuple[TimeField, int], ...] = (
            ("modified", inode.modified),
            ("created", inode.created),
        )
        for field, value in times:
            if value:
                self._context.set_unix_time(
                    member,
                    field,
                    value // 1_000_000_000,
                    nanoseconds=value % 1_000_000_000,
                    source="apfs",
                )
        return member

    def _entry(
        self,
        path: str,
        oid: int,
        inode: apfs.Inode,
        kind: int,
        first: dict[int, str],
    ) -> MemberRecord[Locator] | None:
        """The member for a non-directory, or ``None`` when a record that decides
        what it is may be in a damaged node."""
        tree = self._tree
        xattrs = tree.xattrs.get(oid, {})
        member = self._base(path, inode)
        earlier = first.get(oid)
        compressed = bool(inode.bsd_flags & apfs.UF_COMPRESSED)
        if earlier is not None:
            member.type = MemberType.HARDLINK
            member.link_target = earlier
            # The same inode as its first name, so the same attributes are hidden.
            self._add_xattrs(member, oid, compressed=compressed)
            return MemberRecord(member, None)
        if kind == _S_IFLNK:
            target = xattrs.get(apfs.SYMLINK_XATTR)
            if target is None and tree.damaged(oid, apfs.XATTR) is not None:
                return None
            first[oid] = path
            member.type = MemberType.SYMLINK
            self._add_xattrs(member, oid, compressed=False)
            self._read_target(member, target)
            return MemberRecord(member, None)
        if kind != _S_IFREG:
            first[oid] = path
            member.type = MemberType.OTHER
            member.extra["special_file_type"] = hfsplus.SPECIAL_FILES.get(
                kind, f"0o{kind:o}"
            )
            self._add_xattrs(member, oid, compressed=False)
            return MemberRecord(member, None)
        if (
            compressed
            and apfs.DECMPFS_XATTR not in xattrs
            and tree.damaged(oid, apfs.XATTR) is not None
        ):
            return None
        first[oid] = path
        self._add_xattrs(member, oid, compressed=compressed)
        return MemberRecord(member, self._file_data(member, oid, inode, compressed))

    def _file_data(
        self, member: ArchiveMember, oid: int, inode: apfs.Inode, compressed: bool
    ) -> ApfsData:
        """Where ``member``'s bytes are; sets its size and whether it is sparse."""
        tree = self._tree
        what = f"the APFS file {quoted(member.name)}"
        if not compressed:
            member.size = inode.size
            rsrc = tree.xattrs.get(oid, {}).get(apfs.RESOURCE_FORK_XATTR)
            if rsrc is not None and rsrc.size:
                member.extra["dmg.resource_fork_size"] = rsrc.size
            try:
                _, sparse = apfs.stream_reader(
                    self._volume, tree, inode.stream, inode.size, what
                )
            except ArchiveyError as exc:
                return ApfsData(self._index, oid, False, (type(exc), str(exc)))
            member.is_sparse = sparse
            return ApfsData(self._index, oid, False)
        attr = tree.xattrs.get(oid, {}).get(apfs.DECMPFS_XATTR)
        if attr is None:
            member.size = 0
            return ApfsData(
                self._index,
                oid,
                True,
                (
                    CorruptionError,
                    f"{what} has the compressed flag and no com.apple.decmpfs attribute",
                ),
            )
        try:
            value = apfs.xattr_value(
                self._volume,
                tree,
                attr,
                hfsplus.DECMPFS_KEEP,
                f"the com.apple.decmpfs attribute of {what}",
            )
            member.size = hfsplus.parse_decmpfs(value).size
        except ArchiveyError as exc:
            member.size = 0
            return ApfsData(
                self._index,
                oid,
                True,
                (
                    CorruptionError,
                    f"{what} has a damaged com.apple.decmpfs attribute ({exc})",
                ),
            )
        return ApfsData(self._index, oid, True)

    def _read_target(self, member: ArchiveMember, target: apfs.Xattr | None) -> None:
        """A symlink's target: its ``com.apple.fs.symlink`` attribute, NUL-terminated,
        at most ``SYMLINK_MAX`` bytes."""
        if target is None:
            self._context.link_target_unavailable(
                member,
                reason="damaged",
                message=(
                    f"The APFS symlink {quoted(member.name)} has no "
                    "com.apple.fs.symlink attribute."
                ),
                target_in_archive=False,
            )
            return
        if target.size > hfsplus.SYMLINK_MAX + 1:
            self._context.link_target_unavailable(
                member,
                reason="too_long",
                message=(
                    f"The APFS symlink {quoted(member.name)} stores a "
                    f"{target.size}-byte target, more than the {hfsplus.SYMLINK_MAX} "
                    "bytes macOS allows."
                ),
                target_in_archive=True,
            )
            return
        try:
            raw = apfs.xattr_value(
                self._volume,
                self._tree,
                target,
                hfsplus.SYMLINK_MAX + 1,
                f"the target of {quoted(member.name)}",
            )
        except ArchiveyError as exc:
            self._context.link_target_unavailable(
                member,
                reason="damaged",
                message=(
                    f"The target of the APFS symlink {quoted(member.name)} cannot be "
                    f"read: {exc}"
                ),
                target_in_archive=True,
            )
            return
        member.link_target = self._context.decode_name(raw.split(b"\0", 1)[0])

    def _add_xattrs(self, member: ArchiveMember, oid: int, *, compressed: bool) -> None:
        """D2, as for HFS+: names and small values in ``extra``. The symlink target,
        the resource fork, and a compressed file's decmpfs attribute are not listed."""
        tree = self._tree
        if tree.damaged(oid, apfs.XATTR) is not None:
            self._context.report(
                DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                (
                    f"Extended attribute records of the APFS file {quoted(member.name)} "
                    "may be in a damaged node; the member is listed without them."
                ),
                MemberHeaderRecordContext(record="xattr", reason="damaged record"),
                member=member,
            )
        found = tree.xattrs.get(oid)
        if not found:
            return
        hidden = {apfs.SYMLINK_XATTR, apfs.RESOURCE_FORK_XATTR}
        if compressed:
            hidden.add(apfs.DECMPFS_XATTR)
        xattrs = {
            name: (
                attr.value
                if attr.value is not None and len(attr.value) <= hfsplus.XATTR_VALUE_MAX
                else None
            )
            for name, attr in found.items()
            if name not in hidden
        }
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
    supports_password = True

    @override
    def open(
        self, source: ReaderSource, context: ReaderContext
    ) -> DmgReader | NeedsPassword[dmg_encrypted.ImageKeys, IndexedReader[Any]]:
        if dmg_encrypted.is_encrypted(source):
            return _open_encrypted(source, context)
        _refuse_version_1(source)
        return DmgReader(source, context)


DmgReadBackend = register_builtin_format(
    DmgHandler,
    MAGIC=(*MAGIC, MagicSignature(0, ENCRYPTED_V2, ArchiveFormat.DMG)),
    TRAILER=(
        *TRAILER,
        TrailerSignature(len(ENCRYPTED_V1), ENCRYPTED_V1, ArchiveFormat.DMG),
    ),
)
