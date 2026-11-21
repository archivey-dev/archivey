"""Where the filesystems are on a UDIF image's disk: GPT, Apple partition map, or none.

Design §5 of ``openspec/changes/dmg-reader``. The run tables together are the index of
the disk, and every byte comes from it. Which ranges are probed for a filesystem comes
from the first of these that is valid:

1. the partition map on the disk: a GPT whose header and entry array pass their CRCs
   and whose geometry is sound (primary, else the backup at the last sector), or an
   Apple partition map whose entries are all consistent;
2. the run tables' own sector ranges, when there is no map or it cannot be used (a
   diagnostic says which);
3. the whole disk.

Names only describe. A GPT type, an APM type or a run table's name (``Apple_HFS``,
``Apple_APFS``) never decides what is read: the signature in the partition does
(:func:`probe`), and a disagreement is a diagnostic.
"""

from __future__ import annotations

import itertools
import struct
import uuid
import zlib
from collections.abc import Callable
from typing import NamedTuple

from archivey.exceptions import ResourceLimitError
from archivey.internal.backends.udif import SECTOR, UdifImage
from archivey.terminal import quoted

# At most this many ranges are probed, from any source (design §5).
MAX_CANDIDATES = 128
# A GPT larger than this is not read: 128 entries of at most 512 bytes (64 KiB).
_GPT_MAX_ENTRIES = 128
_GPT_MAX_ENTRY_SIZE = 512
_APM_MAX_ENTRIES = 64
# What a probe reads from the start of a range: the HFS+ volume header at 1024 and the
# APFS container superblock's magic at 32 are both inside it.
PROBE_SIZE = 4096

_GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
_GPT_ENTRY = struct.Struct("<16s16sQQQ72s")
_GPT_SIGNATURE = b"EFI PART"
HFS_GUID = uuid.UUID("48465300-0000-11AA-AA11-00306543ECAC")
APFS_GUID = uuid.UUID("7C3457EF-0000-11AA-AA11-00306543ECAC")
# Partitions that hold no files a disk image is made for: probed like any other, and
# not reported when they hold no filesystem archivey reads.
_GPT_NO_CONTENT = {
    uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"),  # EFI system
    uuid.UUID("426F6F74-0000-11AA-AA11-00306543ECAC"),  # Apple boot
}
_APM_ENTRY = struct.Struct(">2sHIII32s32s")
_APM_NO_CONTENT = ("Apple_partition_map", "Apple_Free", "Apple_Void", "Apple_Patches")

HFS = "HFS+"
HFSX = "HFSX"
HFS_WRAPPER = "HFS"
APFS = "APFS"


class Candidate(NamedTuple):
    """A range of the disk that may hold a filesystem."""

    start: int  # disk byte offset
    length: int
    label: str  # the map entry's name or type, or the run table's name
    # What the map type or the run table's name says it holds: ``HFS``, ``APFS``,
    # ``""`` when it names nothing archivey reads, ``None`` when it names nothing at
    # all (the whole disk).
    hint: str | None
    # A type that holds no files (free space, the map itself, an EFI partition): not
    # reported when it holds no filesystem.
    no_content: bool = False


class Layout(NamedTuple):
    scheme: str  # "GPT", "APM" or "none"
    candidates: list[Candidate]
    # Where the candidates came from: "map", "blkx" or "disk".
    source: str


Report = Callable[[str, str, int], None]


def hint_from_name(name: str) -> str:
    if "Apple_HFS" in name:  # Apple_HFS and Apple_HFSX
        return HFS
    if "Apple_APFS" in name:
        return APFS
    return ""


# What ``hdiutil`` names the run tables of the map structures and free space:
# ``Protective Master Boot Record (MBR : 0)``, ``GPT Header (Primary GPT Header : 1)``,
# `` (Apple_Free : 3)``, ``Apple (Apple_partition_map : 1)``.
_BLKX_NO_CONTENT = (
    "(MBR",
    "GPT Header",
    "GPT Partition Data",
    "GPT Table",
    *_APM_NO_CONTENT,
    "Apple_Driver",
)


def _blkx_no_content(name: str) -> bool:
    return any(part in name for part in _BLKX_NO_CONTENT)


# ── GPT ──────────────────────────────────────────────────────────────────────────────


class _GptRefused(Exception):
    """Why one GPT copy cannot be used."""

    def __init__(self, reason: str, *, oversized: bool = False) -> None:
        super().__init__(reason)
        self.oversized = oversized


def _gpt_copy(image: UdifImage, header_sector: int) -> list[Candidate]:
    """The partitions of the GPT whose header is at ``header_sector``, or
    :class:`_GptRefused` saying why that copy cannot be used."""
    sectors = image.sector_count
    raw = image.read(header_sector * SECTOR, SECTOR)
    if len(raw) < _GPT_HEADER.size or raw[:8] != _GPT_SIGNATURE:
        raise _GptRefused("no GPT header signature")
    (_, _, header_size, header_crc, _, my_lba, _, first_usable, last_usable, _,
     entries_lba, entry_count, entry_size, entries_crc) = _GPT_HEADER.unpack_from(raw)  # fmt: skip
    if not _GPT_HEADER.size <= header_size <= SECTOR:
        raise _GptRefused(f"its header size is {header_size}")
    check = bytearray(raw[:header_size])
    check[16:20] = bytes(4)
    if zlib.crc32(check) != header_crc:
        raise _GptRefused("its header fails its CRC")
    if my_lba != header_sector:
        raise _GptRefused(f"its header says it is at sector {my_lba}")
    if entry_size < 128 or entry_size & (entry_size - 1):
        raise _GptRefused(f"its entries are {entry_size} bytes")
    if entry_count > _GPT_MAX_ENTRIES or entry_size > _GPT_MAX_ENTRY_SIZE:
        raise _GptRefused(
            f"it holds {entry_count} entries of {entry_size} bytes, more than "
            f"archivey reads ({_GPT_MAX_ENTRIES} of at most {_GPT_MAX_ENTRY_SIZE})",
            oversized=True,
        )
    if not first_usable <= last_usable < sectors:
        raise _GptRefused(
            f"its usable sectors {first_usable} to {last_usable} are not on the "
            f"{sectors}-sector disk"
        )
    array_bytes = entry_count * entry_size
    array_sectors = -(-array_bytes // SECTOR)
    if entries_lba + array_sectors > sectors:
        raise _GptRefused("its entry array is not on the disk")
    entries = image.read(entries_lba * SECTOR, array_bytes)
    if len(entries) < array_bytes or zlib.crc32(entries) != entries_crc:
        raise _GptRefused("its entry array fails its CRC")
    found: list[tuple[int, int, Candidate]] = []
    for i in range(entry_count):
        type_guid, _, first, last, _, name = _GPT_ENTRY.unpack_from(
            entries, i * entry_size
        )
        if type_guid == bytes(16):
            continue
        if not first_usable <= first <= last <= last_usable:
            raise _GptRefused(
                f"entry {i} (sectors {first} to {last}) is outside the usable sectors"
            )
        kind = uuid.UUID(bytes_le=type_guid)
        hint = HFS if kind == HFS_GUID else APFS if kind == APFS_GUID else ""
        label = name.decode("utf-16-le", "replace").split("\0", 1)[0] or str(kind)
        found.append(
            (
                first,
                last,
                Candidate(
                    first * SECTOR,
                    (last - first + 1) * SECTOR,
                    label,
                    hint,
                    no_content=kind in _GPT_NO_CONTENT,
                ),
            )
        )
    ordered = sorted(found, key=lambda item: item[0])
    for (_, previous_last, a), (first, _, b) in itertools.pairwise(ordered):
        if first <= previous_last:
            raise _GptRefused(
                f"entries {quoted(a.label)} and {quoted(b.label)} overlap"
            )
    return [candidate for _, _, candidate in found]


def _gpt(image: UdifImage, report: Report) -> list[Candidate] | None:
    """The GPT's partitions (primary, else backup), or ``None`` when there is no GPT
    or neither copy can be used (reported)."""
    try:
        return _gpt_copy(image, 1)
    except _GptRefused as primary:
        if str(primary) == "no GPT header signature":
            backup_sector = image.sector_count - 1
            if image.read(backup_sector * SECTOR, 8) != _GPT_SIGNATURE:
                return None
        first_error = primary
    try:
        partitions = _gpt_copy(image, image.sector_count - 1)
    except _GptRefused as backup:
        why = first_error if first_error.oversized else backup
        report(
            "partition_map",
            f"The image's GPT cannot be used: the primary copy: {first_error}; the "
            f"backup: {backup}. The partitions are read from the run tables' sector "
            f"ranges{' (the GPT is larger than archivey reads)' if why.oversized else ''}.",
            SECTOR,
        )
        return None
    report(
        "gpt_primary",
        f"The image's primary GPT cannot be used ({first_error}); its backup at the "
        "disk's last sector is read.",
        SECTOR,
    )
    return partitions


# ── Apple partition map ──────────────────────────────────────────────────────────────


def _apm(image: UdifImage, report: Report) -> list[Candidate] | None:
    """The Apple partition map's partitions, or ``None`` when there is none or it
    cannot be used (reported)."""
    head = image.read(0, SECTOR)
    if head[:2] != b"ER":
        return None
    (block_size,) = struct.unpack_from(">H", head, 2)
    if block_size not in (512, 1024, 2048, 4096):
        block_size = SECTOR
    first = image.read(block_size, _APM_ENTRY.size)
    if len(first) < _APM_ENTRY.size or first[:2] != b"PM":
        return None
    _, _, count, _, _, _, _ = _APM_ENTRY.unpack(first)

    def refuse(reason: str) -> None:
        report(
            "partition_map",
            f"The image's Apple partition map cannot be used ({reason}); the partitions "
            "are read from the run tables' sector ranges.",
            block_size,
        )

    if count > _APM_MAX_ENTRIES:
        refuse(f"it declares {count} entries, more than the {_APM_MAX_ENTRIES} read")
        return None
    disk = image.disk_size
    partitions: list[Candidate] = []
    for i in range(1, count + 1):
        raw = image.read(i * block_size, _APM_ENTRY.size)
        if len(raw) < _APM_ENTRY.size:
            refuse(f"entry {i} is past the disk")
            return None
        signature, _, entry_count, start, blocks, name, kind = _APM_ENTRY.unpack(raw)
        if signature != b"PM" or entry_count != count:
            refuse(f"entry {i} is not an entry of a {count}-entry map")
            return None
        if (start + blocks) * block_size > disk:
            refuse(f"entry {i} runs past the end of the disk")
            return None
        type_name = kind.split(b"\0", 1)[0].decode("ascii", "replace")
        label = name.split(b"\0", 1)[0].decode("mac_roman", "replace") or type_name
        if not blocks:
            continue
        partitions.append(
            Candidate(
                start * block_size,
                blocks * block_size,
                label,
                hint_from_name(type_name),
                no_content=type_name.startswith(_APM_NO_CONTENT)
                or type_name.startswith("Apple_Driver"),
            )
        )
    return partitions


# ── Choosing ─────────────────────────────────────────────────────────────────────────


def layout(image: UdifImage, report: Report) -> Layout:
    """The ranges to probe for a filesystem, and where they came from."""
    gpt = _gpt(image, report)
    if gpt is not None:
        return Layout("GPT", _capped(gpt, "GPT entries"), "map")
    apm = _apm(image, report)
    if apm is not None:
        return Layout("APM", _capped(apm, "partition map entries"), "map")
    tables = [
        Candidate(
            t.first_sector * SECTOR,
            t.sector_count * SECTOR,
            t.name,
            hint_from_name(t.name),
            no_content=_blkx_no_content(t.name),
        )
        for t in image.tables
        if t.sector_count
    ]
    return Layout("none", _capped(tables, "run tables"), "blkx")


def _capped(candidates: list[Candidate], what: str) -> list[Candidate]:
    if len(candidates) > MAX_CANDIDATES:
        raise ResourceLimitError(
            f"the UDIF image has {len(candidates)} {what} to probe for a filesystem, "
            f"more than the {MAX_CANDIDATES} archivey probes"
        )
    return candidates


def whole_disk(image: UdifImage) -> Candidate:
    return Candidate(0, image.disk_size, "whole disk", None)


def probe(image: UdifImage, candidate: Candidate) -> str | None:
    """The filesystem the range starts with: ``HFS``, ``HFSX``, ``HFS_WRAPPER`` (an
    HFS volume, possibly wrapping HFS+), ``APFS``, or ``None``."""
    head = image.read(candidate.start, min(PROBE_SIZE, candidate.length))
    signature = head[1024:1028]
    if signature in (b"H+\x00\x04", b"HX\x00\x05"):
        return HFS if signature[:2] == b"H+" else HFSX
    if signature[:2] == b"BD":
        return HFS_WRAPPER
    if head[32:36] == b"NXSB":
        return APFS
    return None
