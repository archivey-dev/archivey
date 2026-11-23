"""UDIF disk images (``.dmg``): the ``koly`` block, the property list, the run tables,
and the virtual disk they describe.

A UDIF image is a disk stored as *runs*. Each run covers a range of the disk's 512-byte
sectors and stores it as zeros (nothing stored), raw bytes, or a compressed block (ADC,
zlib, bzip2, LZFSE or xz). The image ends with a 512-byte ``koly`` block (an old layout
puts it first) that says where the data fork and the XML property list are. The
property list's ``blkx`` array holds one ``mish`` table per piece of the disk (the
protective MBR, the GPT, each partition), and each table lists its runs.

:class:`UdifImage` reads the ``koly`` block and the tables at open and checks every
range before any byte of a run is read (design §4 of ``openspec/changes/dmg-reader``).
:meth:`UdifImage.read` serves bytes of the virtual disk, decoding the runs a read
covers; a few decoded runs stay in a cache. :class:`UdifSource` is a
:class:`~archivey.formats.ReaderSource` over a range of the disk, so a filesystem parser
reads a partition as it would read a file.

Runs are kept as packed arrays, one value per run per field, never one Python object
per run, so a table of a million runs costs about 40 bytes a run.

Detection keeps the ``koly`` signatures here (:data:`MAGIC`, :data:`TRAILER`): at offset
0, and as a trailer that outranks the bzip2 or xz stream a compressed image starts with.
"""

from __future__ import annotations

import bisect
import contextlib
import io
import plistlib
import struct
import xml.parsers.expat
import zlib
from array import array
from collections import OrderedDict
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING, BinaryIO, NamedTuple, NoReturn

from archivey.diagnostics import (
    ArchiveEofContext,
    ArchiveStructureContext,
    DiagnosticCode,
)
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    exception_detail,
)
from archivey.formats import ReaderContext, ReaderSource
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.adc_decoder import adc_decompress
from archivey.internal.streams.codecs.lzfse_decoder import lzfse_decompress
from archivey.terminal import quoted

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

from archivey.types import (
    ArchiveFormat,
    CompressionAlgorithm,
    MagicSignature,
    StreamFormat,
    TrailerSignature,
)

SECTOR = 512

# 7-Zip's ``IsKoly``: the four bytes ``koly``, then version 4 and a header size of 512,
# both big-endian. Version or size other than those is not this format.
KOLY_SIGNATURE = b"koly" + (4).to_bytes(4, "big") + (512).to_bytes(4, "big")
_KOLY_SIZE = 512
MAGIC = (MagicSignature(0, KOLY_SIGNATURE, ArchiveFormat.DMG),)
TRAILER = (
    TrailerSignature(
        _KOLY_SIZE,
        KOLY_SIGNATURE,
        ArchiveFormat.DMG,
        # The first run of a compressed image is one of these streams.
        preempts=(ArchiveFormat.BZ2, ArchiveFormat.XZ),
    ),
)

_KOLY = struct.Struct(">4sIIIQQQQQII16sII128sQQ120sII128sIQ12s")
assert _KOLY.size == _KOLY_SIZE
# The code signature's offset and length, inside what the struct above calls the 120
# reserved bytes after the XML length (7-Zip ``DmgHandler.cpp`` reads them there).
_CODE_SIGNATURE = struct.Struct(">QQ")
_CODE_SIGNATURE_AT = 0x128
_MISH = struct.Struct(">4sIQQQII24sII128sI")
assert _MISH.size == 204
_RUN = struct.Struct(">IIQQQQ")
_CHECKSUM_CRC32 = 2

ZERO_FILL = 0x00000000
RAW = 0x00000001
IGNORE = 0x00000002
ADC = 0x80000004
ZLIB = 0x80000005
BZIP2 = 0x80000006
LZFSE = 0x80000007
XZ = 0x80000008
_COMMENT = 0x7FFFFFFE
_TERMINATOR = 0xFFFFFFFF

# The run types by name. ``archive_info().extra["dmg.run_codecs"]`` lists those that
# store bytes.
RUN_CODECS = {
    ZERO_FILL: "zero",
    RAW: "raw",
    IGNORE: "ignore",
    ADC: "adc",
    ZLIB: "zlib",
    BZIP2: "bzip2",
    LZFSE: "lzfse",
    XZ: "xz",
}
_STORED_NOTHING = (ZERO_FILL, IGNORE)
_COMPRESSED = (ADC, ZLIB, BZIP2, LZFSE, XZ)
# How each codec archivey decodes through ``ReaderContext.decompress`` is named there.
_THROUGH_ARCHIVEY: dict[int, CompressionAlgorithm | StreamFormat] = {
    ZLIB: StreamFormat.ZLIB,
    BZIP2: CompressionAlgorithm.BZIP2,
    XZ: CompressionAlgorithm.XZ,
}
# The in-house decoders, and the ``FormatPolicy`` method each one serves.
_IN_HOUSE: dict[int, tuple[CompressionAlgorithm, Callable[[bytes, int], bytes]]] = {
    ADC: (CompressionAlgorithm.ADC, adc_decompress),
    LZFSE: (CompressionAlgorithm.LZFSE, lzfse_decompress),
}

# The property list is read whole at open: nothing about the image is known without
# it. hdiutil's are a few KiB; a million-run image's would be about 55 MiB.
MAX_PLIST = 64 << 20
# The most a compressed run may decode to. hdiutil writes at most 2,048 sectors
# (1 MiB) per run, and no measured producer writes more.
MAX_RUN_DECODED = 16 << 20
# A compressed run may store at most twice its decoded size plus this. A valid
# encoding can be arbitrarily inefficient (zlib allows empty stored blocks without
# end), so this is a support limit, not a validity bound: it admits every ADC run of
# one-byte literals (about twice the decoded size) and every real writer's output.
_STORED_SLACK = 64 << 10
# Decoded runs kept for reuse: the metadata a listing reads back and forth over, and
# the run a member read is in. At most this many times ``MAX_RUN_DECODED``.
CACHE_RUNS = 8
# At open, beyond the property list, the physical bytes read plus the bytes decoded
# must stay within this (design §7).
OPEN_BUDGET = 64 << 20
# How far past a structure's end a scan for non-zero bytes looks, as other formats
# look past their end.
TRAILING_LOOK = 1 << 20
# The checksum pass feeds raw bytes to the CRC in slices of this size.
CHECK_SLICE = 1 << 20
# What a run costs in the packed arrays: a u32 type and four u64 fields.
_RUN_BYTES = 36
# Offsets must stay below 2^63 (``ReaderSource`` takes Python ints, but a disk of more
# sectors than this names offsets no file system can).
_MAX_SECTORS = (1 << 63) // SECTOR


class Koly(NamedTuple):
    """The fields of a ``koly`` block that the reader uses."""

    at: int  # where the block is in the file: 0 or the file's end minus 512
    data_fork_offset: int
    data_fork_length: int
    segment_count: int
    data_checksum: tuple[int, int, bytes]  # type, bits, value
    xml_offset: int
    xml_length: int
    master_checksum: tuple[int, int, bytes]
    image_variant: int
    sector_count: int
    code_signature_offset: int
    code_signature_length: int


def parse_koly(raw: bytes, at: int) -> Koly | None:
    """The ``koly`` block in ``raw`` (512 bytes) read at file offset ``at``, or
    ``None`` when its first 12 bytes are not the signature."""
    if len(raw) < _KOLY_SIZE or raw[: len(KOLY_SIGNATURE)] != KOLY_SIGNATURE:
        return None
    f = _KOLY.unpack(raw)
    signature_offset, signature_length = _CODE_SIGNATURE.unpack_from(
        raw, _CODE_SIGNATURE_AT
    )
    return Koly(
        at=at,
        data_fork_offset=f[5],
        data_fork_length=f[6],
        segment_count=f[10],
        data_checksum=(f[12], f[13], f[14]),
        xml_offset=f[15],
        xml_length=f[16],
        master_checksum=(f[18], f[19], f[20]),
        image_variant=f[21],
        sector_count=f[22],
        code_signature_offset=signature_offset,
        code_signature_length=signature_length,
    )


# ── CRC-32 over zero bytes, without the bytes ────────────────────────────────────────

# zlib's CRC-32 polynomial, reflected.
_CRC_POLY = 0xEDB88320


def _gf2_times(matrix: list[int], vector: int) -> int:
    """``matrix`` (32 columns over GF(2)) applied to the 32-bit ``vector``."""
    out = 0
    i = 0
    while vector:
        if vector & 1:
            out ^= matrix[i]
        vector >>= 1
        i += 1
    return out


def _zero_operators() -> list[list[int]]:
    """For each ``k`` below 64, the operator that runs the raw CRC-32 register over
    ``2**k`` zero bytes: the one-zero-bit operator squared ``3 + k`` times."""
    operator = [_CRC_POLY] + [1 << i for i in range(31)]  # one zero bit
    for _ in range(3):  # 2, 4, then 8 zero bits: one zero byte
        operator = [_gf2_times(operator, column) for column in operator]
    operators = []
    for _ in range(64):
        operators.append(operator)
        operator = [_gf2_times(operator, column) for column in operator]
    return operators


_ZERO_OPERATORS: list[list[int]] | None = None


def crc32_zeros(crc: int, n: int) -> int:
    """``zlib.crc32(bytes(n), crc)``, in time that grows with the number of bits of
    ``n``: the zero-extension operator of zlib's ``crc32_combine``. A zero-fill run of
    2^50 bytes costs a few dozen small matrix products, not a walk over its bytes."""
    global _ZERO_OPERATORS
    if n <= 0:
        return crc
    if n < 64:
        return zlib.crc32(bytes(n), crc)
    if n >= 1 << 64:
        raise ValueError(f"{n} zero bytes is more than a disk can hold")
    operators = _ZERO_OPERATORS
    if operators is None:
        operators = _ZERO_OPERATORS = _zero_operators()
    # zlib inverts the register before and after; zero bytes act linearly on the raw
    # register in between.
    register = crc ^ 0xFFFFFFFF
    k = 0
    while n:
        if n & 1:
            register = _gf2_times(operators[k], register)
        n >>= 1
        k += 1
    return register ^ 0xFFFFFFFF


def crc32_value(checksum: tuple[int, int, bytes]) -> int | None:
    """A checksum field's CRC-32 (type 2, 32 bits), or ``None`` for any other kind."""
    kind, bits, value = checksum
    if kind == _CHECKSUM_CRC32 and bits == 32:
        return int.from_bytes(value[:4], "big")
    return None


class UdifTable(NamedTuple):
    """One ``blkx`` entry: a ``mish`` table and the sector range it covers."""

    name: str
    first_sector: int
    sector_count: int
    # The table's CRC-32 of its decoded runs, ignore runs excepted (checked from the
    # partition pass); ``None`` when it stores another kind or none.
    checksum: int | None
    # Its runs: ``UdifImage``'s run arrays from ``first_run`` up to ``end_run``.
    first_run: int
    end_run: int


def _overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Whether two half-open ranges share a byte (an empty range shares none)."""
    return a_start < a_end and b_start < b_end and a_start < b_end and b_start < a_end


def first_nonzero(
    read: Callable[[int, int], bytes], start: int, end: int
) -> int | None:
    """The offset of the first non-zero byte in the first :data:`TRAILING_LOOK`
    bytes of ``[start, end)``, read with ``read(offset, n)``; ``None`` when they are
    all zero."""
    data = read(start, min(end - start, TRAILING_LOOK))
    stripped = data.lstrip(b"\0")
    return start + len(data) - len(stripped) if stripped else None


def _shown_range(start: int, length: int) -> str:
    return f"{length} bytes at offset {start}"


class DecryptedImageSource(ReaderSource):
    """A :class:`~archivey.formats.ReaderSource` over a decrypted image: its offsets
    are the decrypted image's, not the file's, and messages say so."""


class UdifImage:
    """The virtual disk of one UDIF image.

    Everything the open reads is checked here: the ``koly`` block, the property list,
    each ``mish`` table and run. A run's stored range is checked against the data fork
    at open, and its decode is bounded before any byte of it is read
    (:meth:`_decode_run`). ``read`` serves the disk's bytes.
    """

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        # Whether the source's offsets are a decrypted image's, which the run and
        # truncation messages name, not the file's.
        self._decrypted = isinstance(source, DecryptedImageSource)
        self._offsets = "decrypted image offset" if self._decrypted else "file offset"
        # The open budget: the physical bytes read and the bytes decoded since the
        # property list, until ``end_open`` (design §7). ``None`` once open is done.
        self._budget: int | None = OPEN_BUDGET
        self._budget_total = OPEN_BUDGET
        self._budget_what = "opening the UDIF image"
        # Whether served zeros count against the budget (only inside ``budget()``).
        self._count_zeros = False
        size = source.size
        if size is None:
            with source.view(0) as whole:
                size = whole.seek(0, io.SEEK_END)
        self.file_size = size
        self.koly = koly = self._find_koly(size)
        if koly.segment_count > 1:
            raise UnsupportedFeatureError(
                f"segmented UDIF images ({koly.segment_count} segments) are not "
                "supported"
            )
        if koly.xml_length == 0:
            raise UnsupportedFeatureError(
                "UDIF images without a property list (old resource-fork-only "
                "images) are not supported"
            )
        self._check_ranges(koly, size)
        if not 0 < koly.sector_count <= _MAX_SECTORS:
            raise CorruptionError(
                f"the UDIF image declares a disk of {koly.sector_count} sectors"
            )
        self.sector_count = koly.sector_count
        self.disk_size = koly.sector_count * SECTOR
        # One packed value per run in each array, sorted by start sector.
        self._kind = array("I")
        self._start = array("Q")  # first sector on the disk
        self._count = array("Q")  # sectors
        self._offset = array("Q")  # where its stored bytes start in the file
        self._length = array("Q")  # how many bytes it stores
        self.tables: list[UdifTable] = []
        self.run_codecs: set[str] = set()
        self._load_tables(self._read_plist(koly))
        self._cache: OrderedDict[int, bytes] = OrderedDict()

    # ── The koly block and the file's ranges ─────────────────────────────────────────

    def _find_koly(self, size: int) -> Koly:
        """The ``koly`` block: the last 512 bytes, or, on an old image, the first."""
        if size >= _KOLY_SIZE:
            at = size - _KOLY_SIZE
            koly = parse_koly(self._source.read_exact(at, _KOLY_SIZE), at)
            if koly is not None:
                return koly
            koly = parse_koly(self._source.read_exact(0, _KOLY_SIZE), 0)
            if koly is not None:
                return koly
        raise CorruptionError("no UDIF koly block at the end or the start of the file")

    def _check_ranges(self, koly: Koly, size: int) -> None:
        """Refuse a data fork or property list outside the file or overlapping the
        ``koly`` block or each other; check the code signature's range (a diagnostic,
        never a refusal); report the bytes of the file no structure covers."""
        koly_range = (koly.at, koly.at + _KOLY_SIZE)
        fork = (koly.data_fork_offset, koly.data_fork_offset + koly.data_fork_length)
        plist = (koly.xml_offset, koly.xml_offset + koly.xml_length)
        if koly.xml_length > MAX_PLIST:
            raise ResourceLimitError(
                f"the UDIF property list is {koly.xml_length} bytes, more than the "
                f"{MAX_PLIST >> 20} MiB archivey reads"
            )
        for what, (start, end) in (("data fork", fork), ("property list", plist)):
            if end > size:
                raise CorruptionError(
                    f"the UDIF {what} ({_shown_range(start, end - start)}) runs past "
                    f"the end of the {size}-byte file"
                )
        named = [
            ("data fork", fork),
            ("property list", plist),
            ("koly block", koly_range),
        ]
        for i, (first, (a_start, a_end)) in enumerate(named):
            for second, (b_start, b_end) in named[i + 1 :]:
                if _overlap(a_start, a_end, b_start, b_end):
                    raise CorruptionError(f"the UDIF {first} overlaps the {second}")
        covered = [fork, plist, koly_range]
        self.code_signature = False
        if koly.code_signature_offset or koly.code_signature_length:
            blob = (
                koly.code_signature_offset,
                koly.code_signature_offset + koly.code_signature_length,
            )
            problem = None
            if blob[1] > size or blob[0] >= blob[1]:
                problem = "is outside the file"
            elif any(_overlap(*blob, start, end) for start, end in covered):
                problem = "overlaps another structure"
            if problem is None:
                self.code_signature = True
                covered.append(blob)
            else:
                self.report_structure(
                    "code_signature",
                    f"The UDIF code signature ({_shown_range(blob[0], blob[1] - blob[0])}"
                    f") {problem}; it is ignored and the image is read.",
                    blob[0],
                )
        self._report_uncovered(covered, size)

    def _report_uncovered(self, covered: list[tuple[int, int]], size: int) -> None:
        """Report bytes of the file outside every structure the ``koly`` block
        declares, as ``ARCHIVE_TRAILING_DATA``. Zero bytes are silent; the first
        MiB of each gap is looked at, as other formats look past their end."""
        pos = 0
        for start, end in sorted(r for r in covered if r[1] > r[0]):
            if start > pos:
                self._report_gap(pos, start)
            pos = max(pos, end)
        if pos < size:
            self._report_gap(pos, size)

    def _report_gap(self, start: int, end: int) -> None:
        found = first_nonzero(
            lambda at, n: self._read_file(
                at, n, "bytes outside the image's structures"
            ),
            start,
            end,
        )
        if found is None:
            return
        self._context.report(
            DiagnosticCode.ARCHIVE_TRAILING_DATA,
            (
                f"UDIF image holds {end - start} bytes at offset {start} that no "
                f"structure its koly block declares covers, with a non-zero byte at "
                f"offset {found}. The listing does not account for them."
            ),
            ArchiveEofContext(
                format="dmg",
                expected_marker="zeros_to_eof",
                expected_bytes=0,
                observed_bytes=found,
                observed_kind="nonzero",
            ),
        )

    def report_structure(self, structure: str, message: str, offset: int) -> None:
        self._context.report(
            DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT,
            message,
            ArchiveStructureContext(format="dmg", structure=structure, offset=offset),
        )

    # ── The property list and the run tables ─────────────────────────────────────────

    def _read_plist(self, koly: Koly) -> list[object]:
        """The ``blkx`` array of the property list."""
        raw = self._source.read_exact(koly.xml_offset, koly.xml_length)
        try:
            plist = plistlib.loads(raw)
        except (
            plistlib.InvalidFileException,
            xml.parsers.expat.ExpatError,
            ValueError,
            TypeError,
            # KeyError and IndexError from the parser, and an XML declaration that
            # names an unknown or non-text codec.
            LookupError,
            OverflowError,
            RecursionError,
            struct.error,
        ) as exc:
            raise CorruptionError(
                f"the UDIF property list at offset {koly.xml_offset} does not parse: "
                f"{exc}"
            ) from None
        resource_fork = plist.get("resource-fork") if isinstance(plist, dict) else None
        blkx = resource_fork.get("blkx") if isinstance(resource_fork, dict) else None
        if not isinstance(blkx, list) or not blkx:
            raise CorruptionError("the UDIF property list has no blkx table")
        return blkx

    def _load_tables(self, blkx: list[object]) -> None:
        """Parse every ``mish`` table and keep its runs, sorted by sector."""
        parsed: list[tuple[str, int, int, int | None, bytes, int]] = []
        total_runs = 0
        for index, entry in enumerate(blkx):
            if not isinstance(entry, dict) or not isinstance(entry.get("Data"), bytes):
                raise CorruptionError(f"blkx entry {index} holds no mish table")
            name = entry.get("CFName") or entry.get("Name") or ""
            if not isinstance(name, str):
                name = ""
            data: bytes = entry["Data"]
            if len(data) < _MISH.size:
                raise CorruptionError(
                    f"the mish table of blkx entry {index} is {len(data)} bytes, "
                    f"shorter than its {_MISH.size}-byte header"
                )
            (magic, version, first, count, data_offset, _, _, _, ck_type, ck_bits,
             ck_value, runs) = _MISH.unpack_from(data)  # fmt: skip
            if magic != b"mish" or version != 1:
                raise CorruptionError(
                    f"blkx entry {index} is not a version 1 mish table"
                )
            if _MISH.size + _RUN.size * runs > len(data):
                raise CorruptionError(
                    f"the mish table of blkx entry {index} declares {runs} runs, more "
                    f"than its {len(data)} bytes hold"
                )
            if first + count > self.sector_count:
                raise CorruptionError(
                    f"the mish table {quoted(name)} covers sectors {first} to "
                    f"{first + count}, past the disk's {self.sector_count}"
                )
            total_runs += runs
            parsed.append(
                (
                    name,
                    first,
                    count,
                    crc32_value((ck_type, ck_bits, ck_value)),
                    data,
                    data_offset,
                )
            )
        budget = self._context.config.listing_limits.max_metadata_bytes
        if budget is not None and total_runs * _RUN_BYTES > budget:
            raise ResourceLimitError(
                f"Listing limit reached: max_metadata_bytes={budget} (the UDIF run "
                f"tables hold {total_runs} runs, {total_runs * _RUN_BYTES} bytes kept)"
            )
        # The master checksum in the koly block is a CRC-32 of these, in this order.
        self.plist_checksums = [table[3] for table in parsed]
        parsed.sort(key=lambda table: (table[1], table[2]))
        previous_end = 0
        previous_name = ""
        for name, first, count, checksum, data, data_offset in parsed:
            if count and first < previous_end:
                raise CorruptionError(
                    f"the mish tables {quoted(previous_name)} and {quoted(name)} cover the same "
                    "sectors"
                )
            first_run = len(self._kind)
            self._load_runs(name, first, count, data, data_offset)
            self.tables.append(
                UdifTable(name, first, count, checksum, first_run, len(self._kind))
            )
            if count:
                previous_end, previous_name = first + count, name

    def _load_runs(
        self, name: str, first: int, count: int, data: bytes, data_offset: int
    ) -> None:
        """Check one table's runs and append them to the run arrays."""
        (runs,) = struct.unpack_from(">I", data, _MISH.size - 4)
        fork_start = self.koly.data_fork_offset
        fork_end = fork_start + self.koly.data_fork_length
        table_end = first + count
        previous_end = first
        ended = False
        for i in range(runs):
            kind, _, sector, sectors, offset, length = _RUN.unpack_from(
                data, _MISH.size + _RUN.size * i
            )
            if kind == _TERMINATOR:
                ended = True
                continue
            if ended:
                raise CorruptionError(
                    f"the mish table {quoted(name)} has a run after its terminator"
                )
            if kind == _COMMENT or sectors == 0:
                continue
            start = first + sector
            if start < previous_end or start + sectors > table_end:
                raise CorruptionError(
                    f"run {i} of the mish table {quoted(name)} (sectors {start} to "
                    f"{start + sectors}) is out of order or outside the table's "
                    f"sectors {first} to {table_end}"
                )
            previous_end = start + sectors
            stored_at = fork_start + data_offset + offset
            if (
                kind not in _STORED_NOTHING
                and kind in RUN_CODECS
                and stored_at + length > fork_end
            ):
                raise CorruptionError(
                    f"run {i} of the mish table {quoted(name)} stores "
                    f"{_shown_range(stored_at, length)}, outside the data fork"
                )
            codec = RUN_CODECS.get(kind)
            if codec is not None and kind not in _STORED_NOTHING:
                self.run_codecs.add(codec)
            self._kind.append(kind)
            self._start.append(start)
            self._count.append(sectors)
            self._offset.append(stored_at)
            self._length.append(length)

    # ── Reading ──────────────────────────────────────────────────────────────────────

    def end_open(self) -> None:
        """The open is done: from here on, reads are not counted against the open
        budget."""
        self._budget = None

    @contextlib.contextmanager
    def budget(self, nbytes: int, what: str) -> Generator[None]:
        """Count the bytes read inside the block against ``nbytes``:
        ``ResourceLimitError`` names ``what`` when they would exceed it. For a bounded
        step after the open, such as the APFS checkpoint scan (design §6A.2). The
        physical bytes read and the bytes decoded count, as the open budget counts
        them, and so do the bytes served from zero-fill runs, ignored runs and gaps:
        those cost nothing to store, and the step's work is per byte served."""
        saved = (
            self._budget,
            self._budget_total,
            self._budget_what,
            self._count_zeros,
        )
        self._budget, self._budget_total, self._budget_what = nbytes, nbytes, what
        self._count_zeros = True
        try:
            yield
        finally:
            (
                self._budget,
                self._budget_total,
                self._budget_what,
                self._count_zeros,
            ) = saved

    def _spend(self, nbytes: int) -> None:
        if self._budget is None:
            return
        self._budget -= nbytes
        if self._budget < 0:
            raise ResourceLimitError(
                f"{self._budget_what} read and decoded more than the "
                f"{self._budget_total >> 20} MiB archivey allows for it"
            )

    def _read_file(self, offset: int, n: int, what: str) -> bytes:
        self._spend(n)
        try:
            return self._source.read_exact(offset, n)
        except TruncatedError:
            whole = "decrypted image" if self._decrypted else "file"
            raise TruncatedError(
                f"{what} at {self._offsets} {self._source._origin + offset} runs past "
                f"the end of the {whole}"
            ) from None

    def run_count(self) -> int:
        return len(self._kind)

    def run(self, index: int) -> tuple[int, int, int, int, int]:
        """Run ``index``: (type, first sector, sectors, stored offset, stored length)."""
        return (
            self._kind[index],
            self._start[index],
            self._count[index],
            self._offset[index],
            self._length[index],
        )

    def _where(self, index: int) -> str:
        codec = RUN_CODECS.get(self._kind[index], f"type 0x{self._kind[index]:08x}")
        origin = self._source._origin
        return (
            f"the {codec} run for disk sector {self._start[index]} (stored at "
            f"{self._offsets} {origin + self._offset[index]})"
        )

    def _decode_run(self, index: int, *, keep: bool = True) -> bytes:
        """Compressed run ``index``, decoded and cached (unless ``keep`` is false: the
        checksum pass reads each run once, and must not push out the runs a listing
        or a read keeps). Its bounds are checked before any of its bytes is read; it
        must decode to exactly its sectors."""
        cached = self._cache.get(index)
        if cached is not None:
            self._cache.move_to_end(index)
            return cached
        kind = self._kind[index]
        decoded = self._count[index] * SECTOR
        length = self._length[index]
        if decoded > MAX_RUN_DECODED:
            raise UnsupportedFeatureError(
                f"{self._where(index)} decodes to {decoded} bytes, more than the "
                f"{MAX_RUN_DECODED >> 20} MiB archivey reads for one run"
            )
        if length > 2 * decoded + _STORED_SLACK:
            raise ResourceLimitError(
                f"{self._where(index)} stores {length} bytes for {decoded}: a "
                "compressed run stores more than archivey reads for one run"
            )
        in_house = _IN_HOUSE.get(kind)
        if in_house is not None:
            refusal = self._context.config.formats._codec_refusal(in_house[0])
            if refusal is not None:
                raise UnsupportedFeatureError(f"{refusal}.")
        raw = self._read_file(self._offset[index], length, self._where(index))
        self._spend(decoded)
        # Every miss counts toward the listing's cap: the cache holds a few runs, so a
        # catalog spread over more runs than that decodes some of them again and again.
        draw = self._context._listing_draw
        if draw is not None:
            draw(decoded)
        try:
            if in_house is not None:
                data = in_house[1](raw, decoded + 1)
            else:
                data = self._through_archivey(raw, _THROUGH_ARCHIVEY[kind], decoded)
        except (CorruptionError, TruncatedError) as exc:
            # The run was read whole, so a stream that stops early is a wrong stored
            # size or damage, not a cut file.
            raise CorruptionError(
                f"{self._where(index)}: {exception_detail(exc)}"
            ) from None
        if len(data) != decoded:
            got = f"more than {decoded}" if len(data) > decoded else str(len(data))
            raise CorruptionError(
                f"{self._where(index)} decodes to {got} bytes, not the {decoded} "
                f"bytes of its {self._count[index]} sectors"
            )
        if keep:
            self._cache[index] = data
            if len(self._cache) > CACHE_RUNS:
                self._cache.popitem(last=False)
        return data

    def _through_archivey(
        self, raw: bytes, method: CompressionAlgorithm | StreamFormat, decoded: int
    ) -> bytes:
        """``raw`` decoded with ``ReaderContext.decompress``, so the caller's decoder
        limits, codec policy and process isolation apply; at most ``decoded + 1``
        bytes are pulled from it."""
        with self._context.decompress(io.BytesIO(raw), method) as stream:
            data = stream.read(decoded + 1)
            # A codec reports a cut stream or a bad check value on the read after its
            # data ends, so read on until it ends or passes the run's size.
            while len(data) <= decoded and (
                more := stream.read(decoded + 1 - len(data))
            ):
                data += more
        return data

    def read(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes of the disk from ``offset``; fewer only at its end. A gap
        between runs reads as zeros, as the format says (hdiutil leaves none)."""
        end = min(offset + n, self.disk_size)
        if offset >= end:
            return b""
        parts: list[bytes] = []
        pos = offset
        starts = self._start
        while pos < end:
            sector = pos // SECTOR
            index = bisect.bisect_right(starts, sector) - 1
            if index < 0 or sector >= starts[index] + self._count[index]:
                following = index + 1
                gap_end = starts[following] * SECTOR if following < len(starts) else end
                take = min(end, gap_end) - pos
                if self._count_zeros:
                    self._spend(take)
                parts.append(bytes(take))
                pos += take
                continue
            run_start = starts[index] * SECTOR
            run_end = run_start + self._count[index] * SECTOR
            take = min(end, run_end) - pos
            within = pos - run_start
            kind = self._kind[index]
            if kind in _STORED_NOTHING:
                if self._count_zeros:
                    self._spend(take)
                parts.append(bytes(take))
            elif kind == RAW:
                self._check_raw(index)
                parts.append(
                    self._read_file(
                        self._offset[index] + within, take, self._where(index)
                    )
                )
            elif kind in _COMPRESSED:
                parts.append(self._decode_run(index)[within : within + take])
            else:
                self._refuse_kind(index)
            pos += take
        return b"".join(parts)

    def _check_raw(self, index: int) -> None:
        decoded = self._count[index] * SECTOR
        if self._length[index] != decoded:
            raise CorruptionError(
                f"{self._where(index)} stores {self._length[index]} bytes for "
                f"{decoded}: a raw run must store exactly its sectors"
            )

    def _refuse_kind(self, index: int) -> NoReturn:
        raise UnsupportedFeatureError(
            f"UDIF run type 0x{self._kind[index]:08x} (for disk sector "
            f"{self._start[index]}) is not supported"
        )

    # ── Checksums (the partition pass, design §7.2) ──────────────────────────────────

    def crc_covers(self, start: int, length: int) -> bool:
        """Whether every byte of the disk range is in a run of a table that stores a
        CRC-32: no gap between runs, and no table without one, inside the range."""
        if length <= 0:
            return False
        first = start // SECTOR
        end = -(-(start + length) // SECTOR)
        checked = array("B", bytes(len(self._kind)))
        for table in self.tables:
            if table.checksum is not None:
                for i in range(table.first_run, table.end_run):
                    checked[i] = 1
        starts = self._start
        index = bisect.bisect_right(starts, first) - 1
        if index < 0:
            return False
        pos = first
        while pos < end:
            if (
                index >= len(starts)
                or starts[index] > pos
                or pos >= starts[index] + self._count[index]
                or not checked[index]
            ):
                return False
            pos = starts[index] + self._count[index]
            index += 1
        return True

    def tables_over(self, start: int, length: int) -> list[int]:
        """The indexes in ``tables`` of the tables with a CRC-32 whose sectors share a
        byte with the disk range."""
        end = start + length
        return [
            i
            for i, table in enumerate(self.tables)
            if table.checksum is not None
            and _overlap(
                table.first_sector * SECTOR,
                (table.first_sector + table.sector_count) * SECTOR,
                start,
                end,
            )
        ]

    def table_crc(
        self, table: UdifTable, draw: Callable[[int], None] | None = None
    ) -> int:
        """The CRC-32 of ``table``'s runs as the format defines it: every run but the
        ignore runs, decoded, in sector order. One run is in memory at a time (a raw
        one in slices); a zero-fill run is folded in without its bytes. Decode errors
        raise, naming the run. ``draw(n)`` is told the size of each run that stores
        bytes (compressed or raw) before any of it is read, and may raise to stop:
        runs may share stored bytes, so even raw runs can read far more than the
        file holds."""
        crc = 0
        for index in range(table.first_run, table.end_run):
            kind = self._kind[index]
            size = self._count[index] * SECTOR
            if kind == IGNORE:
                continue
            if kind == ZERO_FILL:
                crc = crc32_zeros(crc, size)
            elif kind == RAW:
                self._check_raw(index)
                if draw is not None:
                    draw(size)
                for at in range(0, size, CHECK_SLICE):
                    n = min(CHECK_SLICE, size - at)
                    data = self._read_file(
                        self._offset[index] + at, n, self._where(index)
                    )
                    crc = zlib.crc32(data, crc)
            elif kind in _COMPRESSED:
                if draw is not None:
                    draw(size)
                crc = zlib.crc32(self._decode_run(index, keep=False), crc)
            else:
                self._refuse_kind(index)
        return crc

    def data_fork_crc(self) -> int:
        """The CRC-32 of the data fork's stored bytes, read in slices."""
        crc = 0
        start, length = self.koly.data_fork_offset, self.koly.data_fork_length
        for at in range(0, length, CHECK_SLICE):
            n = min(CHECK_SLICE, length - at)
            crc = zlib.crc32(self._read_file(start + at, n, "the UDIF data fork"), crc)
        return crc


class UdifSource(ReaderSource):
    """A :class:`~archivey.formats.ReaderSource` over ``length`` bytes of a UDIF
    image's disk from ``start``: a partition, read as a filesystem parser reads a
    file."""

    def __init__(self, image: UdifImage, start: int, length: int) -> None:
        self.image = image
        self.start = start
        self.length = length

        def read_at(offset: int, n: int) -> bytes:
            if offset >= length or n <= 0:
                return b""
            return image.read(start + offset, min(n, length - offset))

        def view(offset: int, n: int | None) -> BinaryIO:
            span = length - offset if n is None else min(n, length - offset)
            raw = DiskView(read_at, offset, max(0, span))
            return io.BufferedReader(raw, buffer_size=64 << 10)

        super().__init__(view, length, None, read_at)

    @override
    def read_exact(self, offset: int, n: int) -> bytes:
        data = self.read_at(offset, n)
        if len(data) < n:
            raise TruncatedError(
                f"the partition ends {len(data)} bytes into the {n} bytes at partition "
                f"offset {offset}"
            )
        return data


class DiskView(io.RawIOBase):
    """A seekable stream over ``length`` bytes of a :class:`UdifSource` from
    ``start``."""

    def __init__(
        self, read_at: Callable[[int, int], bytes], start: int, length: int
    ) -> None:
        self._read_at = read_at
        self._start = start
        self._length = length
        self._pos = 0

    @override
    def readable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True

    @override
    def tell(self) -> int:
        return self._pos

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            pos = offset
        elif whence == io.SEEK_CUR:
            pos = self._pos + offset
        elif whence == io.SEEK_END:
            pos = self._length + offset
        else:
            raise ValueError(f"invalid whence {whence}")
        if pos < 0:
            raise ValueError("negative seek position")
        self._pos = pos
        return pos

    @override
    def readinto(self, buffer: WriteableBuffer, /) -> int:
        # Released before the return: the caller may resize ``buffer`` next, which PyPy
        # refuses while a dropped view waits for a collection.
        with memoryview(buffer) as outer, outer.cast("B") as target:
            want = min(len(target), self._length - self._pos)
            if want <= 0:
                return 0
            data = self._read_at(self._start + self._pos, want)
            n = len(data)
            target[:n] = data
        self._pos += n
        return n
