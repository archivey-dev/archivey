"""Salvage mode for 7z (``open_archive(salvage=True)``): finding an end header the
start header no longer leads to.

The default open reads the start header, checks its CRC, and reads the next header
where it says. When that fails, a salvage reader tries the rules of
``openspec/changes/salvage-7z`` decision 2, in order, and takes the first that
passes:

- R1: the stored next-header offset and size, when the bytes there pass the stored
  next-header CRC (only the start header's own CRC field was damaged);
- R2: each change of one byte of the start header under which its stored CRC passes,
  when the next header that candidate names passes the candidate's next-header CRC;
- R3: a span in the file's tail whose CRC-32 is the stored next-header CRC;
- R4: for a start header that is zero, a header in the last 1 MiB that starts with
  ``17 06`` or ``01 04`` and parses to its ``kEnd``, followed only by zero bytes.

Everything here is pure on bytes, through a ``read_at(offset, size)`` of the archive
counted from its signature header. The reader parses and decodes what is found
(``SevenZipReader``).
"""

from __future__ import annotations

import re
import struct
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Literal

from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.sevenzip_parser import (
    MAX_NEXT_HEADER_SIZE,
    SIGNATURE_HEADER_SIZE,
    parse_header_prefix,
)
from archivey.internal.salvage import ARCHIVE_LAYER, SalvageState

ReadAt = Callable[[int, int], bytes]

# R3c and R4 look this far back from the end of the file for a header's first bytes.
# An encoded next header is under 100 bytes; only the plain header of a large archive
# (``-mhc=off``) is longer.
TAIL_SEARCH = 1 << 20
# R3 ends a span at most this far into the run of zero bytes that ends the file.
ZERO_RUN_ENDS = 64 << 10
# The first two bytes of a plain or encoded next header R3c tries: kEncodedHeader
# then kPackInfo, and kHeader then kArchiveProperties, kMainStreamsInfo or kFilesInfo.
_R3C_STARTS = re.compile(rb"(?=\x17\x06|\x01[\x02\x04\x05])")
_R4_STARTS = re.compile(rb"(?=\x17\x06|\x01\x04)")

Rule = Literal["R1", "R2", "R3a", "R3b", "R3c", "R4", "next_header", "copy"]

_RULE_TEXT: dict[str, str] = {
    "R1": "its stored next-header offset and size, whose bytes pass the stored "
    "next-header CRC (only the start header's own CRC was damaged)",
    "R2": "a change of one of its bytes under which both its CRC and the next "
    "header's CRC pass",
    "R3a": "a search of the file's tail for the stored next-header CRC, with the "
    "stored size",
    "R3b": "a search of the file's tail for the stored next-header CRC, from the "
    "stored offset",
    "R3c": "a search of the file's tail for the stored next-header CRC, from a "
    "header's first bytes",
    "R4": "a search of the file's last 1 MiB for an end header that parses to its "
    "end, the start header being zero",
    "next_header": "parsing the next header, which fails its CRC, as it stands",
    "copy": "the walk of the packed area, as a copy of the end header whose pack "
    "layout agrees with the streams before it",
}


@dataclass(frozen=True)
class EndHeaderFind:
    """An end header salvage found where the start header no longer leads.

    ``start`` is where it starts, counted from the signature header, and ``data`` its
    bytes. ``crc_checked`` is whether a CRC-32 over those bytes confirmed them (R1 to
    R3); R4 and a next header that failed its CRC are checked only by their parse,
    and by an encoded header's folder CRC.
    """

    start: int
    data: bytes
    rule: Rule
    crc_checked: bool

    @property
    def method(self) -> Literal["header_repair", "header_search"]:
        """``SalvageScanContext.method`` for the members listed from it: stored
        fields corrected under a CRC, or a header found by a search."""
        if self.rule in ("R1", "R2", "next_header"):
            return "header_repair"
        return "header_search"

    @property
    def description(self) -> str:
        return _RULE_TEXT[self.rule]


def _fields(start_header: bytes) -> tuple[int, int, int]:
    """``(NextHeaderOffset, NextHeaderSize, NextHeaderCRC)`` of the 20 bytes."""
    return struct.unpack("<QQI", start_header)


def _span(
    read_at: ReadAt, file_size: int, offset: int, size: int
) -> tuple[int, bytes] | None:
    """The next header ``offset`` and ``size`` name, as ``(start, bytes)``, when it is
    a plausible span of the file: not empty, within the parser's limit, inside the
    file."""
    start = SIGNATURE_HEADER_SIZE + offset
    if not 0 < size <= MAX_NEXT_HEADER_SIZE or start + size > file_size:
        return None
    data = read_at(start, size)
    if len(data) != size:
        return None
    return start, data


def repair_stored_fields(
    start_header: bytes, read_at: ReadAt, file_size: int
) -> EndHeaderFind | None:
    """R1: the stored offset and size, when the next header there passes the stored
    next-header CRC. The damage was then in ``StartHeaderCRC`` alone."""
    offset, size, crc = _fields(start_header)
    span = _span(read_at, file_size, offset, size)
    if span is None or zlib.crc32(span[1]) != crc:
        return None
    return EndHeaderFind(span[0], span[1], "R1", crc_checked=True)


def one_byte_candidates(start_header: bytes, stored_crc: int) -> Iterator[bytes]:
    """R2's candidates: each start header that differs from ``start_header`` in one
    byte and whose CRC-32 is ``stored_crc``, in byte order. 20 x 255 tries."""
    for index in range(len(start_header)):
        head = start_header[:index]
        tail = start_header[index + 1 :]
        prefix_crc = zlib.crc32(head)
        for value in range(256):
            if value == start_header[index]:
                continue
            candidate_crc = zlib.crc32(tail, zlib.crc32(bytes((value,)), prefix_crc))
            if candidate_crc == stored_crc:
                yield head + bytes((value,)) + tail


def repair_one_byte(
    start_header: bytes, stored_crc: int, read_at: ReadAt, file_size: int
) -> EndHeaderFind | None:
    """R2: the first one-byte change under which the stored start-header CRC passes
    and the next header it names passes the changed next-header CRC. Both CRCs
    confirm it: 64 bits."""
    for candidate in one_byte_candidates(start_header, stored_crc):
        offset, size, crc = _fields(candidate)
        span = _span(read_at, file_size, offset, size)
        if span is not None and zlib.crc32(span[1]) == crc:
            return EndHeaderFind(span[0], span[1], "R2", crc_checked=True)
    return None


class TailBudget:
    """The bytes of the file's tail R3 and R4 examine, counted once against
    ``SalvageLimits.max_search_bytes``.

    ``claim(lo, file_size)`` gives the lowest offset the search may examine: ``lo``
    when the budget pays for every byte from there to the end, else as far back from
    the end as the budget reaches. Bytes already claimed are not counted again. When
    the budget fell short, :meth:`stopped` records the ``search_limit`` region.
    """

    def __init__(self, state: SalvageState) -> None:
        self._state = state
        self._claimed_from: int | None = None
        self.short = False
        self._wanted_from = 0

    def claim(self, lo: int, file_size: int) -> int:
        lo = max(lo, SIGNATURE_HEADER_SIZE)
        start = file_size if self._claimed_from is None else self._claimed_from
        if lo >= start:
            return lo
        want = start - lo
        remaining = self._state.remaining_bytes()
        if self._state.limit_reached:
            remaining = 0
        if remaining is not None and remaining < want:
            self.short = True
            self._wanted_from = lo
            want = remaining
        self._state.searched_bytes += want
        self._claimed_from = start - want
        return self._claimed_from

    def stopped(self, file_size: int) -> None:
        """Record that the budget stopped the tail search, once."""
        if not self.short or self._state.limit_reached:
            return
        self._state.limit_reached = True
        examined = file_size if self._claimed_from is None else self._claimed_from
        self._state.record_search_limit(
            layer=ARCHIVE_LAYER,
            started_at=self._wanted_from,
            examined_from=examined,
            stopped_at=examined,
        )


def _tail_ends(tail: bytes, tail_start: int, file_size: int) -> list[int]:
    """R3's candidate ends, file offsets: the end of the file, and each offset in the
    run of zero bytes that ends it after its first zero byte (a header ends with its
    ``kEnd``), up to :data:`ZERO_RUN_ENDS` of that run, nearest the data first."""
    last_nonzero = len(tail.rstrip(b"\x00"))
    first = tail_start + last_nonzero + 1
    if last_nonzero == len(tail):
        return [file_size]
    return list(range(first, min(file_size, first + ZERO_RUN_ENDS) + 1))


def search_tail_crc(
    start_header: bytes, read_at: ReadAt, file_size: int, budget: TailBudget
) -> EndHeaderFind | None:
    """R3: a span of the file's tail whose CRC-32 is the stored next-header CRC.

    R3a keeps the stored size and R3b the stored offset, over the last
    ``MAX_NEXT_HEADER_SIZE`` bytes; R3c keeps neither and starts only at a header's
    first two bytes, over the last :data:`TAIL_SEARCH` bytes. Each span ends at one
    of :func:`_tail_ends` or at the stored end when that is inside the file.
    """
    offset, size, crc = _fields(start_header)
    stored_start = SIGNATURE_HEADER_SIZE + offset
    stored_end = stored_start + size
    # The bytes R3a and R3b need: spans of the stored size ending near the end, and
    # the stored start, each within the parser's limit on a next header.
    lo = file_size - TAIL_SEARCH
    if 0 < size <= MAX_NEXT_HEADER_SIZE:
        lo = min(lo, file_size - ZERO_RUN_ENDS - size)
    if file_size - MAX_NEXT_HEADER_SIZE <= stored_start < file_size:
        lo = min(lo, stored_start)
    lo = budget.claim(lo, file_size)
    if lo >= file_size:
        return None
    tail = read_at(lo, file_size - lo)
    ends = _tail_ends(tail, lo, file_size)
    if lo < stored_end < file_size and stored_end not in ends:
        ends.append(stored_end)

    def crc_of(start: int, end: int) -> int:
        return zlib.crc32(tail[start - lo : end - lo])

    if 0 < size <= MAX_NEXT_HEADER_SIZE:
        for end in ends:
            start = end - size
            if start >= lo and crc_of(start, end) == crc:
                return EndHeaderFind(start, tail[start - lo : end - lo], "R3a", True)
    if lo <= stored_start < file_size:
        for end in ends:
            if stored_start < end <= stored_start + MAX_NEXT_HEADER_SIZE and (
                crc_of(stored_start, end) == crc
            ):
                data = tail[stored_start - lo : end - lo]
                return EndHeaderFind(stored_start, data, "R3b", True)
    search_lo = max(lo, file_size - TAIL_SEARCH)
    for start in _starts_from_end(_R3C_STARTS, tail, search_lo - lo, lo):
        for end in ends:
            if end > start and crc_of(start, end) == crc:
                return EndHeaderFind(start, tail[start - lo : end - lo], "R3c", True)
    return None


def _starts_from_end(
    pattern: re.Pattern[bytes], tail: bytes, first: int, tail_start: int
) -> list[int]:
    """The file offsets in ``tail`` from index ``first`` where ``pattern`` matches,
    nearest the end first."""
    found = [tail_start + m.start() for m in pattern.finditer(tail, first)]
    found.reverse()
    return found


def header_parses_to_end(data: bytes) -> int | None:
    """The length of the header block that starts ``data`` when it parses to its
    final ``kEnd``, or ``None``. Only the structure is checked: no limit applies
    here (the header's own size bounds every count), and the caller loads what
    passes under the reader's limits."""
    try:
        _, consumed = parse_header_prefix(data, max_members=None)
    except (
        CorruptionError,
        TruncatedError,
        UnsupportedFeatureError,
        ResourceLimitError,
    ):
        return None
    return consumed


def zeroed_start_candidates(
    read_at: ReadAt, file_size: int, budget: TailBudget
) -> Iterator[tuple[int, bytes]]:
    """R4's candidates, nearest the end first: each header in the last
    :data:`TAIL_SEARCH` bytes that starts with ``17 06`` or ``01 04`` and parses to
    its ``kEnd`` with only zero bytes after it, as ``(start, header bytes)``. The
    caller decodes an encoded one and keeps the first that passes."""
    lo = budget.claim(file_size - TAIL_SEARCH, file_size)
    if lo >= file_size:
        return
    tail = read_at(lo, file_size - lo)
    for start in _starts_from_end(_R4_STARTS, tail, 0, lo):
        index = start - lo
        consumed = header_parses_to_end(tail[index:])
        if consumed is None:
            continue
        if any(tail[index + consumed :]):
            continue
        yield lo + index, tail[index : index + consumed]


__all__ = [
    "TAIL_SEARCH",
    "EndHeaderFind",
    "TailBudget",
    "header_parses_to_end",
    "one_byte_candidates",
    "repair_one_byte",
    "repair_stored_fields",
    "search_tail_crc",
    "zeroed_start_candidates",
]
