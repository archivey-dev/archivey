"""The sessions of a raw CD image read without its ``.cue`` sheet, found from the
addresses in its sector headers.

Every Mode 1 and Mode 2 sector starts with the sync, then its own address on the disc
(minutes, seconds and frames in BCD, counted from two seconds before sector 0), then
its mode. A ``.bin`` holds the disc's tracks back to back, without the gaps a disc has
between sessions (lead-out, lead-in and pregap), so inside a track the address grows
with the position in the file, and at a session boundary it jumps ahead by the gap.
That places every data sector at its address, as a sheet does, and shows which
session a mount reads: the last one. With it, a ``.bin`` opened as a stream lists
what the same file lists by its path beside its sheet.

How the image is walked (:func:`last_session_source`):

- The last data sector near the end of the file is read first. When its address is
  as far past sector 0's as its position is, no address jumps: the image is one
  session and is read from its first track. That costs two reads (sector 0 and the
  tail), and a mixed-mode disc (data, then audio to the end) costs the same.
- Otherwise the file is split into runs: data sectors of one data mode whose address
  minus position is the same number (the run's offset). A run is followed by probing
  ahead in doubling steps and bisecting where a probe fails, so a run costs about two
  reads per doubling of its length, not one per sector. Sectors between runs that are
  not data (audio, a Form 2 postgap) are read in batches until the next data sector.
- Runs whose offsets differ by at least a lead-in (4 500 sectors) are in different
  sessions. The chosen track is the first run of the last session. Its volume
  descriptors are looked for from its sector 16 on (a pregap kept in the file puts
  them later), and checked as the sheet path checks them: the root directory's ``.``
  record must name its own sector (``cue_sheet.find_volume``, two sector reads per
  candidate).

A data sector is a Mode 1 or a Mode 2 Form 1 sector, whatever mode sector 0 is in: a
later session may be written in the other mode (a Mode 1 first session, then CD-ROM XA),
and each run is read in its own mode, as a sheet reads each track in the mode its
``TRACK`` line names.

Anything that does not fit (an address that goes backwards, more runs than a disc has
tracks, no primary volume descriptor in the last session, a root that does not name
itself) leaves the image read from its first track, and the ISO reader reports a
volume it sees after it (``ARCHIVE_UNREAD_SESSION``).
"""

from __future__ import annotations

import io
from dataclasses import dataclass, replace

from archivey.formats import ReaderSource
from archivey.internal.backends.cd_sectors import (
    HEADER_SIZE,
    LEAD_IN_SECTORS,
    RawSectorLayout,
    _SectorChecker,
    data_sector_address,
)
from archivey.internal.backends.cue_sheet import DiscSource, _Extent, find_volume

_MAX_RUNS = 256
"""A disc holds at most 99 tracks; the run-out sectors of each can add a run. More
runs than this are not a disc's layout, and the walk gives up."""

_TAIL_SECTORS = 32
"""Sectors read at the end of the file, in one read, to find its last data sector
(run-out sectors that are not data may follow it)."""

_BATCH_SECTORS = 64
"""Sectors read at once while looking for the next data sector."""


@dataclass(frozen=True)
class _Run:
    """Data sectors ``first`` to ``first + count`` of the file, at address
    ``first + offset`` and on, read with ``checker`` (their data mode)."""

    first: int
    count: int
    offset: int
    checker: _SectorChecker


class _Walk:
    def __init__(
        self, source: ReaderSource, checkers: tuple[_SectorChecker, ...], sectors: int
    ) -> None:
        self._source = source
        # The data modes a sector may be in, sector 0's first.
        self._checkers = checkers
        self._size = checkers[0].sector_size
        self.sectors = sectors

    def _data_in(self, header: bytes) -> tuple[int, _SectorChecker] | None:
        """The address a data sector names and the checker of its mode, or ``None``."""
        for checker in self._checkers:
            address = data_sector_address(checker, header)
            if address is not None:
                return address, checker
        return None

    def _address_in(self, header: bytes) -> int | None:
        found = self._data_in(header)
        return None if found is None else found[0]

    def _place(self, index: int) -> tuple[int, _SectorChecker] | None:
        """The offset of data sector ``index`` and the checker of its mode, or
        ``None`` if it is not one."""
        found = self._data_in(self._source.read_at(index * self._size, HEADER_SIZE))
        return None if found is None else (found[0] - index, found[1])

    def offset(self, index: int) -> int | None:
        place = self._place(index)
        return None if place is None else place[0]

    def last_data(self, first: int, end: int) -> tuple[int, int] | None:
        """The last data sector in ``[first, end)`` and its address, from one read."""
        size = self._size
        raw = self._source.read_at(first * size, (end - first) * size)
        for index in reversed(range(first, end)):
            at = (index - first) * size
            address = self._address_in(raw[at : at + HEADER_SIZE])
            if address is not None:
                return index, address
        return None

    def next_data(self, index: int, last: int) -> int | None:
        """The first data sector from ``index`` to ``last``, read in batches."""
        size = self._size
        while index <= last:
            count = min(_BATCH_SECTORS, last + 1 - index)
            raw = self._source.read_at(index * size, count * size)
            for k in range(count):
                if self._address_in(raw[k * size : k * size + HEADER_SIZE]) is not None:
                    return index + k
            index += count
        return None

    def run_end(self, first: int, place: tuple[int, _SectorChecker], last: int) -> int:
        """The last sector up to ``last`` of the run with ``place`` (its offset and
        mode) that holds ``first``. Probes ahead in doubling steps, then bisects."""
        good, step = first, 1
        bad = None
        while bad is None:
            probe = min(good + step, last)
            if probe == good:
                return good
            if self._place(probe) == place:
                good, step = probe, step * 2
            else:
                bad = probe
        while bad - good > 1:
            middle = (good + bad) // 2
            if self._place(middle) == place:
                good = middle
            else:
                bad = middle
        return good

    def runs(self, last: int) -> list[_Run] | None:
        """The runs from sector 0 to ``last``; ``None`` when the addresses do not
        describe a disc."""
        runs: list[_Run] = []
        index = 0
        while index <= last:
            place = self._place(index)
            if place is None:
                found = self.next_data(index, last)
                if found is None:
                    break
                index = found
                place = self._place(index)
                assert place is not None
            offset, checker = place
            if runs and offset < runs[-1].offset:
                return None  # an address that goes backwards
            end = self.run_end(index, place, last)
            runs.append(_Run(index, end + 1 - index, offset, checker))
            if len(runs) > _MAX_RUNS:
                return None
            index = end + 1
        return runs


class _ImageFile:
    """The raw image as the one file a :class:`DiscSource` reads its tracks from."""

    def __init__(self, source: ReaderSource, name: str) -> None:
        self._source = source
        self.name = name

    def read_at(self, offset: int, n: int) -> bytes:
        return self._source.read_at(offset, n)

    def close(self) -> None:
        pass  # the source is the caller's


def _raw_size(source: ReaderSource) -> int:
    size = source.size
    if size is None:
        with source.view(0) as whole:
            size = whole.seek(0, io.SEEK_END)
    return size


def last_session_source(
    source: ReaderSource, layout: RawSectorLayout, archive_name: str | None
) -> DiscSource | None:
    """The last data session of the raw image ``source``, as a :class:`DiscSource`
    placed by its sector addresses; ``None`` when the image is one session, or its
    addresses do not show a later one that holds an ISO 9660 volume."""
    raw_size = _raw_size(source)
    checker = _SectorChecker(layout, archive_name, raw_size, where="CD sector")
    # A later session may be in the other data mode (Mode 1, or Mode 2 Form 1).
    other = _SectorChecker(
        replace(layout, mode=3 - layout.mode, form2=False),
        archive_name,
        raw_size,
        where="CD sector",
    )
    size = checker.sector_size
    sectors = raw_size // size
    if sectors < 2:
        return None
    walk = _Walk(source, (checker, other), sectors)
    first_offset = walk.offset(0)
    if first_offset is None:
        return None
    tail = walk.last_data(max(1, sectors - _TAIL_SECTORS), sectors)
    if tail is None or tail[1] - tail[0] == first_offset:
        return None  # one session, or nothing after the first track to place
    runs = walk.runs(tail[0])
    if not runs:
        return None
    chosen_at = 0
    for at in range(1, len(runs)):
        if runs[at].offset - runs[at - 1].offset >= LEAD_IN_SECTORS:
            chosen_at = at
    if chosen_at == 0:
        return None
    extents = [
        _Extent(
            run.first + run.offset,
            run.count,
            0,
            run.first * size,
            run.checker,
            number,
        )
        for number, run in enumerate(runs, 1)
    ]
    chosen = extents[chosen_at]
    name = source.path.name if source.path is not None else archive_name or "image"
    image = _ImageFile(source, name)
    base = find_volume([image], extents, chosen)
    if base is None:
        return None
    return DiscSource(
        [image],
        extents,
        chosen,
        archive_name,
        base=base,
        path=source.path,
        hints=True,
    )
