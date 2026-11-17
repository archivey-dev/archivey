"""Where a PE program's resources sit in the file, for an archive stored as one.

Some installers keep their archive as a *resource* of the setup program, inside its
``.rsrc`` section, rather than appending it after the program. Squirrel, the installer
Electron apps use on Windows, does this with a ZIP. Other resources (icons, version
strings) and other sections follow the archive. Those bytes belong to the program, not
to the archive, so when an archive ends inside one resource's data, its reader's
trailing-data check stops at that resource's end.

:class:`ProgramResources` answers one question, :meth:`ProgramResources.explains`, for
the ZIP, 7z and RAR readers' trailing-data checks. ``open_archive`` builds it for every
open of a format that can carry a self-extractor stub, the same way whether the format
was detected or named, so auto-detect and a forced ``format=`` report the same
diagnostics. It reads nothing until a reader asks, which only happens when a reader
already found a non-zero byte after its archive: an archive with no trailing bytes
pays nothing.

What is read is bounded: the first :data:`~archivey.internal.sfx.LAYOUT_PREFIX` bytes
for the headers, then at most :data:`RESOURCE_TABLES_READ` bytes from the start of the
resource directory, where linkers place the directory tables and the data entries.
An entry outside that window is not seen, and the archive is then reported as before.
"""

from __future__ import annotations

import struct
from typing import BinaryIO

from archivey.internal.sfx import LAYOUT_PREFIX, pe_headers

# Data directory 2 of the optional header: the resource directory.
_RESOURCE_DIRECTORY = 2

#: How many bytes of the resource section are read for its directory tables and data
#: entries. A directory table is 16 bytes plus 8 per entry and a data entry is 16, so
#: this holds a few thousand resources; real setup programs have tens.
RESOURCE_TABLES_READ = 64 * 1024

# The resource tree is type, then name, then language, then the data entry. A deeper
# subdirectory is not a resource, and the bound stops a table that names itself.
_MAX_DEPTH = 3
# Entries visited across the whole tree, a bound on the walk's work.
_MAX_ENTRIES = 4096
_SUBDIRECTORY = 0x80000000


class ProgramResources:
    """The resources of the PE program at the start of a seekable source, read once
    and only when first asked."""

    def __init__(self, source: BinaryIO, size: int) -> None:
        self._source = source
        self._size = size
        self._extents: tuple[tuple[int, int], ...] | None = None

    def explains(self, archive_end: int, nonzero_at: int) -> bool:
        """Whether the non-zero byte at ``nonzero_at`` belongs to the program, not to
        data after the archive that ends at ``archive_end``.

        True when the archive ends inside one resource's data (or exactly at its
        end) and ``nonzero_at`` lies at or past that resource's end: the archive is
        stored in that resource, and what follows the resource is the rest of the
        program. A non-zero byte between the archive's end and the resource's end is
        not explained. Both offsets count from the start of the source.
        """
        return any(
            start < archive_end <= end <= nonzero_at for start, end in self.extents()
        )

    def extents(self) -> tuple[tuple[int, int], ...]:
        """Each resource's data as ``(start, end)`` file offsets; empty when the
        source is not a PE or its resource directory does not parse."""
        if self._extents is None:
            self._extents = self._read_extents()
        return self._extents

    def _read_extents(self) -> tuple[tuple[int, int], ...]:
        head = self._read(0, LAYOUT_PREFIX)
        headers = pe_headers(head)
        if headers is None or len(headers.data_directories) <= _RESOURCE_DIRECTORY:
            return ()
        rva, size = headers.data_directories[_RESOURCE_DIRECTORY]
        if not size:
            return ()
        window = min(size, RESOURCE_TABLES_READ)
        base = headers.file_offset(rva, 16)
        if base is None:
            return ()
        tables = self._read(base, min(window, self._size - base))
        extents: list[tuple[int, int]] = []
        for data_rva, data_size in _data_entries(tables):
            start = headers.file_offset(data_rva, data_size)
            if start is not None and data_size and start + data_size <= self._size:
                extents.append((start, start + data_size))
        return tuple(extents)

    def _read(self, offset: int, length: int) -> bytes:
        source = self._source
        position = source.tell()
        try:
            source.seek(offset)
            return source.read(max(0, min(length, self._size - offset)))
        finally:
            source.seek(position)


def _data_entries(tables: bytes) -> list[tuple[int, int]]:
    """The ``(rva, size)`` of every data entry reachable from the root table at the
    start of ``tables``, within the window, the depth bound and the entry bound."""
    found: list[tuple[int, int]] = []
    pending = [(0, 0)]
    visited = 0
    while pending:
        table, depth = pending.pop()
        if table + 16 > len(tables):
            continue
        named, numbered = struct.unpack_from("<HH", tables, table + 12)
        for index in range(named + numbered):
            visited += 1
            if visited > _MAX_ENTRIES:
                return found
            entry = table + 16 + index * 8
            if entry + 8 > len(tables):
                break
            (target,) = struct.unpack_from("<I", tables, entry + 4)
            if target & _SUBDIRECTORY:
                if depth + 1 < _MAX_DEPTH:
                    pending.append((target & ~_SUBDIRECTORY, depth + 1))
            elif target + 8 <= len(tables):
                found.append(struct.unpack_from("<II", tables, target))
    return found
