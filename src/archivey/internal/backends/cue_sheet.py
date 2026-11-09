"""CD images described by a ``.cue`` sheet, read as the ISO 9660 filesystem a drive
would mount.

A ``.cue`` names the raw track files (``FILE "x.bin" BINARY``), the tracks in each
(``TRACK 01 MODE1/2352``, ``AUDIO``), where each starts (``INDEX 01 mm:ss:ff``, in 75ths
of a second), and with ``REM SESSION nn`` the session each belongs to. From it
:func:`disc_source` builds a :class:`DiscSource`: the disc's data sectors at their
absolute addresses, 2048 bytes of user data each, which the ISO reader reads as if it
were a plain image.

Which filesystem is read follows what an operating system mounts:

- the first data track of the last session that has one. On a mixed-mode disc (data,
  then audio) that is track 1; on an Enhanced CD (audio in session 1, data in session
  2) it is the data track; on a multisession data disc it is the newest session, whose
  directory tree also lists the files earlier sessions wrote;
- its volume descriptors are read at that track's start plus 16, as Linux does with
  the session offset, and every other address is absolute.

The track files hold no lead-out or lead-in, so a later session's addresses are not
file positions. The gap a recorder leaves between sessions is 11 400 sectors after the
first and 6 900 after each later one (lead-out, lead-in and the two-second pregap).
That is checked, not trusted: the root directory's first record (``.``) names its own
sector, so the base address is right when that sector holds it, and is searched for in
the track's first sectors when it does not.

A ``FILE`` name is taken only as a plain name in the ``.cue``'s own directory: a path,
``..`` or an absolute name is refused, and so is anything there that is not a regular
file (a FIFO, a device). A symlink there is followed, as the sheet's own path is. A
name that is not there exactly is matched without case, as sheets written on Windows
often spell ``DISC.BIN`` for ``disc.bin``.
"""

from __future__ import annotations

import bisect
import os
import re
import stat
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from archivey.exceptions import CorruptionError, TruncatedError, UnsupportedFeatureError
from archivey.formats import ReaderSource
from archivey.internal.backends.cd_sectors import (
    USER_DATA_SIZE,
    RawSectorLayout,
    _SectorChecker,
    cooked_access,
    load_sectors,
)
from archivey.terminal import quoted
from archivey.types import ArchiveFormat

# A sheet is a few lines per track and at most 99 tracks; a larger file is not one.
MAX_CUE_SIZE = 64 * 1024
_O_BINARY = getattr(os, "O_BINARY", 0)  # Windows: no newline translation
_FRAMES_PER_SECOND = 75
_FIRST_SESSION_GAP = 11_400
_LATER_SESSION_GAP = 6_900
# How far into a track the root directory is looked for when the computed base fails.
_ROOT_SEARCH_SECTORS = 4096
# The volume descriptor set: system area (16 sectors) plus at most this many.
_MAX_DESCRIPTORS = 64

_DATA_MODES = {
    "MODE1/2352": RawSectorLayout(mode=1, form2=False, sector_size=2352),
    "MODE1/2048": RawSectorLayout(mode=1, form2=False, sector_size=USER_DATA_SIZE),
    "MODE2/2352": RawSectorLayout(mode=2, form2=False, sector_size=2352),
}
_OTHER_SIZES = {"AUDIO": 2352, "CDG": 2448, "MODE2/2336": 2336, "CDI/2352": 2352}

_MSF = re.compile(r"\A([0-9]{1,3}):([0-9]{2}):([0-9]{2})\Z")


@dataclass
class CueTrack:
    number: int
    mode: str
    session: int
    index0: int | None = None  # frames from the start of its file
    index1: int | None = None
    pregap: int = 0  # PREGAP frames, not in the file

    @property
    def sector_size(self) -> int:
        layout = _DATA_MODES.get(self.mode)
        if layout is not None:
            assert layout.sector_size is not None
            return layout.sector_size
        return _OTHER_SIZES[self.mode]


@dataclass
class CueFile:
    name: str
    tracks: list[CueTrack] = field(default_factory=list)


def _is_number(text: str) -> bool:
    return text.isascii() and text.isdigit()


def _frames(text: str, line: int) -> int:
    match = _MSF.match(text)
    if match is None:
        raise CorruptionError(
            f"line {line} of the .cue sheet has a bad time {quoted(text)}"
        )
    minutes, seconds, frames = (int(g) for g in match.groups())
    if seconds >= 60 or frames >= _FRAMES_PER_SECOND:
        raise CorruptionError(
            f"line {line} of the .cue sheet has a bad time {quoted(text)}"
        )
    return (minutes * 60 + seconds) * _FRAMES_PER_SECOND + frames


def _file_name(rest: str, line: int) -> str:
    rest = rest.strip()
    if rest.startswith('"'):
        end = rest.find('"', 1)
        if end < 0:
            raise CorruptionError(f"line {line} of the .cue sheet has an open quote")
        return rest[1:end]
    parts = rest.rsplit(None, 1)
    return parts[0] if len(parts) == 2 else rest


def parse_cue(text: str) -> list[CueFile]:
    """The files and tracks a ``.cue`` sheet lists. Commands it does not use (``TITLE``,
    ``PERFORMER``, ``FLAGS``, other ``REM`` lines) are skipped."""
    files: list[CueFile] = []
    session = 1
    track: CueTrack | None = None
    for number, raw_line in enumerate(text.splitlines(), 1):
        words = raw_line.strip().split(None, 1)
        if not words:
            continue
        command = words[0].upper()
        rest = words[1] if len(words) > 1 else ""
        if command == "REM":
            parts = rest.split()
            if (
                len(parts) == 2
                and parts[0].upper() == "SESSION"
                and _is_number(parts[1])
            ):
                session = int(parts[1])
            continue
        if command == "FILE":
            files.append(CueFile(_file_name(rest, number)))
            track = None
        elif command == "TRACK":
            parts = rest.split()
            if not files or len(parts) != 2 or not _is_number(parts[0]):
                raise CorruptionError(f"line {number} of the .cue sheet is a bad TRACK")
            mode = parts[1].upper()
            if mode not in _DATA_MODES and mode not in _OTHER_SIZES:
                raise UnsupportedFeatureError(
                    f"the .cue sheet has a track of mode {quoted(parts[1])}, which archivey "
                    "does not know",
                    source_format=ArchiveFormat.ISO,
                )
            track = CueTrack(int(parts[0]), mode, session)
            files[-1].tracks.append(track)
            if sum(len(f.tracks) for f in files) > 99:
                raise CorruptionError("the .cue sheet lists more than 99 tracks")
        elif command == "INDEX":
            parts = rest.split()
            if track is None or len(parts) != 2 or not _is_number(parts[0]):
                raise CorruptionError(f"line {number} of the .cue sheet is a bad INDEX")
            if int(parts[0]) == 0:
                track.index0 = _frames(parts[1], number)
            elif int(parts[0]) == 1:
                track.index1 = _frames(parts[1], number)
        elif command == "PREGAP" and track is not None:
            track.pregap = _frames(rest.strip(), number)
    for cue_file in files:
        for cue_track in cue_file.tracks:
            if cue_track.index1 is None:
                raise CorruptionError(
                    f"track {cue_track.number} of the .cue sheet has no INDEX 01"
                )
    if not any(f.tracks for f in files):
        raise CorruptionError("the .cue sheet lists no tracks")
    return files


@dataclass(frozen=True)
class _Extent:
    """A run of a data track's sectors at their absolute address."""

    lba: int
    count: int
    file: int  # index into DiscSource._files
    file_offset: int  # byte offset of the run's first sector in its file
    checker: _SectorChecker
    track: int


class _TrackFile:
    """One track file, read under a lock (a position is shared)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        # Non-blocking, so a FIFO is refused by the check below instead of hanging
        # the open waiting for a writer.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _O_BINARY)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsupportedFeatureError(
                    f"the .cue sheet names {quoted(path.name)}, which is not a "
                    "regular file",
                    source_format=ArchiveFormat.ISO,
                )
        except BaseException:
            os.close(fd)
            raise
        self._fp: BinaryIO = os.fdopen(fd, "rb")  # closed by close()
        self._lock = threading.Lock()
        self.size = st.st_size

    def read_at(self, offset: int, n: int) -> bytes:
        with self._lock:
            self._fp.seek(offset)
            return self._fp.read(n)

    def close(self) -> None:
        self._fp.close()


class DiscSource(ReaderSource):
    """The data sectors of a disc a ``.cue`` sheet describes, at absolute addresses.

    Sectors 0 to the end of the volume descriptor set are read from the chosen track's
    start (``base``), as a drive mounting that session does; every other address is
    absolute. A sector in no data track (an audio track, a pregap, the gap between
    sessions) fails the read that reaches it.
    """

    def __init__(
        self,
        files: list[_TrackFile],
        extents: list[_Extent],
        chosen: _Extent,
        archive_name: str | None,
    ) -> None:
        self._files = files
        self._extents = sorted(extents, key=lambda e: e.lba)
        self._starts = [e.lba for e in self._extents]
        self.chosen = chosen
        self._archive_name = archive_name
        self.base = chosen.lba
        self._descriptor_end = 16  # the system area, until the set is measured
        size = max(e.lba + e.count for e in self._extents) * USER_DATA_SIZE
        view, read_at = cooked_access(self._load, size)
        super().__init__(view, size, None, read_at)
        self._descriptor_end = self._measure_descriptors()

    def _extent_of(self, sector: int) -> _Extent | None:
        at = bisect.bisect_right(self._starts, sector) - 1
        if at >= 0:
            extent = self._extents[at]
            if sector < extent.lba + extent.count:
                return extent
        return None

    def _load(self, first: int, end: int) -> bytes:
        if first < self._descriptor_end:
            # The system area and descriptors of the chosen session.
            physical = self.base + first
            end = min(end, self._descriptor_end)
        else:
            physical = first
        extent = self._extent_of(physical)
        if extent is None:
            raise CorruptionError(
                f"CD sector {physical} is in no data track of the .cue sheet (an audio "
                "track, a pregap, or the gap between sessions)",
                source_format=ArchiveFormat.ISO,
                archive_name=self._archive_name,
            )
        count = min(end - first, extent.lba + extent.count - physical)
        track_file = self._files[extent.file]
        data = load_sectors(
            track_file.read_at,
            extent.checker,
            physical - extent.lba,
            count,
            extent.file_offset,
            physical,
        )
        if not data:
            raise TruncatedError(
                f"{quoted(track_file.path.name)} ends inside track {extent.track}",
                source_format=ArchiveFormat.ISO,
                archive_name=self._archive_name,
            )
        return data

    def _measure_descriptors(self) -> int:
        end = 16
        while end < 16 + _MAX_DESCRIPTORS:
            self._descriptor_end = end + 1
            sector = self.read_at(end * USER_DATA_SIZE, USER_DATA_SIZE)
            end += 1
            if sector[1:6] != b"CD001" or sector[0] == 255:
                break
        # And the sector after the terminator, where mkisofs writes a version
        # descriptor that pycdlib reads.
        return end + 1

    def trailing_window(self, volume_end: int, limit: int) -> tuple[int, int]:
        """The cooked range after ``volume_end`` that the chosen track still holds as
        data sectors: the scan stops at the first one that is not (a Mode 2 Form 2
        postgap before the audio, the run-out sectors of a track-at-once track), as
        those are the disc's own and no read asks for them."""
        chosen = self.chosen
        lo = chosen.lba * USER_DATA_SIZE
        hi = (chosen.lba + chosen.count) * USER_DATA_SIZE
        start = min(max(volume_end, lo), hi)
        end = min(hi, start + limit)
        checker = chosen.checker
        read_at = self._files[chosen.file].read_at
        sector = start // USER_DATA_SIZE
        while sector * USER_DATA_SIZE < end:
            offset = chosen.file_offset + (sector - chosen.lba) * checker.sector_size
            if not checker.is_data_sector(read_at(offset, 24)):
                return start, max(start, sector * USER_DATA_SIZE)
            sector += 1
        return start, end

    def close(self) -> None:
        for track_file in self._files:
            track_file.close()


def _plain_name(name: str) -> bool:
    return (
        bool(name)
        and name not in (".", "..")
        and "/" not in name
        and "\\" not in name
        and not os.path.isabs(name)
        and ":" not in name
    )


def _beside(directory: Path, name: str) -> Path | None:
    """``name`` in ``directory``: exactly, or else the one entry that matches it
    without case. ``None`` when there is none, or more than one."""
    exact = directory / name
    if os.path.lexists(exact):
        return exact
    try:
        matches = [p for p in directory.iterdir() if p.name.lower() == name.lower()]
    except OSError:
        return None
    return matches[0] if len(matches) == 1 else None


def read_cue_text(path: Path, archive_name: str | None = None) -> str:
    """The text of the sheet at ``path``: UTF-8 (a BOM is dropped), else Latin-1."""
    with open(path, "rb") as fp:
        raw = fp.read(MAX_CUE_SIZE + 1)
    if len(raw) > MAX_CUE_SIZE:
        raise UnsupportedFeatureError(
            f"{quoted(path.name)} is over {MAX_CUE_SIZE} bytes: not a .cue sheet",
            source_format=ArchiveFormat.ISO,
            archive_name=archive_name,
        )
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _open_files(cue_path: Path, files: list[CueFile]) -> list[_TrackFile]:
    opened: list[_TrackFile] = []
    try:
        for cue_file in files:
            if not _plain_name(cue_file.name):
                raise UnsupportedFeatureError(
                    f"the .cue sheet names {quoted(cue_file.name)}; only a file beside the "
                    "sheet is read",
                    source_format=ArchiveFormat.ISO,
                )
            path = _beside(cue_path.parent, cue_file.name)
            try:
                if path is None:
                    raise FileNotFoundError(cue_file.name)
                opened.append(_TrackFile(path))
            except FileNotFoundError:
                # Not there, or a symlink to nothing. Other OSErrors (a permission
                # error) propagate as they do for the archive's own path.
                raise TruncatedError(
                    f"the .cue sheet names {quoted(cue_file.name)}, which is not beside it",
                    source_format=ArchiveFormat.ISO,
                ) from None
    except BaseException:
        for track_file in opened:
            track_file.close()
        raise
    return opened


def _layout_extents(
    files: list[CueFile], opened: list[_TrackFile], archive_name: str | None
) -> tuple[list[_Extent], list[tuple[int, CueTrack, int]]]:
    """Every data track as an extent at its absolute address, and the (session, track,
    lba) of every track. A later session's address uses the standard gap; the caller
    checks it."""
    extents: list[_Extent] = []
    tracks: list[tuple[int, CueTrack, int]] = []
    position = 0  # the absolute address of the current file's first sector
    shift = 0  # session gaps and PREGAPs so far
    session = 1
    first_index = files[0].tracks[0].index1 if files[0].tracks else 0
    assert first_index is not None
    for file_index, (cue_file, track_file) in enumerate(
        zip(files, opened, strict=True)
    ):
        sizes = {t.sector_size for t in cue_file.tracks}
        if len(sizes) > 1:
            raise UnsupportedFeatureError(
                f"{quoted(cue_file.name)} holds tracks of different sector sizes",
                source_format=ArchiveFormat.ISO,
            )
        size = sizes.pop() if sizes else 2352
        file_sectors = track_file.size // size
        for at, track in enumerate(cue_file.tracks):
            if track.session != session:
                gap = _FIRST_SESSION_GAP if session == 1 else _LATER_SESSION_GAP
                shift += gap * (track.session - session)
                session = track.session
            shift += track.pregap
            assert track.index1 is not None
            lba = position + track.index1 + shift - first_index
            if at + 1 < len(cue_file.tracks):
                following = cue_file.tracks[at + 1]
                stop = (
                    following.index0
                    if following.index0 is not None
                    else following.index1
                )
                assert stop is not None
            else:
                stop = file_sectors
            count = max(0, stop - track.index1)
            tracks.append((track.session, track, lba))
            layout = _DATA_MODES.get(track.mode)
            if layout is not None and count:
                checker = _SectorChecker(
                    layout, archive_name, track_file.size, where="CD sector"
                )
                extents.append(
                    _Extent(
                        lba,
                        count,
                        file_index,
                        track.index1 * size,
                        checker,
                        track.number,
                    )
                )
        position += file_sectors
    return extents, tracks


def _root_extent(read: Callable[[int], bytes]) -> int | None:
    """The root directory's sector, from the primary descriptor at sector 16."""
    pvd = read(16)
    if pvd[:6] != b"\x01CD001":
        return None
    (root,) = struct.unpack_from("<I", pvd, 156 + 2)
    return root


def _names_itself(sector: bytes, lba: int) -> bool:
    """Whether ``sector`` opens with a directory's ``.`` record naming ``lba``."""
    if len(sector) < 34 or sector[0] < 34 or sector[32] != 1 or sector[33] != 0:
        return False
    return struct.unpack_from("<I", sector, 2)[0] == lba


def _rebase(extents: list[_Extent], chosen: _Extent, delta: int) -> list[_Extent]:
    """``extents`` with the chosen track's session moved by ``delta`` sectors."""
    return [
        _Extent(e.lba + delta, e.count, e.file, e.file_offset, e.checker, e.track)
        if e.lba >= chosen.lba
        else e
        for e in extents
    ]


def disc_source(cue_path: Path, archive_name: str | None) -> DiscSource:
    """The disc ``cue_path`` describes, as a :class:`DiscSource` on its chosen track."""
    files = parse_cue(read_cue_text(cue_path, archive_name))
    opened = _open_files(cue_path, files)
    try:
        extents, tracks = _layout_extents(files, opened, archive_name)
        if not extents:
            raise UnsupportedFeatureError(
                "the .cue sheet lists no data track (an audio CD): there is no "
                "filesystem to list",
                source_format=ArchiveFormat.ISO,
                archive_name=archive_name,
            )
        data_tracks = {e.track for e in extents}
        session = max(s for s, track, _ in tracks if track.number in data_tracks)
        numbers = {t.number for s, t, _ in tracks if s == session}
        chosen = min((e for e in extents if e.track in numbers), key=lambda e: e.lba)
        extents = _settle_base(opened, extents, chosen)
        chosen = next(e for e in extents if e.track == chosen.track)
        return DiscSource(opened, extents, chosen, archive_name)
    except BaseException:
        for track_file in opened:
            track_file.close()
        raise


def _settle_base(
    opened: list[_TrackFile], extents: list[_Extent], chosen: _Extent
) -> list[_Extent]:
    """``extents`` with the chosen session at the address its root directory names."""
    track_file = opened[chosen.file]

    def relative(index: int) -> bytes:
        return load_sectors(
            track_file.read_at, chosen.checker, index, 1, chosen.file_offset, index
        )

    root = _root_extent(relative)
    if root is None:
        return extents  # not ISO 9660 here: pycdlib says so when it opens
    if root - chosen.lba in range(chosen.count) and _names_itself(
        relative(root - chosen.lba), root
    ):
        return extents
    for index in range(17, min(chosen.count, _ROOT_SEARCH_SECTORS)):
        if _names_itself(relative(index), root):
            return _rebase(extents, chosen, root - index - chosen.lba)
    return extents
