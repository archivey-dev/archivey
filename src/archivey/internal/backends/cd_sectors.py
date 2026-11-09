"""Raw CD sector images (the ``.bin`` of a ``.bin``/``.cue`` pair), read as plain ISO.

A raw dump keeps every sector whole: a 12-byte sync, a 4-byte header (address and
mode), the payload, and error-correction bytes, 2352 bytes in all, or 2448 with 96
bytes of subchannel data after it. A plain ``.iso`` keeps only the 2048 bytes of user
data of each sector. For the two data layouts, Mode 1 and Mode 2 Form 1, stripping
every sector to those 2048 bytes gives a byte-identical ``.iso``, so the ISO reader
reads the image through a view that does just that (:func:`cooked_source`).

Each sector read is checked: its sync, and its mode byte (and for Mode 2 the Form 1
bit of the subheader) must match the first sector's. A sector that is not a data
sector of that layout (an audio track after the data track, a Form 2 sector of a
Video CD or an XA file, or bytes at a shifted offset) fails the read rather than
handing the ISO reader 2048 wrong bytes. The EDC and ECC bytes are not checked.

Only the first track is read: without the ``.cue`` sheet nothing says where a later
track starts, and on a mixed-mode disc (data first, audio after) the filesystem is
all in the first one.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from archivey.exceptions import CorruptionError, UnsupportedFeatureError
from archivey.formats import ReaderSource
from archivey.internal.overrides import override
from archivey.types import ArchiveFormat

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

RAW_SECTOR_SYNC = b"\x00" + b"\xff" * 10 + b"\x00"
"""The 12 bytes that open every sector of a raw dump. A plain ``.iso`` never starts
with them: its first 32 KiB is the system area, zeros or a boot record."""

RAW_SECTOR_SIZES = (2352, 2448)
"""A full raw sector, and the same with 96 bytes of subchannel data appended."""

USER_DATA_SIZE = 2048

PROBE_SIZE = max(RAW_SECTOR_SIZES) + len(RAW_SECTOR_SYNC)
"""Bytes from the start of the file that :func:`raw_sector_layout` needs."""

# How many sectors one read of the underlying source covers (about 150 KB raw).
_SECTORS_PER_READ = 64


@dataclass(frozen=True)
class RawSectorLayout:
    """What the first sector (and where the second one starts) says about the image."""

    mode: int
    form2: bool
    sector_size: int | None
    """2352 or 2448; ``None`` when no second sector starts at either."""

    @property
    def readable(self) -> bool:
        """Whether the ISO reader can read the image through :func:`cooked_source`."""
        return self.mode in (1, 2) and not self.form2 and self.sector_size is not None

    @property
    def data_offset(self) -> int:
        """Where the 2048 bytes of user data start in a sector: after the 16-byte
        header, and for Mode 2 also after the 8-byte subheader."""
        return 16 if self.mode == 1 else 24

    def describe(self) -> str:
        if self.mode == 1:
            text = "Mode 1"
        elif self.mode == 2:
            text = "Mode 2 Form 2" if self.form2 else "Mode 2 Form 1"
        else:
            text = f"unknown sector mode {self.mode}"
        if self.sector_size is not None:
            text += f", {self.sector_size}-byte sectors"
        return text

    def raw_range(self, start: int, end: int) -> tuple[int, int]:
        """The raw bytes holding cooked bytes ``[start, end)``: whole sectors."""
        assert self.sector_size is not None
        if end <= start:
            raw = start // USER_DATA_SIZE * self.sector_size
            return raw, raw
        first = start // USER_DATA_SIZE
        last = (end - 1) // USER_DATA_SIZE + 1
        return first * self.sector_size, last * self.sector_size


def raw_sector_layout(head: bytes) -> RawSectorLayout | None:
    """The layout of a raw CD sector image starting with ``head``, else ``None``.

    ``head`` is the first :data:`PROBE_SIZE` bytes of the file (fewer when it is
    shorter). Byte 15 is the sector mode. For Mode 2, bit ``0x20`` of the submode byte
    (offset 18, in the subheader) separates Form 1, whose 2048-byte payload holds a
    filesystem, from Form 2, whose 2324-byte payload is video or audio and holds none.
    The sector size is where the second sync lands.
    """
    if not head.startswith(RAW_SECTOR_SYNC) or len(head) < 24:
        return None
    mode = head[15]
    form2 = mode == 2 and bool(head[18] & 0x20)
    sizes = [
        size
        for size in RAW_SECTOR_SIZES
        if head[size : size + len(RAW_SECTOR_SYNC)] == RAW_SECTOR_SYNC
    ]
    return RawSectorLayout(mode, form2, sizes[0] if sizes else None)


class _SectorChecker:
    """Checks raw sectors against the layout, and knows the image's cooked size."""

    def __init__(
        self, layout: RawSectorLayout, archive_name: str | None, raw_size: int
    ) -> None:
        assert layout.sector_size is not None
        self.layout = layout
        self.sector_size = layout.sector_size
        self.archive_name = archive_name
        self.raw_size = raw_size
        full, rest = divmod(raw_size, self.sector_size)
        tail = max(0, min(USER_DATA_SIZE, rest - layout.data_offset))
        self.cooked_size = full * USER_DATA_SIZE + tail

    def _is_form2(self, sector: bytes) -> bool:
        return self.layout.mode == 2 and bool(sector[18] & 0x20)

    def problem(self, sector: bytes) -> str | None:
        """Why ``sector`` is not a data sector of this layout, or ``None``."""
        if len(sector) < self.layout.data_offset:
            return None  # a cut sector: its payload is short, which the size says
        if sector[:12] != RAW_SECTOR_SYNC:
            return "it does not start with the sector sync"
        if sector[15] != self.layout.mode:
            return f"it is a mode {sector[15]} sector, not mode {self.layout.mode}"
        if self._is_form2(sector):
            return "it is a Mode 2 Form 2 sector"
        return None

    def check(self, index: int, sector: bytes) -> None:
        problem = self.problem(sector)
        if problem is None:
            return
        if self._is_form2(sector):
            raise UnsupportedFeatureError(
                f"Raw CD sector {index} is a Mode 2 Form 2 sector (video or audio, as "
                "on a Video CD or in a CD-XA file); its payload is not ISO 9660 data, "
                "and reading it is not supported.",
                source_format=ArchiveFormat.ISO,
                archive_name=self.archive_name,
            )
        raise CorruptionError(
            f"Raw CD sector {index} is not a {self.layout.describe()} data sector: "
            f"{problem}. The data track may end before this point (a later track "
            "needs the .cue sheet), or the image is damaged.",
            source_format=ArchiveFormat.ISO,
            archive_name=self.archive_name,
        )

    def is_data_sector(self, sector: bytes) -> bool:
        return self.problem(sector) is None


class _CookedView(io.RawIOBase):
    """``length`` bytes of user data from cooked offset ``start``, as a stream."""

    def __init__(
        self,
        source: ReaderSource,
        checker: _SectorChecker,
        start: int,
        length: int | None,
    ) -> None:
        super().__init__()
        self._source = source
        self._checker = checker
        size = checker.cooked_size
        self._start = min(start, size)
        end = size if length is None else min(size, self._start + max(0, length))
        self._length = end - self._start
        self._pos = 0
        # The user data of a run of sectors, back to back, from cooked _cache_at.
        self._cache_at = 0
        self._cache = b""

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
            raise ValueError(f"invalid whence ({whence})")
        if pos < 0:
            raise ValueError(f"negative seek position {pos}")
        self._pos = pos
        return pos

    def _load(self, sector: int) -> None:
        checker = self._checker
        size = checker.sector_size
        last = (self._start + self._length - 1) // USER_DATA_SIZE + 1
        count = max(1, min(_SECTORS_PER_READ, last - sector))
        raw = self._source.read_at(sector * size, count * size)
        offset = checker.layout.data_offset
        parts = []
        for i in range(0, len(raw), size):
            one = raw[i : i + size]
            if i and not checker.is_data_sector(one):
                # Read ahead, not asked for: the sector fails only when it is read.
                break
            checker.check(sector + i // size, one)
            parts.append(one[offset : offset + USER_DATA_SIZE])
        self._cache_at = sector * USER_DATA_SIZE
        self._cache = b"".join(parts)

    @override
    def readinto(self, buffer: WriteableBuffer, /) -> int:
        target = memoryview(buffer).cast("B")
        want = min(len(target), self._length - self._pos)
        if want <= 0:
            return 0
        at = self._start + self._pos
        if not self._cache_at <= at < self._cache_at + len(self._cache):
            self._load(at // USER_DATA_SIZE)
        inner = at - self._cache_at
        chunk = self._cache[inner : inner + want]
        if not chunk:
            return 0
        n = len(chunk)
        target[:n] = chunk
        self._pos += n
        return n


class CookedSource(ReaderSource):
    """A :class:`ReaderSource` over a raw sector image's user data.

    ``raw_range`` maps a cooked byte range back to the raw sectors that hold it, for
    the read hints a reader hands archivey; ``data_end`` finds where the data track
    stops after a point, for the ISO reader's trailing-data check.
    """

    def __init__(
        self,
        raw: ReaderSource,
        layout: RawSectorLayout,
        raw_size: int,
        archive_name: str | None,
    ) -> None:
        checker = _SectorChecker(layout, archive_name, raw_size)
        self.layout = layout
        self._raw = raw
        self._checker = checker

        def view(start: int, length: int | None) -> BinaryIO:
            return io.BufferedReader(  # type: ignore[return-value]
                _CookedView(raw, checker, start, length), buffer_size=USER_DATA_SIZE
            )

        def read_at(offset: int, n: int) -> bytes:
            with view(offset, n) as stream:
                return stream.read(n)

        super().__init__(view, checker.cooked_size, raw.path, read_at)

    @property
    def raw_size(self) -> int:
        """The length of the raw image file."""
        return self._checker.raw_size

    def raw_range(self, start: int, end: int) -> tuple[int, int]:
        lo, hi = self.layout.raw_range(start, end)
        return min(lo, self._checker.raw_size), min(hi, self._checker.raw_size)

    def data_end(self, start: int, limit: int) -> int:
        """The cooked offset where the data sectors from ``start`` stop.

        Reads sector headers until one is not a data sector of the layout (the next
        track, which only the ``.cue`` sheet describes), the file ends, or ``limit``
        cooked bytes are covered, whichever comes first.
        """
        checker = self._checker
        size = checker.sector_size
        sector = start // USER_DATA_SIZE
        end = min(checker.cooked_size, start + limit)
        while sector * USER_DATA_SIZE < end:
            header = self._raw.read_at(sector * size, 24)
            if not checker.is_data_sector(header):
                return max(start, sector * USER_DATA_SIZE)
            sector += 1
        return end


def cooked_source(
    source: ReaderSource, layout: RawSectorLayout, archive_name: str | None
) -> CookedSource:
    """``source``'s user data, sector by sector, for a readable ``layout``."""
    size = source.size
    if size is None:
        with source.view(0) as whole:
            size = whole.seek(0, io.SEEK_END)
    return CookedSource(source, layout, size, archive_name)
