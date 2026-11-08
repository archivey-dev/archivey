"""A Microsoft cabinet reader, written against ``archivey.formats``.

The layout, from the Microsoft Cabinet Format specification (MS-CAB) and libmspack's
``cabd.c``: a 36-byte ``CFHEADER``, optional reserve sizes and reserve area, then one
``CFFOLDER`` record per folder and, at ``coffFiles``, one ``CFFILE`` record per file. A
folder is one compressed stream, stored as ``CFDATA`` blocks of at most 32 KiB of output
each; a file is a range of its folder's output. The blocks each carry a checksum over
their stored bytes, which the read checks (0 means none).

A folder is stored, MSZIP (one raw deflate stream per block, each with the previous
block's output as its dictionary), LZX (one bit stream over all the blocks, decoded by
:mod:`~archivey.internal.streams.codecs.lzx_decoder`) or Quantum, which archivey lists
but does not read. A compressed folder is solid: a file is reached by decoding its
folder from the start. The reader keeps the folder decoder the last member stream left
behind, so members read in order decode each folder once.

Cabinet sets (a folder continued in the next ``.cab``) are refused. The handbook page
is ``dev-docs/formats/cab.md``.
"""

from __future__ import annotations

import functools
import io
import operator
import struct
import sys
import threading
import zlib
from collections.abc import Iterator
from typing import TYPE_CHECKING, NamedTuple

from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    IndexedFormatHandler,
    IndexedReader,
    Magic,
    MemberData,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.listing_limits import metadata_limit_error
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.lzx_decoder import (
    FRAME_SIZE,
    MAX_WINDOW_BITS,
    MIN_WINDOW_BITS,
    LzxDecoder,
)
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    MemberType,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

MAGIC = b"MSCF\0\0\0\0"

_HEADER = struct.Struct("<4sIIIIIBBHHHHH")
_RESERVE = struct.Struct("<HBB")
_FOLDER = struct.Struct("<IHH")
_FILE = struct.Struct("<IIHHHH")
_DATA = struct.Struct("<IHH")

_PREV_CABINET = 0x0001
_NEXT_CABINET = 0x0002
_RESERVE_PRESENT = 0x0004

# CFFILE.iFolder values that continue a file from or into another cabinet.
_CONTINUED = 0xFFFD

# cabd.c reads a name (and a set's cabinet and disk names) into a 256-byte buffer and
# refuses one with no NUL in it.
_NAME_MAX = 256
# A block decodes to at most 32 KiB, and stores at most 6 KiB more (cab.h).
_BLOCK_MAX = 32768
_INPUT_MAX = _BLOCK_MAX + 6144

_STORED = 0
_MSZIP = 1
_QUANTUM = 2
_LZX = 3
_METHODS = {
    _STORED: CompressionAlgorithm.STORED,
    _MSZIP: CompressionAlgorithm.DEFLATE,
    _QUANTUM: CompressionAlgorithm.QUANTUM,
    _LZX: CompressionAlgorithm.LZX,
}
_METHOD_NAMES = {_STORED: "stored", _MSZIP: "MSZIP", _QUANTUM: "Quantum", _LZX: "LZX"}

# Read the file table this many bytes at a time.
_TABLE_CHUNK = 65536


class _Folder(NamedTuple):
    start: int
    """Where its first CFDATA block starts."""
    blocks: int
    method: int
    window_bits: int


class _Block(NamedTuple):
    payload: int
    """Where its stored bytes start."""
    stored: int
    decoded: int
    checksum: int


# ``_A_EXEC`` and ``_A_NAME_IS_UTF``: bits a cabinet gives its own meaning, which in a
# Windows attribute mask are FILE_ATTRIBUTE_DEVICE and FILE_ATTRIBUTE_NORMAL.
_CAB_ONLY_ATTRIBUTES = 0x40 | 0x80

# What one block costs in a kept block table, as ``max_metadata_bytes`` weighs it: about
# 128 bytes measured for empty blocks, more once offsets and checksums outgrow the small
# ints Python shares. A 4 GiB cabinet of full blocks keeps about 32 MiB.
_BLOCK_WEIGHT = 256


class _BlockTable(NamedTuple):
    blocks: tuple[_Block, ...]
    output: tuple[int, ...]
    """Where each block's output starts in the folder's output, and, last, the total."""
    complete: bool
    """``False`` when the cabinet ends before the folder's last block header."""


class _Location(NamedTuple):
    folder: int
    offset: int


def _checksum(data: bytes, seed: int = 0) -> int:
    """libmspack's ``cabd_checksum``: the little-endian 32-bit words XORed together,
    then the 1 to 3 bytes left, the first one highest."""
    whole = len(data) & ~3
    words = (
        memoryview(data)[:whole].cast("I")
        if sys.byteorder == "little"
        else struct.unpack(f"<{whole // 4}I", data[:whole])
    )
    value = functools.reduce(operator.xor, words, seed)
    tail = 0
    for byte in data[whole:]:
        tail = tail << 8 | byte
    return value ^ tail


def _block_checksum(payload: bytes, decoded: int) -> int:
    # Over the stored bytes, then the block's two size fields.
    return _checksum(_DATA.pack(0, len(payload), decoded)[4:], _checksum(payload))


class CabReader(IndexedReader[_Location]):
    """One open cabinet."""

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        header = self._read(0, _HEADER.size, "the cabinet header")
        (
            _magic,
            _reserved1,
            self._size,
            _reserved2,
            self._files_at,
            _reserved3,
            minor,
            major,
            folders,
            self._file_count,
            flags,
            _set_id,
            _index,
        ) = _HEADER.unpack(header)
        self._version = f"{major}.{minor}"
        if flags & (_PREV_CABINET | _NEXT_CABINET):
            raise UnsupportedFeatureError(
                "the cabinet is part of a set that spans several files; archivey "
                "reads a single cabinet"
            )
        pos = _HEADER.size
        folder_reserve = 0
        self._data_reserve = 0
        if flags & _RESERVE_PRESENT:
            header_reserve, folder_reserve, self._data_reserve = _RESERVE.unpack(
                self._read(pos, _RESERVE.size, "the reserve sizes")
            )
            pos += _RESERVE.size + header_reserve
        self._folders = self._read_folders(pos, folders, folder_reserve)
        self._solid = any(f.method != _STORED for f in self._folders)
        self._lock = threading.Lock()
        self._tables: dict[int, _BlockTable] = {}
        # What the kept tables weigh, against ``max_metadata_bytes``: folders may all
        # name the same run of block headers, so they are not bounded by the file.
        self._table_bytes = 0
        self._max_meta = context.config.listing_limits.max_metadata_bytes
        # The folder decoder a member stream left behind, to go on from.
        self._parked: _FolderStream | None = None

    # ── Header ───────────────────────────────────────────────────────────────────────

    def _read(self, pos: int, length: int, what: str) -> bytes:
        try:
            return self._source.read_exact(pos, length)
        except TruncatedError:
            raise TruncatedError(
                f"the cabinet ends inside {what} at offset {pos}"
            ) from None

    def _read_folders(self, pos: int, count: int, reserve: int) -> tuple[_Folder, ...]:
        record = _FOLDER.size + reserve
        raw = self._read(pos, count * record, "the folder records")
        folders = []
        for index in range(count):
            start, blocks, kind = _FOLDER.unpack_from(raw, index * record)
            folders.append(_Folder(start, blocks, kind & 0x0F, (kind >> 8) & 0x1F))
        return tuple(folders)

    # ── Listing ──────────────────────────────────────────────────────────────────────

    @override
    def iter_members(self) -> Iterator[MemberRecord[_Location]]:
        table = _Cursor(self, self._files_at)
        context = self._context
        for _ in range(self._file_count):
            size, offset, folder, date, time, attribs = _FILE.unpack(
                table.read(_FILE.size, "a file record")
            )
            raw = table.read_name()
            name = context.decode_name(raw).replace("\\", "/")
            if folder >= _CONTINUED:
                raise CorruptionError(
                    f"file {quoted(name)} continues into another cabinet, but this "
                    "cabinet is not part of a set"
                )
            if folder >= len(self._folders):
                raise CorruptionError(
                    f"file {quoted(name)} is in folder {folder}; the cabinet has "
                    f"{len(self._folders)}"
                )
            stamp = date << 16 | time
            member = ArchiveMember(
                type=MemberType.FILE,
                name=name,
                raw_name=raw,
                size=size,
                windows_attrs=attribs & ~_CAB_ONLY_ATTRIBUTES,
                compression=(
                    CompressionMethod(
                        _METHODS.get(
                            self._folders[folder].method, CompressionAlgorithm.UNKNOWN
                        )
                    ),
                ),
            )
            context.set_dos_time(member, "modified", stamp, source="dos")
            yield MemberRecord(member, _Location(folder, offset))

    # ── Data ─────────────────────────────────────────────────────────────────────────

    def _block_table(self, index: int) -> _BlockTable:
        """The folder's CFDATA headers, read once: where each block's bytes are, and
        where its output starts. Every table is kept, and weighed against
        ``max_metadata_bytes`` as it is read."""
        with self._lock:
            table = self._tables.get(index)
        if table is not None:
            return table
        folder = self._folders[index]
        blocks = []
        output = [0]
        pos = folder.start
        header = _DATA.size + self._data_reserve
        size = self._source.size
        complete = True
        max_meta = self._max_meta
        for number in range(folder.blocks):
            if max_meta is not None and (
                self._table_bytes + (number + 1) * _BLOCK_WEIGHT > max_meta
            ):
                raise self._table_limit(index, number + 1)
            if size is not None and pos + header > size:
                complete = False
                break
            checksum, stored, decoded = _DATA.unpack(
                self._read(pos, _DATA.size, "a data block header")
            )
            if stored > _INPUT_MAX or decoded > _BLOCK_MAX:
                raise CorruptionError(
                    f"data block {number} of folder {index} stores {stored} bytes "
                    f"for {decoded}; a block holds at most {_INPUT_MAX} for "
                    f"{_BLOCK_MAX}"
                )
            blocks.append(_Block(pos + header, stored, decoded, checksum))
            output.append(output[-1] + decoded)
            pos += header + stored
        table = _BlockTable(tuple(blocks), tuple(output), complete)
        with self._lock:
            kept = self._tables.get(index)
            if kept is not None:  # another thread read it meanwhile
                return kept
            self._table_bytes += len(blocks) * _BLOCK_WEIGHT
            if max_meta is not None and self._table_bytes > max_meta:
                self._table_bytes -= len(blocks) * _BLOCK_WEIGHT
                raise self._table_limit(index, len(blocks))
            self._tables[index] = table
        return table

    def _table_limit(self, index: int, block: int) -> ResourceLimitError:
        assert self._max_meta is not None
        return metadata_limit_error(
            self._max_meta,
            f"the block tables kept weigh {self._table_bytes} bytes, and folder "
            f"{index}'s passes the limit at block {block} of "
            f"{self._folders[index].blocks}",
        )

    @override
    def open_member(self, member: ArchiveMember, locator: _Location) -> MemberData:
        folder = self._folders[locator.folder]
        if folder.method == _QUANTUM:
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} is Quantum-compressed, which archivey does "
                "not read"
            )
        if folder.method not in _METHODS:
            raise UnsupportedFeatureError(
                f"{quoted(member.name)} uses cabinet compression method "
                f"{folder.method}, which archivey does not know"
            )
        if folder.method == _LZX and not (
            MIN_WINDOW_BITS <= folder.window_bits <= MAX_WINDOW_BITS
        ):
            raise CorruptionError(
                f"folder {locator.folder} declares an LZX window of "
                f"2**{folder.window_bits} bytes"
            )
        table = self._block_table(locator.folder)
        size = member.size or 0
        end = locator.offset + size
        if table.complete and end > table.output[-1]:
            raise CorruptionError(
                f"{quoted(member.name)} ends at byte {end} of folder "
                f"{locator.folder}, which decodes to {table.output[-1]}"
            )
        # The member is checked when every block up to its end carries a checksum.
        last = _block_at(table, max(end - 1, 0))
        checked = last is not None and all(
            block.checksum for block in table.blocks[: last + 1]
        )
        stream = self._folder_stream(locator.folder, folder, table, locator.offset)
        return MemberData(
            _MemberStream(self, stream, size),
            checked=checked and size > 0,
            bounded=True,
        )

    def _folder_stream(
        self, index: int, folder: _Folder, table: _BlockTable, offset: int
    ) -> _FolderStream:
        with self._lock:
            parked, self._parked = self._parked, None
        if parked is not None and parked.index == index and parked.position <= offset:
            stream = parked
        elif folder.method == _STORED:
            # Stored blocks need no history: start at the block holding ``offset``.
            stream = _FolderStream(self, index, folder, table, _block_at(table, offset))
        else:
            stream = _FolderStream(self, index, folder, table, 0)
        stream.skip(offset - stream.position)
        return stream

    def _park(self, stream: _FolderStream) -> None:
        with self._lock:
            self._parked = stream

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(is_solid=self._solid, format_version=self._version)


def _block_at(table: _BlockTable, offset: int) -> int | None:
    """The block whose output holds byte ``offset`` of the folder, or the next block
    when ``offset`` is where one starts; ``None`` past the blocks read."""
    output = table.output
    lo, hi = 0, len(output) - 1
    if hi == 0 or offset >= output[-1]:
        return None
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if output[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo


class _Cursor:
    """Reads on through the file table, a chunk at a time."""

    def __init__(self, reader: CabReader, pos: int) -> None:
        self._reader = reader
        self._pos = pos
        self._buf = b""
        self._at = 0

    def _fill(self, need: int) -> None:
        source = self._reader._source
        while len(self._buf) - self._at < need:
            chunk = source.read_at(self._pos, _TABLE_CHUNK)
            if not chunk:
                return
            self._buf = self._buf[self._at :] + chunk
            self._at = 0
            self._pos += len(chunk)

    def read(self, n: int, what: str) -> bytes:
        self._fill(n)
        data = self._buf[self._at : self._at + n]
        if len(data) < n:
            raise TruncatedError(f"the cabinet ends inside {what}")
        self._at += n
        return data

    def read_name(self) -> bytes:
        self._fill(_NAME_MAX)
        end = self._buf.find(b"\0", self._at, self._at + _NAME_MAX)
        if end < 0:
            if len(self._buf) - self._at < _NAME_MAX:
                raise TruncatedError("the cabinet ends inside a file name")
            raise CorruptionError(
                f"a file name runs past {_NAME_MAX - 1} bytes with no end"
            )
        if end == self._at:
            raise CorruptionError("a file record has an empty name")
        name = self._buf[self._at : end]
        self._at = end + 1
        return name


class _FolderStream:
    """A folder's output, decoded block by block from where it starts."""

    def __init__(
        self,
        reader: CabReader,
        index: int,
        folder: _Folder,
        table: _BlockTable,
        first: int | None,
    ) -> None:
        self.index = index
        self._reader = reader
        self._folder = folder
        self._table = table
        self._next = len(table.blocks) if first is None else first
        self.position = (
            table.output[self._next] if first is not None else (table.output[-1])
        )
        self._pending = b""
        self._history = b""
        self.failed = False
        self._lzx: LzxDecoder | None = None
        self._lzx_input = self._next
        if folder.method == _LZX:
            self._lzx = LzxDecoder(folder.window_bits, self._lzx_more)

    def _payload(self, number: int) -> bytes:
        block = self._table.blocks[number]
        data = self._reader._read(block.payload, block.stored, "a data block")
        if block.checksum and block.checksum != _block_checksum(data, block.decoded):
            raise CorruptionError(
                f"data block {number} of folder {self.index} fails its checksum"
            )
        return data

    def _lzx_more(self) -> bytes | None:
        if self._lzx_input >= len(self._table.blocks):
            return None
        data = self._payload(self._lzx_input)
        self._lzx_input += 1
        return data

    def _decode_next(self) -> bytes:
        """The next block's output (for LZX, the next 32 KiB frame)."""
        table = self._table
        if self._folder.method == _LZX:
            assert self._lzx is not None
            # Frames are 32 KiB, the last one shorter, whatever the blocks hold.
            left = table.output[-1] - self.position
            if table.complete and left <= 0:
                raise TruncatedError(
                    f"folder {self.index} ends after {self.position} bytes"
                )
            frame = min(FRAME_SIZE, left) if table.complete else FRAME_SIZE
            return self._lzx.decode_frame(frame)
        number = self._next
        if number >= len(table.blocks):
            raise TruncatedError(
                f"folder {self.index} ends after {self.position} bytes"
                if table.complete
                else f"the cabinet ends inside folder {self.index}"
            )
        block = table.blocks[number]
        self._next += 1
        method = self._folder.method
        data = self._payload(number)
        if method == _STORED:
            if len(data) != block.decoded:
                raise CorruptionError(
                    f"stored data block {number} of folder {self.index} holds "
                    f"{len(data)} bytes and says {block.decoded}"
                )
            return data
        # MSZIP: "CK", then a raw deflate stream with the last output as dictionary.
        if data[:2] != b"CK":
            raise CorruptionError(
                f"MSZIP data block {number} of folder {self.index} does not start "
                "with CK"
            )
        decoder = (
            zlib.decompressobj(-15, zdict=self._history)
            if self._history
            else zlib.decompressobj(-15)
        )
        try:
            out = decoder.decompress(data[2:], block.decoded + 1)
        except zlib.error as exc:
            raise CorruptionError(
                f"MSZIP data block {number} of folder {self.index}: {exc}"
            ) from None
        if len(out) != block.decoded or not decoder.eof:
            raise CorruptionError(
                f"MSZIP data block {number} of folder {self.index} decodes to "
                f"{len(out)} bytes{'' if decoder.eof else ' and does not end'}; "
                f"it says {block.decoded}"
            )
        self._history = (self._history + out)[-32768:]
        return out

    def read(self, n: int) -> bytes:
        while not self._pending:
            try:
                self._pending = self._decode_next()
            except BaseException:
                self.failed = True
                raise
        data = self._pending[:n]
        self._pending = self._pending[n:]
        self.position += len(data)
        return data

    def skip(self, n: int) -> None:
        while n > 0:
            if not self._pending and self._folder.method == _STORED:
                # Whole stored blocks are skipped without reading them.
                block = (
                    self._table.blocks[self._next]
                    if (self._next < len(self._table.blocks))
                    else None
                )
                if block is not None and block.decoded <= n:
                    self._next += 1
                    self.position += block.decoded
                    n -= block.decoded
                    continue
            n -= len(self.read(n))


class _MemberStream(io.RawIOBase):
    """One member: ``size`` bytes of its folder's output, from where it starts."""

    # Set before ``__init__`` runs, so ``close()`` works on any instance.
    _folder: _FolderStream | None = None

    def __init__(self, reader: CabReader, folder: _FolderStream, size: int) -> None:
        self._reader = reader
        self._folder = folder
        self._left = size

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        with memoryview(b) as outer, outer.cast("B") as view:
            if self._left == 0 or self._folder is None or not len(view):
                return 0
            data = self._folder.read(min(len(view), self._left))
            n = len(data)
            view[:n] = data
            self._left -= n
            return n

    @override
    def close(self) -> None:
        folder, self._folder = self._folder, None
        if folder is not None and not folder.failed:
            # The next member of the folder goes on from here.
            self._reader._park(folder)
        super().close()


class CabHandler(IndexedFormatHandler):
    """Microsoft cabinets: ``.cab``."""

    format = ArchiveFormat.CAB
    extensions = (".cab",)
    magic = (Magic(0, MAGIC),)
    uses_encoding = True
    non_seekable_reason = "its file table points at folders anywhere in the file"

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> CabReader:
        return CabReader(source, context)


CabReadBackend = register_builtin_format(CabHandler)
