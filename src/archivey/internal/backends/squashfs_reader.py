"""A SquashFS 4.0 reader, written against ``archivey.formats``.

The layout, from the squashfs-tools sources and the kernel's ``squashfs_fs.h``: a 96-byte
superblock, then data blocks and fragment blocks, then the tables. The inode table and
the directory table are runs of *metadata blocks* (a 2-byte header, then up to 8 KiB,
compressed or not); the fragment, id, export and xattr tables are each an array of
8-byte pointers to such blocks. An inode or a directory listing is addressed by the
offset of its metadata block from the start of its table and an offset inside the
decoded block.

The reader trusts nothing it reads: every size is checked against what the format
allows, the directory walk is a loop that refuses a directory reached twice, and every
compressed block goes through ``ReaderContext.decompress``, so archivey's decoder limits
apply, or, for LZ4, through ``lz4.block`` capped at the block's size.

How a listing is built:

1. When the image opens, :func:`_read_superblock` checks the superblock, which says
   where each table starts. The other steps run in :meth:`SquashfsReader.iter_members`.
2. :meth:`SquashfsReader._walk` walks the directory table from the root inode, depth
   first, and keeps one :class:`_Entry` per name. It reads only the directories'
   inodes, since it needs their listings to go on.
3. :meth:`SquashfsReader._file_inodes` reads every other inode once, in table order,
   and keeps a packed record of each inode that reads, with a symlink's target beside
   it. An inode that fails keeps only its reference, and its member raises.
4. :meth:`SquashfsReader._make_member` turns each entry into an ``ArchiveMember``. The
   type, mode, mtime and owner (through the id table) come from the inode. A later
   entry that is not a directory and names the inode of an earlier entry is a hard
   link to that entry, whatever its type.

A file's bytes are its data blocks, decoded one at a time, then its tail, which may sit
in a fragment block shared by many small files (:meth:`SquashfsReader._file_stream`).

The reader is written against ``archivey.formats``. Beyond it, it uses archivey's own
handling of the ``lz4`` package (the PyPy rule, ``exclude_libraries`` and process
isolation) rather than a copy of it. Handbook page: ``dev-docs/formats/squashfs.md``.
"""

from __future__ import annotations

import io
import struct
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import UTC, datetime
from typing import Any, BinaryIO, NamedTuple, NoReturn, cast

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    PackageNotInstalledError,
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
    block_stream,
)
from archivey.internal.excluded_libraries import as_reported
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.isolated import Natives, natives_for
from archivey.internal.streams.codecs.lz4_codec import LZ4_REQUIREMENT
from archivey.terminal import quoted
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ArchiveMember,
    CompressionAlgorithm,
    MemberType,
    OptionalLibrary,
    StreamFormat,
)

MAGIC = b"hsqs"
_SWAPPED_MAGIC = b"sqsh"  # big-endian images, written by SquashFS 3 and older

_SUPERBLOCK = struct.Struct("<IIIIIHHHHHHQQQQQQQQ")
_METADATA_SIZE = 8192
_METADATA_UNCOMPRESSED = 0x8000
_BLOCK_UNCOMPRESSED = 1 << 24
_NO_FRAGMENT = 0xFFFFFFFF
_NO_TABLE = 0xFFFFFFFFFFFFFFFF
# The kernel refuses a symlink target longer than this (``squashfs_read_inode``).
_SYMLINK_MAX = 65535
# The kernel (``SQUASHFS_NAME_LEN``) and unsquashfs refuse a longer entry name.
_NAME_MAX = 256

# When the superblock's compressor-options flag is set, a metadata block of options
# follows the superblock. It is not read: zlib, xz, LZMA Alone and Zstandard streams
# carry their own parameters, and the LZ4 and LZO options only name a compression
# level or variant that the same decoder reads.
_COMPRESSORS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
_DECODED_AS: dict[str, CompressionAlgorithm | StreamFormat] = {
    "gzip": StreamFormat.ZLIB,
    "lzma": StreamFormat.LZMA_ALONE,
    "xz": StreamFormat.XZ,
    "zstd": CompressionAlgorithm.ZSTD,
    # Raw LZO1X, which archivey decodes with liblzo2 through python-lzo, or in Python.
    "lzo": CompressionAlgorithm.LZO,
}

# Inode types; an extended type is the basic one plus 7.
_DIR, _FILE, _SYMLINK, _BLKDEV, _CHRDEV, _FIFO, _SOCKET = range(1, 8)
_SPECIAL = {
    _BLKDEV: "block_device",
    _CHRDEV: "char_device",
    _FIFO: "fifo",
    _SOCKET: "socket",
}
_INODE_HEADER = struct.Struct("<HHHHII")
_DIR_INODE = struct.Struct("<IIHHI")
_EXT_DIR_INODE = struct.Struct("<IIIIHHI")
_FILE_INODE = struct.Struct("<IIII")
_EXT_FILE_INODE = struct.Struct("<QQQIIII")
_DIR_HEADER = struct.Struct("<III")
_DIR_ENTRY = struct.Struct("<HhHH")
_FRAGMENT_ENTRY = struct.Struct("<QII")
# Entries per directory header (``SQUASHFS_DIR_COUNT``).
_DIR_COUNT = 256

# Decoded blocks kept for reuse: metadata blocks while listing, fragment blocks because
# every small file in one fragment shares it. Caches, not limits: they bound what an
# open reader holds (64 x 8 KiB, plus 4 fragments of at most the 1 MiB block size,
# about 4.5 MiB) whatever the image declares, and a miss only decodes the block again.
# 64 covers the directory blocks a listing walks back and forth over in images of tens
# of thousands of files. The listing reads the other inodes once, in table order, and
# keeps a record of each (``_RECORD``), so their blocks need no cache past that read.
# Writers fill one or two fragments at a time in name order, so a few cover a walk in
# listing order; where they would not, ``iter_members`` puts the files with a tail in
# fragment order.
_METADATA_CACHE = 64
_FRAGMENT_CACHE = 4


def _shown(raw: bytes) -> str:
    """A stored name for a message: the error escapes what is not printable."""
    return quoted(raw.decode("utf-8", "surrogateescape"))


class FileLocation(NamedTuple):
    """Where a regular file's data is: what ``open_member`` needs."""

    size: int
    blocks_start: int
    block_count: int
    # The block-size list, right after the inode: (metadata block, offset in it).
    list_block: int
    list_offset: int
    fragment: int
    fragment_offset: int


class _Superblock(NamedTuple):
    inode_count: int
    mkfs_time: int
    block_size: int
    fragment_count: int
    compressor: int
    block_log: int
    flags: int
    id_count: int
    root_inode: int
    bytes_used: int
    id_table: int
    xattr_table: int
    inode_table: int
    directory_table: int
    fragment_table: int
    export_table: int


def _read_superblock(source: ReaderSource) -> _Superblock:
    """The image's superblock, refused unless it is a SquashFS 4.0 one that fits.

    Checks only what the rest of the reader relies on before it reads a table: the
    version, the block size, that the image holds the bytes it declares (when its size
    is known), and that the inode, directory and id tables start inside them, the
    inode table first.
    """
    raw = source.read_at(0, _SUPERBLOCK.size)
    if raw[:4] == _SWAPPED_MAGIC:
        raise UnsupportedFeatureError(
            "big-endian SquashFS (version 3 or older) is not supported"
        )
    if raw[:4] != MAGIC:
        raise CorruptionError("no SquashFS superblock")
    if len(raw) < _SUPERBLOCK.size:
        raise TruncatedError("the SquashFS superblock is cut short")
    fields = _SUPERBLOCK.unpack(raw)
    major, minor = fields[9], fields[10]
    if (major, minor) != (4, 0):
        raise UnsupportedFeatureError(
            f"SquashFS version {major}.{minor} is not supported"
        )
    sb = _Superblock(*fields[1:9], *fields[11:])
    if not 4096 <= sb.block_size <= 1 << 20 or sb.block_size != 1 << sb.block_log:
        raise CorruptionError(
            f"SquashFS block size {sb.block_size} (log {sb.block_log}) is not valid"
        )
    if source.size is not None and sb.bytes_used > source.size:
        raise TruncatedError(
            f"the SquashFS image declares {sb.bytes_used} bytes, but only "
            f"{source.size} are present"
        )
    for name, start in (
        ("inode", sb.inode_table),
        ("directory", sb.directory_table),
        ("id", sb.id_table),
    ):
        if start >= sb.bytes_used:
            raise CorruptionError(
                f"the SquashFS {name} table starts past the image end"
            )
    if sb.inode_table >= sb.directory_table:
        raise CorruptionError(
            "the SquashFS inode table starts after the directory table"
        )
    return sb


class _Inode(NamedTuple):
    type: int  # basic type, 1 to 7
    mode: int
    uid: int
    gid: int
    mtime: int
    # Directory: (listing block, offset, listing size); file: FileLocation; symlink:
    # target bytes; others: None.
    body: object


def _listing(inode: _Inode) -> tuple[int, int, int]:
    """A directory inode's listing: (metadata block, offset in it, size in bytes)."""
    assert isinstance(inode.body, tuple), "a directory inode's body is its listing"
    return inode.body


class _Entry(NamedTuple):
    """A directory entry the walk found, before its member is made."""

    parent: int  # index of its directory's entry, -1 for the root
    name: bytes
    # Its inode, as SquashFS refers to one: metadata block << 16 | offset in it.
    ref: int
    kind: int  # the basic type the entry gives
    inode: _Inode | None  # read during the walk for a directory, else None


# What the first pass keeps of an inode that is not a directory's, packed: its basic
# type, whether the file has holes, mode, uid, gid, mtime, then a regular file's
# ``FileLocation`` (zeros for other types). 58 bytes, a 96-byte object in CPython,
# against about 450 for the ``_Inode`` and ``FileLocation`` it is made from.
_RECORD = struct.Struct("<BBHIIIQQQQHII")
_RECORD_HEAD = struct.Struct("<BBHIII")  # its first 16 bytes
_RECORD_LOCATION = struct.Struct("<QQQQHII")  # the rest
# Of a record, the file's size, fragment and offset in it: what the fragment order reads.
_RECORD_TAIL = struct.Struct("<16xQ26xII")
assert _RECORD_TAIL.size == _RECORD_HEAD.size + _RECORD_LOCATION.size == _RECORD.size
_NO_LOCATION = (0,) * len(FileLocation._fields)


def _lists_over() -> CorruptionError:
    """The error for block lists that add up to more than the decoded inode table
    holds (:meth:`SquashfsReader._block_list_fits`)."""
    return CorruptionError(
        "the files' block lists add up to more than the inode table holds"
    )


# What ``iter_members`` leaves in place of an entry whose member it made.
_MADE = _Entry(-1, b"", -1, 0, None)


class _FileScan(NamedTuple):
    """What the first pass keeps of the inodes that are not directories, by inode
    reference: a ``_RECORD`` for each, which is all the second pass needs to make
    the member, so no inode is read twice."""

    records: dict[int, bytes]
    # A symlink's target, which its member holds anyway: kept beside its record and
    # charged to ``max_metadata_bytes`` as it is kept (``_charge``).
    symlinks: dict[int, bytes]
    # Inodes that did not read, or files whose block list did not scan: only the
    # reference, since an error holds its traceback (some 3.5 KiB, uncharged). Its
    # member reads the inode and the list again and raises (``_raise_again``).
    failed: set[int]
    # The first file, in table order, whose block list crossed what the inode table
    # holds (``_block_list_fits``): it and every file after it were refused there.
    lists_over: int | None
    clean: bool  # every inode read, and of the type its entry gives


def _decodes_twice(keys: Iterable[tuple[int, int]], capacity: int) -> bool:
    """Whether a reader cache of ``capacity`` blocks, asked for the blocks with these
    keys in order, would decode one of them a second time. It replays the policy of
    ``fragment_tail``'s cache: least recently used first."""
    cache: OrderedDict[tuple[int, int], None] = OrderedDict()
    decoded: set[tuple[int, int]] = set()
    last = None
    for key in keys:
        if key == last:
            continue  # the most recent block: a hit that changes nothing
        last = key
        if key in cache:
            cache.move_to_end(key)
            continue
        if key in decoded:
            return True
        decoded.add(key)
        cache[key] = None
        if len(cache) > capacity:
            cache.popitem(last=False)
    return False


def _first_with_inode(entries: list[_Entry]) -> list[int]:
    """For each entry, the first entry listed with its inode: itself, or for a hard link
    the member it names. -1 for a directory."""
    first: list[int] = []
    firsts: dict[int, int] = {}
    for index, entry in enumerate(entries):
        first.append(-1 if entry.kind == _DIR else firsts.setdefault(entry.ref, index))
    return first


class SquashfsReader(IndexedReader[FileLocation | None]):
    """One open SquashFS image."""

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        self._sb = sb = _read_superblock(source)
        compressor = _COMPRESSORS.get(sb.compressor)
        if compressor is None:
            raise CorruptionError(f"unknown SquashFS compressor id {sb.compressor}")
        self._compressor = compressor
        self._decode = self._block_decoder(compressor)
        self._metadata: OrderedDict[int, tuple[bytes, int]] = OrderedDict()
        # Keyed by (start, stored size): two table entries can name one start and
        # disagree on whether the bytes there are compressed.
        self._fragments: OrderedDict[tuple[int, int], bytes] = OrderedDict()
        self._ids = self._ids_table()
        # Block-list bytes counted by the listing so far (``_block_list_fits``).
        self._block_list_bytes = 0
        self._inode_capacity: int | None = None
        # What the listing in progress holds before its members are made, charged
        # against ``max_metadata_bytes`` (``_charge``).
        self._charged = 0

    # ── Decoding ─────────────────────────────────────────────────────────────────────

    def _lz4_natives(self) -> Natives:
        """Where LZ4 blocks decode (a child process unless ``process_isolation`` is
        ``NONE``), or ``PackageNotInstalledError`` when lz4 is missing, unused on this
        interpreter, or turned off by the caller's policy."""
        config = self._context.config
        excluded = config.formats._libraries_off
        if deps.lz4_block is None or OptionalLibrary.LZ4 in excluded:
            requirement = as_reported(LZ4_REQUIREMENT, excluded)
            raise PackageNotInstalledError(
                requirement.message("an LZ4-compressed SquashFS image"),
                missing=(requirement,),
            )
        return natives_for(config.process_isolation)

    def _block_decoder(self, compressor: str) -> Callable[[int, int, int], bytes]:
        """A function that decodes ``length`` bytes at ``start`` to at most ``limit``."""
        method = _DECODED_AS.get(compressor)
        if method is not None:

            def through_archivey(start: int, length: int, limit: int) -> bytes:
                # One locked read of the block, then decode from memory, rather than a
                # view the decoder seeks and reads through; a cut-off block is refused.
                # Every caller has checked ``length`` first: at most 8 KiB for a
                # metadata block, the block size (1 MiB at most) for data.
                raw = io.BytesIO(self._read_exact(start, length, "a compressed block"))
                # LZO1X stores no decoded length: ``size`` is the most it may have.
                size = limit if method is CompressionAlgorithm.LZO else None
                try:
                    with self._context.decompress(raw, method, size=size) as decoded:
                        data = decoded.read(limit + 1)
                        # A codec reports a cut stream or a bad check value on the
                        # read after its data ends, so read on until it ends. The
                        # block itself was read whole, so a stream that stops early
                        # means a wrong stored size: a TruncatedError becomes a
                        # CorruptionError below.
                        while len(data) <= limit and (
                            more := decoded.read(limit + 1 - len(data))
                        ):
                            data += more
                except CorruptionError as exc:
                    raise CorruptionError(f"the block at {start}: {exc}") from None
                if len(data) > limit:
                    raise CorruptionError(
                        f"a block at {start} decodes to more than {limit} bytes"
                    )
                return data

            return through_archivey
        if compressor == "lz4":
            # Decoded here, not through ``ReaderContext.decompress``, so the policy's
            # method entry is asked here as that call would ask it.
            refusal = self._context.config.formats._codec_refusal(
                CompressionAlgorithm.LZ4
            )
            if refusal is not None:
                raise UnsupportedFeatureError(f"{refusal}.")
            natives = self._lz4_natives()
            block_error = cast("Any", deps.lz4_block).LZ4BlockError

            def lz4_block(start: int, length: int, limit: int) -> bytes:
                raw = self._read_exact(start, length, "an LZ4 block")
                try:
                    return natives.lz4_block_decompress(raw, uncompressed_size=limit)
                except block_error as exc:
                    raise CorruptionError(f"the LZ4 block at {start}: {exc}") from None

            return lz4_block
        raise UnsupportedFeatureError(
            f"{compressor.upper()}-compressed SquashFS is not supported"
        )

    def _read_exact(self, start: int, length: int, what: str) -> bytes:
        """:meth:`ReaderSource.read_exact`, naming the structure the image ends in."""
        try:
            return self._source.read_exact(start, length)
        except TruncatedError:
            raise TruncatedError(f"{what} at {start} runs past the image end") from None

    def _read_struct(self, pos: int, fmt: str, what: str) -> tuple[Any, ...]:
        """:meth:`ReaderSource.read_struct`, naming the structure the image ends in."""
        try:
            return self._source.read_struct(pos, fmt)
        except TruncatedError:
            raise TruncatedError(f"{what} at {pos} runs past the image end") from None

    def _metadata_block(self, pos: int) -> tuple[bytes, int]:
        """The decoded metadata block at absolute ``pos``, and where the next starts."""
        cached = self._metadata.get(pos)
        if cached is not None:
            self._metadata.move_to_end(pos)
            return cached
        if pos + 2 > self._sb.bytes_used:
            raise CorruptionError(
                f"a metadata block at {pos} starts past the image end"
            )
        (header,) = self._read_struct(pos, "<H", "a metadata header")
        length = header & ~_METADATA_UNCOMPRESSED
        if not 0 < length <= _METADATA_SIZE:
            raise CorruptionError(
                f"the metadata block at {pos} declares {length} bytes"
            )
        if header & _METADATA_UNCOMPRESSED:
            data = self._read_exact(pos + 2, length, "a metadata block")
        else:
            data = self._decode(pos + 2, length, _METADATA_SIZE)
        block = (data, pos + 2 + length)
        self._metadata[pos] = block
        if len(self._metadata) > _METADATA_CACHE:
            self._metadata.popitem(last=False)
        return block

    def _cursor(self, table: int, block: int, offset: int) -> _MetadataCursor:
        return _MetadataCursor(self, table, block, offset)

    def _ids_table(self) -> tuple[int, ...]:
        count = self._sb.id_count
        if count == 0:
            raise CorruptionError("the SquashFS id table is empty")
        blocks = -(-count * 4 // _METADATA_SIZE)
        pointers = self._read_struct(
            self._sb.id_table, f"<{blocks}Q", "the id table index"
        )
        data = b"".join(self._metadata_block(p)[0] for p in pointers)
        if len(data) < count * 4:
            raise CorruptionError(f"the id table holds {len(data) // 4} of {count} ids")
        return struct.unpack_from(f"<{count}I", data)

    def _fragment(self, index: int) -> tuple[int, int]:
        """The (start, stored size) of fragment block ``index``.

        Read one table block at a time: the count is a 32-bit field, so the whole
        table is not read up front.
        """
        if index >= self._sb.fragment_count:
            raise CorruptionError(
                f"fragment {index} is past the {self._sb.fragment_count} in the table"
            )
        if self._sb.fragment_table == _NO_TABLE:
            raise CorruptionError("the SquashFS image has fragments but no table")
        block, within = divmod(index * _FRAGMENT_ENTRY.size, _METADATA_SIZE)
        (pointer,) = self._read_struct(
            self._sb.fragment_table + 8 * block, "<Q", "the fragment table index"
        )
        data = self._metadata_block(pointer)[0]
        if within + _FRAGMENT_ENTRY.size > len(data):
            raise CorruptionError(
                f"fragment {index} is past the end of its table block"
            )
        start, stored, _ = _FRAGMENT_ENTRY.unpack_from(data, within)
        return start, stored

    def data_block(self, start: int, stored: int, expected: int) -> bytes:
        """One block of file data that decodes to exactly ``expected`` bytes."""
        length = stored & ~_BLOCK_UNCOMPRESSED
        if length > self._sb.block_size:
            raise CorruptionError(f"the data block at {start} declares {length} bytes")
        if stored & _BLOCK_UNCOMPRESSED:
            data = self._read_exact(start, length, "a data block")
        else:
            data = self._decode(start, length, self._sb.block_size)
        if len(data) != expected:
            raise CorruptionError(
                f"the data block at {start} holds {len(data)} bytes, not {expected}"
            )
        return data

    def fragment_tail(self, location: FileLocation, length: int) -> bytes:
        """The last ``length`` bytes of a file, from the fragment block that holds them.

        Writers pack the tails of many small files into one fragment block, so the
        decoded block is cached: reading those files one after another decodes it
        once.
        """
        start, stored = self._fragment(location.fragment)
        # ``_decodes_twice`` replays this cache's policy; change both together.
        key = (start, stored)
        block = self._fragments.get(key)
        if block is None:
            length_on_disk = stored & ~_BLOCK_UNCOMPRESSED
            if length_on_disk > self._sb.block_size:
                raise CorruptionError(
                    f"the fragment block at {start} declares {length_on_disk} bytes"
                )
            if stored & _BLOCK_UNCOMPRESSED:
                block = self._read_exact(start, length_on_disk, "a fragment block")
            else:
                block = self._decode(start, length_on_disk, self._sb.block_size)
            self._fragments[key] = block
            if len(self._fragments) > _FRAGMENT_CACHE:
                self._fragments.popitem(last=False)
        else:
            self._fragments.move_to_end(key)
        end = location.fragment_offset + length
        if end > len(block):
            raise CorruptionError(
                f"a file's tail runs to byte {end} of a {len(block)}-byte fragment"
            )
        return block[location.fragment_offset : end]

    @property
    def block_size(self) -> int:
        return self._sb.block_size

    def block_list(self, location: FileLocation) -> _MetadataCursor:
        return self._cursor(
            self._sb.inode_table, location.list_block, location.list_offset
        )

    # ── Listing ──────────────────────────────────────────────────────────────────────

    def _inode(self, block: int, offset: int) -> _Inode:
        """The inode at ``offset`` in metadata block ``block`` of the inode table.

        An extended inode type is folded into its basic one, the owner's id indexes
        are looked up in the id table, and the body is what the type needs: a
        directory's listing, a file's :class:`FileLocation`, a symlink's target.
        """
        cursor = self._cursor(self._sb.inode_table, block, offset)
        kind, mode, uid_index, gid_index, mtime, _ = _INODE_HEADER.unpack(
            cursor.read(_INODE_HEADER.size)
        )
        if not 1 <= kind <= 14:
            raise CorruptionError(f"unknown SquashFS inode type {kind}")
        extended = kind > 7
        basic = kind - 7 if extended else kind
        if uid_index >= len(self._ids) or gid_index >= len(self._ids):
            raise CorruptionError("an inode's owner is past the end of the id table")
        body: object = None
        if basic == _DIR:
            if extended:
                _, size, listing, _, _, list_offset, _ = _EXT_DIR_INODE.unpack(
                    cursor.read(_EXT_DIR_INODE.size)
                )
            else:
                listing, _, size, list_offset, _ = _DIR_INODE.unpack(
                    cursor.read(_DIR_INODE.size)
                )
            # The size counts 3 bytes for the "." and ".." entries it does not store.
            if size < 3 or list_offset >= _METADATA_SIZE:
                raise CorruptionError(f"a directory inode declares a listing of {size}")
            body = (listing, list_offset, size - 3)
        elif basic == _FILE:
            if extended:
                start, size, _, _, fragment, frag_offset, _ = _EXT_FILE_INODE.unpack(
                    cursor.read(_EXT_FILE_INODE.size)
                )
            else:
                start, fragment, frag_offset, size = _FILE_INODE.unpack(
                    cursor.read(_FILE_INODE.size)
                )
            block_size = self._sb.block_size
            if fragment == _NO_FRAGMENT:
                count = -(-size // block_size)
            else:
                count = size // block_size
                if frag_offset >= block_size:
                    raise CorruptionError("a file's tail starts past its fragment")
            body = FileLocation(
                size, start, count, cursor.block, cursor.offset, fragment, frag_offset
            )
        elif basic == _SYMLINK:
            _, length = struct.unpack("<II", cursor.read(8))
            if length > _SYMLINK_MAX:
                raise CorruptionError(f"a symlink target of {length} bytes")
            body = cursor.read(length)
        return _Inode(
            basic,
            mode & 0o7777,
            self._ids[uid_index],
            self._ids[gid_index],
            mtime,
            body,
        )

    def _entries(
        self, listing: tuple[int, int, int]
    ) -> Iterator[tuple[bytes, int, int]]:
        """(name, inode reference, type) for each entry of a listing."""
        block, offset, size = listing
        cursor = self._cursor(self._sb.directory_table, block, offset)
        while cursor.consumed < size:
            count, inode_block, _ = _DIR_HEADER.unpack(cursor.read(_DIR_HEADER.size))
            if count >= _DIR_COUNT:
                raise CorruptionError(
                    f"a directory header declares {count + 1} entries"
                )
            for _ in range(count + 1):
                inode_offset, _, kind, name_size = _DIR_ENTRY.unpack(
                    cursor.read(_DIR_ENTRY.size)
                )
                if name_size + 1 > _NAME_MAX:
                    raise CorruptionError(
                        f"a directory entry name of {name_size + 1} bytes"
                    )
                name = cursor.read(name_size + 1)
                if b"/" in name or name in (b".", b".."):
                    raise CorruptionError(f"a directory entry is named {_shown(name)}")
                if not 1 <= kind <= 7 or inode_offset >= _METADATA_SIZE:
                    raise CorruptionError(
                        f"a directory entry for {_shown(name)} is not valid"
                    )
                yield name, inode_block << 16 | inode_offset, kind
        if cursor.consumed != size:
            raise CorruptionError(
                f"a directory listing runs to {cursor.consumed} bytes, not {size}"
            )

    def _inode_table_capacity(self) -> int:
        """At most how many bytes the inode table decodes to: every metadata block
        but the last decodes to 8 KiB, so its blocks, counted by their headers, times
        8 KiB. The table on disk is compressed, so its own size is no bound."""
        if self._inode_capacity is None:
            pos, blocks = self._sb.inode_table, 0
            while pos < self._sb.directory_table:
                (header,) = self._read_struct(pos, "<H", "a metadata header")
                length = header & ~_METADATA_UNCOMPRESSED
                if not 0 < length <= _METADATA_SIZE:
                    raise CorruptionError(
                        f"the metadata block at {pos} declares {length} bytes"
                    )
                pos += 2 + length
                blocks += 1
            self._inode_capacity = blocks * _METADATA_SIZE
        return self._inode_capacity

    def _block_list_fits(self, location: FileLocation) -> bool:
        """Count a file's block list before :meth:`_has_holes` scans it, and whether
        the lists counted so far still fit in the decoded inode table. In a valid
        image the files' lists lie in separate bytes of it, so together they fit; a
        damaged image whose lists overlap would otherwise make the scan quadratic.
        Once the total crosses it, it stays over: the total only grows."""
        self._block_list_bytes += location.block_count * 4
        return self._block_list_bytes <= self._inode_table_capacity()

    def _has_holes(self, location: FileLocation) -> bool:
        """Whether a file has a block stored with size 0, which reads as zeros.

        Only the block list says so: mksquashfs writes a sparse file under a basic
        inode, which has no "bytes saved" field."""
        remaining = location.block_count * 4
        cursor = self.block_list(location)
        while remaining:
            chunk = cursor.read(min(remaining, _METADATA_SIZE))
            remaining -= len(chunk)
            # A stored size of 0 is all-zero bytes in either byte order.
            if 0 in memoryview(chunk).cast("I"):
                return True
        return False

    @override
    def iter_members(self) -> Iterator[MemberRecord[FileLocation | None]]:
        """Every member, in listing order, or in fragment order where that would thrash.

        Listing order is the directory walk's: depth first, each directory's entries in
        the order stored, which every SquashFS writer sorts by name.

        A file whose tail is in a fragment block reads that block whole, and the reader
        keeps the last ``_FRAGMENT_CACHE`` of them. When reading the files in listing
        order would decode a fragment block a second time (the cache replayed over
        their blocks' starts and stored sizes, read from the fragment table, which
        needs no block decoded), the files with a tail come sorted by block and offset
        instead, so each block decodes once. Writers that fill fragments in name order
        never reach this: mksquashfs and gensquashfs keep one fragment in progress and
        mksquashfs ``-tailends`` two. sqfstar and tar2sqfs fill fragments in the tar's
        order, so they keep listing order when the tar is in name order. An image built
        from a tar in another order can reach the sort, and so can a crafted one, which
        in listing order would decode a whole fragment block for each small file.

        An image that lists one name twice keeps listing order, which says which entry
        is current.

        Then the members come as: directories, other members and files with no tail in
        listing order, so a directory still comes before its contents; then the files
        with a tail; then the hard links, in listing order, so each comes after the
        member it names.

        It takes two passes, and reads each inode once. The first walks the whole tree,
        then reads the non-directory inodes in their table order (each inode-table
        block decodes once, unless inodes overlap) and keeps of each a fixed-size
        record (``_RECORD``), plus a symlink's target. The second makes the members
        from the records, in the order the first chose. A hard link takes what it needs
        from the member it names, which keeps its owner, mode and time next to its
        name.

        What the first pass holds is charged to ``max_metadata_bytes`` as it is kept
        (``_charge``): each entry's path, and each symlink's target. The charge is at
        most what the members would be charged when they are made, so a listing it
        refuses would cross the limit anyway; refusing before the members are made
        bounds the name and target bytes the passes hold by the limit, where
        directories that share one listing or overlapping symlink inodes would hold far
        more than the image's size. What each entry costs beyond its bytes, the record
        included, is bounded by ``max_members`` only, as for every member.
        """
        self._block_list_bytes = 0
        self._charged = 0
        entries: list[_Entry] = []
        limits = self._context.config.listing_limits
        failure: ArchiveyError | None = None
        try:
            complete = self._walk(entries, limits.max_members)
        except ArchiveyError as exc:
            budget = limits.max_metadata_bytes
            if budget is not None and self._charged > budget:
                raise  # ``_charge`` refused: making the members would hold more
            failure, complete = exc, False
        limit = limits.max_members
        if limit is not None and len(entries) > limit:
            # The walk found more entries than ``max_members`` (it stops one past, or
            # failed on damage after it): refuse before any member, as without
            # ``streaming=True``, rather than yield the first ones.
            raise ResourceLimitError(
                f"Listing limit reached: max_members={limit} (the SquashFS tree "
                f"holds more than {limit} entries)"
            )
        files = self._file_inodes(entries)
        first = _first_with_inode(entries)
        # The members a hard link names: only their names are kept past their record.
        targets = {f for i, f in enumerate(first) if f not in (-1, i)}
        order: Sequence[int] = range(len(entries))
        if complete and failure is None:
            order = self._in_fragment_order(entries, files, first) or order
        # A damaged image keeps listing order: it yields the members before the damage,
        # then raises, as a walk that reads each inode as it goes would.
        names: dict[int, tuple[bytes, str, _Inode | None]] = {}
        for index in order:
            made = self._make_member(
                entries, index, files, first[index], names, targets
            )
            # The member holds the name now. A directory's entry stays: a later
            # member's message names the path through it (``_raw_name``).
            if entries[index].kind != _DIR:
                entries[index] = _MADE
            yield made
        if failure is not None:
            raise failure

    def _walk(self, entries: list[_Entry], limit: int | None) -> bool:
        """Append every entry of the tree to ``entries``, in listing order, reading only
        the directories' inodes. ``False`` when it stopped past ``limit`` entries, which
        the caller refuses before making any member. Each entry's path is charged
        (``_charge``) as the walk finds it."""
        budget = self._context.config.listing_limits.max_metadata_bytes
        charged = self._charged
        try:
            root = self._sb.root_inode
            if root & 0xFFFF >= _METADATA_SIZE:
                raise CorruptionError("the SquashFS root inode reference is not valid")
            inode = self._inode(root >> 16, root & 0xFFFF)
            if inode.type != _DIR:
                raise CorruptionError("the SquashFS root is not a directory")
            seen_dirs = {root}
            # (directory's entry, its listing, the length of its path and a "/")
            stack = [(-1, self._entries(_listing(inode)), 0)]
            while stack:
                parent, listing, prefix = stack[-1]
                item = next(listing, None)
                if item is None:
                    stack.pop()
                    continue
                if limit is not None and len(entries) > limit:
                    return False
                name, ref, kind = item
                path = prefix + len(name)
                # The member's raw name is the path's bytes, and its name decodes to at
                # least as many: ``_charge``. Inlined, as it runs once per entry.
                charged += 2 * path
                if budget is not None and charged > budget:
                    self._charge(charged - self._charged, "the directory tree's names")
                entry = _Entry(parent, name, ref, kind, None)
                if kind == _DIR:
                    inode = self._inode(ref >> 16, ref & 0xFFFF)
                    self._check_type(entries, entry, inode.type)
                    if entry.ref in seen_dirs:
                        raise CorruptionError(
                            f"directory {_shown(self._raw_name(entries, entry))} is "
                            "listed twice"
                        )
                    seen_dirs.add(entry.ref)
                    entry = entry._replace(inode=inode)
                    stack.append(
                        (len(entries), self._entries(_listing(inode)), path + 1)
                    )
                entries.append(entry)
            return True
        finally:
            # Every exit, a raise included: a damaged walk's names stay charged.
            self._charged = charged

    def _charge(self, nbytes: int, what: str) -> None:
        """Charge what the listing holds before its members are made to
        ``max_metadata_bytes``, and refuse the listing when the total crosses it.

        A path counts twice its length, once for the raw name and once for the name; a
        symlink target counts its length once, as its member's target. For names that
        are valid UTF-8, or decoded with a one-byte ``encoding``, each name weighs at
        least its stored length, so the charge never passes what the members will be
        charged when they are made (``member_metadata_bytes``): a listing this refuses
        would cross the limit as its members come. A multibyte ``encoding`` that
        decodes to fewer characters than the stored bytes (UTF-16) weighs the names
        at less, so this can refuse such a listing up to about twice early.
        """
        self._charged += nbytes
        budget = self._context.config.listing_limits.max_metadata_bytes
        if budget is not None and self._charged > budget:
            raise ResourceLimitError(
                f"Listing limit reached: max_metadata_bytes={budget} (at least "
                f"{self._charged} bytes before the members are made, for {what})"
            )

    def _file_inodes(self, entries: list[_Entry]) -> _FileScan:
        """Pass one over the inodes that are not directories, in table order so each
        inode-table block decodes once: keep a ``_RECORD`` of each, and a symlink's
        target (:class:`_FileScan`). The target is charged as it is kept (``_charge``).
        """
        records: dict[int, bytes] = {}
        symlinks: dict[int, bytes] = {}
        failed: set[int] = set()
        lists_over: int | None = None
        clean = True
        previous = -1
        inode_type = 0
        pack = _RECORD.pack
        # Each reference with the types its entries give, in table order. A type is
        # 1..7 (``_entries`` refuses any other), so it fits in the low three bits.
        for key in sorted({e.ref << 3 | e.kind for e in entries if e.kind != _DIR}):
            ref, kind = key >> 3, key & 7
            if ref != previous:
                previous = ref
                try:
                    inode = self._inode(ref >> 16, ref & 0xFFFF)
                except ArchiveyError:
                    failed.add(ref)
                    clean = False
                    continue
                inode_type, mode, uid, gid, mtime, body = inode
                if isinstance(body, FileLocation):
                    try:
                        if lists_over is None and not self._block_list_fits(body):
                            lists_over = ref
                        if lists_over is not None:
                            raise _lists_over()
                        sparse = self._has_holes(body)
                    except ArchiveyError:
                        failed.add(ref)
                        clean = False
                        continue
                    records[ref] = pack(
                        inode_type, sparse, mode, uid, gid, mtime, *body
                    )
                else:
                    if isinstance(body, bytes):
                        self._charge(len(body), "the symlink targets kept")
                        symlinks[ref] = body
                    records[ref] = pack(
                        inode_type, 0, mode, uid, gid, mtime, *_NO_LOCATION
                    )
            if inode_type != kind:
                clean = False
        return _FileScan(records, symlinks, failed, lists_over, clean)

    def _raise_again(self, ref: int, lists_over: int | None) -> NoReturn:
        """Raise the error the first pass met at inode ``ref`` (:class:`_FileScan`):
        read the inode again, then its block list. The listing stops at this raise,
        so it costs one read a listing."""
        inode = self._inode(ref >> 16, ref & 0xFFFF)
        assert isinstance(inode.body, FileLocation), "only a file's list fails"
        if lists_over is not None and ref >= lists_over:
            raise _lists_over()
        # Before ``lists_over`` the lists fit, unless the table's size did not read.
        self._inode_table_capacity()
        self._has_holes(inode.body)
        raise AssertionError("a file that failed the first pass read again")

    def _in_fragment_order(
        self,
        entries: list[_Entry],
        files: _FileScan,
        first: list[int],
    ) -> list[int] | None:
        """The members' order when listing order would decode a fragment block twice
        (:meth:`iter_members`), else ``None``. Only for an image whose every member
        reads without error."""
        if not files.clean:
            return None
        tails: list[tuple[int, int, int]] = []
        block_size = self._sb.block_size
        records, tail_of = files.records, _RECORD_TAIL.unpack_from
        for index, (entry, entry_first) in enumerate(zip(entries, first)):
            if entry_first == index and entry.kind == _FILE:
                size, fragment, offset = tail_of(records[entry.ref])
                if fragment != _NO_FRAGMENT and size % block_size:
                    tails.append((fragment, offset, index))
        # By the block's (start, stored size), as the cache keys it, not by table entry:
        # two entries can name one block, and two can name one start and disagree on
        # whether the bytes there are compressed. Looked up in table order; a bad entry
        # is reported by the member's read.
        keys: dict[int, tuple[int, int]] = {}
        try:
            for fragment in sorted({fragment for fragment, _, _ in tails}):
                keys[fragment] = self._fragment(fragment)
        except ArchiveyError:
            return None
        keyed = [(keys[fragment], offset, index) for fragment, offset, index in tails]
        if not _decodes_twice((key for key, _, _ in keyed), _FRAGMENT_CACHE):
            return None
        # The last entry listed under a name is the current one: an image that lists a
        # name twice keeps the order that says which.
        if len({(entry.parent, entry.name) for entry in entries}) < len(entries):
            return None
        tailed = {index for _, _, index in keyed}
        links = [i for i in range(len(entries)) if first[i] not in (-1, i)]
        rest = [
            i for i in range(len(entries)) if i not in tailed and first[i] in (-1, i)
        ]
        return rest + [index for _, _, index in sorted(keyed)] + links

    def _raw_name(self, entries: list[_Entry], entry: _Entry) -> bytes:
        """An entry's path, from its directories' names (for a message)."""
        parts = [entry.name]
        parent = entry.parent
        while parent >= 0:
            parts.append(entries[parent].name)
            parent = entries[parent].parent
        return b"/".join(reversed(parts))

    def _check_type(self, entries: list[_Entry], entry: _Entry, kind: int) -> None:
        """Refuse an entry whose directory gives it another type than its inode does."""
        if kind != entry.kind:
            raise CorruptionError(
                f"{_shown(self._raw_name(entries, entry))} is listed as type "
                f"{entry.kind}, its inode is {kind}"
            )

    def _make_member(
        self,
        entries: list[_Entry],
        index: int,
        files: _FileScan,
        first: int,
        names: dict[int, tuple[bytes, str, _Inode | None]],
        targets: set[int],
    ) -> MemberRecord[FileLocation | None]:
        """The member for ``entries[index]``. ``names`` holds the raw and decoded name
        of each member already made that a later one needs: its directory, or the
        member a hard link names, which always come first. For the latter it also holds
        its inode without the body, which is all a hard link's member takes from it.
        Other members take their inode from its record in ``files``, which this drops."""
        entry = entries[index]
        parent = entry.parent
        raw_name = names[parent][0] + b"/" + entry.name if parent >= 0 else entry.name
        record = b""
        sparse = 0
        if entry.inode is not None:
            kind, mode, uid, gid, mtime, _ = entry.inode
        elif first != index:
            linked = names[first][2]
            assert linked is not None, "a hard link's target is made first"
            kind, mode, uid, gid, mtime, _ = linked
        else:
            if entry.ref in files.failed:
                self._raise_again(entry.ref, files.lists_over)
            record = files.records.pop(entry.ref)
            kind, sparse, mode, uid, gid, mtime = _RECORD_HEAD.unpack_from(record)
        if kind != entry.kind:
            self._check_type(entries, entry, kind)
        path = self._context.decode_name(raw_name)
        member = ArchiveMember(
            type=MemberType.FILE,
            name=path,
            raw_name=raw_name,
            modified=datetime.fromtimestamp(mtime, UTC),
            mode=mode,
            uid=uid,
            gid=gid,
        )
        location: FileLocation | None = None
        if entry.kind == _DIR:
            member.type = MemberType.DIRECTORY
            names[index] = (raw_name, path, None)
        elif first != index:
            member.type = MemberType.HARDLINK
            member.link_target = names[first][1]
        else:
            if index in targets:
                names[index] = (
                    raw_name,
                    path,
                    _Inode(kind, mode, uid, gid, mtime, None),
                )
            if kind == _FILE:
                location = FileLocation._make(
                    _RECORD_LOCATION.unpack_from(record, _RECORD_HEAD.size)
                )
                member.size = location.size
                member.is_sparse = bool(sparse)
            elif kind == _SYMLINK:
                member.type = MemberType.SYMLINK
                target = files.symlinks.pop(entry.ref)
                member.link_target = self._context.decode_name(target)
            else:
                member.type = MemberType.OTHER
                member.extra["special_file_type"] = _SPECIAL[entry.kind]
        return MemberRecord(member, location)

    @override
    def open_member(
        self, member: ArchiveMember, locator: FileLocation | None
    ) -> MemberData:
        # archivey opens only a FILE: a hard link reaches the member it names.
        assert locator is not None, member.name
        return MemberData(self._file_stream(locator), bounded=True)

    def _file_stream(self, location: FileLocation) -> BinaryIO:
        """A regular file's bytes: its blocks decoded one at a time, then its tail."""
        block_size = self.block_size
        block_list = self.block_list(location)
        # Each block's stored size and start, read from the list as far as needed.
        stored: list[int] = []
        starts = [location.blocks_start]

        def read_block(index: int) -> bytes:
            if index == location.block_count:
                return self.fragment_tail(location, location.size % block_size)
            while len(stored) <= index:
                (size,) = struct.unpack("<I", block_list.read(4))
                stored.append(size)
                starts.append(starts[-1] + (size & ~_BLOCK_UNCOMPRESSED))
            expected = min(block_size, location.size - index * block_size)
            if stored[index] == 0:  # a sparse block: zeros, nothing stored
                return bytes(expected)
            return self.data_block(starts[index], stored[index], expected)

        return block_stream(location.size, block_size, read_block)

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(
            format_version="4.0",
            extra=ArchiveInfoExtra(
                {
                    "squashfs.compressor": self._compressor,
                    "squashfs.block_size": self._sb.block_size,
                }
            ),
        )


class _MetadataCursor:
    """Reads on through consecutive metadata blocks of one table."""

    def __init__(
        self, reader: SquashfsReader, table: int, block: int, offset: int
    ) -> None:
        self._reader = reader
        self._table = table
        self._pos = table + block
        self.offset = offset
        self.consumed = 0

    @property
    def block(self) -> int:
        """The current metadata block, as an offset from the start of the table."""
        return self._pos - self._table

    def read(self, n: int) -> bytes:
        """The next ``n`` bytes, crossing into the next metadata block as needed."""
        parts = []
        while n:
            data, next_pos = self._reader._metadata_block(self._pos)
            if self.offset > len(data):
                raise CorruptionError(
                    f"offset {self.offset} is past a {len(data)}-byte metadata block"
                )
            chunk = data[self.offset : self.offset + n]
            parts.append(chunk)
            n -= len(chunk)
            self.offset += len(chunk)
            self.consumed += len(chunk)
            if self.offset == len(data):
                self._pos, self.offset = next_pos, 0
        return b"".join(parts)


class SquashfsHandler(IndexedFormatHandler):
    """SquashFS 4.0 images: ``.squashfs``, ``.sqfs`` and snap packages."""

    format = ArchiveFormat.SQUASHFS
    extensions = (".squashfs", ".sqfs", ".snap")
    # The tables are at offsets the superblock gives, past the data blocks.
    non_seekable_reason = "its directory and inode tables come after the file data"
    # ``sqsh`` too, so an older big-endian image is refused by name, not left undetected.
    magic = (Magic(0, MAGIC), Magic(0, _SWAPPED_MAGIC))
    uses_encoding = True

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> SquashfsReader:
        return SquashfsReader(source, context)


SquashfsReadBackend = register_builtin_format(SquashfsHandler)
