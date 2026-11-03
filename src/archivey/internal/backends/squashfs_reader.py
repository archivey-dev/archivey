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

The reader is written against ``archivey.formats``. Beyond it, it uses archivey's own
handling of the ``lz4`` package (the PyPy rule, ``exclude_libraries`` and process
isolation) rather than a copy of it. Handbook page: ``dev-docs/formats/squashfs.md``.
"""

from __future__ import annotations

import io
import struct
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from typing import Any, BinaryIO, NamedTuple, cast

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    FormatHandler,
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
# of thousands of files and the inodes a listing reads twice (``iter_members``).
# Writers fill one or
# two fragments at a time in name order, so a few cover a walk in listing order; where
# they would not, ``iter_members`` puts the files with a tail in fragment order.
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
    assert isinstance(inode.body, tuple), "a directory inode's body is its listing"
    return inode.body


class _Entry(NamedTuple):
    """A directory entry the walk found, before its member is made."""

    parent: int  # index of its directory's entry, -1 for the root
    name: bytes
    ref: tuple[int, int]  # its inode: (metadata block, offset)
    kind: int  # the basic type the entry gives
    inode: _Inode | None  # read during the walk for a directory, else None


class _FileScan(NamedTuple):
    """What the first pass keeps of the inodes that are not directories: no inode, only
    what ordering needs. The second pass reads each inode again by its ref."""

    # A file with a tail, by inode: fragment index << 32 | offset in the fragment.
    tails: dict[tuple[int, int], int]
    sparse: set[tuple[int, int]]  # files with holes
    errors: dict[tuple[int, int], ArchiveyError]  # damaged inodes, raised in order
    clean: bool  # every inode read, and of the type its entry gives


def _decodes_twice(starts: Iterable[int]) -> bool:
    """Whether the reader's fragment cache, asked for the blocks at these starts in
    order, would decode one of them a second time."""
    cache: OrderedDict[int, None] = OrderedDict()
    decoded: set[int] = set()
    for start in starts:
        if start in cache:
            cache.move_to_end(start)
            continue
        if start in decoded:
            return True
        decoded.add(start)
        cache[start] = None
        if len(cache) > _FRAGMENT_CACHE:
            cache.popitem(last=False)
    return False


def _firsts(entries: list[_Entry]) -> list[int]:
    """For each entry, the first entry listed with its inode: itself, or for a hard link
    the member it names. -1 for a directory."""
    first: list[int] = []
    firsts: dict[tuple[int, int], int] = {}
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
        self._fragments: OrderedDict[int, bytes] = OrderedDict()
        self._ids = self._ids_table()
        # Block-list bytes scanned by the listing so far (``_has_holes``).
        self._block_list_bytes = 0
        self._inode_capacity: int | None = None

    # ── Decoding ─────────────────────────────────────────────────────────────────────

    def _lz4_natives(self) -> Natives:
        """Where LZ4 blocks decode (a child process unless ``process_isolation`` is
        ``NONE``), or ``PackageNotInstalledError`` when lz4 is missing, unused on this
        interpreter, or turned off by the caller's policy."""
        config = self._context.config
        excluded = config.formats.exclude_libraries
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
        start, stored = self._fragment(location.fragment)
        # ``_decodes_twice`` replays this cache's policy; change both together.
        block = self._fragments.get(start)
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
            self._fragments[start] = block
            if len(self._fragments) > _FRAGMENT_CACHE:
                self._fragments.popitem(last=False)
        else:
            self._fragments.move_to_end(start)
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
    ) -> Iterator[tuple[bytes, int, int, int]]:
        """(name, inode block, inode offset, type) for each entry of a listing."""
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
                yield name, inode_block, inode_offset, kind
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

    def _has_holes(self, location: FileLocation) -> bool:
        """Whether a file has a block stored with size 0, which reads as zeros.

        Only the block list says so: mksquashfs writes a sparse file under a basic
        inode, which has no "bytes saved" field. In a valid image the files' lists
        lie in separate bytes of the decoded inode table, so together they fit in it;
        a damaged image whose lists overlap would otherwise make the scan quadratic.
        """
        remaining = location.block_count * 4
        self._block_list_bytes += remaining
        if self._block_list_bytes > self._inode_table_capacity():
            raise CorruptionError(
                "the files' block lists add up to more than the inode table holds"
            )
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
        the order stored, which every SquashFS writer sorts by name. It takes two
        passes. The first walks the whole tree, then reads the non-directory inodes in
        their table order (each inode-table block decodes once) and keeps of each only
        what the order needs (:class:`_FileScan`). The second reads each member's
        inode again by its reference as it makes the member: holding every inode
        until the order is known cost half as much memory again as the listing.

        A file whose tail is in a fragment block reads that block whole, and the reader
        keeps the last ``_FRAGMENT_CACHE`` of them. When reading the files in listing
        order would decode a fragment block a second time (the cache replayed over
        where their blocks start, read from the fragment table, which needs no block
        decoded), the files with a tail come sorted by block and offset instead, so
        each block decodes once. Writers that fill fragments in name order never reach
        this: mksquashfs and gensquashfs keep one fragment in progress and mksquashfs
        ``-tailends`` two. sqfstar and tar2sqfs fill fragments in the tar's order, so
        they keep listing order when the tar is in name order. An image built from a
        tar in another order can reach the sort, and so can a crafted one, which in
        listing order would decode a whole fragment block for each small file.

        An image that lists one name twice keeps listing order, which says which entry
        is current.

        Then the members come as: directories, other members and files with no tail in
        listing order, so a directory still comes before its contents; then the files
        with a tail; then the hard links, in listing order, so each comes after the
        member it names.
        """
        self._block_list_bytes = 0
        entries: list[_Entry] = []
        limit = self._context.config.listing_limits.max_members
        failure: ArchiveyError | None = None
        try:
            complete = self._walk(entries, limit)
        except ArchiveyError as exc:
            failure, complete = exc, False
        files = self._file_inodes(entries)
        first = _firsts(entries)
        # The members a hard link names: only their names are kept past their record.
        targets = {f for i, f in enumerate(first) if f not in (-1, i)}
        order: Iterable[int] = range(len(entries))
        if complete and failure is None:
            order = self._in_fragment_order(entries, files, first) or order
        # A damaged image keeps listing order: it yields the members before the damage,
        # then raises, as a walk that reads each inode as it goes would.
        names: dict[int, tuple[bytes, str]] = {}
        for index in order:
            yield self._record(entries, index, files, first[index], names, targets)
        if failure is not None:
            raise failure

    def _walk(self, entries: list[_Entry], limit: int | None) -> bool:
        """Append every entry of the tree to ``entries``, in listing order, reading only
        the directories' inodes. ``False`` when it stopped past ``limit`` entries, where
        archivey refuses the listing anyway."""
        root = self._sb.root_inode
        root_ref = (root >> 16, root & 0xFFFF)
        if root_ref[1] >= _METADATA_SIZE:
            raise CorruptionError("the SquashFS root inode reference is not valid")
        inode = self._inode(*root_ref)
        if inode.type != _DIR:
            raise CorruptionError("the SquashFS root is not a directory")
        seen_dirs = {root_ref}
        stack = [(-1, self._entries(_listing(inode)))]
        while stack:
            parent, listing = stack[-1]
            item = next(listing, None)
            if item is None:
                stack.pop()
                continue
            if limit is not None and len(entries) > limit:
                return False
            name, inode_block, inode_offset, kind = item
            entry = _Entry(parent, name, (inode_block, inode_offset), kind, None)
            if kind == _DIR:
                inode = self._inode(*entry.ref)
                self._check_type(entries, entry, inode)
                if entry.ref in seen_dirs:
                    raise CorruptionError(
                        f"directory {_shown(self._raw_name(entries, entry))} is "
                        "listed twice"
                    )
                seen_dirs.add(entry.ref)
                entry = entry._replace(inode=inode)
                stack.append((len(entries), self._entries(_listing(inode))))
            entries.append(entry)
        return True

    def _file_inodes(self, entries: list[_Entry]) -> _FileScan:
        """Pass one over the inodes that are not directories, in table order so each
        inode-table block decodes once: keep only what ordering needs (:class:`_FileScan`).
        A damaged inode is kept as its error, raised when its member comes."""
        tails: dict[tuple[int, int], int] = {}
        sparse: set[tuple[int, int]] = set()
        errors: dict[tuple[int, int], ArchiveyError] = {}
        clean = True
        previous: tuple[int, int] | None = None
        inode_type = 0
        for ref, kind in sorted({(e.ref, e.kind) for e in entries if e.kind != _DIR}):
            if ref != previous:
                previous = ref
                try:
                    inode = self._inode(*ref)
                    inode_type = inode.type
                    location = inode.body
                    if isinstance(location, FileLocation):
                        if self._has_holes(location):
                            sparse.add(ref)
                        if (
                            location.fragment != _NO_FRAGMENT
                            and location.size % self._sb.block_size
                        ):
                            tails[ref] = (
                                location.fragment << 32 | location.fragment_offset
                            )
                except ArchiveyError as exc:
                    errors[ref] = exc
                    clean = False
            if inode_type != kind:
                clean = False
        return _FileScan(tails, sparse, errors, clean)

    def _in_fragment_order(
        self,
        entries: list[_Entry],
        files: _FileScan,
        first: list[int],
    ) -> list[int] | None:
        """The members' order when listing order would decode a fragment block twice
        (:meth:`iter_members`), else ``None``. Only for an image whose every member
        reads without error."""
        # The last entry listed under a name is the current one: an image that lists a
        # name twice keeps the order that says which.
        if len({(entry.parent, entry.name) for entry in entries}) < len(entries):
            return None
        if not files.clean:
            return None
        tails: list[tuple[int, int, int]] = []
        for index, entry in enumerate(entries):
            packed = files.tails.get(entry.ref)
            if packed is not None and first[index] == index:
                tails.append((packed >> 32, packed & 0xFFFFFFFF, index))
        # By the block's start, as the cache keys it: two table entries can name one
        # block. Looked up in table order; a bad entry is reported by the member's read.
        starts: dict[int, int] = {}
        try:
            for fragment in sorted({fragment for fragment, _, _ in tails}):
                starts[fragment] = self._fragment(fragment)[0]
        except ArchiveyError:
            return None
        tails = [(starts[fragment], offset, index) for fragment, offset, index in tails]
        if not _decodes_twice(start for start, _, _ in tails):
            return None
        tailed = {index for _, _, index in tails}
        links = [i for i in range(len(entries)) if first[i] not in (-1, i)]
        rest = [
            i for i in range(len(entries)) if i not in tailed and first[i] in (-1, i)
        ]
        return rest + [index for _, _, index in sorted(tails)] + links

    def _raw_name(self, entries: list[_Entry], entry: _Entry) -> bytes:
        """An entry's path, from its directories' names (for a message)."""
        parts = [entry.name]
        parent = entry.parent
        while parent >= 0:
            parts.append(entries[parent].name)
            parent = entries[parent].parent
        return b"/".join(reversed(parts))

    def _check_type(self, entries: list[_Entry], entry: _Entry, inode: _Inode) -> None:
        if inode.type != entry.kind:
            raise CorruptionError(
                f"{_shown(self._raw_name(entries, entry))} is listed as type "
                f"{entry.kind}, its inode is {inode.type}"
            )

    def _record(
        self,
        entries: list[_Entry],
        index: int,
        files: _FileScan,
        first: int,
        names: dict[int, tuple[bytes, str]],
        targets: set[int],
    ) -> MemberRecord[FileLocation | None]:
        """The member for ``entries[index]``. ``names`` holds the raw and decoded name
        of each member already made that a later one needs: its directory, or the
        member a hard link names, which always come first."""
        entry = entries[index]
        prefix = names[entry.parent][0] + b"/" if entry.parent >= 0 else b""
        raw_name = prefix + entry.name
        sparse = False
        if entry.inode is not None:
            inode = entry.inode
        else:
            error = files.errors.get(entry.ref)
            if error is not None:
                raise error
            inode = self._inode(*entry.ref)
            sparse = entry.ref in files.sparse
            self._check_type(entries, entry, inode)
        path = self._context.decode_name(raw_name)
        member = ArchiveMember(
            type=MemberType.FILE,
            name=path,
            raw_name=raw_name,
            modified=datetime.fromtimestamp(inode.mtime, UTC),
            mode=inode.mode,
            uid=inode.uid,
            gid=inode.gid,
        )
        location: FileLocation | None = None
        if entry.kind == _DIR:
            member.type = MemberType.DIRECTORY
            names[index] = (raw_name, path)
        elif first != index:
            member.type = MemberType.HARDLINK
            member.link_target = names[first][1]
        else:
            if index in targets:
                names[index] = (raw_name, path)
            if entry.kind == _FILE:
                assert isinstance(inode.body, FileLocation)
                location = inode.body
                member.size = location.size
                member.is_sparse = sparse
            elif entry.kind == _SYMLINK:
                assert isinstance(inode.body, bytes)
                member.type = MemberType.SYMLINK
                member.link_target = self._context.decode_name(inode.body)
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


class SquashfsHandler(FormatHandler):
    """SquashFS 4.0 images: ``.squashfs``, ``.sqfs`` and snap packages."""

    format = ArchiveFormat.SQUASHFS
    extensions = (".squashfs", ".sqfs", ".snap")
    # ``sqsh`` too, so an older big-endian image is refused by name, not left undetected.
    magic = (Magic(0, MAGIC), Magic(0, _SWAPPED_MAGIC))
    uses_encoding = True

    @override
    def open(self, source: ReaderSource, context: ReaderContext) -> SquashfsReader:
        return SquashfsReader(source, context)


SquashfsReadBackend = register_builtin_format(
    SquashfsHandler,
    # The tables are at offsets the superblock gives, past the data blocks.
    NON_SEEKABLE_REASON="its directory and inode tables come after the file data",
)
