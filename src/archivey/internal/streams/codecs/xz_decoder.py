"""Seekable XZ decoder for :class:`~.decompressor_stream.DecompressorStream`.

Opened via :class:`~.codecs.XzCodec` / ``open_codec_stream(Codec.XZ, …)``. Backward
index scan + streaming state machine over stdlib ``lzma``.

XZ binary format (summary):
  A file is a sequence of one or more XZ streams, optionally separated by 4-byte-aligned
  null padding.

  Per stream:
    Header  (12 bytes): magic(6) + stream flags(2) + CRC32(4)
    Blocks  (variable): one or more LZMA2 blocks
    Index   (variable): MBI-encoded list of (unpadded_size, uncompressed_size) per block;
                        preceded by a 0x00 indicator byte; padded to a 4-byte boundary;
                        followed by CRC32(4)
    Footer  (12 bytes): CRC32(4) + backward_size(4) + stream flags(2) + magic(2)

  backward_size encodes the index size: actual_bytes = (value + 1) * 4.

XZ spec: https://tukaani.org/xz/xz-file-format.txt
"""

from __future__ import annotations

import functools
import io
import itertools
import lzma
import os
import struct
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import BinaryIO

from archivey.diagnostics import DiagnosticCode, DigestContext, SeekIndexContext
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.config import DecoderLimits, probe_lzma_dictionary
from archivey.internal.diagnostics_collector import (
    DiagnosticCollector,
    resolve_collector,
)
from archivey.internal.logs import streams as logger
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Decompressor, Natives
from archivey.internal.streams.decompressor_stream import (
    TRAILING_DATA_CANDIDATES,
    TRAILING_DATA_SEARCH,
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    PrebuiltIndex,
    SeekPoint,
    SpacedCollector,
    build_index_backwards,
    damaged_stream_error,
    emit_index_thinned,
    near_stream_magic,
    release_decoder,
    truncated_message,
)

_XZ_STREAM_MAGIC = b"\xfd7zXZ\x00"
_XZ_FOOTER_MAGIC = b"YZ"
_STREAM_HEADER_SIZE = 12
_STREAM_FOOTER_SIZE = 12


def _round_up_4(n: int) -> int:
    return (n + 3) & ~3


def _decode_mbi(data: Iterator[int]) -> tuple[int, int]:
    """Decode a multi-byte integer from ``data``; return ``(value, bytes_consumed)``."""
    value = 0
    shift = 0
    for i in range(9):  # XZ spec: max 9 bytes per MBI
        byte = next(data, None)
        if byte is None:
            raise CorruptionError("XZ index MBI truncated")
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            if byte == 0 and i > 0:
                # XZ spec §1.2 requires the shortest encoding; liblzma rejects a
                # trailing 0x00 byte, so the seek index does too.
                raise CorruptionError("XZ index MBI is not minimally encoded")
            return value, i + 1
        shift += 7
    raise CorruptionError("XZ index MBI exceeds 9 bytes")


@dataclass(slots=True)
class _XzBlockBounds:
    """One block's place in the file, and what resuming from it needs.

    The ``stream_*`` fields come from the stream's footer and index, not from the other
    blocks: ``_XzBlockResume`` decodes from this block to where the stream's blocks end,
    so a seek table can keep any subset of a stream's blocks.
    """

    compressed_start: int
    decompressed_start: int
    unpadded_size: int
    uncompressed_size: int
    check: int
    # Where the stream's last block ends and its index starts.
    blocks_end: int
    stream_decompressed_end: int
    # Just past the stream footer, where the next stream (or padding) begins.
    stream_compressed_end: int

    @property
    def decompressed_end(self) -> int:
        return self.decompressed_start + self.uncompressed_size


def _parse_xz_header(data: bytes) -> int:
    if len(data) < _STREAM_HEADER_SIZE:
        raise CorruptionError(f"XZ stream header too short: {len(data)} bytes")
    if data[:6] != _XZ_STREAM_MAGIC:
        raise CorruptionError(f"XZ stream header magic not found (got {data[:6]!r})")
    stream_flags = data[6:8]
    stored_crc = struct.unpack_from("<I", data, 8)[0]
    computed_crc = zlib.crc32(stream_flags) & 0xFFFFFFFF
    if stored_crc != computed_crc:
        raise CorruptionError(
            f"XZ stream header CRC32 mismatch: stored {stored_crc:#010x}, "
            f"computed {computed_crc:#010x}"
        )
    if stream_flags[0] != 0:
        raise CorruptionError(
            f"XZ stream flags reserved byte is non-zero: {stream_flags[0]:#04x}"
        )
    return stream_flags[1] & 0x0F


def _parse_xz_footer(data: bytes) -> tuple[int, int]:
    if len(data) < _STREAM_FOOTER_SIZE:
        raise CorruptionError(f"XZ stream footer too short: {len(data)} bytes")
    if data[10:12] != _XZ_FOOTER_MAGIC:
        raise CorruptionError(
            f"XZ stream footer magic 'YZ' not found (got {data[10:12]!r})"
        )
    stored_crc = struct.unpack_from("<I", data, 0)[0]
    backward_size_raw = struct.unpack_from("<I", data, 4)[0]
    stream_flags = data[8:10]
    computed_crc = zlib.crc32(data[4:10]) & 0xFFFFFFFF
    if stored_crc != computed_crc:
        raise CorruptionError(
            f"XZ stream footer CRC32 mismatch: stored {stored_crc:#010x}, "
            f"computed {computed_crc:#010x}"
        )
    if stream_flags[0] != 0:
        raise CorruptionError(
            f"XZ stream flags reserved byte is non-zero: {stream_flags[0]:#04x}"
        )
    check = stream_flags[1] & 0x0F
    backward_size_bytes = (backward_size_raw + 1) * 4
    return check, backward_size_bytes


def _iter_xz_index(data: bytes) -> Iterator[tuple[int, int]]:
    """:func:`_walk_xz_index` over an index held in memory."""
    return _walk_xz_index(iter(data), len(data))


def _walk_xz_index(data: Iterator[int], length: int) -> Iterator[tuple[int, int]]:
    """Yield one stream's ``(unpadded_size, uncompressed_size)`` records, validating.

    ``data`` gives the index bytes (without its CRC32) one at a time and ``length`` is
    how many there are, so the backward scan can feed an index from the file in bounded
    chunks (:class:`_XzIndexSource`) instead of holding it whole. A ``data`` that ends
    early is a truncated index. A record can be as small as two bytes, so callers that
    may meet millions walk the records rather than store them. The length and padding
    checks run after the last record, so a caller must exhaust the iterator for the
    index to count as valid.
    """
    indicator = next(data, None)
    if indicator != 0x00:
        raise CorruptionError(
            f"XZ index indicator byte expected 0x00, got {indicator:#04x}"
            if indicator is not None
            else "XZ index is empty"
        )
    offset = 1
    num_records, consumed = _decode_mbi(data)
    offset += consumed
    for _ in range(num_records):
        unpadded_size, consumed = _decode_mbi(data)
        offset += consumed
        uncompressed_size, consumed = _decode_mbi(data)
        offset += consumed
        if unpadded_size == 0:
            raise CorruptionError("XZ index: unpadded_size must be > 0")
        yield unpadded_size, uncompressed_size
    # The footer's backward size fixes the index length, so the records plus padding
    # must fill it exactly: fewer records than the index carries, or padding cut short,
    # is a malformed index (liblzma, which does the decoding, rejects both).
    padded_len = _round_up_4(offset)
    if padded_len != length:
        raise CorruptionError(
            f"XZ index length mismatch: records end at {padded_len}, "
            f"index is {length} bytes"
        )
    for i in range(offset, padded_len):
        byte = next(data, None)
        if byte is None:
            raise CorruptionError("XZ index truncated")
        if byte != 0:
            raise CorruptionError(f"XZ index padding byte {i} is non-zero: {byte:#04x}")


# The backward scan reads a stream's index from the file at most this many bytes at a
# time. Only the 12-byte footer must be valid for its backward size to be believed, so
# an index declared larger than this is never read whole: a footer can claim an index
# as large as the file. A real index takes a few bytes per block, so below about
# 200 000 blocks it is one read.
_INDEX_READ_CHUNK = 1 << 20


def _index_chunks(stream: BinaryIO, start: int, length: int) -> Iterator[bytes]:
    """Yield ``length`` bytes of ``stream`` from ``start``, at most a chunk at a time.

    The stream is moved before each read, so another walk may use it in between.
    """
    end = start + length
    while start < end:
        stream.seek(start)
        chunk = stream.read(min(_INDEX_READ_CHUNK, end - start))
        if not chunk:
            raise CorruptionError("XZ index truncated")
        start += len(chunk)
        yield chunk


class _XzIndexSource:
    """One stream's index (without its CRC32) in the file, checked and walked.

    An index declared at most :data:`_INDEX_READ_CHUNK` bytes long is read once and
    kept; a larger one is re-read from the file, a chunk at a time, by every pass. The
    choice keys on the declared length, never on how much a read returned.
    """

    def __init__(self, stream: BinaryIO, start: int, size_with_crc: int) -> None:
        self._stream = stream
        self._start = start
        self.length = size_with_crc - 4
        self._held: bytes | None = None
        self._held_crc = b""
        if self.length <= _INDEX_READ_CHUNK:
            stream.seek(start)
            data = stream.read(size_with_crc)
            if len(data) < size_with_crc:
                raise CorruptionError("XZ index truncated")
            self._held = data[: self.length]
            self._held_crc = data[self.length :]

    def _chunks(self) -> Iterator[bytes]:
        if self._held is not None:
            return iter((self._held,))
        return _index_chunks(self._stream, self._start, self.length)

    def check_crc(self) -> None:
        """Raise :class:`CorruptionError` unless the index matches its CRC32."""
        computed = 0
        for chunk in self._chunks():
            computed = zlib.crc32(chunk, computed)
        if self._held is not None:
            stored_bytes = self._held_crc
        else:
            self._stream.seek(self._start + self.length)
            stored_bytes = self._stream.read(4)
            if len(stored_bytes) < 4:
                raise CorruptionError("XZ index truncated")
        stored = struct.unpack("<I", stored_bytes)[0]
        if stored != computed:
            raise CorruptionError(
                f"XZ index CRC32 mismatch: stored {stored:#010x}, "
                f"computed {computed:#010x}"
            )

    def records(self) -> Iterator[tuple[int, int]]:
        """:func:`_walk_xz_index` over the index; each call walks it from the start."""
        if self._held is not None:
            return _walk_xz_index(iter(self._held), self.length)
        return _walk_xz_index(
            itertools.chain.from_iterable(self._chunks()), self.length
        )


def _stream_padding_length(data: bytes | bytearray, offset: int = 0) -> int:
    """How many bytes of stream padding (4-byte groups of zeros) start at ``offset``.

    The forward decoder (``_XzState``) and :func:`_data_end` both use it, so they agree
    on where the next stream header starts. No padding, the common case, costs one byte
    compare; a run of zeros is measured with ``lstrip`` over slices of at most
    :data:`_PADDING_SCAN_CHUNK`, so the cost follows the run, not the buffer.
    """
    if data[offset : offset + 1] != b"\x00":
        return 0
    run = 0
    pos = offset
    while pos < len(data):
        piece = data[pos : pos + _PADDING_SCAN_CHUNK]
        rest = len(piece.lstrip(b"\x00"))
        run += len(piece) - rest
        if rest:
            break
        pos += len(piece)
    return run - run % 4


# Stream padding is scanned backwards this many bytes per read, and measured forwards
# this many bytes per slice; a multiple of 4.
_PADDING_SCAN_CHUNK = 64 * 1024


def _skip_stream_padding_backwards(
    stream: BinaryIO, compressed_end: int, stop_at: int
) -> int:
    """Return the end of the stream before any zero padding that ends at ``compressed_end``.

    Stream padding (XZ spec §2.2) is 4-byte groups of zeros, aligned to the end being
    walked back from, and unbounded on a well-formed file. Most streams carry none, so
    the first read is one group; each all-zero read grows the next sixteenfold, up to
    :data:`_PADDING_SCAN_CHUNK`. No padding costs 4 bytes, and megabytes of it cost a
    few dozen reads rather than one ``seek`` + ``read(4)`` per group. The result is the
    offset just past the last group holding a non-zero byte, or a value ``<= stop_at``
    when every group down to ``stop_at`` is zero. As with a group-at-a-time walk, the
    lowest group may reach up to 3 bytes below ``stop_at``, and a group that would start
    before offset 0 is an error.
    """
    chunk_limit = 4
    while compressed_end > stop_at:
        groups = -(-(compressed_end - stop_at) // 4)
        groups = min(groups, chunk_limit // 4, compressed_end // 4)
        if groups == 0:
            raise CorruptionError("XZ file too small to contain a valid stream")
        start = compressed_end - 4 * groups
        stream.seek(start)
        chunk = stream.read(4 * groups)
        if len(chunk) < 4 * groups:
            raise CorruptionError("XZ file truncated during backward scan")
        nonzero_end = len(chunk.rstrip(b"\x00"))
        if nonzero_end:
            return start + _round_up_4(nonzero_end)
        compressed_end = start
        chunk_limit = min(chunk_limit * 16, _PADDING_SCAN_CHUNK)
    return compressed_end


def _ends_with_footer(stream: BinaryIO, end: int, stop_at: int) -> bool:
    """Whether a valid stream footer ends at ``end``, after any stream padding."""
    try:
        end = _skip_stream_padding_backwards(stream, end, stop_at)
        if end - stop_at < _STREAM_FOOTER_SIZE:
            return False
        stream.seek(end - _STREAM_FOOTER_SIZE)
        _parse_xz_footer(stream.read(_STREAM_FOOTER_SIZE))
    except CorruptionError:
        return False
    return True


def _data_end(stream: BinaryIO, file_size: int, stop_at: int) -> int:
    """Where the xz data ends: ``file_size``, or the last footer before trailing data.

    A file with something appended does not end with a footer. The footer's magic,
    its CRC-32 and the 4-byte alignment every stream keeps (XZ spec §2.1) find the last
    one in the final :data:`TRAILING_DATA_SEARCH` bytes, trying at most
    :data:`TRAILING_DATA_CANDIDATES` occurrences of the magic; the walk then checks
    every index and header as usual. The forward decoder reports the appended bytes
    when a read reaches them.

    A footer followed (after any stream padding) by a stream header's magic is not the
    last one: the forward decoder starts a stream there, so the later stream's own
    footer is damaged. That is corruption, not appended data, and is raised so the
    last stream is never dropped from the size and the seek range. A header magic
    damaged in a few places (:func:`near_stream_magic`) is corruption too, as the
    forward decoder finds it.
    """
    if _ends_with_footer(stream, file_size, stop_at):
        return file_size
    start = max(stop_at, file_size - TRAILING_DATA_SEARCH)
    stream.seek(start)
    window = stream.read(file_size - start)
    at = len(window)
    for _ in range(TRAILING_DATA_CANDIDATES):
        at = window.rfind(_XZ_FOOTER_MAGIC, 0, at + 1)
        if at < 0:
            break
        end = start + at + len(_XZ_FOOTER_MAGIC)
        if end % 4 == 0 and at + 2 >= _STREAM_FOOTER_SIZE:
            try:
                _parse_xz_footer(window[at + 2 - _STREAM_FOOTER_SIZE : at + 2])
            except CorruptionError:
                pass
            else:
                after = at + 2
                # Same padding rule as _XzState._process (_NEED_HEADER); the two
                # must agree on where the next header starts.
                after += _stream_padding_length(window, after)
                header = window[after : after + 6]
                if header == _XZ_STREAM_MAGIC:
                    raise CorruptionError(
                        f"XZ stream starting at offset {start + after} has no valid "
                        "footer at the end of the file"
                    )
                if near_stream_magic(header, _XZ_STREAM_MAGIC):
                    raise damaged_stream_error(start + after)
                return end
        at -= 1
        if at < 0:
            break
    raise CorruptionError(
        "XZ stream footer not found at the end of the file or in the "
        f"{len(window)} bytes before it (at most {TRAILING_DATA_CANDIDATES} "
        "candidates tried)"
    )


def _read_xz_index_backwards(
    stream: BinaryIO,
    file_size: int,
    stop_at: int = 0,
    start_decompressed_offset: int = 0,
    on_thinned: Callable[[], None] | None = None,
) -> list[_XzBlockBounds]:
    """Walk XZ streams from EOF toward ``stop_at``, building a block index.

    Reads only footers and indices — no decompression. Returns blocks in forward order
    with absolute compressed/decompressed offsets.

    Past the seek-table cap the blocks kept are thinned by decompressed distance
    (:class:`SpacedCollector`) and ``on_thinned`` is called; any subset of blocks
    resumes correctly (``_XzBlockResume``). Within a stream the records are walked
    forward and thinned there first, so a stream declaring millions of blocks is never
    held whole. The last block is always kept, so the total stays exact.
    """
    # Keyed on decompressed distance from the block's start to the end of the scan,
    # which only grows as the walk goes back.
    kept: SpacedCollector[tuple[int, _XzBlockBounds]] = SpacedCollector(lambda e: e[0])
    thinned = False
    total = 0
    compressed_end = _data_end(stream, file_size, stop_at)

    while compressed_end > stop_at:
        compressed_end = _skip_stream_padding_backwards(stream, compressed_end, stop_at)

        if compressed_end <= stop_at:
            break

        if compressed_end < _STREAM_FOOTER_SIZE:
            raise CorruptionError(
                f"Not enough bytes for XZ footer at offset {compressed_end}"
            )
        stream.seek(compressed_end - _STREAM_FOOTER_SIZE)
        footer_data = stream.read(_STREAM_FOOTER_SIZE)
        if len(footer_data) < _STREAM_FOOTER_SIZE:
            raise CorruptionError("XZ footer truncated")
        check, index_size_bytes = _parse_xz_footer(footer_data)

        index_end = compressed_end - _STREAM_FOOTER_SIZE
        index_with_crc_start = index_end - index_size_bytes
        if index_with_crc_start < 0:
            raise CorruptionError("XZ index extends before start of file")

        index = _XzIndexSource(stream, index_with_crc_start, index_size_bytes)
        index.check_crc()

        blocks_compressed_total = 0
        stream_size = 0
        for unpadded_size, uncompressed_size in index.records():
            blocks_compressed_total += _round_up_4(unpadded_size)
            stream_size += uncompressed_size
        stream_header_start = (
            index_with_crc_start - blocks_compressed_total - _STREAM_HEADER_SIZE
        )
        if stream_header_start < 0:
            raise CorruptionError("XZ stream header start computes to negative offset")

        stream.seek(stream_header_start)
        header_data = stream.read(_STREAM_HEADER_SIZE)
        if len(header_data) < _STREAM_HEADER_SIZE:
            raise CorruptionError("XZ stream header truncated")
        header_check = _parse_xz_header(header_data)
        if header_check != check:
            raise CorruptionError(
                f"XZ stream header check {header_check} != footer check {check}"
            )

        # Blocks in forward order, offsets relative to the stream for now. Thinned on
        # their own (keyed on the in-stream offset) and the stream's last block always
        # added back, so the collector below sees them last first.
        in_stream: SpacedCollector[_XzBlockBounds] = SpacedCollector(
            lambda b: b.decompressed_start
        )
        block_compressed_start = stream_header_start + _STREAM_HEADER_SIZE
        block_decompressed_start = 0
        last: _XzBlockBounds | None = None
        for unpadded_size, uncompressed_size in index.records():
            last = _XzBlockBounds(
                compressed_start=block_compressed_start,
                decompressed_start=block_decompressed_start,
                unpadded_size=unpadded_size,
                uncompressed_size=uncompressed_size,
                check=check,
                blocks_end=index_with_crc_start,
                stream_decompressed_end=stream_size,
                stream_compressed_end=compressed_end,
            )
            in_stream.add(last)
            block_compressed_start += _round_up_4(unpadded_size)
            block_decompressed_start += uncompressed_size
        blocks = in_stream.items
        if last is not None and blocks[-1] is not last:
            blocks.append(last)
        thinned = thinned or in_stream.thinned
        # Relative offsets become distances from the end of the scan.
        for block in reversed(blocks):
            kept.add((total + stream_size - block.decompressed_start, block))
        total += stream_size
        compressed_end = stream_header_start

    thinned = thinned or kept.thinned
    if thinned and on_thinned is not None:
        on_thinned()
    end = start_decompressed_offset + total
    result: list[_XzBlockBounds] = []
    for dist, block in reversed(kept.items):
        start = end - dist
        # stream_decompressed_end still holds the stream's size.
        block.stream_decompressed_end += start - block.decompressed_start
        block.decompressed_start = start
        result.append(block)
    return result


# liblzma's ``memlimit`` counts a decoder's whole working set: the dictionary the
# header declares plus the decoder's own overhead. The overhead depends on the liblzma
# build: measured at 65 592 bytes for a lone LZMA2 filter and 65 408 for an LZMA Alone
# decoder on Ubuntu's liblzma 5.4.5, and at 66 200 and 66 016 on the liblzma in the
# python-build-standalone CPython 3.14; the longest chain xz allows (four filters)
# measured 67 992 on 5.4.5. The allowance, about twice that, keeps a dictionary exactly
# at ``max_decoder_memory`` readable, as it is on the raw LZMA and lzip paths, which
# compare the declared dictionary itself. It is kept small because it is also slack:
# the allowance minus the overhead, about 64 KiB on the builds measured. A cap set that
# much or less below a size an xz or .lzma header declares admits that size there.
_LIBLZMA_OVERHEAD_ALLOWANCE = 128 * 1024
_LIBLZMA_MEMLIMIT_MAX = 2**64 - 1


def new_capped_decompressor(
    limits: DecoderLimits,
    format: int = lzma.FORMAT_XZ,
    natives: Natives = IN_PROCESS,
) -> Decompressor:
    """A liblzma decompressor that refuses a dictionary over ``max_decoder_memory``.

    xz and LZMA Alone (``format``) let liblzma read the dictionary size: an xz block
    header declares its own, and ``_XzState`` hands liblzma whole streams without
    walking their blocks; a ``.lzma`` header declares one per stream. liblzma
    compares ``memlimit`` against the declared dictionary after decoding the header
    and before allocating anything for it, which is the same guarantee
    :func:`~archivey.internal.config.check_decoder_memory` gives the other paths. The
    refusal comes from ``decompress``, so on read, not on open.
    """
    cap = limits.max_decoder_memory
    # liblzma's memlimit is a uint64. A cap whose allowance-padded value does not fit
    # refuses nothing liblzma could be asked for, so it is left off, as for no cap.
    if cap is None or cap + _LIBLZMA_OVERHEAD_ALLOWANCE > _LIBLZMA_MEMLIMIT_MAX:
        return natives.lzma_decompressor(format=format)
    return natives.lzma_decompressor(
        format=format, memlimit=cap + _LIBLZMA_OVERHEAD_ALLOWANCE
    )


# A binding with no message for ``LZMA_MEMLIMIT_ERROR`` words it by its code, 6 (PyPy:
# "Unrecognised error from liblzma: 6"); CPython's message starts "Memory usage limit".
_NUMERIC_MEMLIMIT_SUFFIX = "error from liblzma: 6"


def lzma_error_to_archivey(
    exc: lzma.LZMAError, context: str, limits: DecoderLimits | None = None
) -> ArchiveyError:
    """Map a liblzma error to archivey's by its cause.

    CPython raises every liblzma failure as the one ``LZMAError`` type and tells them
    apart only by message text, the same on 3.10 to 3.14, so the text is what there
    is to match on. An options error names a filter or filter property this liblzma
    cannot decode (a block header with a valid CRC naming an unknown filter gets
    here). liblzma gives the same message for corrupt filter properties, but the
    callers that decode properties themselves (the ZIP and 7z readers) classify that
    as corruption before it can arrive here. An unsupported check names an integrity
    check it does not implement, and a memlimit error is a configured cap refusing a
    declared dictionary. None of those is damage. Anything else (corrupt data, a
    header that is not LZMA, an unrecognized code) stays :class:`CorruptionError`.
    ``LZMA_MEM_ERROR`` never gets here: CPython raises it as ``MemoryError``. PyPy's
    ``lzma`` has no message for ``LZMA_MEMLIMIT_ERROR`` and words it by its code
    (:data:`_NUMERIC_MEMLIMIT_SUFFIX`).

    ``limits`` are the limits the decompressor was built with
    (:func:`new_capped_decompressor`). Only a decompressor built with a ``memlimit``
    raises "Memory usage limit exceeded", and that memlimit is ``max_decoder_memory``
    plus the overhead allowance, so the message names the cap when ``limits`` has one.
    """
    text = str(exc)
    if text.startswith(
        ("Invalid or unsupported options", "Unsupported integrity check")
    ):
        return UnsupportedFeatureError(f"{context}: {exc} (liblzma cannot decode this)")
    if text.startswith("Memory usage limit") or text.endswith(_NUMERIC_MEMLIMIT_SUFFIX):
        cap = limits.max_decoder_memory if limits is not None else None
        if cap is not None:
            return ResourceLimitError(
                f"Decoder limit reached: max_decoder_memory={cap} ({context}: the "
                f"stream's declared dictionary needs more than that; liblzma refused "
                f"it before allocating). The archive chose this number; raise "
                f"DecoderLimits.max_decoder_memory if the archive is trusted."
            )
        return ResourceLimitError(
            f"{context}: {exc}. The archive declared a dictionary larger than the "
            f"decoder memory cap; raise DecoderLimits.max_decoder_memory if the "
            f"archive is trusted."
        )
    return CorruptionError(f"{context}: {exc}")


def _report_unverifiable_check(
    check: int, reported: set[int], collector: DiagnosticCollector | None
) -> None:
    """Emit ``DIGEST_UNVERIFIABLE`` for a stream whose check liblzma cannot compute.

    liblzma decodes such a stream without verifying it, and CPython never asks for
    ``LZMA_TELL_UNSUPPORTED_CHECK``, so nothing else would say so. Check 0 (none) is
    supported: the stream offers no check to run. ``reported`` holds the check IDs
    already reported for this file, so a seek that decodes a stream again, or a second
    stream with the same check, does not report it twice.
    """
    if lzma.is_check_supported(check) or check in reported:
        return
    reported.add(check)
    resolve_collector(collector).emit(
        code=DiagnosticCode.DIGEST_UNVERIFIABLE,
        message=(
            f"XZ stream declares integrity check ID {check}, which liblzma cannot "
            "compute; its data is decoded without that check."
        ),
        context=DigestContext(
            algorithm=f"xz check {check}",
            reason="unknown_algorithm_or_backend",
        ),
        logger=logger,
    )


class _XzState:
    """Streaming state machine for multi-stream XZ decompression."""

    _NEED_HEADER = 0
    _IN_STREAM = 1

    def __init__(
        self,
        limits: DecoderLimits,
        on_check: Callable[[int], None],
        *,
        after_stream: bool = False,
        start_offset: int = 0,
        natives: Natives = IN_PROCESS,
    ) -> None:
        """``after_stream``: start just past a stream decoded elsewhere, where padding,
        more streams or the end of the data may follow, as after any stream here.
        ``on_check`` is given each stream's check ID once its header has decoded.
        ``start_offset`` is the source offset of the first byte fed, for errors."""
        self._limits = limits
        self._natives = natives
        self._on_check = on_check
        self._state = self._NEED_HEADER
        self._buf = bytearray()
        self._dec: Decompressor | None = None
        self._bytes_fed = 0
        self._streams_seen = 1 if after_stream else 0
        self._finished = False
        self._stream_decomp_bytes = 0
        # Stream padding stripped since the last stream ended. It is counted into the
        # next stream's compressed size so that XzDecoder's compressed cursor stays on
        # real file offsets; the per-stream backward scan reads the footer from there.
        self._padding_before_stream = 0
        # The source offset where the current stream, or its padding, starts.
        self._stream_offset = start_offset
        self.truncated = False
        # Bytes fed past the last stream that start no further one (see Decoder).
        self.trailing_bytes: int | None = None

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            if self.trailing_bytes is None:
                self._end_at(data)  # only zeros so far: keep looking
            return b"", []
        self._buf.extend(data)
        return self._process(max_length=max_length)

    def _end_at(self, rest: bytes) -> None:
        """End the data before ``rest``: bytes past a stream that start no further one.

        Zeros are padding, as XZ's own stream padding is; the first non-zero byte
        starts the trailing data.
        """
        self._finished = True
        self._buf.clear()
        rest = rest.lstrip(b"\x00")
        if rest:
            self.trailing_bytes = len(rest)

    def flush(self) -> tuple[bytes, list[tuple[int, int]]]:
        if self._state == self._NEED_HEADER:
            if self._streams_seen == 0:
                # The source ended before a first header: nothing, or the start of the
                # magic, is a cut-short xz file; anything else was never one.
                head = bytes(self._buf[:6])
                if self._padding_before_stream or head != _XZ_STREAM_MAGIC[: len(head)]:
                    raise CorruptionError("Not a valid XZ file: no streams found")
                self.truncated = True
                return b"", []
            if len(self._buf) >= 6 and bytes(self._buf[:6]) == _XZ_STREAM_MAGIC:
                self.truncated = True
                return b"", []
            if near_stream_magic(bytes(self._buf), _XZ_STREAM_MAGIC):
                raise damaged_stream_error(self._header_offset())
            self._end_at(bytes(self._buf))
            return b"", []
        # Mid-stream: drain any remaining buffered input for a recoverable prefix,
        # then arm truncation (decoder owns pending_error).
        out, units = self._process(max_length=-1)
        if self._finished:
            return out, units
        if self._dec is not None and not self._dec.needs_input:
            try:
                more = self._dec.decompress(b"")
                out = out + more
            except lzma.LZMAError as e:
                # A corrupt tail is what truncation looks like here, so it stays a
                # truncation. A memlimit or options refusal is not damage and is not
                # swallowed.
                failure = lzma_error_to_archivey(
                    e, "XZ decompression error", self._limits
                )
                if not isinstance(failure, CorruptionError):
                    raise failure from e
        self.truncated = True
        return out, units

    def _header_offset(self) -> int:
        """The source offset of ``_buf[0]`` while a stream header is awaited."""
        return self._stream_offset + self._padding_before_stream

    def is_finished(self) -> bool:
        return self._finished

    @property
    def needs_input(self) -> bool:
        if self._finished:
            return True
        if self._dec is not None and not self._dec.needs_input:
            return False
        return not self._buf

    def _process(self, max_length: int = -1) -> tuple[bytes, list[tuple[int, int]]]:
        output = bytearray()
        new_streams: list[tuple[int, int]] = []
        while True:
            if max_length >= 0 and len(output) >= max_length:
                break
            if self._state == self._NEED_HEADER:
                # XZ spec §2.2 "Stream Padding": concatenated streams may be separated by
                # null bytes whose length is a multiple of four (to keep streams 4-byte
                # aligned). Strip all leading 4-byte runs in one delete.
                padding = _stream_padding_length(self._buf)
                if padding:
                    del self._buf[:padding]
                    self._padding_before_stream += padding

                if len(self._buf) < _STREAM_HEADER_SIZE:
                    break
                header = bytes(self._buf[:_STREAM_HEADER_SIZE])
                if header[:6] != _XZ_STREAM_MAGIC:
                    if self._streams_seen == 0:
                        raise CorruptionError(
                            f"Not a valid XZ file: expected magic {_XZ_STREAM_MAGIC!r}, "
                            f"got {header[:6]!r}"
                        )
                    if near_stream_magic(header, _XZ_STREAM_MAGIC):
                        raise damaged_stream_error(self._header_offset())
                    self._end_at(bytes(self._buf))
                    break
                del self._buf[:_STREAM_HEADER_SIZE]
                try:
                    self._dec = new_capped_decompressor(
                        self._limits, natives=self._natives
                    )
                    remaining = max_length - len(output) if max_length >= 0 else -1
                    plain = self._dec.decompress(header, remaining)
                except lzma.LZMAError as e:
                    raise lzma_error_to_archivey(
                        e, "XZ stream header error", self._limits
                    ) from e
                # liblzma accepted the header, so its CRC holds and byte 6 is zero.
                self._on_check(header[7] & 0x0F)
                self._bytes_fed = _STREAM_HEADER_SIZE
                self._stream_decomp_bytes = len(plain)
                output.extend(plain)
                self._state = self._IN_STREAM

            elif self._state == self._IN_STREAM:
                assert self._dec is not None
                if not self._buf and self._dec.needs_input:
                    break
                chunk = bytes(self._buf)
                self._buf.clear()
                try:
                    remaining = max_length - len(output) if max_length >= 0 else -1
                    plain = self._dec.decompress(chunk, remaining)
                except lzma.LZMAError as e:
                    raise lzma_error_to_archivey(
                        e, "XZ decompression error", self._limits
                    ) from e
                self._bytes_fed += len(chunk)
                self._stream_decomp_bytes += len(plain)
                output.extend(plain)
                if self._dec.eof:
                    unused = self._dec.unused_data
                    compressed_size = (
                        self._padding_before_stream + self._bytes_fed - len(unused)
                    )
                    self._padding_before_stream = 0
                    self._stream_offset += compressed_size
                    new_streams.append((self._stream_decomp_bytes, compressed_size))
                    self._streams_seen += 1
                    release_decoder(self._dec)
                    self._dec = None
                    self._buf[0:0] = unused
                    self._state = self._NEED_HEADER
                elif not self._dec.needs_input:
                    # More output available under the budget; loop to drain with b"".
                    # If a drain produced nothing, stop — avoid spinning on a stuck
                    # decompressor that reports needs_input=False with empty output.
                    if not plain and not chunk:
                        break
                    continue
                else:
                    break
        return bytes(output), new_streams


class _XzBlockResume:
    """Decode one XZ stream from one of its blocks to the end of its blocks.

    liblzma decodes whole streams, so it is given a synthetic stream header (built from
    the stream's check type) followed by the stream's real bytes from ``start`` up to
    where its index begins. Each block still has its header and check verified. The
    stream's index is not fed, since it lists the blocks before ``start`` too; instead
    the output must come to exactly the size the index gives for the rest of the
    stream. Needing only ``start`` is what lets a seek table keep any subset of blocks.

    Exposes the same feed/flush/is_finished interface as ``_XzState``. ``inner`` is
    shared with the ``DecompressorStream`` driving ``feed``, which reads ahead; this
    engine moves it only once, at construction, before anything is read.
    """

    def __init__(
        self,
        start: _XzBlockBounds,
        inner: BinaryIO,
        limits: DecoderLimits,
        on_check: Callable[[int], None],
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._limits = limits
        self._to_feed = start.blocks_end - start.compressed_start
        self._to_output = start.stream_decompressed_end - start.decompressed_start
        self._finished = False
        self.truncated = False
        inner.seek(start.compressed_start)
        self._dec = new_capped_decompressor(limits, natives=natives)
        stream_flags = bytes([0x00, start.check])
        header_crc = zlib.crc32(stream_flags) & 0xFFFFFFFF
        synthetic_header = (
            _XZ_STREAM_MAGIC + stream_flags + struct.pack("<I", header_crc)
        )
        try:
            self._dec.decompress(synthetic_header)
        except lzma.LZMAError as e:
            raise CorruptionError(f"XZ synthetic header error: {e}") from e
        # The stream's real header may never be read on this path.
        on_check(start.check)

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            return b"", []
        # Bytes past the blocks (the index, the footer, later streams) are dropped;
        # XzDecoder repositions inner once this engine has finished.
        chunk = data[: self._to_feed]
        self._to_feed -= len(chunk)
        try:
            plain = self._dec.decompress(chunk, max_length)
        except lzma.LZMAError as e:
            raise lzma_error_to_archivey(
                e, "XZ block decompression error", self._limits
            ) from e
        self._to_output -= len(plain)
        if self._to_output < 0:
            raise CorruptionError(
                "XZ blocks decode to more than the stream index declares"
            )
        if self._to_feed == 0 and self._dec.needs_input:
            if self._to_output:
                raise CorruptionError(
                    "XZ blocks end where the stream index starts, "
                    f"{self._to_output} bytes short of the size it declares"
                )
            self._finished = True
        return plain, []

    def flush(self) -> tuple[bytes, list[tuple[int, int]]]:
        out, units = self.feed(b"")
        if not self._finished:
            self.truncated = True
        return out, units

    def is_finished(self) -> bool:
        return self._finished

    @property
    def needs_input(self) -> bool:
        return self._finished or self._dec.needs_input


class XzDecoder(BaseDecoder):
    """XZ decoder: sequential ``_XzState``, or a block resume via ``recreate``.

    A point carrying an ``_XzBlockBounds`` resumes with ``_XzBlockResume``, which ends
    with that block's stream. The decoder then moves ``inner`` just past the stream
    (``handoff``) and carries on with a sequential ``_XzState``. Everything a resume
    needs is on the point itself, so it never depends on which other points the seek
    table holds.
    """

    def __init__(
        self,
        engine: _XzState | _XzBlockResume,
        *,
        inner: BinaryIO,
        comp_cursor: int,
        decomp_cursor: int,
        index_enabled: bool,
        collector: DiagnosticCollector | None,
        index_built: Callable[[], bool],
        limits: DecoderLimits,
        reported_checks: set[int],
        handoff: SeekPoint | None = None,
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._engine = engine
        self._natives = natives
        self._reported_checks = reported_checks
        self._limits = limits
        self._handoff = handoff
        self._inner = inner
        self._comp_cursor = comp_cursor
        self._decomp_cursor = decomp_cursor
        self._index_enabled = index_enabled
        self._collector = collector
        self._index_built = index_built

    @classmethod
    def from_point(
        cls,
        point: SeekPoint,
        inner: BinaryIO,
        *,
        index_enabled: bool,
        collector: DiagnosticCollector | None,
        index_built: Callable[[], bool],
        limits: DecoderLimits,
        reported_checks: set[int],
        natives: Natives = IN_PROCESS,
    ) -> XzDecoder:
        """``reported_checks`` is shared by every decoder of one file (see
        :func:`_report_unverifiable_check`)."""

        def on_check(check: int) -> None:
            _report_unverifiable_check(check, reported_checks, collector)

        handoff: SeekPoint | None = None
        if point.state is None:
            engine: _XzState | _XzBlockResume = _XzState(
                limits,
                on_check,
                start_offset=point.compressed_offset,
                natives=natives,
            )
        else:
            start: _XzBlockBounds = point.state
            engine = _XzBlockResume(start, inner, limits, on_check, natives)
            handoff = SeekPoint(
                start.stream_decompressed_end, start.stream_compressed_end
            )
        return cls(
            engine,
            inner=inner,
            comp_cursor=point.compressed_offset,
            decomp_cursor=point.decompressed_offset,
            index_enabled=index_enabled,
            collector=collector,
            index_built=index_built,
            limits=limits,
            reported_checks=reported_checks,
            handoff=handoff,
            natives=natives,
        )

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> XzDecoder:
        return XzDecoder.from_point(
            point,
            inner,
            index_enabled=self._index_enabled,
            collector=self._collector,
            index_built=self._index_built,
            limits=self._limits,
            reported_checks=self._reported_checks,
            natives=self._natives,
        )

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        data, units = self._engine.feed(chunk, max_length=max_length)
        points = self._points_for_units(units)
        self._hand_off_if_resume_done()
        return DecodeOut(data, points)

    def flush(self) -> DecodeOut:
        data, units = self._engine.flush()
        if getattr(self._engine, "truncated", False):
            self._pending_error = TruncatedError("XZ file is truncated")
        elif self._handoff is not None and self._engine.is_finished():
            # A guard, not a path DecompressorStream reaches today: feed() hands off as
            # soon as the resume finishes, and flush() runs only once inner is
            # exhausted, which cannot happen before the stream's index that the resume
            # point was read from. Should a resume ever finish here with the hand-off
            # still owed (a seek table that outlived the file it was built from), fail
            # loudly rather than report finished and publish a size that stops short.
            self._pending_error = TruncatedError("XZ file is truncated")
        return DecodeOut(data, self._points_for_units(units))

    def _hand_off_if_resume_done(self) -> None:
        """Continue sequentially past the stream once ``_XzBlockResume`` has finished.

        A finished resume has already dropped the rest of the chunk it was fed, so
        moving ``inner`` here cannot hand ``feed`` bytes it is still consuming.
        """
        if self._handoff is None or not self._engine.is_finished():
            return
        point = self._handoff
        self._handoff = None
        self._inner.seek(point.compressed_offset)
        self._engine = _XzState(
            self._limits,
            lambda check: _report_unverifiable_check(
                check, self._reported_checks, self._collector
            ),
            after_stream=True,
            start_offset=point.compressed_offset,
            natives=self._natives,
        )
        self._comp_cursor = point.compressed_offset
        self._decomp_cursor = point.decompressed_offset

    @property
    def finished(self) -> bool:
        return self._engine.is_finished() and not getattr(
            self._engine, "truncated", False
        )

    @property
    def trailing_bytes(self) -> int | None:
        # Only the sequential engine meets the end of the data; a block resume hands
        # off to one before then.
        return getattr(self._engine, "trailing_bytes", None)

    @property
    def needs_input(self) -> bool:
        return self._engine.needs_input

    def _points_for_units(self, units: list[tuple[int, int]]) -> list[SeekPoint]:
        # Only _XzState reports finished streams; _XzBlockResume never does.
        if not units:
            return []
        return self._progressive_stream_points(units)

    def _progressive_stream_points(
        self, new_streams: list[tuple[int, int]]
    ) -> list[SeekPoint]:
        points: list[SeekPoint] = []
        for decompressed_size, compressed_size in new_streams:
            stream_comp_start = self._comp_cursor
            stream_decomp_start = self._decomp_cursor
            stream_comp_end = stream_comp_start + compressed_size
            emitted_stream_start = False
            if (
                self._index_enabled
                and not self._index_built()
                and self._inner.seekable()
            ):
                saved_pos = self._inner.tell()
                try:
                    thinned: list[bool] = []
                    blocks = _read_xz_index_backwards(
                        self._inner,
                        stream_comp_end,
                        stop_at=stream_comp_start,
                        start_decompressed_offset=stream_decomp_start,
                        on_thinned=functools.partial(thinned.append, True),
                    )
                    if thinned:
                        emit_index_thinned(
                            self._collector, "xz", "per_stream", units="blocks"
                        )
                    # Prefer block-bounds (with resume state) for the stream start
                    # over a state=None placeholder — avoids colliding with a prior
                    # build_index point at the same decompressed offset. A thinned
                    # stream still keeps its first block.
                    for b in blocks:
                        if b.uncompressed_size == 0:
                            continue  # zero-length span is never a useful seek target
                        if b.decompressed_start < stream_decomp_start:
                            continue
                        if b.decompressed_start == stream_decomp_start:
                            if stream_decomp_start > 0:
                                points.append(
                                    SeekPoint(
                                        b.decompressed_start,
                                        b.compressed_start,
                                        state=b,
                                    )
                                )
                                emitted_stream_start = True
                            continue
                        points.append(
                            SeekPoint(b.decompressed_start, b.compressed_start, state=b)
                        )
                except CorruptionError as e:
                    message = (
                        "XZ per-stream backward scan failed; block-level seek points for "
                        f"this stream will not be available: {e}"
                    )
                    resolve_collector(self._collector).emit(
                        code=DiagnosticCode.SEEK_INDEX_DEGRADED,
                        message=message,
                        context=SeekIndexContext(
                            codec="xz",
                            scan="per_stream",
                            error_type=type(e).__name__,
                        ),
                        logger=logger,
                    )
                finally:
                    self._inner.seek(saved_pos)
            # Only emit a state=None stream-start placeholder when we have no block
            # info yet *and* the index is not already populated (a prior SEEK_END /
            # try_get_size build_index would already hold the richer block point).
            if (
                stream_decomp_start > 0
                and not emitted_stream_start
                and not self._index_built()
            ):
                points.append(
                    SeekPoint(stream_decomp_start, stream_comp_start, state=None)
                )
            self._comp_cursor = stream_comp_end
            self._decomp_cursor += decompressed_size
        return points

    def build_index(
        self, inner: BinaryIO, last_known: SeekPoint
    ) -> tuple[list[SeekPoint], int | None]:
        return build_index_backwards(
            inner,
            last_known,
            _read_xz_index_backwards,
            lambda b: SeekPoint(b.decompressed_start, b.compressed_start, state=b),
            "XZ backwards index scan failed; falling back to sequential decompression. "
            "Reason: %s",
            codec_name="xz",
            collector=self._collector,
            # Zero-uncompressed_size blocks share a decompressed_start with the next
            # real block; they are never useful seek targets and must not collide.
            include_block=lambda b: b.uncompressed_size > 0,
        )


def XzDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    collector: DiagnosticCollector | None = None,
    seekable: bool = True,
    decoder_limits: DecoderLimits = DecoderLimits(),
    report_trailing_data: bool = False,
    initial_index: PrebuiltIndex | None = None,
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Seekable XZ decompressor backed by stdlib ``lzma``.

    ``decoder_limits`` caps the dictionary each block header declares (see
    :func:`new_capped_decompressor`); it defaults to the public default, not to no cap.
    ``initial_index`` is an index scan already made over the same source, used in
    place of a second one (see :class:`PrebuiltIndex`).

    ``stream_cell`` late-binds the constructed stream: the ``index_built`` closure
    that ``make_decoder`` passes to each :class:`XzDecoder` reads the stream's
    ``_index_built`` through it. Fine for XZ; when another indexed codec needs the
    same, prefer an explicit seek-table / index-state handle passed into
    ``make_decoder`` rather than another private-attr cell.
    """
    stream_cell: list[DecompressorStream | None] = [None]
    reported_checks: set[int] = set()

    def make_decoder(point: SeekPoint, inner: BinaryIO) -> XzDecoder:
        def index_built() -> bool:
            stream = stream_cell[0]
            assert stream is not None
            return stream._index_built

        return XzDecoder.from_point(
            point,
            inner,
            index_enabled=seekable,
            collector=collector,
            index_built=index_built,
            limits=decoder_limits,
            reported_checks=reported_checks,
            natives=natives,
        )

    stream = DecompressorStream(
        path,
        make_decoder=make_decoder,
        collector=collector,
        codec_name="xz",
        seekable=seekable,
        report_trailing_data=report_trailing_data,
        initial_index=initial_index,
    )
    stream_cell[0] = stream
    return stream


# --- the detection probe's bounded decode --------------------------------------------

# Compressed bytes the probe decode reads at a time.
_HEAD_READ_SIZE = 4096
# The xz filters a probe decodes ahead of LZMA2: delta and the BCJ filters Python's
# ``lzma`` can build for a raw decoder (ARM64 and RISC-V it cannot).
_HEAD_BCJ_FILTERS = frozenset(
    {
        lzma.FILTER_X86,
        lzma.FILTER_POWERPC,
        lzma.FILTER_IA64,
        lzma.FILTER_ARM,
        lzma.FILTER_ARMTHUMB,
        lzma.FILTER_SPARC,
    }
)


def _check_size(check: int) -> int:
    """Bytes of a block's check field for a stream's check ID (xz spec §3.4)."""
    return 0 if check == 0 else 4 << ((check - 1) // 3)


def _lzma2_dictionary(code: int) -> int:
    """The dictionary an LZMA2 properties byte declares (xz spec §5.3.1)."""
    if code > 40:
        raise CorruptionError(f"XZ LZMA2 dictionary byte {code} is over 40")
    if code == 40:
        return 0xFFFFFFFF
    return (2 | (code & 1)) << (code // 2 + 11)


def _head_filter_chain(header: bytes, read_bound: int) -> list[dict[str, int]]:
    """The raw filter chain a block header declares, its LZMA2 dictionary clamped.

    ``header`` is the whole block header, CRC included and already checked. Delta and
    the BCJ filters are kept as declared; only the LZMA2 dictionary changes, to
    :func:`~archivey.internal.config.probe_lzma_dictionary`. A chain this cannot build
    raises ``UnsupportedFeatureError``, which the probe reads as "can't tell".
    """
    body = header[:-4]
    flags = body[1]
    if flags & 0x3C:
        raise UnsupportedFeatureError("XZ block header has reserved flags set")
    pos = 2
    for size_present in (flags & 0x40, flags & 0x80):
        if size_present:  # compressed, then uncompressed size: not needed here
            pos += _decode_mbi(iter(body[pos : pos + 9]))[1]
    last = flags & 0x03
    chain: list[dict[str, int]] = []
    for index in range(last + 1):
        filter_id, n = _decode_mbi(iter(body[pos : pos + 9]))
        pos += n
        props_size, n = _decode_mbi(iter(body[pos : pos + 9]))
        pos += n
        props = body[pos : pos + props_size]
        pos += props_size
        if len(props) != props_size:
            raise CorruptionError("XZ block header filter properties are truncated")
        if index == last and filter_id == lzma.FILTER_LZMA2 and props_size == 1:
            declared = _lzma2_dictionary(props[0])
            chain.append(
                {
                    "id": lzma.FILTER_LZMA2,
                    "dict_size": probe_lzma_dictionary(declared, read_bound),
                }
            )
        elif index < last and filter_id == lzma.FILTER_DELTA and props_size == 1:
            chain.append({"id": lzma.FILTER_DELTA, "dist": props[0] + 1})
        elif index < last and filter_id in _HEAD_BCJ_FILTERS and props_size in (0, 4):
            bcj: dict[str, int] = {"id": filter_id}
            if props_size:
                bcj["start_offset"] = int.from_bytes(props, "little")
            chain.append(bcj)
        else:
            raise UnsupportedFeatureError(
                f"XZ filter {filter_id:#x} at position {index} of the chain is not "
                "decoded by the detection probe"
            )
    if any(body[pos:]):
        raise CorruptionError("XZ block header padding is not zero")
    return chain


class _HeadInput:
    """The compressed input of :func:`_decode_xz_head`: bytes read ahead, then ``read``."""

    def __init__(self, read: Callable[[int], bytes]) -> None:
        self._read = read
        self.pending = bytearray()

    def fill(self, n: int) -> bool:
        """Hold at least ``n`` bytes; ``False`` when the input ends first."""
        while len(self.pending) < n:
            chunk = self._read(max(n - len(self.pending), _HEAD_READ_SIZE))
            if not chunk:
                return False
            self.pending.extend(chunk)
        return True

    def take(self, n: int) -> bytes:
        if not self.fill(n):
            raise TruncatedError(truncated_message("XZ"))
        taken = bytes(self.pending[:n])
        del self.pending[:n]
        return taken

    def take_all(self) -> bytes:
        """Everything held, or the next read when nothing is; truncated at the end."""
        if not self.pending and not self.fill(1):
            raise TruncatedError(truncated_message("XZ"))
        taken = bytes(self.pending)
        self.pending.clear()
        return taken


# An index byte translated through this: ``E`` where it ends an MBI (high bit clear),
# ``C`` where the MBI continues.
_MBI_ENDS = bytes.maketrans(bytes(range(256)), b"E" * 0x80 + b"C" * 0x80)
# An MBI is at most 9 bytes, so 9 continuation bytes in a row are corrupt.
_MBI_TOO_LONG = b"C" * 9


def _mbi_marks(data: bytearray) -> bytearray:
    """``data`` translated through ``_MBI_ENDS``."""
    return data.translate(_MBI_ENDS)


def _skip_index_and_footer(source: _HeadInput) -> None:
    """Consume a stream's index (its 0x00 indicator already taken) and its footer.

    Only the index's own record count says where it ends, so the records are walked:
    each is two MBIs, and only where they end matters, not their values. MBI ends are
    counted a slice at a time, never wider than the MBIs still to end, since each MBI
    takes at least one byte: a slice never reaches past the index, so a short index
    costs a scan of its own bytes, and a count no input can hold costs one pass over
    the bytes the probe may read before it runs into the end of the input and is
    truncated. Any 9 bytes in a row end an MBI, so a slice as wide as ``left`` ends at
    least a ninth of them: the slices per index grow with the logarithm of its count
    (plus one per read), not with the count. The index CRC32 and the footer magic are
    checked.
    """
    crc = zlib.crc32(b"\x00")
    length = 1

    def consume(n: int) -> bytes:
        nonlocal crc, length
        data = source.take(n)
        crc = zlib.crc32(data, crc)
        length += n
        return data

    def vli() -> int:
        value = 0
        for i in range(9):
            byte = consume(1)[0]
            value |= (byte & 0x7F) << (7 * i)
            if not byte & 0x80:
                return value
        raise CorruptionError("XZ index MBI exceeds 9 bytes")

    left = vli() * 2  # MBIs still to end: unpadded and uncompressed size per record
    run = 0  # continuation bytes since the last MBI ended
    while left:
        if not source.pending and not source.fill(1):
            raise TruncatedError(truncated_message("XZ"))
        # ``left`` MBIs take at least ``left`` bytes: this slice is all index.
        marks = _mbi_marks(source.pending[:left])
        if _MBI_TOO_LONG in b"C" * run + marks:
            raise CorruptionError("XZ index MBI exceeds 9 bytes")
        last_end = marks.rfind(b"E")
        run = run + len(marks) if last_end < 0 else len(marks) - 1 - last_end
        left -= marks.count(b"E")
        consume(len(marks))
    padding = consume(-length % 4)
    if any(padding):
        raise CorruptionError("XZ index padding is not zero")
    (stored,) = struct.unpack("<I", source.take(4))
    if crc & 0xFFFFFFFF != stored:
        raise CorruptionError("XZ index CRC32 mismatch")
    if source.take(_STREAM_FOOTER_SIZE)[-2:] != _XZ_FOOTER_MAGIC:
        raise CorruptionError("XZ stream footer magic not found")


def _starts_next_stream(source: _HeadInput) -> bool:
    """Skip stream padding (zeros, four at a time); whether another stream follows.

    ``False`` at the end of the input, and at bytes that start no stream: what follows
    the last stream is the open's business (``ARCHIVE_TRAILING_DATA``), not the probe's.
    """
    while source.fill(4) and source.pending[:4] == b"\x00\x00\x00\x00":
        del source.pending[:4]
    return source.fill(6) and source.pending[:6] == _XZ_STREAM_MAGIC


def _decode_xz_head(
    read: Callable[[int], bytes], size: int, natives: Natives = IN_PROCESS
) -> bytes:
    """Up to ``size`` bytes of the xz data ``read`` returns, its dictionaries clamped.

    Each block is decoded raw, with the filter chain its header declares and the LZMA2
    dictionary clamped to what ``size`` bytes of output need (see
    :func:`_head_filter_chain`). Stream header, block header and index CRCs are
    checked; a block's check is not, since a bounded read rarely reaches it. Past a
    stream's index the walk goes on through stream padding into the next stream, as
    ``XzDecoder`` does, and stops at ``size`` bytes or at the end of the xz data.
    """
    source = _HeadInput(read)
    check = _parse_xz_header(source.take(_STREAM_HEADER_SIZE))
    out = bytearray()
    while len(out) < size:
        first = source.take(1)
        if first == b"\x00":  # the index indicator: this stream has no more blocks
            _skip_index_and_footer(source)
            if not _starts_next_stream(source):
                break
            check = _parse_xz_header(source.take(_STREAM_HEADER_SIZE))
            continue
        header = first + source.take(first[0] * 4 + 3)
        (stored,) = struct.unpack_from("<I", header, len(header) - 4)
        if zlib.crc32(header[:-4]) & 0xFFFFFFFF != stored:
            raise CorruptionError("XZ block header CRC32 mismatch")
        dec = natives.lzma_decompressor(
            format=lzma.FORMAT_RAW, filters=_head_filter_chain(header, size)
        )
        fed = 0
        try:
            while not dec.eof and len(out) < size:
                data = b""
                if dec.needs_input:
                    data = source.take_all()
                    fed += len(data)
                out += dec.decompress(data, size - len(out))
            if not dec.eof:
                break  # ``size`` reached inside the block
            unused = dec.unused_data
        finally:
            release_decoder(dec)
        source.pending[:0] = unused
        compressed = len(header) + fed - len(unused)
        source.take(-compressed % 4 + _check_size(check))  # block padding, then check
    return bytes(out)


def open_xz_head(
    source: BinaryIO, size: int, natives: Natives = IN_PROCESS
) -> BinaryIO:
    """The first ``size`` bytes an xz source decodes to, for a detection probe.

    liblzma reserves the dictionary a block header declares, up to 4 GiB, when its
    xz decoder reads that header; a probe reading 512 bytes needs 4 KiB of it. So
    this decodes each block raw with the dictionary clamped instead
    (``StreamConfig.probe_read_bound``), which gives the same bytes. The stream ends
    at ``size``. ``source`` is the probe's bounded reader: nothing here limits how
    much input a block reads to reach ``size`` bytes.
    """
    return io.BytesIO(_decode_xz_head(source.read, size, natives))
