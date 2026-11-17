"""The seek table of the *Seekable Zstandard* format, read for random access.

The format (``contrib/seekable_format`` in the zstd repository) is ordinary zstd: a run
of independent frames, then one skippable frame that lists them. Any zstd decoder reads
the file, and skips the table. The table, at the very end of the file:

  Skippable frame header (8 bytes): magic 0x184D2A5E (LE) + frame size (4 LE)
  Entries (frame size - 9 bytes):   per frame, compressed size (4 LE) +
                                    decompressed size (4 LE) [+ checksum (4 LE)]
  Footer (9 bytes):                 number of frames (4 LE) + descriptor (1) +
                                    seekable magic 0x8F92EAB1 (4 LE)

Descriptor bit 7 says whether entries carry the checksum (the low 32 bits of each
frame's XXH64). Bits 2 to 6 are reserved and must be zero. The frames start at offset 0
and follow one another: the compressed sizes added up give each frame's offset, and
their sum is where the table starts.

The table is only read, never checked against the data, like the xz and lzip indexes
(threat-model O17): a seek trusts it, and a forward read still decodes and checks every
frame. The per-frame checksum is not used: it is XXH64, which the standard library does
not have, and libzstd checks a frame's own content checksum when the frame carries one.

Spec: https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md
"""

from __future__ import annotations

import functools
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

from archivey.exceptions import CorruptionError
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.decompressor_stream import (
    SeekPoint,
    SpacedCollector,
    build_index_backwards,
)

SEEK_TABLE_MAGIC = 0x184D2A5E
SEEKABLE_MAGIC = 0x8F92EAB1
_HEADER = struct.Struct("<II")
_FOOTER = struct.Struct("<IBI")
_CHECKSUM_FLAG = 0x80
_RESERVED_BITS = 0x7C
# Entries read per source read, so a table of millions of frames is never held whole.
_ENTRIES_PER_READ = 4096


@dataclass(frozen=True, slots=True)
class _FrameBounds:
    """One frame of the table: where it starts in the source and in the output."""

    compressed_start: int
    decompressed_start: int
    decompressed_end: int


def _read_exact(stream: BinaryIO, offset: int, size: int) -> bytes:
    stream.seek(offset)
    data = stream.read(size)
    if len(data) < size:
        raise CorruptionError("zstd seek table is cut short")
    return data


def read_seek_table(
    stream: BinaryIO,
    file_size: int,
    /,
    *,
    stop_at: int = 0,
    start_decompressed_offset: int = 0,
    on_thinned: Callable[[], None] | None = None,
    origin: int = 0,
) -> list[_FrameBounds]:
    """The frames the seek table at the end of ``stream`` lists, first to last.

    An empty list when the file does not end with a seek table: an ordinary zstd file.
    A table that is there but does not describe the frames before it raises
    :class:`CorruptionError`. More frames than the seek-table cap are thinned
    (:class:`SpacedCollector`), keeping the last one so the total size stays exact.

    The table covers the file from offset 0, so ``stop_at`` and
    ``start_decompressed_offset`` (the backward scans' resume arguments) must be 0.
    ``origin`` is where ``stream`` starts in the file (``StreamConfig.source_origin``),
    added to the offsets an error names.
    """
    assert stop_at == 0 and start_decompressed_offset == 0
    if file_size < _HEADER.size + _FOOTER.size:
        return []
    count, descriptor, magic = _FOOTER.unpack(
        _read_exact(stream, file_size - _FOOTER.size, _FOOTER.size)
    )
    if magic != SEEKABLE_MAGIC:
        return []
    if descriptor & _RESERVED_BITS:
        raise CorruptionError(
            f"zstd seek table descriptor {descriptor:#04x} sets reserved bits"
        )
    entry = struct.Struct("<III" if descriptor & _CHECKSUM_FLAG else "<II")
    table_size = count * entry.size + _FOOTER.size
    table_start = file_size - table_size - _HEADER.size
    if table_start < 0:
        raise CorruptionError(
            f"zstd seek table lists {count} frames, more than the file can hold"
        )
    frame_magic, frame_size = _HEADER.unpack(
        _read_exact(stream, table_start, _HEADER.size)
    )
    if frame_magic != SEEK_TABLE_MAGIC or frame_size != table_size:
        raise CorruptionError(
            "zstd seek table footer is not at the end of its skippable frame"
        )
    kept: SpacedCollector[_FrameBounds] = SpacedCollector(
        lambda f: f.decompressed_start
    )
    compressed = decompressed = 0
    offset = table_start + _HEADER.size
    left = count
    while left:
        n = min(left, _ENTRIES_PER_READ)
        chunk = _read_exact(stream, offset, n * entry.size)
        offset += len(chunk)
        left -= n
        for fields in entry.iter_unpack(chunk):
            frame_compressed, frame_decompressed = fields[0], fields[1]
            if frame_compressed == 0:
                # No zstd frame is empty: the magic alone is four bytes.
                raise CorruptionError("zstd seek table lists a frame of 0 bytes")
            kept.add(
                _FrameBounds(
                    compressed, decompressed, decompressed + frame_decompressed
                )
            )
            compressed += frame_compressed
            decompressed += frame_decompressed
    if compressed != table_start:
        raise CorruptionError(
            f"zstd seek table frames end at offset {origin + compressed}, but the "
            f"table starts at {origin + table_start}"
        )
    if kept.thinned and on_thinned is not None:
        on_thinned()
    frames = kept.items
    if frames and frames[-1].decompressed_end != decompressed:
        # Thinning dropped the last frame; its end is the total size.
        frames.append(_FrameBounds(compressed, decompressed, decompressed))
    return frames


def build_seek_table_index(
    inner: BinaryIO,
    last_known: SeekPoint,
    collector: DiagnosticCollector | None,
    origin: int = 0,
) -> tuple[list[SeekPoint], int | None]:
    """Seek points at the frames the seek table lists, and the total size.

    ``origin`` is where ``inner`` starts in the file, for the offsets errors name.

    ``([], None)`` for a file with no seek table. A table that does not match the file
    is reported as ``SEEK_INDEX_DEGRADED`` and gives the same, so reads decode from the
    start as for any zstd file.
    """
    return build_index_backwards(
        inner,
        last_known,
        functools.partial(read_seek_table, origin=origin),
        lambda f: SeekPoint(f.decompressed_start, f.compressed_start),
        "zstd seek table unreadable; falling back to sequential decompression. "
        "Reason: %s",
        codec_name="zstd",
        collector=collector,
        scan="zstd_seek_table",
        # A frame with no output shares its offset with the next frame.
        include_block=lambda f: f.decompressed_end > f.decompressed_start,
    )
