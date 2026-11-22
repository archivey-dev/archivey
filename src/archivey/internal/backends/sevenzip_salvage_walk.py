"""Salvage mode for 7z: the walk of the packed area when no end header is usable
(``openspec/changes/salvage-7z`` decisions 4, 6 and 8).

7-Zip packs every folder's streams back to back from offset 32. An LZMA2 stream is a
chain of chunks whose headers give each chunk's packed and unpacked size, ending in a
``00`` byte, so a stream's extent and unpacked size come from its chunk headers alone,
without decoding::

    p = 32
    while p < end:
      LZMA2 chain at p?   first chunk resets the dictionary (01, or E0-FF)
                          chain ends in 00  -> one stream [p, q); p = q
                          chain breaks      -> a stream up to its last whole chunk
                          chain runs to end -> a cut stream; the walk ends
      LZMA1 at p == 32?   one stream to the area's end, size unknown
      nothing             -> the walk ends

Each stream becomes a content member, ``__salvaged__/7z-stream-NNNN.bin``, read as a
folder of one LZMA2 (or LZMA) coder (:func:`content_archive`). Everything here is pure
on bytes, through a ``read_at(offset, size)`` of the archive counted from its
signature header.
"""

from __future__ import annotations

import lzma
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from archivey.internal.backends.sevenzip_parser import (
    SIGNATURE_HEADER_SIZE,
    SevenZipArchive,
    SevenZipCoder,
    SevenZipFileRecord,
    SevenZipFolder,
)

ReadAt = Callable[[int, int], bytes]

METHOD_LZMA2 = b"\x21"
METHOD_LZMA = b"\x03\x01\x01"
# LZMA1 as 7-Zip writes it: lc=3, lp=0, pb=2. Another property byte decodes to wrong
# bytes with no error, so no other is tried (design, Rejected).
LZMA1_PROPS = 0x5D
# The largest dictionary a 7z LZMA1 coder can declare.
MAX_LZMA1_DICT = (1 << 32) - 1
# The declared output of a stream whose size is not known (the LZMA1 member): the
# read ends where its input does.
UNKNOWN_SIZE = (1 << 62) - 1
# How far the walk reads at once: chunk headers sit at most 64 KiB + 6 bytes apart.
_READ_WINDOW = 1 << 20
_LZMA1_PROBE_INPUT = 1 << 16
_LZMA1_PROBE_OUTPUT = 1 << 12


class CachedReader:
    """``read_at`` with a window cache: the walk reads a few bytes per chunk header,
    one request per :data:`_READ_WINDOW` of the area."""

    def __init__(self, read_at: ReadAt, end: int) -> None:
        self._read_at = read_at
        self.end = end
        self._start = 0
        self._buf = b""

    def read(self, offset: int, size: int) -> bytes:
        size = max(0, min(size, self.end - offset))
        if not (
            self._start <= offset and offset + size <= self._start + len(self._buf)
        ):
            self._start = offset
            self._buf = self._read_at(
                offset, min(self.end - offset, max(size, _READ_WINDOW))
            )
        start = offset - self._start
        return self._buf[start : start + size]


ChainStatus = Literal["complete", "broken", "cut"]


@dataclass(frozen=True)
class Chain:
    """An LZMA2 chunk chain from ``start``, as its chunk headers give it.

    ``status`` is ``"complete"`` when the chain ends in its ``00`` end marker,
    ``"broken"`` when a chunk header is not one, ``"cut"`` when the area ends before
    the end marker. ``end`` is the offset after the end marker (complete) or after
    the last whole chunk; ``broken_at`` is where a broken chain breaks. ``unpacked``
    counts the whole chunks; ``declared`` adds the unpacked size the cut chunk's
    header declares, which bounds what a read of a cut stream can give.
    ``lzma_chunks`` counts the LZMA chunks among the whole ones, and
    ``first_lzma_end`` is where the first ends, and ``first_lzma_unpacked`` the
    unpacked size of the chunks up to its end.
    """

    start: int
    status: ChainStatus
    end: int
    unpacked: int
    declared: int
    lzma_chunks: int
    first_lzma_end: int | None
    broken_at: int | None = None
    first_lzma_unpacked: int = 0


def starts_lzma2(control: int, prop: int | None) -> bool:
    """Whether a chunk whose control byte is ``control`` (and property byte ``prop``,
    for an LZMA chunk that sets them) can start an LZMA2 stream: it resets the
    dictionary, an uncompressed ``01`` chunk or an LZMA chunk ``E0`` to ``FF`` whose
    properties are valid."""
    if control == 0x01:
        return True
    return control >= 0xE0 and prop is not None and _valid_props(prop)


def _valid_props(prop: int) -> bool:
    # LZMA2 holds lc + lp to at most 4 (and pb to at most 4).
    if prop > 224:
        return False
    lc = prop % 9
    lp = (prop // 9) % 5
    return lc + lp <= 4


def scan_chain(reader: CachedReader, start: int, end: int) -> Chain | None:
    """The LZMA2 chunk chain from ``start`` to at most ``end``, or ``None`` when its
    first chunk does not start a stream (:func:`starts_lzma2`). Reads chunk headers
    only."""
    pos = start
    unpacked = 0
    lzma_chunks = 0
    first_lzma_end: int | None = None
    first_lzma_unpacked = 0
    have_props = False
    first = True

    def stop(
        status: ChainStatus, *, declared: int = 0, broken_at: int | None = None
    ) -> Chain:
        return Chain(
            start,
            status,
            pos,
            unpacked,
            unpacked + declared,
            lzma_chunks,
            first_lzma_end,
            broken_at,
            first_lzma_unpacked,
        )

    while True:
        if pos >= end:
            return stop("cut")
        head = reader.read(pos, 6)
        control = head[0]
        if control == 0x00:
            if first:
                return None
            pos += 1
            return stop("complete")
        if control in (0x01, 0x02):
            if first and control != 0x01:
                return None
            if len(head) < 3:
                return None if first else stop("cut")
            size = int.from_bytes(head[1:3], "big") + 1
            chunk_end = pos + 3 + size
            if chunk_end > end:
                return stop("cut", declared=size)
            unpacked += size
        elif control >= 0x80:
            header_size = 6 if control >= 0xC0 else 5
            if len(head) < header_size:
                # The area ends inside the chunk header: nothing shows a first chunk
                # starts a stream.
                return None if first else stop("cut")
            prop = head[5] if control >= 0xC0 else None
            if first and not starts_lzma2(control, prop):
                return None
            if prop is not None:
                if not _valid_props(prop):
                    return stop("broken", broken_at=pos)
                have_props = True
            elif not have_props:
                return stop("broken", broken_at=pos)
            size = ((control & 0x1F) << 16) + int.from_bytes(head[1:3], "big") + 1
            packed = int.from_bytes(head[3:5], "big") + 1
            chunk_end = pos + header_size + packed
            if chunk_end > end:
                return stop("cut", declared=size)
            unpacked += size
            lzma_chunks += 1
            if first_lzma_end is None:
                first_lzma_end = chunk_end
                first_lzma_unpacked = unpacked
        else:
            if first:
                return None
            return stop("broken", broken_at=pos)
        pos = chunk_end
        first = False


def first_lzma_chunk_decodes(reader: CachedReader, chain: Chain) -> bool:
    """Whether the chain's first LZMA chunk, with the chunks before it, decodes
    without error to the size their headers declare. ``False`` when it holds none."""
    if chain.first_lzma_end is None:
        return False
    size = chain.first_lzma_unpacked
    decoder = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": max(size, 4096)}],
    )
    data = reader.read(chain.start, chain.first_lzma_end - chain.start)
    try:
        out = decoder.decompress(data, max_length=size + 1)
    except lzma.LZMAError:
        return False
    return len(out) == size


def lzma2_dict_prop(size: int) -> int:
    """The smallest LZMA2 dictionary property whose size is at least ``size``: a match
    cannot reach back past the stream's first byte, so it is always enough."""
    for prop in range(40):
        if (2 | (prop & 1)) << (prop // 2 + 11) >= size:
            return prop
    return 40


def lzma1_starts_at(read_at: ReadAt, offset: int, end: int) -> bool:
    """Whether an LZMA1 stream with 7-Zip's properties starts at ``offset``: its first
    byte is ``00`` (the range coder's), and its first bytes decode without error."""
    data = read_at(offset, min(_LZMA1_PROBE_INPUT, end - offset))
    if not data or data[0] != 0:
        return False
    decoder = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}
        ],
    )
    try:
        out = decoder.decompress(data, max_length=_LZMA1_PROBE_OUTPUT)
    except lzma.LZMAError:
        return False
    return bool(out)


Codec = Literal["lzma2", "lzma"]


@dataclass(frozen=True)
class ContentStream:
    """One stream the walk found, listed as a content member.

    ``start`` and ``end`` bound its packed bytes, counted from the signature header.
    ``size`` is its unpacked size, ``None`` when it is not known (a cut or broken
    chain, an LZMA1 stream). ``read_size`` bounds what its read can give: the size,
    or what the chunk headers declare, or :data:`UNKNOWN_SIZE`. ``confirmed`` is
    whether it was found at a walk position (offset 32, or where the stream before it
    ended), as every stream of this walk is.
    """

    start: int
    end: int
    codec: Codec
    size: int | None
    read_size: int
    confirmed: bool = True


@dataclass
class WalkResult:
    """The streams the walk found, in archive order, and the ranges where no stream
    starts, as ``(start, length)``."""

    streams: list[ContentStream] = field(default_factory=list)
    skipped: list[tuple[int, int]] = field(default_factory=list)


def stream_from_chain(
    chain: Chain, area_end: int, *, confirmed: bool = True
) -> ContentStream:
    """The content stream of ``chain``: to its end marker, to its last whole chunk
    when it breaks, or to the area's end when it is cut (its read gets every byte
    there)."""
    if chain.status == "complete":
        return ContentStream(
            chain.start, chain.end, "lzma2", chain.unpacked, chain.unpacked, confirmed
        )
    end = area_end if chain.status == "cut" else chain.end
    return ContentStream(
        chain.start, end, "lzma2", None, max(chain.declared, 1), confirmed
    )


def walk_packed_area(read_at: ReadAt, end: int) -> WalkResult:
    """Walk the packed area from offset 32 to ``end`` (decision 4): every LZMA2 stream
    that starts at a walk position, and an LZMA1 stream at offset 32."""
    reader = CachedReader(read_at, end)
    result = WalkResult()
    pos = SIGNATURE_HEADER_SIZE
    while pos < end:
        chain = scan_chain(reader, pos, end)
        if chain is None:
            if pos == SIGNATURE_HEADER_SIZE and lzma1_starts_at(read_at, pos, end):
                result.streams.append(
                    ContentStream(pos, end, "lzma", None, UNKNOWN_SIZE)
                )
                return result
            result.skipped.append((pos, end - pos))
            return result
        if chain.status == "broken" and not first_lzma_chunk_decodes(reader, chain):
            # A chain that breaks is listed only when an LZMA chunk in it decodes:
            # random or encrypted bytes pass a first chunk header often enough.
            result.skipped.append((pos, end - pos))
            return result
        result.streams.append(stream_from_chain(chain, end))
        if chain.status == "cut":
            return result
        if chain.status == "broken":
            assert chain.broken_at is not None
            result.skipped.append((chain.broken_at, end - chain.broken_at))
            return result
        pos = chain.end
    return result


def content_name(index: int) -> str:
    """The name of the ``index``-th content member, from 0: ``0001`` first, at least
    four digits."""
    return f"__salvaged__/7z-stream-{index + 1:04d}.bin"


def content_archive(
    streams: list[ContentStream],
    *,
    major_version: int,
    minor_version: int,
    max_decoder_memory: int | None,
    end_offset: int,
) -> SevenZipArchive:
    """A synthetic archive with one folder of one coder per stream, no CRC, so each
    content member reads through the normal folder pipeline under the unchanged
    limits (decision 8)."""
    folders: list[SevenZipFolder] = []
    files: list[SevenZipFileRecord] = []
    for index, stream in enumerate(streams):
        if stream.codec == "lzma2":
            coder = SevenZipCoder(
                METHOD_LZMA2, 1, 1, bytes((lzma2_dict_prop(stream.read_size),))
            )
        else:
            dict_size = MAX_LZMA1_DICT
            if max_decoder_memory is not None:
                dict_size = min(dict_size, max_decoder_memory)
            coder = SevenZipCoder(
                METHOD_LZMA,
                1,
                1,
                bytes((LZMA1_PROPS,)) + dict_size.to_bytes(4, "little"),
            )
        folders.append(
            SevenZipFolder(
                coders=[coder],
                bind_pairs=[],
                packed_indices=[0],
                unpack_sizes=[stream.read_size],
                crc=None,
                digest_defined=False,
            )
        )
        files.append(
            SevenZipFileRecord(
                filename=content_name(index),
                emptystream=False,
                is_anti=False,
                is_directory=False,
                attributes=None,
                creation_time=None,
                last_access_time=None,
                last_write_time=None,
                folder_index=index,
                file_in_folder=0,
                uncompressed_size=stream.read_size,
                crc32=None,
                compressed_size=stream.end - stream.start,
                is_encrypted=False,
            )
        )
    return SevenZipArchive(
        major_version=major_version,
        minor_version=minor_version,
        pack_pos=0,
        pack_sizes=[s.end - s.start for s in streams],
        pack_positions=[s.start for s in streams],
        folders=folders,
        num_unpackstreams_folders=[1] * len(streams),
        unpack_sizes=[s.read_size for s in streams],
        digests=[None] * len(streams),
        files=files,
        comment=None,
        is_solid=False,
        is_header_encrypted=False,
        has_encrypted_folders=False,
        end_offset=end_offset,
    )


__all__ = [
    "UNKNOWN_SIZE",
    "CachedReader",
    "Chain",
    "ContentStream",
    "WalkResult",
    "content_archive",
    "content_name",
    "first_lzma_chunk_decodes",
    "lzma1_starts_at",
    "lzma2_dict_prop",
    "scan_chain",
    "starts_lzma2",
    "stream_from_chain",
    "walk_packed_area",
]
