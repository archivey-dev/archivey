"""Salvage mode for 7z: the walk of the packed area when no end header is usable
(``dev-docs/formats/7z.md`` §2.6).

7-Zip packs every folder's streams back to back from offset 32. An LZMA2 stream is a
chain of chunks whose headers give each chunk's packed and unpacked size, ending in a
``00`` byte, so a stream's extent and unpacked size come from its chunk headers alone,
without decoding::

    p = 32
    while p < end:
      header copy at p?   a plain kHeader, or (p > 32) an LZMA1 stream that decodes
                          to one, parsing to kEnd, its pack layout agreeing -> use it
      LZMA2 chain at p?   first chunk resets the dictionary (01, or E0-FF)
                          chain ends in 00  -> one stream [p, q); p = q
                          chain breaks      -> a stream up to its last whole chunk;
                                               search from where it breaks
                          chain runs to end -> a cut stream; the walk ends
      LZMA1 at p == 32?   one stream, size unknown; search from p + 1
      nothing             -> search from p

When the walk cannot go on, the end header's copy is first looked for in the area's
last 1 MiB (:func:`tail_copy_search`), and then the next LZMA2 stream is searched for
(:class:`StreamFinder`) through the shared search driver; a complete stream it finds
is a walk position again. Each stream becomes a content member,
``__salvaged__/7z-stream-NNNN.bin``, read as a folder of one LZMA2 (or LZMA) coder
(:func:`content_archive`). Everything here is pure on bytes, through a
``read_at(offset, size)`` of the archive counted from its signature header.
"""

from __future__ import annotations

import lzma
import re
from array import array
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Literal, Protocol

from archivey.config import DecoderLimits
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.sevenzip_parser import (
    MAX_NEXT_HEADER_SIZE,
    SIGNATURE_HEADER_SIZE,
    PlainHeader,
    SevenZipArchive,
    SevenZipCoder,
    SevenZipFileRecord,
    SevenZipFolder,
    parse_header_prefix,
)
from archivey.internal.config import check_decoder_memory
from archivey.internal.resource_usage import ResourceUsageRecorder
from archivey.internal.salvage import HeaderSearch

ReadAt = Callable[[int, int], bytes]
#: ``search(start, end, finder, read)``: the shared search driver over the area from
#: ``start`` to ``end`` with ``finder``, reading through ``read``. It gives where the
#: header it found starts, or ``None`` (none, or the budget ran out), and records the
#: regions it stepped over.
SearchFn = Callable[[int, int, HeaderSearch, ReadAt], "int | None"]
#: ``claim(lo, end)``: the lowest offset from ``lo`` up to ``end`` that the search
#: budget lets the tail search examine, the bytes counted once.
ClaimFn = Callable[[int, int], int]

METHOD_LZMA2 = b"\x21"
METHOD_LZMA = b"\x03\x01\x01"
# LZMA1 as 7-Zip writes it: lc=3, lp=0, pb=2. Another property byte decodes to wrong
# bytes with no error, so a trial of others could not tell which one is right.
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
#: How far back from the area's end the header copy is searched for.
TAIL_COPY_SEARCH = 1 << 20
# The second byte of a plain header: kArchiveProperties, kAdditionalStreamsInfo,
# kMainStreamsInfo or kFilesInfo after kHeader.
_HEADER_SECOND = frozenset((0x02, 0x03, 0x04, 0x05))
# How much input the LZMA1 header decode takes at once; a failing piece is fed again
# one byte at a time, so the bytes decoded before the failure are kept.
_LZMA1_PIECE = 1 << 12
# The most bytes from a candidate the stream search reads to judge it: its first
# LZMA chunk must end within them (a few uncompressed chunks may come first).
_STREAM_HEADER_SPAN = 1 << 18
#: How many times its own size the stream search decodes, in one window, to judge
#: the candidates in it. Each check decodes up to :data:`_STREAM_HEADER_SPAN` bytes,
#: and the uncompressed chunks of many candidates can lead to one LZMA chunk, so
#: without a bound a window of them cost a decode of up to 256 KiB per byte (review
#: C1: 160 KB of 4-byte chunks took 13 s). Random bytes decode about 24 times the
#: window.
LEAD_WORK_FACTOR = 64


def _valid_props_class() -> bytes:
    return b"".join(
        re.escape(bytes((prop,)))
        for prop in range(225)
        if prop % 9 + (prop // 9) % 5 <= 4
    )


# A candidate stream start: an uncompressed chunk that resets the dictionary, or an
# LZMA chunk that resets it with valid properties and whose range coder's first byte
# is 00. A lookahead, so that overlapping candidates are each found.
_STREAM_START = re.compile(
    rb"(?=\x01|[\xe0-\xff][\x00-\xff]{4}[" + _valid_props_class() + rb"]\x00)",
    re.DOTALL,
)


# liblzma's smallest dictionary.
_MIN_DICT = 1 << 12


@dataclass(frozen=True)
class DecoderCap:
    """``DecoderLimits.max_decoder_memory`` for the walk's own trial decodes, which
    judge candidates and decode a header copy: each dictionary is the one its
    output needs, at most the cap (a dictionary as large as the output decodes it
    exactly), and checked before the decoder is built (review C3: a header copy's
    decode reserved 64 MiB under a 1 MiB cap)."""

    limits: DecoderLimits = field(default_factory=DecoderLimits)
    usage: ResourceUsageRecorder | None = None

    def dictionary(self, output: int) -> int:
        """The dictionary for a trial decode of at most ``output`` bytes."""
        size = output
        cap = self.limits.max_decoder_memory
        if cap is not None:
            size = min(size, cap)
        size = max(size, _MIN_DICT)
        check_decoder_memory(
            size,
            limits=self.limits,
            what="the dictionary of a trial LZMA decode in 7z salvage",
            counted_from="the bytes the decode may give, at least 4 KiB",
            usage=self.usage,
        )
        return size


class ChunkReader(Protocol):
    """What :func:`scan_chain` reads chunk headers through."""

    def read(self, offset: int, size: int) -> bytes: ...


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


class BytesReader:
    """A :class:`ChunkReader` over bytes in memory, such as a search window."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + max(0, size)]


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


def scan_chain(
    reader: ChunkReader, start: int, end: int, known: KnownChains | None = None
) -> Chain | None:
    """The LZMA2 chunk chain from ``start`` to at most ``end``, or ``None`` when its
    first chunk does not start a stream (:func:`starts_lzma2`). Reads chunk headers
    only. With ``known``, a chain that reaches a chunk of one scanned before takes
    the rest from it, and is kept there in turn."""
    pos = start
    unpacked = 0
    lzma_chunks = 0
    first_lzma_end: int | None = None
    first_lzma_unpacked = 0
    have_props = False
    first = True
    steps: list[_Step] = []

    def stop(
        status: ChainStatus,
        *,
        declared: int = 0,
        broken_at: int | None = None,
        rest: tuple[_Scanned, int] | None = None,
        props_decide: bool = False,
    ) -> Chain:
        """``props_decide``: the chunk the chain stops at stops it as it does only
        because the chain had its properties, or did not."""
        chain = Chain(
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
        if rest is not None:
            chain = rest[0].joined(chain, rest[1])
        if known is not None:
            known.add(chain, steps, rest, free=not props_decide)
        return chain

    while True:
        if known is not None and not first:
            rest = known.at(pos, have_props)
            if rest is not None:
                if first_lzma_end is None:
                    lead = rest[0].first_lzma[rest[1]]
                    if lead is not None:
                        first_lzma_end = lead[0]
                        first_lzma_unpacked = unpacked + lead[1]
                return stop("complete", rest=rest)
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
            steps.append(_Step(pos, control, have_props, size, chunk_end))
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
            elif not have_props:
                return stop("broken", broken_at=pos, props_decide=True)
            size = ((control & 0x1F) << 16) + int.from_bytes(head[1:3], "big") + 1
            packed = int.from_bytes(head[3:5], "big") + 1
            chunk_end = pos + header_size + packed
            if chunk_end > end:
                return stop("cut", declared=size, props_decide=prop is None)
            steps.append(_Step(pos, control, have_props, size, chunk_end))
            have_props = True
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


@dataclass(frozen=True)
class _Step:
    """One whole chunk of a scanned chain: where it starts, its control byte,
    whether the chain had its properties before it, its unpacked size and where it
    ends."""

    pos: int
    control: int
    had_props: bool
    unpacked: int
    end: int


class _Scanned:
    """A chain :class:`KnownChains` keeps, by its chunks: for the ``i``-th, the
    unpacked bytes and LZMA chunks before it, whether the chain had its properties
    before it, whether the rest of the chain is the same with or without them, and
    where the first LZMA chunk from it on ends with the bytes unpacked up to there."""

    def __init__(
        self,
        chain: Chain,
        steps: list[_Step],
        rest: tuple[_Scanned, int] | None,
        free: bool,
    ) -> None:
        self.chain = chain
        self.unpacked_before: list[int] = []
        self.lzma_before: list[int] = []
        self.had_props: list[bool] = []
        unpacked = lzma_chunks = 0
        for step in steps:
            self.unpacked_before.append(unpacked)
            self.lzma_before.append(lzma_chunks)
            self.had_props.append(step.had_props)
            unpacked += step.unpacked
            lzma_chunks += step.control >= 0x80
        # Backwards: from the chunk where the scan stopped (or took the rest of a
        # chain from), whether the properties it has matter, and the first LZMA
        # chunk ahead.
        if rest is not None:
            free = rest[0].props_free[rest[1]]
            ahead = rest[0].first_lzma[rest[1]]
        else:
            ahead = None
        self.props_free: list[bool] = [False] * len(steps)
        self.first_lzma: list[tuple[int, int] | None] = [None] * len(steps)
        for index in range(len(steps) - 1, -1, -1):
            step = steps[index]
            if step.control >= 0xC0:
                free = True
            elif step.control >= 0x80:
                free = False
            if step.control >= 0x80:
                ahead = (step.end, step.unpacked)
            elif ahead is not None:
                ahead = (ahead[0], step.unpacked + ahead[1])
            self.props_free[index] = free
            self.first_lzma[index] = ahead

    def joined(self, prefix: Chain, index: int) -> Chain:
        """``prefix``, which reached this chain's ``index``-th chunk, with the rest
        of this chain after it."""
        unpacked = self.chain.unpacked - self.unpacked_before[index]
        return replace(
            self.chain,
            start=prefix.start,
            unpacked=prefix.unpacked + unpacked,
            declared=prefix.unpacked
            + self.chain.declared
            - self.unpacked_before[index],
            lzma_chunks=prefix.lzma_chunks
            + self.chain.lzma_chunks
            - self.lzma_before[index],
            first_lzma_end=prefix.first_lzma_end,
            first_lzma_unpacked=prefix.first_lzma_unpacked,
        )


class KnownChains:
    """The chains one stream search scanned to their end, by chunk. A chain from a
    later candidate that reaches one of their chunks is the same from there on, so
    its scan takes the rest from it: each chunk header is read once, however many
    candidates' chains run through it (review C1: a cut chain of small chunks that
    each reset the dictionary is one candidate per chunk, and each read the chain to
    the area's end again)."""

    def __init__(self) -> None:
        self._at: dict[int, tuple[_Scanned, int]] = {}

    def at(self, pos: int, have_props: bool) -> tuple[_Scanned, int] | None:
        """The kept chain with a chunk at ``pos`` and its index, when a chain that
        reaches it with ``have_props`` goes on as that one does."""
        found = self._at.get(pos)
        if found is None:
            return None
        scanned, index = found
        if scanned.had_props[index] != have_props and not scanned.props_free[index]:
            return None
        return found

    def add(
        self,
        chain: Chain,
        steps: list[_Step],
        rest: tuple[_Scanned, int] | None,
        *,
        free: bool,
    ) -> None:
        """Keep ``chain`` by its whole chunks ``steps``; ``rest`` is the kept chain it
        took the rest from, and ``free`` whether the chunk it stopped at stops it
        whatever properties it had."""
        scanned = _Scanned(chain, steps, rest, free)
        for index, step in enumerate(steps):
            self._at[step.pos] = (scanned, index)


def first_lzma_chunk_decodes(
    reader: ChunkReader, chain: Chain, cap: DecoderCap | None = None
) -> bool:
    """Whether the chain's first LZMA chunk, with the chunks before it, decodes
    without error to the size their headers declare. ``False`` when it holds none,
    or when it ends more than :data:`_STREAM_HEADER_SPAN` bytes into the chain:
    a longer run of uncompressed chunks before it is not read to judge it."""
    if chain.first_lzma_end is None:
        return False
    return _lead_decodes(
        reader,
        chain.start,
        chain.first_lzma_end,
        chain.first_lzma_unpacked,
        cap or DecoderCap(),
    )


def _lead_decodes(
    reader: ChunkReader, start: int, lzma_end: int, size: int, cap: DecoderCap
) -> bool:
    """Whether the chunks from ``start`` to ``lzma_end``, the last of them the first
    LZMA chunk, decode without error to ``size`` bytes (see
    :func:`first_lzma_chunk_decodes`)."""
    if lzma_end - start > _STREAM_HEADER_SPAN:
        return False
    decoder = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": cap.dictionary(size)}],
    )
    data = reader.read(start, lzma_end - start)
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


def _range_coder_start(data: bytes) -> bool:
    """Whether ``data`` can start an LZMA1 stream: the range coder's first byte is
    ``00``, and its next four, the code it starts from, are not all zero. Zeros
    decode as LZMA1 without error, and zeros are what a cut or preallocated file
    holds."""
    return len(data) >= 5 and data[0] == 0 and data[1:5] != bytes(4)


def lzma1_starts_at(
    read_at: ReadAt, offset: int, end: int, cap: DecoderCap | None = None
) -> bool:
    """Whether an LZMA1 stream with 7-Zip's properties starts at ``offset``: its first
    bytes can start a range coder (:func:`_range_coder_start`), and they decode
    without error."""
    data = read_at(offset, min(_LZMA1_PROBE_INPUT, end - offset))
    if not _range_coder_start(data):
        return False
    decoder = _lzma1_decoder((cap or DecoderCap()).dictionary(_LZMA1_PROBE_OUTPUT))
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
    whether its place confirms it: found at a walk position (offset 32, or where the
    stream before it ended), or by the search with a chain that ends in ``00``. A
    searched chain that runs to the area's end is not confirmed.
    """

    start: int
    end: int
    codec: Codec
    size: int | None
    read_size: int
    confirmed: bool = True


@dataclass(frozen=True)
class HeaderCopy:
    """A copy of the end header the walk found in the packed area, which 7-Zip
    leaves there as the encoded header's stream: where its stream starts and its
    plain header bytes, to its ``kEnd``."""

    start: int
    data: bytes


@dataclass
class WalkResult:
    """The streams the walk and the search found, in archive order, and the header
    copy when one was found (the caller then lists from it, not from the streams)."""

    streams: list[ContentStream] = field(default_factory=list)
    copy: HeaderCopy | None = None


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


def layout_agrees(
    header: PlainHeader, copy_start: int, streams: list[ContentStream]
) -> bool:
    """Whether a header copy's pack info agrees with the walk: its packed streams lie
    between offset 32 and the copy, and each stream found starts at a pack position
    the copy gives, a complete LZMA2 one with an unpacked size of that folder."""
    info = header.streams
    sizes = info.pack_sizes or []
    base = SIGNATURE_HEADER_SIZE + info.pack_pos
    if base + sum(sizes) > copy_start:
        return False
    starts: dict[int, int] = {}
    position = base
    for index, size in enumerate(sizes):
        starts.setdefault(position, index)
        position += size
    folder_of: dict[int, SevenZipFolder] = {}
    index = 0
    for folder in info.folders or []:
        for _ in folder.packed_indices:
            folder_of[index] = folder
            index += 1
    for stream in streams:
        pack = starts.get(stream.start)
        if pack is None:
            return False
        if stream.codec == "lzma2" and stream.size is not None:
            owner = folder_of.get(pack)
            if owner is None or stream.size not in owner.unpack_sizes:
                return False
    return True


def _check_copy(
    start: int, data: bytes, streams: list[ContentStream]
) -> HeaderCopy | None:
    """``data`` as a header copy at ``start``: a plain header with at least one file
    that parses to its ``kEnd`` and whose layout agrees with ``streams``."""
    try:
        header, consumed = parse_header_prefix(data, max_members=None)
    except (
        CorruptionError,
        TruncatedError,
        UnsupportedFeatureError,
        ResourceLimitError,
    ):
        return None
    if not isinstance(header, PlainHeader) or not header.files:
        return None
    if not layout_agrees(header, start, streams):
        return None
    return HeaderCopy(start, data[:consumed])


def _lzma1_decoder(dict_size: int) -> lzma.LZMADecompressor:
    return lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}
        ],
    )


def _lzma1_header_start(data: bytes, cap: DecoderCap) -> bool:
    """Whether the LZMA1 stream that ``data`` starts decodes to a plain header's
    first two bytes (``kHeader``, then a section)."""
    if not _range_coder_start(data):
        return False
    try:
        out = _lzma1_decoder(cap.dictionary(2)).decompress(data, max_length=2)
    except lzma.LZMAError:
        return False
    return len(out) == 2 and out[0] == 0x01 and out[1] in _HEADER_SECOND


def decode_lzma1_prefix(
    data: bytes, max_out: int, cap: DecoderCap | None = None
) -> bytes:
    """Decode ``data`` as LZMA1 with 7-Zip's properties, keeping the bytes decoded
    before an error: LZMA1 has no end marker, so a decode runs on past its stream
    into whatever follows. The output is at most ``max_out`` bytes, and the
    dictionary is sized from it, at most ``max_decoder_memory`` (``cap``)."""
    dict_size = (cap or DecoderCap()).dictionary(max_out)

    def feed(decoder: lzma.LZMADecompressor, piece: bytes, out: bytearray) -> bool:
        """Feed ``piece``; ``False`` when the output reached a bound."""
        room = max_out - len(out)
        if room <= 0:
            return False
        out += decoder.decompress(piece, max_length=room)
        # Output held back (input left that the room did not let it decode) means a
        # bound cut it.
        return decoder.eof or decoder.needs_input

    decoder = _lzma1_decoder(dict_size)
    out = bytearray()
    for at in range(0, len(data), _LZMA1_PIECE):
        fed = min(len(data), at + _LZMA1_PIECE)
        try:
            more = feed(decoder, data[at:fed], out)
        except lzma.LZMAError:
            # Decode the input before the failing piece again, then the piece one
            # byte at a time, so its bytes before the failure are kept.
            decoder = _lzma1_decoder(dict_size)
            out = bytearray()
            if at:
                feed(decoder, data[:at], out)
            for byte_at in range(at, fed):
                try:
                    if not feed(decoder, data[byte_at : byte_at + 1], out):
                        break
                except lzma.LZMAError:
                    break
                if decoder.eof:
                    break
            break
        if not more or decoder.eof:
            break
    return bytes(out)


@dataclass
class HeaderBudget:
    """What one walk's header copies may cost: ``cap`` bytes for each copy, and
    ``cap`` bytes decoded across all its LZMA1 candidates together, so that a tail
    of many candidates that each decode far costs one cap, not one each."""

    cap: int
    left: int = -1

    def __post_init__(self) -> None:
        if self.left < 0:
            self.left = self.cap


def _input_for(max_header: int) -> int:
    """The most input a header of ``max_header`` bytes can take: LZMA grows data
    that does not compress by under 2 %."""
    return max_header + max_header // 32 + 64


def _lzma1_copy(
    read_at: ReadAt,
    pos: int,
    span: int,
    streams: list[ContentStream],
    header: HeaderBudget,
    cap: DecoderCap,
) -> HeaderCopy | None:
    max_out = header.left
    if max_out <= 0:
        return None
    data = read_at(pos, min(span, _input_for(max_out)))
    decoded = decode_lzma1_prefix(data, max_out, cap)
    header.left -= len(decoded)
    return _check_copy(pos, decoded, streams)


def copy_at(
    read_at: ReadAt,
    pos: int,
    end: int,
    streams: list[ContentStream],
    header: HeaderBudget,
    cap: DecoderCap | None = None,
) -> HeaderCopy | None:
    """The header copy at walk position ``pos``, when one starts there: a plain
    header, or after offset 32 an LZMA1 stream that decodes to one (LZMA1 is tried
    nowhere else after offset 32: its decode cannot tell content from wrong bytes).
    Each is held to ``header``: its cap, and what is left of the walk's decoding."""
    span = end - pos
    head = read_at(pos, min(span, 64))
    if (
        len(head) >= 2
        and head[0] == 0x01
        and head[1] in _HEADER_SECOND
        and span <= header.cap
    ):
        copy = _check_copy(pos, read_at(pos, span), streams)
        if copy is not None:
            return copy
    cap = cap or DecoderCap()
    if pos > SIGNATURE_HEADER_SIZE and _lzma1_header_start(head, cap):
        return _lzma1_copy(read_at, pos, span, streams, header, cap)
    return None


def tail_copy_search(
    read_at: ReadAt,
    end: int,
    streams: list[ContentStream],
    claim: ClaimFn,
    header: HeaderBudget,
    cap: DecoderCap,
) -> HeaderCopy | None:
    """The header copy in the area's last :data:`TAIL_COPY_SEARCH` bytes, from the
    end backwards, for when the walk stopped before reaching it (an LZMA1 or BCJ2
    folder runs into it). The decodes are held to ``header``. An offset
    whose byte is ``00`` and whose LZMA1 decode starts as a plain header goes on to
    the full decode and the copy's checks. No offset inside a complete stream the
    walk found is tried: the copy lies after the packed streams."""
    lo = max(end - TAIL_COPY_SEARCH, SIGNATURE_HEADER_SIZE)
    for stream in streams:
        if stream.codec == "lzma2" and stream.size is not None:
            lo = max(lo, stream.end)
    if lo >= end:
        return None
    lo = claim(lo, end)
    if lo >= end:
        return None
    data = read_at(lo, end - lo)
    at = len(data)
    while (at := data.rfind(b"\x00", 0, at)) >= 0:
        if _lzma1_header_start(data[at : at + 64], cap):
            if header.left <= 0:
                return None
            copy = _lzma1_copy(read_at, lo + at, end - lo - at, streams, header, cap)
            if copy is not None:
                return copy
    return None


class _UncompressedRuns:
    """Where the first LZMA chunk of a chain from each candidate in a window ends,
    found without walking the same chunks twice.

    A chain's uncompressed chunks (``01``, ``02``) are each followed by one at a place
    their header gives, so two candidates whose chains meet share every chunk after
    that place. Walking each candidate's chain on its own made the stream search
    quadratic in a window of ``01`` bytes, each of them a candidate whose chain of
    uncompressed chunks runs to the window's end (review C1: 80 000 bytes took 4 s).
    Each run is walked once, and where it ends is kept for every chunk on it.
    """

    def __init__(self, window: bytes) -> None:
        self._window = window
        # For each offset whose byte is 01 or 02 and that a run was walked through:
        # where the run of uncompressed chunks from it ends (-1: it runs past the
        # window's end), and the bytes the run unpacks to. 0: not walked yet. Made
        # at the first run, so that a search that finds a stream before any costs
        # no more than its window.
        self._run_end = array("i")
        self._unpacked = array("i")

    def _run(self, pos: int) -> tuple[int, int]:
        window = self._window
        size = len(window)
        if not self._run_end:
            self._run_end = array("i", (0,)) * size
            self._unpacked = array("i", (0,)) * size
        run_end = self._run_end
        path: list[int] = []
        sizes: list[int] = []
        at = pos
        while run_end[at] == 0:
            path.append(at)
            if at + 3 > size:
                sizes.append(0)
                end, total = -1, 0
                break
            chunk = int.from_bytes(window[at + 1 : at + 3], "big") + 1
            sizes.append(chunk)
            after = at + 3 + chunk
            if after >= size:
                end, total = -1, 0
                break
            if window[after] not in (0x01, 0x02):
                end, total = after, 0
                break
            at = after
        else:
            end, total = run_end[at], self._unpacked[at]
        for at, chunk in zip(reversed(path), reversed(sizes), strict=True):
            total += chunk
            run_end[at] = end
            self._unpacked[at] = total
        return run_end[pos], self._unpacked[pos]

    def first_lzma(self, index: int) -> tuple[int, int] | None:
        """For the candidate at ``index``, where its chain's first LZMA chunk ends and
        the bytes the chain unpacks to up to there; ``None`` when its chain ends,
        breaks or leaves the window before an LZMA chunk ends, as :func:`scan_chain`
        would find it."""
        window = self._window
        if window[index] == 0x01:
            lzma_at, unpacked = self._run(index)
            if lzma_at < 0:
                return None
            # No LZMA chunk set the properties yet: this one must.
            if window[lzma_at] < 0xC0:
                return None
        else:
            lzma_at, unpacked = index, 0
        head = window[lzma_at : lzma_at + 6]
        if len(head) < 6 or not _valid_props(head[5]):
            return None
        size = ((head[0] & 0x1F) << 16) + int.from_bytes(head[1:3], "big") + 1
        end = lzma_at + 6 + int.from_bytes(head[3:5], "big") + 1
        if end > len(window):
            return None
        return end, unpacked + size


class StreamFinder:
    """The finder of the search for the next LZMA2 stream, for the shared search
    driver, where the walk cannot go on.

    A candidate passes when its first chunk resets the dictionary, an LZMA chunk
    within :data:`_STREAM_HEADER_SPAN` bytes of it decodes without error (a chain of
    uncompressed chunks only has no check), and its chain, read on to the area's
    end, ends in ``00`` or runs to the area's end. The driver reads through
    :meth:`read`. A search's first read starts at its first window, and a window
    that finds nothing is followed by one that starts at its ``stop`` (the step is
    1): that places each window in the area, and the whole chain is read through
    the area's own reader. :meth:`begin` starts a search. :attr:`chains` keeps each
    passing chain.
    """

    def __init__(
        self, read_at: ReadAt, end: int, cap: DecoderCap | None = None
    ) -> None:
        self._read_at = read_at
        self._cap = cap or DecoderCap()
        self._area = CachedReader(read_at, end)
        self._end = end
        # Where the window the driver gives next starts in the area; ``None`` until
        # a search's first read.
        self._window_start: int | None = None
        self.chains: dict[int, Chain] = {}
        self._known = KnownChains()
        self.search = HeaderSearch(
            find_header=self.find, step=1, max_header_size=_STREAM_HEADER_SPAN
        )

    def begin(self) -> None:
        """Start a search: its first read places its first window."""
        self._window_start = None

    def read(self, offset: int, size: int) -> bytes:
        if self._window_start is None:
            self._window_start = offset
        return self._read_at(offset, size)

    def find(self, window: bytes, start: int, stop: int) -> int | None:
        base = self._window_start
        assert base is not None, "find before the search's first read"
        local = BytesReader(window)
        runs = _UncompressedRuns(window)
        work = LEAD_WORK_FACTOR * len(window)
        for match in _STREAM_START.finditer(window, start):
            index = match.start()
            if index >= stop:
                break
            lead = runs.first_lzma(index)
            if lead is None or lead[0] - index > _STREAM_HEADER_SPAN:
                continue
            work -= lead[0] - index
            if work < 0:
                # The checks of this window's candidates are spent: the rest of its
                # candidates are not tried.
                break
            if not _lead_decodes(local, index, *lead, self._cap):
                continue
            chain = scan_chain(self._area, base + index, self._end, self._known)
            if chain is None or chain.status == "broken":
                continue
            self.chains[base + index] = chain
            return index
        self._window_start = base + stop
        return None


def _walk_from(
    reader: CachedReader,
    read_at: ReadAt,
    pos: int,
    end: int,
    result: WalkResult,
    header: HeaderBudget,
    cap: DecoderCap,
) -> int | None:
    """Walk from ``pos`` while a stream starts at each walk position, adding to
    ``result``. Gives where the search goes on from, or ``None`` when the walk
    reached the area's end, ran into a cut stream, or found the header copy."""
    while pos < end:
        copy = copy_at(read_at, pos, end, result.streams, header, cap)
        if copy is not None:
            result.copy = copy
            return None
        chain = scan_chain(reader, pos, end)
        if chain is not None and (
            chain.status != "broken" or first_lzma_chunk_decodes(reader, chain, cap)
        ):
            # A chain that breaks is listed only when an LZMA chunk in it decodes:
            # random or encrypted bytes pass a first chunk header often enough.
            result.streams.append(stream_from_chain(chain, end))
            if chain.status == "cut":
                return None
            if chain.status == "broken":
                assert chain.broken_at is not None
                return chain.broken_at
            pos = chain.end
            continue
        if pos == SIGNATURE_HEADER_SIZE and lzma1_starts_at(read_at, pos, end, cap):
            # Unconfirmed: only its position says it is a stream (LZMA1 has no end
            # marker and no chunk headers to check).
            result.streams.append(
                ContentStream(pos, end, "lzma", None, UNKNOWN_SIZE, confirmed=False)
            )
            return pos + 1
        return pos
    return None


def walk_packed_area(
    read_at: ReadAt,
    end: int,
    *,
    search: SearchFn,
    claim: ClaimFn,
    cap: DecoderCap,
    max_header: int = MAX_NEXT_HEADER_SIZE,
) -> WalkResult:
    """Walk the packed area from offset 32 to ``end``: the streams at walk positions
    and the header copy; when the walk stops before the area's end, the copy in the
    area's tail, then the streams the search finds. A header copy is held to
    ``max_header`` bytes, decoded or plain, and so is the sum of the bytes decoded
    across all the walk's LZMA1 candidates (:class:`HeaderBudget`). Its trial
    decodes are held to ``cap``."""
    reader = CachedReader(read_at, end)
    result = WalkResult()
    header = HeaderBudget(max_header)
    resume = _walk_from(
        reader, read_at, SIGNATURE_HEADER_SIZE, end, result, header, cap
    )
    if resume is None:
        return result
    copy = tail_copy_search(read_at, end, result.streams, claim, header, cap)
    if copy is not None:
        result.copy = copy
        return result
    finder = StreamFinder(read_at, end, cap)
    while resume is not None and resume < end:
        finder.begin()
        found = search(resume, end, finder.search, finder.read)
        if found is None:
            break
        chain = finder.chains[found]
        first = result.streams[0] if result.streams else None
        if first is not None and first.codec == "lzma" and first.end == end:
            # The LZMA1 member's input ends at the first stream the search finds.
            result.streams[0] = replace(first, end=found)
        if chain.status == "cut":
            # Unconfirmed: it does not claim its range, so the search goes on in it.
            result.streams.append(stream_from_chain(chain, end, confirmed=False))
            resume = found + 1
            continue
        result.streams.append(stream_from_chain(chain, end))
        resume = _walk_from(reader, read_at, chain.end, end, result, header, cap)
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
    content member reads through the normal folder pipeline: ``DecoderLimits`` and
    ``ExtractionLimits`` hold it as any member."""
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
    "LEAD_WORK_FACTOR",
    "TAIL_COPY_SEARCH",
    "UNKNOWN_SIZE",
    "BytesReader",
    "CachedReader",
    "Chain",
    "ChunkReader",
    "ClaimFn",
    "ContentStream",
    "DecoderCap",
    "HeaderBudget",
    "HeaderCopy",
    "KnownChains",
    "SearchFn",
    "StreamFinder",
    "WalkResult",
    "content_archive",
    "content_name",
    "copy_at",
    "decode_lzma1_prefix",
    "first_lzma_chunk_decodes",
    "layout_agrees",
    "lzma1_starts_at",
    "lzma2_dict_prop",
    "scan_chain",
    "starts_lzma2",
    "stream_from_chain",
    "tail_copy_search",
    "walk_packed_area",
]
