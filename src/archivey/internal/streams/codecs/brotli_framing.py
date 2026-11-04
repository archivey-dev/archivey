"""Brotli meta-block framing for the content probe (RFC 7932 §9.1–9.2).

The detector needs a cheap classification of opening headers — WBITS plus
meta-block headers — without Huffman-decoding a compressed body. Declared
(uncompressed / metadata) meta-blocks assert a byte count the source must
physically hold; when ``source_length`` is known, a probe that overruns that
length is not a complete valid stream.

The **chain walk** follows byte-aligned self-describing meta-blocks past the
first, stopping at the first compressed block. It reports where that block starts, so
the probe can decode up to it when it lies past the window (``BrotliCodec``). Reference
behaviour lives in ``scripts/investigations/exploration/brotli_probe_field_survey.py``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

# Link cap 8: real-tree census rejected every fabrication by link index ≤ 1;
# revisit with hard data if a future corpus shows deeper rejecting chains.
# Forward-only memory for non-seekable ``read_at`` is capped separately at 1 MiB
# in ``detection_workspace.PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE`` (declared in the
# format-detection chain-walk requirement).
CHAIN_MAX_LINKS = 8
CHAIN_HEADER_READ = 24
# When the walk stops at a compressed block past the window, the probe decodes the
# source from offset 0 to this far past that block's header. Every measured false claim of
# this shape (real files, libmagic bodies) failed within 256 bytes of the header; a
# real stream that reaches the end of the sample is accepted, so more margin only costs
# time.
CHAIN_DECODE_MARGIN = 4096


class BrotliBlock(Enum):
    """Outcome of parsing one meta-block header."""

    COMPRESSED = "compressed"
    UNCOMPRESSED = "uncompressed"
    METADATA = "metadata"
    EMPTY_LAST = "empty_last"
    # Anything we cannot classify cheaply (short prefix, invalid header, …).
    UNDECIDED = "undecided"


@dataclass(frozen=True)
class BrotliFraming:
    """Meta-block classification plus the bytes a declaring block consumes."""

    outcome: BrotliBlock
    consumed: int | None = None
    declared_length: int | None = None
    is_last: bool | None = None

    @property
    def declares_length(self) -> bool:
        return self.outcome in (
            BrotliBlock.UNCOMPRESSED,
            BrotliBlock.METADATA,
        )


class _Bits:
    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, n: int) -> int:
        value = 0
        for i in range(n):
            byte_i, bit_i = divmod(self._pos, 8)
            if byte_i >= len(self._data):
                raise EOFError
            value |= ((self._data[byte_i] >> bit_i) & 1) << i
            self._pos += 1
        return value

    @property
    def pos(self) -> int:
        return self._pos


def _wbits(br: _Bits) -> bool:
    """Consume the window-bits field. Return False on an illegal encoding."""
    if br.take(1) == 0:
        return True
    n = br.take(3)
    if n != 0:
        return True
    m = br.take(3)
    # m == 1 is reserved for the large-window extension (invalid in RFC 7932).
    return m != 1


def _metablock(br: _Bits) -> BrotliFraming:
    islast = br.take(1) == 1
    if islast and br.take(1):  # ISLASTEMPTY
        pad = (-br.pos) % 8
        ok = pad == 0 or br.take(pad) == 0
        if not ok:
            return BrotliFraming(BrotliBlock.UNDECIDED)
        return BrotliFraming(
            BrotliBlock.EMPTY_LAST,
            consumed=(br.pos + 7) // 8,
            is_last=True,
        )

    code = br.take(2)
    if code == 3:  # metadata (MNIBBLES == 0); may carry ISLAST
        if br.take(1) != 0:  # reserved
            return BrotliFraming(BrotliBlock.UNDECIDED)
        nbytes = br.take(2)
        if nbytes == 0:
            skip = 0
        else:
            skip = br.take(nbytes * 8)
            if nbytes > 1 and (skip >> ((nbytes - 1) * 8)) == 0:
                return BrotliFraming(BrotliBlock.UNDECIDED)
            skip += 1
        pad = (-br.pos) % 8
        if pad and br.take(pad) != 0:
            return BrotliFraming(BrotliBlock.UNDECIDED)
        return BrotliFraming(
            BrotliBlock.METADATA,
            consumed=br.pos // 8,
            declared_length=skip,
            is_last=islast,
        )

    nibbles = 4 + code
    mlen = 0
    for i in range(nibbles):
        nib = br.take(4)
        # Top nibble must be non-zero when MNIBBLES > 4 (exuberant-nibble rule).
        if i + 1 == nibbles and nibbles > 4 and nib == 0:
            return BrotliFraming(BrotliBlock.UNDECIDED)
        mlen |= nib << (4 * i)
    declared = mlen + 1

    if not islast and br.take(1):  # ISUNCOMPRESSED
        pad = (-br.pos) % 8
        if pad and br.take(pad) != 0:
            return BrotliFraming(BrotliBlock.UNDECIDED)
        return BrotliFraming(
            BrotliBlock.UNCOMPRESSED,
            consumed=br.pos // 8,
            declared_length=declared,
            is_last=False,
        )
    # Compressed body — Huffman tables follow; we stop without decoding them.
    return BrotliFraming(BrotliBlock.COMPRESSED, is_last=islast)


def parse_metablock(data: bytes, *, first: bool = True) -> BrotliFraming:
    """Classify a meta-block header. ``first=False`` skips the stream WBITS field."""
    br = _Bits(data)
    try:
        if first and not _wbits(br):
            return BrotliFraming(BrotliBlock.UNDECIDED)
        return _metablock(br)
    except EOFError:
        return BrotliFraming(BrotliBlock.UNDECIDED)


def first_block_overruns_source(prefix: bytes, source_length: int) -> bool:
    """True when a declaring first meta-block cannot fit in ``source_length``."""
    info = parse_metablock(prefix, first=True)
    if not info.declares_length:
        return False
    assert info.consumed is not None and info.declared_length is not None
    return info.consumed + info.declared_length > source_length


@dataclass(frozen=True)
class ChainWalk:
    """What the chain walk found.

    ``proves_invalid`` is True when the declared framing cannot be a complete stream.
    Otherwise ``compressed_at`` is the absolute offset of the compressed meta-block the
    walk stopped at, or ``None`` when it stopped for another reason (a declared end that
    fits, a declined read, the link cap).
    """

    proves_invalid: bool
    compressed_at: int | None = None


def walk_chain(
    prefix: bytes,
    source_length: int,
    *,
    read_at: Callable[[int, int], bytes | None] | None = None,
    max_links: int = CHAIN_MAX_LINKS,
) -> ChainWalk:
    """Follow the self-describing block chain from offset 0 (see :func:`chain_proves_invalid`).

    Follows byte-aligned uncompressed/metadata meta-blocks, stopping at the first
    compressed block. Rejects a link that overruns ``source_length`` or a declared end
    that leaves trailing bytes. Link-cap exhaustion or a declined ``read_at`` (``None``)
    means *cannot disprove*.

    ``read_at(offset, length)`` returns bytes at that absolute offset, short/empty on
    EOF, or ``None`` when the caller will not provide the read. When omitted, only
    bytes already in ``prefix`` are reachable — and prefix exhaustion is EOF only
    when ``len(prefix) >= source_length``; otherwise it is declined (cannot disprove).
    """
    cannot_disprove = ChainWalk(proves_invalid=False)
    proven = ChainWalk(proves_invalid=True)
    off = 0
    for _ in range(max_links):
        chunk = probe_bytes_at(prefix, source_length, off, CHAIN_HEADER_READ, read_at)
        if chunk is None:
            return cannot_disprove  # declined
        if not chunk:
            return proven  # expected a header, got EOF
        info = parse_metablock(chunk, first=(off == 0))
        if info.outcome is BrotliBlock.UNDECIDED:
            return proven
        if info.outcome is BrotliBlock.COMPRESSED:
            # No declared length to check: only a decoder can say more.
            return ChainWalk(proves_invalid=False, compressed_at=off)
        if info.outcome is BrotliBlock.EMPTY_LAST:
            assert info.consumed is not None
            return ChainWalk(proves_invalid=off + info.consumed != source_length)
        assert info.consumed is not None and info.declared_length is not None
        nxt = off + info.consumed + info.declared_length
        if nxt > source_length:
            return proven
        if info.is_last:
            return ChainWalk(proves_invalid=nxt != source_length)
        off = nxt
    return cannot_disprove  # link cap


def chain_proves_invalid(
    prefix: bytes,
    source_length: int,
    *,
    read_at: Callable[[int, int], bytes | None] | None = None,
    max_links: int = CHAIN_MAX_LINKS,
) -> bool:
    """True when the self-describing block chain proves the source is not complete Brotli.

    Follows byte-aligned uncompressed/metadata meta-blocks, stopping at the first
    compressed block. Rejects a link that overruns ``source_length`` or a declared end
    that leaves trailing bytes. Link-cap exhaustion or a declined ``read_at``
    (``None``) means *cannot disprove* — returns False so the earlier verdict stands.
    :func:`walk_chain` also reports where a compressed block stopped the walk.
    """
    return walk_chain(
        prefix, source_length, read_at=read_at, max_links=max_links
    ).proves_invalid


def probe_bytes_at(
    prefix: bytes,
    source_length: int,
    offset: int,
    length: int,
    read_at: Callable[[int, int], bytes | None] | None,
) -> bytes | None:
    """``length`` bytes at ``offset``, served from ``prefix`` first, then ``read_at``.

    ``None`` when the bytes cannot be reached: ``read_at`` declined, or it is absent and
    the prefix is not the whole source. Short or empty at EOF.
    """
    end = offset + length
    if offset < len(prefix):
        # Serve whatever of the request sits in the prefix.
        in_prefix = prefix[offset : min(end, len(prefix))]
        if end <= len(prefix):
            return in_prefix
        if read_at is None:
            # Prefix exhausted: real EOF only when the prefix *is* the whole
            # source; otherwise we cannot see further → cannot disprove.
            if len(prefix) >= source_length:
                return in_prefix
            return None
        rest = read_at(len(prefix), end - len(prefix))
        if rest is None:
            return None
        return in_prefix + rest
    if read_at is None:
        if len(prefix) >= source_length:
            return b""  # past EOF of a fully-visible prefix
        return None
    return read_at(offset, length)
