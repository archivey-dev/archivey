"""Resume a DEFLATE decode with ``zlib`` at a block boundary another decoder found.

rapidgzip's index lists DEFLATE block boundaries: a compressed *bit* offset and the
decompressed offset there. At a block boundary an inflater carries only two things
forward: where it is in the input, and the last 32 KiB of output (back-references
reach no further; Huffman tables are per block). Given both, ``zlib`` can start there:

- the output before the point goes in as a preset dictionary, which is what a raw
  DEFLATE ``decompressobj(-15, zdict=...)`` fills its window with;
- the bit offset is the hard part. zlib's ``inflatePrime`` would feed the leftover
  bits, and Python's ``zlib`` does not expose it. So the input starts with empty
  DEFLATE blocks, made up here, whose length in bits ends ``bit`` bits into a byte.
  That byte's other bits are the source's own, and every byte after it is the source
  unchanged, so the decode lines up with the source again from there.

zlib only checks a stream's checksum (gzip CRC-32, zlib Adler-32) over the whole
stream, and a resumed decode never saw the part before its point. So a resumed decode
that reaches the end of its DEFLATE stream raises :class:`ResumeReachedStreamEnd`, and
the caller decodes from the start instead, which checks it. Reaching the end of the
input first is a truncation, which a checksum would not change.

:class:`DeflateResumeDecoder` serves ``_StdlibOnAcceleratorError`` in
``codecs/stdlib_takeover.py``, which takes over a read from rapidgzip. :func:`stream_end`
asks only whether a raw DEFLATE stream reaches a final block, and where. Raw DEFLATE has
no checksum, so there reaching the end is the answer, with no ``ResumeReachedStreamEnd``
case. Its caller is ``_DeflateEndCheckStream`` in ``codecs/zlib_codec.py``, before any
takeover, to decide whether one is needed. The takeover's points come from
``RapidgzipChildStream.resume_point``, the points the stream kept as it read. The end
check under ``refuse_input_after_end`` takes its point from
``RapidgzipChildStream.end_check_point``, the last point of rapidgzip's complete index,
and without the flag from ``resume_point``.
"""

from __future__ import annotations

import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import RAW_DEFLATE_WBITS
from archivey.internal.streams.codecs.isolated import (
    IN_PROCESS,
    Natives,
    ZlibDecompressor,
)
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    Decoder,
    SeekPoint,
    _inflate,
    _inflate_rest,
    release_decoder,
)
from archivey.internal.streams.resume import ResumeReachedStreamEnd

# The most output a DEFLATE back-reference can reach.
WINDOW_SIZE = 32 << 10


@dataclass(frozen=True, slots=True)
class DeflateResume:
    """A :class:`SeekPoint` state: a DEFLATE block boundary inside the stream.

    The block starts ``bit`` bits (0 to 7) into the byte at the point's
    ``compressed_offset``. ``window`` is the output just before the point, up to
    :data:`WINDOW_SIZE` bytes (less only near the start of the stream).
    """

    bit: int
    window: bytes


class _Bits:
    """Bits in DEFLATE order: each byte filled from its least significant bit."""

    def __init__(self) -> None:
        self.bits: list[int] = []

    def value(self, value: int, count: int) -> None:
        """A header field or extra bits: least significant bit first."""
        self.bits.extend((value >> i) & 1 for i in range(count))

    def code(self, code: int, count: int) -> None:
        """A Huffman code: most significant bit first."""
        self.bits.extend((code >> i) & 1 for i in reversed(range(count)))


def _empty_fixed_block(bits: _Bits) -> None:
    """A non-final block with fixed Huffman codes and no symbols: 10 bits."""
    bits.value(0, 1)  # BFINAL
    bits.value(1, 2)  # BTYPE 01, fixed codes
    bits.code(0, 7)  # end of block (256)


# The order the code-length code lengths are written in (RFC 1951 §3.2.7).
_CODE_LENGTH_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)


def _empty_dynamic_block(bits: _Bits) -> None:
    """A non-final block with dynamic Huffman codes and no symbols: 95 bits.

    The literal/length code has only end of block, with length 1; zlib accepts that
    one incomplete code. There are no distance codes. The code-length code is complete
    over the three symbols it uses: 18 (a run of zeros) as ``0``, 0 as ``10``, 1 as
    ``11``. All 19 code-length code lengths are written, which makes the length odd.
    """
    bits.value(0, 1)  # BFINAL
    bits.value(2, 2)  # BTYPE 10, dynamic codes
    bits.value(0, 5)  # HLIT: 257 literal/length codes
    bits.value(0, 5)  # HDIST: 1 distance code
    bits.value(len(_CODE_LENGTH_ORDER) - 4, 4)  # HCLEN: all 19
    lengths = {18: 1, 0: 2, 1: 2}
    for symbol in _CODE_LENGTH_ORDER:
        bits.value(lengths.get(symbol, 0), 3)
    bits.code(0b0, 1)  # 18: 138 zeros
    bits.value(138 - 11, 7)
    bits.code(0b0, 1)  # 18: 118 zeros, so symbols 0 to 255 have no code
    bits.value(118 - 11, 7)
    bits.code(0b11, 2)  # 1: end of block has length 1
    bits.code(0b10, 2)  # 0: the one distance code is unused
    bits.code(0b0, 1)  # end of block


def _prefix(bit: int) -> tuple[bytes, int]:
    """Empty blocks whose length in bits is ``bit`` more than a whole number of bytes.

    Returns the whole bytes, and the ``bit`` low bits of the byte they end in. Fixed
    blocks are 10 bits, so they reach the even values; one 95-bit dynamic block before
    them reaches the odd ones.
    """
    bits = _Bits()
    if bit % 2:
        _empty_dynamic_block(bits)
        fixed = ((bit - 7) % 8) // 2
    else:
        fixed = bit // 2
    for _ in range(fixed):
        _empty_fixed_block(bits)
    assert len(bits.bits) % 8 == bit
    whole = len(bits.bits) // 8
    data = bytes(sum(bits.bits[8 * i + j] << j for j in range(8)) for i in range(whole))
    low = sum(bits.bits[8 * whole + j] << j for j in range(bit))
    return data, low


def _resume_decompressor(
    resume: DeflateResume, natives: Natives = IN_PROCESS
) -> ZlibDecompressor:
    """A raw DEFLATE decompressor with ``resume``'s window, after checking the point."""
    if not 0 <= resume.bit < 8 or len(resume.window) > WINDOW_SIZE:
        raise ValueError(f"not a DEFLATE resume point: {resume!r}")
    if resume.window:
        return natives.zlib_decompressobj(RAW_DEFLATE_WBITS, zdict=resume.window)
    return natives.zlib_decompressobj(RAW_DEFLATE_WBITS)


def _splice(bit: int, chunk: bytes) -> bytes:
    """The first input ``chunk`` of a decode that starts ``bit`` bits into its first
    byte: empty blocks that end ``bit`` bits into a byte, then that byte's other bits,
    then the rest of ``chunk`` unchanged."""
    if not bit or not chunk:
        return chunk
    prefix, low = _prefix(bit)
    high = chunk[0] & (0xFF << bit) & 0xFF
    return prefix + bytes([low | high]) + chunk[1:]


class DeflateResumeDecoder(BaseDecoder):
    """Inflate from a :class:`DeflateResume` point to the end of the input.

    ``base`` is the codec's own decoder, which every other seek point recreates.
    ``corruption`` maps a ``zlib.error`` the way the base decoder does, and
    ``truncated`` is the message the base decoder gives a truncation.
    """

    def __init__(
        self,
        resume: DeflateResume,
        base: Decoder,
        *,
        corruption: Callable[[zlib.error], Exception],
        truncated: str,
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._decomp = _resume_decompressor(resume, natives)
        self._base = base
        self._corruption = corruption
        self._truncated = truncated
        self._bit = resume.bit
        # Cleared once the first byte of input has been spliced onto the prefix.
        self._before_input = True

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        return self._base.recreate(point, inner)

    def _spliced(self, chunk: bytes) -> bytes:
        if not self._before_input or not chunk:
            return chunk
        self._before_input = False
        return _splice(self._bit, chunk)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        data = self._decomp.unconsumed_tail + self._spliced(chunk)
        if not data:
            return DecodeOut(b"")
        out = _inflate(self._decomp, data, max_length, self._corruption)
        if self._decomp.eof:
            raise ResumeReachedStreamEnd
        return DecodeOut(out)

    def flush(self) -> DecodeOut:
        out = _inflate_rest(self._decomp, self._corruption)
        if self._decomp.eof:
            raise ResumeReachedStreamEnd
        self._pending_error = TruncatedError(self._truncated)
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return False

    @property
    @override
    def needs_input(self) -> bool:
        return not self._decomp.unconsumed_tail


def stream_end(
    source: BinaryIO,
    point: SeekPoint | None,
    cap: int,
    *,
    check_input_after: bool = False,
    natives: Natives = IN_PROCESS,
) -> tuple[int | None, bool]:
    """The decompressed offset where the raw DEFLATE stream in ``source`` ends, and
    whether input follows it.

    ``source`` is the compressed stream, seekable from offset 0. The decode starts at
    ``point`` (a :class:`DeflateResume` block boundary at or before ``cap``), or at the
    start of the stream when it is ``None``, and stops at the stream's final block.
    ``None`` when it does not get there: the input runs out first (a cut stream), zlib
    raises, or the output passes ``cap``. Raw DEFLATE has no checksum, so a resumed
    decode that reaches the end is as good as a full one. Output is counted and
    dropped, in bounded pieces.

    The second value is False unless ``check_input_after`` is set. Then it is whether
    ``source`` holds any byte after the stream's end, a zero too, a further stream
    included. From a resume point, "the stream" is the one the point lies in: a point
    can lie in a further stream that rapidgzip read on into, and then the first
    stream's end goes unseen. Only a decode from the start (``point`` of ``None``) finds
    that end.
    """
    if point is not None:
        resume = point.state
        # RapidgzipChildStream.resume_point and end_check_point give only such points.
        assert isinstance(resume, DeflateResume) and point.decompressed_offset <= cap
        decomp = _resume_decompressor(resume, natives)
        produced, bit = point.decompressed_offset, resume.bit
        source.seek(point.compressed_offset)
    else:
        produced, bit = 0, 0
        decomp = natives.zlib_decompressobj(RAW_DEFLATE_WBITS)
        source.seek(0)
    try:
        return _decode_to_end(source, decomp, produced, bit, cap, check_input_after)
    finally:
        release_decoder(decomp)


def _decode_to_end(
    source: BinaryIO,
    decomp: ZlibDecompressor,
    produced: int,
    bit: int,
    cap: int,
    check_input_after: bool,
) -> tuple[int | None, bool]:
    """:func:`stream_end` from where ``decomp`` stands: ``produced`` bytes out, and
    ``bit`` bits of ``source``'s next byte already read."""
    data = b""
    try:
        while not decomp.eof:
            if produced > cap:
                return None, False
            if not data:
                data = source.read(1 << 16)
                if not data:
                    # zlib can still hold output an earlier ``max_length`` cut kept
                    # back, the final block's included: drain it, then let ``eof``
                    # decide whether the stream was cut. No ``flush`` fallback: on a
                    # binding that holds more back, ``None`` costs a second decode
                    # (the caller switches to the standard library), not a wrong
                    # verdict.
                    held = len(decomp.decompress(b"", 1 << 20))
                    if not held and not decomp.eof:
                        return None, False
                    produced += held
                    continue
                data, bit = _splice(bit, data), 0
            produced += len(decomp.decompress(data, 1 << 20))
            data = decomp.unconsumed_tail
    except zlib.error:
        return None, False
    if produced > cap:
        return None, False
    after = check_input_after and (bool(decomp.unused_data) or bool(source.read(1)))
    return produced, after
