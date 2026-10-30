"""Resume a bzip2 decode with ``bz2`` at a block boundary another decoder found.

rapidgzip's bzip2 index lists where each block starts: a compressed *bit* offset and
the decompressed offset there. A bzip2 block carries no state from the blocks before
it (each is a separate Burrows-Wheeler transform with its own Huffman tables and CRC),
so a decoder can start at any block. Two things stand in the way of ``bz2``:

- it reads a stream, not a block, so the input must start with a stream header. The
  header made up here is ``BZh9``. The digit is the largest block size the decoder
  accepts, and it changes nothing else in the output, so it fits a block from a stream
  of any level, including the second stream of a concatenated file;
- a block starts at any bit, and ``bz2`` reads whole bytes. So the input is shifted
  left by the block's bit offset into its first byte, a chunk at a time, with the last
  byte of each chunk carried into the next. Its bits are then where ``bz2`` expects
  them, right after the made-up header.

The stream's combined CRC, in its end-of-stream marker, covers every block's CRC, and a
resumed decode never saw the blocks before its point. So when it reaches the marker the
check fails, and ``bz2`` says "Invalid data stream", exactly as it does for a damaged
block. The resumed decode cannot tell the two apart, and does not try: on that error, or
on a clean end, it raises :class:`ResumeReachedStreamEnd`, and the caller decodes from
the start instead, which decides. Reaching the end of the input first is a truncation,
and the stdlib's own :class:`~archivey.exceptions.TruncatedError` is the verdict.

The caller is ``_StdlibOnAcceleratorError`` in ``codecs/stdlib_takeover.py``, which
takes over a read from rapidgzip's bzip2 decoder; the points come from
``_bzip2_resume_points`` in ``codecs/bzip2_codec.py``.
"""

from __future__ import annotations

import bz2
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from archivey.exceptions import TruncatedError
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    Decoder,
    SeekPoint,
)
from archivey.internal.streams.resume import ResumeReachedStreamEnd

if TYPE_CHECKING:
    from archivey.formats import Decompressor

# A stream header that accepts a block of any size (see the module docstring).
_HEADER = b"BZh9"


@dataclass(frozen=True, slots=True)
class Bzip2Resume:
    """A :class:`SeekPoint` state: a bzip2 block that starts ``bit`` bits (0 to 7) into
    the byte at the point's ``compressed_offset``."""

    bit: int


class BitShifter:
    """Shift a byte sequence left by ``bit`` bits (0 to 7), one chunk at a time.

    The first ``bit`` bits of the first byte are dropped. Each output byte needs the
    next input byte, so the last byte of each chunk is held until the next chunk or
    :meth:`flush`, where it comes out padded with zero bits.
    """

    def __init__(self, bit: int) -> None:
        if not 0 <= bit < 8:
            raise ValueError(f"not a bit offset into a byte: {bit}")
        self._bit = bit
        self._held = b""

    def feed(self, chunk: bytes) -> bytes:
        if not self._bit:
            return chunk
        data = self._held + chunk
        if len(data) < 2:
            self._held = data
            return b""
        self._held = data[-1:]
        size = len(data)
        # One int per chunk, never per stream: the decoder feeds at most a MiB.
        shifted = (int.from_bytes(data, "big") << self._bit) & ((1 << (8 * size)) - 1)
        return shifted.to_bytes(size, "big")[:-1]

    def flush(self) -> bytes:
        if not self._held:
            return b""
        last = (self._held[0] << self._bit) & 0xFF
        self._held = b""
        return bytes([last])


class Bzip2ResumeDecoder(BaseDecoder):
    """Decode from a :class:`Bzip2Resume` point to the end of the input.

    ``base`` is the codec's own decoder, which every other seek point recreates.
    ``new_decompressor`` builds the ``bz2`` decompressor, in this process or a child
    (``process_isolation``), as the base decoder builds its own.
    """

    def __init__(
        self,
        resume: Bzip2Resume,
        base: Decoder,
        new_decompressor: Callable[[], Decompressor] = bz2.BZ2Decompressor,
    ) -> None:
        self._base = base
        self._shifter = BitShifter(resume.bit)
        self._decomp = new_decompressor()
        # Cleared once the made-up header has gone in ahead of the first input.
        self._before_input = True

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        return self._base.recreate(point, inner)

    def _decompress(self, data: bytes, max_length: int) -> bytes:
        if self._before_input:
            self._before_input = False
            data = _HEADER + data
        try:
            out = self._decomp.decompress(data, max_length)
        except OSError as exc:
            # The end-of-stream marker's combined CRC, or a damaged block; the decode
            # from the start tells which (see the module docstring).
            raise ResumeReachedStreamEnd from exc
        if self._decomp.eof:
            # The combined CRC matched by chance; the decode from the start checks it.
            raise ResumeReachedStreamEnd
        return out

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        data = self._shifter.feed(chunk)
        if not data and self._decomp.needs_input and not self._before_input:
            return DecodeOut(b"")
        return DecodeOut(self._decompress(data, max_length))

    def flush(self) -> DecodeOut:
        out = b""
        tail = self._shifter.flush()
        if tail or not self._decomp.needs_input:
            out = self._decompress(tail, -1)
        # bz2 raises nothing at the end of its input; reaching it is the truncation.
        self._pending_error = TruncatedError("File is truncated")
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return False

    @property
    def needs_input(self) -> bool:
        return self._decomp.needs_input
