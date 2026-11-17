"""ARJ method 4, "fastest", decoded in Python.

ARJ's other methods (1 to 3) are LHA's static-Huffman stream
(:mod:`~archivey.internal.streams.codecs.lzh_decoder`); method 4 is a plain LZ77 with
no tables. Each command opens with a length code: unary bits counting a width from
0 to 7, then that many bits. A length of 0 is a literal, its 8 bits next; a length
``n`` is a match of ``n + 2`` bytes, whose distance less one is coded the same way
with widths 9 to 13. Bits are read most significant first.

The decoder follows ``decode_f`` in Robert Jung's UNARJ (public), which ARJ's own
source keeps: the dictionary is 26 624 bytes, and decoding stops at the member's size,
the last match cut there and input left after it ignored. A match from before the
first byte of output reads ARJ's uninitialised buffer, so it is refused as
``CorruptionError``; no ARJ writer makes one.
"""

from __future__ import annotations

from collections.abc import Callable

from archivey.exceptions import CorruptionError, TruncatedError

_DICTIONARY = 26624
_THRESHOLD = 3
# unarj's STRTL/STOPL and STRTP/STOPP: the widths a length and a distance code take.
_LENGTH_WIDTHS = (0, 7)
_DISTANCE_WIDTHS = (9, 13)
# Bits made available before each command: the longest is 7 + 7 + 4 + 13 = 31.
_COMMAND_BITS = 32
_CHUNK = 1 << 16
# Zero bytes the decoder may read past the input; a command reads at most 4 bytes.
_MAX_PADDING = 8


class ArjFastDecoder:
    """Decodes one method-4 member, ``size`` bytes of output.

    ``more`` returns the next run of the member's stored bytes, or ``None`` at their
    end. :meth:`read` returns the output in order, and ``b""`` once ``size`` bytes
    have been returned.
    """

    def __init__(self, size: int, more: Callable[[], bytes | None]) -> None:
        self._more = more
        self._left = size
        # History, then output not yet handed over from ``_start``.
        self._out = bytearray()
        self._start = 0
        # Input: unread bytes from ``_pos``, and a bit buffer of ``_nbits`` bits.
        self._buf = b""
        self._pos = 0
        self._bits = 0
        self._nbits = 0
        self._padding = 0

    def _refill(self) -> None:
        buf, pos = self._buf, self._pos
        while self._nbits < _COMMAND_BITS:
            if pos >= len(buf):
                data = None if self._padding else self._more()
                if data is None:
                    if self._padding >= _MAX_PADDING:
                        raise TruncatedError(
                            "the ARJ method 4 stream ends before the member's data"
                        )
                    self._padding += 4
                    data = bytes(4)
                buf, pos = data, 0
                continue
            take = min(len(buf) - pos, 8)
            chunk = int.from_bytes(buf[pos : pos + take], "big")
            self._bits = (self._bits << (8 * take)) | chunk
            self._nbits += 8 * take
            pos += take
        self._buf, self._pos = buf, pos

    def _check_overread(self) -> None:
        if self._padding * 8 > (len(self._buf) - self._pos) * 8 + self._nbits:
            raise TruncatedError(
                "the ARJ method 4 stream ends before the member's data"
            )

    def _code(self, widths: tuple[int, int]) -> int:
        """A length or distance code: unary width bits, then the value's bits."""
        first, last = widths
        bits, nbits = self._bits, self._nbits
        plus = 0
        width = first
        while width < last:
            nbits -= 1
            if not (bits >> nbits) & 1:
                break
            plus += 1 << width
            width += 1
        nbits -= width
        value = ((bits >> nbits) & ((1 << width) - 1)) + plus
        self._nbits = nbits
        return value

    def _decode(self, want: int) -> None:
        out = self._out
        target = self._start + want
        while len(out) < target and self._left > 0:
            if self._nbits < _COMMAND_BITS:
                self._refill()
            before = len(out)
            length = self._code(_LENGTH_WIDTHS)
            if length == 0:
                self._nbits -= 8
                out.append((self._bits >> self._nbits) & 0xFF)
            else:
                count = length - 1 + _THRESHOLD
                distance = self._code(_DISTANCE_WIDTHS) + 1
                start = len(out) - distance
                if start < 0:
                    raise CorruptionError(
                        f"ARJ method 4 match reaches {distance} bytes back, before the "
                        f"start of the output ({len(out)} bytes)"
                    )
                if count <= distance:
                    out += out[start : start + count]
                else:
                    while count > 0:
                        step = min(len(out) - start, count)
                        out += out[start : start + step]
                        count -= step
            self._bits &= (1 << self._nbits) - 1
            self._left -= len(out) - before
        if self._left < 0:  # the last match ran past the member's end
            del out[len(out) + self._left :]
            self._left = 0
        self._check_overread()

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = self._out
        if len(out) - self._start < n:
            self._decode(max(n, _CHUNK))
        data = bytes(out[self._start : self._start + n])
        self._start += len(data)
        if self._start > _DICTIONARY + 4 * _CHUNK:
            cut = self._start - _DICTIONARY
            del out[:cut]
            self._start -= cut
        return data
