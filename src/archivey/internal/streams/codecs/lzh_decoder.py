"""LHA's static-Huffman LZ77 methods (``-lh4-`` to ``-lh7-``, ``-lhx-``, ``-lk7-``),
and ARJ's methods 1 to 3, which are the same format, decoded in Python.

LHA 2 replaced LHarc's ``-lh1-`` with these methods, and later tools added larger
windows. They share one bit stream layout: blocks of up to 65 535 commands, each block
opening with three Huffman code tables. A command is a literal byte, or a match of 3 to
256 bytes at a distance whose bit count is Huffman-coded and whose low bits follow. The
bit stream is read most significant bit first. A member is one stream, decoded on its
own: LHA is not solid.

The decoder follows lhasa's ``lh_new_decoder.c`` (the tool Debian ships as ``lha``),
and so agrees with it on every LHA stream lhasa reads:

- the window starts filled with spaces, so a match that reaches back before the first
  byte of output copies spaces;
- ``-lh4-`` decodes with ``-lh5-``'s tables and window: LHA wrote it with a smaller
  dictionary, which only lowers the largest distance;
- ``-lk7-`` is LHARK's own ``-lh7-`` (lhasa's name for it), with longer matches and
  another distance coding, after Jason Summers' notes on LHARK;
- a table with a zero count is a single symbol coded with no bits;
- a count over the table's size is cut to its size, as lhasa does;
- decoding stops at the member's size, and input left after it is ignored;
- ARJ methods 1 to 3 (the ``"arj"`` entry) are ``-lh6-``'s layout with ARJ's 26 624-byte
  dictionary. A match before the first byte of output copies the window's spaces there
  too: ARJ's own decoder reads an uninitialised buffer instead, ARJ writers never make
  such a match, and the member's CRC-32 refuses the result. That is archivey's choice;
  ``arj_fast_decoder`` (method 4) refuses the same match as ``CorruptionError``.

Where lhasa decodes damage into bytes the CRC then refuses, this decoder raises
``CorruptionError`` at once: a code length over 16 bits, a table that overfills or
underfills its code space, or a match distance past the window.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import NamedTuple

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.huffman_table import MAX_CODE, Tree, build_table


class LzhMethod(NamedTuple):
    window_bits: int
    """The window is ``2**window_bits`` bytes."""
    offset_bits: int
    """Width of the offset table's count field: the table has up to
    ``2**offset_bits - 1`` codes."""
    codes: int
    """Symbols in the command table: 256 literals, then match lengths."""
    lhark: bool = False


METHODS: dict[str, LzhMethod] = {
    "-lh4-": LzhMethod(14, 4, 510),
    "-lh5-": LzhMethod(14, 4, 510),
    "-lh6-": LzhMethod(16, 5, 510),
    "-lh7-": LzhMethod(17, 5, 510),
    # UNLHA32's extension: a 512 KiB dictionary, which lhasa decodes in a 1 MiB ring.
    "-lhx-": LzhMethod(20, 5, 510),
    "-lk7-": LzhMethod(16, 6, 289, lhark=True),
    # ARJ methods 1 to 3: the same stream, from the same ar002 code, with a 26 624-byte
    # dictionary (unarj's DDICSIZ) and offset codes up to 16 (NP 17, PBIT 5).
    "arj": LzhMethod(15, 5, 510),
}

_TEMP_COUNT_BITS = 5
_TEMP_MAX = (1 << _TEMP_COUNT_BITS) - 1
_COMMAND_COUNT_BITS = 9
_THRESHOLD = 3
# Output is handed over in pieces of about this size; the window stays behind them.
_CHUNK = 1 << 16
# Zero bytes the decoder may append past the input; a command reads at most 68 bits.
_MAX_PADDING = 32
# Bits made available before each command, enough for the longest one.
_COMMAND_BITS = 72
# An unused table entry: decoding it is damage.
_NO_SYMBOL = 0xFFFF

_EMPTY: Tree = ([_NO_SYMBOL << 5], 0)


def _single(symbol: int) -> Tree:
    """A table of one symbol coded with no bits."""
    return [symbol << 5], 0


class LhaBitDecoder:
    """The input and output every LHA method's decoder shares.

    ``size`` bytes are decoded from the runs of input ``more`` returns (``None`` at
    their end); :meth:`read` returns them in order, and ``b""`` once all have been
    returned. The output buffer starts with ``history``, the window as it stands
    before the first byte, and keeps that many bytes behind the output it hands over.
    Input bits are read most significant first. Subclasses decode in
    :meth:`_decode`.
    """

    def __init__(
        self,
        method: str,
        size: int,
        more: Callable[[], bytes | None],
        history: bytes = b"",
    ) -> None:
        self._method = method
        self._more = more
        self._left = size  # output bytes not yet decoded
        # History, then output not yet handed over from ``_start``.
        self._history = len(history)
        self._out = bytearray(history)
        self._start = len(history)
        # Input: unread bytes from ``_pos``, and a bit buffer of ``_nbits`` bits.
        self._buf = b""
        self._pos = 0
        self._bits = 0
        self._nbits = 0
        self._padding = 0  # zero bytes appended past the end of the input

    def _truncated(self) -> TruncatedError:
        return TruncatedError(
            f"the {self._method} stream ends before the member's data"
        )

    def _refill(self, need: int = 24) -> None:
        """Make at least ``need`` bits available. Past the end of the input come zero
        bytes; :meth:`_check_overread` refuses output that needed them."""
        buf, pos = self._buf, self._pos
        bits, nbits = self._bits, self._nbits
        while nbits < need:
            if pos >= len(buf):
                data = None if self._padding else self._more()
                if data is None:
                    # A real stream reads at most a few bytes ahead of its last code.
                    if self._padding >= _MAX_PADDING:
                        raise self._truncated()
                    self._padding += 16
                    data = bytes(16)
                elif not data:
                    continue
                buf, pos = data, 0
            take = min(len(buf) - pos, 16)
            bits = (bits << (8 * take)) | int.from_bytes(buf[pos : pos + take], "big")
            nbits += 8 * take
            pos += take
        self._buf, self._pos = buf, pos
        self._bits, self._nbits = bits & ((1 << nbits) - 1), nbits

    def _check_overread(self) -> None:
        """Refuse output that needed the zero bytes past the input."""
        if self._padding * 8 > (len(self._buf) - self._pos) * 8 + self._nbits:
            raise self._truncated()

    def _finish(self) -> None:
        """Cut what the last command wrote past the member's end, then refuse output
        that needed the zero bytes past the input."""
        if self._left < 0:
            del self._out[len(self._out) + self._left :]
            self._left = 0
        self._check_overread()

    def _decode(self, want: int) -> None:
        """Decode at least ``want`` more bytes, or to the member's end."""
        raise NotImplementedError

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = self._out
        if len(out) - self._start < n and self._left > 0:
            self._decode(max(n, _CHUNK))
        data = bytes(out[self._start : self._start + n])
        self._start += len(data)
        # Drop handed-over output beyond the history.
        if self._start > self._history + 4 * _CHUNK:
            cut = self._start - self._history
            del out[:cut]
            self._start -= cut
        return data


class LzhDecoder(LhaBitDecoder):
    """Decodes one ``-lh4-`` to ``-lh7-``, ``-lhx-`` or ``-lk7-`` stream."""

    def __init__(
        self, method: str, size: int, more: Callable[[], bytes | None]
    ) -> None:
        params = METHODS[method]
        self._params = params
        self._ring = 1 << params.window_bits
        super().__init__(method, size, more, b" " * self._ring)
        self._block_left = 0
        self._commands: Tree = _EMPTY
        self._offsets: Tree = _EMPTY

    def _read(self, n: int) -> int:
        if n == 0:
            return 0
        if self._nbits < n:
            self._refill()
            if self._nbits < n:  # only for n over 24
                high = self._read(n - 16)
                return high << 16 | self._read(16)
        self._nbits -= n
        return (self._bits >> self._nbits) & ((1 << n) - 1)

    def _symbol(self, tree: Tree, limit: int, what: str) -> int:
        table, root = tree
        if root == 0:
            symbol = table[0] >> 5
        else:
            if self._nbits < MAX_CODE:
                self._refill()
            bits, nbits = self._bits, self._nbits
            entry = table[(bits >> (nbits - root)) & ((1 << root) - 1)]
            if entry < 0:
                nbits -= root
                entry = ~entry
                sub = entry & 31
                entry = table[
                    (entry >> 5) + ((bits >> (nbits - sub)) & ((1 << sub) - 1))
                ]
            self._nbits = nbits - (entry & 31)
            symbol = entry >> 5
        if symbol >= limit:
            raise CorruptionError(f"{self._method} {what} table has no such code")
        return symbol

    # ── Block headers ────────────────────────────────────────────────────────────────

    def _length(self) -> int:
        """A code length: three bits, and past 7 one more for each 1 bit."""
        n = self._read(3)
        if n == 7:
            while self._read(1):
                n += 1
                if n > MAX_CODE:
                    raise CorruptionError(
                        f"{self._method} code length is over {MAX_CODE} bits"
                    )
        return n

    def _table(self, lengths: list[int], count: int, what: str) -> Tree:
        table = build_table(lengths, count, f"{self._method} {what}")
        return _EMPTY if table is None else table

    def _start_block(self) -> None:
        read = self._read
        self._block_left = read(16)
        # The table that codes the command table's code lengths.
        n = read(_TEMP_COUNT_BITS)
        if n == 0:
            temp = _single(read(_TEMP_COUNT_BITS))
        else:
            n = min(n, _TEMP_MAX)
            lengths = [0] * (_TEMP_MAX + 3)
            i = 0
            while i < n:
                lengths[i] = self._length()
                if i == 2:  # a 2-bit count of zero lengths follows the third
                    i += read(2)
                i += 1
            temp = self._table(lengths, min(n, _TEMP_MAX), "code length")
        codes = self._params.codes
        n = read(_COMMAND_COUNT_BITS)
        if n == 0:
            self._commands = _single(read(_COMMAND_COUNT_BITS))
        else:
            n = min(n, codes)
            lengths = [0] * codes
            i = 0
            while i < n:
                code = self._symbol(temp, _TEMP_MAX, "code length")
                if code - 2 > MAX_CODE:
                    raise CorruptionError(
                        f"{self._method} code length is over {MAX_CODE} bits"
                    )
                if code == 0:
                    i += 1
                elif code == 1:
                    i += read(4) + 3
                elif code == 2:
                    i += read(9) + 20
                else:
                    lengths[i] = code - 2
                    i += 1
            self._commands = self._table(lengths, n, "command")
        offset_bits = self._params.offset_bits
        n = read(offset_bits)
        if n == 0:
            self._offsets = _single(read(offset_bits))
        else:
            n = min(n, (1 << offset_bits) - 1)
            lengths = [self._length() for _ in range(n)]
            self._offsets = self._table(lengths, n, "offset")

    # ── Commands ─────────────────────────────────────────────────────────────────────

    @override
    def _decode(self, want: int) -> None:
        """Decode until ``want`` bytes wait from ``_start``, or the member ends."""
        out = self._out
        ring = self._ring
        codes = self._params.codes
        lhark = self._params.lhark
        limit = 1 << self._params.offset_bits
        target = self._start + want
        while len(out) < target and self._left > 0:
            if self._block_left == 0:
                self._start_block()
                self._check_overread()
                continue
            # The hot loop: the bit buffer and both tables in locals, each command
            # read with no call unless the buffer runs low.
            c_table, c_root = self._commands
            p_table, p_root = self._offsets
            c_mask = (1 << c_root) - 1
            p_mask = (1 << p_root) - 1
            budget = min(self._left, target - len(out))
            before = len(out)
            stop = before + budget
            left = self._block_left
            bits, nbits = self._bits, self._nbits
            while left and len(out) < stop:
                if nbits < _COMMAND_BITS:
                    self._bits, self._nbits = bits, nbits
                    self._refill(_COMMAND_BITS)
                    bits, nbits = self._bits, self._nbits
                left -= 1
                if c_root:
                    entry = c_table[(bits >> (nbits - c_root)) & c_mask]
                    if entry < 0:
                        nbits -= c_root
                        entry = ~entry
                        sub = entry & 31
                        entry = c_table[
                            (entry >> 5) + ((bits >> (nbits - sub)) & ((1 << sub) - 1))
                        ]
                    nbits -= entry & 31
                    code = entry >> 5
                else:
                    code = c_table[0] >> 5
                if code < 256:
                    out.append(code)
                    continue
                if code >= codes:
                    raise CorruptionError(
                        f"{self._method} command table has no such code"
                    )
                if not lhark or code < 264:
                    count = code - 256 + _THRESHOLD
                elif code < 288:
                    low = (code - 260) >> 2
                    nbits -= low
                    count = (
                        ((4 + (code & 3)) << low)
                        + ((bits >> nbits) & ((1 << low) - 1))
                        + _THRESHOLD
                    )
                else:
                    count = 514
                if p_root:
                    entry = p_table[(bits >> (nbits - p_root)) & p_mask]
                    if entry < 0:
                        nbits -= p_root
                        entry = ~entry
                        sub = entry & 31
                        entry = p_table[
                            (entry >> 5) + ((bits >> (nbits - sub)) & ((1 << sub) - 1))
                        ]
                    nbits -= entry & 31
                    symbol = entry >> 5
                else:
                    symbol = p_table[0] >> 5
                if symbol >= limit:
                    raise CorruptionError(
                        f"{self._method} offset table has no such code"
                    )
                if symbol <= 1 or (lhark and symbol < 4):
                    distance = symbol + 1
                else:
                    if lhark:
                        low = (symbol - 2) >> 1
                        high = (2 + (symbol & 1)) << low
                    else:
                        low = symbol - 1
                        high = 1 << low
                    nbits -= low
                    distance = high + ((bits >> nbits) & ((1 << low) - 1)) + 1
                if distance > ring:
                    raise CorruptionError(
                        f"{self._method} match reaches {distance} bytes back; the "
                        f"window holds {ring}"
                    )
                start = len(out) - distance
                if count <= distance:
                    out += out[start : start + count]
                else:
                    # The match overlaps its own output: copy what exists, which
                    # doubles each time.
                    while count > 0:
                        step = min(len(out) - start, count)
                        out += out[start : start + step]
                        count -= step
            self._bits, self._nbits = bits, nbits
            self._block_left = left
            self._left -= len(out) - before
        self._finish()
