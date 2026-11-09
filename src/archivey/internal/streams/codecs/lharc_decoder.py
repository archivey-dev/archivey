"""LHA's oldest methods, decoded in Python: LHarc's ``-lh1-`` and LArc's ``-lzs-`` and
``-lz5-``.

- ``-lh1-`` is Okumura's LZHUF, as LHarc 1.x wrote it: a 4 KiB window, and one adaptive
  Huffman tree of 314 symbols (256 literals, then match lengths 3 to 60) that is
  updated after each symbol and rebuilt with halved counts when its root reaches
  32 768. A match's distance is a 6-bit low part after a high part of 3 to 8 bits from
  a fixed code.
- ``-lzs-`` (LArc): a 2 KiB ring. A 1 bit and 8 bits are a literal; a 0 bit, an 11-bit
  ring position and a 4-bit length (2 to 17) copy from the ring.
- ``-lz5-`` (LArc, and LHarc's ``-lz5-``): a 4 KiB ring that starts with a fixed
  pattern. A flag byte gives eight commands, least significant bit first: a 1 is a
  literal byte, a 0 two bytes holding a 12-bit ring position and a 4-bit length (3 to
  18).

Bits are read most significant first. The decoders follow lhasa's ``lh1_decoder.c``,
``lzs_decoder.c`` and ``lz5_decoder.c``, and so agree with it on every stream: the
windows start filled with spaces (``-lz5-`` with its pattern), and a ring position may
name bytes the stream has not written yet. Decoding stops at the member's size. A stream
that ends first raises ``TruncatedError``; no code here can name a byte outside the
window, so there is no other damage to catch before the CRC.
"""

from __future__ import annotations

from collections.abc import Callable

from archivey.exceptions import TruncatedError
from archivey.internal.overrides import override

# Output is handed over in pieces of about this size.
_CHUNK = 1 << 16
# Zero bytes a bit stream may read past its input; a command reads at most 23 bits.
_MAX_PADDING = 8


class _Decoder:
    """``size`` bytes decoded from the runs of input ``more`` returns."""

    def __init__(
        self, method: str, size: int, more: Callable[[], bytes | None]
    ) -> None:
        self._method = method
        self._more = more
        self._left = size
        self._out = bytearray()
        self._start = 0
        self._buf = b""
        self._pos = 0
        self._bits = 0
        self._nbits = 0
        self._padding = 0

    def _truncated(self) -> TruncatedError:
        return TruncatedError(
            f"the {self._method} stream ends before the member's data"
        )

    def _refill(self, need: int) -> None:
        """Make at least ``need`` bits available, zeros past the input."""
        buf, pos = self._buf, self._pos
        bits, nbits = self._bits, self._nbits
        while nbits < need:
            if pos >= len(buf):
                data = None if self._padding else self._more()
                if data is None:
                    if self._padding >= _MAX_PADDING:
                        raise self._truncated()
                    self._padding += 4
                    data = bytes(4)
                elif not data:
                    continue
                buf, pos = data, 0
            take = min(len(buf) - pos, 8)
            bits = (bits << (8 * take)) | int.from_bytes(buf[pos : pos + take], "big")
            nbits += 8 * take
            pos += take
        self._buf, self._pos = buf, pos
        self._bits, self._nbits = bits & ((1 << nbits) - 1), nbits

    def _check_overread(self) -> None:
        """Refuse output that needed the zero bytes past the input."""
        if self._padding * 8 > (len(self._buf) - self._pos) * 8 + self._nbits:
            raise self._truncated()

    def _decode(self, want: int) -> None:
        raise NotImplementedError

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = self._out
        if len(out) - self._start < n and self._left > 0:
            self._decode(max(n, _CHUNK))
        data = bytes(out[self._start : self._start + n])
        self._start += len(data)
        self._trim()
        return data

    def _trim(self) -> None:
        # Output handed over is dropped; the ring decoders keep no history in it.
        if self._start > 4 * _CHUNK:
            del self._out[: self._start]
            self._start = 0

    def _finish(self) -> None:
        if self._left < 0:  # the last command ran past the member's end
            del self._out[len(self._out) + self._left :]
            self._left = 0


# ── -lh1- ───────────────────────────────────────────────────────────────────────────

_LH1_CODES = 314
_LH1_NODES = 2 * _LH1_CODES - 1  # 627
_LH1_ROOT = _LH1_NODES - 1
_LH1_REORDER = 0x8000
_LH1_WINDOW = 4096

# The high part of a distance: the next 8 bits name it and its length (3 to 8 bits),
# as in LZHUF's d_code and d_len tables.
_LH1_HIGH = bytearray(256)
_LH1_HIGH_BITS = bytearray(64)


def _lh1_tables() -> None:
    code = high = 0
    for bits, count in enumerate((1, 3, 8, 12, 24, 16), 3):
        span = 1 << (8 - bits)
        for _ in range(count):
            _LH1_HIGH[code : code + span] = bytes([high]) * span
            _LH1_HIGH_BITS[high] = bits
            code += span
            high += 1


_lh1_tables()


class Lh1Decoder(_Decoder):
    """``-lh1-``: LZHUF's adaptive Huffman tree and a 4 KiB window."""

    def __init__(self, size: int, more: Callable[[], bytes | None]) -> None:
        super().__init__("-lh1-", size, more)
        self._out = bytearray(b" " * _LH1_WINDOW)
        self._start = _LH1_WINDOW
        n, t = _LH1_CODES, _LH1_NODES
        freq = [0] * (t + 1)
        son = [0] * t
        parent = [0] * (t + n)
        for i in range(n):
            freq[i] = 1
            son[i] = i + t
            parent[i + t] = i
        i = 0
        for j in range(n, t):
            freq[j] = freq[i] + freq[i + 1]
            son[j] = i
            parent[i] = parent[i + 1] = j
            i += 2
        freq[t] = 0xFFFF  # a sentinel past the last node
        self._freq, self._son, self._parent = freq, son, parent

    def _rebuild(self) -> None:
        """Halve the counts and rebuild the tree, as LZHUF's ``reconst``."""
        t, n = _LH1_NODES, _LH1_CODES
        freq, son, parent = self._freq, self._son, self._parent
        j = 0
        for i in range(t):
            if son[i] >= t:
                freq[j] = (freq[i] + 1) // 2
                son[j] = son[i]
                j += 1
        i = 0
        for j in range(n, t):
            f = freq[i] + freq[i + 1]
            k = j - 1
            while f < freq[k]:
                k -= 1
            k += 1
            freq[k + 1 : j + 1] = freq[k:j]
            freq[k] = f
            son[k + 1 : j + 1] = son[k:j]
            son[k] = i
            i += 2
        for i in range(t):
            k = son[i]
            if k >= t:
                parent[k] = i
            else:
                parent[k] = parent[k + 1] = i

    def _update(self, symbol: int) -> None:
        if self._freq[_LH1_ROOT] == _LH1_REORDER:
            self._rebuild()
        freq, son, parent = self._freq, self._son, self._parent
        t = _LH1_NODES
        c = parent[symbol + t]
        while True:
            freq[c] += 1
            k = freq[c]
            swap = c + 1
            if k > freq[swap]:
                # Move the node past every node of a lower count.
                while k > freq[swap + 1]:
                    swap += 1
                freq[c] = freq[swap]
                freq[swap] = k
                i = son[c]
                parent[i] = swap
                if i < t:
                    parent[i + 1] = swap
                j = son[swap]
                son[swap] = i
                parent[j] = c
                if j < t:
                    parent[j + 1] = c
                son[c] = j
                c = swap
            c = parent[c]
            if c == 0:
                break

    @override
    def _decode(self, want: int) -> None:
        out = self._out
        t = _LH1_NODES
        target = self._start + want
        while len(out) < target and self._left > 0:
            before = len(out)
            stop = before + min(self._left, target - before)
            while len(out) < stop:
                # A symbol is at most 313 bits deep in a skewed tree, so the walk
                # refills as it goes.
                son = self._son
                c = son[_LH1_ROOT]
                while c < t:
                    if not self._nbits:
                        self._refill(32)
                    self._nbits -= 1
                    c = son[c + ((self._bits >> self._nbits) & 1)]
                c -= t
                self._update(c)
                if c < 256:
                    out.append(c)
                    continue
                if self._nbits < 14:
                    self._refill(32)
                bits, nbits = self._bits, self._nbits
                high = _LH1_HIGH[(bits >> (nbits - 8)) & 0xFF]
                nbits -= _LH1_HIGH_BITS[high]
                low = (bits >> (nbits - 6)) & 0x3F
                self._nbits = nbits - 6
                distance = (high << 6 | low) + 1
                count = c - 253
                start = len(out) - distance
                if count <= distance:
                    out += out[start : start + count]
                else:
                    while count > 0:
                        step = min(len(out) - start, count)
                        out += out[start : start + step]
                        count -= step
            self._left -= len(out) - before
        self._finish()
        self._check_overread()

    @override
    def _trim(self) -> None:
        if self._start > _LH1_WINDOW + 4 * _CHUNK:
            cut = self._start - _LH1_WINDOW
            del self._out[:cut]
            self._start -= cut


# ── -lzs- and -lz5- ─────────────────────────────────────────────────────────────────


class LzsDecoder(_Decoder):
    """``-lzs-``: LArc's 2 KiB ring, addressed by position."""

    _RING = 2048

    def __init__(self, size: int, more: Callable[[], bytes | None]) -> None:
        super().__init__("-lzs-", size, more)
        self._ring = bytearray(b" " * self._RING)
        self._at = self._RING - 17

    @override
    def _decode(self, want: int) -> None:
        out = self._out
        ring = self._ring
        mask = self._RING - 1
        at = self._at
        target = self._start + want
        before = len(out)
        stop = before + min(self._left, target - before)
        while len(out) < stop:
            if self._nbits < 16:
                self._refill(32)
            self._nbits -= 1
            if (self._bits >> self._nbits) & 1:
                self._nbits -= 8
                byte = (self._bits >> self._nbits) & 0xFF
                out.append(byte)
                ring[at] = byte
                at = (at + 1) & mask
                continue
            self._nbits -= 15
            command = (self._bits >> self._nbits) & 0x7FFF
            pos = command >> 4
            for k in range((command & 15) + 2):
                byte = ring[(pos + k) & mask]
                out.append(byte)
                ring[at] = byte
                at = (at + 1) & mask
        self._at = at
        self._left -= len(out) - before
        self._finish()
        self._check_overread()


def _lz5_ring() -> bytearray:
    """``-lz5-``'s starting ring, as LArc fills it."""
    ring = bytearray()
    for i in range(256):
        ring += bytes([i]) * 13
    ring += bytes(range(256))
    ring += bytes(range(255, -1, -1))
    ring += bytes(128) + b" " * 110 + bytes(18)
    return ring


class Lz5Decoder(_Decoder):
    """``-lz5-``: LArc's 4 KiB ring, flag bytes, two-byte copy commands."""

    _RING = 4096

    def __init__(self, size: int, more: Callable[[], bytes | None]) -> None:
        super().__init__("-lz5-", size, more)
        self._ring = _lz5_ring()
        self._at = self._RING - 18
        self._flags = 0
        self._flag_bits = 0

    def _byte(self) -> int:
        if self._nbits < 8:
            self._refill(8)
        self._nbits -= 8
        return (self._bits >> self._nbits) & 0xFF

    @override
    def _decode(self, want: int) -> None:
        out = self._out
        ring = self._ring
        mask = self._RING - 1
        at = self._at
        target = self._start + want
        before = len(out)
        stop = before + min(self._left, target - before)
        while len(out) < stop:
            if not self._flag_bits:
                self._flags = self._byte()
                self._flag_bits = 8
            flag = self._flags & 1
            self._flags >>= 1
            self._flag_bits -= 1
            if flag:
                byte = self._byte()
                out.append(byte)
                ring[at] = byte
                at = (at + 1) & mask
                continue
            low = self._byte()
            high = self._byte()
            pos = (high & 0xF0) << 4 | low
            for k in range((high & 15) + 3):
                byte = ring[(pos + k) & mask]
                out.append(byte)
                ring[at] = byte
                at = (at + 1) & mask
        self._at = at
        self._left -= len(out) - before
        self._finish()
        self._check_overread()


DECODERS: dict[str, Callable[[int, Callable[[], bytes | None]], _Decoder]] = {
    "-lh1-": Lh1Decoder,
    "-lzs-": LzsDecoder,
    "-lz5-": Lz5Decoder,
}
"""Each method's decoder, built from the member's size and its input."""
