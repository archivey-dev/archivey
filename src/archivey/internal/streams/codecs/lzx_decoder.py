"""LZX, as Microsoft cabinets store it, decoded in Python.

LZX is LZ77 over a window of 32 KiB to 2 MiB, with Huffman-coded literals, match
lengths and match positions, and three most-recent match distances. Output comes in
32 KiB frames; the input is one bit stream, read as 16-bit little-endian words, most
significant bit first, that realigns to a word at the end of each frame. The stream
starts with the E8 header: whether, and for what file size, the x86 ``CALL``
translation was applied, which the decoder undoes frame by frame.

The decoder follows libmspack's ``lzxd.c`` (the decoder ``cabextract`` uses), with the
CAB parameters: no reset interval and no LZX DELTA. Where the format leaves a
behaviour to the decoder, it does what ``lzxd.c`` does, so the two agree on every
stream:

- a run of code lengths may write past the end of the range being read (by up to 50
  entries), into lengths the next range or the tree build sees;
- a tree with no codes is accepted, and decoding a symbol with it is damage; any
  other tree whose codes do not fill the code space is damage;
- a match may not cross the end of the window or the end of a frame, nor reach back
  before the first byte of output;
- the E8 translation runs for the first 32 768 frames only, from the first block that
  can produce an ``E8`` byte, and leaves the last 10 bytes of each frame alone.

Every Huffman code is at most 16 bits, so each tree decodes through one table of
65 536 entries indexed by the next 16 bits.
"""

from __future__ import annotations

from collections.abc import Callable

from archivey.exceptions import CorruptionError, TruncatedError

FRAME_SIZE = 32768
MIN_WINDOW_BITS = 15
MAX_WINDOW_BITS = 21

_NUM_CHARS = 256
_PRETREE_SYMBOLS = 20
_ALIGNED_SYMBOLS = 8
_LENGTH_SYMBOLS = 249
_PRIMARY_LENGTHS = 7
_MIN_MATCH = 2
# As lzxd.c sizes its arrays: the main tree is built over every symbol the largest
# window has, and the length tree over one more than it reads, so lengths a run wrote
# past the end of a range take part in the tree, as there.
_MAIN_MAX = _NUM_CHARS + 290 * 8
_LENGTH_MAX = _LENGTH_SYMBOLS + 1
_RUN_SLACK = 64

_VERBATIM = 1
_ALIGNED = 2
_UNCOMPRESSED = 3

# Position slots per window size, 2**15 to 2**21.
_POSITION_SLOTS = (30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290)


def _extra_bits(slot: int) -> int:
    return 0 if slot < 4 else min(slot // 2 - 1, 17)


_EXTRA_BITS = tuple(_extra_bits(slot) for slot in range(290))
_POSITION_BASE = [0]
for _slot in range(289):
    _POSITION_BASE.append(_POSITION_BASE[-1] + (1 << _EXTRA_BITS[_slot]))
del _slot

# lzxd.c reads two zero bytes past the end of the input before it refuses the stream;
# the look-ahead here reads further, so it may add more, but uses no more than two.
_PADDING_ALLOWED = 2
_MAX_PADDING = 8

_TABLE_BITS = 16
_EMPTY = -1


def _build_table(lengths: list[int], count: int, what: str) -> list[int] | None:
    """A 16-bit lookup table for the canonical code of ``lengths[:count]``.

    Each entry is ``symbol << 5 | length``. ``None`` for a tree with no codes; a code
    that overfills or underfills the code space is damage.
    """
    table: list[int] = []
    pos = 0
    full = 1 << _TABLE_BITS
    by_length: list[list[int]] = [[] for _ in range(17)]
    for symbol in range(count):
        length = lengths[symbol]
        if length:
            by_length[length].append(symbol)
    for length in range(1, 17):
        span = 1 << (_TABLE_BITS - length)
        for symbol in by_length[length]:
            pos += span
            if pos > full:
                raise CorruptionError(f"LZX {what} tree overfills its code space")
            table += [symbol << 5 | length] * span
    if pos == full:
        return table
    if pos == 0:
        return None
    raise CorruptionError(f"LZX {what} tree does not fill its code space")


class LzxDecoder:
    """Decodes one LZX stream, a frame at a time.

    ``more`` returns the next run of input bytes (a cabinet's next data block), or
    ``None`` at the end of the input. The caller says how long each frame is: 32 KiB,
    except the last.
    """

    def __init__(self, window_bits: int, more: Callable[[], bytes | None]) -> None:
        if not MIN_WINDOW_BITS <= window_bits <= MAX_WINDOW_BITS:
            raise CorruptionError(f"LZX window of 2**{window_bits} bytes")
        self._window_size = 1 << window_bits
        self._window = bytearray(self._window_size)
        self._main_symbols = _NUM_CHARS + (_POSITION_SLOTS[window_bits - 15] << 3)
        self._more = more
        # Input: unread bytes from ``_pos``, and a bit buffer of ``_nbits`` bits.
        self._buf = b""
        self._pos = 0
        self._bits = 0
        self._nbits = 0
        self._padding = 0  # zero bytes appended past the end of the input
        # Decoder state that lives across blocks and frames.
        self._main_lengths = [0] * (_MAIN_MAX + _RUN_SLACK)
        self._length_lengths = [0] * (_LENGTH_MAX + _RUN_SLACK)
        self._main_table: list[int] | None = None
        self._length_table: list[int] | None = None
        self._aligned_table: list[int] | None = None
        self._r0 = self._r1 = self._r2 = 1
        self._header_read = False
        self._intel_size = 0
        self._intel_started = False
        self._block_type = 0
        self._block_length = 0
        self._block_remaining = 0
        self._window_pos = 0
        self._offset = 0  # bytes of output so far
        self._frame = 0

    # ── Input ────────────────────────────────────────────────────────────────────────

    def _refill(self, need: int) -> None:
        """Make at least ``need`` (at most 32) bits available."""
        buf, pos = self._buf, self._pos
        bits, nbits = self._bits, self._nbits
        while nbits < need:
            if pos + 2 > len(buf):
                buf, pos = self._input_more(buf, pos)
            bits = ((bits & ((1 << nbits) - 1)) << 16) | (buf[pos + 1] << 8 | buf[pos])
            pos += 2
            nbits += 16
        self._buf, self._pos = buf, pos
        self._bits, self._nbits = bits, nbits

    def _input_more(self, buf: bytes, pos: int) -> tuple[bytes, int]:
        """The unread input with at least two bytes more, pulling the next run.

        Past the end of the input come zero bytes, so the decoder can look ahead as
        it does inside the stream; :meth:`_check_overread` refuses a stream that
        uses more of them than lzxd.c's two.
        """
        # Keep the last few bytes read: words read ahead into the bit buffer go back
        # to the byte input before an uncompressed block (``_align_for_raw``).
        keep = min(pos, 8)
        rest, pos = buf[pos - keep :], keep
        while len(rest) - pos < 2:
            data = None if self._padding else self._more()
            if data is None:
                if self._padding >= _MAX_PADDING:
                    raise TruncatedError("LZX stream ends before its output")
                self._padding += 2
                data = b"\0\0"
            rest += data
        return rest, pos

    def _check_overread(self) -> None:
        """Refuse a stream that used more than two bytes past the end of the input."""
        if not self._padding:
            return
        unread = (len(self._buf) - self._pos) * 8 + self._nbits
        if self._padding * 8 - unread > _PADDING_ALLOWED * 8:
            raise TruncatedError("LZX stream ends before its output")

    def _read_bits(self, n: int) -> int:
        if self._nbits < n:
            self._refill(n)
        self._nbits -= n
        return (self._bits >> self._nbits) & ((1 << n) - 1)

    def _read_symbol(self, table: list[int] | None, what: str) -> int:
        if table is None:
            raise CorruptionError(f"LZX {what} symbol read from an empty tree")
        if self._nbits < 16:
            self._refill(16)
        entry = table[(self._bits >> (self._nbits - 16)) & 0xFFFF]
        self._nbits -= entry & 31
        return entry >> 5

    def _raw_bytes(self, n: int) -> bytes:
        """``n`` bytes straight from the input, once the bit buffer is empty."""
        assert self._nbits == 0
        buf, pos = self._buf, self._pos
        while len(buf) - pos < n:
            data = None if self._padding else self._more()
            if data is None:
                raise TruncatedError("LZX stream ends inside an uncompressed block")
            keep = min(pos, 8)
            buf, pos = buf[pos - keep :] + data, keep
        self._buf, self._pos = buf, pos + n
        return buf[pos : pos + n]

    def _align_for_raw(self) -> None:
        """Drop the rest of the current 16-bit word (a whole word when aligned), and
        hand the whole words read ahead back to the byte input."""
        drop = self._nbits % 16 or 16
        if self._nbits < drop:
            self._refill(drop)
        self._nbits -= drop
        self._pos -= self._nbits // 8
        self._bits = self._nbits = 0

    # ── Trees ────────────────────────────────────────────────────────────────────────

    def _read_lengths(self, lengths: list[int], first: int, last: int) -> None:
        pre = [self._read_bits(4) for _ in range(_PRETREE_SYMBOLS)]
        table = _build_table(pre, _PRETREE_SYMBOLS, "pretree")
        x = first
        while x < last:
            code = self._read_symbol(table, "pretree")
            if code == 17:
                run = self._read_bits(4) + 4
                lengths[x : x + run] = [0] * run
                x += run
            elif code == 18:
                run = self._read_bits(5) + 20
                lengths[x : x + run] = [0] * run
                x += run
            elif code == 19:
                run = self._read_bits(1) + 4
                code = self._read_symbol(table, "pretree")
                value = (lengths[x] - code) % 17
                lengths[x : x + run] = [value] * run
                x += run
            else:
                lengths[x] = (lengths[x] - code) % 17
                x += 1

    def _read_block_header(self) -> None:
        if self._block_type == _UNCOMPRESSED and self._block_length & 1:
            self._raw_bytes(1)
        block_type = self._read_bits(3)
        high = self._read_bits(16)
        length = (high << 8) | self._read_bits(8)
        self._block_type = block_type
        self._block_length = self._block_remaining = length
        if block_type == _ALIGNED:
            aligned = [self._read_bits(3) for _ in range(_ALIGNED_SYMBOLS)]
            self._aligned_table = _build_table(aligned, _ALIGNED_SYMBOLS, "aligned")
        if block_type in (_VERBATIM, _ALIGNED):
            main = self._main_lengths
            self._read_lengths(main, 0, _NUM_CHARS)
            self._read_lengths(main, _NUM_CHARS, self._main_symbols)
            self._main_table = _build_table(main, _MAIN_MAX, "main")
            if main[0xE8]:
                self._intel_started = True
            self._read_lengths(self._length_lengths, 0, _LENGTH_SYMBOLS)
            self._length_table = _build_table(
                self._length_lengths, _LENGTH_MAX, "length"
            )
        elif block_type == _UNCOMPRESSED:
            self._intel_started = True
            self._align_for_raw()
            stored = self._raw_bytes(12)
            self._r0 = int.from_bytes(stored[0:4], "little")
            self._r1 = int.from_bytes(stored[4:8], "little")
            self._r2 = int.from_bytes(stored[8:12], "little")
        else:
            raise CorruptionError(f"LZX block type {block_type}")

    # ── Frames ───────────────────────────────────────────────────────────────────────

    def decode_frame(self, frame_size: int) -> bytes:
        """The next ``frame_size`` bytes of output: 32 KiB, or less for the last."""
        if not 0 < frame_size <= FRAME_SIZE:
            raise ValueError(f"frame size {frame_size}")
        if not self._header_read:
            if self._read_bits(1):
                high = self._read_bits(16)
                self._intel_size = (high << 16) | self._read_bits(16)
            self._header_read = True
        frame_start = self._window_pos
        todo = frame_size
        while todo > 0:
            if self._block_remaining == 0:
                self._read_block_header()
            run = min(self._block_remaining, todo)
            if self._block_type == _UNCOMPRESSED:
                pos = self._window_pos
                self._window[pos : pos + run] = self._raw_bytes(run)
                self._window_pos = pos + run
                done = run
            else:
                done = self._decode_run(run)
            # A match may run past ``run`` inside its block, not past the frame.
            if done > self._block_remaining:
                raise CorruptionError("LZX match runs past the end of its block")
            self._block_remaining -= done
            todo -= done
        if self._window_pos - frame_start != frame_size:
            raise CorruptionError("LZX match runs past the end of a frame")
        # Realign the input to a 16-bit word.
        self._nbits -= self._nbits % 16
        self._check_overread()
        out = bytes(self._window[frame_start : self._window_pos])
        if self._intel_started and self._intel_size and self._frame < 32768:
            out = self._undo_e8(out)
        self._offset += frame_size
        self._frame += 1
        if self._window_pos == self._window_size:
            self._window_pos = 0
        return out

    def _decode_run(self, run: int) -> int:
        """Decode symbols until at least ``run`` bytes are out; return how many."""
        main_table = self._main_table
        if main_table is None:
            raise CorruptionError("LZX main symbol read from an empty tree")
        length_table = self._length_table
        aligned_table = self._aligned_table if self._block_type == _ALIGNED else None
        window = self._window
        window_size = self._window_size
        position_base = _POSITION_BASE
        extra_bits = _EXTRA_BITS
        # Output before this frame: a match may not reach back past the first byte.
        decoded = self._offset
        r0, r1, r2 = self._r0, self._r1, self._r2
        pos = start = self._window_pos
        end = pos + run
        # The bit reader in locals, for speed. Each symbol starts with at least 32
        # bits buffered: a main code and a length code, 16 bits at most each.
        bits, nbits = self._bits, self._nbits
        buf, bpos = self._buf, self._pos
        blen = len(buf)
        while pos < end:
            if nbits < 32:
                if bpos + 4 <= blen:
                    bits = ((bits & ((1 << nbits) - 1)) << 32) | (
                        buf[bpos + 1] << 24
                        | buf[bpos] << 16
                        | buf[bpos + 3] << 8
                        | buf[bpos + 2]
                    )
                    bpos += 4
                    nbits += 32
                else:
                    bits, nbits, buf, bpos = self._slow_fill(bits, nbits, buf, bpos)
                    blen = len(buf)
            entry = main_table[(bits >> (nbits - 16)) & 0xFFFF]
            nbits -= entry & 31
            symbol = entry >> 5
            if symbol < 256:
                window[pos] = symbol
                pos += 1
                continue
            symbol -= 256
            length = symbol & 7
            if length == _PRIMARY_LENGTHS:
                if length_table is None:
                    raise CorruptionError("LZX length symbol read from an empty tree")
                entry = length_table[(bits >> (nbits - 16)) & 0xFFFF]
                nbits -= entry & 31
                length += entry >> 5
            length += _MIN_MATCH
            slot = symbol >> 3
            if slot == 0:
                offset = r0
            elif slot == 1:
                offset = r1
                r1 = r0
                r0 = offset
            elif slot == 2:
                offset = r2
                r2 = r0
                r0 = offset
            else:
                # At most 17 verbatim bits, or 14 and a 16-bit aligned peek.
                if nbits < 32:
                    bits, nbits, buf, bpos = self._slow_fill(bits, nbits, buf, bpos)
                    blen = len(buf)
                extra = extra_bits[slot]
                offset = position_base[slot] - 2
                if extra >= 3 and aligned_table is not None:
                    if extra > 3:
                        nbits -= extra - 3
                        offset += ((bits >> nbits) & ((1 << (extra - 3)) - 1)) << 3
                    entry = aligned_table[(bits >> (nbits - 16)) & 0xFFFF]
                    nbits -= entry & 31
                    offset += entry >> 5
                elif extra:
                    nbits -= extra
                    offset += (bits >> nbits) & ((1 << extra) - 1)
                r2 = r1
                r1 = r0
                r0 = offset
            if pos + length > window_size:
                raise CorruptionError("LZX match runs past the end of the window")
            if offset > pos:
                # The match starts in the window's previous lap.
                if offset > decoded or offset - pos > window_size:
                    raise CorruptionError("LZX match reaches before the stream start")
                src = window_size - (offset - pos)
                first = min(length, window_size - src)
                window[pos : pos + first] = window[src : src + first]
                if first < length:
                    _copy(window, 0, pos + first, length - first)
            elif offset >= length:
                src = pos - offset
                window[pos : pos + length] = window[src : src + length]
            else:
                _copy(window, pos - offset, pos, length)
            pos += length
        self._r0, self._r1, self._r2 = r0, r1, r2
        self._bits, self._nbits, self._buf, self._pos = bits, nbits, buf, bpos
        self._window_pos = pos
        return pos - start

    def _slow_fill(
        self, bits: int, nbits: int, buf: bytes, pos: int
    ) -> tuple[int, int, bytes, int]:
        """:meth:`_refill` to 32 bits from the hot loop's locals."""
        self._bits, self._nbits, self._buf, self._pos = bits, nbits, buf, pos
        self._refill(32)
        return self._bits, self._nbits, self._buf, self._pos

    def _undo_e8(self, frame: bytes) -> bytes:
        """Turn the absolute ``CALL`` targets the encoder wrote back into relative
        ones, as lzxd.c does: only below ``frame_size - 10``."""
        size = len(frame)
        if size <= 10:
            return frame
        out = bytearray(frame)
        file_size = self._intel_size
        if file_size >= 1 << 31:
            file_size -= 1 << 32
        base = self._offset
        limit = size - 10
        i = out.find(0xE8, 0, limit)
        while i >= 0:
            current = base + i
            value = int.from_bytes(out[i + 1 : i + 5], "little", signed=True)
            if -current <= value < file_size:
                relative = value - current if value >= 0 else value + file_size
                out[i + 1 : i + 5] = (relative & 0xFFFFFFFF).to_bytes(4, "little")
            i = out.find(0xE8, i + 5, limit)
        return bytes(out)


def _copy(window: bytearray, src: int, dst: int, length: int) -> None:
    """Copy ``length`` bytes from ``src`` to ``dst`` in ``window``, byte by byte in
    effect: a source that overlaps the destination repeats."""
    distance = dst - src
    if distance >= length or distance <= 0:
        window[dst : dst + length] = window[src : src + length]
        return
    pattern = window[src:dst]
    reps, extra = divmod(length, distance)
    window[dst : dst + length] = pattern * reps + pattern[:extra]
