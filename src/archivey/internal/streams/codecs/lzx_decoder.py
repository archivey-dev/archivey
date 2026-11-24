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
stream but one kind (below the list):

- a run of code lengths may write past the end of the range being read (by up to 50
  entries), into lengths the next range or the tree build sees;
- a code length is a byte: a delta that takes it below 0 wraps once by 17, and one
  still below 0 wraps as a byte, to 254 or 255; a length above 16 gives its symbol no
  code, and later deltas from it stay above 16;
- the length tree may have no codes, and decoding a symbol with it is damage; any
  other tree whose codes do not fill the code space is damage, an empty one too (a
  tree with only out-of-range lengths is not empty, so it does not fill the space);
- a match may not cross the end of the window or the end of a frame, nor reach back
  before the first byte of output;
- the E8 translation runs for the first 32 768 frames only, from the first block that
  can produce an ``E8`` byte, and leaves the last 10 bytes of each frame alone;
- past the end of the input come two zero bytes, and a stream lzxd.c would read
  further for is refused. It reads 16 bits ahead of each Huffman symbol, and one more
  word to realign at the end of a frame, so how far it reads decides, not how many
  bits the stream uses.

The one deliberate difference: a tree whose codes no longer than ``lzxd.c``'s first
table level (6 bits for the pretree, 7 for the aligned tree, 12 for the others) already
fill the code space, and that also has a code longer than that level, is refused as
overfull. ``lzxd.c`` stops building once the first level is full, so it never sees the
longer code and decodes on. No encoder writes such a tree; it comes from damage, and the
bytes after it are wrong, so archivey refuses the stream rather than return them.

Every Huffman code is at most 16 bits. Each tree decodes through a two-level table:
a root indexed by the next ``min(longest code, 10)`` bits, and, under each root entry
whose codes are longer, a sub-table as wide as the longest of them. A block header
builds up to six trees, and a block may be empty, so the cost of a build follows the
tree it decodes, not the 65 536 entries a one-level 16-bit table would fill.
"""

from __future__ import annotations

from collections.abc import Callable

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.codecs import huffman_table

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
# The input read is dropped once more than this much of it is held, so a trim moves
# a few bytes per kilobyte read, not per block.
_TRIM_AT = 4096

# The trees a block header reads lengths for, in order: main lengths (True) or
# length-tree lengths (False), and the range read (-1: the window's main symbols).
_TREES = ((True, 0, 256), (True, 256, -1), (False, 0, 249))

Tree = huffman_table.Tree
_MAX_CODE = huffman_table.MAX_CODE
_ROOT_BITS = huffman_table.ROOT_BITS


def _build_table(
    lengths: list[int], count: int, what: str, *, may_be_empty: bool = False
) -> Tree | None:
    """The decoding table for the canonical code of ``lengths[:count]``, from the
    shared :func:`huffman_table.build_table`. A length above 16 (a delta that wrapped
    below 0) gives its symbol no code, as in lzxd. With ``may_be_empty``, ``None`` for
    a tree whose lengths are all 0; any other empty tree, and a code that overfills or
    underfills the code space, is damage."""
    return huffman_table.build_table(
        lengths, count, f"LZX {what}", may_be_empty=may_be_empty
    )


def _delta(length: int, code: int) -> int:
    """lzxd's ``z = lens[x] - z; if (z < 0) z += 17;`` into an ``unsigned char``:
    pretree symbols 17 to 19 read after a code 19 can leave it below 0, which the
    byte keeps as 254 or 255, a length no code has."""
    value = length - code
    if value < 0:
        value += 17
    return value & 0xFF


class _NeedMore(Exception):
    """The input given so far ends before the frame does (push mode)."""


class LzxDecoder:
    """Decodes one LZX stream, a frame at a time.

    Push: give input with :meth:`feed` and :meth:`end`, and ask for frames with
    :meth:`try_frame`, which returns ``None`` when the input given so far ends
    before the frame does. The decoder keeps its place, the start of the symbol
    or block header it could not finish, and the next call goes on from there, so
    an input given one data block at a time decodes once.

    Pull: with ``more``, :meth:`decode_frame` asks it for input whenever the
    frame needs more: it returns the next run of input bytes (a cabinet's next data
    block), or ``None`` at the end of the input. It is the push mode, fed one run
    each time the frame runs out, so input is asked for at the same points.

    The caller says how long each frame is: 32 KiB, except the last.
    """

    def __init__(
        self, window_bits: int, more: Callable[[], bytes | None] | None = None
    ) -> None:
        if not MIN_WINDOW_BITS <= window_bits <= MAX_WINDOW_BITS:
            raise CorruptionError(f"LZX window of 2**{window_bits} bytes")
        self._window_size = 1 << window_bits
        self._window = bytearray(self._window_size)
        self._main_symbols = _NUM_CHARS + (_POSITION_SLOTS[window_bits - 15] << 3)
        self._more = more
        # Input: unread bytes from ``_pos``, and a bit buffer of ``_nbits`` bits. The
        # buffer is trimmed only where no place to resume from is kept (the start of
        # a frame or a block header), so such a place stays valid as input arrives.
        self._buf = bytearray()
        self._ended = False
        self._pos = 0
        self._bits = 0
        self._nbits = 0
        self._padding = 0  # zero bytes appended past the end of the input
        # Bits read since the last Huffman symbol began: lzxd.c looks 16 bits ahead
        # from the start of each symbol, so its look-ahead is ``16 - _since_symbol``.
        self._since_symbol = _MAX_CODE
        # Decoder state that lives across blocks and frames.
        self._main_lengths = [0] * (_MAIN_MAX + _RUN_SLACK)
        self._length_lengths = [0] * (_LENGTH_MAX + _RUN_SLACK)
        self._main_table: Tree | None = None
        self._length_table: Tree | None = None
        self._aligned_table: Tree | None = None
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
        # The frame being decoded, once it started: its size, and where in the window.
        self._frame_size: int | None = None
        self._frame_start = 0
        # The input position when the frame started: a frame that ran out of input
        # before reading anything is not started yet.
        self._frame_mark = (0, 0)
        # A block header that ran out of input inside its trees: which tree (an
        # index into ``_TREES``), the next length to read, and its pretree once read.
        self._header: tuple[int, int, Tree | None] | None = None

    # ── Push input ───────────────────────────────────────────────────────────────────

    def feed(self, data: bytes) -> None:
        """Give the next input bytes."""
        if self._ended:
            raise ValueError("feed() after end()")
        self._buf += data

    def end(self) -> None:
        """Say the input has ended: past it come the zero bytes lzxd.c reads."""
        self._ended = True

    @property
    def decoded(self) -> int:
        """Output bytes of the frames finished so far."""
        return self._offset

    @property
    def unread_input(self) -> int:
        """Input bytes given and not read yet (the zero padding past the end left
        out)."""
        return max(0, len(self._buf) - self._padding - self._pos)

    def frame_in_progress(self) -> tuple[int, int] | None:
        """The frame started and not finished: its size and the bytes it decoded."""
        if self._frame_size is None:
            return None
        return self._frame_size, self._window_pos - self._frame_start

    def inside_block(self) -> bool:
        """Whether a block has bytes still to decode, or its header is half read."""
        return self._block_remaining > 0 or self._header is not None

    def owes_pad_byte(self) -> bool:
        """Whether the stream still owes the pad byte after an uncompressed block of
        odd length: the decoder skips it at the next block header, so at the end of
        the stream it is unread, but it is part of the stream."""
        return (
            self._block_type == _UNCOMPRESSED
            and self._block_remaining == 0
            and self._block_length & 1 == 1
        )

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

    def _input_more(self, buf: bytearray, pos: int) -> tuple[bytearray, int]:
        """The unread input with at least two bytes more, or :class:`_NeedMore`
        when the input given so far has no more.

        Past the end of the input come zero bytes, so the decoder can look ahead as
        it does inside the stream; :meth:`_realign` refuses a stream that
        lzxd.c would have read more than two of them for.
        """
        while len(buf) - pos < 2:
            if not self._ended:
                raise _NeedMore
            if self._padding >= _MAX_PADDING:
                raise TruncatedError("LZX stream ends before its output")
            self._padding += 2
            buf += b"\0\0"
        return buf, pos

    def _realign(self) -> None:
        """Realign the input to a 16-bit word at the end of a frame, and refuse a
        stream that lzxd.c would have read more than two bytes past its end for.

        lzxd.c reads the input 16 bits at a time, only when it needs them: 16 bits
        ahead of the start of each Huffman symbol, and the bits a fixed-width field
        takes. At the end of a frame, if its bit buffer is not empty, it reads one
        more word before it drops the rest of the current one. It refuses the stream
        when a read needs more than the two zero bytes it puts after the input. So
        what counts is how far it has read, not how far the stream used: a stream
        whose last frame ends in the last two bytes may still be refused.
        """
        unread = (len(self._buf) - self._pos) * 8 + self._nbits
        partial = self._nbits % 16  # bits left in the current word
        # The bits lzxd.c holds now: the fewest at least its look-ahead that end
        # on a word boundary. Then the realignment reads a word if they are 1-15.
        ahead = partial
        if ahead < _MAX_CODE - self._since_symbol:
            ahead += 16
        if 0 < ahead < 16:
            ahead += 16
        if self._padding and ahead > unread - self._padding * 8 + _PADDING_ALLOWED * 8:
            raise TruncatedError("LZX stream ends before its output")
        self._nbits -= partial
        # Whatever it read past the word boundary is look-ahead for the next frame.
        self._since_symbol = _MAX_CODE - (ahead - partial)

    def _read_bits(self, n: int) -> int:
        if self._nbits < n:
            self._refill(n)
        self._nbits -= n
        self._since_symbol += n
        return (self._bits >> self._nbits) & ((1 << n) - 1)

    def _read_symbol(self, tree: Tree | None, what: str) -> int:
        if tree is None:
            raise CorruptionError(f"LZX {what} symbol read from an empty tree")
        if self._nbits < _MAX_CODE:
            self._refill(_MAX_CODE)
        table, root = tree
        bits, nbits = self._bits, self._nbits
        start = nbits
        entry = table[(bits >> (nbits - root)) & ((1 << root) - 1)]
        if entry < 0:
            nbits -= root
            entry = ~entry
            sub = entry & 31
            entry = table[(entry >> 5) + ((bits >> (nbits - sub)) & ((1 << sub) - 1))]
        self._nbits = nbits - (entry & 31)
        self._since_symbol = start - self._nbits
        return entry >> 5

    def _raw_bytes(self, n: int) -> bytearray:
        """``n`` bytes straight from the input, once the bit buffer is empty."""
        assert self._nbits == 0
        buf, pos = self._buf, self._pos
        if len(buf) - pos < n:
            if not self._ended:
                raise _NeedMore
            # As lzxd.c, read the two zero bytes past the end, but no further.
            if self._padding or len(buf) - pos + _PADDING_ALLOWED < n:
                raise TruncatedError("LZX stream ends inside an uncompressed block")
            self._padding += _PADDING_ALLOWED
            buf += bytes(_PADDING_ALLOWED)
        self._pos = pos + n
        # lzxd.c reads stored bytes as it uses them: it holds nothing ahead.
        self._since_symbol = _MAX_CODE
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

    def _bit_mark(self) -> tuple[int, int, int, int]:
        """The input position, to go back to when a read runs out of input."""
        return self._pos, self._bits, self._nbits, self._since_symbol

    def _back_to(self, mark: tuple[int, int, int, int]) -> None:
        self._pos, self._bits, self._nbits, self._since_symbol = mark

    def _read_lengths(self, tree: int, pre: Tree | None, x: int) -> None:
        """Read tree ``tree``'s code lengths from ``x`` on, after its pretree
        ``pre`` (read first when ``None``). When the input runs out, the header's
        place is kept in ``_header`` and the input goes back to the start of the
        pretree or of the length symbol it was in: each symbol writes its lengths
        only once all its bits are read, so going on from there is exact."""
        main, first, last = _TREES[tree]
        lengths = self._main_lengths if main else self._length_lengths
        if last < 0:
            last = self._main_symbols
        mark = self._bit_mark()
        try:
            if pre is None:
                pre_lengths = [self._read_bits(4) for _ in range(_PRETREE_SYMBOLS)]
                pre = _build_table(pre_lengths, _PRETREE_SYMBOLS, "pretree")
                x = first
            while x < last:
                mark = self._bit_mark()
                code = self._read_symbol(pre, "pretree")
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
                    code = self._read_symbol(pre, "pretree")
                    value = _delta(lengths[x], code)
                    lengths[x : x + run] = [value] * run
                    x += run
                else:
                    lengths[x] = _delta(lengths[x], code)
                    x += 1
        except _NeedMore:
            self._back_to(mark)
            # ``pre`` is still ``None`` when its own lengths ran out.
            self._header = (tree, x, pre)
            raise

    def _read_block_header(self) -> None:
        """Read a block header, or go on with one that ran out of input in its trees
        (``_header``). Its fixed fields are read again from their start when they
        run out: they are a few bytes."""
        if self._header is None:
            mark = self._bit_mark()
            kind, length, remaining = (
                self._block_type,
                self._block_length,
                self._block_remaining,
            )
            intel = self._intel_started
            try:
                self._read_block_start()
            except _NeedMore:
                self._back_to(mark)
                self._block_type, self._block_length = kind, length
                self._block_remaining = remaining
                self._intel_started = intel
                raise
            if self._block_type == _UNCOMPRESSED:
                return
            self._header = (0, 0, None)
        while self._header is not None:
            tree, x, pre = self._header
            self._read_lengths(tree, pre, x)
            if tree == 1:
                main = self._main_lengths
                self._main_table = _build_table(main, _MAIN_MAX, "main")
                if main[0xE8]:
                    self._intel_started = True
            elif tree == 2:
                self._length_table = _build_table(
                    self._length_lengths, _LENGTH_MAX, "length", may_be_empty=True
                )
            self._header = (tree + 1, 0, None) if tree < 2 else None

    def _read_block_start(self) -> None:
        """A block header's fixed fields: type, length, the aligned tree, or an
        uncompressed block's repeated offsets."""
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
            return
        if block_type == _UNCOMPRESSED:
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
        """The next ``frame_size`` bytes of output: 32 KiB, or less for the last.
        Pull mode: asks ``more`` for input each time the frame runs out; without
        it, the input given must cover the frame."""
        more = self._more
        while (out := self.try_frame(frame_size)) is None:
            if more is None:
                raise ValueError("the input given ends inside the frame")
            data = more()
            if data is None:
                self.end()
            else:
                self.feed(data)
        return out

    def _trim(self) -> None:
        """Drop the input read, keeping the last few bytes: words read ahead into the
        bit buffer go back to the byte input before an uncompressed block
        (``_align_for_raw``). Only where no place to resume from is kept."""
        drop = self._pos - min(self._pos, 8)
        if drop > _TRIM_AT:
            del self._buf[:drop]
            self._pos -= drop
            pos, nbits = self._frame_mark
            self._frame_mark = (pos - drop, nbits)

    def try_frame(self, frame_size: int) -> bytes | None:
        """The next ``frame_size`` bytes of output, or ``None`` when the input given
        so far ends first: feed more (or end it) and call again with the same size
        (any size, if the frame read nothing yet).
        """
        if self._frame_size is None:
            if not 0 < frame_size <= FRAME_SIZE:
                raise ValueError(f"frame size {frame_size}")
            self._trim()
            self._frame_mark = (self._pos, self._nbits)
            if not self._header_read:
                mark = self._bit_mark()
                try:
                    if self._read_bits(1):
                        high = self._read_bits(16)
                        self._intel_size = (high << 16) | self._read_bits(16)
                except _NeedMore:
                    self._back_to(mark)
                    return None
                self._header_read = True
            self._frame_size = frame_size
            self._frame_start = self._window_pos
        elif frame_size != self._frame_size:
            raise ValueError(
                f"frame size {frame_size} for a frame started at {self._frame_size}"
            )
        frame_start = self._frame_start
        while (todo := frame_size - (self._window_pos - frame_start)) > 0:
            if self._header is not None or self._block_remaining == 0:
                if self._header is None:
                    self._trim()
                try:
                    self._read_block_header()
                except _NeedMore:
                    return self._stalled()
            run = min(self._block_remaining, todo)
            if self._block_type == _UNCOMPRESSED:
                at, since = self._pos, self._since_symbol
                try:
                    data = self._raw_bytes(run)
                except _NeedMore:
                    self._pos, self._since_symbol = at, since
                    return self._stalled()
                pos = self._window_pos
                self._window[pos : pos + run] = data
                self._window_pos = pos + run
                done = run
            else:
                before = self._window_pos
                try:
                    done = self._decode_run(run)
                except _NeedMore:
                    # The run stopped at the start of a symbol: keep what it decoded.
                    self._block_remaining -= self._window_pos - before
                    return self._stalled()
            # A match may run past ``run`` inside its block, not past the frame.
            if done > self._block_remaining:
                raise CorruptionError("LZX match runs past the end of its block")
            self._block_remaining -= done
        self._frame_size = None
        if self._window_pos - frame_start != frame_size:
            raise CorruptionError("LZX match runs past the end of a frame")
        self._realign()
        out = bytes(self._window[frame_start : self._window_pos])
        if self._intel_started and self._intel_size and self._frame < 32768:
            out = self._undo_e8(out)
        self._offset += frame_size
        self._frame += 1
        if self._window_pos == self._window_size:
            self._window_pos = 0
        return out

    def _stalled(self) -> None:
        """The frame ran out of input. One that has read nothing yet is not started,
        so the next call may ask for another size."""
        if (
            self._window_pos == self._frame_start
            and self._header is None
            and (self._pos, self._nbits) == self._frame_mark
        ):
            self._frame_size = None

    def _decode_run(self, run: int) -> int:
        """Decode symbols until at least ``run`` bytes are out; return how many."""
        if self._main_table is None:
            raise CorruptionError("LZX main symbol read from an empty tree")
        main_table, main_root = self._main_table
        main_mask = (1 << main_root) - 1
        length_table, length_root = self._length_table or ([], 0)
        length_mask = (1 << length_root) - 1
        aligned = self._block_type == _ALIGNED
        aligned_table, aligned_root = self._aligned_table or ([], 0)
        aligned_mask = (1 << aligned_root) - 1
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
        # ``nbits`` where the last Huffman symbol began, for ``_since_symbol``; set so
        # that a run with no symbols (an empty block) leaves it as it was.
        top = nbits + self._since_symbol
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
                    try:
                        bits, nbits, buf, bpos = self._slow_fill(bits, nbits, buf, bpos)
                    except _NeedMore:
                        self._stop_run(r0, r1, r2, bits, nbits, bpos, top, pos)
                        raise
                    blen = len(buf)
            # The symbol's start, to resume from if its extra bits run out of input.
            start_nbits, start_top = nbits, top
            top = nbits
            entry = main_table[(bits >> (nbits - main_root)) & main_mask]
            if entry < 0:
                nbits -= main_root
                entry = ~entry
                sub = entry & 31
                entry = main_table[
                    (entry >> 5) + ((bits >> (nbits - sub)) & ((1 << sub) - 1))
                ]
            nbits -= entry & 31
            symbol = entry >> 5
            if symbol < 256:
                window[pos] = symbol
                pos += 1
                continue
            symbol -= 256
            length = symbol & 7
            if length == _PRIMARY_LENGTHS:
                if not length_table:
                    raise CorruptionError("LZX length symbol read from an empty tree")
                top = nbits
                entry = length_table[(bits >> (nbits - length_root)) & length_mask]
                if entry < 0:
                    nbits -= length_root
                    entry = ~entry
                    sub = entry & 31
                    entry = length_table[
                        (entry >> 5) + ((bits >> (nbits - sub)) & ((1 << sub) - 1))
                    ]
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
                    filled = nbits
                    try:
                        bits, nbits, buf, bpos = self._slow_fill(bits, nbits, buf, bpos)
                    except _NeedMore:
                        # Only the codes read since the symbol began changed ``nbits``.
                        self._stop_run(
                            r0, r1, r2, bits, start_nbits, bpos, start_top, pos
                        )
                        raise
                    blen = len(buf)
                    top += nbits - filled
                extra = extra_bits[slot]
                offset = position_base[slot] - 2
                if extra >= 3 and aligned:
                    # An aligned block's header built its aligned tree, which is
                    # never empty.
                    if extra > 3:
                        nbits -= extra - 3
                        offset += ((bits >> nbits) & ((1 << (extra - 3)) - 1)) << 3
                    # Aligned codes are at most 7 bits: the root holds them all.
                    top = nbits
                    entry = aligned_table[
                        (bits >> (nbits - aligned_root)) & aligned_mask
                    ]
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
        self._since_symbol = top - nbits
        self._window_pos = pos
        return pos - start

    def _stop_run(
        self,
        r0: int,
        r1: int,
        r2: int,
        bits: int,
        nbits: int,
        bpos: int,
        top: int,
        pos: int,
    ) -> None:
        """Keep the hot loop's place at the start of the symbol the input ran out
        in, to resume from there."""
        self._r0, self._r1, self._r2 = r0, r1, r2
        self._bits, self._nbits, self._pos = bits, nbits, bpos
        self._since_symbol = top - nbits
        self._window_pos = pos

    def _slow_fill(
        self, bits: int, nbits: int, buf: bytearray, pos: int
    ) -> tuple[int, int, bytearray, int]:
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
