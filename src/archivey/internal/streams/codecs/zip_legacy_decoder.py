"""Decompressors for the two DOS-era ZIP methods: Shrink (1) and Implode (6).

Opened via :class:`~.zip_legacy_codec.ShrinkHandler` and
:class:`~.zip_legacy_codec.ImplodeHandler`, which ``FramedDecoder`` drives. Both are
pure Python (DR-20). Only archives from PKZIP 1.x and its contemporaries use them, so
the decoders favour plain code over speed.

The formats are PKWARE's APPNOTE (sections 5.1 and 5.3). Where APPNOTE leaves a detail
open, the decoders do what Info-ZIP ``unzip`` (``unshrink.c``, ``explode.c``) does:

- Shrink: a code that names a free slot is the "KwKwK" case, the entry being added
  now; a partial clear frees every code above 256 that is no other code's prefix, and
  new codes reuse the lowest free slot.
- Implode: a copy that reaches before the start of the output reads zeros, and the
  last copy stops at the member's declared size.

Neither stream has an end marker. Implode always ends at the declared size, so it needs
one, and clamps its last copy to it. Shrink stops after the first code that reaches the
size when the size is known, and otherwise where the input does (``flush``); a last
entry that runs past the size is refused by the member's size check above the decoder.
The bits left in the last byte are padding. A whole byte after the end is
``unused_data``, which ``FramedDecoder`` reports as input after the end.

Both decode forward only: a seek goes back to the start and decodes again.
"""

from __future__ import annotations

import heapq
from collections.abc import Generator

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.codecs.unix_compress_decoder import (
    _MAX_ENTRY_TAIL,
    _MAX_FLAT_ENTRY,
    _Entry,
    _expand,
)
from archivey.internal.streams.decompressor_stream import truncated_message

#: What the decode generator yields: True when it paused with output past the read's
#: budget (it can go on without input), False when it needs more input.
_Step = Generator[bool, None, None]


class _InputEnded(Exception):
    """The input ended where a decoder needed more bits (raised inside the generator)."""


class _BitDecompressor:
    """A decompressor (:class:`archivey.formats.Decompressor`, with ``flush``) written
    as a generator over an LSB-first bit stream.

    :meth:`_decode` reads bits with ``yield from self._need(n)`` / :meth:`_take`, puts
    its output in ``self._out``, and calls ``yield from self._budget()`` after each
    symbol so a read with a ``max_length`` stops near it. The generator returning
    means the stream ended.

    A hot decoder may do all three inline over locals instead, as Shrink does. It then
    owes the rest of the class three things: write ``_data_pos`` and ``_produced``
    back before every yield and return (and before raising :class:`_InputEnded`);
    read ``_data``, ``_data_pos`` and ``_limit`` again after every yield, since
    :meth:`feed` replaces the data and sets the budget; and append to ``_out``
    without rebinding it, since :meth:`_hand_out` empties it in place. ``_bits`` and
    ``_nbits`` then go unused.
    """

    label = ""

    def __init__(self, unpack_size: int | None) -> None:
        self._unpack_size = unpack_size
        self._data = b""
        self._data_pos = 0
        self._bits = 0
        self._nbits = 0
        self._eof = False
        self._limit = -1
        # Output decoded but not yet returned, and the total decoded so far.
        self._out = bytearray()
        self._produced = 0
        self._paused = False
        self._done = False
        self._truncation: str | None = None
        # The bytes fed after the end of the stream.
        self._unused = b""
        self._gen = self._decode()

    # --- the generator's helpers ---

    def _need(self, n: int) -> _Step:
        """Wait until ``n`` bits are buffered; raise :class:`_InputEnded` at the end."""
        while self._nbits < n:
            if self._data_pos < len(self._data):
                self._bits |= self._data[self._data_pos] << self._nbits
                self._data_pos += 1
                self._nbits += 8
            elif self._eof:
                raise _InputEnded
            else:
                yield False

    def _take(self, n: int) -> int:
        """Consume ``n`` buffered bits (after :meth:`_need`)."""
        value = self._bits & ((1 << n) - 1)
        self._bits >>= n
        self._nbits -= n
        return value

    def _bits_value(self, n: int) -> Generator[bool, None, int]:
        yield from self._need(n)
        return self._take(n)

    def _emit(self, data: bytes | bytearray) -> None:
        self._out += data
        self._produced += len(data)

    def _budget(self) -> _Step:
        if 0 <= self._limit <= len(self._out):
            yield True

    def _decode(self) -> _Step:
        raise NotImplementedError

    # --- Decompressor ---

    def _run(self) -> None:
        if self._done:
            return
        try:
            self._paused = next(self._gen)
        except StopIteration:
            self._finish()
        except _InputEnded:
            self._truncation = self._truncation or "the input ends inside a code"
            self._finish()

    def _finish(self) -> None:
        self._done = True
        self._paused = False
        self._unused = self._data[self._data_pos :]
        self._data = b""
        self._data_pos = 0

    def _hand_out(self, max_length: int) -> bytes:
        if max_length < 0 or max_length >= len(self._out):
            data = bytes(self._out)
            self._out.clear()
            return data
        data = bytes(self._out[:max_length])
        del self._out[:max_length]
        return data

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if data:
            if self._done:
                self._unused += data
            else:
                self._data = self._data[self._data_pos :] + data
                self._data_pos = 0
        if max_length < 0 or len(self._out) < max_length:
            self._limit = max_length
            self._run()
        return self._hand_out(max_length)

    def flush(self) -> bytes:
        """The input ended: the output still held, then (on the next call) the
        truncation, when the stream cannot end here."""
        self._eof = True
        self._limit = -1
        self._run()
        if self._out:
            return self._hand_out(-1)
        if self._truncation is not None:
            raise TruncatedError(
                f"{truncated_message(self.label)} ({self._truncation})"
            )
        return b""

    @property
    def eof(self) -> bool:
        return self._done and self._truncation is None and not self._out

    @property
    def unused_data(self) -> bytes:
        return self._unused

    @property
    def needs_input(self) -> bool:
        return not self._out and not self._paused


# --- Shrink (method 1): LZW with 9- to 13-bit codes and partial clearing ---

_SHRINK_MAX_WIDTH = 13
_SHRINK_TABLE = 1 << _SHRINK_MAX_WIDTH
_SHRINK_CONTROL = 256
_SHRINK_FIRST_FREE = 257
_SHRINK_WIDEN = 1
_SHRINK_PARTIAL_CLEAR = 2


class ShrinkDecompressor(_BitDecompressor):
    """Shrink: LZW whose code 256 is followed by a control code (widen, partial clear).

    Each code after the first adds one entry, the previous code's string plus the first
    byte of this one's, at the lowest free slot above 256. The table follows 7-Zip's
    ``ShrinkDecoder`` and Info-ZIP's ``unshrink``: a code is a slot and its parent
    pointer, and a partial clear frees slots no other slot points to, even the previous
    code's, which then stays the parent of the next entry (an "orphan" that a later
    entry may take over). Both tools refuse a code when the table has no free slot for
    its entry, and so does this decoder. 7-Zip, which this decoder follows where the two
    differ, also refuses a stream that starts with a control code, an unknown control
    code, a free code that is not the one being added, and a chain that reaches a free
    slot; ``unshrink`` reads on through those and leaves them to the CRC-32.
    """

    label = "Shrink"

    def _decode(self) -> _Step:
        parent = [-1] * _SHRINK_TABLE
        suffix = bytearray(_SHRINK_TABLE)
        used = bytearray(_SHRINK_TABLE)
        used[:_SHRINK_FIRST_FREE] = b"\x01" * _SHRINK_FIRST_FREE
        # Each slot's string, so a code costs one lookup instead of a walk up its
        # parents: flat bytes up to _MAX_FLAT_ENTRY, a (base, tail) link above it
        # (unix-compress's layout and caps, :func:`_expand`), or None for a slot whose
        # parent was free when it was added (an orphan, and every slot below it). Those
        # walk the parents on each use, since the slot that becomes the parent can
        # change. A stored string never goes stale: a slot with children is never
        # freed, so its parent, and every ancestor a link's base can name, stay as
        # they were while it lives.
        strings: list[_Entry | None] = [bytes([i]) for i in range(256)]
        strings += [None] * (_SHRINK_TABLE - 256)
        # The free slots: freed ones in a heap, all below ``fresh``, then the slots
        # never used from ``fresh`` up. The lowest free slot is the heap's top if
        # there is one. A clear frees only slots that were added, so every push is
        # paid for by a code.
        freed: list[int] = []
        fresh = _SHRINK_FIRST_FREE
        # Pointers to each slot from other slots (an orphan's parent counts too, as
        # in 7-Zip), and the used slots above 256 that none points to: what a
        # partial clear frees. A clear then costs the slots it frees, not the
        # table's size, so a run of clears with no output stays cheap.
        children = [0] * _SHRINK_TABLE
        leaves: set[int] = set()
        width = 9
        mask = (1 << width) - 1
        prev = -1
        prev_str = b""
        size = self._unpack_size
        out = self._out
        produced = self._produced
        limit = self._limit
        # The bit reader, in locals (see :class:`_BitDecompressor`): only ``_data_pos``
        # goes back to self before a yield, and ``self._bits`` / ``_nbits`` stay
        # unused.
        data = self._data
        pos = self._data_pos
        bits = 0
        nbits = 0
        control = False

        while size is None or produced < size:
            while nbits < width:
                if pos < len(data):
                    bits |= data[pos] << nbits
                    pos += 1
                    nbits += 8
                    continue
                self._data_pos = pos
                self._produced = produced
                if self._eof:
                    if control:
                        self._truncation = "the input ends inside a control code"
                        raise _InputEnded
                    if size is not None:
                        raise _InputEnded
                    if nbits >= 8:
                        # A whole byte after the last code cannot be padding.
                        self._truncation = "the input ends inside a code"
                    return
                yield False
                data = self._data
                pos = self._data_pos
                limit = self._limit
            code = bits & mask
            bits >>= width
            nbits -= width

            if control:
                control = False
                if code == _SHRINK_WIDEN:
                    if width == _SHRINK_MAX_WIDTH:
                        raise CorruptionError(
                            "Shrink stream widens its codes past 13 bits"
                        )
                    width += 1
                    mask = (1 << width) - 1
                elif code == _SHRINK_PARTIAL_CLEAR:
                    gone = leaves
                    leaves = set()
                    for slot in gone:
                        used[slot] = 0
                        strings[slot] = None
                        heapq.heappush(freed, slot)
                        up = parent[slot]
                        if up > 255:
                            children[up] -= 1
                            # A parent the clear left a leaf goes at the next one.
                            if not children[up] and used[up]:
                                leaves.add(up)
                else:
                    raise CorruptionError(
                        f"Shrink stream has an unknown control code {code}"
                    )
                continue
            if code == _SHRINK_CONTROL:
                if prev < 0:
                    raise CorruptionError("Shrink stream starts with a control code")
                control = True
                continue

            new = -1
            if prev >= 0:
                if freed:
                    new = heapq.heappop(freed)
                elif fresh < _SHRINK_TABLE:
                    new = fresh
                    fresh += 1
                else:
                    raise CorruptionError(
                        "Shrink stream's code table is full and was not cleared"
                    )
                # Its last byte is the first of this code's string: for a code that
                # names the entry itself (KwKwK), the first of the previous string.
                used[new] = 1
                parent[new] = prev
                suffix[new] = prev_str[0]
                if prev > 255:
                    children[prev] += 1
                    leaves.discard(prev)
                if not children[new]:
                    leaves.add(new)
            elif code > 255:
                raise CorruptionError("Shrink stream starts with an undefined code")
            if not used[code]:
                raise CorruptionError(f"Shrink stream names the free code {code}")

            stored = strings[code]
            entry: bytes
            if isinstance(stored, bytes):
                entry = stored
            elif stored is not None:
                entry = prev_str if code == prev else _expand(strings, stored)
            elif code == new and strings[prev] is not None:
                entry = prev_str + prev_str[:1]
            else:
                walked = bytearray()
                walk = code
                while walk > 255:
                    if not used[walk] or len(walked) >= _SHRINK_TABLE:
                        raise CorruptionError(
                            "Shrink stream's code table links to a free code or loops"
                        )
                    walked.append(suffix[walk])
                    walk = parent[walk]
                walked.append(walk)
                walked.reverse()
                entry = bytes(walked)

            if new >= 0:
                suffix[new] = entry[0]
                base = strings[prev]
                if base is None:
                    pass
                elif len(prev_str) < _MAX_FLAT_ENTRY:
                    strings[new] = prev_str + entry[:1]
                elif not isinstance(base, bytes) and len(base[1]) < _MAX_ENTRY_TAIL:
                    strings[new] = (base[0], base[1] + entry[:1])
                else:
                    strings[new] = (prev, entry[:1])
            prev = code
            prev_str = entry
            out += entry
            produced += len(entry)
            if 0 <= limit <= len(out):
                self._data_pos = pos
                self._produced = produced
                yield True
                data = self._data
                pos = self._data_pos
                limit = self._limit
        self._data_pos = pos
        self._produced = produced


# --- Implode (method 6): LZ77 with Shannon-Fano coded literals, lengths, distances ---


def _read_tree(decoder: _BitDecompressor, values: int) -> Generator[bool, None, dict]:
    """Read one Shannon-Fano tree and return its ``{(bit_length, code): value}`` map.

    The tree is stored as run-length coded bit lengths: a byte holding the number of
    bytes that follow, less one, then per byte the run length less one (high nibble) and
    the bit length less one (low nibble). Codes are assigned as APPNOTE 5.3.6 says:
    lengths sorted ascending, values in order within a length, the longest codes first
    counting up from zero in steps of ``1 << (16 - length)``.
    """
    count = (yield from decoder._bits_value(8)) + 1
    lengths: list[int] = []
    for _ in range(count):
        byte = yield from decoder._bits_value(8)
        lengths.extend([(byte & 0x0F) + 1] * ((byte >> 4) + 1))
    if len(lengths) != values:
        raise CorruptionError(
            f"Implode tree has {len(lengths)} code lengths, expected {values}"
        )
    order = sorted(range(values), key=lambda v: lengths[v])
    codes: dict[tuple[int, int], int] = {}
    code = 0
    step = 0
    last = 0
    for value in reversed(order):
        code += step
        length = lengths[value]
        if length != last:
            last = length
            step = 1 << (16 - length)
        if code >= 1 << 16:
            raise CorruptionError(
                "Implode tree's code lengths over-subscribe the codes"
            )
        codes[(length, code >> (16 - length))] = value
    return codes


def _read_symbol(decoder: _BitDecompressor, codes: dict) -> Generator[bool, None, int]:
    """Read one code of ``codes``, its first bit read being the code's highest."""
    acc = 0
    for length in range(1, 17):
        yield from decoder._need(1)
        acc = (acc << 1) | decoder._take(1)
        value = codes.get((length, acc))
        if value is not None:
            return value
    raise CorruptionError("Implode stream has a code its tree does not define")


class ImplodeDecompressor(_BitDecompressor):
    """Implode: a 4 KiB or 8 KiB window, and two or three Shannon-Fano trees."""

    label = "Implode"

    def __init__(
        self, unpack_size: int | None, *, large_window: bool, literal_tree: bool
    ) -> None:
        if unpack_size is None:
            raise CorruptionError(
                "Implode data has no end marker, so it needs the member's size"
            )
        self._large_window = large_window
        self._literal_tree = literal_tree
        super().__init__(unpack_size)

    def _decode(self) -> _Step:
        size = self._unpack_size
        assert size is not None
        literals = (yield from _read_tree(self, 256)) if self._literal_tree else None
        lengths = yield from _read_tree(self, 64)
        distances = yield from _read_tree(self, 64)
        low_bits = 7 if self._large_window else 6
        min_match = 3 if self._literal_tree else 2
        window = 1 << (low_bits + 6)
        # The output so far, trimmed to the window now and then.
        history = bytearray()
        trimmed = 0
        while self._produced < size:
            if (yield from self._bits_value(1)):
                if literals is None:
                    byte = yield from self._bits_value(8)
                else:
                    byte = yield from _read_symbol(self, literals)
                history.append(byte)
                self._emit(history[-1:])
            else:
                low = yield from self._bits_value(low_bits)
                high = yield from _read_symbol(self, distances)
                distance = ((high << low_bits) | low) + 1
                length = yield from _read_symbol(self, lengths)
                if length == 63:
                    length += yield from self._bits_value(8)
                length = min(length + min_match, size - self._produced)
                # ``trimmed`` bytes of output have left ``history``; a source before
                # the start of the output reads zero, as Info-ZIP reads it.
                end = trimmed + len(history)
                for position in range(end, end + length):
                    source = position - distance
                    history.append(history[source - trimmed] if source >= 0 else 0)
                self._emit(history[len(history) - length :])
            yield from self._budget()
            if len(history) > 4 * window:
                trimmed += len(history) - window
                del history[: len(history) - window]
