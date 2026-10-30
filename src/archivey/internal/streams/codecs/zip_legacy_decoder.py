"""Decoders for the two DOS-era ZIP methods: Shrink (1) and Implode (6).

Opened via :class:`~.codecs.ShrinkCodec` and :class:`~.codecs.ImplodeCodec`. Both are
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
one; Shrink ends there when the size is known, and otherwise where the input does. The
bits left in the last byte are padding. A whole byte after the end is input after the
end (:meth:`BaseDecoder._past_end`).

Both decode forward only: a seek goes back to the start and decodes again.
"""

from __future__ import annotations

import heapq
from collections.abc import Generator
from typing import BinaryIO

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    SeekPoint,
    truncated_message,
)

#: What the decode generator yields: True when it paused with output past the read's
#: budget (it can go on without input), False when it needs more input.
_Step = Generator[bool, None, None]


class _InputEnded(Exception):
    """The input ended where a decoder needed more bits (raised inside the generator)."""


class _BitDecoder(BaseDecoder):
    """A decoder written as a generator over an LSB-first bit stream.

    :meth:`_decode` reads bits with ``yield from self._need(n)`` / :meth:`_take`, puts
    its output in ``self._out``, and calls ``yield from self._budget()`` after each
    symbol so a read with a ``max_length`` stops near it. The generator returning
    means the stream ended.
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

    # --- Decoder ---

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> _BitDecoder:
        del point, inner
        return type(self)(self._unpack_size)

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
        rest = self._data[self._data_pos :]
        self._data = b""
        self._data_pos = 0
        if rest:
            self._past_end(rest)

    def _hand_out(self, max_length: int) -> bytes:
        if max_length < 0 or max_length >= len(self._out):
            data = bytes(self._out)
            self._out.clear()
            return data
        data = bytes(self._out[:max_length])
        del self._out[:max_length]
        return data

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        if chunk:
            if self._done:
                self._past_end(chunk)
            else:
                self._data = self._data[self._data_pos :] + chunk
                self._data_pos = 0
        if max_length < 0 or len(self._out) < max_length:
            self._limit = max_length
            self._run()
        return DecodeOut(self._hand_out(max_length))

    def flush(self) -> DecodeOut:
        self._eof = True
        self._limit = -1
        self._run()
        if self._truncation is not None:
            self._pending_error = TruncatedError(
                f"{truncated_message(self.label)} ({self._truncation})"
            )
        return DecodeOut(self._hand_out(-1))

    @property
    def finished(self) -> bool:
        return self._done and self._truncation is None and not self._out

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


class ShrinkDecoder(_BitDecoder):
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
        # The free slots, lowest first: "the lowest free slot" in one pop. A clear
        # frees only slots that were added, so every push is paid for by a code.
        free = list(range(_SHRINK_FIRST_FREE, _SHRINK_TABLE))
        # Pointers to each slot from other slots (an orphan's parent counts too, as
        # in 7-Zip), and the used slots above 256 that none points to: what a
        # partial clear frees. A clear then costs the slots it frees, not the
        # table's size, so a run of clears with no output stays cheap.
        children = [0] * _SHRINK_TABLE
        leaves: set[int] = set()
        width = 9
        prev = -1
        prev_first = 0
        size = self._unpack_size

        while size is None or self._produced < size:
            try:
                yield from self._need(width)
            except _InputEnded:
                if size is not None:
                    raise
                if self._nbits >= 8:
                    # A whole byte after the last code cannot be padding.
                    self._truncation = "the input ends inside a code"
                return
            code = self._take(width)
            if code == _SHRINK_CONTROL:
                if prev < 0:
                    raise CorruptionError("Shrink stream starts with a control code")
                try:
                    sub = yield from self._bits_value(width)
                except _InputEnded:
                    self._truncation = "the input ends inside a control code"
                    raise
                if sub == _SHRINK_WIDEN:
                    if width == _SHRINK_MAX_WIDTH:
                        raise CorruptionError(
                            "Shrink stream widens its codes past 13 bits"
                        )
                    width += 1
                elif sub == _SHRINK_PARTIAL_CLEAR:
                    freed = leaves
                    leaves = set()
                    for slot in freed:
                        used[slot] = 0
                        heapq.heappush(free, slot)
                        up = parent[slot]
                        if up > 255:
                            children[up] -= 1
                            # A parent the clear left a leaf goes at the next one.
                            if not children[up] and used[up]:
                                leaves.add(up)
                else:
                    raise CorruptionError(
                        f"Shrink stream has an unknown control code {sub}"
                    )
                continue

            new = -1
            if prev >= 0:
                if not free:
                    raise CorruptionError(
                        "Shrink stream's code table is full and was not cleared"
                    )
                new = heapq.heappop(free)
                # Its last byte is the first of this code's string: for a code that
                # names the entry itself (KwKwK), the first of the previous string.
                used[new] = 1
                parent[new] = prev
                suffix[new] = prev_first
                if prev > 255:
                    children[prev] += 1
                    leaves.discard(prev)
                if not children[new]:
                    leaves.add(new)
            elif code > 255:
                raise CorruptionError("Shrink stream starts with an undefined code")
            if not used[code]:
                raise CorruptionError(f"Shrink stream names the free code {code}")
            entry = bytearray()
            walk = code
            while walk > 255:
                if not used[walk] or len(entry) >= _SHRINK_TABLE:
                    raise CorruptionError(
                        "Shrink stream's code table links to a free code or loops"
                    )
                entry.append(suffix[walk])
                walk = parent[walk]
            entry.append(walk)
            entry.reverse()
            if new >= 0:
                suffix[new] = entry[0]
            prev = code
            prev_first = entry[0]
            self._emit(entry)
            yield from self._budget()


# --- Implode (method 6): LZ77 with Shannon-Fano coded literals, lengths, distances ---


def _read_tree(decoder: _BitDecoder, values: int) -> Generator[bool, None, dict]:
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


def _read_symbol(decoder: _BitDecoder, codes: dict) -> Generator[bool, None, int]:
    """Read one code of ``codes``, its first bit read being the code's highest."""
    acc = 0
    for length in range(1, 17):
        yield from decoder._need(1)
        acc = (acc << 1) | decoder._take(1)
        value = codes.get((length, acc))
        if value is not None:
            return value
    raise CorruptionError("Implode stream has a code its tree does not define")


class ImplodeDecoder(_BitDecoder):
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

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> ImplodeDecoder:
        del point, inner
        return ImplodeDecoder(
            self._unpack_size,
            large_window=self._large_window,
            literal_tree=self._literal_tree,
        )

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
