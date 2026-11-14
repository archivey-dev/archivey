"""bzip2 one block at a time: the standard library's ``bz2`` behind a decompressor that
hands out a block's bytes only once the block's CRC has passed.

**Why.** A bzip2 block is one Burrows-Wheeler transform with its own CRC-32. ``bz2``
checks that CRC only once the block's last byte is out, so a plain decode hands out a
damaged block's bytes, in 32 KiB pieces, before it raises. Those bytes are of no use:
the inverse transform scrambles the whole block, so one flipped bit anywhere leaves at
most a byte or two of it right. :class:`Bzip2BlockDecompressor` holds each block's
output until ``bz2`` has checked it, and drops the output of a block that fails. Every
byte it hands out has passed its block's CRC, and an error comes only after every good
byte before it (``holds_back_errors``).

**Where blocks start.** A block starts with a 48-bit magic, at any bit offset, and the
stream ends with another 48-bit magic, each followed by a 32-bit CRC: the block's, or
the combined CRC of the stream. Nothing else gives a block's length, so the input is
scanned for both magics (:func:`find_markers`). A match can also lie inside a block's
data. To tell, the input is fed to ``bz2`` up to the match, and the output is drained
(``decompress(b"")`` until it returns nothing). A block decodes only once all its bits
are in, so output there means the block before the match ended at it: the match is a
real block start. No output means it was inside the block, and the scan goes on. A bzip2
block always decodes to at least one byte (``bz2`` refuses an empty one), so the test
cannot miss a block. Between matches no more input is fed than ends before the first
byte a match not found yet can start at, so no block can end unseen there.

**A damaged marker.** When the bytes after a block are no marker, ``bz2`` checks the
block and refuses those bytes in the same call, and that call's output is lost. The
block is then decoded again, fed up to its end only, so its checked bytes still come
out before the error (:meth:`~Bzip2BlockDecompressor._recover_block`).

**Seek points.** A block carries no state from the blocks before it, so a decode can
start at any block start: :meth:`~Bzip2BlockDecompressor.take_block_starts` lists the
blocks checked so far, and :meth:`~Bzip2BlockDecompressor.resume` starts at one.
``bz2`` reads a stream, not a block, and whole bytes, so a resumed decode gives it a
made-up stream header with the stream's level digit, then the input shifted left by
the block's bit offset into its first byte.

**The end of the stream.** The end-of-stream marker is never fed to ``bz2``: its
combined CRC folds in every block's CRC, and a resumed decode has not seen the blocks
before its start. This module checks it instead, from the CRC in each block's header,
carried in the seek point for a resumed decode (:class:`Bzip2BlockStart`). A point
whose combined CRC is not known (``None``), or was read from an accelerator's index and
does not match (the rapidgzip takeover's points), raises
:class:`ResumeReachedStreamEnd` at the end of the stream instead, and its caller
decodes from the start, which checks it.

**Cost.** The scan reads the input once more, and is a few percent of the decode (4.9
MB of input scanned in 0.04 s, decoded in 1.2 s). Holding a block holds its whole
output: about 900 KB for ordinary data at level 9, and at most 46.6 MB
(:data:`MAX_BLOCK_OUTPUT`) for a block of runs that bzip2's first run-length stage
expands almost 52 times. That output counts against
``DecoderLimits.max_decoder_memory`` as it grows: a block whose held output passes the
cap raises ``ResourceLimitError``.
"""

from __future__ import annotations

import bz2
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from archivey.exceptions import CorruptionError, ResourceLimitError
from archivey.internal.config import decoder_cap_error
from archivey.internal.streams.resume import ResumeReachedStreamEnd

if TYPE_CHECKING:
    from archivey.formats import Decompressor

# The 48-bit magic numbers that start a block and the end-of-stream marker. Each is
# followed by a 32-bit CRC: the block's, or the stream's combined CRC.
BLOCK_MAGIC = 0x314159265359
EOS_MAGIC = 0x177245385090
# A marker: the magic and its CRC.
MARKER_BITS = 80
_MAGIC_BITS = 48
# ``BZh`` and the level digit, ``1`` to ``9`` (the block size in units of 100 000).
STREAM_HEADER = b"BZh"
HEADER_BITS = 32
# The most a block can decode to: 900 000 symbols at level 9, which bzip2's first
# run-length stage turns back into at most 259 bytes for every 5 (a run of 4 and a
# count of 255). ``bz2`` enforces the block size; this is what holding a block costs.
MAX_BLOCK_OUTPUT = 9 * 100_000 // 5 * 259


# The output one ``bz2`` call is asked for while feeding and draining. CPython's
# ``decompress`` with no limit grows its buffer as it goes and was about 35% slower on a
# 5 MB stream than calls of 1 MiB (3.11, 0.97 s against 0.70 s); 32 KiB calls cost more
# calls. The drain asks again until a call returns nothing.
_DRAIN_CALL = 1 << 20
# The slices a block is fed in to find where it ends (``_recover_block``): the bytes
# of the last one are then fed one at a time.
_RECOVER_SLICE = 4096


@dataclass(frozen=True, slots=True)
class Bzip2BlockStart:
    """A :class:`~archivey.internal.streams.decompressor_stream.SeekPoint` state: a
    block that starts ``bit`` bits (0 to 7) into the byte at the point's compressed
    offset, in a stream whose header gives ``level`` (1 to 9). ``combined`` is the
    stream's combined CRC over the blocks before this one, or ``None`` when it is not
    known (module docstring).

    ``from_index``: ``combined`` was read from the block headers an accelerator's index
    lists, not from blocks this decoder checked. Should a block be missing from that
    index, the end-of-stream CRC fails for a reason the resumed decode cannot see, so a
    mismatch hands back to a decode from the start (``ResumeReachedStreamEnd``), which
    gives the verdict."""

    bit: int
    level: int
    combined: int | None
    from_index: bool = False


def rotate_combined(combined: int, block_crc: int) -> int:
    """The stream's combined CRC once a block with ``block_crc`` is added."""
    return (((combined << 1) | (combined >> 31)) & 0xFFFFFFFF) ^ block_crc


def _patterns() -> list[tuple[int, int, bytes]]:
    """For each magic and each bit offset ``s`` (0 to 7) it can start at in a byte, the
    five whole bytes it covers from the byte after the one it starts in: a match at
    index ``i`` of the data is a candidate at bit ``(i - 1) * 8 + s``."""
    found = []
    for magic in (BLOCK_MAGIC, EOS_MAGIC):
        for shift in range(8):
            window = (magic << (56 - _MAGIC_BITS - shift)).to_bytes(7, "big")
            found.append((magic, shift, window[1:6]))
    return found


_PATTERNS = _patterns()


def marker_at(data: bytes | bytearray, bit: int) -> tuple[int, int] | None:
    """The 48-bit magic and the 32-bit CRC after it, at bit ``bit`` of ``data``;
    ``None`` when ``data`` ends first."""
    first = bit // 8
    shift = bit % 8
    raw = bytes(data[first : first + 11])
    if len(raw) * 8 < shift + MARKER_BITS:
        return None
    field = (int.from_bytes(raw, "big") >> (len(raw) * 8 - shift - MARKER_BITS)) & (
        (1 << MARKER_BITS) - 1
    )
    return field >> 32, field & 0xFFFFFFFF


def find_markers(
    data: bytes | bytearray, first_bit: int, end_bit: int
) -> list[tuple[int, int, int]]:
    """Every block or end-of-stream marker of ``data`` that starts at a bit in
    ``[first_bit, end_bit)`` and ends inside ``data``, as ``(bit, magic, crc)``, in
    order."""
    hits: dict[int, tuple[int, int]] = {}
    low = max(0, first_bit // 8)
    for magic, shift, pattern in _PATTERNS:
        index = data.find(pattern, low)
        while index != -1:
            bit = (index - 1) * 8 + shift
            if bit >= end_bit:
                break
            if bit >= first_bit and bit not in hits:
                marker = marker_at(data, bit)
                if marker is not None and marker[0] == magic:
                    hits[bit] = marker
            index = data.find(pattern, index + 1)
    return [(bit, *hits[bit]) for bit in sorted(hits)]


class Bzip2BlockDecompressor:
    """One bzip2 stream, behind the one-stream decompressor interface, with each
    block's output held until its CRC passes (module docstring).

    ``new_bz2`` builds the ``bz2`` decompressor, in this process or in a child
    (``process_isolation``). ``memory_cap`` is ``DecoderLimits.max_decoder_memory``:
    a block whose held output grows past it is refused. Input positions here are bits
    from the first byte this decompressor was given. The input buffer keeps the bytes
    from the last one fed on, plus what is not fed yet.
    """

    # A failed block raises only once every byte before it is handed out: see
    # ``Decoder.holds_back_errors``.
    holds_back_errors = True
    # Every byte handed out passed its block's CRC (``checked_spans``).
    checks_output = True

    def __init__(
        self,
        new_bz2: Callable[[], Decompressor] = bz2.BZ2Decompressor,
        *,
        memory_cap: int | None = None,
    ) -> None:
        self._new_bz2 = new_bz2
        self._memory_cap = memory_cap
        self._bz2: Decompressor | None = None
        self._input = bytearray()
        # The bit offset of ``_input[0]``, always a whole byte.
        self._input_bit = 0
        # The made-up header a resumed decode feeds ahead of its first input.
        self._prefix = b""
        # Bits fed to ``bz2`` so far: every bit before this one. After the header it
        # moves in whole bytes from the first block's bit offset (``_shift``).
        self._fed = 0
        self._shift = 0
        # Every marker that starts before this bit and ends inside the input so far is
        # in ``_candidates`` or was dealt with.
        self._scanned = 0
        self._candidates: deque[tuple[int, int, int]] = deque()
        # Where the first marker is: right after the header, or a resumed block.
        self._first_marker: int | None = HEADER_BITS
        self._level: int | None = None
        # The block being decoded: its start and its stored CRC; ``None`` when no
        # block start is known (before the first marker, or after output came where
        # no marker was, which only a damaged block header leads to).
        self._block: tuple[int, int] | None = None
        # The combined CRC of the blocks checked so far; ``None`` when not known.
        self._combined: int | None = 0
        self._resumed = False
        self._from_index = False
        # Output checked and not handed out yet.
        self._ready = memoryview(b"")
        # Output bytes checked so far, from where this decompressor started.
        self._decoded = 0
        self._block_starts: list[tuple[int, int, object]] = []
        # The input ended (``end_input``): everything left may be fed.
        self._input_ended = False
        self._ended = False
        self.unused_data = b""
        # An error met after output this call hands out: the next call raises it.
        self._raise_after: BaseException | None = None
        # A call stopped at its output budget with input it can still decode.
        self._has_work = False

    # -- the decompressor interface ---------------------------------------------------

    def resume(self, state: object) -> None:
        """Start at the block ``state`` (a :class:`Bzip2BlockStart`) names: the input
        begins at the byte that holds its first bit."""
        assert isinstance(state, Bzip2BlockStart)
        assert self._fed == 0 and not self._input
        self._resumed = True
        self._shift = state.bit
        self._fed = state.bit
        self._scanned = state.bit
        self._first_marker = state.bit
        self._level = state.level
        self._combined = state.combined
        self._from_index = state.from_index
        self._prefix = STREAM_HEADER + str(state.level).encode()

    def take_block_starts(self) -> list[tuple[int, int, object]]:
        """The blocks checked since the last call: each block's compressed and output
        offsets from this decompressor's start, and the state :meth:`resume` takes
        (``BlockResumable``)."""
        starts, self._block_starts = self._block_starts, []
        return starts

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._raise_after is not None and not self._ready:
            raise self._raise_after
        if data:
            self._input += data
        out = bytearray()
        self._has_work = False
        try:
            while True:
                self._hand_out(out, max_length)
                if self._ready or (max_length >= 0 and len(out) >= max_length):
                    self._has_work = not self._ended
                    break
                if self._ended or self._raise_after is not None or not self._step():
                    break
        except Exception as exc:
            # The block that failed was held, so nothing of it is out. The blocks
            # checked before it are handed out first, this call and the next ones.
            if not out and not self._ready:
                raise
            self._raise_after = exc
            self._hand_out(out, max_length)
        return bytes(out)

    def _hand_out(self, out: bytearray, max_length: int) -> None:
        """Move checked output into ``out``, up to ``max_length`` in all."""
        if self._ready:
            room = len(self._ready) if max_length < 0 else max_length - len(out)
            out += self._ready[:room]
            self._ready = self._ready[room:]

    @property
    def eof(self) -> bool:
        return self._ended and not self._ready

    @property
    def needs_input(self) -> bool:
        return (
            self._raise_after is None
            and not self._ready
            and not self._ended
            and not self._has_work
        )

    def end_input(self) -> None:
        """The input ended: what is left of it may be fed. Output this frees comes
        from the next ``decompress(b"")``; a stream with no end-of-stream marker reads
        as truncated there (``FramedDecoder.flush``)."""
        self._input_ended = True
        self._has_work = True

    # -- one step ---------------------------------------------------------------------

    def _input_end(self) -> int:
        return self._input_bit + 8 * len(self._input)

    def _step(self) -> bool:
        """Decode up to the next marker, or as far as the input allows. Return whether
        anything moved, so the caller asks again."""
        if self._level is None and not self._read_header():
            return False
        if self._first_marker is not None:
            return self._read_first_marker()
        self._scan()
        if self._candidates:
            bit, magic, crc = self._candidates.popleft()
            self._at_candidate(bit, magic, crc)
            return True
        return self._feed_safe()

    def _read_header(self) -> bool:
        """Check ``BZh`` and the level digit of a stream decoded from its start."""
        head = bytes(self._input[:4])
        expected = STREAM_HEADER
        if head[:3] != expected[: len(head[:3])] or (
            len(head) == 4 and not 0x31 <= head[3] <= 0x39
        ):
            # Not a bzip2 stream header: ``bz2`` raises its own error on it, as a plain
            # decode would.
            self._feed_all(refuse=True)
        if len(head) < 4:
            if self._input_ended:
                self._feed_all(refuse=False)
            return False
        self._level = head[3] - 0x30
        return True

    def _read_first_marker(self) -> bool:
        """Read the marker right after the header, or at a resumed block's start."""
        first = self._first_marker
        assert first is not None
        marker = marker_at(self._input, first - self._input_bit)
        if marker is None:
            if self._input_ended:
                # The stream ends inside its first marker: feed it, so ``bz2`` raises
                # what it raises there, or the stream reads as truncated.
                self._feed_all(refuse=False)
            return False
        magic, crc = marker
        self._first_marker = None
        self._scanned = first + MARKER_BITS
        if magic == BLOCK_MAGIC:
            self._block = (first, crc)
            return True
        if magic == EOS_MAGIC and not self._resumed:
            # A stream with no blocks: its combined CRC is that of no blocks.
            self._end_stream(first, crc)
            return True
        # Neither magic: ``bz2`` refuses the bytes there.
        self._feed_all(refuse=True)
        return True

    def _scan(self) -> None:
        """Queue the markers that start from ``_scanned`` and end inside the input."""
        end = self._input_end()
        last = end - MARKER_BITS + 1
        if last <= self._scanned:
            return
        found = find_markers(
            self._input, self._scanned - self._input_bit, last - self._input_bit
        )
        self._candidates.extend(
            (self._input_bit + bit, magic, crc) for bit, magic, crc in found
        )
        self._scanned = last

    def _at_candidate(self, bit: int, magic: int, crc: int) -> None:
        """Feed up to the marker at ``bit`` and drain: output there means the block
        before it ended there."""
        out = self._feed_block_to(bit)
        if not out:
            return  # inside the block: not a block start
        self._block_checked(out)
        if magic == BLOCK_MAGIC:
            self._block = (bit, crc)
            return
        self._end_stream(bit, crc)

    def _feed_safe(self) -> bool:
        """With no marker queued, feed what ends before any marker not found yet can
        start, so no block can end unseen; at the end of the input, feed everything."""
        if self._input_ended:
            if self._fed >= self._input_end():
                return False
            out = self._feed_block_to(self._input_end())
        else:
            # A marker not found yet starts at ``_scanned`` or later. A block ends
            # where the next marker starts, so feeding only bits before ``_scanned``
            # leaves any such block short of its end. ``_feed_to`` rounds up to whole
            # bytes from ``_fed``.
            target = self._fed + (self._scanned - 1 - self._fed) // 8 * 8
            if target <= self._fed:
                return False
            out = self._feed_block_to(target)
        if out:
            # Output with no marker after it: the input ended right after the block.
            # Its bytes passed their CRC; no point is kept.
            self._end_block(out)
        return True

    def _feed_block_to(self, bit: int) -> bytearray:
        """:meth:`_feed_to`, and when ``bz2`` raises, the block being decoded handed
        out before the error if it is whole.

        The error can come after the block's end: the block ended in this feed and the
        bytes after it are no marker (a damaged block header), so ``bz2`` checked the
        block, then refused those bytes, in one call, and the call's output is gone.
        The block is decoded again up to its end only (:meth:`_recover_block`).
        """
        try:
            return self._feed_to(bit)
        except OSError:
            # ``bz2``'s error for data it refuses, in this process or in a child.
            out = self._recover_block()
            if out is None:
                raise
            self._end_block(out)
            raise

    def _end_block(self, out: bytearray) -> None:
        """Release the block that gave ``out`` with no marker after it: its bytes
        passed their CRC, but no block follows it, so no point is kept and the
        combined CRC is no longer known."""
        self._block = None
        self._combined = None
        self._release(out)

    def _recover_block(self) -> bytearray | None:
        """The output of the block being decoded, which ends before ``_fed`` and is
        followed by bytes that are no marker; ``None`` when the block itself is
        damaged.

        A fresh ``bz2`` is given the block alone, behind a made-up stream header, so
        it never reaches the bytes after it. ``bz2`` gives a block's output only once
        all its bits are in, and checks the CRC in that same call, so output with no
        error is the whole block, checked. The block's end is not known: a first
        decode feeds it ``_RECOVER_SLICE`` bytes at a time and finds the slice where
        ``bz2`` raises; a second feeds everything before that slice at once, then
        the slice one byte at a time, so the call that completes the block holds at
        most 7 bits after it, too few for ``bz2`` to read the next header.
        """
        block, level = self._block, self._level
        if block is None or level is None:
            return None
        start = block[0]
        header = STREAM_HEADER + str(level).encode()
        data = header + self._bits(start, -(-(self._fed - start) // 8))
        try:
            decomp = self._new_bz2()
            for at in range(0, len(data), _RECOVER_SLICE):
                try:
                    out = self._drain(decomp, data[at : at + _RECOVER_SLICE])
                except Exception:  # noqa: BLE001 - the slice the block ends in
                    break
                if out:
                    return out
            else:
                return None
            decomp = self._new_bz2()
            if self._drain(decomp, data[:at]):
                return None  # the block ended before the slice, and bz2 raised
            for i in range(at, min(at + _RECOVER_SLICE, len(data))):
                out = self._drain(decomp, data[i : i + 1])
                if out:
                    return out
        except ResourceLimitError:
            raise
        except Exception:  # noqa: BLE001 - not whole: the first error stands
            return None
        return None

    def _feed_to(self, bit: int) -> bytearray:
        """Feed ``bz2`` every bit before ``bit`` (in whole bytes from ``_fed``), then
        drain it; return the output, which has passed its CRC."""
        count = max(0, -(-(bit - self._fed) // 8))
        data = self._bits(self._fed, count)
        self._fed += 8 * count
        self._drop_fed()
        decomp = self._decoder()
        if self._prefix:
            data, self._prefix = self._prefix + data, b""
        return self._drain(decomp, data)

    def _drain(self, decomp: Decompressor, data: bytes) -> bytearray:
        """Feed ``data`` to ``decomp`` and take all the output it gives for it."""
        out = bytearray(decomp.decompress(data, _DRAIN_CALL))
        while True:
            more = decomp.decompress(b"", _DRAIN_CALL)
            if not more:
                break
            out += more
            self._check_held(len(out))
        return out

    def _check_held(self, held: int) -> None:
        """Refuse a block whose output, held until its CRC passes, is over the cap."""
        cap = self._memory_cap
        if cap is not None and held > cap:
            raise decoder_cap_error(
                f"Decoder limit reached: max_decoder_memory={cap} (a bzip2 block's "
                f"output, held until its CRC passes, passed {held} bytes; a block can "
                f"decode to at most {MAX_BLOCK_OUTPUT}). Raise "
                "DecoderLimits.max_decoder_memory if the archive is trusted.",
                cap=cap,
                needed=None,
            )

    def _bits(self, start: int, count: int) -> bytes:
        """``count`` bytes of the input from bit ``start``, zero-padded past its end."""
        first = (start - self._input_bit) // 8
        shift = (start - self._input_bit) % 8
        if not shift:
            return bytes(self._input[first : first + count])
        raw = bytes(self._input[first : first + count + 1]).ljust(count + 1, b"\x00")
        value = (int.from_bytes(raw, "big") << shift) & ((1 << (8 * (count + 1))) - 1)
        return value.to_bytes(count + 1, "big")[:count]

    def _drop_fed(self) -> None:
        """Drop the input bytes no marker read or feed needs again."""
        keep = min(self._fed, self._scanned)
        if self._block is not None:
            # The block being decoded is decoded again from its start when the bytes
            # after it are no marker (``_recover_block``).
            keep = min(keep, self._block[0])
        keep_from = (keep - self._input_bit) // 8
        if keep_from > 0:
            del self._input[:keep_from]
            self._input_bit += 8 * keep_from

    def _decoder(self) -> Decompressor:
        if self._bz2 is None:
            self._bz2 = self._new_bz2()
        return self._bz2

    def _feed_all(self, *, refuse: bool) -> None:
        """Hand ``bz2`` all the input, for bytes it refuses or that end the input
        short, so its own error is the verdict. When ``refuse`` (the bytes are no
        stream header or no marker) and it raises nothing, refuse them here."""
        self._feed_to(self._input_end())
        self._candidates.clear()
        self._scanned = self._fed
        if refuse:
            raise CorruptionError("bzip2 stream is corrupt: no block starts here")

    def _block_checked(self, out: bytearray) -> None:
        """The block being decoded passed its CRC and gave ``out``: keep its start as a
        seek point, fold its CRC into the combined one, and release its bytes."""
        block = self._block
        if block is not None:
            start, crc = block
            assert self._level is not None
            self._block_starts.append(
                (
                    start // 8,
                    self._decoded,
                    Bzip2BlockStart(start % 8, self._level, self._combined),
                )
            )
            if self._combined is not None:
                self._combined = rotate_combined(self._combined, crc)
        self._release(out)

    def _release(self, out: bytearray) -> None:
        self._ready = memoryview(out)
        self._decoded += len(out)

    def _end_stream(self, bit: int, crc: int) -> None:
        """The end-of-stream marker at ``bit``: check its combined CRC, and keep what
        follows its last byte as ``unused_data``."""
        if self._combined is None:
            if self._resumed:
                # The blocks before this decode's start are not known: the caller
                # decodes from the start, which checks the CRC.
                raise ResumeReachedStreamEnd
            raise CorruptionError(
                "bzip2 stream is corrupt: a block before its end-of-stream marker "
                "does not start with a block header"
            )
        if crc != self._combined:
            if self._from_index:
                raise ResumeReachedStreamEnd
            raise CorruptionError(
                "bzip2 stream is corrupt: the combined CRC in the end-of-stream "
                f"marker is {crc:#010x}, but the stream's blocks combine to "
                f"{self._combined:#010x}"
            )
        end = -(-(bit + MARKER_BITS) // 8) * 8
        self.unused_data = bytes(self._input[(end - self._input_bit) // 8 :])
        self._ended = True
        self._input.clear()
        self._candidates.clear()
