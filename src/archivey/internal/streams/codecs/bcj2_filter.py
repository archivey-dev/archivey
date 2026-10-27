"""BCJ2 decoder: 7-Zip's four-stream x86 branch converter (7z method ``0x0303011B``).

The encoder splits an executable into four streams, stored as four separate 7z pack
streams:

- **main**: every byte of the output except the 4-byte targets it moved out;
- **call**: big-endian absolute targets of converted ``E8`` (CALL rel32);
- **jump**: big-endian absolute targets of converted ``E9`` (JMP rel32) and ``0F 8x``
  (Jcc rel32);
- **rc**: one range-coded bit per branch candidate: was this one converted?

Decoding copies ``main`` up to and including the next candidate opcode, decodes one
bit, and on a 1 takes a target from ``call`` or ``jump``, turns it back into a
relative one (``target - (position + 4)``) and emits it little-endian. The bit's
probability model has 258 contexts: one per preceding byte for ``E8``, one for ``E9``,
one for ``Jcc``. The range coder is LZMA's (11-bit probabilities, 5 move bits, a
5-byte start). Its five start bytes are read with the first output byte, so an empty
output reads no ``rc`` byte at all (9.20 reads them first; the output is the same). When
the start is read, it is refused as 7-Zip 23.01's ``Bcj2Dec_Decode`` refuses it: a nonzero
first byte, which no encoder writes, or a code of ``0xFFFFFFFF``. A folder with no output
never reads it, so refuses nothing there. The decoding itself is 7-Zip 9.20's
``Bcj2_Decode`` (``C/Bcj2.c``); later 7-Zip restructured the code, not the format.

Where the time goes. The Python loop runs once per *candidate* (``E8``, ``E9``,
``0F 8x``), not per byte; real x86 code has one every 30 bytes or so, and a hostile
``main`` made of nothing else is the worst case. Two choices keep that loop cheap,
both measured on 7-Zip ``-mx9`` archives of ``git`` and ``python3.11`` (CPython 3.11):

- Candidates are found with two ``bytes.find`` calls over a translated copy of the
  block (``_MARK`` folds ``E9`` onto ``E8`` and ``80``-``8F`` onto ``80``), which run at
  memchr speed. A regex character class (``[\\xe8\\xe9]|\\x0f[\\x80-\\x8f]``) finds the
  same positions but scans byte by byte in ``re``'s engine, and on ``git`` that scan
  alone cost as much as the rest of the loop.
- ``call`` and ``jump`` are unpacked a block at a time into ints (``_Targets``), so a
  converted branch costs one iterator step. Slicing four bytes and calling
  ``int.from_bytes`` for each target was three times slower per target.

Together they doubled the stage's speed (about 13 to 26 MB/s on ``git``, 17 to 33 MB/s
on ``python3.11``) without changing what the decoder refuses.
"""

from __future__ import annotations

import io
import operator
import struct
from collections.abc import Sequence
from typing import BinaryIO

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    is_seekable,
    resolve_seek,
)

# Every input is read in blocks of this size. Output is produced a main block at a
# time, so a read never holds more than one block's expansion (at most 5x, when every
# main byte is a converted E8).
_BLOCK = 64 * 1024

# Candidate search table: E9 reads as E8 and 80..8F read as 80, so ``find(b"\xe8")``
# finds both CALL and JMP, and ``find(b"\x0f\x80")`` finds every Jcc. Every other byte
# maps to itself, which can create no false match: only E8/E9 become E8, and only
# 80..8F become 80.
_MARK = bytes(
    0xE8 if b == 0xE9 else 0x80 if 0x80 <= b <= 0x8F else b for b in range(256)
)

_TOP = 1 << 24
_NUM_MOVE_BITS = 5
_PROB_INIT = 1024  # half of 1 << 11
_E9_CONTEXT = 256
_JCC_CONTEXT = 257
_PACK_LE32 = struct.Struct("<I").pack


class _RangeCoderInput:
    """The ``rc`` stream, read a byte at a time out of block-sized reads.

    The decoder takes one ``rc`` byte per eight or so decoded bits, so this is off the
    hot path.
    """

    __slots__ = ("_buf", "_pos", "_stream")

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._buf = b""
        self._pos = 0

    def byte(self) -> int:
        if self._pos == len(self._buf):
            self._buf = self._stream.read(_BLOCK)
            self._pos = 0
            if not self._buf:
                raise TruncatedError("BCJ2 range coder stream ended early")
        b = self._buf[self._pos]
        self._pos += 1
        return b


class _Targets:
    """The ``call`` or ``jump`` stream: big-endian 32-bit targets, a block at a time.

    Each block is unpacked into ints in one ``struct`` call, so :meth:`next` is an
    iterator step. A read that ends mid-target carries its tail into the next block.
    """

    __slots__ = ("_carry", "_stream", "_words", "label")

    def __init__(self, stream: BinaryIO, label: str) -> None:
        self._stream = stream
        self.label = label
        self._words = iter(())
        self._carry = b""

    def next(self) -> int:
        word = next(self._words, None)
        if word is None:
            self._unpack_block()
            word = next(self._words)
        return word

    def _unpack_block(self) -> None:
        data = self._carry
        while len(data) < 4:  # a short read may hold less than one target
            chunk = self._stream.read(_BLOCK)
            if not chunk:
                break
            data += chunk
        whole = len(data) - len(data) % 4
        if not whole:
            raise TruncatedError(f"BCJ2 {self.label} stream ended early")
        self._words = iter(struct.unpack(f">{whole // 4}I", data[:whole]))
        self._carry = data[whole:]

    def has_more(self) -> bool:
        """Whether any byte is left. Reads at most one byte from the stream."""
        return (
            operator.length_hint(self._words) > 0
            or bool(self._carry)
            or bool(self._stream.read(1))
        )


class Bcj2DecoderStream(ReadOnlyIOStream):
    """BCJ2 decode of ``unpack_size`` bytes from four input streams.

    Owns its inputs unless ``owns_inputs`` says otherwise: :meth:`close` closes the
    owned ones. Seekable when all four inputs are: BCJ2 keeps no seek points, so a
    backward seek rewinds every input to its start and decodes forward again, and a
    forward seek decodes and discards.

    Refuses rather than guesses (design D5 of the change that added it): an input that
    ends before the declared output is complete raises :class:`TruncatedError` naming
    the stream, and bytes left in ``main``, ``call`` or ``jump`` after the last output
    byte raise :class:`CorruptionError`. Nothing is allocated from ``unpack_size``.
    """

    # What close() reads, set before __init__ runs anything that can raise.
    _owned: Sequence[BinaryIO] = ()

    def __init__(
        self,
        main: BinaryIO,
        call: BinaryIO,
        jump: BinaryIO,
        rc: BinaryIO,
        *,
        unpack_size: int,
        owns_inputs: Sequence[bool] = (True, True, True, True),
    ) -> None:
        super().__init__()
        self._owned = [
            stream
            for stream, owned in zip((main, call, jump, rc), owns_inputs, strict=True)
            if owned
        ]
        self._inputs = (main, call, jump, rc)
        self._seekable = all(is_seekable(stream) for stream in self._inputs)
        self._size = unpack_size
        self._main_stream = main
        self._start_decoding()

    def _start_decoding(self) -> None:
        """Set every piece of decode state to the start of the output."""
        _, call, jump, rc = self._inputs
        self._main = b""
        self._mpos = 0
        self._call = _Targets(call, "call")
        self._jump = _Targets(jump, "jump")
        self._rc = _RangeCoderInput(rc)
        self._produced = 0
        self._left = self._size
        self._pending = bytearray()
        self._probs = [_PROB_INIT] * 258
        self._prev = 0
        self._range = 0xFFFFFFFF
        self._code: int | None = None  # read lazily: an empty output needs no rc bytes
        self._checked_end = False
        # A position at or past the end that seek() reached without decoding to it.
        self._past_end: int | None = None

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if n is None or n < 0:
            return self.readall()
        if self._past_end is not None:
            return b""
        while len(self._pending) < n and self._left:
            self._decode_block()
        if not self._left and not self._checked_end:
            self._checked_end = True
            self._check_inputs_finished()
        out = bytes(self._pending[:n])
        del self._pending[:n]
        return out

    def _decode_block(self) -> None:
        """Decode to the end of the current ``main`` block, or to the end of the output."""
        if self._code is None:
            code = 0
            for _ in range(5):
                code = (code << 8) | self._rc.byte()
            # 7-Zip 23.01 refuses both: an encoder always writes 0 first, and a code
            # of 0xFFFFFFFF cannot come out of one.
            if code >> 32 or code == 0xFFFFFFFF:
                raise CorruptionError("BCJ2 range coder stream has an invalid start")
            self._code = code
        main, mpos = self._main, self._mpos
        if mpos == len(main):
            main = self._main_stream.read(_BLOCK)
            mpos = 0
            if not main:
                raise TruncatedError("BCJ2 main stream ended early")
        pending = self._pending
        start = self._produced - len(pending)  # output position of pending[0]
        left = self._left
        prev, probs, rng, code = self._prev, self._probs, self._range, self._code
        next_call, next_jump, rc_byte = self._call.next, self._jump.next, self._rc.byte

        end = len(main)
        find = main.translate(_MARK).find
        next_e8 = find(b"\xe8", mpos)  # next E8 or E9 opcode
        if next_e8 < 0:
            next_e8 = end
        # The next Jcc opcode, the byte after its 0F. A miss is find() == -1, which the
        # + 1 turns into 0, a falsy value, so ``or`` substitutes ``end``; a 0F at the
        # block start (find() == 0) becomes 1, which is truthy, so it still counts.
        next_jcc = find(b"\x0f\x80", mpos) + 1 or end
        try:
            while True:
                if prev == 0x0F and mpos < end and (main[mpos] & 0xF0) == 0x80:
                    # A Jcc whose 0F is the last byte of the previous block, or the top
                    # byte of a converted target: the search cannot see that 0F.
                    pos = mpos
                elif next_e8 == end and next_jcc == end:
                    chunk = main[mpos : mpos + left]
                    if chunk:
                        pending += chunk
                        left -= len(chunk)
                        mpos += len(chunk)
                        prev = chunk[-1]
                    return
                elif next_e8 < next_jcc:
                    pos = next_e8
                    next_e8 = find(b"\xe8", pos + 1)
                    if next_e8 < 0:
                        next_e8 = end
                else:
                    pos = next_jcc
                    next_jcc = find(b"\x0f\x80", pos + 1) + 1 or end  # as above

                copied = pos + 1 - mpos
                if copied >= left:
                    # The output ends at (or before) this opcode: no bit follows it.
                    pending += main[mpos : mpos + left]
                    mpos += left
                    left = 0
                    return
                b = main[pos]
                if b == 0xE8:
                    # The byte before the opcode is ``prev`` when nothing of main was
                    # copied before it: after a converted target, or at a block start.
                    context = main[pos - 1] if pos != mpos else prev
                else:
                    context = _E9_CONTEXT if b == 0xE9 else _JCC_CONTEXT
                pending += main[mpos : pos + 1]
                left -= copied
                mpos = pos + 1

                if rng < _TOP:
                    rng = (rng << 8) & 0xFFFFFFFF
                    code = ((code << 8) | rc_byte()) & 0xFFFFFFFF
                p = probs[context]
                bound = (rng >> 11) * p
                if code < bound:
                    rng = bound
                    probs[context] = p + ((2048 - p) >> _NUM_MOVE_BITS)
                    prev = b
                    continue
                rng -= bound
                code -= bound
                probs[context] = p - (p >> _NUM_MOVE_BITS)

                target = next_call() if b == 0xE8 else next_jump()
                dest = (target - (start + len(pending) + 4)) & 0xFFFFFFFF
                if left <= 4:
                    # 7-Zip truncates a target that runs past the declared size; so
                    # do we. The member CRC catches a hostile one.
                    pending += _PACK_LE32(dest)[:left]
                    left = 0
                    return
                pending += _PACK_LE32(dest)
                left -= 4
                prev = dest >> 24
        finally:
            self._main, self._mpos, self._prev = main, mpos, prev
            self._range, self._code = rng, code
            self._produced += self._left - left
            self._left = left

    def _check_inputs_finished(self) -> None:
        """Refuse bytes left in ``main``, ``call`` or ``jump`` after the last output byte.

        Their lengths follow from the same conversion decisions as the output, so a
        leftover means the four streams disagree. Reads **at most one byte** from each
        input and never drains one: ``main`` is a decoder whose declared size comes
        from the archive, and bytes decoded here never reach the folder stream that
        extraction limits count. ``rc`` is not checked: older encoders' tails are
        unmeasured (design D5, open question 1).
        """
        if self._mpos < len(self._main) or self._main_stream.read(1):
            raise CorruptionError(
                "BCJ2 main stream has bytes past the end of the output"
            )
        for targets in (self._call, self._jump):
            if targets.has_more():
                raise CorruptionError(
                    f"BCJ2 {targets.label} stream has bytes past the end of the output"
                )

    def seekable(self) -> bool:
        return self._seekable

    def tell(self, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._past_end is not None:
            return self._past_end
        return self._produced - len(self._pending)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        """Move to ``offset``. Backward re-decodes from the start; forward decodes on.

        A position at or past the end is recorded without decoding up to it, as a
        file would, and reads there return nothing.
        """
        here = self.tell()
        if not self._seekable:
            raise io.UnsupportedOperation("seek")
        target = resolve_seek(offset, whence, pos=here, end=lambda: self._size)
        if target >= self._size:
            self._past_end = target
            return target
        # A seek to the end decoded nothing, so the decoder is still where it was.
        self._past_end = None
        if target < self.tell():
            for stream in self._inputs:
                stream.seek(0)
            self._start_decoding()
        # Decode and discard up to ``target``, one main block at a time at most.
        while (skip := target - self.tell()) > 0:
            if not self._pending:
                self._decode_block()
            del self._pending[:skip]
        return target

    def nearest_resume_offset(self, target: int) -> int:
        """Decoding can only start at offset 0: BCJ2 keeps no seek points."""
        return 0

    def close(self) -> None:
        if self.closed:
            return
        try:
            for stream in self._owned:
                stream.close()
        finally:
            self._pending = bytearray()
            super().close()
