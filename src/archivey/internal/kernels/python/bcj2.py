"""BCJ2 in Python, as ``archivey_speedups.bcj2``: 7-Zip's four-stream x86 branch
converter (7z method ``0x0303011B``).

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

import operator
import struct
from typing import Protocol

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.kernels.python._buffers import raw_bytes

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

    def __init__(self, stream: _Counted) -> None:
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

    def left(self) -> int:
        """Bytes read from the stream and not used yet."""
        return len(self._buf) - self._pos


class _Targets:
    """The ``call`` or ``jump`` stream: big-endian 32-bit targets, a block at a time.

    Each block is unpacked into ints in one ``struct`` call, so :meth:`next` is an
    iterator step. A read that ends mid-target carries its tail into the next block.
    """

    __slots__ = ("_carry", "_stream", "_words", "label")

    def __init__(self, stream: _Counted, label: str) -> None:
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

    def left(self) -> int:
        """Bytes read from the stream and not used yet."""
        return 4 * operator.length_hint(self._words) + len(self._carry)

    def has_more(self) -> bool:
        """Whether any byte is left. Reads at most one byte from the stream."""
        return (
            operator.length_hint(self._words) > 0
            or bool(self._carry)
            or bool(self._stream.read(1))
        )


class _Counted:
    """An input stream and the bytes its reads returned."""

    __slots__ = ("_read", "count")

    def __init__(self, stream: _Readable) -> None:
        self._read = stream.read
        self.count = 0

    def read(self, n: int) -> bytes:
        data = raw_bytes(self._read(n))
        if len(data) > n:
            raise ValueError(f"read({n}) returned {len(data)} bytes")
        self.count += len(data)
        return data


class _Readable(Protocol):
    def read(self, n: int, /) -> bytes | bytearray | memoryview: ...


class Decompressor:
    """7-Zip's BCJ2 x86 filter: four input streams (``main``, ``call``, ``jump``,
    ``rc``) give one output of exactly ``out_size`` bytes, read with :meth:`read`.

    The streams are objects with ``read(n)``. An input that ends before the output is
    complete raises :class:`TruncatedError` naming the stream, and bytes left in
    ``main``, ``call`` or ``jump`` after the last output byte raise
    :class:`CorruptionError`. The bytes decoded before an error are returned first;
    the error comes with the next call, and every call after it. Nothing is allocated
    from ``out_size``.
    """

    __slots__ = (
        "_call",
        "_checked",
        "_code",
        "_failure",
        "_jump",
        "_left",
        "_main",
        "_main_stream",
        "_mpos",
        "_out_size",
        "_pending",
        "_pending_pos",
        "_prev",
        "_probs",
        "_range",
        "_rc",
        "_streams",
        "total_out",
    )

    def __init__(
        self,
        main: _Readable,
        call: _Readable,
        jump: _Readable,
        rc: _Readable,
        *,
        out_size: int,
    ) -> None:
        self._streams = tuple(_Counted(s) for s in (main, call, jump, rc))
        self._main_stream = self._streams[0]
        self._main = b""
        self._mpos = 0
        self._call = _Targets(self._streams[1], "call")
        self._jump = _Targets(self._streams[2], "jump")
        self._rc = _RangeCoderInput(self._streams[3])
        self._out_size = out_size
        self._left = out_size  # output bytes not decoded yet
        # Decoded output not yet returned, from ``_pending_pos`` on.
        self._pending = bytearray()
        self._pending_pos = 0
        self._probs = [_PROB_INIT] * 258
        self._prev = 0
        self._range = 0xFFFFFFFF
        self._code: int | None = None  # read lazily: an empty output needs no rc bytes
        self._checked = False  # the end check passed
        # The error that stopped decoding: any, ``KeyboardInterrupt`` too, as the
        # package keeps it. A step it stopped is half done, so nothing decodes after.
        self._failure: BaseException | None = None
        self.total_out = 0

    @property
    def eof(self) -> bool:
        """True once all ``out_size`` bytes are returned and the end check passed."""
        return self._checked and self._pending_pos == len(self._pending)

    @property
    def out_size(self) -> int:
        return self._out_size

    @property
    def decoded(self) -> int:
        """Output bytes decoded so far, returned or not: a read decodes to the end of
        a ``main`` block, so this runs ahead of ``total_out``."""
        return self._out_size - self._left

    @property
    def total_in(self) -> tuple[int, int, int, int]:
        """Bytes used from each stream: (main, call, jump, rc)."""
        main, call, jump, rc = (s.count for s in self._streams)
        return (
            main - (len(self._main) - self._mpos),
            call - self._call.left(),
            jump - self._jump.left(),
            rc - self._rc.left(),
        )

    def read(self, max_length: int = -1) -> bytes:
        """Up to ``max_length`` bytes of output (all of it when negative); ``b""`` at
        the end. ``read(0)`` decodes nothing and reads no input: it raises an error
        the decoder holds, else returns ``b""``."""
        if max_length == 0:
            if self._failure is not None:
                raise self._failure
            return b""
        want = -1 if max_length < 0 else max_length
        result = bytearray()
        while True:
            pending, pos = self._pending, self._pending_pos
            n = (
                len(pending) - pos
                if want < 0
                else min(len(pending) - pos, want - len(result))
            )
            result += pending[pos : pos + n]
            self._pending_pos = pos + n
            self.total_out += n
            if (0 <= want <= len(result)) or self._checked:
                break
            if self._failure is not None:
                if not result:
                    raise self._failure
                break
            self._step()
        # The read that returns the last output byte also runs the end check, so
        # ``eof`` is true after it; an error from the check is raised by the next call.
        if (
            not self._checked
            and self._failure is None
            and not self._left
            and self._pending_pos == len(self._pending)
        ):
            self._step()
            if not result and self._failure is not None:
                raise self._failure
        return bytes(result)

    def _step(self) -> None:
        """Decode the next ``main`` block, or at the end of the output run the end
        check; an error is kept for :meth:`read` to raise."""
        try:
            if not self._left:
                self._check_inputs_finished()
                self._checked = True
                return
            if self._pending_pos:
                del self._pending[: self._pending_pos]
                self._pending_pos = 0
            self._decode_block()
        except BaseException as exc:  # noqa: BLE001 - an input's own error, an interrupt
            self._failure = exc

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
        # The output position of pending[0].
        start = self._out_size - self._left - len(pending)
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
