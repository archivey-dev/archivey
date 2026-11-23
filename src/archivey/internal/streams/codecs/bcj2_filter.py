"""BCJ2 (7-Zip's four-stream x86 branch converter, 7z method ``0x0303011B``) as a
stream over its four input streams.

The decoder is :func:`archivey.internal.kernels.bcj2`'s: archivey-codecs' when it is
installed and allowed, else the Python one in
:mod:`archivey.internal.kernels.python.bcj2`, which describes the format. Both give the
same bytes and errors.
"""

from __future__ import annotations

import io
from collections.abc import Sequence
from typing import TYPE_CHECKING, BinaryIO

from archivey.internal import kernels
from archivey.internal.overrides import override
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    is_seekable,
    resolve_seek,
)

if TYPE_CHECKING:
    from archivey.internal.kernels import Bcj2Decompressor
    from archivey.types import OptionalLibrary

# Output is decoded a ``main`` block at a time, and a forward seek skips at most this
# much at a time, so a long skip does not hold the whole gap in memory.
_BLOCK = 64 * 1024


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
        excluded: frozenset[OptionalLibrary],
        isolated: bool,
        owns_inputs: Sequence[bool] = (True, True, True, True),
    ) -> None:
        super().__init__()
        self._make = kernels.bcj2(excluded, isolated=isolated).Decompressor
        self._owned = [
            stream
            for stream, owned in zip((main, call, jump, rc), owns_inputs, strict=True)
            if owned
        ]
        self._inputs = (main, call, jump, rc)
        self._seekable = all(is_seekable(stream) for stream in self._inputs)
        self._size = unpack_size
        self._start_decoding()

    def decoder_layers_below(self) -> tuple[BinaryIO, ...]:
        """The four input streams, for ``retire_decoder_children``: each may be a
        decoder of its own."""
        return self._inputs

    def _start_decoding(self) -> None:
        """Start a decoder at the start of the output."""
        main, call, jump, rc = self._inputs
        self._d: Bcj2Decompressor = self._make(
            main, call, jump, rc, out_size=self._size
        )
        # A position at or past the end that seek() reached without decoding to it.
        self._past_end: int | None = None
        # Output a read decoded before it raised, returned by the next reads.
        self._held = b""

    @override
    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if n is None or n < 0:
            return self.readall()
        if self._past_end is not None:
            return b""
        out, self._held = self._held[:n], self._held[n:]
        if len(out) == n:
            return out
        # Full count: ``n`` bytes unless the output ends. The decoder decodes a
        # block at a time, returns the bytes before an error first and raises it on
        # the next call. An error found while decoding the blocks this read needed
        # raises from this read; the bytes before it are kept for the next reads,
        # which raise it again once they need more output.
        decoded = self._d.decoded
        try:
            while len(out) < n and self._d.total_out < self._size:
                more = self._d.read(n - len(out))
                if not more:
                    break
                out += more
            if self._d.decoded != decoded:
                if self._d.decoded == self._size and self._d.total_out < self._size:
                    # The last block is decoded: take the rest of it, so the end
                    # check, which runs with the read that returns the last byte,
                    # runs here.
                    out += self._d.read(self._size - self._d.total_out)
                # An error the decoder met in the blocks this read decoded raises
                # here.
                self._d.read(0)
            if self._d.total_out == self._size and not self._d.eof:
                # All the output is returned, but the end check has not passed: the
                # output is empty, so no read returned a last byte to run it with,
                # or the check failed. A read past the end runs it, or raises its
                # error again.
                out += self._d.read(1)
        except BaseException:  # an interrupt too: the decoder keeps it as its failure
            # Keep every byte decoded before the error, those the decoder still
            # holds too: they are returned before the error raises again.
            ahead = self._d.decoded - self._d.total_out
            if ahead > 0:
                out += self._d.read(ahead)
            self._held = out
            raise
        out, self._held = out[:n], out[n:]
        return out

    @override
    def seekable(self) -> bool:
        return self._seekable

    @override
    def tell(self, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._past_end is not None:
            return self._past_end
        return self._d.total_out - len(self._held)

    @override
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
        # Decode and discard up to ``target``, a block at a time at most.
        while (skip := target - self.tell()) > 0:
            if not self.read(min(skip, _BLOCK)):
                break
        return target

    def nearest_resume_offset(self, target: int) -> int:
        """Decoding can only start at offset 0: BCJ2 keeps no seek points."""
        return 0

    @override
    def close(self) -> None:
        if self.closed:
            return
        try:
            for stream in self._owned:
                stream.close()
        finally:
            super().close()
