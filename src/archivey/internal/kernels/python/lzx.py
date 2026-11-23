"""LZX in Python, as ``archivey_codecs.lzx``: one LZX stream (a CAB folder) with the
:class:`lzma.LZMADecompressor` interface, plus ``flush()`` and ``set_output_size()``.

The decoder is :class:`archivey.internal.streams.codecs.lzx_decoder.LzxDecoder` in push
mode; this class gives it the package's API, a port of the package's
``LzxDecompressor`` wrapper.
"""

from __future__ import annotations

from archivey.exceptions import ArchiveyError


class Decompressor:
    """An LZX stream decoder. Output comes in frames of 32 KiB, the last one shorter;
    the frame length sets where the input realigns, so the decoder must know the
    stream's output size: give it with ``output_size`` or, once known, with
    :meth:`set_output_size` before the last frame ends. Without one every frame is
    32 KiB, and the stream ends where its input does.

    The input has no end marker: :meth:`flush` marks its end, and decodes the rest
    with the zero padding lzxd.c reads. A frame the input does not cover then raises
    ``TruncatedError``. The bytes decoded before an error come first; the error raises
    from the next call, and from every call after it.
    """

    __slots__ = (
        "_d",
        "_ended",
        "_failed",
        "_finished",
        "_out",
        "_out_pos",
        "_output_size",
        "_starved",
        "total_out",
    )

    def __init__(self, window_bits: int, *, output_size: int | None = None) -> None:
        from archivey.internal.streams.codecs.lzx_decoder import (
            LzxDecoder,
        )

        self._d = LzxDecoder(window_bits)
        self._output_size = output_size
        # The last frame decoded, returned from ``_out_pos`` on.
        self._out = b""
        self._out_pos = 0
        self._ended = False  # flush() was called
        self._finished = False  # without an output size, the input ended at a frame
        self._starved = True  # the frame in progress waits for input
        self._failed: ArchiveyError | None = None
        self.total_out = 0

    # ── Properties ───────────────────────────────────────────────────────────────────

    @property
    def output_size(self) -> int | None:
        return self._output_size

    @property
    def eof(self) -> bool:
        return self._drained() and self._at_end() and not self._pad_pending()

    @property
    def needs_input(self) -> bool:
        if self._failed is not None or self._ended or not self._drained():
            return False
        if self._at_end():
            return self._pad_pending()
        return self._starved

    def _pad_pending(self) -> bool:
        """The output is complete, but the stream still owes the pad byte of an odd
        uncompressed block and no input holds it yet: the stream does not end until
        it arrives, or until ``flush()`` says it never will."""
        return (
            not self._ended
            and self._d.owes_pad_byte()
            and not self._d.unread_input
        )

    def _drained(self) -> bool:
        return self._out_pos == len(self._out)

    def _at_end(self) -> bool:
        return self._finished or self._output_size == self._d.decoded

    # ── Decoding ─────────────────────────────────────────────────────────────────────

    def set_output_size(self, output_size: int) -> None:
        """Give the declared output size once it is known, before the last frame
        ends."""
        from archivey.internal.streams.codecs.lzx_decoder import (
            FRAME_SIZE,
        )

        d = self._d
        decoded = d.decoded
        if output_size < decoded:
            raise ValueError(
                f"an output size of {output_size}, below the {decoded} bytes already "
                "decoded"
            )
        progress = d.frame_in_progress()
        if progress is not None:
            size, done = progress
            frame = min(output_size - decoded, FRAME_SIZE)
            if frame == done and self._failed is not None:
                # The output ends where the frame got to: the error was met in input
                # after the stream.
                self._failed = None
            if frame != size and not d.resize_frame(frame):
                raise ValueError(
                    f"an output size of {output_size}, below the {decoded + done} "
                    "bytes already decoded"
                )
        self._output_size = output_size
        # The frame that waited for input may now be shorter: try it again.
        self._starved = False

    def decompress(
        self, data: bytes | bytearray | memoryview, max_length: int = -1
    ) -> bytes:
        if self.eof:
            raise EOFError("End of stream already reached")
        if self._ended:
            raise ValueError("decompress() after flush()")
        # After a decode error the input is of no use: the call gives the output
        # before the error, then raises it.
        if data and self._failed is None:
            self._d.feed(bytes(data))
            self._starved = False
        return self._run(max_length)

    def flush(self, max_length: int = -1) -> bytes:
        """Mark the end of the input and return the rest of the output, at most
        ``max_length`` bytes a call; a frame the input still does not cover raises
        ``TruncatedError``."""
        if not self._ended:
            self._ended = True
            self._d.end()
            self._starved = False
        return self._run(max_length)

    def _next_frame(self) -> int | None:
        """The size of the next frame to decode, or ``None`` at the end."""
        from archivey.internal.streams.codecs.lzx_decoder import (
            FRAME_SIZE,
        )

        d = self._d
        if self._output_size is not None:
            left = self._output_size - d.decoded
            return min(left, FRAME_SIZE) if left > 0 else None
        # A stream ends between blocks, at a frame: one that ends inside a block is
        # cut. A frame in progress may hold all its input in the bit buffer.
        if (
            self._ended
            and not d.unread_input
            and d.frame_in_progress() is None
            and not d.inside_block()
        ):
            self._finished = True
            return None
        return FRAME_SIZE

    def _run(self, max_length: int) -> bytes:
        want = -1 if max_length < 0 else max_length
        parts: list[bytes] = []
        got = 0
        while True:
            if self._failed is not None and self._drained() and not got:
                raise self._failed
            out, pos = self._out, self._out_pos
            n = len(out) - pos if want < 0 else min(len(out) - pos, want - got)
            if n:
                parts.append(out[pos : pos + n])
                got += n
                self._out_pos = pos + n
            if 0 <= want <= got:
                break
            frame = self._next_frame()
            if frame is None or self._failed is not None:
                break
            # The decoder keeps its place when the input runs out, so a try with no
            # new input would only run out again.
            if self._starved and not self._ended:
                break
            try:
                decoded = self._d.try_frame(frame)
            except ArchiveyError as exc:
                self._failed = exc
                if not got:
                    raise
                break
            if decoded is None:
                self._starved = True
                break
            self._out, self._out_pos = decoded, 0
            self._starved = False
        result = b"".join(parts)
        self.total_out += len(result)
        return result
