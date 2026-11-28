"""Unix ``compress`` (``.Z``) in Python, as ``archivey_speedups.lzw``: the
:class:`lzma.LZMADecompressor` interface plus ``flush()``, since the format has no end
marker. The decoder is
:class:`archivey.internal.streams.codecs.unix_compress_decoder.LzwState`; this class
gives it the package's API, a port of the package's ``LzwDecompressor`` wrapper.
"""

from __future__ import annotations

from archivey.exceptions import CorruptionError
from archivey.internal.kernels.python._buffers import raw_bytes

# Bytes of a ``.Z`` header: the magic and the flags byte.
_HEADER = 3


class Decompressor:
    """An LZW stream decoder. ``max_width`` and ``block_mode`` describe a stream
    without its 3-byte header (both or neither); ``nine_bit_widens`` fixes the layout
    a full 9-bit table takes (``None``: probe the stream).

    ``max_length`` bounds what each call returns, ``flush()`` included. A bad code
    after some output returns the bytes decoded before it, and the error raises from
    the next call."""

    __slots__ = (
        "_clear_at",
        "_clear_offsets",
        "_fed",
        "_flushed",
        "_header_in_stream",
        "_held",
        "_state",
        "total_out",
    )

    def __init__(
        self,
        *,
        max_width: int | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> None:
        from archivey.internal.streams.codecs.unix_compress_decoder import (
            LzwState,
        )

        # As in the package, ``max_width`` needs ``block_mode``, and a lone
        # ``block_mode`` is ignored (the header is read from the stream).
        if max_width is not None and block_mode is None:
            raise ValueError(
                "give block_mode with max_width (a stream without its header)"
            )
        if max_width is not None and not 9 <= max_width <= 16:
            raise ValueError("max_width is outside 9 to 16")
        self._state = LzwState(
            max_width=max_width,
            block_mode=block_mode if max_width is not None else None,
            nine_bit_widens=nine_bit_widens,
        )
        # Output decoded past the last call's ``max_length``.
        self._held = memoryview(b"")
        self._flushed = False
        self._header_in_stream = max_width is None
        # Where the last CLEAR's segment ends: (input, output) offsets.
        self._clear_at = (0, 0)
        self._clear_offsets: list[tuple[int, int]] = []
        self._fed = 0  # bytes passed to decompress()
        self.total_out = 0

    # ── Properties ───────────────────────────────────────────────────────────────────

    @property
    def eof(self) -> bool:
        return self._flushed and self._state.is_finished() and not self._held

    @property
    def needs_input(self) -> bool:
        return not self._flushed and not self._held and self._state.needs_input

    @property
    def unused_data(self) -> bytes:
        # The stream ends where its input ends: nothing follows it.
        return b""

    @property
    def truncation(self) -> str | None:
        """After ``flush()``, what showed that the stream was cut short, else
        ``None``."""
        return self._state.truncation

    @property
    def header_params(self) -> tuple[int, bool] | None:
        """The header's maximum code width and block mode, once read (or as given)."""
        return self._state.header_params

    @property
    def nine_bit_widens(self) -> bool | None:
        return self._state.nine_bit_widens

    @property
    def clear_offsets(self) -> list[tuple[int, int]]:
        """The CLEAR codes the last call passed, as (input offset, output offset)
        pairs counted as ``total_in`` and ``total_out`` count: where a decoder made
        with this stream's ``header_params`` can start with a fresh dictionary. Each
        call reports only its own."""
        return list(self._clear_offsets)

    @property
    def total_in(self) -> int:
        """Input bytes used: those passed in, less what the decoder holds undecoded."""
        return self._fed - self._state.held_input

    # ── Decoding ─────────────────────────────────────────────────────────────────────

    def decompress(
        self, data: bytes | bytearray | memoryview, max_length: int = -1
    ) -> bytes:
        if self.eof:
            raise EOFError("End of stream already reached")
        if self._flushed:
            raise ValueError("decompress() after flush()")
        data = raw_bytes(data)
        self._clear_offsets = []
        first: list[tuple[int, int]] = []
        if data:
            state = self._state
            self._fed += len(data)
            if self._held:
                # Output from an earlier call is still owed: queue the input and
                # decode no more until it drains.
                state.queue(data)
            else:
                # A feed with no room decodes at most one entry: mostly it queues.
                out, units = state.feed(data, 0)
                self._held = memoryview(out)
                self._note_units(units)
            first = self._clear_offsets
            self._clear_offsets = []
        out = self._produce(max_length)
        self._clear_offsets = first + self._clear_offsets
        return out

    def close(self) -> None:
        """Nothing to give back: this decoder runs in this process."""

    def flush(self, max_length: int = -1) -> bytes:
        """Mark the end of the input and return the rest of the output, at most
        ``max_length`` bytes a call; ``eof`` is true once all of it is returned."""
        self._flushed = True
        return self._produce(max_length)

    def _note_units(self, units: list[tuple[int, int]]) -> None:
        if (
            self._clear_at == (0, 0)
            and self._header_in_stream
            and self._state.header_params is not None
        ):
            self._clear_at = (_HEADER, 0)
        comp, decomp = self._clear_at
        for unit_decomp, unit_comp in units:
            comp += unit_comp
            decomp += unit_decomp
            self._clear_offsets.append((comp, decomp))
        self._clear_at = (comp, decomp)

    def _step(self, budget: int) -> bytes:
        """One decoder step: decode under ``budget``, or after ``flush()`` with less
        than one code left, run the final pass."""
        state = self._state
        if self._flushed and state.needs_input:
            out, units = state.flush()
        else:
            before = state.held_input
            out, units = state.feed(b"", budget)
            if self._flushed and not out and state.held_input == before:
                # Nothing moved: what is left is the final pass's to finish.
                more, more_units = state.flush()
                out, units = more, units + more_units
        self._note_units(units)
        return out

    def _produce(self, max_length: int) -> bytes:
        """Up to ``max_length`` bytes: held output first, then what the decoder
        decodes."""
        want = -1 if max_length < 0 else max_length
        self._clear_offsets = []
        parts: list[bytes] = []
        got = 0
        state = self._state
        while True:
            held = self._held
            if held:
                n = len(held) if want < 0 else min(len(held), want - got)
                parts.append(bytes(held[:n]))
                got += n
                self._held = held[n:]
            if 0 <= want <= got:
                break
            done = state.is_finished() if self._flushed else state.needs_input
            if done:
                break
            try:
                more = self._step(-1 if want < 0 else want - got)
            except CorruptionError:
                if got:
                    # The bytes before the error come first; it raises again next.
                    break
                raise
            self._held = memoryview(more)
            if not more and not self._flushed:
                break
        out = b"".join(parts)
        self.total_out += len(out)
        return out
