"""The Deflate64 decoder (inflate64)."""

from __future__ import annotations

import os
from typing import BinaryIO, Protocol

from archivey.exceptions import TruncatedError
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    SeekPoint,
    truncated_message,
)


class _Inflate64Inflater(Protocol):
    """The ``inflate64.Inflater`` methods this adapter calls.

    Declared here because ``inflate64`` is an optional extra with no stubs.
    """

    def inflate(self, data: bytes) -> bytes: ...

    @property
    def eof(self) -> bool: ...


class Deflate64Decoder(BaseDecoder):
    """Decode a Deflate64 stream via ``inflate64.Inflater``.

    ``inflate64`` has no output-size parameter: one ``inflate`` of a small
    highly-compressible feed can still allocate the full expansion. When the
    stream passes ``max_length >= 0``, feed compressed input in small steps
    (see ``_BUDGETED_FEED``) and retain any overshoot in ``_pending_out`` so
    ``read(n)`` peak buffers stay near the caller's budget.

    Feed-size tradeoff on a 100 MiB zeros Deflate64 bomb (per-call max_out /
    throughput): 1→514 B / ~320 MiB/s; 64→19 KiB / ~700 MiB/s; 256→70 KiB /
    ~710 MiB/s; 64 KiB→18 MiB / ~460 MiB/s. 64 keeps peaks under a 64 KiB
    read budget while recovering most of the speed of larger feeds.

    ``inflate64`` drops input after the end of the stream without a word: it has no
    ``unused_data``, and an ``inflate`` after ``eof`` returns ``b""``. Its ``eof`` turns
    True only once the stream's last byte is in, so the last byte of the input so far
    is held back (``_last``) until more input or ``flush`` comes. When ``eof`` is
    already True by then, that byte and anything after it lie past the end, and
    :meth:`_past_end` accounts for them, as :class:`ZlibDecoder` does with
    ``unused_data``. Input after the end inside the same ``inflate`` call is not
    counted, so :attr:`trailing_bytes` can be low; whether any input follows the end
    is exact.
    """

    # Compressed bytes per inflate() under a max_length budget. See class docstring.
    _BUDGETED_FEED = 64

    def __init__(self, natives: Natives = IN_PROCESS) -> None:
        self._natives = natives
        self._decomp: _Inflate64Inflater = natives.inflater()
        self._pending = b""
        self._pending_out = b""
        # The last input byte, held back from inflate64 (see the class docstring).
        self._last = b""

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Deflate64Decoder:
        del point, inner
        return Deflate64Decoder(self._natives)

    def _inflate(self, data: bytes) -> bytes:
        if self._decomp.eof:
            self._past_end(data)
            return b""
        return self._decomp.inflate(data)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        data = self._pending + self._last + chunk
        self._pending = b""
        self._last = data[-1:]
        data = data[:-1]
        if max_length < 0:
            if self._pending_out:
                data = self._pending_out + (self._inflate(data) if data else b"")
                self._pending_out = b""
                return DecodeOut(data)
            if not data:
                return DecodeOut(b"")
            return DecodeOut(self._inflate(data))

        out = bytearray()
        if self._pending_out:
            take = min(len(self._pending_out), max_length)
            out += self._pending_out[:take]
            self._pending_out = self._pending_out[take:]
            if len(out) >= max_length:
                self._pending = data
                return DecodeOut(bytes(out))

        step = self._BUDGETED_FEED
        while data and len(out) < max_length:
            produced = self._inflate(data[:step])
            data = data[step:]
            room = max_length - len(out)
            if len(produced) > room:
                out += produced[:room]
                self._pending_out = produced[room:]
                break
            out += produced
        self._pending = data
        return DecodeOut(bytes(out))

    def flush(self) -> DecodeOut:
        data = self._pending + self._last
        self._pending = self._last = b""
        out = self._pending_out
        self._pending_out = b""
        if data:
            out += self._inflate(data)
        if not self._decomp.eof:
            # Flush remaining state with an empty feed (mirrors py7zr's
            # Deflate64Decompressor).
            out += self._decomp.inflate(b"")
        if not self.finished:
            self._pending_error = TruncatedError(truncated_message("deflate64"))
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return bool(self._decomp.eof) and not self._pending_out

    @property
    @override
    def needs_input(self) -> bool:
        return not self._pending and not self._pending_out


def Deflate64DecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    refuse_input_after_end: bool = False,
    collector: DiagnosticCollector | None = None,
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Decode a Deflate64 stream (forward-only)."""
    return DecompressorStream(
        path,
        make_decoder=lambda _p, _i: Deflate64Decoder(natives),
        codec_name="deflate64",
        collector=collector,
        refuse_input_after_end=refuse_input_after_end,
    )
