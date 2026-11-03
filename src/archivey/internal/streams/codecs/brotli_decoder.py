"""The Brotli decoder."""

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
    release_decoder,
)


class _BrotliDecompressor(Protocol):
    """The ``brotli.Decompressor`` methods this adapter calls.

    ``brotli`` is an optional extra with no stubs. ``can_accept_more_data`` /
    ``output_buffer_limit`` are brotli ≥1.2.0; the adapter probes for them at
    runtime (``_supports_output_limit``).
    """

    def process(self, data: bytes, output_buffer_limit: int = ...) -> bytes: ...
    def can_accept_more_data(self) -> bool: ...
    def is_finished(self) -> bool: ...


class BrotliDecoder(BaseDecoder):
    """Decode a raw Brotli stream via the ``brotli`` package's incremental decompressor.

    The decompressor comes from ``natives``: ``brotli`` is imported only in-process,
    being an optional dependency with no type stubs;
    ``BrotliCodec.open`` in the codec layer gates on its presence before constructing this, so
    the import here always succeeds.

    Brotli ≥1.2.0 exposes ``process(..., output_buffer_limit=)`` and
    ``can_accept_more_data()`` (CVE-2025-6176 mitigation). The limit is block-granular
    (observed floor ~32 KiB), not a hard byte cap, but it stops a single ``process``
    from materializing multi-megabyte bombs on ``read(1)``.

    **Finding the end.** ``brotli`` says nothing about where a stream ends: a call whose
    input runs past the end fails outright ("decoder failed"), loses that call's output,
    and leaves the decompressor unusable. The same failure is what corrupt data gives, so
    the decoder cannot tell the two apart from the error. It finds out by replaying:
    a fresh decompressor is brought to the last point where everything handed over had
    been decoded and delivered (``_settled``), by decoding the source from the start with
    the output discarded, and the input from there to the failure is then handed over one
    byte at a time. If the stream finishes on one of those bytes, what follows is trailing
    data and the output lost with the failed call is delivered; if not, the original
    error was corruption and is raised. The replay reads the source again, so it needs a
    seekable one; on a pipe the failure stays a ``CorruptionError``, and so do bytes
    that arrive after the end in a later call (:meth:`_bytes_after_end`). It costs one more
    decode up to the failure, paid only by a file with bytes after its stream or a corrupt
    one.
    """

    def __init__(
        self, inner: BinaryIO | None = None, natives: Natives = IN_PROCESS
    ) -> None:
        self._natives = natives
        self._errors = natives.brotli_errors()
        self._inner = inner
        self._decomp: _BrotliDecompressor = natives.brotli_decompressor()
        self._pending = b""
        # True while a prior budgeted process may still have output to drain via
        # process(b"", output_buffer_limit=…).
        self._drain_budgeted = False
        self._supports_output_limit = callable(
            getattr(self._decomp, "can_accept_more_data", None)
        )
        # Compressed bytes handed to process() so far, and the count at the last point
        # where all of them were decoded and their output returned, with the output
        # returned since then.
        self._handed = 0
        self._settled = 0
        self._out_since_settled = 0
        # During a replay: the bytes being handed over one at a time, the next one's
        # index, and how much of their output the caller already has.
        self._replay: bytes | None = None
        self._replay_at = 0
        self._replay_skip = 0
        self._replay_error: BaseException | None = None
        self._replay_draining = False
        self._ended = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> BrotliDecoder:
        del point
        return BrotliDecoder(inner, self._natives)

    def _process(self, data: bytes, max_length: int) -> bytes:
        try:
            if max_length >= 0 and self._supports_output_limit:
                out = self._decomp.process(data, output_buffer_limit=max_length)
            else:
                out = self._decomp.process(data)
        except self._errors as e:
            self._start_replay(self._handed + len(data), e)
            return b""
        self._handed += len(data)
        self._out_since_settled += len(out)
        # Even an unbounded call can hold output back; the decoder has caught up only
        # when a call returns nothing and it takes more input.
        if not self._supports_output_limit or (
            not out and self._decomp.can_accept_more_data()
        ):
            self._settled = self._handed
            self._out_since_settled = 0
        return out

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        if self._ended:
            self._bytes_after_end(chunk)
            return DecodeOut(b"")
        if self._replay is not None:
            self._pending += chunk
            return DecodeOut(self._continue_replay(max_length))
        data = self._pending + chunk
        self._pending = b""
        if max_length < 0 or not self._supports_output_limit:
            out = b""
            if self._supports_output_limit and (
                self._drain_budgeted or not self._decomp.can_accept_more_data()
            ):
                # A budgeted call left output owed; take it before any new input,
                # which the decompressor refuses until then.
                out = self._process(b"", -1)
            self._drain_budgeted = False
            if not data and not out and self._replay is None:
                return DecodeOut(b"")
            # A piece at a time, each drained until it settles, so a replay (below)
            # covers at most one piece.
            for start in range(0, len(data), _BROTLI_REPLAY_CHUNK):
                if self._replay is not None or self._decomp.is_finished():
                    self._pending = data[start:]
                    break
                produced = self._process(data[start : start + _BROTLI_REPLAY_CHUNK], -1)
                while produced and self._supports_output_limit:
                    out += produced
                    produced = self._process(b"", -1)
                out += produced
        else:
            can_accept = bool(self._decomp.can_accept_more_data())
            if not can_accept:
                # Limit reached on a prior call: only empty process is legal until
                # can_accept_more_data() flips true again.
                self._pending = data
                out = self._process(b"", max_length)
            elif data:
                out = self._process(data, max_length)
            elif self._drain_budgeted:
                out = self._process(b"", max_length)
            else:
                return DecodeOut(b"")
        if self._replay is not None:
            remaining = max_length if max_length < 0 else max_length - len(out)
            return DecodeOut(out + self._continue_replay(remaining))
        finished = bool(self._decomp.is_finished())
        if finished:
            # Whatever is still waiting was read past the end; the stream decides what
            # it is. (Handing it to the finished decompressor would fail.)
            self._ended = True
            pending, self._pending = self._pending, b""
            self._bytes_after_end(pending)
        # Keep draining while output is flowing or the decoder refuses more input.
        self._drain_budgeted = (
            self._supports_output_limit
            and max_length >= 0
            and not finished
            and (len(out) > 0 or not bool(self._decomp.can_accept_more_data()))
        )
        return DecodeOut(out)

    def _bytes_after_end(self, data: bytes) -> None:
        """Account for ``data``, which came after the stream's end.

        A replay can tell such bytes from damage only on a source it can read again.
        On one it cannot, bytes that reach ``brotli`` in the same call as the end fail
        that call, and there is no telling them from damage. Whether they do depends
        only on where a read of the source happened to end, so bytes that arrive in a
        later call fail the same way, with the error ``brotli`` gives the combined
        call. A pipe then gives one verdict however its writes arrive.
        """
        inner = self._inner
        if data and (inner is None or not inner.seekable()):
            # The combined call's error, from a fresh decompressor: an empty stream,
            # then the first byte after it.
            try:
                self._natives.brotli_decompressor().process(_EMPTY_STREAM + data[:1])
            except self._errors as error:
                raise error from None
        self._past_end(data)

    def _start_replay(self, failed_end: int, error: BaseException) -> None:
        """Rebuild the state at ``_settled`` and queue the bytes up to ``failed_end``."""
        inner = self._inner
        if inner is None or not inner.seekable():
            raise error
        position = inner.tell()
        decomp: _BrotliDecompressor = self._natives.brotli_decompressor()
        try:
            inner.seek(0)
            remaining = self._settled
            while remaining:
                chunk = inner.read(min(remaining, _BROTLI_REPLAY_CHUNK))
                if not chunk:
                    raise error
                remaining -= len(chunk)
                self._discard(decomp, chunk)
            # Read the whole region even when the source returns short reads (a probe
            # sample serves 4 KiB per read). A short region would end the replay early
            # and report the original error for a stream that only had bytes after it.
            parts: list[bytes] = []
            wanted = failed_end - self._settled
            while wanted:
                chunk = inner.read(wanted)
                if not chunk:
                    break
                parts.append(chunk)
                wanted -= len(chunk)
            region = b"".join(parts)
        except BaseException:
            release_decoder(decomp)
            raise
        finally:
            inner.seek(position)
        release_decoder(self._decomp)
        self._decomp = decomp
        self._replay = region
        self._replay_at = 0
        self._replay_skip = self._out_since_settled
        self._replay_error = error
        self._drain_budgeted = False

    def _discard(self, decomp: _BrotliDecompressor, chunk: bytes) -> None:
        """Hand ``chunk`` to ``decomp`` and drop the output, a bounded piece at a time.

        Drains it fully, so ``decomp`` ends where the original did at ``_settled``.
        """
        if not self._supports_output_limit:
            decomp.process(chunk)
            return
        decomp.process(chunk, output_buffer_limit=_BROTLI_REPLAY_CHUNK)
        while True:
            out = decomp.process(b"", output_buffer_limit=_BROTLI_REPLAY_CHUNK)
            if not out and decomp.can_accept_more_data():
                return

    def _continue_replay(self, max_length: int) -> bytes:
        assert self._replay is not None
        assert self._replay_error is not None
        region = self._replay
        limited = self._supports_output_limit
        limit = _BROTLI_REPLAY_CHUNK if max_length < 0 else max_length
        out = bytearray()
        while max_length < 0 or len(out) < max_length:
            if limited and (
                self._replay_draining or not self._decomp.can_accept_more_data()
            ):
                # Output owed for bytes already in: take it before the next byte,
                # which may be the first one past the end.
                produced = self._decomp.process(b"", output_buffer_limit=limit)
                self._replay_draining = bool(produced)
            elif self._decomp.is_finished():
                # The stream ended on the last byte handed over: the rest is not part
                # of it, nor is anything the stream read after it.
                self._replay = None
                self._ended = True
                self._past_end(region[self._replay_at :] + self._pending)
                self._pending = b""
                break
            elif self._replay_at < len(region):
                byte = region[self._replay_at : self._replay_at + 1]
                self._replay_at += 1
                try:
                    if limited:
                        produced = self._decomp.process(byte, output_buffer_limit=limit)
                        self._replay_draining = bool(produced)
                    else:
                        produced = self._decomp.process(byte)
                except self._errors:
                    # Damage before the stream could end: the original failure stands.
                    raise self._replay_error from None
            else:
                produced = (
                    self._decomp.process(b"", output_buffer_limit=limit)
                    if limited
                    else b""
                )
                if not produced:
                    # Every byte up to the failure went in and the stream did not
                    # end: the failure was damage, not bytes after the end.
                    raise self._replay_error
            if self._replay_skip:
                dropped = min(self._replay_skip, len(produced))
                self._replay_skip -= dropped
                produced = produced[dropped:]
            out.extend(produced)
        return bytes(out)

    def flush(self) -> DecodeOut:
        if self._ended:
            return DecodeOut(b"")
        # Brotli decodes eagerly; there is nothing buffered to flush at EOF.
        if not self.finished:
            self._pending_error = TruncatedError("File is truncated")
        return DecodeOut(b"")

    @property
    def finished(self) -> bool:
        return self._ended or (
            self._replay is None and bool(self._decomp.is_finished())
        )

    @property
    @override
    def needs_input(self) -> bool:
        if self._ended:
            return True
        if self._replay is not None:
            return False
        if self._pending:
            return False
        if self._supports_output_limit and not bool(
            self._decomp.can_accept_more_data()
        ):
            return False
        return not self._drain_budgeted


# Bytes handed to, and output taken from, the Brotli decompressor per call while a
# replay rebuilds its state (see BrotliDecoder).
_BROTLI_REPLAY_CHUNK = 65536
# A complete Brotli stream with no output (``brotli.compress(b"")``).
_EMPTY_STREAM = b";"


def BrotliDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    collector: DiagnosticCollector | None = None,
    report_trailing_data: bool = False,
    refuse_input_after_end: bool = False,
    natives: Natives = IN_PROCESS,
) -> DecompressorStream:
    """Decode a raw Brotli stream (forward-only)."""
    return DecompressorStream(
        path,
        make_decoder=lambda _p, inner: BrotliDecoder(inner, natives),
        collector=collector,
        codec_name="brotli",
        report_trailing_data=report_trailing_data,
        refuse_input_after_end=refuse_input_after_end,
    )
