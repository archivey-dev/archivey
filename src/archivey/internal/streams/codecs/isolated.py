"""Where a codec gets its native decoder objects: this process, or a child process.

Every native decoder construction in the codec layer goes through a :class:`Natives`,
picked by :func:`natives_for` from ``ArchiveyConfig.process_isolation``. In-process it
builds the library's own object; under ``NATIVE_DECODERS`` it builds a proxy with the
same surface whose decoder lives in a child process (``codecs/decoder_child.py``). The
proxy forwards each call with its arguments unchanged, so a codec's per-library details
(zlib's ``max_length=0`` meaning "no limit", the others' ``-1``) stay where they are.

The libraries that re-enable the GIL on a free-threaded build (brotli, inflate64,
pyppmd) are never imported here when isolated: their exception types have stand-ins
(:class:`BrotliChildError`, :class:`PpmdChildError`) that the codecs catch and
translate alongside the real ones.
"""

from __future__ import annotations

import lzma
import zlib
from collections.abc import Mapping
from typing import Any, Protocol

from archivey.config import ProcessIsolation
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.decoder_child import (
    DecoderChild,
    DecoderChildStartError,
    decoder_child_unavailable_reason,
    isolation_error,
)
from archivey.internal.streams.native_memory import note_native_memory


class Decompressor(Protocol):
    """The one-stream decompressor surface of ``bz2``, ``lzma``, zstd and
    ``lz4.frame``, in-process or in a child."""

    def decompress(self, data: bytes, max_length: int = ...) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...


class ZlibDecompressor(Protocol):
    """``zlib.decompressobj()``'s surface, in-process or in a child."""

    def decompress(self, data: bytes, max_length: int = ..., /) -> bytes: ...

    def flush(self, length: int = ..., /) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    @property
    def unconsumed_tail(self) -> bytes: ...


class BrotliChildError(ValueError):
    """Stand-in for ``brotli.error`` raised by a brotli decoder in a child process."""


class PpmdChildError(ValueError):
    """Stand-in for ``pyppmd.PpmdError`` raised by a PPMd decoder in a child process.

    A ``ValueError``, so ``PpmdCodec.translate`` maps it as it maps the real one.
    """


def _known(*classes: type[Exception] | None) -> dict[tuple[str, str], type[Exception]]:
    return {
        (cls.__module__, cls.__qualname__): cls for cls in classes if cls is not None
    }


_ZLIB_ERRORS = _known(zlib.error)
_LZMA_ERRORS = _known(lzma.LZMAError)
# Matched by type name alone ("*"): the modules that raise them differ by build.
_BROTLI_ERRORS: dict[tuple[str, str], type[Exception]] = {
    ("*", "error"): BrotliChildError
}
PPMD_ERRORS: dict[tuple[str, str], type[Exception]] = {
    ("*", "PpmdError"): PpmdChildError
}


def _zstd_errors() -> dict[tuple[str, str], type[Exception]]:
    zstd = deps.zstd
    return _known(getattr(zstd, "ZstdError", None)) if zstd is not None else {}


def _lz4_errors() -> dict[tuple[str, str], type[Exception]]:
    block = deps.lz4_block
    return _known(getattr(block, "LZ4BlockError", None)) if block is not None else {}


# What a decoder of an unknown stream most likely holds outside PyPy's heap
# (``native_memory`` has why it matters and which decoders report). liblzma: the
# dictionary of the default preset (6). zstd: the largest window of the levels a
# default compressor picks.
_TYPICAL_DECODER_MEMORY = 8 << 20
# libbz2: the default (and largest) 900 kB block size.
_BZ2_DECODER_MEMORY = 3600 << 10
# brotli: the ring buffer of the default 22-bit window.
_BROTLI_DECODER_MEMORY = 4 << 20


def _lzma_decoder_memory(
    memlimit: int | None, filters: list[dict[str, Any]] | None
) -> int:
    """What a liblzma decoder most likely allocates: the dictionary a raw filter chain
    names, else the default one, never more than ``memlimit``."""
    estimate = _TYPICAL_DECODER_MEMORY
    if filters is not None:
        estimate = max(
            (
                int(f.get("dict_size", _TYPICAL_DECODER_MEMORY))
                for f in filters
                if f.get("id") in (lzma.FILTER_LZMA1, lzma.FILTER_LZMA2)
            ),
            default=_TYPICAL_DECODER_MEMORY,
        )
    return estimate if memlimit is None else min(estimate, memlimit)


def _zstd_decoder_memory(options: Mapping[int, int] | None) -> int:
    """What a zstd decoder most likely holds: the typical window, never more than the
    ``window_log_max`` it is given.

    A frame can declare a window up to that cap (2 GiB under the default
    ``max_decoder_memory``), and nothing frees it before a collection. Reporting the
    cap would force a major collection per decoder, so the estimate stays typical.
    """
    zstd = deps.zstd
    assert zstd is not None
    log_max = (options or {}).get(zstd.DecompressionParameter.window_log_max)
    if log_max is None:
        return _TYPICAL_DECODER_MEMORY
    return min(_TYPICAL_DECODER_MEMORY, 1 << int(log_max))


class _ChildProxy:
    """The common part of every proxy: the child and its close."""

    # What ``release_decoder`` (decompressor_stream.py) looks for.
    holds_decoder_child = True

    def __init__(self, child: DecoderChild) -> None:
        self._child = child

    def spoil(self) -> None:
        """End the child at :meth:`close` instead of reusing it."""
        self._child.spoil()

    def close(self) -> None:
        self._child.close()


class ChildDecompressor(_ChildProxy):
    """A ``bz2``, ``lzma``, zstd, ``lz4.frame`` or zlib decompressor in a child."""

    def decompress(
        self, data: bytes | bytearray | memoryview, *args: Any, **kwargs: Any
    ) -> bytes:
        return self._child.call("decompress", data, args, kwargs)

    def flush(self, *args: Any) -> bytes:
        return self._child.call("flush", None, args)

    @property
    def eof(self) -> bool:
        return self._child.flag("eof")

    @property
    def needs_input(self) -> bool:
        return self._child.flag("needs_input")

    @property
    def unused_data(self) -> bytes:
        return self._child.unused_data()

    @property
    def unconsumed_tail(self) -> bytes:
        return self._child.unconsumed_tail()


class ChildBrotliDecompressor(_ChildProxy):
    """A ``brotli.Decompressor`` in a child, for a brotli older than 1.2.0: no
    ``can_accept_more_data`` and no ``output_buffer_limit``."""

    def process(self, data: bytes, **kwargs: Any) -> bytes:
        return self._child.call("process", data, (), kwargs)

    def is_finished(self) -> bool:
        return self._child.flag("is_finished")


class ChildBrotliDecompressorWithLimit(ChildBrotliDecompressor):
    """A ``brotli.Decompressor`` in a child, brotli 1.2.0 or later."""

    def can_accept_more_data(self) -> bool:
        return self._child.flag("can_accept_more_data")


class ChildInflater(_ChildProxy):
    """An ``inflate64.Inflater`` in a child."""

    def inflate(self, data: bytes) -> bytes:
        return self._child.call("inflate", data)

    @property
    def eof(self) -> bool:
        return self._child.flag("eof")


class ChildPpmdDecoder(_ChildProxy):
    """A ``pyppmd.Ppmd7Decoder`` or ``Ppmd8Decoder`` in a child.

    ``unused_data`` is asked for, not carried with each reply: pyppmd builds that value
    once, on its first read after ``eof``, and keeps it.
    """

    def decode(self, data: bytes | bytearray | memoryview, length: int) -> bytes:
        return self._child.call("decode", data, (length,))

    @property
    def eof(self) -> bool:
        return self._child.flag("eof")

    @property
    def needs_input(self) -> bool:
        return self._child.flag("needs_input")

    @property
    def unused_data(self) -> bytes:
        return self._child.get("unused_data") if self.eof else b""


class Natives:
    """Builds native decoder objects in this process, or in child processes when
    ``isolated``. A shared instance per mode: :data:`IN_PROCESS`, :data:`ISOLATED`."""

    def __init__(self, *, isolated: bool) -> None:
        self.isolated = isolated

    def __repr__(self) -> str:
        return f"Natives(isolated={self.isolated})"

    # -- the child ---------------------------------------------------------------------

    def _child(
        self,
        codec: str,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        *,
        known: dict[tuple[str, str], type[Exception]] | None = None,
        reuse: bool = True,
    ) -> DecoderChild:
        """A decoder of ``codec`` in a child process. Raises ``ResourceUnavailableError``
        naming ``process_isolation`` when no child can run it."""
        reason = decoder_child_unavailable_reason(codec)
        if reason is not None:
            raise isolation_error(reason)
        try:
            return DecoderChild(codec, args, kwargs, known=known, reuse=reuse)
        except DecoderChildStartError as exc:
            raise isolation_error(str(exc)) from exc

    # -- constructors --------------------------------------------------------------

    def zlib_decompressobj(
        self, wbits: int = zlib.MAX_WBITS, zdict: bytes | None = None
    ) -> ZlibDecompressor:
        if not self.isolated:
            if zdict is None:
                return zlib.decompressobj(wbits)
            return zlib.decompressobj(wbits, zdict=zdict)
        kwargs: dict[str, object] = {} if zdict is None else {"zdict": bytes(zdict)}
        return ChildDecompressor(
            self._child("zlib", (wbits,), kwargs, known=_ZLIB_ERRORS)
        )

    def bz2_decompressor(self) -> Decompressor:
        if not self.isolated:
            import bz2

            decoder = bz2.BZ2Decompressor()
            note_native_memory(decoder, _BZ2_DECODER_MEMORY)
            return decoder
        return ChildDecompressor(self._child("bz2"))

    def lzma_decompressor(
        self,
        format: int = lzma.FORMAT_AUTO,
        memlimit: int | None = None,
        filters: list[dict[str, Any]] | None = None,
    ) -> Decompressor:
        if not self.isolated:
            decoder = lzma.LZMADecompressor(
                format=format, memlimit=memlimit, filters=filters
            )
            note_native_memory(decoder, _lzma_decoder_memory(memlimit, filters))
            return decoder
        kwargs: dict[str, object] = {"format": format}
        if memlimit is not None:
            kwargs["memlimit"] = memlimit
        if filters is not None:
            kwargs["filters"] = [dict(f) for f in filters]
        return ChildDecompressor(self._child("lzma", (), kwargs, known=_LZMA_ERRORS))

    def zstd_decompressor(
        self, options: Mapping[int, int] | None = None
    ) -> Decompressor:
        """Needs zstd installed (``deps.zstd``); the codec checks first."""
        if not self.isolated:
            zstd = deps.zstd
            assert zstd is not None
            decoder = zstd.ZstdDecompressor(options=options)
            note_native_memory(decoder, _zstd_decoder_memory(options))
            return decoder
        # The option keys are ``DecompressionParameter`` members, an ``IntEnum`` that
        # ``marshal`` does not carry; the decoder takes their integer values too.
        kwargs: dict[str, object] = {}
        if options is not None:
            kwargs["options"] = {int(k): int(v) for k, v in options.items()}
        return ChildDecompressor(self._child("zstd", (), kwargs, known=_zstd_errors()))

    def lz4_frame_decompressor(self) -> Decompressor:
        """Needs lz4 installed; the codec checks first."""
        if not self.isolated:
            frame = deps.lz4_frame
            assert frame is not None
            return frame.LZ4FrameDecompressor()
        return ChildDecompressor(self._child("lz4.frame", known=_lz4_errors()))

    def lz4_block_decompress(self, block: bytes, **kwargs: Any) -> bytes:
        """``lz4.block.decompress``; needs lz4 installed."""
        if not self.isolated:
            module = deps.lz4_block
            assert module is not None
            return module.decompress(block, **kwargs)
        child = self._child("lz4.block", known=_lz4_errors())
        try:
            return child.call("decompress", block, (), kwargs)
        finally:
            child.close()

    def brotli_decompressor(self) -> Any:
        """A ``brotli.Decompressor``; needs brotli installed. Not imported here when
        isolated."""
        if not self.isolated:
            brotli = deps.brotli.load()
            assert brotli is not None
            decoder = brotli.Decompressor()
            note_native_memory(decoder, _BROTLI_DECODER_MEMORY)
            return decoder
        child = self._child("brotli", known=_BROTLI_ERRORS)
        if child.has("can_accept_more_data"):
            return ChildBrotliDecompressorWithLimit(child)
        return ChildBrotliDecompressor(child)

    def brotli_errors(self) -> tuple[type[Exception], ...]:
        """The exception types a brotli decoder from :meth:`brotli_decompressor`
        raises on bad data."""
        if self.isolated:
            return (BrotliChildError,)
        brotli = deps.brotli.load()
        assert brotli is not None
        return (brotli.error,)

    def inflater(self) -> Any:
        """An ``inflate64.Inflater``; needs inflate64 installed."""
        if not self.isolated:
            inflate64 = deps.inflate64.load()
            assert inflate64 is not None
            return inflate64.Inflater()
        return ChildInflater(self._child("inflate64"))

    def package_available(self, lazy: deps.LazyOptional) -> bool:
        """Whether a lazily imported package can decode. In-process this imports it
        (``load``); isolated only looks it up, so this process never imports it."""
        if self.isolated:
            return lazy.available()
        return lazy.load() is not None


IN_PROCESS = Natives(isolated=False)
ISOLATED = Natives(isolated=True)


def natives_for(isolation: ProcessIsolation) -> Natives:
    """The :class:`Natives` for a ``process_isolation`` setting."""
    return ISOLATED if isolation is ProcessIsolation.NATIVE_DECODERS else IN_PROCESS
