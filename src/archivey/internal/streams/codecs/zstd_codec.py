"""Zstandard."""

from __future__ import annotations

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
    exception_detail,
)
from archivey.formats import CodecCall, Decompressor, Magic
from archivey.internal.config import (
    DecoderLimits,
    StreamConfig,
)
from archivey.internal.streams.archive_stream import (
    ExceptionTranslator,
    RewindWarning,
)
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    _SKIPPABLE_FRAME,
    Codec,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import (
    StreamIndex,
    StreamStart,
    stream_magic,
)
from archivey.internal.streams.codecs.handler_codec import (
    BuiltinCall,
    BuiltinCodecHandler,
    builtin_codec,
    config_of,
)
from archivey.internal.streams.codecs.isolated import natives_for
from archivey.internal.streams.codecs.zstd_framing import (
    FRAME_MAGIC as ZSTD_FRAME_MAGIC,
    regular_frame_behind_skippable_frames,
)
from archivey.internal.streams.codecs.zstd_seek_table import build_seek_table_index
from archivey.internal.streams.decompressor_stream import _StreamChecksumError
from archivey.types import (
    MissingComponent,
    OptionalLibrary,
    StreamFormat,
)

_ZSTD_STREAMS = stream_magic(
    tuple(bytes([b]) for b in ZSTD_FRAME_MAGIC), _SKIPPABLE_FRAME
)


# libzstd's text for ZSTD_error_frameParameter_windowTooLarge: the frame header
# declares a window over the decoder's ``window_log_max``.
_ZSTD_WINDOW_REFUSED = "Frame requires too much memory for decoding"


def _zstd_window_log_max(limits: DecoderLimits) -> tuple[int, bool]:
    """The ``window_log_max`` to decode with, and whether a refusal means the cap.

    A zstd frame header declares its window, and the decoder keeps that much of the
    output. libzstd refuses a window over ``2**27`` by default. That default is not
    the caller's choice, so it is replaced with ``max_decoder_memory``.

    ``window_log_max`` is a power of two, so the cap is rounded down to one: a window
    between that power of two and a cap that is not one is refused. The rounding
    goes toward refusal, so no window over the cap is decoded. libzstd bounds the
    value (``2**10`` to ``2**31`` on a 64-bit build) and it is clamped to those
    bounds. Below the lower bound a cap acts as 1 KiB. At or above the upper bound, or
    with no cap, a refused window is over libzstd's own ceiling, which no cap can
    lift, and the second value is ``False``. The default cap, 2 GiB, is exactly that
    ceiling, so under the default a refusal is always the ceiling's.
    """
    assert deps.zstd is not None
    low, high = deps.zstd.DecompressionParameter.window_log_max.bounds()
    cap = limits.max_decoder_memory
    if cap is None:
        return high, False
    wanted = max(cap.bit_length() - 1, 0)
    return max(low, min(wanted, high)), cap < 1 << high


# The largest window a detection probe decodes (``StreamConfig.probe_read_bound``):
# libzstd's own default ``window_log_max``, which is what ``zstd -d`` decodes without
# ``--long`` or ``--memory``. Unlike LZMA, a zstd window cannot be shrunk to what the
# read needs: libzstd refuses a frame whose window is over ``window_log_max``, and a
# frame that does not declare its content size has the whole window reserved when
# its header is read (measured: a 2 GiB window under a 256 MiB ``RLIMIT_AS`` fails
# with libzstd's "Allocation error"). So a probe reserves at most this, and a frame
# over it is refused, which the probe reads as "can't tell".
_PROBE_WINDOW_LOG = 27


def _probe_window_log_max(window_log_max: int, probe_bound: int | None) -> int:
    """``window_log_max`` lowered to :data:`_PROBE_WINDOW_LOG` for a detection probe."""
    if probe_bound is None:
        return window_log_max
    return min(window_log_max, _PROBE_WINDOW_LOG)


def _zstd_window_refusal(exc: Exception, limits: DecoderLimits) -> ArchiveyError:
    """Map libzstd's window refusal to the cap that caused it, or to its own ceiling."""
    window_log_max, is_cap = _zstd_window_log_max(limits)
    if is_cap:
        cap = limits.max_decoder_memory
        assert cap is not None
        bound = (
            "the largest power of two within the cap"
            if 1 << window_log_max <= cap
            else "the smallest window libzstd can be limited to"
        )
        return ResourceLimitError(
            f"Decoder limit reached: max_decoder_memory={cap} (a zstd frame declares "
            f"a window over {1 << window_log_max} bytes, {bound}; libzstd refused it "
            f"before allocating). The archive chose this number; raise "
            f"DecoderLimits.max_decoder_memory if the archive is trusted."
        )
    return UnsupportedFeatureError(
        f"A zstd frame declares a window over {1 << window_log_max} bytes, the "
        f"largest window this libzstd can decode: {exc}"
    )


class ZstdHandler(BuiltinCodecHandler):
    codec = Codec.ZSTD
    stream_format = StreamFormat.ZSTD
    magic = (Magic(0, ZSTD_FRAME_MAGIC),)
    requirement = MissingComponent(
        OptionalLibrary.BACKPORTS_ZSTD, "pip install archivey[recommended]", ("zstd",)
    )
    # The backport is only relevant below 3.14; on 3.14+ the stdlib module is used,
    # so the bare hint alone would send such a caller installing a no-op.
    missing_note = "On Python 3.14+ the stdlib compression.zstd module is used instead."

    def _library(self) -> str | None:
        # The module in use: the standard library's on 3.14+, else the backport.
        if deps.zstd is None:
            return None
        return deps.zstd_library or OptionalLibrary.BACKPORTS_ZSTD

    def decompressor(self, call: CodecCall) -> Decompressor:
        assert deps.zstd is not None
        window_log_max, _ = _zstd_window_log_max(call.limits)
        window_log_max = _probe_window_log_max(window_log_max, call.probe_bound)
        options = {deps.zstd.DecompressionParameter.window_log_max: window_log_max}
        return natives_for(config_of(call).process_isolation).zstd_decompressor(options)

    def _stream_start(self, call: BuiltinCall) -> StreamStart:
        # Every frame is content, in a .zst file and in a ZIP or 7z coder alike:
        # RFC 8878 defines Zstd data as one or more frames. A skippable frame may
        # come between them, which ``magic`` does not match.
        del call
        return _ZSTD_STREAMS

    def _stream_index(self, call: BuiltinCall) -> StreamIndex | None:
        config = call.config
        if not config.seekable:
            return None
        # Declared seek demand only (``seekable-decompressor-streams``): each
        # regular frame starts a seek point, and the seekable format's table
        # lists them all without decoding.
        collector = config.collector
        return StreamIndex(
            resumes_at=lambda data: data.startswith(ZSTD_FRAME_MAGIC),
            build=lambda inner, last: build_seek_table_index(inner, last, collector),
        )

    def _translator(self, config: StreamConfig) -> ExceptionTranslator:
        limits = config.decoder_limits

        def translate(exc: Exception) -> ArchiveyError | None:
            if (
                deps.zstd is not None
                and isinstance(exc, deps.zstd.ZstdError)
                and _ZSTD_WINDOW_REFUSED in str(exc)
            ):
                own, _ = _zstd_window_log_max(limits)
                if _probe_window_log_max(own, config.probe_read_bound) < own:
                    return UnsupportedFeatureError(
                        "A zstd frame declares a window over "
                        f"{1 << _PROBE_WINDOW_LOG} bytes, more than a detection "
                        f"probe reserves: {exc}"
                    )
                return _zstd_window_refusal(exc, limits)
            return self.translate_exception(exc)

        return translate

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        if deps.zstd is not None and isinstance(exc, deps.zstd.ZstdError):
            if "Dictionary mismatch" in str(exc):
                # The frame names a dictionary (its Dictionary_ID), and archivey has no
                # way to be given one. zstd reports the same "Dictionary mismatch".
                return UnsupportedFeatureError(
                    "zstd frame needs a dictionary, which is not supported: "
                    f"{exception_detail(exc)}; a damaged header reads the same way"
                )
            if "checksum" in str(exc):
                # The frame's content checksum ("Restored data doesn't match
                # checksum"), over everything the frame decoded.
                return _StreamChecksumError(
                    f"Error reading zstd stream: {exception_detail(exc)}"
                )
            return CorruptionError(
                f"Error reading zstd stream: {exception_detail(exc)}"
            )
        return StreamCodec._eof_truncation(exc, "zstd")

    def _rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return RewindWarning("zstd")

    def _magic_behind_prefix(self, prefix: bytes) -> bool:
        return regular_frame_behind_skippable_frames(prefix)


ZstdCodec = builtin_codec(ZstdHandler)
