"""Zstandard."""

from __future__ import annotations

import functools
from typing import BinaryIO

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
    exception_detail,
)
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
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import (
    FramedDecompressorStream,
    StreamIndex,
    stream_magic,
)
from archivey.internal.streams.codecs.isolated import natives_for
from archivey.internal.streams.codecs.zstd_framing import (
    FRAME_MAGIC as ZSTD_FRAME_MAGIC,
    regular_frame_behind_skippable_frames,
)
from archivey.internal.streams.codecs.zstd_seek_table import build_seek_table_index
from archivey.internal.streams.decompressor_stream import _StreamChecksumError
from archivey.types import (
    ArchiveFormat,
    MagicSignature,
    MissingComponent,
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


def _probe_window_log_max(window_log_max: int, config: StreamConfig) -> int:
    """``window_log_max`` lowered to :data:`_PROBE_WINDOW_LOG` for a detection probe."""
    if config.probe_read_bound is None:
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


class ZstdCodec(StreamCodec):
    codec = Codec.ZSTD
    stream_format = StreamFormat.ZSTD
    magic = (MagicSignature(0, ZSTD_FRAME_MAGIC, ArchiveFormat.ZST),)
    requirement = MissingComponent(
        "backports.zstd", "pip install archivey[recommended]", ("zstd",)
    )

    def _backend_present(self) -> bool:
        return deps.zstd is not None

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        if deps.zstd is None:
            # The backport is only relevant below 3.14; on 3.14+ the stdlib module is used,
            # so the bare hint alone would send such a caller installing a no-op.
            raise self._missing(
                "zstd streams",
                note="On Python 3.14+ the stdlib compression.zstd module is used instead.",
            )
        zstd = deps.zstd
        window_log_max, _ = _zstd_window_log_max(config.decoder_limits)
        window_log_max = _probe_window_log_max(window_log_max, config)
        options = {zstd.DecompressionParameter.window_log_max: window_log_max}
        index = None
        if config.seekable:
            # Declared seek demand only (``seekable-decompressor-streams``): each
            # regular frame starts a seek point, and the seekable format's table
            # lists them all without decoding.
            collector = config.collector
            index = StreamIndex(
                resumes_at=lambda data: data.startswith(ZSTD_FRAME_MAGIC),
                build=lambda inner, last: build_seek_table_index(
                    inner, last, collector
                ),
            )
        return FramedDecompressorStream(
            source,
            functools.partial(
                natives_for(config.process_isolation).zstd_decompressor, options
            ),
            codec_name="zstd",
            # Every frame is content, in a .zst file and in a ZIP or 7z coder alike:
            # RFC 8878 defines Zstd data as one or more frames.
            magic=_ZSTD_STREAMS,
            index=index,
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        limits = config.decoder_limits

        def translate(exc: Exception) -> ArchiveyError | None:
            if (
                deps.zstd is not None
                and isinstance(exc, deps.zstd.ZstdError)
                and _ZSTD_WINDOW_REFUSED in str(exc)
            ):
                own, _ = _zstd_window_log_max(limits)
                if _probe_window_log_max(own, config) < own:
                    return UnsupportedFeatureError(
                        "A zstd frame declares a window over "
                        f"{1 << _PROBE_WINDOW_LOG} bytes, more than a detection "
                        f"probe reserves: {exc}"
                    )
                return _zstd_window_refusal(exc, limits)
            return self.translate(exc)

        return translate

    def translate(self, exc: Exception) -> ArchiveyError | None:
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
        return self._eof_truncation(exc, "zstd")

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return RewindWarning("zstd")

    def magic_behind_prefix(self, prefix: bytes) -> bool:
        return regular_frame_behind_skippable_frames(prefix)
