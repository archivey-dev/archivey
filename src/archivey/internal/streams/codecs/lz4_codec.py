"""LZ4 (frame format and the legacy format)."""

from __future__ import annotations

from typing import BinaryIO

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    UnsupportedFeatureError,
    exception_detail,
)
from archivey.internal.config import StreamConfig
from archivey.internal.streams.archive_stream import RewindWarning
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
    stream_magic,
)
from archivey.internal.streams.codecs.isolated import natives_for
from archivey.internal.streams.codecs.lz4_legacy import LEGACY_MAGIC, Lz4Decompressor
from archivey.internal.streams.decompressor_stream import _StreamChecksumError
from archivey.types import (
    ArchiveFormat,
    MagicSignature,
    MissingComponent,
    StreamFormat,
)

# LZ4 also takes a legacy stream (``lz4 -l``), which the ``lz4`` command reads after a
# frame and a frame after it.
_LZ4_STREAMS = stream_magic(
    (b"\x04", b"\x22", b"\x4d", b"\x18"),
    tuple(bytes([b]) for b in LEGACY_MAGIC),
    _SKIPPABLE_FRAME,
)


class Lz4Codec(StreamCodec):
    codec = Codec.LZ4
    stream_format = StreamFormat.LZ4
    magic = (
        MagicSignature(0, b"\x04\x22\x4d\x18", ArchiveFormat.LZ4),
        # The legacy stream ``lz4 -l`` writes, and Linux kernel images use.
        MagicSignature(0, LEGACY_MAGIC, ArchiveFormat.LZ4),
    )
    requirement = MissingComponent(
        "lz4",
        "pip install archivey[recommended]",
        ("lz4",),
        reason=deps.unused_reason("lz4"),
    )

    def _backend_present(self) -> bool:
        return deps.lz4_frame is not None and deps.lz4_block is not None

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        if deps.lz4_frame is None or deps.lz4_block is None:
            raise self._missing("lz4 streams")
        # A rewind re-decompresses from the start (the outer ArchiveStream warns on a
        # rewind — see rewind_warning).
        natives = natives_for(config.process_isolation)
        return FramedDecompressorStream(
            source,
            lambda: Lz4Decompressor(natives),
            codec_name="lz4",
            # Every frame is content, in a .lz4 file and in a 7z coder alike: the LZ4
            # frame format lets frames be appended.
            magic=_LZ4_STREAMS,
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, RuntimeError) and str(exc).startswith("LZ4"):
            if "headerVersion_wrong" in str(exc):
                # The frame's version bits are not 01, the only version the LZ4 frame
                # format defines; the lz4 CLI's decoder refuses it the same way.
                return UnsupportedFeatureError(
                    f"Unsupported lz4 frame version: {exception_detail(exc)}; a "
                    "damaged header reads the same way"
                )
            if "contentChecksum" in str(exc):
                # The frame's content checksum, over everything the frame decoded; a
                # block checksum covers one block and stays a plain corruption.
                return _StreamChecksumError(
                    f"Error reading lz4 stream: {exception_detail(exc)}"
                )
            return CorruptionError(f"Error reading lz4 stream: {exception_detail(exc)}")
        if deps.lz4_block is not None and isinstance(exc, deps.lz4_block.LZ4BlockError):
            # A block of a legacy stream; it has no checksum to fail.
            return CorruptionError(f"Error reading lz4 stream: {exception_detail(exc)}")
        return self._eof_truncation(exc, "lz4")

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return RewindWarning("lz4")
