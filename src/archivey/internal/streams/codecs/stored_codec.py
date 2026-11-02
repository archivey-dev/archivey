"""Stored: no compression."""

from __future__ import annotations

import os
from typing import BinaryIO

from archivey.internal.config import StreamConfig
from archivey.internal.overrides import override
from archivey.internal.streams.archive_stream import RewindWarning
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.streamtools import ensure_binaryio
from archivey.types import StreamFormat


class StoredCodec(StreamCodec):
    codec = Codec.STORED
    stream_format = StreamFormat.UNCOMPRESSED

    @override
    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        # Reads nothing from ``config``: ``open_codec_stream`` relies on that and hands
        # a stored stream source the caller's config without the decoder config work.
        if isinstance(source, (str, os.PathLike)):
            return open(os.fspath(source), "rb")
        return ensure_binaryio(source)

    @override
    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        # Nothing is decoded, so a backward seek re-decodes nothing. The only codec for
        # which "never report a rewind" is the truthful answer.
        return None
