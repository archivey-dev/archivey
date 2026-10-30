"""Deflate64 (ZIP method 9)."""

from __future__ import annotations

import zlib
from typing import BinaryIO

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    exception_detail,
)
from archivey.internal.config import StreamConfig
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    StreamCodec,
)
from archivey.internal.streams.codecs.deflate64_decoder import (
    Deflate64DecompressorStream,
)
from archivey.internal.streams.codecs.isolated import natives_for
from archivey.types import MissingComponent, OptionalLibrary


class Deflate64Codec(StreamCodec):
    codec = Codec.DEFLATE64
    requirement = MissingComponent(
        OptionalLibrary.INFLATE64,
        "pip install archivey[recommended]",
        ("deflate64",),
        reason=deps.unused_reason(OptionalLibrary.INFLATE64),
    )

    def _backend_present(self) -> bool:
        return deps.inflate64.available()

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        natives = natives_for(config.process_isolation)
        if not natives.package_available(deps.inflate64):
            raise self._missing("Deflate64 streams")
        return Deflate64DecompressorStream(
            source,
            collector=config.collector,
            refuse_input_after_end=config.refuse_input_after_end,
            natives=natives,
        )

    def translate(self, exc: Exception) -> ArchiveyError | None:
        if isinstance(exc, (ValueError, zlib.error)):
            return CorruptionError(
                f"Error reading deflate64 stream: {exception_detail(exc)}"
            )
        return self._eof_truncation(exc, "deflate64")
