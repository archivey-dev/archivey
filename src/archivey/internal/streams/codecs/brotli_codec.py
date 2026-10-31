"""Brotli."""

from __future__ import annotations

from typing import BinaryIO

from archivey.config import ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    exception_detail,
)
from archivey.internal.config import StreamConfig
from archivey.internal.detection_workspace import (
    DETECTION_LIMIT,
    PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE,
)
from archivey.internal.overrides import override
from archivey.internal.streams.archive_stream import RewindWarning
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    ProbeChargeDecode,
    ProbeReadAt,
    StreamCodec,
)
from archivey.internal.streams.codecs.brotli_decoder import BrotliDecompressorStream
from archivey.internal.streams.codecs.brotli_framing import (
    CHAIN_DECODE_MARGIN,
    first_block_overruns_source,
    probe_bytes_at,
    walk_chain,
)
from archivey.internal.streams.codecs.isolated import BrotliChildError, natives_for
from archivey.types import (
    MissingComponent,
    OptionalLibrary,
    StreamFormat,
)

# The chain decode reads ``[0, end)`` and does not run when ``end`` would pass this: the
# same 1 MiB reach as a non-seekable ``read_at``, applied to seekable sources too, so no
# source is decoded further for detection. Past it the walk's verdict stands. Under
# detection the caller's ``charge_decode`` applies this bound with the budget's (and
# records the skip); the probe applies it itself only when it is not metered.
CHAIN_DECODE_MAX_END = PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE


class BrotliCodec(StreamCodec):
    codec = Codec.BROTLI
    stream_format = StreamFormat.BROTLI
    extension_aliases = (".brotli",)
    # Brotli has no signature; the detector recognizes it by decoding a bounded prefix.
    requirement = MissingComponent(
        OptionalLibrary.BROTLI, "pip install archivey[recommended]", ("brotli",)
    )

    @override
    def _backend_present(self) -> bool:
        return deps.brotli.available()

    @override
    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        excluded = config.excluded_libraries
        natives = natives_for(config.process_isolation)
        if self.excluded_by(excluded) or not natives.package_available(deps.brotli):
            raise self._missing("Brotli streams", excluded=excluded)
        # Brotli has no random-access index; a backward seek re-decodes from the start (the
        # outer ArchiveStream warns — see rewind_warning).
        return BrotliDecompressorStream(
            source,
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
            natives=natives,
        )

    @override
    def translate(self, exc: Exception) -> ArchiveyError | None:
        # brotli raises its own brotli.error for corrupt data; a truncated stream doesn't
        # raise here (the decompressor just never reports finished), so the base
        # DecompressorStream surfaces that as TruncatedError on its own.
        brotli = deps.brotli.loaded()
        if isinstance(exc, BrotliChildError) or (
            brotli is not None and isinstance(exc, brotli.error)
        ):
            return CorruptionError(
                f"Error reading brotli stream: {exception_detail(exc)}"
            )
        return None

    @override
    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return RewindWarning("brotli")

    @override
    def content_probe(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """Recognize a raw Brotli stream — which has no magic — by decoding a bounded prefix.

        When ``source_length`` is known, reject a first meta-block that *declares* more
        bytes than the source can hold (uncompressed / metadata), then follow the
        self-describing block chain when a ``read_at`` facility (or the prefix alone)
        can reach successor offsets. Completeness — whole source visible and decode
        wants more input — is applied inside ``_decodes_sample``. When the chain stops at
        a compressed block the window decode did not reach, the source is decoded from
        offset 0 to just past that block's header (:meth:`_decodes_through`).
        """
        compressed_at: int | None = None
        if source_length is not None:
            if first_block_overruns_source(prefix, source_length):
                return False
            walk = walk_chain(prefix, source_length, read_at=read_at)
            if walk.proves_invalid:
                return False
            compressed_at = walk.compressed_at
        if not self._decodes_sample(
            prefix, source_length=source_length, isolation=isolation
        ):
            return False
        if compressed_at is None or source_length is None:
            return True
        return self._decodes_through(
            prefix,
            source_length,
            compressed_at,
            read_at=read_at,
            charge_decode=charge_decode,
            isolation=isolation,
        )

    def _decodes_through(
        self,
        prefix: bytes,
        source_length: int,
        compressed_at: int,
        *,
        read_at: ProbeReadAt | None,
        charge_decode: ProbeChargeDecode | None,
        isolation: ProcessIsolation,
    ) -> bool:
        """Whether the source decodes to ``CHAIN_DECODE_MARGIN`` past ``compressed_at``.

        The chain walk checks every declared length up to the first compressed block and
        stops there. Data whose opening bytes parse as a long uncompressed or metadata
        block (a ``.pyc``, a font, 1.2 % of random data over 64 KiB) passes the walk and
        the window decode, which never reaches the compressed block; a real decoder then
        fails within a few hundred bytes of its header. Decoding ``[0, end)`` is mostly a
        copy of the uncompressed bytes, and a sequential read.

        ``True`` (cannot disprove) when the window decode already covered ``end``, when
        ``charge_decode`` refuses ``[0, end)`` (or, unmetered, ``end`` is past
        ``CHAIN_DECODE_MAX_END``), or when ``read_at`` declines the bytes. A real stream
        either keeps decoding or runs out of input, and both are accepted.

        The charge comes before the read because the read is what the budget bounds: on
        a seekable source ``read_at`` has no ceiling of its own. The detector's
        ``read_at`` serves any ``[0, end)`` its ``charge_decode`` accepted, so a granted
        charge is always spent on a decode.
        """
        if source_length <= len(prefix):
            return True  # the window decode had the whole source
        end = min(compressed_at + CHAIN_DECODE_MARGIN, source_length)
        if end <= min(len(prefix), DETECTION_LIMIT):
            return True
        if charge_decode is None:
            if end > CHAIN_DECODE_MAX_END:
                return True
        elif not charge_decode(end):
            return True
        data = probe_bytes_at(prefix, source_length, 0, end, read_at)
        if data is None:
            return True
        # ``source_length`` is left out on purpose: a sample that ends at EOF would
        # otherwise get the 64 KiB completeness drain, which the uncompressed copy alone
        # can fill before the decoder reaches the compressed block.
        return self._decodes_sample(data, sample_bytes=len(data), isolation=isolation)
