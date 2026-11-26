"""Brotli: ``.br`` files and 7z Brotli coders, decoded by the ``brotli`` package
(:func:`BrotliDecompressorStream`).

Brotli has no magic number, so detection recognizes it with a content probe: a walk of
the opening meta-block headers (``brotli_framing``), then a bounded trial decode. The
package is imported only when a stream needs it, because it re-enables the GIL on a
free-threaded build (``deps.LazyOptional``).
"""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import BinaryIO

from archivey.config import DecoderLimits, ProcessIsolation
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
from archivey.internal.probe_verdict import (
    PROBE_MATCH,
    PROBE_REJECTED,
    ProbeVerdict,
    probe_verdict,
)
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    ProbeChargeDecode,
    ProbeReadAccess,
    ProbeReadAt,
    ProbeReadAvailable,
    StreamCodec,
)
from archivey.internal.streams.codecs.brotli_decoder import (
    BrotliDecoder,
    BrotliDecompressorStream,
)
from archivey.internal.streams.codecs.brotli_framing import (
    CHAIN_DECODE_MARGIN,
    first_block_overruns_source,
    probe_bytes_at,
    walk_chain,
)
from archivey.internal.streams.codecs.isolated import BrotliChildError
from archivey.internal.streams.decompressor_stream import DecompressorStream, SeekPoint
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


class _ForwardProbeSample(io.BufferedIOBase, BinaryIO):
    """A bounded, replayable view that fetches arrived bytes only as decoding needs them.

    The workspace retains every fetched byte, so decoder replay can seek inside this
    view. BufferedIOBase keeps the codec from adding a fill-count buffering layer:
    each arrived chunk must reach the decoder before another source read. A completed
    decoder makes the view end without an optional pipe read.
    """

    def __init__(self, read_available: ProbeReadAvailable, end: int) -> None:
        super().__init__()
        self._read_available = read_available
        self._end = end
        self._position = 0
        self.finished: Callable[[], bool] = lambda: False

    @override
    def close(self) -> None:
        # The decoder retains this view for replay; do not keep the decoder alive
        # through the finished callback after the trial closes.
        self.finished = lambda: False
        super().close()

    @override
    def readable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True

    @override
    def tell(self) -> int:
        return self._position

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            offset += self._position
        elif whence != io.SEEK_SET:
            raise io.UnsupportedOperation("The probe source length is unknown")
        if offset < 0:
            raise ValueError("negative probe seek")
        self._position = offset
        return offset

    @override
    def read(self, size: int | None = -1, /) -> bytes:
        if self._position >= self._end or self.finished() or size == 0:
            return b""
        if size is None or size < 0:
            size = DETECTION_LIMIT
        wanted = min(size, DETECTION_LIMIT, self._end - self._position)
        observed = self._read_available(self._position, wanted)
        if observed is None:
            return b""
        data, _ended = observed
        self._position += len(data)
        return data


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
        natives = config.natives
        if self.excluded_by(excluded) or not natives.package_available(deps.brotli):
            raise self._missing("Brotli streams", excluded=excluded)
        if isinstance(source, _ForwardProbeSample):

            def make_decoder(_point: SeekPoint, inner: BinaryIO) -> BrotliDecoder:
                decoder = BrotliDecoder(inner, natives)
                source.finished = lambda: decoder.finished
                return decoder

            return DecompressorStream(
                source, make_decoder=make_decoder, codec_name="brotli"
            )
        # Brotli has no random-access index; a backward seek re-decodes from the start (the
        # outer ArchiveStream warns; the default rewind_warning names this codec).
        return BrotliDecompressorStream(
            source,
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
            refuse_input_after_end=config.refuse_input_after_end,
            natives=natives,
            source_origin=config.source_origin,
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
    def content_probe(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
        decoder_limits: DecoderLimits = DecoderLimits(),
    ) -> ProbeVerdict:
        """Recognize a raw Brotli stream — which has no magic — by decoding a bounded prefix.

        When ``source_length`` is known, reject a first meta-block that *declares* more
        bytes than the source can hold (uncompressed / metadata). With or without a
        known length, follow the block chain when ``read_at`` (or the prefix alone)
        can reach successor offsets. Completeness — whole source visible and decode
        wants more input — is applied inside ``_decodes_sample``. When the chain stops at
        a compressed block the window decode did not reach, the source is decoded from
        offset 0 to just past that block's header (:meth:`_decodes_through`).
        """
        if source_length is not None and first_block_overruns_source(
            prefix, source_length
        ):
            return PROBE_REJECTED
        read_available = (
            read_at.available if isinstance(read_at, ProbeReadAccess) else None
        )
        walk = walk_chain(
            prefix, source_length, read_at=read_at, read_available=read_available
        )
        if walk.proves_invalid:
            return PROBE_REJECTED
        compressed_at = walk.compressed_at
        if not self._decodes_sample(
            prefix,
            source_length=source_length,
            isolation=isolation,
            decoder_limits=decoder_limits,
        ):
            return PROBE_REJECTED
        if compressed_at is None:
            return PROBE_MATCH
        return probe_verdict(
            self._decodes_through(
                prefix,
                source_length,
                compressed_at,
                read_at=read_at,
                charge_decode=charge_decode,
                read_available=read_available,
                isolation=isolation,
                decoder_limits=decoder_limits,
            )
        )

    def _decodes_through(
        self,
        prefix: bytes,
        source_length: int | None,
        compressed_at: int,
        *,
        read_at: ProbeReadAt | None,
        charge_decode: ProbeChargeDecode | None,
        isolation: ProcessIsolation,
        decoder_limits: DecoderLimits,
        read_available: ProbeReadAvailable | None = None,
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

        The target input is charged before fetching it. A pipe feeds arrived chunks
        to one decoder and stops fetching once it finishes or fails. This preserves
        the bounded trial without waiting for optional bytes after a valid stream.
        """
        if source_length is not None and source_length <= len(prefix):
            return True  # the window decode had the whole source
        end = compressed_at + CHAIN_DECODE_MARGIN
        if source_length is not None:
            end = min(end, source_length)
        if end <= min(len(prefix), DETECTION_LIMIT):
            return True
        if read_available is not None and source_length is None:
            if end > CHAIN_DECODE_MAX_END:
                if charge_decode is not None:
                    charge_decode(end)  # record why the target is out of reach
                return True
            if charge_decode is not None and not charge_decode(end):
                return True
            # Reserve the target input before fetching it. The decoder requests
            # arrived bytes until it fails, finishes, or exhausts the bounded sample.
            with _ForwardProbeSample(read_available, end) as sample:
                return self._decodes_probe_stream(
                    sample,
                    out_budget=end,
                    isolation=isolation,
                    decoder_limits=decoder_limits,
                )
        else:
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
        return self._decodes_sample(
            data,
            sample_bytes=len(data),
            isolation=isolation,
            decoder_limits=decoder_limits,
        )
