"""The liblzma family: xz, lzip, ``.lzma`` (LZMA Alone), and raw LZMA1/LZMA2 for
containers.
"""

from __future__ import annotations

import functools
import lzma
import os
from collections.abc import Callable
from typing import BinaryIO

from archivey.config import ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.config import (
    DecoderLimits,
    StreamConfig,
    check_decoder_memory,
    probe_lzma_dictionary,
)
from archivey.internal.hashing import crc32_digest
from archivey.internal.streams.archive_stream import ExceptionTranslator, RewindWarning
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    CodecSource,
    MetadataContext,
    ProbeChargeDecode,
    ProbeReadAt,
    StreamCodec,
)
from archivey.internal.streams.codecs.framed_decoder import FramedDecompressorStream
from archivey.internal.streams.codecs.isolated import (
    IN_PROCESS,
    Decompressor,
    Natives,
    natives_for,
)
from archivey.internal.streams.codecs.lzip_decoder import LzipDecompressorStream
from archivey.internal.streams.codecs.xz_decoder import (
    XzDecompressorStream,
    lzma_error_to_archivey,
    new_capped_decompressor,
    open_xz_head,
)
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    Decoder,
    DecompressorStream,
    SeekPoint,
    truncated_message,
)
from archivey.internal.streams.streamtools.slice import SlicingStream
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    HashAlgorithm,
    MagicSignature,
    StreamFormat,
)

_ALONE_HEADER_SIZE = 13
# Alone header marks unknown uncompressed size with all-ones uint64.
_ALONE_UNKNOWN_SIZE = (1 << 64) - 1


def _translate_lzma(
    exc: Exception, limits: DecoderLimits | None = None
) -> ArchiveyError | None:
    if isinstance(exc, lzma.LZMAError):
        return lzma_error_to_archivey(exc, "Error reading LZMA/XZ stream", limits)
    return StreamCodec._eof_truncation(exc, "LZMA/XZ")


class _LzmaErrorCodec(StreamCodec):
    """Shared LZMA/XZ error taxonomy for the lzma-family codecs (xz, lzip, raw LZMA)."""

    def translate(self, exc: Exception) -> ArchiveyError | None:
        return _translate_lzma(exc)

    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        # The limits the stream's decompressors are built with, so a memlimit refusal
        # names the cap (``.lzma``: ``new_capped_decompressor``).
        return functools.partial(_translate_lzma, limits=config.decoder_limits)


class _SizedLzmaCodec(_LzmaErrorCodec):
    """xz / lzip: surface the decompressed size recorded in the stream index/trailer."""

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        member.size = ctx.probe_decompressed_size()


class XzCodec(_SizedLzmaCodec):
    codec = Codec.XZ
    stream_format = StreamFormat.XZ
    magic = (MagicSignature(0, b"\xfd7zXZ\x00", ArchiveFormat.XZ),)

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        if config.probe_read_bound is not None:
            # Probes decode from a bounded in-memory or peek reader, never a path.
            assert not isinstance(source, (str, os.PathLike))
            return open_xz_head(
                source,
                config.probe_read_bound,
                natives_for(config.process_isolation),
            )
        return XzDecompressorStream(
            source,
            collector=config.collector,
            seekable=config.seekable,
            decoder_limits=config.decoder_limits,
            report_trailing_data=config.report_trailing_data,
            initial_index=config.seek_index,
            natives=natives_for(config.process_isolation),
        )


class LzipCodec(_SizedLzmaCodec):
    codec = Codec.LZIP
    checks_content = True
    stream_format = StreamFormat.LZIP
    magic = (MagicSignature(0, b"LZIP", ArchiveFormat.LZIP),)

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        return LzipDecompressorStream(
            source,
            collector=config.collector,
            seekable=config.seekable,
            decoder_limits=config.decoder_limits,
            report_trailing_data=config.report_trailing_data,
            probe_read_bound=config.probe_read_bound,
            natives=natives_for(config.process_isolation),
            usage=config.usage,
        )

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """Surface decompressed size and whole-member CRC-32 from one seekable index scan.

        ``probe_lzip_index`` returns both values from a single backward trailer walk.
        The CRC is the combine of every per-member trailer CRC-32 with that member's
        uncompressed ``data_size`` (single-member degenerates to the trailer CRC).
        """
        summary = ctx.probe_lzip_index()
        if summary is None:
            return
        member.size, crc32 = summary
        hashes = dict(member.hashes)
        hashes[HashAlgorithm.CRC32] = crc32_digest(crc32)
        member.hashes = hashes


# liblzma's ``LZMA_LCLP_MAX``: the largest lc + lp its LZMA1 decoder takes.
_LIBLZMA_LCLP_MAX = 4


def _split_lzma_props(props: int) -> tuple[int, int, int] | None:
    """The ``(lc, lp, pb)`` an LZMA1 properties byte encodes, or ``None`` out of range.

    The byte is (pb * 5 + lp) * 9 + lc with lc <= 8, lp <= 4, pb <= 4: 225 of the 256
    values are in range.
    """
    if props >= 9 * 5 * 5:
        return None
    return props % 9, props // 9 % 5, props // 45


def _alone_props_plausible(props: int) -> bool:
    """Whether ``props`` encodes a valid Alone ``(lc, lp, pb)`` triple.

    Detection admits all 225 values in the format's range, since a header grammar
    accepts the format's full legal range and the decode decides.
    """
    return _split_lzma_props(props) is not None


def _alone_props_liblzma_decodes(props: int) -> bool:
    """Whether liblzma decodes a stream with these properties: 75 of the 256 values.

    liblzma also requires lc + lp <= 4 (``LZMA_LCLP_MAX``). The next-stream check uses
    this, because a header liblzma refuses there fails the whole read.
    """
    split = _split_lzma_props(props)
    return split is not None and split[0] + split[1] <= _LIBLZMA_LCLP_MAX


def _alone_header_plausible(prefix: bytes) -> bool:
    """Cheap Alone header gate before a decode probe.

    The 13-byte header is a properties byte, a 32-bit dictionary size, and a 64-bit
    uncompressed size (all-ones meaning "unknown"). Two of the three are checked:

    - **Properties** must encode a legal ``(lc, lp, pb)`` triple.
    - **Uncompressed size** must not be exactly zero. Any value but the all-ones
      sentinel is the stream's exact output length, so zero declares a stream carrying
      no payload — nothing archivey could open. That is the rule the probe already
      applies after decoding (``require_output``), stated at the header because the
      bounded probe cannot reach it: 18 zero bytes are a *valid, complete, empty* Alone
      stream (13-byte header plus a five-byte range-coder init, which must begin with a
      zero), so zero-filled padding decodes cleanly to nothing, and the bounded read
      then runs off the end of the trailing zeros and reports truncation — which is a
      match. It refuses nothing that was ever detected: an empty stream is not claimed
      with or without this gate, because ``require_output`` already declines an empty
      decode, and a ``.lzma`` name still opens one through the extension.
    - **Dictionary size** is deliberately *not* gated, at any value. Every 32-bit value
      is legal and the LZMA specification requires decoders to round one below 4 KiB up
      to 4 KiB, so a stream whose field is zero still decodes — rejecting it was a false
      negative on real input, and it is independent of the size field above (a
      dictionary-zeroed stream of 700 bytes decodes fine). That rejection also served as
      an ordering workaround, keeping a zero-filled ISO system area from decoding as an
      empty Alone stream before far-magic ISO detection ran; far magic now runs before
      the content probes and answers that source itself (``format-detection``).
    """
    if len(prefix) < _ALONE_HEADER_SIZE or not _alone_props_plausible(prefix[0]):
        return False
    return int.from_bytes(prefix[5:13], "little") != 0


# A zero run this long, starting in the first ``_ALONE_ZERO_RUN_SPAN`` bytes of the
# range-coder data, means the bytes are not an encoder's output.
_ALONE_ZERO_RUN = 16
_ALONE_ZERO_RUN_SPAN = 32


def _alone_payload_has_zero_run(prefix: bytes) -> bool:
    """Whether a zero run near the start of the range-coder data rules out a real stream.

    A range coder fed zeros decodes zero literals without error, so any header that
    passes the gate and is followed by zeros decodes as a valid stream of zeros: a few
    hundred zero bytes give the probe its 4 KiB of output. A zero byte and one to nine
    random bytes before the run do too, in up to a third of cases (measured over 16 000
    random heads). ID3-tagged MP3s and OLE files have this shape, and they were claimed
    and read as a member of zeros, with no error.

    The two encoders measured never write a run like this. The longest zero run
    measured anywhere in a payload: 3 bytes from liblzma (``FORMAT_ALONE``, presets 0-9, plain and extreme)
    and 7 from the LZMA SDK encoder (7-Zip 23.01, levels 1-9, varied ``lc``/``lp``/
    ``pb``, dictionary, ``a=0``/``a=1``, with and without an end marker), on zeros,
    ``A``, ``ff``, ``ab`` and ``abc`` runs, random data, text and mixtures, and every
    input of 1-64 zero bytes (``-mx=9``). The 7-byte run is a two-zero-byte input with
    no end marker: two zero literals are all zero bits, so the whole payload is the
    range-coder init plus a zero flush. Both encoders code the third byte of a run as a
    match, and a match writes a one bit; that argument holds for any LZMA1 encoder, but
    other ``.lzma`` writers (XZ for Java, the SDK's ``lzma`` tool, ``lzma-rs``) were
    not run. A 16-byte run is over twice the longest one measured, and a run starting
    anywhere in the first 32 bytes is caught, where the latest start seen to reach 4 KiB
    of output over random heads was byte 10. The span bounds accidental collisions, not
    crafted input: a head of 32 or more bytes built to keep the range coder decoding
    before a zero run passes this rule (threat-model O10).
    """
    payload = prefix[_ALONE_HEADER_SIZE:]
    window = payload[: _ALONE_ZERO_RUN_SPAN + _ALONE_ZERO_RUN - 1]
    return bytes(_ALONE_ZERO_RUN) in window


def _starts_alone_stream(data: bytes) -> bool | None:
    """Whether the bytes after an Alone stream start another one, as ``lzma`` reads it.

    ``lzma.LZMAFile`` reads a second Alone stream after the first, so a concatenated
    ``.lzma`` is one payload. Alone has no magic to tell it by, so this checks what the
    header must hold: a properties byte liblzma decodes, and a zero first byte of
    range-coder data (byte 13), which every LZMA encoder writes. Text and most binary
    junk fail one of the two and are trailing data; junk that passes both (about one
    random tail in 870) is decoded as a stream and fails the read with
    ``CorruptionError``. A stream whose dictionary is over ``max_decoder_memory`` is
    refused by its decoder, as the first one is (``new_capped_decompressor``).
    """
    if len(data) <= _ALONE_HEADER_SIZE:
        return None
    return _alone_props_liblzma_decodes(data[0]) and data[_ALONE_HEADER_SIZE] == 0


class _ClampedAloneDecompressor:
    """An Alone decompressor whose header's dictionary size is clamped before liblzma sees it.

    liblzma reserves the dictionary the 13-byte header declares when it reads the
    header, so a detection probe (``StreamConfig.probe_read_bound``) rewrites bytes 1-4
    of its own copy to :func:`~archivey.internal.config.probe_lzma_dictionary` first.
    The output up to the bound is the same bytes. Each stream of a concatenated
    ``.lzma`` gets a new one, so every header the probe reaches is clamped.
    """

    def __init__(self, read_bound: int, natives: Natives = IN_PROCESS) -> None:
        self._read_bound = read_bound
        self._dec = natives.lzma_decompressor(format=lzma.FORMAT_ALONE)
        self._header: bytes | None = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._header is not None:
            header = self._header + data
            if len(header) < _ALONE_HEADER_SIZE:
                self._header = header
                return b""
            self._header = None
            dict_size = probe_lzma_dictionary(
                int.from_bytes(header[1:5], "little"), self._read_bound
            )
            data = header[:1] + dict_size.to_bytes(4, "little") + header[5:]
        return self._dec.decompress(data, max_length)

    @property
    def eof(self) -> bool:
        return self._dec.eof

    @property
    def unused_data(self) -> bytes:
        return self._dec.unused_data

    @property
    def needs_input(self) -> bool:
        return self._header is not None or self._dec.needs_input


def _new_alone_decompressor(
    read_bound: int | None, limits: DecoderLimits, natives: Natives = IN_PROCESS
) -> Decompressor:
    """A decompressor for one Alone stream.

    The dictionary its header declares is refused over ``max_decoder_memory`` by
    liblzma's ``memlimit``, on the first ``decompress`` call, so on read. That timing
    matters: ``.lzma`` has no magic, detection claims it by content probe alone, and a
    probe-only claim's read errors are stamped ``format_unconfirmed``
    (``error-handling``). The single-file reader opens a codec stream eagerly at
    ``open_archive``, before that provenance is attached, so a refusal raised on open
    would reach the caller unstamped, telling them to raise the cap for a file the
    probe may have misread. A probe (``read_bound``) clamps the dictionary instead.
    """
    if read_bound is None:
        return new_capped_decompressor(limits, lzma.FORMAT_ALONE, natives)
    return _ClampedAloneDecompressor(read_bound, natives)


class LzmaAloneCodec(_LzmaErrorCodec):
    """Legacy LZMA Alone (``.lzma``) — framed standalone stream, not raw FORMAT_RAW."""

    codec = Codec.LZMA_ALONE
    stream_format = StreamFormat.LZMA_ALONE
    # No exact magic: the properties byte is too weak; recognition is by content probe.

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        # A rewind re-decompresses from the start; the outer ArchiveStream warns (see
        # rewind_warning).
        return FramedDecompressorStream(
            source,
            functools.partial(
                _new_alone_decompressor,
                config.probe_read_bound,
                config.decoder_limits,
                natives_for(config.process_isolation),
            ),
            codec_name="lzma",
            magic=_starts_alone_stream,
            collector=config.collector,
            report_trailing_data=config.report_trailing_data,
        )

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        return RewindWarning("lzma")

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        header = ctx.peek_header(_ALONE_HEADER_SIZE)
        if len(header) < _ALONE_HEADER_SIZE:
            return
        size = int.from_bytes(header[5:13], "little")
        if size != _ALONE_UNKNOWN_SIZE:
            member.size = size

    def content_probe(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """Recognize LZMA Alone: plausible 13-byte header that then yields decode output.

        A source no longer than the 13-byte header carries no range-coder payload and
        cannot be an Alone stream — the whole of the measured real-world false-positive
        set. When ``source_length`` is unknown the check is skipped.

        A zero run at the start of the range-coder data is refused before any decode
        (``_alone_payload_has_zero_run``): it decodes cleanly, but no measured encoder writes it.

        Completeness and the bounded decode share ``_decodes_sample``; Alone additionally
        requires a positive output length (an empty successful read is not a claim).
        """
        if not _alone_header_plausible(prefix) or not self.available:
            return False
        if _alone_payload_has_zero_run(prefix):
            return False
        if source_length is not None and source_length <= _ALONE_HEADER_SIZE:
            return False
        return self._decodes_sample(
            prefix,
            source_length=source_length,
            require_output=True,
            isolation=isolation,
        )


LZMA_DICTIONARY_FILTERS: dict[int, str] = {
    lzma.FILTER_LZMA1: "LZMA",
    lzma.FILTER_LZMA2: "LZMA2",
}

# stdlib exposes no public decoder for a raw LZMA1/LZMA2 property blob → filter dict;
# zipfile and py7zr rely on the same private helper. Bind once at import, loudly.
_raw_decode_filter_properties = getattr(lzma, "_decode_filter_properties", None)
if _raw_decode_filter_properties is None:  # pragma: no cover
    raise ImportError(
        "This Python's `lzma` module no longer exposes `_decode_filter_properties`, which "
        "archivey needs to decode raw LZMA properties (ZIP method 14, 7z LZMA/LZMA2 "
        "coders). Please report this to archivey (with your Python version)."
    )
_decode_filter_properties: Callable[[int, bytes], dict] = _raw_decode_filter_properties


def decode_lzma_filter_properties(filter_id: int, props: bytes, *, what: str) -> dict:
    """liblzma filter dict for a raw LZMA1/LZMA2 property blob.

    7-Zip accepts LZMA1 ``lc + lp`` up to 12 (``-mm=LZMA:lc=8`` writes it, in 7z and in
    ZIP method 14); liblzma decodes at most 4. Such a properties byte is well formed,
    so it raises ``UnsupportedFeatureError`` naming ``what`` (the container's coder).
    Any other blob liblzma refuses is malformed: ``CorruptionError`` naming ``what``.
    The caller adds its archive context.
    """
    try:
        return _decode_filter_properties(filter_id, props)
    except (lzma.LZMAError, ValueError) as exc:
        split = _split_lzma_props(props[0]) if len(props) == 5 else None
        if filter_id == lzma.FILTER_LZMA1 and split is not None:
            lc, lp, _pb = split
            if lc + lp > _LIBLZMA_LCLP_MAX:
                raise UnsupportedFeatureError(
                    f"{what} with lc={lc}, lp={lp} is not supported: "
                    f"liblzma decodes lc + lp up to {_LIBLZMA_LCLP_MAX}"
                ) from exc
        raise CorruptionError(f"Malformed {what} properties") from exc


class _RawLzmaCodec(_LzmaErrorCodec):
    """Raw LZMA1/LZMA2 (FORMAT_RAW + properties); container-only (no standalone stream)."""

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        if params.filters is None:
            raise ValueError(
                "raw LZMA decoding requires filter properties (CodecParams.filters)"
            )
        # The 7z coder properties and the ZIP method-14 header both arrive here as
        # decoded filter dicts, so this one check covers both containers. A filter
        # with no ``dict_size`` (7z LZMA without properties) gets liblzma's preset
        # default, which the archive did not choose.
        for spec in params.filters:
            if spec.get("id") in LZMA_DICTIONARY_FILTERS and "dict_size" in spec:
                check_decoder_memory(
                    spec["dict_size"],
                    limits=config.decoder_limits,
                    what=f"{LZMA_DICTIONARY_FILTERS[spec['id']]} dictionary size",
                    usage=config.usage,
                )
        filters = params.filters
        # The coder's input span. A 7z AES stage decrypts whole blocks, so its output
        # runs up to 15 pad bytes past the next coder's input; ``pack_size`` (the AES
        # coder's unpack size) is the span 7-Zip reads, and the pad is not in it.
        # The slice does not clamp to its source's own size: reading on lets a
        # truncated source raise its own error (the AES stage's mid-block one).
        if params.pack_size is not None and not isinstance(source, (str, os.PathLike)):
            source = SlicingStream(
                source,
                length=params.pack_size,
                owns_inner=False,
                probe_source_size=False,
            )
        # One stream, as 7-Zip reads it: the data ends where the declared size or
        # the end marker says, and any byte of the span after that (a zero too,
        # with one exception for LZMA1, see _LzmaToSizeDecoder) is "Data Error"
        # there and DataAfterEndError here. ``LZMAFile`` would instead have started
        # a second raw stream on those bytes and delivered it as content. Raw LZMA
        # is container-only, so the stream always refuses them (``refuse_input_after_end``).
        natives = natives_for(config.process_isolation)
        if params.unpack_size is None:
            return FramedDecompressorStream(
                source,
                lambda: natives.lzma_decompressor(
                    format=lzma.FORMAT_RAW, filters=filters
                ),
                codec_name="lzma",
                magic=_no_second_lzma_stream,
                zero_padding=False,
                collector=config.collector,
                refuse_input_after_end=True,
            )
        size = params.unpack_size
        lzma2 = any(spec.get("id") == lzma.FILTER_LZMA2 for spec in filters)
        return DecompressorStream(
            source,
            make_decoder=lambda _p, _i: _LzmaToSizeDecoder(
                filters, size, lzma2=lzma2, natives=natives
            ),
            collector=config.collector,
            codec_name="lzma",
            refuse_input_after_end=True,
        )


def _no_second_lzma_stream(data: bytes) -> bool:
    """A raw LZMA coder holds one stream: what follows its end starts no other."""
    del data
    return False


# Input held back from liblzma until the source ends (see _LzmaToSizeDecoder): the
# byte that may complete the output, and one zero byte 7-Zip's encoder may write after
# it. That one byte is the whole tolerance; a stream with more input after its output
# goes through _probe, where only an end marker may fill it.
_LZMA_HELD_BACK = 2
# A coder that declares no output holds at most an empty stream: five range-coder
# bytes, or those and an end marker (10 bytes from liblzma). More than this is input
# it does not use. The bound leaves a few bytes of slack over the measured length, so
# that a producer that flushes a little more is not refused for it.
_LZMA_EMPTY_STREAM_MAX = 16
# Zeros fed after a stream's input to read its range coder's end, and the most output
# asked of them (_LzmaToSizeDecoder._check_range_coder_end).
_LZMA_ZEROS = b"\x00" * 16
_LZMA_ZEROS_OUTPUT = 64
# The error when an LZMA2 stream reaches its declared size with no end marker after it.
_LZMA2_NO_END_MARKER = (
    f"{truncated_message('LZMA2')}: no end marker after its declared size"
)

# _LzmaToSizeDecoder's states: decoding; output at the declared size, looking for an
# end marker in the input left; an end marker before that size; settled.
_RUN, _AT_SIZE, _ENDED_SHORT, _DONE = range(4)


class _LzmaToSizeDecoder(BaseDecoder):
    """Raw LZMA1/LZMA2 decoded to its declared output size, with the input checked.

    A raw LZMA1 stream may be written without an end marker (7-Zip's default in 7z,
    ZIP method 14 with general-purpose bit 1 clear): it ends where its known output
    size says, and liblzma cannot tell that from the input. So output stops at
    ``size``, and the input must end there too, as 7-Zip checks: right after the
    byte that completes the output, or one zero byte later (7-Zip's encoder flushes
    its range coder one byte past where liblzma stops reading, about once in 70
    streams, and that byte is zero), with the range coder at its end
    (:meth:`_check_range_coder_end`); or after an end marker. Anything else is input
    the member declares and does not use, :class:`DataAfterEndError` through the
    stream's ``refuse_input_after_end``.

    How much input liblzma used is not observable while it decodes in bulk, since
    its ``needs_input`` is false whenever an output limit is reached. So the last
    ``_LZMA_HELD_BACK`` bytes fed are held back until the source ends, then given to
    it one at a time: the byte on which the output reaches ``size`` is where the
    stream ends. A stream that reaches ``size`` before them has at least two bytes of
    input left, which only an end marker may fill; the rest is decoded one output
    byte at a time to find it (``_AT_SIZE``).

    An end marker before ``size`` leaves the output short (``TruncatedError``), and
    input after that marker is still refused. LZMA2 always ends with its end byte,
    so a stream that reaches ``size`` without one is truncated too. No shipped reader
    builds this decoder for LZMA2: 7z gives an LZMA2 chain no ``unpack_size`` (its end
    byte ends it, and the pipeline checks the size it decoded), and ZIP has no LZMA2
    method. The ``lzma2`` branches serve a direct
    ``open_codec_stream(Codec.LZMA2, ..., params=CodecParams(unpack_size=...))``.
    """

    def __init__(
        self,
        filters: list[dict],
        size: int,
        *,
        lzma2: bool,
        natives: Natives = IN_PROCESS,
    ) -> None:
        self._filters = filters
        self._size = size
        self._lzma2 = lzma2
        self._natives = natives
        self._decomp = natives.lzma_decompressor(
            format=lzma.FORMAT_RAW, filters=filters
        )
        self._produced = 0
        # Input not yet given to liblzma: the bytes held back, and input kept while
        # a zero output limit allowed no decoding.
        self._held = b""
        self._pending = b""
        self._fed = False
        # A coder that declares no output: its input, collected (_finish_empty).
        self._empty: bytes | None = b"" if size == 0 else None
        self._state = _AT_SIZE if size == 0 else _RUN

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        del point, inner
        return _LzmaToSizeDecoder(
            self._filters, self._size, lzma2=self._lzma2, natives=self._natives
        )

    def _surplus(self) -> None:
        """The input holds bytes after the stream's end: the stream refuses them."""
        self._input_after_end = True
        self._state = _DONE

    def _decode(self, data: bytes, limit: int) -> bytes:
        out = self._decomp.decompress(data, limit)
        self._produced += len(out)
        if self._decomp.eof:
            # An end marker: at the size, or before it.
            self._state = _DONE if self._produced == self._size else _ENDED_SHORT
            if self._decomp.unused_data:
                self._surplus()
        elif self._produced == self._size:
            self._state = _AT_SIZE
        return out

    def _check_range_coder_end(self, rest: bytes) -> None:
        """Settle a stream whose output reached its size on its last input bytes.

        ``rest`` is the input after the byte that completed the output: for LZMA1,
        nothing or one zero byte. A stream without an end marker ends where its
        range coder's code is zero, which is what 7-Zip checks there. liblzma does
        not expose the code, so it is read from what liblzma decodes when the input
        goes on with zeros: from a zero code every bit decodes as 0, so the output is
        zero bytes and nothing else, while any other code decodes a one bit within a
        few bytes (a non-zero byte, an error, or an end marker). An end marker is the
        stream's end too, when it lies in the real input, before the zeros.

        The simpler test, asking liblzma for one more byte of the real input, does
        not work: 7-Zip's own encoded 7z headers decode one more byte there. What
        this cannot see is a declared size that cuts off only zero bytes, measured
        on 7-Zip 23.01's ZIP LZMA: their encoding leaves the code at zero, and the
        bytes hidden that way are zeros.
        """
        try:
            more = self._decomp.decompress(rest + _LZMA_ZEROS, _LZMA_ZEROS_OUTPUT)
        except lzma.LZMAError:
            self._surplus()
            return
        if self._decomp.eof:
            ok = not more and len(self._decomp.unused_data) >= len(_LZMA_ZEROS)
        elif self._lzma2:
            self._pending_error = TruncatedError(_LZMA2_NO_END_MARKER)
            self._state = _DONE
            return
        else:
            ok = not more.strip(b"\x00")
        if ok:
            self._state = _DONE
        else:
            self._surplus()

    def _probe(self, data: bytes) -> None:
        """Look for an end marker in ``data``, input after the output reached size.

        A decoded byte is output the coder does not declare: surplus. This has no
        range-coder test: from a zero code liblzma decodes a zero byte, so zero bytes
        here are surplus too. That is deliberate. 7-Zip 23.01 refuses two zero bytes
        after a stream without an end marker (and one too, unless its encoder wrote
        it), so the only zero byte accepted is the one ``_check_range_coder_end``
        sees, right after the byte that completes the output.
        """
        if self._empty is not None:
            self._empty += data
            if len(self._empty) > _LZMA_EMPTY_STREAM_MAX:
                self._surplus()
            return
        if not data and self._decomp.needs_input:
            return
        try:
            out = self._decomp.decompress(data, 1)
        except lzma.LZMAError:
            self._surplus()
            return
        if out:
            self._surplus()
        elif self._decomp.eof:
            self._state = _DONE
            if self._decomp.unused_data:
                self._surplus()

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        self._fed = self._fed or bool(chunk)
        if self._state == _AT_SIZE:
            self._probe(chunk)
            return DecodeOut(b"")
        if self._state != _RUN:
            if chunk:
                self._surplus()
            return DecodeOut(b"")
        if chunk:
            held = self._held + chunk
            self._held = held[-_LZMA_HELD_BACK:]
            data = self._pending + held[:-_LZMA_HELD_BACK]
        else:
            data = self._pending
        self._pending = b""
        limit = self._size - self._produced
        if max_length >= 0:
            limit = min(limit, max_length)
        if limit == 0:
            self._pending = data
            return DecodeOut(b"")
        out = self._decode(data, limit)
        if self._state == _AT_SIZE:
            # The size is reached before the held-back bytes: they and anything
            # after them may only be an end marker.
            held, self._held = self._held, b""
            self._probe(held)
        elif self._decomp.eof and self._held:
            # An end marker before the held-back bytes: they are after it.
            self._surplus()
        return DecodeOut(out)

    def flush(self) -> DecodeOut:
        out = bytearray()
        if self._state == _RUN:
            if self._pending or not self._decomp.needs_input:
                out += self._decode(self._pending, self._size - self._produced)
                self._pending = b""
            held, self._held = self._held, b""
            if self._state == _AT_SIZE:
                self._probe(held)
            elif self._decomp.eof:
                if held:
                    self._surplus()
            else:
                out += self._feed_one_at_a_time(held)
        if self._state == _AT_SIZE:
            if self._empty is not None:
                self._finish_empty()
            elif self._lzma2:
                self._pending_error = TruncatedError(_LZMA2_NO_END_MARKER)
                self._state = _DONE
            else:
                # Input after the output's end that holds no end marker.
                self._surplus()
        elif self._state == _ENDED_SHORT:
            self._pending_error = TruncatedError(
                f"LZMA stream ends after {self._produced} of its declared "
                f"{self._size} bytes"
            )
            self._state = _DONE
        elif self._state == _RUN:
            self._pending_error = TruncatedError(
                "File is truncated" if self._fed else "File is empty"
            )
            self._state = _DONE
        return DecodeOut(bytes(out))

    def _feed_one_at_a_time(self, held: bytes) -> bytes:
        """Decode the held-back bytes singly, to see which one ends the output."""
        out = bytearray()
        for i in range(len(held)):
            if self._state != _RUN:
                break
            out += self._decode(held[i : i + 1], self._size - self._produced)
            if self._state == _RUN:
                continue
            rest = held[i + 1 :]
            if self._state == _AT_SIZE:
                if not self._lzma2 and rest in (b"", b"\x00"):
                    self._check_range_coder_end(rest)
                else:
                    self._probe(rest)
            elif rest:
                self._surplus()
        return bytes(out)

    def _finish_empty(self) -> None:
        """Settle a coder that declares no output, from its whole input."""
        data = self._empty or b""
        self._empty = None
        if not data:
            self._pending_error = TruncatedError("File is empty")
            self._state = _DONE
            return
        self._check_range_coder_end(data)

    @property
    def finished(self) -> bool:
        return self._state == _DONE and not self._input_after_end

    @property
    def needs_input(self) -> bool:
        if self._state != _RUN:
            return True
        return not self._pending and self._decomp.needs_input


class LzmaCodec(_RawLzmaCodec):
    codec = Codec.LZMA


class Lzma2Codec(_RawLzmaCodec):
    codec = Codec.LZMA2
