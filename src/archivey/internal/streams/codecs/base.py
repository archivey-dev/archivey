"""The pieces every codec shares: the :class:`Codec` ids, :class:`CodecParams`, the
:class:`StreamCodec` base class, helpers that read a source without moving it, and the
format values several codecs must agree on (the zlib ``wbits``, the gzip magic, the bzip2
stream header).
"""

from __future__ import annotations

import io
import lzma
import os
import re
import zlib
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from typing import BinaryIO, ClassVar

from archivey.config import ProcessIsolation
from archivey.exceptions import (
    ArchiveyError,
    PackageNotInstalledError,
    TruncatedError,
    exception_detail,
)
from archivey.internal.config import (
    DEFAULT_STREAM_CONFIG,
    DecoderLimits,
    StreamConfig,
)
from archivey.internal.detection_workspace import DETECTION_LIMIT
from archivey.internal.streams.archive_stream import (
    ExceptionTranslator,
    RewindWarning,
)
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV
from archivey.internal.streams.decompressor_stream import truncated_message
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    ContainerFormat,
    MagicSignature,
    MissingComponent,
    StreamFormat,
)

CodecSource = str | os.PathLike[str] | BinaryIO


class Codec(Enum):
    """The codecs the stream layer can decompress (the ``compressed-streams`` table).

    Single-file/TAR stream formats and 7z/ZIP folder coders both resolve to these.
    Filter-only entries (Delta, the BCJ family) are not opened standalone — they compose
    into a raw-LZMA filter chain (built by the 7z reader); their LZMA filter ids
    are recorded in :data:`LZMA_FILTER_IDS`.
    """

    STORED = "stored"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"
    LZIP = "lzip"
    LZMA_ALONE = "lzma_alone"  # legacy LZMA Alone file format (FORMAT_ALONE)
    LZMA = "lzma"  # raw LZMA1 (FORMAT_RAW + properties)
    LZMA2 = "lzma2"  # raw LZMA2 (FORMAT_RAW + properties)
    DEFLATE = "deflate"  # raw deflate (zlib -15)
    ZLIB = "zlib"  # zlib-wrapped deflate
    ZSTD = "zstd"
    LZ4 = "lz4"
    BROTLI = "brotli"
    UNIX_COMPRESS = "unix_compress"  # LZW (.Z)
    PPMD = "ppmd"
    DEFLATE64 = "deflate64"
    # Filter-only (composed with raw LZMA; see LZMA_FILTER_IDS).
    DELTA = "delta"
    BCJ_X86 = "bcj_x86"
    BCJ_ARM = "bcj_arm"
    BCJ_ARMT = "bcj_armt"
    BCJ_PPC = "bcj_ppc"
    BCJ_SPARC = "bcj_sparc"
    BCJ_IA64 = "bcj_ia64"
    BCJ_ARM64 = "bcj_arm64"
    BCJ_RISCV = "bcj_riscv"


# liblzma raw-filter ids for the filter-only codecs. Each one but ARM64 and RISC-V can
# join a 7z raw liblzma chain; those two are decoded in Python (see sevenzip_pipeline).
LZMA_FILTER_IDS: dict[Codec, int] = {
    Codec.DELTA: lzma.FILTER_DELTA,
    Codec.BCJ_X86: lzma.FILTER_X86,
    Codec.BCJ_ARM: lzma.FILTER_ARM,
    Codec.BCJ_ARMT: lzma.FILTER_ARMTHUMB,
    Codec.BCJ_PPC: lzma.FILTER_POWERPC,
    Codec.BCJ_SPARC: lzma.FILTER_SPARC,
    Codec.BCJ_IA64: lzma.FILTER_IA64,
    # liblzma's ids; Python's lzma refuses them, so archivey decodes them in Python.
    Codec.BCJ_ARM64: FILTER_ARM64,
    Codec.BCJ_RISCV: FILTER_RISCV,
}


@dataclass(frozen=True)
class CodecParams:
    """Per-open parameters that vary by container/coder.

    - ``filters`` — the ``lzma`` raw filter chain (required for raw LZMA1/LZMA2; this is
      where Delta/BCJ stages and the coder properties enter).
    - ``properties`` — raw coder properties blob (e.g. 7z PPMd var.H parameters).
    - ``ppmd_order`` / ``ppmd_mem_size`` / ``ppmd_restore_method`` — ZIP method-98 PPMd8
      parameters (mutually exclusive with 7z ``properties`` for :class:`PpmdCodec`).
    - ``unpack_size`` — known uncompressed output length (7z folder unpack size). Passed
      to PPMd as ``max_length`` so PPMd7 cannot overshoot without an end mark. Raw
      LZMA1/LZMA2 stop reading at it; pass it only for a stream that may have no end
      marker (ZIP LZMA with bit 1 clear, a 7z LZMA1 chain), since it also hides output
      past that size. An end marker found right at it is still checked. Raw
      DEFLATE under rapidgzip hands over to zlib at it, when the container sets no
      ``StreamConfig.expected_decompressed_size`` (a 7z coder).
    - ``pack_size`` — known compressed length for the PPMd coder input (7z pack stream /
      ZIP compressed size / sized view). Raw LZMA reads no input past it, so a 7z AES
      pad after it is not input after the end marker. Must match the bytes passed to
      ``PpmdDecoder.feed`` (not an enclosing member size). Gates post-eof empty
      drains; when omitted, PPMd recovery stays conservative (single capped NUL only).
    - ``single_stream`` — the coder's data is one stream of its codec: a bzip2 ZIP
      member or 7z coder. The decoder ends at the first stream's end rather than
      reading a further stream as a concatenated file's, so a further stream is
      input after the end, which a
      ``refuse_input_after_end`` stream refuses. Under the bzip2 accelerator, which
      reads on into a further stream, the read hands over to the standard library
      where one starts (``bzip2_codec._Bzip2Layout``). A Zstd ZIP member and a 7z
      Zstd or LZ4 coder do not set it: there concatenated frames count together
      against the declared size, as RFC 8878 defines Zstd data as one or more frames
      and the LZ4 frame format lets frames be appended.
      Raw LZMA1/LZMA2 needs no flag: it is container-only and always ends at its first
      end marker, refusing any input after it.
    - ``input_runs_on`` — the source does not end where the coder's data does: a ZIP
      member read from a stream that cannot seek, its sizes in a data descriptor after
      its data, is followed by the rest of the archive. A codec must then not wait for
      the source's end before decoding. Only PPMd8 reads it (it otherwise holds its
      input until the whole pack is in); the other codecs ZIP uses decode as input
      arrives, and a ``refuse_input_after_end`` stream stops at their end.
    """

    filters: list[dict] | None = None
    properties: bytes | None = None
    ppmd_order: int | None = None
    ppmd_mem_size: int | None = None
    ppmd_restore_method: int = 0
    unpack_size: int | None = None
    pack_size: int | None = None
    single_stream: bool = False
    input_runs_on: bool = False


_DEFAULT_PARAMS = CodecParams()


@contextmanager
def _restoring_position(source: CodecSource) -> Generator[None, None, None]:
    """Put a stream source back at its position on exit. A path has no position."""
    if isinstance(source, (str, os.PathLike)):
        yield
        return
    start = source.tell()
    try:
        yield
    finally:
        source.seek(start)


@contextmanager
def _peeking(source: CodecSource) -> Generator[BinaryIO, None, None]:
    """Read ``source`` without moving it: a path is opened afresh, and a stream's position
    is put back on exit."""
    if isinstance(source, (str, os.PathLike)):
        with open(os.fspath(source), "rb") as f:
            yield f
        return
    with _restoring_position(source):
        yield source


def _source_tail(
    source: CodecSource, *, size: int, min_length: int
) -> tuple[int | None, bytes | None]:
    """``(source_byte_length, last size bytes)`` of ``source``, without moving it.

    ``(length, None)`` when the source is shorter than ``min_length``, and
    ``(None, None)`` when it cannot be read: a stream without ``seek``, ``tell`` or
    ``read``, one that says it cannot seek, or a read that fails.
    """
    try:
        if not isinstance(source, (str, os.PathLike)):
            seekable = getattr(source, "seekable", None)
            if any(
                getattr(source, name, None) is None for name in ("seek", "tell", "read")
            ):
                return None, None
            if seekable is not None and not seekable():
                return None, None
        with _peeking(source) as f:
            length = f.seek(0, io.SEEK_END)
            if length < min_length:
                return length, None
            f.seek(-size, io.SEEK_END)
            return length, f.read(size)
    except (OSError, io.UnsupportedOperation, ValueError, TypeError):
        return None, None


def _stream_prefix(source: CodecSource, size: int) -> bytes:
    """The first ``size`` bytes of ``source`` (fewer when it is shorter), read without
    moving it."""
    with _peeking(source) as f:
        f.seek(0)
        return f.read(size)


# zlib's ``wbits`` for raw DEFLATE (no header or trailer; ZIP, 7z and the resume
# decoders) and for a gzip member (header, then CRC-32 and ISIZE checked at its end).
RAW_DEFLATE_WBITS = -zlib.MAX_WBITS
GZIP_WBITS = 16 + zlib.MAX_WBITS
# The first two bytes of every gzip member (RFC 1952 ID1 and ID2).
GZIP_MAGIC = b"\x1f\x8b"
# A bzip2 stream header: ``BZh`` and the block-size digit 1 to 9. It must accept the same
# bytes as ``bzip2_codec._BZIP2_MAGIC`` (the ``_BZIP2_STREAMS`` magic that decides whether
# the standard library reads a further stream): the end handover
# (``_first_trailing_byte``) and the layout walk (``_bzip2_stream_starts``) rely on the
# two agreeing. The rapidgzip format gate in ``zlib_codec`` reads it too, so a change
# made for that gate moves what the two walks accept.
BZIP2_HEADER = re.compile(rb"BZh[1-9]")

# A frame, or a skippable frame (magic 0x184D2A50 to 0x184D2A5F), for both.
_SKIPPABLE_FRAME = (range(0x50, 0x60), b"\x2a", b"\x4d", b"\x18")

# Bytes a content probe decodes when the source is not fully visible: the sample is
# clamped to this whatever the caller peeked, because the false-positive measurement is
# for 4096 specifically; it equals ``DETECTION_LIMIT`` and, on every shipping budget,
# ``max_prefix_bytes``. A fully visible source (including the whole-source re-run in
# detection's ``_probe_completes``) is fed whole and drained to
# ``_PROBE_COMPLETENESS_OUTPUT``. A shorter sample let text through: 256 bytes of a Perl
# module starting ``package`` decode as a Brotli meta-block that only turns invalid
# further in (measured: 7 of 800 ``/usr/share/perl`` modules detected as Brotli at 256,
# none at 4096).
_PROBE_PREFIX = DETECTION_LIMIT
# Output drain when the whole source is visible and completeness is checked. Caps
# expansion bomb cost (a 4 KiB zlib sample can expand to ~4 MiB); large enough to
# catch the small/medium truncations that dominate measured fabrications.
_PROBE_COMPLETENESS_OUTPUT = 64 * 1024

# Optional bounded read-at callback for probes that follow a self-describing block chain
# past the peeked prefix (``compressed-streams``). ``None`` means the caller declined.
ProbeReadAt = Callable[[int, int], bytes | None]
# Optional hook for a probe that decodes more than the sample it was handed (the Brotli
# chain decode): ``charge_decode(n)`` asks to read and decode the total ``[0, n)`` of
# the source, and is called before the read, which it also bounds. ``True`` means the
# caller's budget covers it and ``n`` is charged; ``False`` means it does not, and the
# probe must keep the verdict it has without reading or decoding.
ProbeChargeDecode = Callable[[int], bool]


@dataclass(frozen=True)
class MetadataContext:
    """The reader-side hooks a codec's metadata extractor may call.

    Lets a codec's ``extract_metadata`` read what it needs from the source without the codec
    layer depending on the single-file reader. ``peek_header(n)`` returns the leading ``n``
    bytes of the compressed source without consuming it; ``probe_decompressed_size()``
    returns the decompressed size from the stream index/trailer when cheaply available
    (else ``None``); ``probe_lzip_index()`` returns
    ``(decompressed_size, combined_crc32)`` from one seekable lzip index scan when
    available (else ``None``); ``peek_trailer(n)`` returns the last ``n`` bytes of the
    compressed source when it can reach its end cheaply (else ``None``, also for a
    source shorter than ``n``).
    """

    peek_header: Callable[[int], bytes]
    probe_decompressed_size: Callable[[], int | None]
    probe_lzip_index: Callable[[], tuple[int, int] | None]
    peek_trailer: Callable[[int], bytes | None]


class _ProbeSample(io.BytesIO):
    """A probe's sample, served at most ``_PROBE_PREFIX`` bytes per read.

    It stays seekable, so the Brotli decoder can still tell bytes after a stream's end
    from damage: on a decode error it replays from the start and then hands over, one
    byte at a time, the input of the call that failed. The smaller reads bound that
    byte-at-a-time stretch to one read. With the decoder's own 64 KiB reads, a 1 MiB
    chain-decode sample that fails took a second to reject; 4 KiB reads take a few
    milliseconds.
    """

    def read(self, size: int | None = -1, /) -> bytes:
        if size is None or size < 0 or size > _PROBE_PREFIX:
            size = _PROBE_PREFIX
        return super().read(size)


# --- the codec descriptors -------------------------------------------------------------


# Detection probes decode uncapped: capping a probe would make detection answer "not
# this format" for a stream whose dictionary is over the cap, and a caller who opened
# it with ``DecoderLimits.UNLIMITED`` would get the wrong format rather than the read
# they asked for. ``DecoderLimits`` says so; the open that follows detection applies
# the caller's limits. Nor does a probe reserve what the archive declares: each one
# sets ``StreamConfig.probe_read_bound`` to the output it reads, and the LZMA family
# builds its decoder with only the dictionary that read needs (liblzma would
# otherwise reserve the declared size, up to 4 GiB, which under ``RLIMIT_AS`` or a
# strict commit limit is a ``MemoryError`` during detection). zstd cannot shrink a
# window, so a probe lowers ``window_log_max`` to libzstd's default and a frame over
# it is "can't tell".
_PROBE_STREAM_CONFIG = replace(
    DEFAULT_STREAM_CONFIG, decoder_limits=DecoderLimits.UNLIMITED
)


class StreamCodec:
    """One single-stream codec: its behavior, detection signals, and requirement.

    Subclasses override the behavior methods (:meth:`open`, :meth:`translate`, optionally
    :meth:`translator` / :meth:`extract_metadata` / :meth:`content_probe`) and declare the
    detection data as class attributes (``stream_format`` / ``magic``) plus an
    optional-dependency ``requirement``. The standalone single-file ``ArchiveFormat`` and its
    file extension are *derived* from ``stream_format`` (see the properties below). Instances
    are collected in :data:`STREAM_CODECS`, which the detector, the single-file reader, and
    the registry read directly — so a new standalone codec is a single subclass, with no edits
    to those consumers (see ``compressed-streams``). Container-only / filter-only codecs
    override just ``open`` + ``translate``.
    """

    codec: ClassVar[Codec]
    # The single-file/TAR StreamFormat this codec decodes, when it is a stream format at all
    # (raw container coders such as DEFLATE/LZMA have none). This drives the derived
    # single-file format + extension below.
    stream_format: ClassVar[StreamFormat | None] = None
    # Exact magic signals for the standalone format, aggregated by the detector.
    magic: ClassVar[tuple[MagicSignature, ...]] = ()
    # The optional-dependency requirement (package / extra / hint + unlocked capability);
    # ``None`` for codecs served by the stdlib, which are always available.
    requirement: ClassVar[MissingComponent | None] = None
    # Other extensions files of this format are commonly given, besides the canonical one.
    # They matter most for the formats only a content probe recognises, whose probe runs
    # only for a name that claims the format.
    extension_aliases: ClassVar[tuple[str, ...]] = ()
    # Whether the decoder checks every byte it decodes against a checksum the format
    # requires (gzip's CRC-32, bzip2's CRCs, lzip's CRC-32, zlib's Adler-32), raising on
    # a mismatch before it reports the end. Formats whose checksum is optional per
    # frame (xz, zstd, LZ4) leave it False until their decoders report, per frame,
    # that one was present. Read by a stream's verification level.
    checks_content: ClassVar[bool] = False

    # --- derived single-file identity ---

    @property
    def single_file_format(self) -> ArchiveFormat | None:
        """The standalone single-file ``ArchiveFormat`` (``RAW_STREAM`` + ``stream_format``).

        ``None`` for a container-only codec (no ``stream_format``) and for ``STORED`` (a bare
        uncompressed stream is not a standalone single-file format).
        """
        sf = self.stream_format
        if sf is None or sf is StreamFormat.UNCOMPRESSED:
            return None
        return ArchiveFormat(ContainerFormat.RAW_STREAM, sf)

    @property
    def extensions(self) -> tuple[str, ...]:
        """Standalone file extension(s): the canonical one, derived from the format (e.g.
        ``GZIP`` → ``.gz``) by ``ArchiveFormat.file_extension()``, then ``extension_aliases``.
        """
        fmt = self.single_file_format
        if fmt is None:
            return ()
        return (f".{fmt.file_extension()}", *self.extension_aliases)

    # --- behavior (overridden by subclasses) ---

    def open(
        self, source: CodecSource, params: CodecParams, config: StreamConfig
    ) -> BinaryIO:
        raise NotImplementedError

    def check_accelerator(self, source: CodecSource, config: StreamConfig) -> None:
        """For an accelerator set to ``ON``, raise what :meth:`open` raises before
        decoding because it cannot run: its package is absent, ``source`` cannot seek, or
        no child process can run it (:func:`rapidgzip_child_unavailable_reason`). Starts
        no process; it reads ``source`` only where :meth:`open` would decide on its first
        bytes to leave it to the standard library (a gzip header zlib refuses), and then
        raises nothing, as :meth:`open` does. A child that fails to start is not
        known until one is started, so that error stays with :meth:`open`. ``AUTO`` is
        not resolved here: the open resolves it against the config the registry
        prepares, which this caller does not have, and logs its own fallback.
        Default: the codec has no accelerator."""
        return

    def translate(self, exc: Exception) -> ArchiveyError | None:
        """Map a raw decoder exception to an ``ArchiveyError`` subclass, or ``None``."""
        return None

    @staticmethod
    def _eof_truncation(exc: Exception, label: str) -> TruncatedError | None:
        """The :class:`TruncatedError` for an ``EOFError`` from a ``label`` stream's
        decoder, or ``None`` for any other exception. A :meth:`translate` calls it for
        its ``EOFError`` arm, so every codec words a truncation the same way."""
        if isinstance(exc, EOFError):
            return TruncatedError(
                f"{truncated_message(label)}: {exception_detail(exc)}"
            )
        return None

    def translator(self, config: StreamConfig) -> ExceptionTranslator:
        """The translator matching the backend chosen for ``config``.

        Default is the static :meth:`translate`; codecs whose backend varies by config (the
        gzip/bzip2 accelerators have a different exception taxonomy) override this.
        """
        return self.translate

    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """Fill ``ArchiveMember`` fields from the source. Default: no extra metadata."""
        return

    def content_probe(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """Whether ``prefix`` is recognized as this codec's stream.

        Default: this codec has no content probe (it is identified by exact magic). Codecs
        without a usable magic (Brotli; zlib's too-unspecific header; LZMA Alone) override
        this. ``source_length`` is optional: when detection knows the cheap byte size of
        the source it is passed through so a probe can reject declared framing that
        cannot fit, or an incomplete decode when the whole source is visible; ``None``
        means "unknown — do not reject on that basis." ``read_at`` is an optional bounded
        read facility for probes that follow a self-describing block chain past the
        peeked prefix; absent by default. ``charge_decode`` meters a decode past the
        sample (see ``ProbeChargeDecode``); absent means the probe is not metered.
        """
        return False

    def magic_behind_prefix(self, prefix: bytes) -> bool:
        """Whether this codec's exact magic sits behind a structural prefix it defines.

        Default: this codec's magic, if it has one, starts at the offset the magic table
        declares. zstd overrides this — a run of skippable frames may legally precede its
        first regular frame, and their declared sizes make the walk exact arithmetic over
        already-peeked bytes (see ``zstd_framing``). A hit is an exact magic match, so
        detection reports it as one; it is not a magic-table entry because the structural
        prefix alone must not be claimed as the format.
        """
        return False

    def rewind_warning(self, config: StreamConfig) -> RewindWarning | None:
        """How to phrase ``STREAM_REWIND_REDECOMPRESSES`` for this codec.

        It no longer decides *whether* to report: that is the seek's measured re-decode
        distance, computed by ``ArchiveStream`` against the live seek-point table (a
        format that can carry an index does not always have a useful one — a single-block
        ``.xz`` re-decodes from byte zero like a codec with none). This only supplies the
        codec name and, where one exists, the accelerator to mention.

        ``None`` means "a backward seek here re-decodes nothing" — true only of
        ``STORED``. The default names the codec and no accelerator; ``suggest_install``
        is meaningless without one.
        """
        return RewindWarning(self.codec.value, suggest_install=False)

    def prepare_config(self, source: CodecSource, config: StreamConfig) -> StreamConfig:
        """Fill in what this codec can learn from ``source`` before it is resolved.

        :func:`open_codec_stream` calls it before :func:`resolve_codec`, so the
        translator and the rewind warning see the same config as ``open``. The default
        changes nothing.
        """
        return config

    # --- availability ---

    @property
    def available(self) -> bool:
        """Whether this codec's decompression backend is importable right now."""
        return self.requirement is None or self._backend_present()

    def _backend_present(self) -> bool:
        """Whether the optional backing package is importable (optional codecs override)."""
        return True

    def _missing(self, purpose: str, *, note: str = "") -> PackageNotInstalledError:
        """The error to raise from ``open()`` when this codec's backend is absent.

        Built from the declared ``requirement`` so the install advice matches what
        ``format_availability()`` reports for the same codec.
        """
        assert self.requirement is not None, (
            f"{type(self).__name__} raises PackageNotInstalledError but declares no requirement"
        )
        return PackageNotInstalledError(self.requirement.message(purpose, note=note))

    @property
    def probes_content(self) -> bool:
        """Whether this codec overrides the no-op base content probe (the detector uses it)."""
        return type(self).content_probe is not StreamCodec.content_probe

    @property
    def walks_magic_prefix(self) -> bool:
        """Whether this codec overrides the no-op base :meth:`magic_behind_prefix`."""
        return type(self).magic_behind_prefix is not StreamCodec.magic_behind_prefix

    # --- shared probe primitive ---

    def _decodes_sample(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        require_output: bool = False,
        sample_bytes: int = _PROBE_PREFIX,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """Whether a bounded ``prefix`` decodes cleanly through this codec (the probe primitive).

        A valid stream decodes some output (or runs out of the bounded prefix →
        ``TruncatedError``), while non-matching data raises a corruption error. Returns
        ``False`` when the backend is absent, so detection falls through to the extension
        guess. Operates on already-peeked bytes, so it consumes nothing from the source.

        **Completeness (bounded):** when ``source_length`` is known and does not exceed
        ``len(prefix)``, the probe holds the whole source. A decode that still wants more
        input after a bounded output drain (``_PROBE_COMPLETENESS_OUTPUT``) is then a
        rejection — a complete valid stream that finishes within that drain terminates.
        Streams whose full expansion exceeds the drain without hitting "needs more input"
        are not rejected here (the check is bounded, not a full drain). When the source is
        larger than the prefix, ``TruncatedError`` remains a match (there genuinely is more
        input). ``require_output`` rejects an empty successful read (LZMA Alone).
        ``sample_bytes`` widens the bounded sample past the detection window for a probe
        that has already read further (the Brotli chain decode); the output drain grows
        with it.
        """
        # The registry imports every codec module, and so this one: import it here.
        from archivey.internal.streams.codecs.registry import open_codec_stream

        if not self.available:
            return False
        fully_visible = source_length is not None and source_length <= len(prefix)
        # Feed the whole source when it is fully visible so "needs more input" means
        # incomplete; otherwise keep the bounded probe sample.
        sample = prefix[:source_length] if fully_visible else prefix[:sample_bytes]
        out_budget = (
            _PROBE_COMPLETENESS_OUTPUT
            if fully_visible
            else max(len(sample), _PROBE_PREFIX)
        )
        # The most output read below: the budget, then one byte past it.
        config = replace(
            _PROBE_STREAM_CONFIG,
            probe_read_bound=out_budget + 1,
            process_isolation=isolation,
        )
        try:
            with open_codec_stream(
                self.codec, _ProbeSample(sample), config=config
            ) as stream:
                if fully_visible:
                    # Drain up to the budget in chunks. A truncated high-ratio stream
                    # often yields its whole expansion on the first large read without
                    # raising; the next read is what surfaces TruncatedError.
                    #
                    # After filling the budget without a clean EOF, one extra byte
                    # distinguishes three outcomes: TruncatedError (reject — including
                    # a stream that ends *exactly* on the budget), more output (accept —
                    # complete stream larger than the drain), or empty (accept —
                    # terminated on the last budgeted byte). ``produced`` alone is
                    # enough; only Alone's ``require_output`` cares that any bytes
                    # came out.
                    produced = 0
                    while produced < out_budget:
                        chunk = stream.read(min(8192, out_budget - produced))
                        if not chunk:
                            break
                        produced += len(chunk)
                    if produced >= out_budget:
                        more = stream.read(1)
                        if more:
                            produced += len(more)
                    out_len = produced
                else:
                    out_len = len(stream.read(out_budget))
            if require_output:
                return out_len > 0
            return True
        except TruncatedError:
            # With the whole file in hand, the stream did not terminate; otherwise it
            # decoded fine and just ran out of the bounded prefix.
            return not fully_visible
        except ArchiveyError:
            return False
        except MemoryError:
            # A decoder the bound did not shrink (Brotli's window, up to 16 MiB) under
            # a tight memory limit: "can't tell", not a failed detection.
            return False
