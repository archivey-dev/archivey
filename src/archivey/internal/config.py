"""Internal views of :class:`ArchiveyConfig` and the limits it carries.

:class:`StreamConfig` is the stream layer's view of the config. The decoder-memory
checks and :class:`KeyDerivationBudget` enforce :class:`~archivey.config.DecoderLimits`
for the backends.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from archivey.config import (
    DEFAULT_ARCHIVEY_CONFIG,
    AcceleratorMode,
    ArchiveyConfig,
    DecoderLimits,
    ProcessIsolation,
)
from archivey.exceptions import ResourceLimitError
from archivey.internal.excluded_libraries import NO_EXCLUSIONS
from archivey.types import OptionalLibrary

if TYPE_CHECKING:
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.resource_usage import ResourceUsageRecorder
    from archivey.internal.streams.decompressor_stream import PrebuiltIndex

# Only the names other modules import from here. ``ArchiveyConfig`` and
# ``DEFAULT_ARCHIVEY_CONFIG`` are imported for use below, not re-exported —
# callers take those from ``archivey.config``.
__all__ = [
    "DEFAULT_STREAM_CONFIG",
    "AcceleratorMode",
    "DecoderLimits",
    "KeyDerivationBudget",
    "ProcessIsolation",
    "StreamConfig",
    "check_decoder_memory",
    "probe_lzma_dictionary",
    "stream_config_from_archivey",
    "without_accelerators",
]


@dataclass(frozen=True)
class StreamConfig:
    """Options that influence how compressed streams are opened.

    ``seekable`` is declared seek demand (``MemberStreams.SEEKABLE``): accelerator
    ``AUTO`` resolution and index construction key off it. ``streaming`` remains the
    archive access mode for backends that still need to know forward-only vs random.
    ``compressed_input_size`` is the known compressed byte length of the source (path
    size, slice length, …), used by ``use_rapidgzip`` AUTO's minimum-size gate; ``None``
    means unknown (AUTO keeps pre-threshold behaviour when truncation is also
    verifiable). ``expected_decompressed_size`` is a container-declared uncompressed
    length (ZIP central-dir size, …) used both to gate rapidgzip AUTO and to wrap the
    accelerator in a length-verifying stream. ``gzip_isize_backstop`` is set when a
    seekable gzip source has a readable ISIZE trailer — enough for AUTO to select
    rapidgzip with the ISIZE truncation check, but *not* a hard ``VerifyingStream``
    bound (ISIZE is mod 2**32 and multi-member trailers only cover the last member).
    ``gzip_isize`` is that trailer's value, which AUTO's ratio gate for a sequential
    read uses as an estimate of the decoded size and nothing else. ``source_seekable``
    is set by :func:`open_codec_stream` when the source is a path or a stream that can
    seek: a sequential read (no declared seek demand) can still go through an
    accelerator under AUTO, which needs a source it can seek. A reader may fill it
    first with the same value, as the ZIP reader does to save a copy per member.
    ``decoder_limits`` is the caller's :class:`~archivey.config.DecoderLimits`,
    carried down so a codec can refuse an archive-declared allocation before making
    it; it defaults to the public default rather than to "unlimited", because a
    :class:`StreamConfig` built directly (detection, tests) is still decoding a file
    someone else wrote. ``collector`` is the reader's (or ``open_stream``'s)
    diagnostic collector, so a codec stream that reports something itself — the xz,
    lzip and unix-compress ``SEEK_INDEX_DEGRADED`` — reports it under the caller's
    policy and into ``reader.diagnostics``; ``None`` falls back to
    :func:`~archivey.internal.diagnostics_collector.resolve_collector`'s throwaway. It
    is left out of equality: it says where reports go, not how the stream decodes.
    ``report_trailing_data`` is set where the codec stream *is* the file — a bare
    compressed file, a compressed TAR, ``open_stream`` — so bytes after the stream's
    end are something the caller was given and not told about, and the stream codecs
    report them as ``ARCHIVE_TRAILING_DATA``. ``refuse_input_after_end`` is set by the
    ZIP and 7z readers instead: there the source is exactly one coder's compressed data,
    whose size the archive declares, so a byte the codec leaves after its end (a zero
    byte too) is input the member declares and does not use. It may hide a second
    payload, and 7-Zip reports it as a data error, so the codec raises
    ``DataAfterEndError`` (a ``CorruptionError``; DR-3). The 7z reader cuts a coder's
    input at its declared size first, so a 7z AES stage's block padding is not in it.
    Raw LZMA is container-only and refuses such bytes whatever the flag says.
    ``probe_read_bound`` is set only by a detection probe: the most decompressed bytes
    it reads from the stream. A codec whose decoder reserves a window the archive
    declares builds it no larger than that read needs (:func:`probe_lzma_dictionary`
    for the LZMA family; zstd, which cannot shrink a window, lowers
    ``window_log_max``). Past the bound the stream may end or fail, so the probe reads
    no further. ``process_isolation`` is the caller's
    :class:`~archivey.config.ProcessIsolation`: a codec builds its native decoder
    through :func:`~archivey.internal.streams.codecs.isolated.natives_for` with it.
    ``seek_index`` is an xz index scan the single-file reader already
    made over this same source; the xz stream uses it in place of its own scan. Like
    ``collector`` it is left out of equality. So is ``usage``, the reader's
    :class:`~archivey.internal.resource_usage.ResourceUsageRecorder`: a codec passes it
    to :func:`check_decoder_memory`, which notes each declaration there. A detection
    probe builds its config without one, so a probe's sizes are never recorded.
    ``excluded_libraries`` is the caller's ``FormatPolicy.exclude_libraries``: a codec
    whose package it names opens as if the package were not installed.
    """

    streaming: bool = False
    seekable: bool = False
    use_rapidgzip: AcceleratorMode = AcceleratorMode.AUTO
    use_indexed_bzip2: AcceleratorMode = AcceleratorMode.AUTO
    compressed_input_size: int | None = None
    expected_decompressed_size: int | None = None
    gzip_isize_backstop: bool = False
    gzip_isize: int | None = None
    source_seekable: bool = False
    decoder_limits: DecoderLimits = DecoderLimits()
    process_isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES
    collector: DiagnosticCollector | None = field(default=None, compare=False)
    report_trailing_data: bool = False
    probe_read_bound: int | None = None
    refuse_input_after_end: bool = False
    seek_index: PrebuiltIndex | None = field(default=None, compare=False)
    usage: ResourceUsageRecorder | None = field(default=None, compare=False)
    excluded_libraries: frozenset[OptionalLibrary] = NO_EXCLUSIONS


def stream_config_from_archivey(
    config: ArchiveyConfig,
    *,
    streaming: bool,
    seekable: bool = False,
    refuse_input_after_end: bool = False,
    usage: ResourceUsageRecorder | None = None,
) -> StreamConfig:
    """Derive the codec-layer view from the public config and declared seek demand."""
    return StreamConfig(
        usage=usage,
        streaming=streaming,
        seekable=seekable,
        refuse_input_after_end=refuse_input_after_end,
        use_rapidgzip=config.use_rapidgzip,
        use_indexed_bzip2=config.use_indexed_bzip2,
        decoder_limits=config.decoder_limits,
        process_isolation=config.process_isolation,
        excluded_libraries=config.formats.exclude_libraries,
    )


def without_accelerators(config: StreamConfig) -> StreamConfig:
    """``config`` decoding with the standard library, whatever its accelerators say.

    Every accelerator setting a ``StreamConfig`` has is listed here once, so a new one
    added here reaches every path that must not start a child.
    """
    return replace(
        config,
        use_rapidgzip=AcceleratorMode.OFF,
        use_indexed_bzip2=AcceleratorMode.OFF,
    )


DEFAULT_STREAM_CONFIG = stream_config_from_archivey(
    DEFAULT_ARCHIVEY_CONFIG, streaming=False, seekable=False
)


# liblzma's smallest dictionary: the LZMA specification has a decoder round a smaller
# declaration up to it, so a clamp below it would change nothing.
_LZMA_DICT_MIN = 4096
# Output a filter ahead of LZMA2 in an xz chain may ask of LZMA2 beyond what it hands
# on: a BCJ filter holds back the bytes that may start an instruction (liblzma's x86
# filter, at most 5). 64 covers that with margin. The test on a delta + x86 + LZMA2
# chain at an 8 KiB bound needs a match 4 bytes past the bound, and an allowance of 0
# fails it. Allowances of 1 to 3 pass that test too, but only because liblzma rounds a
# declared dictionary up to a multiple of 16 bytes; they do not show that 1 byte of
# lookahead is enough. Only the xz inner-TAR probe has such a chain today, and its
# 512-byte bound sits under the 4 KiB floor.
_LZMA_FILTER_LOOKAHEAD = 64


def probe_lzma_dictionary(declared: int, read_bound: int | None) -> int:
    """The LZMA dictionary to decode with when at most ``read_bound`` bytes are read.

    An LZMA or LZMA2 match refers back at most as far as the output already produced,
    so a dictionary as large as the output decodes it exactly as the declared one
    does: liblzma's decoder produces only what it is asked for, and a dictionary it
    never fills is only reserved. A detection probe reads a few KiB; the declaration
    is the archive's, up to 4 GiB, and liblzma reserves all of it when the decoder is
    built — under ``RLIMIT_AS`` or a strict commit limit that is a ``MemoryError``
    during detection. ``None`` (not a probe) keeps the declared size.
    """
    if read_bound is None:
        return declared
    return min(declared, max(read_bound + _LZMA_FILTER_LOOKAHEAD, _LZMA_DICT_MIN))


def check_decoder_memory(
    declared: int,
    *,
    limits: DecoderLimits,
    what: str,
    counted_from: str | None = None,
    usage: ResourceUsageRecorder | None = None,
) -> None:
    """Refuse an archive-declared decoder allocation above ``max_decoder_memory``.

    ``usage`` is the reader's recorder; the declaration is noted there before the
    comparison, so a refused one is recorded at its full size.

    ``declared`` is the number the *archive* asked for: read out of a header field,
    not a measurement of anything, and not bounded by the file's own size. Or, when
    ``counted_from`` is given, a count the caller derived from header fields. ``what``
    names the field or count for the message, so a caller who raised the cap on
    purpose can tell which archive is asking and for how much.

    ``counted_from`` names the header values a derived count comes from, as a phrase
    ("the 4294967296-byte dictionary member 'a' declares"). RAR is the caller: it
    counts a dictionary only up to the unpacked bytes the read decodes, and the
    dictionary can be another member's. The message then says the count is
    counted, and from what, so it does not present the count as the number a header
    holds.

    Callers run this before the decoder object is constructed, because the
    allocation it guards is made inside a C extension, and what a refused native
    allocation does differs by extension. pyppmd 1.3.1's failure path is unsound —
    measured, ``Ppmd7Decoder(6, 0xFFFFFFFF)`` under a 2 GiB ``RLIMIT_AS`` aborts on
    ``double free or corruption`` with SIGABRT, leaving nothing to catch. liblzma
    does return ``MemoryError`` when the reservation itself fails, but a reservation
    that succeeds is the worse case there: the dictionary is touched as output is
    written, so a 151 KB stream declaring 4 GiB holds 1.1 GiB resident after
    producing 1 GiB of zeros, where the same stream declaring 1 MiB holds 59 MB.

    Lives here rather than in ``codecs/`` so the xz and lzip decoders, which the
    codec modules import, can call it without an import cycle.
    """
    if usage is not None:
        usage.note_decoder_memory(declared, what)
    cap = limits.max_decoder_memory
    if cap is None or declared <= cap:
        return
    if counted_from is None:
        detail, numbers = f"{what} declares {declared} bytes", "this number"
    else:
        detail = f"{what} is {declared} bytes, counted from {counted_from}"
        numbers = "these numbers"
    raise ResourceLimitError(
        f"Decoder limit reached: max_decoder_memory={cap} "
        f"({detail}). The archive chose {numbers}; "
        "raise DecoderLimits.max_decoder_memory if the archive is trusted."
    )


class KeyDerivationBudget:
    """The rounds of archive-declared key derivation one open archive may still run.

    One per reader, built from its :class:`~archivey.config.DecoderLimits` and shared
    by every key cache the reader holds. A cache calls :meth:`spend` on a miss,
    immediately before the derivation, so a hit costs nothing and the refusal lands
    before the work starts, which is the only place it helps: the derivation runs in
    ``hashlib`` with the GIL released and cannot be interrupted.

    ``spend`` is locked so two threads opening members at once cannot both pass the
    check on the same remaining budget. The derivation itself runs outside the lock.
    """

    __slots__ = ("_cap", "_lock", "_spent")

    def __init__(self, limits: DecoderLimits = DecoderLimits()) -> None:
        self._cap = limits.max_key_derivation_rounds
        self._spent = 0
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"<KeyDerivationBudget: {self._spent} of {self._cap} rounds spent>"

    @property
    def spent(self) -> int:
        """Rounds charged so far."""
        return self._spent

    def spend(self, rounds: int, *, what: str) -> None:
        """Charge ``rounds`` to the budget, or raise before the derivation runs.

        ``what`` names the scheme for the message, for example
        ``"RAR5 key derivation"``.
        """
        with self._lock:
            total = self._spent + rounds
            if self._cap is not None and total > self._cap:
                raise ResourceLimitError(
                    f"Decoder limit reached: max_key_derivation_rounds={self._cap} "
                    f"({what} at {rounds} rounds would bring this archive's total "
                    f"to {total}). The archive chose the cost and the number of "
                    f"keys; raise DecoderLimits.max_key_derivation_rounds if the "
                    f"archive is trusted."
                )
            self._spent = total
