"""Format detection: ``detect_format()``, which returns a :class:`~archivey.FormatInfo`.

Why the steps are in this order, what each one guards against, and how the budget bounds
them is in ``dev-docs/topics/detection.md``; this docstring covers the local path.

Detection is **magic-first** (an exact magic-byte match at the expected offset →
``CERTAIN``) with an extension fallback (``GUESS``). The magic and extension tables are
not hand-maintained here: each registered backend declares its ``MAGIC`` / ``EXTENSIONS``
as data and the detector aggregates them, so a new format becomes detectable by
registering its backend (see ``format-detection`` and ``backend-registry``).

Detection never consumes bytes from the source: paths keep one detection handle; a
seekable stream is restored to its **starting position** (the archive is taken to begin
wherever the stream is positioned when handed in); a non-seekable stream
is peeked through the :class:`~archivey.internal.source.ArchiveSource` the opener built,
whose replay prefix keeps the bytes for the backend. A raw non-seekable stream handed to
``detect_format`` directly loses what detection read, unless the caller buffers it.

Every front-of-source read goes through one detection-owned
:class:`~archivey.internal.detection_workspace.PrefixWorkspace` that grows monotonically —
extending the window reads only the delta, and bytes already in the prefix buffer are
not fetched again. The trailer read is outside that buffer: it seeks to its block and
restores the handle, and a later tier that grows the prefix over those bytes fetches
them again.

Formats without an exact magic are recognized by a **content probe**: Brotli (no signature
at all) and zlib (a 2-byte header too unspecific to trust, so its probe gates on that
header before decoding). Each probe is a function the backends declare as data — for the
stream codecs, on the codec descriptor — so the detector stays format-agnostic. Unless
``ArchiveyConfig.always_probe_content`` is set (``open_stream`` sets it), only the probe of
a format the source's extension names runs: on a nameless source a probe would be the only
evidence, and real binary files pass them. A built-in probe is matched by its stream; a
plugin format's, by the format itself, since every plugin format shares its stream with
ZIP and TAR. The probes also do not run on a prefix that is
evidence of a non-archive file: a structurally confirmed executable
(``ExecutableCue.STRONG``) or a known non-archive signature (``_PROBE_STOPPING_SIGNATURES``,
today OLE compound files), and the error then names that evidence. A non-archive signature
also stops the SFX scan.

The steps run strongest-signal-first: near magic → SFX scan → **far magic** → trailer
magic → self-checking header → content probes → extension. The signals ahead of the
probes are there for the same reason — a probe is the weakest evidence archivey has, and
one asked to judge arbitrary bytes will sometimes say yes:

- A **self-extracting** archive has no archive magic at offset 0 at all: a prefix
  (executable stub or ``#!`` launcher) comes first. When the leading bytes look
  prefix-shaped the detector searches forward for the backends' ``SFX_MAGIC`` within
  the shared ``SFX_MAX`` window and reports the payload start as ``payload_offset``
  (``PROBABLE`` / ``sfx_scan``). The cue is a cost gate — avoid reading 2 MiB from
  every file — not a false-positive defence; a format-owned validator rejects a
  decoy. See ``executable_cue`` and ``format-detection``'s "Executable-looking
  prefixes must not silently become a wrong stream format".
- **Far magic** is exact magic whose end offset lies outside the default window (today
  ISO 9660's ``CD001`` at 32 769), so it needs an extended peek taken on demand. It runs
  before the probes because a bootable or hybrid ISO reserves its first 32 KiB for
  bootloader code — the data class a probe accepts — and the exact magic was available at
  a known offset the whole time. The peek is size-gated: a source known to be smaller than
  the window never pays it.
- **Trailer magic** is exact magic at the start of a fixed-length block at the end of
  the source (today UDIF's ``koly`` block, the last 512 bytes). It runs after far magic,
  so an ISO that already matched is not asked for a tail read, and before the probes, so
  a zlib-first disk image is named as the image. A near-magic hit the trailer lists in
  ``preempts`` (bzip2, xz) is the same image: the magic is one block, and the trailer
  replaces it. The read is a cheap seek that restores the handle. A non-seekable source
  and an ``ArchiveStream`` are not seeked to the end; a tail already inside the prefix
  (a short pipe, which the far-magic peek reads to its end) still matches.
- A **self-checking header** is a first block that proves its format with no magic in
  it (``ReadBackend.HEADER_CHECKS``; today a v7 TAR header, whose checksum must equal
  its byte sum and whose numeric fields must parse). It is ``PROBABLE`` /
  ``content_probe``, and it runs on every source, named or not: the check is arithmetic
  over the peeked window, and a scan of 200 333 local files found no block that passed
  it outside a real tar. The inner-TAR probe accepts it too, so a gzipped v7 tar is
  ``TAR_GZ``.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from dataclasses import replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from archivey.config import (
    DEFAULT_ARCHIVEY_CONFIG,
    ProcessIsolation,
)
from archivey.detection import DetectedBy, DetectionConfidence, FormatInfo
from archivey.detection_cost import DetectionBudget, TierSkipReason
from archivey.diagnostics import (
    DiagnosticCode,
    FormatConflictContext,
)
from archivey.exceptions import (
    ArchiveyError,
    FormatDetectionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.format_policy import FormatPolicy
from archivey.internal.arg_checks import (
    check_config,
    check_path_not_empty,
    require_source,
)
from archivey.internal.detection_cost_receipt import MutableDetectionCostReceipt
from archivey.internal.detection_workspace import (
    DETECTION_LIMIT,
    PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE,
    CandidateView,
    PrefixWorkspace,
)
from archivey.internal.diagnostics_collector import (
    DiagnosticCollector,
    collector_from_config,
)
from archivey.internal.logs import detection as logger
from archivey.internal.registry import ContentProbe, get_registry
from archivey.internal.sfx import (
    MAX_VALIDATED_CANDIDATES,
    SFX_MAX,
    VALIDATOR_PEEK_MAX,
    ExecutableCue,
    HitOutcome,
    HitSelector,
    HitValidator,
    ScanNeedle,
    executable_cue,
    iter_magic_in_prefix,
)
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.codecs.brotli_framing import (
    BrotliBlock,
    parse_metablock,
)
from archivey.internal.streams.streamtools import (
    OneReadEachStream,
    ReadOnlyIOStream,
    source_name,
)
from archivey.internal.volumes import first_volume_for_stub, resolve_source
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    MagicSignature,
    PluginContainer,
    StreamFormat,
    TrailerSignature,
)

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig

# Decompressed bytes the inner-container probe decodes: enough to see a TAR ``ustar``
# signature at offset 257 (one 512-byte header block covers it). Registration keeps a
# sequential plugin's magic within them, so a plugin cannot make the probe decode more.
INNER_CONTAINER_PROBE_BYTES = 512

# The window a self-checking header needs: every check today reads one 512-byte block
# (``ReadBackend.HEADER_CHECKS``). A shorter prefix budget turns the step off, and the
# receipt says so.
HEADER_CHECK_BYTES = 512

# Upper bound on compressed input the inner-container probe reads from the source when
# the peeked detection prefix is too short. bzip2 is block-transform (BWT) based: it emits no output
# until a whole block is read, and a block holds up to 900 KB uncompressed (level 9), which
# for incompressible leading data compresses to just over 900 KB. 1 MiB covers a full
# worst-case first block with margin; a stream-oriented codec (gzip/xz/zstd/…) reaches the
# header region from the ordinary prefix and never triggers this larger read. The legacy LZ4
# stream is block-based too, with blocks of up to 8 MiB: one whose first block compresses
# to more than this bound is left un-upgraded, by choice (handbook ``zstd-lz4.md`` §2.1).
_INNER_CONTAINER_MAX_PROBE_BYTES = 1 << 20

# Leading signatures of non-archive formats that stop the content probes, the same way a
# structurally confirmed executable does (``ExecutableCue.STRONG``). A content probe is
# the weakest evidence detection has, and these files hold what the probes accept: a
# constant header, then zero runs. An 8-byte signature at offset 0 is as specific as an
# archive's exact magic, so a real stream that starts with it is not a case to keep.
#
# A signature here also stops the SFX scan, whatever executable cue its bytes raise.
# These files are not executable stubs, so an archive the scan finds in one is an object
# stored inside the document, and reporting it as the file's payload is a wrong answer.
#
# Each entry is ``(signature, what it is)``; the description goes into the
# ``FormatDetectionError`` raised when no extension follows.
_PROBE_STOPPING_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (
        bytes.fromhex("d0cf11e0a1b11ae1"),
        (
            "an OLE compound file signature (.doc, .xls, .ppt, .msi, Thumbs.db), "
            "which is not an archive format"
        ),
    ),
)


def _non_archive_signature(data: bytes) -> str | None:
    """Describe the probe-stopping signature ``data`` starts with, or ``None``."""
    for signature, description in _PROBE_STOPPING_SIGNATURES:
        if data.startswith(signature):
            return description
    return None


class _BoundedPeekReader(ReadOnlyIOStream):
    """A bounded, non-consuming reader over a ``peek_more`` callable.

    ``peek_more(end, start)`` returns the candidate's bytes ``[start, end)`` without
    consuming them (a workspace :class:`CandidateView`). The reader keeps what it has
    peeked and asks only for the bytes past it, and the workspace takes only those
    bytes from its source (``ArchiveSource.peek_arrived``'s ``start``), so the cost
    stays linear in the bytes read, plus a fixed cost per peek, even when each peek
    grows the prefix by a few bytes. Reads walk an internal offset over that buffer,
    letting a codec pull exactly as much compressed input as it needs and never more
    than ``limit`` (one maximum compressor block).

    Seekable within the bound so codecs that use seek during a probe (or need a
    repositionable view of the peeked prefix) can still run; seeking never pulls
    bytes beyond ``limit``, and peeks still grow only on demand when a read needs
    more of the prefix.

    With ``arrived``, ``peek_more`` is a view that returns what has arrived
    (``PrefixWorkspace.candidate_view(..., arrived=True)``), and a short peek is not
    the end of the source. A sized read then returns at least one byte unless the
    source has ended, as a raw stream's read does, and ``read(-1)`` keeps peeking to
    the end or the bound. Such a view grows by at least one byte per peek unless the
    source has ended, so a sized read from where the last one stopped takes one
    peek; it peeks again only after a seek past what the view has returned.

    The seekability reaches the codec only on a random-access source. On a
    forward-only one, :func:`_probe_inner_container` hands the codec this reader wrapped
    in a non-seekable :class:`OneReadEachStream`.
    """

    def __init__(
        self, peek_more: CandidateView, limit: int, *, arrived: bool = False
    ) -> None:
        super().__init__()
        self._peek_more = peek_more
        self._limit = limit
        self._arrived = arrived
        self._offset = 0
        self._buf = bytearray()
        # Set when a read asked for bytes past ``limit`` and the window was full, so the
        # bound (not the end of the source) cut the read short.
        self.hit_limit = False

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self, /) -> int:
        return self._offset

    def seek(self, offset: int, whence: int = 0, /) -> int:
        if whence == 0:  # SEEK_SET
            new_pos = offset
        elif whence == 1:  # SEEK_CUR
            new_pos = self._offset + offset
        elif whence == 2:  # SEEK_END — end of the bounded window, not the real source
            new_pos = self._limit + offset
        else:
            raise ValueError(f"invalid whence: {whence!r}")
        if new_pos < 0:
            raise ValueError(f"negative seek position {new_pos}")
        # Cap at the bound; reads past the peeked prefix already return b"".
        self._offset = min(new_pos, self._limit)
        return self._offset

    def read(self, n: int = -1, /) -> bytes:
        past_limit = n < 0 or self._offset + n > self._limit
        end = self._limit if n < 0 else min(self._offset + n, self._limit)
        if end > len(self._buf):
            self._buf += self._peek_more(end, len(self._buf))
            # Peek again while the view is short of what this read must return: a
            # drain wants all of it, and a sized read after a seek past the buffer
            # wants a byte at the offset. A peek that adds nothing is the end of the
            # source.
            while (
                self._arrived
                and len(self._buf) < end
                and (n < 0 or len(self._buf) <= self._offset)
            ):
                grown = self._peek_more(end, len(self._buf))
                if not grown:
                    break
                self._buf += grown
        if past_limit and len(self._buf) >= self._limit:
            self.hit_limit = True
        chunk = bytes(self._buf[self._offset : end])
        self._offset += len(chunk)
        return chunk


def _match_trailer(
    workspace: PrefixWorkspace,
    entries: list[TrailerSignature],
) -> ArchiveFormat | None:
    """Return the format whose trailer magic matches the end of the source.

    One read per distinct trailer length. A source that cannot seek cheaply, or
    that is shorter than the block, is a decline: the caller keeps the answer it
    already had.
    """
    if not entries:
        return None
    by_length: dict[int, list[TrailerSignature]] = {}
    for entry in entries:
        by_length.setdefault(entry.length, []).append(entry)
    for length, group in by_length.items():
        tail = workspace.read_tail(length)
        if tail is None:
            continue
        for entry in group:
            if tail.startswith(entry.magic):
                return entry.format
    return None


def _match_magic(
    data: bytes,
    magic_entries: list[MagicSignature],
) -> ArchiveFormat | None:
    """Return the format of the first exact magic signature matching ``data``."""
    for entry in magic_entries:
        if data[entry.offset : entry.offset + len(entry.magic)] == entry.magic:
            return entry.format
    return None


def _near_magic_settled(
    head: bytes,
    magic_entries: list[MagicSignature],
    preempted: frozenset[ArchiveFormat],
) -> bool:
    """Whether :func:`_match_magic` gives the same answer for every longer prefix.

    ``head`` is a prefix of the source, maybe shorter than the window. Signatures are
    tried in table order, as :func:`_match_magic` tries them. A signature whose bytes
    are all in ``head`` matches or not, and no later byte changes that. One whose bytes
    in ``head`` already differ from it cannot match. Any other one could still match,
    so the answer is not settled. A match settles the answer unless a trailer can
    outrank its format: that check needs the source length (``preempted``). No match is
    not settled, because the tiers after near magic read the whole window.
    """
    for entry in magic_entries:
        start = entry.offset
        held = head[start : start + len(entry.magic)]
        if len(held) == len(entry.magic):
            if held == entry.magic:
                return entry.format not in preempted
            continue
        if entry.magic.startswith(held):
            return False
    return False


def _match_magic_behind_prefix(
    data: bytes,
    walks: list[tuple[ArchiveFormat, Callable[[bytes], bool]]],
) -> ArchiveFormat | None:
    """Return the format whose exact magic sits behind its own structural prefix frames.

    Each walk is arithmetic over ``data`` alone (the already-peeked prefix) and never
    triggers a larger read: a declared frame size running past those bytes is a decline.
    """
    for fmt, walk in walks:
        if walk(data):
            return fmt
    return None


def _match_extension(
    name: str | None, extension_map: dict[str, ArchiveFormat]
) -> tuple[ArchiveFormat, str] | None:
    if name is None:
        return None
    lowered = name.lower()
    # Longest extension wins so ".tar.gz" beats ".gz".
    for ext in sorted(extension_map, key=len, reverse=True):
        if lowered.endswith(ext.lower()):
            return extension_map[ext], ext
    return None


def _probe_inner_container(
    stream_format: StreamFormat,
    peek_more: CandidateView,
    workspace: PrefixWorkspace | None = None,
    *,
    view_arrived: bool = False,
) -> ArchiveFormat | None:
    """The container decompressing the source yields, as its uncompressed format, or
    ``None``.

    The codec layer decodes the compressed source and the first 512 decoded bytes are
    matched against the registry's inner-container magic (``ReadBackend.INNER_MAGIC``):
    TAR's ``ustar`` at offset 257 first, then the magic of each registered sequential
    plugin, which registration keeps within those 512 bytes. A v7 tar has no magic, so
    when none matches, a first TAR header that checks itself
    (``ReadBackend.HEADER_CHECKS``) still finds it. So a tarball, or a plugin's
    sequential archive, wrapped in the compressor is found the same way, and a plugin
    cannot make the probe decode more. The decoder reads from a bounded, non-consuming
    view of the source (:class:`_BoundedPeekReader` over ``peek_more``), so it pulls
    exactly as much compressed input as it needs to decode those 512 bytes and no
    more.

    Accelerators are forced ``OFF`` on both paths: a declared seek demand must not flip
    AUTO rapidgzip / IndexedBzip2File on for a short detection peek. Decoder limits are
    lifted for the same reason the codec content probes lift them
    (``_PROBE_STREAM_CONFIG`` in ``codecs/base.py``): a capped probe would call a
    ``.tar.xz`` with a large dictionary a bare ``.xz`` even for a caller who opened it
    with ``DecoderLimits.UNLIMITED``. The
    open that follows applies the caller's limits. ``probe_read_bound`` keeps the probe
    from reserving what the archive declares: the LZMA family (``.xz``, ``.lzma``,
    ``.lz``) decodes the 512 bytes with a 4 KiB dictionary, which gives the same bytes,
    and a zstd frame whose window is over libzstd's default 128 MiB is "can't tell".
    A ``MemoryError`` from a decoder no bound shrinks is "can't tell" too.

    With a workspace, the compressed input is bounded by what is left of the budget's
    ``max_decode_input`` (and the workspace's read ceiling) as well as by
    :data:`_INNER_CONTAINER_MAX_PROBE_BYTES`, and the decode is charged whether it
    succeeds or fails. A probe that reaches its bound without finding an inner magic
    records ``inner_tar`` as ``BUDGET_EXHAUSTED``: the answer is "not found within
    budget".

    Returns ``None`` (deferring the determination to open time) when the codec backend is
    absent, the source is not decodable as this codec, or the decoded output carries no
    inner-container magic. An absent backend, or a decoder the probe cannot build within
    its reservation (``UnsupportedFeatureError``, ``ResourceLimitError``,
    ``MemoryError``), records ``inner_tar`` as ``CAPABILITY_UNAVAILABLE``: the answer is
    "can't tell", not "none". The tier keeps its name, ``inner_tar``, which the detection
    receipt reports.
    Only one reason is recorded, in this order: a budget that turns the tier off
    (``NOT_ENABLED_BY_POLICY``), an absent backend (``CAPABILITY_UNAVAILABLE``), a budget
    that cannot cover the probe (``BUDGET_EXHAUSTED``).
    """
    # Imported here rather than at module load to avoid a detection<->codecs import cycle.
    from archivey.internal.config import (
        DecoderLimits,
        StreamConfig,
        without_accelerators,
    )
    from archivey.internal.streams.codecs import (
        codec_for_stream_format,
        is_codec_available,
        open_codec_stream,
    )

    try:
        codec = codec_for_stream_format(stream_format)
    except KeyError:
        return None
    # One reason is recorded, in this order: the policy turned the tier off, then the
    # backend is absent (more budget would not help), then the budget cannot cover it.
    if workspace is not None:
        budget = workspace.budget
        # Off when either face value is zero.
        if _record_tier_limit(
            workspace,
            "inner_tar",
            enabled=budget.max_decode_input > 0 and budget.max_decode_output > 0,
        ):
            return None
    if not is_codec_available(codec):
        if workspace is not None:
            workspace.record_skip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE)
        return None
    limit = _INNER_CONTAINER_MAX_PROBE_BYTES
    if workspace is not None:
        # Cut short: output against the budget's face value, since this is the only
        # tier that charges output and a pass that reaches it returns a format, so no
        # earlier pass (the sibling-volume retry shares the receipt) has charged any.
        # Input against what is left, since a content probe and its completion check
        # draw on the same allowance.
        if _record_tier_limit(
            workspace,
            "inner_tar",
            covered=workspace.budget.max_decode_output >= INNER_CONTAINER_PROBE_BYTES
            and workspace.decode_input_left > 0,
        ):
            return None
        limit = min(limit, workspace.decode_input_left, workspace.read_ceiling)

    source = _BoundedPeekReader(peek_more, limit, arrived=view_arrived)
    # The codec stream puts a full-count buffer in front of a raw source, and that
    # buffer would wait for a whole 64 KiB feed from a pipe. A view that returns
    # what has arrived is handed over as a buffered stream that makes one read per
    # read, so the decoder is fed what is there. The decoder reads until ``b""``, and
    # a feed split at any byte gives the same output. The wrap cannot seek, so this
    # path relies on every codec reading a non-seekable input forward (the ones that
    # can seek check their input first). A codec that seeks anyway raises an
    # ``OSError``, caught below, and the probe answers "no inner container". A drain
    # (``read(-1)``, or ``read1()`` with no size) would read to the bound or to the
    # end of the source and wait on a held-open pipe, so this path also relies on
    # every codec reading sized chunks.
    codec_input: BinaryIO = OneReadEachStream(source) if view_arrived else source
    head = b""
    unavailable = False
    try:
        with open_codec_stream(
            codec,
            codec_input,
            config=without_accelerators(
                StreamConfig(
                    streaming=True,
                    seekable=not view_arrived,
                    decoder_limits=DecoderLimits.UNLIMITED,
                    probe_read_bound=INNER_CONTAINER_PROBE_BYTES,
                    process_isolation=(
                        workspace.isolation
                        if workspace is not None
                        else ProcessIsolation.KNOWN_CRASHES
                    ),
                )
            ),
        ) as stream:
            head = stream.read(INNER_CONTAINER_PROBE_BYTES)
    except (UnsupportedFeatureError, ResourceLimitError, MemoryError):
        # The decoder could not be built within the probe's reservation: a zstd window
        # over the probe's limit, an xz filter chain it cannot decode raw, or an
        # allocation refused. "Can't tell", and the receipt says so.
        unavailable = True
    except (ArchiveyError, OSError, ValueError):
        # Not decodable as this codec, or truncated before a full block: no inner
        # container.
        pass
    found = next(
        (
            sig.format
            for sig in get_registry().inner_magic_entries()
            if head[sig.offset : sig.offset + len(sig.magic)] == sig.magic
        ),
        None,
    ) or next(
        # A first header that checks itself: a v7 tar has no magic.
        (
            fmt
            for fmt, check in get_registry().header_checks()
            if fmt.container is ContainerFormat.TAR and check(head)
        ),
        None,
    )
    if workspace is not None:
        # Charged on every path: a decode that ran and then failed did the work too.
        workspace.charge_decode(
            input_bytes=source.tell(),
            output_bytes=len(head),
        )
        if unavailable:
            workspace.record_skip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE)
        elif found is None and source.hit_limit:
            workspace.record_skip("inner_tar", TierSkipReason.BUDGET_EXHAUSTED)
    return found


def _record_tier_limit(
    workspace: PrefixWorkspace,
    tier: str,
    *,
    enabled: bool = True,
    covered: bool = True,
) -> bool:
    """Record ``tier`` as not enabled when ``enabled`` is false, else as cut short when
    ``covered`` is false; return whether a record was made.

    Most callers skip the tier on a record. The far tier takes the record but not the
    decision: it still searches the signatures its window reaches.
    """
    if not enabled:
        workspace.record_skip(tier, TierSkipReason.NOT_ENABLED_BY_POLICY)
        return True
    if not covered:
        workspace.record_skip(tier, TierSkipReason.BUDGET_EXHAUSTED)
        return True
    return False


def _decode_allowance_covers(
    workspace: PrefixWorkspace, input_bytes: int, tier: str
) -> bool:
    """Whether ``input_bytes`` of decoding still fits the call's decode allowance.

    When it does not, records ``tier`` as not enabled (the budget allows no decoding)
    or as cut short (an earlier tier spent the allowance). For ``probe_completion``
    only the cut-short record is reachable: a zero allowance stops the content probes
    before any hit asks for completion.
    """
    return not _record_tier_limit(
        workspace,
        tier,
        enabled=workspace.budget.max_decode_input > 0,
        covered=workspace.decode_input_left >= input_bytes,
    )


def _probe_completes(
    probe: ContentProbe,
    data: bytes,
    length: int | None,
    read_at: Callable[[int, int], bytes | None],
    charge_decode: Callable[[int], bool],
    workspace: PrefixWorkspace,
) -> bool:
    """Whether a probe that accepted the prefix still accepts the whole source.

    A probe handed only the detection window cannot tell a stream that goes on from one
    that turns invalid past the window: text that happens to decode for 4 KiB is a
    Brotli stream as far as the window shows. When the source is small enough, all of it
    is peeked and the probe runs again with the whole source in hand, where its
    completeness check (``_decodes_sample``) rejects a decode that is still asking for
    input at the end.

    Runs only when the source length is known, longer than the window the probe already
    saw, and within the budget's ``completion_window_bytes`` (64 KiB under ``BALANCED``;
    ``FAST`` does not complete, and records ``probe_completion`` as not enabled). A
    source the decode allowance can no longer cover is accepted on the window alone and
    ``probe_completion`` is recorded as cut short.
    """
    if length is None or length <= len(data):
        # Unknown length: nothing to complete against. At or under the window: the
        # probe already had the whole source and ran its completeness check.
        return True
    budget = workspace.budget
    # Off by policy (``FAST``): say so, since the hit stands on the window alone.
    if _record_tier_limit(
        workspace, "probe_completion", enabled=budget.completion_window_bytes > 0
    ):
        return True
    if length > min(budget.completion_window_bytes, workspace.read_ceiling):
        # A size bound, not a disabled tier: nothing is recorded.
        return True
    if not _decode_allowance_covers(workspace, length, "probe_completion"):
        return True
    whole = workspace.peek_prefix(length)
    workspace.charge_decode(input_bytes=len(whole))
    return probe(
        whole,
        source_length=length,
        read_at=read_at,
        charge_decode=charge_decode,
        isolation=workspace.isolation,
    )


# Short aliases that name a probe-only codec besides the one the extension map gives.
# ``.tlz`` maps to TAR x LZIP, but lzma-utils wrote ``.tlz`` for TAR x LZMA Alone before
# lzip took the name; lzip has exact magic, so only the Alone reading needs a probe.
_ALSO_NAMES_STREAM: dict[str, StreamFormat] = {".tlz": StreamFormat.LZMA_ALONE}


def _streams_named_by(
    ext_match: tuple[ArchiveFormat, str] | None,
) -> frozenset[StreamFormat]:
    """The stream formats whose content probe the source's extension allows."""
    if ext_match is None:
        return frozenset()
    fmt, ext = ext_match
    also = _ALSO_NAMES_STREAM.get(ext)
    return frozenset({fmt.stream} if also is None else {fmt.stream, also})


def _probe_named(
    fmt: ArchiveFormat, ext_match: tuple[ArchiveFormat, str] | None
) -> bool:
    """Whether the source's extension allows ``fmt``'s content probe to run.

    A built-in probe is keyed by its stream, so ``.tlz`` can name two. Every plugin
    format shares the ``UNCOMPRESSED`` stream with ZIP, TAR and the rest, so its probe
    runs only when the extension names that format itself.
    """
    if isinstance(fmt.container, PluginContainer):
        return ext_match is not None and ext_match[0] == fmt
    return fmt.stream in _streams_named_by(ext_match)


def _brotli_probe_confidence(
    prefix: bytes,
    ext_match: tuple[ArchiveFormat, str] | None,
) -> DetectionConfidence:
    """PROBABLE when ``.br`` (or a TAR+Brotli extension) agrees, or first block is compressed.

    Uncompressed/metadata-first with no corroborating extension is the residual
    false-positive class and reports ``GUESS``. Confidence grades evidence strength
    only; whether a later decode failure is stamped ``format_unconfirmed`` is a
    separate provenance question (probe-only vs corroborated).
    """
    if ext_match is not None and ext_match[0].stream is StreamFormat.BROTLI:
        return DetectionConfidence.PROBABLE
    if parse_metablock(prefix).outcome is BrotliBlock.COMPRESSED:
        return DetectionConfidence.PROBABLE
    return DetectionConfidence.GUESS


def _resolve_single_file_or_tar(
    fmt: ArchiveFormat,
    base_confidence: DetectionConfidence,
    base_detected_by: DetectedBy,
    peek_more: CandidateView,
    *,
    ext_match: tuple[ArchiveFormat, str] | None = None,
    workspace: PrefixWorkspace | None = None,
    view_arrived: bool = False,
) -> FormatInfo:
    """Upgrade a single-file-compressor match to its container combo when the payload
    is a tarball or a sequential plugin's archive.

    A ``RAW_STREAM`` compressor (``.gz``/``.bz2``/``.xz``/…) is probed for an inner
    container (:func:`_probe_inner_container`); on a hit it becomes ``(TAR, <stream>)``
    (e.g. ``TAR_GZ``), or ``(<plugin container>, <stream>)``, reported as ``PROBABLE`` /
    ``content_probe`` (the inner test is structural, weaker than an exact magic).
    An inner-container upgrade is corroboration for a probe hit — two independent signals
    had to hold — so ``corroborated`` is set. Otherwise a matching extension (same stream
    format) is the corroborating signal. ``peek_more`` gives the probe a bounded,
    non-consuming view of the source to decode from; ``view_arrived`` says it is a
    view that returns what has arrived (:class:`_BoundedPeekReader`).
    """
    inner = (
        _probe_inner_container(
            fmt.stream, peek_more, workspace, view_arrived=view_arrived
        )
        if fmt.container == ContainerFormat.RAW_STREAM
        and fmt.stream != StreamFormat.UNCOMPRESSED
        else None
    )
    if inner is not None:
        return FormatInfo(
            ArchiveFormat(inner.container, fmt.stream),
            DetectionConfidence.PROBABLE,
            "content_probe",
            corroborated=True,
        )
    corroborated = base_detected_by == "content_probe" and _extension_corroborates(
        ext_match, fmt
    )
    return FormatInfo(fmt, base_confidence, base_detected_by, corroborated=corroborated)


def _is_deferred_inner_container(
    ext_fmt: ArchiveFormat, resolved: ArchiveFormat
) -> bool:
    """Whether a compressed-container extension over a bare-compressor result is a
    *benign* mismatch.

    ``foo.tar.gz`` (extension → ``TAR_GZ``) reported as bare ``GZ`` is the documented
    deferred case: the inner-container probe could not run (codec backend absent) or
    found no magic, so the bare compressor is reported and the inner determination is
    left to open time. That is not a real conflict, so it must not emit a warning. A
    sequential plugin's ``foo.cpio.gz`` is the same case.
    """
    return (
        resolved.container == ContainerFormat.RAW_STREAM
        and ext_fmt.container
        not in (ContainerFormat.RAW_STREAM, ContainerFormat.UNKNOWN)
        and ext_fmt.stream != StreamFormat.UNCOMPRESSED
        and ext_fmt.stream == resolved.stream
    )


def _extension_corroborates(
    ext_match: tuple[ArchiveFormat, str] | None,
    resolved: ArchiveFormat,
) -> bool:
    """Whether the filename agrees with ``resolved`` — the same test as "no conflict".

    No extension (``None``) is not corroboration, so a caller testing for no conflict
    handles ``None`` itself.
    """
    if ext_match is None:
        return False
    ext_fmt = ext_match[0]
    return ext_fmt == resolved or _is_deferred_inner_container(ext_fmt, resolved)


class _ConflictEvidence(Enum):
    """Which branch outranked the extension, phrased for the conflict diagnostic."""

    MAGIC = "magic bytes indicate"
    SFX_SCAN = "archive magic behind an executable stub indicates"
    CONTENT_PROBE = "content inspection indicates"


def _warn_on_conflict(
    collector: DiagnosticCollector,
    name: str | None,
    ext_match: tuple[ArchiveFormat, str] | None,
    resolved: ArchiveFormat,
    evidence: _ConflictEvidence,
) -> None:
    if ext_match is None or _extension_corroborates(ext_match, resolved):
        return
    ext_fmt, extension = ext_match
    message = (
        f"Format conflict for {name!r}: extension suggests {ext_fmt!r} but "
        f"{evidence.value} {resolved!r}; using that result over the extension."
    )
    collector.emit(
        code=DiagnosticCode.FORMAT_EXTENSION_CONFLICT,
        message=message,
        context=FormatConflictContext(
            source_name=name,
            extension=extension,
            extension_format=repr(ext_fmt),
            detected_format=repr(resolved),
        ),
        logger=logger,
    )


def validator_allowance(budget: DetectionBudget) -> int:
    """Bytes an SFX hit validator may read past the scan window under ``budget``.

    :data:`VALIDATOR_PEEK_MAX` covers every validator's largest header, but a constant
    would let a small ``max_scan_bytes`` read many times its own size. Taking the
    smaller of the two keeps the tier's reads within twice ``max_scan_bytes``; a
    header that does not fit is rejected and the tier recorded as cut short. Zero
    when the scan is off.
    """
    return min(VALIDATOR_PEEK_MAX, budget.max_scan_bytes)


def _scan_for_sfx_payload(
    entries: list[MagicSignature],
    peek_more: Callable[[int], bytes],
    workspace: PrefixWorkspace,
    *,
    scan_limit: int,
    peek_allowance: int,
    validators: dict[ArchiveFormat, HitValidator],
    capped_formats: frozenset[ArchiveFormat],
    restrict_to_validated: bool,
) -> FormatInfo | None:
    """Search the SFX window for an appended archive, as ``(format, payload_offset)``.

    ``entries`` are the backends' ``SFX_MAGIC`` declarations. Each needle carries its
    candidate-internal offset (today all zero for ZIP/RAR/7z; TAR ``ustar`` → 257 once
    that needle lands). The returned ``payload_offset`` is the **candidate origin**, not
    the raw needle position. Hits are graded by their format-owned validator (none means
    ``VALID``) and chosen by :class:`HitSelector` with no damaged fallback: earliest
    *valid* match, not earliest needle. ``capped_formats`` are the formats whose parser
    runs its own capped scan; each gets the parsers' :data:`MAX_VALIDATED_CANDIDATES`
    rejection cap, counted per format as each parser counts its own, and no other format
    is capped. Once a format reaches the cap its needles are no longer searched for, so
    its later candidates are not judged and a window carpeted with its decoys costs only
    the other needles' search; the scan ends when no needle is left. A capped scan
    records ``sfx_scan`` as cut short whether or not it answers, because the candidates
    it did not judge could have changed the answer. A CRC-valid decoy in the stub that
    ends early (``VALID_SHORT``) must not beat the real payload appended after it, so a
    later ``VALID`` hit of the *same format* displaces a held short hit; a ``VALID`` hit
    of another format ends the scan with the short hit, so the exact-end preference
    never reorders formats. Holding a short hit, the scan keeps reading to
    ``scan_limit``: a decoy in the stub ends before the real payload starts, so nothing
    about the short hit bounds where that payload can be. That is the cost of a short
    hit with data after it (an Authenticode signature, say): up to the whole window, as
    a miss already pays. ``PROBABLE`` rather than ``CERTAIN``: an exact magic found at a
    *searched-for* offset is a weaker claim than one found at the offset the format
    specifies.

    ``scan_limit`` is the budget-clamped window (``min(SFX_MAX, budget.max_scan_bytes)``);
    the charge lands whether the scan hits or misses so the receipt reflects the work.
    This is the one place that records the ``sfx_scan`` tier as cut short, or as not
    enabled when the window is zero. The window bounds where a needle may start; a
    validator may read ``peek_allowance`` (:func:`validator_allowance`) past it, so a
    candidate near the end is judged on its whole header, and those bytes are charged
    to the prefix. A header that does not fit is rejected, and the clamped view makes
    the scan record ``sfx_scan`` as cut short.

    ``restrict_to_validated`` is the shebang cue: a script is text, so magics appear
    as literals. Search only formats that have a hit validator — derived from
    ``validators``, so 7z/RAR join automatically when they register theirs. Do not
    key this off :attr:`ExecutableCue.WEAK` alone: an unconfirmed ``MZ`` / ELF stub
    is the live 7z/RAR SFX path and keeps the full needle set.
    """
    # A zero ``max_scan_bytes`` turns the tier off, as a zero field does for the others.
    if _record_tier_limit(workspace, "sfx_scan", enabled=scan_limit > 0):
        return None
    if restrict_to_validated:
        entries = [entry for entry in entries if entry.format in validators]
    needles = tuple(ScanNeedle(entry.magic, entry.offset) for entry in entries)
    # The selector is keyed by each format's index in ``formats``, not by the format:
    # a hit costs a few dict lookups, and hashing an ``ArchiveFormat`` in each of them
    # was most of the cost of a window carpeted with uncapped ZIP decoys.
    formats = list(dict.fromkeys(entry.format for entry in entries))
    by_needle = {
        entry.magic: (formats.index(entry.format), validators.get(entry.format))
        for entry in entries
    }
    magics_by_key = [
        {entry.magic for entry in entries if entry.format == fmt} for fmt in formats
    ]
    # One magic, one format: both lookups are keyed by magic bytes, so a magic two
    # formats shared would route its hits to one and be dropped with either's cap.
    assert len(by_needle) == len(entries)
    # The selector holds (format key, origin); the one FormatInfo is built from the
    # winner, so a decoy-carpeted window costs no construction per candidate.
    selector: HitSelector[tuple[int, int]] = HitSelector(
        keep_damaged=False,
        cap=MAX_VALIDATED_CANDIDATES,
        cap_keys={key for key, fmt in enumerate(formats) if fmt in capped_formats},
    )
    # A capped format's magics: the parser for that format would have stopped by now,
    # so the scan stops searching for them and another format's candidates are still
    # judged.
    dropped: set[bytes] = set()
    # The window bounds where a magic may start, not how far its validator reads: a
    # candidate inside it is judged on its whole header, as far as the budget allows.
    view_limit = scan_limit + peek_allowance
    for hit in iter_magic_in_prefix(
        peek_more, needles, limit=scan_limit, dropped=dropped
    ):
        key, validator = by_needle[hit.needle]
        origin = hit.candidate_origin
        outcome = HitOutcome.VALID
        if validator is not None:
            view = workspace.candidate_view(origin, limit=view_limit)
            source_len = workspace.remaining_known()
            remaining = None if source_len is None else max(0, source_len - origin)
            outcome = validator(view, remaining)
        if selector.offer(key, (key, origin), outcome):
            break
        if selector.is_capped(key):
            dropped |= magics_by_key[key]
    chosen, _ = selector.result()
    result = (
        None
        if chosen is None
        else FormatInfo(
            formats[chosen[0]],
            DetectionConfidence.PROBABLE,
            "sfx_scan",
            payload_offset=chosen[1],
        )
    )
    # Charge the window actually examined — a miss is the expensive case.
    workspace.charge_scanned(min(workspace.buffered_length, scan_limit))
    # A miss in a window the budget made shorter than ``SFX_MAX`` is a search cut
    # short, unless the source ends inside the window anyway. Under a budget as wide
    # as ``SFX_MAX`` the structural bound stopped the scan, not the budget.
    source_len = workspace.remaining_known()
    cut_short = scan_limit < SFX_MAX and (source_len is None or source_len > scan_limit)
    # Take the flag on its own line: the call clears it, so it must always run.
    clamped = workspace.take_clamped_view_read()
    # A capped scan skipped candidates it never judged, so it is cut short even when it
    # answers: a held short hit is only the fallback the skipped ones could have beaten.
    if clamped or selector.capped or (result is None and cut_short):
        workspace.record_skip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED)
    return result


def probe_config(config: ArchiveyConfig | None) -> ArchiveyConfig:
    """The library default config carrying only ``config``'s detection settings
    (``detection_budget``, ``always_probe_content``, ``process_isolation``, which
    says where the probes' trial decodes run, and ``formats``, so a plugin the caller
    turned off runs no code here either).

    For a detection whose result is internal (a stub check, the rescan that words an
    empty-listing advisory): it spends what the caller allowed, but its diagnostics
    are judged by the default policy and never reach the caller's ``on_diagnostic``,
    as with any collector-less emission. Passing the caller's config instead would
    deliver a discarded probe's findings as the reader's, and a ``STRICT`` policy
    would raise inside the probe.
    """
    if config is None or (
        config.detection_budget is DEFAULT_ARCHIVEY_CONFIG.detection_budget
        and config.always_probe_content == DEFAULT_ARCHIVEY_CONFIG.always_probe_content
        and config.process_isolation is DEFAULT_ARCHIVEY_CONFIG.process_isolation
        and config.formats == DEFAULT_ARCHIVEY_CONFIG.formats
    ):
        return DEFAULT_ARCHIVEY_CONFIG
    return replace(
        DEFAULT_ARCHIVEY_CONFIG,
        detection_budget=config.detection_budget,
        always_probe_content=config.always_probe_content,
        process_isolation=config.process_isolation,
        formats=config.formats,
    )


def directory_format_info() -> FormatInfo:
    """The fixed answer for a directory source, shared by ``detect_format`` and the
    reader ``open_archive`` builds over a directory.

    Nothing is read, so the receipt is the zero one: every other return carries a
    receipt, and callers compare them across sources.
    """
    return FormatInfo(
        ArchiveFormat.DIRECTORY,
        DetectionConfidence.CERTAIN,
        "directory",
        cost_receipt=MutableDetectionCostReceipt().freeze(),
    )


def detect_format(
    source: str | Path | BinaryIO,
    *,
    config: ArchiveyConfig | None = None,
    follow_stub_volumes: bool = True,
) -> FormatInfo:
    """Identify the archive format of ``source`` without fully opening it.

    Returns a :class:`FormatInfo`. Raises :class:`FormatDetectionError` when no magic
    pattern matches and no extension guess is available. A non-blocking stream with
    nothing ready (its ``read`` returns ``None``) raises ``BlockingIOError`` instead:
    bytes that have not arrived are not the same as no bytes. Detection diagnostics
    are on the returned :attr:`FormatInfo.diagnostics`, recorded into a standalone
    collector made from ``config`` (or the library default).

    What detection may read and decode is ``config.detection_budget``
    (:attr:`ArchiveyConfig.detection_budget`), ``BALANCED`` by default — the same
    budget :func:`~archivey.open_archive` detects under for that config.

    LZMA Alone, zlib and Brotli have no magic. Their content probes run only when the
    source's name ends in that format's extension, unless
    :attr:`ArchiveyConfig.always_probe_content` is set; a nameless raw stream of these
    formats raises :class:`FormatDetectionError`.

    ``config.formats`` (:class:`~archivey.FormatPolicy`) does not change the answer for
    a built-in format. A plugin format it turns off is not detected: its magic,
    extensions and content probe are left out, and ``unavailable_tiers`` records each
    tier that left one out as ``NOT_ENABLED_BY_POLICY``.

    A stub-only ``.exe`` / ``.sfx`` (no archive magic) beside a 7-Zip split first
    volume is detected as that volume's format when ``follow_stub_volumes`` is true
    — the default, so ``detect_format("vol.exe")`` agrees with ``open_archive``.
    ``open_archive`` probes with this flag off, then switches the source itself.
    The returned ``cost_receipt`` and ``unavailable_tiers`` then cover both passes, the
    stub's and the volume's. Each pass runs under the full ``budget``, and the receipt's
    ``passes`` is 2.

    A path to any part of a numbered split set (``set.7z.002``, ``set.zip.003``) or to
    a RAR continuation is detected on the set ``open_archive`` reads for it: the parts
    joined in order, or RAR volume 1. A middle part alone has no magic at offset 0.
    That resolution runs before detection reads a byte, and it can raise:
    ``TruncatedError`` for a numbered set with a gap (``set.zip.002`` and
    ``set.zip.003`` with no ``set.zip.001``), as ``open_archive`` does. A lone first
    part (``set.zip.001`` with no other part) is detected as the format its bytes
    show, where ``open_archive`` refuses it as an incomplete set.

    A directory path returns :attr:`ArchiveFormat.DIRECTORY` with ``CERTAIN``
    confidence and ``detected_by="directory"``, matching ``open_archive``, which reads
    it as a directory archive. Nothing is read to decide that, so ``cost_receipt`` is
    the zero receipt (one pass, no bytes).

    Raises:
        FormatDetectionError: No format matches the source's contents or name.
        TruncatedError: The path names part of a numbered split set with a gap.
        DiagnosticRaisedError: A diagnostic that the :class:`~archivey.DiagnosticPolicy`
            in the config raises on, recorded during detection.
        ArchiveyUsageError: One argument has a type or value the call cannot use (then
            also a ``TypeError`` or ``ValueError``).
        FileNotFoundError: The path does not exist.
    """
    return detect_format_into(
        source, config=config, collector=None, follow_stub_volumes=follow_stub_volumes
    )


def detect_format_into(
    source: str | Path | BinaryIO,
    *,
    config: ArchiveyConfig | None,
    collector: DiagnosticCollector | None,
    follow_stub_volumes: bool = True,
) -> FormatInfo:
    """:func:`detect_format` with the collector chosen by the caller.

    ``open_archive`` passes the prospective reader's collector so detection diagnostics
    land on ``reader.diagnostics``; ``None`` makes a finite standalone collector from
    ``config``. Internal: the public entry point never takes a collector, so the
    ``internal/`` type stays off the surface.
    """
    # Before anything is read: an object that is neither a path nor a binary stream
    # used to reach the prefix workspace and die there as
    # `AttributeError: 'int' object has no attribute 'read'`, while `open_archive` on
    # the same value already said "unsupported source type". Same refusal, same words.
    require_source(source)
    check_path_not_empty(source, call="detect_format()")
    check_config(config, call="detect_format(config=…)")
    if not isinstance(source, (str, Path)):
        return _detect_source_into(source, config, collector, follow_stub_volumes)
    # A path is resolved once, as ``open_archive`` resolves it: any part of a numbered
    # split set (``set.zip.002``) becomes the joined set, and a RAR continuation its
    # volume 1. A middle part has no magic of its own, so detecting the named file
    # alone refused what ``open_archive`` opens. Resolution can itself raise, before
    # detection reads a byte: ``TruncatedError`` for a numbered set with a gap.
    with closing(resolve_source(source).source) as resolved:
        return _detect_source_into(resolved, config, collector, follow_stub_volumes)


def _detect_source_into(
    source: BinaryIO,
    config: ArchiveyConfig | None,
    collector: DiagnosticCollector | None,
    follow_stub_volumes: bool,
) -> FormatInfo:
    """:func:`detect_format_into` on a stream or an already resolved source."""
    if isinstance(source, ArchiveSource) and source.is_directory:
        return directory_format_info()

    effective_config = config if config is not None else DEFAULT_ARCHIVEY_CONFIG
    owned_collector = collector is None
    if owned_collector:
        collector = collector_from_config(effective_config)
        detection_wm = None
    else:
        detection_wm = collector.watermark()

    resolved_budget = effective_config.detection_budget
    always_probe = effective_config.always_probe_content
    # One receipt across both passes: the stub pass is usually the expensive one (a
    # strong executable cue runs the full SFX scan), so the sibling-volume answer
    # carries its cost and its skips too. ``passes`` says there were two.
    receipt = MutableDetectionCostReceipt()
    try:
        info = _detect_format_body(
            source,
            collector,
            resolved_budget,
            receipt,
            always_probe=always_probe,
            isolation=effective_config.process_isolation,
            formats=effective_config.formats,
        )
    except FormatDetectionError:
        alt = _first_volume_beside_stub(source) if follow_stub_volumes else None
        if alt is None:
            raise
        receipt.passes += 1
        # The volume is resolved as ``open_archive`` resolves it after the switch:
        # ``vol.7z.001`` is detected on the joined set, not on its first slice.
        with closing(resolve_source(alt).source) as alt_source:
            info = _detect_format_body(
                alt_source,
                collector,
                resolved_budget,
                receipt,
                always_probe=always_probe,
                isolation=effective_config.process_isolation,
                formats=effective_config.formats,
            )
    diagnostics = (
        collector.snapshot()
        if owned_collector
        else collector.snapshot(since=detection_wm)
    )
    return replace(info, diagnostics=diagnostics)


def _first_volume_beside_stub(source: BinaryIO) -> Path | None:
    if isinstance(source, ArchiveSource) and source.path is not None:
        return first_volume_for_stub(source.path)
    return None


def _attach_receipt(info: FormatInfo, workspace: PrefixWorkspace) -> FormatInfo:
    return replace(
        info,
        cost_receipt=workspace.receipt,
        unavailable_tiers=workspace.skips,
    )


def _detect_format_body(
    source: str | Path | BinaryIO,
    collector: DiagnosticCollector,
    budget: DetectionBudget,
    receipt: MutableDetectionCostReceipt | None = None,
    *,
    always_probe: bool = False,
    isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    formats: FormatPolicy,
) -> FormatInfo:
    registry = get_registry()
    magic_entries = registry.magic_entries()
    trailers = registry.trailer_entries()
    extension_map = registry.extension_map()
    probes = registry.content_probes()
    # A plugin format the policy turns off is not a candidate: its probe is its own
    # code, and its magic, matched in registration order, could claim a file that an
    # allowed plugin also matches. Built-in formats are candidates under every policy,
    # so their answer never depends on it. Each tier that loses an entry is recorded
    # below, once the workspace exists.
    off_near = off_far = off_extension = off_probe = False
    off_formats: set[ArchiveFormat] = set()
    if formats._turns_off_plugins:

        def is_off(fmt: ArchiveFormat) -> bool:
            if isinstance(fmt.container, PluginContainer) and not formats.allows(fmt):
                off_formats.add(fmt)
                return True
            return False

        kept_magic: list[MagicSignature] = []
        for e in magic_entries:
            if not is_off(e.format):
                kept_magic.append(e)
            elif e.offset + len(e.magic) <= DETECTION_LIMIT:
                off_near = True
            else:
                off_far = True
        magic_entries = kept_magic
        kept_extensions = {
            ext: fmt for ext, fmt in extension_map.items() if not is_off(fmt)
        }
        off_extension = len(kept_extensions) < len(extension_map)
        extension_map = kept_extensions
        kept_probes = [(f, p) for f, p in probes if not is_off(f)]
        off_probe = len(kept_probes) < len(probes)
        probes = kept_probes
    name = source_name(source)
    ext_match = _match_extension(name, extension_map)
    ext_fmt = ext_match[0] if ext_match is not None else None

    with PrefixWorkspace(source, budget, receipt, isolation=isolation) as workspace:

        def conclude(info: FormatInfo, evidence: _ConflictEvidence) -> FormatInfo:
            _warn_on_conflict(collector, name, ext_match, info.format, evidence)
            return _attach_receipt(info, workspace)

        for tier, left_out in (
            ("near_magic", off_near),
            ("far_magic", off_far),
            ("content_probe", off_probe),
            ("extension", off_extension),
        ):
            if left_out:
                workspace.record_skip(tier, TierSkipReason.NOT_ENABLED_BY_POLICY)

        # Magic signals split by where they live: "near" ones fit in the default window;
        # "far" ones (ISO's CD001 at 32 769) need an extended peek taken on demand.
        near = [e for e in magic_entries if e.offset + len(e.magic) <= DETECTION_LIMIT]
        far = [e for e in magic_entries if e.offset + len(e.magic) > DETECTION_LIMIT]
        near_span = max((e.offset + len(e.magic) for e in near), default=0)
        if near:
            # A "near" magic past the budgeted prefix is unsearchable — record it rather
            # than silently incomplete-searching (DETECTION_LIMIT and max_prefix_bytes
            # are independent constants that happen both to be 4 096 today). A zero
            # ``max_prefix_bytes`` turns the tier off. The record only: the match still
            # runs on whatever the prefix holds.
            _record_tier_limit(
                workspace,
                "near_magic",
                enabled=budget.max_prefix_bytes > 0,
                covered=budget.max_prefix_bytes >= near_span,
            )
        near_needed = min(
            budget.max_prefix_bytes,
            max(DETECTION_LIMIT, near_span),
        )
        # A pipe is read for what has arrived and stops as soon as the near magic
        # settles the answer, so a short archive whose writer keeps the pipe open is
        # detected without waiting for the writer to close it. Any other outcome still
        # reads the whole window: the later tiers look at all of it, and a short
        # window is how they learn the source length.
        preempted = frozenset(f for entry in trailers for f in entry.preempts)
        data = workspace.peek_prefix_until(
            near_needed, lambda head: _near_magic_settled(head, near, preempted)
        )
        peek_more = workspace.candidate_view(0)

        # Freeze the probe/far size-gate length from the near peek alone. A later SFX or
        # far growth that hits EOF would make ``remaining_known()`` report a length; that
        # is correct for capability accounting but must not flip content-probe framing
        # gates that deliberately treat a DETECTION_LIMIT-sized non-seekable peek as
        # unknown-length (A-34 stub residual). A peek that stopped early on a pipe is
        # short with the source not ended, and ``remaining_known()`` is ``None`` then.
        length = workspace.remaining_known()

        # 1. Exact magic in the default window.
        magic_fmt = _match_magic(data, near)
        if magic_fmt is None:
            magic_fmt = _match_magic_behind_prefix(data, registry.magic_prefix_walks())
        if magic_fmt is not None:
            # A bzip2 or xz header can be the first block of a UDIF image. The
            # trailer outranks that hit; the block codec is a member of the image.
            if any(magic_fmt in entry.preempts for entry in trailers):
                trailer_fmt = _match_trailer(workspace, trailers)
                if trailer_fmt is not None:
                    magic_fmt = trailer_fmt
            # On a forward-only source the inner-container probe reads what has arrived
            # too: a short ``.gz`` on a held-open pipe decodes its first TAR header
            # without waiting for the writer to close the pipe. A random-access
            # source keeps the seekable view.
            arrived = workspace.forward_only
            info = _resolve_single_file_or_tar(
                magic_fmt,
                DetectionConfidence.CERTAIN,
                "magic",
                workspace.candidate_view(0, arrived=arrived),
                ext_match=ext_match,
                workspace=workspace,
                view_arrived=arrived,
            )
            return conclude(info, _ConflictEvidence.MAGIC)

        # 2. Self-extracting archives. A known non-archive signature is not a stub.
        non_archive = _non_archive_signature(data)
        cue = executable_cue(data)
        if cue is not ExecutableCue.NONE and non_archive is None:
            sfx_info = _scan_for_sfx_payload(
                registry.sfx_magic_entries(),
                peek_more,
                workspace,
                scan_limit=min(SFX_MAX, budget.max_scan_bytes),
                peek_allowance=validator_allowance(budget),
                validators=registry.sfx_hit_validators(),
                capped_formats=registry.sfx_parser_scanned_formats(),
                # Shebang is text; ``WEAK`` alone is also unconfirmed MZ/ELF.
                restrict_to_validated=data.startswith(b"#!"),
            )
            if sfx_info is not None:
                return conclude(sfx_info, _ConflictEvidence.SFX_SCAN)

        # 3. Far magic (ISO's CD001 at offset 32 769). A signature that ends past
        # ``max_far_bytes`` cannot match in the clamped window, so it is dropped and the
        # tier is recorded as cut short, the same rule the near tier follows. A source
        # provably too short to hold the signature loses nothing to the clamp. A zero
        # ``max_far_bytes`` turns the tier off, and it is recorded as not enabled.
        reachable_far: list[MagicSignature] = []
        unreachable_far: list[MagicSignature] = []
        for e in far:
            fits = e.offset + len(e.magic) <= budget.max_far_bytes
            (reachable_far if fits else unreachable_far).append(e)
        if far:
            # The record only: the signatures the window reaches are searched anyway.
            _record_tier_limit(
                workspace,
                "far_magic",
                enabled=budget.max_far_bytes > 0,
                covered=all(
                    length is not None and length < e.offset + len(e.magic)
                    for e in unreachable_far
                ),
            )
        if reachable_far:
            far_needed = max(e.offset + len(e.magic) for e in reachable_far)
            if length is not None and length < far_needed:
                pass  # size-gated: never pay the peek
            else:
                far_data = workspace.peek_prefix(far_needed)
                # Charge the bytes actually requested even when the window came up short.
                workspace.charge_far(len(far_data))
                far_fmt = _match_magic(far_data, reachable_far)
                if far_fmt is not None:
                    return conclude(
                        FormatInfo(far_fmt, DetectionConfidence.CERTAIN, "magic"),
                        _ConflictEvidence.MAGIC,
                    )

        # 4. Trailer magic (UDIF's koly block). After far magic, so an ISO whose
        # CD001 already matched is read as that ISO — an uncompressed UDIF image
        # of an ISO 9660 disk included — and is not asked for a tail read.
        # Before the probes, so a zlib-first image is the image and not its
        # first block.
        trailer_fmt = _match_trailer(workspace, trailers)
        if trailer_fmt is not None:
            return conclude(
                FormatInfo(trailer_fmt, DetectionConfidence.CERTAIN, "magic"),
                _ConflictEvidence.MAGIC,
            )

        # 5. Self-checking headers: a format with no magic whose first block proves
        # itself (a v7 TAR header, by its checksum). Before the content probes, and not
        # held back by the name as they are: the check is arithmetic over bytes already
        # peeked, and text or binary data passes only when built to. A hit is its own
        # corroboration (DR-7): a checksum and every numeric field had to hold, so a
        # later read failure is not stamped as probe-only. A window too short for the
        # block is recorded, as the magic tiers record theirs.
        header_checks = registry.header_checks()
        if header_checks:
            _record_tier_limit(
                workspace,
                "header_check",
                enabled=budget.max_prefix_bytes > 0,
                covered=budget.max_prefix_bytes >= HEADER_CHECK_BYTES,
            )
        for check_fmt, check in header_checks:
            if check(data):
                return conclude(
                    FormatInfo(
                        check_fmt,
                        DetectionConfidence.PROBABLE,
                        "content_probe",
                        corroborated=True,
                    ),
                    _ConflictEvidence.CONTENT_PROBE,
                )

        # 6. Content probes, unless the prefix is a confirmed executable or a known
        # non-archive signature. The reason is kept for the error below. Unless the
        # config asks for all of them, only the probe of the format the extension names
        # runs: a probe is the weakest evidence, and on an unnamed source it is the only
        # evidence. With a matching extension the probe can only confirm the name.
        probes_stopped_by = non_archive
        if probes_stopped_by is None and cue is ExecutableCue.STRONG:
            probes_stopped_by = (
                "a structurally valid executable header (PE, ELF or Mach-O), and no "
                "archive was found behind it"
            )
        if not always_probe:
            named_probes = [(f, p) for f, p in probes if _probe_named(f, ext_match)]
            # Recorded whenever the name left a probe out, even if another one runs: a
            # .zz source still skips the LZMA Alone and Brotli probes.
            if len(named_probes) < len(probes):
                workspace.record_skip(
                    "content_probe", TierSkipReason.NOT_ENABLED_BY_POLICY
                )
            probes = named_probes
        if probes_stopped_by is None:

            def read_at(offset: int, n: int) -> bytes | None:
                return workspace.read_at(offset, n)

            def charge_decode(n: int) -> bool:
                # Brotli's chain decode reads and decodes the total [0, n): it draws on
                # the decode allowance, and reads no further than any buffered tier
                # may, nor past the 1 MiB reach of a probe read.
                if n > min(
                    workspace.read_ceiling, PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE
                ):
                    workspace.record_skip(
                        "content_probe_decode", TierSkipReason.BUDGET_EXHAUSTED
                    )
                    return False
                if not _decode_allowance_covers(workspace, n, "content_probe_decode"):
                    return False
                workspace.charge_decode(input_bytes=n)
                return True

            for probe_fmt, probe in probes:
                if not _decode_allowance_covers(workspace, len(data), "content_probe"):
                    break
                # Charged at the sample the probe was handed, whether it decodes all of
                # it or a header check turns it away first: the ceiling of its input.
                # Its output is not charged: the codec's drain bounds it per probe
                # (4 KiB, 64 KiB with the whole source in hand, or the sample length,
                # up to 1 MiB, for Brotli's chain decode).
                workspace.charge_decode(input_bytes=len(data))
                if probe(
                    data,
                    source_length=length,
                    read_at=read_at,
                    charge_decode=charge_decode,
                    isolation=workspace.isolation,
                ) and _probe_completes(
                    probe, data, length, read_at, charge_decode, workspace
                ):
                    confidence = DetectionConfidence.PROBABLE
                    if probe_fmt.stream is StreamFormat.BROTLI:
                        confidence = _brotli_probe_confidence(data, ext_match)
                    info = _resolve_single_file_or_tar(
                        probe_fmt,
                        confidence,
                        "content_probe",
                        peek_more,
                        ext_match=ext_match,
                        workspace=workspace,
                    )
                    return conclude(info, _ConflictEvidence.CONTENT_PROBE)

        # 7. Extension-only guess.
        if ext_fmt is not None:
            return _attach_receipt(
                FormatInfo(ext_fmt, DetectionConfidence.GUESS, "extension"),
                workspace,
            )

        if length == 0:
            # Every step "declined" an empty source, but there was nothing to match;
            # saying no magic matched would send the caller looking for a wrong byte.
            # ``length`` counts from the current position, so a handle already read
            # to its end lands here too; the message covers both.
            raise FormatDetectionError(
                "Could not detect archive format: there are no bytes to read (the "
                "source is empty, or already positioned at its end).",
                archive_name=name,
            )
        if probes_stopped_by is not None:
            raise FormatDetectionError(
                f"Could not detect archive format: the source starts with "
                f"{probes_stopped_by}. No content probe was run, and no file extension "
                "matched.",
                archive_name=name,
            )
        message = (
            "Could not detect archive format: no magic bytes, content probe or file "
            "extension matched."
        )
        if not always_probe:
            message = (
                "Could not detect archive format: no magic bytes or file extension "
                "matched. A raw LZMA Alone, zlib or Brotli stream has no magic and is "
                "only recognised by its extension: give the file one (.lzma, .zz, "
                ".br), pass format=, use open_stream(), or set "
                "ArchiveyConfig(always_probe_content=True)."
            )
        if off_formats:
            # Added to the advice above, not in its place: the file may be one of the
            # formats that advice reaches, and only the policy reaches an off plugin.
            names = ", ".join(sorted(f.display_name for f in off_formats))
            message += (
                f" ArchiveyConfig.formats turns off the plugin formats {names}, so "
                "they were not tried."
            )
        raise FormatDetectionError(message, archive_name=name)
