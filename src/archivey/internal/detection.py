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
magic → a plugin's near magic → self-checking header → content probes → leading-bytes
scan → extension. ``_detect_format_body`` runs them in that order, and each longer step
is a helper of its own. A plugin's magic waits for every built-in signature, so registering a
plugin never changes the answer for a file a built-in format reads. The cost is that a
plugin format is decided only after the far window (about 32 KiB, which the receipt's
``far_bytes`` reports) and the trailer are read, where a built-in near magic stops at the
4 KiB window. The
signals ahead of the probes are there for the same reason — a probe is the weakest
evidence archivey has, and one asked to judge arbitrary bytes will sometimes say yes:

- A **self-extracting** archive has no archive magic at offset 0 at all: a prefix
  (executable stub or ``#!`` launcher) comes first. When the leading bytes look
  prefix-shaped the detector searches forward for the backends' ``SFX_MAGIC`` within
  the shared ``SFX_MAX`` window and reports the payload start as ``payload_offset``
  (``PROBABLE`` / ``sfx_scan``). The cue is a cost gate — avoid reading 2 MiB from
  every file before the cheaper steps — not a false-positive defence; a format-owned
  validator rejects a decoy. With no cue the same scan runs last, as the
  **leading-bytes scan**, so only a source every other step declined pays for it: an
  archive behind an image, zeros or text, as 7-Zip, unrar and unzip find one. See
  ``executable_cue`` and ``format-detection``'s "Executable-looking prefixes must not
  silently become a wrong stream format".
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
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, cast

from archivey.config import (
    DEFAULT_ARCHIVEY_CONFIG,
    DecoderLimits,
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
from archivey.internal.excluded_libraries import NO_EXCLUSIONS
from archivey.internal.logs import detection as logger
from archivey.internal.overrides import override
from archivey.internal.registry import BackendRegistry, ContentProbe, get_registry
from archivey.internal.remote import (
    emit_source_change_undetectable,
    is_open_file,
    noting_fsspec_decoding,
    raising_source_change,
)
from archivey.internal.sfx import (
    LAYOUT_PREFIX,
    MAX_VALIDATED_CANDIDATES,
    SFX_MAX,
    VALIDATOR_PEEK_MAX,
    ExecutableCue,
    ExecutableLayout,
    HitOutcome,
    HitSelector,
    HitValidator,
    ScanNeedle,
    executable_cue,
    executable_layout,
    iter_magic_in_prefix,
    pe_layout,
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
from archivey.internal.volumes import SourceItem, first_volume_for_stub, resolve_source
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    MagicSignature,
    PluginContainer,
    PluginStream,
    StreamFormat,
    TrailerSignature,
)

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig
    from archivey.internal.streams.codecs.base import CodecId
    from archivey.types import OptionalLibrary

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

    @override
    def readable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True

    @override
    def tell(self, /) -> int:
        return self._offset

    @override
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

    @override
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


def _is_plugin_format(fmt: ArchiveFormat) -> bool:
    """Whether a plugin reads or decodes ``fmt``: its container or its stream is one."""
    return isinstance(fmt.container, PluginContainer) or isinstance(
        fmt.stream, PluginStream
    )


def _plugin_name(fmt: ArchiveFormat) -> str:
    """The plugin half of ``fmt``: its container, else its stream (``TOYS`` for
    ``TOYS_GZIP``, ``TOY`` for ``TAR_TOY``)."""
    if isinstance(fmt.container, PluginContainer):
        return fmt.container.name
    return fmt.stream.name


def _plugin_off(formats: FormatPolicy | None, fmt: ArchiveFormat) -> bool:
    """Whether ``fmt`` is a plugin format ``formats`` turns off. Built-in formats are
    detected under every policy and refused after detection, so this is never true
    for one."""
    return (
        formats is not None
        and formats._turns_off_plugins
        and _is_plugin_format(fmt)
        and not formats.allows(fmt)
    )


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
    stream_format: StreamFormat | PluginStream,
    peek_more: CandidateView,
    workspace: PrefixWorkspace | None = None,
    *,
    view_arrived: bool = False,
    named: ArchiveFormat | None = None,
    always_probe: bool = False,
    formats: FormatPolicy | None = None,
) -> ArchiveFormat | None:
    """The container decompressing the source yields, as its uncompressed format, or
    ``None``.

    The codec layer decodes the compressed source and the first 512 decoded bytes are
    matched against the registry's inner-container magic (``ReadBackend.INNER_MAGIC``):
    TAR's ``ustar`` at offset 257 first, then the magic of each registered sequential
    plugin, which registration keeps within those 512 bytes. A v7 tar has no magic, so
    when none matches, a first TAR header that checks itself
    (``ReadBackend.HEADER_CHECKS``) still finds it. A container with no reliable magic
    (binary CPIO) is found by its content probe on those bytes, run only when ``named``,
    the uncompressed format the extension names inside the compressor (``.cpio.gz``), is
    that container, or when ``always_probe`` is set: the same rule :func:`_probe_named`
    keeps for an uncompressed source. So a tarball, or a plugin's sequential archive,
    wrapped in the compressor is found the same way, and a plugin cannot make the probe
    decode more. The decoder reads from a bounded, non-consuming view of the source
    (:class:`_BoundedPeekReader` over ``peek_more``), so it pulls exactly as much
    compressed input as it needs to decode those 512 bytes and no more.

    Accelerators are forced ``OFF`` on both paths: a declared seek demand must not flip
    AUTO rapidgzip / IndexedBzip2File on for a short detection peek. The decoder is held
    to the caller's ``DecoderLimits`` (the workspace's ``decoder_limits``), as the codec
    content probes are (``StreamCodec._decodes_sample``): detection reserves no more
    than the read that follows may. ``probe_read_bound`` keeps the probe from reserving
    what the archive declares where the codec allows it: the LZMA family (``.xz``,
    ``.lzma``, ``.lz``) decodes the 512 bytes with a 4 KiB dictionary, which gives the
    same bytes, and the cap is checked against that dictionary. A zstd frame whose
    window is over the cap, or over libzstd's default 128 MiB, is "can't tell", and so
    is any other decoder the cap refuses. The open that follows then reads the source
    as the bare compressed stream, and an INFO log on ``archivey.detection`` names the
    limit. A ``MemoryError`` from a decoder no bound shrinks is "can't tell" too.

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
    Of the reasons the probe could not answer, only one is recorded, in this order: a
    budget that turns the tier off (``NOT_ENABLED_BY_POLICY``), an absent backend
    (``CAPABILITY_UNAVAILABLE``), a budget that cannot cover the probe
    (``BUDGET_EXHAUSTED``).

    ``formats`` leaves out what it leaves out of an uncompressed source: a plugin
    format it turns off, judged as the pair ``(container, stream_format)``, and a probe
    whose backend needs a package ``exclude_libraries`` lists. The off plugin's code
    does not run and its magic cannot claim the decoded bytes. When the probe runs
    with an off plugin left out, ``inner_tar`` is also recorded as
    ``NOT_ENABLED_BY_POLICY``, as the uncompressed tiers record theirs; a probe left
    out for an excluded package is not, as there. That record is separate from the one
    reason above and can sit next to it: the policy left the plugin out, and the
    budget or the backend also cut the probe short.
    """
    # Imported here rather than at module load to avoid a detection<->codecs import cycle.
    from archivey.internal.streams.codecs import codec_for_stream_format

    try:
        codec = codec_for_stream_format(stream_format)
    except KeyError:
        return None
    excluded = workspace.excluded_libraries if workspace is not None else NO_EXCLUSIONS
    limit = _inner_probe_input_limit(codec, workspace, excluded)
    if limit is None:
        return None

    source = _BoundedPeekReader(peek_more, limit, arrived=view_arrived)
    # The codec stream puts a full-count buffer in front of a raw source, and that
    # buffer would wait for a whole 64 KiB feed from a pipe. A view that returns
    # what has arrived is handed over as a buffered stream that makes one read per
    # read, so the decoder is fed what is there. The decoder reads until ``b""``, and
    # a feed split at any byte gives the same output. The wrap cannot seek, so this
    # path relies on every codec reading a non-seekable input forward (the ones that
    # can seek check their input first). A codec that seeks anyway raises an
    # ``OSError``, caught in :func:`_decode_inner_head`, and the probe answers "no
    # inner container". A drain (``read(-1)``, or ``read1()`` with no size) would read
    # to the bound or to the end of the source and wait on a held-open pipe, so this
    # path also relies on every codec reading sized chunks.
    codec_input: BinaryIO = OneReadEachStream(source) if view_arrived else source
    candidates = _inner_candidates(stream_format, formats, workspace, excluded)
    head, unavailable = _decode_inner_head(
        codec,
        codec_input,
        stream_format,
        view_arrived=view_arrived,
        workspace=workspace,
        excluded=excluded,
    )
    found = candidates.match(head, named=named, always_probe=always_probe)
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


def _inner_probe_input_limit(
    codec: CodecId,
    workspace: PrefixWorkspace | None,
    excluded: frozenset[OptionalLibrary],
) -> int | None:
    """How much compressed input the inner-container probe may read, or ``None`` when
    the probe must not run.

    One reason is recorded, in this order: the policy turned the tier off, then the
    backend is absent (more budget would not help), then the budget cannot cover it.
    """
    from archivey.internal.streams.codecs import is_codec_available

    if workspace is not None:
        budget = workspace.budget
        # Off when either face value is zero.
        if _record_tier_limit(
            workspace,
            "inner_tar",
            enabled=budget.max_decode_input > 0 and budget.max_decode_output > 0,
        ):
            return None
    if not is_codec_available(codec, excluded):
        if workspace is not None:
            workspace.record_skip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE)
        return None
    if workspace is None:
        return _INNER_CONTAINER_MAX_PROBE_BYTES
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
    return min(
        _INNER_CONTAINER_MAX_PROBE_BYTES,
        workspace.decode_input_left,
        workspace.read_ceiling,
    )


@dataclass(frozen=True)
class _InnerCandidates:
    """The signals that can name the container inside a compressed stream, minus the
    plugin formats the policy turns off and the probes of excluded packages."""

    magic: list[MagicSignature]
    """Inner-container magic (``ReadBackend.INNER_MAGIC``): TAR's ``ustar``, then each
    sequential plugin's."""

    header_checks: list[tuple[ArchiveFormat, Callable[[bytes], bool]]]
    """Self-checking first headers (``ReadBackend.HEADER_CHECKS``)."""

    probes: list[tuple[ArchiveFormat, ContentProbe]]
    """Content probes of containers with no reliable magic (binary CPIO)."""

    def match(
        self, head: bytes, *, named: ArchiveFormat | None, always_probe: bool
    ) -> ArchiveFormat | None:
        """The container the decoded ``head`` shows: magic first, then a header that
        checks itself, then a probe."""
        for sig in self.magic:
            if head[sig.offset : sig.offset + len(sig.magic)] == sig.magic:
                return sig.format
        # A first header that checks itself: a v7 tar has no magic.
        for fmt, check in self.header_checks:
            if fmt.container is ContainerFormat.TAR and check(head):
                return fmt
        # A container with no reliable magic, found by its own probe where the name
        # says it is that container (the rule and its scope are on _probe_named).
        # Prefix only: the decoded head is all there is.
        for fmt, probe in self.probes:
            if (always_probe or fmt == named) and head and probe(head):
                return fmt
        return None


def _inner_candidates(
    stream_format: StreamFormat | PluginStream,
    formats: FormatPolicy | None,
    workspace: PrefixWorkspace | None,
    excluded: frozenset[OptionalLibrary],
) -> _InnerCandidates:
    """The registry's inner-container signals for a payload of ``stream_format``.

    A plugin container is judged as the pair ``(container, stream_format)``. When the
    policy leaves one out, ``inner_tar`` is recorded as ``NOT_ENABLED_BY_POLICY``.
    """
    registry = get_registry()

    def kept(container: ContainerFormat | PluginContainer) -> bool:
        return not _plugin_off(formats, ArchiveFormat(container, stream_format))

    inner_magic = registry.inner_magic_entries()
    header_checks = registry.header_checks()
    # A container's probes only: a codec's probe names no container to find here.
    probes = [
        (f, p)
        for f, p in registry.content_probes()
        if f.container is not ContainerFormat.RAW_STREAM
    ]
    kept_magic = [sig for sig in inner_magic if kept(sig.format.container)]
    kept_checks = [(f, c) for f, c in header_checks if kept(f.container)]
    kept_probes = [(f, p) for f, p in probes if kept(f.container)]
    if workspace is not None and (
        len(kept_magic) < len(inner_magic)
        or len(kept_checks) < len(header_checks)
        or len(kept_probes) < len(probes)
    ):
        workspace.record_skip("inner_tar", TierSkipReason.NOT_ENABLED_BY_POLICY)
    # Not recorded, as on an uncompressed source: an excluded package reads as absent.
    kept_probes = [
        (f, p)
        for f, p in kept_probes
        if not registry.needs_excluded_package(f, excluded)
    ]
    return _InnerCandidates(kept_magic, kept_checks, kept_probes)


def _decode_inner_head(
    codec: CodecId,
    codec_input: BinaryIO,
    stream_format: StreamFormat | PluginStream,
    *,
    view_arrived: bool,
    workspace: PrefixWorkspace | None,
    excluded: frozenset[OptionalLibrary],
) -> tuple[bytes, bool]:
    """Decode the first :data:`INNER_CONTAINER_PROBE_BYTES` of the payload.

    Returns the decoded bytes (empty when the input does not decode as this codec) and
    whether the decoder could not be built within the probe's reservation, which is
    "can't tell" rather than "no inner container".
    """
    from archivey.internal.config import (
        StreamConfig,
        without_accelerators,
    )
    from archivey.internal.streams.codecs import open_codec_stream, single_file_codec

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
                    decoder_limits=(
                        workspace.decoder_limits
                        if workspace is not None
                        else DecoderLimits()
                    ),
                    probe_read_bound=INNER_CONTAINER_PROBE_BYTES,
                    excluded_libraries=excluded,
                    process_isolation=(
                        workspace.isolation
                        if workspace is not None
                        else ProcessIsolation.KNOWN_CRASHES
                    ),
                )
            ),
        ) as stream:
            head = stream.read(INNER_CONTAINER_PROBE_BYTES)
    except ResourceLimitError as exc:
        # The decoder is over the caller's ``max_decoder_memory`` (or a probe ceiling),
        # or its child could not run: "can't tell". Said in a log, since the open that
        # follows reads the source as the bare compressed stream, and a caller who
        # lowered the cap learns why.
        unavailable = True
        _log_probe_refused(
            f"look inside the {stream_format.name} stream for an archive (it is read "
            "as the bare compressed stream; pass format= to name the container)",
            exc,
        )
    except (UnsupportedFeatureError, MemoryError):
        # The decoder could not be built within the probe's reservation: a zstd window
        # over the probe's limit, an xz filter chain it cannot decode raw, or an
        # allocation refused. "Can't tell", and the receipt says so.
        unavailable = True
    except (ArchiveyError, OSError, ValueError):
        # Not decodable as this codec, or truncated before a full block: no inner
        # container.
        pass
    except Exception:
        # A plugin decoder that raises what its translate_exception does not map is no
        # inner container, as a plugin probe that raises is no match
        # (``format_adapter.prefix_probe``): one plugin must not change how input
        # fails to be detected. A built-in codec's unknown error is archivey's bug
        # and propagates. A read of the stream still raises it.
        from archivey.internal.codec_adapter import PluginCodec

        plugin_codec = single_file_codec(stream_format)
        if not isinstance(plugin_codec, PluginCodec):
            raise
        logger.log(
            plugin_codec.detection_error_level(),
            "plugin codec %s raised while detection decoded its start; taken as no "
            "inner container",
            stream_format.name,
            exc_info=True,
        )
    return head, unavailable


def _log_probe_refused(what: str, exc: ResourceLimitError) -> None:
    """Log at INFO that a probe could not build its decoder, so detection could not tell.

    ``exc`` says why: ``DecoderLimits.max_decoder_memory`` with its value when the
    caller's cap refused it, a probe's own ceiling (an lzop or mozlz4 block), or, as a
    ``ResourceUnavailableError``, a decoder child that could not run. The receipt
    records the tier as ``CAPABILITY_UNAVAILABLE``.
    """
    logger.info(
        "Detection could not %s: it could not build the decoder it needs. %s",
        what,
        exc,
    )


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
    try:
        return probe(
            whole,
            source_length=length,
            read_at=read_at,
            charge_decode=charge_decode,
            isolation=workspace.isolation,
            decoder_limits=workspace.decoder_limits,
        )
    except ResourceLimitError as exc:
        # The whole-source decode reads up to 64 KiB, so a probe's clamped LZMA
        # dictionary is larger here than for the window, and a cap between the two
        # refuses only this decode. The hit stands on the window alone, as when the
        # allowance cannot cover the source.
        workspace.record_skip("probe_completion", TierSkipReason.CAPABILITY_UNAVAILABLE)
        _log_probe_refused("decode the whole source to confirm its format", exc)
        return True


# Short aliases that name a probe-only codec besides the one the extension map gives.
# ``.tlz`` maps to TAR x LZIP, but lzma-utils wrote ``.tlz`` for TAR x LZMA Alone before
# lzip took the name; lzip has exact magic, so only the Alone reading needs a probe.
_ALSO_NAMES_STREAM: dict[str, StreamFormat] = {".tlz": StreamFormat.LZMA_ALONE}


def _streams_named_by(
    ext_match: tuple[ArchiveFormat, str] | None,
) -> frozenset[StreamFormat | PluginStream]:
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

    A single-file codec's probe is keyed by its stream, so ``.tlz`` can name two. A
    container's probe (binary CPIO, or a plugin's) shares the ``UNCOMPRESSED`` stream
    with ZIP, TAR and the rest, so it runs only when the extension names that format
    itself. Only a format with no reliable magic declares a container probe (today
    binary CPIO and any plugin); ZIP, TAR, 7z, RAR and ISO declare exact magic and no
    probe, so a built-in container that adds one later takes this rule on purpose.
    """
    if fmt.container is not ContainerFormat.RAW_STREAM:
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
    always_probe: bool = False,
    formats: FormatPolicy | None = None,
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
    named = None
    if ext_match is not None and ext_match[0].stream is fmt.stream:
        named = ArchiveFormat(ext_match[0].container, StreamFormat.UNCOMPRESSED)
    inner = (
        _probe_inner_container(
            fmt.stream,
            peek_more,
            workspace,
            view_arrived=view_arrived,
            named=named,
            always_probe=always_probe,
            formats=formats,
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
    ``foo.cpio.gz``, or a sequential plugin's ``foo.lha.gz``, is the same case.
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


def _executable_head(
    data: bytes, peek_more: Callable[[int], bytes], workspace: PrefixWorkspace
) -> bytes:
    """The leading bytes an executable's layout is read from: ``data``, grown to
    :data:`~archivey.internal.sfx.LAYOUT_PREFIX` bytes when it is shorter.

    A ``max_prefix_bytes`` below that span would hide the headers, and the end and
    start detection reports would then differ from the ones a forced ``format=``
    reads from the same span (``open_archive``): what an archive holds never depends
    on whether its format was named. The scan that follows reads past this span
    anyway, on a pipe too, so growing it waits for no byte the scan would not.
    """
    total = workspace.remaining_known()
    if len(data) >= (LAYOUT_PREFIX if total is None else min(LAYOUT_PREFIX, total)):
        return data
    return peek_more(LAYOUT_PREFIX)


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
    cut_reason: TierSkipReason = TierSkipReason.BUDGET_EXHAUSTED,
    leading: bytes = b"",
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

    ``cut_reason`` is what a window shorter than ``SFX_MAX`` is recorded as: the budget
    by default, ``CAPABILITY_UNAVAILABLE`` when the caller cut the window to the bytes a
    forward-only source already holds.

    ``leading`` is the prefix detection holds. When it is a PE, ELF or Mach-O
    program whose layout parses (:func:`~archivey.internal.sfx.executable_layout`),
    the candidate at its overlay start is judged first. When it is a signed PE, a
    candidate at or past its certificate table is not judged, and the answer carries
    the table's start as ``payload_end``: the table is not parsed, so a needle inside
    it could pass a validator, and the readers stop there (``archive-reading``).
    The overlay start is judged up to ``SFX_MAX`` whatever ``scan_limit`` is
    (:func:`_judge_overlay_start`), so the budget never changes which archive is
    found, only whether one is.
    """
    # A zero ``max_scan_bytes`` turns the tier off, as a zero field does for the others.
    if _record_tier_limit(workspace, "sfx_scan", enabled=scan_limit > 0):
        return None
    if restrict_to_validated:
        entries = [entry for entry in entries if entry.format in validators]
    needles = tuple(ScanNeedle(entry.magic, entry.offset) for entry in entries)
    index = _sfx_needle_index(entries, validators)
    # The selector holds (format key, origin); the one FormatInfo is built from the
    # winner, so a decoy-carpeted window costs no construction per candidate.
    selector: HitSelector[tuple[int, int]] = HitSelector(
        keep_damaged=False,
        cap=MAX_VALIDATED_CANDIDATES,
        cap_keys={
            key for key, fmt in enumerate(index.formats) if fmt in capped_formats
        },
    )
    # A capped format's magics: the parser for that format would have stopped by now,
    # so the scan stops searching for them and another format's candidates are still
    # judged.
    dropped: set[bytes] = set()
    # The window bounds where a magic may start, not how far its validator reads: a
    # candidate inside it is judged on its whole header, as far as the budget allows.
    view_limit = scan_limit + peek_allowance
    layout = executable_layout(leading, workspace.remaining_known())
    payload_end = None if layout is None else layout.payload_end
    if layout is not None:
        first = _judge_overlay_start(
            layout, entries, index, workspace, scan_limit, view_limit
        )
        if isinstance(first, _OutOfReach):
            # The uncapped paths judge the overlay start before any needle in the
            # image. Answering from the image would list what they do not, so the
            # scan gives up instead.
            workspace.record_skip("sfx_scan", cut_reason)
            return None
        if first is not None:
            return first
    for hit in iter_magic_in_prefix(
        peek_more, needles, limit=scan_limit, dropped=dropped
    ):
        key, validator = index.by_needle[hit.needle]
        origin = hit.candidate_origin
        if payload_end is not None and origin >= payload_end:
            # Inside the certificate table: no payload starts there, and every later
            # needle is further in.
            break
        outcome = _grade_candidate(workspace, origin, validator, view_limit)
        if selector.offer(key, (key, origin), outcome):
            break
        if selector.is_capped(key):
            dropped |= index.magics_by_key[key]
    chosen, _ = selector.result()
    result = (
        None
        if chosen is None
        else FormatInfo(
            index.formats[chosen[0]],
            DetectionConfidence.PROBABLE,
            "sfx_scan",
            payload_offset=chosen[1],
            prefixed=True,
            payload_end=payload_end,
        )
    )
    _account_sfx_scan(
        workspace,
        scan_limit,
        answered=result is not None,
        capped=selector.capped,
        cut_reason=cut_reason,
    )
    return result


@dataclass(frozen=True)
class _SfxNeedleIndex:
    """The SFX scan's lookups from a needle's magic bytes to its format.

    A format is named by its key, its index in ``formats``, rather than by value: a
    hit costs a few dict lookups, and hashing an ``ArchiveFormat`` in each of them was
    most of the cost of a window carpeted with uncapped ZIP decoys.
    """

    formats: list[ArchiveFormat]
    """The scanned formats, in the order their needles were declared."""

    by_needle: dict[bytes, tuple[int, HitValidator | None]]
    """Each magic's format key and that format's validator (``None``: every hit is
    ``VALID``)."""

    magics_by_key: list[set[bytes]]
    """Each format's magics, which the scan stops searching for together once that
    format reaches its candidate cap."""


def _sfx_needle_index(
    entries: list[MagicSignature], validators: dict[ArchiveFormat, HitValidator]
) -> _SfxNeedleIndex:
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
    return _SfxNeedleIndex(formats, by_needle, magics_by_key)


def _grade_candidate(
    workspace: PrefixWorkspace,
    origin: int,
    validator: HitValidator | None,
    view_limit: int,
) -> HitOutcome:
    """Grade the SFX candidate at ``origin`` with its format's validator, reading no
    further than ``view_limit``. A format with no validator takes every hit as
    ``VALID``."""
    if validator is None:
        return HitOutcome.VALID
    view = workspace.candidate_view(origin, limit=view_limit)
    source_len = workspace.remaining_known()
    remaining = None if source_len is None else max(0, source_len - origin)
    return validator(view, remaining)


def _account_sfx_scan(
    workspace: PrefixWorkspace,
    scan_limit: int,
    *,
    answered: bool,
    capped: bool,
    cut_reason: TierSkipReason,
) -> None:
    """Charge the forward SFX scan to the receipt and record ``sfx_scan`` when
    something cut it short."""
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
    # One reason per tier: a window cut to the bytes a stream has delivered names that
    # cut, ahead of the candidate cap, since more budget would not help it (as the
    # inner-TAR probe records an absent backend ahead of an exhausted budget).
    if clamped or (not answered and cut_short):
        workspace.record_skip("sfx_scan", cut_reason)
    elif capped:
        workspace.record_skip("sfx_scan", TierSkipReason.BUDGET_EXHAUSTED)


#: The PE tail probe's reads (``detection-cost``, the *tail allowance*): the end-record
#: search span, as long as the ZIP reader's, and the fixed parts of the two records
#: that confirm it. Literals that mirror ``zip_parser.EOCD_SEARCH_WINDOW`` and
#: ``zip_parser.TAIL_CONFIRM_READS``, since detection imports that module only when
#: the probe runs; ``tests/test_pe_tail_probe.py`` pins them together.
TAIL_PROBE_SPAN = 65_558
TAIL_PROBE_ALLOWANCE = TAIL_PROBE_SPAN + 46 + 30


def _probe_pe_tail(
    workspace: PrefixWorkspace,
    leading: bytes,
    *,
    scan_limit: int,
    enabled: bool,
) -> FormatInfo | None:
    """A ZIP end record before a PE's payload end, after the SFX scan missed.

    Runs only for a PE whose layout parses (:func:`~archivey.internal.sfx.pe_layout`)
    on a source of known length, whose payload end (the certificate table's start, or
    the end of the source) lies past both the overlay start and the scanned window: a
    program with nothing appended past its sections other than a certificate never
    pays for the read.
    The search covers the :data:`TAIL_PROBE_SPAN` bytes ending at the payload end, with
    the ZIP reader's own locator, so the reader then finds the same record. The record
    is confirmed (``zip_parser.confirm_tail_record``) before answering ``ZIP`` /
    ``PROBABLE`` / ``sfx_scan`` with the base the record implies as
    ``payload_offset``, which is never after any member. ZIP64 records are declined.

    Records ``sfx_tail`` as *not enabled by policy* when the scan tier is off, and as
    *capability unavailable* when the source does not allow a cheap tail read: a
    stream of unknown length that runs past the window and the overlay start, whose
    end only reading all of it would find, or one whose tail cannot be read without
    re-decoding (``read_tail``). Nothing for a source the gate excludes.
    """
    total = workspace.remaining_known()
    layout = pe_layout(leading, total)
    if layout is None:
        return None
    if total is None:
        # Not ended yet, so the stream runs past the bytes it delivered.
        if workspace.buffered_length >= max(scan_limit, layout.overlay_start):
            workspace.record_skip(
                "sfx_tail",
                TierSkipReason.CAPABILITY_UNAVAILABLE
                if enabled
                else TierSkipReason.NOT_ENABLED_BY_POLICY,
            )
        return None
    end = total if layout.payload_end is None else layout.payload_end
    if end <= layout.overlay_start or end <= scan_limit:
        return None
    if not enabled:
        workspace.record_skip("sfx_tail", TierSkipReason.NOT_ENABLED_BY_POLICY)
        return None
    span = workspace.read_tail(TAIL_PROBE_SPAN, end=end, tier="sfx_tail")
    if span is None:
        return None
    # Imported here: detection reads no backend module on any other path.
    from archivey.internal.backends.zip_parser import (
        confirm_tail_record,
        locate_classic_record,
    )

    span_start = end - len(span)

    def read_at(offset: int, length: int) -> bytes:
        if span_start <= offset and offset + length <= end:
            return span[offset - span_start : offset - span_start + length]
        return workspace.read_at(offset, length) or b""

    found = locate_classic_record(read_at, end)
    if found is None:
        return None
    eocd_offset, record, _comment = found
    base = confirm_tail_record(read_at, eocd_offset, record, layout.overlay_start)
    if base is None:
        return None
    return FormatInfo(
        ArchiveFormat.ZIP,
        DetectionConfidence.PROBABLE,
        "sfx_scan",
        payload_offset=base,
        prefixed=True,
        payload_end=layout.payload_end,
    )


class _OutOfReach:
    """The overlay start lies inside ``SFX_MAX`` and the budget kept detection from
    judging the candidate there in full."""


_OUT_OF_REACH = _OutOfReach()


def _judge_overlay_start(
    layout: ExecutableLayout,
    entries: list[MagicSignature],
    index: _SfxNeedleIndex,
    workspace: PrefixWorkspace,
    scan_limit: int,
    view_limit: int,
) -> FormatInfo | _OutOfReach | None:
    """The SFX answer at an executable's overlay start, judged before the forward
    scan.

    The overlay start is where the program's own headers say appended data begins, so
    it is stronger evidence than "earliest needle" and than the 7z exact-end
    tie-break. A candidate there that its validator grades ``VALID`` or
    ``VALID_SHORT`` is the answer (a signed 7z SFX ends before its certificate, so
    ``VALID_SHORT`` is the common case); anything else leaves the scan to run as it
    does for any stub. The RAR and 7z parsers' scans and the forward ZIP walk apply
    the same rule, so forced ``format=`` opens the same payload.

    Those paths judge the overlay start when its magic ends inside ``SFX_MAX``, and so
    does this one, whatever the budget made of ``scan_limit``: otherwise a smaller
    budget would answer with an archive inside the program image that the default
    budget and a forced open pass over. A candidate past the window is read by seeking
    (:meth:`PrefixWorkspace.seek_view`): one read for a header of normal size, all
    within the validator allowance a candidate in the window gets
    (``view_limit - scan_limit``). The answer is :data:`_OUT_OF_REACH` instead when
    the source cannot seek cheaply, since reading on to the candidate would pass the
    budget, and when the allowance cut the validator's view short and it declined:
    the uncapped paths could accept that candidate.
    """
    origin = layout.overlay_start
    if layout.payload_end is not None and origin >= layout.payload_end:
        return None
    total = workspace.remaining_known()
    if total is not None and origin >= total:
        # Nothing appended: no candidate there for any path to judge.
        return None
    far_view: CandidateView | None = None
    for entry in entries:
        start = origin + entry.offset
        magic_end = start + len(entry.magic)
        if magic_end > SFX_MAX:
            continue
        in_window = magic_end <= scan_limit
        if in_window:
            view = workspace.candidate_view(origin, limit=view_limit)
        else:
            if far_view is None:
                far_view = workspace.seek_view(origin, length=view_limit - scan_limit)
                if far_view is None:
                    return _OUT_OF_REACH
            view = far_view
        if view(entry.offset + len(entry.magic))[entry.offset :] != entry.magic:
            continue
        key, validator = index.by_needle[entry.magic]
        outcome = HitOutcome.VALID
        if validator is not None:
            remaining = None if total is None else max(0, total - origin)
            outcome = validator(
                workspace.candidate_view(origin, limit=view_limit)
                if in_window
                else view,
                remaining,
            )
        if outcome not in (HitOutcome.VALID, HitOutcome.VALID_SHORT):
            if workspace.take_clamped_view_read():
                return _OUT_OF_REACH
            continue
        # The window examined is the bytes up to the candidate's magic; a candidate
        # read by a seek was the only place examined.
        workspace.charge_scanned(magic_end if in_window else len(entry.magic))
        workspace.take_clamped_view_read()
        return FormatInfo(
            index.formats[key],
            DetectionConfidence.PROBABLE,
            "sfx_scan",
            payload_offset=origin,
            prefixed=True,
            payload_end=layout.payload_end,
        )
    return None


def probe_config(config: ArchiveyConfig | None) -> ArchiveyConfig:
    """The library default config carrying only ``config``'s detection settings
    (``detection_budget``, ``always_probe_content``, ``process_isolation``, which
    says where the probes' trial decodes run, ``formats``, so a plugin the caller
    turned off runs no code here either, ``discover_volumes``, so a probe that
    resolves a path opens no file the caller ruled out, and ``decoder_limits``, so a
    probe's trial decoder reserves no more than the caller allows).

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
        and config.discover_volumes == DEFAULT_ARCHIVEY_CONFIG.discover_volumes
        and config.decoder_limits == DEFAULT_ARCHIVEY_CONFIG.decoder_limits
    ):
        return DEFAULT_ARCHIVEY_CONFIG
    return replace(
        DEFAULT_ARCHIVEY_CONFIG,
        detection_budget=config.detection_budget,
        always_probe_content=config.always_probe_content,
        process_isolation=config.process_isolation,
        formats=config.formats,
        discover_volumes=config.discover_volumes,
        decoder_limits=config.decoder_limits,
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
    source: SourceItem,
    *,
    config: ArchiveyConfig | None = None,
    follow_stub_volumes: bool = True,
) -> FormatInfo:
    """Identify the archive format of ``source`` without fully opening it.

    ``source`` takes what :func:`~archivey.open_archive` takes for one archive: a path,
    a binary stream, or an ``fsspec.core.OpenFile`` read by range requests.

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
    source: SourceItem,
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
    # Before anything is read: a value that is neither a path nor a binary stream gets
    # the refusal ``open_archive`` gives it, in the same words, instead of an
    # ``AttributeError`` from inside the prefix workspace.
    require_source(source)
    check_path_not_empty(source, call="detect_format()")
    check_config(config, call="detect_format(config=…)")
    discover = (config or DEFAULT_ARCHIVEY_CONFIG).discover_volumes
    follow_stub_volumes = follow_stub_volumes and discover
    if is_open_file(source):
        # Resolved as open_archive resolves it, through the fetch planner.
        max_read_through = (config or DEFAULT_ARCHIVEY_CONFIG).max_read_through
        with (
            noting_fsspec_decoding(source),
            closing(
                resolve_source(source, max_read_through=max_read_through).source
            ) as resolved,
        ):
            return _detect_source_into(resolved, config, collector, follow_stub_volumes)
    if not isinstance(source, (str, Path)):
        # ``is_open_file`` cannot narrow the union, so the stream is named here.
        return _detect_source_into(
            cast("BinaryIO", source), config, collector, follow_stub_volumes
        )
    # A path is resolved once, as ``open_archive`` resolves it: any part of a numbered
    # split set (``set.zip.002``) becomes the joined set, and a RAR continuation its
    # volume 1. A middle part has no magic of its own, so detecting the named file
    # alone would refuse what ``open_archive`` opens. Resolution can itself raise, before
    # detection reads a byte: ``TruncatedError`` for a numbered set with a gap.
    with closing(resolve_source(source, discover_volumes=discover).source) as resolved:
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
    # Recorded by detection, so ``detect_format(of)`` and ``open_archive(of)``'s
    # ``format_info`` carry it alike; open_archive records it itself only when
    # ``format=`` skips detection.
    if isinstance(source, ArchiveSource):
        emit_source_change_undetectable(
            source, collector, getattr(source, "name", None)
        )

    resolved_budget = effective_config.detection_budget
    always_probe = effective_config.always_probe_content
    # One receipt across both passes: the stub pass is usually the expensive one (a
    # strong executable cue runs the full SFX scan), so the sibling-volume answer
    # carries its cost and its skips too. ``passes`` says there were two.
    receipt = MutableDetectionCostReceipt()
    # A change of a remote object ends detection, whatever the probes made of it: a
    # probe that took the change for bytes that do not decode answers with another
    # format (a ``.tar.gz`` as GZ), or with none.
    ranges = source.remote_sources if isinstance(source, ArchiveSource) else ()
    with raising_source_change(ranges, archive_name=getattr(source, "name", None)):
        try:
            info = _detect_format_body(
                source,
                collector,
                resolved_budget,
                receipt,
                always_probe=always_probe,
                isolation=effective_config.process_isolation,
                formats=effective_config.formats,
                decoder_limits=effective_config.decoder_limits,
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
                    decoder_limits=effective_config.decoder_limits,
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
    decoder_limits: DecoderLimits = DecoderLimits(),
) -> FormatInfo:
    """One detection pass over ``source``: the steps in the module docstring, in order.

    Each step either returns the answer or declines, and the first answer wins. The
    pass ends with the extension guess, or a :class:`FormatDetectionError` that says
    what was tried. ``receipt`` is shared with a second pass when the caller retries
    on the volume beside a stub.
    """
    registry = get_registry()
    candidates = _candidate_tables(registry, formats)
    trailers = registry.trailer_entries()
    name = source_name(source)
    ext_match = _match_extension(name, candidates.extension_map)

    with PrefixWorkspace(
        source,
        budget,
        receipt,
        isolation=isolation,
        excluded_libraries=formats.exclude_libraries,
        decoder_limits=decoder_limits,
    ) as workspace:
        for tier in candidates.off_tiers:
            workspace.record_skip(tier, TierSkipReason.NOT_ENABLED_BY_POLICY)

        # Magic signals split by where they live: "near" ones fit in the default window;
        # "far" ones (ISO's CD001 at 32 769) need an extended peek taken on demand.
        magic_entries = candidates.magic_entries
        all_near = [
            e for e in magic_entries if e.offset + len(e.magic) <= DETECTION_LIMIT
        ]
        far = [e for e in magic_entries if e.offset + len(e.magic) > DETECTION_LIMIT]
        # A plugin's near magic counts only when no built-in signal matched, including
        # the ones further in (the SFX scan, far magic, trailer magic): it is tried in
        # its own tier after them (step 4a).
        near = [e for e in all_near if not _is_plugin_format(e.format)]
        plugin_near = [e for e in all_near if _is_plugin_format(e.format)]
        data = _read_near_window(workspace, budget, all_near, near, trailers)

        detection = _DetectionPass(
            workspace=workspace,
            collector=collector,
            registry=registry,
            budget=budget,
            name=name,
            ext_match=ext_match,
            trailers=trailers,
            always_probe=always_probe,
            formats=formats,
            data=data,
            peek_more=workspace.candidate_view(0),
            # Freeze the probe/far size-gate length from the near peek alone. A later
            # SFX or far growth that hits EOF would make ``remaining_known()`` report a
            # length; that is correct for capability accounting but must not flip
            # content-probe framing gates that deliberately treat a
            # DETECTION_LIMIT-sized non-seekable peek as unknown-length. A peek that
            # stopped early on a pipe is short with the source not ended, and
            # ``remaining_known()`` is ``None`` then.
            length=workspace.remaining_known(),
        )

        # 1. Exact built-in magic in the default window.
        magic_fmt = _match_magic(data, near)
        if magic_fmt is None:
            magic_fmt = _match_magic_behind_prefix(data, registry.magic_prefix_walks())
        if magic_fmt is not None:
            return _near_magic_hit(detection, magic_fmt)

        # 2. Self-extracting archives. A known non-archive signature is not a stub.
        non_archive = _non_archive_signature(data)
        cue = executable_cue(data)
        if cue is not ExecutableCue.NONE and non_archive is None:
            info = _sfx_behind_executable(detection)
            if info is not None:
                return info

        # 3. Far magic (ISO's CD001 at offset 32 769).
        info = _far_magic(detection, far)
        if info is not None:
            return info

        # 4. Trailer magic (UDIF's koly block). After far magic, so an ISO whose
        # CD001 already matched is read as that ISO — an uncompressed UDIF image
        # of an ISO 9660 disk included — and is not asked for a tail read.
        # Before the probes, so a zlib-first image is the image and not its
        # first block.
        trailer_fmt = _match_trailer(workspace, trailers)
        if trailer_fmt is not None:
            return detection.conclude(
                FormatInfo(trailer_fmt, DetectionConfidence.CERTAIN, "magic"),
                _ConflictEvidence.MAGIC,
            )

        # 4a. A plugin's exact magic in the default window, now that no built-in
        # signature matched (step 1 says why it waits). Before the header checks and
        # the probes, which are weaker evidence than an exact magic. So a plugin format
        # is decided only after the far window (about 32 KiB) and the trailer are read.
        magic_fmt = _match_magic(data, plugin_near)
        if magic_fmt is not None:
            return _near_magic_hit(detection, magic_fmt)

        # 5. Self-checking headers (a v7 TAR header, by its checksum).
        info = _self_checking_header(detection)
        if info is not None:
            return info

        # 6. Content probes, unless the prefix is a confirmed executable or a known
        # non-archive signature. The reason is kept for the error below.
        probes_stopped_by = non_archive
        if probes_stopped_by is None and cue is ExecutableCue.STRONG:
            probes_stopped_by = (
                "a structurally valid executable header (PE, ELF or Mach-O), and no "
                "archive was found behind it"
            )
        info = _content_probes(detection, candidates.probes, probes_stopped_by)
        if info is not None:
            return info

        # 7. An archive behind leading bytes that look like nothing.
        info, leading_scan_window = _leading_bytes_scan(detection, cue, non_archive)
        if info is not None:
            return info

        # 8. Extension-only guess.
        if ext_match is not None:
            return _attach_receipt(
                FormatInfo(ext_match[0], DetectionConfidence.GUESS, "extension"),
                workspace,
            )

        raise _undetected_error(
            detection,
            probes_stopped_by=probes_stopped_by,
            leading_scan_window=leading_scan_window,
            off_formats=candidates.off_formats,
        )


@dataclass(frozen=True)
class _CandidateTables:
    """The registry's detection tables for one call, minus what ``formats`` leaves out.

    A plugin format the policy turns off is not a candidate: its probe is its own
    code, and its magic, matched in registration order, could claim a file that an
    allowed plugin also matches. Built-in formats are candidates under every policy,
    so their answer never depends on it.
    """

    magic_entries: list[MagicSignature]
    extension_map: dict[str, ArchiveFormat]
    probes: list[tuple[ArchiveFormat, ContentProbe]]

    off_tiers: tuple[str, ...]
    """The tiers that lost an entry to the policy, to record as
    ``NOT_ENABLED_BY_POLICY`` once the workspace exists."""

    off_formats: frozenset[ArchiveFormat]
    """The plugin formats the policy left out, named in the final error."""


def _candidate_tables(
    registry: BackendRegistry, formats: FormatPolicy
) -> _CandidateTables:
    magic_entries = registry.magic_entries()
    extension_map = registry.extension_map()
    probes = registry.content_probes()
    off_near = off_far = off_extension = off_probe = False
    off_formats: set[ArchiveFormat] = set()
    if formats._turns_off_plugins:
        pair_bases = [base.container for base in registry.stream_pair_bases()]

        def is_off(fmt: ArchiveFormat, *, signal: bool = False) -> bool:
            # A plugin codec's magic or probe (a ``signal``) also finds each container
            # read inside it, as gzip's finds a tarball: it stays while the policy
            # allows the bare stream or one of those pairs, and the open refuses a bare
            # stream the policy does not allow, as for a built-in codec. An extension
            # names one pair, so it is judged as that pair.
            candidates = [fmt]
            if signal and fmt.container is ContainerFormat.RAW_STREAM:
                candidates += [ArchiveFormat(c, fmt.stream) for c in pair_bases]
            if all(_plugin_off(formats, c) for c in candidates):
                off_formats.add(fmt)
                return True
            return False

        kept_magic: list[MagicSignature] = []
        for e in magic_entries:
            if not is_off(e.format, signal=True):
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
        kept_probes = [(f, p) for f, p in probes if not is_off(f, signal=True)]
        off_probe = len(kept_probes) < len(probes)
        probes = kept_probes
    excluded = formats.exclude_libraries
    if excluded:
        # A probe whose format needs a package the policy turns off does not run, so the
        # package is not called: a codec's probe decodes with it, and a plugin's probe
        # is handed no policy and may import what its ``requires`` names. Nothing is
        # recorded in ``unavailable_tiers``: an excluded package reads as absent, and
        # with it absent the probe would run and answer no, which records nothing
        # either, so the two stay alike.
        from archivey.internal.streams.codecs import stream_codec_for_format

        probes = [
            (fmt, probe)
            for fmt, probe in probes
            if not registry.needs_excluded_package(fmt, excluded)
            and (
                fmt.stream is StreamFormat.UNCOMPRESSED
                or not stream_codec_for_format(fmt.stream).excluded_by(excluded)
            )
        ]
    off_tiers = tuple(
        tier
        for tier, left_out in (
            ("near_magic", off_near),
            ("far_magic", off_far),
            ("content_probe", off_probe),
            ("extension", off_extension),
        )
        if left_out
    )
    return _CandidateTables(
        magic_entries, extension_map, probes, off_tiers, frozenset(off_formats)
    )


def _read_near_window(
    workspace: PrefixWorkspace,
    budget: DetectionBudget,
    all_near: list[MagicSignature],
    near: list[MagicSignature],
    trailers: list[TrailerSignature],
) -> bytes:
    """Peek the default window that every step up to the content probes matches
    against: :data:`DETECTION_LIMIT` bytes, or more when a near signature ends further
    in, within ``max_prefix_bytes``."""
    near_span = max((e.offset + len(e.magic) for e in all_near), default=0)
    if all_near:
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
    return workspace.peek_prefix_until(
        near_needed, lambda head: _near_magic_settled(head, near, preempted)
    )


@dataclass(frozen=True)
class _DetectionPass:
    """What the steps of one detection pass share, fixed once the near window is
    read."""

    workspace: PrefixWorkspace
    collector: DiagnosticCollector
    registry: BackendRegistry
    budget: DetectionBudget
    name: str | None
    ext_match: tuple[ArchiveFormat, str] | None
    trailers: list[TrailerSignature]
    always_probe: bool
    formats: FormatPolicy

    data: bytes
    """The near window (:func:`_read_near_window`)."""

    peek_more: CandidateView
    """A view of the source from offset 0 that grows the prefix on demand."""

    length: int | None
    """The source length as the near peek proved it, or ``None`` when unknown."""

    def conclude(self, info: FormatInfo, evidence: _ConflictEvidence) -> FormatInfo:
        """Warn when the extension names another format, and attach the receipt."""
        _warn_on_conflict(
            self.collector, self.name, self.ext_match, info.format, evidence
        )
        return _attach_receipt(info, self.workspace)


def _near_magic_hit(detection: _DetectionPass, magic_fmt: ArchiveFormat) -> FormatInfo:
    """The answer for an exact magic in the near window (step 1 or 4a)."""
    workspace = detection.workspace
    trailers = detection.trailers
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
        ext_match=detection.ext_match,
        workspace=workspace,
        view_arrived=arrived,
        always_probe=detection.always_probe,
        formats=detection.formats,
    )
    return detection.conclude(info, _ConflictEvidence.MAGIC)


def _sfx_behind_executable(detection: _DetectionPass) -> FormatInfo | None:
    """Step 2: an archive appended to an executable stub or a ``#!`` launcher.

    Runs the SFX scan, then, when it misses, the PE tail probe.
    """
    workspace = detection.workspace
    budget = detection.budget
    registry = detection.registry
    data = detection.data
    scan_limit = min(SFX_MAX, budget.max_scan_bytes)
    head = _executable_head(data, detection.peek_more, workspace)
    sfx_info = _scan_for_sfx_payload(
        registry.sfx_magic_entries(),
        detection.peek_more,
        workspace,
        scan_limit=scan_limit,
        peek_allowance=validator_allowance(budget),
        validators=registry.sfx_hit_validators(),
        capped_formats=registry.sfx_parser_scanned_formats(),
        # Shebang is text; ``WEAK`` alone is also unconfirmed MZ/ELF.
        restrict_to_validated=data.startswith(b"#!"),
        leading=head,
    )
    if sfx_info is not None:
        return detection.conclude(sfx_info, _ConflictEvidence.SFX_SCAN)
    # A ZIP far behind a PE stub, found from its end record (the install4j
    # shape). Gated on the PE's own layout, so only a large installer whose
    # overlay runs past the window pays for the tail read.
    tail_info = _probe_pe_tail(
        workspace,
        head,
        scan_limit=scan_limit,
        enabled=budget.max_scan_bytes > 0,
    )
    if tail_info is not None:
        return detection.conclude(tail_info, _ConflictEvidence.SFX_SCAN)
    return None


def _far_magic(
    detection: _DetectionPass, far: list[MagicSignature]
) -> FormatInfo | None:
    """Step 3: exact magic past the default window, from an extended peek.

    A signature that ends past ``max_far_bytes`` cannot match in the clamped window,
    so it is dropped and the tier is recorded as cut short, the same rule the near
    tier follows. A source provably too short to hold the signature loses nothing to
    the clamp. A zero ``max_far_bytes`` turns the tier off, and it is recorded as not
    enabled.
    """
    workspace = detection.workspace
    budget = detection.budget
    length = detection.length
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
    if not reachable_far:
        return None
    far_needed = max(e.offset + len(e.magic) for e in reachable_far)
    if length is not None and length < far_needed:
        return None  # size-gated: never pay the peek
    far_data = workspace.peek_prefix(far_needed)
    # Charge the bytes actually requested even when the window came up short.
    workspace.charge_far(len(far_data))
    far_fmt = _match_magic(far_data, reachable_far)
    if far_fmt is None:
        return None
    return detection.conclude(
        FormatInfo(far_fmt, DetectionConfidence.CERTAIN, "magic"),
        _ConflictEvidence.MAGIC,
    )


def _self_checking_header(detection: _DetectionPass) -> FormatInfo | None:
    """Step 5: a format with no magic whose first block proves itself.

    Before the content probes, and not held back by the name as they are: the check
    is arithmetic over bytes already peeked, and text or binary data passes only when
    built to. A hit is its own corroboration (DR-7): a checksum and every numeric
    field had to hold, so a later read failure is not stamped as probe-only. A window
    too short for the block is recorded, as the magic tiers record theirs.
    """
    budget = detection.budget
    header_checks = detection.registry.header_checks()
    if header_checks:
        _record_tier_limit(
            detection.workspace,
            "header_check",
            enabled=budget.max_prefix_bytes > 0,
            covered=budget.max_prefix_bytes >= HEADER_CHECK_BYTES,
        )
    for check_fmt, check in header_checks:
        if check(detection.data):
            return detection.conclude(
                FormatInfo(
                    check_fmt,
                    DetectionConfidence.PROBABLE,
                    "content_probe",
                    corroborated=True,
                ),
                _ConflictEvidence.CONTENT_PROBE,
            )
    return None


def _content_probes(
    detection: _DetectionPass,
    probes: list[tuple[ArchiveFormat, ContentProbe]],
    stopped_by: str | None,
) -> FormatInfo | None:
    """Step 6: the content probes of formats with no reliable magic.

    Unless the config asks for all of them, only the probe of the format the
    extension names runs: a probe is the weakest evidence, and on an unnamed source it
    is the only evidence. With a matching extension the probe can only confirm the
    name. ``stopped_by`` describes the evidence of a non-archive file that keeps every
    probe from running, or is ``None``.
    """
    workspace = detection.workspace
    data = detection.data
    length = detection.length
    ext_match = detection.ext_match
    if not detection.always_probe:
        named_probes = [(f, p) for f, p in probes if _probe_named(f, ext_match)]
        # Recorded whenever the name left a probe out, even if another one runs: a
        # .zz source still skips the LZMA Alone and Brotli probes.
        if len(named_probes) < len(probes):
            workspace.record_skip("content_probe", TierSkipReason.NOT_ENABLED_BY_POLICY)
        probes = named_probes
    if stopped_by is not None:
        return None

    def read_at(offset: int, n: int) -> bytes | None:
        return workspace.read_at(offset, n)

    def charge_decode(n: int) -> bool:
        # Brotli's chain decode reads and decodes the total [0, n): it draws on
        # the decode allowance, and reads no further than any buffered tier
        # may, nor past the 1 MiB reach of a probe read.
        if n > min(workspace.read_ceiling, PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE):
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
        try:
            hit = probe(
                data,
                source_length=length,
                read_at=read_at,
                charge_decode=charge_decode,
                isolation=workspace.isolation,
                decoder_limits=workspace.decoder_limits,
            )
        except ResourceLimitError as exc:
            # Its decoder is over the caller's ``max_decoder_memory``, or its child
            # could not run: "can't tell", not "not this format". The next probe
            # still runs.
            workspace.record_skip(
                "content_probe", TierSkipReason.CAPABILITY_UNAVAILABLE
            )
            _log_probe_refused(f"try the {probe_fmt} content probe", exc)
            hit = False
        if hit and _probe_completes(
            probe, data, length, read_at, charge_decode, workspace
        ):
            confidence = DetectionConfidence.PROBABLE
            if probe_fmt.stream is StreamFormat.BROTLI:
                confidence = _brotli_probe_confidence(data, ext_match)
            info = _resolve_single_file_or_tar(
                probe_fmt,
                confidence,
                "content_probe",
                detection.peek_more,
                ext_match=ext_match,
                workspace=workspace,
                always_probe=detection.always_probe,
                formats=detection.formats,
            )
            return detection.conclude(info, _ConflictEvidence.CONTENT_PROBE)
    return None


def _leading_bytes_scan(
    detection: _DetectionPass, cue: ExecutableCue, non_archive: str | None
) -> tuple[FormatInfo | None, int]:
    """Step 7: an archive behind leading bytes that look like nothing.

    The SFX scan's window and validators without its executable cue, as 7-Zip, unrar
    and unzip find one. Last, so only a source every other step declined pays for the
    window. An executable cue already ran the scan. A known non-archive signature is
    not a prefix, and a name that names a format keeps its guess: the ZIP, 7z and RAR
    readers find a prefixed archive themselves, and the ZIP reader from the end, where
    the first local header the scan meets may belong to a later member (a ZIP missing
    its first bytes). An unnamed ZIP missing its first bytes is knowingly left to
    that: the scan opens it at a later member's header, and the reader's
    missing-bytes message counts from there.

    Returns the answer, or ``None``, and the window a budget-bounded scan searched in
    vain (0 when no such scan ran), which the final error names.
    """
    workspace = detection.workspace
    budget = detection.budget
    if cue is not ExecutableCue.NONE:
        return None, 0
    if non_archive is not None or detection.ext_match is not None:
        workspace.record_skip("sfx_scan", TierSkipReason.NOT_ENABLED_BY_POLICY)
        return None, 0
    scan_limit = min(SFX_MAX, budget.max_scan_bytes)
    allowance = validator_allowance(budget)
    cut_reason = TierSkipReason.BUDGET_EXHAUSTED
    held = workspace.buffered_length
    if (
        workspace.forward_only
        and workspace.remaining_known() is None
        and held < scan_limit + allowance
    ):
        # A forward-only source is scanned over the bytes detection already
        # holds and never waits for more: an unrecognised stream whose writer
        # keeps it open fails at once.
        scan_limit, allowance = held, 0
        cut_reason = TierSkipReason.CAPABILITY_UNAVAILABLE
    sfx_info = _scan_for_sfx_payload(
        detection.registry.sfx_magic_entries(),
        detection.peek_more,
        workspace,
        scan_limit=scan_limit,
        peek_allowance=allowance,
        validators=detection.registry.sfx_hit_validators(),
        capped_formats=detection.registry.sfx_parser_scanned_formats(),
        # With no cue, a bare needle is too weak: every needle needs its
        # format's validator.
        restrict_to_validated=True,
        cut_reason=cut_reason,
    )
    if sfx_info is not None:
        # No name, so no extension to conflict with: the evidence is unused.
        return detection.conclude(sfx_info, _ConflictEvidence.SFX_SCAN), 0
    if cut_reason is TierSkipReason.BUDGET_EXHAUSTED:
        return None, scan_limit
    return None, 0


def _undetected_error(
    detection: _DetectionPass,
    *,
    probes_stopped_by: str | None,
    leading_scan_window: int,
    off_formats: frozenset[ArchiveFormat],
) -> FormatDetectionError:
    """The :class:`FormatDetectionError` that ends a pass no step answered.

    The message names the most useful reason first: an empty source, then evidence of
    a non-archive file, then the advice for a format with no magic.
    """
    name = detection.name
    if detection.length == 0:
        # Every step "declined" an empty source, but there was nothing to match;
        # saying no magic matched would send the caller looking for a wrong byte.
        # ``length`` counts from the current position, so a handle already read
        # to its end lands here too; the message covers both.
        return FormatDetectionError(
            "Could not detect archive format: there are no bytes to read (the "
            "source is empty, or already positioned at its end).",
            archive_name=name,
        )
    if probes_stopped_by is not None:
        return FormatDetectionError(
            f"Could not detect archive format: the source starts with "
            f"{probes_stopped_by}. No content probe was run, and no file extension "
            "matched.",
            archive_name=name,
        )
    message = (
        "Could not detect archive format: no magic bytes, content probe or file "
        "extension matched."
    )
    if not detection.always_probe:
        message = (
            "Could not detect archive format: no magic bytes or file extension "
            "matched. A raw LZMA Alone, zlib or Brotli stream has no magic and is "
            "only recognised by its extension: give the file one (.lzma, .zz, "
            ".br), pass format=, use open_stream(), or set "
            "ArchiveyConfig(always_probe_content=True)."
        )
    if leading_scan_window:
        message += (
            f" No ZIP, 7z or RAR archive starts in the first {leading_scan_window} "
            "bytes behind other data either; for one further in, pass format=."
        )
    if off_formats:
        # Added to the advice above, not in its place: the file may be one of the
        # formats that advice reaches, and only the policy reaches an off plugin.
        # Each plugin once, not each compressed pair it reads.
        names = ", ".join(sorted({_plugin_name(f) for f in off_formats}))
        message += (
            f" ArchiveyConfig.formats turns off the plugin formats {names}, so "
            "they were not tried."
        )
    return FormatDetectionError(message, archive_name=name)
