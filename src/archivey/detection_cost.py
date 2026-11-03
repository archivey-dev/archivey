"""Detection budget and cost receipt.

Detection's I/O happens before a reader exists, so its measured work is a sibling of
:class:`~archivey.cost.CostReceipt` rather than part of it. The two share vocabulary for
kinds of work; they are never summed together. See the ``detection-cost`` and
``access-mode-and-cost`` capability specs.

**Public, not re-exported.** Callers reach :class:`DetectionBudget`, its presets and
:class:`DetectionBudgetPreset` here, as ``archivey.detection_cost.…``, to set
:attr:`ArchiveyConfig.detection_budget <archivey.ArchiveyConfig.detection_budget>`.
The receipt and skip types are what :attr:`FormatInfo.cost_receipt
<archivey.FormatInfo.cost_receipt>` is made of. All of them are documented on the API
page and stable under the same rule as ``archivey.terminal``; the mutable accumulator
detectors write into lives under ``internal/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from archivey.internal.arg_checks import check_limit_fields
from archivey.internal.sfx import SFX_MAX


class DetectionBudgetPreset(Enum):
    """Named detection budgets. ``BALANCED`` is the ``detect_format`` default."""

    BALANCED = "balanced"
    FAST = "fast"
    THOROUGH = "thorough"


class TierSkipReason(Enum):
    """Why a detection tier did not run.

    Distinct reasons matter: ``NOT_ENABLED_BY_POLICY`` does not make the search incomplete,
    while ``CAPABILITY_UNAVAILABLE`` and ``BUDGET_EXHAUSTED`` do.
    """

    NOT_ENABLED_BY_POLICY = "not_enabled_by_policy"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True)
class TierSkip:
    """A tier that detection did not run, with the reason."""

    tier: str
    """The tier's name."""

    reason: TierSkipReason
    """Why it did not run."""


@dataclass(frozen=True)
class DetectionBudget:
    """Upper bounds on what detection may spend.

    Content-probe header reads at an offset are not a budget field: the Brotli chain walk
    caps them itself, at ``CHAIN_MAX_LINKS`` (8) header reads of 24 bytes. The Brotli
    chain decode that follows reads ``[0, end)``: it is charged to ``max_decode_input``
    and runs only when ``end`` is within the prefix/far/scan ceiling.
    """

    max_prefix_bytes: int
    """Bytes detection may read from the start of the source."""

    max_far_bytes: int
    """Bytes the far-magic tier may read, for a signature at a fixed offset past the
    prefix. Separate from ``max_prefix_bytes`` because ISO's ``CD001`` at 32 769 needs
    a window of about 32 KiB that a 4 KiB prefix budget would forbid."""

    max_scan_bytes: int
    """How far into the source the scan for an archive behind a prefix looks for a
    signature: behind an SFX stub or launcher, and, as detection's last step, behind
    leading bytes of any kind. Zero turns both off. A candidate found there is judged
    on its whole header, which may extend past the window by up to 132 KiB or
    ``max_scan_bytes``, whichever is smaller; a header that does not fit is rejected,
    and ``sfx_scan`` recorded as cut short."""

    max_decode_input: int
    """Compressed bytes decoding may consume, one allowance for the whole call, shared
    by the content probes, the Brotli chain decode, their completion check and the
    inner-TAR probe."""

    max_decode_output: int
    """Decoded bytes the inner-TAR probe may produce. A content probe's output is
    bounded by the codec's own drain instead: 4 KiB, 64 KiB with the whole source in
    hand, and the sample length (up to 1 MiB) for the Brotli chain decode. That output
    is not charged, as it is mostly a copy of input already charged to
    ``max_decode_input``."""

    # The completion check is defined in ``openspec/specs/format-detection``.
    completion_window_bytes: int
    """The largest source a content-probe hit is re-checked against in full; ``0``
    turns the check off."""

    def __post_init__(self) -> None:
        # Every field is a non-negative int; there is no ``None`` to mean "off".
        check_limit_fields(self, cls="DetectionBudget")

    @classmethod
    def for_preset(cls, preset: DetectionBudgetPreset) -> DetectionBudget:
        if preset is DetectionBudgetPreset.BALANCED:
            return BALANCED_BUDGET
        if preset is DetectionBudgetPreset.FAST:
            return FAST_BUDGET
        if preset is DetectionBudgetPreset.THOROUGH:
            return THOROUGH_BUDGET
        raise ValueError(f"unknown detection budget preset: {preset!r}")


@dataclass(frozen=True)
class DetectionCostReceipt:
    """Measured detection work — charged as reads happen, not reconstructed afterwards."""

    prefix_bytes: int = 0
    """Sum of range lengths *requested* via ``peek_range`` (overlapping peeks accumulate).

    Not comparable 1:1 with ``max_prefix_bytes``: seek-based ``read_at`` does not charge
    here, and growing peeks bill each request in full. Prefer ``unique_bytes_read`` for
    "how much did we fetch from the source".
    """

    unique_bytes_read: int = 0
    """Bytes fetched from the source.

    A forward read of the prefix counts each of those bytes once. The trailer
    read counts its block as well, including when a later tier then reads the
    same bytes as part of the prefix.
    """

    far_bytes: int = 0
    """Bytes the far-magic tier peeked. Bounded by ``max_far_bytes``."""

    scanned_bytes: int = 0
    """Bytes the scan for an archive behind a prefix looked through. Bounded by
    ``max_scan_bytes``."""

    decode_input: int = 0
    """Compressed bytes decoded. Bounded by ``max_decode_input``."""

    decode_output: int = 0
    """Decoded bytes the inner-TAR probe produced. Bounded by ``max_decode_output``."""
    passes: int = 1
    """Detection passes this receipt sums, each run under the full budget.

    2 when ``detect_format`` followed a stub-only executable to its sibling split
    volume: the stub's pass and the volume's pass.
    """


# ISO CD001 ends at offset 32 773 inclusive → 32 774 bytes from origin.
_ISO_FAR_BYTES = 32_774
# The SFX tier's structural bound: a wider budget field would scan past what the
# parsers accept, and a narrower default would record every miss as cut short.
_SFX_SCAN_BYTES = SFX_MAX
_COMPLETION_WINDOW = 64 * 1024
_INNER_TAR_DECODE = 1 << 20


BALANCED_BUDGET = DetectionBudget(
    max_prefix_bytes=4096,
    max_far_bytes=_ISO_FAR_BYTES,
    max_scan_bytes=_SFX_SCAN_BYTES,
    max_decode_input=_INNER_TAR_DECODE,
    max_decode_output=_INNER_TAR_DECODE,
    completion_window_bytes=_COMPLETION_WINDOW,
)

FAST_BUDGET = DetectionBudget(
    max_prefix_bytes=4096,
    max_far_bytes=_ISO_FAR_BYTES,
    max_scan_bytes=256 * 1024,
    max_decode_input=64 * 1024,
    max_decode_output=64 * 1024,
    completion_window_bytes=0,  # no whole-source completion
)

THOROUGH_BUDGET = DetectionBudget(
    max_prefix_bytes=4096,
    max_far_bytes=_ISO_FAR_BYTES,
    max_scan_bytes=_SFX_SCAN_BYTES,
    max_decode_input=_INNER_TAR_DECODE,
    max_decode_output=_INNER_TAR_DECODE,
    # Whole-source completion as far as the decode allowance reaches; the allowance
    # (``max_decode_input``) is the real bound, so this is the same 1 MiB.
    completion_window_bytes=_INNER_TAR_DECODE,
)
