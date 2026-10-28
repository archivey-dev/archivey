"""The result of format detection: :class:`FormatInfo` and :class:`DetectionConfidence`.

Returned by :func:`archivey.detect_format` and re-exported from :mod:`archivey`, which is
where callers should import them from. They are defined here, in a public module, so
that their ``__module__`` is a stable path: ``pickle`` records it, and a class defined
under ``archivey.internal`` would freeze an internal path into data a caller persists.
The detector itself is internal (``archivey.internal.detection``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from archivey.detection_cost import DetectionCostReceipt, TierSkip
from archivey.diagnostics import DiagnosticSummary
from archivey.types import ArchiveFormat, PluginContainer

__all__ = ["DetectionConfidence", "FormatInfo"]

# How a format was decided; see ``FormatInfo.detected_by``. Not exported: callers
# compare against the strings, and the alias exists so the detector and the field agree.
DetectedBy = Literal["magic", "extension", "content_probe", "sfx_scan", "directory"]


class DetectionConfidence(Enum):
    """How much :func:`~archivey.detect_format` trusts the format it reports.

    Provisional in 0.2.x: which grade a detection step reports may change in a later
    release (a two-byte magic reported below ``CERTAIN``, for instance). Branch on the
    format, not on the grade.
    """

    CERTAIN = "certain"
    """An exact magic-byte match at the expected offset."""

    PROBABLE = "probable"
    """A structural or content probe matched: the inner-TAR probe, the SFX scan, or a
    content probe hit (LZMA-alone, zlib, or Brotli whose first meta-block is
    compressed or whose extension agrees)."""

    GUESS = "guess"
    """No confirmation strong enough to rely on: an extension-only guess, or a content
    probe hit in the weak evidence class (today: extensionless Brotli whose first
    meta-block is uncompressed or metadata)."""


@dataclass(frozen=True)
class FormatInfo:
    """The result of :func:`~archivey.detect_format` — the detected format plus how sure
    we are."""

    format: ArchiveFormat
    """The detected format."""

    confidence: DetectionConfidence
    """How far the evidence behind ``format`` goes."""

    detected_by: DetectedBy
    """Which evidence decided: ``"magic"``, ``"extension"``, ``"content_probe"``,
    ``"sfx_scan"`` or ``"directory"``.

    An open set: a later release may add a detection step with a new value, so code
    that matches on it should handle a value it does not know. ``"sfx_scan"`` covers
    any archive found behind a prefix, a ``#!`` launcher included, not only a
    self-extractor's executable stub."""

    payload_offset: int = 0
    """Where the archive starts in the source. Nonzero only for a self-extracting
    archive, so ``payload_offset > 0`` is the test for one."""

    diagnostics: DiagnosticSummary = field(default_factory=DiagnosticSummary.empty)
    """What detection reported on its way to the answer."""

    corroborated: bool = field(default=False, compare=False, repr=False)
    """Provisional and informational, not part of the :func:`~archivey.detect_format`
    contract: whether a matching extension, an inner-TAR upgrade, or a self-checking
    header (a TAR header checksum) corroborated a content-probe claim.

    Read it only together with ``detected_by == "content_probe"``. ``False`` also means
    "not a probe at all", so an exact magic hit reads ``False`` too. A later release may
    replace this field with a record of the evidence that separates the two cases."""
    # ``compare=False`` and ``repr=False`` keep it out of ``__eq__`` and ``__repr__``, so
    # two results that differ only here compare equal. The overloaded ``False`` is why it
    # is provisional: a bool cannot separate "no corroboration" from "not a probe".
    # ``probe-provenance-unconfirmed`` task 5.1 tracks the evidence-set shape that could.

    cost_receipt: DetectionCostReceipt | None = field(
        default=None, compare=False, repr=False
    )
    """The work detection did, as a
    :class:`~archivey.detection_cost.DetectionCostReceipt`: bytes read and scanned, decode
    input and output, and the number of passes. It covers the whole call, both passes
    when :func:`~archivey.detect_format` followed a stub to its split volume.

    :func:`~archivey.detect_format` always fills it; a directory gets the zero receipt.
    ``None`` only on a ``FormatInfo`` that detection did not produce."""
    # ``compare=False`` and ``repr=False`` keep equality about what was detected, not
    # about what detecting it cost. Not merged into ``CostReceipt`` /
    # ``ArchiveInfo.cost``: the two receipts are never summed.

    unavailable_tiers: tuple[TierSkip, ...] = field(
        default=(), compare=False, repr=False
    )
    """The detection tiers that did not run, each a
    :class:`~archivey.detection_cost.TierSkip` with its
    :class:`~archivey.detection_cost.TierSkipReason`: not enabled by policy, a
    capability the source lacks, or the budget ran out. Empty when every tier ran."""

    @property
    def from_plugin(self) -> bool:
        """Whether ``format`` is one a plugin added (``archivey.plugins``), not a
        built-in one. A plugin's parser is not covered by archivey's limits, so a
        caller that reads untrusted input can refuse such a format."""
        return isinstance(self.format.container, PluginContainer)
