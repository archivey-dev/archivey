"""Detection's mutable cost accumulator.

Implementation companions to :mod:`archivey.detection_cost`: detectors write into
:class:`MutableDetectionCostReceipt` and freeze it into the public
:class:`~archivey.detection_cost.DetectionCostReceipt` on the :class:`~archivey.FormatInfo`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from archivey.detection_cost import (
    DetectionCostReceipt,
    TierSkip,
    TierSkipReason,
)


@dataclass
class MutableDetectionCostReceipt:
    """Mutable accumulator used by the workspace; freeze with :meth:`freeze`."""

    prefix_bytes: int = 0
    unique_bytes_read: int = 0
    far_bytes: int = 0
    scanned_bytes: int = 0
    decode_input: int = 0
    decode_output: int = 0
    passes: int = 1
    skips: list[TierSkip] = field(default_factory=list)

    def freeze(self) -> DetectionCostReceipt:
        # ``skips`` is not part of the public receipt: it reaches the caller as
        # ``FormatInfo.unavailable_tiers``.
        return DetectionCostReceipt(
            prefix_bytes=self.prefix_bytes,
            unique_bytes_read=self.unique_bytes_read,
            far_bytes=self.far_bytes,
            scanned_bytes=self.scanned_bytes,
            decode_input=self.decode_input,
            decode_output=self.decode_output,
            passes=self.passes,
        )

    def record_skip(self, tier: str, reason: TierSkipReason) -> None:
        # A second pass can record a skip the first pass already recorded; a repeat
        # carries no information, so the list keeps one of each.
        skip = TierSkip(tier=tier, reason=reason)
        if skip not in self.skips:
            self.skips.append(skip)
