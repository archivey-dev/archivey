"""The answer of a content probe: a three-valued verdict, never a bool.

A probe answers ``None`` when the bytes are not its format, ``GUESS`` for a weak
match, and ``PROBABLE`` for a match. ``CERTAIN`` is never a probe's: only a
signature gives it. Detection adds what only it knows, that the extension names the
format, and raises a ``GUESS`` to ``PROBABLE`` then.
"""

from __future__ import annotations

from typing import TypeAlias

from archivey.detection import DetectionConfidence

ProbeVerdict: TypeAlias = DetectionConfidence | None
"""A content probe's answer: ``None``, ``GUESS`` or ``PROBABLE``."""

PROBE_MATCH = DetectionConfidence.PROBABLE
"""The verdict of a probe that only tells yes from no, when it says yes."""

PROBE_MATCHES = (DetectionConfidence.GUESS, DetectionConfidence.PROBABLE)
"""The verdicts that are a match."""


def probe_verdict(match: bool) -> ProbeVerdict:
    """The verdict of a probe that only tells yes from no."""
    return PROBE_MATCH if match else None


def graded(verdict: DetectionConfidence, *, named: bool) -> DetectionConfidence:
    """The confidence detection reports for a probe's match: a ``GUESS`` is
    ``PROBABLE`` when the source's extension names the format."""
    if named and verdict is DetectionConfidence.GUESS:
        return DetectionConfidence.PROBABLE
    return verdict


__all__ = ["PROBE_MATCH", "PROBE_MATCHES", "ProbeVerdict", "graded", "probe_verdict"]
