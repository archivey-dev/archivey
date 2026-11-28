"""The answer of a content probe: a three-valued verdict, never a bool or ``None``.

A probe answers ``REJECTED`` when the bytes are not its format, ``GUESS`` for a weak
match, and ``PROBABLE`` for a match. ``CERTAIN`` is never a probe's: only a
signature gives it. ``None`` is not an answer either, so a probe that forgets a
``return`` is a bug, not a quiet "no". Detection adds what only it knows, that the
extension names the format, and raises a ``GUESS`` to ``PROBABLE`` then.
"""

from __future__ import annotations

from typing import TypeAlias

from archivey.detection import DetectionConfidence

ProbeVerdict: TypeAlias = DetectionConfidence
"""A content probe's answer: ``REJECTED``, ``GUESS`` or ``PROBABLE``."""

PROBE_MATCH = DetectionConfidence.PROBABLE
"""The verdict of a probe that only tells yes from no, when it says yes."""

PROBE_REJECTED = DetectionConfidence.REJECTED
"""The verdict of a probe that says no."""

PROBE_MATCHES = (DetectionConfidence.GUESS, DetectionConfidence.PROBABLE)
"""The verdicts that are a match."""

PROBE_VERDICTS = (PROBE_REJECTED, *PROBE_MATCHES)
"""Every answer a probe may give."""


def probe_verdict(match: bool) -> ProbeVerdict:
    """The verdict of a probe that only tells yes from no."""
    return PROBE_MATCH if match else PROBE_REJECTED


def is_match(verdict: ProbeVerdict) -> bool:
    """Whether ``verdict`` is a match, weak or not. Decided on the match verdicts,
    by identity, so any other answer (``None``, a bool, ``CERTAIN``) is no match."""
    return any(verdict is match for match in PROBE_MATCHES)


def graded(verdict: DetectionConfidence, *, named: bool) -> DetectionConfidence:
    """The confidence detection reports for a probe's match: a ``GUESS`` is
    ``PROBABLE`` when the source's extension names the format."""
    if named and verdict is DetectionConfidence.GUESS:
        return DetectionConfidence.PROBABLE
    return verdict


__all__ = [
    "PROBE_MATCH",
    "PROBE_MATCHES",
    "PROBE_REJECTED",
    "PROBE_VERDICTS",
    "ProbeVerdict",
    "graded",
    "is_match",
    "probe_verdict",
]
