"""The probe verdict helpers: a match is one of the two match verdicts, nothing else."""

from __future__ import annotations

import pytest

from archivey import DetectionConfidence
from archivey.internal.probe_verdict import is_match


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        (DetectionConfidence.PROBABLE, True),
        (DetectionConfidence.GUESS, True),
        (DetectionConfidence.REJECTED, False),
        # Not verdicts: a built-in probe's stray answer is no match, as a plugin's is.
        (DetectionConfidence.CERTAIN, False),
        (None, False),
        (True, False),
        ([1], False),
    ],
)
def test_only_a_match_verdict_is_a_match(answer: object, match: bool) -> None:
    assert is_match(answer) is match  # type: ignore[arg-type]


def test_rejected_is_listed_after_the_grades() -> None:
    assert list(DetectionConfidence)[-1] is DetectionConfidence.REJECTED
