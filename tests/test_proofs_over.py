"""``ArchiveStreamImpl._proofs_over`` joins the stream's own proofs, the verifier's and
the layers' below in one record, for speed. It must equal the plain form,
``own.combine(verifier).combine(below)``, for every field of
:class:`VerificationProofs`: a field added to the class and to ``combine`` but not to
``_proofs_over`` would be dropped at the member level, and these tests catch that.
"""

from __future__ import annotations

from dataclasses import fields, replace
from types import SimpleNamespace

import pytest

from archivey.internal.streams.archive_stream import ArchiveStreamImpl
from archivey.internal.streams.verification import NO_PROOFS, VerificationProofs

FIELDS = [f.name for f in fields(VerificationProofs)]
NO_VERIFIER = "no verifier"


def _stream(verifier: VerificationProofs | None, *, ended: bool, checks: bool):
    ns = SimpleNamespace(
        _ended_from_start=ended,
        _checks_content=checks,
        _verifier=None
        if verifier is None
        else SimpleNamespace(proofs=lambda: verifier),
        _level_member=None,
    )
    ns._frame_verdict = lambda below: ArchiveStreamImpl._frame_verdict(ns, below)  # type: ignore[arg-type]
    return ns


def _plain(stream, below: VerificationProofs, frames: bool) -> VerificationProofs:
    """The form ``_proofs_over`` replaced: three records joined with ``combine``."""
    ended = stream._ended_from_start
    fc, fp = stream._frame_verdict(below) if frames else (False, False)
    own = VerificationProofs(
        ended=ended,
        content=(stream._checks_content and ended) or fc,
        content_possible=stream._checks_content or fp,
    )
    if stream._verifier is not None:
        own = own.combine(stream._verifier.proofs())
    return own.combine(below)


def _one(name: str | None) -> VerificationProofs:
    return NO_PROOFS if name is None else replace(NO_PROOFS, **{name: True})


@pytest.mark.parametrize("frames", [True, False])
@pytest.mark.parametrize("ended", [True, False])
@pytest.mark.parametrize("checks", [True, False])
@pytest.mark.parametrize("below_field", [None, *FIELDS])
# NO_VERIFIER: the stream has none; None: it has one that proves nothing.
@pytest.mark.parametrize("verifier_field", [NO_VERIFIER, None, *FIELDS])
def test_proofs_over_matches_combine(
    frames: bool,
    ended: bool,
    checks: bool,
    below_field: str | None,
    verifier_field: str | None,
) -> None:
    verifier = None if verifier_field == NO_VERIFIER else _one(verifier_field)
    stream = _stream(verifier, ended=ended, checks=checks)
    below = _one(below_field)
    got = ArchiveStreamImpl._proofs_over(stream, below, frames=frames)  # type: ignore[arg-type]
    assert got == _plain(stream, below, frames)
