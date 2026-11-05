"""How ``open_archive`` chose the format, kept for the empty-listing check.

An empty listing is only interesting when the format was **not confirmed by the
archive's bytes** — an explicit ``format=`` that skipped detection, or an extension
fallback that ran precisely because every content signal declined. Whether that was the
case is known at open; whether the listing is empty is not known until it completes. This
record carries the first fact forward to the place that learns the second
(``BaseArchiveReader._publish_materialized``).

It also carries whether a content-probe match was the *sole* evidence (no matching
extension, no inner-TAR upgrade): a later decode failure then stamps
``format_unconfirmed`` and emits ``PROBE_FORMAT_UNCONFIRMED``. A decode failure under
``chosen_by == "extension"`` is stamped the same way and emits
``EXTENSION_FORMAT_UNCONFIRMED``. Confidence is not part of either channel.

It lives on the reader rather than in ``ReadBackend.open_read``'s signature because no
backend uses it: adding a parameter would touch every backend for a fact none of them
reads.

:func:`stamp_error_context` is the stamp itself: the reader applies it to every error
it raises, and ``open_archive`` to an error a backend raises while its reader is built,
before any reader exists to stamp it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NamedTuple

from archivey.diagnostics import DiagnosticCode, UnconfirmedFormatContext
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    ResourceUnavailableError,
)
from archivey.terminal import escape_control_chars

if TYPE_CHECKING:
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.types import ArchiveFormat

UnconfirmedEvidence = Literal["extension", "content_probe"]


@dataclass(frozen=True)
class FormatProvenance:
    """Where the resolved ``ArchiveFormat`` came from."""

    chosen_by: Literal["argument", "extension", "content", "directory"]
    """``"content"`` covers every detection step that read the bytes: magic (near,
    far and trailer), the SFX scan and the content probes.

    ``"extension"`` means detection fell through to the filename because every one of
    those steps declined, which is the same answer ``detect_format`` gives when it
    refuses a file outright.
    """

    source: Path | None = None
    """The source as ``open_archive`` resolved it, for a re-detection pass.

    Only used for the ``"argument"`` case, which skipped detection and therefore has
    nothing recorded to compare against. A stream source is recorded as ``None``:
    reopening a file cannot disturb the reader, while seeking a live stream back to
    its origin can.
    """

    probe_only: bool = False
    """True when detection chose the format via a content probe with no corroboration.

    That is the probe channel for ``format_unconfirmed`` on a later decode failure, at
    any ``DetectionConfidence``; the other is ``chosen_by == "extension"``, which is
    stamped through that field and leaves this one ``False``. Magic, SFX, a self-checking
    header, and probe hits corroborated by a matching extension or an inner-TAR upgrade
    leave it ``False`` and are not stamped.
    """

    @property
    def unconfirmed_evidence(self) -> UnconfirmedEvidence | None:
        """What a decode failure's ``format_unconfirmed`` stamp rests on, if anything.

        The two cases cannot overlap: ``core`` sets ``probe_only`` only for a content-probe
        detection and ``chosen_by="extension"`` only for an extension one.
        """
        if self.probe_only:
            return "content_probe"
        return "extension" if self.chosen_by == "extension" else None


class _UnconfirmedWording(NamedTuple):
    code: DiagnosticCode
    evidence_text: str  # "identified only by {evidence_text}"
    evidence_short: str  # "unconfirmed ({evidence_short})"


_UNCONFIRMED_EVIDENCE: Mapping[UnconfirmedEvidence, _UnconfirmedWording] = {
    "extension": _UnconfirmedWording(
        DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED,
        "its file extension",
        "extension only",
    ),
    "content_probe": _UnconfirmedWording(
        DiagnosticCode.PROBE_FORMAT_UNCONFIRMED,
        "a content probe",
        "content probe only",
    ),
}
"""A decode-failure diagnostic per unconfirmed evidence: its code and two phrasings.

The extension code is also the empty-listing code, which the reader's
``_emit_listed_empty_unconfirmed`` emits with its own message.
"""


def unconfirmed_context(
    archive_format: ArchiveFormat,
    archive_name: str | None,
    chosen_by: Literal["argument", "extension", "content_probe"],
    detected_format: str | None,
) -> UnconfirmedFormatContext:
    return UnconfirmedFormatContext(
        archive_name=archive_name,
        format=archive_format.display_name,
        chosen_by=chosen_by,
        detected_format=detected_format,
    )


def stamp_error_context(
    exc: ArchiveyError,
    *,
    archive_format: ArchiveFormat,
    archive_name: str | None,
    provenance: FormatProvenance | None,
    collector: DiagnosticCollector,
    member_name: str | None = None,
    claim_diagnostic: Callable[[], bool] | None = None,
) -> None:
    """Stamp format, archive and member onto ``exc`` where not set, and mark a decode
    failure under an unconfirmed format.

    The mark applies to a ``CorruptionError`` or ``ResourceLimitError`` when
    ``provenance`` says the format rested on a content probe with nothing corroborating
    it (``PROBE_FORMAT_UNCONFIRMED``), or on the filename alone, because every content
    signal declined (``EXTENSION_FORMAT_UNCONFIRMED``): the message says so,
    ``format_unconfirmed`` is set, and the diagnostic is emitted through ``collector``.
    ``claim_diagnostic`` returns whether this call may emit it; a reader passes one so
    the diagnostic is one per reader however many errors it stamps. Without it, every
    call emits.
    """
    if exc.source_format is None:
        exc.source_format = archive_format
    if exc.archive_name is None:
        exc.archive_name = archive_name
    if exc.member_name is None and member_name is not None:
        exc.member_name = member_name
    if provenance is None or not isinstance(exc, (CorruptionError, ResourceLimitError)):
        return
    evidence = provenance.unconfirmed_evidence
    if evidence is None:
        return
    _mark_unconfirmed_message(exc, evidence, archive_format)
    if claim_diagnostic is not None and not claim_diagnostic():
        return
    _emit_unconfirmed_failure(exc, evidence, archive_format, archive_name, collector)


def _mark_unconfirmed_message(
    exc: ArchiveyError, evidence: UnconfirmedEvidence, archive_format: ArchiveFormat
) -> None:
    if exc.format_unconfirmed:
        return
    evidence_short = _UNCONFIRMED_EVIDENCE[evidence].evidence_short
    # The stamped message speaks of the format the exception names, which a lower
    # layer (a codec, the spool) may have set to something other than the reader's
    # format; the diagnostic speaks of the reader's.
    stamped_format = (exc.source_format or archive_format).display_name
    detail = exc.raw_message.rstrip(".")
    unconfirmed = (
        f"Format identification was unconfirmed ({evidence_short}); "
        f"the source may not be {stamped_format}."
    )
    if isinstance(exc, ResourceUnavailableError):
        # The system ran short, maybe part-way through (a decoder process killed from
        # outside), so no limit is to blame and output may exist.
        new_msg = (
            f"{unconfirmed} The read was stopped because the system ran short: "
            f"{detail}. Partial output may already have been produced"
        )
    elif isinstance(exc, ResourceLimitError):
        # A limit stops the read rather than the decoder failing on it, and a
        # decoder-memory refusal stops it before anything is decoded, so neither
        # "decode failed" nor "partial output" would be true of it.
        new_msg = f"{unconfirmed} The read was stopped by a limit: {detail}"
    else:
        new_msg = (
            f"{unconfirmed} Decode failed: {detail}. "
            f"Partial output may already have been produced"
        )
    escaped = escape_control_chars(new_msg)
    exc.raw_message = new_msg
    exc.message = escaped
    exc.args = (escaped,)
    exc.format_unconfirmed = True


def _emit_unconfirmed_failure(
    exc: ArchiveyError,
    evidence: UnconfirmedEvidence,
    archive_format: ArchiveFormat,
    archive_name: str | None,
    collector: DiagnosticCollector,
) -> None:
    code, evidence_text, _ = _UNCONFIRMED_EVIDENCE[evidence]
    # Under PEDANTIC (RAISE on every code), a bare emit would raise
    # DiagnosticRaisedError mid-raise and destroy the typed TruncatedError/
    # CorruptionError/ResourceLimitError. escalate_as keeps that type when RAISE
    # fires; under COLLECT it stays unset, so the caller re-raises the stamped ``exc``.
    #
    # A reader claims the emit before it happens (``claim_diagnostic``): under RAISE
    # the emit does not return, and a flag set afterwards would never be reached, so
    # every retried read would record the diagnostic again. `diagnostics` splits those
    # concerns ("deduplication is a presentation concern; escalation is not"), and
    # normally a deduplicated code still escalates on later occurrences via
    # `escalate_only`. This code needs no such re-escalation: the caller re-raises the
    # stamped `exc` (same type, same `format_unconfirmed=True`) on every occurrence, so
    # a caller who asked to be stopped is stopped whether or not the diagnostic fires a
    # second time.
    escalate_as: type[BaseException] | None = None
    escalate_message: str | None = None
    escalate_kwargs: dict[str, object] | None = None
    if code in collector.policy.raise_on:
        escalate_as = type(exc)
        escalate_message = exc.raw_message
        escalate_kwargs = {
            "source_format": exc.source_format,
            "archive_name": exc.archive_name,
            "member_name": exc.member_name,
            "link_target": exc.link_target,
            "format_unconfirmed": True,
        }
    reader_format = archive_format.display_name
    collector.emit(
        code=code,
        message=f"Reading {reader_format} failed (a decode failure or a limit), and "
        f"it was identified only by {evidence_text}; the source may not be that "
        f"format",
        context=unconfirmed_context(
            archive_format,
            archive_name,
            evidence,
            # An extension guess is what detection falls back to when it refuses the
            # bytes, so it has no content answer to restate.
            reader_format if evidence == "content_probe" else None,
        ),
        escalate_as=escalate_as,
        escalate_message=escalate_message,
        escalate_kwargs=escalate_kwargs,
    )
