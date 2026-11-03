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
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


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
    def unconfirmed_evidence(self) -> Literal["extension", "content_probe"] | None:
        """What a decode failure's ``format_unconfirmed`` stamp rests on, if anything.

        The two cases cannot overlap: ``core`` sets ``probe_only`` only for a content-probe
        detection and ``chosen_by="extension"`` only for an extension one.
        """
        if self.probe_only:
            return "content_probe"
        return "extension" if self.chosen_by == "extension" else None
