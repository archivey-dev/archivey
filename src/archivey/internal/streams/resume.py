"""Seek-point plumbing shared by the decompressing streams.

``ask_resume_offset`` is the rewind-cost query used by
``ArchiveStreamImpl._maybe_warn_rewind``. This is an archivey concept — seek-point tables
on decompressing streams. Implementations:

- own a table — ``DecompressorStream``, ``RapidgzipChildStream`` (the child's index)
- preserve that offset space — ``ArchiveStream``, ``OutputCountingStream``,
  ``VerifyingStream``, ``_GzipTruncationCheckStream``
- translate the offset space — ``AesDecryptStream`` (ciphertext to plaintext),
  ``SlicingStream`` (contiguous window; ``SharedView`` inherits it)

``DelegatingStream`` does not grow it.

The duck-typing helper itself is generic ``getattr`` plumbing, so it lives in
:mod:`archivey.internal.streams.streamtools.binaryio` and this module
re-exports it as the archivey-facing name.

:class:`ResumeReachedStreamEnd` is the signal both mid-stream resume decoders
(``deflate_resume`` and ``bzip2_resume``) raise when they cannot give a verdict.
"""

from __future__ import annotations

from contextvars import ContextVar

from archivey.internal.streams.streamtools.binaryio import ask_resume_offset

__all__ = [
    "ResumeReachedStreamEnd",
    "ask_resume_offset",
    "ask_seek_resume_offset",
    "hold_for_planned_seek",
    "planning_seek",
]

# Inside ``ask_seek_resume_offset``: the reports held for the planning caller.
_PLANNING_SEEK: ContextVar[list[Exception] | None] = ContextVar(
    "archivey_planning_seek", default=None
)


def ask_seek_resume_offset(
    inner: object | None, target: int
) -> tuple[int | None, Exception | None]:
    """``ask_resume_offset`` for a caller about to seek ``inner`` to ``target``.

    The plain query reads each seek-point table as it stands, so a diagnostic never
    changes the cost it reports. A caller planning a seek wants the answer the seek
    itself would act on: a ``DecompressorStream`` builds its index on a forward seek
    (an lzip or xz trailer read) and may then jump. While this call runs, such a
    stream builds that index first (:func:`planning_seek`). The flag rides a context
    variable, so the wrappers that forward the query need no change.

    Returns the resume point and the first report that index build escalated, if
    any. The report belongs to the seek being planned, so the caller raises it once
    that seek has moved, as the stream's own seek would have (or drops it with the
    plan). Nothing is left on the stream for an unrelated later call to raise.
    """
    held: list[Exception] = []
    token = _PLANNING_SEEK.set(held)
    try:
        resume = ask_resume_offset(inner, target)
    finally:
        _PLANNING_SEEK.reset(token)
    return resume, held[0] if held else None


def planning_seek() -> bool:
    """True inside :func:`ask_seek_resume_offset`: answer for the seek about to run."""
    return _PLANNING_SEEK.get() is not None


def hold_for_planned_seek(report: Exception) -> None:
    """Hand a report escalated while planning a seek to the planning caller.

    Only valid inside :func:`ask_seek_resume_offset` (:func:`planning_seek` is true).
    The first report is kept; a block raises once.
    """
    held = _PLANNING_SEEK.get()
    assert held is not None, "hold_for_planned_seek outside a planned seek"
    if not held:
        held.append(report)


class ResumeReachedStreamEnd(Exception):
    """A decode resumed mid-stream reached the end of its stream. The stream's checksum
    covers output from before the resume point, which this decode cannot check, so the
    caller decodes again from the start.

    Raised by ``DeflateResumeDecoder`` (the gzip CRC-32 or zlib Adler-32) and by
    ``Bzip2ResumeDecoder`` (the combined CRC, whose failure ``bz2`` reports the same
    way as a damaged block, so that decoder raises this on either).

    It is control flow, not an error a caller may see: it is not an ``ArchiveyError``.
    Only ``_StdlibOnAcceleratorError`` in ``codecs/stdlib_takeover.py`` adds resume points to a
    decoder, and every call of its that can decode (``read`` and ``seek``; ``readinto``
    and ``readall`` go through ``read``) catches it. A new caller of either decoder
    must catch it the same way.
    """
