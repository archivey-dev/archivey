"""The mark on an exception that the caller's own source raised while a decoder read it.

A shared layer because the codec base (:meth:`StreamCodec.eof_truncation`), the
rapidgzip child, the public stream's error translation and the ``on_source_read``
reporter (which marks what the caller's callback raises) all need it.
"""

from __future__ import annotations

_FROM_SOURCE = "_archivey_raised_by_callers_source"


def from_callers_source(exc: BaseException) -> bool:
    """Whether ``exc`` came from the caller's own source, parked while a decoder read it
    (the rapidgzip child's reads), or raised by a file region's check before a call to
    the child (what reading that source would have raised; see ``file_region``).

    Such an exception is raised to the caller as itself, so a translator must leave it
    alone, including one whose types (``EOFError``) it would map for a decoder.
    """
    return getattr(exc, _FROM_SOURCE, False) is True


def mark_callers_source(exc: BaseException) -> None:
    """Mark ``exc`` as raised by the caller's own source (see :func:`from_callers_source`)."""
    try:
        setattr(exc, _FROM_SOURCE, True)
    except AttributeError:  # an exception type that refuses new attributes
        pass


_FROM_CALLBACK = "_archivey_raised_by_on_source_read"


def from_source_callback(exc: BaseException) -> bool:
    """Whether ``exc`` was raised by ``on_source_read``.

    Such an exception is also marked as the caller's own (:func:`from_callers_source`),
    so the codec translators leave it alone. This second mark is for the boundaries
    above them: the public stream's translation, the reader's, detection's probes and
    extraction's per-member handling raise it as itself. An exception the caller's
    source raised (a closed file) keeps the translation those boundaries give it.
    """
    return getattr(exc, _FROM_CALLBACK, False) is True


def mark_source_callback(exc: BaseException) -> None:
    """Mark ``exc`` as raised by ``on_source_read`` (see :func:`from_source_callback`)."""
    mark_callers_source(exc)
    try:
        setattr(exc, _FROM_CALLBACK, True)
    except AttributeError:  # an exception type that refuses new attributes
        pass
