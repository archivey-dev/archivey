"""Which span of the archive a stream archivey made for a plugin reads.

A ``ReaderSource.view()`` knows its span, and a ``ReaderContext.decompress()`` over a
view reads the same one. archivey marks each such stream with a callable that tells
the source it reads that span next (``_will_read``). It calls the mark when the
plugin hands the stream back as a member's data without ``MemberData.ranges``, and
when :class:`~archivey.internal.streams.blocks.BlockStream` gets it as a block. So a
plugin whose data is a view gets the range hint without declaring it.

A hint never changes what a read returns, so a stream that cannot carry the mark (a
type with ``__slots__``, say) just goes without one.
"""

from __future__ import annotations

from collections.abc import Callable

__all__ = ["mark_read_span", "read_span_hint"]

_ATTR = "_archivey_read_span_hint"


def mark_read_span(stream: object, hint: Callable[[], None]) -> None:
    """Mark ``stream`` as reading the span ``hint`` announces."""
    try:
        setattr(stream, _ATTR, hint)
    except (AttributeError, TypeError):
        pass


def read_span_hint(stream: object) -> Callable[[], None] | None:
    """The mark :func:`mark_read_span` left on ``stream``, if any."""
    hint = getattr(stream, _ATTR, None)
    return hint if callable(hint) else None
