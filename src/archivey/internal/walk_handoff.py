"""A random-access member's data area that raises at a cut: :class:`MemberDataView`.

TAR's own ``open()`` reads a member through it, and so does a random-access pass that
finds the walk already past the member it opens (TAR's and the sequential adapter's
``_open_member_in_walk``).
"""

from __future__ import annotations

from archivey.exceptions import TruncatedError
from archivey.internal.overrides import override
from archivey.internal.streams.streamtools import (
    DelegatingStream,
    SharedView,
    check_read_size,
)
from archivey.internal.streams.streamtools.binaryio import (
    ask_resume_offset,
    read_blocking,
)


class MemberDataView(DelegatingStream):
    """A random-access member's data area that raises at a cut, not a clean end.

    TAR's own opens use it, and so does a pass's view once the walk has moved on
    (TAR's and the sequential adapter's ``_open_member_in_walk``).

    The view under it returns ``b""`` where the archive ends, which reads as the end of
    the member. Here a read that ends before ``length`` keeps the full-count rule (ADR
    0014): a sized read returns the bytes before the cut and the next read raises, and a
    read with no size raises and returns nothing. The source size is not needed.
    ``what`` names the archive in the error ("TAR archive").
    """

    readinto_passthrough = False

    def __init__(
        self, view: SharedView, data_offset: int, length: int, *, what: str
    ) -> None:
        super().__init__(view)
        self._data_offset = data_offset
        self._length = length
        self._what = what

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        n = check_read_size(n)
        position = self._inner.tell()
        whole = n < 0
        want = self._length - position if whole else min(n, self._length - position)
        if want <= 0:
            return b""
        data = read_blocking(self._inner, want)
        while whole and data and len(data) < want:
            # A read with no size asks again after a short read, so that an error the
            # view's stream holds for its next read (a codec's verdict on the bytes
            # after those it handed back) comes out as itself. Only an empty read is
            # the cut.
            more = read_blocking(self._inner, want - len(data))
            if not more:
                break
            data += more
        if len(data) < want and (whole or not data):
            raise TruncatedError(
                f"{self._what} is truncated inside a member's data at offset "
                f"{self._data_offset + position + len(data)}"
            )
        return data

    def nearest_resume_offset(self, target: int) -> int | None:
        # The member's offsets are the view's.
        return ask_resume_offset(self._inner, target)
