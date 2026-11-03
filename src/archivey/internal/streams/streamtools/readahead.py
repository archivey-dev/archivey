"""``ReadAheadStream`` — a read buffer that keeps a full-count inner's short-is-terminal rule.

``io.BufferedReader`` is the wrong buffer over a full-count stream that defers its
error. When a fill returns fewer bytes than the caller still wants, it fills again in
the same call. A decoder with deferred truncation returns the recoverable prefix on
one read and raises on the next, so that second fill moves the error into the call
and the prefix is lost.

This buffer reads its inner at most once per caller ``read``, and asks for at least
``buffer_size`` bytes each time. The inner is full-count: a short return is its end,
so the caller gets a short return too, and the error comes on the next call. When the
one fill raises and bytes from an earlier fill are still held, those bytes go to the
caller first and the error is raised on the next ``read``.

With ``fill_arrived``, each fill is the inner's ``read_ahead`` instead, for a codec
stream over a source that cannot seek. It asks for the bytes the caller still wants
and takes what the decoder's last feed gave past them, up to ``buffer_size``. So it
does not wait for bytes nobody asked for yet. Errors are as above.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from typing import BinaryIO, Protocol, cast

from archivey.internal.overrides import override
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    ask_resume_offset,
    check_read_size,
    check_seek_args,
    read_blocking,
)


class _ReadsAhead(Protocol):
    def read_ahead(self, need: int, n: int, /) -> bytes: ...


def _seek_to(stream: BinaryIO, target: int) -> bool:
    """Seek ``stream`` to ``target``. False when it cannot, without raising."""
    try:
        stream.seek(target)
    except (OSError, AttributeError, ValueError, io.UnsupportedOperation):
        return False
    return True


class ReadAheadStream(DelegatingStream):
    """Buffer reads of a full-count ``inner``, reading it at most once per ``read``.

    Owns ``inner``, as every :class:`DelegatingStream` does. Seekable when ``inner``
    is: a seek drops the buffer and any held error, then seeks ``inner``.

    ``rewind_oversize`` is for an inner whose seek is a pointer move. A read larger
    than the buffer then rewinds any prefetched tail and returns that one inner read.
    Joining the tail to a second read would copy the whole request. Leave it off for
    a codec: rewinding it re-decodes. If that read raises, the inner is moved just
    past the tail before the tail is returned, so the next read raises the error
    and does not return the tail again. A restore that fails raises now and
    returns nothing.
    """

    readinto_passthrough = False

    def __init__(
        self,
        inner: BinaryIO,
        buffer_size: int,
        *,
        rewind_oversize: bool = False,
        fill_arrived: bool = False,
    ) -> None:
        # The buffered bytes are ``_buffer[_offset:]``: a read moves the offset and
        # copies only what it returns.
        self._buffer = b""
        self._offset = 0
        self._held: Exception | None = None
        self._buffer_size = buffer_size
        self._rewind_oversize = rewind_oversize
        # The inner's ``read_ahead`` (an ArchiveStream's) when ``fill_arrived``.
        self._read_ahead: Callable[[int, int], bytes] | None = (
            cast("_ReadsAhead", inner).read_ahead if fill_arrived else None
        )
        super().__init__(inner)

    @override
    def read(self, n: int | None = -1, /) -> bytes:
        n = check_read_size(n)
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._held is not None:
            err, self._held = self._held, None
            raise err
        start = self._offset
        buffered = len(self._buffer) - start
        if 0 <= n <= buffered:
            self._offset = start + n
            return self._buffer[start : start + n]
        held = self._buffer[start:]
        self._buffer = b""
        self._offset = 0
        # The tail is shorter than this read. Rewinding it and reading once
        # returns the inner's own buffer; joining the two copies the request.
        if self._rewind_oversize and held and (n < 0 or n > self._buffer_size):
            try:
                self._inner.seek(-len(held), io.SEEK_CUR)
            except (OSError, ValueError, io.UnsupportedOperation):
                pass
            else:
                # The rewind put ``held`` back on the inner. Remember where that
                # starts: a failed read must leave the inner just past those bytes
                # before they are returned, or the next read delivers them again.
                try:
                    mark = self._inner.tell()
                except (OSError, AttributeError, ValueError, io.UnsupportedOperation):
                    mark = None
                try:
                    return read_blocking(self._inner, n)
                except Exception as err:
                    if mark is not None and _seek_to(self._inner, mark + len(held)):
                        self._held = err
                        return held
                    raise
        want = -1 if n < 0 else max(n - buffered, self._buffer_size)
        try:
            if self._read_ahead is not None and n > buffered:
                data = self._read_ahead(n - buffered, want)
            else:
                data = read_blocking(self._inner, want)
        except Exception as err:
            if not held:
                raise
            self._held = err
            return held
        if n < 0 or len(data) <= n - buffered:
            return held + data
        take = n - buffered
        self._buffer = data
        self._offset = take
        return held + data[:take]

    def read_arrived(self, n: int, /) -> bytes:
        """Between 1 and ``n`` bytes, or ``b""`` only at the end: the buffered bytes
        when there are any, else one fill. With ``fill_arrived`` that fill is what the
        decoder's next feed gives, so a consumer that reads until ``b""`` (a decoder
        fed from this buffer) never waits for bytes a held-open pipe has not sent."""
        if n <= 0:
            raise ValueError("n must be positive")
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        buffered = len(self._buffer) - self._offset
        if buffered or self._held is not None or self._read_ahead is None:
            return self.read(min(n, buffered) if buffered else n)
        return self._read_ahead(1, n)

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        offset, whence = check_seek_args(offset, whence)
        if self._buffer and whence != io.SEEK_END:
            # A target inside the buffer moves the offset and leaves the inner where
            # it is: a forward-only inner would otherwise seek back to re-read it.
            end = self._inner.tell()
            begin = end - len(self._buffer)
            target = offset if whence == io.SEEK_SET else begin + self._offset + offset
            if begin <= target <= end:
                self._offset = target - begin
                return target
        if whence == io.SEEK_CUR:
            # The inner is ahead of the caller by the bytes still in the buffer.
            offset -= len(self._buffer) - self._offset
        position = self._inner.seek(offset, whence)
        self._buffer = b""
        self._offset = 0
        self._held = None
        return position

    @override
    def tell(self, /) -> int:
        return self._inner.tell() - (len(self._buffer) - self._offset)

    def nearest_resume_offset(self, target: int) -> int | None:
        # The buffer keeps the inner's offsets.
        return ask_resume_offset(self._inner, target)
