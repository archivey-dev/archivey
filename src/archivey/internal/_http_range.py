"""One HTTP range request, read only as far as it needs, with its answer checked.

:class:`~archivey.internal.remote.RangeSource` reads an object over fsspec's HTTP file
system through :func:`bounded_http_cat` instead of ``fs.cat_file``, when the installed
fsspec has the members the adapter uses (else ``cat_file``, unbounded). This module is
the single-request boundary: it builds the request, reads the answer and checks that the
answer holds the bytes asked for. Everything that spans requests stays in
:mod:`archivey.internal.remote`: the request budget, continuing after a short answer,
asking again after an ignored range, detecting a changed object, and the I/O counters.

A request runs on fsspec's event loop thread. Without a progress hook it is one
``sync()`` call; with one (``on_received``) the answer's body is read one ``sync()`` per
chunk of up to :data:`CHUNK` bytes, so the hook runs between chunks on the thread that
sent the request. When that is a caller's thread, the hook calls ``on_source_read``
there; on a thread archivey started (the RAR volume feeder) the reporter keeps the
latest report for the caller's next read, as for the request's other reports.

fsspec and aiohttp are never imported here at import time. :func:`bounded_http_cat`
answers ``None`` unless fsspec's HTTP module is already loaded, so a core-only install
imports this module without them.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from archivey.internal.remote import display_url

# ``bytes a-b/n`` or ``bytes a-b/*``, ASCII digits only: ``str.isdigit`` also takes
# digits ``int`` refuses (a superscript two). At most 20 digits, more than any object
# needs: ``int`` refuses a string of over 4300 digits with a bare ``ValueError``, and a
# header can be longer, so a longer number fails the match instead.
_CONTENT_RANGE = re.compile(
    r"bytes (\d{1,20})-(\d{1,20})/(\d{1,20}|\*)", re.ASCII | re.IGNORECASE
)

# ``bytes */n``, a ``416``'s Content-Range: the object is ``n`` bytes long.
_UNSATISFIED_RANGE = re.compile(r"bytes \*/(\d{1,20})", re.ASCII | re.IGNORECASE)


@dataclass(frozen=True)
class HttpAnswer:
    """What one range request over HTTP gave (:func:`bounded_http_cat`)."""

    data: bytes
    kind: Literal["range", "whole", "ignored", "unsatisfiable"]
    """``"range"``: a ``206`` holding ``data`` from the requested start;
    ``"whole"``: the object from byte 0, cut at the requested end; ``"ignored"``: the
    range was ignored for a request past byte 0, and nothing was read;
    ``"unsatisfiable"``: a ``416``, the range starts past the object's end, and nothing
    was read."""
    total: int | None = None
    """The object's size the answer named, when it named one: a ``206`` or ``416`` in
    ``Content-Range``, a ``200`` in ``Content-Length``."""


# The most one read of an answer's body asks for.
CHUNK = 1 << 20


class RangeRequest(Protocol):
    """One request for bytes ``[start, end)`` of the object at a URL.

    ``on_received``, when given, is called on the caller's thread with the bytes of
    the body received so far, after each chunk of the body. What it raises ends the
    request (the answer is closed) and propagates.
    """

    def __call__(
        self,
        url: str,
        start: int,
        end: int,
        *,
        on_received: Callable[[int], None] | None = None,
    ) -> HttpAnswer: ...


@dataclass(frozen=True)
class _Body:
    """An answer whose status and headers were checked and whose body is next."""

    response: Any
    context: Any
    kind: Literal["range", "whole"]
    limit: int
    """The most bytes of the body to read: the declared length plus one for a
    ``206`` (one more shows a body longer than declared), the requested end for a
    whole object."""
    length: int | None
    """A ``206``'s declared length, which the body must match."""
    total: int | None

    @property
    def complete(self) -> int:
        """The size of a complete body: a ``206``'s declared length, else ``limit``."""
        return self.length if self.length is not None else self.limit

    def next_read(self, received: int) -> int:
        """How many bytes to ask for next, after ``received``: at most one chunk, and
        never past ``limit``. 0 once ``limit`` is reached."""
        return min(CHUNK, self.limit - received)

    def answer(self, url: str, start: int, data: bytes) -> HttpAnswer:
        if self.length is not None and len(data) != self.length:
            raise OSError(
                f"{display_url(url)}: the server declared {self.length} bytes "
                f"from {start} in Content-Range and sent "
                f"{'more' if len(data) > self.length else len(data)}"
            )
        return HttpAnswer(data, self.kind, self.total)


def content_range(
    url: str, header: str | None, start: int, end: int
) -> tuple[int, int | None]:
    """The span ``(length, total)`` a ``206`` answer to a request for ``[start, end)``
    declares. Refused with ``OSError`` when ``Content-Range`` is missing, malformed,
    or does not start at ``start`` and end inside the range, so its bytes are never
    served at the wrong offset."""
    match = None if header is None else _CONTENT_RANGE.fullmatch(header.strip())
    if match is not None:
        first, last = int(match[1]), int(match[2])
        if first == start and first <= last < end:
            return last - first + 1, None if match[3] == "*" else int(match[3])
    raise OSError(
        f"{display_url(url)}: the server answered a request for bytes "
        f"{start}-{end} with Content-Range {header!r}, which does not match it: "
        f"its bytes cannot be placed in the file"
    )


def bounded_http_cat(fs: Any) -> RangeRequest | None:
    """For fsspec's HTTP file system, one range request whose answer is read only as
    far as needed; ``None`` for every other file system.

    fsspec's own ``cat_file`` reads the whole response body into memory before it
    returns, so a server that answers a 64 KiB range request with a 1.5 GB ``200``
    costs 1.5 GB. This one never reads past what the request asked for, plus one
    byte that shows a body longer than declared. It is built from the HTTP file
    system's session and its request options, as its ``cat_file`` is, and ``None``
    when the installed fsspec lacks one of them: ``cat_file`` is used then.

    How the answer says what it holds (RFC 9110, sections 15.3.1 and 15.3.7):
    ``206`` with ``Content-Range: bytes a-b/n`` holds bytes ``a`` to ``b`` of an
    object of ``n`` bytes; it must start at the requested start and its body must
    be exactly that long (:func:`content_range`). Any other success status holds
    the whole object from byte 0. The request asks for the bytes as stored
    (``Accept-Encoding: identity``), as fsspec does when it reads the size, so the
    offsets are the stored object's; an answer in another encoding is refused.
    """
    http = sys.modules.get("fsspec.implementations.http")
    if http is None or not isinstance(fs, getattr(http, "HTTPFileSystem", ())):
        return None
    if not all(
        hasattr(fs, name) for name in ("kwargs", "loop", "set_session", "encode_url")
    ) or not callable(getattr(fs, "_raise_not_found_for_status", None)):
        return None
    from fsspec.asyn import sync

    async def begin(url: str, start: int, end: int) -> HttpAnswer | _Body:
        """Send the request and check its status and headers: an answer that holds
        no bytes, or the body to read."""
        kw = dict(fs.kwargs)
        headers = dict(kw.pop("headers", None) or {})
        headers["Range"] = f"bytes={start}-{end - 1}"
        headers["Accept-Encoding"] = "identity"
        kw["headers"] = headers
        session = await fs.set_session()
        kw["auto_decompress"] = False
        context = session.get(fs.encode_url(url), **kw)
        r = await context.__aenter__()
        try:
            body = _check(r, url, start, end, context)
        except BaseException:
            await context.__aexit__(*sys.exc_info())
            raise
        if isinstance(body, HttpAnswer):
            await context.__aexit__(None, None, None)
        return body

    def _check(
        r: Any, url: str, start: int, end: int, context: Any
    ) -> HttpAnswer | _Body:
        if r.status == 416:
            # The range starts past the object's end. Every request lies inside
            # the size read at open, so the object is shorter now.
            match = _UNSATISFIED_RANGE.fullmatch(
                r.headers.get("Content-Range", "").strip()
            )
            return HttpAnswer(
                b"", "unsatisfiable", None if match is None else int(match[1])
            )
        fs._raise_not_found_for_status(r, url)
        encoding = r.headers.get("Content-Encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise OSError(
                f"{display_url(url)}: the server answered a request for bytes "
                f"{start}-{end} in Content-Encoding {encoding!r}, though the "
                f"request asked for the bytes as stored"
            )
        if r.status == 206:
            length, total = content_range(
                url, r.headers.get("Content-Range"), start, end
            )
            return _Body(r, context, "range", length + 1, length, total)
        # The range was ignored: the body is the whole object from byte 0.
        if start > 0:
            return HttpAnswer(b"", "ignored")
        return _Body(r, context, "whole", end, None, r.content_length)

    async def read_chunk(body: _Body, n: int) -> bytes:
        """Up to ``n`` bytes of the body: fewer only at its end. aiohttp hands over
        what has arrived (often 64 KiB), so this gathers several of its reads."""
        out = bytearray()
        while len(out) < n:
            part = await body.response.content.read(n - len(out))
            if not part:
                break
            out += part
        return bytes(out)

    async def finish(body: _Body, exc: BaseException | None) -> None:
        if exc is None:
            await body.context.__aexit__(None, None, None)
        else:
            await body.context.__aexit__(type(exc), exc, exc.__traceback__)

    async def cat(url: str, start: int, end: int) -> HttpAnswer:
        """The whole request in one call on the event loop."""
        body = await begin(url, start, end)
        if isinstance(body, HttpAnswer):
            return body
        out = bytearray()
        try:
            while n := body.next_read(len(out)):
                chunk = await read_chunk(body, n)
                if not chunk:
                    break
                out += chunk
        except BaseException as exc:
            await finish(body, exc)
            raise
        await finish(body, None)
        return body.answer(url, start, bytes(out))

    def run(
        url: str,
        start: int,
        end: int,
        *,
        on_received: Callable[[int], None] | None = None,
    ) -> HttpAnswer:
        if on_received is None:
            return cast(HttpAnswer, sync(fs.loop, cat, url, start, end))
        body = cast("HttpAnswer | _Body", sync(fs.loop, begin, url, start, end))
        if isinstance(body, HttpAnswer):
            return body
        out = bytearray()
        try:
            while n := body.next_read(len(out)):
                chunk = cast(bytes, sync(fs.loop, read_chunk, body, n))
                if not chunk:
                    break
                out += chunk
                if len(chunk) == n and len(out) < body.complete:
                    # On the thread that sent the request, between two reads of the
                    # body. Not once the body is complete, nor after a short chunk,
                    # which is its end: the request's end report or its error
                    # follows.
                    on_received(len(out))
        except BaseException as exc:
            sync(fs.loop, finish, body, exc)
            raise
        sync(fs.loop, finish, body, None)
        return body.answer(url, start, bytes(out))

    return run
