"""One HTTP range request, read only as far as it needs, with its answer checked.

:class:`~archivey.internal.remote.RangeSource` reads an object over fsspec's HTTP file
system through :func:`bounded_http_cat` instead of ``fs.cat_file``. This module is the
single-request boundary: it builds the request, reads the answer and checks that the
answer holds the bytes asked for. Everything that spans requests stays in
:mod:`archivey.internal.remote`: the request budget, continuing after a short answer,
asking again after an ignored range, detecting a changed object, and the I/O counters.

fsspec and aiohttp are never imported here at import time. :func:`bounded_http_cat`
answers ``None`` unless fsspec's HTTP module is already loaded, so a core-only install
imports this module without them.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, cast

from archivey.internal.remote import display_url

# ``bytes a-b/n`` or ``bytes a-b/*``, ASCII digits only: ``str.isdigit`` also takes
# digits ``int`` refuses (a superscript two).
_CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+|\*)", re.ASCII | re.IGNORECASE)


@dataclass(frozen=True)
class HttpAnswer:
    """What one range request over HTTP gave (:func:`bounded_http_cat`)."""

    data: bytes
    kind: Literal["range", "whole", "ignored"]
    """``"range"``: a ``206`` holding ``data`` from the requested start;
    ``"whole"``: the object from byte 0, cut at the requested end; ``"ignored"``: the
    range was ignored for a request past byte 0, and nothing was read."""
    total: int | None = None
    """The object's size a ``206`` named, when it named one."""


RangeRequest = Callable[[str, int, int], HttpAnswer]
"""One request for bytes ``[start, end)`` of the object at a URL."""


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

    async def cat(url: str, start: int, end: int) -> HttpAnswer:
        kw = dict(fs.kwargs)
        headers = dict(kw.pop("headers", None) or {})
        headers["Range"] = f"bytes={start}-{end - 1}"
        headers["Accept-Encoding"] = "identity"
        kw["headers"] = headers
        session = await fs.set_session()
        kw["auto_decompress"] = False
        async with session.get(fs.encode_url(url), **kw) as r:
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
                data = await read_at_most(r, length + 1)
                if len(data) != length:
                    raise OSError(
                        f"{display_url(url)}: the server declared {length} bytes "
                        f"from {start} in Content-Range and sent "
                        f"{'more' if len(data) > length else len(data)}"
                    )
                return HttpAnswer(data, "range", total)
            # The range was ignored: the body is the whole object from byte 0.
            if start > 0:
                return HttpAnswer(b"", "ignored")
            return HttpAnswer(await read_at_most(r, end), "whole")

    async def read_at_most(r: Any, limit: int) -> bytes:
        out = bytearray()
        while len(out) < limit:
            chunk = await r.content.read(min(1 << 20, limit - len(out)))
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def run(url: str, start: int, end: int) -> HttpAnswer:
        return cast(HttpAnswer, sync(fs.loop, cat, url, start, end))

    return run
