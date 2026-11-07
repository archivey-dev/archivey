"""The child process: reads one archive with libarchive, as the parent asks.

Standard library only, so the child never imports archivey. Run as
``python -m archivey_libarchive._worker``; it talks over its stdin and stdout.
"""

from __future__ import annotations

import sys
from typing import IO

from archivey_libarchive import _protocol as proto
from archivey_libarchive._libarchive import LibarchiveError, Session


def _error(out: IO[bytes], exc: LibarchiveError) -> None:
    proto.send(
        out,
        b"X",
        proto.pack_json({"code": exc.code, "errno": exc.errno, "message": exc.message}),
    )


def serve(inp: IO[bytes], out: IO[bytes]) -> None:
    def read_input(n: int) -> bytes:
        proto.send(out, b"N", proto.pack_size(n))
        tag, payload = proto.receive(inp)
        if tag != b"I":
            raise proto.ProtocolError(f"expected input, got {tag!r}")
        return payload

    tag, payload = proto.receive(inp)
    if tag != b"O":
        raise proto.ProtocolError(f"expected open, got {tag!r}")
    request = proto.unpack_json(payload)
    charset = request.get("hdrcharset")
    try:
        session = Session(
            str(request.get("format")),
            read_input,
            charset if isinstance(charset, str) else None,
        )
    except LibarchiveError as exc:
        _error(out, exc)
        return
    proto.send(out, b"K")
    try:
        while True:
            tag, payload = proto.receive(inp)
            try:
                if tag == b"H":
                    header = session.next_header()
                    if header is None:
                        proto.send(out, b"E")
                    else:
                        proto.send(out, b"H", proto.pack_json(header))
                elif tag == b"R":
                    n = min(proto.unpack_size(payload), 1 << 20)
                    proto.send(out, b"D", session.read(n))
                elif tag == b"S":
                    session.skip()
                    proto.send(out, b"K")
                elif tag == b"Q":
                    return
                else:
                    raise proto.ProtocolError(f"unknown request {tag!r}")
            except LibarchiveError as exc:
                _error(out, exc)
    finally:
        session.close()


def main() -> None:
    try:
        serve(sys.stdin.buffer, sys.stdout.buffer)
    except proto.ProtocolError:
        # The parent went away or broke the protocol: nothing to report to.
        sys.exit(2)


if __name__ == "__main__":
    main()
