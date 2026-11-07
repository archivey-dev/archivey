"""archivey's side of a libarchive read: in a child process, or in this one.

Both kinds of session have the methods of :class:`~archivey_libarchive._libarchive.Session`
and raise its :class:`~archivey_libarchive._libarchive.LibarchiveError`. A child that
dies raises :class:`ChildDied`; one that cannot start raises :class:`ChildUnavailable`.
"""

from __future__ import annotations

import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from archivey_libarchive import _protocol as proto
from archivey_libarchive._libarchive import ARCHIVE_FATAL, LibarchiveError, Session

_PACKAGE_ROOT = str(Path(__file__).resolve().parent.parent)
_BOOT = (
    "import sys; sys.path.insert(0, {root!r}); "
    "from archivey_libarchive._worker import main; main()"
)


class ChildUnavailable(Exception):
    """No child process could be started here."""


class ChildDied(Exception):
    """The child process ended while reading: ``killed`` when SIGKILL ended it (most
    often the out-of-memory killer), otherwise it crashed or broke the protocol."""

    def __init__(self, message: str, *, killed: bool) -> None:
        super().__init__(message)
        self.killed = killed


class AnySession(Protocol):
    def next_header(self) -> dict[str, object] | None: ...
    def read(self, n: int) -> bytes: ...
    def skip(self) -> None: ...
    def close(self) -> None: ...


def in_process_session(
    fmt: str, read_input: Callable[[int], bytes], hdrcharset: str | None = None
) -> AnySession:
    return Session(fmt, read_input, hdrcharset)


class ChildSession:
    """A :class:`Session` in a child process of its own, fed by ``read_input``."""

    def __init__(
        self,
        fmt: str,
        read_input: Callable[[int], bytes],
        hdrcharset: str | None = None,
    ) -> None:
        self._read_input = read_input
        try:
            self._proc = subprocess.Popen(
                [sys.executable, "-I", "-c", _BOOT.format(root=_PACKAGE_ROOT)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, ValueError) as exc:
            raise ChildUnavailable(
                f"cannot start a libarchive process: {exc}"
            ) from None
        self._closed = False
        try:
            self._call(
                b"O", proto.pack_json({"format": fmt, "hdrcharset": hdrcharset}), b"K"
            )
        except BaseException:
            self.close()
            raise

    def _died(self, detail: str) -> ChildDied:
        self.close()
        code = self._proc.returncode
        if code is not None and code < 0:
            sig = -code
            name = signal.Signals(sig).name if sig in signal.valid_signals() else sig
            return ChildDied(
                f"the libarchive process was ended by {name}",
                killed=sig == signal.SIGKILL,
            )
        return ChildDied(
            f"the libarchive process stopped ({detail}, exit status {code})",
            killed=False,
        )

    def _call(self, tag: bytes, payload: bytes, *expect: bytes) -> tuple[bytes, bytes]:
        """Send one request, feed the child the input it asks for, and return its
        answer, whose tag must be one of ``expect``."""
        self._send(tag, payload)
        while True:
            got, body = self._receive()
            if got != b"N":
                break
            # The source's own errors (a damaged compressed layer, a cut pipe) pass
            # through as they are.
            size = self._size(body)
            # The child asks for Session.CHUNK at a time; a larger request is a child
            # that is not running our code, and would have this side buffer it.
            if size > Session.CHUNK:
                raise self._died(f"asked for {size} bytes of input at once")
            self._send(b"I", self._read_input(size))
        if got == b"X":
            try:
                error = proto.unpack_json(body)
            except (proto.ProtocolError, ValueError) as exc:
                raise self._died(f"bad error report: {exc}") from None
            code, errno = error.get("code"), error.get("errno")
            raise LibarchiveError(
                code if isinstance(code, int) else ARCHIVE_FATAL,
                errno if isinstance(errno, int) else 0,
                str(error.get("message", "libarchive error")),
            )
        if got not in expect:
            raise self._died(f"unexpected reply {got!r}")
        return got, body

    def _send(self, tag: bytes, payload: bytes) -> None:
        assert self._proc.stdin is not None
        try:
            proto.send(self._proc.stdin, tag, payload)
        except (OSError, ValueError) as exc:
            # ValueError: a write to a pipe this side already closed.
            raise self._died(str(exc)) from None

    def _receive(self) -> tuple[bytes, bytes]:
        assert self._proc.stdout is not None
        try:
            return proto.receive(self._proc.stdout)
        except (OSError, ValueError, proto.ProtocolError) as exc:
            raise self._died(str(exc)) from None

    def _size(self, body: bytes) -> int:
        try:
            return proto.unpack_size(body)
        except proto.ProtocolError as exc:
            raise self._died(str(exc)) from None

    def next_header(self) -> dict[str, object] | None:
        got, body = self._call(b"H", b"", b"H", b"E")
        if got == b"E":
            return None
        try:
            return proto.unpack_json(body)
        except (proto.ProtocolError, ValueError) as exc:
            raise self._died(f"bad header: {exc}") from None

    def read(self, n: int) -> bytes:
        _, body = self._call(b"R", proto.pack_size(n), b"D")
        if len(body) > n:
            raise self._died("more data than asked for")
        return body

    def skip(self) -> None:
        self._call(b"S", b"", b"K")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        try:
            if proc.poll() is None and proc.stdin is not None:
                proto.send(proc.stdin, b"Q")
        except (OSError, ValueError):
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def child_session(
    fmt: str, read_input: Callable[[int], bytes], hdrcharset: str | None = None
) -> AnySession:
    return ChildSession(fmt, read_input, hdrcharset)
