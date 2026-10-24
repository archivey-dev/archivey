"""A native decoder in a child process: the parent's side of ``decoder_worker.py``.

:class:`DecoderChild` is one decoder object living in a child process. It forwards
each call to the child unchanged and keeps the state the child reported with its last
reply, so the codec that uses it cannot tell it from the native object, except that a
native crash costs the member and not the caller. The proxies in
``codecs/isolated.py`` give it each library's surface.

Children come from a small pool. A decoder takes a child of its own when it is built,
so a crash is charged to exactly the decoder whose request was in flight, and threads
decode in parallel. It gives the child back when it is closed or collected: the child
waits for the next decoder, which skips the 12 to 18 ms a start costs, unless the
decoder reported an error, died or was interrupted, or the codec is one whose known
fault is a corruption that need not crash at once (PPMd); that child is ended. Idle
children are ended at interpreter exit, and a forked process forgets its parent's.
"""

from __future__ import annotations

import atexit
import marshal
import os
import subprocess
import threading
import weakref
import zlib
from pathlib import Path
from typing import Any

from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    ReadError,
    ResourceUnavailableError,
)
from archivey.internal.streams.child_process import (
    describe_exit,
    is_crash,
    mark_no_verdict,
    outside_death_error,
    python_argv,
    reap,
    spawn,
    unavailable_reason,
)
from archivey.internal.streams.codecs.decoder_worker import (
    CALL,
    CLOSE,
    FRAME,
    GET,
    OK,
    OPEN,
    parse_error_payload,
    read_exact_or_none,
)

WORKER = Path(__file__).with_name("decoder_worker.py")

# The most idle children the pool keeps. Members are mostly read one after another, so
# one or two are reused in turn; more than this serve only many threads at once.
MAX_IDLE = 4
# Decoders one child serves before it is ended. A fault that corrupts a child's memory
# without crashing it at once can surface on a later decoder; a bound on how many it
# serves bounds how long such a state can live.
MAX_DECODERS_PER_CHILD = 64
# Input a decoder in a reused child records so that it can re-run in a fresh child (see
# ``DecoderChild``). Past it, the decoder moves to a fresh child at once.
REPLAY_LIMIT = 1 << 20


class DecoderChildStartError(RuntimeError):
    """No working decoder child process could be started.

    The spawn failed (a sandbox that refuses ``fork``/``exec``, a process cap, a
    ``sys.executable`` that is not Python), the child died before its first reply, or it
    could not import the codec's library. The caller turns it into the error its
    setting calls for.
    """


class DecoderChildReportedError(RuntimeError):
    """The child reported an exception of a type the parent does not rebuild.

    No translator maps it, so it propagates: an unknown exception is a bug or an
    environment fault to map on purpose, not a verdict on the data.
    """


def start_error(reason: str) -> DecoderChildStartError:
    return DecoderChildStartError(f"cannot start the decoder process: {reason}")


def decoder_child_unavailable_reason(decoder: str) -> str | None:
    """Why no decoder child process can run, or ``None`` when one can (see
    :func:`~archivey.internal.streams.child_process.unavailable_reason`)."""
    return unavailable_reason(WORKER, decoder)


class _Process:
    """One worker process and its pipes. Not thread-safe: one decoder uses it at a
    time, and the pool hands it over under its lock."""

    def __init__(self) -> None:
        self.proc = spawn(
            python_argv(WORKER, start_error),
            start_error,
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        # Whether a reply has ever come back: a death before that is a start failure.
        self.answered = False
        self.pid = os.getpid()
        # Decoders this child finished and was given back from.
        self.served = 0

    def owned(self) -> bool:
        """Whether this process started the child: a process created by ``fork``
        inherits the pipes, and must not write to them or reap the child."""
        return self.pid == os.getpid()

    def alive(self) -> bool:
        return self.owned() and self.proc.poll() is None

    def send(self, tag: int, arg: int, *parts: bytes) -> None:
        stdin = self.proc.stdin
        assert stdin is not None
        stdin.write(FRAME.pack(tag, arg, sum(len(part) for part in parts)))
        for part in parts:
            if part:
                stdin.write(part)
        stdin.flush()

    def receive(self) -> tuple[int, int, bytes, bytes]:
        """``(tag, argument, state bytes, output)`` of one reply. ``None`` halves are
        never returned: a pipe that ends raises ``EOFError``."""
        stdout = self.proc.stdout
        assert stdout is not None
        header = read_exact_or_none(stdout, FRAME.size)
        if header is None:
            raise EOFError
        tag, arg, size = FRAME.unpack(header)
        if tag == OK:
            state = read_exact_or_none(stdout, arg) if arg else b""
            output = read_exact_or_none(stdout, size - arg) if size > arg else b""
        else:
            state, output = b"", read_exact_or_none(stdout, size) if size else b""
        if state is None or output is None:
            raise EOFError
        self.answered = True
        return tag, arg, state, output

    def end(self, *, kill: bool = False) -> None:
        if self.owned():
            reap(self.proc, kill=kill)


class _Pool:
    """Idle worker processes, shared by every thread."""

    def __init__(self) -> None:
        # Reentrant: a decoder collected by the garbage collector gives its child back
        # from a finalizer, which can run inside any allocation, this lock's sections
        # included.
        self._lock = threading.RLock()
        self._idle: list[_Process] = []

    def take(self, *, fresh: bool = False) -> _Process:
        """An idle child, or a new one; always a new one when ``fresh``."""
        if fresh:
            return _Process()
        while True:
            with self._lock:
                process = self._idle.pop() if self._idle else None
            if process is None:
                return _Process()
            if process.alive():
                return process
            process.end()

    def give_back(self, process: _Process) -> None:
        if not process.owned():
            return  # the parent's child, inherited through ``fork``: leave it alone
        process.served += 1
        if process.served >= MAX_DECODERS_PER_CHILD:
            process.end()
            return
        try:
            process.send(CLOSE, 0)
        except (OSError, ValueError):
            process.end()
            return
        except BaseException:
            # Interrupted part-way through the frame: no lease holds the child any
            # more, so it is ended here or never.
            process.end()
            raise
        with self._lock:
            if process.alive() and len(self._idle) < MAX_IDLE:
                self._idle.append(process)
                return
        process.end()

    def close_idle(self) -> None:
        """End every idle child. The pool stays usable."""
        with self._lock:
            idle, self._idle = self._idle, []
        for process in idle:
            process.end()

    def forget(self) -> None:
        """Drop the idle children without ending them: called in a forked child,
        whose copies of the pipes belong to its parent."""
        self._idle = []
        self._lock = threading.RLock()

    def idle_count(self) -> int:
        with self._lock:
            return len(self._idle)


POOL = _Pool()
atexit.register(POOL.close_idle)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=POOL.forget)


class _Lease:
    """A decoder's hold on its child, given back by :meth:`release` exactly once."""

    def __init__(self, process: _Process, reuse: bool) -> None:
        self.process: _Process | None = process
        self.reusable = reuse

    def release(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        if self.reusable:
            POOL.give_back(process)
        else:
            process.end()


def _release(holder: list[_Lease]) -> None:
    holder[0].release()


class _Died(Exception):
    """The child went away during a request (internal to :class:`DecoderChild`)."""

    def __init__(self, process: _Process) -> None:
        super().__init__()
        self.answered = process.answered
        process.end()
        self.returncode = process.proc.returncode


# The exception types a child may report that are rebuilt as themselves, keyed by
# (module, qualified name) as ``decoder_worker.error_payload`` sends them.
_BUILTIN_ERRORS: dict[tuple[str, str], type[Exception]] = {
    ("builtins", cls.__qualname__): cls
    for cls in (
        ValueError,
        EOFError,
        MemoryError,
        OverflowError,
        OSError,
        RuntimeError,
        TypeError,
        SystemError,
        IndexError,
        KeyError,
        NotImplementedError,
    )
}


def rebuild_error(
    payload: bytes,
    known: dict[tuple[str, str], type[Exception]],
    unknown: type[Exception] = DecoderChildReportedError,
) -> Exception:
    """The exception an ``ERR`` payload reports: the type ``known`` or the builtins
    table names, built from the message, else ``unknown`` naming the type."""
    module, name, _errno, message = parse_error_payload(payload)
    cls = (
        known.get((module, name))
        or known.get(("*", name))
        or _BUILTIN_ERRORS.get((module, name))
    )
    if cls is None:
        return unknown(f"{module}.{name}: {message}")
    return cls(message)


class DecoderChild:
    """One decoder object of ``codec`` in a child process.

    ``args`` and ``kwargs`` are the constructor's, sent with ``marshal``. ``known``
    maps the exception types the decoder raises to the types rebuilt here. ``reuse``
    lets the child serve another decoder after this one, if it ends cleanly.
    ``setting`` names the ``process_isolation`` value that put this decoder in a child,
    for the error raised when a fresh child is needed part-way and none can start.

    A child that served earlier decoders may carry damage one of them left without
    crashing, so its crash or error is not blamed on this decoder at once: the decoder
    records what it sent (up to ``REPLAY_LIMIT`` bytes, then it moves to a fresh child
    straight away), re-runs it in a fresh child, and only that child's crash or error
    is the verdict. Decoders are deterministic, so the re-run reaches the same state.
    The output the caller already has is checked on the way: the re-run's output for
    each request must match it (CRC-32), or the call raises ``ReadError``, since the
    reused child gave wrong bytes that no later read can take back. Neither child's
    verdict is then charged to the data.

    After the child dies, every later call raises the same error again. After a request
    or its reply was interrupted (``KeyboardInterrupt`` part-way through), every later
    call raises ``ArchiveyUsageError``, and the child is ended at close (see
    :meth:`_abandon`): the rest of the request is still to be read, or the rest of the
    reply is still in the pipe.
    """

    # How a death during a request is reported: the subclass for PPMd keeps the
    # codec's own error types.
    describe = "decoder process"
    # Whether this decoder runs in a child under every setting but ``NONE``, which
    # decides the advice when no child can start (``isolation_error``).
    isolated_unless_none = False

    def __init__(
        self,
        codec: str,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        *,
        known: dict[tuple[str, str], type[Exception]] | None = None,
        reuse: bool = True,
        setting: str = "NATIVE_DECODERS",
    ) -> None:
        self._codec = codec
        self._setting = setting
        message: tuple[Any, ...] = (codec, args, kwargs or {})
        self._open_message = marshal.dumps(message)
        self._known = known or {}
        self._reuse = reuse
        self._state: dict[str, object] = {}
        self._input = b""
        self._unused = b""
        self._unused_stale = False
        self._interrupted = False
        self._death: Exception | None = None
        # True between the two replies to ``OPEN``: the library is imported and the
        # decoder is being built (see ``_death_error``).
        self._building = False
        # What was sent since ``OPEN``, while the child is a reused one (see the class
        # docstring); ``None`` in a fresh child.
        # Each entry: the request, and the CRC-32 of the output it got.
        self._log: list[tuple[int, int, tuple[bytes, ...], int]] | None = None
        self._log_size = 0
        process = POOL.take()
        self._holder = [_Lease(process, reuse)]
        self._finalizer = weakref.finalize(self, _release, self._holder)
        try:
            if process.served:
                self._log = []
            try:
                self._open()
            except Exception:
                if self._log is None or self._interrupted:
                    raise
                # The reused child failed to build the decoder: try a fresh one.
                self._log = None
                self._replace_process()
                self._open()
        except _Died as died:
            self._lease.reusable = False
            self.close()
            raise self._death_from(died) from None
        except BaseException:
            self._lease.reusable = False
            self.close()
            raise

    @property
    def _lease(self) -> _Lease:
        return self._holder[0]

    def _replace_process(self) -> None:
        """End the current child and take a fresh one."""
        self._lease.reusable = False
        self._lease.release()
        self._holder[0] = _Lease(POOL.take(fresh=True), self._reuse)

    def _open(self) -> None:
        """Send ``OPEN`` and take its two replies (after the import, after the build)."""
        self._building = False
        tag, state, output = self._exchange(OPEN, 0, (self._open_message,))
        if tag != OK:
            exc = rebuild_error(output, self._known)
            if isinstance(exc, ImportError):
                raise start_error(f"cannot import the {self._codec} library: {exc}")
            raise start_error(str(exc))
        self._building = True
        tag, state, output = self._receive_raw()
        if tag != OK:
            raise rebuild_error(output, self._known)
        self._building = False
        self._state = marshal.loads(state) if state else {}

    # -- requests -------------------------------------------------------------------

    def _check_usable(self) -> _Process:
        if self._death is not None:
            raise self._death
        if self._interrupted:
            raise ArchiveyUsageError(
                f"the {self.describe} was interrupted in the middle of a request "
                "or its reply, and this decoder cannot continue"
            )
        process = self._lease.process
        if process is None:
            raise ArchiveyUsageError("the decoder is closed")
        if not process.owned():
            raise ArchiveyUsageError(
                f"this decoder's {self.describe} belongs to the process this one was "
                "forked from; open the member again in this process"
            )
        return process

    def _exchange(
        self, tag: int, arg: int, parts: tuple[bytes, ...]
    ) -> tuple[int, bytes, bytes]:
        process = self._check_usable()
        try:
            process.send(tag, arg, *parts)
        except (OSError, ValueError):
            raise _Died(process) from None
        except BaseException:
            # Interrupted part-way through a request: the child is still reading it,
            # and would read the next frame as the rest of its payload.
            self._abandon()
            raise
        return self._receive_raw()

    def _receive_raw(self) -> tuple[int, bytes, bytes]:
        process = self._lease.process
        assert process is not None
        try:
            tag, _arg, state, output = process.receive()
        except (EOFError, OSError, ValueError):
            raise _Died(process) from None
        except BaseException:
            # Interrupted part-way through a reply: the rest of it is still in the
            # pipe, and the next read would take its bytes for a reply header.
            self._abandon()
            raise
        return tag, state, output

    def _abandon(self) -> None:
        """Give up on the child after an interrupt part-way through a frame: every
        later call refuses, and :meth:`close` ends the child instead of reusing it.
        The child is not ended here: ending it waits for it to exit (up to
        ``REAP_TIMEOUT``), and that wait must not run inside the interrupt."""
        self._interrupted = True
        self._lease.reusable = False

    def _request(self, tag: int, arg: int, *parts: bytes) -> bytes:
        """Send one request and return its output, re-running in a fresh child a crash
        or error from a reused one (see the class docstring)."""
        # Before the bound check: a move to a fresh child must not revive a decoder
        # that is closed, or one inherited through ``fork``.
        self._check_usable()
        if (
            self._log is not None
            and self._log_size + sum(len(part) for part in parts) > REPLAY_LIMIT
        ):
            # Past the record's bound: move before sending, so the reused child never
            # gets a request the fresh one would have to run again.
            self._move_to_fresh_child()
        try:
            reply, state, output = self._exchange(tag, arg, parts)
        except _Died as died:
            if self._log is not None and is_crash(died.returncode):
                return self._rerun_fresh(tag, arg, parts)
            raise self._death_from(died) from None
        if reply != OK:
            if self._log is not None:
                return self._rerun_fresh(tag, arg, parts)
            self._lease.reusable = False
            raise rebuild_error(output, self._known)
        self._state = marshal.loads(state) if state else {}
        if self._log is not None:
            self._log.append((tag, arg, parts, zlib.crc32(output)))
            self._log_size += sum(len(part) for part in parts)
        return output

    def _move_to_fresh_child(self) -> None:
        """Re-run everything sent so far in a fresh child, and go on there."""
        log, self._log, self._log_size = self._log, None, 0
        assert log is not None
        try:
            try:
                self._replace_process()
                self._open()
            except _Died as died:
                raise self._death_from(died) from None
        except Exception as exc:
            # Translated as when the decoder was opened: the same environment failure
            # must not reach the caller as a different error because it came later.
            self._lease.reusable = False
            self._lease.release()
            self._death = self._fresh_child_error(exc)
            if self._death is exc:
                raise
            raise self._death from exc
        for tag, arg, parts, crc in log:
            if zlib.crc32(self._request(tag, arg, *parts)) != crc:
                self._lease.reusable = False
                raise ReadError(
                    f"the {self.describe} that had served earlier members gave output "
                    "that a fresh one does not reproduce, and part of it was already "
                    "returned; read this member again"
                )

    def _rerun_fresh(self, tag: int, arg: int, parts: tuple[bytes, ...]) -> bytes:
        self._move_to_fresh_child()
        return self._request(tag, arg, *parts)

    def _fresh_child_error(self, exc: Exception) -> Exception:
        """The error for a fresh child that could not be started and opened part-way
        through a member. PPMd overrides this for a model it cannot allocate."""
        if isinstance(exc, DecoderChildStartError):
            return isolation_error(
                str(exc), self._setting, isolated_unless_none=self.isolated_unless_none
            )
        return exc

    def _death_from(self, died: _Died) -> Exception:
        """Record and return the error for a child that went away."""
        self._lease.reusable = False
        self._lease.release()
        if not died.answered:
            # Never replied at all: it did not start, which says nothing about data.
            self._death = start_error(
                f"the {self.describe} exited before replying "
                f"({describe_exit(died.returncode)})"
            )
        else:
            self._death = self._death_error(died.returncode)
        return self._death

    def _death_error(self, returncode: int | None) -> Exception:
        """The error for a child that ended during a request (``returncode``): a crash
        is a verdict on the data, any other end is not. A death while the decoder is
        built (``_building``) is reported the same way: the constructor's arguments come
        from the archive. PPMd overrides this."""
        if is_crash(returncode):
            return CorruptionError(
                f"the {self.describe} crashed while decoding this data "
                f"({describe_exit(returncode)})"
            )
        what = f"the {self.describe} exited unexpectedly ({describe_exit(returncode)})"
        return outside_death_error(returncode, what)

    def call(
        self,
        method: str,
        data: bytes | bytearray | memoryview | None,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
    ) -> bytes:
        """Run ``method`` on the child's decoder, with ``data`` first when given;
        return its bytes (a non-bytes result is in :attr:`result`)."""
        request: tuple[Any, ...] = (method, args, kwargs or {}, data is not None)
        header = marshal.dumps(request)
        if data is None:
            out = self._request(CALL, len(header), header)
        else:
            if not isinstance(data, bytes):
                data = bytes(data)
            self._input = data
            out = self._request(CALL, len(header), header, data)
        self._note_unused()
        return out

    def get(self, name: str) -> bytes:
        """The child decoder's ``name`` attribute, as bytes."""
        return self._request(GET, 0, name.encode("ascii"))

    # -- the state the last reply carried --------------------------------------------

    def flag(self, name: str) -> bool:
        value = self._state.get(name)
        if not isinstance(value, bool):
            # Stands in for the decoder lacking this attribute.
            raise AttributeError(name)  # noqa: TRY004
        return value

    def has(self, name: str) -> bool:
        return name in self._state

    @property
    def result(self) -> object:
        return self._state.get("result")

    def _note_unused(self) -> None:
        """Extend the copy of ``unused_data`` by what the last call added.

        What a decoder adds to ``unused_data`` is the end of the input it was just
        given, so the parent rebuilds it from its own copy. A length that does not
        fit that rule is fetched with ``GET`` when it is read.
        """
        size = self._state.get("unused_data")
        if not isinstance(size, int) or size == len(self._unused):
            return
        grown = size - len(self._unused)
        if 0 < grown <= len(self._input) and not self._unused_stale:
            self._unused += self._input[len(self._input) - grown :]
        else:
            self._unused_stale = True

    def unused_data(self) -> bytes:
        if "unused_data" not in self._state:
            raise AttributeError("unused_data")
        if self._state["unused_data"] is None:
            return b""  # lz4.frame's None: every caller reads it as ``or b""``
        if self._unused_stale:
            self._unused = self.get("unused_data")
            self._unused_stale = False
        return self._unused

    def unconsumed_tail(self) -> bytes:
        size = self._state.get("unconsumed_tail")
        if not isinstance(size, int):
            # Stands in for the decoder lacking this attribute.
            raise AttributeError("unconsumed_tail")  # noqa: TRY004
        if size == 0:
            return b""
        if size <= len(self._input):
            return self._input[len(self._input) - size :]
        return self.get("unconsumed_tail")

    @property
    def served_before(self) -> bool:
        """Whether the child served another decoder before this one (tests)."""
        return self._log is not None

    def spoil(self) -> None:
        """End the child at :meth:`close` instead of giving it back: the decoder left
        the library in a state that must not serve another decoder."""
        self._lease.reusable = False

    def close(self) -> None:
        """Give the child back (or end it). Idempotent; never raises."""
        self._finalizer()


def isolation_error(
    reason: str, setting: str = "NATIVE_DECODERS", *, isolated_unless_none: bool = False
) -> ResourceUnavailableError:
    """The error for a decoder that ``process_isolation`` (``setting``) runs only in a
    child process, when no child can start. ``isolated_unless_none``: the decoder runs
    in a child under every setting but ``NONE`` (PPMd), so ``NONE`` is the only advice
    that helps."""
    instead = (
        "ProcessIsolation.KNOWN_CRASHES"
        if setting == "NATIVE_DECODERS" and not isolated_unless_none
        else "ProcessIsolation.NONE (not recommended for files you do not trust)"
    )
    error = ResourceUnavailableError(
        f"{reason}. process_isolation={setting} decodes this only in a child "
        f"process; use {instead} to decode it in this process."
    )
    mark_no_verdict(error)
    return error
