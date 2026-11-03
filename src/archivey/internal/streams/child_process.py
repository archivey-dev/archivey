"""Start a child process, end it, and read how it ended from its return code.

A native decoder that archivey runs in a child process (see ``decoder_child`` and
``rapidgzip_child``) can crash on hostile input. Only a crash is a
verdict on the data. A child ended from outside (the out-of-memory killer, an
operator, a supervisor) says nothing about the data, and the caller must not be told
it does.

The external data programs (``unrar``, ``unar``; see ``archivey.internal.external``)
start and end through the same functions, and map their own exit statuses.
"""

from __future__ import annotations

import signal
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO

from archivey.exceptions import ArchiveyError, ReadError, ResourceUnavailableError

# Seconds a child has to exit after it is told to end (its pipes closed, or a signal
# sent) before it is killed.
REAP_TIMEOUT = 5

# Makes the caller's start error from the reason (the ``OSError``, or no interpreter).
StartFailure = Callable[[str], Exception]


def python_argv(script: Path, fail: StartFailure) -> list[str]:
    """The argv that runs ``script`` under this interpreter.

    Raises ``fail(...)`` when ``sys.executable`` is not set: ``Popen([None, ...])``
    raises ``TypeError``, not ``OSError``, so :func:`spawn` would not map it.
    """
    if not sys.executable:
        raise fail("sys.executable is not set")
    # -P: the script's own directory is not put on sys.path, so no file beside it can
    # shadow a standard-library module the worker imports (as ``streams/codecs/`` once
    # shadowed the stdlib ``codecs`` when the workers sat beside it).
    return [sys.executable, "-P", str(script)]


def unavailable_reason(worker: Path, decoder: str) -> str | None:
    """Why no Python child process can run the ``worker`` script, or ``None`` when one
    can. ``decoder`` names the decoder in the reason, such as ``"rapidgzip"``.

    A frozen application (PyInstaller and the like) has no Python interpreter at
    ``sys.executable``, an embedded interpreter may not know its own path
    (``sys.executable`` is ``None`` or empty), and a zip-imported archivey has no
    worker file on disk.
    """
    if getattr(sys, "frozen", False):
        return (
            "this is a frozen application, with no Python interpreter to run the "
            f"{decoder} decoder process"
        )
    if not sys.executable:
        return (
            f"sys.executable is not set, so the {decoder} decoder process cannot start"
        )
    if not worker.is_file():
        return (
            f"the {decoder} worker script {worker.name} is not a file on disk "
            "(archivey imported from a zip archive?), so the decoder process cannot start"
        )
    return None


def spawn(
    argv: Sequence[str | bytes],
    fail: StartFailure,
    *,
    stdin: int | IO[bytes],
    stderr: int | IO[bytes],
    bufsize: int = -1,
    env: Mapping[str, str] | None = None,
    pass_fds: Sequence[int] = (),
) -> subprocess.Popen[bytes]:
    """Start ``argv`` with its stdout on a pipe. An ``OSError`` raises ``fail(str(exc))``.

    ``env`` replaces the child's environment; ``None`` inherits this process's.
    ``pass_fds`` are descriptors the child inherits under the same numbers (POSIX only).
    """
    try:
        return subprocess.Popen(
            argv,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=stderr,
            bufsize=bufsize,
            env=env,
            pass_fds=pass_fds,
        )
    except OSError as exc:
        raise fail(str(exc)) from exc


def wait_or_kill(proc: subprocess.Popen[bytes]) -> None:
    """Wait for the child to exit; kill it after ``REAP_TIMEOUT`` seconds."""
    try:
        proc.wait(timeout=REAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def reap(proc: subprocess.Popen[bytes], *, kill: bool = False) -> None:
    """End a child that talks on its pipes, and wait for it. Never raises.

    ``kill`` kills it first; otherwise closing the pipes ends it.
    """
    if kill:
        try:
            proc.kill()
        except OSError:
            pass
    # Both pipes before the wait: a child blocked writing to a pipe nobody reads gets
    # EPIPE and exits, where it would otherwise never see stdin close.
    for pipe in (proc.stdin, proc.stdout):
        try:
            if pipe is not None:
                pipe.close()
        except OSError:
            pass
    wait_or_kill(proc)


# The system kills with SIGKILL: the kernel's out-of-memory killer, an operator or a
# supervisor. Windows has no such signal.
SIGKILL: int | None = getattr(signal, "SIGKILL", None)

# The deaths that read as a crash of the decoder itself: the POSIX signals a native
# fault raises, and the Windows NTSTATUS codes for the same faults.
_CRASH_SIGNALS = frozenset(
    -int(sig)
    for name in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE")
    if (sig := getattr(signal, name, None)) is not None
)
_CRASH_NTSTATUS = frozenset(
    {
        0xC0000005,  # access violation
        0xC000001D,  # illegal instruction
        0xC0000094,  # integer divide by zero
        0xC00000FD,  # stack overflow
        0xC0000409,  # stack buffer overrun / fail-fast (the C runtime's abort path)
    }
)
# The Microsoft C runtime's abort() exits with status 3 when it does not fail fast.
# A worker that archivey runs never exits with 3 by itself (a Python child exits 0,
# or 1 on an uncaught exception), so on Windows a 3 is the decoder's abort.
_WINDOWS_ABORT_STATUS = 3


def is_crash(returncode: int | None) -> bool:
    """Whether a child that ended with ``returncode`` crashed, rather than was ended.

    A crash is a native fault signal, or the Windows status for one. Every other end
    (SIGKILL, SIGTERM, a plain exit status) came from outside the decoder.
    """
    if returncode is None:
        return False
    if returncode in _CRASH_SIGNALS or returncode in _CRASH_NTSTATUS:
        return True
    return sys.platform == "win32" and returncode == _WINDOWS_ABORT_STATUS


def is_system_kill(returncode: int | None) -> bool:
    """Whether the child was ended by SIGKILL, most often the out-of-memory killer."""
    return SIGKILL is not None and returncode == -SIGKILL


def outside_death(returncode: int | None, what: str) -> tuple[type[ArchiveyError], str]:
    """The error class and unescaped message for a decoder child that ended without
    crashing (see :func:`is_crash`). The caller builds the exception, so its message is
    escaped once, there.

    ``what`` says which process ended and how, such as ``describe_exit``'s text. The
    end came from outside the decoder, so it is no verdict on the data:
    ``ResourceUnavailableError`` for SIGKILL (most often the out-of-memory killer), and
    ``ReadError`` for any other end.

    ``signal_exit_error`` in ``archivey.internal.external.cli`` classifies the end of
    ``unrar`` and ``unar`` the same way for SIGKILL, with "program" wording. It differs
    on crash signals: there a crash is no verdict either, because ``unar`` crashes on
    valid archives, while a decoder child's crash here is left to the caller to call
    corruption. A change to the SIGKILL classification belongs in both places.
    """
    if is_system_kill(returncode):
        return (
            ResourceUnavailableError,
            (
                f"{what}. SIGKILL comes from outside the decoder, most often the "
                "system's out-of-memory killer, so the data may be valid; read it "
                "again with more memory available."
            ),
        )
    return (
        ReadError,
        (
            f"{what}. The decoder did not crash: something outside it ended the "
            "process, so the data may be valid; try reading it again."
        ),
    )


# Set on an error that says nothing about the data a decoder child was given: the child
# ended from outside (:func:`outside_death_error`) or could not start. Read by the seek
# index check, which drops an index only for a verdict on the data
# (``decompressor_stream._is_data_verdict``).
_NO_VERDICT = "_archivey_no_verdict_on_the_data"


def mark_no_verdict(exc: ArchiveyError) -> ArchiveyError:
    """``exc``, marked as no verdict on the data (:func:`is_no_verdict`)."""
    setattr(exc, _NO_VERDICT, True)
    return exc


def is_no_verdict(exc: BaseException) -> bool:
    """Whether ``exc`` was marked by :func:`mark_no_verdict`."""
    return getattr(exc, _NO_VERDICT, False) is True


def outside_death_error(returncode: int | None, what: str) -> ArchiveyError:
    """The error :func:`outside_death` describes, built and marked as no verdict on the
    data (:func:`mark_no_verdict`)."""
    cls, message = outside_death(returncode, what)
    return mark_no_verdict(cls(message))


def describe_exit(returncode: int | None) -> str:
    """How a child ended, for an error message: a signal name or an exit status."""
    if returncode is None:
        return "exit status unknown"
    if returncode < 0:
        try:
            return f"killed by {signal.Signals(-returncode).name}"
        except ValueError:
            return f"killed by signal {-returncode}"
    if returncode > 255:  # a Windows NTSTATUS, such as 0xC0000005 (access violation)
        return f"exit status {returncode:#x}"
    return f"exit status {returncode}"
