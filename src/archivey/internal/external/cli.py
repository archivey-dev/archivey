"""Find and identify an external decompressor on ``PATH``, once per binary.

A program on ``PATH`` with the right name is not proof that it is the right program, so
each candidate runs once with an identification argv, and its banner decides. The
answer is cached by absolute path and stat identity, so later reads do not spawn the
probe again, and a binary replaced on disk is probed afresh.

This is the policy :func:`archivey.internal.backends.rar_unrar.find_rarlab_unrar`
applies to RARLAB ``unrar``, written once for any program. That finder shares
:func:`stat_identity` with this module, but it still runs its own loop and cache;
moving it onto :class:`CliToolFinder` is recorded in ``dev-docs/IDEAS.md``.

Once found, a program runs with its output on a pipe: :func:`spawn_for_stdout` starts
it, and a :class:`ProcessOutputStream` subclass owns it until close. Both the ``unrar``
and the ``unar`` read paths use them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from abc import abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, BinaryIO, cast

from archivey.exceptions import (
    PackageNotInstalledError,
    ReadError,
    ResourceUnavailableError,
)
from archivey.internal.streams.child_process import (
    describe_exit,
    is_system_kill,
    spawn,
    wait_or_kill,
)
from archivey.internal.streams.streamtools import DelegatingStream
from archivey.terminal import display_path

# Seconds each probe of one binary may run: the identification run, and the finder's
# ``verify`` check where it runs one (``unar``'s RAR5 check reads this too). A binary
# that has not answered by then is remembered as unusable (see ``CliToolFinder``). With
# both, the worst case for one binary is twice this.
PROBE_TIMEOUT_SECONDS: float = 10


@dataclass(frozen=True, slots=True)
class Banner:
    """What one identification banner says: the right program or not, and its version."""

    identified: bool
    version: tuple[int, ...] | None


@dataclass(frozen=True, slots=True)
class _Probe:
    banner: Banner
    identity: tuple[int, int, int, int]
    timed_out: bool
    # Why a binary that identified and met the floor failed the finder's ``verify``
    # check, or ``None``.
    rejected: str | None = None


def stat_identity(path: str) -> tuple[int, int, int, int]:
    """``(st_dev, st_ino, st_mtime_ns, st_size)``: the identity a replaced binary cannot keep."""
    st = os.stat(path)
    return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)


class CliToolFinder:
    """Locate one program on ``PATH`` and accept it only if its banner identifies it.

    ``names`` are tried in order; the first candidate that identifies and meets
    ``version_floor`` wins. ``parse_banner`` receives stdout and stderr of
    ``<candidate> <probe_args>`` decoded as UTF-8 with replacement.

    Cache rules (the same as the ``unrar`` finder):

    - A durable answer is stored per absolute path with the binary's stat identity, so a
      lookalike costs one process per process lifetime, not one per member read.
    - A probe that runs out of time is stored as unusable. Re-probing would cost the
      full timeout on every read; the refusal names the binary and the timeout, so the
      cause stays visible. A replaced binary changes the stat identity and is probed
      again.
    - A ``which`` miss and a probe that could not *start* the binary (``OSError``) are
      not stored, so a program installed later is found without a restart.

    ``verify``, when given, runs once on a binary that identified and met the floor,
    and returns why the binary must not be used, or ``None``. Its answer is stored
    with the banner, under the same rules. An ``OSError`` it raises means the check
    could not run, which says nothing about the binary: it is not stored, and the
    refusal says the check could not run and includes the error.
    """

    def __init__(
        self,
        *,
        display_name: str,
        names: Sequence[str],
        probe_args: Sequence[str],
        parse_banner: Callable[[str], Banner],
        version_floor: tuple[int, ...],
        install_hint: str,
        verify: Callable[[str], str | None] | None = None,
    ) -> None:
        self._display_name = display_name
        self._names = tuple(names)
        self._probe_args = tuple(probe_args)
        self._parse_banner = parse_banner
        self._version_floor = version_floor
        self._install_hint = install_hint
        self._verify = verify
        self._cache: dict[str, _Probe] = {}
        self._lock = threading.Lock()

    def clear_cache(self) -> None:
        """Forget every probe answer. For tests that swap binaries on ``PATH``."""
        with self._lock:
            self._cache.clear()

    def _floor_text(self) -> str:
        return ".".join(str(part) for part in self._version_floor)

    def _probe(self, path: str) -> Banner:
        completed = subprocess.run(
            [path, *self._probe_args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
        text = ((completed.stdout or b"") + (completed.stderr or b"")).decode(
            "utf-8", errors="replace"
        )
        return self._parse_banner(text)

    def _meets_floor(self, banner: Banner) -> bool:
        return (
            banner.identified
            and banner.version is not None
            and banner.version >= self._version_floor
        )

    def find(self, *, purpose: str) -> str:
        """Return the absolute path of a usable binary, or raise ``PackageNotInstalledError``.

        ``purpose`` completes "<program> is required …" in the refusal, so the caller
        can say which read needed the program.
        """
        # Sample PATH once, so a concurrent ``os.environ`` rewrite cannot mix two values.
        path_env = os.environ.get("PATH", "")
        too_old: list[tuple[str, tuple[int, ...] | None]] = []
        timed_out: list[str] = []
        rejected: list[tuple[str, str]] = []
        unchecked: list[tuple[str, OSError]] = []
        cause: BaseException | None = None
        for name in self._names:
            candidate = shutil.which(name, path=path_env)
            if candidate is None:
                continue
            candidate = os.path.abspath(candidate)
            try:
                identity = stat_identity(candidate)
            except OSError as exc:
                cause = exc
                continue
            with self._lock:
                cached = self._cache.get(candidate)
            if cached is None or cached.identity != identity:
                probe_timed_out = False
                try:
                    banner = self._probe(candidate)
                except subprocess.TimeoutExpired as exc:
                    cause = exc
                    probe_timed_out = True
                    banner = Banner(identified=False, version=None)
                except (OSError, subprocess.SubprocessError) as exc:
                    cause = exc
                    continue
                rejection = None
                if self._verify is not None and self._meets_floor(banner):
                    try:
                        rejection = self._verify(candidate)
                    except OSError as exc:
                        cause = exc
                        unchecked.append((candidate, exc))
                        continue
                cached = _Probe(banner, identity, probe_timed_out, rejection)
                with self._lock:
                    self._cache[candidate] = cached
            if cached.rejected is not None:
                rejected.append((candidate, cached.rejected))
                continue
            if self._meets_floor(cached.banner):
                return candidate
            if cached.banner.identified:
                too_old.append((candidate, cached.banner.version))
            elif cached.timed_out:
                timed_out.append(candidate)
        raise PackageNotInstalledError(
            self._refusal(purpose, too_old, timed_out, rejected, unchecked)
        ) from cause

    def _refusal(
        self,
        purpose: str,
        too_old: list[tuple[str, tuple[int, ...] | None]],
        timed_out: list[str],
        rejected: list[tuple[str, str]],
        unchecked: list[tuple[str, OSError]],
    ) -> str:
        name = self._display_name
        if rejected:
            # The reason carries its own advice: a generic install hint could name the
            # very package that was just rejected.
            found = "; ".join(
                f"{display_path(path)} {reason}" for path, reason in rejected
            )
            return f"{name} is required {purpose}, but {found}"
        if unchecked:
            # The binary is the right program; the environment stopped the check. An
            # install hint would send the reader after the wrong problem.
            found = "; ".join(
                f"{display_path(path)} ({exc})" for path, exc in unchecked
            )
            return (
                f"{name} is required {purpose}. Found {found} on PATH and identified "
                f"it, but archivey could not run its check on it. The check writes a "
                "small archive to the temporary directory, so check that it exists "
                "and has space. archivey tries the check again on the next lookup."
            )
        if too_old:
            found = "; ".join(
                f"{display_path(path)} reports version "
                + ".".join(str(part) for part in version)
                if version is not None
                else f"the version of {display_path(path)} could not be parsed"
                for path, version in too_old
            )
            return (
                f"{name} {self._floor_text()} or later is required {purpose}, but "
                f"{found}. {self._install_hint}"
            )
        if timed_out:
            shown = " and ".join(display_path(path) for path in timed_out)
            return (
                f"{name} is required {purpose}. Found {shown} on PATH, but it did not "
                f"answer the identification probe within {PROBE_TIMEOUT_SECONDS:g} "
                "seconds. archivey does not probe an unchanged binary again in this "
                f"process. {self._install_hint}"
            )
        return (
            f"{name} is required {purpose}, but it was not found on PATH (or the "
            f"program found under that name is not {name}). {self._install_hint}"
        )


def terminate_process(proc: subprocess.Popen[bytes] | None) -> bool:
    """Stop a child process if it is still running, and reap it.

    Returns whether archivey stopped it, so its exit status is archivey's doing.
    """
    if proc is None or proc.poll() is not None:
        return False
    proc.terminate()
    wait_or_kill(proc)
    return True


def spawn_for_stdout(
    cmd: Sequence[str | bytes],
    *,
    name: str,
    not_started: str,
    stdin: int | IO[bytes] = subprocess.DEVNULL,
    env: Mapping[str, str] | None = None,
) -> tuple[subprocess.Popen[bytes], BinaryIO]:
    """Start ``cmd`` with stdout on a pipe and stderr discarded; return ``(proc, stdout)``.

    A program that cannot start raises ``PackageNotInstalledError(not_started)``. The
    caller owns the process until a :class:`ProcessOutputStream` takes it: nothing
    reaps it if the caller raises before that constructor's ``try`` is reached.
    ``env`` replaces the child's environment; ``None`` inherits this process's. An
    argument may be ``bytes`` on POSIX, where argv is bytes.
    """
    proc = spawn(
        cmd,
        lambda _: PackageNotInstalledError(not_started),
        stdin=stdin,
        stderr=subprocess.DEVNULL,
        bufsize=1024 * 1024,
        env=env,
    )
    if proc.stdout is None:
        terminate_process(proc)
        # Defensive: stdout=PIPE was asked for, so this should be unreachable. Typed
        # anyway, because every archive-read failure surfaces as an ArchiveyError.
        raise ReadError(f"{name} produced no stdout pipe")
    # typeshed types Popen[bytes].stdout as IO[bytes], not BinaryIO; the pipe is opened
    # in binary mode, so it is one at runtime.
    return proc, cast(BinaryIO, proc.stdout)


def signal_exit_error(
    name: str, returncode: int
) -> ReadError | ResourceUnavailableError:
    """The error for a program that a signal ended after it closed its output.

    Not a verdict on the archive, which is why this never raises ``CorruptionError``
    or ``TruncatedError``: SIGKILL comes from outside (most often the out-of-memory
    killer), and is a ``ResourceUnavailableError`` as in ``outside_death``
    (``archivey.internal.streams.child_process``), which classifies the end of the ppmd
    and rapidgzip decoder children. Any other signal is a ``ReadError``, the crash
    signals included: ``unar`` 1.10.1 crashes on some valid archives, so a crash of
    these programs does not condemn the data. That is where the two differ:
    ``outside_death`` handles only ends that are not crashes, because a decoder
    child's crash is a verdict on the data. Its messages also say "decoder" and "data"
    where these say "program" and "archive". A change to the SIGKILL classification
    belongs in both places.
    """
    how = describe_exit(returncode)
    if is_system_kill(returncode):
        return ResourceUnavailableError(
            f"{name} was killed ({how}) while reading data. SIGKILL comes from "
            "outside the program, most often the system's out-of-memory killer, so "
            "the archive may be valid; read it again with more memory available."
        )
    return ReadError(
        f"{name} stopped on a signal ({how}) while reading data; the archive may be "
        "valid, so try reading it again."
    )


class ProcessOutputStream(DelegatingStream):
    """A program's stdout that owns the program: close stops and reaps it.

    ``_raise_for_returncode`` maps the exit status once: on the read at end of file
    (``_at_eof``) if the program has exited by then, else on close. A program that close
    has to stop is not mapped: its status reports archivey's signal. ``read(0)`` is not
    end of file. The stream owns the program from the ``try`` in ``__init__`` on: a
    raise from there stops the program first. A subclass's own assignments before
    ``super().__init__`` run before that, so they must not raise.
    """

    _SUBCLASS_CLOSES_INNER = True
    # read() counts and checks the exit; readinto must go through it.
    readinto_passthrough = False
    # Seconds the read at end of file waits for the program to exit. The program closed
    # its stdout, so it is exiting; one that takes longer is stopped on close, and its
    # status is not mapped.
    _EOF_EXIT_WAIT = 1.0

    def __init__(self, stdout: BinaryIO, proc: subprocess.Popen[bytes]) -> None:
        # Everything close() reads is assigned before DelegatingStream.__init__, which
        # can raise. A subclass assigns its own fields before it calls this.
        self._proc = proc
        self._bytes_read = 0
        self._exit_checked = False
        try:
            super().__init__(stdout)
        except BaseException:
            terminate_process(proc)
            raise

    def read(self, n: int = -1, /) -> bytes:
        data = super().read(n)
        self._bytes_read += len(data)
        if not data and n != 0:
            self._at_eof()
        return data

    def _at_eof(self) -> None:
        """Map the exit status on the read at end of file, so a fault raises from read."""
        self._check_exit(wait_timeout=self._EOF_EXIT_WAIT)

    @abstractmethod
    def _raise_for_returncode(self, rc: int) -> None:
        """Raise the error that exit status ``rc`` reports, or return when it is none."""

    def _check_exit(self, *, wait_timeout: float | None) -> None:
        """Map the exit status once, if the program has exited or exits in ``wait_timeout``."""
        if self._exit_checked:
            return
        if self._proc.poll() is None:
            if wait_timeout is None:
                return
            try:
                self._proc.wait(timeout=wait_timeout)
            except subprocess.TimeoutExpired:
                return
        self._exit_checked = True
        self._raise_for_returncode(self._proc.returncode)

    def close(self) -> None:
        if self.closed:
            return
        close_error: BaseException | None = None
        try:
            self._inner.close()
        # BaseException: close must reap the program even on KeyboardInterrupt.
        except BaseException as exc:  # noqa: BLE001
            close_error = exc
        if terminate_process(self._proc):
            # archivey sent the signal: the status reports that, not the program. This
            # includes a program that closed its stdout but was slower to exit than
            # ``_EOF_EXIT_WAIT``, whose output was read in full.
            self._exit_checked = True
        # Marks this stream closed; _SUBCLASS_CLOSES_INNER keeps it from closing inner.
        super().close()
        # Map the status now if no read at end of file mapped it.
        try:
            self._check_exit(wait_timeout=None)
        # BaseException: chain onto inner.close()'s error, do not replace it.
        except BaseException as mapped:
            if close_error is not None:
                raise close_error from mapped
            raise
        if close_error is not None:
            raise close_error
