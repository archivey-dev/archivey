"""Per-test oracle for leaked OS resources.

A stream-layer ownership bug (close the wrapper, forget the subprocess) does not
raise and does not fail an assertion: the member reads as the right bytes, the
test goes green, and ``unrar`` stays alive holding its stdout pipe. This plugin
is the gate that makes that a red test.

What it detects, at *teardown* of each test:

- Child processes spawned during the test that are still alive (``Popen.poll()``
  is ``None``). A zombie is not this: ``poll()`` reaps it, so it never appears.
- Unclosed streams that own a private inner: ``SlicingStream(..., owns_inner=True)``
  and a ``DelegatingStream`` whose resolved ``_subclass_closes_inner`` is True
  (the ``subclass_closes_inner=True`` kwarg, or a subclass that sets
  ``_SUBCLASS_CLOSES_INNER = True`` and omits the kwarg). Those are the
  population that wraps a subprocess, a finalize-guarded accelerator, or some
  other inner the wrapper is responsible for reaping. The constructing test
  must close them before it returns.
- Extra pipe/socket file descriptors on Linux (``/proc/self/fd``), reported as
  context on a process/stream leak. Not a standalone fail: ``os.pipe()`` test
  helpers and pytest-cov change when GC closes those fds. Regular files are
  ignored.

What it deliberately does not:

- Unclosed ``BytesIO`` / default ``DelegatingStream`` wrappers. They hold no OS
  resource, and tests construct them by the thousand.
- A leftover pipe fd with no leaked child and no unclosed owning stream.
  ``tests/test_stream_inputs.py``'s ``os_pipe_reader`` is the specimen. Same
  for a ``Popen`` that already exited and was never ``wait``-ed: ``poll()``
  reaps the zombie; the leftover stdout pipe is fd-alone.
- Owning streams handed to a later test. Closing them in test B still fails
  test A — the pin is per-test. Close in the test that constructed the object.
- Module/session-scoped owning streams. Higher-scoped setup runs before this
  function fixture, and ``_reset_pins()`` at test start drops those pins.
- ``unrar`` / ``7z`` leaks under ``[core-only]``. Those binaries are absent, the
  tests that spawn them skip, and there is nothing to observe. The oracle still
  runs; it just has no subprocesses to catch. Isolated tests in
  ``test_leak_oracle.py`` spawn ``sys.executable`` so the gate is exercised in
  every config, including core-only.
- Interpreter-shutdown accelerator leftovers. None run in the test process any more:
  rapidgzip decodes every codec in a child process (``rapidgzip_worker.py``).

Cost: one ``Popen.__init__`` append, a flag check on two constructors, and two
small ``/proc`` snapshots. Disable with ``ARCHIVEY_LEAK_ORACLE=0``. A single
test opts out of the *fail* (not the reap) with
``@pytest.mark.allow_resource_leaks``. Teardown reaps leaked children via
``Popen.terminate``; ``os.WNOHANG`` is Unix-only and must not be used on the
portable path.

Owning streams and ``Popen`` objects are *pinned* until they are explicitly
closed (or until teardown). That is load-bearing: CPython refcounting would
otherwise run ``IOBase.__del__`` → ``close()`` when the test function returns,
reaping the child before this fixture sees it, and the leak would stay silent.
Pinning is why deleting ``owns_inner=True`` on the glob-mask RAR pipe fails a
test instead of looking fine. ``SlicingStream`` is keyed on the ``owns_inner``
kwarg; ``DelegatingStream`` is keyed on the resolved ``_subclass_closes_inner``
instance flag (class default or kwarg). A rename that does not update this
file disarms the gate.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import pytest

_ENV_FLAG = "ARCHIVEY_LEAK_ORACLE"

# Markers / env values that mean "do not install, do not check".
_OFF = frozenset({"0", "false", "no", "off"})


def _enabled() -> bool:
    raw = os.environ.get(_ENV_FLAG, "1").strip().lower()
    return raw not in _OFF


@dataclass
class _ProcRec:
    pid: int
    argv: str
    proc: subprocess.Popen[bytes]


@dataclass
class _StreamRec:
    kind: str
    cls: str
    stream: object


# Reentrant on purpose. The pins are touched from GC finalizers: an unclosed
# DelegatingStream reaches ``io.IOBase.__del__``, which calls ``close()``, which is
# this module's ``_d_close``, which unpins. A collection can fire inside any
# allocation, the snapshot a locked section takes included, so a plain Lock lets a
# thread deadlock against itself — the interrupted frame cannot release while the
# finalizer waits for it. Caught in CI on 2026-09-22 (macOS, py3.11): the
# teardown fixture hung in ``_unpin_stream`` under ``list(_pinned_procs.values())``,
# named only because pytest-timeout's thread method could still dump the stack of a
# thread deadlocked against itself. Use ``_snapshot`` rather than ``list(...)`` for
# the other half of the same hazard.
_lock = threading.RLock()
_T = TypeVar("_T")
_pinned_procs: dict[int, _ProcRec] = {}
_pinned_streams: dict[int, _StreamRec] = {}
_installed = False
_orig_popen_init: Callable[..., None] | None = None
_orig_delegating_init: Callable[..., None] | None = None
_orig_delegating_close: Callable[..., None] | None = None
_orig_slice_init_from_source: Callable[..., None] | None = None
_orig_slice_close: Callable[..., None] | None = None


def _fmt_argv(args: object) -> str:
    if isinstance(args, bytes):
        return args.decode("utf-8", "replace")
    if isinstance(args, str):
        return args
    try:
        parts = []
        for raw in args:  # type: ignore[union-attr]
            if isinstance(raw, bytes):
                parts.append(raw.decode("utf-8", "replace"))
            else:
                parts.append(str(raw))
    except TypeError:
        return repr(args)
    if len(parts) > 6:
        parts = parts[:6] + ["..."]
    return " ".join(parts)


def _note_popen(proc: subprocess.Popen[bytes], args: object) -> None:
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return
    rec = _ProcRec(pid=pid, argv=_fmt_argv(args), proc=proc)
    with _lock:
        _pinned_procs[pid] = rec


def _unpin_stream(stream: object) -> None:
    with _lock:
        _pinned_streams.pop(id(stream), None)


def _pin_stream(stream: object, kind: str) -> None:
    rec = _StreamRec(kind=kind, cls=type(stream).__name__, stream=stream)
    with _lock:
        _pinned_streams[id(stream)] = rec


def _install_popen_hook() -> None:
    global _orig_popen_init
    if _orig_popen_init is not None:
        return
    _orig_popen_init = subprocess.Popen.__init__

    def _init(self: subprocess.Popen[bytes], *args: object, **kwargs: object) -> None:
        assert _orig_popen_init is not None
        _orig_popen_init(self, *args, **kwargs)
        argv = args[0] if args else kwargs.get("args")
        _note_popen(self, argv)

    subprocess.Popen.__init__ = _init  # type: ignore[method-assign]  # wrap, do not subclass


def _install_stream_hooks() -> None:
    global _orig_delegating_init, _orig_delegating_close
    global _orig_slice_init_from_source, _orig_slice_close

    from archivey.internal.streams.streamtools.base import DelegatingStream
    from archivey.internal.streams.streamtools.slice import SlicingStream

    if _orig_delegating_init is None:
        _orig_delegating_init = DelegatingStream.__init__
        _orig_delegating_close = DelegatingStream.close

        def _d_init(self: DelegatingStream, *args: object, **kwargs: object) -> None:
            assert _orig_delegating_init is not None
            _orig_delegating_init(self, *args, **kwargs)
            # Resolved close contract: the class flag, or a kwarg that overrides it.
            # Keying only on ``kwargs.get("subclass_closes_inner")`` missed subclasses
            # that set ``_SUBCLASS_CLOSES_INNER`` and omit the kwarg.
            if getattr(self, "_subclass_closes_inner", False):
                _pin_stream(self, "subclass_closes_inner")

        def _d_close(self: DelegatingStream) -> None:
            _unpin_stream(self)
            assert _orig_delegating_close is not None
            _orig_delegating_close(self)

        DelegatingStream.__init__ = _d_init  # type: ignore[method-assign]  # wrap production ctor
        DelegatingStream.close = _d_close  # type: ignore[method-assign]  # unpin on explicit close

    if _orig_slice_init_from_source is None:
        _orig_slice_init_from_source = SlicingStream._init_from_source
        _orig_slice_close = SlicingStream.close

        def _s_init(self: SlicingStream, *args: object, **kwargs: object) -> None:
            assert _orig_slice_init_from_source is not None
            _orig_slice_init_from_source(self, *args, **kwargs)
            if kwargs.get("owns_inner"):
                _pin_stream(self, "owns_inner")

        def _s_close(self: SlicingStream) -> None:
            _unpin_stream(self)
            assert _orig_slice_close is not None
            _orig_slice_close(self)

        SlicingStream._init_from_source = _s_init  # type: ignore[method-assign]  # wrap; SharedView uses this too
        SlicingStream.close = _s_close  # type: ignore[method-assign]  # unpin on explicit close


def _child_pids() -> set[int]:
    """Direct children of this process, Linux ``/proc`` only.

    A backstop for anything that did not go through ``subprocess.Popen``. Empty
    on macOS/Windows — the Popen hook is the portable path there.
    """
    pid = os.getpid()
    path = Path(f"/proc/{pid}/task/{pid}/children")
    try:
        text = path.read_text(encoding="ascii")
    except OSError:
        return set()
    return {int(x) for x in text.split() if x.isdigit()}


def _pipe_fds() -> dict[int, str]:
    """Open pipe/socket fds → ``readlink`` target. Linux only; else empty."""
    fd_dir = Path("/proc/self/fd")
    if not fd_dir.is_dir():
        return {}
    found: dict[int, str] = {}
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        return {}
    for entry in entries:
        try:
            fd = int(entry.name)
        except ValueError:
            continue
        if fd < 3:
            continue
        try:
            mode = os.fstat(fd).st_mode
        except OSError:
            continue
        if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
            continue
        try:
            target = os.readlink(entry)
        except OSError:
            target = "?"
        found[fd] = target
    return found


def _pid_alive(pid: int) -> bool:
    # Windows: os.kill(pid, 0) is TerminateProcess, not a liveness probe.
    if os.name == "nt":
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _reap_proc(proc: subprocess.Popen[bytes]) -> None:
    """Reap via ``Popen`` so Windows (no ``os.WNOHANG``) can still kill the child."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=1.0)
        return
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        return
    try:
        proc.kill()
        proc.wait(timeout=1.0)
    except (subprocess.TimeoutExpired, OSError):
        return


def _reap_pid(pid: int) -> None:
    """POSIX backstop for children not spawned via ``Popen``.

    ``os.WNOHANG`` is Unix-only. On Windows this is a no-op; the Popen hook
    plus ``_reap_proc`` is the portable path.
    """
    wnohang = getattr(os, "WNOHANG", None)
    if wnohang is None:
        return
    try:
        waited, _ = os.waitpid(pid, wnohang)
    except (ChildProcessError, OSError):
        waited = 0
    if waited:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, wnohang)
        except (ChildProcessError, OSError):
            return
        if waited:
            return
        time.sleep(0.02)
    sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
    try:
        os.kill(pid, sigkill)
    except OSError:
        return
    try:
        os.waitpid(pid, 0)
    except (ChildProcessError, OSError):
        return


def _close_quietly(stream: object) -> None:
    close = getattr(stream, "close", None)
    if close is None:
        return
    try:
        close()
    except Exception:  # noqa: BLE001, S110 - teardown cleanup; the fail message is the report
        pass


def _snapshot(pinned: dict[int, _T]) -> list[_T]:
    """Copy a pinned map that a finalizer on this thread may be mutating.

    The lock is reentrant (see its comment), so an unpin that a GC finalizer triggers
    inside this very call proceeds instead of deadlocking -- and lands mid-iteration,
    which ``dict`` reports as a ``RuntimeError``. Retrying is correct here: each pass
    starts over, and a stream the finalizer removed was genuinely closed.
    """
    while True:
        try:
            return list(pinned.values())
        except RuntimeError:  # "dictionary changed size during iteration"
            continue


def _leaked_procs() -> list[_ProcRec]:
    leaked: list[_ProcRec] = []
    with _lock:
        recs = _snapshot(_pinned_procs)
    for rec in recs:
        if rec.proc.poll() is None:
            leaked.append(rec)
    return leaked


def _leaked_streams() -> list[_StreamRec]:
    with _lock:
        return _snapshot(_pinned_streams)


def _reset_pins() -> None:
    with _lock:
        _pinned_procs.clear()
        _pinned_streams.clear()


def _cleanup_leaks(
    procs: list[_ProcRec],
    streams: list[_StreamRec],
    extra_children: set[int] | None = None,
) -> None:
    for rec in streams:
        _close_quietly(rec.stream)
    reaped: set[int] = set()
    for rec in procs:
        _reap_proc(rec.proc)
        reaped.add(rec.pid)
    for pid in extra_children or ():
        if pid not in reaped:
            _reap_pid(pid)
    _reset_pins()


def _report(
    procs: list[_ProcRec],
    streams: list[_StreamRec],
    extra_fds: dict[int, str],
    extra_children: set[int],
) -> str:
    lines = ["test leaked OS resources:"]
    for rec in procs:
        lines.append(f"  child process still running: pid={rec.pid} argv={rec.argv!r}")
    for pid in sorted(extra_children):
        if any(rec.pid == pid for rec in procs):
            continue
        lines.append(
            f"  child process still running: pid={pid} (not spawned via subprocess.Popen)"
        )
    for rec in streams:
        lines.append(f"  unclosed {rec.kind} stream: {rec.cls}")
    for fd, target in sorted(extra_fds.items()):
        lines.append(f"  leaked pipe/socket fd {fd} -> {target}")
    lines.append(
        "These are pinned until explicit close so GC/__del__ cannot hide them. "
        "Close the owning wrapper (owns_inner=True / the stream that reaps the "
        "subprocess), or reap the child, in the same test that constructed it. "
        "Legitimate exception: @pytest.mark.allow_resource_leaks (still reaps) "
        "or ARCHIVEY_LEAK_ORACLE=0 (disables the plugin)."
    )
    return "\n".join(lines)


def pytest_configure(config: pytest.Config) -> None:
    # Marker text lives in pyproject.toml so it is registered even when the
    # plugin is off (ARCHIVEY_LEAK_ORACLE=0) or loads after conftest.
    del config
    if not _enabled():
        return
    global _installed
    if _installed:
        return
    _install_popen_hook()
    _install_stream_hooks()
    _installed = True


def _close_idle_decoder_children() -> None:
    from archivey.internal.streams.codecs.decoder_child import POOL

    POOL.close_idle()


@pytest.fixture(autouse=True)
def _archivey_leak_oracle(request: pytest.FixtureRequest) -> Iterator[None]:
    """Snapshot children/pipe fds, run the test, fail if anything new is still live."""
    if not _enabled():
        yield
        return
    if request.node.get_closest_marker("allow_resource_leaks") is not None:
        children_before = _child_pids()
        yield
        _close_idle_decoder_children()
        # Skip the fail, not the reap — leftover children would outlive the
        # session (the next test's snapshot hides them). extra_children is the
        # Linux /proc backstop for spawns that skipped subprocess.Popen.
        extra_children = {
            pid for pid in _child_pids() - children_before if _pid_alive(pid)
        }
        try:
            _cleanup_leaks(_leaked_procs(), _leaked_streams(), extra_children)
        except Exception:  # noqa: BLE001, S110 - marker path must not raise
            pass
        return

    _reset_pins()
    fds_before = _pipe_fds()
    children_before = _child_pids()
    yield

    # Idle decoder children wait in a pool for the next decoder, which is no leak; a
    # child still leased to a decoder nobody closed is one.
    _close_idle_decoder_children()
    procs = _leaked_procs()
    streams = _leaked_streams()
    extra_fds = {
        fd: target for fd, target in _pipe_fds().items() if fd not in fds_before
    }
    extra_children = {pid for pid in _child_pids() - children_before if _pid_alive(pid)}
    # Pipe fds alone are not a fail: os.pipe() test helpers close them via GC
    # on a schedule coverage changes. They still annotate a process/stream leak.
    if not (procs or streams or extra_children):
        _reset_pins()
        return

    message = _report(procs, streams, extra_fds, extra_children)
    try:
        _cleanup_leaks(procs, streams, extra_children)
    except Exception:  # noqa: BLE001, S110 - never hide the leak report behind cleanup
        pass
    pytest.fail(message)
