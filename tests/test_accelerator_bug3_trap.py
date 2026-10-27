"""Bug 3 containment: rapidgzip must not abort the process when its caller-owned source
faults mid-decode (``dev-docs/known-issues.md`` Bug 3).

rapidgzip ``std::terminate``s (SIGABRT) when a Python source callback raises while it is
decoding — classically, the caller closes their own source underneath a live accelerator. No
Python ``try/except`` can contain that abort. ``_open_rapidgzip`` runs rapidgzip in a child
process and serves the child's reads of a caller-owned source from this process, so the fault
is raised here as a normal Python exception, and rapidgzip only ever sees an end of input. The
bzip2 decoder runs in the same kind of child. Each scenario runs in its own subprocess so an abort is
contained; the assertion is that the **untrapped** raw path aborts (documenting the hazard)
while archivey's path exits cleanly with a Python-level error.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

# Incompressible payload so the compressed source is large and rapidgzip must pull from it
# across several read() calls — closing it underneath a live accelerator is then reached
# *during a read*, where the trap re-raises (a tiny/compressible source would be fully buffered
# on the first read, and the fault would land only in close(), which correctly stays quiet).
_SETUP = """
import gzip, io, os, rapidgzip
full = gzip.compress(os.urandom(20_000_000))

class Src(io.RawIOBase):
    def __init__(self, data):
        self._b = io.BytesIO(data)
        self._served = 0
        self.fail_after = None  # raise after this many compressed bytes (trapped path)
        self._dead = False
    def readable(self): return True
    def seekable(self): return True
    def seek(self, o, w=0): return self._b.seek(o, w)
    def tell(self): return self._b.tell()
    def readinto(self, buf):
        if self._dead:
            raise ValueError("I/O operation on closed file")
        # Deterministic mid-decode fault: do not rely on "close then hope the next
        # stream.read() still needs the source". rapidgzip may already hold a decoded
        # window large enough that one subsequent read() never touches the source
        # (observed as RAISED None on macOS / Python 3.14 CI).
        if self.fail_after is not None and self._served >= self.fail_after:
            self._dead = True
            self._b.close()
            raise ValueError("I/O operation on closed file")
        n = self._b.readinto(buf)
        if n:
            self._served += n
        return n
    def kill(self):
        self._dead = True
        self._b.close()   # close the underlying source underneath the accelerator
"""

_UNTRAPPED = _SETUP + textwrap.dedent(
    """
    src = Src(full)
    rf = rapidgzip.open(src, parallelization=0)   # raw rapidgzip, no archivey trap
    rf.read(1024)
    src.kill()
    try:
        rf.read()
    except Exception:
        pass
    try:
        rf.close()
    except Exception:
        pass
    print("NO_ABORT")
    """
)

_TRAPPED = _SETUP + textwrap.dedent(
    """
    from archivey.internal.config import AcceleratorMode, StreamConfig
    from archivey.internal.streams.codecs.rapidgzip_select import _open_rapidgzip
    src = Src(full)
    # Fault on the next source pull after ~64 KiB compressed — well after open/header,
    # well before the 20 MiB payload is exhausted, so decode must observe it.
    src.fail_after = 64 * 1024
    on = StreamConfig(seekable=True, use_rapidgzip=AcceleratorMode.ON)
    stream = _open_rapidgzip(src, "gzip", on)  # archivey: rapidgzip in a child process
    raised = None
    try:
        stream.read()
    except BaseException as exc:
        raised = type(exc).__name__
    stream.close()
    print("RAISED", raised)
    print("NO_ABORT")
    """
)


def _run(script: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, timeout=60, check=False
    )


def test_bug3_untrapped_raw_rapidgzip_aborts() -> None:
    """Baseline: the raw accelerator over a source closed underneath it aborts the process.

    This is the hazard archivey contains; if a future rapidgzip stops aborting here, this
    assertion flips and the trap can be reconsidered.
    """
    pytest.importorskip("rapidgzip")
    proc = _run(_UNTRAPPED)
    # SIGABRT: negative return code (killed by signal) or the 134 convention; and it never
    # reached the NO_ABORT print.
    assert proc.returncode != 0, proc.stdout
    assert b"NO_ABORT" not in proc.stdout


def test_bug3_trapped_archivey_survives_and_reraises() -> None:
    """archivey's trap: the same fault surfaces as a Python exception, no process abort."""
    pytest.importorskip("rapidgzip")
    proc = _run(_TRAPPED)
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
    assert b"NO_ABORT" in proc.stdout
    # A source-side fault was re-raised on the archivey side (not swallowed, not an abort).
    assert b"RAISED" in proc.stdout and b"RAISED None" not in proc.stdout
