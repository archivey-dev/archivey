"""Canary for the accelerator interpreter-shutdown abort and archivey's guard against it
(see ``dev-docs/investigations/rapidgzip-upstream-report.md`` §6). archivey runs rapidgzip
only in its decoder process (``rapidgzip_worker.py``), which closes the stream before it
exits and then skips interpreter finalization (``os._exit``).

archivey uses a single accelerator library, ``rapidgzip``, for both gzip (``RapidgzipFile``) and
bzip2 (its bundled ``IndexedBzip2File``) — deliberately NOT the separate ``indexed_bzip2``
package, because loading both into one process corrupts the heap and aborts on macOS (see
``test_archivey_uses_single_accelerator_library`` below and
``dev-docs/investigations/rapidgzip-upstream-report.md`` §7).

The accelerator spawns C++ worker threads. A thread still running when the interpreter finalizes
trips the library's guard ("Detected Python finalization from running … thread") and aborts the
process with SIGABRT. Critically, ``join_threads()`` does **not** stop the thread — only
``close()`` does — so a stream must be *closed*, not merely joined, before it is freed.

The matrix below crosses both codecs (each via rapidgzip) × intact / corrupt / truncated input ×
cleanup strategy, each in its own subprocess (so any abort is contained), and is emitted as a
warning for the record:

- ``closed`` — ``read()`` then ``join_threads()`` + ``close()`` during the run.
- ``cycle_gc`` / ``unclosed`` — the **raw** object finalized by the cyclic GC mid-run, or left to
  interpreter shutdown, with **no** close. These abort on every platform measured — the
  underlying-library behaviour archivey works around.
- ``guard_cycle_gc`` / ``guard_unclosed`` — the same two finalization paths but wrapped in a
  ``weakref.finalize`` guard, which **closes** the raw object when the wrapper is reclaimed.
  These exit cleanly. archivey's in-process wrapper had this guard; it is kept here as the
  record that closing is what stops the thread.

Asserted invariants: ``closed`` and the two ``guard_*`` paths exit cleanly on every platform (the
cleanup contract archivey depends on), while the raw ``cycle_gc`` / ``unclosed`` paths abort (the
upstream behaviour; if a future release stops aborting there, the assertion flips, signalling the
worker's close before it exits is no longer load-bearing).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import warnings

import pytest

# (codec label, rapidgzip opener) — both codecs are driven through rapidgzip alone.
_ACCELERATORS = [
    ("gzip", "rapidgzip.RapidgzipFile"),
    ("bzip2", "rapidgzip.IndexedBzip2File"),
]
_VARIANTS = ["intact", "corrupt", "truncated"]
# Cleanup strategies, in increasing "let the runtime do it" order:
#   closed         — read, then close() during the run (what archivey does; close() alone stops
#                    the worker thread — an explicit join_threads() first is not needed).
#   cycle_gc       — raw object dropped into a reference cycle and reclaimed by the cyclic GC
#                    mid-run (the mechanism a corrupt/truncated read's exception traceback
#                    creates), with no close.
#   guard_cycle_gc — same, but wrapped in archivey's weakref.finalize close guard.
#   unclosed       — raw object finalized at interpreter shutdown, with no close.
#   guard_unclosed — same, but wrapped in archivey's weakref.finalize close guard.
_CLEANUPS = ["closed", "cycle_gc", "guard_cycle_gc", "unclosed", "guard_unclosed"]


def _script(fmt: str, opener: str, variant: str, cleanup: str) -> str:
    """A minimal standalone program that uses the rapidgzip accelerator *directly* (no archivey)."""
    return textwrap.dedent(
        f"""
        import gc, io, gzip, bz2, weakref
        import rapidgzip

        payload = b'canary payload ' * 4000
        data = bytearray(gzip.compress(payload) if {fmt!r} == 'gzip' else bz2.compress(payload))
        if {variant!r} == 'corrupt':
            data[15:40] = b'\\x00' * 25
        elif {variant!r} == 'truncated':
            data = data[: len(data) // 2]

        cleanup = {cleanup!r}

        # The guard archivey's in-process wrapper used: weakref.finalize holds the raw
        # object strongly and CLOSES it exactly once, when the wrapper is collected (cyclically or
        # not) or at interpreter exit — whichever comes first. close() (not join_threads()) is
        # what stops the worker thread, and is sufficient on its own.
        def _close(inner):
            try:
                inner.close()
            except Exception:
                pass

        class Guard:
            def __init__(self, inner):
                self._inner = inner
                self._fin = weakref.finalize(self, _close, inner)

        raw = {opener}(io.BytesIO(bytes(data)), parallelization=0)
        if cleanup.startswith('guard_'):
            obj = Guard(raw)
            del raw            # only the guard (and its finalize) reference the raw object
            reader = obj._inner
        else:
            obj = raw
            reader = raw
        try:
            reader.read()
        except Exception:
            pass  # corrupt/truncated reads may raise; shutdown behaviour is what we measure
        del reader

        if cleanup == 'closed':
            obj.close()  # close() alone stops the worker thread (no explicit join needed)
        elif cleanup in ('cycle_gc', 'guard_cycle_gc'):
            # Make `obj` reachable only through a reference cycle, then reclaim it via the cyclic
            # collector during the run (not at shutdown). For the raw object this detaches the
            # worker thread; for the guarded object the finalize must still close it.
            box = []
            box.append(box)
            box.append(obj)
            del obj
            gc.collect()
        # 'unclosed' / 'guard_unclosed': leave `obj` referenced so it is finalized at shutdown.
        """
    )


def _run(fmt: str, opener: str, variant: str, cleanup: str) -> int:
    """Run one scenario in a subprocess; return its exit code (negative == killed by signal)."""
    proc = subprocess.run(
        [sys.executable, "-c", _script(fmt, opener, variant, cleanup)],
        capture_output=True,
        timeout=30,
        check=False,
    )
    return proc.returncode


@pytest.mark.parametrize(
    ("fmt", "opener"), _ACCELERATORS, ids=[f for f, _ in _ACCELERATORS]
)
def test_accelerator_shutdown_canary(fmt: str, opener: str) -> None:
    pytest.importorskip("rapidgzip")

    matrix = {
        f"{variant}/{cleanup}": _run(fmt, opener, variant, cleanup)
        for variant in _VARIANTS
        for cleanup in _CLEANUPS
    }
    warnings.warn(
        f"[accel-shutdown] rapidgzip {fmt} (platform={sys.platform}) exit codes: {matrix}",
        stacklevel=1,
    )

    # The measured behaviour is the same on every platform (the input variant is irrelevant);
    # only how the object is finalized matters.

    # 1. The cleanup contract archivey depends on: an accelerator object that is closed exits
    #    cleanly — whether close() is called explicitly during the run ('closed') or by the
    #    weakref.finalize guard when the wrapper is reclaimed by the cyclic GC ('guard_cycle_gc')
    #    or at interpreter exit ('guard_unclosed'). The decoder process relies on the same
    #    fact: it closes the stream before it exits, so if any of these abort, its cleanup
    #    is broken.
    for variant in _VARIANTS:
        for safe in ("closed", "guard_cycle_gc", "guard_unclosed"):
            rc = matrix[f"{variant}/{safe}"]
            assert rc == 0, (
                f"rapidgzip {fmt}: a {variant}/{safe} stream aborted on {sys.platform} (rc={rc}) "
                f"— the accelerator cleanup contract is broken (close() should stop the thread)."
            )

    # 2. The underlying-library behaviour, and the canary for it: a raw accelerator object
    #    finalized *without* being closed — reclaimed by the cyclic GC ('cycle_gc') or left to
    #    interpreter shutdown ('unclosed') — aborts with SIGABRT, because join_threads() alone
    #    does not stop the C++ worker thread; only close() does. This is why the decoder
    #    process closes (not merely joins) the stream before it exits. When a future release
    #    stops aborting here, these assertions fail — the signal that the close is no longer
    #    load-bearing. Asserted on the characterised platforms (Linux, macOS).
    if sys.platform in ("linux", "darwin"):
        for ungraceful in ("cycle_gc", "unclosed"):
            rc = matrix[f"intact/{ungraceful}"]
            assert rc != 0, (
                f"rapidgzip {fmt}: a raw (unguarded) {ungraceful} object now exits cleanly on "
                f"{sys.platform} (rc={rc}). The upstream interpreter-finalization abort may be "
                f"fixed — the decoder process's close before exit may no longer be needed."
            )


_SINGLE_LIBRARY_SCRIPT = """
import io, gzip, bz2, sys
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream

payload = b'single accelerator library ' * 4000
with open_codec_stream(
    Codec.GZIP, io.BytesIO(gzip.compress(payload)),
    config=StreamConfig(use_rapidgzip=AcceleratorMode.ON),
) as s:
    assert s.read() == payload
with open_codec_stream(
    Codec.BZIP2, io.BytesIO(bz2.compress(payload)),
    config=StreamConfig(use_indexed_bzip2=AcceleratorMode.ON),
) as s:
    assert s.read() == payload

# The crux: archivey must drive bzip2 through rapidgzip's bundled IndexedBzip2File, never the
# standalone indexed_bzip2 package. Loading both libraries corrupts the heap on macOS.
assert 'indexed_bzip2' not in sys.modules, 'archivey imported the conflicting indexed_bzip2 package'
print('OK')
"""


def test_archivey_uses_single_accelerator_library() -> None:
    """archivey decompresses gzip AND bzip2 via rapidgzip alone, never loading indexed_bzip2.

    Run in a subprocess that exercises both codecs and exits: on macOS this would abort with
    SIGABRT if archivey loaded both rapidgzip and indexed_bzip2 (the heap-corruption coexistence
    bug); it also asserts the standalone indexed_bzip2 package is never imported.
    """
    pytest.importorskip("rapidgzip")
    proc = subprocess.run(
        [sys.executable, "-c", _SINGLE_LIBRARY_SCRIPT],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, (
        f"using both codecs through archivey did not exit cleanly (rc={proc.returncode}): "
        f"{proc.stderr.decode('utf-8', 'replace')[-400:]}"
    )
    assert proc.stdout.decode("utf-8", "replace").strip().endswith("OK")
