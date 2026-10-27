"""Standalone reproduction for the macOS accelerator shutdown abort.

Background
----------
``rapidgzip`` / ``indexed_bzip2`` spawn C++ worker threads. A thread still running when the
interpreter finalizes trips their guard and aborts the process with SIGABRT (exit 134):

    Detected Python finalization from running rapidgzip thread.
    terminate called without an active exception

We found that ``join_threads()`` does NOT stop the thread — only ``close()`` does — and fixed
archivey's ``weakref.finalize`` guard to close the object (since removed: archivey now
runs rapidgzip only in a child process, ``rapidgzip_worker.py``). In isolation that
makes leaked / cyclically-collected / never-closed streams shut down cleanly on Linux
**and** macOS.

But the *full* test suite on macOS still aborts at shutdown once accelerators are active
in-process, even with that guard — and our isolated subprocess canary
(``tests/test_accelerator_shutdown.py``) does NOT reproduce it. This script exists to find the
difference on a real Mac.

What it does
------------
Runs a matrix of small scenarios, **each in its own subprocess** (so one crash doesn't stop the
run), and reports each subprocess's exit code and the tail of its stderr. Scenarios cover:

  * raw library vs. archivey's wrapped path (``open_codec_stream`` with the accelerator forced ON);
  * cleanup strategies: explicit close, rely-on-finalize, gc.collect(), exception-traceback cycle,
    partial read + backward seek, many streams (mixed closed/leaked);
  * the same scenarios **with a tracer active** (``--trace``), to mimic ``pytest-cov``'s
    ``sys.settrace`` C tracer — a prime suspect for why the suite aborts but a plain process does not.

Usage
-----
    python scripts/macos_accelerator_debug.py                  # full matrix, gzip + bzip2
    python scripts/macos_accelerator_debug.py --module gzip    # gzip (rapidgzip) only
    python scripts/macos_accelerator_debug.py --trace          # also run every scenario under a tracer
    coverage run scripts/macos_accelerator_debug.py --run arch_many   # one scenario under real coverage

Please paste the whole printed report into the issue / PR thread.
"""

from __future__ import annotations

import argparse
import bz2
import gc
import gzip
import io
import platform
import subprocess
import sys
import threading
from collections.abc import Callable

# --------------------------------------------------------------------------------------------
# Per-module knobs: how to build payloads and open streams, raw and via archivey.
# --------------------------------------------------------------------------------------------

PAYLOAD = (
    b"archivey macos accelerator debug payload " * 4000
)  # ~1.6 MiB, enough for threading


def _compress(module: str) -> bytes:
    return gzip.compress(PAYLOAD) if module == "gzip" else bz2.compress(PAYLOAD)


def _open_raw(module: str, data: bytes):
    """Open the raw accelerator object directly (no archivey)."""
    if module == "gzip":
        import rapidgzip

        return rapidgzip.open(io.BytesIO(data), parallelization=0)
    import indexed_bzip2

    return indexed_bzip2.open(io.BytesIO(data), parallelization=0)


def _open_archivey(module: str, data: bytes):
    """Open through archivey's full path (ArchiveStream -> the rapidgzip child), forced ON."""
    from archivey.internal.config import AcceleratorMode, StreamConfig
    from archivey.internal.streams.codecs import Codec, open_codec_stream

    if module == "gzip":
        config = StreamConfig(use_rapidgzip=AcceleratorMode.ON)
        codec = Codec.GZIP
    else:
        config = StreamConfig(use_indexed_bzip2=AcceleratorMode.ON)
        codec = Codec.BZIP2
    return open_codec_stream(codec, io.BytesIO(data), config=config)


# --------------------------------------------------------------------------------------------
# Scenarios. Each runs in its own subprocess and then lets the interpreter shut down naturally;
# the parent records the exit code. A clean scenario exits 0; a tripped guard exits 134 (-6).
#
# IMPORTANT: "leave it to shutdown" means the object must still be referenced *when the
# interpreter finalizes*. A function local is released when the function returns (its destructor
# runs while the interpreter is still alive — which closes/joins cleanly and proves nothing). So
# scenarios that test shutdown finalization stash their objects in this module-global list, which
# stays alive until the very end. Scenarios that test the *cyclic collector* instead build a
# reference cycle and call gc.collect() mid-run.
# --------------------------------------------------------------------------------------------

_LEAKED: list[object] = []  # module-global: survives until interpreter shutdown


def _scn_raw_close(module: str) -> None:
    f = _open_raw(module, _compress(module))
    f.read()
    f.close()


def _scn_raw_noclose(module: str) -> None:
    f = _open_raw(module, _compress(module))
    f.read()
    _LEAKED.append(f)  # alive at interpreter shutdown, never closed


def _scn_raw_cycle(module: str) -> None:
    # Raw object reachable only through a reference cycle, reclaimed by the cyclic GC mid-run.
    f = _open_raw(module, _compress(module))
    f.read()
    box: list[object] = []
    box.append(box)
    box.append(f)
    del f
    gc.collect()


def _scn_arch_close(module: str) -> None:
    f = _open_archivey(module, _compress(module))
    f.read()
    f.close()


def _scn_arch_noclose(module: str) -> None:
    f = _open_archivey(module, _compress(module))
    f.read()
    _LEAKED.append(f)  # rely on the weakref.finalize guard at interpreter shutdown


def _scn_arch_cycle(module: str) -> None:
    # Wrapper reachable only through a reference cycle, reclaimed by the cyclic GC mid-run.
    f = _open_archivey(module, _compress(module))
    f.read()
    box: list[object] = []
    box.append(box)
    box.append(f)
    del f
    gc.collect()


def _scn_arch_cycle_exc(module: str) -> None:
    # Corrupt input: the read raises; the exception's traceback captures the stream in a cycle
    # (the real-world path). Retain the exception to shutdown so the wrapper is alive in a cycle.
    data = bytearray(_compress(module))
    data[15:40] = b"\x00" * 25
    f = _open_archivey(module, bytes(data))
    try:
        f.read()
    except Exception as exc:  # noqa: BLE001 - retained to keep the traceback cycle alive
        _LEAKED.append(exc)  # exc.__traceback__ -> frame -> f
    else:
        _LEAKED.append(f)


def _scn_arch_seek(module: str) -> None:
    # Random-access pattern: partial read + backward seek, then leave unclosed. Exercises the
    # accelerator's seeking/index threads, which a plain full-read does not.
    f = _open_archivey(module, _compress(module))
    f.read(1000)
    try:
        f.seek(0)
        f.read(2000)
        f.seek(len(PAYLOAD) // 2)
        f.read(1000)
    except Exception:  # noqa: BLE001, S110
        pass
    _LEAKED.append(f)


def _scn_arch_many(module: str) -> None:
    # Many streams left unclosed (closest to a test suite that opens lots of archives).
    data = _compress(module)
    for _ in range(25):
        f = _open_archivey(module, data)
        f.read()
        _LEAKED.append(f)


def _scn_arch_many_mixed(module: str) -> None:
    data = _compress(module)
    for i in range(25):
        f = _open_archivey(module, data)
        f.read()
        if i % 2 == 0:
            f.close()  # half explicitly closed
        else:
            _LEAKED.append(f)  # half left to the guard at shutdown


SCENARIOS: dict[str, Callable[[str], None]] = {
    "raw_close": _scn_raw_close,
    "raw_noclose": _scn_raw_noclose,
    "raw_cycle": _scn_raw_cycle,
    "arch_close": _scn_arch_close,
    "arch_noclose": _scn_arch_noclose,
    "arch_cycle": _scn_arch_cycle,
    "arch_cycle_exc": _scn_arch_cycle_exc,
    "arch_seek": _scn_arch_seek,
    "arch_many": _scn_arch_many,
    "arch_many_mixed": _scn_arch_many_mixed,
}

_EXPECTATION = {
    "raw_close": "clean (close stops the thread)",
    "raw_noclose": "ABORT expected (raw, alive at shutdown, never closed)",
    "raw_cycle": "ABORT expected (raw, reclaimed by cyclic GC, never closed)",
    "arch_close": "clean (explicit close)",
    "arch_noclose": "clean IF the finalize guard closes at shutdown",
    "arch_cycle": "clean IF the guard closes on cyclic collection",
    "arch_cycle_exc": "clean IF the guard handles the exception-traceback cycle",
    "arch_seek": "clean IF close() stops seek/index threads too",
    "arch_many": "clean IF the guard scales to many leaked streams",
    "arch_many_mixed": "clean (mix of explicit close + guard)",
}


def _install_tracer() -> None:
    """Install a trivial tracer on this thread and all future threads, mimicking pytest-cov.

    coverage installs a C trace function via sys.settrace; tracing retains frame objects for the
    lifetime of tracebacks and can shift GC/finalization timing. This is a Python-level proxy for
    that effect. For the real thing, run a single scenario under ``coverage run`` (see --help).
    """

    def _tracer(frame, event, arg):
        return _tracer

    threading.settrace(_tracer)
    sys.settrace(_tracer)


def _run_one(name: str, module: str, trace: bool) -> None:
    """Execute a single scenario in this process, then return (interpreter shuts down after)."""
    if trace:
        _install_tracer()
    SCENARIOS[name](module)


def _spawn(name: str, module: str, trace: bool) -> tuple[int, str]:
    cmd = [sys.executable, __file__, "--run", name, "--module", module]
    if trace:
        cmd.append("--trace")
    proc = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
    stderr = proc.stderr.decode("utf-8", "replace").strip()
    # Keep only the interesting tail (the abort banner), not the whole traceback.
    tail = " | ".join(line for line in stderr.splitlines() if line.strip())[-300:]
    return proc.returncode, tail


def _print_env() -> None:
    print("=" * 90)
    print("ENVIRONMENT")
    print("-" * 90)
    print(f"platform        : {sys.platform}  ({platform.platform()})")
    print(f"machine         : {platform.machine()}")
    print(
        f"python          : {sys.version.split()[0]}  ({platform.python_implementation()})"
    )
    for mod in ("rapidgzip", "indexed_bzip2"):
        try:
            m = __import__(mod)
            print(f"{mod:<15} : {getattr(m, '__version__', '?')}")
        except Exception as exc:  # noqa: BLE001
            print(f"{mod:<15} : NOT INSTALLED ({exc})")
    print()


def _run_matrix(modules: list[str], trace_modes: list[bool]) -> int:
    overall_ok = True
    for module in modules:
        try:
            _open_raw(module, _compress(module)).close()
        except Exception as exc:  # noqa: BLE001
            print(f"SKIP {module}: accelerator not usable ({exc})\n")
            continue
        for trace in trace_modes:
            label = f"module={module}  tracer={'ON' if trace else 'off'}"
            print("=" * 90)
            print(f"SCENARIOS  ({label})")
            print("-" * 90)
            print(f"{'scenario':<18}{'exit':>6}  {'result':<9} expectation / note")
            for name in SCENARIOS:
                rc, tail = _spawn(name, module, trace)
                aborted = rc != 0
                result = "ABORT" if aborted else "clean"
                # raw_* aborting is expected; arch_* aborting is the bug we're hunting.
                unexpected = aborted and name.startswith("arch")
                overall_ok = overall_ok and not unexpected
                flag = "  <-- UNEXPECTED" if unexpected else ""
                print(f"{name:<18}{rc:>6}  {result:<9} {_EXPECTATION[name]}{flag}")
                if aborted and tail:
                    print(f"{'':<26}stderr: {tail}")
            print()
    print("=" * 90)
    if overall_ok:
        print(
            "RESULT: no archivey-path scenario aborted. If CI still aborts, try --trace and"
        )
        print(
            "        `coverage run scripts/macos_accelerator_debug.py --run arch_many` (real coverage)."
        )
    else:
        print(
            "RESULT: an archivey-path scenario aborted above (marked UNEXPECTED). That scenario is"
        )
        print(
            "        the minimal reproduction — note whether it only aborts with tracer=ON."
        )
    print("=" * 90)
    return 0 if overall_ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--module",
        choices=["gzip", "bz2"],
        help="limit to one accelerator (default: both)",
    )
    ap.add_argument(
        "--trace",
        action="store_true",
        help="install a sys.settrace tracer (mimics pytest-cov)",
    )
    ap.add_argument(
        "--run", metavar="SCENARIO", choices=list(SCENARIOS), help=argparse.SUPPRESS
    )
    args = ap.parse_args()

    if args.run is not None:
        # Child mode: run exactly one scenario, then let the interpreter shut down.
        _run_one(args.run, args.module or "gzip", args.trace)
        return 0

    # Driver mode.
    _print_env()
    modules = [args.module] if args.module else ["gzip", "bz2"]
    trace_modes = [False, True] if args.trace else [False]
    return _run_matrix(modules, trace_modes)


if __name__ == "__main__":
    sys.exit(main())
