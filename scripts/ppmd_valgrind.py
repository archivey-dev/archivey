#!/usr/bin/env python3
"""Deterministic valgrind gate for archivey's PPMd decoder.

Runs archivey's ``PpmdDecoder`` on truncated PPMd7 input under valgrind's memcheck
and fails on any memcheck error. It runs in the non-required ``PPMd native stress``
workflow (Linux). See ``dev-docs/known-issues.md``.

Scenarios
---------
* ``archivey-truncated`` — archivey ``PpmdDecoder``: truncated PPMd7 fed + flushed
  then disposed via ``__del__``. Expected **clean**.
* ``archivey-stream`` — same, driven through ``PpmdDecompressorStream`` so disposal
  runs the explicit ``close()`` path. Expected **clean**.

Usage
-----
::

    python scripts/ppmd_valgrind.py                       # all scenarios
    python scripts/ppmd_valgrind.py --scenario archivey-truncated
    python scripts/ppmd_valgrind.py --scenario all --cycles 8

Exit code is nonzero if valgrind reports any memcheck error. Requires ``valgrind`` on
PATH.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Highly compressible payload, so a small mid-stream cut leaves much undecoded.
_PREAMBLE = textwrap.dedent(
    """\
    import os, sys
    sys.path.insert(0, os.path.join({repo!r}, "src"))
    sys.path.insert(0, {repo!r})
    import pyppmd

    ORDER, MEM = 6, 1 << 20
    CONTENT = (b"the quick brown fox jumps over the lazy dog\\n" * 200)
    _e = pyppmd.Ppmd7Encoder(ORDER, MEM)
    PACKED = _e.encode(CONTENT) + _e.flush()
    CYCLES = int(os.environ.get("PPMD_VALGRIND_CYCLES", "6"))
    """
)

_SCENARIOS: dict[str, str] = {
    # archivey PpmdDecoder, truncated PPMd7, disposed via __del__.
    "archivey-truncated": _PREAMBLE
    + textwrap.dedent(
        """\
        from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecoder
        for _ in range(CYCLES):
            dec = PpmdDecoder(order=ORDER, mem_size=MEM, variant=7,
                              unpack_size=len(CONTENT), pack_size=len(PACKED))
            dec.feed(PACKED[: len(PACKED) // 2], len(CONTENT))
            try:
                dec.flush()
            except Exception:
                pass
            del dec
        print("ok", flush=True)
        """
    ),
    # archivey stream, disposal via the explicit close() path (context manager).
    "archivey-stream": _PREAMBLE
    + textwrap.dedent(
        """\
        import io
        from archivey.exceptions import TruncatedError
        from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
        for _ in range(CYCLES):
            with PpmdDecompressorStream(
                io.BytesIO(PACKED[: len(PACKED) // 2]),
                order=ORDER, mem_size=MEM, variant=7,
                unpack_size=len(CONTENT), pack_size=len(PACKED),
            ) as stream:
                try:
                    stream.read()
                except TruncatedError:
                    pass
        print("ok", flush=True)
        """
    ),
}

_ERROR_SUMMARY = re.compile(r"ERROR SUMMARY:\s+(\d+)\s+errors")


def _run_scenario(name: str, cycles: int, timeout: float) -> tuple[int, bool, str]:
    """Return (memcheck_error_count, body_ok, tail_of_output)."""
    script = _SCENARIOS[name]
    env = dict(os.environ)
    env["PPMD_VALGRIND_CYCLES"] = str(cycles)
    # Keep pymalloc (do NOT set PYTHONMALLOC=malloc): the decoder's output blocks are
    # large PyBytes that pymalloc routes to raw malloc, so valgrind already tracks
    # them; forcing libc malloc for every allocation instead floods the report with
    # CPython-interpreter false positives (measured ~984 errors on a clean run).
    with tempfile.TemporaryDirectory(prefix="ppmd-valgrind-") as tmp:
        driver = Path(tmp) / f"{name}.py"
        driver.write_text(script.format(repo=str(_REPO_ROOT)), encoding="utf-8")
        cmd = [
            "valgrind",
            "--error-exitcode=0",  # we parse ERROR SUMMARY ourselves
            "--num-callers=6",
            "--smc-check=all",
            sys.executable,
            str(driver),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    combined = (proc.stdout or "") + (proc.stderr or "")
    body_ok = any(line.strip() == "ok" for line in (proc.stdout or "").splitlines())
    match = _ERROR_SUMMARY.search(combined)
    errors = int(match.group(1)) if match else -1
    tail = "\n".join(combined.strip().splitlines()[-8:])
    return errors, body_ok, tail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=[*sorted(_SCENARIOS), "all", "archivey"],
        default="archivey",
        help="Scenario to run ('archivey' = both archivey scenarios; 'all' = every scenario).",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=6,
        help="Decode/dispose cycles per child (default 6).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=400.0,
        help="Per-scenario valgrind timeout (s).",
    )
    args = parser.parse_args(argv)

    if shutil.which("valgrind") is None:
        print("valgrind not found on PATH (apt-get install valgrind)", file=sys.stderr)
        return 2
    try:
        import pyppmd  # noqa: F401
    except ImportError:
        print("pyppmd is not installed (pip install 'pyppmd>=1.3.1')", file=sys.stderr)
        return 2

    if args.scenario == "all":
        names = sorted(_SCENARIOS)
    elif args.scenario == "archivey":
        names = ["archivey-truncated", "archivey-stream"]
    else:
        names = [args.scenario]

    failed = False
    print(f"ppmd_valgrind: scenarios={names} cycles={args.cycles}")
    for name in names:
        errors, body_ok, tail = _run_scenario(name, args.cycles, args.timeout)
        # A scenario that never ran its body (import error, early crash, wrong env)
        # or produced no parseable valgrind summary is a failure regardless: a
        # "0 errors" from a body that never executed the repro is a false PASS.
        if not body_ok:
            status, scenario_failed = "FAIL (body did not run)", True
        elif errors < 0:
            status, scenario_failed = "FAIL (no valgrind summary)", True
        elif errors == 0:
            status, scenario_failed = "OK", False
        else:
            status, scenario_failed = "FAIL", True
        failed = failed or scenario_failed
        print(f"  {name:<20} memcheck_errors={errors:<6} {status}")
        if scenario_failed or errors != 0:
            print(textwrap.indent(tail, "      "))

    print()
    print("PASS" if not failed else "FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
