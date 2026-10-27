"""Does loading BOTH rapidgzip and indexed_bzip2 in one process corrupt the heap on macOS?

The full-suite macOS abort turned out NOT to be archivey leaving streams unclosed (the leak
tracer reports 0 un-closed streams). Instead it surfaces as an intermittent

    malloc: *** error for object 0x...: pointer being freed was not allocated

that appears only when BOTH ``rapidgzip`` and ``indexed_bzip2`` are importable in the same
process. Both are by the same author and statically bundle a large overlapping C++ core, so this
looks like a duplicate-symbol / allocator-mismatch collision between the two extension modules
(classic on macOS, where dyld coalesces weak C++ symbols across dylibs).

This script confirms that hypothesis with NO archivey, NO pytest, NO coverage involved. It runs
each scenario in its own subprocess, many times (the corruption is intermittent), and reports how
many runs crashed. Scenarios isolate import-only vs. use, and one library vs. both:

    uv run --with rapidgzip,indexed_bzip2 python scripts/dual_accelerator_repro.py
    uv run --with rapidgzip,indexed_bzip2 python scripts/dual_accelerator_repro.py 100   # more iters

If the ``both_*`` scenarios crash while the single-library controls never do, that confirms the
two libraries cannot safely coexist in one process — an upstream issue, not an archivey bug.
"""

from __future__ import annotations

import subprocess
import sys

ITERS = int(sys.argv[1]) if len(sys.argv) > 1 else 40

# Each scenario is a self-contained program. The parent runs each ITERS times in fresh
# subprocesses and counts crashes (nonzero exit / malloc / abort).
_SCENARIOS: dict[str, str] = {
    # --- controls: a single library, imported and used. Expected: never crash. ---
    "gz_only_use": """
import io, gzip, rapidgzip
f = rapidgzip.open(io.BytesIO(gzip.compress(b'x'*200000)), parallelization=0)
f.read(); f.close()
""",
    "bz_only_use": """
import io, bz2, indexed_bzip2
f = indexed_bzip2.open(io.BytesIO(bz2.compress(b'x'*200000)), parallelization=0)
f.read(); f.close()
""",
    # --- both libraries importable in the same process ---
    "both_import_only": """
import rapidgzip, indexed_bzip2  # imported, never used
""",
    "both_use_gz": """
import io, gzip, rapidgzip, indexed_bzip2
f = rapidgzip.open(io.BytesIO(gzip.compress(b'x'*200000)), parallelization=0)
f.read(); f.close()
""",
    "both_use_bz": """
import io, bz2, rapidgzip, indexed_bzip2
f = indexed_bzip2.open(io.BytesIO(bz2.compress(b'x'*200000)), parallelization=0)
f.read(); f.close()
""",
    "both_use_both": """
import io, gzip, bz2, rapidgzip, indexed_bzip2
g = rapidgzip.open(io.BytesIO(gzip.compress(b'x'*200000)), parallelization=0)
g.read(); g.close()
b = indexed_bzip2.open(io.BytesIO(bz2.compress(b'x'*200000)), parallelization=0)
b.read(); b.close()
""",
    # --- THE FIX CANDIDATE: both codecs, but bzip2 goes through rapidgzip's bundled
    # IndexedBzip2File instead of the separate indexed_bzip2 package. Only ONE library is
    # loaded, so this should NEVER crash even though both gzip and bzip2 are decompressed. ---
    "fix_both_via_rapidgzip": """
import io, gzip, bz2, rapidgzip   # note: indexed_bzip2 is NOT imported
g = rapidgzip.RapidgzipFile(io.BytesIO(gzip.compress(b'x'*200000)), parallelization=0)
g.read(); g.close()
b = rapidgzip.IndexedBzip2File(io.BytesIO(bz2.compress(b'x'*200000)), parallelization=0)
b.read(); b.close()
""",
}

_CRASH_MARKERS = (
    "malloc",
    "pointer being freed",
    "terminating",
    "Detected Python finalization",
)


def _run(name: str, code: str) -> tuple[int, int, str]:
    crashes = 0
    sample = ""
    for _ in range(ITERS):
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, timeout=60, check=False
        )
        err = proc.stderr.decode("utf-8", "replace")
        crashed = proc.returncode != 0 or any(m in err for m in _CRASH_MARKERS)
        if crashed:
            crashes += 1
            if not sample:
                sample = " | ".join(ln for ln in err.splitlines() if ln.strip())[:200]
    return ITERS, crashes, sample


def main() -> int:
    print("=" * 90)
    print(f"dual-accelerator coexistence repro  (iters per scenario: {ITERS})")
    for mod in ("rapidgzip", "indexed_bzip2"):
        try:
            m = __import__(mod)
            print(f"  {mod}: {getattr(m, '__version__', '?')}")
        except Exception as exc:  # noqa: BLE001
            print(
                f"  {mod}: NOT INSTALLED ({exc}) -- install both to exercise the 'both_*' cases"
            )
    print("=" * 90)
    print(f"{'scenario':<20}{'runs':>6}{'crashes':>9}   sample stderr")
    print("-" * 90)
    coexist_crash = False
    fix_crash = False
    for name, code in _SCENARIOS.items():
        runs, crashes, sample = _run(name, code)
        flag = ""
        if crashes and name.startswith("both_use"):
            coexist_crash = True
            flag = "  <-- coexistence crash (both libraries used)"
        elif crashes and name == "fix_both_via_rapidgzip":
            fix_crash = True
            flag = "  <-- FIX FAILED (rapidgzip-only still crashed!)"
        elif crashes:
            flag = "  <-- UNEXPECTED (single-library control crashed!)"
        print(f"{name:<24}{runs:>6}{crashes:>9}   {sample}{flag}")
    print("=" * 90)
    if coexist_crash and not fix_crash:
        print(
            "CONCLUSION: using both libraries crashes, but routing bzip2 through rapidgzip's"
        )
        print(
            "bundled IndexedBzip2File (fix_both_via_rapidgzip = 0 crashes) does NOT — so the fix"
        )
        print(
            "is to use rapidgzip for both gzip and bzip2 and never load indexed_bzip2."
        )
    elif coexist_crash and fix_crash:
        print(
            "CONCLUSION: both-libraries crashes AND the rapidgzip-only fix candidate also crashed."
        )
        print(
            "The fix is insufficient on this platform; fall back to disabling accelerators."
        )
    else:
        print(
            "No coexistence crash observed in this run. The corruption is intermittent; re-run"
        )
        print("with more iterations (e.g. `... dual_accelerator_repro.py 200`).")
    print("=" * 90)
    return 0


if __name__ == "__main__":
    sys.exit(main())
