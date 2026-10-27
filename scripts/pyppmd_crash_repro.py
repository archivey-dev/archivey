"""Minimal ``pyppmd`` native-abort repro (no archivey / no py7zr).

For upstream bug reports and version bisects. Only needs ``pyppmd`` (+ stdlib).

Background (pinned on Linux / pyppmd 1.3.1)
-------------------------------------------
Two distinct pure-``pyppmd`` abort families (fresh subprocesses, ~5 cycles each):

1. **after-eof unbounded** (``--mode extra-null``): sized decode to ``eof=True``,
   then ``decode(b"\\0", -1)`` or ``decode(b"", -1)``. ~40% crash / 5 cycles.
   Pre-EOF extra NUL (appended to input, or only while ``needs_input and not eof``)
   has been clean. Repeated after-eof on the *same* decoder object was also clean;
   the hot pattern is new decoder + after-eof unbounded, repeated in-process.

2. **overshoot** (``--mode overshoot``): ``decode(packed, -1)`` on PPMd7 (no end
   mark) with no second call. ~15–25% crash / 5 cycles. So **avoiding after-eof
   alone is not enough** — unbounded ``max_length=-1`` is itself crashy.

3. **oversized** (``--mode oversized``): sized ``decode(packed, len(data) + 65536)``
   — no ``-1`` anywhere. Crashes at a similar rate to overshoot, while ``+64`` /
   ``+4096`` over-requests stayed clean. The unsafe property is requesting
   materially more output than the stream's true remaining payload; the exact
   remaining size (py7zr-style) is the safe contract.

4. **spent-quiesce-nul** (``--mode spent-quiesce-nul``): archivey's teardown call
   order on a member that ended early. A sized decode of random input returns short
   at ``eof`` with all input fed; then ``decode(b"\\0", 1)``, at most 8 times, before
   the decoder is freed. That NUL is a decode after the model's end. See
   ``dev-docs/investigations/ppmd-native-investigation-results.md`` §K.4.

5. **nul-after-error** (``--mode nul-after-error``): the same input, with the NULs
   sent after a ``decode`` that raised ``ValueError``. archivey does not make this
   call (§K.4).

Controls that stayed at 0 crashes in 100-child soaks: sized-only decode;
pre-EOF ``decode(packed + b"\\0", size)``; skip after-eof when ``dec.eof``;
underfed sized decode then dealloc (``--mode underfed-sized``); bounded decode
of garbage after eof (``--mode hostile-tail``).

Leftover-state check: after a *surviving* after-eof call, subsequent *fresh*
sized-only decoders were clean (0/80) — not a simple “poison the next decoder”
bug for the happy path.

Root cause (pinpointed from the 1.2.0 → 1.3.1 sdist diff)
---------------------------------------------------------
The regression landed in pyppmd 1.3.0's ``ThreadDecoder.c`` rewrite (upstream
PR miurahr/pyppmd#126). ``Ppmd7Decoder.decode`` runs the symbol loop on a
worker thread; 1.3.0 removed the loop's input-empty stop condition, so with
``max_length=-1`` (an ``INT_MAX`` symbol budget in ``_ppmdmodule.c``) the
worker decodes past the true end of a PPMd7 stream (which has no end mark),
walking the native model on a desynchronized range coder — heap corruption.
The same release added an after-eof guard to the *cffi* backend only; the C
extension has none, so ``decode(b"\\0", -1)`` after eof restarts the runaway
worker on finished state (hottest trigger). Full write-up + suggested fixes:
``dev-docs/investigations/pyppmd-upstream-report.md``.

Examples::

    python scripts/pyppmd_crash_repro.py
    python scripts/pyppmd_crash_repro.py 50 --mode extra-null
    python scripts/pyppmd_crash_repro.py 40 --mode overshoot
    python scripts/pyppmd_crash_repro.py 40 --mode warmup-overshoot
    python scripts/pyppmd_crash_repro.py 30 --mode sized-safe
    python scripts/pyppmd_crash_repro.py 30 --mode pre-eof-null
    python scripts/pyppmd_crash_repro.py 30 --mode skip-after-eof
    python scripts/pyppmd_crash_repro.py 30 --mode underfed-sized
    python scripts/pyppmd_crash_repro.py 30 --mode hostile-tail
    python scripts/pyppmd_crash_repro.py 100 --mode spent-quiesce-nul --cycles 20
    python scripts/pyppmd_crash_repro.py 100 --mode nul-after-error --cycles 20
    PPMD_REPRO_VARIANT=7 python scripts/pyppmd_crash_repro.py 100 \\
        --mode nul-after-error --cycles 20

    pip install 'pyppmd==1.2.0'
    pip install 'pyppmd==1.3.1'

Exit code is non-zero if any child crashed or failed.
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

_MODES: dict[str, str] = {
    # Hottest pure-pyppmd abort trigger observed on 1.3.1 (~half of children).
    "extra-null": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = b"alpha\\n" * 100
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, len(data))
            assert out == data
            # Stream is already finished (eof=True, needs_input=False), but the
            # documented "extra NUL" API is easy to call unconditionally.
            # On pyppmd 1.3.1 this often returns thousands of garbage bytes and
            # intermittently aborts the process (malloc / SIGABRT / SIGSEGV).
            more = dec.decode(b"\\0", -1)
            _ = more
        print("ok", pyppmd.__version__, "cycles", cycles)
        """
    ),
    # Unbounded PPMd7 decode (no end mark) — lower crash rate, still pure pyppmd.
    "overshoot": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = (b"alpha\\n" * 100) + (bytes(range(64)) * 16)
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, -1)
            _ = out
        print("ok", pyppmd.__version__, "out_len", len(out), "want", len(data))
        """
    ),
    # Stdlib zlib/bz2/lzma warmup then unbounded PPMd7 (no archivey).
    "warmup-overshoot": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import bz2
        import lzma
        import zlib

        import pyppmd

        warm = b"alpha\\n" * 200 + bytes(range(256)) * 8
        for _ in range(5):
            zlib.decompress(zlib.compress(warm))
            bz2.decompress(bz2.compress(warm))
            lzma.decompress(lzma.compress(warm))

        ORDER, MEM = 6, 1 << 20
        data = (b"alpha\\n" * 100) + (bytes(range(64)) * 16)
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "3"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, -1)
            _ = out
        print("ok", pyppmd.__version__, "out_len", len(out))
        """
    ),
    # Control: sized decode only — should stay clean.
    "sized-safe": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = (b"alpha\\n" * 100) + (bytes(range(64)) * 16)
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, len(data))
            assert out == data
        print("ok", pyppmd.__version__, "sized", len(data))
        """
    ),
    # Control: extra NUL only before EOF (appended to compressed input).
    "pre-eof-null": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = b"alpha\\n" * 100
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed + b"\\0", len(data))
            assert out == data
        print("ok", pyppmd.__version__, "pre-eof-null")
        """
    ),
    # Sized decode whose budget exceeds the true payload by 64 KiB — crashes WITHOUT
    # any max_length=-1. Small over-requests (+64, +4096) stayed clean in 20-child
    # soaks; +65536 crashed 13/20. The unsafe property is requesting materially more
    # output than the stream can produce, not the -1 sentinel itself.
    "oversized": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = (b"alpha\\n" * 100) + (bytes(range(64)) * 16)
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, len(data) + 65536)
            assert out[: len(data)] == data
        print("ok", pyppmd.__version__, "oversized")
        """
    ),
    # Control: sized decode with only half the input, then dealloc — the worker
    # thread is blocked mid-valid-stream awaiting input when Ppmd7T_Free runs.
    # Models truncated input / early close under archivey's bounded-decode scheme.
    "underfed-sized": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = (b"alpha\\n" * 2000) + (bytes(range(64)) * 256)
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed[: len(packed) // 2], len(data))
            assert len(out) < len(data)
            del dec  # teardown with the decode worker blocked awaiting input
        print("ok", pyppmd.__version__, "underfed-sized")
        """
    ),
    # Control: bounded decode of garbage bytes after genuine eof — models a
    # hostile container header that inflates unpack_size past the true payload.
    "hostile-tail": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = b"alpha\\n" * 100
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for i in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, len(data))
            assert out == data
            tail = bytes((i * 37 + j) % 256 for j in range(64))
            extra = dec.decode(tail, 4096)  # bounded — unbounded here crashes
            _ = extra
        print("ok", pyppmd.__version__, "hostile-tail")
        """
    ),
    # Control: would-be after-eof path, but skipped because eof is set.
    "skip-after-eof": textwrap.dedent(
        """\
        import faulthandler
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM = 6, 1 << 20
        data = b"alpha\\n" * 100
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        for _ in range(cycles):
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = dec.decode(packed, len(data))
            assert out == data and dec.eof
            if not dec.eof:
                _ = dec.decode(b"\\0", -1)
        print("ok", pyppmd.__version__, "skipped-after-eof")
        """
    ),
    # archivey's teardown on a spent payload (``PpmdDecoder._quiesce_worker``): random
    # input fed whole, a sized request it cannot fill, a short return at eof, then
    # single-symbol NULs before the free. PPMd8 by default; PPMD_REPRO_VARIANT=7 for
    # PPMd7. The seed differs per child and is printed, so a crash can be replayed
    # with PPMD_REPRO_SEED.
    "spent-quiesce-nul": textwrap.dedent(
        """\
        import faulthandler
        import random
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM, SIZE = 6, 16 << 20, 65536
        variant = int(os.environ.get("PPMD_REPRO_VARIANT", "8"))
        seed = int(os.environ.get("PPMD_REPRO_SEED", str(os.getpid() * 1000)))
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        print("seed", seed, file=sys.stderr, flush=True)
        after_eof = 0
        for cycle in range(cycles):
            data = b"\\0" + random.Random(seed + cycle).randbytes(SIZE - 1)
            if variant == 8:
                dec = pyppmd.Ppmd8Decoder(ORDER, MEM, 0)
            else:
                dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            try:
                out = dec.decode(data, 16 * SIZE)
            except ValueError:
                continue  # pyppmd reported the corruption; nothing is parked
            if len(out) == 16 * SIZE or not dec.eof:
                continue  # not the spent-payload state
            for _ in range(8):  # _PPMD_QUIESCE_MAX_CALLS
                after_eof += dec.eof
                if dec.decode(b"\\0", 1):
                    break
            del dec
        print("ok", pyppmd.__version__, "nul-after-eof", after_eof)
        """
    ),
    # The same input, but the NULs follow a decode that raised ValueError ("Corrupted
    # input data"). archivey does not make this call: after the error pyppmd reports
    # eof=True, and _quiesce_worker returns without decoding. Kept as the measured
    # pyppmd defect. Seed and variant as in spent-quiesce-nul.
    "nul-after-error": textwrap.dedent(
        """\
        import faulthandler
        import random
        import sys

        faulthandler.enable(all_threads=True, file=sys.stderr)

        import pyppmd

        ORDER, MEM, SIZE = 6, 16 << 20, 65536
        variant = int(os.environ.get("PPMD_REPRO_VARIANT", "8"))
        seed = int(os.environ.get("PPMD_REPRO_SEED", str(os.getpid() * 1000)))
        cycles = int(os.environ.get("PPMD_REPRO_CYCLES", "5"))
        print("seed", seed, file=sys.stderr, flush=True)
        errors = 0
        for cycle in range(cycles):
            data = b"\\0" + random.Random(seed + cycle).randbytes(SIZE - 1)
            if variant == 8:
                dec = pyppmd.Ppmd8Decoder(ORDER, MEM, 0)
            else:
                dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            try:
                dec.decode(data, 16 * SIZE)
                continue  # no error: not this call order
            except ValueError:
                errors += 1
            for _ in range(8):
                try:
                    if dec.decode(b"\\0", 1):
                        break
                except ValueError:
                    break
            del dec
        print("ok", pyppmd.__version__, "nul-after-error", errors)
        """
    ),
}


def _format_rc(returncode: int) -> str:
    unsigned = returncode & 0xFFFFFFFF
    ntstatus = {
        0xC0000005: "STATUS_ACCESS_VIOLATION",
        0xC0000374: "STATUS_HEAP_CORRUPTION",
        0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    }
    if returncode < 0 or returncode > 255:
        name = ntstatus.get(unsigned)
        if name is not None:
            return f"0x{unsigned:08X} ({name}); signed={returncode}"
        if -64 < returncode < 0:
            return f"{returncode} (likely signal {-returncode})"
        return f"0x{unsigned:08X}; signed={returncode}"
    return str(returncode)


def _is_crash(returncode: int) -> bool:
    unsigned = returncode & 0xFFFFFFFF
    return (
        returncode < 0
        or returncode > 255
        or unsigned
        in {
            0xC0000005,
            0xC0000374,
            0xC0000409,
        }
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "iterations",
        nargs="?",
        type=int,
        default=int(os.environ.get("PPMD_REPRO_ITERS", "30")),
        help="Fresh subprocesses to run (default: 30)",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(_MODES),
        default="extra-null",
        help="Repro scenario (default: extra-null, hottest pure-pyppmd abort)",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=5,
        help="Encode/decode cycles inside each child (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Per-child timeout in seconds (default: 60)",
    )
    args = parser.parse_args(argv)

    try:
        import pyppmd
    except ImportError:
        print("pyppmd is not installed (pip install pyppmd)", file=sys.stderr)
        return 2

    child_src = "import os\n" + _MODES[args.mode]
    print(
        f"pyppmd crash repro: mode={args.mode!r} iters={args.iterations} "
        f"cycles/child={args.cycles} pyppmd={pyppmd.__version__} "
        f"python={sys.version.split()[0]} platform={platform.platform()!r}"
    )

    crashes = 0
    failures = 0
    passes = 0
    env = os.environ.copy()
    env["PPMD_REPRO_CYCLES"] = str(args.cycles)

    with tempfile.TemporaryDirectory(prefix="pyppmd-crash-repro-") as tmp:
        root = Path(tmp)
        for i in range(1, args.iterations + 1):
            driver = root / f"child_{i:04d}.py"
            driver.write_text(child_src, encoding="utf-8")
            try:
                proc = subprocess.run(
                    [sys.executable, "-u", str(driver)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    timeout=args.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                failures += 1
                print(f"  [{i}/{args.iterations}] TIMEOUT")
                continue
            if proc.returncode == 0:
                passes += 1
                print(f"  [{i}/{args.iterations}] ok")
                continue
            if _is_crash(proc.returncode):
                crashes += 1
                kind = "CRASH"
            else:
                failures += 1
                kind = "FAIL"
            print(f"  [{i}/{args.iterations}] {kind} rc={_format_rc(proc.returncode)}")
            if proc.stderr.strip():
                tail = "\n".join(proc.stderr.strip().splitlines()[-6:])
                print(textwrap.indent(tail, "    "))

    print()
    print(
        f"summary: mode={args.mode} pyppmd={pyppmd.__version__} "
        f"passes={passes}/{args.iterations} crashes={crashes} failures={failures}"
    )
    if crashes:
        print(
            "Native abort reproduced. Useful for a pyppmd issue: include this "
            "script, mode, version, OS/Python, and the crash rate above."
        )
    return 1 if crashes or failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
