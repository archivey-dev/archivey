"""Characterize rapidgzip (and IndexedBzip2File) truncation/corruption behaviour.

Builds gzip/bzip2 fixtures of several shapes, truncates at every byte offset (or a
dense stratified sample for large fixtures), and records whether rapidgzip raises,
returns short/zero silently, returns full output, hangs, or crashes — compared to
stdlib ``gzip`` / ``bz2`` as the oracle.

Path sources only (upstream Bug 3: Python file-object sources can ``terminate()``).
Each cut runs in a fresh subprocess with a wall-clock timeout (C++ hang risk).
Accelerators are forced ON; this is intentionally separate from mutation/Atheris
(which keep accelerators off).

Usage::

    uv run --extra seekable python scripts/rapidgzip_truncation_sweep.py
    uv run --extra seekable python scripts/rapidgzip_truncation_sweep.py --codec gzip
    uv run --extra seekable python scripts/rapidgzip_truncation_sweep.py \\
        --json-out /tmp/rgz-trunc.json --md-out /tmp/rgz-trunc.md

Platform note: run on Linux *and* macOS (arm64) — see change
``rapidgzip-truncation-investigation`` task 1.3.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import json
import platform
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

# Wall-clock budget per cut. Crafted truncations can busy-loop in C++ threads.
DEFAULT_TIMEOUT_S = 5.0

# Gzip magic + CM=deflate + FLG=0 + MTIME=0 + XFL=0 + OS=255 → bare 10-byte header.
_GZIP_HEADER_ONLY = bytes.fromhex("1f8b08000000000000ff")


@dataclass(frozen=True)
class Fixture:
    name: str
    codec: str  # "gzip" | "bzip2"
    data: bytes
    expected_payload: bytes | None  # None ⇒ incomplete / not fully decodable
    note: str = ""


@dataclass
class CutResult:
    fixture: str
    codec: str
    cut: int
    size: int
    backend: str  # rapidgzip | stdlib | indexed_bzip2 | stdlib_bz2
    parallelization: int | None
    outcome: str  # raise | silent_zero | silent_short | full | timeout | crash | error
    out_len: int | None
    expected_len: int | None
    exc_type: str | None
    exc_text: str | None
    elapsed_ms: float
    returncode: int | None


def _gzip_multi_block(payload: bytes) -> bytes:
    """Build a single-member gzip with multiple deflate blocks via Z_FULL_FLUSH."""
    import zlib

    comp = zlib.compressobj(
        level=6, method=zlib.DEFLATED, wbits=-zlib.MAX_WBITS, memLevel=8
    )
    body = bytearray()
    # Split into several chunks so each FULL_FLUSH yields a separate block.
    chunk = max(1, len(payload) // 4)
    for i in range(0, len(payload), chunk):
        body.extend(comp.compress(payload[i : i + chunk]))
        body.extend(comp.flush(zlib.Z_FULL_FLUSH))
    body.extend(comp.flush())
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    isize = len(payload) & 0xFFFFFFFF
    header = _GZIP_HEADER_ONLY  # FLG=0, no extras
    trailer = struct.pack("<II", crc, isize)
    return header + bytes(body) + trailer


def build_gzip_fixtures() -> list[Fixture]:
    empty = b""
    tiny = b"x"
    small = b"hello world"
    medium = b"abcdefghijklmnopqrstuvwxyz" * 40  # ~1 KiB
    large = b"The quick brown fox jumps over the lazy dog.\n" * 800  # ~36 KiB
    multi_a = gzip.compress(b"member-one-payload")
    multi_b = gzip.compress(b"member-two-payload-longer")
    return [
        Fixture("gz_empty", "gzip", gzip.compress(empty), empty, "empty payload"),
        Fixture("gz_tiny", "gzip", gzip.compress(tiny), tiny, "< 1 block"),
        Fixture("gz_small", "gzip", gzip.compress(small), small, "< 1 block"),
        Fixture(
            "gz_medium", "gzip", gzip.compress(medium), medium, "single block ~1KiB"
        ),
        Fixture(
            "gz_large",
            "gzip",
            gzip.compress(large),
            large,
            "single-member larger payload",
        ),
        Fixture(
            "gz_multiblock",
            "gzip",
            _gzip_multi_block(medium),
            medium,
            "single member, multiple deflate blocks (Z_FULL_FLUSH)",
        ),
        Fixture(
            "gz_multimember",
            "gzip",
            multi_a + multi_b,
            b"member-one-payload" + b"member-two-payload-longer",
            "concatenated two-member gzip",
        ),
        Fixture(
            "gz_header_only_10",
            "gzip",
            _GZIP_HEADER_ONLY,
            None,
            "bare 10-byte gzip header, no deflate/trailer (maintainer silent case)",
        ),
        Fixture(
            "gz_header_plus_1",
            "gzip",
            _GZIP_HEADER_ONLY + b"\x00",
            None,
            "header + 1 byte of would-be deflate",
        ),
        Fixture(
            "gz_header_plus_8",
            "gzip",
            _GZIP_HEADER_ONLY + b"\x00" * 8,
            None,
            "header + 8 bytes (still no valid trailer)",
        ),
    ]


def build_bzip2_fixtures() -> list[Fixture]:
    empty = b""
    tiny = b"x"
    small = b"hello world"
    medium = b"abcdefghijklmnopqrstuvwxyz" * 40
    large = b"The quick brown fox jumps over the lazy dog.\n" * 800
    return [
        Fixture("bz_empty", "bzip2", bz2.compress(empty), empty, "empty payload"),
        Fixture("bz_tiny", "bzip2", bz2.compress(tiny), tiny, "tiny"),
        Fixture("bz_small", "bzip2", bz2.compress(small), small, "small"),
        Fixture("bz_medium", "bzip2", bz2.compress(medium), medium, "~1 KiB"),
        Fixture("bz_large", "bzip2", bz2.compress(large), large, "~36 KiB"),
    ]


def _cut_offsets(size: int, dense_limit: int) -> list[int]:
    """Every offset for small files; stratified sample for larger ones.

    Always includes 0, 1, size-1, size (full file), and every offset in 0..size
    when size <= dense_limit. For larger files, samples every ``stride`` bytes plus
    the first/last dense_limit//4 offsets.
    """
    if size <= dense_limit:
        return list(range(size + 1))
    edge = max(8, dense_limit // 4)
    stride = max(1, size // dense_limit)
    offsets = set(range(edge + 1))
    offsets.update(range(max(0, size - edge), size + 1))
    offsets.update(range(0, size + 1, stride))
    # Around gzip header boundary (10) and trailer (last 8 bytes) when relevant.
    for special in (8, 9, 10, 11, 12, 16, 17, 18, 19, 20):
        if 0 <= special <= size:
            offsets.add(special)
    return sorted(offsets)


_WORKER = textwrap.dedent(
    r"""
    import sys, json
    path, codec, backend, parallelization = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    parallelization = None if parallelization == "none" else int(parallelization)
    out = {"outcome": "error", "out_len": None, "exc_type": None, "exc_text": None}
    try:
        if backend == "rapidgzip":
            import rapidgzip
            f = rapidgzip.open(path, parallelization=parallelization)
        elif backend == "indexed_bzip2":
            import rapidgzip
            f = rapidgzip.IndexedBzip2File(path, parallelization=parallelization)
        elif backend == "stdlib":
            import gzip
            f = gzip.open(path, "rb")
        elif backend == "stdlib_bz2":
            import bz2
            f = bz2.open(path, "rb")
        else:
            raise SystemExit(f"unknown backend {backend}")
        try:
            data = f.read()
        finally:
            try:
                f.close()
            except Exception:
                pass
        out["outcome"] = "ok"
        out["out_len"] = len(data)
    except BaseException as exc:
        out["outcome"] = "raise"
        out["exc_type"] = type(exc).__name__
        out["exc_text"] = str(exc)[:500]
    sys.stdout.write(json.dumps(out))
    """
)


def _run_cut(
    path: Path,
    *,
    codec: str,
    backend: str,
    parallelization: int | None,
    timeout_s: float,
) -> tuple[str, int | None, str | None, str | None, float, int | None]:
    """Return (outcome, out_len, exc_type, exc_text, elapsed_ms, returncode)."""
    par = "none" if parallelization is None else str(parallelization)
    cmd = [sys.executable, "-c", _WORKER, str(path), codec, backend, par]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        elapsed = (time.perf_counter() - t0) * 1000
        return "timeout", None, None, None, elapsed, None
    elapsed = (time.perf_counter() - t0) * 1000
    if proc.returncode != 0 and not proc.stdout.strip():
        # Abort / segfault / non-JSON crash.
        stderr = (proc.stderr or "")[:300]
        return (
            "crash",
            None,
            None,
            stderr or f"rc={proc.returncode}",
            elapsed,
            proc.returncode,
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return (
            "crash",
            None,
            None,
            (proc.stdout + proc.stderr)[:300],
            elapsed,
            proc.returncode,
        )
    if payload["outcome"] == "raise":
        return (
            "raise",
            None,
            payload.get("exc_type"),
            payload.get("exc_text"),
            elapsed,
            proc.returncode,
        )
    return "ok", payload.get("out_len"), None, None, elapsed, proc.returncode


def _classify(
    raw_outcome: str,
    out_len: int | None,
    expected_len: int | None,
) -> str:
    if raw_outcome in {"raise", "timeout", "crash", "error"}:
        return raw_outcome
    assert raw_outcome == "ok"
    if expected_len is None:
        # Incomplete fixture: any successful read is a silent acceptance of bad input.
        if out_len == 0:
            return "silent_zero"
        return "silent_short"
    if out_len == expected_len:
        return "full"
    if out_len == 0:
        return "silent_zero"
    if out_len is not None and out_len < expected_len:
        return "silent_short"
    return "error"


def sweep_fixture(
    fixture: Fixture,
    *,
    dense_limit: int,
    timeout_s: float,
    parallelizations: list[int | None],
    tmp: Path,
) -> list[CutResult]:
    results: list[CutResult] = []
    expected_len = (
        None if fixture.expected_payload is None else len(fixture.expected_payload)
    )
    offsets = _cut_offsets(len(fixture.data), dense_limit)

    if fixture.codec == "gzip":
        backends: list[tuple[str, int | None]] = [("stdlib", None)]
        for par in parallelizations:
            backends.append(("rapidgzip", par))
    else:
        backends = [("stdlib_bz2", None)]
        for par in parallelizations:
            backends.append(("indexed_bzip2", par))

    for cut in offsets:
        truncated = fixture.data[:cut]
        path = tmp / f"{fixture.name}.cut{cut}"
        path.write_bytes(truncated)
        for backend, par in backends:
            raw, out_len, exc_type, exc_text, elapsed, rc = _run_cut(
                path,
                codec=fixture.codec,
                backend=backend,
                parallelization=par,
                timeout_s=timeout_s,
            )
            outcome = _classify(
                raw,
                out_len,
                # For a proper prefix cut of a complete fixture, expected full output is
                # only achievable if the cut still contains a complete stream. Treat
                # "expected" as full length only for the uncut file; for cuts, any ok
                # read that isn't a raise is silent short/zero relative to full payload,
                # unless out_len equals full (shouldn't for real truncations).
                expected_len,
            )
            # Refine: for cuts of complete fixtures, "full" means recovered full payload
            # despite truncation (bad). For the uncut file, "full" is success.
            if cut < len(fixture.data) and outcome == "full":
                # Recovered full payload from a truncated file — treat as silent anomaly
                # only if expected was known; keep label "full" (surprising).
                pass
            if cut < len(fixture.data) and expected_len is not None and raw == "ok":
                if out_len == 0:
                    outcome = "silent_zero"
                elif out_len is not None and out_len < expected_len:
                    outcome = "silent_short"
                elif out_len == expected_len:
                    outcome = "full"  # unexpected: full payload from truncated input
            results.append(
                CutResult(
                    fixture=fixture.name,
                    codec=fixture.codec,
                    cut=cut,
                    size=len(fixture.data),
                    backend=backend,
                    parallelization=par,
                    outcome=outcome,
                    out_len=out_len,
                    expected_len=expected_len,
                    exc_type=exc_type,
                    exc_text=exc_text,
                    elapsed_ms=round(elapsed, 1),
                    returncode=rc,
                )
            )
        path.unlink(missing_ok=True)
    return results


def _summarize(results: list[CutResult]) -> dict:
    by_backend: dict[str, Counter] = {}
    silent: list[dict] = []
    timeouts: list[dict] = []
    crashes: list[dict] = []
    for r in results:
        key = (
            r.backend
            if r.parallelization is None
            else f"{r.backend}:par={r.parallelization}"
        )
        by_backend.setdefault(key, Counter())[r.outcome] += 1
        if r.outcome in {"silent_zero", "silent_short"} and r.backend in {
            "rapidgzip",
            "indexed_bzip2",
        }:
            silent.append(asdict(r))
        if r.outcome == "timeout" and r.backend in {"rapidgzip", "indexed_bzip2"}:
            timeouts.append(asdict(r))
        if r.outcome == "crash" and r.backend in {"rapidgzip", "indexed_bzip2"}:
            crashes.append(asdict(r))
    return {
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "counts_by_backend": {k: dict(v) for k, v in by_backend.items()},
        "silent_accelerator_cases": silent,
        "timeout_accelerator_cases": timeouts,
        "crash_accelerator_cases": crashes,
        "n_results": len(results),
    }


def _md_report(
    fixtures: list[Fixture],
    results: list[CutResult],
    summary: dict,
) -> str:
    lines: list[str] = []
    lines.append("# rapidgzip truncation sweep results")
    lines.append("")
    plat = summary["platform"]
    lines.append(
        f"Platform: **{plat['system']} {plat['machine']}** "
        f"(Python {plat['python']}, `{plat['platform']}`)"
    )
    lines.append("")
    lines.append("## Counts by backend")
    lines.append("")
    lines.append(
        "| backend | raise | silent_zero | silent_short | full | timeout | crash |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for backend, counts in sorted(summary["counts_by_backend"].items()):
        lines.append(
            "| {backend} | {raise_} | {sz} | {ss} | {full} | {to} | {cr} |".format(
                backend=backend,
                raise_=counts.get("raise", 0),
                sz=counts.get("silent_zero", 0),
                ss=counts.get("silent_short", 0),
                full=counts.get("full", 0),
                to=counts.get("timeout", 0),
                cr=counts.get("crash", 0),
            )
        )
    lines.append("")
    lines.append("## Silent accelerator cases (the interesting set)")
    lines.append("")
    silent = summary["silent_accelerator_cases"]
    if not silent:
        lines.append("_None observed._")
    else:
        lines.append(
            "| fixture | cut/size | backend | par | outcome | out_len | expected | exc |"
        )
        lines.append("| --- | --- | --- | --- | --- | ---: | ---: | --- |")
        for s in silent:
            lines.append(
                "| {fixture} | {cut}/{size} | {backend} | {par} | {outcome} | {out} | {exp} | {exc} |".format(
                    fixture=s["fixture"],
                    cut=s["cut"],
                    size=s["size"],
                    backend=s["backend"],
                    par=s["parallelization"],
                    outcome=s["outcome"],
                    out=s["out_len"],
                    exp=s["expected_len"],
                    exc=(s["exc_text"] or "")[:60].replace("|", "/"),
                )
            )
    lines.append("")
    lines.append("## Fixtures")
    lines.append("")
    lines.append("| name | codec | size | expected_payload | note |")
    lines.append("| --- | --- | ---: | ---: | --- |")
    for f in fixtures:
        exp = (
            "n/a (incomplete)"
            if f.expected_payload is None
            else str(len(f.expected_payload))
        )
        lines.append(f"| {f.name} | {f.codec} | {len(f.data)} | {exp} | {f.note} |")
    lines.append("")
    if summary["timeout_accelerator_cases"]:
        lines.append("## Timeouts")
        lines.append("")
        lines.append(
            f"{len(summary['timeout_accelerator_cases'])} accelerator timeout(s)."
        )
        lines.append("")
    if summary["crash_accelerator_cases"]:
        lines.append("## Crashes")
        lines.append("")
        lines.append(
            f"{len(summary['crash_accelerator_cases'])} accelerator crash(es)."
        )
        lines.append("")
    lines.append("## Per-fixture rapidgzip vs stdlib (gzip) / IndexedBzip2 vs bz2")
    lines.append("")
    for f in fixtures:
        lines.append(f"### {f.name}")
        lines.append("")
        fx = [r for r in results if r.fixture == f.name]
        # Pivot: for each cut, show accelerator outcomes vs stdlib.
        std_backend = "stdlib" if f.codec == "gzip" else "stdlib_bz2"
        accel_backend = "rapidgzip" if f.codec == "gzip" else "indexed_bzip2"
        cuts = sorted({r.cut for r in fx})
        lines.append("| cut | stdlib | rapidgzip/par=0 | notes |")
        lines.append("| ---: | --- | --- | --- |")
        # Cap table length for large fixtures: show silent/mismatch rows + edges.
        rows_emitted = 0
        max_rows = 40
        interesting_cuts = set()
        for r in fx:
            if r.backend == accel_backend and r.outcome not in {"raise", "full"}:
                interesting_cuts.add(r.cut)
            if r.backend == std_backend and r.outcome not in {"raise", "full"}:
                interesting_cuts.add(r.cut)
        show = sorted(
            set(cuts[:3])
            | set(cuts[-3:])
            | interesting_cuts
            | {c for c in cuts if c in {0, 1, 9, 10, 11, 17, 18}}
        )
        if len(show) > max_rows:
            show = show[:max_rows]
        for cut in show:
            std = next(
                (r for r in fx if r.cut == cut and r.backend == std_backend), None
            )
            accel = next(
                (
                    r
                    for r in fx
                    if r.cut == cut
                    and r.backend == accel_backend
                    and r.parallelization == 0
                ),
                None,
            )

            def _fmt(r: CutResult | None) -> str:
                if r is None:
                    return "—"
                if r.outcome == "raise":
                    return f"raise:{r.exc_type}"
                if r.outcome in {"silent_zero", "silent_short"}:
                    return f"**{r.outcome}**(len={r.out_len})"
                return r.outcome

            note = ""
            if accel and std and accel.outcome != std.outcome:
                if (
                    accel.outcome in {"silent_zero", "silent_short"}
                    and std.outcome == "raise"
                ):
                    note = "SILENT vs stdlib raise"
                elif accel.outcome == "raise" and std.outcome == "raise":
                    note = ""
                else:
                    note = f"diff ({std.outcome} vs {accel.outcome})"
            lines.append(f"| {cut} | {_fmt(std)} | {_fmt(accel)} | {note} |")
            rows_emitted += 1
        if len(cuts) > rows_emitted:
            lines.append(f"| … | _{len(cuts) - rows_emitted} cuts omitted_ | | |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--codec",
        choices=("gzip", "bzip2", "all"),
        default="all",
        help="Which codec family to sweep (default: all)",
    )
    parser.add_argument(
        "--dense-limit",
        type=int,
        default=256,
        help="Max fixture size for every-offset sweep (default: 256)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"Wall-clock timeout per cut in seconds (default: {DEFAULT_TIMEOUT_S})",
    )
    parser.add_argument(
        "--parallelization",
        default="0",
        help="Comma-separated rapidgzip parallelization values to test "
        "(default: 0, matching archivey). Use '0,1' to compare.",
    )
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--md-out", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        import rapidgzip  # noqa: F401
    except ImportError:
        print("rapidgzip not installed; install the 'seekable' extra", file=sys.stderr)
        return 2

    pars: list[int | None] = []
    for part in str(args.parallelization).split(","):
        part = part.strip()
        if part.lower() == "none":
            pars.append(None)
        else:
            pars.append(int(part))

    fixtures: list[Fixture] = []
    if args.codec in {"gzip", "all"}:
        fixtures.extend(build_gzip_fixtures())
    if args.codec in {"bzip2", "all"}:
        fixtures.extend(build_bzip2_fixtures())

    results: list[CutResult] = []
    with tempfile.TemporaryDirectory(prefix="rgz-trunc-") as tmp:
        tmp_path = Path(tmp)
        for fx in fixtures:
            print(
                f"sweeping {fx.name} ({fx.codec}, {len(fx.data)} B, "
                f"{len(_cut_offsets(len(fx.data), args.dense_limit))} cuts)…",
                flush=True,
            )
            results.extend(
                sweep_fixture(
                    fx,
                    dense_limit=args.dense_limit,
                    timeout_s=args.timeout,
                    parallelizations=pars,
                    tmp=tmp_path,
                )
            )

    summary = _summarize(results)
    report = {
        "summary": summary,
        "fixtures": [
            {
                "name": f.name,
                "codec": f.codec,
                "size": len(f.data),
                "expected_len": None
                if f.expected_payload is None
                else len(f.expected_payload),
                "note": f.note,
            }
            for f in fixtures
        ],
        "results": [asdict(r) for r in results],
    }

    md = _md_report(fixtures, results, summary)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {args.json_out}")
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(md)
        print(f"wrote {args.md_out}")

    # Always print a short console summary.
    print()
    print(f"platform: {summary['platform']['system']} {summary['platform']['machine']}")
    print(f"results: {summary['n_results']}")
    for backend, counts in sorted(summary["counts_by_backend"].items()):
        print(f"  {backend}: {dict(counts)}")
    print(f"silent accelerator cases: {len(summary['silent_accelerator_cases'])}")
    for s in summary["silent_accelerator_cases"][:30]:
        print(
            f"  SILENT {s['fixture']} cut={s['cut']}/{s['size']} "
            f"{s['backend']} par={s['parallelization']} -> {s['outcome']} "
            f"out_len={s['out_len']}"
        )
    if len(summary["silent_accelerator_cases"]) > 30:
        print(f"  … +{len(summary['silent_accelerator_cases']) - 30} more")
    print(f"timeouts: {len(summary['timeout_accelerator_cases'])}")
    print(f"crashes: {len(summary['crash_accelerator_cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
