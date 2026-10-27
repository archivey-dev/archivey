"""Stress-test PPMd native decode surfaces (Windows + Linux investigation).

Background
----------
On Windows, ``test_py7zr_codec_fixtures_roundtrip[ppmd]`` intermittently aborts with
``STATUS_HEAP_CORRUPTION`` (``0xC0000374``) inside ``pyppmd`` on a *valid* solid PPMd
stream. Fresh PPMd-only subprocesses are enough to crash (~few percent on py3.11), so
prior-test contamination is not required.

On Linux, a related but distinct flake shows up when other 7z codecs are exercised in
the same process before PPMd (``warmup_codecs``): SIGSEGV / ``malloc(): invalid size``
at roughly ~1/3 of child runs. Raw ``pyppmd`` encode/decode alone has not reproduced
that Linux abort here.

See ``dev-docs/known-issues.md``.

This script is the dedicated investigation vehicle. Default scenarios favour the
**minimal surface** (raw ``pyppmd`` / archivey codec streams, no 7z container), then
the original 7z baseline, then secondary contamination axes::

    uv run --extra all python scripts/ppmd_native_stress.py
    uv run --extra all python scripts/ppmd_native_stress.py 40
    uv run --extra all python scripts/ppmd_native_stress.py --scenarios raw_pyppmd7 warmup_codecs

Exit code is non-zero if any child crashed or failed. Console I/O is ASCII-safe for
Windows cp1252 runners.
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

_REPO_ROOT = Path(__file__).resolve().parents[1]

_WINDOWS_NTSTATUS: dict[int, str] = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0x80000003: "STATUS_BREAKPOINT",
}

# Minimal surface first; 7z baseline; secondary contamination / reuse axes last.
_DEFAULT_SCENARIOS: tuple[str, ...] = (
    "raw_pyppmd7",
    "raw_pyppmd8",
    "raw_archivey_ppmd7",
    "raw_archivey_ppmd8",
    "fresh_baseline",
    "warmup_codecs",
)

_ALL_SCENARIOS: tuple[str, ...] = (
    *_DEFAULT_SCENARIOS,
    "same_process",
    "fresh_varied",
)


def _safe_print(msg: str, *, file=None) -> None:
    stream = file or sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        stream.write(msg + "\n")
    except UnicodeEncodeError:
        stream.write(msg.encode(encoding, errors="replace").decode(encoding) + "\n")
    stream.flush()


def _format_rc(returncode: int) -> str:
    unsigned = returncode & 0xFFFFFFFF
    if returncode < 0 or returncode > 255:
        name = _WINDOWS_NTSTATUS.get(unsigned)
        if name is not None:
            return f"0x{unsigned:08X} ({name}); signed={returncode}"
        if -64 < returncode < 0:
            return f"{returncode} (likely signal {-returncode})"
        return f"0x{unsigned:08X} (unknown); signed={returncode}"
    return str(returncode)


def _phase_helpers() -> str:
    return textwrap.dedent(
        """\
        from __future__ import annotations
        import faulthandler
        import os
        import sys
        from pathlib import Path

        faulthandler.enable(all_threads=True, file=sys.stderr)
        work = Path(os.environ["ARCHIVEY_PPMD_STRESS_WORK"])
        phase_path = work / "phase.txt"

        def _phase(msg: str) -> None:
            line = msg + "\\n"
            with phase_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            print(f"[phase] {msg}", flush=True)

        _phase("start")
        """
    )


def _payload_sets() -> list[tuple[str, dict[str, bytes], str]]:
    baseline = {
        "alpha.txt": b"alpha\n" * 100,
        "nested/beta.bin": bytes(range(64)) * 16,
    }
    tiny = {"a.txt": b"x", "b.txt": b"y" * 17}
    single = {"only.txt": b"solo-ppmd-member-" * 40}
    many_small = {
        f"m{i:02d}.bin": bytes([(i * 17 + j) % 256 for j in range(32)])
        for i in range(8)
    }
    larger = {
        "big.txt": (b"PPMd-stress-line\n" * 2000),
        "mid.bin": bytes(range(256)) * 64,
        "tail.txt": b"z" * 503,
    }
    repetitive = {"r.txt": b"AAAA" * 500, "s.bin": b"\x00\x01" * 800}
    return [
        ("baseline_sorted", baseline, "sorted"),
        ("baseline_reverse", baseline, "reverse"),
        ("baseline_stream", baseline, "stream"),
        ("tiny_sorted", tiny, "sorted"),
        ("single_sorted", single, "sorted"),
        ("many_small_sorted", many_small, "sorted"),
        ("many_small_reverse", many_small, "reverse"),
        ("larger_sorted", larger, "sorted"),
        ("repetitive_sorted", repetitive, "sorted"),
    ]


def _sevenzip_helpers() -> str:
    return textwrap.dedent(
        """\
        def _roundtrip_7z(archive_path, files, *, read_order="sorted"):
            from archivey import open_archive
            with open_archive(archive_path) as archive:
                members = {m.name: m for m in archive.members() if m.is_file}
                assert set(members) == set(files)
                if read_order == "sorted":
                    names = sorted(files)
                elif read_order == "reverse":
                    names = sorted(files, reverse=True)
                elif read_order == "stream":
                    streamed = {
                        m.name: s.read()
                        for m, s in archive.stream_members()
                        if m.is_file and s is not None
                    }
                    assert streamed == files
                    return
                else:
                    raise ValueError(read_order)
                for name in names:
                    _phase(f"read_member:{name}:start")
                    data = archive.read(members[name])
                    _phase(f"read_member:{name}:done len={len(data)}")
                    assert data == files[name]

        def _build_ppmd_7z(archive_path, files):
            from tests.test_sevenzip_reader import _filters, _write_py7zr_archive
            _write_py7zr_archive(archive_path, files, filters=_filters("PPMD"))
        """
    )


def _write_driver(path: Path, scenario: str, *, rounds: int, seed: int) -> None:
    payloads_repr = repr(
        [(label, files, order) for label, files, order in _payload_sets()]
    )
    body = _phase_helpers()

    if scenario == "raw_pyppmd7":
        body += textwrap.dedent(
            f"""\
            import pyppmd
            ORDER, MEM = 6, 1 << 20
            data = b"alpha\\n" * 100
            _phase("raw_pyppmd7:encode")
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            _phase(f"raw_pyppmd7:decode packed={{len(packed)}}")
            dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
            out = bytearray(dec.decode(packed, len(data)))
            while len(out) < len(data):
                need = len(data) - len(out)
                chunk = dec.decode(b"\\0" if dec.needs_input else b"", need)
                if not chunk:
                    break
                out.extend(chunk)
            assert bytes(out) == data
            _phase("roundtrip-ok")
            # Optional multi-cycle in the same child (seed selects count).
            cycles = 1 + ({seed} % 8)
            _phase(f"raw_pyppmd7:extra-cycles={{cycles}}")
            for i in range(cycles):
                enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
                packed = enc.encode(data) + enc.flush()
                dec = pyppmd.Ppmd7Decoder(ORDER, MEM)
                out = bytearray(dec.decode(packed, len(data)))
                while len(out) < len(data):
                    need = len(data) - len(out)
                    chunk = dec.decode(b"\\0" if dec.needs_input else b"", need)
                    if not chunk:
                        break
                    out.extend(chunk)
                assert bytes(out) == data
            _phase("cycles-ok")
            """
        )
    elif scenario == "raw_pyppmd8":
        body += textwrap.dedent(
            """\
            import pyppmd
            ORDER, MEM = 6, 1 << 20
            data = b"alpha\\n" * 100
            _phase("raw_pyppmd8:encode")
            enc = pyppmd.Ppmd8Encoder(ORDER, MEM, 0)
            packed = enc.encode(data) + enc.flush(True)
            _phase(f"raw_pyppmd8:decode packed={{len(packed)}}")
            dec = pyppmd.Ppmd8Decoder(ORDER, MEM, 0)
            out = dec.decode(packed, -1)
            while not dec.eof:
                more = dec.decode(b"\\0" if dec.needs_input else b"", -1)
                if not more:
                    break
                out += more
            assert out == data
            _phase("roundtrip-ok")
            """
        )
    elif scenario == "raw_archivey_ppmd7":
        body += textwrap.dedent(
            """\
            import io
            import pyppmd
            from archivey.internal.streams.codecs.ppmd_decoder import PpmdDecompressorStream
            from archivey.internal.streams.streamtools import read_exact
            ORDER, MEM = 6, 1 << 20
            data = b"alpha\\n" * 100
            _phase("raw_archivey_ppmd7:encode")
            enc = pyppmd.Ppmd7Encoder(ORDER, MEM)
            packed = enc.encode(data) + enc.flush()
            _phase("raw_archivey_ppmd7:decode-sized")
            # Pass unpack_size + pack_size (required for PPMd7 — no end mark).
            with PpmdDecompressorStream(
                io.BytesIO(packed),
                order=ORDER,
                mem_size=MEM,
                variant=7,
                unpack_size=len(data),
                pack_size=len(packed),
            ) as stream:
                got = read_exact(stream, len(data))
            assert got == data
            _phase("roundtrip-ok")
            """
        )
    elif scenario == "raw_archivey_ppmd8":
        body += textwrap.dedent(
            """\
            import io
            import pyppmd
            from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream
            ORDER, MEM = 6, 1 << 20
            data = b"alpha\\n" * 100
            _phase("raw_archivey_ppmd8:encode")
            enc = pyppmd.Ppmd8Encoder(ORDER, MEM, 0)
            packed = enc.encode(data) + enc.flush(True)
            _phase("raw_archivey_ppmd8:open_codec_stream")
            with open_codec_stream(
                Codec.PPMD,
                io.BytesIO(packed),
                params=CodecParams(ppmd_order=ORDER, ppmd_mem_size=MEM),
            ) as stream:
                got = stream.read()
            assert got == data
            _phase("roundtrip-ok")
            """
        )
    elif scenario == "fresh_baseline":
        body += _sevenzip_helpers()
        body += textwrap.dedent(
            """\
            from tests.test_sevenzip_reader import _FILES
            archive_path = work / "ppmd.7z"
            _phase("building-archive label=baseline_sorted")
            _build_ppmd_7z(archive_path, _FILES)
            _phase(f"archive-built size={archive_path.stat().st_size}")
            _phase("open_archive")
            _roundtrip_7z(archive_path, _FILES, read_order="sorted")
            _phase("roundtrip-ok")
            """
        )
    elif scenario == "fresh_varied":
        body += _sevenzip_helpers()
        body += textwrap.dedent(
            f"""\
            payloads = {payloads_repr}
            label, files, order = payloads[{seed} % len(payloads)]
            archive_path = work / f"{{label}}.7z"
            _phase(f"building-archive label={{label}} order={{order}}")
            _build_ppmd_7z(archive_path, files)
            _phase(f"archive-built size={{archive_path.stat().st_size}}")
            _roundtrip_7z(archive_path, files, read_order=order)
            _phase("roundtrip-ok")
            """
        )
    elif scenario == "same_process":
        body += _sevenzip_helpers()
        body += textwrap.dedent(
            f"""\
            payloads = {payloads_repr}
            rounds = {rounds}
            for i in range(rounds):
                label, files, order = payloads[(i + {seed}) % len(payloads)]
                archive_path = work / f"same-{{i:04d}}-{{label}}.7z"
                _phase(f"round={{i}}:building label={{label}} order={{order}}")
                _build_ppmd_7z(archive_path, files)
                _phase(f"round={{i}}:reading")
                _roundtrip_7z(archive_path, files, read_order=order)
                _phase(f"round={{i}}:ok")
            _phase("roundtrip-ok")
            """
        )
    elif scenario == "warmup_codecs":
        # Linux: highly flaky (~1/3 SIGSEGV / malloc abort) after other codecs then PPMd.
        body += _sevenzip_helpers()
        body += textwrap.dedent(
            f"""\
            from tests.test_sevenzip_reader import _FILES, _filters, _write_py7zr_archive
            from archivey import open_archive

            payloads = {payloads_repr}
            warmups = ("LZMA2", "DEFLATE", "BZIP2")
            for codec in warmups:
                path = work / f"warm-{{codec}}.7z"
                _phase(f"warmup-build {{codec}}")
                _write_py7zr_archive(path, _FILES, filters=_filters(codec))
                _phase(f"warmup-read {{codec}}")
                with open_archive(path) as archive:
                    members = {{m.name: m for m in archive.members() if m.is_file}}
                    for name in sorted(_FILES):
                        assert archive.read(members[name]) == _FILES[name]
                _phase(f"warmup-ok {{codec}}")

            label, files, order = payloads[{seed} % len(payloads)]
            archive_path = work / f"after-warmup-{{label}}.7z"
            _phase(f"ppmd-after-warmup label={{label}} order={{order}}")
            _build_ppmd_7z(archive_path, files)
            _roundtrip_7z(archive_path, files, read_order=order)
            _phase("roundtrip-ok")
            """
        )
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    path.write_text(body, encoding="utf-8")


def _one_iteration(
    iter_dir: Path,
    *,
    scenario: str,
    rounds: int,
    seed: int,
    timeout: float,
) -> tuple[int, str, str, str]:
    iter_dir.mkdir(parents=True, exist_ok=True)
    phase_path = iter_dir / "phase.txt"
    driver = iter_dir / "_driver.py"
    _write_driver(driver, scenario, rounds=rounds, seed=seed)
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(_REPO_ROOT / "src"),
            str(_REPO_ROOT / "tests"),
            str(_REPO_ROOT),
            env.get("PYTHONPATH", ""),
        ]
    )
    env["ARCHIVEY_PPMD_STRESS_WORK"] = str(iter_dir)
    env.setdefault("PYTHONFAULTHANDLER", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run(
        [sys.executable, "-u", str(driver)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    phase = (
        phase_path.read_text(encoding="utf-8") if phase_path.exists() else "<missing>"
    )
    return proc.returncode, phase, proc.stdout, proc.stderr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "iterations",
        nargs="?",
        type=int,
        default=int(os.environ.get("ARCHIVEY_PPMD_STRESS_ITERS", "20")),
        help="Child iterations per scenario (default: env ARCHIVEY_PPMD_STRESS_ITERS or 20)",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=list(_DEFAULT_SCENARIOS),
        choices=list(_ALL_SCENARIOS),
        help="Scenario families to run (default: minimal + baseline + warmup)",
    )
    parser.add_argument(
        "--same-rounds",
        type=int,
        default=8,
        help="PPMd roundtrips inside each same_process child (default: 8)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Per-child subprocess timeout in seconds (default: 180)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Optional path to write a Markdown summary",
    )
    args = parser.parse_args(argv)

    try:
        import pyppmd  # noqa: F401
    except ImportError:
        _safe_print(
            "pyppmd not installed; cannot stress PPMd. Install archivey[recommended].",
            file=sys.stderr,
        )
        return 2

    scenarios = list(dict.fromkeys(args.scenarios))
    needs_py7zr = any(
        s in {"fresh_baseline", "fresh_varied", "same_process", "warmup_codecs"}
        for s in scenarios
    )
    if needs_py7zr:
        try:
            import py7zr  # noqa: F401
        except ImportError:
            _safe_print(
                "py7zr not installed; needed for 7z scenarios.",
                file=sys.stderr,
            )
            return 2

    _safe_print(
        f"PPMd native stress: scenarios={scenarios!r} "
        f"iters_per_scenario={args.iterations} same_rounds={args.same_rounds} "
        f"platform={platform.platform()!r} python={sys.version.split()[0]} "
        f"executable={sys.executable!r}"
    )

    crashes: list[tuple[str, int, int, str]] = []
    failures: list[tuple[str, int, int, str]] = []
    passes_by_scenario: dict[str, int] = dict.fromkeys(scenarios, 0)
    total_runs = 0

    with tempfile.TemporaryDirectory(prefix="archivey-ppmd-stress-") as tmp:
        root = Path(tmp)
        for scenario in scenarios:
            _safe_print(f"== scenario {scenario} ==")
            for i in range(1, args.iterations + 1):
                total_runs += 1
                iter_dir = root / scenario / f"iter-{i:04d}"
                try:
                    rc, phase, _stdout, stderr = _one_iteration(
                        iter_dir,
                        scenario=scenario,
                        rounds=args.same_rounds,
                        seed=i - 1,
                        timeout=args.timeout,
                    )
                except subprocess.TimeoutExpired:
                    failures.append((scenario, i, -1, "timeout"))
                    _safe_print(f"  [{scenario} {i}/{args.iterations}] TIMEOUT")
                    continue
                last_phase = (
                    phase.strip().splitlines()[-1] if phase.strip() else "<empty>"
                )
                if rc == 0:
                    passes_by_scenario[scenario] += 1
                    _safe_print(f"  [{scenario} {i}/{args.iterations}] ok")
                    continue
                unsigned = rc & 0xFFFFFFFF
                is_crash = unsigned in _WINDOWS_NTSTATUS or rc < 0 or rc > 255
                bucket = crashes if is_crash else failures
                bucket.append((scenario, i, rc, last_phase))
                kind = "CRASH" if is_crash else "FAIL"
                _safe_print(
                    f"  [{scenario} {i}/{args.iterations}] {kind} "
                    f"rc={_format_rc(rc)} last_phase={last_phase!r}"
                )
                if stderr.strip():
                    tail = "\n".join(stderr.strip().splitlines()[-8:])
                    _safe_print(f"    stderr tail:\n{textwrap.indent(tail, '    ')}")

    lines = [
        "# PPMd native stress results",
        "",
        f"- platform: `{platform.platform()}`",
        f"- python: `{sys.version.split()[0]}`",
        f"- scenarios: `{', '.join(scenarios)}`",
        f"- total child runs: **{total_runs}**",
        f"- native crashes: **{len(crashes)}**",
        f"- other failures: **{len(failures)}**",
        "",
        "## Passes by scenario",
        "",
    ]
    for scenario in scenarios:
        lines.append(
            f"- `{scenario}`: **{passes_by_scenario[scenario]}** / {args.iterations}"
        )
    lines.append("")
    if crashes:
        lines.append("## Crashes")
        lines.append("")
        for scenario, i, rc, last_phase in crashes:
            lines.append(
                f"- `{scenario}` iter {i}: `{_format_rc(rc)}` at phase `{last_phase}`"
            )
        lines.append("")
    if failures:
        lines.append("## Other failures")
        lines.append("")
        for scenario, i, rc, last_phase in failures:
            lines.append(
                f"- `{scenario}` iter {i}: `{_format_rc(rc)}` at phase `{last_phase}`"
            )
        lines.append("")
    lines.append(
        "Known issue: valid PPMd streams can abort inside `pyppmd` (Windows "
        "`STATUS_HEAP_CORRUPTION`; Linux SIGSEGV / malloc abort especially after "
        "other-codec warmup). Prefer `raw_*` scenarios to isolate the minimal "
        "surface. See `dev-docs/known-issues.md`."
    )
    summary = "\n".join(lines) + "\n"

    if args.summary is not None:
        args.summary.write_text(summary, encoding="utf-8")
    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        with open(gh_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)
    _safe_print(summary)

    if crashes or failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
