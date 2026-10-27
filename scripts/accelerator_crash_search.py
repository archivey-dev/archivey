"""Look for inputs that crash rapidgzip's decoders when they run in-process.

archivey runs rapidgzip in a child process for every codec it decodes (gzip, zlib, raw
DEFLATE and bzip2; ``src/archivey/internal/streams/codecs/rapidgzip_child.py``), so a
crash in its C++ code costs one stream and not the caller's program. This script answers
whether that isolation is still needed: it runs the decoders **in-process**, the way a caller
without archivey would, on damaged input, and reports every crash by its signature.

- DEFLATE family (gzip, zlib, deflate): rapidgzip 0.16 aborts on a stream that ends
  early (``dev-docs/known-issues.md`` Bug 4). That signature is listed as known, and so
  is an abort with no message on an input the standard library reads as ending early.
  Windows writes no message at all, so there an abort on any input the standard library
  does not read cleanly is filed as known too; the Linux and macOS runs, which see the
  message, are the ones that can name a new DEFLATE crash. When a run with cut inputs
  no longer finds it, the abort may be fixed upstream.
- bzip2 (``rapidgzip.IndexedBzip2File``): no crash has been seen. Any crash is new.

How it works. Each case is a valid stream (payload shape, size and compression level
picked from the seed), then one mutation: a cut, flipped bits, an overwritten, deleted
or repeated range, appended bytes, or none. Files given with ``--corpus`` are mutated
too. A worker process decodes the cases one after another with rapidgzip, from an
``io.BytesIO`` or from a path, reads to the end (at most ``_OUTPUT_CAP`` bytes), seeks
back and reads again. This process watches the worker: a worker that dies during a
case is a crash, and one that does not answer in ``--timeout`` seconds is a hang. The
case is saved to ``--out``, the worker is restarted, and the search goes on. Python
exceptions are the expected outcome for damaged input and are only counted.

The cases are deterministic for a given ``--seed``, so a crash reproduces with
``--replay FILE``, which decodes one saved input in a watched worker.

Usage::

    uv run --no-sync python scripts/accelerator_crash_search.py
    uv run --no-sync python scripts/accelerator_crash_search.py --codec bzip2 --seconds 600
    uv run --no-sync python scripts/accelerator_crash_search.py --codec gzip --cases 200 \\
        --out crashes/ --json-out crash-search.json
    uv run --no-sync python scripts/accelerator_crash_search.py --codec bzip2 \\
        --replay crashes/bzip2-0123abcd.bin

Exit status: 0 when every crash and hang found has a known signature, 1 when one does
not (``--fail-on any`` also fails on known ones), 2 for a usage error. The workflow
``.github/workflows/accelerator-crash-search.yml`` runs it on Linux, macOS and Windows.
"""

from __future__ import annotations

import argparse
import bz2
import faulthandler
import gzip
import hashlib
import json
import os
import platform
import queue
import random
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO

CODECS = ("gzip", "zlib", "deflate", "bzip2")

# Crash signatures that are known and contained. A signature is the text after the last
# ``what():`` the C++ runtime writes as it aborts, or a description of the exit.
KNOWN_SIGNATURES: dict[str, tuple[str, ...]] = {
    # rapidgzip 0.16, a DEFLATE-family stream that ends early (known-issues.md Bug 4).
    "gzip": (
        "The bit buffer should not contain more data than have been read from the file!",
    ),
    "zlib": (
        "The bit buffer should not contain more data than have been read from the file!",
    ),
    "deflate": (
        "The bit buffer should not contain more data than have been read from the file!",
    ),
    "bzip2": (),
}

# What a DEFLATE-family abort that left no message is filed under, when the standard
# library confirms the input ends early: that is Bug 4's trigger, and Windows aborts
# without writing the message (exit code 3, or 0xc0000409 from a fail-fast).
_UNNAMED_TRUNCATION_ABORT = "abort without a message, on a stream that ends early"
# On Windows, where no abort has a message, one on input the standard library rejects
# for another reason first. A flipped bit before a cut is the usual case: the Linux run
# of the same input names Bug 4's message.
_UNNAMED_DAMAGED_ABORT = (
    "abort without a message, on damaged input (Windows writes none; the Linux and "
    "macOS runs name it)"
)
_WBITS = {"gzip": 31, "zlib": 15, "deflate": -15}

# The most decoded bytes a case reads, so a small input that expands a lot (a
# decompression bomb) costs bounded time.
_OUTPUT_CAP = 64 << 20

_MUTATIONS = (
    "none",
    "cut",
    "flip",
    "overwrite",
    "delete",
    "repeat",
    "append",
    "cut+flip",
)

# Worker protocol: the supervisor sends <BI> (source kind, size) and the input; the
# worker answers one byte when it starts a case and <B> outcome when it ends it.
_CASE = struct.Struct("<BI")
_SOURCE_KINDS = ("bytesio", "path")
_OUTCOMES = ("clean", "raised", "capped")
_STARTED = b"S"
# Seconds past --timeout before the supervisor gives up on itself: the bounded waits of
# one case (the write, the start, the kill) add up to well under this.
_CASE_WATCHDOG = 300


# --- the worker ---------------------------------------------------------------------------


def _decode(codec: str, source: object, parallelization: int) -> int:
    """Decode ``source`` in this process; return the outcome's index in _OUTCOMES."""
    import rapidgzip

    opener = rapidgzip.IndexedBzip2File if codec == "bzip2" else rapidgzip.open
    try:
        stream = opener(source, parallelization=parallelization)
    except Exception:  # noqa: BLE001 - a Python error is an expected outcome
        return 1
    try:
        total = 0
        while chunk := stream.read(1 << 20):
            total += len(chunk)
            if total >= _OUTPUT_CAP:
                return 2
        # A backward seek goes through the decoder's index, which the read built.
        stream.seek(total // 2)
        while stream.read(1 << 20):
            pass
        return 0
    except Exception:  # noqa: BLE001 - a Python error is an expected outcome
        return 1
    finally:
        # close() stops rapidgzip's threads; one still running at exit aborts.
        try:
            stream.close()
        except Exception:  # noqa: BLE001, S110 - the case is over either way
            pass


def _read_exact(stream: IO[bytes], size: int) -> bytes | None:
    parts: list[bytes] = []
    while size:
        chunk = stream.read(size)
        if not chunk:
            return None
        parts.append(chunk)
        size -= len(chunk)
    return b"".join(parts)


def worker_main(codec: str, parallelization: int, tmpdir: str) -> None:
    import io

    if sys.platform == "win32":
        # No error dialog for a crash: on a desktop it would hold the dead worker open.
        import ctypes

        sem_failcriticalerrors, sem_nogpfaulterrorbox = 0x1, 0x2
        ctypes.windll.kernel32.SetErrorMode(  # type: ignore[attr-defined]
            sem_failcriticalerrors | sem_nogpfaulterrorbox
        )
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    # The supervisor owns ``tmpdir`` and removes it: this process may never get to.
    path = os.path.join(tmpdir, f"case.{codec}")
    while True:
        header = _read_exact(stdin, _CASE.size)
        if header is None:
            break
        kind, size = _CASE.unpack(header)
        data = _read_exact(stdin, size) if size else b""
        if data is None:
            break
        if _SOURCE_KINDS[kind] == "path":
            with open(path, "wb") as f:
                f.write(data)
            source: object = path
        else:
            source = io.BytesIO(data)
        stdout.write(_STARTED)
        stdout.flush()
        outcome = _decode(codec, source, parallelization)
        stdout.write(bytes([outcome]))
        stdout.flush()


# --- inputs -------------------------------------------------------------------------------


def _payload(rng: random.Random) -> bytes:
    size = int(
        rng.choice((0, 1, 100, 10_000, 200_000, 1_500_000)) * rng.uniform(0.5, 1.5)
    )
    shape = rng.choice(("text", "random", "zeros", "mixed"))
    if shape == "random":
        return rng.randbytes(size)
    if shape == "zeros":
        return bytes(size)
    words = [
        bytes(rng.choices(b"abcdefghij \n", k=rng.randint(1, 12))) for _ in range(64)
    ]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words)
        if shape == "mixed" and rng.random() < 0.05:
            out += rng.randbytes(rng.randint(1, 4096))
    return bytes(out[:size])


def _compress(codec: str, rng: random.Random) -> bytes:
    streams = 1 if rng.random() < 0.8 else rng.randint(2, 3)
    parts = []
    for _ in range(streams):
        payload = _payload(rng)
        level = rng.randint(1, 9)
        if codec == "bzip2":
            parts.append(bz2.compress(payload, level))
        elif codec == "gzip":
            parts.append(gzip.compress(payload, level, mtime=0))
        elif codec == "zlib":
            parts.append(zlib.compress(payload, level))
        else:
            compressor = zlib.compressobj(level, wbits=-15)
            parts.append(compressor.compress(payload) + compressor.flush())
    return b"".join(parts)


def _mutate(data: bytes, rng: random.Random, mutation: str) -> bytes:
    if not data or mutation == "none":
        return data
    buf = bytearray(data)
    if mutation in ("cut", "cut+flip"):
        buf = buf[: rng.randrange(len(buf))]
    if mutation in ("flip", "cut+flip"):
        for _ in range(rng.randint(1, 8)):
            if buf:
                buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
    elif mutation == "overwrite":
        start = rng.randrange(len(buf))
        length = min(rng.randint(1, 4096), len(buf) - start)
        fill = bytes(length) if rng.random() < 0.5 else rng.randbytes(length)
        buf[start : start + length] = fill
    elif mutation == "delete":
        start = rng.randrange(len(buf))
        del buf[start : start + rng.randint(1, 4096)]
    elif mutation == "repeat":
        start = rng.randrange(len(buf))
        piece = buf[start : start + rng.randint(1, 4096)]
        buf[start:start] = piece
    elif mutation == "append":
        buf += bytes(rng.randint(1, 64)) if rng.random() < 0.5 else rng.randbytes(64)
    return bytes(buf)


def _corpus(paths: list[Path], codec: str) -> list[bytes]:
    magic = {"gzip": b"\x1f\x8b", "bzip2": b"BZh"}.get(codec)
    found = []
    for root in paths:
        files = (
            [root]
            if root.is_file()
            else sorted(p for p in root.rglob("*") if p.is_file())
        )
        for path in files:
            data = path.read_bytes()
            if magic is None or data.startswith(magic):
                found.append(data)
    return found


def case_input(
    codec: str, seed: int, index: int, corpus: list[bytes]
) -> tuple[bytes, str]:
    """Case ``index`` of a run: its input and the mutation it got."""
    rng = random.Random(f"{seed}:{codec}:{index}")
    if corpus and rng.random() < 0.5:
        base = rng.choice(corpus)
    else:
        base = _compress(codec, rng)
    mutation = rng.choice(_MUTATIONS)
    return _mutate(base, rng, mutation), mutation


# --- the supervisor -----------------------------------------------------------------------


@dataclass
class Finding:
    codec: str
    kind: str  # "crash" | "hang"
    signature: str
    known: bool
    case: int | None
    mutation: str
    source: str
    size: int
    sha1: str
    saved: str | None


@dataclass
class CodecReport:
    codec: str
    cases: int = 0
    outcomes: Counter[str] = field(default_factory=Counter)
    mutations: Counter[str] = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)

    def signatures(self) -> Counter[str]:
        return Counter(f"{f.kind}: {f.signature}" for f in self.findings)


def signature_of(returncode: int | None, stderr: bytes) -> str:
    """The text of the last ``what():`` line in ``stderr``, else of the exit."""
    text = stderr.decode("utf-8", "replace")
    for line in reversed(text.splitlines()):
        at = line.rfind("what():")
        if at >= 0:
            return line[at + len("what():") :].strip()[:300]
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith(("terminate called", "Detected Python finalization")):
            return stripped[:300]
    if returncode is None:
        return "no exit code"
    if returncode < 0:
        return f"killed by signal {-returncode}"
    return f"exit code {returncode} ({returncode & 0xFFFFFFFF:#x})"


def _stdlib_reading(codec: str, data: bytes) -> str:
    """How the standard library reads ``data`` as a DEFLATE-family stream: ``"clean"``,
    ``"ends early"`` (before its end marker, with no error before that) or ``"error"``.

    Every stream in it is read, as rapidgzip reads them: the search concatenates two or
    three now and then, and a cut in a later one is still a cut. A gzip stream is
    followed only by another gzip member; anything else after it is trailing data."""
    wbits = _WBITS[codec]
    rest = data
    while True:
        decompressor = zlib.decompressobj(wbits)
        try:
            # Stop at the end marker: past it, a call with a size limit leaves the input
            # after the marker in unconsumed_tail and appends it to unused_data again,
            # so looping on the tail never ends (it stalled the Windows search, the only
            # one that classifies crashes this way).
            while rest and not decompressor.eof:
                decompressor.decompress(rest, 1 << 20)
                rest = decompressor.unconsumed_tail
        except zlib.error:
            return "error"
        if not decompressor.eof:
            return "ends early"
        rest = decompressor.unused_data
        if not rest or (codec == "gzip" and not rest.startswith(b"\x1f\x8b")):
            return "clean"


def ends_early(codec: str, data: bytes) -> bool:
    """Whether the standard library reads ``data`` as a DEFLATE-family stream that ends
    before its end marker, with no error before that (gzip: in any member)."""
    return codec in _WBITS and _stdlib_reading(codec, data) == "ends early"


def _classify(
    codec: str,
    signature: str,
    data: bytes,
    *,
    messageless: bool = sys.platform == "win32",
) -> tuple[str, bool]:
    """The signature a crash is filed under, and whether it is known. ``messageless``:
    this platform's aborts never carry a message (Windows)."""
    if signature in KNOWN_SIGNATURES[codec]:
        return signature, True
    unnamed = signature.startswith(
        ("exit code", "killed by signal", "terminate called")
    )
    if not unnamed or not KNOWN_SIGNATURES[codec]:
        return signature, False
    reading = _stdlib_reading(codec, data)
    if reading == "ends early":
        return _UNNAMED_TRUNCATION_ABORT, True
    if messageless and reading == "error":
        return _UNNAMED_DAMAGED_ABORT, True
    return signature, False


class _Worker:
    """One watched worker process. Its stdout is read on a thread, so the supervisor can
    wait for an answer with a timeout on every platform."""

    def __init__(self, codec: str, parallelization: int) -> None:
        # The handle outlives this statement; its owner closes it.
        self.stderr = tempfile.TemporaryFile()  # noqa: SIM115
        # Where the worker writes its ``path`` cases. Removed here after the worker is
        # reaped, since a worker that aborts never runs its own clean-up.
        self.tmpdir = tempfile.TemporaryDirectory(
            prefix="accel-crash-search-", ignore_cleanup_errors=True
        )
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-P",
                __file__,
                "--worker",
                codec,
                str(parallelization),
                self.tmpdir.name,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
        )
        self.answers: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self._writer: threading.Thread | None = None
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        """Read the worker's answers. This thread owns the worker's stdout and closes it
        at its end: a close from another thread would wait for a read in progress, for
        good if the worker cannot be ended."""
        stdout = self.proc.stdout
        assert stdout is not None
        try:
            while True:
                byte = stdout.read(1)
                self.answers.put(byte)
                if not byte:
                    return
        except (OSError, ValueError):
            self.answers.put(b"")
        finally:
            try:
                stdout.close()
            except OSError:
                pass

    def send(self, kind: int, data: bytes, timeout: float) -> bool | None:
        """Write one case. ``False`` if the worker died, ``None`` if it did not take the
        input in ``timeout`` seconds. The write runs on a thread: a pipe holds less than
        most inputs, so a worker that stopped reading would block it for good (seen on
        Windows after a crash, 2026-10-10)."""
        assert self.proc.stdin is not None
        stdin = self.proc.stdin
        result: list[bool] = []

        def write() -> None:
            try:
                stdin.write(_CASE.pack(kind, len(data)))
                stdin.write(data)
                stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                result.append(False)
            else:
                result.append(True)

        self._writer = threading.Thread(target=write, daemon=True)
        self._writer.start()
        self._writer.join(timeout)
        return result[0] if result else None

    def answer(self, timeout: float) -> bytes | None:
        """The next byte from the worker, ``b""`` if it died, ``None`` on a timeout."""
        try:
            return self.answers.get(timeout=timeout)
        except queue.Empty:
            return None

    def death(self) -> tuple[int | None, bytes]:
        """Wait for a worker that died (or kill a hung one); its exit code and stderr."""
        returncode = self._wait_or_kill()
        self.stderr.seek(0)
        text = self.stderr.read()
        self.close()
        return returncode, text

    def close(self) -> None:
        # Closing stdin tells an idle worker to exit. A write still in progress holds
        # the pipe's lock, so a close would wait for it; the worker is killed instead,
        # and the pipe is left to the garbage collector.
        stdin = self.proc.stdin
        if stdin is not None and (self._writer is None or not self._writer.is_alive()):
            try:
                stdin.close()
            except OSError:
                pass
        self._wait_or_kill()
        self.stderr.close()
        self.tmpdir.cleanup()

    def _wait_or_kill(self) -> int | None:
        """The worker's exit code once it has exited; killed after 10 seconds. ``None``
        if even a kill does not end it in 10 more: the search goes on without it."""
        for kill in (False, True):
            if kill:
                try:
                    self.proc.kill()
                except OSError:
                    pass
            try:
                return self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                continue
        return None


def _save(out: Path | None, codec: str, data: bytes, sha1: str) -> str | None:
    if out is None:
        return None
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{codec}-{sha1[:12]}.bin"
    path.write_bytes(data)
    return str(path)


def search(
    codec: str,
    *,
    seed: int,
    cases: int | None,
    seconds: float | None,
    timeout: float,
    parallelization: int,
    corpus: list[bytes],
    out: Path | None,
    inputs: list[tuple[bytes, str]] | None = None,
    progress: bool = True,
) -> CodecReport:
    """Run one codec's cases in a watched worker. ``inputs`` replaces the generated
    cases (``--replay``)."""
    report = CodecReport(codec)
    deadline = None if seconds is None else time.monotonic() + seconds
    worker: _Worker | None = None
    index = 0
    try:
        while True:
            if inputs is not None:
                if index >= len(inputs):
                    break
                data, mutation = inputs[index]
            else:
                if cases is not None and index >= cases:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                data, mutation = case_input(codec, seed, index, corpus)
            # Every wait in a case is bounded, so a case that runs far past them is a bug
            # in this script: print every thread's stack and exit rather than stall.
            faulthandler.dump_traceback_later(timeout + _CASE_WATCHDOG, exit=True)
            kind = index % len(_SOURCE_KINDS)
            if worker is None:
                worker = _Worker(codec, parallelization)
            report.cases += 1
            report.mutations[mutation] += 1
            sent = worker.send(kind, data, timeout=60)
            if sent:
                started = worker.answer(timeout=60)
                if started == _STARTED:
                    answer = worker.answer(timeout=timeout)
                else:
                    answer = started if started is None else b""
            else:
                answer = None if sent is None else b""
            if answer and answer[0] < len(_OUTCOMES):
                report.outcomes[_OUTCOMES[answer[0]]] += 1
            else:
                hang = answer is None
                returncode, stderr = worker.death()
                worker = None
                if hang:
                    signature, is_known = "no answer in time", False
                else:
                    signature, is_known = _classify(
                        codec, signature_of(returncode, stderr), data
                    )
                sha1 = hashlib.sha1(data).hexdigest()
                finding = Finding(
                    codec=codec,
                    kind="hang" if hang else "crash",
                    signature=signature,
                    known=is_known,
                    case=None if inputs is not None else index,
                    mutation=mutation,
                    source=_SOURCE_KINDS[kind],
                    size=len(data),
                    sha1=sha1,
                    saved=_save(out, codec, data, sha1),
                )
                report.findings.append(finding)
                report.outcomes[finding.kind] += 1
                if progress and not finding.known:
                    print(
                        f"  {codec}: NEW {finding.kind} on case {index} "
                        f"({mutation}, {finding.source}): {signature}",
                        file=sys.stderr,
                    )
            index += 1
            if progress and index % 200 == 0:
                print(f"  {codec}: {index} cases", file=sys.stderr)
    finally:
        faulthandler.cancel_dump_traceback_later()
        if worker is not None:
            worker.close()
    return report


def _verdict(report: CodecReport) -> str:
    new = [f for f in report.findings if not f.known]
    known = [f for f in report.findings if f.known]
    if new:
        return (
            f"{len(new)} crash(es) or hang(s) with a new signature: see the list below"
        )
    if known:
        return (
            f"the known abort still reproduces ({len(known)} cases); the child process "
            "is still needed"
        )
    if KNOWN_SIGNATURES[report.codec]:
        cuts = report.mutations["cut"] + report.mutations["cut+flip"]
        return (
            f"no crash in {report.cases} cases ({cuts} cut). The known abort did not "
            "reproduce: if cut inputs were among them, it may be fixed upstream"
        )
    return f"no crash in {report.cases} cases"


def _print_report(reports: list[CodecReport]) -> None:
    print(
        f"rapidgzip crash search, {platform.platform()}, Python {platform.python_version()}"
    )
    try:
        import importlib.metadata

        print(f"rapidgzip {importlib.metadata.version('rapidgzip')}")
    except Exception:  # noqa: BLE001, S110 - only a label
        pass
    for report in reports:
        outcomes = ", ".join(f"{k} {v}" for k, v in sorted(report.outcomes.items()))
        print(f"\n{report.codec}: {report.cases} cases ({outcomes})")
        print(f"  verdict: {_verdict(report)}")
        for signature, count in report.signatures().most_common():
            first = next(
                f for f in report.findings if f"{f.kind}: {f.signature}" == signature
            )
            tag = "known" if first.known else "NEW"
            where = f", saved {first.saved}" if first.saved else ""
            print(f"  [{tag}] {count} x {signature} (first: case {first.case}{where})")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["--worker"]:
        worker_main(args[1], int(args[2]), args[3])
        return 0
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--codec", action="append", choices=CODECS, help="repeatable; default: all four"
    )
    budget = parser.add_mutually_exclusive_group()
    budget.add_argument("--cases", type=int, help="cases per codec (default 300)")
    budget.add_argument(
        "--seconds", type=float, help="time per codec instead of a count"
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds per case")
    parser.add_argument(
        "--parallelization",
        type=int,
        default=0,
        help="rapidgzip's parallelization (0, all cores, is what archivey uses)",
    )
    parser.add_argument("--corpus", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, help="directory for crashing inputs")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--replay", type=Path, help="decode one saved input")
    parser.add_argument(
        "--fail-on",
        choices=("new", "any", "never"),
        default="new",
        help="which findings make the exit status 1 (default: new signatures)",
    )
    ns = parser.parse_args(args)
    codecs = ns.codec or list(CODECS)
    if ns.replay is not None and len(codecs) != 1:
        parser.error("--replay needs exactly one --codec")
    try:
        import rapidgzip  # noqa: F401
    except ImportError as exc:
        parser.error(
            f"rapidgzip is not importable ({exc}); install the [seekable] extra"
        )
    cases = ns.cases if ns.cases is not None or ns.seconds is not None else 300
    reports = []
    for codec in codecs:
        inputs = None
        if ns.replay is not None:
            inputs = [(ns.replay.read_bytes(), "replay")]
        reports.append(
            search(
                codec,
                seed=ns.seed,
                cases=cases,
                seconds=ns.seconds,
                timeout=ns.timeout,
                parallelization=ns.parallelization,
                corpus=_corpus(ns.corpus, codec),
                out=ns.out,
                inputs=inputs,
            )
        )
    _print_report(reports)
    if ns.json_out is not None:
        ns.json_out.write_text(
            json.dumps(
                {
                    "platform": platform.platform(),
                    "python": platform.python_version(),
                    "seed": ns.seed,
                    "codecs": [
                        {
                            "codec": r.codec,
                            "cases": r.cases,
                            "outcomes": dict(r.outcomes),
                            "mutations": dict(r.mutations),
                            "verdict": _verdict(r),
                            "findings": [asdict(f) for f in r.findings],
                        }
                        for r in reports
                    ],
                },
                indent=2,
            )
        )
    findings = [f for r in reports for f in r.findings]
    if ns.fail_on == "any" and findings:
        return 1
    if ns.fail_on == "new" and any(not f.known for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
