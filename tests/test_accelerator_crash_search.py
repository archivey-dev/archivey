"""``scripts/accelerator_crash_search.py`` runs rapidgzip in-process on damaged input in a
process it watches, and reports each crash by its signature. These tests keep it
working: they run it on a few cases, and check that it finds the known DEFLATE abort.
"""

from __future__ import annotations

import base64
import gzip
import importlib.util
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.conftest import requires
from tests.test_accelerator_truncation_abort import _rapidgzip_is_prebuilt_linux_wheel

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "accelerator_crash_search.py"

_spec = importlib.util.spec_from_file_location("accelerator_crash_search", SCRIPT)
assert _spec is not None and _spec.loader is not None
search = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package, so the module is loaded by path. It has to be in
# `sys.modules` before it executes: `@dataclass` looks its own module up by name.
sys.modules[_spec.name] = search
_spec.loader.exec_module(search)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.mark.parametrize(
    ("returncode", "stderr", "expected"),
    [
        (
            -6,
            (
                b"terminate called after throwing an instance of 'std::logic_error'\n"
                b"  what():  The bit buffer should not contain more data\n"
            ),
            "The bit buffer should not contain more data",
        ),
        (-6, b"terminate called without an active exception\n", None),
        (-11, b"", "killed by signal 11"),
        (3, b"", "exit code 3 (0x3)"),
    ],
)
def test_the_signature_is_the_last_what_line_or_the_exit(
    returncode: int, stderr: bytes, expected: str | None
) -> None:
    signature = search.signature_of(returncode, stderr)
    if expected is None:
        assert signature == "terminate called without an active exception"
    else:
        assert signature == expected


def test_the_cases_are_the_same_for_a_seed() -> None:
    first = [search.case_input("bzip2", 3, i, []) for i in range(5)]
    again = [search.case_input("bzip2", 3, i, []) for i in range(5)]
    assert first == again
    assert first != [search.case_input("bzip2", 4, i, []) for i in range(5)]


@requires("rapidgzip")
def test_a_short_run_reports_every_codec(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    proc = _run("--cases", "6", "--json-out", str(report), "--fail-on", "never")
    assert proc.returncode == 0, proc.stderr[-2000:]
    data = json.loads(report.read_text())
    assert [c["codec"] for c in data["codecs"]] == list(search.CODECS)
    for codec in data["codecs"]:
        assert codec["cases"] == 6
        assert sum(codec["outcomes"].values()) == 6
        assert codec["verdict"]


@requires("rapidgzip")
def test_a_cut_gzip_is_the_known_abort(tmp_path: Path) -> None:
    """The cut from ``test_raw_rapidgzip_aborts_on_truncated_gzip``: the search finds the
    abort, names it known, saves the input, and exits 0 by default and 1 under
    ``--fail-on any``. Only a prebuilt Linux wheel is known to abort on it with that
    message (see the canary)."""
    if not sys.platform.startswith("linux") or not _rapidgzip_is_prebuilt_linux_wheel():
        pytest.skip("only rapidgzip's prebuilt Linux wheels are known to abort here")
    payload = base64.encodebytes(random.Random(0).randbytes(1_600_000))
    cut = tmp_path / "cut.gz"
    cut.write_bytes(gzip.compress(payload)[:-1500])
    out = tmp_path / "crashes"
    report = tmp_path / "report.json"
    args = ["--codec", "gzip", "--replay", str(cut), "--out", str(out)]
    proc = _run(*args, "--json-out", str(report))
    assert proc.returncode == 0, proc.stdout + proc.stderr[-2000:]
    (finding,) = json.loads(report.read_text())["codecs"][0]["findings"]
    assert finding["kind"] == "crash"
    assert finding["known"]
    assert Path(finding["saved"]).read_bytes() == cut.read_bytes()
    assert _run(*args, "--fail-on", "any").returncode == 1


def test_an_abort_with_no_message_on_a_cut_deflate_stream_is_known() -> None:
    """Windows aborts without writing the message. A DEFLATE-family abort with none is
    still the known one when the standard library reads the input as ending early; on
    a whole stream, or for bzip2, it is new."""
    whole = gzip.compress(b"payload " * 10_000)
    cut = whole[:-100]
    assert search._classify("gzip", "exit code 3 (0x3)", cut) == (
        search._UNNAMED_TRUNCATION_ABORT,
        True,
    )
    assert search._classify("gzip", "exit code 3 (0x3)", whole)[1] is False
    assert search._classify("bzip2", "exit code 3 (0x3)", cut)[1] is False


def test_on_windows_an_abort_with_no_message_on_damaged_deflate_is_known() -> None:
    """Windows writes no message for any abort, and a bit flipped before a cut makes the
    standard library reject the input before it reaches the cut. On Linux the same
    input names the known message (seen on CI, 2026-10-10), so where aborts carry no
    message it is filed as known; where they do, it stays new."""
    data = bytearray(
        gzip.compress(base64.encodebytes(random.Random(1).randbytes(4000)))
    )
    data[20] ^= 0xFF
    damaged = bytes(data[:-200])
    assert search._stdlib_reading("gzip", damaged) == "error"
    signature = "exit code 3221226505 (0xc0000409)"
    assert search._classify("gzip", signature, damaged, messageless=True) == (
        search._UNNAMED_DAMAGED_ABORT,
        True,
    )
    assert search._classify("gzip", signature, damaged, messageless=False)[1] is False
    whole = gzip.compress(b"payload " * 10_000)
    assert search._classify("gzip", signature, whole, messageless=True)[1] is False
    assert search._classify("bzip2", signature, damaged, messageless=True)[1] is False


def test_a_worker_that_stops_reading_is_a_hang_not_a_stall() -> None:
    """A case is written on a thread with a timeout: a worker that never reads its input
    is reported as a hang and replaced, and the search ends."""

    class _Stuck:
        def __init__(self) -> None:
            self.proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.PIPE,
            )

    stuck = _Stuck()
    try:
        sent = search._Worker.send(stuck, 1, b"x" * (4 << 20), timeout=1)  # type: ignore[arg-type]
        assert sent is None
    finally:
        stuck.proc.kill()
        stuck.proc.wait()


@requires("rapidgzip")
def test_a_crashed_worker_leaves_no_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker that dies never runs its own clean-up, and the search starts a new one
    after every crash, so the directory a worker writes its ``path`` cases to is removed
    by the supervisor once the worker is reaped."""
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", None)
    worker = search._Worker("gzip", 1)
    path_kind = search._SOURCE_KINDS.index("path")
    assert worker.send(path_kind, gzip.compress(b"payload " * 1000), timeout=60)
    assert worker.answer(timeout=60) == search._STARTED
    assert worker.answer(timeout=60)
    worker.proc.kill()  # what a crash looks like from the supervisor
    worker.death()
    assert not list(tmp_path.glob("accel-crash-search-*"))


def test_a_cut_in_a_later_concatenated_stream_ends_early() -> None:
    """The search concatenates streams now and then, and rapidgzip reads past the first
    one. A cut in the second is Bug 4's trigger too (seen on Windows CI, 2026-10-10)."""
    import zlib

    first = zlib.compress(b"first " * 1000)
    second = zlib.compress(base64.encodebytes(random.Random(2).randbytes(20_000)))
    assert search._stdlib_reading("zlib", first + second) == "clean"
    assert search._stdlib_reading("zlib", first + second[:-500]) == "ends early"
    assert search._classify("zlib", "exit code 3 (0x3)", first + second[:-500]) == (
        search._UNNAMED_TRUNCATION_ABORT,
        True,
    )


def test_reading_a_stream_whose_end_falls_inside_a_size_limited_call_ends() -> None:
    """A raw DEFLATE stream that expands past one 1 MiB call and ends inside the next,
    with data after it: reading must stop at the end marker (it used to loop for good,
    which stalled the Windows search)."""
    import zlib

    compressor = zlib.compressobj(6, wbits=-15)
    big = compressor.compress(b"\0" * (3 << 20)) + compressor.flush()
    tail = b"\x55" * 9000
    assert search._stdlib_reading("deflate", big + tail) in ("error", "ends early")
    assert search._stdlib_reading("deflate", big) == "clean"
