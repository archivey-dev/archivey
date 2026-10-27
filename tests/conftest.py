"""Top-level pytest configuration and shared fixtures."""

from __future__ import annotations

import functools
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import types
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Literal, overload

import pytest

if TYPE_CHECKING:
    from archivey.reader import ForwardArchiveReader
    from archivey.types import ArchiveMember


# Whether this is CPython. Tests that pin CPython's exact wording or object lifetimes
# check it; other interpreters (PyPy) word errors differently and collect later.
CPYTHON = sys.implementation.name == "cpython"


# PyPy has no ``_tracemalloc``, so ``import tracemalloc`` fails there and every test
# module that imports it, directly or through tests/memory_util.py, would fail to
# load. This stand-in skips only the test that calls it.
class _TracemallocUnavailable(types.ModuleType):
    def __getattr__(self, name: str) -> Callable[..., object]:
        if name.startswith("__"):
            raise AttributeError(name)

        def unavailable(*_args: object, **_kwargs: object) -> object:
            pytest.skip("tracemalloc is not available on this interpreter")

        return unavailable


if importlib.util.find_spec("_tracemalloc") is None:
    sys.modules["tracemalloc"] = _TracemallocUnavailable("tracemalloc")

# archivey never uses rapidgzip, lz4, pyppmd or inflate64 under PyPy, where they misread
# data or crash the interpreter (deps.unused_reason), and the tests treat them as not
# installed there. rapidgzip and lz4 get a ``None`` entry, which makes the import fail and
# ``importlib.util.find_spec`` return ``None``, so no test loads them. pyppmd and
# inflate64 cannot: py7zr, a test oracle, imports both. Tests that need them ask
# ``has_package`` (through ``requires`` or ``importorskip``) instead. The source of truth
# is ``deps._UNUSED_UNDER_PYPY``; this copy is kept by hand because it must be in place
# before anything imports archivey, and importing ``deps`` imports ``lz4.frame``.
# ``tests/test_codecs.py`` checks that it matches.
UNUSED_UNDER_PYPY_NAMES = frozenset({"rapidgzip", "lz4", "pyppmd", "inflate64"})
UNUSED_UNDER_PYPY = (
    UNUSED_UNDER_PYPY_NAMES if sys.implementation.name == "pypy" else frozenset()
)
for _blocked in UNUSED_UNDER_PYPY - {"pyppmd", "inflate64"}:
    sys.modules[_blocked] = None  # type: ignore[assignment]


def has_package(name: str) -> bool:
    """Whether optional package ``name`` is installed and archivey uses it here."""
    return name not in UNUSED_UNDER_PYPY and importlib.util.find_spec(name) is not None


def importorskip(name: str) -> types.ModuleType:
    """``pytest.importorskip``, also skipping a package archivey does not use here."""
    if name in UNUSED_UNDER_PYPY:
        pytest.skip(f"archivey does not use {name} under PyPy")
    return pytest.importorskip(name)


# Per-test OS-resource leak oracle (child processes, owning streams, pipe fds).
pytest_plugins = ("leak_oracle",)

# Test archive cache dir (configurable via env var)
ARCHIVEY_TEST_CACHE = os.environ.get(
    "ARCHIVEY_TEST_CACHE",
    str(Path(__file__).parent.parent / ".pytest_cache" / "archivey-archives"),
)


def complete_listing(reader: ForwardArchiveReader) -> list[ArchiveMember]:
    """The member list from ``members_report()``, raising its error if incomplete.

    The complete-or-raise listing that works on a streaming reader too.
    """
    report = reader.members_report()
    if report.error is not None:
        raise report.error
    return list(report.members)


class ReadSizeSpy:
    """Wrap a stream and record the largest ``read(n)`` it was asked for.

    Used to pin that 7z password confirmation reads in bounded chunks: a single
    request sized to the whole folder is the gather that PR #318 removed. It is a
    proxy for peak memory, not a measurement of it.
    """

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.max_requested = 0

    def read(self, n: int = -1, /) -> bytes:
        # A negative n is read-everything, which is the unbounded case; record it as
        # larger than any real request rather than as 0.
        self.max_requested = max(self.max_requested, 2**31 if n < 0 else n)
        return self._inner.read(n)

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def case_sensitive(path: Path) -> bool:
    """Whether the filesystem at ``path`` tells ``CaseProbe`` from ``caseprobe``. Writes
    and removes ``path / "CaseProbe"``, so ``path`` is left as it was."""
    probe = path / "CaseProbe"
    probe.write_bytes(b"")
    try:
        return not (path / "caseprobe").exists()
    finally:
        probe.unlink()


def requires(*packages: str) -> pytest.MarkDecorator:
    """Skip a test (or parametrization) when an optional package is not importable.

    This is what lets the whole suite run in the `core-only` CI leg: tests that need
    an optional format library are skipped cleanly there rather than erroring, while
    they run normally in the `[all]` leg. Use it as a decorator::

        @requires_zstd()
        def test_zstd_stream(): ...

    Tests asserting the *degradation* behavior (a missing lib raising
    PackageNotInstalledError) should instead run unconditionally and assert that error.
    """
    unused = [p for p in packages if p in UNUSED_UNDER_PYPY]
    missing = [p for p in packages if p not in unused and not has_package(p)]
    reasons = []
    if missing:
        reasons.append(f"requires optional package(s): {', '.join(missing)}")
    if unused:
        reasons.append(f"archivey does not use {', '.join(unused)} under PyPy")
    return pytest.mark.skipif(bool(reasons), reason="; ".join(reasons))


def unar_refusal() -> str | None:
    """Why archivey will not use the ``unar`` on ``PATH``, or ``None`` when it will.

    A ``unar`` that fails archivey's RAR5 check (Debian and Ubuntu packages before
    1.10.8+ds1-10, see ``dev-docs/known-issues.md``) is on ``PATH`` but unusable, so
    a test that needs ``unar`` skips there, as it does where ``unar`` is missing.
    """
    from archivey.exceptions import PackageNotInstalledError
    from archivey.internal.external.unar import find_unar

    if shutil.which("unar") is None:
        return "unar is not on PATH"
    try:
        find_unar(purpose="for the test suite")
    except PackageNotInstalledError as exc:
        return str(exc)
    return None


def unrar_refusal() -> str | None:
    """Why archivey has no RARLAB data program, or ``None`` when it has one.

    ``find_rarlab_unrar`` accepts RARLAB ``unrar``, or ``rar`` 6.0+ when there is no
    usable ``unrar``, and refuses a lookalike or a release below 6.0. A test that reads
    RAR data with ``rar_decompressor="unrar"`` needs exactly what it accepts.
    """
    from archivey.exceptions import PackageNotInstalledError
    from archivey.internal.backends.rar_unrar import find_rarlab_unrar

    try:
        find_rarlab_unrar()
    except PackageNotInstalledError as exc:
        return str(exc)
    return None


def unrar_cli_refusal() -> str | None:
    """Why a test cannot run the ``unrar`` command itself, or ``None`` when it can.

    A test that runs ``unrar`` as an oracle needs that command to be the RARLAB
    ``unrar`` archivey accepts; such a test is marked :func:`requires_unrar_cli`.
    :func:`unrar_refusal` alone is not enough: it also accepts ``rar`` 6.0+ when
    ``unrar`` is missing or a lookalike, and the test would then run the wrong program.
    """
    from archivey.internal.backends.rar_unrar import find_rarlab_unrar

    on_path = shutil.which("unrar")
    if on_path is None:
        return "unrar is not on PATH"
    refusal = unrar_refusal()
    if refusal is not None:
        return refusal
    # find_rarlab_unrar returns an absolute path already; abspath both sides anyway,
    # so a relative PATH entry cannot make the two spellings differ.
    accepted = find_rarlab_unrar()
    if os.path.normcase(os.path.abspath(on_path)) != os.path.normcase(
        os.path.abspath(accepted)
    ):
        return f"archivey refuses the unrar at {on_path} and uses rar instead"
    return None


def binary_refusal(name: str) -> str | None:
    """Why a test cannot use ``name``, or ``None`` when it can.

    For ``unar`` and ``unrar`` this is archivey's own policy (:func:`unar_refusal`,
    :func:`unrar_refusal`), so a binary on ``PATH`` that archivey refuses reads as
    missing. Any other name only has to be on ``PATH``. A test that runs the
    ``unrar`` command itself uses :func:`unrar_cli_refusal` or
    :func:`requires_unrar_cli` instead.
    """
    if name == "unar":
        return unar_refusal()
    if name == "unrar":
        return unrar_refusal()
    return None if shutil.which(name) else f"{name} is not on PATH"


def has_binary(name: str) -> bool:
    """Whether a test can use ``name``: :func:`binary_refusal` has no objection."""
    return binary_refusal(name) is None


def requires_binary(*names: str) -> pytest.MarkDecorator:
    """Skip a test when an external tool (e.g. the ``7z`` or ``unrar`` CLI) is not on PATH.

    The oracle-availability rule (``testing-contract`` spec): a test that shells out to an external
    binary must *skip*, not fail, where that binary is absent, so CI legs and dev
    machines without it stay green. ``unar`` also skips where archivey refuses the one
    on ``PATH`` (:func:`unar_refusal`). ``unrar`` means archivey's RARLAB data program
    (:func:`unrar_refusal`) rather than the command: ``rar`` 6.0+ alone runs the test,
    and so does a lookalike ``unrar`` beside it. A test that runs the ``unrar`` command
    itself is marked :func:`requires_unrar_cli` instead.
    """
    missing = [n for n in names if n != "unrar" and shutil.which(n) is None]
    reason = f"requires external binary(ies): {', '.join(missing)}"
    if not missing:
        for name, refuse in (("unar", unar_refusal), ("unrar", unrar_refusal)):
            if name not in names:
                continue
            refusal = refuse()
            if refusal is not None:
                missing = [name]
                reason = f"requires a {name} archivey will use: {refusal}"
                break
    return pytest.mark.skipif(bool(missing), reason=reason)


def requires_unrar_cli() -> pytest.MarkDecorator:
    """Skip a test that runs the ``unrar`` command unless archivey accepts that command.

    For an oracle test that spawns ``unrar`` itself (:func:`unrar_cli_refusal`). A test
    that only needs archivey to read RAR data uses ``requires_binary("unrar")``.
    """
    refusal = unrar_cli_refusal()
    return pytest.mark.skipif(
        refusal is not None, reason=f"requires a unrar archivey will use: {refusal}"
    )


SEVEN_ZIP_CLI_TIMEOUT = 30.0
"""Seconds a ``7z`` command-line run may take before :func:`run_7z` stops it."""


@overload
def run_7z(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = False,
    text: Literal[False] = False,
    input: bytes | None = None,
    timeout: float = SEVEN_ZIP_CLI_TIMEOUT,
    program: str = "7z",
) -> subprocess.CompletedProcess[bytes]: ...


@overload
def run_7z(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = False,
    text: Literal[True],
    input: str | None = None,
    timeout: float = SEVEN_ZIP_CLI_TIMEOUT,
    program: str = "7z",
) -> subprocess.CompletedProcess[str]: ...


def run_7z(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = False,
    text: bool = False,
    input: bytes | str | None = None,
    timeout: float = SEVEN_ZIP_CLI_TIMEOUT,
    program: str = "7z",
) -> subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str]:
    """Run the ``7z`` CLI with ``args``, capture its output, and bound how long it runs.

    A test that shells out to ``7z`` goes through here;
    ``tests/test_7z_cli_boundary.py`` enforces that and lists the files that still
    run ``7z`` directly. A run without a timeout once hung on a Windows CI leg; the
    per-test timeout then killed the xdist worker and left no traceback. With
    ``timeout`` the hang becomes a ``subprocess.TimeoutExpired`` in the test that
    caused it. Stdin is ``subprocess.DEVNULL`` unless ``input`` is given, so a prompt
    (for example a password or overwrite question) gets end-of-file instead of
    waiting. ``program`` names another 7-Zip CLI, such as ``7zz``.
    """
    return subprocess.run(
        [program, *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=text,
        input=input,
        stdin=subprocess.DEVNULL if input is None else None,
        timeout=timeout,
    )


@functools.cache
def sevenzip_lists_arm64() -> bool:
    """Whether ``7z i`` lists the ARM64 filter.

    p7zip 16.02, and Homebrew's ``7z`` on macOS, predate the filter and exit 2 on
    ``-m0=ARM64``. 7-Zip 23 and later name ARM64 in that listing. A missing ``7z``
    is false. A run that does not finish is false and is written to stderr once.
    A test that needs the filter skips on either answer.
    """
    if shutil.which("7z") is None:
        return False
    try:
        listing = run_7z(["i"], text=True).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        # The listing was not read. Report the failure once; the cache keeps it.
        print(f"7z i did not finish: {exc}", file=sys.stderr)
        return False
    return re.search(r"\bARM64\b", listing) is not None


@functools.cache
def sevenzip_with_riscv() -> str | None:
    """The first of ``7zz`` and ``7z`` on ``PATH`` whose ``7z i`` lists RISCV, or None.

    7-Zip 24 added the RISC-V filter; Ubuntu's ``7z`` (23.01) and p7zip predate it.
    ``scripts/install-7zip-from-source.sh`` builds a ``7zz`` that has it. A run that
    does not finish counts as not listing it and is written to stderr once.
    """
    for program in ("7zz", "7z"):
        if shutil.which(program) is None:
            continue
        try:
            listing = run_7z(["i"], text=True, program=program).stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"{program} i did not finish: {exc}", file=sys.stderr)
            continue
        if re.search(r"\bRISCV\b", listing):
            return program
    return None


def requires_zstd() -> pytest.MarkDecorator:
    """Skip when neither stdlib ``compression.zstd`` nor ``backports.zstd`` is importable."""
    has = _has_zstd_backend()
    return pytest.mark.skipif(
        not has,
        reason="requires zstd backend (compression.zstd or backports.zstd)",
    )


def _has_zstd_backend() -> bool:
    for name in ("compression.zstd", "backports.zstd"):
        try:
            if importlib.util.find_spec(name) is not None:
                return True
        except ModuleNotFoundError:
            continue
    return False


def zstd_backend():
    """Return the installed zstd codec module (stdlib on 3.14+, else backports)."""
    import importlib

    for name in ("compression.zstd", "backports.zstd"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    raise RuntimeError("no zstd backend installed")


def pytest_exception_interact(node, call, report) -> None:
    """Print the active fuzz mutation when a parametrized case times out or errors."""
    if call.when != "call" or "test_mutation_fuzz.py" not in node.nodeid:
        return
    from tests.test_mutation_fuzz import active_mutation_report

    msg = active_mutation_report()
    if msg is None:
        return
    tr = node.config.pluginmanager.get_plugin("terminalreporter")
    if tr is not None:
        tr.write_line(msg, red=True, bold=True)


def pytest_configure(config: pytest.Config) -> None:
    """Register the shared Hypothesis settings profile used by property-safety tests.

    Default: ``max_examples=100``, ``deadline=None``, ``derandomize=True`` (reproducible
    CI budget). ``ARCHIVEY_FUZZ_EXAMPLES`` selects a deeper local/nightly sweep — mirrors
    the mutation harness's ``ARCHIVEY_FUZZ_MUTATIONS`` pattern. Hypothesis is a ``dev``
    dependency; under ``[core-only]`` the import is absent and this is a no-op (the
    property module itself skips collection).
    """
    try:
        from hypothesis import settings
    except ImportError:
        return
    raw = os.environ.get("ARCHIVEY_FUZZ_EXAMPLES", "100")
    try:
        max_examples = int(raw)
    except ValueError as exc:
        raise pytest.UsageError(
            f"ARCHIVEY_FUZZ_EXAMPLES must be an integer, got {raw!r}"
        ) from exc
    settings.register_profile(
        "archivey",
        max_examples=max_examples,
        deadline=None,
        derandomize=True,
    )
    settings.load_profile("archivey")


@pytest.fixture
def test_dir(tmp_path: Path) -> Path:
    """Create a test directory with some files and subdirectories."""
    (tmp_path / "file1.txt").write_bytes(b"hello world")
    (tmp_path / "file2.txt").write_bytes(b"foo bar baz")
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_bytes(b"nested content")
    return tmp_path


@pytest.fixture
def named_fifo_with_writer() -> Iterator[Callable[[Path, bytes], None]]:
    """Make named FIFOs whose writer thread delivers a payload once the read end opens.

    The writer blocks in ``open()`` until something opens the read end, and in
    ``write()`` while a payload larger than the pipe buffer is not drained. A test whose
    code under test raises before reading would leave it blocked for the rest of the
    session, so teardown opens the read end itself, drains it and joins the writer.
    """
    writers: list[tuple[Path, threading.Thread]] = []

    def make(path: Path, payload: bytes) -> None:
        os.mkfifo(path)

        def _fill() -> None:
            try:
                with open(path, "wb") as writer:
                    writer.write(payload)
            except OSError:
                pass

        thread = threading.Thread(target=_fill, daemon=True)
        thread.start()
        writers.append((path, thread))

    yield make
    for path, thread in writers:
        if thread.is_alive():
            # Non-blocking, so this returns at once even if the writer already left.
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                deadline = time.monotonic() + 5
                while thread.is_alive() and time.monotonic() < deadline:
                    try:
                        os.read(fd, 1 << 16)
                    except BlockingIOError:
                        pass
                    thread.join(0.01)
            finally:
                os.close(fd)
        assert not thread.is_alive(), f"FIFO writer for {path} is still blocked"
