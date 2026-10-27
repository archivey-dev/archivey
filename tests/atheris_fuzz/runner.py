"""Shared Atheris runner: budgets, corpus, crash artifacts, typed-error contract."""

from __future__ import annotations

import os
import signal
import sys
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from tests.atheris_fuzz import DEFAULT_BUDGETS
from tests.atheris_fuzz.crc_fixup import FixupFn, apply_fixup
from tests.atheris_fuzz.seeds import write_seed_corpus

# Artifact root (CI uploads this directory on failure).
_DEFAULT_ARTIFACT_DIR = Path(
    os.environ.get("ARCHIVEY_FUZZ_ARTIFACT_DIR", "artifacts/atheris")
)

TargetFn = Callable[[bytes], None]


def budget_seconds(target: str, default: int | None = None) -> int:
    """Per-target wall budget. Env: ``ARCHIVEY_FUZZ_BUDGET_<TARGET_UPPER>``."""
    env_key = f"ARCHIVEY_FUZZ_BUDGET_{target.upper()}"
    raw = os.environ.get(env_key)
    if raw is not None:
        return max(0, int(raw))
    if default is not None:
        return default
    return DEFAULT_BUDGETS.get(target, 10)


def artifact_dir() -> Path:
    return Path(
        os.environ.get("ARCHIVEY_FUZZ_ARTIFACT_DIR", str(_DEFAULT_ARTIFACT_DIR))
    )


def repro_command(target: str, crash_path: Path) -> str:
    return (
        f"uv run --no-sync python -m tests.atheris_fuzz --target {target} "
        f"--repro {crash_path}"
    )


def persist_crash(target: str, data: bytes, *, reason: str) -> Path:
    out = artifact_dir() / target
    out.mkdir(parents=True, exist_ok=True)
    path = out / "crash-input.bin"
    path.write_bytes(data)
    meta = out / "crash-meta.txt"
    meta.write_text(
        f"reason={reason}\nrepro={repro_command(target, path)}\n", encoding="utf-8"
    )
    print(
        f"[atheris] crash persisted: {path} ({reason})\n"
        f"[atheris] repro: {repro_command(target, path)}",
        file=sys.stderr,
        flush=True,
    )
    return path


def _install_slice_alarm(seconds: float) -> None:
    """Hard wall-clock kill for a single TestOneInput (ISO hang class)."""

    def _handler(signum: int, frame: Any) -> None:
        raise TimeoutError(f"atheris input exceeded {seconds:.1f}s wall clock")

    signal.signal(signal.SIGALRM, _handler)
    # setitimer gives sub-second resolution; alarm() is integer-only.
    signal.setitimer(signal.ITIMER_REAL, seconds)


def _clear_slice_alarm() -> None:
    signal.setitimer(signal.ITIMER_REAL, 0)


def run_target(
    *,
    name: str,
    test_one_input: TargetFn,
    seeds: Sequence[bytes],
    budget: int | None = None,
    fixup: FixupFn | None = None,
    per_input_timeout: float | None = None,
    libfuzzer_args: Sequence[str] = (),
    argv: list[str] | None = None,
    smoke: bool = False,
) -> int:
    """Run one Atheris target. Returns process exit code (0 = success).

    Success contract: budget expires with only typed ``ArchiveyError`` or clean returns
    inside ``test_one_input`` (the target itself must swallow ``ArchiveyError``). Any other
    exception, timeout, or abort fails the run and persists the crashing input.

    ``libfuzzer_args`` are extra libFuzzer flags from the target spec (the accelerator
    targets' ``-timeout`` and ``-rss_limit_mb``). Their breaches are written by libFuzzer
    itself under the artifact prefix (``timeout-*``, ``oom-*``), not by ``persist_crash``.
    """
    import atheris

    seconds = 1 if smoke else budget_seconds(name, budget)
    if seconds <= 0 and not smoke:
        print(f"[atheris] skipping {name}: budget={seconds}", flush=True)
        return 0

    corpus = artifact_dir() / "corpus" / name
    write_seed_corpus(corpus, list(seeds))

    # libFuzzer flags: time budget, artifact prefix, jobs=1 (deterministic-ish CI).
    artifact_prefix = str(artifact_dir() / name) + "/"
    Path(artifact_prefix).mkdir(parents=True, exist_ok=True)
    lf_argv = [
        sys.argv[0],
        f"-max_total_time={max(1, seconds)}",
        f"-artifact_prefix={artifact_prefix}",
        "-print_final_stats=1",
        *libfuzzer_args,
        str(corpus),
    ]
    if argv:
        lf_argv.extend(argv)

    @atheris.instrument_func
    def _entry(data: bytes) -> None:
        payload = apply_fixup(data, fixup)
        if per_input_timeout is not None and per_input_timeout > 0:
            _install_slice_alarm(per_input_timeout)
        try:
            test_one_input(payload)
        except TimeoutError:
            persist_crash(name, payload, reason="per-input-timeout")
            raise
        except Exception as exc:
            # Targets must convert ArchiveyError to a soft return; anything else is a finding.
            persist_crash(name, payload, reason=type(exc).__name__)
            raise
        finally:
            if per_input_timeout is not None and per_input_timeout > 0:
                _clear_slice_alarm()

    try:
        # instrument_imports covers first-load; instrument_all rewrites already-imported
        # archivey modules so libFuzzer sees Python edge coverage (otherwise ft stays ~4).
        atheris.instrument_all()
        atheris.Setup(lf_argv, _entry)
        atheris.Fuzz()
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    except Exception:  # noqa: BLE001 — libFuzzer/setup failures must fail the job
        traceback.print_exc()
        return 1
    return 0


def run_repro(
    *,
    name: str,
    test_one_input: TargetFn,
    path: Path,
    fixup: FixupFn | None = None,
    per_input_timeout: float | None = None,
) -> int:
    """Replay a single crashing input without libFuzzer."""
    data = path.read_bytes()
    payload = apply_fixup(data, fixup)
    if per_input_timeout is not None and per_input_timeout > 0:
        _install_slice_alarm(per_input_timeout)
    try:
        test_one_input(payload)
    except Exception:  # noqa: BLE001 — repro must report any unexpected exception
        traceback.print_exc()
        persist_crash(name, payload, reason="repro-failure")
        return 1
    finally:
        if per_input_timeout is not None and per_input_timeout > 0:
            _clear_slice_alarm()
    print(f"[atheris] repro of {path} completed without exception", flush=True)
    return 0
