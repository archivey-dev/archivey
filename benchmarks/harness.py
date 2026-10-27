"""Benchmark harness: wall time, bytes decompressed, source seeks.

Run::

    uv run --extra all python -m benchmarks.harness
    uv run --extra all python -m benchmarks.harness --update-baselines
    uv run --extra all python -m benchmarks.harness --mode structural
    uv run --extra all python -m benchmarks.harness --mode full --scale realistic

``--update-baselines`` requires the *complete* toolchain (all extras **and** RARLAB
``unrar`` on PATH) and refuses up front otherwise: a partial run would rewrite
``structural.json`` without the cases it could not measure, quietly shrinking what the
gate covers. ``missing_baseline_requirements()`` names what is absent.

Modes:

- ``structural`` (default for CI/PR): **the automated gate** — seek-count baselines,
  solid decode-once bounds, and a non-solid over-decode bound on ``read_all``.
  Under-decode remains an integrity check; over-decode catches silent re-open churn
  that the old seek slack (baseline×2+8) used to absorb.
- ``full``: also report wall-time ratios vs stdlib peers, and the per-member cost and
  throughput fitted by ``benchmarks/cost_model.py``. Absolute ratios are noisy
  on shared runners, so full mode is **not** a PR gate. The change-guarded nightly
  (``benchmark-wall.yml``) hard-fails on (1) the ~10× sanity ceiling and (2)
  **wall-ratio drift** vs the JSON artifact of the last run that measured, pass or
  fail (perf-review Q2 / debt-ledger Q1 option (a)). Quiet days re-publish that
  artifact (preserving ``measured_at``); a full re-measure is forced at least
  every ~30 days. VISION absolute bands stay informational prints.

Comparing two revisions (read this before believing a wall-time delta):

- **Check the workload before the clock.** Fixture sizes change over time — #328 took
  the ZIP/TAR fixtures from ~32 KiB to ~128 KiB — so ``wall_s`` is not comparable
  across a range that crosses such a commit. Diff ``bytes_decompressed`` and
  ``unpacked_bytes`` per case first; where they differ, compare wall *per byte* or
  not at all. Skipping this reads as a 2-3x regression on exactly the cases whose
  fixture grew, which is how one nearly got reported.
- **Pin both sides by SHA.** A local ``main`` in a fresh container can be far behind
  ``origin/main``; ``git checkout main`` then silently measures something else.
  ``git rev-parse`` both revisions and put the SHAs in the write-up.
- **One run each way cannot resolve a small effect.** Per-case wall noise here is
  roughly +-7%. Alternate the two revisions (A, B, A, B, ...) so drift cancels, take
  the per-case *minimum* over 15-20 runs, and establish the floor with a null control
  — the identical procedure with the same SHA on both sides, which should come out
  near 50/50 with a median near zero. A consistent sign across cases is the signal;
  a sign test over the per-case deltas states it honestly. A structural run is ~2 s,
  so 20 alternating pairs costs about 90 s.
- Structural fields (``bytes_decompressed``, ``source_seek_count``) are exact and need
  none of this: diff them directly.

Formats covered here: ZIP (deflate / LZMA / WinZip AES / ZipCrypto), TAR, gzip,
``.Z`` (text-like and a long zero run, which builds long LZW dictionary entries),
tar.gz/tar.bz2 (+ accelerators), in-ZIP accelerated deflate, solid 7z, and RAR
data paths on committed fixtures when RARLAB ``unrar`` is present (large solid
RAR when the ``rar`` writer can build one). Listing wall peers: ``zipfile`` /
``tarfile`` / ``py7zr`` / ``rarfile`` (Q1 bands); ``benchmarks/peers.py`` reports
list, read and extract against py7zr / rarfile / libarchive-c, outside the gate.
ISO and directory backends are instrumented for measurement but deliberately out
of scope for this harness — see ``benchmarks/tar_iso_lock_baseline.py`` for ISO.
"""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import shutil
import sys
import tarfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from archivey import open_archive
from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.exceptions import PackageNotInstalledError
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.measurement import enable_measurement
from benchmarks.cost_model import format_cost_model, run_cost_model
from benchmarks.fixtures import (
    SCALES,
    ZIP_AES_PASSWORD,
    ZIPCRYPTO_PASSWORD,
    FixtureSet,
    materialize_fixtures,
)
from benchmarks.wall_baseline import (
    measurement_provenance,
    overlapping_wall_ratio_count,
    wall_ratio_map,
)

ROOT = Path(__file__).resolve().parents[1]
BASELINES_DIR = Path(__file__).resolve().parent / "baselines"
STRUCTURAL_BASELINE = BASELINES_DIR / "structural.json"

# Sequential solid read may decode a little padding / skip; keep a small slack factor.
# (Unit tests use a tighter bound on controlled fixtures — see test_measurement.py.)
# Was 2.0: that let a clean "decode every solid folder exactly twice" regression
# pass (perf review G3 / VISION "re-reads a solid block fails the benchmark").
SOLID_DECODE_FACTOR = 1.25
# Non-solid read_all over-decode guard. Output-counting makes under-decode the
# only previous check; without an upper bound, a decode-twice-deliver-once ZIP
# regression doubles bytes_decompressed and still passes (perf review G4).
NONSOLID_DECODE_FACTOR = 1.1
# Random-access solid cost is inherent, but bound it against the committed
# baseline so a folder-cache regression cannot silently double the work (G5).
SOLID_RANDOM_BYTES_FACTOR = 1.5
# Seek-count slack against the committed ci baseline (two-sided: baseline±slack).
# Was baseline×2+8 (upper-only), which absorbed a full ZIP decode-twice seek doubling
# (28→52) and could not catch silent non-engagement of paths that seek *more*
# (in-ZIP accel ON 44 → OFF 28). Fixtures are deterministic; ±8 covers host jitter.
SEEK_BASELINE_SLACK = 8
# Wall-time sanity ceiling for --mode full. Absolute VISION ≤1.3× / ~2× bands stay
# informational (shared-runner noise); nightly enforces *drift* vs the last measured
# run's JSON instead (debt-ledger Q1 / perf Q2 option (a)).
WALL_RATIO_BUDGET = 10.0
WALL_RATIO_VISION = 1.3
WALL_RATIO_VISION_SAFETY = 2.0
# Relative wall_ratio regression vs previous nightly. Dual gate: new > old×factor
# AND new − old ≥ min abs delta (avoids failing 1.02→1.08 noise on near-parity paths).
WALL_RATIO_DRIFT_FACTOR = 1.25
WALL_RATIO_DRIFT_MIN_ABS = 0.15
# Third drift condition: the drift must also cost at least this much wall time,
# (new − old ratio) × this run's stdlib time. A sub-millisecond listing case can move
# its ratio by 2× on scheduler noise alone: rar_open_list went 2.60 → 5.71 (1.0 ms vs
# a 0.2 ms peer) between the 2026-09-06 run and nightly run 34122511826 on 2026-09-07,
# with no change to RAR listing cost that large. That one night froze the nightly
# baseline for a month. Gross slowdowns of tiny cases still fail on the 10× ceiling.
WALL_RATIO_DRIFT_MIN_EXTRA_S = 0.001
# Q1 listing bands (informational in full-mode reports; not PR-gated):
# ZIP (stdlib) and TAR (native walker) → 2–3×/member vs zipfile/tarfile; native
# 7z/RAR → ≈parity with py7zr/rarfile.
LISTING_RATIO_ZIP_TAR = 3.0
LISTING_RATIO_NATIVE = 1.25


@dataclass
class CaseResult:
    case: str
    format: str
    operation: str
    wall_s: float
    bytes_decompressed: int
    source_seek_count: int
    unpacked_bytes: int | None = None
    stdlib_wall_s: float | None = None
    wall_ratio: float | None = None
    notes: str = ""

    skipped: bool = False
    """True when the case could not run (missing optional dependency).

    Its axes are then all zero, meaning *no data* — not a measurement of zero. Every
    structural rule must ignore such a row: a zero that means "never ran" is otherwise
    indistinguishable from a real short read or a non-engaging accelerator, and gets
    reported as one. Carry the reason in ``notes``.
    """


def _as_base(reader: Any) -> BaseArchiveReader:
    assert isinstance(reader, BaseArchiveReader)
    return reader


def _accel_skipped_case(case: str, fmt: str) -> CaseResult:
    """Row for an accelerator-ON case that could not run (no rapidgzip installed).

    Emitted rather than omitted so a local report still shows *why* the accelerator
    case is absent; the structural gate fails closed on it in CI. ``skipped=True`` and
    a ``None`` ``unpacked_bytes`` keep it out of the structural rules — it once carried
    the fixture's real size (that size *is* a property of the fixture, so filling it in
    looked harmless), which made a missing extra surface as
    ``bytes_decompressed=0 < unpacked=...``: a codec-shaped failure for a
    packaging-shaped cause.
    """
    return CaseResult(
        case,
        fmt,
        "read_all",
        0.0,
        0,
        0,
        notes="skipped: rapidgzip not installed ([seekable] extra)",
        skipped=True,
    )


def _op_open_list(path: Path) -> tuple[int, int]:
    with enable_measurement(), open_archive(path) as reader:
        base = _as_base(reader)
        _ = reader.info
        list(reader.members())
        return base.bytes_decompressed, base.source_seek_count


def _accel_config(*, enabled: bool) -> ArchiveyConfig:
    """Force rapidgzip / indexed-bzip2 (via rapidgzip's IndexedBzip2File) on or off.

    ``ON`` engages the accelerator even without ``seekable_members=True`` (AUTO would
    not). The bzip2 accelerator is rapidgzip's bundled decoder, not the separate
    ``indexed_bzip2`` package — see codecs/deps.py.
    """
    mode = AcceleratorMode.ON if enabled else AcceleratorMode.OFF
    return ArchiveyConfig(use_rapidgzip=mode, use_indexed_bzip2=mode)


def _op_read_all(
    path: Path,
    *,
    config: ArchiveyConfig | None = None,
    seekable_members: bool = False,
    password: bytes | str | None = None,
) -> tuple[int, int, int]:
    with (
        enable_measurement(),
        open_archive(
            path, config=config, seekable_members=seekable_members, password=password
        ) as reader,
    ):
        base = _as_base(reader)
        unpacked = 0
        for member, stream in reader.stream_members():
            if stream is not None:
                data = stream.read()
                unpacked += len(data)
        return base.bytes_decompressed, base.source_seek_count, unpacked


_extract_n = 0


def _op_extract(path: Path, dest_root: Path) -> tuple[int, int]:
    global _extract_n
    _extract_n += 1
    dest = dest_root / f"run-{_extract_n}"
    dest.mkdir(parents=True, exist_ok=True)
    with enable_measurement(), open_archive(path) as reader:
        base = _as_base(reader)
        reader.extract_all(dest)
        return base.bytes_decompressed, base.source_seek_count


def _op_read_all_unmeasured(
    path: Path,
    *,
    config: ArchiveyConfig | None = None,
    seekable_members: bool = False,
    password: bytes | str | None = None,
) -> None:
    """Read every member without measurement wrappers — fair wall-time peer."""
    with open_archive(
        path, config=config, seekable_members=seekable_members, password=password
    ) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


def _op_random_read_all(
    path: Path, *, password: bytes | str | None = None
) -> tuple[int, int]:
    with enable_measurement(), open_archive(path, password=password) as reader:
        base = _as_base(reader)
        names = [m.name for m in reader.members() if m.is_file]
        for name in reversed(names):
            reader.read(name)
        return base.bytes_decompressed, base.source_seek_count


def _timed(fn: Callable[[], Any]) -> tuple[float, Any]:
    t0 = time.perf_counter()
    result = fn()
    return time.perf_counter() - t0, result


def _interleaved_pair_times(
    archivey_fn: Callable[[], Any],
    stdlib_fn: Callable[[], None],
    *,
    rounds: int = 5,
) -> tuple[float, Any, float]:
    """Alternate archivey/stdlib timing; return (median_ay_s, ay_result, median_std_s).

    One shared warmup of each side first. Alternating order removes the
    "whoever ran last left the page cache hot" bias. Diagnostic log spam is
    silenced for the timed window — ZIP name-encoding advisories otherwise
    flood stderr and skew sub-20ms samples (early runs reported archivey
    *faster* than ``zipfile``, which is impossible as a steady state since we
    wrap it).
    """
    import logging

    archivey_fn()
    stdlib_fn()
    ay_samples: list[float] = []
    std_samples: list[float] = []
    last_ay: Any = None
    prev_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        for i in range(rounds):
            if i % 2 == 0:
                wall, last_ay = _timed(archivey_fn)
                ay_samples.append(wall)
                wall, _ = _timed(stdlib_fn)
                std_samples.append(wall)
            else:
                wall, _ = _timed(stdlib_fn)
                std_samples.append(wall)
                wall, last_ay = _timed(archivey_fn)
                ay_samples.append(wall)
    finally:
        logging.disable(prev_disable)
    ay_samples.sort()
    std_samples.sort()
    mid = len(ay_samples) // 2
    return ay_samples[mid], last_ay, std_samples[mid]


def _stdlib_zip_open_list(path: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        zf.namelist()
        zf.infolist()


def _stdlib_zip_extract(path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)


def _stdlib_zip_read_all(path: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            info = zf.getinfo(name)
            if info.is_dir():
                continue
            zf.read(name)


def _stdlib_tar_read_all(path: Path) -> None:
    with tarfile.open(path, "r:") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if f is not None:
                f.read()


def _stdlib_tar_open_list(path: Path) -> None:
    with tarfile.open(path, "r:") as tf:
        tf.getmembers()


def _py7zr_open_list(path: Path) -> None:
    import py7zr

    with py7zr.SevenZipFile(path, "r") as archive:
        list(archive.list())


def _rarfile_open_list(path: Path) -> None:
    import rarfile

    with rarfile.RarFile(path) as archive:
        archive.infolist()


def _py7zr_available() -> bool:
    try:
        import py7zr  # noqa: F401

        return True
    except ImportError:
        return False


def _rarfile_available() -> bool:
    try:
        import rarfile  # noqa: F401

        return True
    except ImportError:
        return False


def _stdlib_gzip_read_all(path: Path) -> None:
    with gzip.open(path, "rb") as gf:
        gf.read()


def _stdlib_targz_read_all(path: Path) -> None:
    # Iterate rather than getmembers(): listing first decompresses to the end, and
    # the first extractfile() then seeks back, which restarts the decompression. The
    # restart is a property of a compressed stream: the plain-tar peers above keep
    # getmembers(), because seeking back in an uncompressed file costs nothing.
    with tarfile.open(path, "r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if f is not None:
                f.read()


def _stdlib_tarbz2_read_all(path: Path) -> None:
    # Iterate rather than getmembers(): listing first decompresses to the end, and
    # the first extractfile() then seeks back, which restarts the decompression. The
    # restart is a property of a compressed stream: the plain-tar peers above keep
    # getmembers(), because seeking back in an uncompressed file costs nothing.
    with tarfile.open(path, "r:bz2") as tf:
        for member in tf:
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if f is not None:
                f.read()


def _rapidgzip_available() -> bool:
    try:
        import rapidgzip  # noqa: F401

        return True
    except ImportError:
        return False


def _ncompress_available() -> bool:
    """True when ``ncompress`` (dev dependency) is importable — it writes the ``.Z``
    fixtures."""
    return importlib.util.find_spec("ncompress") is not None


def _unrar_available() -> bool:
    """True when RARLAB ``unrar`` is on PATH (needed for RAR *data* cases)."""
    try:
        from archivey.internal.backends.rar_unrar import find_rarlab_unrar

        find_rarlab_unrar()
        return True
    except PackageNotInstalledError:
        return False


def _crypto_available() -> bool:
    """True when the ``cryptography`` package is importable (``[crypto]`` extra)."""
    return importlib.util.find_spec("cryptography") is not None


def missing_baseline_requirements() -> list[str]:
    """Optional tooling whose absence would make a baseline rewrite *partial*.

    Every entry gates cases that are in the committed ``structural.json``. Without the
    tool those cases either never reach the file (dropped outright) or arrive as skip
    rows, and the next run gates against a baseline describing less than the suite
    actually measures — silently, since a shorter file still validates.
    """
    checks = (
        (
            _rapidgzip_available(),
            "rapidgzip — the accelerator ON cases; install the [seekable] extra",
        ),
        (
            _py7zr_available(),
            "py7zr — builds the solid 7z fixture behind the sevenzip_* cases",
        ),
        (
            _crypto_available(),
            "cryptography — zip_aes_read_all / encrypted RAR; install the [crypto] extra",
        ),
        (
            _unrar_available(),
            "unrar — the RARLAB binary on PATH; the rar_* data cases",
        ),
        (
            _ncompress_available(),
            "ncompress — builds the .Z fixtures behind the z_* cases; dev group",
        ),
    )
    return [why for available, why in checks if not available]


def run_cases(
    fixtures: FixtureSet,
    work: Path,
    *,
    warmup: bool = False,
) -> list[CaseResult]:
    results: list[CaseResult] = []

    def timed_with_optional_warmup(fn: Callable[[], Any]) -> tuple[float, Any]:
        if warmup:
            fn()  # discard — fill page cache / import side effects
        return _timed(fn)

    # Wall-ratio cases: interleaved medians when warmup is on (realistic scale).
    # Structural metrics come from a separate measured pass — wall timing must not
    # install seek/output counters (those change the ZIP open path and skew ~10ms
    # samples enough to invent a bogus "faster than zipfile" ratio).
    def pair_wall(
        std_fn: Callable[[], None],
        path: Path,
        *,
        config: ArchiveyConfig | None = None,
        seekable_members: bool = False,
    ) -> tuple[float, float]:
        def ay() -> None:
            _op_read_all_unmeasured(
                path, config=config, seekable_members=seekable_members
            )

        if warmup:
            ay_wall, _ignored, std_wall = _interleaved_pair_times(
                ay,
                std_fn,
                rounds=7,
            )
            return ay_wall, std_wall
        wall, _ = timed_with_optional_warmup(ay)
        std_wall, _ = timed_with_optional_warmup(std_fn)
        return wall, std_wall

    # --- ZIP ---
    # open_list wall vs zipfile (structural bytes from the measured pass).
    _m_wall, (bdec, seeks) = timed_with_optional_warmup(
        lambda: _op_open_list(fixtures.zip_path)
    )

    def _ay_open_list() -> None:
        with open_archive(fixtures.zip_path) as reader:
            _ = reader.info
            list(reader.members())

    if warmup:
        wall, _ignored, std_wall = _interleaved_pair_times(
            _ay_open_list,
            lambda: _stdlib_zip_open_list(fixtures.zip_path),
            rounds=7,
        )
    else:
        wall, _ = timed_with_optional_warmup(_ay_open_list)
        std_wall, _ = timed_with_optional_warmup(
            lambda: _stdlib_zip_open_list(fixtures.zip_path)
        )
    results.append(
        CaseResult(
            "zip_open_list",
            "zip",
            "open_list",
            wall,
            bdec,
            seeks,
            stdlib_wall_s=std_wall,
            wall_ratio=(wall / std_wall) if std_wall > 0 else None,
            notes="vs zipfile; Q1 listing band 2–3×",
        )
    )
    # Structural bytes from a measured pass; wall ratio from an unmeasured peer race.
    _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
        lambda: _op_read_all(fixtures.zip_path)
    )
    wall, std_wall = pair_wall(
        lambda: _stdlib_zip_read_all(fixtures.zip_path),
        fixtures.zip_path,
    )
    results.append(
        CaseResult(
            "zip_read_all",
            "zip",
            "read_all",
            wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,
            stdlib_wall_s=std_wall,
            wall_ratio=(wall / std_wall) if std_wall > 0 else None,
        )
    )
    _m_wall, (bdec, seeks) = timed_with_optional_warmup(
        lambda: _op_extract(fixtures.zip_path, work / "extract-zip")
    )
    _ext_i = 0

    def _ay_extract_clean() -> None:
        nonlocal _ext_i
        _ext_i += 1
        dest = work / "extract-zip-wall" / f"ay-{_ext_i}"
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        with open_archive(fixtures.zip_path) as reader:
            reader.extract_all(dest)

    def _std_extract_clean() -> None:
        nonlocal _ext_i
        _ext_i += 1
        dest = work / "extract-zip-wall" / f"std-{_ext_i}"
        if dest.exists():
            shutil.rmtree(dest)
        _stdlib_zip_extract(fixtures.zip_path, dest)

    if warmup:
        wall, _ignored, std_wall = _interleaved_pair_times(
            _ay_extract_clean, _std_extract_clean, rounds=7
        )
    else:
        wall, _ = timed_with_optional_warmup(_ay_extract_clean)
        std_wall, _ = timed_with_optional_warmup(_std_extract_clean)
    results.append(
        CaseResult(
            "zip_extract",
            "zip",
            "extract",
            wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,  # same fixture as zip_read_all
            stdlib_wall_s=std_wall,
            wall_ratio=(wall / std_wall) if std_wall > 0 else None,
        )
    )

    # --- ZIP LZMA (native codec path; stdlib zipfile writes, archivey lzma reads) ---
    _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
        lambda: _op_read_all(fixtures.zip_lzma_path)
    )
    results.append(
        CaseResult(
            "zip_lzma_read_all",
            "zip",
            "read_all",
            _m_wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,
            notes="native ZIP LZMA codec; no stdlib peer (zipfile writes only)",
        )
    )

    # --- ZIP WinZip AES (VerifyingStream + [crypto]; skip when extra absent) ---
    if fixtures.zip_aes_path is not None and _crypto_available():
        aes_path = fixtures.zip_aes_path
        _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda: _op_read_all(aes_path, password=ZIP_AES_PASSWORD)
        )
        results.append(
            CaseResult(
                "zip_aes_read_all",
                "zip",
                "read_all",
                _m_wall,
                bdec,
                seeks,
                unpacked_bytes=unpacked,
                notes="WinZip AES-256 AE-2; requires [crypto]",
            )
        )

    # --- ZIP ZipCrypto (pure-Python decrypt loop; STORED so the cipher dominates) ---
    _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
        lambda: _op_read_all(fixtures.zipcrypto_path, password=ZIPCRYPTO_PASSWORD)
    )
    results.append(
        CaseResult(
            "zipcrypto_read_all",
            "zip",
            "read_all",
            _m_wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,
            notes="ZipCrypto STORED member; times the pure-Python decrypt loop",
        )
    )

    # --- In-ZIP accelerated deflate (forced ON/OFF; mirrors tar.gz accelerator cases) ---
    # AUTO would decline below RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE; ON exercises the
    # per-member rapidgzip path that G7 noted was missing from the harness.
    has_accel = _rapidgzip_available()
    cfg_zip_off = _accel_config(enabled=False)
    _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
        lambda: _op_read_all(fixtures.zip_path, config=cfg_zip_off)
    )
    # Wall time unmeasured, as for the ON row below, so the pair compares.
    wall, _ = timed_with_optional_warmup(
        lambda: _op_read_all_unmeasured(fixtures.zip_path, config=cfg_zip_off)
    )
    results.append(
        CaseResult(
            "zip_read_all_accel_off",
            "zip",
            "read_all",
            wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,
            notes=(
                "stdlib deflate codec; accelerators forced OFF; counts from the "
                "measured route, wall time from the unmeasured one"
            ),
        )
    )
    if has_accel:
        cfg_zip_on = _accel_config(enabled=True)
        _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda: _op_read_all(
                fixtures.zip_path, config=cfg_zip_on, seekable_members=True
            )
        )
        # Two routes. With measurement on, the seek counter wraps the archive handle,
        # so the child reads each member through the parent and every seek is counted
        # (``file_region`` finds no file under the counter). Without it, on POSIX, the
        # child reads the archive file itself: the route callers get, timed here.
        wall, _ = timed_with_optional_warmup(
            lambda: _op_read_all_unmeasured(
                fixtures.zip_path, config=cfg_zip_on, seekable_members=True
            )
        )
        results.append(
            CaseResult(
                "zip_read_all_accel_on",
                "zip",
                "read_all",
                wall,
                bdec,
                seeks,
                unpacked_bytes=unpacked,
                notes=(
                    "rapidgzip accelerator ON for in-ZIP deflate ([seekable]); count "
                    "depends on the rapidgzip version, so the gate checks only ON > OFF; "
                    "counts are from the measured route (child reads through the "
                    "parent), wall time from the unmeasured one (on POSIX, the child "
                    "reads the file)"
                ),
            )
        )
    else:
        results.append(_accel_skipped_case("zip_read_all_accel_on", "zip"))

    # --- TAR (plain / uncompressed — harness peer is tarfile r:) ---
    _m_wall, (bdec, seeks) = timed_with_optional_warmup(
        lambda: _op_open_list(fixtures.tar_path)
    )

    def _ay_tar_open_list() -> None:
        with open_archive(fixtures.tar_path) as reader:
            _ = reader.info
            list(reader.members())

    if warmup:
        wall, _ignored, std_wall = _interleaved_pair_times(
            _ay_tar_open_list,
            lambda: _stdlib_tar_open_list(fixtures.tar_path),
            rounds=7,
        )
    else:
        wall, _ = timed_with_optional_warmup(_ay_tar_open_list)
        std_wall, _ = timed_with_optional_warmup(
            lambda: _stdlib_tar_open_list(fixtures.tar_path)
        )
    results.append(
        CaseResult(
            "tar_open_list",
            "tar",
            "open_list",
            wall,
            bdec,
            seeks,
            stdlib_wall_s=std_wall,
            wall_ratio=(wall / std_wall) if std_wall > 0 else None,
            notes="vs tarfile.getmembers; Q1 listing band 2–3×",
        )
    )
    _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
        lambda: _op_read_all(fixtures.tar_path)
    )
    wall, std_wall = pair_wall(
        lambda: _stdlib_tar_read_all(fixtures.tar_path),
        fixtures.tar_path,
    )
    results.append(
        CaseResult(
            "tar_read_all",
            "tar",
            "read_all",
            wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,
            stdlib_wall_s=std_wall,
            wall_ratio=(wall / std_wall) if std_wall > 0 else None,
            notes="plain uncompressed TAR vs tarfile r: (not .tar.gz)",
        )
    )

    # --- gzip single-file ---
    _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
        lambda: _op_read_all(fixtures.gzip_path)
    )
    wall, std_wall = pair_wall(
        lambda: _stdlib_gzip_read_all(fixtures.gzip_path),
        fixtures.gzip_path,
    )
    results.append(
        CaseResult(
            "gzip_read_all",
            "gzip",
            "read_all",
            wall,
            bdec,
            seeks,
            unpacked_bytes=unpacked,
            stdlib_wall_s=std_wall,
            wall_ratio=(wall / std_wall) if std_wall > 0 else None,
        )
    )

    # --- unix-compress (.Z) single-file: archivey's own pure-Python LZW decoder ---
    # No stdlib peer, and a C decoder (ncompress) would sit far past the wall ceiling,
    # so these rows carry wall time and structure only. The zero run builds dictionary
    # entries longer than the flat-entry cap, so it times the linked-entry path.
    for z_case, z_path in (
        ("z_text_read_all", fixtures.unix_compress_text_path),
        ("z_zeros_read_all", fixtures.unix_compress_zeros_path),
    ):
        if z_path is None:
            results.append(
                CaseResult(
                    z_case,
                    "Z",
                    "read_all",
                    0.0,
                    0,
                    0,
                    notes="skipped: ncompress not installed (dev group)",
                    skipped=True,
                )
            )
            continue
        _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda p=z_path: _op_read_all(p)
        )
        wall, _ = timed_with_optional_warmup(
            lambda p=z_path: _op_read_all_unmeasured(p)
        )
        results.append(
            CaseResult(
                z_case,
                "Z",
                "read_all",
                wall,
                bdec,
                seeks,
                unpacked_bytes=unpacked,
                notes=(
                    "pure-Python LZW; no stdlib peer; "
                    "+1 byte is the one-byte probe read at open"
                ),
            )
        )

    # --- .tar.gz / .tar.bz2 with accelerators off vs on ---
    # Default AUTO leaves accelerators off unless SEEKABLE is declared; we force ON/OFF
    # explicitly. bzip2 accelerator = rapidgzip.IndexedBzip2File (not indexed_bzip2 pkg).
    has_accel = _rapidgzip_available()
    for label, path, std_fn, fmt in (
        ("targz", fixtures.targz_path, _stdlib_targz_read_all, "tar.gz"),
        ("tarbz2", fixtures.tarbz2_path, _stdlib_tarbz2_read_all, "tar.bz2"),
    ):
        cfg_off = _accel_config(enabled=False)
        _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda p=path, c=cfg_off: _op_read_all(p, config=c)
        )
        wall_off, std_wall = pair_wall(
            lambda p=path, s=std_fn: s(p), path, config=cfg_off
        )
        results.append(
            CaseResult(
                f"{label}_read_all_accel_off",
                fmt,
                "read_all",
                wall_off,
                bdec,
                seeks,
                unpacked_bytes=unpacked,
                stdlib_wall_s=std_wall,
                wall_ratio=(wall_off / std_wall) if std_wall > 0 else None,
                notes="stdlib gzip/bz2 codec; accelerators forced OFF",
            )
        )
        if not has_accel:
            results.append(_accel_skipped_case(f"{label}_read_all_accel_on", fmt))
            continue
        cfg_on = _accel_config(enabled=True)
        # seekable_members so AUTO would also engage; ON engages either way. Matches
        # the intended accelerator use case (indexed / parallel decode).
        _m_wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda p=path, c=cfg_on: _op_read_all(p, config=c, seekable_members=True)
        )
        wall_on, std_wall_on = pair_wall(
            lambda p=path, s=std_fn: s(p),
            path,
            config=cfg_on,
            seekable_members=True,
        )
        speedup = (wall_off / wall_on) if wall_on > 0 else None
        speedup_note = f"; vs accel_off {speedup:.2f}×" if speedup is not None else ""
        results.append(
            CaseResult(
                f"{label}_read_all_accel_on",
                fmt,
                "read_all",
                wall_on,
                bdec,
                seeks,
                unpacked_bytes=unpacked,
                stdlib_wall_s=std_wall_on,
                wall_ratio=(wall_on / std_wall_on) if std_wall_on > 0 else None,
                notes=f"rapidgzip accelerator ON{speedup_note}",
            )
        )

    # --- Solid 7z ---
    if fixtures.solid_7z is not None:
        _m_wall, (bdec, seeks) = timed_with_optional_warmup(
            lambda: _op_open_list(fixtures.solid_7z)  # type: ignore[arg-type]
        )
        solid_7z_path = fixtures.solid_7z

        def _ay_7z_open_list() -> None:
            with open_archive(solid_7z_path) as reader:
                _ = reader.info
                list(reader.members())

        if _py7zr_available():
            if warmup:
                wall, _ignored, std_wall = _interleaved_pair_times(
                    _ay_7z_open_list,
                    lambda: _py7zr_open_list(solid_7z_path),
                    rounds=7,
                )
            else:
                wall, _ = timed_with_optional_warmup(_ay_7z_open_list)
                std_wall, _ = timed_with_optional_warmup(
                    lambda: _py7zr_open_list(solid_7z_path)
                )
            results.append(
                CaseResult(
                    "sevenzip_open_list",
                    "7z",
                    "open_list",
                    wall,
                    bdec,
                    seeks,
                    stdlib_wall_s=std_wall,
                    wall_ratio=(wall / std_wall) if std_wall > 0 else None,
                    notes="vs py7zr.list; Q1 native listing target ≈parity",
                )
            )
        else:
            wall, _ = timed_with_optional_warmup(_ay_7z_open_list)
            results.append(
                CaseResult(
                    "sevenzip_open_list",
                    "7z",
                    "open_list",
                    wall,
                    bdec,
                    seeks,
                    notes="skipped peer: py7zr not installed",
                )
            )
        wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda: _op_read_all(fixtures.solid_7z)  # type: ignore[arg-type]
        )
        results.append(
            CaseResult(
                "sevenzip_solid_sequential",
                "7z",
                "read_all_sequential",
                wall,
                bdec,
                seeks,
                unpacked_bytes=fixtures.unpacked_solid_7z,
                notes="solid invariant: bytes_decompressed <= unpacked * factor",
            )
        )
        wall, (bdec, seeks) = timed_with_optional_warmup(
            lambda: _op_random_read_all(fixtures.solid_7z)  # type: ignore[arg-type]
        )
        results.append(
            CaseResult(
                "sevenzip_solid_random",
                "7z",
                "read_all_random",
                wall,
                bdec,
                seeks,
                unpacked_bytes=fixtures.unpacked_solid_7z,
                notes="re-decode recorded; gated vs baseline×SOLID_RANDOM_BYTES_FACTOR",
            )
        )

    def _append_7z_open_list(
        case: str,
        path: Path,
        *,
        notes: str,
    ) -> None:
        _m_wall, (bdec, seeks) = timed_with_optional_warmup(
            lambda p=path: _op_open_list(p)
        )

        def _ay() -> None:
            with open_archive(path) as reader:
                _ = reader.info
                list(reader.members())

        if _py7zr_available():
            if warmup:
                wall, _ignored, std_wall = _interleaved_pair_times(
                    _ay,
                    lambda p=path: _py7zr_open_list(p),
                    rounds=7,
                )
            else:
                wall, _ = timed_with_optional_warmup(_ay)
                std_wall, _ = timed_with_optional_warmup(
                    lambda p=path: _py7zr_open_list(p)
                )
            results.append(
                CaseResult(
                    case,
                    "7z",
                    "open_list",
                    wall,
                    bdec,
                    seeks,
                    stdlib_wall_s=std_wall,
                    wall_ratio=(wall / std_wall) if std_wall > 0 else None,
                    notes=notes,
                )
            )
        else:
            wall, _ = timed_with_optional_warmup(_ay)
            results.append(
                CaseResult(
                    case,
                    "7z",
                    "open_list",
                    wall,
                    bdec,
                    seeks,
                    notes=f"{notes}; skipped peer: py7zr not installed",
                )
            )

    # Many-member solid COPY listing — regression guard for per-folder caches.
    # The LZMA2 solid fixture above is too few members for this signal to clear noise.
    if fixtures.many_7z is not None:
        n = fixtures.scale.list_members
        _append_7z_open_list(
            "sevenzip_many_open_list",
            fixtures.many_7z,
            notes=(
                f"vs py7zr.list; {n} tiny COPY members (solid); "
                "listing-cost regression guard"
            ),
        )

    # Non-solid listing negative control (7z -ms=off): cache misses every member.
    if fixtures.nonsolid_7z is not None:
        n = fixtures.scale.nonsolid_list_members
        _append_7z_open_list(
            "sevenzip_nonsolid_open_list",
            fixtures.nonsolid_7z,
            notes=(
                f"vs py7zr.list; {n} store members (-ms=off); "
                "negative control (no per-folder amortize)"
            ),
        )

    # --- 7z BCJ branch filter (x86) ---
    # archivey stages branch filters through liblzma rather than through pybcj
    # (see dev-docs/investigations/pybcj-upstream-report.md). liblzma refuses a raw
    # chain whose only filter is a branch filter, so a separately-staged BCJ reframes
    # its input as LZMA2 uncompressed chunks; these cases are what makes that
    # reframing cost visible.
    # ``copy`` isolates the filter, ``lzma1`` is the shape that forces the staging
    # (the 7-Zip CLI writes LZMA1 without an end-of-stream marker), and ``lzma2``
    # is the common executable-archive shape, where liblzma runs the whole chain
    # itself and no reframing happens at all — the control.
    _BCJ_NOTES = {
        "lzma2": "BCJ+LZMA2: one liblzma chain, no reframing (control)",
        "lzma1": "BCJ+LZMA1 (no EOS): BCJ staged separately, reframed as LZMA2 chunks",
        "copy": "BCJ+Copy: branch filter is the whole decode cost",
    }
    for label in ("lzma2", "lzma1", "copy"):
        bcj_path = fixtures.bcj_7z.get(label)
        if bcj_path is None:
            continue
        wall, (bdec, seeks, _unpacked) = timed_with_optional_warmup(
            lambda p=bcj_path: _op_read_all(p)
        )
        results.append(
            CaseResult(
                f"sevenzip_bcj_{label}_read_all",
                "7z",
                "read_all_sequential",
                wall,
                bdec,
                seeks,
                unpacked_bytes=fixtures.unpacked_bcj_7z,
                notes=_BCJ_NOTES[label],
            )
        )

    # --- RAR open_list vs rarfile ---
    # Committed fixtures so CI (unrar only, no ``rar`` writer) still runs the many-
    # member listing guard. On-demand builders remain for realistic-scale regenerations.
    def _append_rar_open_list(
        case: str,
        path: Path,
        *,
        notes: str,
    ) -> None:
        _m_wall, (bdec, seeks) = timed_with_optional_warmup(
            lambda p=path: _op_open_list(p)
        )

        def _ay() -> None:
            with open_archive(path) as reader:
                _ = reader.info
                list(reader.members())

        if _rarfile_available():
            if warmup:
                wall, _ignored, std_wall = _interleaved_pair_times(
                    _ay,
                    lambda p=path: _rarfile_open_list(p),
                    rounds=7,
                )
            else:
                wall, _ = timed_with_optional_warmup(_ay)
                std_wall, _ = timed_with_optional_warmup(
                    lambda p=path: _rarfile_open_list(p)
                )
            results.append(
                CaseResult(
                    case,
                    "rar",
                    "open_list",
                    wall,
                    bdec,
                    seeks,
                    stdlib_wall_s=std_wall,
                    wall_ratio=(wall / std_wall) if std_wall > 0 else None,
                    notes=notes,
                )
            )
        else:
            wall, _ = timed_with_optional_warmup(_ay)
            results.append(
                CaseResult(
                    case,
                    "rar",
                    "open_list",
                    wall,
                    bdec,
                    seeks,
                    notes=f"{notes}; skipped peer: rarfile not installed",
                )
            )

    rar_fixtures = ROOT / "tests" / "fixtures" / "rar"
    rar_list_path = rar_fixtures / "basic_solid__.rar"
    if rar_list_path.is_file():
        _append_rar_open_list(
            "rar_open_list",
            rar_list_path,
            notes="vs rarfile.infolist; Q1 native listing target ≈parity",
        )

    # Prefer scale-matched generated corpora when present; always fall back to the
    # committed ci-sized fixtures so the structural gate cannot soft-skip.
    committed_many = rar_fixtures / "many_list_store__.rar"
    many_path = fixtures.many_rar if fixtures.many_rar is not None else committed_many
    if many_path.is_file():
        n = (
            fixtures.scale.list_members
            if fixtures.many_rar is not None
            else SCALES["ci"].list_members  # committed fixture is built at ci scale
        )
        _append_rar_open_list(
            "rar_many_open_list",
            many_path,
            notes=(
                f"vs rarfile.infolist; {n} tiny store members (-m0); "
                "listing-cost regression guard"
            ),
        )

    committed_nonsolid = rar_fixtures / "many_list_store_nonsolid__.rar"
    nonsolid_path = (
        fixtures.nonsolid_rar
        if fixtures.nonsolid_rar is not None
        else committed_nonsolid
    )
    if nonsolid_path.is_file():
        n = (
            fixtures.scale.nonsolid_list_members
            if fixtures.nonsolid_rar is not None
            else SCALES["ci"].nonsolid_list_members  # committed fixture is ci scale
        )
        _append_rar_open_list(
            "rar_nonsolid_open_list",
            nonsolid_path,
            notes=(
                f"vs rarfile.infolist; {n} store members (-m0 -s-); "
                "smaller listing control"
            ),
        )

    # --- Solid RAR data path ---
    # At ci scale always prefer the committed basic_solid fixture so the structural
    # baseline is stable whether or not the ``rar`` writer is installed. Both the
    # PR structural gate and the nightly wall job install RARLAB ``unrar``. Realistic
    # scale may use a generated large solid RAR when the writer built one.
    rar_data_path: Path | None = None
    rar_fixture_note = ""
    committed_solid = ROOT / "tests" / "fixtures" / "rar" / "basic_solid__.rar"
    use_generated = (
        fixtures.scale.name != "ci"
        and fixtures.solid_rar is not None
        and _unrar_available()
    )
    if use_generated:
        rar_data_path = fixtures.solid_rar
        rar_fixture_note = "generated solid fixture"
    elif committed_solid.is_file() and _unrar_available():
        rar_data_path = committed_solid
        rar_fixture_note = "committed basic_solid__.rar"

    if rar_data_path is not None:
        rar_path = rar_data_path
        wall, (bdec, seeks, rar_unpacked) = timed_with_optional_warmup(
            lambda p=rar_path: _op_read_all(p)
        )
        results.append(
            CaseResult(
                "rar_solid_sequential",
                "rar",
                "read_all_sequential",
                wall,
                bdec,
                seeks,
                unpacked_bytes=rar_unpacked,
                notes=(
                    f"solid invariant: bytes_decompressed <= unpacked * factor "
                    f"({rar_fixture_note})"
                ),
            )
        )
        wall, (bdec, seeks) = timed_with_optional_warmup(
            lambda p=rar_path: _op_random_read_all(p)
        )
        results.append(
            CaseResult(
                "rar_solid_random",
                "rar",
                "read_all_random",
                wall,
                bdec,
                seeks,
                # Same fixture as sequential; random op does not return unpacked.
                unpacked_bytes=rar_unpacked,
                notes=(
                    "smoke + seek baseline; byte re-decode not observable via unrar "
                    f"pipe output (P9) ({rar_fixture_note})"
                ),
            )
        )

    # --- Encrypted RAR (committed fixture; password + unrar data path) ---
    enc_rar = ROOT / "tests" / "fixtures" / "rar" / "encryption__.rar"
    if enc_rar.is_file() and _unrar_available():
        enc_path = enc_rar
        wall, (bdec, seeks, unpacked) = timed_with_optional_warmup(
            lambda p=enc_path: _op_read_all(p, password="password")
        )
        results.append(
            CaseResult(
                "rar_encrypted_read_all",
                "rar",
                "read_all",
                wall,
                bdec,
                seeks,
                unpacked_bytes=unpacked,
                notes="committed encryption__.rar; requires RARLAB unrar",
            )
        )

    return results


def _structural_checks(
    results: list[CaseResult],
    baseline: dict[str, Any] | None = None,
    *,
    check_seek_baselines: bool = True,
) -> list[str]:
    failures: list[str] = []
    cases = (baseline or {}).get("cases", {}) if baseline else {}
    for r in results:
        if r.skipped:
            # No data, not a measurement of zero — see CaseResult.skipped.
            continue
        if r.case.endswith("_sequential") and r.unpacked_bytes:
            limit = int(r.unpacked_bytes * SOLID_DECODE_FACTOR)
            if r.bytes_decompressed > limit:
                failures.append(
                    f"{r.case}: bytes_decompressed={r.bytes_decompressed} "
                    f"> unpacked×{SOLID_DECODE_FACTOR}={limit} (solid re-decode?)"
                )
        if (
            check_seek_baselines
            and r.case.endswith("_random")
            and r.unpacked_bytes
            and r.format in ("7z", "rar")
        ):
            # Absolute re-decode cost is inherent for solid random access; gate
            # against the committed ci baseline so "got worse" is still visible.
            # Skipped on non-ci scales (baseline is ci-only), same as seek checks.
            ref = cases.get(r.case)
            if ref is not None and ref.get("bytes_decompressed") is not None:
                limit = int(ref["bytes_decompressed"] * SOLID_RANDOM_BYTES_FACTOR)
                if r.bytes_decompressed > limit:
                    failures.append(
                        f"{r.case}: bytes_decompressed={r.bytes_decompressed} "
                        f"> baseline×{SOLID_RANDOM_BYTES_FACTOR}={limit}"
                    )
        # zip/tar/gzip count at member output. Under-decode is a silent short
        # read; over-decode catches decode-twice-deliver-once (each open still
        # increments the shared ByteCounter even when only the second handle
        # is delivered to the caller).
        if (
            r.operation == "read_all"
            and r.unpacked_bytes is not None
            and r.format in ("zip", "tar", "gzip", "Z", "tar.gz", "tar.bz2", "rar")
        ):
            if r.bytes_decompressed < r.unpacked_bytes:
                failures.append(
                    f"{r.case}: bytes_decompressed={r.bytes_decompressed} "
                    f"< unpacked={r.unpacked_bytes}"
                )
            over_limit = int(r.unpacked_bytes * NONSOLID_DECODE_FACTOR)
            if r.bytes_decompressed > over_limit:
                failures.append(
                    f"{r.case}: bytes_decompressed={r.bytes_decompressed} "
                    f"> unpacked×{NONSOLID_DECODE_FACTOR}={over_limit} "
                    f"(non-solid re-decode?)"
                )
        # Seek counts: two-sided vs committed baseline ± slack. Upper bound catches
        # silent re-open churn; lower bound catches paths that characteristically
        # seek *more* silently falling back. Missing baseline = skip. Only
        # meaningful against the ci-scale baseline.
        #
        # Accelerator ON cases are exempt: their seek counts come from rapidgzip
        # index builds and can drift across rapidgzip versions (all vs all-lowest).
        # Engagement is gated by the relative ON > OFF check below instead.
        if check_seek_baselines and not r.case.endswith("_accel_on"):
            ref = cases.get(r.case)
            if ref is not None and "source_seek_count" in ref:
                baseline_seeks = int(ref["source_seek_count"])
                upper = baseline_seeks + SEEK_BASELINE_SLACK
                lower = max(0, baseline_seeks - SEEK_BASELINE_SLACK)
                if r.source_seek_count > upper:
                    failures.append(
                        f"{r.case}: source_seek_count={r.source_seek_count} > bound {upper}"
                    )
                elif r.source_seek_count < lower:
                    failures.append(
                        f"{r.case}: source_seek_count={r.source_seek_count} "
                        f"< bound {lower} (below baseline−{SEEK_BASELINE_SLACK})"
                    )

    # In-ZIP accelerator engagement: ON must seek more than OFF on the same
    # fixture. Version-independent signal that rapidgzip actually engaged
    # (ON regressing to stdlib keeps seeks≈accel_off).
    if check_seek_baselines:
        by_case = {r.case: r for r in results}
        accel_off = by_case.get("zip_read_all_accel_off")
        accel_on = by_case.get("zip_read_all_accel_on")
        # A skipped ON row seeks 0 times because it never ran; that is not evidence
        # the accelerator failed to engage (this check predates skip rows, when a
        # missing rapidgzip omitted the case entirely).
        if (
            accel_off is not None
            and accel_on is not None
            and not accel_on.skipped
            and accel_on.source_seek_count <= accel_off.source_seek_count
        ):
            failures.append(
                f"zip_read_all_accel_on: source_seek_count="
                f"{accel_on.source_seek_count} <= accel_off "
                f"{accel_off.source_seek_count} (accelerator not engaged?)"
            )
    return failures


def _wall_checks(
    results: list[CaseResult],
    *,
    enforce_vision: bool = False,
) -> list[str]:
    """Sanity ceiling (+ optional informational VISION-band messages as failures)."""
    failures: list[str] = []
    for r in results:
        # A skipped row measured nothing. Its wall_ratio happens to be None today, but
        # the contract in CaseResult.skipped is on the flag, not on that coincidence.
        if r.skipped or r.wall_ratio is None:
            continue
        if r.wall_ratio > WALL_RATIO_BUDGET:
            failures.append(
                f"{r.case}: wall_ratio={r.wall_ratio:.2f} > sanity budget {WALL_RATIO_BUDGET}"
            )
        if not enforce_vision:
            continue
        if r.operation == "open_list":
            if r.format in ("zip", "tar") and r.wall_ratio > LISTING_RATIO_ZIP_TAR:
                failures.append(
                    f"{r.case}: wall_ratio={r.wall_ratio:.2f} > Q1 listing "
                    f"{LISTING_RATIO_ZIP_TAR}× (ZIP/TAR peer band)"
                )
            elif r.format in ("7z", "rar") and r.wall_ratio > LISTING_RATIO_NATIVE:
                failures.append(
                    f"{r.case}: wall_ratio={r.wall_ratio:.2f} > Q1 native listing "
                    f"parity (~{LISTING_RATIO_NATIVE}× vs py7zr/rarfile)"
                )
        elif r.wall_ratio > WALL_RATIO_VISION_SAFETY:
            failures.append(
                f"{r.case}: wall_ratio={r.wall_ratio:.2f} > VISION safety "
                f"{WALL_RATIO_VISION_SAFETY}× (target {WALL_RATIO_VISION}×)"
            )
    return failures


def _previous_wall_ratios(previous: dict[str, Any]) -> dict[str, float]:
    """Map case name → wall_ratio from a prior harness JSON payload."""
    return wall_ratio_map(previous)


def _wall_drift_checks(
    results: list[CaseResult],
    previous: dict[str, Any] | None,
    *,
    factor: float = WALL_RATIO_DRIFT_FACTOR,
    min_abs: float = WALL_RATIO_DRIFT_MIN_ABS,
    min_extra_s: float = WALL_RATIO_DRIFT_MIN_EXTRA_S,
) -> list[str]:
    """Fail when wall_ratio regresses vs a previous nightly JSON.

    Compares peer ratios only (cases with ``wall_ratio`` on both sides). A case fails
    only when all three hold: ``new > old × factor``, ``new − old ≥ min_abs``, and
    ``(new − old) × stdlib_wall_s ≥ min_extra_s`` — the extra wall time the drift
    costs at this run's machine speed. The last condition keeps sub-millisecond
    cases from failing on timer noise. ``run_cases`` sets ``stdlib_wall_s`` whenever
    it sets ``wall_ratio``, so the nightly always applies it; a hand-built
    ``CaseResult`` without ``stdlib_wall_s`` is judged on the two ratio conditions
    alone. Absolute wall seconds are not compared across runs — machine skew
    dominates; the ratio cancels most of it. Missing previous / new cases / dropped
    cases are skipped (seed or rename).
    Callers that *require* a baseline should fail closed when
    ``overlapping_wall_ratio_count`` is 0 — this helper alone treats empty prior
    as no failures (true seed).
    """
    if previous is None:
        return []
    prior = _previous_wall_ratios(previous)
    if not prior:
        return []
    failures: list[str] = []
    for r in results:
        # See _wall_checks: skipped rows are not measurements, regardless of ratio.
        if r.skipped or r.wall_ratio is None:
            continue
        old = prior.get(r.case)
        if old is None or old <= 0:
            continue
        new = r.wall_ratio
        if not (new > old * factor and (new - old) >= min_abs):
            continue
        if r.stdlib_wall_s is not None:
            extra_s = (new - old) * r.stdlib_wall_s
            if extra_s < min_extra_s:
                continue
            cost = f"; +{extra_s * 1e3:.1f} ms"
        else:
            cost = ""
        failures.append(
            f"{r.case}: wall_ratio={new:.2f} drifted from previous {old:.2f} "
            f"(>{factor:.2f}× and +{min_abs:.2f} abs{cost}; nightly drift gate)"
        )
    return failures


def write_baselines(results: list[CaseResult]) -> None:
    """Rewrite the committed structural (seek/bytes) baseline only.

    Refuses to write anything when a case did not run. Dropping such a row would leave
    a baseline that no longer covers it, and *keeping* it would bake a "didn't run"
    zero in — after which a later run with the tool installed reads as a regression.
    Neither is recoverable by inspection: both produce a well-formed file. Fail instead,
    and let the operator install what is missing (``missing_baseline_requirements``).
    """
    skipped = sorted(r.case for r in results if r.skipped)
    if skipped:
        raise ValueError(
            "refusing to write a partial structural baseline; these cases did not "
            f"run: {', '.join(skipped)}. Install the full benchmark toolchain "
            "(uv sync --group dev --extra all, plus RARLAB unrar on PATH) and re-run."
        )
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)
    structural: dict[str, Any] = {
        "solid_decode_factor": SOLID_DECODE_FACTOR,
        "nonsolid_decode_factor": NONSOLID_DECODE_FACTOR,
        "solid_random_bytes_factor": SOLID_RANDOM_BYTES_FACTOR,
        "seek_baseline_slack": SEEK_BASELINE_SLACK,
        "cases": {},
    }
    for r in results:
        structural["cases"][r.case] = {
            "bytes_decompressed": r.bytes_decompressed,
            "source_seek_count": r.source_seek_count,
            "unpacked_bytes": r.unpacked_bytes,
            "notes": r.notes,
        }
    STRUCTURAL_BASELINE.write_text(json.dumps(structural, indent=2) + "\n")


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _fmt_seconds(seconds: float) -> str:
    if seconds <= 0:
        return "—"
    if seconds < 1.0:
        return f"{seconds * 1000:.1f} ms"
    return f"{seconds:.3f} s"


def _fmt_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return str(n)
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n / (1024 * 1024):.2f} MiB"


def _vision_label(ratio: float | None, *, operation: str = "", format: str = "") -> str:
    if ratio is None:
        return "—"
    if operation == "open_list":
        if format in ("zip", "tar"):
            if ratio <= LISTING_RATIO_ZIP_TAR:
                return f"within Q1 listing ≤{LISTING_RATIO_ZIP_TAR}×"
            return f"above Q1 listing {LISTING_RATIO_ZIP_TAR}×"
        if format in ("7z", "rar"):
            if ratio <= LISTING_RATIO_NATIVE:
                return f"within Q1 native ≤{LISTING_RATIO_NATIVE}×"
            return f"above Q1 native parity (~{LISTING_RATIO_NATIVE}×)"
    if ratio <= WALL_RATIO_VISION:
        return f"within ≤{WALL_RATIO_VISION}×"
    if ratio <= WALL_RATIO_VISION_SAFETY:
        return f"above {WALL_RATIO_VISION}×, under {WALL_RATIO_VISION_SAFETY}×"
    return f"above {WALL_RATIO_VISION_SAFETY}× safety"


def format_text_report(payload: dict[str, Any]) -> str:
    """Render a human-friendly markdown report from harness JSON payload."""
    results = [
        CaseResult(**r) if isinstance(r, dict) else r for r in payload["results"]
    ]
    scale = payload.get("scale", "?")
    detail = payload.get("scale_detail") or {}
    lines: list[str] = [
        "# Benchmark report",
        "",
        f"- **mode:** `{payload.get('mode', '?')}`",
        f"- **scale:** `{scale}`",
        f"- **warmup:** `{payload.get('warmup', False)}`",
    ]
    measured = payload.get("measured_at")
    if isinstance(measured, str) and measured:
        lines.append(f"- **measured_at:** `{measured}`")
        source_run = payload.get("source_run_id")
        if source_run:
            lines.append(f"- **source_run_id:** `{source_run}`")
        source_sha = payload.get("source_sha")
        if isinstance(source_sha, str) and source_sha:
            lines.append(f"- **source_sha:** `{source_sha[:12]}`")
    republished = payload.get("republished_at")
    if isinstance(republished, str) and republished:
        lines.append(f"- **republished_at:** `{republished}` (ratios unchanged)")
    if detail:
        lines.extend(
            [
                "",
                "## Corpus",
                "",
                (
                    f"- common members: {detail.get('common_members', '?')} × "
                    f"{_fmt_bytes(detail.get('common_member_size'))}"
                ),
                f"- gzip size: {_fmt_bytes(detail.get('gzip_size'))}",
                (
                    f"- solid members: {detail.get('solid_members', '?')} × "
                    f"{_fmt_bytes(detail.get('solid_member_size'))}"
                ),
                (
                    f"- 7z/RAR list members: {detail.get('list_members', '?')} solid "
                    f"tiny / {detail.get('nonsolid_list_members', '?')} nonsolid"
                ),
            ]
        )

    wall_cases = [r for r in results if r.wall_ratio is not None]
    other_cases = [r for r in results if r.wall_ratio is None]

    if wall_cases:
        lines.extend(
            [
                "",
                "## Wall-time vs stdlib",
                "",
                "| Case | archivey | stdlib | ratio | vs VISION |",
                "| --- | ---: | ---: | ---: | --- |",
            ]
        )
        for r in wall_cases:
            ratio = f"{r.wall_ratio:.2f}×" if r.wall_ratio is not None else "—"
            lines.append(
                f"| `{r.case}` | {_fmt_seconds(r.wall_s)} | "
                f"{_fmt_seconds(r.stdlib_wall_s or 0.0)} | {ratio} | "
                f"{_vision_label(r.wall_ratio, operation=r.operation, format=r.format)} |"
            )

    cost_model = payload.get("cost_model")
    if cost_model:
        lines.extend(format_cost_model(cost_model))
    elif payload.get("cost_model_error"):
        lines.extend(
            ["", "## Cost model", "", f"Not measured: {payload['cost_model_error']}"]
        )

    lines.extend(
        [
            "",
            "## All cases",
            "",
            "| Case | format | op | wall | bytes_dec | seeks | notes |",
            "| --- | --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for r in results:
        notes = r.notes.replace("|", "\\|") if r.notes else ""
        # Printing 0 for a case that never ran recreates in the table the exact
        # ambiguity the structural gate stopped treating as data; the reason is in
        # notes, so the numeric columns should not claim a measurement.
        bytes_dec = "—" if r.skipped else _fmt_bytes(r.bytes_decompressed)
        seeks = "—" if r.skipped else str(r.source_seek_count)
        lines.append(
            f"| `{r.case}` | {r.format} | {r.operation} | "
            f"{_fmt_seconds(r.wall_s)} | {bytes_dec} | "
            f"{seeks} | {notes} |"
        )

    if other_cases and any(r.case.endswith("_sequential") for r in other_cases):
        lines.extend(["", "## Solid decode notes", ""])
        for r in results:
            if not r.case.endswith(("_sequential", "_random")):
                continue
            unpacked = r.unpacked_bytes or 0
            factor = (r.bytes_decompressed / unpacked) if unpacked else None
            factor_s = f"{factor:.2f}× unpacked" if factor is not None else "—"
            lines.append(
                f"- `{r.case}`: bytes_decompressed={_fmt_bytes(r.bytes_decompressed)} "
                f"({factor_s}); seeks={r.source_seek_count}"
            )

    lines.extend(
        [
            "",
            "## Policy reminder",
            "",
            (
                f"- VISION target ≤{WALL_RATIO_VISION}× stdlib on common paths "
                f"(~{WALL_RATIO_VISION_SAFETY}× safety band is informational on nightly)."
            ),
            f"- Sanity ceiling {WALL_RATIO_BUDGET:.0f}× fails the job.",
            (
                f"- Nightly also fails on wall-ratio *drift* vs the last measured run's "
                f"JSON, pass or fail (>{WALL_RATIO_DRIFT_FACTOR:.2f}×, "
                f"+{WALL_RATIO_DRIFT_MIN_ABS:.2f} abs and "
                f"≥{WALL_RATIO_DRIFT_MIN_EXTRA_S * 1e3:.0f} ms extra wall time) — not on "
                "absolute VISION bands."
            ),
            (
                "- Quiet nights re-publish the previous artifact (preserving "
                "`measured_at`); a full re-measure is forced at least every ~30 days."
            ),
            "- Structural seek/bytes gates live on the PR path (`ci.yml`), not here.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("structural", "full"),
        default="structural",
        help="structural=bytes/seeks only (PR); full=include wall-time ratios",
    )
    parser.add_argument(
        "--scale",
        choices=("ci", "realistic"),
        default="ci",
        help="ci=small PR fixtures; realistic=multi-MiB corpora for wall-time",
    )
    parser.add_argument(
        "--warmup",
        action="store_true",
        help="Discard one pass per timed op before measuring (recommended with --scale realistic)",
    )
    parser.add_argument(
        "--update-baselines",
        action="store_true",
        help="Rewrite benchmarks/baselines/structural.json from this run (ci scale only)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write full results JSON to this path",
    )
    parser.add_argument(
        "--text-out",
        type=Path,
        default=None,
        help="Write a human-friendly markdown report to this path",
    )
    parser.add_argument(
        "--wall-drift-baseline",
        type=Path,
        default=None,
        help=(
            "Previous harness JSON (nightly artifact). When set, fail if any "
            "case's wall_ratio regresses beyond --wall-drift-factor, "
            "--wall-drift-min-abs and --wall-drift-min-extra-ms (missing file / no "
            "overlapping ratios fail closed)"
        ),
    )
    parser.add_argument(
        "--wall-drift-factor",
        type=float,
        default=WALL_RATIO_DRIFT_FACTOR,
        help=(
            "Max allowed relative wall_ratio increase vs --wall-drift-baseline "
            f"(default {WALL_RATIO_DRIFT_FACTOR})"
        ),
    )
    parser.add_argument(
        "--wall-drift-min-abs",
        type=float,
        default=WALL_RATIO_DRIFT_MIN_ABS,
        help=(
            "Min absolute wall_ratio increase required together with "
            f"--wall-drift-factor (default {WALL_RATIO_DRIFT_MIN_ABS})"
        ),
    )
    parser.add_argument(
        "--wall-drift-min-extra-ms",
        type=float,
        default=WALL_RATIO_DRIFT_MIN_EXTRA_S * 1e3,
        help=(
            "Min extra wall time, in ms, that a drift must cost, (new - old ratio) x "
            "this run's stdlib time, required together with the two ratio "
            f"thresholds (default {WALL_RATIO_DRIFT_MIN_EXTRA_S * 1e3:g})"
        ),
    )
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        default=None,
        help="Directory for on-demand fixtures (default: temp / ARCHIVEY_BENCH_CACHE)",
    )
    args = parser.parse_args(argv)

    if args.update_baselines and args.scale != "ci":
        print(
            "--update-baselines only writes the committed ci baselines; "
            f"refusing scale={args.scale!r}",
            file=sys.stderr,
        )
        return 2

    # Checked up front rather than at write time: the run takes minutes, and a
    # regeneration that can only produce a partial file should cost seconds to reject.
    if args.update_baselines:
        missing = missing_baseline_requirements()
        if missing:
            print(
                "--update-baselines needs the full benchmark toolchain — a partial "
                "run would drop the affected cases from structural.json, leaving the "
                "gate measuring less than it claims. Missing:",
                file=sys.stderr,
            )
            for item in missing:
                print(f"  - {item}", file=sys.stderr)
            print(
                "Install with: uv sync --group dev --extra all "
                "(plus RARLAB unrar on PATH), then re-run.",
                file=sys.stderr,
            )
            return 2

    warmup = args.warmup or args.scale == "realistic"
    fixtures = materialize_fixtures(args.fixture_dir, scale=args.scale)
    work = fixtures.root / "work"
    if work.exists():
        import shutil

        shutil.rmtree(work)
    work.mkdir(parents=True)

    results = run_cases(fixtures, work, warmup=warmup)
    payload = {
        "mode": args.mode,
        "scale": fixtures.scale.name,
        "scale_detail": {
            "common_members": fixtures.scale.common_members,
            "common_member_size": fixtures.scale.common_member_size,
            "gzip_size": fixtures.scale.gzip_size,
            "solid_members": fixtures.scale.solid_members,
            "solid_member_size": fixtures.scale.solid_member_size,
            "list_members": fixtures.scale.list_members,
            "nonsolid_list_members": fixtures.scale.nonsolid_list_members,
        },
        "fixture_root": str(fixtures.root),
        "warmup": warmup,
        "results": [asdict(r) for r in results],
    }
    # Stamp when ratios were actually timed (nightly skip re-publish preserves this).
    if args.mode == "full":
        # Per-member cost and throughput from a ladder of archive shapes, next to
        # the per-fixture ratios. Informational: no gate reads it, so a failure here
        # is reported in its section and must not lose the run's results. The ladder
        # is the same at every scale, so it lives beside the scale directories.
        try:
            payload["cost_model"] = run_cost_model(fixtures.root.parent / "ladder")
        except Exception as exc:  # noqa: BLE001 - see above
            payload["cost_model_error"] = f"{type(exc).__name__}: {exc}"

        payload.update(measurement_provenance())
    report = format_text_report(payload)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2) + "\n")
    if args.text_out is not None:
        args.text_out.parent.mkdir(parents=True, exist_ok=True)
        args.text_out.write_text(report)

    # Friendly table first (CI logs / terminals); full JSON still available via --json-out.
    print(report)
    if args.json_out is None:
        print(json.dumps(payload, indent=2))

    if args.update_baselines:
        write_baselines(results)
        print(f"Updated baselines under {BASELINES_DIR}", file=sys.stderr)

    # Seek baselines are committed for the ci scale only.
    failures = _structural_checks(
        results,
        load_json(STRUCTURAL_BASELINE),
        check_seek_baselines=(args.scale == "ci"),
    )
    if args.mode == "full":
        # Sanity ceiling always; absolute VISION bands stay informational prints.
        # Nightly drift vs previous JSON is the hard wall-ratio gate (Q2 option a).
        for f in _wall_checks(results, enforce_vision=False):
            failures.append(f)
        if args.scale == "realistic":
            for f in _wall_checks(results, enforce_vision=True):
                if "VISION safety" in f or "Q1 listing" in f or "Q1 native" in f:
                    print(f"VISION BUDGET (informational): {f}", file=sys.stderr)
        if args.wall_drift_baseline is not None:
            prev = load_json(args.wall_drift_baseline)
            if prev is None:
                print(
                    f"wall-drift baseline missing: {args.wall_drift_baseline}",
                    file=sys.stderr,
                )
                return 2
            comparable = overlapping_wall_ratio_count(results, prev)
            if comparable == 0:
                failures.append(
                    f"wall-drift baseline {args.wall_drift_baseline} has no "
                    "overlapping wall_ratio cases to compare"
                )
            else:
                drift = _wall_drift_checks(
                    results,
                    prev,
                    factor=args.wall_drift_factor,
                    min_abs=args.wall_drift_min_abs,
                    min_extra_s=args.wall_drift_min_extra_ms / 1e3,
                )
                failures.extend(drift)
                if not drift:
                    print(
                        f"Wall-ratio drift OK vs {args.wall_drift_baseline} "
                        f"({comparable} cases; factor={args.wall_drift_factor}, "
                        f"min_abs={args.wall_drift_min_abs}, "
                        f"min_extra_ms={args.wall_drift_min_extra_ms})",
                        file=sys.stderr,
                    )

    if failures:
        print("BENCHMARK GATE FAILURES:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
