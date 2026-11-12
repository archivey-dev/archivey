"""Pytest entry for the structural benchmark gate (solid no-re-decode + axes)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from benchmarks import harness
from benchmarks.fixtures import materialize_fixtures
from benchmarks.harness import (
    STRUCTURAL_BASELINE,
    CaseResult,
    _accel_skipped_case,
    _crypto_available,
    _rapidgzip_available,
    _structural_checks,
    _unrar_available,
    load_json,
    run_cases,
    write_baselines,
)
from tests.conftest import UNUSED_UNDER_PYPY

_RAR_DATA_CASES = (
    "rar_solid_sequential",
    "rar_solid_random",
    "rar_encrypted_read_all",
)

_ACCEL_ON_CASES = (
    "zip_read_all_accel_on",
    "targz_read_all_accel_on",
    "tarbz2_read_all_accel_on",
)


def _running_in_ci() -> bool:
    return os.environ.get("CI", "").lower() in ("1", "true", "yes")


def _unreachable_materialize_fixtures(*args: object, **kwargs: object) -> object:
    raise AssertionError("--update-baselines must refuse before building fixtures")


@pytest.mark.timeout(120)
def test_benchmark_structural_gate(tmp_path: Path) -> None:
    """PR gate: solid sequential decode bound + common-path byte counts."""
    fixtures = materialize_fixtures(tmp_path / "fixtures")
    if fixtures.solid_7z is None:
        pytest.importorskip("py7zr")
    work = tmp_path / "work"
    work.mkdir()
    results = run_cases(fixtures, work)
    by_case = {r.case: r for r in results}

    # Ensure the solid sequential case ran when 7z is available.
    sequential = by_case.get("sevenzip_solid_sequential")
    assert sequential is not None, "expected sevenzip_solid_sequential case"
    assert sequential.bytes_decompressed <= (sequential.unpacked_bytes or 0) * 2

    # Many-member COPY listing is the regression guard for per-folder caches.
    assert "sevenzip_many_open_list" in by_case
    # Non-solid listing needs the 7z CLI (-ms=off); soft-skip when absent.
    if fixtures.nonsolid_7z is not None:
        assert "sevenzip_nonsolid_open_list" in by_case

    # Many-member RAR listing: committed fixtures so CI always runs the guard
    # (workflow installs unrar, not the ``rar`` writer).
    assert "rar_many_open_list" in by_case
    assert "rar_nonsolid_open_list" in by_case

    random = by_case.get("sevenzip_solid_random")
    assert random is not None
    # Random opens re-decode; recorded, not failed — but must be visible.
    assert random.bytes_decompressed >= sequential.bytes_decompressed

    # T3 / perf P6: RAR data cases. Soft locally without unrar; fail-closed in CI
    # (and whenever unrar is present) so a missing binary cannot silently omit them.
    # Reached only when py7zr is present (importorskip above); the CI matrix
    # co-installs unrar on those same legs (--group dev + workflow apt/brew/choco).
    missing_rar = [name for name in _RAR_DATA_CASES if name not in by_case]
    if missing_rar and (_running_in_ci() or _unrar_available()):
        pytest.fail(
            "RAR data cases missing from structural run: "
            f"{missing_rar}. Install RARLAB unrar on PATH "
            "(ci.yml matrix installs apt/brew-cask/choco unrar; "
            "benchmark jobs apt-get install unrar on Linux)."
        )

    if _crypto_available() and fixtures.zip_aes_path is not None:
        assert "zip_aes_read_all" in by_case
    assert "zip_lzma_read_all" in by_case
    assert "zipcrypto_read_all" in by_case
    assert "zip_read_all_accel_off" in by_case

    # Accelerator ON cases: soft locally without rapidgzip, fail-closed in CI (and
    # whenever it is installed) so a resolution change to the ``[seekable]`` extra
    # cannot silently drop accelerator coverage. A skipped case is *present but
    # unmeasured*, so presence alone is not enough.
    unmeasured_accel = [
        name for name in _ACCEL_ON_CASES if name not in by_case or by_case[name].skipped
    ]
    # Under PyPy archivey does not use rapidgzip at all (UNUSED_UNDER_PYPY), so the
    # ON cases measure nothing there.
    accel_used = "rapidgzip" not in UNUSED_UNDER_PYPY
    if unmeasured_accel and accel_used and (_running_in_ci() or _rapidgzip_available()):
        pytest.fail(
            "accelerator ON cases did not run: "
            f"{unmeasured_accel}. Install the '[seekable]' extra (rapidgzip>=0.16.0); "
            "the CI matrix gets it via --extra all."
        )

    if accel_used and _rapidgzip_available():
        # Engagement signal: ON seeks more than OFF on the same deflate ZIP.
        assert (
            by_case["zip_read_all_accel_on"].source_seek_count
            > by_case["zip_read_all_accel_off"].source_seek_count
        )

    failures = _structural_checks(results, load_json(STRUCTURAL_BASELINE))
    assert not failures, "structural gate failures:\n" + "\n".join(failures)


@pytest.mark.timeout(120)
def test_accel_on_skip_is_not_reported_as_under_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing ``[seekable]`` extra must not look like a codec short read.

    The accel-ON cases are skipped when rapidgzip is absent. The skip placeholder
    used to carry the real ``unpacked_bytes`` alongside ``bytes_decompressed=0``, so
    the read_all under-decode rule reported
    ``targz_read_all_accel_on: bytes_decompressed=0 < unpacked=32768`` — a fabricated
    defect pointing at the codec instead of at the missing extra, and expensive to
    diagnose because ``_structural_checks`` failures do not carry the case notes.
    """
    monkeypatch.setattr(harness, "_rapidgzip_available", lambda: False)
    fixtures = materialize_fixtures(tmp_path / "fixtures")
    work = tmp_path / "work"
    work.mkdir()
    results = run_cases(fixtures, work)

    failures = _structural_checks(results, load_json(STRUCTURAL_BASELINE))
    assert not [f for f in failures if "accel_on" in f], (
        "skipped accel-ON cases must not produce structural failures:\n"
        + "\n".join(failures)
    )

    # Every accel-ON case must still be *visible* as a skip — a silently absent row
    # is how coverage evaporates unnoticed (see the fail-closed guard in the
    # structural gate). ZIP used to omit its case entirely, which is why it never hit
    # the under-decode bug but also left no trace of the missing extra.
    by_case = {r.case: r for r in results}
    for name in _ACCEL_ON_CASES:
        assert name in by_case, f"{name} should be reported as skipped, not omitted"
        skipped = by_case[name]
        assert skipped.skipped, f"{name}: a case that never ran must say so"
        assert skipped.unpacked_bytes is None, (
            f"{name}: a skipped case measured nothing"
        )
        assert "rapidgzip not installed" in skipped.notes


def test_write_baselines_refuses_partial_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run with a skipped case must not rewrite the baseline at all.

    Both ways of absorbing a skip are silently wrong and produce a well-formed file:
    keeping the row bakes in ``bytes_decompressed=0`` (later runs *with* the tool then
    read as regressions), and dropping it yields a baseline that no longer covers the
    case. Refusing is the only outcome that cannot quietly weaken the gate.
    """
    baseline = tmp_path / "structural.json"
    monkeypatch.setattr(harness, "BASELINES_DIR", tmp_path)
    monkeypatch.setattr(harness, "STRUCTURAL_BASELINE", baseline)

    measured = CaseResult(
        case="zip_read_all_accel_off",
        format="zip",
        operation="read_all",
        wall_s=0.01,
        bytes_decompressed=32768,
        source_seek_count=28,
        unpacked_bytes=32768,
    )
    with pytest.raises(ValueError, match="zip_read_all_accel_on"):
        write_baselines([measured, _accel_skipped_case("zip_read_all_accel_on", "zip")])

    assert not baseline.exists(), (
        "a refused update must leave no file behind — a half-written baseline is "
        "exactly what the refusal is protecting against"
    )

    # The same results without the skip still write normally.
    write_baselines([measured])
    cases = json.loads(baseline.read_text())["cases"]
    assert cases["zip_read_all_accel_off"]["bytes_decompressed"] == 32768
    assert cases["zip_read_all_accel_off"]["source_seek_count"] == 28


def test_update_baselines_refuses_before_running_when_tooling_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Missing tooling fails the CLI up front, naming what to install.

    The run takes minutes; a regeneration that can only produce a partial file should
    be rejected in seconds. Returning before ``materialize_fixtures`` is what makes
    this test cheap, and is the behaviour worth pinning.
    """
    monkeypatch.setattr(harness, "_rapidgzip_available", lambda: False)
    monkeypatch.setattr(
        harness, "materialize_fixtures", _unreachable_materialize_fixtures
    )

    assert harness.main(["--update-baselines"]) == 2

    err = capsys.readouterr().err
    assert "rapidgzip" in err and "[seekable]" in err
    assert "structural.json" in err


def test_structural_baseline_committed() -> None:
    assert STRUCTURAL_BASELINE.is_file()
    data = json.loads(STRUCTURAL_BASELINE.read_text())
    cases = data["cases"]
    assert "sevenzip_solid_sequential" in cases
    # P6 remainder / T3 coverage must stay in the committed ci baseline.
    for name in (
        "rar_solid_sequential",
        "rar_solid_random",
        "rar_encrypted_read_all",
        "rar_many_open_list",
        "rar_nonsolid_open_list",
        "zip_aes_read_all",
        "zip_lzma_read_all",
        "zipcrypto_read_all",
        "zip_read_all_accel_off",
        # All three accel-ON cases, matching the fail-closed guard's set: a
        # no-rapidgzip regeneration drops them together, so pinning only ZIP left the
        # tar keys protected by coincidence rather than by the assertion.
        *_ACCEL_ON_CASES,
    ):
        assert name in cases, f"missing structural baseline case {name}"


def test_accel_engagement_is_relative_not_absolute() -> None:
    """Accel ON engagement uses ON > OFF; absolute ±slack does not apply to *_accel_on.

    rapidgzip seek counts can drift across versions (all vs all-lowest), so the
    absolute two-sided bound would be a false-failure risk. Non-engagement is
    caught by the relative check instead.
    """
    baseline = {
        "cases": {
            "zip_read_all_accel_on": {
                "bytes_decompressed": 32768,
                "source_seek_count": 44,
                "unpacked_bytes": 32768,
            },
            "zip_read_all_accel_off": {
                "bytes_decompressed": 32768,
                "source_seek_count": 28,
                "unpacked_bytes": 32768,
            },
        }
    }
    # Silent non-engagement: ON case reports OFF-like seeks.
    fake_on = CaseResult(
        case="zip_read_all_accel_on",
        format="zip",
        operation="read_all",
        wall_s=0.0,
        bytes_decompressed=32768,
        source_seek_count=28,
        unpacked_bytes=32768,
    )
    fake_off = CaseResult(
        case="zip_read_all_accel_off",
        format="zip",
        operation="read_all",
        wall_s=0.0,
        bytes_decompressed=32768,
        source_seek_count=28,
        unpacked_bytes=32768,
    )
    failures = _structural_checks([fake_off, fake_on], baseline)
    assert any("accelerator not engaged" in f for f in failures)
    # Absolute lower bound must not fire on *_accel_on (engagement check only).
    assert not any("below baseline" in f for f in failures)

    # Version-drift-shaped seeks still pass absolute checks when ON > OFF.
    drifted_on = CaseResult(
        case="zip_read_all_accel_on",
        format="zip",
        operation="read_all",
        wall_s=0.0,
        bytes_decompressed=32768,
        source_seek_count=60,  # well above baseline+8
        unpacked_bytes=32768,
    )
    failures = _structural_checks([fake_off, drifted_on], baseline)
    assert failures == []


def test_format_text_report_table() -> None:
    """Friendly markdown report is readable without downloading JSON."""
    from benchmarks.harness import format_text_report

    payload = {
        "mode": "full",
        "scale": "realistic",
        "warmup": True,
        "scale_detail": {
            "common_members": 64,
            "common_member_size": 262144,
            "gzip_size": 33554432,
            "solid_members": 64,
            "solid_member_size": 262144,
        },
        "results": [
            {
                "case": "zip_read_all",
                "format": "zip",
                "operation": "read_all",
                "wall_s": 0.0158,
                "bytes_decompressed": 1_048_576,
                "source_seek_count": 3,
                "unpacked_bytes": 1_048_576,
                "stdlib_wall_s": 0.0134,
                "wall_ratio": 1.18,
                "notes": "",
            },
            {
                "case": "sevenzip_solid_sequential",
                "format": "7z",
                "operation": "read_all_sequential",
                "wall_s": 0.4,
                "bytes_decompressed": 1_048_576,
                "source_seek_count": 2,
                "unpacked_bytes": 1_048_576,
                "stdlib_wall_s": None,
                "wall_ratio": None,
                "notes": "solid invariant",
            },
            {
                "case": "zip_read_all_accel_on",
                "format": "zip",
                "operation": "read_all",
                "wall_s": 0.0,
                "bytes_decompressed": 0,
                "source_seek_count": 0,
                "unpacked_bytes": None,
                "stdlib_wall_s": None,
                "wall_ratio": None,
                "notes": "skipped: rapidgzip not installed ([seekable] extra)",
                "skipped": True,
            },
        ],
    }
    report = format_text_report(payload)
    assert "# Benchmark report" in report
    assert "| Case | archivey | stdlib | ratio | vs VISION |" in report
    assert "`zip_read_all`" in report
    assert "1.18×" in report
    assert "within ≤1.3×" in report
    assert "solid invariant" in report
    assert "64 × 256.0 KiB" in report or "64 × 256 KiB" in report
    assert "wall-ratio *drift*" in report

    # A skipped case reports "—" in the numeric columns rather than 0, which would
    # read as "the accelerator decompressed nothing and never seeked".
    skipped_row = next(
        line for line in report.splitlines() if "`zip_read_all_accel_on`" in line
    )
    assert "| — | — |" in skipped_row, skipped_row
    assert "rapidgzip not installed" in skipped_row


def test_wall_drift_checks_regressions_and_noise() -> None:
    """Nightly drift gate: relative+abs dual threshold; seed/missing skipped."""
    from benchmarks.harness import CaseResult, _wall_drift_checks
    from benchmarks.wall_baseline import overlapping_wall_ratio_count

    def _case(name: str, ratio: float | None) -> CaseResult:
        return CaseResult(
            case=name,
            format="zip",
            operation="read_all",
            wall_s=0.02,
            bytes_decompressed=100,
            source_seek_count=1,
            # run_cases always sets stdlib_wall_s with wall_ratio; 20 ms keeps the
            # 1 ms time floor out of the way, so these cases test the ratio rules.
            stdlib_wall_s=0.02,
            wall_ratio=ratio,
        )

    previous = {
        "results": [
            {"case": "zip_read_all", "wall_ratio": 1.20},
            {"case": "gzip_read_all", "wall_ratio": 1.05},
            {"case": "no_peer", "wall_ratio": None},
        ]
    }
    # Clear regression: 1.20 → 1.80 (>1.25× and +0.15 abs).
    bad = _wall_drift_checks(
        [_case("zip_read_all", 1.80), _case("gzip_read_all", 1.06)],
        previous,
    )
    assert len(bad) == 1
    assert "zip_read_all" in bad[0]

    # Small bump under both thresholds — OK (noise).
    ok = _wall_drift_checks(
        [_case("zip_read_all", 1.30), _case("gzip_read_all", 1.10)],
        previous,
    )
    assert ok == []

    # Relative yes, abs no (old small): 0.4 → 0.51 (>1.25× but +0.11 < 0.15).
    assert (
        _wall_drift_checks(
            [_case("zip_read_all", 0.51)],
            {"results": [{"case": "zip_read_all", "wall_ratio": 0.4}]},
        )
        == []
    )

    # Abs yes, relative no: 2.0 → 2.40 (+0.40 but only 1.20× < 1.25×).
    assert (
        _wall_drift_checks(
            [_case("zip_read_all", 2.40)],
            {"results": [{"case": "zip_read_all", "wall_ratio": 2.0}]},
        )
        == []
    )

    # Improvement — OK.
    better = _wall_drift_checks([_case("zip_read_all", 1.00)], previous)
    assert better == []

    # No previous / empty — seed helper returns no failures (callers fail closed).
    assert _wall_drift_checks([_case("zip_read_all", 9.0)], None) == []
    assert _wall_drift_checks([_case("zip_read_all", 9.0)], {"results": []}) == []
    assert (
        overlapping_wall_ratio_count([_case("zip_read_all", 9.0)], {"results": []}) == 0
    )

    # New case not in previous — skip.
    assert _wall_drift_checks([_case("brand_new_case", 5.0)], previous) == []

    # A hand-built result with no stdlib time is judged on the ratio rules alone.
    no_stdlib = CaseResult(
        case="zip_read_all",
        format="zip",
        operation="read_all",
        wall_s=0.000_1,
        bytes_decompressed=100,
        source_seek_count=1,
        wall_ratio=1.80,
    )
    assert len(_wall_drift_checks([no_stdlib], previous)) == 1


def test_wall_drift_checks_ignore_drift_that_costs_under_a_millisecond() -> None:
    """A ratio jump on a sub-millisecond case does not fail the drift gate.

    Numbers from nightly run 37935834666 against the 2026-09-06 baseline: the RAR
    listing ratio doubled on a 0.13 ms peer (+0.33 ms of wall time), while the
    accelerated tar.gz read and the plain TAR read cost whole milliseconds more.
    """
    from benchmarks.harness import CaseResult, _wall_drift_checks

    def _case(name: str, ratio: float, stdlib_s: float) -> CaseResult:
        return CaseResult(
            case=name,
            format="x",
            operation="read_all",
            wall_s=ratio * stdlib_s,
            bytes_decompressed=0,
            source_seek_count=0,
            stdlib_wall_s=stdlib_s,
            wall_ratio=ratio,
        )

    previous = {
        "results": [
            {"case": "rar_open_list", "wall_ratio": 2.60},
            {"case": "targz_read_all_accel_on", "wall_ratio": 0.43},
            {"case": "tar_read_all", "wall_ratio": 1.75},
        ]
    }
    current = [
        _case("rar_open_list", 5.12, 0.000_13),
        _case("targz_read_all_accel_on", 1.98, 0.023_3),
        _case("tar_read_all", 2.36, 0.002_3),
    ]

    failures = _wall_drift_checks(current, previous)
    assert [f.split(":")[0] for f in failures] == [
        "targz_read_all_accel_on",
        "tar_read_all",
    ]
    assert "+36.1 ms" in failures[0]

    # With no time floor, the sub-millisecond case fails as it did before.
    no_floor = _wall_drift_checks(current, previous, min_extra_s=0.0)
    assert "rar_open_list" in no_floor[0]


def test_wall_baseline_provenance_and_republish(tmp_path: Path) -> None:
    """measured_at age drives the 30d force-run; re-publish preserves it."""
    from datetime import UTC, datetime, timedelta

    from benchmarks.wall_baseline import (
        MEASURE_MAX_AGE_SECONDS,
        measured_at_age_seconds,
        measurement_provenance,
        republish_files,
        stamp_republish,
        wall_ratio_map,
    )

    measured = datetime(2026, 6, 1, 6, 17, tzinfo=UTC)
    payload = {
        "measured_at": measured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_run_id": "111",
        "source_sha": "abc123",
        "results": [{"case": "zip_read_all", "wall_ratio": 1.2}],
    }
    now = measured + timedelta(days=31)
    age = measured_at_age_seconds(payload, now=now)
    assert age is not None
    assert age > MEASURE_MAX_AGE_SECONDS

    stamped = stamp_republish(payload, run_id="222")
    assert stamped["measured_at"] == payload["measured_at"]
    assert stamped["source_run_id"] == "111"
    assert stamped["republish_run_id"] == "222"
    assert "republished_at" in stamped

    src = tmp_path / "benchmark-wall-realistic.json"
    src.write_text(json.dumps(payload) + "\n")
    (tmp_path / "benchmark-wall-realistic.md").write_text("# Benchmark report\n\nok\n")
    out = tmp_path / "out"
    republish_files(src, out, run_id="333")
    written = json.loads((out / "benchmark-wall-realistic.json").read_text())
    assert written["measured_at"] == payload["measured_at"]
    assert written["republish_run_id"] == "333"
    md = (out / "benchmark-wall-realistic.md").read_text()
    assert "Re-published without re-measurement" in md
    assert "ok" in md

    fresh = measurement_provenance(run_id="444", sha="deadbeef")
    assert fresh["source_run_id"] == "444"
    assert fresh["source_sha"] == "deadbeef"
    assert fresh["measured_at"].endswith("Z")

    assert wall_ratio_map({"results": [{"case": "a", "wall_ratio": True}]}) == {}
    assert measured_at_age_seconds({"results": []}) is None


def test_main_passes_wall_drift_min_extra_ms_as_milliseconds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--wall-drift-min-extra-ms`` reaches the drift gate in milliseconds.

    The case below drifts 1.00 → 2.00 on a 2 ms stdlib peer: +2 ms of wall time. A
    1 ms floor fails it and a 5 ms floor passes it. Read as seconds, both floors
    would pass it, and the nightly drift gate could never fail.
    """
    from types import SimpleNamespace

    from benchmarks import harness
    from benchmarks.fixtures import SCALES
    from benchmarks.harness import CaseResult

    current = CaseResult(
        case="zip_read_all",
        format="zip",
        operation="read_all",
        wall_s=0.004,
        bytes_decompressed=100,
        source_seek_count=1,
        stdlib_wall_s=0.002,
        wall_ratio=2.0,
    )
    monkeypatch.setattr(
        harness,
        "materialize_fixtures",
        lambda *_a, **_k: SimpleNamespace(root=tmp_path, scale=SCALES["ci"]),
    )
    monkeypatch.setattr(harness, "run_cases", lambda *_a, **_k: [current])
    monkeypatch.setattr(harness, "_structural_checks", lambda *_a, **_k: [])
    # Full mode also times the cost-model ladder, which this test does not need.
    monkeypatch.setattr(harness, "run_cost_model", lambda *_a, **_k: [])
    baseline = tmp_path / "prev.json"
    baseline.write_text(
        json.dumps({"results": [{"case": "zip_read_all", "wall_ratio": 1.0}]})
    )

    def run(*extra: str) -> int:
        argv = ["--mode", "full", "--scale", "ci", "--wall-drift-baseline"]
        return harness.main([*argv, str(baseline), *extra])

    assert run() == 1  # default floor: 1 ms
    assert run("--wall-drift-min-extra-ms", "1") == 1
    assert run("--wall-drift-min-extra-ms", "5") == 0


def test_cost_model_fit_recovers_known_costs() -> None:
    """The end-rung fit returns the costs a linear model was built from, and
    predicts the check rungs exactly when the model holds."""
    from benchmarks.cost_model import FIT_RUNGS, LADDER, MIB, Rung, fit

    open_ms, list_us, read_us, mib_s = 0.4, 12.0, 120.0, 800.0

    def rung(members: int, size: int) -> Rung:
        return Rung(
            members,
            size,
            list_ms=open_ms + members * list_us / 1e3,
            read_ms=open_ms
            + members * read_us / 1e3
            + members * size / MIB * 1e3 / mib_s,
        )

    rungs = [rung(n, s) for n, s in LADDER]
    f = fit(rungs)
    assert f.open_ms == pytest.approx(open_ms)
    assert f.list_us_per_member == pytest.approx(list_us)
    assert f.read_us_per_member == pytest.approx(read_us)
    assert f.throughput_mib_s == pytest.approx(mib_s)
    for r in (r for i, r in enumerate(rungs) if i not in FIT_RUNGS):
        assert f.predict_read(r.members, r.members * r.member_size) == pytest.approx(
            r.read_ms
        )


def test_format_text_report_cost_model_section() -> None:
    """A full-mode payload's cost model renders as a table, flagging a check rung
    the fit does not predict."""
    from benchmarks.harness import format_text_report

    fit_row = {
        "open_ms": 0.4,
        "list_us_per_member": 12.0,
        "read_us_per_member": 120.0,
        "throughput_mib_s": 800.0,
    }
    payload = {
        "mode": "full",
        "scale": "realistic",
        "results": [],
        "cost_model": [
            {
                "format": "zip",
                "peer": "zipfile",
                "codec": True,
                "sides": {
                    "archivey": {
                        "fit": fit_row,
                        "rungs": [],
                        "checks": [
                            {
                                "members": 64,
                                "member_size": 262144,
                                "op": "read",
                                "measured_ms": 40.0,
                                "predicted_ms": 28.0,
                                "error": 0.3,
                            }
                        ],
                    },
                    # A listing miss marks the row too: the open cost comes from it.
                    "zipfile": {
                        "fit": fit_row,
                        "rungs": [],
                        "checks": [
                            {
                                "members": 4,
                                "member_size": 4 * 1024 * 1024,
                                "op": "list",
                                "measured_ms": 2.0,
                                "predicted_ms": 3.0,
                                "error": -0.5,
                            },
                            # Far off in relative terms, but under the absolute floor.
                            {
                                "members": 16,
                                "member_size": 1024 * 1024,
                                "op": "list",
                                "measured_ms": 0.1,
                                "predicted_ms": 0.15,
                                "error": -0.5,
                            },
                        ],
                    },
                },
            },
            {
                "format": "tar",
                "peer": "tarfile",
                "codec": False,
                "sides": {
                    "archivey": {
                        "fit": {**fit_row, "open_ms": 0.005},
                        "rungs": [],
                        "checks": [],
                    },
                    "tarfile": {
                        "fit": {**fit_row, "open_ms": -0.06},
                        "rungs": [],
                        "checks": [],
                    },
                },
            },
        ],
    }
    report = format_text_report(payload)
    assert "## Cost model" in report
    assert "| tar | archivey | under 0.01 ms | 8k members/s | no codec |" in report
    assert "| tar | tarfile | not resolved | 8k members/s | no codec |" in report
    assert "| zip | archivey \\* | 0.40 ms | 8k members/s | 800 MiB/s |" in report
    assert "zip archivey read 64 × 256 KiB" in report
    assert "| zip | zipfile \\* |" in report
    assert "zip zipfile list 4 × 4 MiB" in report
    assert "zip zipfile list 16 × 1 MiB" not in report


@pytest.mark.parametrize(
    ("mode", "peer"),
    [
        ("w:gz", harness._stdlib_targz_read_all),
        ("w:bz2", harness._stdlib_tarbz2_read_all),
    ],
)
def test_compressed_tar_peers_read_the_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, peer
) -> None:
    """The tar.gz / tar.bz2 stdlib peers decompress the stream once, and read every
    member's data.

    ``getmembers()`` before ``extractfile()`` reads the compressed file twice: listing
    decompresses to the end, and the first seek back restarts from byte zero. That
    made the peer about twice as slow as a one-pass read and the published ratios
    flattered archivey. A peer that stopped reading member data would also read the
    file once, so the data read is counted too.
    """
    import io
    import tarfile

    from benchmarks.fixtures import SCALES, build_tar

    scale = SCALES["ci"]
    path = tmp_path / f"peer.tar.{mode[2:]}"
    build_tar(path, scale, mode=mode)
    compressed_read = 0
    data_read = 0
    opened: list[io.FileIO] = []

    class CountingFile(io.FileIO):
        def readinto(self, b):  # type: ignore[override]
            nonlocal compressed_read
            n = super().readinto(b)
            compressed_read += n or 0
            return n

    real_open = tarfile.open
    real_extractfile = tarfile.TarFile.extractfile

    def counting_open(name, mode="r", **kwargs):  # type: ignore[no-untyped-def]
        raw = CountingFile(name)
        opened.append(raw)
        return real_open(fileobj=io.BufferedReader(raw), mode=mode, **kwargs)

    class CountingMember:
        def __init__(self, inner) -> None:  # type: ignore[no-untyped-def]
            self._inner = inner

        def read(self, n: int = -1) -> bytes:
            nonlocal data_read
            data = self._inner.read(n)
            data_read += len(data)
            return data

    def counting_extractfile(self, member):  # type: ignore[no-untyped-def]
        inner = real_extractfile(self, member)
        return None if inner is None else CountingMember(inner)

    monkeypatch.setattr(harness.tarfile, "open", counting_open)
    monkeypatch.setattr(harness.tarfile.TarFile, "extractfile", counting_extractfile)
    try:
        peer(path)
    finally:
        for raw in opened:
            raw.close()
    assert compressed_read <= path.stat().st_size * 1.05
    assert data_read == scale.common_members * scale.common_member_size


def test_min_sample_s_records_the_mean_per_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Each call "takes" a fixed time on a fake clock. With min_sample_s, every sample
    # repeats its call until the minimum has passed and records the per-call mean, not
    # the total (fails against `return total, result`) and not a single call (fails
    # against a loop that stops after the first call).
    now = [0.0]
    monkeypatch.setattr(harness.time, "perf_counter", lambda: now[0])
    calls = {"ay": 0, "std": 0}

    def ay() -> str:
        calls["ay"] += 1
        now[0] += 0.002
        return "result"

    def std() -> None:
        calls["std"] += 1
        now[0] += 0.0005

    ay_s, result, std_s = harness._interleaved_pair_times(
        ay, std, rounds=3, min_sample_s=0.01
    )
    assert ay_s == pytest.approx(0.002)
    assert std_s == pytest.approx(0.0005)
    assert result == "result"
    # One warmup each, then three samples of at least 0.01 s each.
    assert calls["ay"] >= 1 + 3 * 5
    assert calls["std"] >= 1 + 3 * 20
