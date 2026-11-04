"""benchmarks/compare_refs.py: fastest run per side, the band and floor, workload notes,
and cases with data on one side only."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.compare_refs import main


def _write(path: Path, rows: list[dict[str, object]], scale: str = "realistic") -> Path:
    path.write_text(json.dumps({"scale_detail": {"name": scale}, "results": rows}))
    return path


def _row(
    case: str,
    wall_s: float,
    peer_s: float | None = None,
    *,
    unpacked: int = 100,
    decoded: int = 100,
) -> dict[str, object]:
    return {
        "case": case,
        "wall_s": wall_s,
        "stdlib_wall_s": peer_s,
        "unpacked_bytes": unpacked,
        "bytes_decompressed": decoded,
        "skipped": False,
    }


def _skipped(case: str) -> dict[str, object]:
    return {"case": case, "wall_s": 0.0, "skipped": True, "notes": "skipped: no lib"}


def _report(tmp_path: Path, base: list[Path], cand: list[Path], *extra: str) -> str:
    md = tmp_path / "out.md"
    args = ["--baseline", *map(str, base), "--candidate", *map(str, cand)]
    assert main([*args, *extra, "--md-out", str(md)]) == 0
    return md.read_text()


def test_fastest_run_and_its_own_peer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = [
        _write(tmp_path / "b1.json", [_row("a", 0.100, 0.050)]),
        _write(tmp_path / "b2.json", [_row("a", 0.090, 0.045)]),
    ]
    cand = [
        # The fastest peer is in the slower run: it is not borrowed.
        _write(tmp_path / "c1.json", [_row("a", 0.200, 0.040)]),
        _write(tmp_path / "c2.json", [_row("a", 0.180, 0.050)]),
    ]
    report = _report(tmp_path, base, cand)
    assert report == capsys.readouterr().out
    # 90 -> 180 ms is 2x; per run, 0.180/0.050 over 0.090/0.045 is 1.80.
    assert "| a | 90.0 | 180.0 | 2.00 | 1.80 | slower |  |" in report
    assert "**1 slower, 0 faster.**" in report
    assert "up to 2 baseline and 2 candidate" in report


def test_faster_and_the_band(tmp_path: Path) -> None:
    base = [_write(tmp_path / "b.json", [_row("a", 0.100), _row("b", 0.100)])]
    cand = [_write(tmp_path / "c.json", [_row("a", 0.050), _row("b", 0.110)])]
    report = _report(tmp_path, base, cand)
    assert "| a | 100.0 | 50.0 | 0.50 |  | faster |  |" in report
    assert "| b | 100.0 | 110.0 | 1.10 |  |  |  |" in report
    assert "**0 slower, 1 faster.**" in report
    # A narrower band flags the 10% case too.
    assert "**1 slower, 1 faster.**" in _report(tmp_path, base, cand, "--band", "1.05")


def test_the_millisecond_floor(tmp_path: Path) -> None:
    base = [_write(tmp_path / "b.json", [_row("a", 0.0004)])]
    cand = [_write(tmp_path / "c.json", [_row("a", 0.0012)])]
    # Off by default: one host, so a sub-millisecond move is real.
    assert "| a | 0.4 | 1.2 | 3.00 |  | slower |  |" in _report(tmp_path, base, cand)
    floored = _report(tmp_path, base, cand, "--min-ms", "1")
    assert "| a | 0.4 | 1.2 | 3.00 |  |  |  |" in floored
    assert "**0 slower, 0 faster.**" in floored


def test_workload_differences_are_named(tmp_path: Path) -> None:
    base = [_write(tmp_path / "b.json", [_row("a", 0.1), _row("b", 0.1)])]
    cand = [
        _write(
            tmp_path / "c.json",
            [_row("a", 0.4, unpacked=400, decoded=400), _row("b", 0.1, decoded=50)],
            scale="bigger",
        )
    ]
    report = _report(tmp_path, base, cand)
    assert (
        "| a | 100.0 | 400.0 | 4.00 |  | slower | input differs; decoded 100 -> 400 |"
        in report
    )
    assert "| b | 100.0 | 100.0 | 1.00 |  |  | decoded 100 -> 50 |" in report
    assert "**The fixture scale differs between the sides.**" in report


def test_one_sided_and_skipped_cases(tmp_path: Path) -> None:
    base = [_write(tmp_path / "b.json", [_row("gone", 0.1), _skipped("lib")])]
    cand = [_write(tmp_path / "c.json", [_row("new", 0.1), _row("lib", 0.1)])]
    report = _report(tmp_path, base, cand)
    assert (
        "Measured only in the baseline (added, removed, or skipped on the other side): `gone`"
        in report
    )
    assert (
        "Measured only in the candidate (added, removed, or skipped on the other side): `lib`, `new`"
        in report
    )
    assert "Skipped in every baseline run: `lib` (skipped: no lib)" in report
