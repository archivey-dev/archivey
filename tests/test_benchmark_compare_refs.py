"""benchmarks/compare_refs.py: fastest run per side, the band, and one-sided cases."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.compare_refs import main


def _write(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_text(json.dumps({"results": rows}))
    return path


def _row(case: str, wall_s: float, peer_s: float | None = None) -> dict[str, object]:
    return {"case": case, "wall_s": wall_s, "stdlib_wall_s": peer_s, "skipped": False}


def test_fastest_run_per_side_and_flags(tmp_path: Path, capsys) -> None:
    base = [
        _write(tmp_path / "b1.json", [_row("a", 0.100, 0.050), _row("b", 0.010)]),
        _write(tmp_path / "b2.json", [_row("a", 0.090, 0.045), _row("b", 0.011)]),
    ]
    cand = [
        _write(tmp_path / "c1.json", [_row("a", 0.200, 0.045), _row("b", 0.0101)]),
        _write(tmp_path / "c2.json", [_row("a", 0.180, 0.050), _row("c", 0.001)]),
    ]
    md = tmp_path / "out.md"
    args = ["--baseline", *map(str, base), "--candidate", *map(str, cand)]
    assert main([*args, "--md-out", str(md)]) == 0
    report = md.read_text()
    assert report == capsys.readouterr().out
    # a: 90 -> 180 ms is 2x; peers 45 -> 45 leave the normalised ratio at 2 too.
    assert "| a | 90.0 | 180.0 | 2.00 | 2.00 | slower |" in report
    # b: under a millisecond apart, never flagged however the ratio falls.
    assert "| b | 10.0 | 10.1 | 1.01 |  |  |" in report
    assert "**1 slower, 0 faster.**" in report
    assert "Only in the candidate: `c`" in report


def test_skipped_rows_are_left_out(tmp_path: Path, capsys) -> None:
    skipped: dict[str, object] = {
        "case": "a",
        "wall_s": 0.0,
        "stdlib_wall_s": None,
        "skipped": True,
    }
    base = _write(tmp_path / "b.json", [skipped])
    cand = _write(tmp_path / "c.json", [_row("a", 0.1)])
    main(["--baseline", str(base), "--candidate", str(cand)])
    assert "Only in the candidate: `a`" in capsys.readouterr().out
