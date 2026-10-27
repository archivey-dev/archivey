"""Smoke test for ``benchmarks/peers.py``: it runs, and peers read the same bytes.

Asserts no timing. A peer that is not installed prints a skip row instead of a ratio.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks import peers


@pytest.mark.timeout(120)
def test_peers_report_runs_at_ci_scale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ARCHIVEY_BENCH_CACHE", str(tmp_path))
    # read_all asserts byte equality between archivey and each peer before timing,
    # so a broken peer call or archivey API change raises here.
    peers.run("ci", rounds=1)

    rows = [line for line in capsys.readouterr().out.splitlines() if line]
    body = rows[2:]  # header and separator
    assert body, "no rows printed"
    for row in body:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 6, row
        measured = cells[5].endswith("×")
        skipped = cells[3] == "—" and cells[4] == "—"
        assert measured or skipped, row
    # ZIP and TAR fixtures need only the stdlib, so their rows are measured whenever
    # libarchive-c imports.
    if peers._peer_available("libarchive-c") is None:
        assert any(r.startswith("| ZIP | read_all |") and "×" in r for r in body)
    # py7zr writes the solid 7z fixture itself, so its rows are measured whenever it
    # imports, including on legs without the system libarchive.
    if peers._peer_available("py7zr") is None:
        assert any(
            r.startswith("| 7z solid | read_all | py7zr |") and "×" in r for r in body
        )
