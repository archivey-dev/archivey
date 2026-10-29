"""Pytest entry for the remote benchmark gate (range requests over fsspec)."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fsspec")

from benchmarks.remote import (
    GATED_FORMATS,
    REMOTE_BASELINE,
    CountingFileSystem,
    RemoteCaseResult,
    baseline_applies,
    check_against_baseline,
    run_cases,
)


def test_counting_file_system_records_each_fetch(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(bytes(range(256)) * 4)
    fs = CountingFileSystem()
    with fs.open(str(path), "rb", cache_type="none") as f:
        assert f.read(10) == bytes(range(10))
        f.seek(1000)
        assert f.read() == (bytes(range(256)) * 4)[1000:]
    assert fs.log.ranges == [(str(path), 0, 10), (str(path), 1000, 1024)]
    assert fs.log.bytes_fetched == 34
    assert [call for call, _ in fs.log.metadata] == ["info"]


def test_remote_requests_match_the_baseline():
    """Request counts are exact and bytes fetched never grow, on the seeded fixtures.

    A planner change that moves these is a reviewed baseline diff:
    ``uv run --extra all python -m benchmarks.remote --update-baselines``.
    """
    baseline = json.loads(REMOTE_BASELINE.read_text())
    if not baseline_applies(baseline):
        pytest.skip("baseline measured with another io.DEFAULT_BUFFER_SIZE")
    results = run_cases()
    assert {r.format for r in results} >= GATED_FORMATS
    assert check_against_baseline(results, baseline) == []


def _result(case: str, fmt: str, requests: int, fetched: int) -> RemoteCaseResult:
    return RemoteCaseResult(
        case=case,
        format=fmt,
        operation="list",
        cache="nocache",
        range_requests=requests,
        metadata_requests=1,
        bytes_fetched=fetched,
        archive_size=1000,
    )


def test_gate_catches_moved_counts_and_dropped_cases():
    baseline = {
        "cases": {
            "tar_list_nocache": {
                "format": "tar",
                "range_requests": 3,
                "bytes_fetched": 100,
            },
            "zip_stored_list_nocache": {
                "format": "zip_stored",
                "range_requests": 2,
                "bytes_fetched": 50,
            },
            "tar_gz_list_nocache": {
                "format": "tar_gz",
                "range_requests": 9,
                "bytes_fetched": 9,
            },
        }
    }
    results = [
        _result("tar_list_nocache", "tar", 4, 101),
        # Ungated formats never fail, whatever they measure.
        _result("tar_gz_list_nocache", "tar_gz", 99, 999),
    ]
    failures = check_against_baseline(results, baseline)
    assert failures == [
        "tar_list_nocache: 4 range requests, baseline 3",
        "tar_list_nocache: fetched 101 bytes, baseline 100",
        "zip_stored_list_nocache: in the baseline but not measured",
    ]
    # Fewer bytes than the baseline passes; the request count stays exact.
    assert check_against_baseline(
        [_result("tar_list_nocache", "tar", 3, 90)], baseline
    ) == ["zip_stored_list_nocache: in the baseline but not measured"]
