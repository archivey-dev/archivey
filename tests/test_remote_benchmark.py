"""Pytest entry for the remote benchmark gate (range requests over fsspec)."""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("fsspec")

from benchmarks.remote import (
    GATED_FORMATS,
    PLANNER_MODE,
    PLANNER_TEST_CONSTANTS,
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


def _result(
    case: str, fmt: str, requests: int, fetched: int, operation: str = "list"
) -> RemoteCaseResult:
    return RemoteCaseResult(
        case=case,
        format=fmt,
        operation=operation,
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
                "operation": "list",
                "range_requests": 3,
                "bytes_fetched": 100,
            },
            "zip_stored_list_nocache": {
                "format": "zip_stored",
                "operation": "list",
                "range_requests": 2,
                "bytes_fetched": 50,
            },
            "tar_gz_list_nocache": {
                "format": "tar_gz",
                "operation": "list",
                "range_requests": 9,
                "bytes_fetched": 9,
            },
        }
    }
    results = [
        _result("tar_list_nocache", "tar", 4, 101),
        # Ungated formats and operations never fail, whatever they measure.
        _result("tar_gz_list_nocache", "tar_gz", 99, 999),
        _result("tar_threads_nocache", "tar", 99, 999, operation="threads"),
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


# The ceilings table in openspec/changes/fsspec-integration/specs/fsspec-integration/
# spec.md, §"ceilings that follow from the format", for the formats the planner cases
# run on. ``F`` is the maximum fetch the planner cases run with.
_F = PLANNER_TEST_CONSTANTS.max_fetch
_LIST_OPS = frozenset({"list"})
_READ_ONE_OPS = frozenset({"read_first", "read_middle", "read_last", "file_system"})
_CEILING_FORMATS = frozenset({"zip_stored", "zip_deflate", "7z_solid", "tar", "tar_gz"})


def _ceiling_failures(case: dict[str, Any]) -> list[str]:
    fmt, op = case["format"], case["operation"]
    requests, fetched, size = (
        case["range_requests"],
        case["bytes_fetched"],
        case["archive_size"],
    )
    if op not in _LIST_OPS | _READ_ONE_OPS:
        return []
    listing = op in _LIST_OPS
    if fmt.startswith("zip_"):
        limit = 2 if listing else 3
        return [] if requests <= limit else [f"{requests} requests > {limit}"]
    if fmt == "7z_solid":
        if listing:
            return [] if requests <= 2 else [f"{requests} requests > 2"]
        # The row bounds bytes by (member end - folder start) + F; the archive size
        # bounds the member end.
        bound = size + _F
    elif fmt == "tar":
        bound = size + _F
    elif fmt == "tar_gz":
        bound = size + _F if listing else 2 * (size + _F)
    else:
        return []
    return [] if fetched <= bound else [f"{fetched} bytes > {bound}"]


def test_planner_baseline_stays_inside_the_spec_ceilings():
    """Each planner case in the committed baseline is inside its row of the spec's
    ceilings table, gated or not. The baseline gate holds a case to its own numbers;
    this holds the numbers to the spec."""
    cases = json.loads(REMOTE_BASELINE.read_text())["cases"]
    planner = {name: c for name, c in cases.items() if c["cache"] == PLANNER_MODE}
    # A new fixture format needs its row here, or this test checks nothing for it.
    assert {c["format"] for c in planner.values()} <= _CEILING_FORMATS
    failures = {name: f for name, c in planner.items() if (f := _ceiling_failures(c))}
    assert failures == {}
