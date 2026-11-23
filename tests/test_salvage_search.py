"""The salvage search driver (``archivey.internal.salvage``) over synthetic finders.

A format's ``find_header(window, start, stop)`` is pure on bytes, so these tests drive
the search with small finders over in-memory layers and check the shared rules: windows
and their overlap, the byte budget, each position examined once per layer, alignment
from a base offset, and the ``ARCHIVE_REGION_SKIPPED`` records with their cap.
"""

from __future__ import annotations

import json

import pytest

from archivey import DiagnosticCode, SalvageLimits
from archivey.diagnostics import RegionSkippedContext
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.salvage import (
    HeaderSearch,
    QuietSalvageState,
    SalvageState,
    requesting_salvage,
    search_forward,
    take_salvage_request,
)

MAGIC = b"HDR!"


def _magic_search(step: int = 1, header: int = 8) -> HeaderSearch:
    """A header is ``MAGIC`` at a candidate position, then ``header - 4`` more bytes
    that must be there too."""

    def find(window: bytes, start: int, stop: int) -> int | None:
        at = start
        while True:
            at = window.find(MAGIC, at)
            if at < 0 or at >= stop:
                return None
            if (at - start) % step == 0 and at + header <= len(window):
                return at
            at += 1

    return HeaderSearch(find_header=find, step=step, max_header_size=header)


def _state(
    *, max_search_bytes: int | None = None, max_reported_regions: int = 1000
) -> tuple[SalvageState, DiagnosticCollector]:
    collector = DiagnosticCollector()
    state = SalvageState(
        requested=True,
        enabled=True,
        limits=SalvageLimits(
            max_search_bytes=max_search_bytes,
            max_reported_regions=max_reported_regions,
        ),
        collector=collector,
        archive_name="x.bin",
        format_name="TEST",
    )
    return state, collector


class _Layer:
    """An in-memory layer that records each read and checks they run forward."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.reads: list[tuple[int, int]] = []

    def read_at(self, offset: int, size: int) -> bytes:
        if self.reads:
            last_offset, last_size = self.reads[-1]
            assert offset == last_offset + last_size, "reads must be contiguous"
        self.reads.append((offset, size))
        return self.data[offset : offset + size]


def _regions(collector: DiagnosticCollector) -> list[RegionSkippedContext]:
    out = []
    for d in collector.snapshot().retained:
        assert d.code is DiagnosticCode.ARCHIVE_REGION_SKIPPED
        assert isinstance(d.context, RegionSkippedContext)
        out.append(d.context)
    return out


def test_finds_the_first_header_and_records_the_gap() -> None:
    data = b"\x00" * 100 + MAGIC + b"rest" + b"\x00" * 50
    state, collector = _state()
    layer = _Layer(data)
    result = search_forward(state, layer.read_at, _magic_search(), start=10)
    assert result.found == 100
    assert not result.limit_reached
    [region] = _regions(collector)
    assert (region.offset, region.length, region.reason) == (10, 90, "no_header")
    assert (region.layer, region.format, region.archive_name) == (
        "archive",
        "TEST",
        "x.bin",
    )
    # Positions 10..100 were examined, one byte each.
    assert state.searched_bytes == 91
    assert state.position() == 101


def test_no_header_records_the_rest_of_the_layer() -> None:
    data = b"\x00" * 300
    state, collector = _state()
    layer = _Layer(data)
    result = search_forward(state, layer.read_at, _magic_search(), start=20)
    assert result.found is None and not result.limit_reached
    [region] = _regions(collector)
    assert (region.offset, region.length, region.reason) == (20, 280, "no_header")
    assert state.searched_bytes == 280


def test_no_gap_record_when_the_header_is_at_the_start() -> None:
    data = MAGIC + b"rest" + b"\x00" * 10
    state, collector = _state()
    result = search_forward(state, _Layer(data).read_at, _magic_search(), start=0)
    assert result.found == 0
    assert _regions(collector) == []


@pytest.mark.parametrize("shift", range(-8, 9))
def test_a_header_across_a_window_edge_is_found_once(shift: int) -> None:
    """With windows of 64 bytes and an 8-byte header, a header anywhere around the
    first window's end is found, at its true offset."""
    window = 64
    at = window + shift
    data = b"\x00" * at + MAGIC + b"tail" + b"\x00" * 100
    state, _ = _state()
    layer = _Layer(data)
    result = search_forward(
        state, layer.read_at, _magic_search(), start=0, window_size=window
    )
    assert result.found == at
    assert state.searched_bytes == at + 1


def test_windows_overlap_by_the_header_size_minus_one() -> None:
    """The search reads forward only, and each window shows the next one's first
    ``max_header_size - 1`` bytes too."""
    data = b"\x00" * 1000
    state, _ = _state()
    layer = _Layer(data)
    search_forward(
        state, layer.read_at, _magic_search(header=8), start=0, window_size=100
    )
    offsets = [offset for offset, _ in layer.reads]
    # The first read fills a window and its overlap; each later read adds one
    # window's worth, so a window starts every 100 bytes.
    assert layer.reads[0] == (0, 107)
    assert offsets == sorted(offsets)
    assert sum(size for _, size in layer.reads) >= len(data)
    assert state.searched_bytes == 1000


def test_a_header_cut_by_the_layer_end_does_not_pass() -> None:
    data = b"\x00" * 50 + MAGIC + b"ab"  # 6 of the 8 bytes
    state, collector = _state()
    result = search_forward(state, _Layer(data).read_at, _magic_search(), start=0)
    assert result.found is None
    [region] = _regions(collector)
    assert (region.offset, region.length) == (0, len(data))


def test_end_bounds_the_reads() -> None:
    data = b"\x00" * 100 + MAGIC + b"rest"
    state, collector = _state()
    layer = _Layer(data)
    result = search_forward(state, layer.read_at, _magic_search(), start=0, end=100)
    assert result.found is None
    assert max(offset + size for offset, size in layer.reads) <= 100
    [region] = _regions(collector)
    assert (region.offset, region.length) == (0, 100)


def test_alignment_counts_from_the_base() -> None:
    """Candidate positions are ``base + k * step``: a header off that grid is not a
    candidate, one on it is found."""
    base = 3
    step = 16
    data = bytearray(400)
    data[base + 5 * step + 1 : base + 5 * step + 5] = MAGIC  # off the grid
    data[base + 9 * step : base + 9 * step + 4] = MAGIC  # on it
    state, collector = _state()
    result = search_forward(
        state,
        _Layer(bytes(data)).read_at,
        _magic_search(step=step, header=16),
        start=base + 1,
        base=base,
    )
    assert result.found == base + 9 * step
    [region] = _regions(collector)
    assert (region.offset, region.length) == (base + 1, 9 * step - 1)
    # Examined: the positions from base + step through the found one, step bytes each.
    assert state.searched_bytes == 9 * step


def test_a_finder_off_the_grid_is_a_bug() -> None:
    search = HeaderSearch(find_header=lambda w, s, e: 3, step=4, max_header_size=4)
    state, _ = _state()
    with pytest.raises(AssertionError, match="not a candidate position"):
        search_forward(state, _Layer(b"\x00" * 64).read_at, search, start=0)


def test_the_position_only_moves_forward() -> None:
    """A second search from an earlier start examines nothing twice: it starts where
    the first one stopped, and the bytes count once."""
    data = b"\x00" * 40 + MAGIC + b"rest" + b"\x00" * 40 + MAGIC + b"rest"
    state, collector = _state()
    search = _magic_search()
    first = search_forward(state, _Layer(data).read_at, search, start=0)
    assert first.found == 40
    assert state.position() == 41
    # An unconfirmed member: the search goes on inside its data, from position 41;
    # asking from 0 again starts at 41 too.
    second = search_forward(state, _Layer(data).read_at, search, start=0)
    assert second.found == 88
    assert state.searched_bytes == 89
    regions = [(r.offset, r.length) for r in _regions(collector)]
    assert regions == [(0, 40), (41, 47)]


def test_layers_have_their_own_positions_and_share_the_budget() -> None:
    data = b"\x00" * 30 + MAGIC + b"rest"
    state, collector = _state(max_search_bytes=50)
    search = _magic_search()
    assert search_forward(state, _Layer(data).read_at, search, start=0).found == 30
    result = search_forward(state, _Layer(data).read_at, search, start=0, layer="gzip")
    # 31 bytes spent on the archive layer leave 19 for the gzip one.
    assert result.found is None and result.limit_reached
    assert state.position("gzip") == 19
    assert state.searched_bytes == 50
    last = _regions(collector)[-1]
    assert (last.layer, last.offset, last.length, last.reason) == (
        "gzip",
        0,
        None,
        "search_limit",
    )


def test_a_zero_budget_stops_at_once() -> None:
    data = b"\x00" * 10 + MAGIC + b"rest"
    state, collector = _state(max_search_bytes=0)
    layer = _Layer(data)
    result = search_forward(state, layer.read_at, _magic_search(), start=5)
    assert result.found is None and result.limit_reached
    assert state.searched_bytes == 0
    [region] = _regions(collector)
    assert (region.offset, region.length, region.reason) == (5, None, "search_limit")


def test_the_budget_ends_the_search_before_a_header_it_cannot_reach() -> None:
    data = b"\x00" * 100 + MAGIC + b"rest"
    state, _ = _state(max_search_bytes=100)
    result = search_forward(state, _Layer(data).read_at, _magic_search(), start=0)
    # Reaching the header at 100 examines 101 positions.
    assert result.limit_reached
    assert state.searched_bytes == 100


def test_a_budget_that_covers_the_header_finds_it() -> None:
    data = b"\x00" * 100 + MAGIC + b"rest"
    state, _ = _state(max_search_bytes=101)
    result = search_forward(state, _Layer(data).read_at, _magic_search(), start=0)
    assert result.found == 100
    assert state.remaining_bytes() == 0


def test_a_budget_that_covers_the_layer_end_is_not_a_limit() -> None:
    data = b"\x00" * 100
    state, collector = _state(max_search_bytes=100)
    result = search_forward(state, _Layer(data).read_at, _magic_search(), start=0)
    assert result.found is None and not result.limit_reached
    assert [r.reason for r in _regions(collector)] == ["no_header"]


def test_after_the_limit_every_search_stops_without_a_new_record() -> None:
    state, collector = _state(max_search_bytes=10)
    search = _magic_search()
    data = b"\x00" * 100
    assert search_forward(state, _Layer(data).read_at, search, start=0).limit_reached
    again = search_forward(state, _Layer(data).read_at, search, start=50, layer="xz")
    assert again.limit_reached
    assert [r.reason for r in _regions(collector)] == ["search_limit"]


def test_the_budget_runs_out_across_windows() -> None:
    data = b"\x00" * 10_000
    state, _ = _state(max_search_bytes=2_500)
    result = search_forward(
        state, _Layer(data).read_at, _magic_search(), start=0, window_size=1000
    )
    assert result.limit_reached
    assert state.searched_bytes == 2_500
    assert state.position() == 2_500


def test_region_records_stop_at_the_cap_and_finish_counts_the_rest() -> None:
    # Headers every 20 bytes with 12 bytes of nothing between them: each search
    # skips one region.
    unit = b"\x00" * 12 + MAGIC + b"rest"
    data = unit * 6
    state, collector = _state(max_reported_regions=2)
    search = _magic_search()
    found = []
    while True:
        result = search_forward(state, _Layer(data).read_at, search, start=0)
        if result.found is None:
            break
        found.append(result.found)
    # The walk goes on past the cap: every header is found.
    assert found == [12, 32, 52, 72, 92, 112]
    state.finish()
    state.finish()  # once per walk
    regions = _regions(collector)
    assert [(r.offset, r.length, r.reason) for r in regions] == [
        (0, 12, "no_header"),
        (13, 19, "no_header"),
        (33, None, "report_limit"),
    ]
    report = collector.snapshot().retained[-1]
    # Seven ranges in all (one before each header, one after the last), two reported.
    assert "5 more ranges" in report.message


def test_restart_forgets_the_earlier_walk() -> None:
    data = b"\x00" * 20 + MAGIC + b"rest"
    state, _ = _state(max_search_bytes=25)
    assert search_forward(state, _Layer(data).read_at, _magic_search(), start=0).found
    state.restart()
    assert state.searched_bytes == 0 and state.position() == 0
    assert search_forward(state, _Layer(data).read_at, _magic_search(), start=0).found


def test_a_reader_that_does_not_salvage_cannot_search() -> None:
    collector = DiagnosticCollector()
    state = SalvageState(
        requested=True,
        enabled=False,
        limits=SalvageLimits(),
        collector=collector,
        archive_name=None,
        format_name="ZIP",
    )
    with pytest.raises(AssertionError):
        search_forward(state, _Layer(b"").read_at, _magic_search(), start=0)


def test_header_search_needs_a_header_as_long_as_its_step() -> None:
    with pytest.raises(AssertionError):
        HeaderSearch(find_header=lambda w, s, e: None, step=8, max_header_size=4)


def test_region_context_is_json_safe() -> None:
    state, collector = _state()
    search_forward(state, _Layer(b"\x00" * 10).read_at, _magic_search(), start=0)
    [record] = collector.snapshot().retained
    payload = record.to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["context"]["kind"] == "region_skipped"


def test_the_salvage_request_goes_to_the_first_reader_only() -> None:
    assert take_salvage_request().requested is False
    with requesting_salvage(True, supported=False):
        first = take_salvage_request()
        second = take_salvage_request()
    assert (first.requested, first.supported) == (True, False)
    assert second.requested is False
    assert take_salvage_request().requested is False


def test_a_zero_budget_reads_nothing() -> None:
    state, collector = _state(max_search_bytes=0)
    layer = _Layer(b"\x00" * 10_000)
    result = search_forward(state, layer.read_at, _magic_search(), start=0)
    assert result.limit_reached
    assert layer.reads == []
    assert [r.reason for r in _regions(collector)] == ["search_limit"]


def test_a_small_budget_reads_no_more_than_it_can_examine() -> None:
    search = _magic_search(header=8)
    state, _ = _state(max_search_bytes=100)
    layer = _Layer(b"\x00" * (4 << 20))
    result = search_forward(state, layer.read_at, search, start=0)
    assert result.limit_reached
    # With no ``end``, one byte more tells the layer's end from the budget's.
    assert sum(size for _, size in layer.reads) <= 100 + search.max_header_size
    assert state.searched_bytes == 100
    state, _ = _state(max_search_bytes=100)
    layer = _Layer(b"\x00" * (4 << 20))
    search_forward(state, layer.read_at, search, start=0, end=4 << 20)
    assert sum(size for _, size in layer.reads) <= 100 + search.max_header_size - 1


def test_an_end_behind_the_position_is_refused_and_moves_nothing() -> None:
    data = b"\x00" * 300
    state, collector = _state()
    search = _magic_search()
    assert (
        search_forward(state, _Layer(data).read_at, search, start=0, end=200).found
        is None
    )
    assert state.position() == 200
    with pytest.raises(AssertionError, match="end"):
        search_forward(state, _Layer(data).read_at, search, start=0, end=50)
    assert state.position() == 200
    # The range up to 200 was searched: asking again examines and records nothing.
    again = search_forward(state, _Layer(data).read_at, search, start=0, end=200)
    assert again.found is None
    assert state.position() == 200
    assert state.searched_bytes == 200
    assert [(r.offset, r.length) for r in _regions(collector)] == [(0, 200)]


def test_an_end_before_the_start_is_refused() -> None:
    state, _ = _state()
    with pytest.raises(AssertionError, match="end"):
        search_forward(
            state, _Layer(b"\x00" * 400).read_at, _magic_search(), start=300, end=80
        )
    assert state.position() == 0


def test_the_cursor_never_moves_back() -> None:
    state, _ = _state()
    search_forward(state, _Layer(b"\x00" * 100).read_at, _magic_search(), start=0)
    with pytest.raises(AssertionError, match="back"):
        state._examined("archive", 40, 50)


def test_the_search_limit_message_says_where_the_search_started_and_stopped() -> None:
    state, collector = _state(max_search_bytes=30)
    search_forward(state, _Layer(b"\x00" * 100).read_at, _magic_search(), start=10)
    message = collector.snapshot().retained[-1].message
    assert "started at offset 10" in message
    assert "stopped at offset 40" in message
    state, collector = _state(max_search_bytes=0)
    search_forward(state, _Layer(b"\x00" * 100).read_at, _magic_search(), start=10)
    message = collector.snapshot().retained[-1].message
    assert "started at offset 10" in message
    assert "before examining a byte" in message


def test_a_budget_that_covers_an_unsized_layer_to_its_end_is_not_a_limit() -> None:
    """With no ``end`` the search learns where the layer ends only from a short
    read; a budget that pays for every byte left still ends in ``no_header``."""
    search = HeaderSearch(find_header=lambda w, s, e: None, step=1, max_header_size=1)
    state, collector = _state(max_search_bytes=10)
    result = search_forward(state, _Layer(b"\x00" * 10).read_at, search, start=0)
    assert result.found is None and not result.limit_reached
    assert [(r.offset, r.length, r.reason) for r in _regions(collector)] == [
        (0, 10, "no_header")
    ]


def test_an_unsized_layer_that_ends_on_a_window_edge_is_not_a_limit() -> None:
    """The window span, not the budget, stops the read exactly at the layer's end,
    and the budget pays for every byte left: the search reads one byte more to see
    the end, and gives the same answer as with ``end``."""
    search = HeaderSearch(find_header=lambda w, s, e: None, step=2, max_header_size=2)
    for end in (None, 25):
        state, collector = _state(max_search_bytes=25)
        result = search_forward(
            state, _Layer(b"\x00" * 25).read_at, search, start=0, end=end, window_size=2
        )
        assert result.found is None and not result.limit_reached
        assert state.searched_bytes == 25
        assert [(r.offset, r.length, r.reason) for r in _regions(collector)] == [
            (0, 25, "no_header")
        ]


def test_a_second_walk_searches_quietly_as_the_first_did() -> None:
    """A walk started over to reach member data uses a :class:`QuietSalvageState`:
    it finds the same header from the start, and the reader's budget and records
    stay as the listing walk left them."""
    data = b"\x00" * 40 + MAGIC + b"rest"
    state, collector = _state(max_search_bytes=1000)
    search = _magic_search()
    assert search_forward(state, _Layer(data).read_at, search, start=0).found == 40
    searched = state.searched_bytes
    records = len(collector.snapshot().retained)
    again = QuietSalvageState(
        requested=True,
        enabled=True,
        limits=state.limits,
        collector=collector,
        archive_name="x.bin",
        format_name="TEST",
    )
    assert search_forward(again, _Layer(data).read_at, search, start=0).found == 40
    again.finish()
    assert state.searched_bytes == searched
    assert len(collector.snapshot().retained) == records


def test_a_one_byte_region_says_byte() -> None:
    data = b"\x00" + MAGIC + b"rest"
    state, collector = _state()
    assert (
        search_forward(state, _Layer(data).read_at, _magic_search(), start=0).found == 1
    )
    [record] = collector.snapshot().retained
    assert "skipped 1 byte at offset 0" in record.message


@pytest.mark.parametrize(("budget", "examined"), [(None, 14), (6, 6)])
def test_a_variable_width_finder_visits_each_start_once_within_the_budget(
    budget: int | None, examined: int
) -> None:
    """A finder whose headers vary in length checks a short header at a start a
    fixed-width one could not reach. The search bounds the starts it may visit, so
    it visits each one once, in one window, and none the budget does not pay for."""
    # Each byte holds its own offset, so the finder knows where each start is.
    data = bytes(range(14))
    visited: list[int] = []

    def find(window: bytes, start: int, stop: int) -> int | None:
        for at in range(start, stop):
            visited.append(window[at])
            # A header is 1 to 8 bytes long, as its first byte says, and none
            # passes. The window holds all of it unless the layer ends first.
            assert at + 1 + window[at] % 8 <= len(window) or window[-1] == data[-1]
        return None

    search = HeaderSearch(find_header=find, step=1, max_header_size=8)
    state, _ = _state(max_search_bytes=budget)
    search_forward(state, _Layer(data).read_at, search, start=0, window_size=4)
    assert visited == list(range(examined))
    assert state.searched_bytes == examined


@pytest.mark.parametrize("end_known", [False, True], ids=["unsized", "sized"])
@pytest.mark.parametrize("size", [3, 4])
def test_a_search_past_the_last_candidate_reports_only_bytes_that_exist(
    size: int, end_known: bool
) -> None:
    """A search from offset 2 with step 4 has its first candidate at offset 4, at or
    past the layer's end: it reports the bytes left after offset 2, with or without
    ``end``, and moves the position to the end, so a second search reports nothing."""
    state, collector = _state()
    search = _magic_search(step=4, header=8)
    data = b"abcd"[:size]
    for _ in range(2):
        result = search_forward(
            state,
            _Layer(data).read_at,
            search,
            start=2,
            end=size if end_known else None,
        )
        assert result.found is None and not result.limit_reached
    assert [(r.offset, r.length, r.reason) for r in _regions(collector)] == [
        (2, size - 2, "no_header")
    ]
    assert state.position() == size
    assert state.searched_bytes == 0
