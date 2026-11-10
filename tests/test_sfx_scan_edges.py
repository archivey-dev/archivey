"""Edge cases of the self-extracting archive scan (``scan_for_magic``).

These pin the parts of the scan that mutation testing found no test for: the read
bound when nothing matches, a hit at the very first byte, what a validator is shown
there, the overlay start (``first_at``) judged ahead of the window, and how the scan
moves past a decoy or a hit with a negative origin. The needle finder, the prefix
iteration and the hit selector under it are pinned too.
"""

from __future__ import annotations

import io
from collections.abc import Callable

import pytest

from archivey.internal.sfx import (
    HitOutcome,
    HitSelector,
    MagicHit,
    MagicScan,
    ScanMiss,
    ScanNeedle,
    _EarliestFinder,
    _remaining_from_origin,
    iter_magic_in_prefix,
    scan_for_magic,
)


class _CountingSource(io.BytesIO):
    """A source that counts the bytes the scan reads from it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_bytes = 0

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.read_bytes += len(data)
        return data


def _always(
    outcome: HitOutcome,
) -> Callable[[Callable[[int], bytes], int | None], HitOutcome]:
    def validator(peek: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
        return outcome

    return validator


def test_no_needles_is_a_plain_miss() -> None:
    assert scan_for_magic(io.BytesIO(b"abc"), []) == MagicScan(
        None, ScanMiss.NO_MATCH, 0
    )


def test_a_one_byte_needle_at_the_first_byte_is_found() -> None:
    scan = scan_for_magic(io.BytesIO(b"Xabc"), [b"X"])
    assert scan == MagicScan(MagicHit(0, b"X", 0), None, 0)


@pytest.mark.parametrize("validated", [False, True])
def test_a_scan_with_no_match_reads_no_more_than_its_limit(validated: bool) -> None:
    # The limit bounds the read, not only the hit: a miss over a large source
    # stops after ``limit`` bytes, across several chunks.
    source = _CountingSource(bytes(1 << 20))
    validator = _always(HitOutcome.VALID) if validated else None
    scan = scan_for_magic(source, [b"MAGI"], limit=200_000, validator=validator)
    assert scan.miss is ScanMiss.NO_MATCH
    assert source.read_bytes == 200_000


def test_a_validator_sees_the_bytes_of_a_hit_at_the_first_byte() -> None:
    data = b"MAGIC" + bytes(100)
    seen: list[tuple[bytes, bytes, int | None]] = []

    def validator(peek: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
        seen.append((peek(1), peek(5), remaining))
        return HitOutcome.VALID

    scan = scan_for_magic(io.BytesIO(data), [b"MAGI"], validator=validator)
    assert scan.hit == MagicHit(0, b"MAGI", 0)
    assert seen == [(b"M", b"MAGIC", len(data))]


def _short_at_full_length(
    total: int,
) -> Callable[[Callable[[int], bytes], int | None], HitOutcome]:
    """VALID_SHORT for the candidate at the start of the source, VALID elsewhere."""

    def validator(peek: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
        return HitOutcome.VALID_SHORT if remaining == total else HitOutcome.VALID

    return validator


def test_a_short_hit_at_the_overlay_start_wins_over_a_later_valid_one() -> None:
    # Where the executable says its overlay begins is judged first, and a short
    # hit there is the answer; the window alone would prefer the later VALID hit.
    data = b"MG" + b"." * 50 + b"MG" + b"." * 10
    validator = _short_at_full_length(len(data))
    assert scan_for_magic(io.BytesIO(data), [b"MG"], validator=validator).hit == (
        MagicHit(52, b"MG", 0)
    )
    scan = scan_for_magic(io.BytesIO(data), [b"MG"], validator=validator, first_at=0)
    assert scan == MagicScan(MagicHit(0, b"MG", 0), None, 0)


def test_the_overlay_start_counts_only_when_its_magic_fits_the_limit() -> None:
    data = b"x" * 10 + b"MG" + b"x" * 10
    valid = _always(HitOutcome.VALID)
    fits = scan_for_magic(
        io.BytesIO(data), [b"MG"], limit=12, validator=valid, first_at=10
    )
    assert fits == MagicScan(MagicHit(10, b"MG", 0), None, 0)
    cut = scan_for_magic(
        io.BytesIO(data), [b"MG"], limit=11, validator=valid, first_at=10
    )
    assert cut == MagicScan(None, ScanMiss.NO_MATCH, 0)


@pytest.mark.parametrize(
    "limit",
    [
        # The long needle runs past the limit at the overlay start.
        pytest.param(26, id="long-needle-does-not-fit"),
        # The long needle fits but is not what sits there.
        pytest.param(1000, id="long-needle-absent"),
    ],
)
def test_the_overlay_start_tries_every_needle(limit: int) -> None:
    data = b"MG" + b"." * 20 + b"MG" + b"." * 40
    scan = scan_for_magic(
        io.BytesIO(data),
        [b"LONGNEEDLE", b"MG"],
        limit=limit,
        validator=_always(HitOutcome.VALID),
        first_at=22,
    )
    assert scan.hit == MagicHit(22, b"MG", 0)


def test_the_overlay_start_is_given_its_remaining_length() -> None:
    # Remaining counts from the candidate, and the scan starts where the source
    # stands, not at its byte 0.
    data = b"#####" + b"." * 20 + b"MG" + b"." * 30
    seen: list[int | None] = []

    def validator(peek: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
        seen.append(remaining)
        return HitOutcome.VALID

    source = io.BytesIO(data)
    source.seek(5)
    scan = scan_for_magic(source, [b"MG"], validator=validator, first_at=20)
    assert scan.hit == MagicHit(20, b"MG", 0)
    assert seen == [len(data) - 5 - 20]


def test_a_decoy_right_before_the_payload_does_not_hide_it() -> None:
    # "RR" matches at 0 and again at 1, overlapping; the first is a decoy.
    calls: list[bytes] = []

    def validator(peek: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
        calls.append(peek(3))
        if len(calls) == 1:
            return HitOutcome.NOT_THIS_FORMAT
        return HitOutcome.VALID

    scan = scan_for_magic(io.BytesIO(b"RRRx" + bytes(10)), [b"RR"], validator=validator)
    assert scan == MagicScan(MagicHit(1, b"RR", 0), None, 1)
    assert calls == [b"RRR", b"RRx"]


def test_a_hit_with_a_negative_origin_is_skipped_by_one_byte() -> None:
    # The needle sits one byte into its candidate, so a hit at 0 has no origin;
    # the overlapping hit at 1 is the candidate at 0.
    scan = scan_for_magic(io.BytesIO(b"RRRx"), [ScanNeedle(b"RR", 1)])
    assert scan == MagicScan(MagicHit(0, b"RR", 1), None, 0)


# The needle finder


def test_the_finder_finds_a_one_byte_needle_at_the_first_byte() -> None:
    needle = ScanNeedle(b"X")
    assert _EarliestFinder(b"Xab", [needle]).find() == (0, needle)


def test_the_finder_skips_a_dropped_needle_and_searches_the_rest() -> None:
    dropped, kept = ScanNeedle(b"AA"), ScanNeedle(b"BB")
    finder = _EarliestFinder(b"xxAAxxBB", [dropped, kept], dropped={b"AA"})
    assert finder.find() == (6, kept)


def test_the_finder_gives_a_tie_to_the_needle_listed_first() -> None:
    short, long = ScanNeedle(b"AB"), ScanNeedle(b"ABC")
    assert _EarliestFinder(b"xABCx", [short, long]).find() == (1, short)
    assert _EarliestFinder(b"xABCx", [long, short]).find() == (1, long)


def test_the_finder_keeps_a_match_at_zero_when_the_data_grows() -> None:
    needle = ScanNeedle(b"AB")
    data = bytearray(b"ABxx")
    finder = _EarliestFinder(data, [needle])
    assert finder.find() == (0, needle)
    data += b"xxAB"
    assert finder.find() == (0, needle)


def test_the_finder_searches_grown_data_only_from_start() -> None:
    needle = ScanNeedle(b"AB")
    data = bytearray(b"xxxxx")
    finder = _EarliestFinder(data, [needle])
    assert finder.find() is None
    data += b"ABxAB"
    assert finder.find(8) == (8, needle)


def test_remaining_from_an_origin_at_the_end_is_zero() -> None:
    assert _remaining_from_origin(2, 8, 10) == 0
    assert _remaining_from_origin(2, 9, 10) is None
    assert _remaining_from_origin(None, 0, 10) is None
    assert _remaining_from_origin(0, 0, None) is None


# The prefix iteration


def _peek(data: bytes) -> Callable[[int], bytes]:
    def peek(n: int) -> bytes:
        return data[:n]

    return peek


def test_prefix_iteration_finds_a_one_byte_needle_at_the_first_byte() -> None:
    assert list(iter_magic_in_prefix(_peek(b"Xab"), [b"X"])) == [MagicHit(0, b"X", 0)]


def test_prefix_iteration_yields_overlapping_hits_and_their_offset() -> None:
    hits = list(iter_magic_in_prefix(_peek(b"RRRRx"), [ScanNeedle(b"RR", 1)]))
    # The hit at 0 has no origin; the ones at 1 and 2 are candidates at 0 and 1.
    assert hits == [MagicHit(0, b"RR", 1), MagicHit(1, b"RR", 1)]


# The hit selector


def test_a_capped_format_is_not_decided_by_a_later_valid_hit() -> None:
    selector: HitSelector[str] = HitSelector(keep_damaged=True, cap=1)
    assert not selector.offer("rar", "decoy", HitOutcome.NOT_THIS_FORMAT)
    assert selector.is_capped("rar")
    assert not selector.offer("rar", "payload", HitOutcome.VALID)
    assert selector.result() == (None, ScanMiss.CAPPED)
