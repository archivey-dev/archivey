"""The SFX magic scan: linear candidate search and the fat Mach-O 64 layout.

Kept apart from ``test_sfx.py`` so the search's own contract (same hits as a
from-scratch search, in linear time) reads on its own.
"""

from __future__ import annotations

import io
import random
import struct
import time
from collections.abc import Callable

import pytest

from archivey.internal.backends.rar_parser import RAR5_ID, RAR_ID
from archivey.internal.backends.sevenzip_parser import MAGIC_7Z
from archivey.internal.sfx import (
    MAX_VALIDATED_CANDIDATES,
    ExecutableCue,
    HitOutcome,
    HitSelector,
    MagicHit,
    MagicScan,
    ScanMiss,
    ScanNeedle,
    _EarliestFinder,
    _remaining_from_origin,
    executable_cue,
    iter_magic_in_prefix,
    scan_for_magic,
)

_NEEDLES = (ScanNeedle(RAR5_ID), ScanNeedle(RAR_ID), ScanNeedle(MAGIC_7Z))


def _reference_earliest(
    data: bytes | bytearray,
    needles: tuple[ScanNeedle, ...],
    start: int,
    searched: int,
) -> tuple[int, ScanNeedle] | None:
    """The search as it was before positions were carried: every needle from ``start``."""
    best: tuple[int, ScanNeedle] | None = None
    for needle in needles:
        found = data.find(needle.magic, max(start, searched - (len(needle.magic) - 1)))
        if found >= 0 and (best is None or found < best[0]):
            best = (found, needle)
    return best


def _random_haystack(rng: random.Random, size: int) -> bytearray:
    """Random bytes seeded with whole and partial magics, often overlapping."""
    pieces = [RAR5_ID, RAR_ID, MAGIC_7Z, b"Rar!", b"Rar!\x1a\x07", b"7z", b"\x00"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(pieces) if rng.random() < 0.6 else bytes([rng.randrange(256)])
    return out


@pytest.mark.parametrize("seed", range(40))
def test_finder_matches_a_from_scratch_search(seed: int) -> None:
    rng = random.Random(seed)
    data = _random_haystack(rng, rng.randrange(0, 400))
    searched = rng.choice([0, 0, rng.randrange(0, len(data) + 1)])
    finder = _EarliestFinder(data, _NEEDLES, searched=searched)
    start = 0
    while True:
        expected = _reference_earliest(data, _NEEDLES, start, searched)
        assert finder.find(start) == expected
        if expected is None:
            break
        # The scans advance to one past the hit, or further (a validator's skip).
        start = expected[0] + 1 + (rng.randrange(8) if rng.random() < 0.2 else 0)


@pytest.mark.parametrize("seed", range(40))
def test_finder_sees_bytes_appended_between_calls(seed: int) -> None:
    """The validated scan's window grows under the finder when a validator peeks.

    ``scan_for_magic`` builds each chunk's finder with ``searched`` carried from the
    previous chunk and then appends to that window, so both are exercised together.
    """
    rng = random.Random(1000 + seed)
    full = _random_haystack(rng, rng.randrange(20, 400))
    data = bytearray(full[: rng.randrange(0, len(full))])
    searched = rng.choice([0, rng.randrange(0, len(data) + 1)])
    finder = _EarliestFinder(data, _NEEDLES, searched=searched)
    start = 0
    while True:
        if len(data) < len(full) and rng.random() < 0.5:
            data += full[len(data) : len(data) + rng.randrange(1, 32)]
        expected = _reference_earliest(data, _NEEDLES, start, searched)
        assert finder.find(start) == expected
        if expected is None:
            if len(data) == len(full):
                break
            data += full[len(data) :]
            continue
        start = expected[0] + 1


def test_iter_magic_in_prefix_is_linear_in_decoys() -> None:
    """Back-to-back RAR5 ids with RAR4 and 7z absent: each miss used to re-read the tail.

    On the from-scratch search this took about 75 s at 1 MiB (0.47 s at 64 KiB).
    """
    data = b"MZ" + RAR5_ID * (1024 * 1024 // len(RAR5_ID))
    started = time.perf_counter()
    count = sum(
        1
        for _ in iter_magic_in_prefix(
            lambda n: data[:n], [RAR5_ID, RAR_ID, MAGIC_7Z], limit=len(data)
        )
    )
    elapsed = time.perf_counter() - started
    assert count == 1024 * 1024 // len(RAR5_ID)
    assert elapsed < 10, f"scan took {elapsed:.1f}s"


def test_iter_magic_in_prefix_stops_reading_once_every_needle_is_dropped() -> None:
    """With every magic dropped, the iteration yields nothing and reads no further."""
    data = b"MZ" + RAR5_ID + b"\x00" * (1 << 17) + MAGIC_7Z + b"\x00" * (1 << 17)
    magics = {needle.magic for needle in _NEEDLES}
    peeks: list[int] = []

    def peek_more(n: int) -> bytes:
        peeks.append(n)
        return data[:n]

    assert list(iter_magic_in_prefix(peek_more, _NEEDLES, dropped=magics)) == []
    assert len(peeks) <= 1

    # Dropping every magic after the first hit ends the scan before the next peek,
    # so the 7z past the first peek step is never searched for.
    peeks.clear()
    dropped: set[bytes] = set()
    hits = []
    for hit in iter_magic_in_prefix(peek_more, _NEEDLES, dropped=dropped):
        hits.append(hit.candidate_origin)
        dropped |= magics
    assert hits == [2]
    assert len(peeks) == 1


def test_validated_scan_hits_are_unchanged() -> None:
    """``scan_for_magic`` still validates candidates in order and returns the first VALID."""
    payload = b"MZ" + b"\x00" * 100 + RAR5_ID + b"\x00" * 50 + MAGIC_7Z + b"\x00" * 64
    payload += RAR_ID + b"\x00" * 64
    seen: list[bytes] = []

    def validator(
        peek_more: Callable[[int], bytes], remaining: int | None
    ) -> HitOutcome:
        head = peek_more(8)
        seen.append(head)
        return (
            HitOutcome.VALID if head.startswith(RAR_ID) else HitOutcome.NOT_THIS_FORMAT
        )

    scan = scan_for_magic(
        io.BytesIO(payload), [RAR5_ID, RAR_ID, MAGIC_7Z], validator=validator
    )
    assert scan.hit is not None
    assert scan.hit.candidate_origin == payload.index(RAR_ID + b"\x00" * 64)
    assert [h[:6] for h in seen] == [RAR5_ID[:6], MAGIC_7Z, RAR_ID[:6]]


def test_validated_scan_prefers_a_later_valid_hit_over_a_short_one() -> None:
    """A ``VALID_SHORT`` hit is the fallback, ahead of a skipped ``DAMAGED`` one."""
    payload = (
        b"MZ" + b"\x00" * 40 + MAGIC_7Z + b"D" * 40 + MAGIC_7Z + b"S" * 40 + MAGIC_7Z
    )
    payload += b"V" * 40
    grades = {
        ord("D"): HitOutcome.DAMAGED,
        ord("S"): HitOutcome.VALID_SHORT,
        ord("V"): HitOutcome.VALID,
    }

    def validator(
        peek_more: Callable[[int], bytes], remaining: int | None
    ) -> HitOutcome:
        return grades[peek_more(len(MAGIC_7Z) + 1)[-1]]

    origins = [i for i in range(len(payload)) if payload.startswith(MAGIC_7Z, i)]
    scan = scan_for_magic(io.BytesIO(payload), [MAGIC_7Z], validator=validator)
    assert scan.hit is not None and scan.hit.candidate_origin == origins[2]

    # Without the VALID hit, the short one wins over the earlier damaged one.
    no_valid = payload[: origins[2]]
    scan = scan_for_magic(io.BytesIO(no_valid), [MAGIC_7Z], validator=validator)
    assert scan.hit is not None and scan.hit.candidate_origin == origins[1]


def test_rejection_cap_keeps_a_short_hit() -> None:
    """A ``VALID_SHORT`` hit is not a rejection, so the cap does not discard it."""
    short_at = 2 + 40
    payload = b"MZ" + b"\x00" * 40 + MAGIC_7Z + b"S" * 40
    payload += MAX_VALIDATED_CANDIDATES * (MAGIC_7Z + b"D" * 40)
    grades = {ord("D"): HitOutcome.DAMAGED, ord("S"): HitOutcome.VALID_SHORT}

    def validator(
        peek_more: Callable[[int], bytes], remaining: int | None
    ) -> HitOutcome:
        return grades[peek_more(len(MAGIC_7Z) + 1)[-1]]

    scan = scan_for_magic(io.BytesIO(payload), [MAGIC_7Z], validator=validator)
    assert scan.hit is not None and scan.hit.candidate_origin == short_at
    assert scan.rejected_count == MAX_VALIDATED_CANDIDATES


def _fat_macho64(endian: str, align: int) -> bytes:
    header = struct.pack(endian + "II", 0xCAFEBABF, 1)
    # fat_arch_64: cputype, cpusubtype, offset(64), size(64), align, reserved.
    arch = struct.pack(endian + "iiQQII", 0x01000007, 3, 0x1000, 0x2000, align, 0)
    return header + arch + b"\x00" * (8192 - len(header) - len(arch))


@pytest.mark.parametrize("endian", [">", "<"])
@pytest.mark.parametrize("align", [0, 12])
def test_fat_macho_64_header_parses(endian: str, align: int) -> None:
    # The old ``iiIQQI`` layout read a little-endian align-0 header's size as 0.
    assert executable_cue(_fat_macho64(endian, align)) is ExecutableCue.STRONG


@pytest.mark.parametrize("endian", [">", "<"])
def test_fat_macho_64_with_implausible_align_is_refused(endian: str) -> None:
    # The old layout read the reserved word as ``align`` and let this through.
    assert executable_cue(_fat_macho64(endian, 40)) is ExecutableCue.NONE


# --- Edges of the scan ----------------------------------------------------------------
# Edge cases of the self-extracting archive scan (``scan_for_magic``).
#
# These pin the parts of the scan that mutation testing found no test for: the read
# bound when nothing matches, a hit at the very first byte, what a validator is shown
# there, the overlay start (``first_at``) judged ahead of the window, and how the scan
# moves past a decoy or a hit with a negative origin. The needle finder, the prefix
# iteration and the hit selector under it are pinned too.


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
