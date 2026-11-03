"""The shared password-confirmation ladder: planner, runner, codec evidence, watch.

The planner and runner are format-free, so they are tested here directly. The 7z and
ZIP wiring is tested end to end in ``test_sevenzip_password_confirm.py`` and
``test_zip_multipassword.py``.
"""

from __future__ import annotations

import io
import lzma
import random
import sys
import zlib

import pytest

from archivey.exceptions import ArchiveyError
from archivey.internal import detection
from archivey.internal.password_confirm import (
    PASSWORD_CONFIRM_CHUNK_BYTES,
    PASSWORD_CONFIRM_MAX_INPUT_BYTES,
    REJECTING_CODECS,
    PasswordConfirmPlan,
    PasswordConfirmVerdict,
    UnverifiedPasswordReadWatch,
    plan_password_confirm,
    run_password_confirm_plan,
)
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    is_codec_available,
    open_codec_stream,
)
from archivey.internal.streams.codecs.lzma_filter_decoder import FilterStream
from tests.conftest import ReadSizeSpy

BUDGET = 64 * 1024


def _crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


# --- plan_password_confirm ------------------------------------------------------------------


def test_a_one_byte_anchor_does_not_end_the_plan() -> None:
    # 1 verified byte carries 8 bits, not 32: the plan continues to the next anchor.
    plan = plan_password_confirm(
        [(1, _crc(b"a")), (10, _crc(b"b" * 10)), (100, _crc(b"c" * 100))],
        None,
        budget=BUDGET,
        codec_rejects=False,
    )
    assert plan.segments == ((1, _crc(b"a")), (10, _crc(b"b" * 10)))
    assert plan.confirms and plan.bounded


def test_short_anchors_add_up_to_four_bytes() -> None:
    plan = plan_password_confirm(
        [(1, 1), (3, 3), (50, 50)], None, budget=BUDGET, codec_rejects=False
    )
    assert plan.segments == ((1, 1), (3, 3))
    assert plan.confirms


def test_a_crc_less_first_member_is_read_through_to_the_first_anchor() -> None:
    plan = plan_password_confirm(
        [(100, None), (8, 8), (100, 100)], None, budget=BUDGET, codec_rejects=True
    )
    assert plan.segments == ((100, None), (8, 8))
    assert plan.confirms


def test_member_crcs_win_over_the_folder_digest() -> None:
    # A folder carrying both anchors on its first member, not on its end.
    plan = plan_password_confirm(
        [(10, 10), (1000, 1000)], 0xABCD, budget=BUDGET, codec_rejects=False
    )
    assert plan.segments == ((10, 10),)
    assert plan.unit_crc is None
    assert plan.confirms


def test_the_folder_digest_is_the_fallback_anchor() -> None:
    plan = plan_password_confirm(
        [(10, None), (20, None)], 0xABCD, budget=BUDGET, codec_rejects=True
    )
    assert plan.segments == ((10, None), (20, None))
    assert plan.unit_crc == 0xABCD
    assert plan.confirms and plan.bounded


def test_no_anchor_at_all_reads_at_most_the_budget() -> None:
    for rejects in (True, False):
        plan = plan_password_confirm(
            [(BUDGET, None), (BUDGET * 100, None)],
            None,
            budget=BUDGET,
            codec_rejects=rejects,
        )
        assert plan.read_bytes == BUDGET
        assert not plan.confirms and plan.bounded


def test_no_anchor_small_unit_reads_the_unit() -> None:
    plan = plan_password_confirm([(10, None)], None, budget=BUDGET, codec_rejects=False)
    assert plan.segments == ((10, None),)
    assert not plan.confirms


def test_rejecting_codec_does_not_walk_a_late_crc() -> None:
    plan = plan_password_confirm(
        [(200 * BUDGET, 0x1234)], None, budget=BUDGET, codec_rejects=True
    )
    assert plan.segments == ((BUDGET, None),)
    assert not plan.confirms and plan.bounded


def test_non_rejecting_codec_walks_a_late_crc() -> None:
    plan = plan_password_confirm(
        [(200 * BUDGET, 0x1234)], None, budget=BUDGET, codec_rejects=False
    )
    assert plan.segments == ((200 * BUDGET, 0x1234),)
    assert plan.confirms and not plan.bounded


def test_rejecting_codec_late_folder_digest_is_not_walked() -> None:
    plan = plan_password_confirm(
        [(200 * BUDGET, None)], 0x1234, budget=BUDGET, codec_rejects=True
    )
    assert plan.read_bytes == BUDGET
    assert plan.unit_crc is None and not plan.confirms


def test_non_rejecting_codec_walks_a_late_folder_digest() -> None:
    plan = plan_password_confirm(
        [(200 * BUDGET, None)], 0x1234, budget=BUDGET, codec_rejects=False
    )
    assert plan.unit_crc == 0x1234 and plan.confirms and not plan.bounded


def test_an_anchor_inside_the_prefix_is_kept_when_the_budget_cuts() -> None:
    # A short anchor inside the budget can still reject, so it stays in the plan.
    plan = plan_password_confirm(
        [(2, 2), (200 * BUDGET, 99)], None, budget=BUDGET, codec_rejects=True
    )
    assert plan.segments == ((2, 2), (BUDGET - 2, None))
    assert not plan.confirms


def test_a_unit_shorter_than_four_bytes_never_confirms() -> None:
    plan = plan_password_confirm(
        [(3, _crc(b"abc"))], None, budget=BUDGET, codec_rejects=False
    )
    assert (
        run_password_confirm_plan(io.BytesIO(b"abc"), plan)
        is PasswordConfirmVerdict.INCONCLUSIVE
    )
    assert (
        run_password_confirm_plan(io.BytesIO(b"abd"), plan)
        is PasswordConfirmVerdict.REJECTED
    )


# --- run_password_confirm_plan ----------------------------------------------------------------


def test_run_confirms_on_matching_member_crcs() -> None:
    first, second = b"aaaa", b"bbbb"
    plan = plan_password_confirm(
        [(4, _crc(first)), (4, _crc(second))], None, budget=BUDGET, codec_rejects=False
    )
    assert run_password_confirm_plan(io.BytesIO(first + second), plan) is (
        PasswordConfirmVerdict.CONFIRMED
    )


def test_run_rejects_a_mismatched_member_crc() -> None:
    plan = plan_password_confirm(
        [(4, 0xDEADBEEF)], None, budget=BUDGET, codec_rejects=False
    )
    assert (
        run_password_confirm_plan(io.BytesIO(b"abcd"), plan)
        is PasswordConfirmVerdict.REJECTED
    )


def test_run_rejects_a_mismatched_folder_digest() -> None:
    plan = plan_password_confirm(
        [(4, None)], 0xDEADBEEF, budget=BUDGET, codec_rejects=False
    )
    assert (
        run_password_confirm_plan(io.BytesIO(b"abcd"), plan)
        is PasswordConfirmVerdict.REJECTED
    )


def test_run_confirms_a_matching_folder_digest() -> None:
    payload = b"folder-crc-ok"
    plan = plan_password_confirm(
        [(5, None), (8, None)], _crc(payload), budget=BUDGET, codec_rejects=False
    )
    assert (
        run_password_confirm_plan(io.BytesIO(payload), plan)
        is PasswordConfirmVerdict.CONFIRMED
    )


def test_run_rejects_a_short_stream() -> None:
    # The CRC is the one the short bytes hash to, so only the short-read guard can
    # reject here.
    plan = PasswordConfirmPlan(
        ((8, _crc(b"short")),), None, confirms=True, bounded=True
    )
    assert (
        run_password_confirm_plan(io.BytesIO(b"short"), plan)
        is PasswordConfirmVerdict.REJECTED
    )


def test_run_rejects_a_short_stream_with_no_anchor() -> None:
    plan = plan_password_confirm([(8, None)], None, budget=BUDGET, codec_rejects=False)
    assert (
        run_password_confirm_plan(io.BytesIO(b"ab"), plan)
        is PasswordConfirmVerdict.REJECTED
    )


def test_run_short_read_after_the_input_cap_is_inconclusive() -> None:
    # The caller's input cap ended the stream, not the key.
    plan = plan_password_confirm([(8, None)], None, budget=BUDGET, codec_rejects=True)
    verdict = run_password_confirm_plan(
        io.BytesIO(b"ab"), plan, input_exhausted=lambda: True
    )
    assert verdict is PasswordConfirmVerdict.INCONCLUSIVE
    verdict = run_password_confirm_plan(
        io.BytesIO(b"ab"), plan, input_exhausted=lambda: False
    )
    assert verdict is PasswordConfirmVerdict.REJECTED


def test_run_mismatched_anchor_is_rejected_even_after_the_input_cap() -> None:
    # A mismatch is decisive evidence, whatever input it took to produce the bytes.
    plan = plan_password_confirm(
        [(4, _crc(b"good"))], None, budget=BUDGET, codec_rejects=True
    )
    verdict = run_password_confirm_plan(
        io.BytesIO(b"evil"), plan, input_exhausted=lambda: True
    )
    assert verdict is PasswordConfirmVerdict.REJECTED


def test_run_reads_in_bounded_chunks() -> None:
    payload = b"x" * (PASSWORD_CONFIRM_CHUNK_BYTES * 2 + 17)
    plan = plan_password_confirm(
        [(len(payload), _crc(payload))], None, budget=BUDGET, codec_rejects=False
    )
    spy = ReadSizeSpy(io.BytesIO(payload))
    assert run_password_confirm_plan(spy, plan) is PasswordConfirmVerdict.CONFIRMED
    assert spy.max_requested <= PASSWORD_CONFIRM_CHUNK_BYTES


def test_the_input_cap_is_the_inner_tar_probe_bound() -> None:
    # Design §2: the compressed-input cap is not a new number. If the detection bound
    # moves (bzip2's worst-case block is what sizes both), this one should too.
    assert (
        PASSWORD_CONFIRM_MAX_INPUT_BYTES == detection._INNER_CONTAINER_MAX_PROBE_BYTES
    )
    # Cut on an AES block boundary, so a capped CBC stream never ends mid-block.
    assert PASSWORD_CONFIRM_MAX_INPUT_BYTES % 16 == 0


# --- codec rejection evidence (task 5.2) ---------------------------------------------

_TRIALS = 200
_RANDOM_INPUT = 96 * 1024


def _codec_params(codec: Codec) -> CodecParams:
    if codec is Codec.LZMA:
        return CodecParams(
            filters=[
                {
                    "id": lzma.FILTER_LZMA1,
                    "lc": 3,
                    "lp": 0,
                    "pb": 2,
                    "dict_size": 1 << 20,
                }
            ]
        )
    if codec is Codec.LZMA2:
        return CodecParams(filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    if codec is Codec.IMPLODE:
        # Implode refuses to open without a size, which would pass here vacuously.
        return CodecParams(
            unpack_size=10 * BUDGET,
            implode_large_window=True,
            implode_literal_tree=True,
        )
    return CodecParams()


def _survivors(codec: Codec, seed: int) -> int:
    """How many random inputs (a wrong AES key's output) decode a full prefix."""
    rng = random.Random(seed)
    survived = 0
    for _ in range(_TRIALS):
        data = rng.randbytes(_RANDOM_INPUT)
        try:
            with open_codec_stream(
                codec, io.BytesIO(data), params=_codec_params(codec)
            ) as stream:
                got = 0
                while got < BUDGET:
                    chunk = stream.read(BUDGET - got)
                    if not chunk:
                        break
                    got += len(chunk)
        except ArchiveyError:
            continue
        if got >= BUDGET:
            survived += 1
    return survived


@pytest.mark.parametrize("codec", sorted(REJECTING_CODECS, key=lambda c: c.value))
def test_rejecting_codecs_reject_random_input(codec: Codec) -> None:
    """Every codec in the rejecting set dies on random input inside the prefix.

    This is the evidence the codec rung rests on, in the 7z and ZIP readers: a unit whose
    chain holds one of these stops at ``PASSWORD_CONFIRM_PREFIX_BYTES`` instead of
    walking to a late CRC.
    If a dependency change lets random bytes decode a full prefix, the codec must
    leave the set. Mutation check: adding ``Codec.BROTLI`` to the set fails here.
    """
    if not is_codec_available(codec):
        pytest.skip(f"{codec.value} backend not installed")
    assert _survivors(codec, seed=0x5EED) == 0


def test_brotli_does_not_reject_random_input() -> None:
    """Measured: about one random input in twenty decodes a full prefix. Non-rejecting.

    PPMd is non-rejecting too (2 of 200 in the design's measurement). Its random-input
    runs live in ``tests/test_ppmd_crash_isolation.py``, inside a child interpreter:
    unguarded pyppmd 1.3.x segfaults on some of it (``dev-docs/known-issues.md``).
    """
    if not is_codec_available(Codec.BROTLI):
        pytest.skip("brotli backend not installed")
    assert Codec.BROTLI not in REJECTING_CODECS
    assert Codec.PPMD not in REJECTING_CODECS
    assert _survivors(Codec.BROTLI, seed=0x5EED) > 0


@pytest.mark.parametrize(
    "lzma_filter",
    [
        {"id": lzma.FILTER_DELTA, "dist": 1},
        {"id": lzma.FILTER_X86},
        {"id": lzma.FILTER_ARM},
    ],
    ids=["delta", "bcj_x86", "bcj_arm"],
)
def test_filters_never_reject_random_input(lzma_filter: dict[str, int]) -> None:
    """Delta and BCJ are bijective transforms: every input decodes in full.

    Why ``MethodKind.LZMA_FAMILY`` (which holds them) is the wrong predicate for rung 3.
    """
    for codec in (Codec.DELTA, Codec.BCJ_X86, Codec.BCJ_ARM):
        assert codec not in REJECTING_CODECS
    data = random.Random(7).randbytes(BUDGET)
    stream = FilterStream(io.BytesIO(data), lzma_filter=lzma_filter, unpack_size=BUDGET)
    try:
        assert len(stream.read(BUDGET)) == BUDGET
    finally:
        stream.close()


# --- UnverifiedPasswordReadWatch -------------------------------------------------------------


class _Calls:
    def __init__(self) -> None:
        self.count = 0
        self.reasons: list[str] = []

    def __call__(self, reason: str) -> None:
        self.count += 1
        self.reasons.append(reason)


def _watch(
    data: bytes, *, seek_forfeits: bool = True
) -> tuple[UnverifiedPasswordReadWatch, _Calls]:
    calls = _Calls()
    watch = UnverifiedPasswordReadWatch(
        io.BytesIO(data),
        size=len(data),
        on_unverified=calls,
        seek_forfeits=seek_forfeits,
    )
    return watch, calls


def test_watch_reports_a_partial_read() -> None:
    watch, calls = _watch(b"0123456789")
    assert watch.read(3) == b"012"
    watch.close()
    assert calls.reasons == ["partial_read"]
    watch.close()
    assert calls.count == 1


def test_watch_is_silent_after_reading_to_the_size() -> None:
    watch, calls = _watch(b"0123456789")
    assert watch.read(10) == b"0123456789"
    watch.close()
    assert calls.count == 0


def test_watch_is_silent_after_read_all() -> None:
    watch, calls = _watch(b"0123456789")
    assert watch.read() == b"0123456789"
    watch.close()
    assert calls.count == 0


@pytest.mark.parametrize(("read_all", "reported"), [(True, 0), (False, 1)])
def test_watch_with_no_known_end_counts_only_reaching_eof(
    read_all: bool, reported: int
) -> None:
    """A size no read reaches (a ZIP pass, which checks on the read after the last
    byte): ``read(-1)`` returns at EOF, so it counts; ``read(len(data))`` does not."""
    data = b"0123456789"
    calls = _Calls()
    watch = UnverifiedPasswordReadWatch(
        io.BytesIO(data), size=sys.maxsize, on_unverified=calls
    )
    assert (watch.read() if read_all else watch.read(len(data))) == data
    watch.close()
    assert calls.count == reported


def test_watch_is_silent_when_nothing_was_read() -> None:
    watch, calls = _watch(b"0123456789")
    watch.close()
    assert calls.count == 0


def test_watch_is_silent_after_a_read_error() -> None:
    class _Failing(io.BytesIO):
        def read(self, n: int | None = -1, /) -> bytes:
            if self.tell() > 0:
                raise ValueError("boom")
            return super().read(n)

    calls = _Calls()
    watch = UnverifiedPasswordReadWatch(
        _Failing(b"0123456789"), size=10, on_unverified=calls
    )
    watch.read(2)
    with pytest.raises(ValueError, match="boom"):
        watch.read(2)
    watch.close()
    assert calls.count == 0


def test_watch_still_reports_after_a_seek_error() -> None:
    # A failed seek leaves the handle usable (here BytesIO refuses a negative
    # position before moving), so it must not disarm the report on the bytes read.
    watch, calls = _watch(b"0123456789")
    watch.read(3)
    with pytest.raises(ValueError, match="negative"):
        watch.seek(-1)
    watch.close()
    assert calls.count == 1


def test_a_refused_seek_leaves_the_digest_reachable() -> None:
    # BytesIO refuses a negative position before moving, so a full read after it
    # still reaches the digest, and the watch stays silent.
    watch, calls = _watch(b"0123456789")
    watch.read(3)
    with pytest.raises(ValueError, match="negative"):
        watch.seek(-1)
    assert watch.read() == b"3456789"
    watch.close()
    assert calls.count == 0


class _MovesThenRaises(io.BytesIO):
    """A seek that finishes moving and then raises, as ``DecompressorStream`` does
    when it escalates a rewind report."""

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        super().seek(offset, whence)
        raise RuntimeError("rewind report")


class _TellFails(io.BytesIO):
    """A seek that moves and then raises, after which the position cannot be read."""

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        super().seek(offset, whence)
        raise RuntimeError("seek failed")

    def tell(self) -> int:
        raise RuntimeError("tell failed")


@pytest.mark.parametrize(
    ("inner_type", "seek_forfeits", "expected"),
    [
        (_MovesThenRaises, True, ["seek"]),
        (_TellFails, True, ["seek"]),
        # A digest that survives seeks is reached by the read to the end...
        (_MovesThenRaises, False, []),
        # ...unless the position is unknown, and then no read can be placed.
        (_TellFails, False, ["seek"]),
    ],
)
def test_a_seek_error_that_moved_forfeits_the_digest(
    inner_type: type[io.BytesIO], seek_forfeits: bool, expected: list[str]
) -> None:
    # A failed seek that moved past the furthest read (or left the position unknown)
    # forfeits the digest the inner drops on a skip, so reading on to the end reports.
    calls = _Calls()
    watch = UnverifiedPasswordReadWatch(
        inner_type(b"0123456789"),
        size=10,
        on_unverified=calls,
        seek_forfeits=seek_forfeits,
    )
    watch.read(3)
    with pytest.raises(RuntimeError):
        watch.seek(5)
    watch.read()
    watch.close()
    assert calls.reasons == expected


def test_watch_readinto_counts_as_a_read() -> None:
    watch, calls = _watch(b"0123456789")
    buffer = bytearray(4)
    assert watch.readinto(buffer) == 4
    watch.close()
    assert calls.count == 1


def test_a_skip_pauses_the_digest_when_the_inner_drops_it() -> None:
    # A fused verifier stops hashing on a read that skips bytes past its frontier, so
    # reading on to the end after a skip does not reach the digest.
    watch, calls = _watch(b"0123456789")
    watch.read(1)
    watch.seek(5)
    assert watch.read() == b"56789"
    watch.close()
    assert calls.reasons == ["seek"]


def test_a_seek_back_after_a_skip_gets_the_digest_back() -> None:
    # A read that skips bytes leaves the hashing frontier where it was; a seek back to
    # it, then a read on to the end, completes the digest.
    watch, calls = _watch(b"0123456789")
    watch.read(1)
    watch.seek(5)
    assert watch.read() == b"56789"
    watch.seek(1)
    assert watch.read() == b"123456789"
    watch.close()
    assert calls.count == 0


def test_a_backward_seek_keeps_the_digest() -> None:
    # The fused verifier has hashed up to its furthest read, so a read after a seek
    # back hashes only what lies past it, and a read on to the end reaches the digest.
    watch, calls = _watch(b"0123456789")
    watch.read(6)
    watch.seek(2)
    assert watch.read() == b"23456789"
    watch.close()
    assert calls.count == 0


def test_a_skip_undone_before_a_read_keeps_the_digest() -> None:
    # Only a read that skips bytes loses the digest: a jump ahead that the caller
    # undoes before reading skips nothing. Closing there is still a partial read.
    watch, calls = _watch(b"0123456789")
    watch.read(3)
    watch.seek(7)
    watch.seek(3)
    watch.close()
    assert calls.reasons == ["partial_read"]
    # Closing while parked past the furthest read short of the end names the seek.
    watch, calls = _watch(b"0123456789")
    watch.read(3)
    watch.seek(7)
    watch.close()
    assert calls.reasons == ["seek"]


def test_a_rewind_to_start_rearms_the_digest() -> None:
    # A seek to 0 re-arms the fused verifier's checksum, so a read from there to the
    # end reaches the digest again, whatever seeks came before.
    watch, calls = _watch(b"0123456789")
    watch.read(1)
    watch.seek(5)
    watch.seek(0)
    assert watch.read() == b"0123456789"
    watch.close()
    assert calls.count == 0


def test_a_seek_keeps_a_digest_that_survives_seeks() -> None:
    # A WinZip AES HMAC is completed by the read that reaches the end, wherever the
    # reads started, so a skip then a read to the end is verified...
    watch, calls = _watch(b"0123456789", seek_forfeits=False)
    watch.read(1)
    watch.seek(5)
    assert watch.read() == b"56789"
    watch.close()
    assert calls.count == 0
    # ...and a skip then a short read is a partial read, not a seek.
    watch, calls = _watch(b"0123456789", seek_forfeits=False)
    watch.read(1)
    watch.seek(5)
    assert watch.read(2) == b"56"
    watch.close()
    assert calls.reasons == ["partial_read"]


def test_rejecting_codec_budget_cut_after_a_large_crc_less_item() -> None:
    # A large CRC-less first item does not drag the prefix past the budget.
    plan = plan_password_confirm(
        [(200 * BUDGET, None), (10, 10)], None, budget=BUDGET, codec_rejects=True
    )
    assert plan.segments == ((BUDGET, None),)
