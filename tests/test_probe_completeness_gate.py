"""Completeness gate + Brotli chain walk (probe-completeness-gate)."""

from __future__ import annotations

import io
import lzma
import os
import random
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    DetectionConfidence,
    detect_format,
)
from archivey.config import ArchiveyConfig
from archivey.exceptions import FormatDetectionError
from archivey.internal.detection_workspace import DETECTION_LIMIT
from archivey.internal.probe_verdict import PROBE_MATCH
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.codecs import BrotliCodec, LzmaAloneCodec, ZlibCodec
from archivey.internal.streams.codecs.brotli_framing import (
    CHAIN_MAX_LINKS,
    BrotliBlock,
    chain_proves_invalid,
    first_block_overruns_source,
    parse_metablock,
)
from tests.conftest import requires
from tests.detection_cost_util import within_budget
from tests.streams_util import (
    NonSeekableBytesIO,
    brotli_compressed_metablock_header,
    brotli_link_cap_residual,
    truncated_brotli,
)

# The sources below are unnamed, and detection runs content probes on an unnamed source
# only when the config asks for all of them.
PROBE_ALL = ArchiveyConfig(always_probe_content=True)


def _compressed_second_header() -> bytes:
    """A non-first meta-block header that classifies as COMPRESSED (walk stops)."""
    return brotli_compressed_metablock_header(first=False)


def _guess_residual_surviving_chain() -> bytes:
    """Uncompressed-first fabrication that passes framing + chain, fails full decode.

    The chain runs past the walk's link cap, so the walk cannot disprove it and the
    probe never decodes past its window. A chain that stops at a compressed block is
    decoded up to that block, which rejects the ``/**\n`` + padding + compressed-link
    shape this used to be.
    """
    return brotli_link_cap_residual()


@requires("brotli")
def test_small_real_brotli_survives_completeness() -> None:
    """A complete stream that fits in the prefix must still be accepted."""
    import brotli

    for payload in (b"", b"hello", b"x" * 50, b"payload " * 10):
        data = brotli.compress(payload)
        assert len(data) <= DETECTION_LIMIT
        assert BrotliCodec().content_probe(data, source_length=len(data)) is PROBE_MATCH
        info = detect_format(io.BytesIO(data), config=PROBE_ALL)
        assert info.format == ArchiveFormat.BROTLI


@requires("brotli")
def test_mid_positioned_stream_detects_valid_brotli() -> None:
    """Archive-relative ``source_length``: padding before the origin must not reject."""
    import brotli

    from archivey import open_archive

    raw = os.urandom(1000)
    payload = brotli.compress(raw, quality=0)
    for pad in (16, 4096):
        buf = io.BytesIO(b"\x00" * pad + payload)
        buf.seek(pad)
        info = detect_format(buf, config=PROBE_ALL)
        assert info.format == ArchiveFormat.BROTLI, f"pad={pad}"
        buf.seek(pad)
        with open_archive(buf, config=PROBE_ALL) as archive:
            assert archive.read(next(iter(archive))) == raw


@requires("brotli")
def test_chain_prefix_exhaustion_without_read_at_cannot_disprove() -> None:
    """Prefix-only walk must not treat prefix end as EOF when more source remains."""
    import brotli

    data = brotli.compress(os.urandom(300_000), quality=0, lgwin=10)
    # Cut mid-header of a later link (review F2: 1028/1029 on this shape).
    for cut in (1028, 1029):
        assert cut < len(data)
        assert chain_proves_invalid(data[:cut], len(data), read_at=None) is False, (
            f"cut={cut}"
        )


def test_zlib_completeness_rejects_truncated_high_ratio_stream() -> None:
    """Bounded completeness output (~64 KiB) must reject truncations that expand within it."""
    full = zlib.compress(b"A" * 200_000, 9)
    # 20B → ~1.8 KiB and 60B → ~43 KiB expand inside the drain and then TruncatedError.
    # A 100B truncate expands ~84 KiB — past the declared drain — so the bounded check
    # correctly cannot disprove (see format-detection completeness requirement).
    for n in (20, 60):
        blob = full[:n]
        assert (
            ZlibCodec().content_probe(blob, source_length=len(blob))
            is DetectionConfidence.REJECTED
        )
    over_drain = full[:100]
    assert (
        ZlibCodec().content_probe(over_drain, source_length=len(over_drain))
        is PROBE_MATCH
    )


@requires("brotli")
def test_completeness_rejects_tiny_nonterminating_file() -> None:
    blob = b"hello"
    assert parse_metablock(blob).outcome is BrotliBlock.COMPRESSED
    assert (
        BrotliCodec().content_probe(blob, source_length=len(blob))
        is DetectionConfidence.REJECTED
    )
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(blob), config=PROBE_ALL)


@requires("brotli")
def test_completeness_skipped_when_source_larger_than_prefix() -> None:
    import brotli

    data = brotli.compress(os.urandom(64 * 1024))
    assert len(data) > DETECTION_LIMIT
    prefix = data[:DETECTION_LIMIT]
    assert BrotliCodec().content_probe(prefix, source_length=len(data)) is PROBE_MATCH


@requires("brotli")
def test_real_brotli_corpus_includes_sub_100_byte_payloads() -> None:
    import brotli

    payloads = [b"", b"hello", b"x", b"a" * 9, b"payload under 100 bytes here"]
    for quality in (0, 1, 5, 9, 11):
        for lgwin in (10, 22, 24):
            for payload in payloads:
                try:
                    data = brotli.compress(payload, quality=quality, lgwin=lgwin)
                except brotli.error:
                    continue
                info = detect_format(io.BytesIO(data), config=PROBE_ALL)
                assert info.format == ArchiveFormat.BROTLI, (
                    f"missed q={quality} lgwin={lgwin} len={len(payload)}"
                )


def test_zlib_completeness_rejects_fully_visible_nonterminating() -> None:
    # Recognized CMF/FLG plus bytes that start a deflate block but never finish.
    blob = b"\x78\x9c\x01\x00\x00"
    assert (
        ZlibCodec().content_probe(blob, source_length=len(blob))
        is DetectionConfidence.REJECTED
    )


def test_zlib_complete_small_stream_still_accepted() -> None:
    data = zlib.compress(b"zlib payload")
    assert (
        detect_format(io.BytesIO(data), config=PROBE_ALL).format == ArchiveFormat.ZLIB
    )
    assert ZlibCodec().content_probe(data, source_length=len(data)) is PROBE_MATCH


def test_lzma_alone_completeness_on_fully_visible_nonterminating() -> None:
    alone = LzmaAloneCodec()
    # A real stream cut 10 bytes short. A header over zeros would also never terminate,
    # but the probe refuses a zero run before decoding.
    stream = lzma.compress(random.Random(3).randbytes(200), format=lzma.FORMAT_ALONE)
    blob = stream[:-10]
    # Prefix-only must match; when the whole source is visible and does not terminate,
    # completeness must reject.
    assert alone.content_probe(blob, source_length=None) is PROBE_MATCH
    assert (
        alone.content_probe(blob, source_length=len(blob))
        is DetectionConfidence.REJECTED
    )


@requires("brotli")
def test_chain_walk_rejects_second_link_overrun() -> None:
    framing = parse_metablock(b"/**\n")
    assert framing.consumed is not None and framing.declared_length is not None
    # Source long enough for the first block, too short for a second declaring MLEN.
    source_length = framing.consumed + framing.declared_length + 8
    prefix = (b"/**\n" + b"x" * framing.declared_length)[:DETECTION_LIMIT]
    overrun_hdr = b"MZ" + b"\x90" * 22

    def read_at(offset: int, length: int) -> bytes | None:
        if offset + length <= len(prefix):
            return prefix[offset : offset + length]
        return overrun_hdr[:length]

    assert chain_proves_invalid(prefix, source_length, read_at=read_at) is True


@requires("brotli")
def test_chain_walk_rejects_trailing_bytes_after_declared_end() -> None:
    assert parse_metablock(b"\x06").outcome is BrotliBlock.EMPTY_LAST
    # Prefix must be long enough for the header read; trailing bytes past consumed=1.
    blob = b"\x06" + b"\x00" * 40
    assert chain_proves_invalid(blob, len(blob)) is True


@requires("brotli")
def test_chain_walk_link_cap_does_not_reject() -> None:
    # Every link is a tiny non-last uncompressed block; hitting the link cap must not
    # reject (cannot disprove).
    small = None
    info = None
    for seed in range(256):
        cand = bytes([seed]) + b"\x00" * 23
        got = parse_metablock(cand)
        if (
            got.outcome is BrotliBlock.UNCOMPRESSED
            and got.declared_length is not None
            and got.declared_length <= 4
            and got.consumed is not None
            and not got.is_last
        ):
            small, info = cand, got
            break
    if small is None or info is None:
        pytest.skip("could not synthesize repeating chain links")
    step = info.consumed + info.declared_length
    source_length = step * (CHAIN_MAX_LINKS + 4)

    def read_at(offset: int, length: int) -> bytes | None:
        return small[:length]

    assert (
        chain_proves_invalid(
            small, source_length, read_at=read_at, max_links=CHAIN_MAX_LINKS
        )
        is False
    )


@requires("brotli")
def test_chain_walk_stops_immediately_on_compressed_first() -> None:
    import brotli

    data = brotli.compress(b"payload " * 40)
    assert parse_metablock(data).outcome is BrotliBlock.COMPRESSED
    reads: list[tuple[int, int]] = []

    def read_at(offset: int, length: int) -> bytes | None:
        reads.append((offset, length))
        return data[offset : offset + length]

    assert chain_proves_invalid(data[:4], len(data), read_at=read_at) is False
    # May extend the first-header read past a short prefix; must not walk to a later link.
    assert all(off < 24 for off, _ in reads)


@requires("brotli")
def test_ole_coff_residuals_still_accepted_above_prefix() -> None:
    ole = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 8000
    assert len(ole) > DETECTION_LIMIT
    assert first_block_overruns_source(ole, len(ole)) is False
    prefix = ole[:DETECTION_LIMIT]

    def read_at(offset: int, length: int) -> bytes | None:
        return ole[offset : offset + length]

    # The decode past the window rejects it; detection does not run the probes on an
    # OLE signature in any case.
    assert (
        BrotliCodec().content_probe(prefix, source_length=len(ole), read_at=read_at)
        is DetectionConfidence.REJECTED
    )
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(ole), config=PROBE_ALL)

    coff_header = bytes.fromhex("6486100100")
    framing = parse_metablock(coff_header)
    assert framing.outcome is BrotliBlock.UNCOMPRESSED
    assert framing.consumed is not None and framing.declared_length is not None
    second = _compressed_second_header()
    coff = (
        coff_header
        + b"\x00" * (framing.consumed + framing.declared_length - len(coff_header))
        + second
        + b"\x00" * 8
    )
    assert first_block_overruns_source(coff, len(coff)) is False
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(coff), config=PROBE_ALL)


@requires("brotli")
def test_unknown_length_keeps_today_behaviour_for_both_rules() -> None:
    blob = b"MZ" + b"\x90" * 8000
    assert BrotliCodec().content_probe(blob, source_length=None) is PROBE_MATCH
    assert (
        BrotliCodec().content_probe(blob, source_length=len(blob))
        is DetectionConfidence.REJECTED
    )


@requires("brotli")
def test_nonseekable_unknown_length_skips_both_rules() -> None:
    stub = b"MZ" + b"\x90" * 4094
    info = detect_format(
        ArchiveSource.for_stream(NonSeekableBytesIO(stub)), config=PROBE_ALL
    )
    assert info.format == ArchiveFormat.BROTLI


@requires("brotli")
def test_sixteen_mib_vacuous_first_block_caught_by_walk(tmp_path: Path) -> None:
    """MLEN ceiling makes the first-block check vacuous; the walk still decides."""
    framing = parse_metablock(b"/**\n")
    assert framing.consumed is not None and framing.declared_length is not None
    # 16 MiB source: first declaring block fits trivially; second link overruns.
    size = 16 * 1024 * 1024
    assert framing.consumed + framing.declared_length <= size
    assert first_block_overruns_source(b"/**\n", size) is False
    path = tmp_path / "big.bin"
    with path.open("wb") as f:
        f.write(b"/**\n")
        f.write(b"\x00" * framing.declared_length)
        f.write(b"MZ" + b"\x90" * 22)
        f.seek(size - 1)
        f.write(b"\x00")

    def read_at(offset: int, length: int) -> bytes | None:
        with path.open("rb") as f:
            f.seek(offset)
            return f.read(length)

    assert chain_proves_invalid(b"/**\n" + b"\x00" * 20, size, read_at=read_at) is True
    assert (
        BrotliCodec().content_probe(
            (b"/**\n" + b"\x00" * 100)[:DETECTION_LIMIT],
            source_length=size,
            read_at=read_at,
        )
        is DetectionConfidence.REJECTED
    )


@requires("brotli")
def test_guess_residual_surviving_chain_is_still_guess() -> None:
    blob = _guess_residual_surviving_chain()
    info = detect_format(io.BytesIO(blob), config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI
    assert info.confidence == DetectionConfidence.GUESS


# ---------------------------------------------------------------------------
# The probe sample and the whole-source completion check.
# ---------------------------------------------------------------------------

# A Perl module's opening, then filler. The first 256 bytes decode as a Brotli
# meta-block that only turns invalid further in; real modules shaped like this were the
# measured false positives (7 of 800 under ``/usr/share/perl`` with a 256-byte sample).
_PERL_LIKE_TEXT = b"package Bar;\n\nuse warnings handler source" + (
    b"# filler comment line\n" * 272
)


@requires("brotli")
def test_text_that_decodes_for_256_bytes_is_not_brotli() -> None:
    assert len(_PERL_LIKE_TEXT) > DETECTION_LIMIT
    # Positive control: a 256-byte sample of this text is a Brotli meta-block.
    assert BrotliCodec().content_probe(
        _PERL_LIKE_TEXT[:256], source_length=len(_PERL_LIKE_TEXT)
    )
    # Both the known-length and the unknown-length paths: a pipe gets no completion
    # check, so the larger probe sample alone has to turn this away.
    for source in (io.BytesIO(_PERL_LIKE_TEXT), NonSeekableBytesIO(_PERL_LIKE_TEXT)):
        with pytest.raises(FormatDetectionError):
            detect_format(source, config=PROBE_ALL)


@requires("brotli")
def test_probe_hit_under_the_completion_window_is_checked_whole() -> None:
    from archivey.detection_cost import BALANCED_BUDGET, FAST_BUDGET, TierSkipReason

    blob = truncated_brotli(20_000)
    assert DETECTION_LIMIT < len(blob) <= BALANCED_BUDGET.completion_window_bytes
    # The window alone says Brotli; the whole source says the stream never ends.
    assert BrotliCodec().content_probe(blob[:DETECTION_LIMIT], source_length=len(blob))
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(blob), config=PROBE_ALL)

    # ``FAST`` has no completion window, so the window's answer stands, and the
    # receipt says the check was off.
    fast = detect_format(
        io.BytesIO(blob), config=replace(PROBE_ALL, detection_budget=FAST_BUDGET)
    )
    assert fast.format == ArchiveFormat.BROTLI
    assert any(
        s.tier == "probe_completion"
        and s.reason is TierSkipReason.NOT_ENABLED_BY_POLICY
        for s in fast.unavailable_tiers
    ), fast.unavailable_tiers
    assert fast.cost_receipt is not None
    assert within_budget(fast.cost_receipt, FAST_BUDGET)


@requires("brotli")
def test_complete_stream_under_the_completion_window_still_detects() -> None:
    import random

    import brotli

    from archivey.detection_cost import BALANCED_BUDGET

    data = brotli.compress(random.Random(1).randbytes(15_000).hex().encode())
    assert DETECTION_LIMIT < len(data) <= BALANCED_BUDGET.completion_window_bytes
    info = detect_format(io.BytesIO(data), config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI
    assert info.cost_receipt is not None
    # The completion decode is charged: the whole source on top of the window.
    assert info.cost_receipt.decode_input >= len(data)
    assert within_budget(info.cost_receipt, BALANCED_BUDGET)


@requires("brotli")
def test_probe_hit_above_the_completion_window_is_accepted_on_the_window() -> None:
    from archivey.detection_cost import BALANCED_BUDGET

    blob = truncated_brotli(BALANCED_BUDGET.completion_window_bytes + 1)
    info = detect_format(io.BytesIO(blob), config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI
    assert not any(s.tier == "probe_completion" for s in info.unavailable_tiers)


@requires("brotli")
def test_completion_the_decode_allowance_cannot_cover_is_recorded() -> None:
    from archivey.detection_cost import BALANCED_BUDGET, TierSkipReason

    blob = truncated_brotli(20_000)
    # Enough for the probes' windows, not for the whole source on top.
    budget = replace(BALANCED_BUDGET, max_decode_input=4 * DETECTION_LIMIT)
    info = detect_format(
        io.BytesIO(blob), config=replace(PROBE_ALL, detection_budget=budget)
    )
    assert info.format == ArchiveFormat.BROTLI
    assert any(
        s.tier == "probe_completion" and s.reason is TierSkipReason.BUDGET_EXHAUSTED
        for s in info.unavailable_tiers
    ), info.unavailable_tiers
    assert info.cost_receipt is not None
    assert within_budget(info.cost_receipt, budget)
