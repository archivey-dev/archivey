"""The Brotli probe decodes up to a compressed meta-block the window decode never reached.

Data whose first bytes parse as a long uncompressed or metadata meta-block passes the
framing gate, the chain walk (which stops at the first compressed block) and the 4 KiB
window decode. When the source is over the 64 KiB completion window, nothing else looked
at it, and it was claimed as ``BROTLI`` / ``GUESS``: CPython 3.11 and 3.14 ``.pyc``
files, a Type 1 font, 1.2 % of uniform random data. The probe now decodes the source
from offset 0 to just past that compressed block's header, where such data fails.

Detection runs here on files named ``.br``: the probe runs on them whatever the
default for unnamed sources is, and a rejected probe leaves only the extension guess.
"""

from __future__ import annotations

import io
import random
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import ArchiveFormat, ArchiveyConfig, FormatDetectionError, detect_format
from archivey.config import ProcessIsolation
from archivey.detection import DetectionConfidence
from archivey.detection_cost import (
    BALANCED_BUDGET,
    FAST_BUDGET,
    TierSkip,
    TierSkipReason,
)
from archivey.internal.detection_workspace import (
    DETECTION_LIMIT,
    PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE,
)
from archivey.internal.probe_verdict import PROBE_MATCH
from archivey.internal.streams.codecs import BrotliCodec
from archivey.internal.streams.codecs.brotli_codec import _ForwardProbeSample
from archivey.internal.streams.codecs.brotli_framing import (
    CHAIN_DECODE_MARGIN,
    BrotliBlock,
    parse_metablock,
    walk_chain,
)
from tests.conftest import requires
from tests.detection_cost_util import within_budget
from tests.streams_util import (
    ShortReadBytesIO,
    brotli_compressed_metablock_header,
    brotli_declared_metablock_header,
    brotli_link_cap_residual,
)

# Seed 61 at 256 KiB is one of the random blobs the probe claimed before this check
# (137 of 10 000 at that size).
_CLAIMED_RANDOM_SEED = 61
_RANDOM_SIZE = 256 * 1024

# CPython 3.11's ``.pyc`` magic declares an uncompressed meta-block of 268 828 bytes.
_PYC_311_MAGIC = bytes.fromhex("a70d0d0a")
_PYC_SIZE = 295_412  # pyparsing/core.cpython-311.pyc, one of the claimed files


def _read_at(blob: bytes):
    def read_at(offset: int, length: int) -> bytes | None:
        return blob[offset : offset + length]

    return read_at


def _probe(blob: bytes, **kwargs) -> DetectionConfidence:
    return BrotliCodec().content_probe(
        blob[:DETECTION_LIMIT],
        source_length=len(blob),
        read_at=_read_at(blob),
        **kwargs,
    )


def _passes_the_earlier_checks(blob: bytes) -> int:
    """Assert the shape this check exists for, and return the compressed block's offset.

    The chain walk fits and stops at a compressed block past the window, and the window
    decode alone accepts: before this check, the probe claimed the blob.
    """
    walk = walk_chain(blob[:DETECTION_LIMIT], len(blob), read_at=_read_at(blob))
    assert not walk.proves_invalid
    assert walk.compressed_at is not None
    assert walk.compressed_at > DETECTION_LIMIT
    assert BrotliCodec()._decodes_sample(
        blob[:DETECTION_LIMIT], source_length=len(blob)
    )
    return walk.compressed_at


def _claimed_random_blob() -> bytes:
    return random.Random(_CLAIMED_RANDOM_SEED).randbytes(_RANDOM_SIZE)


def _pyc_like_blob() -> bytes:
    header = parse_metablock(_PYC_311_MAGIC)
    assert header.outcome is BrotliBlock.UNCOMPRESSED
    assert header.consumed is not None and header.declared_length == 268_828
    body = random.Random(311).randbytes(header.declared_length + header.consumed - 4)
    blob = _PYC_311_MAGIC + body + brotli_compressed_metablock_header()
    return blob + random.Random(312).randbytes(_PYC_SIZE - len(blob))


def _uncompressed_first_stream(noise_kib: int, quality: int, lgwin: int) -> bytes:
    """A real stream: ``noise_kib`` KiB of random bytes, then compressible text.

    The encoder stores the noise as uncompressed meta-blocks (64 KiB or 256 KiB each)
    and the text compressed; the settings used here put a compressed block past the
    window.
    """
    import brotli

    noise = random.Random(noise_kib).randbytes(noise_kib * 1024)
    text = b"".join(b"line %d of some text\n" % i for i in range(5000))
    data = brotli.compress(noise + text, quality=quality, lgwin=lgwin)
    assert brotli.decompress(data) == noise + text
    return data


def _metadata_first_stream(metadata_kib: int) -> bytes:
    """A real stream that opens with a metadata meta-block of ``metadata_kib`` KiB.

    ``brotli`` cannot emit metadata from Python, so the block is spliced in front of a
    stream whose own first block is uncompressed. Both use a 64 KiB window, which is
    what the one-bit WBITS of the spliced header declares.
    """
    import brotli

    inner = _uncompressed_first_stream(100, quality=1, lgwin=16)
    first = parse_metablock(inner)
    assert first.outcome is BrotliBlock.UNCOMPRESSED
    assert first.consumed is not None and first.declared_length is not None
    skipped = random.Random(metadata_kib).randbytes(metadata_kib * 1024)
    data = (
        brotli_declared_metablock_header(len(skipped), metadata=True, first=True)
        + skipped
        + brotli_declared_metablock_header(first.declared_length)
        + inner[first.consumed :]
    )
    assert brotli.decompress(data) == brotli.decompress(inner)
    return data


def _detect_named(tmp_path: Path, blob: bytes, *, budget=BALANCED_BUDGET):
    path = tmp_path / "x.br"
    path.write_bytes(blob)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert info.cost_receipt is not None
    assert within_budget(info.cost_receipt, budget)
    return info


# --- false claims the check removes ---------------------------------------------------


@requires("brotli")
@pytest.mark.parametrize(
    "make", [_claimed_random_blob, _pyc_like_blob], ids=["random", "pyc"]
)
def test_data_that_fails_past_the_window_is_not_brotli(tmp_path: Path, make) -> None:
    blob = make()
    assert len(blob) > BALANCED_BUDGET.completion_window_bytes
    compressed_at = _passes_the_earlier_checks(blob)
    assert compressed_at + CHAIN_DECODE_MARGIN < PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE

    assert _probe(blob) is DetectionConfidence.REJECTED
    # Detection keeps only the extension guess; the decode was charged.
    info = _detect_named(tmp_path, blob)
    assert info.detected_by == "extension"
    receipt = info.cost_receipt
    assert receipt is not None
    decoded = compressed_at + CHAIN_DECODE_MARGIN
    assert receipt.decode_input >= decoded
    # [0, decoded) is read once: the part the far-magic peek already holds is not
    # fetched again.
    held = max(decoded, BALANCED_BUDGET.max_far_bytes)
    assert receipt.unique_bytes_read <= held + 1024


@requires("brotli")
def test_random_blobs_over_the_completion_window_are_not_claimed() -> None:
    # Before the check, 137 of these 10 000 seeds were claimed; 30 of them are here.
    claimed = 0
    for seed in range(400):
        blob = random.Random(seed).randbytes(80 * 1024)
        claimed += _probe(blob) is not DetectionConfidence.REJECTED
    assert claimed == 0


# --- real streams the check must keep --------------------------------------------------


@requires("brotli")
@pytest.mark.parametrize(
    ("noise_kib", "quality", "lgwin"), [(100, 1, 16), (300, 5, 16), (900, 1, 22)]
)
def test_real_stream_with_a_long_uncompressed_first_block_is_kept(
    tmp_path: Path, noise_kib: int, quality: int, lgwin: int
) -> None:
    data = _uncompressed_first_stream(noise_kib, quality, lgwin)
    assert len(data) > BALANCED_BUDGET.completion_window_bytes
    compressed_at = _passes_the_earlier_checks(data)

    charged: list[int] = []

    def charge(n: int) -> bool:
        charged.append(n)
        return True

    assert _probe(data, charge_decode=charge) is PROBE_MATCH
    # The decode ran, and reached past the compressed block's header.
    assert charged == [min(compressed_at + CHAIN_DECODE_MARGIN, len(data))]
    info = _detect_named(tmp_path, data)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"


@requires("brotli")
def test_real_stream_with_a_long_metadata_first_block_is_kept(tmp_path: Path) -> None:
    data = _metadata_first_stream(200)
    assert parse_metablock(data).outcome is BrotliBlock.METADATA
    _passes_the_earlier_checks(data)
    assert _probe(data) is PROBE_MATCH
    info = _detect_named(tmp_path, data)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"


@requires("brotli")
def test_compressed_first_stream_decodes_nothing_more() -> None:
    import brotli

    data = brotli.compress(random.Random(0).randbytes(100_000).hex().encode())
    assert parse_metablock(data).outcome is BrotliBlock.COMPRESSED

    def charge(n: int) -> bool:
        raise AssertionError("a compressed first block needs no chain decode")

    assert _probe(data, charge_decode=charge) is PROBE_MATCH


# --- where the check cannot run: the walk's verdict stands ------------------------------


@requires("brotli")
@pytest.mark.parametrize("length", [(1 << 20) - 100, (1 << 20) + 1])
def test_compressed_block_past_the_reach_is_not_decoded(
    tmp_path: Path, length: int
) -> None:
    # Headers just below or above 1 MiB remain cheap to seek to. The sequential
    # decode would exceed its separate input cap, so its refusal must name that tier.
    head = brotli_declared_metablock_header(length, first=True)
    blob = (
        head
        + bytes(length)
        + brotli_compressed_metablock_header()
        + bytes(CHAIN_DECODE_MARGIN)
    )
    _passes_the_earlier_checks(blob)

    def read_at(offset: int, n: int) -> bytes | None:
        assert n <= 24, "past the reach, only headers are read"
        return blob[offset : offset + n]

    # Unmetered, the probe applies the reach itself.
    assert (
        BrotliCodec().content_probe(
            blob[:DETECTION_LIMIT], source_length=len(blob), read_at=read_at
        )
        is PROBE_MATCH
    )
    # Cheap header seeks still run, but the larger decode has its own input cap.
    info = _detect_named(tmp_path, blob)
    assert info.detected_by == "content_probe"
    assert TierSkip("content_probe_decode", TierSkipReason.BUDGET_EXHAUSTED) in (
        info.unavailable_tiers
    )


@requires("brotli")
def test_declined_charge_or_read_keeps_the_claim() -> None:
    blob = _claimed_random_blob()
    assert _probe(blob, charge_decode=lambda n: False) is PROBE_MATCH

    def read_at(offset: int, length: int) -> bytes | None:
        # Header reads only: the decode's long read is declined.
        return blob[offset : offset + length] if length <= 24 else None

    assert (
        BrotliCodec().content_probe(
            blob[:DETECTION_LIMIT], source_length=len(blob), read_at=read_at
        )
        is PROBE_MATCH
    )


@requires("brotli")
def test_fast_budget_cannot_cover_the_decode_and_says_so(tmp_path: Path) -> None:
    # The pyc shape needs 270 KiB of decoding; FAST allows 64 KiB for the whole call.
    blob = _pyc_like_blob()
    info = _detect_named(tmp_path, blob, budget=FAST_BUDGET)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"
    assert TierSkip("content_probe_decode", TierSkipReason.BUDGET_EXHAUSTED) in (
        info.unavailable_tiers
    )
    # A decode allowance that covers it is not enough: the decode reads [0, 270 KiB),
    # past FAST's 256 KiB read ceiling.
    roomy = replace(FAST_BUDGET, max_decode_input=BALANCED_BUDGET.max_decode_input)
    info = _detect_named(tmp_path, blob, budget=roomy)
    assert info.detected_by == "content_probe"
    assert TierSkip("content_probe_decode", TierSkipReason.BUDGET_EXHAUSTED) in (
        info.unavailable_tiers
    )
    # BALANCED covers both, and turns the claim away.
    assert _detect_named(tmp_path, blob).detected_by == "extension"


@requires("brotli")
def test_link_cap_residual_is_still_claimed() -> None:
    # The residual the provenance tests use: a chain longer than the link cap is
    # "cannot disprove", and the chain decode never starts.
    blob = brotli_link_cap_residual()
    walk = walk_chain(blob[:DETECTION_LIMIT], len(blob), read_at=_read_at(blob))
    assert not walk.proves_invalid and walk.compressed_at is None
    assert _probe(blob) is PROBE_MATCH


@requires("brotli")
@pytest.mark.parametrize("settings", [(300, 5, 16), (900, 1, 22)])
@pytest.mark.parametrize("max_chunk", [7, 65536])
@pytest.mark.parametrize(
    "isolation", [ProcessIsolation.KNOWN_CRASHES, ProcessIsolation.NATIVE_DECODERS]
)
def test_pipe_chain_decode_reaches_damage_after_a_valid_compressed_header(
    settings: tuple[int, int, int], max_chunk: int, isolation: ProcessIsolation
) -> None:
    stream = _uncompressed_first_stream(*settings)
    compressed_at = _passes_the_earlier_checks(stream)
    # Preserve the real compressed header and its first 64 bytes. Completion cannot
    # check this large source; the chain decode must reach the later corruption.
    damaged = stream[: compressed_at + 64] + random.Random(64).randbytes(1_300_000)
    assert len(damaged) > 1 << 20
    config = ArchiveyConfig(
        always_probe_content=True,
        detection_budget="thorough",
        process_isolation=isolation,
    )
    with io.BytesIO(damaged) as source, pytest.raises(FormatDetectionError):
        detect_format(source, config=config)
    with (
        ShortReadBytesIO(damaged, max_chunk=max_chunk, seekable=False) as source,
        pytest.raises(FormatDetectionError),
    ):
        detect_format(source, config=config)


# --- The probe's forward sample -------------------------------------------------------
# The incremental trial must stop at its input cap or its decoder's end.


def test_forward_sample_caps_reads_and_replays_buffered_bytes() -> None:
    data = bytes(10_000)
    reads: list[tuple[int, int]] = []

    def available(offset: int, length: int) -> tuple[bytes, bool]:
        assert offset + length <= 5000
        reads.append((offset, length))
        return data[offset : offset + length], False

    with _ForwardProbeSample(available, 5000) as sample:
        assert len(sample.read(6000)) == 4096
        assert len(sample.read()) == 904
        assert sample.read(1) == b""
        assert reads == [(0, 4096), (4096, 904)]
        sample.seek(4000)
        assert len(sample.read(2000)) == 1000
        assert sample.tell() == 5000


def test_a_finished_probe_does_not_fetch_optional_bytes() -> None:
    def available(offset: int, length: int) -> tuple[bytes, bool]:
        raise AssertionError("the finished decoder fetched optional bytes")

    with _ForwardProbeSample(available, 5000) as sample:
        sample.finished = lambda: True
        assert sample.read(1) == b""
