"""Within the completion window, a probe judges the same bytes the same with and
without a known size.

A content probe sees only the detection window, so detection runs it again over the
whole source (``_probe_completes``) when the source fits the completion window. That
needed the source's size. A seekable stream archivey does not recognize (a socket
wrapper, a user-written file object) has no size it can learn cheaply, so its bytes
were accepted on the window alone. Random bytes that a ``BytesIO`` left undetected
came back as Brotli, and an archive behind a few junk bytes as Brotli instead of the
archive. Found by the fuzz oracle that reads one input from a ``BytesIO`` and from a
short-read source.
"""

from __future__ import annotations

import contextlib
import dataclasses
import gzip
import io
import random
import zipfile

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyError,
    FormatDetectionError,
    detect_format,
)
from archivey.detection_cost import FAST_BUDGET, THOROUGH_BUDGET
from tests.conftest import requires
from tests.streams_util import ShortReadBytesIO

# Every case here is about the Brotli content probe, which core-only installs lack.
pytestmark = requires("brotli")

_CONFIG = ArchiveyConfig(always_probe_content=True)


def _detected(
    source: io.BytesIO | ShortReadBytesIO, config: ArchiveyConfig = _CONFIG
) -> ArchiveFormat | str:
    try:
        return detect_format(source, config=config).format
    except ArchiveyError as exc:
        return type(exc).__name__


def _noise(seed: int) -> bytes:
    # A Brotli-looking first byte, then noise: some of these decode for the whole
    # detection window and fail only further on.
    rng = random.Random(seed)
    first = rng.choice(b"\x0b\x1b\x2b\x8b\xcb\x21\x00\xff")
    return bytes([first]) + rng.randbytes(rng.choice([5000, 9000, 20000]))


@pytest.mark.parametrize("seed", [3, 5, 8, 22, 30])
def test_noise_is_detected_the_same_without_a_known_size(seed: int) -> None:
    data = _noise(seed)
    known = _detected(io.BytesIO(data))
    assert known != ArchiveFormat.BROTLI
    assert _detected(ShortReadBytesIO(data, max_chunk=1 << 16)) == known


def test_an_archive_behind_noise_is_detected_the_same_without_a_known_size() -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "hello " * 100)
    data = _noise(22) + archive.getvalue()
    known = _detected(io.BytesIO(data))
    assert _detected(ShortReadBytesIO(data, max_chunk=7)) == known


def test_a_source_past_the_completion_window_is_read_one_byte_past_it() -> None:
    # Detection does not read a long source of unknown size to its end: the measure
    # stops one byte past the window (64 KiB under the default budget). The buffered
    # wrapper may read one buffer further: io.DEFAULT_BUFFER_SIZE is 128 KiB from 3.14.
    data = _noise(22) + bytes(1 << 20)
    source = ShortReadBytesIO(data, max_chunk=1 << 16, seekable=False)
    _detected(source)
    assert source.consumed <= 64 * 1024 + 1 + io.DEFAULT_BUFFER_SIZE


@pytest.mark.parametrize("seekable", [True, False])
@pytest.mark.parametrize("max_chunk", [7, 1 << 16])
@pytest.mark.parametrize("preset", ["fast", "balanced", "thorough"])
def test_past_the_completion_window_invalid_framing_is_rejected(
    seekable: bool, max_chunk: int, preset: str
) -> None:
    # This malformed stream declares a literal block larger than the source.
    # Synthetic noise is intentional: a real encoder cannot emit invalid framing.
    data = _noise(22) + bytes(100_000)
    config = ArchiveyConfig(always_probe_content=True, detection_budget=preset)
    assert _detected(io.BytesIO(data)) == "FormatDetectionError"
    with ShortReadBytesIO(data, max_chunk=max_chunk, seekable=seekable) as source:
        expected = (
            "FormatDetectionError"
            if seekable or preset == "thorough"
            else ArchiveFormat.BROTLI
        )
        assert _detected(source, config) == expected


@pytest.mark.parametrize("seekable", [True, False])
def test_unknown_size_rejects_damage_at_a_reachable_compressed_block(
    seekable: bool,
) -> None:
    # Random damage is intentional: the opening literal block fits, but the
    # compressed block after it fails in the reference decoder.
    data = random.Random(61).randbytes(256 * 1024)
    config = ArchiveyConfig(always_probe_content=True, detection_budget="thorough")
    with ShortReadBytesIO(data, max_chunk=65536, seekable=seekable) as source:
        assert _detected(source, config) == "FormatDetectionError"


@pytest.mark.parametrize("quality", [0, 5, 11])
@pytest.mark.parametrize("seekable", [True, False])
def test_large_real_literal_blocks_are_accepted_without_a_known_size(
    quality: int,
    seekable: bool,
) -> None:
    import brotli

    payload = random.Random(123).randbytes(300123)
    data = brotli.compress(payload, quality=quality, lgwin=22)
    assert brotli.decompress(data) == payload
    config = ArchiveyConfig(always_probe_content=True, detection_budget="thorough")
    with ShortReadBytesIO(data, max_chunk=65536, seekable=seekable) as source:
        assert _detected(source, config) == ArchiveFormat.BROTLI


@pytest.mark.parametrize("preset", ["fast", "balanced"])
def test_default_pipe_chain_does_not_read_beyond_the_completion_window(
    preset: str,
) -> None:
    data = _noise(22) + bytes(1 << 20)
    config = ArchiveyConfig(always_probe_content=True, detection_budget=preset)
    with ShortReadBytesIO(data, max_chunk=7, seekable=False) as source:
        info = detect_format(source, config=config)
        assert info.format == ArchiveFormat.BROTLI
        assert source.consumed <= 64 * 1024 + 1 + io.DEFAULT_BUFFER_SIZE
        assert "content_probe_read_at" in {skip.tier for skip in info.unavailable_tiers}


def test_custom_forward_allowance_controls_pipe_header_reads() -> None:
    data = _noise(22) + bytes(100_000)
    for allowance, expected in [
        (0, ArchiveFormat.BROTLI),
        (600_000, "FormatDetectionError"),
    ]:
        budget = dataclasses.replace(
            FAST_BUDGET, max_probe_forward_bytes=allowance, max_scan_bytes=600_000
        )
        config = ArchiveyConfig(always_probe_content=True, detection_budget=budget)
        with ShortReadBytesIO(data, max_chunk=7, seekable=False) as source:
            assert _detected(source, config) == expected
            assert source.consumed <= max(64 * 1024, allowance) + io.DEFAULT_BUFFER_SIZE


@pytest.mark.parametrize("preset", ["balanced", "thorough"])
def test_a_decoding_seekable_source_keeps_bounded_read_ahead(preset: str) -> None:
    data = _noise(22) + bytes(100_000)
    config = ArchiveyConfig(always_probe_content=True, detection_budget=preset)
    with (
        io.BytesIO(gzip.compress(data)) as compressed,
        gzip.GzipFile(fileobj=compressed) as source,
    ):
        assert source.seekable()
        with pytest.raises(FormatDetectionError):
            detect_format(source, config=config)


def test_the_measure_stops_at_the_decode_allowance() -> None:
    # Under THOROUGH the completion window is 1 MiB, more than a small allowance can
    # complete: the source is not read past what the allowance could use.
    budget = dataclasses.replace(
        THOROUGH_BUDGET, max_decode_input=32 * 1024, max_probe_forward_bytes=32 * 1024
    )
    config = ArchiveyConfig(always_probe_content=True, detection_budget=budget)
    data = _noise(22) + bytes((1 << 20) - 6000)
    source = ShortReadBytesIO(data, max_chunk=1 << 16, seekable=False)
    with contextlib.suppress(ArchiveyError):
        detect_format(source, config=config)
    assert source.consumed <= 64 * 1024


def test_fast_records_the_completion_skip_without_a_known_size() -> None:
    from archivey.config import DEFAULT_ARCHIVEY_CONFIG
    from archivey.format_policy import FormatPolicy
    from archivey.internal.detection import _detect_format_body
    from archivey.internal.detection_cost_receipt import MutableDetectionCostReceipt
    from archivey.internal.diagnostics_collector import collector_from_config

    data = _noise(22) + bytes(1 << 20)
    for source in (io.BytesIO(data), ShortReadBytesIO(data, max_chunk=1 << 16)):
        receipt = MutableDetectionCostReceipt()
        _detect_format_body(
            source,
            collector_from_config(DEFAULT_ARCHIVEY_CONFIG),
            FAST_BUDGET,
            receipt,
            always_probe=True,
            formats=FormatPolicy(),
        )
        assert "probe_completion" in {skip.tier for skip in receipt.skips}
