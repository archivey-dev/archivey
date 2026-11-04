"""The ``AUTO`` size gate for the bzip2 accelerator,
:data:`~archivey.config.INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE`, at its shipped value.

The DEFLATE family's gate has the same tests in ``test_rapidgzip_deflate_zlib.py``.
"""

from __future__ import annotations

import bz2
import functools
import io
import random

import pytest

from archivey.config import INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
from tests.conftest import requires

pytestmark = requires("rapidgzip")

_SMALL = b"the quick brown fox jumps over the lazy dog\n" * 50


@functools.cache
def _at_threshold() -> tuple[bytes, bytes]:
    """Random bytes whose bzip2 stream is just past the shipped threshold (random data
    does not compress), and that stream."""
    payload = random.Random(1).randbytes(INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE + 4096)
    compressed = bz2.compress(payload)
    assert len(compressed) >= INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
    return payload, compressed


def _uses_child(stream: object) -> bool:
    """Whether the codec stream reads through the rapidgzip child (it sits under the
    takeover and check layers, each holding the next as ``_inner``)."""
    inner = stream
    while inner is not None:
        if isinstance(inner, RapidgzipChildStream):
            return True
        inner = getattr(inner, "_inner", None)
    return False


def _config(mode: AcceleratorMode, compressed: bytes) -> StreamConfig:
    return StreamConfig(
        use_indexed_bzip2=mode,
        seekable=True,
        compressed_input_size=len(compressed),
    )


def test_the_auto_threshold_is_inside_the_child_break_even() -> None:
    """The child costs about 45 ms to start. A full read broke even near 0.6 MiB
    compressed with 4 cores and near 2 MiB with one (``scripts/investigations/bench_bzip2_child.py``),
    so the gate sits between the two."""
    assert 600 * 1024 <= INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE <= 2 * 1024 * 1024


@pytest.mark.parametrize("mode", [AcceleratorMode.OFF, AcceleratorMode.AUTO])
def test_off_and_auto_below_the_threshold_use_the_standard_library(
    mode: AcceleratorMode,
) -> None:
    compressed = bz2.compress(_SMALL)
    assert len(compressed) < INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
    config = _config(mode, compressed)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert not _uses_child(s)
        assert s.read() == _SMALL


def test_on_uses_the_accelerator_below_the_threshold() -> None:
    compressed = bz2.compress(_SMALL)
    assert len(compressed) < INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE
    config = _config(AcceleratorMode.ON, compressed)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert _uses_child(s)
        assert s.read() == _SMALL


def test_auto_uses_the_accelerator_from_the_threshold() -> None:
    payload, compressed = _at_threshold()
    config = _config(AcceleratorMode.AUTO, compressed)
    with open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config) as s:
        assert _uses_child(s)
        assert s.read() == payload
