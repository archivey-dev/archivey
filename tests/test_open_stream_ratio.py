"""``open_stream()`` holds its decode to ``DecoderLimits.max_ratio``, as a member read
of the same bytes through ``open_archive()`` is held (DR-9)."""

from __future__ import annotations

import bz2
import gzip
import io
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    DecoderLimits,
    ResourceLimitError,
    open_archive,
    open_stream,
)
from tests.streams_util import NonSeekableBytesIO

_MIB = 2**20
_ZEROS = bytes(24 * _MIB)


def _drain(stream: io.RawIOBase | io.BufferedIOBase) -> int:
    n = 0
    while chunk := stream.read(_MIB):
        n += len(chunk)
    return n


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress])
def test_open_stream_refuses_a_bare_stream_past_the_default_ratio(
    tmp_path: Path, compress: Callable[[bytes], bytes]
) -> None:
    path = tmp_path / "bomb"
    path.write_bytes(compress(_ZEROS))
    with open_archive(path) as reader, pytest.raises(ResourceLimitError):
        _drain(reader.open(reader.members()[0]))
    with (
        open_stream(path) as stream,
        pytest.raises(ResourceLimitError, match="max_ratio=800:1"),
    ):
        _drain(stream)


def test_open_stream_refuses_a_seekable_stream_by_its_size() -> None:
    with (
        open_stream(io.BytesIO(gzip.compress(_ZEROS))) as stream,
        pytest.raises(ResourceLimitError, match="Archive-wide"),
    ):
        stream.read()


def test_open_stream_refuses_a_pipe_by_the_bytes_it_took() -> None:
    # A pipe has no trusted size: the live ratio judges it, past its own floor.
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(live_ratio_activation_threshold=_MIB)
    )
    with (
        open_stream(NonSeekableBytesIO(gzip.compress(_ZEROS)), config=config) as s,
        pytest.raises(ResourceLimitError, match="Live decompression ratio"),
    ):
        _drain(s)


def test_open_stream_seekable_is_held_on_a_seek_to_the_end(tmp_path: Path) -> None:
    path = tmp_path / "bomb.gz"
    path.write_bytes(gzip.compress(_ZEROS))
    with (
        open_stream(path, seekable=True) as stream,
        pytest.raises(ResourceLimitError),
    ):
        stream.seek(0, io.SEEK_END)


def test_open_stream_reads_a_bomb_with_the_ratio_off() -> None:
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_ratio=None))
    with open_stream(io.BytesIO(gzip.compress(_ZEROS)), config=config) as stream:
        assert _drain(stream) == len(_ZEROS)


def test_open_stream_reads_ordinary_data_under_the_default_ratio() -> None:
    data = bytes(range(256)) * 40_000
    with open_stream(io.BytesIO(gzip.compress(data))) as stream:
        assert stream.read() == data
