"""A compressed tar's decode is held to the archive-wide ratio while listing, not only
while extracting (``DecodeRatioGuard``)."""

from __future__ import annotations

import bz2
import functools
import io
import tarfile

import pytest

from archivey import (
    ArchiveyConfig,
    ExtractionLimits,
    ResourceLimitError,
    open_archive,
)
from archivey.internal.bomb_tracker import DecodeRatioGuard
from tests.streams_util import NonSeekableBytesIO

_ZEROS = 24 * 2**20


class _Zeros(io.RawIOBase):
    def __init__(self, size: int) -> None:
        self._left = size

    def readable(self) -> bool:
        return True

    def readinto(self, b: memoryview) -> int:  # type: ignore[override]
        n = min(len(b), self._left)
        b[:n] = bytes(n)
        self._left -= n
        return n


@functools.cache
def _bomb() -> bytes:
    """A ``.tar.bz2`` of a few hundred bytes holding 24 MiB of zeros, tens of thousands to one."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo("zeros.bin")
        info.size = _ZEROS
        tf.addfile(info, _Zeros(_ZEROS))
        tf.addfile(tarfile.TarInfo("after.txt"), io.BytesIO(b""))
    return bz2.compress(raw.getvalue(), 9)


def test_listing_a_compressed_tar_past_the_ratio_is_refused() -> None:
    data = _bomb()
    assert len(data) < 1024
    with (
        open_archive(io.BytesIO(data)) as reader,
        pytest.raises(ResourceLimitError, match="max_ratio=1000:1"),
    ):
        reader.members()


def test_a_piped_compressed_tar_is_refused_past_the_live_floor() -> None:
    limits = ExtractionLimits(live_ratio_activation_threshold=8 * 2**20)
    config = ArchiveyConfig(extraction_limits=limits)
    with (
        open_archive(
            NonSeekableBytesIO(_bomb()), streaming=True, config=config
        ) as reader,
        pytest.raises(ResourceLimitError, match="Live decompression ratio"),
    ):
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


class _Decoder(io.BytesIO):
    """Stands in for a codec stream: records the furthest offset each call reached."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.furthest = 0

    def read(self, n: int | None = -1, /) -> bytes:
        data = super().read(n)
        self.furthest = max(self.furthest, self.tell())
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        pos = super().seek(offset, whence)
        self.furthest = max(self.furthest, pos)
        return pos


def _guarded(decoder: _Decoder) -> DecodeRatioGuard:
    return DecodeRatioGuard(
        decoder, limits=ExtractionLimits(), static_size=100, consumed=None
    )


@pytest.mark.parametrize("move", ["read", "seek"])
def test_the_decoder_stops_within_a_step_of_the_limit(move: str) -> None:
    """A whole read or a long forward seek reaches the decoder 1 MiB at a time, so
    the refusal comes before it decodes the rest."""
    decoder = _Decoder(bytes(_ZEROS))
    guard = _guarded(decoder)
    with pytest.raises(ResourceLimitError, match="max_ratio"):
        if move == "read":
            guard.read()
        else:
            guard.seek(_ZEROS - 1)
    floor = ExtractionLimits().ratio_activation_threshold
    assert decoder.furthest <= floor + 2**20


def test_a_backward_seek_does_not_count_again() -> None:
    decoder = _Decoder(bytes(4 * 2**20))
    guard = _guarded(decoder)
    for _ in range(3):
        guard.seek(0)
        assert len(guard.read()) == 4 * 2**20


def test_the_ratio_switched_off_lists_as_before() -> None:
    config = ArchiveyConfig(extraction_limits=ExtractionLimits(max_ratio=None))
    with open_archive(io.BytesIO(_bomb()), config=config) as reader:
        assert [m.name for m in reader.members()] == ["zeros.bin", "after.txt"]
