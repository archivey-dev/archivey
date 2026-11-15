"""``open_stream()`` holds its decode to ``DecoderLimits.max_ratio``, as a member read
of the same bytes through ``open_archive()`` is held (DR-9)."""

from __future__ import annotations

import bz2
import gzip
import io
import random
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    CorruptionError,
    DecoderLimits,
    ResourceLimitError,
    TruncatedError,
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
        pytest.raises(ResourceLimitError, match="of the stream decoded"),
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


def _random(n: int) -> bytes:
    return random.Random(0).randbytes(n)


@pytest.mark.parametrize("size", [1000, 3 * _MIB])
@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress])
def test_one_read_of_a_cut_stream_raises(
    size: int, compress: Callable[[bytes], bytes]
) -> None:
    # The guard must not hold the decoder's error for a later read: a caller that
    # reads the stream once would get cut data and no error.
    packed = compress(_random(size))[:-20]
    with open_stream(io.BytesIO(packed)) as stream, pytest.raises(TruncatedError):
        stream.read()


def test_one_read_of_a_gzip_with_a_bad_crc_raises() -> None:
    packed = bytearray(gzip.compress(_random(3 * _MIB)))
    packed[-8] ^= 0xFF
    with (
        open_stream(io.BytesIO(bytes(packed))) as stream,
        pytest.raises(CorruptionError),
    ):
        stream.read()


def test_a_path_with_no_stat_size_is_held_by_its_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A block device: seekable, but stat gives no size, and the codec opens the path
    # itself, so no count of the source's bytes would ever grow. The length comes
    # from a seek to the end, as a member read of the same bytes finds it.
    import os
    import stat as stat_module

    import archivey.internal.source as source_module

    path = tmp_path / "bomb.gz"
    path.write_bytes(gzip.compress(bytes(8 * _MIB)))
    real_stat = os.stat

    def block_device_stat(p: object, *args: object, **kwargs: object) -> object:
        st = real_stat(p, *args, **kwargs)  # type: ignore[arg-type]
        if str(p) != str(path):
            return st
        fields = list(st)
        fields[0] = stat_module.S_IFBLK | 0o600
        return os.stat_result(fields)

    monkeypatch.setattr(source_module.os, "stat", block_device_stat)
    with open_stream(path) as stream, pytest.raises(ResourceLimitError):
        _drain(stream)


def test_a_seekable_stream_with_no_size_hint_is_held_by_its_length() -> None:
    # A SpooledTemporaryFile is seekable but has no stat size: the length comes from
    # a seek to the end, not from the live count and its 256 MiB floor.
    import tempfile

    with tempfile.SpooledTemporaryFile(max_size=64 * _MIB) as f:
        f.write(gzip.compress(bytes(8 * _MIB)))
        f.seek(0)
        with open_stream(f) as stream, pytest.raises(ResourceLimitError):
            _drain(stream)


class _NoSeekEnd(io.RawIOBase):
    """Seekable, but a seek to the end raises, as some device or socket wrappers do."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        return self._buf.readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_END:
            raise OSError(29, "Illegal seek")
        return self._buf.seek(offset, whence)

    def tell(self) -> int:
        return self._buf.tell()


def test_a_stream_that_refuses_a_seek_to_the_end_still_reads() -> None:
    data = _random(100_000)
    with open_stream(_NoSeekEnd(gzip.compress(data))) as stream:
        assert stream.read() == data


class _NoSizeHint(io.RawIOBase):
    """Seekable, with no size an ``ArchiveSource`` can read off it, so the guard
    measures it by a seek to the end (a ``BytesIO`` would give its buffer length)."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        return self._buf.readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._buf.seek(offset, whence)

    def tell(self) -> int:
        return self._buf.tell()


@pytest.mark.parametrize("seekable", [False, True])
def test_the_length_probe_leaves_the_source_where_the_codec_left_it(
    seekable: bool,
) -> None:
    # The guard measures a source with no size hint by a seek to its end after the
    # codec has opened it; with seekable=True the codec has already read (gzip finds
    # its trailer). The probe must put the source back there, not at its start, or a
    # codec reading on from the shared position would start over. The built-in codecs
    # re-seek before they read, so compare the position with an unguarded open too.
    data = _random(100_000)
    packed = b"x" * 8 + gzip.compress(data)

    def opened_at(config: ArchiveyConfig) -> int:
        source = _NoSizeHint(packed)
        source.seek(8)
        with open_stream(source, config=config, seekable=seekable) as stream:
            position = source.tell()
            assert stream.read() == data
        return position

    unguarded = ArchiveyConfig(decoder_limits=DecoderLimits(max_ratio=None))
    assert opened_at(ArchiveyConfig()) == opened_at(unguarded)
