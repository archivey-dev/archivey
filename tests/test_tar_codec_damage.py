"""A damaged codec stream under a TAR raises the codec's error, not a cut.

A codec stream hands back the bytes before damage and raises on the next read (ADR
0014). Three TAR reads took that short read as the end of the archive and never read
again: the header read, a member read with no size, and the forward walk's skip over
member data. So a corrupt ``.tar.gz`` or ``.tar.xz`` listed with only a warning about
a missing end-of-archive marker, a full read of a member raised ``TruncatedError``,
and on a pipe the skip raised ``TruncatedError``. Each now raises the codec's
``CorruptionError``. Found by fuzzing seekable against pipe reads.
"""

from __future__ import annotations

import gzip
import io
import lzma
import random
import tarfile

import pytest

import archivey
from archivey import CorruptionError
from tests.streams_util import NonSeekableBytesIO

# A second gzip member whose first deflate block has the reserved type: zlib fails
# on it at once, so the damage sits right after the first member's bytes.
_BAD_GZIP_MEMBER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x07"


def _tar(members: int, size: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i in range(members):
            info = tarfile.TarInfo(f"f{i}")
            info.size = size
            tar.addfile(info, io.BytesIO(random.Random(i).randbytes(size)))
    return buf.getvalue()


def _gzip_damaged_at(raw: bytes, offset: int) -> bytes:
    """``raw`` gzipped, with the stream failing after ``offset`` decoded bytes."""
    return gzip.compress(raw[:offset]) + _BAD_GZIP_MEMBER


def _xz_flipped(raw: bytes) -> bytes:
    # Random data goes into LZMA2's plain chunks, so the flipped byte decodes to a
    # wrong byte and the block's check fails after the last of the data.
    packed = bytearray(lzma.compress(raw))
    packed[len(packed) // 2] ^= 0xFF
    return bytes(packed)


def _raises_corruption(exc_info: pytest.ExceptionInfo[CorruptionError]) -> None:
    # TruncatedError is a CorruptionError too, and it is the wrong verdict here.
    assert type(exc_info.value) is CorruptionError, exc_info.value


def test_damage_after_the_last_member_raises_when_listing() -> None:
    # The codec fails in the blocks after the only member. The header read there got
    # the bytes before the damage, which read as a cut end marker: a warning.
    data = _gzip_damaged_at(_tar(1, 80), 1024 + 100)
    with (
        archivey.open_archive(io.BytesIO(data)) as reader,
        pytest.raises(CorruptionError) as exc_info,
    ):
        list(reader)
    _raises_corruption(exc_info)


@pytest.mark.parametrize(
    "data",
    [_gzip_damaged_at(_tar(1, 3000), 2000), _xz_flipped(_tar(1, 3000))],
    ids=["gz", "xz"],
)
def test_a_full_read_of_a_damaged_member_raises_the_codec_error(data: bytes) -> None:
    with archivey.open_archive(io.BytesIO(data)) as reader:
        members = []
        with pytest.raises(CorruptionError):
            members.extend(reader)
        assert [m.name for m in members] == ["f0"]
        with pytest.raises(CorruptionError) as exc_info:
            reader.open(members[0]).read()
    _raises_corruption(exc_info)


def test_skipping_a_damaged_member_on_a_pipe_raises_the_codec_error() -> None:
    data = _xz_flipped(_tar(3, 3000))
    with (
        pytest.raises(CorruptionError) as exc_info,
        archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader,
    ):
        for _member, _stream in reader.stream_members():
            pass
    _raises_corruption(exc_info)
