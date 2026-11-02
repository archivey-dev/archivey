"""A decoder seek decodes nothing: the next read decodes to its target.

``DecompressorStream.seek`` records the target when reaching it would decode (a seek
back, or forward past the buffered output). The next read decodes to it, so a seek
that no read follows, or that a later seek replaces, costs nothing.
"""

from __future__ import annotations

import io
import lzma
from typing import Any

import pytest

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.streams import decompressor_stream
from archivey.internal.streams.codecs.lzip_decoder import LzipDecompressorStream
from archivey.internal.streams.codecs.xz_decoder import XzDecompressorStream
from tests.streams_util import make_multi_member_lzip

PARTS = [bytes([65 + i]) * 3000 + bytes(range(256)) * 4 for i in range(4)]
FULL = b"".join(PARTS)


class _Counts:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.resets = 0
        self.chunks = 0
        cls = decompressor_stream.DecompressorStream
        real_reset = cls._reset_to_seek_point
        real_chunk = cls._read_decompressed_chunk

        def reset(stream: Any, point: Any) -> None:
            self.resets += 1
            real_reset(stream, point)

        def chunk(stream: Any, *args: Any) -> bytes:
            self.chunks += 1
            return real_chunk(stream, *args)

        monkeypatch.setattr(cls, "_reset_to_seek_point", reset)
        monkeypatch.setattr(cls, "_read_decompressed_chunk", chunk)


def test_a_seek_back_after_a_full_read_decodes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = lzma.compress(FULL, format=lzma.FORMAT_XZ)
    with XzDecompressorStream(io.BytesIO(data)) as stream:
        assert stream.read() == FULL
        counts = _Counts(monkeypatch)
        assert stream.seek(100) == 100
        assert stream.tell() == 100
        assert counts.resets == 0
        assert counts.chunks == 0
        assert stream.read(10) == FULL[100:110]
        assert counts.resets == 1


def test_seeks_that_no_read_follows_cost_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = make_multi_member_lzip(PARTS)
    with LzipDecompressorStream(io.BytesIO(data)) as stream:
        assert stream.read(10) == FULL[:10]
        counts = _Counts(monkeypatch)
        stream.seek(5000)
        stream.seek(-1000, io.SEEK_CUR)
        assert stream.tell() == 4000
        stream.seek(9000)
        assert counts.resets == 0
        assert counts.chunks == 0
        # One restart, for the last target only.
        assert stream.read(10) == FULL[9000:9010]
        assert counts.resets <= 1


def test_a_seek_within_the_buffered_output_is_done_at_once() -> None:
    data = lzma.compress(FULL, format=lzma.FORMAT_XZ)
    with XzDecompressorStream(io.BytesIO(data)) as stream:
        assert stream.read(1) == FULL[:1]
        stream.seek(0, io.SEEK_END)
        size = stream.tell()
        assert size == len(FULL)
        # A size already known: a seek at or past it ends the stream without a decode.
        assert stream.seek(size + 5) == size + 5
        assert stream.read(1) == b""


def test_seek_cur_counts_from_the_target() -> None:
    data = make_multi_member_lzip(PARTS)
    with LzipDecompressorStream(io.BytesIO(data)) as stream:
        stream.seek(4000)
        assert stream.seek(100, io.SEEK_CUR) == 4100
        assert stream.seek(-200, io.SEEK_CUR) == 3900
        assert stream.read(10) == FULL[3900:3910]
        assert stream.tell() == 3910


def test_a_seek_past_a_truncation_raises_at_the_read() -> None:
    data = lzma.compress(FULL, format=lzma.FORMAT_XZ)
    cut = data[: len(data) // 2]
    with XzDecompressorStream(io.BytesIO(cut)) as stream:
        assert stream.seek(len(FULL) - 10) == len(FULL) - 10
        with pytest.raises(TruncatedError):
            stream.read(10)
        # Still truncated on the next read; a seek back restarts the decoder.
        with pytest.raises(TruncatedError):
            stream.read(10)
        stream.seek(0)
        assert stream.read(10) == FULL[:10]


def test_damage_in_the_gap_raises_at_the_read_and_keeps_the_target() -> None:
    members = [make_multi_member_lzip([part]) for part in PARTS]
    second = bytearray(members[1])
    second[len(second) // 2] ^= 0xFF
    data = members[0] + bytes(second) + members[2] + members[3]
    target = len(PARTS[0]) + len(PARTS[1]) // 2 + 100
    with LzipDecompressorStream(io.BytesIO(data)) as stream:
        assert stream.seek(target) == target
        with pytest.raises(CorruptionError):
            stream.read(10)
        assert stream.tell() == target
        with pytest.raises(CorruptionError):
            stream.read(10)
        stream.seek(0)
        assert stream.read(10) == FULL[:10]
