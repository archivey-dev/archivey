"""A compressed TAR opened for random access records restart points by default, so a
member read after the listing resumes near the member and does not decode the archive
again from its first byte. A streaming open records none: its walk never seeks back."""

from __future__ import annotations

import gzip
import io
import random
import tarfile
from collections.abc import Callable
from typing import Any

import pytest

import archivey
from archivey.internal.config import StreamConfig
from archivey.internal.streams import codecs
from archivey.internal.streams.codecs.deflate_decoder import SNAPSHOT_SPACING
from tests.streams_util import CountingBytesIO, make_multi_member_lzip

MEMBER_SIZE = 512 * 1024
MEMBERS = 8


def _tar() -> bytes:
    rng = random.Random(1234)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for i in range(MEMBERS):
            data = rng.randbytes(MEMBER_SIZE)
            info = tarfile.TarInfo(f"m{i}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _tar_gz() -> bytes:
    return gzip.compress(_tar())


def _tar_lz() -> bytes:
    # One lzip member per MiB: its trailers are the restart points.
    raw = _tar()
    step = 1 << 20
    return make_multi_member_lzip([raw[i : i + step] for i in range(0, len(raw), step)])


@pytest.mark.parametrize("build", [_tar_gz, _tar_lz], ids=["gzip", "lzip"])
def test_member_read_after_listing_resumes_near_the_member(
    build: Callable[[], bytes],
) -> None:
    data = build()
    source = CountingBytesIO(data)
    target = MEMBERS - 2
    with archivey.open_archive(source) as reader:
        members = [m for m in reader.members() if m.is_file]
        after_listing = source.bytes_read
        with reader.open(members[target]) as stream:
            assert len(stream.read()) == MEMBER_SIZE
        re_read = source.bytes_read - after_listing
    # Without restart points the read decodes again from the start: about
    # (target + 1) / MEMBERS of the archive. With them it starts at most about one
    # MiB (a gzip snapshot's spacing, an lzip member here) before the member.
    assert re_read <= MEMBER_SIZE + 2 * SNAPSHOT_SPACING
    assert re_read < len(data) // 2


@pytest.mark.parametrize("streaming", [False, True])
def test_restart_points_only_in_random_access(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    # Detection's probe of the inner format opens a codec stream first, under its own
    # config; the reader's stream (``_open_outer_codec_stream``) is the last one.
    seen: list[bool] = []
    real = codecs.open_codec_stream

    def spy(*args: Any, config: StreamConfig, **kwargs: Any) -> Any:
        seen.append(config.records_restart_points)
        return real(*args, config=config, **kwargs)

    monkeypatch.setattr(codecs, "open_codec_stream", spy)
    with archivey.open_archive(io.BytesIO(_tar_gz()), streaming=streaming) as reader:
        for member, stream in reader.stream_members():
            del member, stream
    assert len(seen) == 2
    assert seen[-1] is not streaming
