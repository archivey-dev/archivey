"""A compressed TAR opened for random access records restart points by default, so a
member read after the listing resumes near the member and does not decode the archive
again from its first byte. A streaming open records none: its walk never seeks back."""

from __future__ import annotations

import gzip
import io
import random
import struct
import tarfile
import zlib
from collections.abc import Callable
from typing import Any

import pytest

import archivey
from archivey.internal.config import StreamConfig
from archivey.internal.streams import codecs
from archivey.internal.streams.codecs.deflate_decoder import SNAPSHOT_SPACING
from tests.conftest import zstd_backend
from tests.streams_util import (
    CountingBytesIO,
    encode_xz_mbi,
    make_multi_member_lzip,
    make_multiblock_xz,
    xz_cli_available,
)

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


def _tar_xz() -> bytes:
    # One xz block per MiB, in one stream: the blocks a decode passes are the points.
    if not xz_cli_available():
        pytest.skip("the xz CLI builds the multi-block fixture")
    return make_multiblock_xz(_tar(), block_size=1 << 20)


def _tar_zst() -> bytes:
    # One zstd frame per MiB: the frame starts a decode passes are the restart points.
    try:
        zstd = zstd_backend()
    except RuntimeError:
        pytest.skip("no zstd module")
    raw = _tar()
    step = 1 << 20
    return b"".join(zstd.compress(raw[i : i + step]) for i in range(0, len(raw), step))


@pytest.mark.parametrize(
    "build",
    [_tar_gz, _tar_lz, _tar_xz, _tar_zst],
    ids=["gzip", "lzip", "xz", "zstd"],
)
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
    # The reader's stream (``_open_outer_codec_stream``) is the one that reports
    # trailing data; detection's probe of the inner format opens one too, under its
    # own config.
    seen: list[bool] = []
    real = codecs.open_codec_stream

    def spy(*args: Any, config: StreamConfig, **kwargs: Any) -> Any:
        if config.report_trailing_data:
            seen.append(config.records_restart_points)
        return real(*args, config=config, **kwargs)

    monkeypatch.setattr(codecs, "open_codec_stream", spy)
    with archivey.open_archive(io.BytesIO(_tar_gz()), streaming=streaming) as reader:
        for member, stream in reader.stream_members():
            del member, stream
    assert seen == [not streaming]


def _with_merged_index(compressed: bytes) -> bytes:
    """``compressed`` with xz index records 0 and 1 merged into one record that keeps
    block 0's uncompressed size: an index consistent with itself but not with the data
    (the construction of ``test_xz_cold_seek_trusts_a_self_consistent_block_index``)."""
    from archivey.internal.streams.codecs import xz_decoder as xz_module

    footer = compressed[-12:]
    _check, index_size = xz_module._parse_xz_footer(footer)
    index_start = len(compressed) - 12 - index_size
    records = list(xz_module._iter_xz_index(compressed[index_start : -12 - 4]))
    (u0, d0), (u1, _d1) = records[0], records[1]
    merged = [(xz_module._round_up_4(u0) + u1, d0), *records[2:]]
    body = b"\x00" + encode_xz_mbi(len(merged))
    body += b"".join(encode_xz_mbi(u) + encode_xz_mbi(d) for u, d in merged)
    body += b"\x00" * (xz_module._round_up_4(len(body)) - len(body))
    index = body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
    footer_body = struct.pack("<I", len(index) // 4 - 1) + footer[8:10]
    new_footer = (
        struct.pack("<I", zlib.crc32(footer_body) & 0xFFFFFFFF)
        + footer_body
        + footer[10:]
    )
    return compressed[:index_start] + index + new_footer


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_a_default_open_never_trusts_the_files_own_index() -> None:
    # Restart points keep only the points a decode finds. The file's index is read on
    # declared seek demand alone (threat-model O17), so a crafted one cannot change
    # what a default read of a member returns.
    out = io.BytesIO()
    contents = {f"m{i}": bytes([ord("A") + i]) * 65536 for i in range(6)}
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, data in contents.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    bad = _with_merged_index(make_multiblock_xz(out.getvalue(), block_size=65536))
    with archivey.open_archive(io.BytesIO(bad)) as reader:
        report = reader.members_report()
        # Last first: each read seeks back, where the index's points would be used.
        for member in reversed(report.members):
            if member.is_file:
                try:
                    data = reader.read(member)
                except archivey.ArchiveyError:
                    continue
                assert data == contents[member.name]
