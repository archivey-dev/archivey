"""Members of a compressed TAR rise to ``CHECKSUM`` as soon as the block checks of
the codec cover their data (``checked_spans``), not only when a walk reaches the
stream's end.

Spec ``compressed-streams`` §"A stream reports the verification it has reached and can
reach" (the `.tar.bz2` rows).
"""

from __future__ import annotations

import bz2
import functools
import gzip
import io
import random
import tarfile

import pytest

import archivey
from archivey import Verification
from archivey.exceptions import CorruptionError
from archivey.internal.streams import checked_spans
from archivey.internal.streams.checked_spans import CheckedSpans
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO


def test_spans_merge_where_they_touch_or_overlap() -> None:
    spans = CheckedSpans()
    spans.add(10, 20)
    spans.add(30, 40)
    assert spans.covers(10, 20)
    assert not spans.covers(10, 30)
    spans.add(20, 30)
    assert spans.covers(10, 40)
    spans.add(5, 12)
    assert spans.covers(5, 40)
    assert not spans.covers(4, 6)
    spans.add(7, 7)  # empty: nothing
    assert spans.take_new() == [(10, 20), (30, 40), (20, 30), (5, 12)]
    assert spans.take_new() == []


def test_new_ranges_that_follow_each_other_are_one_range() -> None:
    spans = CheckedSpans()
    spans.add(0, 5)
    spans.add(5, 9)
    assert spans.take_new() == [(0, 9)]


def test_past_the_span_limit_the_first_span_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(checked_spans, "MAX_SPANS", 2)
    spans = CheckedSpans()
    for start in (0, 10, 20):
        spans.add(start, start + 5)
    assert not spans.covers(0, 5)
    assert spans.covers(10, 15)
    assert spans.covers(20, 25)


_COUNT = 30


def _members(count: int = _COUNT) -> list[tuple[str, bytes]]:
    rng = random.Random(1)
    return [
        (
            f"f{i}",
            bytes(rng.choice(b"abcdefgh ") for _ in range(rng.randint(1000, 60000))),
        )
        for i in range(count)
    ]


@functools.cache
def _tar() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in _members():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def _bz3(data: bytes) -> bytes:
    from bz3.backends import BZ3Compressor

    compressor = BZ3Compressor(65 << 10)
    return compressor.compress(data) + compressor.flush()


def _levels_while_streaming(blob: bytes) -> dict[str, Verification]:
    """Each file's level when the walk hands out the last member, before it reaches
    the stream's end."""
    files: list[archivey.ArchiveMember] = []
    levels: dict[str, Verification] = {}
    with archivey.open_archive(NonSeekableBytesIO(blob), streaming=True) as archive:
        for member, stream in archive.stream_members():
            if member.is_file:
                files.append(member)
            if member.name == f"f{_COUNT - 1}":
                levels = {m.name: m.verified for m in files}
            if stream is not None:
                stream.read()
    return levels


@pytest.mark.parametrize(
    "compress",
    [
        pytest.param(lambda data: bz2.compress(data, 1), id="bzip2"),
        pytest.param(_bz3, id="bzip3", marks=requires("bz3")),
    ],
)
def test_a_member_is_checksum_verified_once_its_blocks_pass(compress) -> None:
    levels = _levels_while_streaming(compress(_tar()))
    # The last member is still being walked, and its data may end in the stream's
    # last block. Every earlier one, small members listed after the check of their
    # block passed among them, is in checked blocks.
    names = [name for name, _ in _members()]
    early = {name: levels[name] for name in names[:-1]}
    assert set(early.values()) == {Verification.CHECKSUM}, early


def test_a_codec_without_block_checks_raises_only_at_the_end() -> None:
    levels = _levels_while_streaming(gzip.compress(_tar()))
    assert Verification.CHECKSUM not in set(levels.values())


def test_the_members_before_a_damaged_block_are_checksum_verified() -> None:
    blob = bytearray(bz2.compress(_tar(), 1))
    blob[len(blob) * 3 // 4] ^= 0x55
    seen: list[archivey.ArchiveMember] = []
    source = NonSeekableBytesIO(bytes(blob))
    with (
        pytest.raises(CorruptionError),
        archivey.open_archive(source, streaming=True) as archive,
    ):
        for member, stream in archive.stream_members():
            seen.append(member)
            if stream is not None:
                stream.read()
    files = [m for m in seen if m.is_file]
    # The first block holds well over the first member.
    assert files[0].verified is Verification.CHECKSUM
    assert files[-1].verified is not Verification.CHECKSUM


def test_listing_then_random_access_keeps_checksum() -> None:
    blob = bz2.compress(_tar(), 1)
    with archivey.open_archive(io.BytesIO(blob)) as archive:
        members = [m for m in archive.members() if m.is_file]
        assert {m.verified for m in members} == {Verification.CHECKSUM}
        with archive.open(members[10]) as stream:
            assert stream.read() == dict(_members())["f10"]
        assert members[10].verified is Verification.CHECKSUM
