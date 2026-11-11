"""``ListingLimits.max_decoded_bytes``: the bytes one listing pass may decode."""

from __future__ import annotations

import dataclasses
import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

import archivey
from archivey import ArchiveyConfig, Budget, ListingLimits, ResourceLimitError

_MEMBER = 100_000


def _tar(count: int = 3) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(count):
            info = tarfile.TarInfo(f"t{i}.bin")
            info.size = _MEMBER
            tf.addfile(info, io.BytesIO(b"t" * _MEMBER))
    return buf.getvalue()


def _config(cap: int | None, **kwargs: object) -> ArchiveyConfig:
    return ArchiveyConfig(
        listing_limits=ListingLimits(max_decoded_bytes=cap),
        **kwargs,  # type: ignore[arg-type]
    )


def test_the_default_is_four_gib() -> None:
    assert ListingLimits().max_decoded_bytes == 4 * 2**30
    assert ListingLimits.UNLIMITED.max_decoded_bytes is None


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_listing_a_tar_gz_past_the_cap_is_refused(streaming: bool) -> None:
    data = gzip.compress(_tar(), mtime=0)
    with (
        archivey.open_archive(
            io.BytesIO(data), config=_config(_MEMBER), streaming=streaming
        ) as reader,
        pytest.raises(ResourceLimitError, match="max_decoded_bytes=100000"),
    ):
        for _member, _stream in reader.stream_members():
            pass


def test_a_listing_under_the_cap_lists_and_reads() -> None:
    tar = _tar()
    data = gzip.compress(tar, mtime=0)
    with archivey.open_archive(io.BytesIO(data), config=_config(len(tar))) as reader:
        assert len(reader.members()) == 3
        # Member reads after the listing do not count toward it.
        for name in ("t0.bin", "t1.bin", "t2.bin", "t0.bin"):
            assert len(reader.read(name)) == _MEMBER
        assert reader._listing_decode.drawn <= len(tar)  # type: ignore[attr-defined]


def test_a_streaming_pass_counts_only_what_the_walk_decodes() -> None:
    """Members the caller reads are the caller's; the walk counts the headers and the
    members it skips."""
    tar = _tar()
    data = gzip.compress(tar, mtime=0)
    # Reading every member leaves the walk only the headers to decode.
    with archivey.open_archive(
        io.BytesIO(data), config=_config(_MEMBER // 2), streaming=True
    ) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert len(stream.read()) == _MEMBER
    # Skipping them makes the walk decode them, past the cap.
    with (
        archivey.open_archive(
            io.BytesIO(data), config=_config(_MEMBER // 2), streaming=True
        ) as reader,
        pytest.raises(ResourceLimitError, match="max_decoded_bytes"),
    ):
        for _member, _stream in reader.stream_members():
            pass


def test_each_pass_counts_from_zero() -> None:
    tar = _tar()
    data = gzip.compress(tar, mtime=0)
    config = _config(len(tar))
    for _ in range(3):
        with archivey.open_archive(io.BytesIO(data), config=config) as reader:
            assert len(reader.members()) == 3


def test_none_disables_it() -> None:
    data = gzip.compress(_tar(), mtime=0)
    with archivey.open_archive(io.BytesIO(data), config=_config(None)) as reader:
        assert len(reader.members()) == 3


def test_it_draws_with_a_budget_and_both_hold() -> None:
    tar = _tar()
    data = gzip.compress(tar, mtime=0)
    budget = Budget()
    with archivey.open_archive(
        io.BytesIO(data), config=_config(len(tar), budget=budget)
    ) as reader:
        reader.members()
    assert budget.decoded_bytes >= 3 * _MEMBER
    small = Budget(max_decoded_bytes=_MEMBER)
    with (
        archivey.open_archive(
            io.BytesIO(data), config=_config(len(tar), budget=small)
        ) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
    ):
        reader.members()


def test_an_encoded_7z_header_counts_at_open() -> None:
    path = Path(__file__).parent / "fixtures" / "sevenzip" / "solid_three_members.7z"
    with (
        pytest.raises(ResourceLimitError, match="max_decoded_bytes=10"),
        archivey.open_archive(path, config=_config(10)),
    ):
        pass
    with archivey.open_archive(path, config=_config(4096)) as reader:
        assert reader.members()


def test_a_random_access_zip_lists_without_decoding() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a", b"a" * _MEMBER)
    with archivey.open_archive(io.BytesIO(buf.getvalue()), config=_config(1)) as reader:
        assert reader.read("a") == b"a" * _MEMBER


def test_replace_keeps_the_field() -> None:
    limits = dataclasses.replace(ListingLimits(), max_decoded_bytes=5)
    assert limits.max_decoded_bytes == 5


def test_the_crossing_step_decodes_one_byte_past_the_cap() -> None:
    data = gzip.compress(_tar(), mtime=0)
    with (
        archivey.open_archive(
            io.BytesIO(data), config=_config(_MEMBER), streaming=True
        ) as reader,
        pytest.raises(ResourceLimitError, match="has decoded 100001 bytes"),
    ):
        for _member, _stream in reader.stream_members():
            pass


def test_a_walk_started_over_counts_from_zero() -> None:
    """A random-access reader keeps a listing once a walk completes, so only a walk
    discarded after a failure starts over; the count does too. The first walk keeps
    what opening the archive decoded."""
    from archivey.internal.listing_limits import ListingDecodeCount

    count = ListingDecodeCount(1000)
    previous = count.enter()
    try:
        count.draw(10)  # at open, before the first walk
        count.start_pass()
        assert count.drawn == 10
        count.draw(500)
        count.start_pass()
        assert count.drawn == 0
        count.draw(1000)
        with pytest.raises(ResourceLimitError, match="max_decoded_bytes=1000"):
            count.draw(1)
    finally:
        count.leave(previous)
    # Not entered on this thread: nothing counts.
    count.start_pass()
    count.draw(5000)
    assert count.drawn == 0


class _Unseekable(io.RawIOBase):
    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # type: ignore[override]
        self.data += b
        return len(b)


def test_a_streaming_zip_counts_the_start_of_each_member_it_passes() -> None:
    """A bit-3 member nobody reads is decoded only as far as a link target could be
    (``MAX_LINK_TARGET_BYTES`` and the byte past it); the scan finds its end."""
    from tests.streams_util import NonSeekableBytesIO

    sink = _Unseekable()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(3):
            with zf.open(f"m{i}", "w") as out:
                out.write(bytes([i]) * _MEMBER)
    data = bytes(sink.data)

    def stream(cap: int | None) -> archivey.ArchiveReader:
        return archivey.open_archive(
            NonSeekableBytesIO(data), config=_config(cap), streaming=True
        )

    with stream(None) as reader:
        assert len(list(reader.stream_members())) == 3
    with stream(1 << 20) as reader:
        for _member, _stream in reader.stream_members():
            pass
        assert reader._listing_decode.drawn == 3 * 4097  # type: ignore[attr-defined]
    with (
        stream(5000) as reader,
        pytest.raises(ResourceLimitError, match="has decoded 5001 bytes"),
    ):
        for _member, _stream in reader.stream_members():
            pass
    # Read by the caller, the members count nothing.
    with stream(1) as reader:
        for _member, member_stream in reader.stream_members():
            assert member_stream is not None
            assert len(member_stream.read()) == _MEMBER


def test_a_decompress_layer_counts() -> None:
    """An RPM's payload is a format adapter ``decompress()`` layer."""
    from tests.test_rpm import _F, _build, _Package

    files = [_F(f"/opt/f{i}".encode(), data=bytes([i]) * _MEMBER) for i in range(3)]
    data = _build(_Package(files))
    with archivey.open_archive(io.BytesIO(data), config=_config(None)) as reader:
        assert len(reader.members()) == 3
    with (
        archivey.open_archive(io.BytesIO(data), config=_config(_MEMBER)) as reader,
        pytest.raises(ResourceLimitError, match="max_decoded_bytes=100000"),
    ):
        reader.members()
