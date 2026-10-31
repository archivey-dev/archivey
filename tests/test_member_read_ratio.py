"""A member read through ``open()``, ``read()`` or ``stream_members()`` is held to
``max_ratio`` as extraction holds what it writes (``MemberRatioGuard``)."""

from __future__ import annotations

import bz2
import dataclasses
import functools
import io
import os
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveMember,
    ArchiveyConfig,
    DecoderLimits,
    ExtractionLimits,
    ResourceLimitError,
    open_archive,
)
from archivey.internal.bomb_tracker import (
    AlwaysStopResourceLimitError,
    MemberRatioGuard,
    ReadRatioTally,
)
from archivey.types import MemberType
from tests.streams_util import NonSeekableBytesIO, SizedNonSeekable
from tests.test_audit_tar_streams import _TRAILER, _gnu_sparse

_MIB = 2**20


def _zip(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_BZIP2) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return path


@functools.cache
def _noise() -> bytes:
    # Incompressible, so the archive is large enough that one refused member's
    # output does not break the archive-wide ratio on its own.
    return os.urandom(64 * 1024)


def _drain(stream: io.RawIOBase | io.BufferedIOBase) -> int:
    n = 0
    while chunk := stream.read(_MIB):
        n += len(chunk)
    return n


def test_open_refuses_a_member_past_the_ratio(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bomb.zip", [("zeros", bytes(24 * _MIB))])
    with (
        open_archive(path) as reader,
        reader.open("zeros") as stream,
        pytest.raises(ResourceLimitError, match="max_ratio=800:1") as err,
    ):
        _drain(stream)
    assert not isinstance(err.value, AlwaysStopResourceLimitError)
    assert err.value.member_name == "zeros"


def test_read_refuses_a_bare_compressed_file_past_the_ratio(tmp_path: Path) -> None:
    path = tmp_path / "zeros.bz2"
    path.write_bytes(bz2.compress(bytes(24 * _MIB), 9))
    with (
        open_archive(path) as reader,
        pytest.raises(ResourceLimitError, match="max_ratio=800:1"),
    ):
        reader.read(reader.members()[0])


def test_a_forward_seek_past_the_ratio_is_refused(tmp_path: Path) -> None:
    # The seek or the read after it (a verifier hashes the skipped bytes on the next
    # read) raises; the bytes past the limit are never returned.
    path = _zip(tmp_path / "bomb.zip", [("zeros", bytes(24 * _MIB))])
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("zeros") as stream,
        pytest.raises(ResourceLimitError, match="max_ratio=800:1"),
    ):
        stream.seek(20 * _MIB)
        stream.read(1)


def test_a_pass_goes_on_after_a_member_past_the_ratio(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "mixed.zip",
        [("a", b"first"), ("zeros", bytes(24 * _MIB)), ("c", _noise())],
    )
    read: dict[str, int] = {}
    refused: list[str] = []
    with open_archive(path) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            try:
                read[member.name] = _drain(stream)
            except ResourceLimitError as exc:
                assert not isinstance(exc, AlwaysStopResourceLimitError)
                refused.append(member.name)
    assert refused == ["zeros"]
    assert read == {"a": 5, "c": len(_noise())}


def test_small_members_together_past_the_ratio_stop_the_reader(tmp_path: Path) -> None:
    # Each member stays under the 5 MiB activation floor; their total does not.
    path = _zip(tmp_path / "many.zip", [(f"z{i}", bytes(4 * _MIB)) for i in range(3)])
    with (
        open_archive(path) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Archive-wide"),
    ):
        for _member, stream in reader.stream_members():
            assert stream is not None
            _drain(stream)


# A ZIP, TAR or 7z read straight from a pipe has no size to divide by and no codec
# input counter: the bytes its source takes from the pipe are the live denominator.
# The live floor is lowered so the test decodes megabytes, not the default 256 MiB.
_LOW_LIVE_FLOOR = ArchiveyConfig(
    decoder_limits=DecoderLimits(live_ratio_activation_threshold=8 * _MIB)
)


def _small_bzip2_members(tmp_path: Path) -> bytes:
    # Each member stays under the 5 MiB per-member floor; together they are 24 MiB.
    path = _zip(tmp_path / "many.zip", [(f"z{i}", bytes(4 * _MIB)) for i in range(6)])
    return path.read_bytes()


@pytest.mark.parametrize("sized", [False, True], ids=["bare", "size-claim"])
def test_a_piped_zip_pass_is_held_to_the_live_ratio(
    tmp_path: Path, sized: bool
) -> None:
    # A pipe's size attribute is the caller's claim and does not count as the
    # archive's size, so the live denominator holds there too.
    data = _small_bzip2_members(tmp_path)
    pipe = SizedNonSeekable(data, len(data)) if sized else NonSeekableBytesIO(data)
    with (
        open_archive(pipe, streaming=True, config=_LOW_LIVE_FLOOR) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Live decompression ratio"),
    ):
        for _member, stream in reader.stream_members():
            assert stream is not None
            _drain(stream)


def test_a_piped_zip_extraction_is_held_to_the_live_ratio(tmp_path: Path) -> None:
    data = _small_bzip2_members(tmp_path)
    with (
        open_archive(
            NonSeekableBytesIO(data), streaming=True, config=_LOW_LIVE_FLOOR
        ) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Live decompression ratio"),
    ):
        reader.extract_all(tmp_path / "out")


def test_a_piped_sparse_tar_is_held_to_the_live_ratio() -> None:
    # 30 MiB of holes in a member that stores no data: the archive is 2.5 KiB.
    member = _gnu_sparse("holes", [(30 * _MIB, 0)], 30 * _MIB, b"")
    data = member + _TRAILER
    with (
        open_archive(
            NonSeekableBytesIO(data), streaming=True, config=_LOW_LIVE_FLOOR
        ) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Live decompression ratio"),
    ):
        for _member, stream in reader.stream_members():
            if stream is not None:
                _drain(stream)


def test_a_piped_zip_counts_the_bytes_taken_from_the_pipe(tmp_path: Path) -> None:
    data = _small_bzip2_members(tmp_path)
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            _drain(stream)
        consumed = reader.compressed_bytes_consumed
    assert consumed is not None
    assert 0 < consumed <= len(data)


def test_a_piped_zip_of_stored_data_passes_the_live_ratio(tmp_path: Path) -> None:
    path = tmp_path / "stored.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for i in range(3):
            zf.writestr(f"s{i}", bytes(4 * _MIB))
    with open_archive(
        NonSeekableBytesIO(path.read_bytes()), streaming=True, config=_LOW_LIVE_FLOOR
    ) as reader:
        total = 0
        for _member, stream in reader.stream_members():
            assert stream is not None
            total += _drain(stream)
    assert total == 12 * _MIB


def test_measurement_reports_the_piped_count(tmp_path: Path) -> None:
    from archivey.internal.measurement import enable_measurement

    data = _small_bzip2_members(tmp_path)
    with (
        enable_measurement(),
        open_archive(NonSeekableBytesIO(data), streaming=True) as reader,
    ):
        for _member, stream in reader.stream_members():
            assert stream is not None
            _drain(stream)
        stats = reader.io_stats()
        assert stats is not None
        assert stats.compressed_bytes_consumed == reader.compressed_bytes_consumed
        assert stats.compressed_bytes_consumed is not None


def test_a_directory_counts_nothing(tmp_path: Path) -> None:
    # A directory source cannot seek, but it has no stream to count.
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f").write_bytes(b"x")
    with open_archive(tmp_path / "d") as reader:
        assert reader.compressed_bytes_consumed is None


def test_a_seekable_zip_keeps_the_static_ratio(tmp_path: Path) -> None:
    data = _small_bzip2_members(tmp_path)
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.compressed_bytes_consumed is None


def test_a_member_read_again_counts_once(tmp_path: Path) -> None:
    path = _zip(tmp_path / "one.zip", [("z", bytes(4 * _MIB))])
    with open_archive(path) as reader:
        for _ in range(3):
            assert len(reader.read("z")) == 4 * _MIB


def test_no_ratio_in_the_config_reads_and_extracts_unchanged(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bomb.zip", [("zeros", bytes(24 * _MIB))])
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_ratio=None))
    with open_archive(path, config=config) as reader:
        assert len(reader.read("zeros")) == 24 * _MIB
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert _drain(stream) == 24 * _MIB
        reader.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "zeros").stat().st_size == 24 * _MIB


def test_the_decoder_ratio_holds_extraction(tmp_path: Path) -> None:
    path = _zip(tmp_path / "small.zip", [("text", b"abc" * (4 * _MIB))])
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(max_ratio=10.0, ratio_activation_threshold=1024)
    )
    with (
        open_archive(path, config=config) as reader,
        pytest.raises(ResourceLimitError, match="max_ratio=10:1"),
    ):
        reader.extract_all(tmp_path / "out")


def test_the_default_ratio_is_below_deflates_ceiling() -> None:
    # Deflate tops out near 1032:1, and zeros land between about 1003 and 1032:1:
    # under a limit of 800, gzip of zeros is refused every time, not by chance.
    assert DecoderLimits().max_ratio == 800.0
    assert ExtractionLimits().max_ratio == 800.0


def test_a_deprecated_extraction_ratio_warns_and_still_applies(tmp_path: Path) -> None:
    path = _zip(tmp_path / "bomb.zip", [("zeros", bytes(24 * _MIB))])
    with pytest.warns(DeprecationWarning, match="DecoderLimits"):
        off = ExtractionLimits(max_ratio=1e9)
    # In the reader's config it holds every decode, as decoder_limits would.
    with pytest.warns(DeprecationWarning):
        config = ArchiveyConfig(extraction_limits=ExtractionLimits(max_ratio=1e9))
    with open_archive(path, config=config) as reader:
        assert len(reader.read("zeros")) == 24 * _MIB
    # Per call, it governs that extraction only.
    with open_archive(path) as reader:
        reader.extract_all(tmp_path / "out", limits=off)
        with pytest.raises(ResourceLimitError):
            reader.read("zeros")
    assert (tmp_path / "out" / "zeros").stat().st_size == 24 * _MIB


def test_extraction_limits_left_unset_do_not_warn(
    recwarn: pytest.WarningsRecorder,
) -> None:
    ExtractionLimits()
    ExtractionLimits(max_extracted_bytes=1)
    _ = ExtractionLimits.UNLIMITED
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


def test_a_copy_of_unlimited_does_not_warn_and_keeps_the_ratio_off(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    capped = dataclasses.replace(ExtractionLimits.UNLIMITED, max_entries=5)
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]
    path = _zip(tmp_path / "bomb.zip", [("zeros", bytes(24 * _MIB))])
    with open_archive(path) as reader:
        reader.extract_all(tmp_path / "out", limits=capped)
    assert (tmp_path / "out" / "zeros").stat().st_size == 24 * _MIB


class _Decoder(io.RawIOBase):
    """Stands in for a member's decoder: records the furthest offset any call reached.
    Not a ``BytesIO``, so its size is never cheap."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)
        self.furthest = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b: memoryview) -> int:  # type: ignore[override]
        n = self._data.readinto(b)
        self.furthest = max(self.furthest, self._data.tell())
        return n

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        pos = self._data.seek(offset, whence)
        self.furthest = max(self.furthest, pos)
        return pos

    def tell(self) -> int:
        return self._data.tell()


def _guard(
    decoder: _Decoder,
    *,
    size: int | None,
    compressed_size: int,
    limits: DecoderLimits | None = None,
    tally: ReadRatioTally | None = None,
    consumed: int | None = None,
) -> MemberRatioGuard:
    member = ArchiveMember(
        type=MemberType.FILE,
        name="m",
        size=size,
        compressed_size=compressed_size,
        _member_id=1,
    )
    return MemberRatioGuard(
        decoder,
        limits=limits or DecoderLimits(),
        member=member,
        tally=tally or ReadRatioTally(),
        static_size=None,
        consumed=None if consumed is None else lambda: consumed,
    )


def test_a_seek_to_the_end_of_an_unsized_member_stops_within_a_step() -> None:
    # A bz2 or gzip member records no size: the end is read to a step at a time.
    decoder = _Decoder(bytes(64 * _MIB))
    guard = _guard(decoder, size=None, compressed_size=100)
    with pytest.raises(ResourceLimitError, match="max_ratio=800:1"):
        guard.seek(0, io.SEEK_END)
    floor = DecoderLimits().ratio_activation_threshold
    assert decoder.furthest <= floor + 16 * _MIB


def test_a_seek_to_the_end_under_the_ratio_lands_there() -> None:
    data = b"abc" * _MIB
    guard = _guard(_Decoder(data), size=None, compressed_size=len(data))
    assert guard.seek(-3, io.SEEK_END) == len(data) - 3
    assert guard.read() == b"abc"


def test_a_relative_seek_in_steps_lands_where_it_was_asked() -> None:
    # The archive-wide room is one step, so the seek goes to the decoder in steps;
    # the offset left after them is applied once.
    data = bytearray(40 * _MIB)
    data[6 * _MIB : 6 * _MIB + 4] = b"MARK"
    limits = DecoderLimits(max_ratio=10.0, live_ratio_activation_threshold=_MIB)
    guard = _guard(
        _Decoder(bytes(data)),
        size=len(data),
        compressed_size=len(data),
        limits=limits,
        consumed=100 * _MIB,
    )
    assert guard.seek(6 * _MIB, io.SEEK_CUR) == 6 * _MIB
    assert guard.read(4) == b"MARK"
    assert guard.seek(-4, io.SEEK_CUR) == 6 * _MIB
    assert guard.read(4) == b"MARK"


def test_call_limits_without_a_ratio_keep_the_configs_deprecated_one(
    tmp_path: Path,
) -> None:
    path = _zip(tmp_path / "bomb.zip", [("zeros", bytes(24 * _MIB))])
    with pytest.warns(DeprecationWarning):
        config = ArchiveyConfig(extraction_limits=ExtractionLimits(max_ratio=1e9))
    with open_archive(path, config=config) as reader:
        reader.extract_all(
            tmp_path / "out", limits=ExtractionLimits(max_extracted_bytes=10**12)
        )
    assert (tmp_path / "out" / "zeros").stat().st_size == 24 * _MIB
