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
    ArchiveyConfig,
    DecoderLimits,
    ExtractionLimits,
    ResourceLimitError,
    open_archive,
)
from archivey.internal.bomb_tracker import AlwaysStopResourceLimitError

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
