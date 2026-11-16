"""Adding unknown-size checks must preserve checks on finite archive sources."""

from __future__ import annotations

import io
import random
import zipfile
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, FormatDetectionError, detect_format, open_archive
from tests.conftest import requires
from tests.streams_util import brotli_declared_metablock_header

pytestmark = requires("brotli")


def _invalid_successor(length: int) -> bytes:
    # A real encoder cannot produce this: the literal block fits, but its successor
    # has invalid last-block padding. Random literal data is valid as stored bytes.
    return (
        brotli_declared_metablock_header(length, first=True)
        + random.Random(length).randbytes(length)
        + b"\xff" * 30_000
    )


@pytest.mark.parametrize("preset", ["fast", "balanced", "thorough"])
@pytest.mark.parametrize("as_path", [False, True])
def test_a_cheap_header_seek_past_one_mib_still_checks_framing(
    tmp_path: Path, preset: str, as_path: bool
) -> None:
    data = _invalid_successor(1_100_000)
    config = ArchiveyConfig(always_probe_content=True, detection_budget=preset)
    if as_path:
        path = tmp_path / "invalid.bin"
        path.write_bytes(data)
        with pytest.raises(FormatDetectionError):
            detect_format(path, config=config)
    else:
        with io.BytesIO(data) as source, pytest.raises(FormatDetectionError):
            detect_format(source, config=config)


@requires("fsspec")
@pytest.mark.parametrize("preset", ["fast", "balanced", "thorough"])
def test_a_finite_remote_source_keeps_its_bounded_framing_check(preset: str) -> None:
    import fsspec

    data = _invalid_successor(100_000)
    config = ArchiveyConfig(always_probe_content=True, detection_budget=preset)
    with io.BytesIO(data) as source, pytest.raises(FormatDetectionError):
        detect_format(source, config=config)
    remote = fsspec.open("memory://brotli-review/invalid.bin", "wb")
    with remote as stream:
        stream.write(data)
    try:
        with pytest.raises(FormatDetectionError):
            detect_format(
                fsspec.open("memory://brotli-review/invalid.bin"), config=config
            )
    finally:
        remote.fs.rm(remote.path)


@pytest.mark.parametrize("preset", ["fast", "balanced", "thorough"])
def test_a_seekable_decoded_member_keeps_its_bounded_framing_check(preset: str) -> None:
    data = _invalid_successor(100_000)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as writer:
        writer.writestr("invalid.bin", data)
    archive.seek(0)
    config = ArchiveyConfig(always_probe_content=True, detection_budget=preset)
    with (
        open_archive(archive, seekable_members=True) as reader,
        reader.open("invalid.bin") as member,
    ):
        assert member.seekable()
        with pytest.raises(FormatDetectionError):
            detect_format(member, config=config)
