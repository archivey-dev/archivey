"""Detection of a TAR with no ``ustar`` magic by its first header's checksum.

A v7 tar (``tar --format=v7``, old bsdtar, star) has no magic. Before the header check
it was found only by a ``.tar`` name, so the same bytes from a pipe or a ``BytesIO``
raised ``FormatDetectionError``, and inside gzip they opened as a bare ``GZ``.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DetectionConfidence,
    FormatInfo,
    MemberType,
    detect_format,
    open_archive,
)
from archivey.detection_cost import BALANCED_BUDGET, TierSkip, TierSkipReason
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import ArchiveyError, FormatDetectionError
from archivey.internal.backends.tar_parser import starts_with_header
from archivey.internal.backends.tar_reader import TarReadBackend
from archivey.internal.registry import get_registry
from tests.streams_util import NonSeekableBytesIO

_FILES = {"hello.txt": b"hello, world\n", "dir/inner.txt": b"inner\n" * 100}


def _reseal(block: bytearray, start: int, *, signed: bool = False) -> None:
    """Rewrite the checksum of the header block at ``start`` from its bytes."""
    header = block[start : start + 512]
    header[148:156] = b" " * 8
    total = sum(b - 256 if signed and b > 127 else b for b in header)
    block[start + 148 : start + 156] = b"%06o\x00 " % total


def _v7_tar(files: dict[str, bytes] = _FILES) -> bytes:
    """A tar with each header's ustar fields cleared, as a v7 writer leaves them."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
    raw = bytearray(buf.getvalue())
    offset = 0
    for data in files.values():
        # magic, version, uname, gname, devmajor, devminor, prefix: none are v7 fields.
        raw[offset + 257 : offset + 500] = bytes(243)
        _reseal(raw, offset)
        offset += 512 + -(-len(data) // 512) * 512
    return bytes(raw)


_PROBABLE_TAR = FormatInfo(
    ArchiveFormat.TAR, DetectionConfidence.PROBABLE, "content_probe"
)


def test_builder_makes_a_v7_tar() -> None:
    data = _v7_tar()
    assert data[257:262] != b"ustar"
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        assert {m.name: tar.extractfile(m).read() for m in tar} == _FILES  # type: ignore[union-attr]


@pytest.mark.parametrize("source", ["bytesio", "pipe", "nameless_path", "tar_path"])
def test_v7_tar_is_detected_by_its_header(source: str, tmp_path: Path) -> None:
    data = _v7_tar()
    if source == "bytesio":
        info = detect_format(io.BytesIO(data))
    elif source == "pipe":
        info = detect_format(NonSeekableBytesIO(data))
    else:
        path = tmp_path / ("archive.tar" if source == "tar_path" else "archive")
        path.write_bytes(data)
        info = detect_format(path)
    assert info == _PROBABLE_TAR
    # The checksum is its own corroboration (DR-7), with or without a ``.tar`` name.
    assert info.corroborated is True


def test_truncated_v7_tar_is_not_format_unconfirmed() -> None:
    """A failure after a header-check hit is damage, not a doubtful format."""
    data = _v7_tar()[:600]
    with (
        pytest.raises(ArchiveyError) as caught,
        open_archive(io.BytesIO(data)) as archive,
    ):
        for _member, stream in archive.stream_members():
            if stream is not None:
                stream.read()
    assert caught.value.format_unconfirmed is False


def test_v7_tar_under_a_disagreeing_name_conflicts_but_is_not_unconfirmed(
    tmp_path: Path,
) -> None:
    """A ``.zip`` name disagrees with the header: a conflict, but no stamp (DR-7)."""
    path = tmp_path / "archive.zip"
    path.write_bytes(_v7_tar()[:600])
    info = detect_format(path)
    assert (info.format, info.confidence, info.detected_by) == (
        ArchiveFormat.TAR,
        DetectionConfidence.PROBABLE,
        "content_probe",
    )
    assert info.corroborated is True
    assert info.diagnostics.counts[DiagnosticCode.FORMAT_EXTENSION_CONFLICT] == 1
    with pytest.raises(ArchiveyError) as caught, open_archive(path) as archive:
        for _member, stream in archive.stream_members():
            if stream is not None:
                stream.read()
    assert caught.value.format_unconfirmed is False


@pytest.mark.parametrize(
    ("prefix", "reason"),
    [
        (300, TierSkipReason.BUDGET_EXHAUSTED),
        (0, TierSkipReason.NOT_ENABLED_BY_POLICY),
    ],
)
def test_short_prefix_budget_records_the_header_check(
    prefix: int, reason: TierSkipReason, tmp_path: Path
) -> None:
    """A window too short for a header block says so; the name is then all that is left."""
    path = tmp_path / "archive.tar"
    path.write_bytes(_v7_tar())
    budget = replace(BALANCED_BUDGET, max_prefix_bytes=prefix)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    assert (info.format, info.detected_by) == (ArchiveFormat.TAR, "extension")
    assert TierSkip("header_check", reason) in info.unavailable_tiers


@pytest.mark.parametrize("pipe", [False, True], ids=["bytesio", "pipe"])
def test_v7_tar_opens_without_a_name(pipe: bool) -> None:
    data = _v7_tar()
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, streaming=pipe) as archive:
        assert archive.format == ArchiveFormat.TAR
        read = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert read == _FILES


def test_gzipped_v7_tar_is_tar_gz() -> None:
    data = gzip.compress(_v7_tar())
    info = detect_format(io.BytesIO(data))
    assert info.format == ArchiveFormat.TAR_GZ
    assert info.confidence is DetectionConfidence.PROBABLE
    with open_archive(io.BytesIO(data)) as archive:
        assert [m.name for m in archive.members()] == list(_FILES)
        assert archive.read("hello.txt") == _FILES["hello.txt"]


def test_signed_checksum_counts() -> None:
    """Old Sun tars summed signed bytes; GNU tar and ``tarfile`` accept either sum."""
    raw = bytearray(_v7_tar({"café.txt": b"x"}))
    assert any(b > 127 for b in raw[:100])
    _reseal(raw, 0, signed=True)
    assert starts_with_header(bytes(raw))
    assert detect_format(io.BytesIO(bytes(raw))) == _PROBABLE_TAR


def _first_block_changed(edit: dict[int, bytes], *, reseal: bool) -> bytes:
    raw = bytearray(_v7_tar())
    for offset, value in edit.items():
        raw[offset : offset + len(value)] = value
    if reseal:
        _reseal(raw, 0)
    return bytes(raw)


# Ids name the case: the default id of a bytes value is its escaped bytes, which makes
# ``PYTEST_CURRENT_TEST`` too long for a Windows environment variable.
_NEAR_MISSES = [
    (_first_block_changed({0: b"j"}, reseal=False), "one byte off the checksum"),
    (_first_block_changed({0: bytes(100)}, reseal=True), "no name"),
    (
        _first_block_changed({124: b"12345678x\x00\x00\x00"}, reseal=True),
        "bad size",
    ),
    (_first_block_changed({148: b"      \x00 "}, reseal=False), "no checksum"),
    (_v7_tar()[:511], "shorter than a block"),
    (bytes(1024), "zero blocks"),
    (b"Lorem ipsum dolor sit amet. " * 200, "text"),
]


@pytest.mark.parametrize(
    ("data", "why"), [pytest.param(d, w, id=w) for d, w in _NEAR_MISSES]
)
def test_near_misses_are_not_tar(data: bytes, why: str) -> None:
    assert not starts_with_header(data), why
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))


def test_ustar_magic_still_wins() -> None:
    """A ustar tar is still exact magic: CERTAIN, not the header check's PROBABLE."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        tar.addfile(tarfile.TarInfo("empty"), io.BytesIO())
    info = detect_format(io.BytesIO(buf.getvalue()))
    assert info == FormatInfo(ArchiveFormat.TAR, DetectionConfidence.CERTAIN, "magic")


def test_v7_directory_member_lists() -> None:
    raw = bytearray(_v7_tar({"d/": b""}))
    raw[156:157] = b"5"
    _reseal(raw, 0)
    with open_archive(io.BytesIO(bytes(raw))) as archive:
        (member,) = archive.members()
    assert (member.name, member.type) == ("d/", MemberType.DIRECTORY)


def test_plugin_backends_contribute_header_checks() -> None:
    """``header_checks`` aggregates plugin backends too, as the other signal tables do."""

    def check(prefix: bytes) -> bool:
        return False

    class _PluginTar(TarReadBackend):
        HEADER_CHECKS = ((ArchiveFormat.TAR, check),)

    registry = get_registry()
    restore = registry.save_plugin_state()
    try:
        registry.register_plugin_backend(_PluginTar)
        assert (ArchiveFormat.TAR, check) in registry.header_checks()
    finally:
        restore()
    assert (ArchiveFormat.TAR, check) not in registry.header_checks()
