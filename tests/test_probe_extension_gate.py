"""Content probes run only for a source whose name claims a probe-only format.

LZMA Alone, zlib and Brotli have no magic that detection can trust, so a content probe
is the only evidence for them. On a nameless source that evidence stands alone, and real
binary files pass it (``dev-docs/investigations/2026-10-backup-scan.md``). By default
``open_archive`` and ``detect_format`` run a probe only when the source's extension names
that format; ``ArchiveyConfig.always_probe_content`` turns every probe back on, and
``open_stream`` always runs them all.
"""

from __future__ import annotations

import io
import lzma
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

import archivey
from archivey import ArchiveFormat, detect_format
from archivey.config import ArchiveyConfig
from archivey.detection import DetectionConfidence
from archivey.detection_cost import TierSkip, TierSkipReason
from archivey.exceptions import FormatDetectionError
from archivey.types import ContainerFormat, StreamFormat
from tests.conftest import requires

PROBE_ALL = ArchiveyConfig(always_probe_content=True)

_SKIPPED_BY_POLICY = TierSkip("content_probe", TierSkipReason.NOT_ENABLED_BY_POLICY)


_PAYLOAD = b"payload behind a probe-only codec " * 20


def _zlib() -> bytes:
    return zlib.compress(_PAYLOAD)


def _lzma_alone() -> bytes:
    return lzma.compress(_PAYLOAD, format=lzma.FORMAT_ALONE)


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("hello.txt")
        payload = b"hello from inside the tar\n"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


@pytest.mark.parametrize(
    ("make", "fmt"),
    [
        pytest.param(_zlib, ArchiveFormat.ZLIB, id="zlib"),
        pytest.param(_lzma_alone, ArchiveFormat.LZMA_ALONE, id="lzma-alone"),
    ],
)
def test_a_nameless_probe_only_stream_is_refused_by_default(make, fmt) -> None:
    with pytest.raises(FormatDetectionError, match="always_probe_content=True") as exc:
        detect_format(io.BytesIO(make()))
    # Renaming the file is the one remedy the command line has.
    assert "give the file one (.lzma, .zz, .br)" in str(exc.value)
    with pytest.raises(FormatDetectionError, match="always_probe_content=True"):
        archivey.open_archive(io.BytesIO(make()))

    info = detect_format(io.BytesIO(make()), config=PROBE_ALL)
    assert info.format == fmt
    assert info.detected_by == "content_probe"


@requires("brotli")
def test_a_nameless_brotli_stream_is_refused_by_default() -> None:
    import brotli

    data = brotli.compress(b"some brotli payload to decode")
    with pytest.raises(FormatDetectionError, match="always_probe_content=True"):
        detect_format(io.BytesIO(data))
    info = detect_format(io.BytesIO(data), config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI


@pytest.mark.parametrize(
    "make",
    [pytest.param(_zlib, id="zlib"), pytest.param(_lzma_alone, id="lzma-alone")],
)
def test_open_stream_probes_a_nameless_stream_without_the_switch(make) -> None:
    # The caller of open_stream says the source is a compressed stream, so a probe
    # only picks the codec; it never decides whether the bytes are an archive.
    with archivey.open_stream(io.BytesIO(make())) as stream:
        assert stream.read() == _PAYLOAD


@pytest.mark.parametrize(
    ("name", "make", "fmt"),
    [
        pytest.param("data.zz", _zlib, ArchiveFormat.ZLIB, id="zz"),
        pytest.param("data.lzma", _lzma_alone, ArchiveFormat.LZMA_ALONE, id="lzma"),
    ],
)
def test_a_matching_extension_runs_its_probe(tmp_path: Path, name, make, fmt) -> None:
    # The probe confirms the name, so the answer is PROBABLE and corroborated, not the
    # GUESS the extension alone would give. The other probes did not run, and the
    # receipt says so.
    path = tmp_path / name
    path.write_bytes(make())
    info = detect_format(path)
    assert info.format == fmt
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"
    assert info.corroborated
    assert info.unavailable_tiers == (_SKIPPED_BY_POLICY,)

    info = detect_format(path, config=PROBE_ALL)
    assert info.format == fmt
    assert info.unavailable_tiers == ()


def test_a_matching_extension_keeps_the_inner_tar_check(tmp_path: Path) -> None:
    # A .zz file that holds a tar opens as TAR+zlib: the inner-TAR check runs on a
    # probe hit, and a bare extension guess would report the raw stream.
    path = tmp_path / "backup.zz"
    path.write_bytes(zlib.compress(_tar_bytes()))
    info = detect_format(path)
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.ZLIB)
    with archivey.open_archive(path) as reader:
        assert [m.name for m in reader.members()] == ["hello.txt"]


def test_an_extension_runs_only_its_own_probe(tmp_path: Path) -> None:
    # LZMA Alone bytes named .zz: the zlib probe declines, the LZMA Alone probe does not
    # run, and the answer is the extension guess.
    path = tmp_path / "data.zz"
    path.write_bytes(_lzma_alone())
    info = detect_format(path)
    assert info.format == ArchiveFormat.ZLIB
    assert info.confidence == DetectionConfidence.GUESS
    assert info.detected_by == "extension"

    info = detect_format(path, config=PROBE_ALL)
    assert info.format == ArchiveFormat.LZMA_ALONE


def test_an_unrelated_extension_records_the_probes_as_off(tmp_path: Path) -> None:
    # A .gz name over zlib bytes: no probe matches the name, so the step is recorded as
    # not enabled, which does not make the search incomplete.
    path = tmp_path / "data.gz"
    path.write_bytes(_zlib())
    info = detect_format(path)
    assert info.format == ArchiveFormat.GZ
    assert info.detected_by == "extension"
    assert _SKIPPED_BY_POLICY in info.unavailable_tiers

    info = detect_format(path, config=PROBE_ALL)
    assert info.format == ArchiveFormat.ZLIB
    assert _SKIPPED_BY_POLICY not in info.unavailable_tiers


def test_a_member_stream_carries_its_name_into_detection() -> None:
    # A nested .zz member is found by the extension its archive gives it: the member
    # stream's ``name`` is the member's name, as zipfile's ZipExtFile has it.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dir/inner.zz", _zlib())
    buf.seek(0)
    with archivey.open_archive(buf) as outer, outer.open("dir/inner.zz") as member:
        assert member.name == "dir/inner.zz"
        with archivey.open_archive(member, pipe=True) as inner:
            assert inner.format_info.format == ArchiveFormat.ZLIB
            seen = {m.name: s.read() for m, s in inner.stream_members() if s}
            assert seen == {"inner": _PAYLOAD}


def test_an_open_stream_has_no_name() -> None:
    # Its output is decompressed bytes with no name of their own, like io.BytesIO.
    with archivey.open_stream(io.BytesIO(_zlib())) as stream:
        assert not hasattr(stream, "name")


@pytest.mark.parametrize("name", ["data.zlib", "data.tar.zlib"])
def test_the_zlib_alias_runs_the_zlib_probe(tmp_path: Path, name: str) -> None:
    is_tar = name.endswith(".tar.zlib")
    path = tmp_path / name
    path.write_bytes(zlib.compress(_tar_bytes() if is_tar else _PAYLOAD))
    info = detect_format(path)
    container = ContainerFormat.TAR if is_tar else ContainerFormat.RAW_STREAM
    assert info.format == ArchiveFormat(container, StreamFormat.ZLIB)
    assert info.detected_by == "content_probe"
    assert info.corroborated


@requires("brotli")
def test_the_brotli_alias_runs_the_brotli_probe(tmp_path: Path) -> None:
    import brotli

    path = tmp_path / "page.html.brotli"
    path.write_bytes(brotli.compress(_PAYLOAD))
    info = detect_format(path)
    assert info.format == ArchiveFormat.BROTLI
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.corroborated
    with archivey.open_archive(path) as reader:
        assert [m.name for m in reader.members()] == ["page.html"]
