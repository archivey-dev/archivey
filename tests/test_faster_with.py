"""``FormatAvailability.faster_with``: absent packages that only make a read faster."""

from __future__ import annotations

import pytest

from archivey import ArchiveFormat, ArchiveyConfig, format_availability
from archivey.core import list_known_formats
from archivey.format_policy import FormatPolicy
from archivey.internal.excluded_libraries import EXCLUDED_REASON
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.deps import LazyOptional
from archivey.types import FormatSupport, OptionalLibrary


def _absent(monkeypatch: pytest.MonkeyPatch, *names: OptionalLibrary) -> None:
    """Make each package in ``names`` read as not installed."""
    for name in names:
        absent = LazyOptional(name, present=False)
        if name is OptionalLibrary.RAPIDGZIP:
            monkeypatch.setattr(deps, "rapidgzip", absent)
        if name is OptionalLibrary.COMPRESS_UTILS:
            monkeypatch.setattr(deps, "compress_utils", absent)
        if name in deps.snappy_libraries:
            monkeypatch.setitem(deps.snappy_libraries, name, absent)


def _names(fmt: ArchiveFormat, config: ArchiveyConfig | None = None) -> list[str]:
    return [str(m.name) for m in format_availability(fmt, config=config).faster_with]


def test_absent_rapidgzip_slows_the_deflate_family_and_bzip2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _absent(monkeypatch, OptionalLibrary.RAPIDGZIP)
    for fmt in (
        ArchiveFormat.GZ,
        ArchiveFormat.ZLIB,
        ArchiveFormat.BZ2,
        ArchiveFormat.TAR_GZ,
        ArchiveFormat.ZIP,
        ArchiveFormat.SEVEN_Z,
    ):
        assert _names(fmt) == ["rapidgzip"], fmt
        # A speed-up never lowers the support level.
        assert format_availability(fmt).support is not FormatSupport.NONE
    assert _names(ArchiveFormat.XZ) == []
    assert _names(ArchiveFormat.TAR) == []


def test_payload_and_member_containers_report_rapidgzip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """XAR and PKG members and PKG, RPM, DEB and makeself payloads reach the gzip and bzip2
    codecs, so they gain from rapidgzip too; makeself's lzop payload from
    compress-utils."""
    _absent(monkeypatch, OptionalLibrary.RAPIDGZIP, OptionalLibrary.COMPRESS_UTILS)
    for fmt in (
        ArchiveFormat.XAR,
        ArchiveFormat.PKG,
        ArchiveFormat.RPM,
        ArchiveFormat.DEB,
    ):
        assert _names(fmt) == ["rapidgzip"], fmt
    assert _names(ArchiveFormat.MAKESELF) == ["rapidgzip", "compress_utils"]


@pytest.mark.parametrize(
    "config",
    [
        ArchiveyConfig(use_rapidgzip="off", use_indexed_bzip2="off"),
        ArchiveyConfig(process_isolation="none"),
    ],
    ids=["accelerators-off", "isolation-none"],
)
def test_config_that_never_uses_rapidgzip_does_not_list_it(
    monkeypatch: pytest.MonkeyPatch, config: ArchiveyConfig
) -> None:
    _absent(monkeypatch, OptionalLibrary.RAPIDGZIP)
    for fmt in (ArchiveFormat.GZ, ArchiveFormat.BZ2, ArchiveFormat.ZIP):
        assert _names(fmt, config) == [], fmt
    assert _names(ArchiveFormat.GZ) == ["rapidgzip"]


def test_one_accelerator_off_leaves_the_other(monkeypatch: pytest.MonkeyPatch) -> None:
    _absent(monkeypatch, OptionalLibrary.RAPIDGZIP)
    config = ArchiveyConfig(use_rapidgzip="off")
    assert _names(ArchiveFormat.GZ, config) == []
    assert _names(ArchiveFormat.BZ2, config) == ["rapidgzip"]


def test_lzo_and_snappy_report_their_python_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _absent(
        monkeypatch,
        OptionalLibrary.COMPRESS_UTILS,
        OptionalLibrary.CRAMJAM,
        OptionalLibrary.GOOGLE_CRC32C,
        OptionalLibrary.CRC32C,
    )
    assert _names(ArchiveFormat.LZOP) == ["compress_utils"]
    assert _names(ArchiveFormat.SQUASHFS) == ["compress_utils"]
    assert _names(ArchiveFormat.SNAPPY) == ["compress_utils", "google_crc32c"]


def test_either_snappy_package_is_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    """cramjam stands in for compress-utils, crc32c for google-crc32c."""
    _absent(monkeypatch, OptionalLibrary.COMPRESS_UTILS, OptionalLibrary.GOOGLE_CRC32C)
    monkeypatch.setitem(
        deps.snappy_libraries,
        OptionalLibrary.CRAMJAM,
        LazyOptional(OptionalLibrary.CRAMJAM, present=True),
    )
    monkeypatch.setitem(
        deps.snappy_libraries,
        OptionalLibrary.CRC32C,
        LazyOptional(OptionalLibrary.CRC32C, present=True),
    )
    assert _names(ArchiveFormat.SNAPPY) == []


def test_installed_speedups_leave_it_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    present = LazyOptional(OptionalLibrary.RAPIDGZIP, present=True)
    monkeypatch.setattr(deps, "rapidgzip", present)
    assert _names(ArchiveFormat.GZ) == []


def test_excluded_speedup_carries_the_policy_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deps, "rapidgzip", LazyOptional(OptionalLibrary.RAPIDGZIP, present=True)
    )
    config = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"rapidgzip"}))
    (component,) = format_availability(ArchiveFormat.GZ, config=config).faster_with
    assert component.name == OptionalLibrary.RAPIDGZIP
    assert component.reason == EXCLUDED_REASON


def test_unreadable_formats_have_no_speedups(monkeypatch: pytest.MonkeyPatch) -> None:
    _absent(monkeypatch, *OptionalLibrary)
    for fmt in list_known_formats():
        availability = format_availability(fmt)
        if availability.support is FormatSupport.NONE:
            assert availability.faster_with == (), fmt


def test_snappy_reports_the_package_the_policy_leaves_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With compress-utils excluded and cramjam absent, installing cramjam is what
    helps, so cramjam is reported, with its install hint and no reason."""
    _absent(
        monkeypatch,
        OptionalLibrary.CRAMJAM,
        OptionalLibrary.CRC32C,
    )
    for name in (OptionalLibrary.COMPRESS_UTILS, OptionalLibrary.GOOGLE_CRC32C):
        monkeypatch.setitem(
            deps.snappy_libraries, name, LazyOptional(name, present=True)
        )
    config = ArchiveyConfig(
        formats=FormatPolicy(exclude_libraries={"compress_utils", "google_crc32c"})
    )
    found = format_availability(ArchiveFormat.SNAPPY, config=config).faster_with
    assert [(str(m.name), m.reason) for m in found] == [("cramjam", ""), ("crc32c", "")]
    assert found[0].install_hint == "pip install cramjam"


def test_snappy_reports_the_policy_when_it_turns_every_package_off() -> None:
    config = ArchiveyConfig(
        formats=FormatPolicy(
            exclude_libraries={"compress_utils", "cramjam", "google_crc32c", "crc32c"}
        )
    )
    found = format_availability(ArchiveFormat.SNAPPY, config=config).faster_with
    assert [str(m.name) for m in found] == ["compress_utils", "google_crc32c"]
    assert all(m.reason == EXCLUDED_REASON for m in found)
