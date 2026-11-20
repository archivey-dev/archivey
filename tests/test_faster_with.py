"""``FormatAvailability.faster_with``: absent packages that only make a read faster."""

from __future__ import annotations

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    FormatSupport,
    format_availability,
    list_known_formats,
)
from archivey.format_policy import FormatPolicy
from archivey.internal.excluded_libraries import EXCLUDED_REASON
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.deps import LazyOptional
from archivey.types import OptionalLibrary


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
