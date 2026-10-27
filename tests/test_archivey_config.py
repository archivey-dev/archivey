"""Tests for the public ArchiveyConfig / ExtractionLimits surface (Phase 5 stage 1)."""

from __future__ import annotations

import dataclasses
import io
import logging
from typing import Optional

import pytest

import archivey
from archivey import (
    DEFAULT_ARCHIVEY_CONFIG,
    AcceleratorMode,
    ArchiveyConfig,
    ExtractionLimits,
    ListingLimits,
    open_archive,
)
from archivey.exceptions import ResourceLimitError
from archivey.internal.arg_checks import check_limit_fields
from archivey.internal.config import stream_config_from_archivey
from archivey.types import ArchiveFormat
from tests.extract_util import open_and_extract


def test_config_types_are_frozen() -> None:
    cfg = ArchiveyConfig()
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.rar_allow_glob_member_concatenation = True  # type: ignore[misc]
    limits = ExtractionLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_ratio = 1.0  # type: ignore[misc]
    listing = ListingLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        listing.max_members = 1  # type: ignore[misc]


def test_default_config_is_module_constant() -> None:
    assert DEFAULT_ARCHIVEY_CONFIG is archivey.DEFAULT_ARCHIVEY_CONFIG
    assert DEFAULT_ARCHIVEY_CONFIG.use_rapidgzip is AcceleratorMode.AUTO
    assert DEFAULT_ARCHIVEY_CONFIG.extraction_limits == ExtractionLimits()
    assert DEFAULT_ARCHIVEY_CONFIG.listing_limits == ListingLimits()
    assert ListingLimits().max_members == ExtractionLimits().max_entries == 262_144


def test_open_archive_without_config_uses_defaults(tmp_path) -> None:
    (tmp_path / "f.txt").write_bytes(b"x")
    with open_archive(tmp_path) as ar:
        assert ar._config == DEFAULT_ARCHIVEY_CONFIG  # type: ignore[attr-defined]


def test_stream_config_derived_from_archivey_config() -> None:
    cfg = ArchiveyConfig(
        use_rapidgzip=AcceleratorMode.ON,
        use_indexed_bzip2=AcceleratorMode.OFF,
    )
    stream_cfg = stream_config_from_archivey(cfg, streaming=True)
    assert stream_cfg.streaming is True
    assert stream_cfg.use_rapidgzip is AcceleratorMode.ON
    assert stream_cfg.use_indexed_bzip2 is AcceleratorMode.OFF


def test_accelerator_modes_honored_via_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tarfile

    import archivey.internal.backends.tar_reader as tar_reader_module

    # open_codec_stream is stubbed so we can assert the config it received, but the
    # stub must still yield a real uncompressed tar: tar_reader wraps it in
    # BufferedReader, and on Python 3.14 (esp. macOS) a bare MagicMock's readinto()
    # recurses through __index__ until pytest-timeout kills the test.
    uncompressed = io.BytesIO()
    with tarfile.open(fileobj=uncompressed, mode="w") as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    tar_bytes = uncompressed.getvalue()

    captured: list[object] = []

    def _capture_open(
        codec, source, *, config, stamp=None, collector=None, repeat_verdict=True
    ):
        captured.append(config)
        return io.BytesIO(tar_bytes)

    monkeypatch.setattr(tar_reader_module, "open_codec_stream", _capture_open)
    cfg = ArchiveyConfig(
        use_rapidgzip=AcceleratorMode.ON,
        use_indexed_bzip2=AcceleratorMode.OFF,
    )
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    buf.seek(0)
    with open_archive(buf, format=ArchiveFormat.TAR_GZ, config=cfg) as ar:
        ar.members()
    assert captured
    assert captured[0].use_rapidgzip is AcceleratorMode.ON
    assert captured[0].use_indexed_bzip2 is AcceleratorMode.OFF


def test_strict_archive_eof_is_gone() -> None:
    # Removed before 0.2.0: a missing TAR trailer is an ordinary diagnostic, made fatal
    # by setting ARCHIVE_EOF_MARKER_MISSING to RAISE (tests/test_tar.py).
    assert "strict_archive_eof" not in {
        f.name for f in dataclasses.fields(ArchiveyConfig)
    }
    with pytest.raises(TypeError):
        ArchiveyConfig(strict_archive_eof=True)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("kwargs", "reported"),
    [
        # Each pair is in the opposite order as fields; the checked-first one wins.
        (
            {"use_rapidgzip": "sometimes", "extraction_limits": "none"},
            "extraction_limits=",
        ),
        ({"read_link_targets": "yes", "detection_budget": "nope"}, "detection_budget="),
        (
            {"rar_decompressor": "x", "max_retained_diagnostic_references": -1},
            "max_retained_diagnostic_references",
        ),
    ],
)
def test_config_with_several_bad_fields_reports_in_check_order(
    kwargs: dict[str, object], reported: str
) -> None:
    with pytest.raises(archivey.ArchiveyUsageError) as exc_info:
        ArchiveyConfig(**kwargs)  # type: ignore[arg-type]
    assert reported in str(exc_info.value)


def test_limits_with_several_bad_fields_report_the_first_field() -> None:
    with pytest.raises(archivey.ArchiveyUsageError, match="max_extracted_bytes"):
        ExtractionLimits(max_extracted_bytes="x", max_entries=-1)  # type: ignore[arg-type]


def test_limit_field_with_an_unknown_annotation_is_refused() -> None:
    # Guessing allow_none / allow_float from an unfamiliar spelling could switch a
    # guard on or off without anyone noticing, so the helper refuses to guess.
    @dataclasses.dataclass(frozen=True)
    class _Limits:
        max_things: Optional[int] = None  # noqa: UP045

    with pytest.raises(AssertionError, match=r"_Limits\.max_things"):
        check_limit_fields(_Limits(), cls="_Limits")


def test_limits_subclass_error_names_the_documented_class() -> None:
    @dataclasses.dataclass(frozen=True)
    class MyListingLimits(ListingLimits):
        pass

    with pytest.raises(
        archivey.ArchiveyUsageError, match=r"^ListingLimits\.max_members"
    ):
        MyListingLimits(max_members=-1)


def test_missing_eof_marker_warns_by_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from tests.test_tar import _tar_missing_eof_block

    data = _tar_missing_eof_block()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.backends"),
        open_archive(io.BytesIO(data), format=ArchiveFormat.TAR) as ar,
    ):
        ar.members()
    assert any("truncated" in r.getMessage().lower() for r in caplog.records)


def test_extract_limits_from_config(tmp_path) -> None:
    import zipfile

    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("a.txt", b"x" * 5000)
    dest = tmp_path / "out"
    with pytest.raises(ResourceLimitError):
        open_and_extract(
            src,
            dest,
            config=ArchiveyConfig(
                extraction_limits=ExtractionLimits(max_extracted_bytes=1000)
            ),
        )


def test_per_call_limits_override_config(tmp_path) -> None:
    import zipfile

    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("a.txt", b"x" * 5000)
    dest = tmp_path / "out"
    tight = ArchiveyConfig(extraction_limits=ExtractionLimits(max_extracted_bytes=100))
    with open_archive(src, config=tight) as reader:
        reader.extract_all(dest, limits=ExtractionLimits(max_extracted_bytes=10_000))
    assert (dest / "a.txt").exists()


def test_unlimited_preset_disables_guards(tmp_path) -> None:
    import zipfile

    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("a.txt", b"x" * 5000)
    dest = tmp_path / "out"
    open_and_extract(src, dest, limits=ExtractionLimits.UNLIMITED)
    assert (dest / "a.txt").read_bytes() == b"x" * 5000


def test_public_api_exports_config_types() -> None:
    for name in (
        "ArchiveyConfig",
        "ExtractionLimits",
        "ListingLimits",
        "SpoolLimits",
        "AcceleratorMode",
        "DEFAULT_ARCHIVEY_CONFIG",
        "ResourceLimitError",
    ):
        assert name in archivey.__all__
        assert hasattr(archivey, name)


def test_config_is_hashable() -> None:
    """A frozen config advertises hashability; a nested ``MappingProxyType`` broke it."""
    assert hash(archivey.DEFAULT_ARCHIVEY_CONFIG) == hash(ArchiveyConfig())
    strict = ArchiveyConfig(diagnostic_policy=archivey.DiagnosticPolicy.STRICT)
    assert strict != ArchiveyConfig()
    assert len({strict, ArchiveyConfig(), archivey.DEFAULT_ARCHIVEY_CONFIG}) == 2
