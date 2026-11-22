"""``open_archive(salvage=True)``: the switch.

Salvage needs a seekable file, so ``streaming=True`` is refused before the source is
read. A format without a salvage search (ZIP and TAR here) reads exactly as the
default and records ``SALVAGE_UNAVAILABLE`` once at open; RAR has one, and an intact
RAR records nothing. ``salvage=False`` records none of the salvage codes.
"""

from __future__ import annotations

import dataclasses
import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ARCHIVE_INTEGRITY_CODES,
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    SalvageLimits,
    open_archive,
)
from archivey.diagnostics import (
    RegionSkippedContext,
    SalvageScanContext,
    SalvageUnavailableContext,
    validate_code_context,
)
from archivey.exceptions import ArchiveyUsageError
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.salvage import SalvageState, emit_salvage_unavailable

_RAR_FIXTURE = Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__.rar"

SALVAGE_CODES = {
    DiagnosticCode.MEMBER_FOUND_BY_SCAN,
    DiagnosticCode.ARCHIVE_REGION_SKIPPED,
    DiagnosticCode.SALVAGE_UNAVAILABLE,
}


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", b"alpha")
        z.writestr("dir/b.txt", b"beta" * 100)
    return path


def _tar(path: Path) -> Path:
    with tarfile.open(path, "w") as t:
        for name, data in (("a.txt", b"alpha"), ("b.txt", b"beta" * 100)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return path


def _rar(path: Path) -> Path:
    shutil.copyfile(_RAR_FIXTURE, path)
    return path


def _listing(path: Path, **kwargs: object) -> list[tuple[object, ...]]:
    with open_archive(path, **kwargs) as reader:  # type: ignore[call-overload]
        return [
            (m.name, m.type, m.size, m.member_id, reader.read(m) if m.is_file else None)
            for m in reader.members()
        ]


class _Unread(io.RawIOBase):
    """A stream that fails the test if anything reads or seeks it."""

    def readable(self) -> bool:
        return True

    def readinto(self, b: object) -> int:  # pragma: no cover - the test fails here
        raise AssertionError("the source was read")

    def seekable(self) -> bool:
        raise AssertionError("the source was asked to seek")


def test_salvage_with_streaming_is_refused_before_the_source_is_read() -> None:
    with pytest.raises(ArchiveyUsageError, match="seekable file") as caught:
        open_archive(_Unread(), streaming=True, salvage=True)  # type: ignore[arg-type]
    assert isinstance(caught.value, ValueError)
    assert "Save the stream to a file first" in str(caught.value)


def test_salvage_takes_a_real_bool(tmp_path: Path) -> None:
    with pytest.raises(ArchiveyUsageError, match="salvage"):
        open_archive(_zip(tmp_path / "a.zip"), salvage="yes")  # type: ignore[call-overload]


@pytest.mark.parametrize("make", [_zip, _tar, _rar], ids=["zip", "tar", "rar"])
def test_an_intact_archive_reads_the_same_with_salvage(make, tmp_path: Path) -> None:
    path = make(tmp_path / ("a." + make.__name__.strip("_")))
    assert _listing(path, salvage=True) == _listing(path)


@pytest.mark.parametrize(
    ("make", "fmt"), [(_zip, "ZIP"), (_tar, "TAR")], ids=["zip", "tar"]
)
def test_a_format_without_salvage_records_unavailable_once(
    make, fmt: str, tmp_path: Path
) -> None:
    path = make(tmp_path / ("a." + make.__name__.strip("_")))
    with open_archive(path, salvage=True) as reader:
        reader.members()
        list(reader.stream_members())
        counts = reader.diagnostics.counts
        assert counts.get(DiagnosticCode.SALVAGE_UNAVAILABLE) == 1
        assert not counts.get(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
        assert not counts.get(DiagnosticCode.ARCHIVE_REGION_SKIPPED)
        [record] = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SALVAGE_UNAVAILABLE
        ]
        assert record.context == SalvageUnavailableContext(
            archive_name=str(path), format=fmt, reason="no_salvage_search"
        )
        assert "no salvage search for this format" in record.message
        assert isinstance(reader, BaseArchiveReader)
        assert reader._salvage_mode.requested
        assert not reader._salvage_mode.enabled


@pytest.mark.parametrize("make", [_zip, _tar, _rar], ids=["zip", "tar", "rar"])
def test_without_salvage_no_salvage_code_is_recorded(make, tmp_path: Path) -> None:
    path = make(tmp_path / ("a." + make.__name__.strip("_")))
    with open_archive(path) as reader:
        reader.members()
        assert not SALVAGE_CODES & set(reader.diagnostics.counts)
        assert isinstance(reader, BaseArchiveReader)
        assert not reader._salvage_mode.requested
        assert not reader._salvage_mode.enabled


def test_a_format_with_salvage_records_nothing_on_an_intact_archive(
    tmp_path: Path,
) -> None:
    """RAR has a salvage search: an intact archive gets no salvage code at all."""
    path = _rar(tmp_path / "a.rar")
    with open_archive(path, salvage=True) as reader:
        reader.members()
        list(reader.stream_members())
        assert not SALVAGE_CODES & set(reader.diagnostics.counts)
        assert isinstance(reader, BaseArchiveReader)
        assert reader._salvage_mode.enabled


def test_strict_does_not_raise_on_salvage_unavailable(tmp_path: Path) -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    path = _zip(tmp_path / "a.zip")
    with open_archive(path, salvage=True, config=config) as reader:
        assert len(reader.members()) == 2
    assert not SALVAGE_CODES & ARCHIVE_INTEGRITY_CODES


def test_a_reader_opened_with_parent_takes_its_own_flag(tmp_path: Path) -> None:
    outer_path = _tar(tmp_path / "outer.tar")
    inner_path = _zip(tmp_path / "inner.zip")
    with open_archive(outer_path, salvage=True) as outer:
        with open_archive(inner_path, parent=outer) as inner:
            assert isinstance(inner, BaseArchiveReader)
            assert not inner._salvage_mode.requested
        with open_archive(inner_path, parent=outer, salvage=True) as inner:
            assert isinstance(inner, BaseArchiveReader)
            assert inner._salvage_mode.requested


def test_the_reader_reads_its_salvage_limits_from_the_config(tmp_path: Path) -> None:
    limits = SalvageLimits(max_search_bytes=4096, max_reported_regions=3)
    config = ArchiveyConfig(salvage_limits=limits)
    with open_archive(_zip(tmp_path / "a.zip"), salvage=True, config=config) as r:
        assert isinstance(r, BaseArchiveReader)
        state = r._salvage_mode
        assert isinstance(state, SalvageState)
        assert state.limits is limits


def test_salvage_limits_defaults_and_frozen() -> None:
    limits = SalvageLimits()
    assert limits.max_search_bytes is None
    assert limits.max_reported_regions == 1000
    assert ArchiveyConfig().salvage_limits == limits
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_reported_regions = 5  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_search_bytes": -1},
        {"max_search_bytes": "1"},
        {"max_search_bytes": True},
        {"max_reported_regions": None},
        {"max_reported_regions": -1},
        {"max_reported_regions": 1.5},
    ],
)
def test_salvage_limits_refuse_bad_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ArchiveyUsageError, match="SalvageLimits"):
        SalvageLimits(**kwargs)  # type: ignore[arg-type]


def test_config_refuses_a_salvage_limits_that_is_not_one() -> None:
    with pytest.raises(ArchiveyUsageError, match="salvage_limits"):
        ArchiveyConfig(salvage_limits=None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("code", "context"),
    [
        (
            DiagnosticCode.MEMBER_FOUND_BY_SCAN,
            SalvageScanContext(
                archive_name="x.tar",
                member_name="a",
                member_id=3,
                format="TAR",
                offset=1024,
                confirmed=True,
                unchecked=("position", "name"),
            ),
        ),
        (
            DiagnosticCode.ARCHIVE_REGION_SKIPPED,
            RegionSkippedContext(
                archive_name="x.tar",
                format="TAR",
                layer="gzip",
                offset=512,
                length=None,
                reason="search_limit",
            ),
        ),
        (
            DiagnosticCode.MEMBER_FOUND_BY_SCAN,
            SalvageScanContext(
                archive_name="x.part1.rar",
                member_name="a",
                member_id=0,
                format="RAR",
                method="next_volume",
                offset=20,
                confirmed=True,
                unchecked=(),
                volume_index=2,
            ),
        ),
        (
            DiagnosticCode.ARCHIVE_REGION_SKIPPED,
            RegionSkippedContext(
                archive_name="x.part1.rar",
                format="RAR",
                layer="archive",
                offset=7,
                length=100,
                reason="no_header",
                volume_index=1,
            ),
        ),
        (
            DiagnosticCode.SALVAGE_UNAVAILABLE,
            SalvageUnavailableContext(archive_name="x.zip", format="ZIP"),
        ),
        (
            DiagnosticCode.SALVAGE_UNAVAILABLE,
            SalvageUnavailableContext(
                archive_name="x.cpio", format="CPIO", reason="forward_only_reader"
            ),
        ),
    ],
)
def test_salvage_contexts_pair_with_their_codes_and_are_json_safe(
    code: DiagnosticCode, context: object
) -> None:
    validate_code_context(code, context)  # type: ignore[arg-type]
    payload = context.to_dict()  # type: ignore[attr-defined]
    assert json.loads(json.dumps(payload)) == payload


@pytest.mark.parametrize(
    ("reason", "cause"),
    [
        ("no_salvage_search", "archivey has no salvage search for this format"),
        ("forward_only_reader", "cannot run on an archive inside another one"),
    ],
)
def test_the_unavailable_message_names_its_reason(reason: str, cause: str) -> None:
    collector = DiagnosticCollector()
    emit_salvage_unavailable(
        collector,
        archive_name="x.cpio",
        format_name="CPIO",
        reason=reason,  # type: ignore[arg-type]
    )
    [record] = collector.snapshot().retained
    assert record.code is DiagnosticCode.SALVAGE_UNAVAILABLE
    assert record.context == SalvageUnavailableContext(
        archive_name="x.cpio",
        format="CPIO",
        reason=reason,  # type: ignore[arg-type]
    )
    assert cause in record.message


def test_scan_context_defaults_hold_position_unchecked() -> None:
    context = SalvageScanContext()
    assert context.method == "header_search"
    assert context.unchecked == ("position",)
    assert context.to_dict()["unchecked"] == ["position"]


def test_a_nested_reader_archivey_opens_inherits_the_flag() -> None:
    """A ``.deb``'s control and data tars are read by readers archivey opens itself
    (``ReaderContext.open_nested``): they are asked to salvage when the package is,
    and, with no TAR salvage search yet, each records ``SALVAGE_UNAVAILABLE``."""
    from tests.test_deb import _deb

    with open_archive(io.BytesIO(_deb()), salvage=True) as reader:
        reader.members()
        formats = [
            d.context.format
            for d in reader.diagnostics.retained
            if isinstance(d.context, SalvageUnavailableContext)
        ]
    assert formats == ["DEB", "TAR", "TAR_XZ"]
    with open_archive(io.BytesIO(_deb())) as reader:
        reader.members()
        assert not SALVAGE_CODES & set(reader.diagnostics.counts)
