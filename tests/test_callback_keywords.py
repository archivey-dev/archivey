"""The ``on_diagnostic=`` and ``on_source_read=`` keywords of the opening calls."""

from __future__ import annotations

import gzip
import io
import lzma
import os
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    ArchiveyUsageError,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.diagnostics import Diagnostic, DiagnosticCode
from archivey.internal.read_progress import LOCAL_REPORT_STEP
from archivey.types import ArchiveFormat, SourceProgress

_EMPTY = DiagnosticCode.EMPTY_ARCHIVE


def _empty_zip(tmp_path: Path, name: str = "empty.zip") -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w"):
        pass
    return path


def _zip_in_zip(tmp_path: Path, payload: int = 0) -> Path:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        if payload:
            zf.writestr("x.bin", os.urandom(payload))
    path = tmp_path / "outer.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("inner.zip", inner.getvalue())
    return path


def _codes(seen: list[Diagnostic]) -> list[DiagnosticCode]:
    return [d.code for d in seen]


def test_open_archive_calls_its_on_diagnostic(tmp_path: Path) -> None:
    seen: list[Diagnostic] = []
    with open_archive(_empty_zip(tmp_path), on_diagnostic=seen.append) as reader:
        assert list(reader) == []
    assert _codes(seen) == [_EMPTY]


def test_open_archive_calls_its_on_source_read(tmp_path: Path) -> None:
    path = tmp_path / "d.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", os.urandom(2 * LOCAL_REPORT_STEP))
    seen: list[SourceProgress] = []
    with open_archive(path, on_source_read=seen.append) as reader:
        reader.read("big.bin")
    assert seen
    assert all(p.nest_level == 0 for p in seen)


def test_open_stream_calls_both_keywords(tmp_path: Path) -> None:
    path = tmp_path / "d.gz"
    # Bytes after the gzip member are reported as a diagnostic.
    path.write_bytes(gzip.compress(os.urandom(2 * LOCAL_REPORT_STEP)) + b"junk")
    diagnostics: list[Diagnostic] = []
    reads: list[SourceProgress] = []
    with open_stream(
        path, on_diagnostic=diagnostics.append, on_source_read=reads.append
    ) as stream:
        stream.read()
    assert diagnostics
    assert reads


def test_open_stream_source_read_step_still_comes_from_the_config(
    tmp_path: Path,
) -> None:
    path = tmp_path / "d.xz"
    path.write_bytes(lzma.compress(os.urandom(4 * LOCAL_REPORT_STEP), preset=0))

    def reports(config: ArchiveyConfig) -> int:
        seen: list[SourceProgress] = []
        with open_stream(path, config=config, on_source_read=seen.append) as stream:
            while stream.read(1 << 16):
                pass
        return len(seen)

    # Step 0 reports every read; the default reports about once per MiB.
    assert reports(ArchiveyConfig(source_read_step=0)) > 2 * reports(ArchiveyConfig())


def test_detect_format_calls_its_on_diagnostic(tmp_path: Path) -> None:
    path = _empty_zip(tmp_path, "x.tar.gz")
    seen: list[Diagnostic] = []
    info = detect_format(path, on_diagnostic=seen.append)
    assert info.format == ArchiveFormat.ZIP
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in _codes(seen)


def test_the_config_fields_warn_and_still_decide(tmp_path: Path) -> None:
    seen: list[Diagnostic] = []
    reads: list[SourceProgress] = []
    with pytest.warns(DeprecationWarning, match=r"on_diagnostic=") as caught:
        config = ArchiveyConfig(on_diagnostic=seen.append, on_source_read=reads.append)
    assert caught[0].filename == __file__
    assert "on_source_read=" in str(caught[0].message)
    with open_archive(_empty_zip(tmp_path), config=config) as reader:
        assert list(reader) == []
    assert _codes(seen) == [_EMPTY]
    assert reads


def test_archiveys_copies_of_a_config_do_not_warn_again(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    with pytest.warns(DeprecationWarning):
        config = ArchiveyConfig(on_diagnostic=lambda _d: None)
    recwarn.clear()
    with open_archive(_empty_zip(tmp_path), config=config, on_source_read=print):
        pass
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


def test_the_keyword_wins_over_the_config_field(tmp_path: Path) -> None:
    from_config: list[Diagnostic] = []
    from_keyword: list[Diagnostic] = []
    with pytest.warns(DeprecationWarning):
        config = ArchiveyConfig(on_diagnostic=from_config.append)
    with open_archive(
        _empty_zip(tmp_path), config=config, on_diagnostic=from_keyword.append
    ) as reader:
        assert list(reader) == []
    assert _codes(from_keyword) == [_EMPTY]
    assert from_config == []


@pytest.mark.parametrize("own_config", [False, True])
def test_a_parent_child_without_callbacks_inherits_the_parents(
    tmp_path: Path, own_config: bool
) -> None:
    path = _zip_in_zip(tmp_path, payload=2 * LOCAL_REPORT_STEP)
    diagnostics: list[Diagnostic] = []
    reads: list[SourceProgress] = []
    child_config = {"config": ArchiveyConfig()} if own_config else {}
    with (
        open_archive(
            path, on_diagnostic=diagnostics.append, on_source_read=reads.append
        ) as outer,
        outer.open("inner.zip") as member,
        open_archive(member, parent=outer, pipe=True, **child_config) as nested,
        nested.stream_members() as members,
    ):
        for _, stream in members:
            if stream is not None:
                stream.read()
    assert any(p.nest_level == 1 for p in reads)


@pytest.mark.parametrize("own_config", [False, True])
def test_a_parent_child_without_on_diagnostic_reports_to_the_parents(
    tmp_path: Path, own_config: bool
) -> None:
    path = _zip_in_zip(tmp_path)
    seen: list[Diagnostic] = []
    child_config = {"config": ArchiveyConfig()} if own_config else {}
    with (
        open_archive(path, seekable_members=True, on_diagnostic=seen.append) as outer,
        outer.open("inner.zip") as member,
        open_archive(member, parent=outer, **child_config) as nested,
    ):
        assert list(nested) == []
    assert _codes(seen) == [_EMPTY]


def test_a_parent_child_with_its_own_callbacks_uses_them(tmp_path: Path) -> None:
    path = _zip_in_zip(tmp_path)
    outer_seen: list[Diagnostic] = []
    inner_seen: list[Diagnostic] = []
    with (
        open_archive(
            path, seekable_members=True, on_diagnostic=outer_seen.append
        ) as outer,
        outer.open("inner.zip") as member,
        open_archive(member, parent=outer, on_diagnostic=inner_seen.append) as nested,
    ):
        assert list(nested) == []
    assert _codes(inner_seen) == [_EMPTY]
    assert outer_seen == []


@pytest.mark.parametrize(
    ("call", "keyword"),
    [
        ("open_archive", "on_diagnostic"),
        ("open_archive", "on_source_read"),
        ("open_stream", "on_diagnostic"),
        ("open_stream", "on_source_read"),
        ("detect_format", "on_diagnostic"),
    ],
)
def test_a_callback_that_cannot_be_called_is_refused(
    tmp_path: Path, call: str, keyword: str
) -> None:
    path = tmp_path / "d.gz"
    path.write_bytes(gzip.compress(b"x"))
    function = {
        "open_archive": open_archive,
        "open_stream": open_stream,
        "detect_format": detect_format,
    }[call]
    with pytest.raises(ArchiveyUsageError, match=rf"{call}\({keyword}=…\)"):
        function(path, **{keyword: "not a function"})
