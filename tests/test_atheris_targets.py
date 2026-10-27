"""The Atheris target callables, run on their seeds without libFuzzer.

A seed that raises outside ``ArchiveyError`` would fail every fuzz run on its
first iteration. These tests are that check, plus the paths the new targets
exist to reach: an SFX payload, a ZIP pipe, a UDIF refusal, a filter decode.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from archivey import ArchiveFormat, ArchiveyError, open_archive
from tests.atheris_fuzz import TARGET_NAMES, seeds as fuzz_seeds
from tests.atheris_fuzz.seeds import (
    _compressed_tar_seeds,
    _koly_block,
    _uncompressed_header_sevenzip_archives,
    filter_seeds,
    open_detected_seeds,
    uncompressed_header_spec_names,
)
from tests.atheris_fuzz.targets import (
    filters_one,
    open_detected_one,
    sevenzip_open_one,
    zip_open_one,
)
from tests.conftest import has_package

_PAYLOAD = b"sfx-member\n"


def _stored_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("member.txt", _PAYLOAD)
    return buf.getvalue()


def test_open_detected_reads_a_zip_behind_a_stub() -> None:
    data = b"MZ" + b"\x00" * 128 + _stored_zip()
    open_detected_one(data)
    with open_archive(io.BytesIO(data)) as arc:
        members = [member for member in arc if member.is_file]
        assert [member.name for member in members] == ["member.txt"]
        with arc.open(members[0]) as stream:
            assert stream.read() == _PAYLOAD


def test_open_detected_refuses_a_udif_image() -> None:
    data = _koly_block()
    open_detected_one(data)
    with (
        pytest.raises(ArchiveyError, match="UDIF"),
        open_archive(io.BytesIO(data)) as arc,
    ):
        list(arc)


def test_open_detected_reads_a_compressed_tar_and_the_gzip_around_it() -> None:
    data = _compressed_tar_seeds()[0]
    open_detected_one(data)
    with open_archive(io.BytesIO(data)) as arc:
        names = [member.name for member in arc if member.is_file]
    assert any(name.endswith("file.txt") for name in names)
    with open_archive(io.BytesIO(data), format="gz") as arc:
        assert any(member.is_file for member in arc)


def test_zip_target_reads_a_stored_archive_both_ways() -> None:
    zip_open_one(_stored_zip())


def test_sevenzip_open_reads_an_uncompressed_header(tmp_path: Path) -> None:
    """A clear next header plus a bounded read must return the member bytes.

    Header compression would hide a coder-field mutation behind a failed
    decompress. These seeds are the ones that keep the coder graph reachable,
    and the open target has to actually decode them. A spec names the package
    its decode needs (``pyppmd``, ``cryptography``). The seed is built either
    way, and the decode below runs only when that package imports. ARM64 is
    required only when this ``7z`` lists the filter.
    """
    built = _uncompressed_header_sevenzip_archives(tmp_path)
    if not built and shutil.which("7z") is None:
        pytest.skip("7z CLI is not on PATH")
    assert [name for name, _blob, _package in built] == uncompressed_header_spec_names()
    for _name, blob, package in built:
        sevenzip_open_one(blob)
        if package is not None and not has_package(package):
            continue
        with open_archive(
            io.BytesIO(blob),
            format=ArchiveFormat.SEVEN_Z,
            password=["", "password"],
        ) as arc:
            files = [member for member in arc if member.is_file]
            assert files
            with arc.open(files[0]) as stream:
                assert stream.read(64)


def test_an_arm64_switch_is_skipped_when_7z_omits_the_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A row is gated by ``-m0=ARM64`` in its switches, and the skip is printed.

    ``renamed`` carries that switch under another name. A ``7z`` that does not
    list ARM64 leaves the row out and says so.
    """
    if shutil.which("7z") is None:
        pytest.skip("7z CLI is not on PATH")
    monkeypatch.setattr(fuzz_seeds, "sevenzip_lists_arm64", lambda: False)
    monkeypatch.setattr(
        fuzz_seeds,
        "_UNCOMPRESSED_HEADER_SPECS",
        (
            ("copy", ("-mhc=off", "-m0=Copy"), "one", None),
            ("renamed", ("-mhc=off", "-m0=ARM64", "-m1=Copy"), "one", None),
        ),
    )
    built = _uncompressed_header_sevenzip_archives(tmp_path)
    assert [name for name, _blob, _package in built] == ["copy"]
    assert uncompressed_header_spec_names() == ["copy"]
    assert (
        "7z seed renamed skipped: this 7z does not list the ARM64 filter"
        in capsys.readouterr().err
    )


def test_a_7z_probe_that_does_not_finish_is_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A ``7z i`` that raises is written to stderr and answers false."""
    from tests import conftest

    monkeypatch.setattr(conftest.shutil, "which", lambda _name: "7z")

    def fail(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=["7z", "i"], timeout=30)

    monkeypatch.setattr(conftest, "run_7z", fail)
    conftest.sevenzip_lists_arm64.cache_clear()
    try:
        assert conftest.sevenzip_lists_arm64() is False
    finally:
        conftest.sevenzip_lists_arm64.cache_clear()
    assert "7z i did not finish" in capsys.readouterr().err


def test_filter_seeds_stay_inside_the_typed_error_contract() -> None:
    for seed in filter_seeds():
        filters_one(seed)


def test_open_detected_seeds_stay_inside_the_typed_error_contract() -> None:
    for seed in open_detected_seeds():
        open_detected_one(seed)


def test_workflow_sets_a_budget_for_every_atheris_target() -> None:
    text = (
        Path(__file__).resolve().parents[1] / ".github/workflows/atheris-fuzz.yml"
    ).read_text(encoding="utf-8")
    missing = [
        name
        for name in TARGET_NAMES
        if f"ARCHIVEY_FUZZ_BUDGET_{name.upper()}" not in text
    ]
    assert missing == []


def test_soak_workflow_runs_every_accelerator_target() -> None:
    text = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/accelerator-fuzz-soak.yml"
    ).read_text(encoding="utf-8")
    matrix = next(line for line in text.splitlines() if "target: [" in line)
    accel = [name for name in TARGET_NAMES if name.endswith("_accel")]
    assert accel
    assert [name for name in accel if name not in matrix] == []
