"""``ArchiveReader.backends_used``: what a reader ran to read its archive.

The format reader comes first, then each optional package, plugin codec and external
program as it is first used. The standard library's codecs are not listed, and neither
is what detection decoded.
"""

from __future__ import annotations

import gzip
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    BackendUse,
    ContainerFormat,
    FormatPolicy,
    open_archive,
)
from archivey.internal.backends import rar_unrar
from archivey.internal.resource_usage import ResourceUsageRecorder, handler_name
from tests.conftest import requires, requires_zstd
from tests.test_format_policy import StdlibZipPlugin

_FIXTURES = Path(__file__).parent / "fixtures"
_ARCHIVEY_ZIP = BackendUse("reader", "archivey", "ZIP")


def _read_first_file(reader: object) -> None:
    for member in reader.members():  # type: ignore[attr-defined]
        if member.is_file:
            reader.read(member)  # type: ignore[attr-defined]
            return


def _zip(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", b"a" * 1000)
    return path


def test_a_standard_library_read_lists_only_the_reader(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        assert reader.backends_used == (_ARCHIVEY_ZIP,)
        reader.read("a.txt")
        reader.read("a.txt")
        assert reader.backends_used == (_ARCHIVEY_ZIP,)


def test_a_replacement_plugin_is_named_by_its_class(tmp_path: Path) -> None:
    config = ArchiveyConfig(
        formats=FormatPolicy(replace={ContainerFormat.ZIP: StdlibZipPlugin})
    )
    with open_archive(_zip(tmp_path), config=config) as reader:
        (use,) = reader.backends_used
    assert use == BackendUse(
        "reader", "tests.test_format_policy.StdlibZipPlugin", "ZIP"
    )


def test_a_handler_archivey_ships_is_archivey() -> None:
    from archivey.internal.backends.iso_reader import IsoHandler

    assert handler_name(IsoHandler) == "archivey"
    assert handler_name(StdlibZipPlugin()) == "tests.test_format_policy.StdlibZipPlugin"


@requires_zstd()
def test_a_package_codec_is_listed(tmp_path: Path) -> None:
    from archivey.internal.streams.codecs import deps

    path = tmp_path / "a.txt.zst"
    assert deps.zstd is not None
    path.write_bytes(deps.zstd.compress(b"z" * 1000))
    with open_archive(path) as reader:
        _read_first_file(reader)
        reader_use, library = reader.backends_used
    assert reader_use.kind == "reader"
    assert library.kind == "library"
    assert library.name in ("compression.zstd", "backports.zstd")
    assert library.used_for == "zstd"


@requires("rapidgzip")
def test_the_accelerator_is_listed_when_it_runs(tmp_path: Path) -> None:
    path = tmp_path / "a.txt.gz"
    path.write_bytes(gzip.compress(b"g" * 100_000))
    with open_archive(path, config=ArchiveyConfig(use_rapidgzip="on")) as reader:
        _read_first_file(reader)
        assert BackendUse("library", "rapidgzip", "gzip") in reader.backends_used
    with open_archive(path, config=ArchiveyConfig(use_rapidgzip="off")) as reader:
        _read_first_file(reader)
        assert [u.kind for u in reader.backends_used] == ["reader"]


@requires("lz4")
@pytest.mark.parametrize(
    "fixture", [_FIXTURES / "sevenzip" / "lz4.7z", _FIXTURES / "squashfs" / "lz4.sqfs"]
)
def test_lz4_is_listed_for_7z_and_squashfs(fixture: Path) -> None:
    with open_archive(fixture) as reader:
        _read_first_file(reader)
        libraries = [u for u in reader.backends_used if u.kind == "library"]
    assert [u.name for u in libraries] == ["lz4"]


@requires("cryptography")
@pytest.mark.parametrize(
    ("fixture", "password"),
    [
        (_FIXTURES / "rar" / "encryption_stored__.rar", "password"),
        (_FIXTURES / "sevenzip" / "encrypted_link.7z", "SECRET"),
    ],
)
def test_aes_decryption_lists_cryptography(fixture: Path, password: str) -> None:
    with open_archive(fixture, password=password) as reader:
        _read_first_file(reader)
        assert (
            BackendUse("library", "cryptography", "AES decryption")
            in reader.backends_used
        )


def test_an_unrar_spawn_records_the_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "unrar"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    monkeypatch.setattr(
        rar_unrar, "find_rarlab_unrar", lambda _program=None: str(binary)
    )
    usage = ResourceUsageRecorder()
    proc, stdout = rar_unrar.open_unrar_p(
        _FIXTURES / "rar" / "basic_solid__.rar", usage=usage
    )
    stdout.read()
    stdout.close()
    proc.wait()
    assert usage.backends() == (BackendUse("program", "unrar", "RAR", str(binary)),)


def test_detection_decodes_are_not_listed(tmp_path: Path) -> None:
    # A gzip file is decoded a little to detect what is inside; only the open counts.
    path = tmp_path / "a.txt.gz"
    path.write_bytes(gzip.compress(b"x" * 1000))
    with open_archive(path) as reader:
        assert [u.kind for u in reader.backends_used] == ["reader"]


def test_the_list_is_a_snapshot(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        first = reader.backends_used
        assert isinstance(first, tuple)
    assert reader.backends_used == first
