"""``ArchiveReader.backends_used``: what a reader ran to read its archive.

The format reader comes first, then each optional package, plugin codec and external
program as it is first used. The standard library's codecs are not listed (zstd names
its module, ``compression.zstd`` on 3.14), and neither is what detection decoded.
"""

from __future__ import annotations

import gzip
import io
import sys
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    BackendUse,
    ContainerFormat,
    FormatPolicy,
    StreamFormat,
    open_archive,
)
from archivey.formats import register_codec, register_format
from archivey.internal.backends import rar_unrar
from archivey.internal.config import StreamConfig
from archivey.internal.external import unar
from archivey.internal.format_adapter import registration_scope
from archivey.internal.resource_usage import ResourceUsageRecorder, handler_name
from archivey.internal.streams.codecs import Codec, open_codec_stream
from tests.conftest import requires, requires_zstd
from tests.streams_util import NonSeekableBytesIO
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


@pytest.mark.skipif(
    sys.platform == "win32", reason="uses a POSIX shell script as a stand-in unrar"
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


@requires_zstd()
def test_a_detection_probe_decode_is_not_listed() -> None:
    # A probe's config (``probe_read_bound`` set) records nothing, even with a
    # recorder: fails if ``_open_backend`` records without checking the bound.
    from archivey.internal.streams.codecs import deps

    assert deps.zstd is not None
    data = deps.zstd.compress(b"z" * 1000)
    for bound, expected in ((64, 0), (None, 1)):
        usage = ResourceUsageRecorder()
        config = StreamConfig(probe_read_bound=bound, usage=usage)
        with open_codec_stream(Codec.ZSTD, io.BytesIO(data), config=config) as stream:
            stream.read(64)
        assert len(usage.backends()) == expected


def test_the_list_is_a_snapshot(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        first = reader.backends_used
        assert isinstance(first, tuple)
    assert reader.backends_used == first


@requires("cryptography")
def test_a_forward_zip_aes_read_lists_cryptography() -> None:
    # A non-seekable source reads through ZipForwardReader, which decrypts itself.
    data = (_FIXTURES / "external" / "aes_ae1_pyzipper036.zip").read_bytes()
    source = io.BufferedReader(NonSeekableBytesIO(data))
    with open_archive(source, password="secret", streaming=True) as reader:
        for member, stream in reader.stream_members():
            if stream is not None:
                assert stream.read()
        assert (
            BackendUse("library", "cryptography", "AES decryption")
            in reader.backends_used
        )


@requires_zstd()
def test_a_nested_archive_lists_in_the_outer_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.streams.codecs import deps
    from tests import test_format_api_nested as nested

    assert deps.zstd is not None
    inner = deps.zstd.compress(nested._tar([("a.txt", b"abc")]))
    tar_zstd = ArchiveFormat(ContainerFormat.TAR, StreamFormat.ZSTD)
    monkeypatch.setitem(nested._KINDS, b"S", tar_zstd)
    with registration_scope():
        register_format(nested.BoxesHandler)
        source = io.BytesIO(nested._boxes((b"S", inner)))
        with open_archive(
            source, format=nested.BoxesHandler.format, streaming=True
        ) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                assert stream.read() == b"abc"
            uses = reader.backends_used
    assert uses[0] == BackendUse(
        "reader", "tests.test_format_api_nested.BoxesHandler", "BOXES"
    )
    # The inner archive's own reader and the zstd package it decoded with.
    assert BackendUse("reader", "archivey", tar_zstd.display_name) in uses
    assert [u.name for u in uses if u.kind == "library"] in (
        ["compression.zstd"],
        ["backports.zstd"],
    )


def test_a_plugin_codec_lists_itself_and_its_packages(tmp_path: Path) -> None:
    from tests.test_codec_api import ToyHandler, toy_compress

    class _ToyNeedsJson(ToyHandler):
        requires = ("json",)

    path = tmp_path / "a.txt.toy"
    path.write_bytes(toy_compress(b"t" * 1000))
    with registration_scope():
        register_codec(_ToyNeedsJson)
        with open_archive(path) as reader:
            _read_first_file(reader)
            uses = reader.backends_used
    name = f"{__name__}.test_a_plugin_codec_lists_itself_and_its_packages.<locals>"
    assert [(u.kind, u.name) for u in uses[1:]] == [
        ("codec", f"{name}._ToyNeedsJson"),
        ("library", "json"),
    ]


@requires("pycdlib")
def test_a_handler_built_on_a_package_lists_it() -> None:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(b"iso"), 3, "/F.;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    out.seek(0)
    with open_archive(out) as reader:
        assert reader.backends_used == (
            BackendUse("reader", "archivey", "ISO"),
            BackendUse("library", "pycdlib", "ISO"),
        )


def test_a_unar_spawn_records_the_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = str(tmp_path / "unar")
    monkeypatch.setattr(unar, "find_unar", lambda **_kwargs: binary)
    monkeypatch.setattr(unar, "spawn_for_stdout", lambda *_a, **_k: (None, None))
    usage = ResourceUsageRecorder()
    unar.open_unar_stdout("x.rar", None, purpose="for a test", usage=usage)
    assert usage.backends() == (BackendUse("program", "unar", "RAR", binary),)


def test_python_lzo_is_recorded_when_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.internal.streams.codecs import lzo_decoder

    def package(data: bytes, size: int) -> bytes:
        return b""

    monkeypatch.setattr(lzo_decoder, "_python_lzo", lambda *_a: package)
    usage = ResourceUsageRecorder()
    assert lzo_decoder.lzo1x_decompressor(usage=usage) is package
    assert usage.backends() == (BackendUse("library", "lzo", "lzo"),)
    monkeypatch.setattr(lzo_decoder, "_python_lzo", lambda *_a: None)
    usage = ResourceUsageRecorder()
    lzo_decoder.lzo1x_decompressor(usage=usage)
    assert usage.backends() == ()
