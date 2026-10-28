"""``extract --outer`` and ``test --outer``: the compression layer alone, as gunzip does."""

from __future__ import annotations

import gzip
import io
import lzma
import os
import sys
import tarfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey.cli.common import outer_layer_format
from archivey.cli.exit_codes import EXIT_FAIL, EXIT_OK, EXIT_USAGE
from archivey.cli.main import main
from archivey.internal.format_args import outer_stream_format
from archivey.types import (
    ArchiveFormat,
    ContainerFormat,
    PluginContainer,
    StreamFormat,
)


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 6
        tf.addfile(info, io.BytesIO(b"hello\n"))
    return buf.getvalue()


def _run(argv: list[str]) -> tuple[int, str]:
    err = io.StringIO()
    code = main([*argv, "--hide-progress"], out=io.StringIO(), err=err)
    return code, err.getvalue()


@pytest.mark.parametrize(
    ("name", "compress", "written"),
    [
        ("data.tar.gz", gzip.compress, "data.tar"),
        ("data.tgz", gzip.compress, "data.tar"),
        ("data.txz", lzma.compress, "data.tar"),
        ("data.tar.xz", lzma.compress, "data.tar"),
    ],
)
def test_extract_outer_writes_the_tar_inside(
    tmp_path: Path, name: str, compress: Callable[[bytes], bytes], written: str
) -> None:
    src = tmp_path / name
    src.write_bytes(compress(_tar_bytes()))
    dest = tmp_path / "out"
    code, err = _run(["extract", str(src), "--outer", "-d", str(dest)])
    assert code == EXIT_OK, err
    assert sorted(os.listdir(dest)) == [written]
    assert (dest / written).read_bytes() == _tar_bytes()


@pytest.mark.parametrize(
    "flags",
    [[], ["--dry-run"]],
    ids=["default-dest", "dry-run"],
)
def test_extract_outer_on_a_single_compressed_file_matches_plain_extract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
) -> None:
    """No -d goes through the default-destination choice, which reads the reader's
    format; --outer changes that format, so both spellings are compared whole."""
    src = tmp_path / "notes.txt.gz"
    src.write_bytes(gzip.compress(b"notes\n"))
    results = {}
    for name, outer in (("plain", []), ("outer", ["--outer"])):
        cwd = tmp_path / name
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        results[name] = (_run(["extract", str(src), *outer, *flags]), os.listdir(cwd))
    assert results["outer"] == results["plain"]
    (code, err), written = results["outer"]
    assert code == EXIT_OK, err
    assert written == ([] if flags else ["notes.txt"])


def test_extract_outer_keeps_the_overwrite_policy(tmp_path: Path) -> None:
    src = tmp_path / "data.tar.gz"
    src.write_bytes(gzip.compress(_tar_bytes()))
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "data.tar").write_bytes(b"mine")
    code, err = _run(["extract", str(src), "--outer", "-d", str(dest)])
    assert code == EXIT_OK, err
    assert (dest / "data.tar").read_bytes() == b"mine"
    assert sorted(os.listdir(dest)) == ["data (1).tar", "data.tar"]


def test_test_outer_reads_the_whole_decompressed_stream(tmp_path: Path) -> None:
    src = tmp_path / "data.tar.gz"
    src.write_bytes(gzip.compress(_tar_bytes()))
    code, err = _run(["test", str(src), "--outer"])
    assert code == EXIT_OK, err
    assert "1 OK, 0 failed" in err


def test_test_outer_fails_on_a_bad_trailer(tmp_path: Path) -> None:
    data = bytearray(gzip.compress(_tar_bytes()))
    data[-8] ^= 0xFF  # the CRC-32 of the decompressed bytes
    src = tmp_path / "data.tar.gz"
    src.write_bytes(bytes(data))
    code, err = _run(["test", str(src), "--outer"])
    assert code == EXIT_FAIL
    assert "FAIL data.tar" in err


@pytest.mark.parametrize("verb", ["extract", "test"])
def test_outer_on_a_container_says_to_leave_the_flag_out(
    tmp_path: Path, verb: str
) -> None:
    src = tmp_path / "plain.tar"
    src.write_bytes(_tar_bytes())
    code, err = _run([verb, str(src), "--outer"])
    assert code == EXIT_FAIL
    assert "is a tar archive, which has no compression layer" in err
    assert f"leave out --outer to {verb} its members" in err


@pytest.mark.parametrize("verb", ["extract", "test"])
def test_outer_with_patterns_is_a_usage_error(tmp_path: Path, verb: str) -> None:
    src = tmp_path / "data.tar.gz"
    src.write_bytes(gzip.compress(_tar_bytes()))
    code, err = _run([verb, str(src), "--outer", "a.txt"])
    assert code == EXIT_USAGE
    assert "takes no member patterns" in err


def test_outer_on_a_directory_is_a_usage_error(tmp_path: Path) -> None:
    code, err = _run(["test", str(tmp_path), "--outer"])
    assert code == EXIT_USAGE
    assert "is a directory, which has no compression layer" in err


def test_outer_names_a_missing_path_like_the_other_verbs(tmp_path: Path) -> None:
    missing = str(tmp_path / "nope.gz")
    assert _run(["test", missing, "--outer"]) == _run(["test", missing])


@pytest.mark.skipif(sys.platform == "win32", reason="no FIFOs on Windows")
def test_outer_on_a_pipe_points_at_cat(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.gz"
    os.mkfifo(fifo)
    code, err = _run(["extract", str(fifo), "--outer", "-d", str(tmp_path / "o")])
    assert code == EXIT_USAGE
    assert "archivey cat --outer" in err


class _PluginContainer(PluginContainer):
    SEQ = "outer-rule-seq"


@pytest.mark.parametrize("container", [*ContainerFormat, _PluginContainer.SEQ])
@pytest.mark.parametrize("stream", list(StreamFormat))
def test_outer_rule_matches_what_open_stream_accepts(
    container: ContainerFormat | PluginContainer, stream: StreamFormat
) -> None:
    """extract/test --outer and cat --outer (open_stream) peel the same formats,
    a plugin container's compressed pair (``.cpio.gz``) included."""
    fmt = ArchiveFormat(container, stream)
    outer = outer_layer_format(fmt)
    codec = outer_stream_format(fmt)
    if codec is None:
        assert outer is None
    else:
        assert outer == ArchiveFormat(ContainerFormat.RAW_STREAM, codec)


def test_exclude_alone_is_named_in_the_refusal(tmp_path: Path) -> None:
    src = tmp_path / "data.tar.gz"
    src.write_bytes(gzip.compress(_tar_bytes()))
    code, err = _run(["test", str(src), "--outer", "--exclude", "x*"])
    assert code == EXIT_USAGE
    assert "takes no member patterns or --exclude" in err


@pytest.mark.parametrize("verb", ["extract", "test"])
def test_outer_finds_the_layer_by_content_whatever_the_name(
    tmp_path: Path, verb: str
) -> None:
    """zlib has no magic: only a content probe finds it, as cat --outer's does."""
    src = tmp_path / "weird.name"
    src.write_bytes(zlib.compress(b"payload\n"))
    dest = tmp_path / "out"
    flags = ["-d", str(dest)] if verb == "extract" else []
    code, err = _run([verb, str(src), "--outer", *flags])
    assert code == EXIT_OK, err
    if verb == "extract":
        assert (dest / "weird.name.uncompressed").read_bytes() == b"payload\n"


def test_extract_outer_without_dest_writes_the_tar_into_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--outer turns a compressed tar into a single-file archive, so the default
    destination is the cwd with no ``data/`` wrapper, as for any ``.gz``."""
    src = tmp_path / "data.tgz"
    src.write_bytes(gzip.compress(_tar_bytes()))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    code, err = _run(["extract", str(src), "--outer"])
    assert code == EXIT_OK, err
    assert os.listdir(cwd) == ["data.tar"]
    assert (cwd / "data.tar").read_bytes() == _tar_bytes()
