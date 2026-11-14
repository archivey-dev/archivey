"""``archivey cat``: member contents, or the decompressed outer stream, to stdout.

Also the ``cat`` / ``test`` split on a directory that declares data: ``cat`` skips it,
``test`` reads it.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import lzma
import os
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from archivey.cli.exit_codes import (
    EXIT_BROKEN_PIPE,
    EXIT_FAIL,
    EXIT_OK,
    EXIT_USAGE,
)
from archivey.cli.main import main

_MEMBERS = {"a.txt": b"hello\n", "b.log": b"world\n", "d/c.log": b"deep\n"}
# Every byte value: the members reach stdout as bytes, never through the text layer.
_BINARY = bytes(range(256))


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        directory = tarfile.TarInfo("d")
        directory.type = tarfile.DIRTYPE
        tf.addfile(directory)
        for name, data in _MEMBERS.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "a.txt"
        tf.addfile(link)
    return buf.getvalue()


@pytest.fixture
def tar_xz(tmp_path: Path) -> Path:
    path = tmp_path / "t.tar.xz"
    path.write_bytes(lzma.compress(_tar_bytes()))
    return path


@pytest.fixture
def sample_zip(tmp_path: Path) -> Path:
    path = tmp_path / "z.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in _MEMBERS.items():
            zf.writestr(name, data)
    return path


class _Pipe(io.RawIOBase):
    """Bytes that read like a pipe: forward only, no seek."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:  # type: ignore[override]
        return self._data.readinto(buffer)


class _Run:
    """One ``main()`` call with a binary-backed stdout and a captured stderr."""

    def __init__(self, argv: list[str], stdin: bytes | None = None) -> None:
        self._stdout = io.BytesIO()
        out = io.TextIOWrapper(self._stdout, encoding="utf-8")
        err = io.StringIO()
        saved = sys.stdin
        if stdin is not None:
            sys.stdin = io.TextIOWrapper(io.BufferedReader(_Pipe(stdin)))
        try:
            self.code = main(argv, out=out, err=err)
        finally:
            sys.stdin = saved
        out.flush()
        self.stdout = self._stdout.getvalue()
        self.stderr = err.getvalue()


def test_cat_writes_file_members_in_archive_order(tar_xz: Path) -> None:
    run = _Run(["cat", str(tar_xz)])
    assert run.code == EXIT_OK, run.stderr
    # The directory and the symlink have no body of their own.
    assert run.stdout == b"hello\nworld\ndeep\n"


def _zip_with_directory_data(path: Path, *, bad_crc: bool = False) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(zipfile.ZipInfo("d/"), b"hidden data!")
        zf.writestr("d/f.txt", b"visible")
    if bad_crc:
        # The directory's CRC-32 sits in its local header and its central entry.
        crc = zlib.crc32(b"hidden data!").to_bytes(4, "little")
        data = path.read_bytes()
        assert data.count(crc) == 2
        path.write_bytes(data.replace(crc, bytes([crc[0] ^ 1]) + crc[1:]))
    return path


def test_cat_skips_and_test_reads_a_directory_that_declares_data(
    tmp_path: Path,
) -> None:
    # stream_members() yields a stream for such a directory. Its bytes are not file
    # content, so cat writes the files only; test is the integrity check, so it reads
    # them and counts the directory with the files.
    path = _zip_with_directory_data(tmp_path / "dirdata.zip")
    run = _Run(["cat", str(path)])
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == b"visible"
    run = _Run(["test", str(path)])
    assert run.code == EXIT_OK, run.stderr
    assert "2 OK, 0 failed" in run.stderr


def test_test_fails_a_directory_whose_data_fails_its_checksum(tmp_path: Path) -> None:
    path = _zip_with_directory_data(tmp_path / "dirdata.zip", bad_crc=True)
    run = _Run(["test", str(path)])
    assert run.code == EXIT_FAIL
    assert "FAIL d/" in run.stderr
    assert "crc32" in run.stderr
    assert "1 OK, 1 failed" in run.stderr
    # cat never reads the directory, so the damage does not stop it.
    run = _Run(["cat", str(path)])
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == b"visible"


def _zip_with_method_77(path: Path, member_index: int) -> Path:
    # Method 77 is not one archivey decodes. Patch it into one entry's local header
    # (method at offset 8) and central entry (offset 10).
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(zipfile.ZipInfo("d/"), b"hidden data!")
        zf.writestr("d/f.txt", b"visible")
    data = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as zf:
        local = zf.infolist()[member_index].header_offset
    data[local + 8 : local + 10] = (77).to_bytes(2, "little")
    cd = data.index(b"PK\x01\x02")
    for _ in range(member_index):
        cd = data.index(b"PK\x01\x02", cd + 4)
    data[cd + 10 : cd + 12] = (77).to_bytes(2, "little")
    path.write_bytes(bytes(data))
    return path


def test_test_skips_a_directory_whose_data_it_cannot_decode(tmp_path: Path) -> None:
    # The bytes are never extracted, so the directory is not tested rather than
    # failed, as unzip -t skips it (DR-4).
    path = _zip_with_method_77(tmp_path / "dirdata.zip", 0)
    run = _Run(["test", str(path)])
    assert run.code == EXIT_FAIL
    assert "skip d/:" in run.stderr
    assert "compression method 77" in run.stderr
    assert "1 OK, 0 failed, 1 not tested" in run.stderr


def test_test_still_fails_a_file_whose_data_it_cannot_decode(tmp_path: Path) -> None:
    path = _zip_with_method_77(tmp_path / "filedata.zip", 1)
    run = _Run(["test", str(path)])
    assert run.code == EXIT_FAIL
    assert "FAIL d/f.txt:" in run.stderr
    assert "compression method 77" in run.stderr
    assert "1 OK, 1 failed" in run.stderr


@pytest.mark.parametrize(
    ("patterns", "expected"),
    [
        (["b.log"], b"world\n"),
        (["*.log"], b"world\n"),  # ``*`` stays in the top folder
        (["**/*.log"], b"world\ndeep\n"),
        (["d"], b"deep\n"),  # a folder brings its contents
        (["--exclude", "a.txt"], b"world\ndeep\n"),
    ],
)
def test_cat_selects_members_like_the_other_verbs(
    sample_zip: Path, patterns: list[str], expected: bytes
) -> None:
    run = _Run(["cat", str(sample_zip), *patterns])
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == expected


def test_cat_pattern_that_matches_nothing_fails_before_writing(
    sample_zip: Path,
) -> None:
    run = _Run(["cat", str(sample_zip), "nomatch"])
    assert run.code == EXIT_FAIL
    assert "pattern matched no members: 'nomatch'" in run.stderr
    # ZIP has a free index, so the patterns are judged before any byte is written.
    assert run.stdout == b""


def test_cat_warns_about_one_unmatched_pattern_among_several(
    sample_zip: Path,
) -> None:
    # As for test and extract: the run fails only when the patterns select nothing.
    run = _Run(["cat", str(sample_zip), "a.txt", "nomatch"])
    assert run.code == EXIT_OK
    assert "pattern matched no members: 'nomatch'" in run.stderr
    assert run.stdout == b"hello\n"


def test_cat_pattern_that_matches_nothing_fails_after_a_pass(tar_xz: Path) -> None:
    # A compressed tar has no index: the pass itself finds the unmatched pattern.
    run = _Run(["cat", str(tar_xz), "nomatch"])
    assert run.code == EXIT_FAIL
    assert "pattern matched no members: 'nomatch'" in run.stderr


def test_cat_verbose_names_members_on_stderr(tar_xz: Path) -> None:
    run = _Run(["cat", str(tar_xz), "-v"])
    assert run.code == EXIT_OK
    assert run.stdout == b"hello\nworld\ndeep\n"
    assert run.stderr.splitlines() == [
        "skip d/",
        "a.txt",
        "b.log",
        "d/c.log",
        "skip link.txt",
    ]


def test_cat_writes_member_bytes_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "bin.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("all.bin", _BINARY)
    run = _Run(["cat", str(path)])
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == _BINARY


def test_cat_outer_writes_bytes_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "all.bin.gz"
    path.write_bytes(gzip.compress(_BINARY))
    run = _Run(["cat", str(path), "--outer"])
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == _BINARY


def test_cat_reads_an_archive_from_stdin(tar_xz: Path) -> None:
    run = _Run(["cat", "-", "**/*.log"], stdin=tar_xz.read_bytes())
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == b"world\ndeep\n"


def test_cat_from_stdin_names_stdin_when_the_format_must_seek() -> None:
    sevenzip = Path(__file__).parent / "fixtures" / "sevenzip" / "encrypted_link.7z"
    run = _Run(["cat", "-"], stdin=sevenzip.read_bytes())
    assert run.code == EXIT_FAIL
    assert "stdin: the 7z format cannot be read from a pipe" in run.stderr


def test_cat_without_a_standard_input_says_so(tar_xz: Path) -> None:
    saved = sys.stdin
    sys.stdin = None  # type: ignore[assignment]  # as CPython leaves it for a closed fd 0
    try:
        err = io.StringIO()
        out = io.TextIOWrapper(io.BytesIO())
        assert main(["cat", "-"], out=out, err=err) == EXIT_USAGE
    finally:
        sys.stdin = saved
    assert "no standard input to read the archive from" in err.getvalue()
    assert "/dev/stdin" not in err.getvalue()


def test_the_stdin_token_stays_reserved_for_the_other_verbs(tar_xz: Path) -> None:
    run = _Run(["list", "-"], stdin=tar_xz.read_bytes())
    assert run.code == EXIT_USAGE
    assert "'-' token for stdin is reserved" in run.stderr


def test_cat_stops_at_a_damaged_member(tmp_path: Path) -> None:
    data = bytearray(gzip.compress(b"abc" * 1000))
    data[-8] ^= 1  # the CRC32 in the trailer
    path = tmp_path / "bad.gz"
    path.write_bytes(bytes(data))
    run = _Run(["cat", str(path)])
    assert run.code == EXIT_FAIL
    assert run.stderr.startswith("archivey: bad: ")


def test_cat_outer_removes_only_the_compression_layer(tar_xz: Path) -> None:
    run = _Run(["cat", str(tar_xz), "--outer"])
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == _tar_bytes()


def test_cat_outer_from_stdin(tar_xz: Path) -> None:
    run = _Run(["cat", "-", "--outer"], stdin=tar_xz.read_bytes())
    assert run.code == EXIT_OK, run.stderr
    assert run.stdout == _tar_bytes()


def test_cat_and_outer_agree_on_a_single_compressed_file(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt.gz"
    path.write_bytes(gzip.compress(b"notes\n"))
    assert _Run(["cat", str(path)]).stdout == b"notes\n"
    assert _Run(["cat", str(path), "--outer"]).stdout == b"notes\n"


def test_cat_outer_on_a_container_says_to_leave_the_flag_out(
    sample_zip: Path,
) -> None:
    run = _Run(["cat", str(sample_zip), "--outer"])
    assert run.code == EXIT_FAIL
    assert "is a zip archive, which has no compression layer" in run.stderr
    assert "leave out --outer" in run.stderr
    assert "open_archive" not in run.stderr


def test_cat_outer_names_a_missing_path_like_the_other_verbs(tmp_path: Path) -> None:
    missing = tmp_path / "nope.gz"
    outer = _Run(["cat", str(missing), "--outer"])
    members = _Run(["cat", str(missing)])
    assert outer.code == members.code == EXIT_FAIL
    assert "cannot open" in outer.stderr
    assert "no such file or directory" in outer.stderr
    assert outer.stderr == members.stderr


def test_cat_outer_on_a_directory_is_a_usage_error(tmp_path: Path) -> None:
    run = _Run(["cat", str(tmp_path), "--outer"])
    assert run.code == EXIT_USAGE
    assert "is a directory, which has no compression layer" in run.stderr


@pytest.mark.parametrize("extra", [["a.txt"], ["--exclude", "a.txt"], ["--track-io"]])
def test_cat_outer_refuses_member_options(tar_xz: Path, extra: list[str]) -> None:
    run = _Run(["cat", str(tar_xz), "--outer", *extra])
    assert run.code == EXIT_USAGE
    assert run.stdout == b""


def test_cat_needs_a_binary_stdout(sample_zip: Path) -> None:
    err = io.StringIO()
    assert main(["cat", str(sample_zip)], out=io.StringIO(), err=err) == EXIT_USAGE
    assert "binary standard output" in err.getvalue()


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full")
@pytest.mark.parametrize("outer", [False, True])
def test_cat_blames_a_failed_stdout_write_on_the_output(
    tar_xz: Path, outer: bool
) -> None:
    out = open("/dev/full", "w")  # noqa: SIM115  # closing it fails too
    err = io.StringIO()
    argv = ["cat", str(tar_xz), *(["--outer"] if outer else [])]
    try:
        assert main(argv, out=out, err=err) == EXIT_FAIL
    finally:
        with contextlib.suppress(OSError):
            out.close()
    lines = err.getvalue().splitlines()
    # One line, from main(): no member is named for the output's failure.
    assert lines == ["archivey: No space left on device"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX pipe semantics")
def test_cat_into_a_closed_pipe_exits_141(tmp_path: Path) -> None:
    path = tmp_path / "big.gz"
    path.write_bytes(gzip.compress(b"y\n" * 4_000_000, compresslevel=1))
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    with os.fdopen(write_fd, "w") as out:
        assert main(["cat", str(path)], out=out, err=io.StringIO()) == (
            EXIT_BROKEN_PIPE
        )
