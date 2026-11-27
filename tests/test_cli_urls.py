"""The CLI's archive argument as a URL, read through fsspec (``cli`` spec, URL inputs).

Most cases use fsspec's ``memory://`` file system. The HTTP cases run against a local
server that answers range requests, and skip where aiohttp is not installed (the
core-only CI leg). The dependency-absence cases need neither package and always run.
"""

from __future__ import annotations

import gzip
import io
import lzma
import os
import sys
import tarfile
import threading
import zipfile
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from archivey.cli import sources
from archivey.cli.exit_codes import EXIT_FAIL, EXIT_OK
from archivey.cli.extract_cmd import UrlName, _archive_stem
from archivey.cli.main import main
from archivey.types import ArchiveFormat, SourceProgress

# --- fixtures -------------------------------------------------------------------------


def _zip_bytes(members: dict[str, bytes], *, stored: bool = False) -> bytes:
    buf = io.BytesIO()
    method = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TWO = {"a.txt": b"hello\n", "b.txt": b"bye\n"}


class _Run:
    def __init__(self, code: int, out: str, err: str) -> None:
        self.code, self.out, self.err = code, out, err


def _run(argv: list[str]) -> _Run:
    out, err = io.StringIO(), io.StringIO()
    code = main([*argv], out=out, err=err)
    return _Run(code, out.getvalue(), err.getvalue())


@pytest.fixture
def memfs() -> Iterator[Any]:
    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    fs.mkdir("/cli-urls")
    try:
        yield fs
    finally:
        fs.rm("/cli-urls", recursive=True)


@pytest.fixture
def no_fsspec(monkeypatch: pytest.MonkeyPatch) -> None:
    """``import fsspec`` fails, as it does where fsspec is not installed."""
    monkeypatch.setitem(sys.modules, "fsspec", None)


# --- source resolution ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("arg", "protocol"),
    [
        ("https://host/a.zip", "https"),
        ("s3://bucket/key", "s3"),
        ("git+ssh://x/y", "git+ssh"),
        ("simplecache::https://host/a.zip", "simplecache"),
        ("zip://inner.tar::memory://outer.zip", "zip"),
        ("C:\\archive.zip", None),
        ("C://archive.zip", None),
        ("c:/archive.zip", None),
        ("\\\\server\\share\\a.zip", None),
        ("./https://x", None),
        ("archive.zip", None),
        ("ab::c", "ab"),
        ("a::b", None),
        ("1x://y", None),
        ("::https://x", None),
    ],
)
def test_url_candidates(arg: str, protocol: str | None) -> None:
    assert sources.first_protocol(arg) == protocol


def test_every_verb_reads_a_memory_url(
    memfs: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))
    url = "memory://cli-urls/data.zip"

    listed = _run([url])
    assert listed.code == EXIT_OK, listed.err
    assert "a.txt" in listed.out and "b.txt" in listed.out
    for alias in ("l", "list"):
        assert _run([alias, url]).code == EXIT_OK

    info = _run(["info", url])
    assert info.code == EXIT_OK, info.err
    assert "path:        memory://cli-urls/data.zip" in info.out
    assert "format:      zip" in info.out

    tested = _run(["t", url])
    assert tested.code == EXIT_OK, tested.err
    assert "2 OK" in tested.err

    monkeypatch.chdir(tmp_path)
    extracted = _run(["x", url, "--hide-progress"])
    assert extracted.code == EXIT_OK, extracted.err
    assert (tmp_path / "data" / "a.txt").read_bytes() == b"hello\n"

    explicit = _run(["x", url, "-d", "out", "--hide-progress"])
    assert explicit.code == EXIT_OK, explicit.err
    assert (tmp_path / "out" / "b.txt").read_bytes() == b"bye\n"


def test_track_io_counts_the_requests_of_a_url(memfs: Any) -> None:
    data = _zip_bytes(TWO)
    memfs.pipe("/cli-urls/data.zip", data)
    run = _run(["--track-io", "memory://cli-urls/data.zip"])
    assert run.code == EXIT_OK, run.err
    line = next(x for x in run.err.splitlines() if x.startswith("track-io:"))
    fields = dict(f.split("=", 1) for f in line.split()[1:])
    assert int(fields["remote_requests"]) >= 1
    # The whole archive fits in the first request's window.
    assert int(fields["remote_bytes_fetched"]) == len(data)
    assert fields["remote_size"] == str(len(data))
    assert fields["remote_fetched_share"] == "100.00%"


def test_track_io_counts_every_request_and_every_part(
    memfs: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fsspec
    from fsspec.implementations.memory import MemoryFileSystem

    from archivey import open_archive
    from archivey.internal.measurement import enable_measurement, io_stats

    calls: list[int] = []
    cat_file = MemoryFileSystem.cat_file

    def counted(
        self: Any, path: str, start: Any = None, end: Any = None, **kw: Any
    ) -> Any:
        data = cat_file(self, path, start=start, end=end, **kw)
        calls.append(len(data))
        return data

    monkeypatch.setattr(MemoryFileSystem, "cat_file", counted)
    # Larger than the first window, so the listing takes more than one request.
    data = _zip_bytes({"a.bin": os.urandom(400_000)}, stored=True)
    memfs.pipe("/cli-urls/big.zip", data)
    run = _run(["--track-io", "memory://cli-urls/big.zip"])
    assert run.code == EXIT_OK, run.err
    line = next(x for x in run.err.splitlines() if x.startswith("track-io:"))
    fields = dict(f.split("=", 1) for f in line.split()[1:])
    assert len(calls) > 1
    assert int(fields["remote_requests"]) == len(calls)
    assert int(fields["remote_bytes_fetched"]) == sum(calls)

    # A volume list: the size is the sum of the parts.
    half = len(data) // 2
    memfs.pipe("/cli-urls/big.zip.001", data[:half])
    memfs.pipe("/cli-urls/big.zip.002", data[half:])
    parts = [fsspec.open(f"memory://cli-urls/big.zip.00{i}") for i in (1, 2)]
    with enable_measurement(), open_archive(parts) as reader:
        reader.members()
        stats = io_stats(reader)
    assert stats is not None
    assert stats.remote_size == len(data)
    assert stats.remote_requests is not None and stats.remote_requests >= 1


def test_track_io_of_a_local_path_has_no_request_counts(tmp_path: Path) -> None:
    path = tmp_path / "data.zip"
    path.write_bytes(_zip_bytes(TWO))
    run = _run(["--track-io", str(path)])
    assert run.code == EXIT_OK, run.err
    assert "source_seek_count=" in run.err
    assert "remote_requests" not in run.err


def test_cat_reads_a_memory_url(
    memfs: Any, capfdbinary: pytest.CaptureFixture[bytes]
) -> None:
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))
    code = main(["cat", "memory://cli-urls/data.zip", "a.txt"])
    assert code == EXIT_OK
    assert capfdbinary.readouterr().out == b"hello\n"


def test_outer_forms_read_a_memory_url(
    memfs: Any, tmp_path: Path, capfdbinary: pytest.CaptureFixture[bytes]
) -> None:
    tar = _tar_bytes(TWO)
    memfs.pipe("/cli-urls/data.tar.gz", gzip.compress(tar))
    url = "memory://cli-urls/data.tar.gz"

    tested = _run(["test", "--outer", url, "--hide-progress"])
    assert tested.code == EXIT_OK, tested.err

    extracted = _run(["x", "--outer", url, "-d", str(tmp_path), "--hide-progress"])
    assert extracted.code == EXIT_OK, extracted.err
    assert (tmp_path / "data.tar").read_bytes() == tar

    assert main(["cat", "--outer", url]) == EXIT_OK
    assert capfdbinary.readouterr().out == tar


def test_outer_on_a_url_container_names_the_url(memfs: Any) -> None:
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))
    result = _run(["test", "--outer", "memory://cli-urls/data.zip"])
    assert result.code == EXIT_FAIL
    assert "--outer: memory://cli-urls/data.zip is a zip archive" in result.err


def test_chains_are_read_through_fsspec(memfs: Any) -> None:
    memfs.pipe("/cli-urls/outer.zip", _zip_bytes({"inner.tar": _tar_bytes(TWO)}))
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))

    member = _run(["zip://inner.tar::memory://cli-urls/outer.zip"])
    assert member.code == EXIT_OK, member.err
    assert "a.txt" in member.out and "inner.tar" not in member.out

    cached = _run(["simplecache::memory://cli-urls/data.zip"])
    assert cached.code == EXIT_OK, cached.err
    assert "b.txt" in cached.out


def test_url_characters_are_kept_literally(memfs: Any) -> None:
    # Neither a glob nor a second name: one object whose name holds ``*`` and ``[``.
    memfs.pipe("/cli-urls/a*[1].zip", _zip_bytes(TWO))
    memfs.pipe("/cli-urls/ab1.zip", _zip_bytes({"other.txt": b"x"}))
    result = _run(["memory://cli-urls/a*[1].zip"])
    assert result.code == EXIT_OK, result.err
    assert "a.txt" in result.out and "other.txt" not in result.out


def test_a_missing_object_is_a_clean_failure(memfs: Any) -> None:
    result = _run(["memory://cli-urls/nothere.zip"])
    assert result.code == EXIT_FAIL
    assert result.err.startswith(
        "archivey: cannot open 'memory://cli-urls/nothere.zip': no such file"
    )
    assert "Traceback" not in result.err


def test_an_existing_local_path_wins_without_fsspec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_fsspec: None
) -> None:
    # ``https://x/a.zip`` as a relative POSIX path is ``https:/x/a.zip``.
    if sys.platform == "win32":
        pytest.skip("':' cannot appear in a Windows file name")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "https:" / "x").mkdir(parents=True)
    (tmp_path / "https:" / "x" / "a.zip").write_bytes(_zip_bytes(TWO))
    result = _run(["https://x/a.zip"])
    assert result.code == EXIT_OK, result.err
    assert "a.txt" in result.out


@pytest.mark.parametrize(
    "arg", ["https://host/a.zip", "foo://x", "simplecache::https://h/a.zip"]
)
def test_a_url_without_fsspec_gets_an_install_hint(arg: str, no_fsspec: None) -> None:
    result = _run(["list", arg])
    assert result.code == EXIT_FAIL
    assert "needs fsspec" in result.err and "pip install fsspec" in result.err
    assert "Traceback" not in result.err


@pytest.mark.parametrize(
    "arg", ["C:\\missing.zip", "missing.zip", "\\\\srv\\share\\m.zip"]
)
def test_local_paths_never_import_fsspec(arg: str, no_fsspec: None) -> None:
    result = _run(["list", arg])
    assert result.code == EXIT_FAIL
    assert "no such file or directory" in result.err
    assert "fsspec" not in result.err


def test_an_unknown_protocol_is_a_local_path(memfs: Any) -> None:
    result = _run(["list", "nosuchproto://x.zip"])
    assert result.code == EXIT_FAIL
    # The local open's own error: ENOENT on POSIX, EINVAL on Windows (``:`` in a name).
    assert result.err.startswith("archivey: cannot open 'nosuchproto:"), result.err
    assert "fsspec" not in result.err


def test_a_known_protocol_with_a_missing_backend_is_a_dependency_error(
    memfs: Any,
) -> None:
    from fsspec.registry import known_implementations, register_implementation

    register_implementation(
        "archiveytestnopkg",
        "archivey_no_such_module.FS",
        errtxt="Install archivey-no-such-package to read archiveytestnopkg URLs",
    )
    try:
        result = _run(["list", "archiveytestnopkg://bucket/a.zip"])
    finally:
        known_implementations.pop("archiveytestnopkg", None)
    assert result.code == EXIT_FAIL
    assert "needs a package that is not installed" in result.err
    assert "archivey-no-such-package" in result.err
    assert "no such file or directory" not in result.err


def _raiser(error: BaseException) -> Any:
    def cat_file(
        self: Any, path: str, start: Any = None, end: Any = None, **kw: Any
    ) -> Any:
        raise error

    return cat_file


def _register_failing_fs(protocol: str, error: BaseException) -> Any:
    from fsspec.implementations.memory import MemoryFileSystem
    from fsspec.registry import register_implementation

    class Failing(MemoryFileSystem):
        pass

    Failing.protocol = (protocol,)
    prefix = f"{protocol}://"

    def strip(cls: Any, path: str) -> str:
        return MemoryFileSystem._strip_protocol(path.removeprefix(prefix))

    Failing._strip_protocol = classmethod(strip)  # type: ignore[method-assign,assignment]
    Failing.cat_file = _raiser(error)  # type: ignore[method-assign]
    register_implementation(protocol, Failing, clobber=True)
    return Failing


def test_a_backend_oserror_is_a_clean_failure(memfs: Any) -> None:
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))
    _register_failing_fs("archiveytestoserror", ConnectionResetError("peer went away"))
    from fsspec.registry import _registry as registry

    try:
        result = _run(["list", "archiveytestoserror://cli-urls/data.zip"])
    finally:
        registry.pop("archiveytestoserror", None)
    assert result.code == EXIT_FAIL
    assert "peer went away" in result.err
    assert "Traceback" not in result.err


def test_an_unlisted_backend_exception_propagates(memfs: Any) -> None:
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))
    _register_failing_fs("archiveytestruntime", RuntimeError("backend bug"))
    from fsspec.registry import _registry as registry

    try:
        with pytest.raises(RuntimeError, match="backend bug"):
            main(["list", "archiveytestruntime://cli-urls/data.zip"])
    finally:
        registry.pop("archiveytestruntime", None)


# --- labels and names -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pw@host/a.zip?X-Amz-Signature=abc#frag",
        "http://host:8080/path/a.tar.gz?sig=x%2Fy",
        "s3://bucket/key?with=question.zip",
        "s3://key:secret@bucket/a.zip",
        "memory://a/b.zip",
        "/local/path.zip",
        "HTTPS://Host/A.zip?q",
        "ftp://u@h/x#y",
    ],
)
def test_display_url_matches_the_library_policy(url: str) -> None:
    from archivey.internal.remote import display_url

    assert sources.display_url(url) == display_url(url)


def test_chain_labels_sanitize_each_link() -> None:
    url = "zip://inner.tar::https://u:p@host/o.zip?sig=s"
    assert sources.url_label(url) == "zip://inner.tar::https://host/o.zip"


@pytest.mark.parametrize(
    ("url", "name"),
    [
        ("https://host/data.tar.gz?signature=secret#part", "data.tar.gz"),
        ("https://u:p@host/dir/a%20b.tar.gz", "a%20b.tar.gz"),
        ("https://host/", ""),
        ("https://host", ""),
        ("s3://bucket/key?x.zip", "key?x.zip"),
        ("https://host/..\\..\\x.tar.gz", "..\\..\\x.tar.gz"),
    ],
)
def test_url_file_names(url: str, name: str) -> None:
    assert sources.url_file_name(url, None) == name


class _Chain:
    path = "inner/sub.tar"


def test_chain_file_name_comes_from_the_open_file() -> None:
    assert (
        sources.url_file_name("zip://inner/sub.tar::memory://o.zip", _Chain())
        == "sub.tar"
    )


@pytest.mark.parametrize(
    ("name", "fmt", "stem", "windows"),
    [
        ("data.tar.gz", ArchiveFormat.TAR_GZ, "data", False),
        ("", ArchiveFormat.ZIP, "archive", False),
        (".tar.gz", ArchiveFormat.TAR_GZ, "archive", False),
        ("...zip", ArchiveFormat.ZIP, "archive", False),
        ("..\\..\\x.tar.gz", ArchiveFormat.TAR_GZ, "archive", False),
        ("..\\..\\x.tar.gz", ArchiveFormat.TAR_GZ, "archive", True),
        ("a:b.tar.gz", ArchiveFormat.TAR_GZ, "archive", False),
        ("a?b*.tar.gz", ArchiveFormat.TAR_GZ, "a?b*", False),
        ("a?b*.tar.gz", ArchiveFormat.TAR_GZ, "archive", True),
        ("a%20b.tar.gz", ArchiveFormat.TAR_GZ, "a%20b", False),
        ("%5C.tar.gz", ArchiveFormat.TAR_GZ, "%5C", True),
        ("con.zip", ArchiveFormat.ZIP, "archive", True),
        ("com1.x.zip", ArchiveFormat.ZIP, "archive", True),
        ("con.zip", ArchiveFormat.ZIP, "con", False),
        ("trail .zip", ArchiveFormat.ZIP, "archive", True),
        ("trail..zip", ArchiveFormat.ZIP, "archive", True),
        ("bell\x07.zip", ArchiveFormat.ZIP, "archive", False),
    ],
)
def test_url_stems_are_one_safe_segment(
    name: str,
    fmt: ArchiveFormat,
    stem: str,
    windows: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32" if windows else "linux")
    assert _archive_stem(UrlName(name), format=fmt) == stem


def test_local_names_keep_their_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    # The URL checks do not reach a local path: a reserved Windows device name in a
    # local file name keeps the existing local naming rules.
    monkeypatch.setattr(sys, "platform", "win32")
    assert _archive_stem(Path("con.tar.gz"), format=ArchiveFormat.TAR_GZ) == "con"


# --- HTTP -----------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    """Serves ``files`` with range support; a path in ``poison`` answers 403 for any
    range that touches its ``(start, end)`` span. While ``ignore_ranges[0]`` is not
    zero, a range request gets the whole file with ``200``, as a CDN node that ignores
    ``Range`` sends it (each such answer counts it down; below zero, it never stops).
    ``ranges`` records each range request's header."""

    files: ClassVar[dict[str, bytes]] = {}
    poison: ClassVar[dict[str, tuple[int, int]]] = {}
    agents: ClassVar[list[str]] = []
    ignore_ranges: ClassVar[list[int]] = [0]
    # A ``Content-Range`` header to send instead of the right one, on every 206
    # (``""``: none at all), and a body to send instead of the range's bytes.
    content_range: ClassVar[list[str | None]] = [None]
    body_206: ClassVar[list[bytes | None]] = [None]
    # On a 206: answer at most this many bytes (a valid short range); declare this
    # many in Content-Range whatever the body holds; name this total size.
    max_206: ClassVar[list[int | None]] = [None]
    declare_206: ClassVar[list[int | None]] = [None]
    total_206: ClassVar[list[int | None]] = [None]
    # Serve the file gzip-encoded (ranges count in the encoded bytes) to a request
    # whose Accept-Encoding allows gzip, as a server that negotiates encoding does.
    gzip_if_allowed: ClassVar[list[bool]] = [False]
    # Answer every range request with this status and Content-Range, and no body.
    status_override: ClassVar[list[tuple[int, str] | None]] = [None]
    ranges: ClassVar[list[str]] = []

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _body(self) -> bytes | None:
        self.agents.append(self.headers.get("User-Agent", ""))
        path = self.path.partition("?")[0]
        data = self.files.get(path)
        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        return data

    def do_HEAD(self) -> None:
        data = self._body()
        if data is None:
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_GET(self) -> None:
        data = self._body()
        if data is None:
            return
        gzipped = self.gzip_if_allowed[0] and "gzip" in self.headers.get(
            "Accept-Encoding", ""
        )
        if gzipped:
            data = gzip.compress(data, mtime=0)
        start, end = 0, len(data) - 1
        ranged = self.headers.get("Range")
        if ranged:
            self.ranges.append(ranged)
        if ranged and self.status_override[0] is not None:
            status, header = self.status_override[0]
            self.send_response(status)
            self.send_header("Content-Range", header)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if ranged and self.ignore_ranges[0] != 0:
            self.ignore_ranges[0] -= 1
            ranged = None
        if ranged:
            first, _, last = ranged.removeprefix("bytes=").partition("-")
            start = int(first)
            end = min(int(last), len(data) - 1) if last else len(data) - 1
            if start >= len(data):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(data)}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.max_206[0] is not None:
                end = min(end, start + self.max_206[0] - 1)
        span = self.poison.get(self.path.partition("?")[0])
        if span is not None and start < span[1] and end >= span[0]:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(206 if ranged else 200)
        if ranged:
            header = self.content_range[0]
            declared = end
            if self.declare_206[0] is not None:
                declared = start + self.declare_206[0] - 1
            total = self.total_206[0] or len(data)
            if header != "":
                self.send_header(
                    "Content-Range", header or f"bytes {start}-{declared}/{total}"
                )
        if gzipped:
            self.send_header("Content-Encoding", "gzip")
        body = data[start : end + 1]
        if ranged and self.body_206[0] is not None:
            body = self.body_206[0]
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client stopped reading a body it did not need


@pytest.fixture
def http_base() -> Iterator[str]:
    pytest.importorskip("aiohttp")
    pytest.importorskip("fsspec")
    _Handler.files, _Handler.poison, _Handler.agents = {}, {}, []
    _Handler.ignore_ranges[0] = 0
    _Handler.status_override[0] = None
    _Handler.content_range[0] = None
    _Handler.body_206[0] = None
    _Handler.max_206[0] = _Handler.declare_206[0] = _Handler.total_206[0] = None
    _Handler.gzip_if_allowed[0] = False
    _Handler.ranges.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


SECRET = "X-Amz-Signature=s3cr3t%2Fpart"


def test_http_info_prints_a_sanitized_url(http_base: str) -> None:
    _Handler.files["/data.zip"] = _zip_bytes(TWO)
    host = http_base.removeprefix("http://")
    result = _run(["info", f"http://user:pw@{host}/data.zip?{SECRET}#frag"])
    assert result.code == EXIT_OK, result.err
    assert f"path:        http://{host}/data.zip\n" in result.out
    assert "s3cr3t" not in result.out + result.err
    assert "pw@" not in result.out + result.err


def test_http_smart_extraction_names_the_folder_from_the_url_path(
    http_base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _Handler.files["/data.tar.gz"] = gzip.compress(_tar_bytes(TWO))
    monkeypatch.chdir(tmp_path)
    result = _run(["x", f"{http_base}/data.tar.gz?{SECRET}#part", "--hide-progress"])
    assert result.code == EXIT_OK, result.err
    assert sorted(os.listdir(tmp_path / "data")) == ["a.txt", "b.txt"]
    assert "s3cr3t" not in result.err


def test_http_404_on_a_signed_url_hides_the_signature(http_base: str) -> None:
    result = _run(["list", f"{http_base}/missing.zip?{SECRET}"])
    assert result.code == EXIT_FAIL
    assert f"cannot open '{http_base}/missing.zip': no such file" in result.err
    assert "s3cr3t" not in result.err
    assert "Traceback" not in result.err


def test_http_403_during_a_member_read_keeps_partial_output(
    http_base: str, capfdbinary: pytest.CaptureFixture[bytes]
) -> None:
    first = b"first member\n"
    big = os.urandom(6 << 20)
    data = _zip_bytes({"first.txt": first, "big.bin": big}, stored=True)
    _Handler.files["/flaky.zip"] = data
    at = data.index(big[:64])
    _Handler.poison["/flaky.zip"] = (at + (3 << 20), at + (3 << 20) + 1)
    err = io.StringIO()
    code = main(["cat", f"{http_base}/flaky.zip?{SECRET}", "*"], err=err)
    assert code == EXIT_FAIL
    out = capfdbinary.readouterr().out
    assert out.startswith(first)
    assert len(out) < len(first) + len(big)
    text = err.getvalue()
    assert "HTTP 403" in text, text
    assert f"{http_base}/flaky.zip" in text
    assert "s3cr3t" not in text and "s3cr3t/part" not in text
    assert "Traceback" not in text


def test_http_403_at_setup_is_a_clean_failure(http_base: str) -> None:
    data = _zip_bytes(TWO)
    _Handler.files["/denied.zip"] = data
    _Handler.poison["/denied.zip"] = (0, len(data))
    result = _run(["info", f"{http_base}/denied.zip?{SECRET}"])
    assert result.code == EXIT_FAIL
    assert "403" in result.err
    assert "s3cr3t" not in result.err
    assert "Traceback" not in result.err


# --- review round 1 -------------------------------------------------------------------


class _FullDisk(io.RawIOBase):
    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        raise OSError(28, "No space left on device")


def test_a_local_write_error_is_not_blamed_on_the_url(memfs: Any) -> None:
    memfs.pipe("/cli-urls/data.zip", _zip_bytes(TWO))
    out = io.TextIOWrapper(io.BufferedWriter(_FullDisk(), buffer_size=1))
    err = io.StringIO()
    code = main(["cat", "memory://cli-urls/data.zip", "a.txt"], out=out, err=err)
    assert code == EXIT_FAIL
    assert "No space left on device" in err.getvalue()
    assert "memory://" not in err.getvalue()


def test_info_prints_the_identity_of_a_url_that_fails_to_open(memfs: Any) -> None:
    # A 7z signature header with nothing behind it: detection knows the format, and
    # the open fails with an ArchiveyError.
    memfs.pipe("/cli-urls/broken.7z", b"7z\xbc\xaf\x27\x1c" + bytes(64))
    result = _run(["info", "memory://cli-urls/broken.7z"])
    assert result.code == EXIT_FAIL
    assert "path:        memory://cli-urls/broken.7z" in result.out, result.err
    assert "format:      7z" in result.out


def _closed_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_http_refused_connection_is_not_a_missing_object(http_base: str) -> None:
    result = _run(["list", f"http://127.0.0.1:{_closed_port()}/x.zip?{SECRET}"])
    assert result.code == EXIT_FAIL
    assert "no such file" not in result.err, result.err
    assert "s3cr3t" not in result.err
    assert "Traceback" not in result.err


def test_https_to_a_plain_server_is_not_a_missing_object(http_base: str) -> None:
    _Handler.files["/data.zip"] = _zip_bytes(TWO)
    url = http_base.replace("http://", "https://")
    result = _run(["list", f"{url}/data.zip?{SECRET}"])
    assert result.code == EXIT_FAIL
    assert "no such file" not in result.err, result.err
    assert "s3cr3t" not in result.err
    assert "Traceback" not in result.err


def test_http_requests_send_an_archivey_user_agent(http_base: str) -> None:
    import archivey

    _Handler.files["/data.zip"] = _zip_bytes(TWO)
    for url in (f"{http_base}/data.zip", f"simplecache::{http_base}/data.zip"):
        _Handler.agents.clear()
        result = _run(["list", url])
        assert result.code == EXIT_OK, result.err
        assert _Handler.agents
        assert set(_Handler.agents) == {f"archivey/{archivey.__version__}"}


def test_a_configured_user_agent_and_client_options_are_kept(
    http_base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fsspec.config import conf

    _Handler.files["/data.zip"] = _zip_bytes(TWO)
    configured = {
        "client_kwargs": {"headers": {"user-agent": "mine/1", "X-Extra": "1"}}
    }
    monkeypatch.setitem(conf, "http", configured)
    options = sources._http_options(f"{http_base}/data.zip")
    assert options["http"]["client_kwargs"]["headers"] == {
        "user-agent": "mine/1",
        "X-Extra": "1",
    }
    assert configured == {
        "client_kwargs": {"headers": {"user-agent": "mine/1", "X-Extra": "1"}}
    }
    assert _run(["list", f"{http_base}/data.zip"]).code == EXIT_OK
    assert set(_Handler.agents) == {"mine/1"}


# --- review round 2 -------------------------------------------------------------------

SIGNED = "http://user:pw@10.255.255.1/d.zip?X-Amz-Signature=s3cr3t%2Fpart&a=b"


@pytest.fixture
def resolved_signed(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A run that resolved ``SIGNED``, without any network."""

    class _Stub:
        path = SIGNED

    monkeypatch.setitem(sources._resolved, SIGNED, _Stub())
    sources._register_redactions(SIGNED)
    try:
        yield
    finally:
        sources.reset()


def test_a_reencoded_url_in_aiohttp_text_is_redacted(resolved_signed: None) -> None:
    aiohttp = pytest.importorskip("aiohttp")
    yarl = pytest.importorskip("yarl")
    reencoded = str(yarl.URL(SIGNED, encoded=False).with_user(None))
    assert "s3cr3t/part" in reencoded  # the shape aiohttp prints
    # The 3.9 floor's base classes of ConnectionTimeoutError and InvalidUrlClientError.
    timeout = aiohttp.ServerTimeoutError(f"Connection timeout to host {reencoded}")
    wrapped = FileNotFoundError(SIGNED)
    wrapped.__cause__ = timeout
    text = sources.remote_error_text(wrapped)
    assert text is not None and "ServerTimeoutError" in text
    assert "s3cr3t" not in text and "pw" not in text
    invalid = aiohttp.InvalidURL(reencoded)
    shown = sources.http_error_text(invalid)
    assert shown is not None and "s3cr3t" not in shown


def test_an_empty_cause_is_named_by_its_type(resolved_signed: None) -> None:
    wrapped = FileNotFoundError(SIGNED)
    wrapped.__cause__ = TimeoutError()
    assert (
        sources.remote_error_text(wrapped) == "http://10.255.255.1/d.zip: TimeoutError"
    )


def test_url_tokens_are_left_alone_in_a_local_run() -> None:
    sources.reset()
    text = "member http://x/y?z=1 is odd"
    assert sources.redact(text) == text


@pytest.mark.parametrize(
    ("sections", "url", "headers"),
    [
        (
            {
                "http": {
                    "client_kwargs": {"headers": {"X-Auth": "tok"}, "trust_env": True}
                }
            },
            "https://h/x.zip",
            {"X-Auth": "tok", "User-Agent": "archivey/{v}"},
        ),
        (
            {"https": {"client_kwargs": {"headers": {"User-Agent": "mine/1"}}}},
            "http://h/x.zip",
            {"User-Agent": "mine/1"},
        ),
        (
            {
                "http": {"client_kwargs": {"headers": {"A": "1"}}},
                "https": {"client_kwargs": {"headers": {"B": "2"}}},
            },
            "http://h/x.zip",
            {"B": "2", "User-Agent": "archivey/{v}"},
        ),
    ],
)
def test_http_options_read_both_http_sections_as_fsspec_does(
    sections: dict[str, Any],
    url: str,
    headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import archivey

    pytest.importorskip("fsspec")
    from fsspec.config import conf

    monkeypatch.delitem(conf, "http", raising=False)
    monkeypatch.delitem(conf, "https", raising=False)
    for name, section in sections.items():
        monkeypatch.setitem(conf, name, section)
    protocol = url.partition(":")[0]
    client = sources._http_options(url)[protocol]["client_kwargs"]
    expected = {k: v.format(v=archivey.__version__) for k, v in headers.items()}
    assert client["headers"] == expected
    if "trust_env" in str(sections):
        assert client["trust_env"] is True


# --- a server that ignores range requests ------------------------------------------


def test_http_a_range_ignored_now_and_then_is_asked_again(http_base: str) -> None:
    # A CDN node answered with the whole file twice, then honoured ranges: the read
    # asks again and the listing succeeds.
    big = {"a.bin": os.urandom(300_000)}
    _Handler.files["/data.zip"] = _zip_bytes(big, stored=True)
    _Handler.ignore_ranges[0] = 2
    result = _run(["t", f"{http_base}/data.zip"])
    assert result.code == EXIT_OK, result.err
    assert "1 OK" in result.err
    # The first answer (from byte 0) was used as it came; the second, past byte 0,
    # was asked for again.
    assert _Handler.ranges[1] == _Handler.ranges[2]
    assert not _Handler.ranges[1].startswith("bytes=0-")


def test_http_a_server_that_never_honours_ranges_is_refused(http_base: str) -> None:
    # Larger than the first window, so the listing needs bytes past byte 0 (a small
    # file comes whole with the first request and is listed).
    big = {"a.bin": os.urandom(300_000)}
    _Handler.files["/data.zip"] = _zip_bytes(big, stored=True)
    _Handler.ignore_ranges[0] = -1
    result = _run([f"{http_base}/data.zip"])
    assert result.code == EXIT_FAIL
    assert "does not honour range requests" in result.err
    # One request past byte 0 is sent three times, then refused.
    past_start = [r for r in _Handler.ranges if not r.startswith("bytes=0-")]
    assert len(past_start) == 3 and len(set(past_start)) == 1


def test_http_a_whole_body_answer_from_byte_0_is_read_only_as_far_as_needed(
    http_base: str,
) -> None:
    import tracemalloc

    import fsspec

    from archivey.internal.remote import RangeSource, WindowPool

    data = os.urandom(1 << 20) * 32  # 32 MiB
    _Handler.files["/big.bin"] = data
    _Handler.ignore_ranges[0] = -1
    of = fsspec.open(f"{http_base}/big.bin")
    src = RangeSource.from_open_file(of, pool=WindowPool(), max_read_through=1 << 20)
    tracemalloc.start()
    try:
        assert src.read(100) == data[:100]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        src.close()
    # The first window (64 KiB), not the 32 MiB body.
    assert peak < 4 << 20


@pytest.mark.parametrize(
    "header",
    [
        "bytes 0-99/1000",
        "bytes */1000",
        "garbage",
        "",  # no Content-Range at all
        # A superscript two, which ``str.isdigit`` takes and ``int`` refuses; sent as
        # its UTF-8 bytes (``http.server`` writes header values as latin-1).
        "bytes \u00b2-9/100".encode().decode("latin-1"),
    ],
)
def test_http_a_partial_answer_for_other_bytes_is_refused(
    http_base: str, header: str
) -> None:
    import fsspec

    from archivey.internal.remote import RangeSource, WindowPool

    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.content_range[0] = header
    of = fsspec.open(f"{http_base}/big.bin")
    src = RangeSource.from_open_file(of, pool=WindowPool(), max_read_through=1 << 20)
    try:
        src.seek(100_000)
        with pytest.raises(OSError, match="does not match it"):
            src.read(10)
    finally:
        src.close()


def test_http_a_partial_answer_longer_than_its_range_is_not_read_whole(
    http_base: str,
    reporting: None,
) -> None:
    import tracemalloc

    import fsspec

    from archivey.internal.remote import RangeSource, WindowPool

    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    # A correct Content-Range over a 32 MiB body.
    _Handler.body_206[0] = b"\0" * (32 << 20)
    of = fsspec.open(f"{http_base}/big.bin")
    src = RangeSource.from_open_file(of, pool=WindowPool(), max_read_through=1 << 20)
    tracemalloc.start()
    try:
        src.seek(100_000)
        with pytest.raises(OSError, match="sent more"):
            src.read(10)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        src.close()
    assert peak < 4 << 20


# The reports of the range sources ``_range_source`` makes, while the ``reporting``
# fixture runs with ``on_source_read`` set; ``None`` while it runs without.
_REPORTS: list[list[SourceProgress]] | None = None


@pytest.fixture(params=[False, True], ids=["unreported", "reported"])
def reporting(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Run an HTTP adapter test without and with ``on_source_read``: with it, each
    answer's body is read one chunk per call, and the outcome must be the same.

    The reported arm reads in 4 KiB chunks, so the answers of these tests (up to a few
    hundred KiB) report inside themselves too. At teardown each request's reports
    must be well formed: a report inside an answer never claims more than the
    request's range, nor more than the answer brought in the end. A hook that
    reported ``received + 1``, or counted the extra byte read past a ``206``'s
    declared length, fails here.
    """
    global _REPORTS
    if request.param:
        from archivey.internal import _http_range

        monkeypatch.setattr(_http_range, "CHUNK", _SMALL_CHUNK)
    _REPORTS = [] if request.param else None
    try:
        yield
        for calls in _REPORTS or ():
            _check_reports(calls)
    finally:
        _REPORTS = None


_SMALL_CHUNK = 4096


def _check_reports(calls: list[SourceProgress]) -> None:
    totals = [c.bytes_read for c in calls]
    assert totals == sorted(totals)
    by_request: dict[int, list[SourceProgress]] = {}
    for c in calls:
        assert c.requests is not None
        assert c.request_start is not None and c.request_end is not None
        assert c.request_received is not None
        assert 0 <= c.request_received <= c.request_end - c.request_start
        assert c.position == c.request_start + c.request_received
        by_request.setdefault(c.requests, []).append(c)
    for reports in by_request.values():
        done = [c for c in reports if c.request_done]
        within = [c for c in reports if not c.request_done and c.request_received]
        received = [c.request_received for c in within]
        assert received == sorted(received)
        # Chunks are gathered whole until the answer ends, so a report inside it
        # comes after a whole number of them.
        assert all(r % _SMALL_CHUNK == 0 for r in received)  # type: ignore[operator]
        if done:
            assert all(r < done[-1].request_received for r in received)  # type: ignore[operator]
            if done[-1].request_received > _SMALL_CHUNK:  # type: ignore[operator]
                # An answer longer than one chunk reported before it ended.
                assert within


def _range_source(url: str) -> Any:
    import fsspec

    from archivey.internal.read_progress import SourceReadReporter
    from archivey.internal.remote import RangeSource, WindowPool

    src = RangeSource.from_open_file(
        fsspec.open(url), pool=WindowPool(), max_read_through=1 << 20
    )
    if _REPORTS is not None:
        calls: list[SourceProgress] = []
        _REPORTS.append(calls)
        src.progress = SourceReadReporter(calls.append, url, src.size)
    return src


def test_http_a_body_longer_than_its_declared_span_is_refused(
    http_base: str, reporting: None
) -> None:
    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.declare_206[0] = 10  # declares 10 bytes, sends the whole window
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        with pytest.raises(OSError, match="declared 10 bytes"):
            src.read(10)
    finally:
        src.close()


def test_http_a_206_body_shorter_than_declared_is_refused(
    http_base: str, reporting: None
) -> None:
    # The body ends 10 000 bytes in, not on a chunk boundary: the short last chunk is
    # the body's end, so the reported arm makes no report for it (the teardown checks
    # that each report inside an answer comes after whole chunks).
    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.body_206[0] = b"x" * 10_000
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        with pytest.raises(OSError, match="sent 10000"):
            src.read(20_000)
    finally:
        src.close()


def test_http_a_valid_short_range_is_continued(http_base: str, reporting: None) -> None:
    # The server answers each range with at most 4 KiB, as RFC 9110 allows: a read
    # longer than that asks for the rest from where each answer stopped.
    data = bytes(range(256)) * 1024
    _Handler.files["/big.bin"] = data
    _Handler.max_206[0] = 4096
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        assert src.read(20_000) == data[100_000:120_000]
    finally:
        src.close()


def test_http_short_ranges_do_not_spend_the_budget_on_read_ahead(
    http_base: str,
    reporting: None,
) -> None:
    # A 10-byte read wants a 64 KiB window; 4 KiB answers cover the read in one
    # request, and the window keeps what came rather than asking 16 times.
    data = bytes(range(256)) * 1024
    _Handler.files["/big.bin"] = data
    _Handler.max_206[0] = 4096
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        before = src.fetch_count
        assert src.read(10) == data[100_000:100_010]
        assert src.fetch_count - before == 1
    finally:
        src.close()


@pytest.mark.parametrize(
    "offsets",
    [
        pytest.param([256 * 1024 - 10], id="tail"),
        pytest.param([1000, 200_000], id="seek-past-a-gap"),
    ],
)
def test_http_short_ranges_before_the_read_are_skipped(
    http_base: str, offsets: list[int], reporting: None
) -> None:
    # A tail read plans its window to start up to 64 KiB before the read, and a
    # forward seek can extend a window across a gap. 4 KiB answers would spend the
    # budget on those bytes; the first short answer before the read goes to the read.
    data = bytes(range(256)) * 1024
    _Handler.files["/big.bin"] = data
    _Handler.max_206[0] = 4096
    src = _range_source(f"{http_base}/big.bin")
    try:
        for at in offsets:
            src.seek(at)
            before = src.fetch_count
            assert src.read(10) == data[at : at + 10]
            assert src.fetch_count - before <= 2
    finally:
        src.close()


def test_http_skipped_read_ahead_does_not_spend_the_reads_budget(
    http_base: str,
    reporting: None,
) -> None:
    # The last 32 KiB in 4 KiB answers takes eight answers from the read's offset,
    # the whole budget, after one answer of read-ahead before it that is dropped.
    from archivey.internal.remote import SHORT_RANGE_REQUESTS

    data = bytes(range(256)) * 1024
    _Handler.files["/big.bin"] = data
    _Handler.max_206[0] = 4096
    src = _range_source(f"{http_base}/big.bin")
    try:
        at = len(data) - 32 * 1024
        src.seek(at)
        before = src.fetch_count
        assert src.read(32 * 1024) == data[at:]
        assert src.fetch_count - before == 1 + SHORT_RANGE_REQUESTS
    finally:
        src.close()


def test_http_a_sequential_read_through_short_ranges(
    http_base: str, reporting: None
) -> None:
    # The planner's windows double to several MiB; a server that caps its answers
    # at 256 KiB still serves the whole object, one answer per window.
    data = os.urandom(1 << 20) * 16  # 16 MiB
    _Handler.files["/big.bin"] = data
    _Handler.max_206[0] = 256 * 1024
    src = _range_source(f"{http_base}/big.bin")
    try:
        out = bytearray()
        while chunk := src.read(64 * 1024):
            out += chunk
        assert out == data
    finally:
        src.close()


def test_http_a_server_that_answers_too_little_too_often_is_refused(
    http_base: str,
    reporting: None,
) -> None:
    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.max_206[0] = 1
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        with pytest.raises(OSError, match="with fewer than 4096 bytes each"):
            src.read(10)
    finally:
        src.close()


def test_http_a_server_that_caps_its_answers_serves_a_large_read(
    http_base: str,
    reporting: None,
) -> None:
    # A server may cap every answer (16 KiB here). Each answer makes real progress,
    # so a read many times the cap is continued to its end, as a local read is.
    data = bytes(range(256)) * (12 * 1024)
    _Handler.files["/big.bin"] = data
    _Handler.max_206[0] = 16 * 1024
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(1000)
        assert src.read(len(data)) == data[1000:]
    finally:
        src.close()


def test_http_a_416_after_the_object_shrank_is_a_changed_object(
    http_base: str,
    reporting: None,
) -> None:
    from archivey.exceptions import SourceChangedError

    data = bytes(range(256)) * 1024
    _Handler.files["/big.bin"] = data
    src = _range_source(f"{http_base}/big.bin")
    try:
        _Handler.files["/big.bin"] = data[:1000]
        src.seek(100_000)
        with pytest.raises(SourceChangedError, match="has no byte 100000 of 1000"):
            src.read(10)
    finally:
        src.close()


def test_http_a_416_naming_the_same_size_is_refused_not_a_change(
    http_base: str,
    reporting: None,
) -> None:
    from archivey.exceptions import SourceChangedError

    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.status_override[0] = (416, "bytes */262144")
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        with pytest.raises(OSError, match="refused bytes 100000") as caught:
            src.read(10)
        assert not isinstance(caught.value, SourceChangedError)
    finally:
        src.close()


@pytest.mark.parametrize(
    ("status", "content_range", "error"),
    [
        pytest.param(
            416, "bytes */" + "9" * 5000, "changed while it was read", id="416"
        ),
        pytest.param(
            206, "bytes 100000-100009/" + "9" * 5000, "does not match it", id="206"
        ),
    ],
)
def test_http_a_size_of_thousands_of_digits_is_not_a_bare_value_error(
    http_base: str, status: int, content_range: str, error: str, reporting: None
) -> None:
    # ``int`` refuses over 4300 digits with a bare ValueError; such a header is
    # refused as malformed first.
    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.status_override[0] = (status, content_range)
    from archivey import ArchiveyError

    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        with pytest.raises((OSError, ArchiveyError), match=error):
            src.read(10)
    finally:
        src.close()


def test_http_a_whole_answer_of_another_size_is_a_changed_object(
    http_base: str,
    reporting: None,
) -> None:
    # A server that ignores ranges answers a read from byte 0 with the whole object;
    # a Content-Length other than the size read at open is another object.
    from archivey.exceptions import SourceChangedError

    _Handler.files["/small.bin"] = b"a" * 85
    src = _range_source(f"{http_base}/small.bin")
    try:
        _Handler.files["/small.bin"] = b"b" * 129
        _Handler.ignore_ranges[0] = -1
        with pytest.raises(SourceChangedError, match="129"):
            src.read(10)
    finally:
        src.close()


def test_http_a_206_naming_another_size_is_a_changed_object(
    http_base: str, reporting: None
) -> None:
    from archivey.exceptions import SourceChangedError

    _Handler.files["/big.bin"] = bytes(range(256)) * 1024
    _Handler.total_206[0] = 999_999
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(100_000)
        with pytest.raises(SourceChangedError, match="999999"):
            src.read(10)
    finally:
        src.close()


def test_http_ranges_ask_for_the_bytes_as_stored(
    http_base: str, reporting: None
) -> None:
    # A server that gzips for a client that allows it counts ranges in the gzipped
    # bytes; the size fsspec read at open is the stored one. Asking for identity
    # keeps the two in the same coordinates.
    data = os.urandom(200_000)
    _Handler.files["/big.bin"] = data
    _Handler.gzip_if_allowed[0] = True
    src = _range_source(f"{http_base}/big.bin")
    try:
        src.seek(150_000)
        assert src.read(10) == data[150_000:150_010]
    finally:
        src.close()


def test_http_a_session_wrapper_with_only_public_methods(http_base: str) -> None:
    # fsspec lets a caller pass its own client factory; a wrapper that exposes only
    # the session's public request methods still reads.
    import aiohttp
    from fsspec.implementations.http import HTTPFileSystem

    from archivey.internal.remote import RangeSource, WindowPool

    class Wrapper:
        def __init__(self, session: aiohttp.ClientSession) -> None:
            self._session = session

        def get(self, *args: Any, **kw: Any) -> Any:
            return self._session.get(*args, **kw)

        def head(self, *args: Any, **kw: Any) -> Any:
            return self._session.head(*args, **kw)

        async def close(self) -> None:
            await self._session.close()

    async def get_client(**kw: Any) -> Wrapper:
        return Wrapper(aiohttp.ClientSession(**kw))

    data = bytes(range(256)) * 1024
    _Handler.files["/big.bin"] = data
    fs = HTTPFileSystem(get_client=get_client, skip_instance_cache=True)
    from fsspec.core import OpenFile

    src = RangeSource.from_open_file(
        OpenFile(fs, f"{http_base}/big.bin"),
        pool=WindowPool(),
        max_read_through=1 << 20,
    )
    try:
        src.seek(100_000)
        assert src.read(10) == data[100_000:100_010]
    finally:
        src.close()


def test_http_a_large_answer_reports_as_it_comes_in(http_base: str) -> None:
    from archivey import ArchiveyConfig, open_stream

    pytest.importorskip("fsspec")
    import fsspec

    data = os.urandom(5 << 20)
    _Handler.files["/big.bin.xz"] = lzma.compress(data, preset=0)
    calls: list[SourceProgress] = []
    threads: set[int] = set()

    def record(progress: SourceProgress) -> None:
        calls.append(progress)
        threads.add(threading.get_ident())

    config = ArchiveyConfig(on_source_read=record)
    with open_stream(fsspec.open(f"{http_base}/big.bin.xz"), config=config) as stream:
        assert stream.read() == data
    # Every report, those inside an answer included, ran on this thread, never on
    # fsspec's event loop thread (a hook called from ``read_chunk`` would).
    assert threads == {threading.get_ident()}
    within = [c for c in calls if c.request_done is False and c.request_received]
    # Each MiB of an answer reports, before the answer ends: the requests grow to
    # 2 MiB and more, so a 5 MiB file has at least two such reports.
    assert len(within) >= 2
    for c in within:
        assert c.position == c.request_start + c.request_received  # type: ignore[operator]
        assert c.request_received < c.request_end - c.request_start  # type: ignore[operator]
    assert calls[-1].request_done is True


class _Stop(Exception):
    pass


def test_http_a_stop_inside_an_answer_reaches_the_caller(
    http_base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey import ArchiveyConfig, open_stream

    pytest.importorskip("fsspec")
    import aiohttp
    import fsspec

    _Handler.files["/big.bin.xz"] = lzma.compress(os.urandom(5 << 20), preset=0)
    # Each GET answer aiohttp released. The answer the stop came inside must be
    # among them: without ``finish`` after the hook raised, it stays open.
    opened: list[object] = []
    released: list[object] = []
    request = aiohttp.ClientSession._request
    release = aiohttp.ClientResponse.release

    async def counted_request(self: Any, method: str, *args: Any, **kwargs: Any) -> Any:
        response = await request(self, method, *args, **kwargs)
        if method == "GET":
            opened.append(response)
        return response

    def counted_release(self: Any) -> Any:
        if self.method == "GET" and self not in released:
            released.append(self)
        return release(self)

    monkeypatch.setattr(aiohttp.ClientSession, "_request", counted_request)
    monkeypatch.setattr(aiohttp.ClientResponse, "release", counted_release)

    def stop(progress: SourceProgress) -> None:
        if progress.request_done is False and progress.request_received:
            raise _Stop

    config = ArchiveyConfig(on_source_read=stop)
    with (
        pytest.raises(_Stop),
        open_stream(fsspec.open(f"{http_base}/big.bin.xz"), config=config) as s,
    ):
        s.read()
    assert opened
    assert all(response in released for response in opened)
