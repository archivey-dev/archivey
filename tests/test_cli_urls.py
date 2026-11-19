"""The CLI's archive argument as a URL, read through fsspec (``cli`` spec, URL inputs).

Most cases use fsspec's ``memory://`` file system. The HTTP cases run against a local
server that answers range requests, and skip where aiohttp is not installed (the
core-only CI leg). The dependency-absence cases need neither package and always run.
"""

from __future__ import annotations

import gzip
import io
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
from archivey.types import ArchiveFormat

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
    assert "no such file or directory" in result.err


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


def test_local_names_keep_their_rules() -> None:
    # The URL checks do not reach a local path: ``a:b`` is a valid POSIX file name.
    assert _archive_stem(Path("a:b.tar.gz"), format=ArchiveFormat.TAR_GZ) == "a:b"


# --- HTTP -----------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    """Serves ``files`` with range support; a path in ``poison`` answers 403 for any
    range that touches its ``(start, end)`` span."""

    files: ClassVar[dict[str, bytes]] = {}
    poison: ClassVar[dict[str, tuple[int, int]]] = {}
    agents: ClassVar[list[str]] = []

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
        start, end = 0, len(data) - 1
        ranged = self.headers.get("Range")
        if ranged:
            first, _, last = ranged.removeprefix("bytes=").partition("-")
            start = int(first)
            end = min(int(last), len(data) - 1) if last else len(data) - 1
        span = self.poison.get(self.path.partition("?")[0])
        if span is not None and start < span[1] and end >= span[0]:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(206 if ranged else 200)
        if ranged:
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
        self.send_header("Content-Length", str(end - start + 1))
        self.end_headers()
        self.wfile.write(data[start : end + 1])


@pytest.fixture
def http_base() -> Iterator[str]:
    pytest.importorskip("aiohttp")
    pytest.importorskip("fsspec")
    _Handler.files, _Handler.poison, _Handler.agents = {}, {}, []
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
    timeout = aiohttp.ConnectionTimeoutError(f"Connection timeout to host {reencoded}")
    wrapped = FileNotFoundError(SIGNED)
    wrapped.__cause__ = timeout
    text = sources.remote_error_text(wrapped)
    assert text is not None and "ConnectionTimeoutError" in text
    assert "s3cr3t" not in text and "pw" not in text
    invalid = aiohttp.InvalidUrlClientError(reencoded)
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
