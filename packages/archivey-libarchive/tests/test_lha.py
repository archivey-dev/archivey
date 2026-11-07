"""LHA through archivey-libarchive: libarchive's own test archives, read through
archivey, in a child process and in this one."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import signal
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import archivey_libarchive
from archivey import (
    ArchiveyConfig,
    CorruptionError,
    MemberType,
    ProcessIsolation,
    ResourceUnavailableError,
    StreamFormat,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from archivey_libarchive import _client, _formats, _libarchive, _protocol as proto

FIXTURES = Path(__file__).parent / "fixtures"
ISOLATIONS = list(ProcessIsolation)

FILE1 = b" " * 26 + b"file 1 contents\n" + b"hello\n" * 3
FILE2 = b" " * 26 + b"file 2 contents\n" + b"hello\n" * 6
TREE = {
    "dir/": (MemberType.DIRECTORY, None),
    "dir2/": (MemberType.DIRECTORY, None),
    "dir2/symlink1": (MemberType.SYMLINK, "../file1"),
    "dir2/symlink2": (MemberType.SYMLINK, "../file2"),
    "file1": (MemberType.FILE, FILE1),
    "file2": (MemberType.FILE, FILE2),
}
NO_LINKS = {k: v for k, v in TREE.items() if v[0] is not MemberType.SYMLINK}

try:
    _libarchive.load()
except _libarchive.LibraryUnavailable as exc:  # pragma: no cover - depends on host
    # CI installs libarchive for this suite: a skip there would hide its loss.
    if os.environ.get("CI") == "true":
        raise
    pytest.skip(str(exc), allow_module_level=True)

archivey_libarchive.register()


class _Pipe(io.RawIOBase):
    """A source that cannot seek, read in pieces of at most ``step`` bytes."""

    def __init__(self, data: bytes, step: int = 7) -> None:
        self._inner = io.BytesIO(data)
        self._step = step

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._inner.read(min(len(buffer), self._step))
        buffer[: len(data)] = data
        return len(data)


def _config(isolation: ProcessIsolation) -> ArchiveyConfig:
    return ArchiveyConfig(process_isolation=isolation)


def _contents(source: object, **kwargs: object) -> dict[str, object]:
    out: dict[str, object] = {}
    with open_archive(source, **kwargs) as archive:  # type: ignore[arg-type]
        for member in archive.members():
            if member.type is MemberType.FILE:
                out[member.name] = (member.type, archive.read(member))
            else:
                out[member.name] = (member.type, member.link_target)
    return out


@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("lha_lh0.lzh", TREE),
        ("lha_lh6.lzh", TREE),
        ("lha_lh7.lzh", TREE),
        ("lha_header0.lzh", TREE),
        ("lha_header1.lzh", TREE),
        ("lha_header2.lzh", TREE),
        ("lha_header3.lzh", NO_LINKS),
        ("lha_withjunk.lzh", TREE),
    ],
)
def test_libarchives_test_archives(
    name: str, expected: dict[str, object], isolation: ProcessIsolation
) -> None:
    path = FIXTURES / name
    assert detect_format(path).format == archivey_libarchive.LHA
    assert _contents(path, config=_config(isolation)) == expected


def test_a_member_carries_its_metadata() -> None:
    with open_archive(FIXTURES / "lha_lh6.lzh") as archive:
        file2 = archive.get("file2")
        assert file2.size == 78
        assert file2.mode == 0o666
        assert (file2.uid, file2.gid) == (1001, 1001)
        assert file2.modified is not None and file2.modified.year == 1970
        assert archive.get("dir/").mode == 0o750


def test_a_compressed_member_is_large_enough_to_matter() -> None:
    data = _contents(FIXTURES / "lha_bugfix_0.lzh")["f"]
    assert data[0] is MemberType.FILE
    assert hashlib.sha256(data[1]).hexdigest() == (  # type: ignore[arg-type]
        "5f59ec737fc007a0857687637352e03eb945ae15a178682f70c33b1599587e25"
    )


@pytest.mark.parametrize("name", ["lha_filename_cp932.lzh", "lha_filename_utf16.lzh"])
def test_names_libarchive_converts(name: str) -> None:
    names = set(_contents(FIXTURES / name))
    assert names & {"漢字.txt", "ÜÖÄüöä/テスト.txt"}


@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
def test_found_by_its_magic_and_read_from_a_pipe(isolation: ProcessIsolation) -> None:
    raw = (FIXTURES / "lha_lh6.lzh").read_bytes()
    assert detect_format(io.BytesIO(raw)).format == archivey_libarchive.LHA
    seen = {}
    with open_archive(_Pipe(raw), streaming=True, config=_config(isolation)) as archive:
        for member, stream in archive.stream_members():
            seen[member.name] = stream.read() if stream is not None else None
    assert seen["file1"] == FILE1
    assert seen["file2"] == FILE2


def test_members_read_out_of_order_and_again() -> None:
    with open_archive(FIXTURES / "lha_lh7.lzh") as archive:
        assert archive.read("file2") == FILE2
        assert archive.read("file1") == FILE1
        assert archive.read("file2") == FILE2
        assert archive.cost.access_cost.value == "solid"


def test_inside_gzip() -> None:
    raw = gzip.compress((FIXTURES / "lha_lh6.lzh").read_bytes())
    info = detect_format(io.BytesIO(raw))
    assert info.format.stream is StreamFormat.GZIP
    assert info.format.container is archivey_libarchive.LibarchiveContainer.LHA
    with open_archive(io.BytesIO(raw)) as archive:
        assert archive.read("file1") == FILE1


# --- damage ----------------------------------------------------------------------


def _crc16(data: bytes) -> int:
    """LHA's CRC-16 (polynomial 0xA001, reflected, starting at 0)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def _stored_lha(name: bytes, data: bytes) -> bytes:
    """A level-0 LHA archive of one ``-lh0-`` (stored) member."""
    body = (
        b"-lh0-"
        + struct.pack("<IIIBB", len(data), len(data), 0x5A2E_6000, 0x20, 0)
        + bytes([len(name)])
        + name
        + struct.pack("<H", _crc16(data))
    )
    return bytes([len(body), sum(body) & 0xFF]) + body + data + b"\0"


def test_a_stored_member() -> None:
    raw = _stored_lha(b"a.txt", b"stored bytes\n")
    assert _contents(io.BytesIO(raw)) == {"a.txt": (MemberType.FILE, b"stored bytes\n")}


@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
def test_a_damaged_stored_member_fails_its_crc(isolation: ProcessIsolation) -> None:
    raw = bytearray(_stored_lha(b"a.txt", b"stored bytes\n"))
    raw[raw.index(b"stored")] ^= 0x20
    with (
        open_archive(io.BytesIO(bytes(raw)), config=_config(isolation)) as archive,
        pytest.raises(CorruptionError, match="CRC"),
    ):
        archive.read("a.txt")


def test_damaged_compressed_data_is_corrupt() -> None:
    raw = bytearray((FIXTURES / "lha_lh6.lzh").read_bytes())
    raw[-30] ^= 0xFF
    with pytest.raises(CorruptionError):
        _contents(io.BytesIO(bytes(raw)))


@pytest.mark.parametrize("isolation", ISOLATIONS, ids=lambda i: i.name)
def test_a_cut_archive_is_truncated(isolation: ProcessIsolation) -> None:
    raw = (FIXTURES / "lha_lh6.lzh").read_bytes()[:300]
    with pytest.raises(TruncatedError):
        _contents(io.BytesIO(raw), config=_config(isolation))


# --- errors from libarchive ---------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "errno", "kind"),
    [
        ("Truncated LHa file body", 84, TruncatedError),
        ("Unsupported LHa compression method", 84, UnsupportedFeatureError),
        ("LHa data CRC error", 84, CorruptionError),
        ("Can't allocate memory", 12, ResourceUnavailableError),
    ],
)
def test_libarchive_errors_map_by_message(
    message: str, errno: int, kind: type[Exception]
) -> None:
    error = _formats.translate(_libarchive.LibarchiveError(-30, errno, message), "x")
    assert type(error) is kind
    assert message in str(error)


# --- the child process ------------------------------------------------------------


def _with_boot(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    monkeypatch.setattr(_client, "_BOOT", code.replace("{", "{{").replace("}", "}}"))


@pytest.mark.parametrize(
    ("sig", "kind"),
    [(signal.SIGSEGV, CorruptionError), (signal.SIGKILL, ResourceUnavailableError)],
)
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_child_that_dies(
    monkeypatch: pytest.MonkeyPatch, sig: signal.Signals, kind: type[Exception]
) -> None:
    _with_boot(monkeypatch, f"import os, signal; os.kill(os.getpid(), {int(sig)})")
    with pytest.raises(kind, match=sig.name):
        _contents(FIXTURES / "lha_lh6.lzh")


def test_a_child_that_breaks_the_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    _with_boot(
        monkeypatch,
        "import sys, struct; sys.stdout.buffer.write(struct.pack('<cI', b'K', 1 << 30))",
    )
    with pytest.raises(CorruptionError, match="over the limit"):
        _contents(FIXTURES / "lha_lh6.lzh")


_FAKE_CHILD = """
import base64, json, struct, sys
out, inp = sys.stdout.buffer, sys.stdin.buffer
def send(tag, body=b""):
    out.write(struct.pack("<cI", tag, len(body)) + body); out.flush()
def receive():
    tag, n = struct.unpack("<cI", inp.read(5)); return tag, inp.read(n)
receive(); send(b"K")
for reply in REPLIES:
    receive()
    send(reply[0], b"x" * ((1 << 20) + 4096) if reply[1] is None else reply[1])
receive()
"""
_HEADER = {
    "path": base64.b64encode(b"a.bin").decode(),
    "filetype": 0o100000,
    "perm": 0o174644,
    "size": 4,
}


def _fake_child(
    monkeypatch: pytest.MonkeyPatch, replies: list[tuple[bytes, bytes | None]]
) -> None:
    _with_boot(monkeypatch, f"REPLIES = {replies!r}\n" + _FAKE_CHILD)


def test_a_child_cannot_send_more_data_than_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    header = json.dumps(_HEADER).encode()
    # The largest message the protocol takes, past any read archivey asks for.
    _fake_child(monkeypatch, [(b"H", header), (b"D", None)])
    with pytest.raises(CorruptionError):
        _contents(FIXTURES / "lha_lh6.lzh")


def test_a_child_that_answers_out_of_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, [(b"D", b"x")])
    with pytest.raises(CorruptionError, match="unexpected reply"):
        _contents(FIXTURES / "lha_lh6.lzh")


def test_a_childs_mode_is_only_permission_bits(monkeypatch: pytest.MonkeyPatch) -> None:
    header = json.dumps(_HEADER).encode()
    _fake_child(
        monkeypatch, [(b"H", header), (b"D", b"data"), (b"D", b""), (b"E", b"")]
    )
    with open_archive(FIXTURES / "lha_lh6.lzh") as archive:
        (member,) = archive.members()
        assert member.mode == 0o4644


def test_a_damaged_header_is_corrupt() -> None:
    raw = bytearray(_stored_lha(b"a.txt", b"stored bytes\n"))
    raw[1] ^= 0xFF  # the header checksum
    with pytest.raises(CorruptionError, match="header sum error"):
        _contents(io.BytesIO(bytes(raw)), format=archivey_libarchive.LHA)


def test_a_member_read_to_its_end_is_verified() -> None:
    raw = _stored_lha(b"a.txt", b"stored bytes\n")
    with open_archive(io.BytesIO(raw)) as archive:
        (member,) = archive.members()
        archive.read(member)
        assert member.verified is Verification.CHECKSUM


def test_no_child_process_is_resource_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("spawning is refused here")

    monkeypatch.setattr(_client.subprocess, "Popen", refuse)
    with pytest.raises(ResourceUnavailableError, match="ProcessIsolation.NONE"):
        _contents(FIXTURES / "lha_lh6.lzh")
    # NONE needs no child.
    assert _contents(FIXTURES / "lha_lh6.lzh", config=_config(ProcessIsolation.NONE))[
        "file1"
    ] == (MemberType.FILE, FILE1)


def test_the_child_does_not_import_archivey() -> None:
    root = str(Path(archivey_libarchive.__file__).resolve().parent.parent)
    code = (
        f"import sys; sys.path.insert(0, {root!r}); "
        "import archivey_libarchive._worker; print('archivey' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, check=True, text=True
    )
    assert out.stdout.strip() == "False"


def test_the_protocol_refuses_bytes_where_a_name_belongs() -> None:
    with pytest.raises(proto.ProtocolError, match="path is not a string"):
        proto.unpack_json(b'{"path": 5}')
    header = {"path": b"\xff/a", "size": 3}
    assert proto.unpack_json(proto.pack_json(header)) == header


def test_without_libarchive_the_format_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing() -> None:
        raise _libarchive.LibraryUnavailable("no libarchive here")

    monkeypatch.setattr(_formats, "load", missing)
    with pytest.raises(UnsupportedFeatureError, match="no libarchive here"):
        _contents(FIXTURES / "lha_lh6.lzh")


def test_register_twice_is_harmless() -> None:
    archivey_libarchive.register()
    assert archivey_libarchive.libarchive_version().startswith("libarchive 3.")
