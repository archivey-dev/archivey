"""RAR read front to back from a source that cannot seek: the header walk
(``rar_forward``) and the reader that streams members through rolling volumes
(``rar_forward_reader``)."""

from __future__ import annotations

import hashlib
import io
import os
import struct
import subprocess
import threading
import time
import zlib
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import (
    ArchiveMember,
    ArchiveyConfig,
    CorruptionError,
    TruncatedError,
    open_archive,
)
from archivey.config import SpoolLimits
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    ArchiveyError,
    PackageNotInstalledError,
    StreamNotSeekableError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import (
    rar_forward_reader,
    rar_parser as rp,
    rar_reader,
    rar_rolling as rl,
)
from archivey.internal.backends.rar_forward import ForwardSource, ForwardSpan
from archivey.internal.backends.rar_parser import _RAR3_FILE_SOLID
from archivey.internal.backends.rar_unrar import unrar_reads_rolling_volumes
from archivey.internal.hashing.blake2sp import blake2sp as blake2sp_digest
from tests.conftest import (
    requires,
    requires_binary,
    requires_unrar_cli,
    unrar_reads_from_pipes,
)
from tests.streams_util import open_mode
from tests.test_audit_rar_iso_dir import (
    _rar3_build,
    _rar3_parse,
    _rar3_rename,
    _rar5_build,
    _rar5_file_blocks,
    _rar5_parse,
)
from tests.test_rar_owner import OWNER_NAMES_RAR4
from tests.test_rar_reader import _rar3_file_block
from tests.test_rar_synthetic import _password

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
# Volumes of a set, and archives whose walk needs a password the test gives.
_SINGLE = sorted(
    p
    for p in _FIXTURES.glob("*.rar")
    if ".part" not in p.name and p.name != "tinyvol_rnn.rar"
)
# The same, with the archives whose listing needs the header key (AES, the
# cryptography package) skipped when it is missing, as in the core-only CI leg.
_SINGLE_PARAMS = [
    pytest.param(p, marks=requires("cryptography"))
    if _password(p) == "header_password"
    else p
    for p in _SINGLE
]


class _Pipe(io.RawIOBase):
    """Bytes read once, in pieces of at most ``step``: a pipe."""

    def __init__(self, data: bytes, step: int = 4093) -> None:
        self._data = memoryview(data)
        self._at = 0
        self._step = step

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data)
        n = min(n, self._step)
        out = bytes(self._data[self._at : self._at + n])
        self._at += len(out)
        return out


def _fields(member: rp.RarMemberInfo) -> tuple[object, ...]:
    return (
        member.filename,
        member.header_offset,
        member.data_offset,
        member.compress_size,
        member.file_size,
        member.crc32,
        member.file_solid,
    )


def _parse(data: bytes, password: str | None) -> rp.RarArchive:
    return rp.parse_rar_archive(
        io.BytesIO(data), password=password, use_qo=False, kdf_cache=rp.RarKdfCache()
    )


@pytest.mark.parametrize("cut", [None, 0.5, 0.9])
@pytest.mark.parametrize("path", _SINGLE_PARAMS, ids=lambda p: p.name)
def test_a_forward_walk_lists_what_the_seekable_walk_lists(
    path: Path, cut: float | None
) -> None:
    """Every member, read from a pipe with each member's data consumed before the
    walk goes on, as the seekable walk lists it, whole or cut short; the walk never
    seeks back past what the forward source holds."""
    data = path.read_bytes()
    if cut is not None:
        data = data[: int(len(data) * cut)]
    password = None
    try:
        expected = _parse(data, None)
    except Exception:  # a fixture with no known password re-raises
        password = _password(path)
        if password is None:
            raise
        expected = _parse(data, password)
    source = ForwardSource(_Pipe(data))
    _version, walk = rp.open_forward_walk(
        source,
        password=password,
        kdf_cache=rp.RarKdfCache(),
        max_members=None,
        max_metadata_bytes=None,
    )
    got = []
    for found in rp.public_walk_errors(walk.walk()):
        assert source.tell() == found.data_offset
        span = ForwardSpan(source, found.data_offset, found.data_size)
        consumed = 0
        while chunk := span.read(1000):
            consumed += len(chunk)
        assert consumed == min(found.data_size, len(data) - found.data_offset)
        got.append(found.member)
    archive = walk.result()
    rp._settle_rar15_solid(archive)
    assert [_fields(m) for m in archive.members] == [
        _fields(m) for m in expected.members
    ]
    assert len(got) == sum(1 for m in expected.members)
    assert archive.comment == expected.comment
    assert archive.truncated == expected.truncated
    assert archive.damaged == expected.damaged


def test_the_forward_source_refuses_a_seek_back_past_what_it_holds() -> None:
    source = ForwardSource(_Pipe(bytes(range(256)) * 100), keep=1000)
    source.seek(5000)
    assert source.read(4) == bytes(range(256))[5000 % 256 : 5000 % 256 + 4]
    source.seek(4100)  # held
    with pytest.raises(io.UnsupportedOperation):
        source.seek(3000)
    with pytest.raises(io.UnsupportedOperation):
        source.seek(0, io.SEEK_END)
    source.seek(30_000)
    assert source.read(1) == b""
    assert source.seek(0, io.SEEK_END) == 25_600


# --- The reader: stream_members() from a pipe ----------------------------------------


class _PipeStream(io.RawIOBase):
    """A caller's non-seekable stream over ``data``, read in small pieces."""

    def __init__(self, data: bytes, step: int = 4093) -> None:
        self._pipe = _Pipe(data, step)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._pipe.read(len(buffer))
        memoryview(buffer).cast("B")[: len(data)] = data
        return len(data)


@pytest.fixture
def rolling_unrar() -> None:
    try:
        reads = unrar_reads_rolling_volumes()
    except PackageNotInstalledError:
        pytest.skip("no RARLAB unrar")
    if not reads:
        pytest.skip("this unrar is older than the one rolling volumes were measured on")


def _pipe(data: bytes) -> io.BufferedReader:
    return io.BufferedReader(_PipeStream(data))


def _outcome(error: BaseException) -> tuple[str, str]:
    """What raised, by its public class: the seekable reader's own decryption can
    raise a private subclass."""
    public = next(c for c in type(error).__mro__ if not c.__name__.startswith("_"))
    return ("raises", public.__name__)


def _pass(source: BinaryIO, password: str | None, **kwargs: object) -> list[object]:
    """What a streaming pass gives: each member's fields and its bytes' digest, or
    what its read raised, then what the pass raised."""
    out: list[object] = []
    try:
        with open_archive(
            source, **open_mode(source, streaming=True), password=password, **kwargs
        ) as reader:
            for member, stream in reader.stream_members():
                fields = (
                    member.name,
                    member.type,
                    member.size,
                    member.mode,
                    member.modified,
                    member.uname,
                    member.link_target,
                    member.comment,
                    member.is_encrypted,
                )
                if stream is None:
                    out.append((fields, None))
                    continue
                try:
                    data: object = hashlib.sha256(stream.read()).hexdigest()
                except ArchiveyError as exc:
                    data = _outcome(exc)
                out.append((fields, data))
            out.append(("info", reader.info.comment))
    except ArchiveyError as exc:
        out.append(_outcome(exc))
    return out


def _file_copies(path: Path, password: str | None) -> set[str]:
    with open_archive(path, password=password) as reader:
        return {
            m.name
            for m in reader.members()
            if isinstance(m._raw, rp.RarMemberInfo) and m._raw.is_file_copy()
        }


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
# The default volumes hold every fixture in the first one, written on the caller's
# thread; 2 000-byte volumes split most members, so the thread that writes the later
# volumes runs the walk and lists the members.
@pytest.mark.parametrize("limit", [None, 4000], ids=["one-volume", "many-volumes"])
@pytest.mark.parametrize("cut", [None, 0.5, 0.9])
@pytest.mark.parametrize("path", _SINGLE_PARAMS, ids=lambda p: p.name)
def test_a_pipe_pass_gives_what_the_seekable_pass_gives(
    path: Path, cut: float | None, limit: int | None
) -> None:
    """Every committed single-volume RAR fixture, whole or cut short, read from a pipe:
    the same members, bytes and errors as a streaming pass over the same bytes in a
    ``BytesIO``. A RAR5 file copy is the one difference: its read is refused."""
    data = path.read_bytes()
    if cut is not None:
        data = data[: int(len(data) * cut)]
    password = _password(path)
    expected = _pass(io.BytesIO(data), password)
    copies = _file_copies(path, password)
    for index, entry in enumerate(expected):
        if isinstance(entry, tuple) and isinstance(entry[0], tuple):
            fields, _ = entry
            if fields[0] in copies:
                expected[index] = (fields, ("raises", "UnsupportedFeatureError"))
    config = None if limit is None else _config(limit)
    assert _pass(_pipe(data), password, config=config) == expected


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("limit", [None, 4000], ids=["one-volume", "many-volumes"])
@pytest.mark.parametrize("path", _SINGLE_PARAMS, ids=lambda p: p.name)
def test_a_pipe_pass_that_reads_some_members_lists_them_all(
    path: Path, limit: int | None
) -> None:
    """Reading every other member, or none: the listing is the seekable pass's, and
    the members read give its bytes. ``unrar``'s output of the members skipped is
    read past, so it never fills its pipe while the walk waits for a volume."""
    data = path.read_bytes()
    password = _password(path)
    config = None if limit is None else _config(limit)

    def listing(source: BinaryIO, every: int | None, **kwargs: object) -> list[object]:
        out: list[object] = []
        try:
            with open_archive(
                source,
                **open_mode(source, streaming=True),
                password=password,
                **kwargs,
            ) as reader:
                for index, (member, stream) in enumerate(reader.stream_members()):
                    entry: list[object] = [member.name, member.uname]
                    if stream is not None and every is not None and index % every == 0:
                        try:
                            entry.append(hashlib.sha256(stream.read()).hexdigest())
                        except ArchiveyError as exc:
                            entry.append(_outcome(exc))
                    out.append(entry)
        except ArchiveyError as exc:
            out.append(_outcome(exc))
        return out

    copies = _file_copies(path, password)
    for every in (None, 2):
        expected = listing(io.BytesIO(data), every)
        for entry in expected:
            if isinstance(entry, list) and entry[0] in copies and len(entry) == 3:
                entry[2] = ("raises", "UnsupportedFeatureError")
        assert listing(_pipe(data), every, config=config) == expected


def _owner_archive(
    *sizes: int, uow: bytes | None = None, comment: bytes | None = None
) -> bytes:
    """``OWNER_NAMES_RAR4`` (``a.txt``, then a ``UOW`` header naming root) with one
    such pair per size: members ``m0.bin``, ``m1.bin`` ... of that many stored random
    bytes. ``uow`` replaces the ``UOW`` header's data; ``comment`` adds a ``CMT``
    header holding it after each ``UOW``."""
    main, file, uow_block, end = _rar3_parse(OWNER_NAMES_RAR4)
    if uow is not None:
        header = uow_block["header"]
        header[32 + struct.unpack_from("<H", header, 26)[0] :] = uow
        struct.pack_into("<H", header, 5, len(header))
    blocks = [main]
    for index, size in enumerate(sizes):
        block = {"type": file["type"], "header": bytearray(file["header"])}
        _rar3_rename(block, f"m{index}.bin".encode())
        data = os.urandom(size)
        header = block["header"]
        struct.pack_into("<II", header, 7, size, size)
        struct.pack_into("<I", header, 16, zlib.crc32(data))
        header[25] = 0x30  # stored
        block["data"] = data
        blocks += [block, {**uow_block, "header": bytearray(uow_block["header"])}]
        if comment is not None:
            cmt = _rar3_file_block(
                b"CMT",
                flags=_RAR3_FILE_SOLID,
                pack_lo=len(comment),
                unp_lo=len(comment),
                block_type=0x7A,
            )
            blocks.append({"type": 0x7A, "header": bytearray(cmt), "data": comment})
    blocks.append(end)
    return _rar3_build(blocks)


def _piped_members(
    data: bytes, config: ArchiveyConfig
) -> list[tuple[ArchiveMember, bytes, bool]]:
    """Each member a pipe pass yields, its data, and ``member_state_final`` as it
    was yielded."""
    got = []
    with open_archive(_pipe(data), pipe=True, config=config) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            got.append((member, stream.read(), member.member_state_final))
    return got


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("size", [5_000, 50_000], ids=["one-volume", "split"])
def test_a_split_member_gets_the_owner_and_comment_read_after_it(size: int) -> None:
    """A member split across two volumes is listed when the first is written, before
    the walk reads the ``UOW`` and ``CMT`` headers after it: they are written into
    the member, which is not final until the pass ends, so it ends up as a file
    lists it."""
    data = _owner_archive(size, comment=b"member comment")
    with open_archive(io.BytesIO(data), streaming=True) as reader:
        ((member, stream),) = [
            (m, s.read() if s is not None else None) for m, s in reader.stream_members()
        ]
    assert (member.uname, member.gname, member.comment) == (
        "root",
        "root",
        "member comment",
    )
    ((piped, piped_data, final),) = _piped_members(data, _config())
    assert piped_data == stream
    assert not final
    assert (piped.uname, piped.gname, piped.uid, piped.gid, piped.comment) == (
        member.uname,
        member.gname,
        member.uid,
        member.gid,
        member.comment,
    )
    assert piped.diagnostics == ()


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_an_owner_header_read_after_a_split_member_that_names_none_is_reported() -> (
    None
):
    """A ``UOW`` header with no owner in it, after a split member: reported once, as a
    file reports it."""
    data = _owner_archive(50_000, uow=b"root")
    with open_archive(io.BytesIO(data)) as reader:
        (member,) = reader.members()
        expected = [(d.code, d.message) for d in member.diagnostics]
    assert [code for code, _ in expected] == [
        DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
    ]
    ((piped, _, _),) = _piped_members(data, _config())
    assert (piped.uname, piped.gname) == (None, None)
    assert [(d.code, d.message) for d in piped.diagnostics] == expected


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_the_walk_waits_while_a_member_released_early_is_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The walk reads the header after a split member on its own thread; it does
    not read it while the caller's thread builds the member, so the owner is in the
    member either way. A pause after each member is built is where it would land."""
    real = rar_forward_reader.RarForwardReader._list_member

    def slow(self: rar_forward_reader.RarForwardReader, found: object) -> object:
        member = real(self, found)  # type: ignore[arg-type]
        time.sleep(0.3)
        return member

    monkeypatch.setattr(rar_forward_reader.RarForwardReader, "_list_member", slow)
    data = _owner_archive(*(30_000,) * 5)
    members = [member for member, _, _ in _piped_members(data, _config())]
    assert [(m.name, m.uname, m.diagnostics) for m in members] == [
        (f"m{index}.bin", "root", ()) for index in range(5)
    ]


class _SlowBuilding:
    """``_ForwardPass.building``, released late by the caller: once the caller lets
    go of it, the walk it held back runs first."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def __enter__(self) -> None:
        self._lock.acquire()

    def __exit__(self, *exc: object) -> None:
        self._lock.release()
        if threading.current_thread() is threading.main_thread():
            time.sleep(0.3)


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_a_member_released_early_keeps_what_the_walk_reads_once_let_go(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The walk reads the header after a member listed early once the caller lets it
    go. What it adds then still reaches the member, however soon it comes."""
    real = rar_forward_reader._ForwardPass.__init__

    def init(self: rar_forward_reader._ForwardPass, reader: object) -> None:
        real(self, reader)  # type: ignore[arg-type]
        self.building = _SlowBuilding()  # type: ignore[assignment]

    monkeypatch.setattr(rar_forward_reader._ForwardPass, "__init__", init)
    data = _owner_archive(*(30_000,) * 5, comment=b"c")
    members = [member for member, _, _ in _piped_members(data, _config())]
    assert [(m.name, m.uname, m.comment, m.diagnostics) for m in members] == [
        (f"m{index}.bin", "root", "c", ()) for index in range(5)
    ]


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_only_a_member_split_by_a_volume_is_listed_early(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Members that each fit a volume are never split, and none is listed before the
    walk reads the header after it, though most do not fit the volume the one
    before them ends."""
    early: list[set[int]] = []
    real = rar_forward_reader._ForwardPass.__init__

    def init(self: rar_forward_reader._ForwardPass, reader: object) -> None:
        real(self, reader)  # type: ignore[arg-type]
        early.append(self.early)

    monkeypatch.setattr(rar_forward_reader._ForwardPass, "__init__", init)
    data = _owner_archive(*(12_000,) * 4)
    members = _piped_members(data, _config())
    assert [m.uname for m, _, _ in members] == ["root"] * 4
    assert early == [set()]


class _StallingStream(io.RawIOBase):
    """A non-seekable source that gives ``data[:stall_at]``, then blocks until
    ``release`` is set, then ends."""

    def __init__(self, data: bytes, stall_at: int) -> None:
        self._data = data[:stall_at]
        self._at = 0
        self.release = threading.Event()
        self.stalled = threading.Event()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        if self._at >= len(self._data):
            self.stalled.set()
            self.release.wait(30)
            return 0
        n = min(len(buffer), 4093, len(self._data) - self._at)
        memoryview(buffer).cast("B")[:n] = self._data[self._at : self._at + n]
        self._at += n
        return n


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_closing_does_not_wait_for_a_source_that_stopped_sending(
    volumes_made: list[rl.RollingVolumes],
) -> None:
    """The thread that writes the volumes reads the caller's source: closing stops
    waiting for it (and for ``unrar``, which waits on a volume prompt), and the thread
    removes the volumes once its read returns. Until then the caller's own close of
    the source waits for that read, as the docs say."""
    # Members under 4 KiB, Windows' pipe buffer: the output ``unrar`` makes of a
    # member nobody reads yet fits the pipe, so it goes on to ask for the volume
    # whose writing reaches the stall.
    data = _owner_archive(3000, 3000, 3000, 3000)
    source = _StallingStream(data, int(len(data) * 0.8))
    buffered = io.BufferedReader(source)
    try:
        reader = open_archive(buffered, pipe=True, config=_config(4000))
        it = reader.stream_members()
        for _ in range(2):
            _member, stream = next(it)
            assert stream is not None
            assert len(stream.read()) == 3000
        # The third, listed and not read. The thread now reads ahead into the last
        # member, where the source stops sending, to finish the volume that ends
        # the third.
        next(it)
        assert source.stalled.wait(10)
        started = time.monotonic()
        it.close()
        reader.close()
        assert time.monotonic() - started < 4
        closer = threading.Thread(target=buffered.close)
        closer.start()
        closer.join(1)
        assert closer.is_alive()  # the read the thread is blocked in holds the lock
    finally:
        source.release.set()
    closer.join(10)
    assert not closer.is_alive()
    (volumes,) = volumes_made
    deadline = time.monotonic() + 10
    while volumes.dir.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not volumes.dir.exists()


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize(
    ("sizes", "fail_after", "limit"),
    [
        # The walk reads a small member's data ahead to tell whether it is whole.
        pytest.param((30_000,) * 4, 80_000, 40_000, id="reading-ahead"),
        # A member larger than the forward source keeps is read as it is copied.
        pytest.param((5_000_000,), 4_600_000, 4_000_000, id="copying"),
    ],
)
def test_a_failed_source_read_raises_its_own_error(
    sizes: tuple[int, ...], fail_after: int, limit: int
) -> None:
    """An ``OSError`` reading the source, on the thread that writes the later
    volumes, reaches the caller as it is, not as a failure to write a volume."""
    data = _owner_archive(*sizes)

    class _Failing(_PipeStream):
        def __init__(self) -> None:
            super().__init__(data)
            self._given = 0

        def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
            if self._given > fail_after:
                raise ConnectionResetError("the peer reset the connection")
            n = super().readinto(buffer)
            self._given += n
            return n

    with (
        open_archive(
            io.BufferedReader(_Failing()), pipe=True, config=_config(limit)
        ) as reader,
        pytest.raises(ConnectionResetError, match="peer reset"),
    ):
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


_DAMAGED = Path(__file__).parent / "fixtures" / "damaged_member"


def _pass_on_a_thread(
    data: bytes, config: ArchiveyConfig, timeout: float = 30
) -> list[tuple[str, object]]:
    """Each member's name and its bytes' digest, or what its read raised, from a pipe
    pass run on a thread. A pass still running after ``timeout`` seconds fails the
    test; the reader is closed then, which ends ``unrar`` and lets the thread go."""
    got: list[tuple[str, object]] = []
    reader = open_archive(_pipe(data), pipe=True, config=config)

    def run() -> None:
        try:
            for member, stream in reader.stream_members():
                assert stream is not None
                try:
                    digest: object = hashlib.sha256(stream.read()).hexdigest()
                except ArchiveyError as exc:
                    digest = _outcome(exc)
                got.append((member.name, digest))
        except ArchiveyError as exc:
            got.append(("pass", _outcome(exc)))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    hung = thread.is_alive()
    try:
        reader.close()
    finally:
        thread.join(10)
        assert not hung, f"the pipe pass hung after {got}"
    return got


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("name", ["rar5_nonsolid.rar", "rar5_solid.rar"])
def test_a_member_that_decodes_short_does_not_stop_the_pass(name: str) -> None:
    """``b.txt`` decodes to fewer bytes than its header says, and ``c.txt`` after it
    is split across volumes (600-byte spool limit, 300-byte volumes). The read of
    ``b.txt`` waits for output that ``unrar`` writes only after the next volume; the
    thread that writes it must not wait for the caller to list ``c.txt`` first."""
    data = (_DAMAGED / name).read_bytes()
    with open_archive(io.BytesIO(data)) as reader:
        expected = hashlib.sha256(reader.read("a.txt")).hexdigest()
    got = _pass_on_a_thread(data, _config(600))
    assert [name for name, _ in got] == ["a.txt", "b.txt", "c.txt"]
    assert got[0][1] == expected
    assert got[1][1] == ("raises", "CorruptionError")


def _rar(tmp_path: Path, files: dict[str, bytes], *switches: str) -> bytes:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, data in files.items():
        (src / name).write_bytes(data)
    archive = tmp_path / "out.rar"
    archive.unlink(missing_ok=True)
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", *switches, str(archive), *files],
        cwd=src,
        check=True,
        timeout=60,
    )
    return archive.read_bytes()


def _text(size: int) -> bytes:
    """Random data that compresses (hex digits), so ``rar`` does not store it."""
    return os.urandom(size // 2).hex().encode()


def _config(limit: int | None = 40_000) -> ArchiveyConfig:
    # A spool limit of 40 000 bytes makes volumes of 20 000: most members split.
    return ArchiveyConfig(
        rar_decompressor="unrar", spool_limits=SpoolLimits(max_bytes=limit)
    )


@pytest.fixture
def volumes_made(monkeypatch: pytest.MonkeyPatch) -> list[rl.RollingVolumes]:
    """Every set of rolling volumes a reader makes."""
    made: list[rl.RollingVolumes] = []
    real = rl.RollingVolumes.__init__

    def record(self: rl.RollingVolumes, *args: object, **kwargs: object) -> None:
        real(self, *args, **kwargs)  # type: ignore[arg-type]
        made.append(self)

    monkeypatch.setattr(rl.RollingVolumes, "__init__", record)
    return made


_SHAPES = {
    "solid": ("-s",),
    "nonsolid": (),
    "solid-p": ("-s", "-psecret"),
    "nonsolid-p": ("-psecret",),
    "solid-hp": ("-s", "-hpsecret"),
    "stored": ("-m0",),
}


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_a_pipe_pass_over_many_volumes_reads_every_member(
    tmp_path: Path, shape: str, volumes_made: list[rl.RollingVolumes]
) -> None:
    """Members larger than a volume, members that share one, and empty ones, read
    from a pipe through volumes of 20 000 bytes: what the seekable pass reads, with
    one volume on disk at a time and one ``unrar`` for the pass."""
    files = {
        f"f{i}.bin": _text(size) for i, size in enumerate([90_000, 300, 0, 45_000])
    }
    files["big.bin"] = os.urandom(70_000)  # stored by rar: split across volumes
    raw = _rar(tmp_path, files, *_SHAPES[shape])
    password = "secret" if any("secret" in s for s in _SHAPES[shape]) else None
    expected = _pass(io.BytesIO(raw), password, config=_config())
    volumes_made.clear()
    assert _pass(_pipe(raw), password, config=_config()) == expected
    assert {
        entry[0][0]: entry[1]  # type: ignore[index]
        for entry in expected
        if isinstance(entry[0], tuple)
    } == {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    assert len(volumes_made) == 1
    volumes = volumes_made[0]
    assert volumes.count > 5
    assert volumes.peak <= 20_000
    assert not volumes.dir.exists()


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("read", ["none", "some"])
def test_a_pipe_pass_that_reads_few_members_lists_them_all(
    tmp_path: Path, read: str
) -> None:
    """A pass that reads no member, or only some, still lists every member: the
    listing reads past ``unrar``'s output of the members it skipped, so ``unrar``
    asks for the next volume and the walk goes on."""
    files = {f"f{i}.bin": _text(60_000) for i in range(6)}
    raw = _rar(tmp_path, files, "-s")
    names = []
    with open_archive(_pipe(raw), pipe=True, config=_config()) as reader:
        for member, stream in reader.stream_members():
            names.append(member.name)
            if read == "some" and member.name in {"f1.bin", "f4.bin"}:
                assert stream is not None
                assert stream.read() == files[member.name]
    assert names == list(files)


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
def test_a_pipe_listing_without_a_pass_runs_no_unrar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {f"f{i}.bin": _text(60_000) for i in range(4)}
    raw = _rar(tmp_path, files, "-s")

    def no_unrar(*args: object, **kwargs: object) -> object:
        raise AssertionError("unrar started for a listing")

    monkeypatch.setattr(rar_forward_reader, "open_unrar_p", no_unrar)
    with open_archive(_pipe(raw), pipe=True, config=_config()) as reader:
        report = reader.members_report()
    assert report.error is None
    assert [m.name for m in report.members] == list(files)


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
def test_a_pipe_pass_closed_early_removes_its_volumes(
    tmp_path: Path, volumes_made: list[rl.RollingVolumes]
) -> None:
    files = {f"f{i}.bin": _text(60_000) for i in range(4)}
    raw = _rar(tmp_path, files, "-s")
    with open_archive(_pipe(raw), pipe=True, config=_config()) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read(10) == files[member.name][:10]
            break
        assert len(volumes_made) == 1
    assert not volumes_made[0].dir.exists()


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
def test_several_passwords_pick_the_one_a_rar5_check_accepts(tmp_path: Path) -> None:
    files = {"a.txt": _text(30_000), "b.txt": _text(30_000)}
    raw = _rar(tmp_path, files, "-s", "-psecret")
    with open_archive(
        _pipe(raw), pipe=True, password=["wrong", "secret"], config=_config()
    ) as reader:
        got = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert got == files


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_several_passwords_on_rar4_data_encryption_are_refused() -> None:
    """RAR 1.5-4 data has no password check value, and one ``unrar`` cannot try
    several: the encrypted member's read names one password as the fix."""
    raw = (_FIXTURES / "encryption__rar4.rar").read_bytes()
    with open_archive(_pipe(raw), pipe=True, password=["wrong", "password"]) as reader:
        refused = []
        for member, stream in reader.stream_members():
            if member.is_encrypted and stream is not None:
                with pytest.raises(UnsupportedFeatureError, match="one password"):
                    stream.read()
                refused.append(member.name)
    assert refused


@requires_unrar_cli()
@requires("cryptography")
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("password", ["header_password", ["wrong", "header_password"]])
def test_a_header_password_is_found(password: str | list[str]) -> None:
    """One candidate, and several, where the walk restarts after the wrong one."""
    raw = (_FIXTURES / "encrypted_header__rar4.rar").read_bytes()
    with open_archive(io.BytesIO(raw), password="header_password") as reader:
        expected = {m.name: reader.read(m) for m in reader.members() if m.is_file}
    with open_archive(_pipe(raw), pipe=True, password=password) as reader:
        got = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert got == expected


@pytest.mark.usefixtures("rolling_unrar")
def test_a_volume_set_is_refused_from_a_pipe() -> None:
    raw = (_FIXTURES / "tinyvol_rnn.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError, match="volume set"):
        open_archive(_pipe(raw), pipe=True)


def test_unar_is_refused_from_a_pipe() -> None:
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError, match="RARLAB unrar"):
        open_archive(
            _pipe(raw), pipe=True, config=ArchiveyConfig(rar_decompressor="unar")
        )


def test_an_unrar_older_than_7_is_refused_from_a_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rar_reader, "unrar_reads_rolling_volumes", lambda program=None: False
    )
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError, match="7.00 or later"):
        open_archive(
            _pipe(raw), pipe=True, config=ArchiveyConfig(rar_decompressor="unrar")
        )


def test_random_access_on_a_pipe_stays_refused() -> None:
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError):
        open_archive(_pipe(raw), pipe=False)


def _rar5_vint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _rar5_block(body: bytes) -> bytes:
    framed = _rar5_vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(framed)) + framed


def _rar5_stored(name: str, data: bytes, *, size: int, packed: int) -> bytes:
    """A stored RAR5 FILE header that declares ``size`` unpacked and ``packed``
    packed bytes, then ``data``, which may be shorter than ``packed``."""
    fields = (
        _rar5_vint(4)  # file flags: CRC32
        + _rar5_vint(size)
        + _rar5_vint(0o100644)
        + struct.pack("<I", zlib.crc32(data))
        + _rar5_vint(0)  # stored
        + _rar5_vint(1)  # Unix
        + _rar5_vint(len(name))
        + name.encode()
    )
    return _rar5_block(b"\x02\x02" + _rar5_vint(packed) + fields) + data


def _rar5_archive(*files: bytes, end: bool = True) -> bytes:
    return (
        b"Rar!\x1a\x07\x01\x00"
        + _rar5_block(b"\x01\x00\x00")  # MAIN
        + b"".join(files)
        + (_rar5_block(b"\x05\x00\x00") if end else b"")  # ENDARC
    )


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("declared", [5_978 + 22, 5_978 - 22], ids=["more", "fewer"])
def test_a_stored_member_whose_sizes_differ_does_not_shift_the_next(
    declared: int,
) -> None:
    """A stored member whose unpacked size is not its packed size is refused, as the
    seekable reader refuses it, and ``unrar`` writes its packed bytes: the member
    after it is placed after those and reads intact."""
    after = os.urandom(30_000)
    raw = _rar5_archive(
        _rar5_stored("short", b"s" * 5_978, size=declared, packed=5_978),
        _rar5_stored("after", after, size=len(after), packed=len(after)),
    )
    expected = _pass(io.BytesIO(raw), None)
    assert [entry[1] for entry in expected[:2]] == [
        ("raises", "CorruptionError"),
        hashlib.sha256(after).hexdigest(),
    ]
    assert _pass(_pipe(raw), None, config=_config(None)) == expected


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_a_member_after_one_that_decoded_short_is_refused() -> None:
    """``b.txt`` decodes to fewer bytes than its header says, so the output after
    it no longer lines up. ``c.txt`` is refused as a member after such output, not
    reported as cut short: its own data is intact."""
    data = (
        Path(__file__).parent / "fixtures" / "damaged_member" / "rar5_nonsolid.rar"
    ).read_bytes()
    with open_archive(io.BytesIO(data)) as reader:
        a_txt = hashlib.sha256(reader.read("a.txt")).hexdigest()
    got = _pass(_pipe(data), None, config=_config(None))
    assert [(entry[0][0], entry[1]) for entry in got[:3]] == [  # type: ignore[index]
        ("a.txt", a_txt),
        ("b.txt", ("raises", "CorruptionError")),
        ("c.txt", ("raises", "UnsupportedFeatureError")),
    ]


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_an_empty_member_after_one_that_decoded_short_does_not_end_the_doubt() -> None:
    """An empty ``e.txt`` between ``b.txt``, which decodes short, and ``c.txt``. Its
    output matches its CRC32 wherever it starts, so it does not show that the output
    lines up again: ``e.txt`` reads empty and ``c.txt`` is still refused."""
    blocks = _rar5_parse(
        (
            Path(__file__).parent / "fixtures" / "damaged_member" / "rar5_nonsolid.rar"
        ).read_bytes()
    )
    files = _rar5_file_blocks(blocks)
    assert [block["name"] for block in files] == [b"a.txt", b"b.txt", b"c.txt"]
    empty = dict(files[2], name=b"e.txt", unpacked=0, crc=bytes(4), cinfo=0, data=b"")
    blocks.insert(blocks.index(files[2]), empty)
    got = _pass(_pipe(_rar5_build(blocks)), None, config=_config(None))
    assert [(entry[0][0], entry[1]) for entry in got[1:4]] == [  # type: ignore[index]
        ("b.txt", ("raises", "CorruptionError")),
        ("e.txt", hashlib.sha256(b"").hexdigest()),
        ("c.txt", ("raises", "UnsupportedFeatureError")),
    ]


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_a_cut_member_writes_no_volume_after_the_one_the_cut_is_in(
    volumes_made: list[rl.RollingVolumes],
) -> None:
    """A stored member that declares 8 MiB and holds 16 bytes: the source ends
    inside it. The volume the cut is in is padded, so the members before it there
    still decode, and the pass ends then with the cut. It does not pad the rest
    of the declared size, a volume at a time."""
    raw = _rar5_archive(
        _rar5_stored("before", b"b" * 1_000, size=1_000, packed=1_000),
        _rar5_stored("cut", b"x" * 16, size=8 << 20, packed=8 << 20),
        end=False,
    )
    got = _pass(_pipe(raw), None, config=_config())
    assert [(entry[0][0], entry[1]) for entry in got[:2]] == [  # type: ignore[index]
        ("before", hashlib.sha256(b"b" * 1_000).hexdigest()),
        ("cut", ("raises", "TruncatedError")),
    ]
    assert got[2:] == [("raises", "TruncatedError")]
    (volumes,) = volumes_made
    assert volumes.count <= 2


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_members_after_one_that_fails_its_digest_still_read_when_they_line_up() -> None:
    """The first member's header holds a wrong CRC32, so its read fails, though its
    output has the length its header says. The pass cannot tell that from a member
    that decoded short until the next member's own CRC32 matches where it was
    placed: from then on, the members read as from a seekable source."""
    blocks = _rar5_parse((_FIXTURES / "wildcard_dirglob__.rar").read_bytes())
    first = _rar5_file_blocks(blocks)[0]
    first["crc"] = bytes(b ^ 0xFF for b in first["crc"])
    raw = _rar5_build(blocks)
    expected = _pass(io.BytesIO(raw), None)
    assert expected[0][1] == ("raises", "CorruptionError")  # type: ignore[index]
    assert [entry[1] is not None for entry in expected[1:-1]] == [  # type: ignore[index]
        False,  # a directory
        True,
        False,
        True,
        False,
    ]
    assert all(isinstance(entry[1], (str, type(None))) for entry in expected[1:-1])  # type: ignore[index]
    assert _pass(_pipe(raw), None, config=_config(None)) == expected


# --- Members built by hand: a late cut, extra-area padding ------------------------


def _rar5_file(
    name: str,
    payload: bytes,
    *,
    padded: bool = False,
    blake2sp: bool | bytes = False,
) -> bytes:
    """A stored RAR5 FILE header and its data, with a CRC32 or a BLAKE2sp digest.

    ``blake2sp`` may be the digest itself: the pure-Python hasher takes about two
    seconds per MiB. With ``padded``, the header's extra area holds one padding
    byte. The native walk permits this byte, and RARLAB unrar tests the complete
    member successfully.
    """
    extra = b""
    if blake2sp:
        digest = blake2sp if isinstance(blake2sp, bytes) else blake2sp_digest(payload)
        record = _rar5_vint(2) + _rar5_vint(0) + digest  # HASH, BLAKE2sp
        extra += _rar5_vint(len(record)) + record
    if padded:
        extra += b"\x00"
    fields = (
        _rar5_vint(0 if blake2sp else 4)  # file flags: CRC32 unless BLAKE2sp
        + _rar5_vint(len(payload))
        + _rar5_vint(0o100644)
        + (b"" if blake2sp else struct.pack("<I", zlib.crc32(payload)))
        + _rar5_vint(0)  # stored
        + _rar5_vint(1)  # Unix
        + _rar5_vint(len(name.encode()))
        + name.encode()
    )
    header = (
        (b"\x02\x03" + _rar5_vint(len(extra)) if extra else b"\x02\x02")  # type, flags
        + _rar5_vint(len(payload))
        + fields
        + extra
    )
    return _rar5_block(header) + payload


# BLAKE2sp of 6 and 24 MiB of zeros. Hashing them in the test takes about a minute
# with the pure-Python hasher, past the per-test timeout.
_ZEROS_BLAKE2SP = {
    6: bytes.fromhex(
        "b878b13c60bac85d452f92d71b9ce5cae3cf606242db7c3a6fde70630aa9cedb"
    ),
    24: bytes.fromhex(
        "a83583bd897a0226f97faaf8f95b2bc718e343ce90d85d6ef1cccc13ea8cf681"
    ),
}


@pytest.mark.skipif(
    not unrar_reads_from_pipes(), reason="requires RARLAB unrar 7.00 or later"
)
@requires_unrar_cli()
def test_a_truncated_pipe_member_never_verifies_zero_padding(tmp_path: Path) -> None:
    payload = bytes(6 << 20)
    # Built by hand, as ``rar a -ma5 -m0`` stores it: CI never installs the RAR writer.
    cut = _rar5_archive(_rar5_file("a", payload))[: 5 << 20]
    path = tmp_path / "cut.rar"
    path.write_bytes(cut)
    oracle = subprocess.run(
        ["unrar", "t", "-cfg-", "-inul", str(path)], check=False, capture_output=True
    )
    assert oracle.returncode == 3
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=2 << 20))
    with open_archive(io.BytesIO(cut), streaming=True, config=config) as reader:
        members = reader.stream_members()
        member, stream = next(members)
        assert member.size == len(payload)
        assert stream is not None
        with pytest.raises(TruncatedError):
            stream.read()
    # The missing bytes are zero in the original. Invented padding therefore passes
    # the member's CRC. The error must come from the source ending, not the digest.
    with open_archive(_pipe(cut), pipe=True, config=config) as reader:
        members = reader.stream_members()
        member, stream = next(members)
        assert member.size == len(payload)
        assert stream is not None
        with pytest.raises(TruncatedError, match="cut short"):
            stream.read()


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("blake2sp", [False, True], ids=["crc32", "blake2sp"])
@pytest.mark.parametrize(
    "limit", [2 << 20, None], ids=["small-volumes", "default-volumes"]
)
@pytest.mark.parametrize("read", ["all", "exact", "chunks", "readinto"])
def test_a_late_source_cut_fails_the_member_read(
    blake2sp: bool, limit: int | None, read: str
) -> None:
    # More than the 4 MiB source lookahead and one synthetic volume. The member is
    # listed before the feeder discovers its missing tail. That tail would be all
    # zeros, so a digest over synthetic padding alone cannot detect its absence.
    size, cut_at = (6, 5) if limit is not None else (24, 20)
    # Built by hand, as ``rar a -m0`` stores it: CI never installs the RAR writer.
    raw = _rar5_archive(
        _rar5_file("before", b"intact prefix", blake2sp=blake2sp),
        _rar5_file(
            "zeros", bytes(size << 20), blake2sp=blake2sp and _ZEROS_BLAKE2SP[size]
        ),
    )[: cut_at << 20]
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=limit))
    with (
        open_archive(_pipe(raw), pipe=True, config=config) as reader,
        reader.stream_members() as members,
    ):
        member, stream = next(members)
        assert member.name == "before"
        assert stream is not None
        assert stream.read() == b"intact prefix"
        member, stream = next(members)
        assert member.name == "zeros"
        assert member.size == size << 20
        assert stream is not None
        with pytest.raises(TruncatedError, match="cut short"):
            if read == "all":
                stream.read()
            elif read == "exact":
                # One read that reaches the end of ``unrar``'s output: the member's
                # own error, not the pass's (``_ForwardUnrarStream`` exit mapping).
                stream.read(member.size)
            elif read == "chunks":
                while stream.read(64 << 10):
                    pass
            else:
                buffer = bytearray(64 << 10)
                while stream.readinto(buffer):
                    pass


class _ExitedProc:
    """Enough of ``Popen`` for ``_ForwardUnrarStream.close``: a program that already
    exited, killed by the thread that writes the volumes."""

    returncode = -9

    def __init__(self) -> None:
        self.stdin = io.BytesIO()

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


class _StoppedFeeder:
    """Enough of ``VolumeFeeder``: a thread that has returned with ``error``."""

    def __init__(self, error: ArchiveyError) -> None:
        self.error = error

    def close_after(self, cleanup: object, *, timeout: float | None = None) -> None:
        assert callable(cleanup)
        cleanup()


class _StoppedPass:
    """Enough of ``_ForwardPass`` for its ``unrar`` stream."""

    source = None
    cut_stop = None

    def __init__(self) -> None:
        self.stopping = False

    def stop(self) -> None:
        self.stopping = True


class _Volumes:
    def close(self) -> None:
        pass


def _stopped_stream(error: ArchiveyError) -> rar_forward_reader._ForwardUnrarStream:
    return rar_forward_reader._ForwardUnrarStream(
        _StoppedPass(),  # type: ignore[arg-type]
        io.BytesIO(b""),
        _ExitedProc(),  # type: ignore[arg-type]
        _StoppedFeeder(error),  # type: ignore[arg-type]
        _Volumes(),  # type: ignore[arg-type]
        lambda: None,
    )


def test_a_close_that_stops_the_volume_thread_mid_volume_raises_nothing() -> None:
    """``close`` stops the walk, then terminates ``unrar``. The thread writing a
    volume can see the stop first, at its next read of the source, and kill
    ``unrar`` itself with ``_Closed``: the close is all that happened.
    ``test_a_late_source_cut_fails_the_member_read`` can reach this order: the
    member's read has already raised, and the thread is still padding the cut
    volume when the pass closes."""
    _stopped_stream(rar_forward_reader._Closed()).close()


def test_a_volume_thread_failure_still_raises_from_close() -> None:
    """A ``_Closed`` feeder error is the only one a close leaves out."""
    error = TruncatedError("the source ended")
    with pytest.raises(TruncatedError, match="the source ended"):
        _stopped_stream(error).close()


@pytest.mark.skipif(
    not unrar_reads_from_pipes(), reason="requires RARLAB unrar 7.00 or later"
)
@requires_unrar_cli()
@pytest.mark.xfail(
    strict=True,
    raises=CorruptionError,
    reason="R2: Splitting a RAR5 member rejects extra-area padding that unrar accepts",
)
def test_extra_area_padding_survives_a_rolling_volume_split(tmp_path: Path) -> None:
    payload = bytes(range(251)) * 40
    raw = _rar5_archive(_rar5_file("a", payload, padded=True))
    path = tmp_path / "padded.rar"
    path.write_bytes(raw)
    subprocess.run(
        ["unrar", "t", "-cfg-", "-inul", str(path)], check=True, capture_output=True
    )
    oracle = subprocess.run(
        ["unrar", "p", "-cfg-", "-inul", str(path), "a"],
        check=True,
        capture_output=True,
    )
    assert oracle.stdout == payload
    with open_archive(path) as reader:
        (member,) = reader.members()
        with reader.open(member) as stream:
            assert stream.read() == payload
    with open_archive(_pipe(raw), pipe=True) as reader:
        assert [
            (m.name, s.read() if s else None) for m, s in reader.stream_members()
        ] == [("a", payload)]
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=4000))
    with open_archive(_pipe(raw), pipe=True, config=config) as reader:
        assert [
            (m.name, s.read() if s else None) for m, s in reader.stream_members()
        ] == [("a", payload)]
