"""RAR read front to back from a source that cannot seek: the header walk
(``rar_forward``) and the reader that streams members through rolling volumes
(``rar_forward_reader``)."""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import ArchiveyConfig, SpoolLimits, open_archive
from archivey.exceptions import (
    ArchiveyError,
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
from archivey.internal.backends.rar_unrar import unrar_reads_rolling_volumes
from tests.conftest import requires_binary, requires_unrar_cli
from tests.test_rar_synthetic import _password

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
# Volumes of a set, and archives whose walk needs a password the test gives.
_SINGLE = sorted(
    p
    for p in _FIXTURES.glob("*.rar")
    if ".part" not in p.name and p.name != "tinyvol_rnn.rar"
)
_PASSWORD = "password"


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
@pytest.mark.parametrize("path", _SINGLE, ids=lambda p: p.name)
def test_a_forward_walk_lists_what_the_seekable_walk_lists(
    path: Path, cut: float | None
) -> None:
    """Every member, read from a pipe with each member's data consumed before the
    walk goes on, as the seekable walk lists it, whole or cut short; the walk never
    seeks back past what the forward source holds."""
    data = path.read_bytes()
    if cut is not None:
        data = data[: int(len(data) * cut)]
    try:
        expected = _parse(data, None)
        password = None
    except Exception:  # noqa: BLE001 - a header password, or not a walkable RAR
        try:
            expected = _parse(data, _PASSWORD)
        except Exception:  # noqa: BLE001
            pytest.skip("the seekable walk does not list this archive either")
        password = _PASSWORD
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
    if not unrar_reads_rolling_volumes():
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
            source, streaming=True, password=password, **kwargs
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
@pytest.mark.parametrize("cut", [None, 0.5, 0.9])
@pytest.mark.parametrize("path", _SINGLE, ids=lambda p: p.name)
def test_a_pipe_pass_gives_what_the_seekable_pass_gives(
    path: Path, cut: float | None
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
    assert _pass(_pipe(data), password) == expected


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
    with open_archive(_pipe(raw), streaming=True, config=_config()) as reader:
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
    with open_archive(_pipe(raw), streaming=True, config=_config()) as reader:
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
    with open_archive(_pipe(raw), streaming=True, config=_config()) as reader:
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
        _pipe(raw), streaming=True, password=["wrong", "secret"], config=_config()
    ) as reader:
        got = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert got == files


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
def test_several_passwords_on_rar4_data_encryption_are_refused() -> None:
    """RAR 1.5-4 data has no password check value, and one ``unrar`` cannot try
    several: the encrypted member's read names one password as the fix."""
    raw = (_FIXTURES / "encryption__rar4.rar").read_bytes()
    with open_archive(
        _pipe(raw), streaming=True, password=["wrong", "password"]
    ) as reader:
        refused = []
        for member, stream in reader.stream_members():
            if member.is_encrypted and stream is not None:
                with pytest.raises(UnsupportedFeatureError, match="one password"):
                    stream.read()
                refused.append(member.name)
    assert refused


@requires_unrar_cli()
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("password", ["password", ["wrong", "password"]])
def test_a_header_password_is_found_from_several(password: object) -> None:
    raw = (_FIXTURES / "encrypted_header__rar4.rar").read_bytes()
    with open_archive(io.BytesIO(raw), password="header_password") as reader:
        expected = {m.name: reader.read(m) for m in reader.members() if m.is_file}
    del password
    with open_archive(
        _pipe(raw), streaming=True, password=["wrong", "header_password"]
    ) as reader:
        got = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert got == expected


@pytest.mark.usefixtures("rolling_unrar")
def test_a_volume_set_is_refused_from_a_pipe() -> None:
    raw = (_FIXTURES / "tinyvol_rnn.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError, match="volume set"):
        open_archive(_pipe(raw), streaming=True)


def test_unar_is_refused_from_a_pipe() -> None:
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError, match="RARLAB unrar"):
        open_archive(
            _pipe(raw), streaming=True, config=ArchiveyConfig(rar_decompressor="unar")
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
            _pipe(raw), streaming=True, config=ArchiveyConfig(rar_decompressor="unrar")
        )


def test_random_access_on_a_pipe_stays_refused() -> None:
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with pytest.raises(StreamNotSeekableError):
        open_archive(_pipe(raw), streaming=False)
