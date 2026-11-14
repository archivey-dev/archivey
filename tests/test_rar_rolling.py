"""Rolling RAR volumes: ``unrar -vp`` reads a synthetic archive written one volume at a
time, and prints what it prints for the original archive.

``rar_rolling`` splits the synthetic archive :mod:`rar_synthetic` builds into volumes
and feeds them to ``unrar`` as it asks for them. These tests read every member with
packed data of every committed RAR fixture (the member alone, or its solid chain)
through volumes small enough that most members split, and compare the output with
what the reader reads from the original archive.
"""

from __future__ import annotations

import dataclasses
import os
import stat
import subprocess
from io import BytesIO
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, SpoolLimits, open_archive
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ReadError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.internal.backends import (
    rar_reader,
    rar_rolling as rl,
    rar_synthetic as rs,
)
from archivey.internal.backends.rar_parser import RarMemberInfo
from archivey.internal.backends.rar_reader import RarReader
from archivey.internal.backends.rar_unrar import unrar_reads_rolling_volumes
from tests.conftest import requires_binary, requires_unrar_cli
from tests.test_rar_synthetic import _FIXTURES, _fixture_params, _password


def _members(
    reader: RarReader, raws: list[RarMemberInfo], target: int, password: str | None
) -> list[rs.SyntheticMember]:
    """The synthetic members a read of ``raws[target]`` needs, as the reader builds them."""
    archive = reader._archive
    indices = rs.solid_chain(raws, target) if archive.is_solid else [target]
    chain = [i for i in indices if rs.has_packed_data(raws[i])]
    out = []
    for position, index in enumerate(chain):
        entry = reader._synthetic_entry("m", raws[index], position)
        assert entry is not None
        out.append(entry)
    return out


def _rolling_read(
    reader: RarReader,
    raws: list[RarMemberInfo],
    target: int,
    password: str | None,
    volume_bytes: int,
    min_part_bytes: int,
) -> tuple[bytes, int]:
    """``unrar p``'s output for ``raws[target]`` read through rolling volumes, and the
    number of volumes."""
    archive = reader._archive
    members = _members(reader, raws, target, password)
    volumes = rl.RollingVolumes(
        archive.version,
        members,
        solid=archive.is_solid,
        volume_bytes=volume_bytes,
        min_part_bytes=min_part_bytes,
    )
    try:
        proc, stdout, feeder = rl.start_rolling_unrar(
            volumes,
            password=password,
            member=(
                rs.placeholder_mask(len(members) - 1, raws[target], archive.version)
                if archive.is_solid
                else None
            ),
            version_control=True,
            rar5=archive.version == 5,
        )
        with stdout:
            out = stdout.read()
        rc = proc.wait()
        feeder.join()
        assert feeder.error is None, feeder.error
        assert rc == 0, feeder.stderr_tail
        assert volumes.finished
        return out, volumes.count
    finally:
        volumes.close()


@requires_unrar_cli()
@pytest.mark.parametrize(
    ("volume_bytes", "min_part_bytes"), [(400, 64), (1500, 300), (8192, 2048)]
)
@pytest.mark.parametrize("volumes", list(_fixture_params()), ids=lambda v: v[0].name)
def test_rolling_read_matches_the_original(
    volumes: list[Path], volume_bytes: int, min_part_bytes: int
) -> None:
    if not unrar_reads_rolling_volumes():
        pytest.skip("this unrar is older than the one rolling volumes were measured on")
    password = _password(volumes[0])
    source = volumes[0] if len(volumes) == 1 else volumes
    with open_archive(source, password=password) as reader:
        assert isinstance(reader, RarReader)
        members = list(reader.members())
        raws = [m._raw for m in members]
        compared = 0
        for index, member in enumerate(members):
            if not rs.has_packed_data(raws[index]) or raws[index].is_symlink:
                continue
            try:
                with reader.open(member) as stream:
                    want = stream.read()
            except ArchiveyError:
                continue
            try:
                entry = _members(reader, raws, index, password)
            except ArchiveyError:
                continue
            del entry
            got, count = _rolling_read(
                reader, raws, index, password, volume_bytes, min_part_bytes
            )
            assert got == want, member.name
            if volume_bytes == 400 and raws[index].compress_size > 2 * volume_bytes:
                assert count > 1
            compared += 1
        if any(rs.has_packed_data(raw) for raw in raws):
            assert compared, "no member compared"


# --- Building volumes ------------------------------------------------------------


def _member(header: bytes, data: bytes) -> rs.SyntheticMember:
    return rs.SyntheticMember(
        header=header, data=lambda: [(BytesIO(data), len(data))], data_size=len(data)
    )


def _rar5_header(size: int) -> bytes:
    """A RAR5 FILE header for a stored member of ``size`` bytes with a CRC32."""
    fields = (
        rs._vint(0x04)  # file flags: CRC32 present
        + rs._vint(size)
        + rs._vint(0)  # attributes
        + b"\x00\x00\x00\x00"  # CRC32
        + rs._vint(0)  # compression info: stored
        + rs._vint(1)  # host OS
        + rs._vint(1)
        + b"m"
    )
    return rs._rar5_block(
        rs._vint(2) + rs._vint(rs._RAR5_FLAG_DATA) + rs._vint(size) + fields
    )


def test_volumes_hold_one_file_at_a_time_and_split_with_whole_parts() -> None:
    data = bytes(range(256)) * 8
    volumes = rl.RollingVolumes(
        5, [_member(_rar5_header(len(data)), data)], solid=False, volume_bytes=700
    )
    try:
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(volumes.dir).st_mode) == 0o700
        sizes = []
        while not volumes.finished:
            path = volumes.write_next()
            assert sorted(volumes.dir.iterdir()) == [path]
            sizes.append(path.stat().st_size)
            if os.name == "posix":
                assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert len(sizes) > 2
        assert max(sizes) <= 700
        with pytest.raises(ValueError, match="every volume"):
            volumes.write_next()
    finally:
        volumes.close()
    assert not volumes.dir.exists()
    volumes.close()


def test_a_small_member_starts_the_next_volume_whole() -> None:
    first, second = b"a" * 300, b"b" * 300
    members = [
        _member(_rar5_header(len(first)), first),
        _member(_rar5_header(len(second)), second),
    ]
    # Room for the first member and part of the second, but not two parts of
    # min_part_bytes: the second is not split.
    volumes = rl.RollingVolumes(
        5, members, solid=False, volume_bytes=500, min_part_bytes=200
    )
    try:
        one = volumes.write_next().read_bytes()
        two = volumes.write_next().read_bytes()
        assert volumes.finished
        assert first in one and b"b" not in one
        assert second in two
    finally:
        volumes.close()


def test_a_member_that_fits_no_volume_is_refused() -> None:
    data = b"x" * 100
    volumes = rl.RollingVolumes(
        5, [_member(_rar5_header(len(data)), data)], solid=False, volume_bytes=40
    )
    try:
        with pytest.raises(ResourceLimitError, match="do not fit one volume"):
            volumes.write_next()
    finally:
        volumes.close()


def test_a_member_whose_data_ends_early_raises_and_closes_its_stream() -> None:
    stream = BytesIO(b"short")
    member = rs.SyntheticMember(
        header=_rar5_header(50), data=lambda: [(stream, 50)], data_size=50
    )
    volumes = rl.RollingVolumes(5, [member], solid=False, volume_bytes=1000)
    try:
        with pytest.raises(TruncatedError):
            volumes.write_next()
    finally:
        volumes.close()
    assert stream.closed


def test_a_non_last_part_carries_no_checksum() -> None:
    """RAR5: the part split after drops its CRC32 and hash record; the last part
    keeps the member's header. RAR 1.5-4: FILE_CRC 0xFFFFFFFF on the first part."""
    header = _rar5_header(10)
    first = rs.parse_stored_header(
        5, rl.part_header(5, header, data_size=4, before=False, after=True)
    )
    last = rs.parse_stored_header(
        5, rl.part_header(5, header, data_size=6, before=True, after=False)
    )
    assert first.crc32 is None and first.data_size == 4 and first.split
    assert last.crc32 == 0 and last.data_size == 6 and last.split
    plain = rs.parse_stored_header(
        5, rl.part_header(5, header, data_size=10, before=False, after=False)
    )
    assert plain.raw == header


# --- The feeder --------------------------------------------------------------------


class _Chunks:
    """A stderr whose reads return the scripted chunks one at a time."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read1(self, n: int = -1) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        pass


class _FakeProc:
    """Enough of ``Popen`` for :class:`VolumeFeeder`: scripted stderr, recorded stdin."""

    def __init__(self, *stderr: bytes) -> None:
        self.stderr = _Chunks(list(stderr))
        self.stdin = BytesIO()
        self.killed = False

    def kill(self) -> None:
        self.killed = True


def test_the_feeder_stops_unrar_on_a_question_it_does_not_answer() -> None:
    data = b"z" * 10
    volumes = rl.RollingVolumes(
        5, [_member(_rar5_header(10), data)] * 3, solid=False, volume_bytes=80
    )
    try:
        volumes.write_next()
        proc = _FakeProc(b"\nRead error in v.part000001.rar\n[R]etry, [A]bort ")
        feeder = rl.VolumeFeeder(proc, volumes)  # type: ignore[arg-type]
        feeder.join()
        assert proc.killed
        assert isinstance(feeder.error, ReadError)
        assert "[R]etry" in str(feeder.error)
        assert volumes.count == 1
    finally:
        volumes.close()


def test_the_feeder_answers_only_the_expected_volume() -> None:
    data = b"z" * 10
    volumes = rl.RollingVolumes(
        5, [_member(_rar5_header(10), data)] * 3, solid=False, volume_bytes=80
    )
    try:
        volumes.write_next()
        prompt = b"\nInsert disk with /t/v.part000002.rar [C]ontinue, [Q]uit "
        again = b"\nInsert disk with /t/v.part000002.rar [C]ontinue, [Q]uit "
        proc = _FakeProc(prompt, again)
        feeder = rl.VolumeFeeder(proc, volumes)  # type: ignore[arg-type]
        feeder.join()
        # The first prompt is answered; the same name again is a question the
        # feeder does not answer (the volume it wrote did not open).
        assert volumes.count == 2
        assert proc.stdin.getvalue() == b"\n"
        assert proc.killed and isinstance(feeder.error, ReadError)
    finally:
        volumes.close()


# --- The reader ------------------------------------------------------------------


def _rar(tmp_path: Path, files: dict[str, bytes], *switches: str) -> bytes:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, data in files.items():
        (src / name).write_bytes(data)
    archive = tmp_path / "out.rar"
    archive.unlink(missing_ok=True)
    subprocess.run(
        ["rar", "a", "-idq", *switches, str(archive), *files],
        cwd=src,
        check=True,
        timeout=60,
    )
    return archive.read_bytes()


@pytest.fixture
def rolling_unrar() -> None:
    if not unrar_reads_rolling_volumes():
        pytest.skip("this unrar is older than the one rolling volumes were measured on")


@pytest.fixture
def unrar_runs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """The keyword arguments of every ``unrar`` the reader starts."""
    runs: list[dict[str, object]] = []
    real = rar_reader.open_unrar_p

    def spy(*args: object, **kwargs: object) -> object:
        runs.append(kwargs)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)
    return runs


def _config(limit: int | None) -> ArchiveyConfig:
    return ArchiveyConfig(
        rar_decompressor="unrar", spool_limits=SpoolLimits(max_bytes=limit)
    )


def _text(size: int) -> bytes:
    """Random data that compresses (hex digits), so ``rar`` does not store it."""
    return os.urandom(size // 2).hex().encode()


def _archive(
    tmp_path: Path, kind: str, files: dict[str, bytes], *switches: str
) -> tuple[bytes, str | None, dict[str, bytes]]:
    """``(archive bytes, password, contents)`` of a ``kind`` archive: RAR5 written
    here (``rar`` 7 writes no RAR 1.5-4), RAR 1.5-4 a committed fixture."""
    if kind == "rar4-p":
        name = (
            "encryption_large_solid__rar4.rar"
            if "-s" in switches
            else ("encryption_large__rar4.rar")
        )
        path = _FIXTURES / name
        with open_archive(path, password="password") as reader:
            contents = {m.name: reader.read(m) for m in reader.members()}
        return path.read_bytes(), "password", contents
    password = "secret" if kind == "rar5-p" else None
    extra = ("-psecret",) if password else ()
    return _rar(tmp_path, files, "-ma5", *switches, *extra), password, files


_KINDS = ["rar5", "rar5-p", "rar4-p"]


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("kind", _KINDS)
def test_a_large_member_of_a_stream_reads_through_rolling_volumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unrar_runs: list[dict[str, object]],
    kind: str,
) -> None:
    """A member over the spool limit, read from a stream, is not refused: it is
    fed to unrar one volume at a time, and the spool never holds more than one."""
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    raw, password, files = _archive(tmp_path, kind, {"big.bin": _text(150_000)})
    unrar_runs.clear()  # the fixture's own reads
    with open_archive(
        BytesIO(raw), password=password, config=_config(40_000)
    ) as reader:
        for name, content in files.items():
            assert reader.read(name) == content
        peak = reader._resource_usage().spool_bytes
    assert [run.get("volume_pause") for run in unrar_runs] == [True] * len(files)
    assert 0 < peak <= 20_000


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("kind", _KINDS)
def test_a_solid_chain_over_the_spool_limit_reads_through_rolling_volumes(
    tmp_path: Path, unrar_runs: list[dict[str, object]], kind: str
) -> None:
    """A solid stream copy the limit has no room to keep is not refused: the chain
    is fed to unrar in volumes, from the stream start, on each read."""
    files = {f"f{i}.bin": _text(60_000) for i in range(4)}
    raw, password, files = _archive(tmp_path, kind, files, "-s")
    unrar_runs.clear()  # the fixture's own reads
    names = list(files)
    first, last = names[0], names[-1]
    with open_archive(
        BytesIO(raw), password=password, config=_config(40_000)
    ) as reader:
        assert reader.read(last) == files[last]
        assert reader.read(first) == files[first]
    assert [run.get("volume_pause") for run in unrar_runs][:1] == [True]


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
@pytest.mark.parametrize("kind", _KINDS)
def test_a_solid_pass_over_a_stream_is_one_rolling_run(
    tmp_path: Path, unrar_runs: list[dict[str, object]], kind: str
) -> None:
    """stream_members() over a solid archive from a stream: one unrar, fed volumes,
    with a spool limit far below the archive."""
    files = {f"f{i}.bin": _text(60_000) for i in range(5)}
    files["small.txt"] = b"small"
    raw, password, files = _archive(tmp_path, kind, files, "-s")
    unrar_runs.clear()  # the fixture's own reads
    got: dict[str, bytes] = {}
    with open_archive(
        BytesIO(raw), password=password, config=_config(40_000)
    ) as reader:
        for member, stream in reader.stream_members():
            if stream is not None and member.is_file:
                got[member.name] = stream.read()
        peak = reader._resource_usage().spool_bytes
    assert got == files
    assert [run.get("volume_pause") for run in unrar_runs] == [True]
    assert 0 < peak <= 20_000


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
def test_a_rolling_pass_closed_early_removes_its_volumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    made: list[rl.RollingVolumes] = []
    real = rl.RollingVolumes.__init__

    def record(self: rl.RollingVolumes, *args: object, **kwargs: object) -> None:
        real(self, *args, **kwargs)  # type: ignore[arg-type]
        made.append(self)

    monkeypatch.setattr(rl.RollingVolumes, "__init__", record)
    files = {f"f{i}.bin": _text(60_000) for i in range(4)}
    raw = _rar(tmp_path, files, "-ma5", "-s")
    with open_archive(BytesIO(raw), config=_config(40_000)) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read(10) == files[member.name][:10]
            break
        assert len(made) == 1
    assert not made[0].dir.exists()


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.usefixtures("rolling_unrar")
def test_a_source_cut_short_while_feeding_raises_truncated(
    tmp_path: Path,
) -> None:
    """The source ends while a later volume is written: the read raises what the
    source raised, not unrar's exit status."""
    payload = _text(200_000)
    raw = _rar(tmp_path, {"a.bin": payload, "b.bin": b"tail"}, "-ma5", "-s")
    with open_archive(BytesIO(raw), config=_config(40_000)) as reader:
        # Cut the source after the listing: the volumes after the first fail.
        source = reader._shared
        real_view = source.view

        def short_view(start: int, length: int | None = None) -> object:
            if start > 30_000:
                return BytesIO(b"")
            return real_view(start, length)

        reader._shared.view = short_view  # type: ignore[method-assign]
        with pytest.raises((TruncatedError, CorruptionError)):
            for _member, stream in reader.stream_members():
                if stream is not None:
                    stream.read()


@requires_unrar_cli()
@pytest.mark.parametrize("version", [(6, 23), (7, 0)])
def test_rolling_volumes_need_unrar_7(
    monkeypatch: pytest.MonkeyPatch, version: tuple[int, int]
) -> None:
    from archivey.internal.backends import rar_unrar

    found = rar_unrar.find_rarlab_unrar()
    probe = rar_unrar._cached_unrar[found]
    monkeypatch.setitem(
        rar_unrar._cached_unrar, found, dataclasses.replace(probe, version=version)
    )
    assert rar_unrar.unrar_reads_rolling_volumes() is (version >= (7, 0))
