"""``SpoolLimits.max_bytes`` bounds the disk copy a RAR stream source needs for unrar.

A RAR opened from a stream is copied to temporary storage the first time a member has
to go through ``unrar``, which reads only files. These tests pin the bound on that copy:
refused before anything is written when the size is known, stopped at the limit when it
is not, measured across a whole volume set, and never applied to a path ``unrar`` reads
in place. The one path source that is copied, a prefixed archive read with ``unar``, is
bounded the same way.
"""

from __future__ import annotations

import hashlib
import io
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, RarDecompressor, SpoolLimits, open_archive
from archivey.exceptions import (
    ArchiveyUsageError,
    ResourceLimitError,
)
from archivey.internal.backends import rar_reader
from archivey.internal.spool import SpoolBudget
from archivey.types import ArchiveFormat
from tests.conftest import requires_binary

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
# Solid, so every member goes through unrar and needs the copy.
_SOLID = _FIXTURES / "basic_solid__.rar"
# Compressed, so unrar reads it and needs the volumes on disk; a stored member split
# across volumes is joined natively and copies nothing.
_VOLUMES = [_FIXTURES / "tinyvol_m3.part1.rar", _FIXTURES / "tinyvol_m3.part2.rar"]
_VOLUME_PAYLOAD = b"".join(
    hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(50)
)


def _config(max_bytes: int | None) -> ArchiveyConfig:
    return ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=max_bytes))


def _unrar_config(max_bytes: int | None) -> ArchiveyConfig:
    """Pinned to unrar, so a test of unrar's staging cannot fall back to unar's
    private directory where ``AUTO`` would reject the installed ``unrar``."""
    return ArchiveyConfig(
        rar_decompressor=RarDecompressor.UNRAR,
        spool_limits=SpoolLimits(max_bytes=max_bytes),
    )


def _volume_streams() -> list[io.BytesIO]:
    return [io.BytesIO(path.read_bytes()) for path in _VOLUMES]


def _volume_total() -> int:
    return sum(path.stat().st_size for path in _VOLUMES)


@pytest.fixture
def temp_artifacts(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Every temp file and directory the RAR reader creates."""
    created: list[Path] = []
    real_mkdtemp = rar_reader.tempfile.mkdtemp
    real_mkstemp = rar_reader.tempfile.mkstemp

    def spy_mkdtemp(*args: object, **kwargs: object) -> str:
        made = real_mkdtemp(*args, **kwargs)  # type: ignore[arg-type]
        created.append(Path(made))
        return made

    def spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, made = real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]
        created.append(Path(made))
        return fd, made

    monkeypatch.setattr(rar_reader.tempfile, "mkdtemp", spy_mkdtemp)
    monkeypatch.setattr(rar_reader.tempfile, "mkstemp", spy_mkstemp)
    return created


@pytest.fixture
def no_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the reader spawns unrar."""

    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError("unrar was spawned")

    monkeypatch.setattr(rar_reader, "open_unrar_p", refuse)


class _UnsizedStream(io.RawIOBase):
    """A seekable stream whose size archivey cannot probe cheaply.

    ``source_byte_size`` does not trust an end-seek on a stream type it does not know,
    so the reader reaches the copy without a size to check up front.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        chunk = self._data[self._pos : self._pos + len(buffer)]
        buffer[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: len(self._data)}
        self._pos = base[whence] + offset
        return self._pos

    def tell(self) -> int:
        return self._pos


# --- the setting ----------------------------------------------------------------------


def test_default_is_one_gib_and_unlimited_disables_it() -> None:
    assert ArchiveyConfig().spool_limits == SpoolLimits()
    assert SpoolLimits().max_bytes == 2**30
    assert SpoolLimits.UNLIMITED.max_bytes is None


@pytest.mark.parametrize("bad", [-1, True, "1", 1.5])
def test_bad_max_bytes_is_refused_at_construction(bad: object) -> None:
    with pytest.raises(ArchiveyUsageError, match=r"SpoolLimits\.max_bytes"):
        SpoolLimits(max_bytes=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["none", None, SpoolLimits, 0])
def test_config_refuses_a_non_spool_limits_value(bad: object) -> None:
    with pytest.raises(ArchiveyUsageError, match=r"spool_limits"):
        ArchiveyConfig(spool_limits=bad)  # type: ignore[arg-type]


# --- the budget itself ----------------------------------------------------------------


def _budget(max_bytes: int | None) -> SpoolBudget:
    return SpoolBudget(
        SpoolLimits(max_bytes=max_bytes),
        what="test copy",
        archive_name="a.rar",
        source_format=ArchiveFormat.RAR,
    )


def test_budget_copy_stops_at_the_limit_without_writing_past_it() -> None:
    out = io.BytesIO()
    with pytest.raises(ResourceLimitError, match=r"SpoolLimits\.max_bytes=100"):
        _budget(100).copy(io.BytesIO(b"x" * 101), out)
    assert len(out.getvalue()) <= 100


def test_budget_copy_exactly_at_the_limit_succeeds() -> None:
    out = io.BytesIO()
    _budget(100).copy(io.BytesIO(b"x" * 100), out)
    assert out.getvalue() == b"x" * 100


def test_budget_is_shared_across_copies() -> None:
    budget = _budget(100)
    budget.copy(io.BytesIO(b"x" * 60), io.BytesIO())
    with pytest.raises(ResourceLimitError):
        budget.copy(io.BytesIO(b"x" * 41), io.BytesIO())


def test_budget_check_total_counts_bytes_already_written() -> None:
    budget = _budget(100)
    budget.copy(io.BytesIO(b"x" * 60), io.BytesIO())
    budget.check_total(40)
    with pytest.raises(ResourceLimitError):
        budget.check_total(41)


class _FailsAfterOneChunk(io.RawIOBase):
    """Yields one chunk, then fails like a disk or source I/O error part-way."""

    def __init__(self, chunk: bytes) -> None:
        self._chunk: bytes | None = chunk

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        if self._chunk is None:
            raise OSError(5, "Input/output error")
        chunk, self._chunk = self._chunk, None
        return chunk


def test_budget_refusal_names_bytes_an_earlier_attempt_spent() -> None:
    """A refusal whose own size fits must say what the earlier attempt charged."""
    budget = _budget(100)
    budget.check_total(80)
    with pytest.raises(OSError):
        budget.copy(_FailsAfterOneChunk(b"x" * 40), io.BytesIO())  # type: ignore[arg-type]
    with pytest.raises(ResourceLimitError) as info:
        budget.check_total(80)
    message = str(info.value)
    assert "80 bytes on top of 40 bytes this reader already spooled" in message
    assert "SpoolLimits.max_bytes=100" in message


def test_budget_copy_refusal_names_what_is_left() -> None:
    budget = _budget(100)
    budget.copy(io.BytesIO(b"x" * 60), io.BytesIO())
    with pytest.raises(ResourceLimitError) as info:
        budget.copy(io.BytesIO(b"x" * 41), io.BytesIO())
    assert "more than 40 bytes on top of 60 bytes" in str(info.value)


def test_budget_refuses_everything_after_its_first_refusal() -> None:
    budget = _budget(100)
    with pytest.raises(ResourceLimitError):
        budget.check_total(101)
    # Well within the limit on its own, and still refused, before any read.
    with pytest.raises(ResourceLimitError, match="101 bytes"):
        budget.check_total(None)
    src = io.BytesIO(b"x")
    with pytest.raises(ResourceLimitError):
        budget.copy(src, io.BytesIO())
    assert src.tell() == 0


def test_budget_try_reserve_charges_or_declines_without_refusing() -> None:
    """A write with a fallback (a solid pass keeping a file copy's source) is charged
    when it fits; when it does not, nothing is charged and nothing later is refused."""
    budget = _budget(100)
    assert budget.try_reserve(60)
    assert not budget.try_reserve(41)
    budget.check_total(40)
    with pytest.raises(ResourceLimitError, match="41 bytes on top of 60 bytes"):
        budget.check_total(41)
    assert not budget.try_reserve(1)


def test_budget_release_gives_a_reservation_back() -> None:
    """A kept file deleted at the end of a pass no longer counts: the next copy has
    the whole allowance again. A refusal already made stays."""
    budget = _budget(100)
    assert budget.try_reserve(60)
    budget.release(60)
    budget.check_total(100)
    assert budget.try_reserve(100)
    with pytest.raises(ValueError, match="only 100 are charged"):
        budget.release(101)
    budget.release(100)
    with pytest.raises(ResourceLimitError):
        budget.check_total(101)
    budget.release(0)
    with pytest.raises(ResourceLimitError):
        budget.check_total(1)


def test_budget_made_by_a_reservation_takes_the_first_copys_name() -> None:
    budget = SpoolBudget(
        SpoolLimits(max_bytes=10),
        what=None,
        archive_name="a.rar",
        source_format=ArchiveFormat.RAR,
    )
    assert budget.try_reserve(5)
    budget.describe("the whole stream source")
    budget.describe("a later name")
    with pytest.raises(ResourceLimitError, match="the whole stream source"):
        budget.check_total(6)


def test_budget_without_a_limit_copies_everything() -> None:
    out = io.BytesIO()
    budget = _budget(None)
    budget.check_total(10**15)
    budget.copy(io.BytesIO(b"x" * 5000), out)
    assert len(out.getvalue()) == 5000


# --- single stream source -------------------------------------------------------------


@requires_binary("unrar")
def test_stream_within_the_limit_reads(temp_artifacts: list[Path]) -> None:
    blob = _SOLID.read_bytes()
    with open_archive(io.BytesIO(blob), config=_config(len(blob))) as archive:
        assert archive.read("file1.txt")
        assert len(temp_artifacts) == 1
    assert not temp_artifacts[0].exists()


def test_stream_over_the_limit_refuses_before_writing_or_spawning(
    temp_artifacts: list[Path], no_unrar: None
) -> None:
    blob = _SOLID.read_bytes()
    with open_archive(io.BytesIO(blob), config=_config(len(blob) - 1)) as archive:
        # Listing is served from the stream and needs no copy.
        assert "file1.txt" in [m.name for m in archive.members()]
        with pytest.raises(ResourceLimitError) as info:
            archive.read("file1.txt")
    # The exact type, not the internal always-stop subclass.
    assert type(info.value) is ResourceLimitError
    message = str(info.value)
    assert "SpoolLimits.max_bytes" in message
    assert f"{len(blob)} bytes" in message
    assert info.value.source_format is ArchiveFormat.RAR
    assert temp_artifacts == []


def test_stream_of_unknown_size_stops_at_the_limit_and_removes_the_copy(
    temp_artifacts: list[Path], no_unrar: None
) -> None:
    blob = _SOLID.read_bytes()
    source = _UnsizedStream(blob)
    with (
        open_archive(source, config=_config(len(blob) // 2)) as archive,
        pytest.raises(ResourceLimitError, match=r"SpoolLimits\.max_bytes"),
    ):
        archive.read("file1.txt")
    assert len(temp_artifacts) == 1
    assert not temp_artifacts[0].exists()


def test_zero_limit_keeps_direct_reads_and_refuses_the_copy(
    temp_artifacts: list[Path], no_unrar: None
) -> None:
    stored = (_FIXTURES / "stored_m0.rar").read_bytes()
    with open_archive(io.BytesIO(stored), config=_config(0)) as archive:
        member = next(m for m in archive.members() if m.is_file)
        assert archive.read(member) == b"stored payload"
    solid = _SOLID.read_bytes()
    with (
        open_archive(io.BytesIO(solid), config=_config(0)) as archive,
        pytest.raises(ResourceLimitError),
    ):
        archive.read("file1.txt")
    assert temp_artifacts == []


@requires_binary("unrar")
@pytest.mark.parametrize(
    "limits",
    [SpoolLimits.UNLIMITED, SpoolLimits(max_bytes=None)],
    ids=["UNLIMITED", "None"],
)
def test_no_limit_never_refuses(limits: SpoolLimits) -> None:
    blob = _SOLID.read_bytes()
    config = ArchiveyConfig(spool_limits=limits)
    with open_archive(io.BytesIO(blob), config=config) as archive:
        assert archive.read("file1.txt")
    with open_archive(_UnsizedStream(blob), config=config) as archive:
        assert archive.read("file1.txt")


def _only_note(source: object, max_bytes: int | None) -> str:
    with open_archive(source, config=_config(max_bytes)) as archive:  # type: ignore[arg-type]
        (note,) = archive.cost.notes
    return note


def test_cost_note_names_the_limit() -> None:
    blob = _SOLID.read_bytes()
    note = _only_note(io.BytesIO(blob), len(blob))
    assert "will copy the whole archive to disk" in note
    assert f"SpoolLimits.max_bytes={len(blob)}" in note
    note = _only_note(_volume_streams(), _volume_total())
    assert "will copy every volume to a temp directory" in note
    assert f"SpoolLimits.max_bytes={_volume_total()}" in note
    for source in (io.BytesIO(blob), _volume_streams()):
        note = _only_note(source, None)
        assert "will copy" in note
        assert "no size limit" in note


@pytest.mark.parametrize(
    ("source", "max_bytes", "reason"),
    [
        pytest.param(
            lambda: io.BytesIO(_SOLID.read_bytes()),
            0,
            "max_bytes=0 allows no copy",
            id="zero",
        ),
        # Zero decides the outcome even when the size is not known at open.
        pytest.param(
            lambda: _UnsizedStream(_SOLID.read_bytes()),
            0,
            "max_bytes=0 allows no copy",
            id="zero-unknown-size",
        ),
        pytest.param(
            lambda: io.BytesIO(_SOLID.read_bytes()),
            _SOLID.stat().st_size - 1,
            f"a copy of the archive would be {_SOLID.stat().st_size} bytes",
            id="stream-over",
        ),
        pytest.param(
            _volume_streams,
            _volume_total() - 1,
            f"a copy of every volume would be {_volume_total()} bytes",
            id="volumes-over",
        ),
        pytest.param(
            _volume_streams, 0, "max_bytes=0 allows no copy", id="volumes-zero"
        ),
    ],
)
def test_cost_note_says_refused_when_the_limit_decides_at_open(
    source: Callable[[], object], max_bytes: int, reason: str
) -> None:
    """No copy is promised when the limit already rules one out."""
    note = _only_note(source(), max_bytes)
    assert "will be refused" in note
    assert reason in note
    assert "will copy" not in note


def test_cost_note_for_an_unknown_size_names_the_limit() -> None:
    blob = _SOLID.read_bytes()
    note = _only_note(_UnsizedStream(blob), len(blob) - 1)
    assert "will copy the whole archive to disk" in note
    assert f"SpoolLimits.max_bytes={len(blob) - 1}" in note


def test_over_default_limit_is_refused(
    tmp_path: Path, temp_artifacts: list[Path], no_unrar: None
) -> None:
    """The 1 GiB default itself, driven with a sparse file one byte over it.

    ``test_default_is_one_gib_and_unlimited_disables_it`` pins the constant; this one
    pins its wiring, that a config left at its default actually refuses. No corpus
    archive comes near 1 GiB, so this is the only test that would notice the default
    not reaching the guard. The trailing zeros sit after the end-of-archive block,
    where the parser does not read; opening the file as a stream makes it a copy
    candidate. Nothing is read or copied from the zeros.

    The cost: ext4, APFS and tmpfs keep the file sparse, so it takes no space. NTFS
    does not unless the file is marked sparse, so on Windows the file claims a real
    gigabyte of the temp filesystem. The test skips when that filesystem has less
    free space than the file, or refuses the size.
    """
    size = 2**30 + 1
    if shutil.disk_usage(tmp_path).free < size + (64 << 20):
        pytest.skip("temp filesystem has too little free space for the 1 GiB file")
    big = tmp_path / "big.rar"
    with big.open("wb") as out:
        out.write(_SOLID.read_bytes())
        try:
            out.truncate(size)
        except OSError as exc:
            pytest.skip(f"temp filesystem cannot hold a {size}-byte file: {exc}")
    with (
        big.open("rb") as handle,
        open_archive(handle) as archive,
        pytest.raises(ResourceLimitError, match=str(size)),
    ):
        archive.read("file1.txt")
    assert temp_artifacts == []


# --- stream volume set ----------------------------------------------------------------


@requires_binary("unrar")
def test_volume_set_within_the_limit_reads(temp_artifacts: list[Path]) -> None:
    with open_archive(_volume_streams(), config=_config(_volume_total())) as archive:
        assert archive.read("payload.bin") == _VOLUME_PAYLOAD
        assert len(temp_artifacts) == 1
    assert not temp_artifacts[0].exists()


def test_volume_set_limit_weighs_the_total_not_each_volume(
    temp_artifacts: list[Path], no_unrar: None
) -> None:
    # Every volume fits on its own; the set does not.
    limit = _volume_total() - 1
    assert all(path.stat().st_size <= limit for path in _VOLUMES)
    with (
        open_archive(_volume_streams(), config=_config(limit)) as archive,
        pytest.raises(ResourceLimitError, match=r"every volume"),
    ):
        archive.read("payload.bin")
    assert temp_artifacts == []


@pytest.mark.parametrize(
    ("sources", "limit"),
    [
        # Runs out part-way through the second volume.
        pytest.param(
            _volume_streams, _VOLUMES[0].stat().st_size + 10, id="stream-volumes"
        ),
        # A mixed set copies its file volume too, and that copy counts. The limit
        # holds the stream volume alone but runs out inside the first volume, which
        # is a path.
        pytest.param(
            lambda: [_VOLUMES[0], io.BytesIO(_VOLUMES[1].read_bytes())],
            _VOLUMES[1].stat().st_size + 10,
            id="file-volume-in-a-mixed-set",
        ),
    ],
)
def test_volume_set_limit_stops_mid_copy_and_removes_the_directory(
    monkeypatch: pytest.MonkeyPatch,
    temp_artifacts: list[Path],
    no_unrar: None,
    sources: Callable[[], list[io.BytesIO | Path]],
    limit: int,
) -> None:
    """The copy itself enforces the limit, not only the up-front total.

    The up-front check is switched off, so what refuses here is the budget running
    out during the copy.
    """
    monkeypatch.setattr(SpoolBudget, "check_total", lambda self, total: None)
    with (
        open_archive(sources(), config=_config(limit)) as archive,
        pytest.raises(ResourceLimitError),
    ):
        archive.read("payload.bin")
    assert len(temp_artifacts) == 1
    assert not temp_artifacts[0].exists()


def _spread_volumes(tmp_path: Path) -> list[Path]:
    """The volumes in two directories, so unrar cannot find the second by name and
    the reader stages the set in a private directory under its own names."""
    paths = []
    for index, volume in enumerate(_VOLUMES):
        directory = tmp_path / f"dir{index}"
        directory.mkdir()
        paths.append(Path(shutil.copy(volume, directory)))
    return paths


def _refuse_to_link_the_second(monkeypatch: pytest.MonkeyPatch) -> None:
    link = rar_reader._link_file

    def refuse_the_second(source: Path, dest: Path) -> None:
        if source.name == _VOLUMES[1].name:
            raise OSError("this volume will not link")
        link(source, dest)

    monkeypatch.setattr(rar_reader, "_link_file", refuse_the_second)


@requires_binary("unrar")
def test_staged_volume_set_charges_only_the_volumes_it_copies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Where one volume will not link, only that one is copied and charged.

    The fallback used to copy the whole set once any link failed, so a limit that
    held the one unlinkable volume still refused the read. unar's private directory
    already copied only the volumes that would not link; both now share that rule.
    """
    paths = _spread_volumes(tmp_path)
    _refuse_to_link_the_second(monkeypatch)
    second = _VOLUMES[1].stat().st_size
    assert second < _volume_total() - 1
    with open_archive(paths, config=_unrar_config(second)) as archive:
        assert archive.read("payload.bin") == _VOLUME_PAYLOAD
    with (
        open_archive(paths, config=_unrar_config(second - 1)) as archive,
        pytest.raises(ResourceLimitError, match=r"beside the others"),
    ):
        archive.read("payload.bin")


@requires_binary("unrar")
def test_staged_volume_set_stops_mid_copy_and_removes_the_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    temp_artifacts: list[Path],
    no_unrar: None,
) -> None:
    """The staging copy enforces the limit itself, and a refusal leaves nothing.

    The up-front check is switched off, so what refuses is the budget running out
    part-way through the one volume that will not link.
    """
    paths = _spread_volumes(tmp_path)
    _refuse_to_link_the_second(monkeypatch)
    monkeypatch.setattr(SpoolBudget, "check_total", lambda self, total: None)
    limit = _VOLUMES[1].stat().st_size // 2
    with (
        open_archive(paths, config=_unrar_config(limit)) as archive,
        pytest.raises(ResourceLimitError),
    ):
        archive.read("payload.bin")
    assert len(temp_artifacts) == 1
    assert not temp_artifacts[0].exists()


# --- path sources ---------------------------------------------------------------------


@requires_binary("unrar")
def test_path_source_is_never_copied_or_refused(temp_artifacts: list[Path]) -> None:
    with open_archive(_SOLID, config=_config(0)) as archive:
        assert archive.cost.notes == ()
        assert archive.read("file1.txt")
    with open_archive(_VOLUMES[0], config=_config(0)) as archive:
        assert archive.read("payload.bin") == _VOLUME_PAYLOAD
    assert temp_artifacts == []


# Compressed and not solid: unar reads it, and its members need the copy.
_UNAR_READABLE = (
    Path(__file__).parent / "fixtures" / "corpus" / "rar" / "compressed.rar"
)


def _prefixed_copy(tmp_path: Path) -> Path:
    """A path source with 4 KiB in front of the RAR, which unar needs copied away."""
    prefixed = tmp_path / "prefixed.rar"
    prefixed.write_bytes(b"\x00" * 4096 + _UNAR_READABLE.read_bytes())
    return prefixed


_UNAR = {"rar_decompressor": "unar"}


@requires_binary("unar")
def test_prefixed_path_over_the_limit_is_refused_under_unar_before_copying(
    tmp_path: Path, temp_artifacts: list[Path]
) -> None:
    prefixed = _prefixed_copy(tmp_path)
    limit = _UNAR_READABLE.stat().st_size - 1
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=limit), **_UNAR)
    with open_archive(prefixed, config=config) as archive:
        (note,) = archive.cost.notes
        assert note.startswith("Reading a member that unar has to read")
        # A stored encrypted member may still need the program, so it is not promised.
        assert "such as stored, unencrypted ones, can still be read" in note
        with pytest.raises(ResourceLimitError, match="rar_decompressor to 'unrar'"):
            archive.read("zeros.bin")
    assert temp_artifacts == []


@requires_binary("unar")
def test_prefixed_path_within_the_limit_reads_under_unar(
    tmp_path: Path, temp_artifacts: list[Path]
) -> None:
    prefixed = _prefixed_copy(tmp_path)
    config = ArchiveyConfig(
        spool_limits=SpoolLimits(max_bytes=_UNAR_READABLE.stat().st_size), **_UNAR
    )
    with open_archive(prefixed, config=config) as archive:
        (note,) = archive.cost.notes
        assert "SpoolLimits.max_bytes=" in note
        assert archive.read("zeros.bin") == b"\x00" * 8192
    # unar's private directory, and the copy made inside it.
    assert len(temp_artifacts) == 2
    assert not any(path.exists() for path in temp_artifacts)


def test_refusal_is_remembered_so_a_retry_writes_nothing(
    temp_artifacts: list[Path], no_unrar: None
) -> None:
    """One reader's limit holds across retries, not per attempt.

    With no size to check up front, each refused attempt writes up to the limit before
    it trips. A caller that catches the error and reads again, or ``extract_all`` with
    ``OnError.CONTINUE`` moving to the next member, must not start the copy over.
    """
    blob = _SOLID.read_bytes()
    with open_archive(_UnsizedStream(blob), config=_config(len(blob) // 2)) as archive:
        names = [m.name for m in archive.members() if m.is_file]
        assert len(names) > 1
        for name in names * 2:
            with pytest.raises(ResourceLimitError, match=r"SpoolLimits\.max_bytes"):
                archive.read(name)
    assert len(temp_artifacts) == 1
