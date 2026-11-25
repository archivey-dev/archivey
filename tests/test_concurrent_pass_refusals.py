"""A pass has the reader to itself, with or without ``concurrent_operations=True``.

A pass is ``stream_members()``, ``extract_all()``, ``verify_all()``, or a streaming
reader's listing (iteration, ``members_report()``). While one runs, every lookup call
(``open()``, ``read()``, ``get()``, ``members()``, ``members_report()``, iteration) and
every other pass raises ``ArchiveyUsageError``, from the loop body and from other
threads, and the pass goes on unharmed. Metadata (``format``, ``info``, ``cost``,
``diagnostics``, ``in``) stays readable, and ``members_report_if_available()`` answers
the report the pass pinned when it started, reading nothing. A pass does not start
beside another call, and a data pass not beside a stream from ``open()``. The
bookkeeping itself is unit-tested at the bottom.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    ArchiveyUsageError,
    ListingLimits,
    ReadError,
    ResourceLimitError,
    TruncatedError,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.internal import base_reader
from archivey.internal.reader_state import PassKind, ReaderState
from archivey.reader import ArchiveReader
from archivey.types import MemberStreams
from tests.cab_util import CabFile, CabFolder, write_cab
from tests.conftest import requires, requires_binary

pytestmark = pytest.mark.concurrent_reader

_FIXTURES = Path(__file__).parent / "fixtures"

_FILES = {
    "a.txt": b"alpha " * 100,
    "dir/b.bin": bytes(range(256)) * 40,
    "c.txt": b"gamma",
}


def _zip(tmp_path: Path) -> Path:
    path = tmp_path / "files.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _FILES.items():
            zf.writestr(name, data)
    return path


def _tar(tmp_path: Path, mode: str = "w", suffix: str = ".tar") -> Path:
    path = tmp_path / f"files{suffix}"
    with tarfile.open(path, mode) as tf:
        for name, data in _FILES.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _tgz(tmp_path: Path) -> Path:
    return _tar(tmp_path, "w:gz", ".tar.gz")


def _directory(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    for name, data in _FILES.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return root


def _iso(tmp_path: Path) -> Path:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_directory("/DIR", rr_name="dir")
    for name, data in _FILES.items():
        iso_name = "/" + name.upper().replace(".", "_") + ".;1"
        iso.add_fp(io.BytesIO(data), len(data), iso_name, rr_name=name.split("/")[-1])
    path = tmp_path / "files.iso"
    iso.write(str(path))
    iso.close()
    return path


def _gz(tmp_path: Path) -> Path:
    path = tmp_path / "c.txt.gz"
    path.write_bytes(gzip.compress(_FILES["c.txt"] * 500))
    return path


def _fixture(name: str) -> Callable[[Path], Path]:
    return lambda _tmp: _FIXTURES / name


# Formats whose random-access pass always lists the archive before it yields.
LISTED_UP_FRONT = [
    pytest.param(_zip, id="zip"),
    pytest.param(_directory, id="dir"),
    pytest.param(_iso, id="iso", marks=requires("pycdlib")),
    pytest.param(_gz, id="gz"),
    pytest.param(
        _fixture("rar/basic_nonsolid__.rar"),
        id="rar-nonsolid",
        marks=requires_binary("unrar"),
    ),
]

# Formats whose pass lists as it goes.
LISTED_BY_THE_PASS = [
    pytest.param(_tar, id="tar"),
    pytest.param(_tgz, id="tar.gz"),
    pytest.param(_fixture("sevenzip/links_mid_folder_solid.7z"), id="7z-solid"),
    pytest.param(
        _fixture("rar/basic_solid__.rar"),
        id="rar-solid",
        marks=requires_binary("unrar"),
    ),
]

ALL_FORMATS = [*LISTED_UP_FRONT, *LISTED_BY_THE_PASS]


def _expected(path: Path) -> dict[str, bytes]:
    with open_archive(path) as reader:
        return {
            m.name: reader.read(m)
            for m in reader.members()
            if m.is_file and m.is_current
        }


def _in_thread(fn: Callable[[], object]) -> object:
    """Run ``fn`` on a new thread; return its result or re-raise its exception."""
    box: list[object] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            box.append(fn())
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return box[0]


def _run_together(*calls: Callable[[], object]) -> list[object]:
    """Start every call on its own thread at the same moment; return their results."""
    barrier = threading.Barrier(len(calls))
    results: list[object] = [None] * len(calls)
    errors: list[BaseException] = []

    def run(i: int, call: Callable[[], object]) -> None:
        try:
            barrier.wait(5)
            results[i] = call()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(i, call)) for i, call in enumerate(calls)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    if errors:
        raise errors[0]
    return results


def _big_tar(tmp_path: Path, mode: str, suffix: str) -> tuple[Path, dict[str, bytes]]:
    """Members larger than the walk's read-ahead, so a pass stream is mid-member."""
    files = {
        f"m{i}.bin": bytes((i * 7 + j) % 251 for j in range(300_000)) for i in range(4)
    }
    path = tmp_path / f"big{suffix}"
    with tarfile.open(path, mode) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path, files


_TAR_MODES = [
    pytest.param("w", ".tar", id="tar"),
    pytest.param("w:gz", ".tar.gz", id="tar.gz"),
]


class _CountingSource(io.BytesIO):
    """An in-memory archive that counts the bytes read from it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        return data

    def readinto(self, buffer, /) -> int:  # type: ignore[no-untyped-def, override]
        n = super().readinto(buffer)
        self.bytes_read += n
        return n


_MODES = [
    pytest.param(False, id="default"),
    pytest.param(True, id="concurrent"),
]


def _lookup_calls(reader: ArchiveReader, name: str) -> list[Callable[[], object]]:
    return [
        lambda: reader.read(name),
        lambda: reader.open(name),
        lambda: reader.get(name),
        reader.members,
        reader.members_report,
        lambda: list(reader),
        lambda: next(iter(reader.stream_members())),
    ]


@pytest.mark.parametrize("concurrent", _MODES)
@pytest.mark.parametrize("make", ALL_FORMATS)
def test_lookup_calls_beside_a_pass_raise_and_leave_it_usable(
    tmp_path: Path, make: Callable[[Path], Path], concurrent: bool
) -> None:
    """Each lookup call and a second pass, from the loop body and from another
    thread, raises; the pass then reads every member's bytes as a pass alone does."""
    path = make(tmp_path)
    expected = _expected(path)
    name = next(iter(expected))
    passed: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=concurrent) as reader:
        for i, (member, stream) in enumerate(reader.stream_members()):
            if i == 0:
                for call in _lookup_calls(reader, name):
                    with pytest.raises(ArchiveyUsageError, match="already active"):
                        call()
                    with pytest.raises(ArchiveyUsageError, match="already active"):
                        _in_thread(call)
                with pytest.raises(ArchiveyUsageError, match="already active"):
                    reader.extract_all(tmp_path / "out")
                assert not (tmp_path / "out").exists()
            if stream is not None and member.is_current:
                passed[member.name] = stream.read()
        # Usable again once the pass has ended.
        assert reader.read(name) == expected[name]
    assert passed == expected


@pytest.mark.parametrize("concurrent", _MODES)
def test_metadata_stays_readable_inside_a_pass(
    tmp_path: Path, concurrent: bool
) -> None:
    """``format``, ``info``, ``cost``, ``diagnostics`` and ``in`` are not lookup calls:
    they work in the loop body, from another thread, and from a progress callback."""
    path = _zip(tmp_path)
    seen: list[object] = []

    def read_metadata(reader: ArchiveReader, member: object) -> None:
        seen.append(
            (
                reader.format,
                reader.info.format,
                reader.cost,
                reader.diagnostics.total_count,
                member in reader,
            )
        )

    with open_archive(path, concurrent_operations=concurrent) as reader:
        for member, _stream in reader.stream_members():
            read_metadata(reader, member)
            _in_thread(lambda m=member: read_metadata(reader, m))
        reader.extract_all(
            tmp_path / "out",
            on_progress=lambda p: read_metadata(reader, p.member) if p.member else None,
        )
    assert seen
    assert all(row[-1] for row in seen)


@pytest.mark.parametrize("concurrent", _MODES)
def test_a_pass_does_not_start_beside_an_open_stream(
    tmp_path: Path, concurrent: bool
) -> None:
    """A stream from ``open()`` refuses ``stream_members()`` at its first ``next()``,
    ``extract_all()`` before the destination exists, and ``verify_all()``; a listing is
    not a data pass and still works."""
    path = _zip(tmp_path)
    with open_archive(path, concurrent_operations=concurrent) as reader:
        held = reader.open("c.txt")
        it = reader.stream_members()
        with pytest.raises(ArchiveyUsageError, match="Close it first"):
            next(it)
        dest = tmp_path / "out"
        with pytest.raises(ArchiveyUsageError, match="Close it first"):
            reader.extract_all(dest)
        assert not dest.exists()
        with pytest.raises(ArchiveyUsageError, match="Close it first"):
            reader.verify_all()
        assert {m.name for m in reader.members()} >= set(_FILES)
        held.close()
        assert {m.name for m, _ in reader.stream_members()} >= set(_FILES)
        reader.extract_all(dest)
    assert (dest / "c.txt").read_bytes() == _FILES["c.txt"]


@pytest.mark.parametrize("concurrent", _MODES)
def test_a_pass_with_no_streams_is_refused_too(
    tmp_path: Path, concurrent: bool
) -> None:
    """An archive of directories and symlinks only: the pass hands out no stream, and
    it is refused beside a held stream all the same, at its first ``next()``."""
    path = tmp_path / "links.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"a")
        zf.writestr("d/", b"")
    with open_archive(path, concurrent_operations=concurrent) as reader:
        held = reader.open("a.txt")
        with pytest.raises(ArchiveyUsageError, match="Close it first"):
            next(iter(reader.stream_members(lambda m: m.is_dir)))
        held.close()
        assert [m.name for m, _ in reader.stream_members(lambda m: m.is_dir)] == ["d/"]


def test_a_dropped_stream_does_not_block_a_pass(tmp_path: Path) -> None:
    """A stream nothing references any more is collected before the refusal stands."""
    path = _zip(tmp_path)
    with open_archive(path) as reader:
        handle = reader.open("c.txt")
        cycle: list[object] = [handle]
        cycle.append(cycle)
        del handle, cycle
        assert {m.name for m, _ in reader.stream_members()} >= set(_FILES)


def test_a_pass_does_not_start_beside_another_threads_call(tmp_path: Path) -> None:
    """Under the flag, a pass started while a lookup call runs on another thread
    raises, and so does a lookup call started while the pass runs its startup."""
    path = _zip(tmp_path)
    with open_archive(path, concurrent_operations=True) as reader:
        entered, release = threading.Event(), threading.Event()
        real = reader._materialize_members  # type: ignore[attr-defined]

        def slow() -> object:
            entered.set()
            assert release.wait(10)
            return real()

        reader._materialize_members = slow  # type: ignore[attr-defined]
        listing = threading.Thread(target=reader.members)
        listing.start()
        assert entered.wait(10)
        try:
            with pytest.raises(ArchiveyUsageError, match="still in progress"):
                next(iter(reader.stream_members()))
            with pytest.raises(ArchiveyUsageError, match="still in progress"):
                reader.extract_all(tmp_path / "out")
        finally:
            release.set()
            listing.join(10)
        reader._materialize_members = real  # type: ignore[attr-defined]
        assert {m.name for m, _ in reader.stream_members()} >= set(_FILES)


def test_verify_all_holds_the_reader_across_its_phases(tmp_path: Path) -> None:
    """``verify_all()`` is one pass from its stream pass to its report: a call from
    another thread during its spanning-pass phase raises."""
    path = _zip(tmp_path)
    with open_archive(path, concurrent_operations=True) as reader:
        entered, release = threading.Event(), threading.Event()

        def spanning(failed: frozenset[int]) -> None:
            entered.set()
            assert release.wait(10)

        reader._run_spanning_passes = spanning  # type: ignore[attr-defined]
        result: list[object] = []
        verifying = threading.Thread(target=lambda: result.append(reader.verify_all()))
        verifying.start()
        assert entered.wait(10)
        try:
            with pytest.raises(ArchiveyUsageError, match="already active"):
                reader.open("c.txt")
            with pytest.raises(ArchiveyUsageError, match="already active"):
                next(iter(reader.stream_members()))
        finally:
            release.set()
            verifying.join(10)
        assert result and not result[0].failures  # type: ignore[attr-defined]


# --- The peek while a pass is open -----------------------------------------------------


def _cab(tmp_path: Path) -> Path:
    path = tmp_path / "files.cab"
    files = [CabFile(name.replace("/", "\\"), data) for name, data in _FILES.items()]
    path.write_bytes(write_cab(files, [CabFolder("none")]))
    return path


# Readers with an upfront list: the peek answers the full report before a pass.
_PEEK_UPFRONT = [
    pytest.param(_zip, id="zip"),
    pytest.param(_fixture("sevenzip/links_mid_folder_solid.7z"), id="7z"),
    pytest.param(_gz, id="gz"),
    pytest.param(_cab, id="cab"),
]


def _peek_names(reader: ArchiveReader) -> list[str] | None:
    report = reader.members_report_if_available()
    return None if report is None else [m.name for m in report.members]


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
@pytest.mark.parametrize("make", _PEEK_UPFRONT)
def test_peek_inside_the_loop_answers_as_before_it(
    tmp_path: Path, make: Callable[[Path], Path], streaming: bool
) -> None:
    """With an upfront list, the peek in the loop body gives the report a peek before
    the pass gives, from the first member on, and reads nothing from the archive."""
    path = make(tmp_path)
    with open_archive(io.BytesIO(path.read_bytes()), streaming=streaming) as reader:
        before = _peek_names(reader)
    assert before is not None
    for peek_first in (False, True):
        source = _CountingSource(path.read_bytes())
        with open_archive(source, streaming=streaming) as reader:
            if peek_first:
                assert _peek_names(reader) == before
            inside = []
            for _member, _stream in reader.stream_members():
                read = source.bytes_read
                inside.append(_peek_names(reader))
                inside.append(_in_thread(lambda: _peek_names(reader)))
                assert source.bytes_read == read
            assert inside and all(names == before for names in inside), inside
            assert _peek_names(reader) == before


@pytest.mark.parametrize("make", [_tar, _tgz])
def test_peek_inside_a_tar_pass_stays_none_until_it_ends(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    """With no upfront list the peek answers ``None`` during the whole pass, even once
    the pass has reached the end of the archive, then the full report after it."""
    path = make(tmp_path)
    with open_archive(path) as reader:
        assert reader.members_report_if_available() is None
        it = reader.stream_members()
        for _member, _stream in it:
            assert reader.members_report_if_available() is None
        assert _peek_names(reader) == list(_FILES)


def test_peek_inside_a_pass_after_members_answers_the_listing(tmp_path: Path) -> None:
    """A TAR listed before the pass: the pass pins that report, and the peek in the
    loop returns it."""
    path = _tar(tmp_path)
    with open_archive(path) as reader:
        listed = reader.members_report()
        for _member, _stream in reader.stream_members():
            assert reader.members_report_if_available() is listed


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_extraction_progress_totals_are_taken_inside_its_pass(
    tmp_path: Path, streaming: bool
) -> None:
    """``extract_all()`` counts its totals from the index under its own pass, and a
    peek from its progress callback answers that same report."""
    path = _zip(tmp_path)
    totals: list[object] = []
    peeks: list[list[str] | None] = []
    with open_archive(path, streaming=streaming) as reader:

        def on_progress(progress: object) -> None:
            totals.append(progress.members_total)  # type: ignore[attr-defined]
            peeks.append(_peek_names(reader))

        reader.extract_all(tmp_path / "out", on_progress=on_progress)
    assert set(totals) == {len(_FILES)}
    assert all(names is not None and set(names) >= set(_FILES) for names in peeks)


def _many_files_cab(count: int) -> io.BytesIO:
    """A CAB of ``count`` files: an upfront list that does not declare its count in a
    way checked at open, so the limit is met while the list is walked."""
    files = [CabFile(f"f{i:03}", b"x") for i in range(count)]
    return io.BytesIO(write_cab(files, [CabFolder("none")]))


def test_a_listing_limit_met_by_the_drain_at_pass_start() -> None:
    """A streaming pass over an upfront list drains it first. Past a listing limit the
    pass yields the members before it and raises the limit, and the peek in it and
    after it answers ``None``: a limit is never stored on a report."""
    path = _many_files_cab(30)
    cfg = ArchiveyConfig(listing_limits=ListingLimits(max_members=20))
    with open_archive(path, streaming=True, config=cfg) as reader:
        seen = []
        with pytest.raises(ResourceLimitError, match="max_members"):
            for member, _stream in reader.stream_members():
                seen.append(member.name)
                assert reader.members_report_if_available() is None
        assert len(seen) == 20
        assert reader.members_report_if_available() is None


def test_a_peek_that_met_the_limit_refuses_the_next_pass() -> None:
    """A peek before the pass raises the limit; the pass then raises the ``ReadError``
    naming it before any member."""
    path = _many_files_cab(30)
    cfg = ArchiveyConfig(listing_limits=ListingLimits(max_members=20))
    with open_archive(path, streaming=True, config=cfg) as reader:
        with pytest.raises(ResourceLimitError):
            reader.members_report_if_available()
        seen = []
        with pytest.raises(ReadError, match="ResourceLimitError"):
            for member, _stream in reader.stream_members():
                seen.append(member)
        assert seen == []


# --- A pass alone ------------------------------------------------------------------


@pytest.mark.parametrize(("mode", "suffix"), _TAR_MODES)
def test_tar_pass_alone_reads_the_archive_once(
    tmp_path: Path, mode: str, suffix: str
) -> None:
    """A CONCURRENT pass nobody walks ahead of reads the archive once, as a default
    reader's pass does: its streams read through the walk."""
    path, files = _big_tar(tmp_path, mode, suffix)
    size = path.stat().st_size
    for concurrent in (False, True):
        source = _CountingSource(path.read_bytes())
        with open_archive(source, concurrent_operations=concurrent) as reader:
            got = {m.name: s.read() for m, s in reader.stream_members() if s}
            rewinds = reader.diagnostics.counts.get(
                DiagnosticCode.STREAM_REWIND_REDECOMPRESSES, 0
            )
        assert got == files
        assert source.bytes_read <= size + 64 * 1024, (concurrent, source.bytes_read)
        assert rewinds == 0


def test_damaged_tar_pass_ends_with_the_same_error_on_both_readers(
    tmp_path: Path,
) -> None:
    """A pass over a cut tar raises the error its own read hit, with or without
    ``concurrent_operations``: the concurrent pass walks as it goes, as the default one
    does."""
    path = tmp_path / "cut.tar"
    with tarfile.open(path, "w") as tf:
        for i in range(10):
            info = tarfile.TarInfo(f"f{i}")
            info.size = 5000
            tf.addfile(info, io.BytesIO(bytes(5000)))
    path.write_bytes(path.read_bytes()[:20480])
    ends = []
    for concurrent in (False, True):
        with open_archive(path, concurrent_operations=concurrent) as reader:
            read_errors = []
            with pytest.raises(TruncatedError) as end:
                for member, stream in reader.stream_members():
                    assert stream is not None
                    try:
                        stream.read()
                    except TruncatedError as exc:
                        read_errors.append((member.name, str(exc)))
            ends.append((read_errors, str(end.value)))
    assert ends[0] == ends[1]
    assert "member='f3'" in ends[1][1]


def test_listing_after_an_abandoned_pass_refuses_the_same_way_each_time(
    tmp_path: Path,
) -> None:
    from tests.test_listing_limits import _tar_of_empty_members

    tar_path = _tar_of_empty_members(tmp_path / "many.tar", 100)
    cfg = ArchiveyConfig(listing_limits=ListingLimits(max_members=20))
    with open_archive(tar_path, config=cfg) as reader:
        passes = reader.stream_members()
        next(passes)
        next(passes)
        passes.close()  # type: ignore[attr-defined]
        messages = []
        for _ in range(3):
            with pytest.raises(ResourceLimitError) as refused:
                reader.members()
            messages.append(str(refused.value))
    assert len(set(messages)) == 1, messages


def _many_members(fmt: str, names: list[str]) -> bytes:
    buf = io.BytesIO()
    if fmt == "zip":
        with zipfile.ZipFile(buf, "w") as zf:
            for name in names:
                zf.writestr(name, b"x")
    else:
        with tarfile.open(fileobj=buf, mode="w:gz" if fmt == "tar.gz" else "w") as tf:
            for name in names:
                info = tarfile.TarInfo(name)
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


@pytest.mark.parametrize("extra", [-1, 0, 1, base_reader._DRAIN_BATCH])
@pytest.mark.parametrize(
    ("fmt", "streaming"),
    [("zip", False), ("zip", True), ("tar", False), ("tar.gz", False)],
    ids=["zip", "zip-streaming", "tar", "tar.gz"],
)
def test_listing_drains_across_batch_boundaries(
    fmt: str, streaming: bool, extra: int
) -> None:
    """A listing pulls in batches of ``_DRAIN_BATCH``; every member is listed, in
    order, however the count falls. A streaming ZIP pass drains through the streaming
    branch (``_walk_ahead``)."""
    names = [f"f{i}" for i in range(base_reader._DRAIN_BATCH + extra)]
    data = _many_members(fmt, names)
    with open_archive(
        io.BytesIO(data), streaming=streaming, concurrent_operations=not streaming
    ) as reader:
        if streaming:
            listed = [m.name for m, _ in reader.stream_members()]
        else:
            listed = [m.name for m in reader.members()]
    assert listed == names


# --- ReaderState bookkeeping --------------------------------------------------------


def _state(*, concurrent: bool = True) -> ReaderState:
    streams = MemberStreams.CONCURRENT if concurrent else MemberStreams(0)
    return ReaderState(member_streams=streams, open_site=None)


@pytest.mark.parametrize("concurrent", _MODES)
@pytest.mark.parametrize("kind", list(PassKind))
def test_pass_and_worker_exclude_each_other(concurrent: bool, kind: PassKind) -> None:
    state = _state(concurrent=concurrent)
    worker = _in_thread(lambda: state.acquire_worker("open"))
    with pytest.raises(ArchiveyUsageError, match="still in progress"):
        state.acquire_pass("stream_members", kind)
    state.release_worker(worker)  # type: ignore[arg-type]
    token = state.acquire_pass("stream_members", kind)
    with pytest.raises(ArchiveyUsageError, match="already active"):
        _in_thread(lambda: state.acquire_worker("open"))
    with pytest.raises(ArchiveyUsageError, match="already active"):
        _in_thread(lambda: state.acquire_pass("extract_all", PassKind.DATA))
    state.release_pass(token)


@pytest.mark.parametrize("concurrent", _MODES)
def test_only_a_data_pass_refuses_a_live_stream(concurrent: bool) -> None:
    state = _state(concurrent=concurrent)
    reservation = state.reserve_live_stream()
    with pytest.raises(ArchiveyUsageError, match="Close it first"):
        state.acquire_pass("stream_members", PassKind.DATA)
    for kind in (PassKind.LOOKUP, PassKind.LIST):
        state.release_pass(state.acquire_pass("members", kind))
    state.release_reservation(reservation)
    state.release_pass(state.acquire_pass("stream_members", PassKind.DATA))


def test_peek_answers_the_pinned_report_while_a_pass_is_open() -> None:
    """Inside a pass the peek takes no token and answers the pin; outside one it
    takes a worker token. A default reader's lookup token is not a pass."""
    state = _state(concurrent=False)
    pinned = object()
    token = state.acquire_pass("stream_members", PassKind.DATA, lambda: pinned)  # type: ignore[arg-type, return-value]
    assert state.acquire_peek("peek") == (None, pinned)
    assert _in_thread(lambda: state.acquire_peek("peek")) == (None, pinned)
    later = object()
    state.pin_report(token, later)  # type: ignore[arg-type]
    assert state.acquire_peek("peek") == (None, later)
    state.release_pass(token)
    worker, report = state.acquire_peek("peek")
    assert worker is not None and report is None
    state.release_worker(worker)
    lookup = state.acquire_pass("members")
    with pytest.raises(ArchiveyUsageError, match="re-entered"):
        state.acquire_peek("peek")
    state.release_pass(lookup)


# --- callbacks of a pass are not the library's own calls ------------------------------


@pytest.mark.parametrize("concurrent", [False, True])
@pytest.mark.parametrize("make", [_zip, _tar, _tgz])
def test_an_extraction_callback_cannot_call_the_reader(
    tmp_path: Path, concurrent: bool, make: Callable[[Path], Path]
) -> None:
    """open(), members() and verify_all() from on_progress are refused as re-entry
    (none of them may move the walk the pass reads through), and the extraction
    still writes every member when the callback catches the refusal."""
    reader = open_archive(make(tmp_path), concurrent_operations=concurrent)
    refused: dict[str, list[str]] = {"open": [], "members": [], "verify_all": []}
    calls: dict[str, Callable[[], object]] = {
        "open": lambda: reader.open("c.txt").close(),
        "members": reader.members,
        "verify_all": reader.verify_all,
    }

    def on_progress(_progress: object) -> None:
        for name, call in calls.items():
            try:
                call()
            except ArchiveyUsageError as exc:
                refused[name].append(str(exc))

    out = tmp_path / "out"
    with reader:
        reader.extract_all(out, on_progress=on_progress)
    for name, messages in refused.items():
        assert messages, name
        assert all("re-entered" in m for m in messages), (name, messages)
    for name, data in _FILES.items():
        assert (out / name).read_bytes() == data


# --- the peek pin: built at the grant, on the outer pass -------------------------------


def test_the_admission_pin_is_built_at_the_grant_and_not_on_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pinned report is built once the pass holds the gate, so nothing can
    publish in between; a refused pass builds nothing."""
    reader = open_archive(_zip(tmp_path))
    state = reader._state  # type: ignore[attr-defined]
    real = reader._built_report  # type: ignore[attr-defined]
    seen: list[object] = []

    def built() -> object:
        seen.append(state._root)
        return real()

    monkeypatch.setattr(reader, "_built_report", built)
    with reader:
        held = reader.open("c.txt")
        with pytest.raises(ArchiveyUsageError, match="Close it first"):
            next(iter(reader.stream_members()))
        assert seen == []  # refused before anything was built
        held.close()
        for _member, _stream in reader.stream_members():
            break
    assert seen, "the admitted pass must have built its pin"
    assert seen[0] is not None and seen[0].name == "stream_members"


def test_admission_after_an_index_only_listing_copies_nothing_under_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After an index-only listing (a peek), a pass's admission pins the report
    published at the end of the walk: under the state lock it only picks a
    reference, and copies no member list or diagnostics."""
    reader = open_archive(_zip(tmp_path))
    state = reader._state  # type: ignore[attr-defined]
    collector = reader._diagnostics_collector  # type: ignore[attr-defined]
    real_snapshot = collector.snapshot
    under_lock: list[bool] = []

    def snapshot() -> object:
        under_lock.append(state._lock._is_owned())
        return real_snapshot()

    monkeypatch.setattr(collector, "snapshot", snapshot)
    with reader:
        peek = reader.members_report_if_available()
        assert peek is not None
        for _member, _stream in reader.stream_members():
            inside = reader.members_report_if_available()
            assert inside is not None
            assert inside.members == peek.members
            break
    assert not any(under_lock), under_lock


def test_verify_all_pins_its_startup_on_the_outer_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No peek before verify_all(): the nested stream pass's startup drains the
    upfront index, and the peek during verification answers that, not ``None``."""
    reader = open_archive(_zip(tmp_path))
    real_pin = reader._pin_pass  # type: ignore[attr-defined]
    peeks: list[object] = []

    def pin_then_peek(token: object) -> None:
        real_pin(token)
        peeks.append(reader.members_report_if_available())

    monkeypatch.setattr(reader, "_pin_pass", pin_then_peek)
    with reader:
        reader.verify_all()
    assert peeks
    report = peeks[0]
    assert report is not None
    assert sorted(m.name for m in report.members) == sorted(_FILES)  # type: ignore[attr-defined]


# --- callbacks run outside the library's internal window --------------------------------


@pytest.mark.parametrize("outer", ["extract_all", "verify_all"])
def test_a_link_resolution_diagnostic_cannot_call_the_reader(
    tmp_path: Path, outer: str
) -> None:
    """Resolving a link whose target data is damaged reports
    ``SYMLINK_TARGET_UNAVAILABLE`` from inside the library's own link-data read.
    The callback still runs as the caller's code: a pass, a lookup or a listing it
    starts is refused as re-entry, and is not admitted under the library's window."""
    from tests.test_audit2_zip import _zip64_header_offset_zip

    holder: list[object] = []
    seen: dict[str, list[BaseException]] = {"verify_all": [], "members": [], "get": []}

    def on_diagnostic(diag: object) -> None:
        if getattr(diag, "code", None) is not DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE:
            return
        reader = holder[0]
        calls: dict[str, Callable[[], object]] = {
            "verify_all": reader.verify_all,  # type: ignore[attr-defined]
            "members": reader.members,  # type: ignore[attr-defined]
            "get": lambda: reader.get("x"),  # type: ignore[attr-defined]
        }
        for name, call in calls.items():
            try:
                call()
            except BaseException as exc:  # noqa: BLE001 - the test inspects it
                seen[name].append(exc)

    blob = _zip64_header_offset_zip(2**63, symlink=True)
    config = ArchiveyConfig(on_diagnostic=on_diagnostic)
    with open_archive(io.BytesIO(blob), config=config) as reader:
        holder.append(reader)
        if outer == "extract_all":
            reader.extract_all(tmp_path / "out", on_error="continue")
        else:
            reader.verify_all()
    for name, errors in seen.items():
        assert errors, name
        assert all(
            isinstance(e, ArchiveyUsageError) and "re-entered" in str(e) for e in errors
        ), (name, errors)


@pytest.mark.parametrize("outer", ["extract_all", "verify_all"])
def test_a_password_provider_during_a_link_data_read_cannot_call_the_reader(
    tmp_path: Path, outer: str
) -> None:
    """An encrypted ZIP keeps a symlink's target as encrypted member data, so the
    first-touch link-data read asks the password provider, inside the library's own
    window. The provider is the caller's code: a pass it starts is refused as
    re-entry, not filed as a child of the running pass."""
    from tests.zipcrypto import build_zipcrypto_zip

    holder: list[object] = []
    seen: list[BaseException] = []

    def provider(request: object) -> str:
        try:
            holder[0].verify_all()  # type: ignore[attr-defined]
        except BaseException as exc:  # noqa: BLE001 - the test inspects it
            seen.append(exc)
        return "secret"

    blob = build_zipcrypto_zip(b"secret", b"link", b"target.txt", unix_mode=0o120777)
    with open_archive(io.BytesIO(blob), password=provider) as reader:
        holder.append(reader)
        if outer == "extract_all":
            reader.extract_all(tmp_path / "out", on_error="continue")
        else:
            reader.verify_all()
    assert seen
    assert all(
        isinstance(e, ArchiveyUsageError) and "re-entered" in str(e) for e in seen
    ), seen
