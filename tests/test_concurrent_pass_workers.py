"""Random-access calls and other passes beside a ``stream_members()`` pass.

On a ``CONCURRENT`` reader every pass and listing call shares the reader's one member
walk, each at its own position, so ``open()``, ``read()``, ``get()``, ``members()``,
iteration and further ``stream_members()`` passes work beside a pass on every format,
from the loop body and from other threads. On a reader opened without
``concurrent_operations=True`` they still raise ``ArchiveyUsageError``. ``extract_all()``
works beside a pass the same way. The bookkeeping itself is unit-tested at the bottom.
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
    ExtractionError,
    TruncatedError,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.internal.reader_state import LifecycleState, ReaderState
from archivey.reader import ArchiveReader
from archivey.types import MemberStreams
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


def _random_calls(reader: ArchiveReader, expected: dict[str, bytes]) -> None:
    """Every random-access call, each checked against the bytes read outside the pass."""
    for name, data in expected.items():
        assert reader.read(name) == data
        with reader.open(name) as stream:
            assert stream.read() == data
        member = reader.get(name)
        assert member is not None
        assert member.name == name
    names = {m.name for m in reader.members()}
    assert set(expected) <= names
    assert {m.name for m in reader} == names
    assert {m.name for m in reader.members_report().members} == names


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_random_calls_inside_the_loop_after_members(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    path = make(tmp_path)
    expected = _expected(path)
    passed: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=True) as reader:
        reader.members()
        for member, stream in reader.stream_members():
            # Before the pass's own stream is read, so a random read between the
            # pass's members cannot move it.
            _random_calls(reader, expected)
            _in_thread(lambda: _random_calls(reader, expected))
            if stream is not None and member.is_current:
                passed[member.name] = stream.read()
    assert passed == expected


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_random_reads_interleaved_with_the_pass_stream(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    """A random stream held open while the pass streams are read a chunk at a time."""
    path = make(tmp_path)
    expected = _expected(path)
    passed: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=True) as reader:
        reader.members()
        held = {name: reader.open(name) for name in expected}
        got = dict.fromkeys(expected, b"")
        for member, stream in reader.stream_members():
            if stream is None or not member.is_current:
                continue
            chunks = []
            while True:
                chunk = stream.read(7)
                for name, other in held.items():
                    got[name] += other.read(5)
                if not chunk:
                    break
                chunks.append(chunk)
            passed[member.name] = b"".join(chunks)
        for name, other in held.items():
            got[name] += other.read()
            other.close()
    assert passed == expected
    assert got == expected


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_first_pass_needs_no_members_call(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    """The calls work on a first pass too, before anything has listed the archive.

    TAR, 7z and solid RAR list as the pass goes; a call that needs more of the list
    than the pass has reached walks ahead of it.
    """
    path = make(tmp_path)
    expected = _expected(path)
    with open_archive(path, concurrent_operations=True) as reader:
        for _member, _stream in reader.stream_members():
            _random_calls(reader, expected)
            assert next(reader.stream_members(), None) is not None


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_default_reader_still_refuses(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    path = make(tmp_path)
    with open_archive(path) as reader:
        name = next(m.name for m in reader.members() if m.is_file)
        it = reader.stream_members()
        next(it)
        for call in (
            lambda: reader.read(name),
            lambda: reader.open(name),
            lambda: reader.get(name),
            reader.members,
        ):
            with pytest.raises(ArchiveyUsageError, match="already active"):
                call()
            with pytest.raises(ArchiveyUsageError, match="already active"):
                _in_thread(call)
        it.close()


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_passes_side_by_side(tmp_path: Path, make: Callable[[Path], Path]) -> None:
    """Two passes advance in lockstep on one thread, and a third runs on another."""
    path = make(tmp_path)
    expected = _expected(path)

    def drain(it):
        return {m.name: s.read() for m, s in it if s is not None and m.is_current}

    with open_archive(path, concurrent_operations=True) as reader:
        reader.members()
        first: dict[str, bytes] = {}
        second: dict[str, bytes] = {}
        other = reader.stream_members()
        for member, stream in reader.stream_members():
            paired, paired_stream = next(other)
            assert paired is member
            if stream is not None and member.is_current:
                assert paired_stream is not None
                # Interleaved reads: the two passes' streams are independent.
                first[member.name] = stream.read(3)
                second[member.name] = paired_stream.read()
                first[member.name] += stream.read()
                assert _in_thread(lambda: drain(reader.stream_members())) == expected
        assert next(other, None) is None
    assert first == expected
    assert second == expected


def _extracted(dest: Path, expected: dict[str, bytes]) -> dict[str, bytes]:
    return {name: (dest / name).read_bytes() for name in expected}


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


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_extraction_inside_the_loop_and_from_another_thread(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    path = make(tmp_path)
    expected = _expected(path)
    passed: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=True) as reader:
        for i, (member, stream) in enumerate(reader.stream_members()):
            if i == 0:
                reader.extract_all(tmp_path / "inside")
                _in_thread(lambda: reader.extract_all(tmp_path / "thread"))
            if stream is not None and member.is_file and member.is_current:
                passed[member.name] = stream.read()
    assert passed == expected
    assert _extracted(tmp_path / "inside", expected) == expected
    assert _extracted(tmp_path / "thread", expected) == expected


@pytest.mark.parametrize("make", ALL_FORMATS)
def test_extractions_and_calls_at_once(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    """Two extractions, a pass and random reads start together on a fresh reader."""
    path = make(tmp_path)
    expected = _expected(path)

    def drain() -> dict[str, bytes]:
        return {
            m.name: s.read()
            for m, s in reader.stream_members()
            if s is not None and m.is_file and m.is_current
        }

    with open_archive(path, concurrent_operations=True) as reader:
        first, second, passed, read = _run_together(
            lambda: reader.extract_all(tmp_path / "one"),
            lambda: reader.extract_all(tmp_path / "two"),
            drain,
            lambda: {name: reader.read(name) for name in expected},
        )
    assert passed == expected
    assert read == expected
    assert first is not None and second is not None
    assert _extracted(tmp_path / "one", expected) == expected
    assert _extracted(tmp_path / "two", expected) == expected


def test_extractions_into_one_folder_clash_as_two_readers_would(
    tmp_path: Path,
) -> None:
    """The reader does not arbitrate between two extractions into one folder.

    A file already there (or one the other extraction wrote first) is an existing
    destination to each of them, under the overwrite policy each was given.
    """
    path = _zip(tmp_path)
    dest = tmp_path / "same"
    dest.mkdir()
    (dest / "c.txt").write_bytes(b"there first")
    errors: list[BaseException] = []

    def extract() -> None:
        try:
            reader.extract_all(dest)
        except ExtractionError as exc:
            errors.append(exc)

    with open_archive(path, concurrent_operations=True) as reader:
        _run_together(extract, extract)
    assert len(errors) == 2
    assert all("already exists" in str(e) for e in errors)
    assert (dest / "c.txt").read_bytes() == b"there first"


def test_extraction_report_keeps_only_its_own_diagnostics(tmp_path: Path) -> None:
    """A diagnostic one extraction emits stays out of the one running beside it."""
    path = _zip(tmp_path)
    with open_archive(path, concurrent_operations=True) as reader:
        selected, everything = _run_together(
            lambda: reader.extract_all(
                tmp_path / "one", members=["c.txt", "missing.txt"]
            ),
            lambda: reader.extract_all(tmp_path / "two"),
        )
        unmatched = DiagnosticCode.MEMBER_SELECTOR_UNMATCHED
        assert selected.diagnostics.counts == {unmatched: 1}  # type: ignore[attr-defined]
        assert everything.diagnostics.total_count == 0  # type: ignore[attr-defined]
        assert reader.diagnostics.counts[unmatched] == 1


def test_close_winds_down_every_suspended_pass(tmp_path: Path) -> None:
    path = _zip(tmp_path)
    reader = open_archive(path, concurrent_operations=True)
    first = reader.stream_members()
    second = reader.stream_members()
    _, first_stream = next(first)
    _, second_stream = next(second)
    reader.close()
    assert first_stream is not None and first_stream.closed
    assert second_stream is not None and second_stream.closed
    for it in (first, second):
        with pytest.raises(ArchiveyUsageError):
            next(it)


def test_close_inside_the_loop_after_random_calls(tmp_path: Path) -> None:
    path = _zip(tmp_path)
    reader = open_archive(path, concurrent_operations=True)
    it = reader.stream_members()
    next(it)
    held = reader.open("c.txt")
    reader.close()
    with pytest.raises(ArchiveyUsageError):
        next(it)
    # close() closes the pass's stream and every other open member stream with it.
    assert held.closed


# --- ReaderState bookkeeping --------------------------------------------------------


def _state(*, concurrent: bool = True) -> ReaderState:
    streams = MemberStreams.CONCURRENT if concurrent else MemberStreams(0)
    return ReaderState(member_streams=streams, open_site=None)


def test_pass_starts_beside_another_threads_worker() -> None:
    state = _state()
    worker = _in_thread(lambda: state.acquire_worker("open"))
    token = state.acquire_pass("stream_members")
    state.release_pass(token)
    state.release_worker(worker)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("concurrent", "name"),
    [(False, "stream_members"), (False, "extract_all"), (True, "members")],
)
def test_pass_and_worker_still_exclude_each_other(concurrent: bool, name: str) -> None:
    state = _state(concurrent=concurrent)
    worker = _in_thread(lambda: state.acquire_worker("open"))
    with pytest.raises(ArchiveyUsageError, match="still in progress"):
        state.acquire_pass(name)
    state.release_worker(worker)  # type: ignore[arg-type]
    token = state.acquire_pass(name)
    with pytest.raises(ArchiveyUsageError, match="already active"):
        _in_thread(lambda: state.acquire_worker("open"))
    state.release_pass(token)


def _close_waiting_on_a_worker(
    resume_pass: bool,
) -> tuple[ReaderState, list[str], list[BaseException]]:
    """close() beside a suspended pass and an in-flight worker; the worker then ends.

    With ``resume_pass`` the pass resumes while close() waits for the worker.
    """
    state = _state()
    token = state.acquire_pass("stream_members")
    closed: list[str] = []
    state.set_pass_closer(token, lambda: closed.append("pass"))
    state.set_suspended(token, True)
    worker = _in_thread(lambda: state.acquire_worker("open"))
    errors: list[BaseException] = []

    def close() -> None:
        try:
            state.mark_reader_closed()
        except BaseException as exc:  # noqa: BLE001 - checked by the caller
            errors.append(exc)

    closer = threading.Thread(target=close)
    closer.start()
    while not state._closing:
        threading.Event().wait(0.001)
    if resume_pass:
        state.set_suspended(token, False)
    state.release_worker(worker)  # type: ignore[arg-type]
    closer.join()
    return state, ["pass"] if state._pass_wind_down else [], errors


def test_close_waits_for_the_worker_then_winds_the_pass_down() -> None:
    state, wind_down, errors = _close_waiting_on_a_worker(resume_pass=False)
    assert errors == []
    assert state.lifecycle is LifecycleState.READER_CLOSED
    assert wind_down == ["pass"]


def test_close_refuses_a_pass_that_resumed_while_it_waited() -> None:
    state, wind_down, errors = _close_waiting_on_a_worker(resume_pass=True)
    assert len(errors) == 1
    assert isinstance(errors[0], ArchiveyUsageError)
    assert "already active" not in str(errors[0])
    assert "is active" in str(errors[0])
    assert state.lifecycle is LifecycleState.OPEN
    assert not state._closing
    assert wind_down == []


def test_7z_link_opened_from_another_thread_leaves_the_pass_decoder_alone() -> None:
    """A link the pass sits on, followed by ``open()`` on another thread.

    With ``read_link_targets=False`` the pass offers its own folder decoder for the
    link's bytes. Only the pass's thread may read through it: a read from another
    thread would move the decoder under the pass.
    """
    path = _FIXTURES / "sevenzip" / "links_mid_folder_solid.7z"
    expected = _expected(path)
    config = ArchiveyConfig(read_link_targets=False)
    with open_archive(path, config=config) as reader:
        through_links = {m.name: reader.read(m) for m in reader.members() if m.is_link}
    assert through_links
    passed: dict[str, bytes] = {}
    followed = 0
    with open_archive(path, concurrent_operations=True, config=config) as reader:
        reader.members()
        for member, stream in reader.stream_members():
            if member.is_link:
                # Count reads through the pass's decoder.
                pass_link = reader._pass_link  # type: ignore[attr-defined]
                assert pass_link is not None
                assert pass_link[0] is member
                used: list[str] = []

                def counted(opener=pass_link[1]):
                    used.append(threading.current_thread().name)  # noqa: B023 - called within this iteration
                    return opener()

                reader._pass_link = (member, counted, *pass_link[2:])  # type: ignore[attr-defined]
                target = _in_thread(lambda m=member: reader.read(m))
                assert target == through_links[member.name]
                assert used == []
                followed += 1
            elif stream is not None:
                passed[member.name] = stream.read()
    assert followed
    assert passed == expected


def test_close_takes_every_suspended_pass_closer() -> None:
    state = _state()
    ran: list[str] = []
    tokens = []
    for _ in range(2):
        tokens.append(state.acquire_pass("stream_members"))
        state.set_suspended(tokens[-1], True)
    for i, token in enumerate(tokens):

        def closer(i: int = i) -> None:
            ran.append(f"pass {i}")
            raise ValueError(f"pass {i}")

        state.set_pass_closer(token, closer)
        state.set_suspended(token, True)
    state.mark_reader_closed()
    wind_down = state.take_pass_wind_down()
    assert wind_down is not None
    with pytest.raises(ExceptionGroup) as info:
        wind_down()
    assert ran == ["pass 0", "pass 1"]
    assert [str(e) for e in info.value.exceptions] == ["pass 0", "pass 1"]
    assert state.take_pass_wind_down() is None


def test_ending_the_first_pass_hands_the_reader_to_the_one_beside_it() -> None:
    state = _state()
    first = state.acquire_pass("stream_members")
    state.set_suspended(first, True)
    second = state.acquire_pass("stream_members")
    state.set_suspended(second, True)
    state.release_pass(first)
    with pytest.raises(ArchiveyUsageError, match="'stream_members'"):
        state.acquire_pass("members")
    state.release_pass(second)
    state.release_pass(state.acquire_pass("members"))


def test_extraction_runs_beside_passes_and_workers() -> None:
    state = _state()
    worker = _in_thread(lambda: state.acquire_worker("open"))
    passing = state.acquire_pass("stream_members")
    extracting = _in_thread(lambda: state.acquire_pass("extract_all"))
    # The loop body runs while the pass is suspended at a yield.
    state.set_suspended(passing, True)
    second = state.acquire_pass("extract_all")
    for token in (passing, extracting, second):
        state.release_pass(token)  # type: ignore[arg-type]
    state.release_worker(worker)  # type: ignore[arg-type]
    assert state._root is None


def test_internal_scope_belongs_to_its_own_threads_pass() -> None:
    """A child scope is filed under the pass of the thread that opened it.

    ``_root`` may be another thread's pass, which can end first; the extraction's own
    opens must stay under the extraction.
    """
    state = _state()
    other = _in_thread(lambda: state.acquire_pass("stream_members"))
    assert state._root is other
    extracting = state.acquire_pass("extract_all")
    state.begin_internal_opens()
    try:
        inner = state.acquire_pass("stream_members")
        scope = state.enter_child_scope("link_reads")
    finally:
        state.end_internal_opens()
    assert inner.parent is extracting
    assert scope is not None and scope.parent is extracting
    state.release_pass(other)  # type: ignore[arg-type]
    assert inner in state._children
    assert scope in state._children
    state.release_child(scope)
    state.release_pass(inner)
    state.release_pass(extracting)
    assert state._children == set()
    assert state.enter_child_scope("link_reads") is None


def test_scope_on_a_thread_without_a_pass_stays_off_other_passes() -> None:
    """``members()`` on a ``CONCURRENT`` reader holds a worker, not a pass.

    Its link reads must not be filed under a pass another thread holds, which could
    end while they run and take them out of the bookkeeping.
    """
    state = _state()
    other = _in_thread(lambda: state.acquire_pass("stream_members"))
    worker = state.acquire_worker("members")
    assert state.enter_child_scope("link_reads") is None
    state.begin_internal_opens()
    try:
        inner = state.acquire_worker("open")
    finally:
        state.end_internal_opens()
    # A worker of its own, which close() drains, not a child of the other pass.
    assert inner.kind == "worker"
    assert inner in state._workers
    state.release_pass(other)  # type: ignore[arg-type]
    assert inner in state._workers
    state.release_worker(inner)
    state.release_worker(worker)


@pytest.mark.parametrize("make", [_tar, _zip])
def test_call_during_the_pass_listing_waits_for_it(
    tmp_path: Path, make: Callable[[Path], Path]
) -> None:
    """A read on another thread while the pass is pulling a member waits for it."""
    path = make(tmp_path)
    expected = _expected(path)
    reader = open_archive(path, concurrent_operations=True)
    listing, release = threading.Event(), threading.Event()
    real_iter = reader._iter_members

    def slow_iter():
        members = real_iter()
        first = next(members)
        listing.set()
        assert release.wait(10)
        yield first
        yield from members

    reader._iter_members = slow_iter  # type: ignore[method-assign]
    passes = reader.stream_members()
    first: list[object] = []
    pass_thread = threading.Thread(target=lambda: first.append(next(passes)))
    pass_thread.start()
    assert listing.wait(10)
    got: list[object] = []
    reader_thread = threading.Thread(target=lambda: got.append(reader.read("c.txt")))
    reader_thread.start()
    reader_thread.join(0.2)
    assert reader_thread.is_alive()
    assert not got
    release.set()
    pass_thread.join(10)
    reader_thread.join(10)
    assert got == [expected["c.txt"]]
    assert first
    passes.close()
    reader.close()


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


@pytest.mark.parametrize(("mode", "suffix"), _TAR_MODES)
@pytest.mark.parametrize("same_thread", [True, False], ids=["loop-body", "thread"])
def test_listing_ahead_of_a_tar_pass_keeps_its_open_stream(
    tmp_path: Path, mode: str, suffix: str, same_thread: bool
) -> None:
    """``members()`` walks past the member a pass is half way through reading.

    The pass's stream reads through the walk until then, and from a view of its own
    after, so its bytes are the member's either way.
    """
    path, files = _big_tar(tmp_path, mode, suffix)
    passed: dict[str, bytes] = {}
    with open_archive(path, concurrent_operations=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            head = stream.read(1000)
            if member.name == "m1.bin":
                names = (
                    [m.name for m in reader.members()]
                    if same_thread
                    else [m.name for m in _in_thread(reader.members)]  # type: ignore[attr-defined]
                )
                assert names == list(files)
            passed[member.name] = head + stream.read()
    assert passed == files


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


class _LockWithReleaseHook:
    """The reader's walk lock, running ``hook`` once just after a release."""

    def __init__(self, lock: object) -> None:
        self._lock = lock
        self.hook: Callable[[], None] | None = None

    def __enter__(self) -> None:
        self._lock.__enter__()  # type: ignore[attr-defined]

    def __exit__(self, *exc: object) -> None:
        self._lock.__exit__(*exc)  # type: ignore[attr-defined]
        hook, self.hook = self.hook, None
        if hook is not None:
            hook()


@pytest.mark.parametrize(("mode", "suffix"), _TAR_MODES)
def test_walk_moving_on_right_after_a_read_keeps_the_stream_position(
    tmp_path: Path, mode: str, suffix: str
) -> None:
    """A pull on another thread just after a read through the walk releases the lock
    detaches the stream where that read ended, not where it began."""
    path, files = _big_tar(tmp_path, mode, suffix)
    with open_archive(path, concurrent_operations=True) as reader:
        lock = _LockWithReleaseHook(reader._walk_lock)  # type: ignore[attr-defined]
        reader._walk_lock = lock  # type: ignore[attr-defined]
        passes = reader.stream_members()
        member, stream = next(passes)
        assert stream is not None
        head = stream.read(1000)
        lock.hook = lambda: _in_thread(reader.members)
        middle = stream.read(1000)
        assert lock.hook is None
        assert head + middle + stream.read() == files[member.name]
        passes.close()  # type: ignore[attr-defined]


def test_refused_listing_calls_beside_a_pass_keep_memory_within_the_caps(
    tmp_path: Path,
) -> None:
    """``members()`` refused on every iteration keeps the listing within the caps,
    and the pass beside it still raises at the member that crosses one."""
    from archivey import ListingLimits, ResourceLimitError
    from tests.test_listing_limits import _tar_of_empty_members

    tar_path = _tar_of_empty_members(tmp_path / "many.tar", 4_000)
    cfg = ArchiveyConfig(listing_limits=ListingLimits(max_members=20))
    with open_archive(tar_path, config=cfg, concurrent_operations=True) as reader:
        seen = 0
        with pytest.raises(ResourceLimitError, match="max_members"):
            for _member, _stream in reader.stream_members():
                seen += 1
                with pytest.raises(ResourceLimitError):
                    reader.members()
                assert len(reader._listed) <= 20  # type: ignore[attr-defined]
        assert seen == 20


def test_listing_after_an_abandoned_pass_refuses_the_same_way_each_time(
    tmp_path: Path,
) -> None:
    from archivey import ListingLimits, ResourceLimitError
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
