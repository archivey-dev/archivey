"""Cooperative concurrency / lifecycle / password tests for MemberStreams.CONCURRENT.

Multi-thread / free-threaded stress lives in ``test_concurrent_multithread.py`` and the
Linux ``3.13t`` ``free-threaded-concurrency`` CI job.
"""

from __future__ import annotations

import contextvars
import gc
import gzip
import io
import sys
import tarfile
import threading
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from archivey import (
    ArchiveMember,
    ArchiveyError,
    ArchiveyUsageError,
    open_archive,
)
from archivey.internal.password import _PasswordCandidates
from archivey.internal.reader_state import LifecycleState
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.reader import ArchiveReader
from tests.conftest import binary_refusal

pytestmark = pytest.mark.concurrent_reader


def _dir_with_files(tmp_path: Path) -> Path:
    (tmp_path / "a.txt").write_bytes(b"aaa")
    (tmp_path / "b.txt").write_bytes(b"bbb")
    return tmp_path


# --- 7.3 cooperative state / overlap ----------------------------------------------------


def test_open_during_stream_members_raises(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader:
        it = reader.stream_members()
        _member, stream = next(it)
        assert stream is not None
        with pytest.raises(ArchiveyUsageError, match="already active"):
            reader.open("b.txt")
        assert stream.read() == b"aaa"
        # Exhaust / close the pass so the reader can be closed cleanly.
        list(it)


def test_members_then_open_ok(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    with open_archive(root, concurrent_operations=True) as reader:
        names = {m.name for m in reader.members()}
        assert names == {"a.txt", "b.txt"}
        s1 = reader.open("a.txt")
        s2 = reader.open("b.txt")
        assert s1.read() == b"aaa"
        assert s2.read() == b"bbb"
        s1.close()
        s2.close()


# --- iterate-then-open regression (random-mode __iter__ holds no pass across consumption) ---


@pytest.mark.parametrize("concurrent", [False, True])
def test_iterate_and_open_inside_loop(tmp_path: Path, concurrent: bool) -> None:
    """`for m in reader: reader.open(m)` must work on default and CONCURRENT readers.

    Random-mode iteration only walks the published snapshot, so it must not hold a
    reader-wide pass that would reject open()/get() in the loop body (D7 scope).
    """
    root = _dir_with_files(tmp_path)
    got: dict[str, bytes] = {}
    with open_archive(root, concurrent_operations=concurrent) as reader:
        for member in reader:
            if member.is_file:
                with reader.open(member) as stream:
                    got[member.name] = stream.read()
    assert got == {"a.txt": b"aaa", "b.txt": b"bbb"}


def test_iterate_and_get_inside_loop(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader:
        for member in reader:
            assert reader.get(member.name) is not None


def test_iterate_default_single_live_stream_gate_preserved(tmp_path: Path) -> None:
    """The fix must not weaken the default single-live-stream gate during iteration."""
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader, pytest.raises(ArchiveyUsageError):
        held = []
        for member in reader:
            if member.is_file:
                # Keep each stream open (never closed) → the second overlaps the first.
                held.append(reader.open(member))


def test_iterate_rejected_during_active_pass(tmp_path: Path) -> None:
    """Random-mode iteration still cannot start while another pass owns the reader."""
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader:
        it = reader.stream_members()
        next(it)
        with pytest.raises(ArchiveyUsageError, match="already active"):
            next(iter(reader))
        list(it)


# --- Closing while a pass is suspended at a yield ---------------------------------------
#
# A pass whose generator is suspended at a yield is not running: the caller holds the
# iterator. close() closes the reader anyway, like zipfile.ZipFile.close() with member
# handles open, and resuming the iterator afterwards raises ArchiveyUsageError.

_FIXTURES = Path(__file__).parent / "fixtures"
_RAR_FIXTURE = _FIXTURES / "rar" / "basic_solid__.rar"
_SEVENZIP_FIXTURE = _FIXTURES / "sevenzip" / "links_mid_folder_solid.7z"


def _zip_with_files(tmp_path: Path) -> Path:
    path = tmp_path / "files.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"aaa")
        zf.writestr("b.txt", b"bbb")
    return path


def _tar_gz_with_files(tmp_path: Path) -> Path:
    path = tmp_path / "files.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, data in (("a.txt", b"aaa"), ("b.txt", b"bbb")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _rar_fixture(_tmp: Path) -> Path:
    return _RAR_FIXTURE


def _sevenzip_fixture(_tmp: Path) -> Path:
    return _SEVENZIP_FIXTURE


_SUSPENDED_SOURCES = [
    pytest.param(_dir_with_files, False, id="dir"),
    pytest.param(_zip_with_files, False, id="zip"),
    pytest.param(_zip_with_files, True, id="zip-streaming"),
    pytest.param(_tar_gz_with_files, True, id="tar.gz-streaming"),
    pytest.param(_rar_fixture, False, id="rar-solid"),
    pytest.param(_rar_fixture, True, id="rar-solid-streaming"),
    pytest.param(_sevenzip_fixture, False, id="7z-solid"),
    pytest.param(_sevenzip_fixture, True, id="7z-solid-streaming"),
]

# Reading a member of the RAR fixture runs RARLAB unrar, which a core-only install
# may lack. Listing it does not, so only the tests that read are gated, keyed on the
# fixture function rather than the row id. binary_refusal("unrar") is archivey's own
# rule, met by RARLAB unrar or rar 6.0+.
_UNRAR_REFUSAL = binary_refusal("unrar")
_READ_SOURCES = [
    pytest.param(
        *p.values,
        id=p.id,
        marks=pytest.mark.skipif(
            _UNRAR_REFUSAL is not None, reason=f"needs unrar: {_UNRAR_REFUSAL}"
        ),
    )
    if p.values[0] is _rar_fixture
    else p
    for p in _SUSPENDED_SOURCES
]


@pytest.mark.parametrize(("make_source", "streaming"), _READ_SOURCES)
def test_close_while_stream_members_suspended_closes_reader(
    tmp_path: Path, make_source, streaming: bool
) -> None:
    reader = open_archive(make_source(tmp_path), streaming=streaming)
    it = reader.stream_members()
    # Stop at the first file with data and read one byte of it, so a stream is part-read
    # mid-pass (a solid block or an unrar pipe in flight).
    stream = next(s for m, s in it if s is not None and m.size)
    assert len(stream.read(1)) == 1
    reader.close()
    # The yielded stream went with the reader, reads as any closed stream does, and the
    # reader takes no new calls.
    assert stream.closed
    with pytest.raises(ValueError, match="closed file"):
        stream.read(1)
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.stream_members()
    # Resuming the suspended pass reports the close instead of reading on.
    with pytest.raises(ArchiveyUsageError, match="closed"):
        next(it)
    with pytest.raises(StopIteration):
        next(it)
    reader.close()  # idempotent


@pytest.mark.parametrize(("make_source", "streaming"), _SUSPENDED_SOURCES)
def test_with_exit_closes_reader_with_suspended_stream_members(
    tmp_path: Path, make_source, streaming: bool
) -> None:
    """The iterator kept in a variable: leaving the block closes the reader cleanly."""
    with open_archive(make_source(tmp_path), streaming=streaming) as reader:
        it = reader.stream_members()
        next(it)
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.stream_members()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        next(it)


@pytest.mark.parametrize(("make_source", "streaming"), _SUSPENDED_SOURCES)
def test_body_exception_survives_with_exit_over_suspended_stream_members(
    tmp_path: Path, make_source, streaming: bool
) -> None:
    """A wrapped pass held in a variable is still alive at exit; the body's error wins."""
    with (
        pytest.raises(RuntimeError, match="boom") as excinfo,
        open_archive(make_source(tmp_path), streaming=streaming) as reader,
    ):
        numbered = enumerate(reader.stream_members())
        for _i, (_member, _stream) in numbered:
            raise RuntimeError("boom")
    assert excinfo.value.__context__ is None
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.stream_members()


@pytest.mark.parametrize(
    ("make_source", "streaming"),
    [p for p in _SUSPENDED_SOURCES if p.values[1]],
)
def test_close_while_streaming_iteration_suspended_closes_reader(
    tmp_path: Path, make_source, streaming: bool
) -> None:
    """Streaming ``iter(reader)`` holds the same kind of pass as ``stream_members()``."""
    reader = open_archive(make_source(tmp_path), streaming=streaming)
    it = iter(reader)
    next(it)
    reader.close()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        next(it)


@dataclass
class _SuspendedPass:
    reader: ArchiveReader
    it: Iterator[tuple[ArchiveMember, ArchiveStream | None]]
    stream: ArchiveStream
    source: object
    events: list[str]


def _open_under_suspended_pass(
    path: Path,
    streaming: bool,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail: frozenset[str] = frozenset(),
) -> _SuspendedPass:
    """A reader whose ``stream_members()`` pass is suspended after a member was read.

    A member is read so the pass holds its resources (a solid block, an ``unrar``
    pipe). The backend's pass iterator, ``_close_public_streams`` and ``_close_archive``
    are wrapped to record when each has run; each step named in ``fail`` raises after
    it has done its real work: ``"wind-down"`` (the pass's own ``finally``),
    ``"streams"`` and ``"teardown"``.
    """
    events: list[str] = []
    reader = open_archive(path, streaming=streaming)
    real_pass = reader._iter_with_data
    real_close_streams = reader._close_public_streams
    real_close_archive = reader._close_archive

    def recorded_pass(*args, **kwargs):  # a generator wrapper
        try:
            yield from real_pass(*args, **kwargs)
        finally:
            events.append("pass wound down")
            if "wind-down" in fail:
                raise RuntimeError("wind-down failed")

    def recorded_close_streams() -> None:
        real_close_streams()
        events.append("streams closed")
        if "streams" in fail:
            raise OSError("stream close failed")

    def recorded_close_archive() -> None:
        events.append("archive closed")
        real_close_archive()
        if "teardown" in fail:
            raise OSError("teardown failed")

    monkeypatch.setattr(reader, "_iter_with_data", recorded_pass)
    monkeypatch.setattr(reader, "_close_public_streams", recorded_close_streams)
    monkeypatch.setattr(reader, "_close_archive", recorded_close_archive)
    it = reader.stream_members()
    stream = next(s for m, s in it if s is not None and m.size)
    assert stream.read()
    return _SuspendedPass(reader, it, stream, reader._source, events)


_CLOSE_ORDER = ["pass wound down", "streams closed", "archive closed"]


@pytest.mark.parametrize(("make_source", "streaming"), _READ_SOURCES)
def test_close_winds_down_suspended_pass_before_teardown(
    tmp_path: Path,
    make_source,
    streaming: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """close() finishes the backend's pass and the streams before it closes the archive.

    The pass end is recorded once the backend iterator's own ``finally`` (last stream
    close, then pass cleanup) has run.
    """
    p = _open_under_suspended_pass(make_source(tmp_path), streaming, monkeypatch)
    p.reader.close()
    assert p.events == _CLOSE_ORDER
    assert p.source is None or p.source.closed
    with pytest.raises(ArchiveyUsageError, match="closed"):
        next(p.it)


def _messages(group: BaseExceptionGroup) -> list[str]:
    return [f"{type(e).__name__}: {e}" for e in group.exceptions]


_FAILING_STEPS = {
    "wind-down": frozenset({"wind-down"}),
    "streams": frozenset({"streams"}),
    "both": frozenset({"wind-down", "streams"}),
    "wind-down+teardown": frozenset({"wind-down", "teardown"}),
}


@pytest.mark.parametrize("fail", list(_FAILING_STEPS))
@pytest.mark.parametrize(("make_source", "streaming"), _READ_SOURCES)
def test_close_tears_down_when_a_close_step_fails(
    tmp_path: Path,
    make_source,
    streaming: bool,
    fail: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing wind-down or stream close propagates, and the archive is torn down.

    The wind-down lease keeps teardown back until both steps have run; a step that
    raises must not leave the archive and its source open.
    """
    p = _open_under_suspended_pass(
        make_source(tmp_path), streaming, monkeypatch, fail=_FAILING_STEPS[fail]
    )
    with pytest.raises(Exception) as excinfo:  # checked per case below
        p.reader.close()
    exc = excinfo.value
    if fail == "wind-down":
        assert type(exc) is RuntimeError
        assert str(exc) == "wind-down failed"
    elif fail == "streams":
        assert type(exc) is OSError
        assert str(exc) == "stream close failed"
    else:
        assert isinstance(exc, ExceptionGroup)
        if fail == "both":
            assert exc.message == (
                "winding down the pass and closing member streams both failed"
            )
            assert _messages(exc) == [
                "RuntimeError: wind-down failed",
                "OSError: stream close failed",
            ]
        else:
            assert exc.message == "close-time cleanup and archive teardown both failed"
            assert _messages(exc) == [
                "RuntimeError: wind-down failed",
                "OSError: teardown failed",
            ]
    assert p.events == _CLOSE_ORDER
    assert p.source is None or p.source.closed
    assert p.stream.closed
    p.reader.close()  # idempotent after the failed close
    with pytest.raises(ArchiveyUsageError, match="closed"):
        next(p.it)


def _interrupt_close_at(
    state: object,
    point: str,
    monkeypatch: pytest.MonkeyPatch,
    then: Callable[[], None] | None = None,
) -> None:
    """Make the next ``close()`` raise ``KeyboardInterrupt`` inside its stream-shutdown step.

    ``"claim"``: just after it took the claim, before it took the closer. ``"closer"``:
    inside the closer, after the closer's real work (the pass wound down). ``then``
    runs just before the interrupt. Later calls are not interrupted.
    """
    fired: list[int] = []

    def interrupt() -> None:
        if not fired:
            fired.append(1)
            if then is not None:
                then()
            raise KeyboardInterrupt

    if point == "claim":
        real_claim = state.claim_stream_shutdown

        def claim(ticket: object) -> bool:
            claimed = real_claim(ticket)
            interrupt()
            return claimed

        monkeypatch.setattr(state, "claim_stream_shutdown", claim)
    else:
        real_take = state.take_pass_wind_down

        def take() -> Callable[[], None] | None:
            closer = real_take()
            if closer is None:
                return None

            def closer_then_interrupt() -> None:
                closer()
                interrupt()

            return closer_then_interrupt

        monkeypatch.setattr(state, "take_pass_wind_down", take)


def _assert_wound_down_once_in_order(events: list[str]) -> None:
    """The close order held, and the pass was wound down exactly once.

    An interrupt inside the closer still closes the streams on its way out (the step's
    ``finally``), and the retry closes them again, a no-op; so "streams closed" may be
    recorded twice.
    """
    assert events.count("pass wound down") == 1
    assert events.count("archive closed") == 1
    assert list(dict.fromkeys(events)) == _CLOSE_ORDER


@pytest.mark.parametrize("point", ["claim", "closer"])
def test_close_after_a_peer_close_and_an_interrupt_still_tears_down(
    tmp_path: Path, point: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A peer close() that ran while the step's holder worked must not end the close.

    The peer finds the claim held and teardown refused, and returns. The holder is then
    interrupted and hands the claim back. A later close() must still retake it, drop the
    pass wind-down lease and tear the archive down.
    """
    p = _open_under_suspended_pass(_zip_with_files(tmp_path), False, monkeypatch)
    state = p.reader._state
    peer_errors: list[BaseException] = []

    def peer_close() -> None:
        def run() -> None:
            try:
                p.reader.close()
            except BaseException as exc:  # noqa: BLE001 - surfaced by the assert below
                peer_errors.append(exc)

        peer = threading.Thread(target=run)
        peer.start()
        peer.join(10)
        assert not peer.is_alive()

    _interrupt_close_at(state, point, monkeypatch, then=peer_close)
    with pytest.raises(KeyboardInterrupt):
        p.reader.close()
    assert peer_errors == []
    assert state.lifecycle is LifecycleState.READER_CLOSED
    p.reader.close()
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    _assert_wound_down_once_in_order(p.events)
    assert p.source is None or p.source.closed


@pytest.mark.parametrize("point", ["claim", "closer"])
@pytest.mark.parametrize(("make_source", "streaming"), _READ_SOURCES)
def test_interrupted_close_tears_down_when_the_pass_iterator_goes(
    tmp_path: Path,
    make_source,
    streaming: bool,
    point: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no later close(), dropping the suspended pass still reaches teardown.

    The interrupted close() handed the claim back with the pass wind-down lease still
    held. The pass iterator's own ``finally`` must then finish the step.
    """
    p = _open_under_suspended_pass(make_source(tmp_path), streaming, monkeypatch)
    state = p.reader._state
    _interrupt_close_at(state, point, monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        p.reader.close()
    assert state.lifecycle is LifecycleState.READER_CLOSED
    p.it.close()
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    _assert_wound_down_once_in_order(p.events)
    assert p.source is None or p.source.closed
    assert p.stream.closed


_RECOVERED_STEP_FAILURES = {
    "wind-down": (frozenset({"wind-down"}), RuntimeError, "wind-down failed"),
    "teardown": (frozenset({"teardown"}), OSError, "teardown failed"),
}


@pytest.mark.parametrize("route", ["generator close", "collect"])
@pytest.mark.parametrize("fail", list(_RECOVERED_STEP_FAILURES))
def test_failure_in_a_step_the_pass_iterator_finished_comes_out_of_it(
    tmp_path: Path, fail: str, route: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing step finished by the pass iterator surfaces where the iterator ended.

    An interrupted close() handed the step back; the pass iterator then finishes it.
    Closed explicitly, the failure comes out of its ``close()``. Collected, there is no
    caller to raise to, so it goes to ``sys.unraisablehook``. Teardown runs on both.
    """
    steps, exc_type, message = _RECOVERED_STEP_FAILURES[fail]
    p = _open_under_suspended_pass(
        _zip_with_files(tmp_path), False, monkeypatch, fail=steps
    )
    state = p.reader._state
    _interrupt_close_at(state, "claim", monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        p.reader.close()
    assert state.lifecycle is LifecycleState.READER_CLOSED
    if route == "generator close":
        with pytest.raises(exc_type, match=message):
            p.it.close()
    else:
        unraisable: list[BaseException | None] = []
        monkeypatch.setattr(
            sys, "unraisablehook", lambda args: unraisable.append(args.exc_value)
        )
        del p.it
        gc.collect()
        assert [(type(e), str(e)) for e in unraisable] == [(exc_type, message)]
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    _assert_wound_down_once_in_order(p.events)
    assert p.source is None or p.source.closed
    assert p.stream.closed


def test_close_still_refused_while_pass_runs_on_another_thread(tmp_path: Path) -> None:
    """Only a pass suspended at a yield is closed underneath; a running one still blocks."""
    root = _dir_with_files(tmp_path)
    reader = open_archive(root)
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def selector(_member: object) -> bool:
        entered.set()
        release.wait(10)
        return True

    def run() -> None:
        try:
            list(reader.stream_members(selector))
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assert below
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(10)
        with pytest.raises(ArchiveyUsageError, match="is active"):
            reader.close()
    finally:
        release.set()
        worker.join(10)
    assert errors == []
    reader.close()


# --- 7.4 cooperative lifecycle ----------------------------------------------------------


def test_reader_close_closes_member_streams(tmp_path: Path) -> None:
    """A member stream does not outlive its reader (stdlib ZipFile/TarFile parity)."""
    root = _dir_with_files(tmp_path)
    reader = open_archive(root)
    stream = reader.open("a.txt")
    reader.close()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.open("b.txt")
    assert stream.closed
    with pytest.raises(ValueError, match="closed file"):
        stream.read()
    stream.close()  # idempotent


def test_caller_owned_source_not_closed_by_reader() -> None:
    buf = io.BytesIO(gzip.compress(b"payload"))
    with open_archive(buf) as reader, reader.open(reader.members()[0]) as stream:
        assert stream.read() == b"payload"
    assert not buf.closed


def test_usage_errors_escape_archivey_error(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader:
        s = reader.open("a.txt")
        try:
            with pytest.raises(ArchiveyUsageError):
                reader.open("b.txt")
        finally:
            s.close()
    assert not issubclass(ArchiveyUsageError, ArchiveyError)


# --- 7.5 password (simplified D10) ------------------------------------------------------


def test_password_provider_reentry_raises() -> None:
    box: dict[str, _PasswordCandidates] = {}

    def provider(req):
        # Same-reader reentry while the provider lock marks depth > 0.
        with pytest.raises(ArchiveyUsageError, match="reentered"):
            box["c"]._call_provider(None, 99)
        return b"pw" if req.attempt == 1 else None

    candidates = _PasswordCandidates.from_input(provider)
    box["c"] = candidates
    assert candidates.attempt(None, lambda _p: b"data") == b"data"


def test_password_provider_second_thread_waits_instead_of_raising() -> None:
    """Two workers needing the provider at once is a correct program, not reentry.

    The guard used to count calls per reader, so while one thread's provider was
    running, any other thread asking the same reader failed with the reentry error.
    """
    entered = threading.Event()
    release = threading.Event()
    active = 0
    max_active = 0
    lock = threading.Lock()

    def provider(req):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        entered.set()
        release.wait(5)
        with lock:
            active -= 1
        return b"pw"

    candidates = _PasswordCandidates.from_input(provider)
    results: dict[str, object] = {}

    def ask(name: str) -> None:
        try:
            results[name] = candidates._call_provider(None, 1)
        except BaseException as exc:  # noqa: BLE001 - reported below
            results[name] = exc

    first = threading.Thread(target=ask, args=("first",))
    first.start()
    assert entered.wait(5)
    second = threading.Thread(target=ask, args=("second",))
    second.start()
    # The second call must be parked on the turn, not failed and finished.
    second.join(0.2)
    assert second.is_alive(), results.get("second")
    release.set()
    first.join(5)
    second.join(5)
    assert results == {"first": b"pw", "second": b"pw"}
    assert max_active == 1


def test_password_provider_reentry_from_a_context_carrying_thread_raises() -> None:
    """A provider that hands reader work to a helper thread is still reentry.

    The helper is not the provider's thread, so a thread check alone would park it
    behind the turn the provider holds while the provider waits on the helper.
    ``contextvars.copy_context().run`` is what ``asyncio.to_thread`` does.
    """
    box: dict[str, object] = {}

    def helper() -> None:
        try:
            box["result"] = candidates._call_provider(None, 99)
        except ArchiveyUsageError as exc:
            box["result"] = exc

    def provider(req):
        context = contextvars.copy_context()
        worker = threading.Thread(target=context.run, args=(helper,), daemon=True)
        worker.start()
        worker.join(5)
        box["deadlocked"] = worker.is_alive()
        return b"pw"

    candidates = _PasswordCandidates.from_input(provider)
    assert candidates._call_provider(None, 1) == b"pw"
    assert box["deadlocked"] is False
    assert isinstance(box["result"], ArchiveyUsageError)
    assert "reentered" in str(box["result"])


def test_password_provider_turn_released_when_provider_raises() -> None:
    calls = 0

    def provider(req):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("prompt cancelled")
        return b"pw"

    candidates = _PasswordCandidates.from_input(provider)
    with pytest.raises(RuntimeError, match="prompt cancelled"):
        candidates._call_provider(None, 1)
    worker: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: worker.update(pw=candidates._call_provider(None, 1))
    )
    thread.start()
    thread.join(5)
    assert worker == {"pw": b"pw"}


def test_password_known_good_promotion_converges() -> None:
    state = _PasswordCandidates.from_input([b"wrong", b"right"])
    calls: list[bytes] = []

    def decrypt(password: bytes) -> bytes:
        calls.append(password)
        if password != b"right":
            from archivey.exceptions import EncryptionError

            raise EncryptionError("nope")
        return b"ok"

    assert state.attempt(None, decrypt) == b"ok"
    assert calls == [b"wrong", b"right"]
    # Second unit prefers known-good first.
    calls.clear()
    assert state.attempt(None, decrypt) == b"ok"
    assert calls[0] == b"right"


# --- 7.6 ArchiveStream open_fn without stream lock --------------------------------------


def test_archive_stream_open_fn_runs_outside_stream_lock() -> None:
    held = {"during_open": False}

    def open_fn() -> io.BytesIO:
        held["during_open"] = True
        return io.BytesIO(b"xyz")

    stream = ArchiveStream(
        open_fn,
        translate=lambda _e: None,
        lazy=True,
        seekable=False,
    )
    # open_fn must complete without needing the stream lock (a non-reentrant Lock would
    # deadlock if _ensure_open held it across the call).
    assert stream._open_lock.acquire(blocking=False)
    stream._open_lock.release()
    assert stream.read() == b"xyz"
    assert held["during_open"]


# --- 7.7 stream_members ownership -------------------------------------------------------


def test_stream_members_advance_closes_prior(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader:
        it = reader.stream_members()
        _m1, s1 = next(it)
        assert s1 is not None
        _m2, s2 = next(it)
        assert s2 is not None
        assert s1.closed
        assert s2.read() == b"bbb"
        list(it)


def test_stream_members_abandon_releases_pass(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    with open_archive(root) as reader:
        it = reader.stream_members()
        next(it)
        it.close()  # abandon
        # Pass released: a new open is allowed.
        with reader.open("a.txt") as s:
            assert s.read() == b"aaa"


# --- Same-thread re-entry from callbacks must raise, not deadlock (deep N4) -------------


def _zip_with_bad_dos_date(tmp_path: Path) -> Path:
    """A ZIP whose materialization emits MEMBER_TIMESTAMP_INVALID (invalid DOS day)."""
    import zipfile

    path = tmp_path / "bad-date.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("bad.txt", date_time=(2021, 2, 31, 0, 0, 0))
        zf.writestr(info, b"x")
    return path


def test_reader_reentry_from_diagnostic_callback_raises_not_deadlocks(
    tmp_path: Path,
) -> None:
    """A diagnostic callback calling back into the reader mid-materialization would
    wait on the materialization condition for a notify only its own thread can send.
    It must be rejected loudly instead (the pre-fix behavior was a permanent
    single-thread hang; pytest-timeout would trip on a regression)."""
    from archivey import ArchiveyConfig

    path = _zip_with_bad_dos_date(tmp_path)
    reader = None

    def on_diagnostic(diagnostic: object) -> None:
        assert reader is not None
        reader.members()  # re-enter the reader that is mid-materialization

    config = ArchiveyConfig(on_diagnostic=on_diagnostic)
    with open_archive(path, concurrent_operations=True, config=config) as opened:
        reader = opened
        with pytest.raises(ArchiveyUsageError, match="re-entered"):
            reader.members()
        # The failed election rolled back; the reader stays usable once the callback
        # behaves (subsequent emit re-fires the callback, so swap it off first).
        reader = None


def test_close_from_diagnostic_callback_raises_not_deadlocks(tmp_path: Path) -> None:
    """close() from inside one of the reader's own worker calls (via a callback) would
    drain-wait forever for a worker that cannot return until close() does."""
    from archivey import ArchiveyConfig

    path = _zip_with_bad_dos_date(tmp_path)
    reader = None

    def on_diagnostic(diagnostic: object) -> None:
        assert reader is not None
        reader.close()

    config = ArchiveyConfig(on_diagnostic=on_diagnostic)
    reader_cm = open_archive(path, concurrent_operations=True, config=config)
    try:
        reader = reader_cm
        with pytest.raises(ArchiveyUsageError, match="from inside one of its own"):
            reader.members()
    finally:
        reader = None
        reader_cm.close()
