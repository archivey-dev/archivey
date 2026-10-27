"""Reader lifecycle bookkeeping (``internal/reader_state.py``) and link-chain walks.

Covers the same-thread re-entry diagnosis (S21-K4), a close whose drain is interrupted
while a second closer waits (S21-K5), and long symlink chains: listing must be linear
in the chain length (S17-K10), and opening a dangling or cyclic chain must raise the
library's own errors rather than ``RecursionError`` (S17-K11).
"""

from __future__ import annotations

import contextlib
import io
import random
import tarfile
import threading
import time
import unicodedata
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from archivey import ArchiveMember, ArchiveyConfig, open_archive
from archivey.exceptions import (
    ArchiveyUsageError,
    LinkTargetNotFoundError,
    ReadError,
)
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.reader_state import (
    LifecycleState,
    OperationToken,
    ReaderState,
)
from archivey.reader import ArchiveReader
from archivey.types import MemberStreams
from tests.test_concurrent_cooperative import (
    _assert_wound_down_once_in_order,
    _interrupt_close_at,
    _open_under_suspended_pass,
    _zip_with_files,
)

REENTRY = "re-entered from inside its own"
CLOSE_FROM_INSIDE = "from inside one of its own calls"


def _state(*, concurrent: bool = False) -> ReaderState:
    streams = MemberStreams.CONCURRENT if concurrent else MemberStreams(0)
    return ReaderState(member_streams=streams, open_site=None)


def _in_thread(fn: Callable[[], object]) -> None:
    thread = threading.Thread(target=fn)
    thread.start()
    thread.join()


# ---------------------------------------------------------------------------
# S21-K4: same-thread re-entry is diagnosed before the generic overlap messages
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("concurrent", [False, True])
def test_close_inside_own_pass_names_the_callback(concurrent: bool) -> None:
    state = _state(concurrent=concurrent)
    state.acquire_pass("members")
    with pytest.raises(ArchiveyUsageError, match=CLOSE_FROM_INSIDE):
        state.mark_reader_closed()
    assert state.lifecycle is LifecycleState.OPEN


@pytest.mark.parametrize("concurrent", [False, True])
def test_close_inside_own_worker_names_the_callback(concurrent: bool) -> None:
    state = _state(concurrent=concurrent)
    state.acquire_worker("open")
    with pytest.raises(ArchiveyUsageError, match=CLOSE_FROM_INSIDE):
        state.mark_reader_closed()
    assert state.lifecycle is LifecycleState.OPEN


@pytest.mark.parametrize("concurrent", [False, True])
def test_pass_inside_own_pass_names_the_callback(concurrent: bool) -> None:
    state = _state(concurrent=concurrent)
    state.acquire_pass("members")
    with pytest.raises(ArchiveyUsageError, match=REENTRY):
        state.acquire_pass("members")
    with pytest.raises(ArchiveyUsageError, match=REENTRY):
        state.acquire_worker("open")


def test_worker_inside_own_worker_names_the_callback() -> None:
    state = _state(concurrent=True)
    state.acquire_worker("members")
    with pytest.raises(ArchiveyUsageError, match=REENTRY):
        state.acquire_worker("get")


def test_another_threads_pass_keeps_the_generic_message() -> None:
    state = _state()
    _in_thread(lambda: state.acquire_pass("members"))
    with pytest.raises(ArchiveyUsageError, match="another reader operation") as ei:
        state.mark_reader_closed()
    assert REENTRY not in str(ei.value)
    with pytest.raises(ArchiveyUsageError, match="another reader operation"):
        state.acquire_pass("members")


def test_suspended_pass_is_not_diagnosed_as_a_callback() -> None:
    """A generator suspended at a yield: its thread is running the caller's loop body."""
    state = _state()
    token = state.acquire_pass("stream_members")
    state.set_suspended(token, True)
    with pytest.raises(ArchiveyUsageError, match="another reader operation"):
        state.acquire_worker("open")
    # Running again (a diagnostic fired inside a step): that is re-entry.
    state.set_suspended(token, False)
    with pytest.raises(ArchiveyUsageError, match=REENTRY):
        state.acquire_worker("open")
    with pytest.raises(ArchiveyUsageError, match=CLOSE_FROM_INSIDE):
        state.mark_reader_closed()
    # Suspended again: the close comes from the caller's loop body, and a suspended
    # pass does not block it. The reader closes under the pass.
    state.set_suspended(token, True)
    state.mark_reader_closed()
    assert state.lifecycle is not LifecycleState.OPEN


def test_internal_open_window_still_admits_children() -> None:
    state = _state()
    root = state.acquire_pass("extract_all")
    state.begin_internal_opens()
    try:
        child = state.acquire_pass("stream_members")
        worker = state.acquire_worker("open")
    finally:
        state.end_internal_opens()
    assert child.parent is root
    assert worker.parent is root


def _zip_with_bidi_name() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil\u202etxt.exe", b"x")
        zf.writestr("plain.txt", b"y")
    return buf.getvalue()


def test_default_reader_callback_close_during_members_names_the_callback() -> None:
    """End to end: the case the sweep measured on a default (non-concurrent) reader."""
    assert unicodedata.bidirectional("\u202e") == "RLO"
    errors: list[BaseException] = []
    holder: list[ArchiveReader] = []

    def on_diagnostic(_diag: object) -> None:
        try:
            holder[0].close()
        except ArchiveyUsageError as exc:
            errors.append(exc)

    config = ArchiveyConfig(on_diagnostic=on_diagnostic)
    with open_archive(io.BytesIO(_zip_with_bidi_name()), config=config) as reader:
        holder.append(reader)
        reader.members()
    assert errors, "fixture must emit a diagnostic during listing"
    assert CLOSE_FROM_INSIDE in str(errors[0])


def test_callback_inside_stream_members_step_names_the_callback() -> None:
    """The streaming path: a diagnostic fires while the generator runs a step."""
    errors: list[BaseException] = []
    holder: list[ArchiveReader] = []

    def on_diagnostic(_diag: object) -> None:
        try:
            holder[0].get("plain.txt")
        except ArchiveyUsageError as exc:
            errors.append(exc)

    config = ArchiveyConfig(on_diagnostic=on_diagnostic)
    with open_archive(io.BytesIO(_zip_with_bidi_name()), config=config) as reader:
        holder.append(reader)
        for _member, _stream in reader.stream_members():
            pass
    assert errors, "fixture must emit a diagnostic during the pass"
    assert REENTRY in str(errors[0])


def test_loop_body_of_stream_members_keeps_the_generic_message() -> None:
    """The caller's own loop body is not a callback, so the message stays generic."""
    with open_archive(io.BytesIO(_zip_with_bidi_name())) as reader:
        for _member, _stream in reader.stream_members():
            with pytest.raises(ArchiveyUsageError) as ei:
                reader.get("plain.txt")
            assert "another reader operation ('stream_members')" in str(ei.value)
            # Not a callback either: the close is the caller's, and a pass suspended
            # at a yield does not block it.
            reader.close()
            with pytest.raises(ArchiveyUsageError, match="closed"):
                reader.get("plain.txt")
            break


# ---------------------------------------------------------------------------
# S21-K5: an interrupted drain must not tell a waiting closer the reader closed
# ---------------------------------------------------------------------------


def test_interrupted_drain_hands_close_to_the_waiting_closer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(concurrent=True)
    worker_box: list[OperationToken] = []
    _in_thread(lambda: worker_box.append(state.acquire_worker("open")))

    real_workers_wait = state._workers_cv.wait
    real_close_wait = state._close_cv.wait
    second_waiting = threading.Event()
    first_closer: list[threading.Thread] = []

    def workers_wait(timeout: float | None = None) -> bool:
        if threading.current_thread() in first_closer:
            # Hold the drain until the second closer is parked, then abort it the
            # way Ctrl-C does during Condition.wait().
            deadline = time.monotonic() + 5
            while not second_waiting.is_set() and time.monotonic() < deadline:
                real_workers_wait(0.01)
            raise KeyboardInterrupt
        return real_workers_wait(timeout)

    def close_wait(timeout: float | None = None) -> bool:
        second_waiting.set()
        return real_close_wait(timeout)

    monkeypatch.setattr(state._workers_cv, "wait", workers_wait)
    monkeypatch.setattr(state._close_cv, "wait", close_wait)

    first_raised: list[BaseException] = []
    second_result: list[bool] = []

    def first() -> None:
        first_closer.append(threading.current_thread())
        try:
            state.mark_reader_closed()
        except KeyboardInterrupt as exc:
            first_raised.append(exc)

    def second() -> None:
        # Enter only once the first closer is draining.
        deadline = time.monotonic() + 5
        while not state._closing and time.monotonic() < deadline:
            time.sleep(0.001)
        second_result.append(state.mark_reader_closed())

    t1 = threading.Thread(target=first, daemon=True)
    t2 = threading.Thread(target=second, daemon=True)
    t1.start()
    t2.start()
    t1.join(5)
    assert first_raised, "the first closer's drain must have been interrupted"
    # The second closer must now be draining itself, not reporting a peer's close.
    time.sleep(0.05)
    assert not second_result
    assert state.lifecycle is LifecycleState.OPEN
    state.release_worker(worker_box[0])
    t2.join(5)
    assert not t2.is_alive()
    assert second_result == [True]
    assert state.lifecycle is LifecycleState.READER_CLOSED
    assert state.claim_teardown()


def test_interrupt_after_the_transition_still_tears_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ctrl-C on the closers' notify, after the reader moved to READER_CLOSED."""
    reader = open_archive(io.BytesIO(_zip_with_bidi_name()))
    assert isinstance(reader, BaseArchiveReader)
    state = reader._state
    real_notify = state._close_cv.notify_all
    calls: list[int] = []

    def notify_all() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt
        real_notify()

    monkeypatch.setattr(state._close_cv, "notify_all", notify_all)
    with pytest.raises(KeyboardInterrupt):
        reader.close()
    assert state.lifecycle is LifecycleState.READER_CLOSED
    reader.close()
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


@pytest.mark.parametrize(
    ("target", "method"),
    [
        # Between the transition and the reader's lease drop.
        ("state", "_drop_reader_lease_locked"),
        # Just after the reader's lease flag is cleared.
        ("state", "_teardown_due_locked"),
        # Past the transition, in close()'s own stream-shutdown step.
        ("state", "claim_stream_shutdown"),
        ("reader", "_close_public_streams"),
    ],
)
def test_interrupted_close_is_finished_by_the_next_close(
    monkeypatch: pytest.MonkeyPatch, target: str, method: str
) -> None:
    reader = open_archive(io.BytesIO(_zip_with_bidi_name()))
    assert isinstance(reader, BaseArchiveReader)
    state = reader._state
    obj: object = state if target == "state" else reader
    real = getattr(obj, method)
    calls: list[int] = []

    def interrupt_once(*args: object, **kwargs: object) -> object:
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt
        return real(*args, **kwargs)

    monkeypatch.setattr(obj, method, interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        reader.close()
    assert state.lifecycle is LifecycleState.READER_CLOSED
    reader.close()
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


@pytest.mark.parametrize(
    "point",
    [
        # Just after close() took the stream-shutdown claim, before it took the closer:
        # the retry runs the closer.
        "claim",
        # Inside the closer, after its real work: the closer is gone, so the retry
        # skips the wind-down and only closes the streams and drops the lease.
        "closer",
    ],
)
def test_close_interrupted_in_the_stream_shutdown_step_is_finished_by_the_next_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    """Ctrl-C inside close()'s stream-shutdown step, with a pass suspended.

    The close transition took the pass wind-down lease. The interrupted close() must
    hand the claim back, so the next close() can finish the step, drop that lease and
    tear the archive down. A spent claim would strand the lease for good. The pass is
    wound down exactly once, before teardown, at either point.
    """
    p = _open_under_suspended_pass(_zip_with_files(tmp_path), False, monkeypatch)
    state = p.reader._state
    _interrupt_close_at(state, point, monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        p.reader.close()
    assert state.lifecycle is LifecycleState.READER_CLOSED
    p.reader.close()
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    _assert_wound_down_once_in_order(p.events)
    assert p.source is None or p.source.closed
    assert p.stream.closed
    with pytest.raises(ArchiveyUsageError, match="closed"):
        next(p.it)


# ---------------------------------------------------------------------------
# S17-K10 / S17-K11: long symlink chains
# ---------------------------------------------------------------------------


def _symlink_chain_tar(
    path: Path, n: int, *, last_target: str, file_at_end: bool = False
) -> Path:
    with tarfile.open(path, "w") as tf:
        for i in range(n):
            info = tarfile.TarInfo(f"l{i}")
            info.type = tarfile.SYMTYPE
            info.linkname = f"l{i + 1}" if i + 1 < n else last_target
            tf.addfile(info)
        if file_at_end:
            data = b"payload"
            info = tarfile.TarInfo(last_target)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def test_listing_a_long_symlink_chain_is_linear(tmp_path: Path) -> None:
    """5000 chained links took ~27s when every link walked the chain from scratch."""
    n = 5000
    path = _symlink_chain_tar(
        tmp_path / "chain.tar", n, last_target="end.txt", file_at_end=True
    )
    start = time.perf_counter()
    with open_archive(path) as reader:
        members = {m.name: m for m in reader.members()}
        elapsed = time.perf_counter() - start
        for i in (0, n // 2, n - 1):
            target = members[f"l{i}"].link_target_member
            assert target is not None and target.name == "end.txt"
        assert reader.read("l0") == b"payload"
    assert elapsed < 5.0, f"listing {n} chained links took {elapsed:.1f}s"


def test_open_long_dangling_chain_raises_link_target_not_found(
    tmp_path: Path,
) -> None:
    n = 2000
    path = _symlink_chain_tar(tmp_path / "dangling.tar", n, last_target=f"l{n}")
    with open_archive(path) as reader:
        start = reader.get("l0")
        assert start is not None and start.link_target_member is None
        with pytest.raises(LinkTargetNotFoundError):
            reader.open("l0")


def test_open_long_cycle_raises_read_error(tmp_path: Path) -> None:
    n = 2000
    path = _symlink_chain_tar(tmp_path / "cycle.tar", n, last_target="l0")
    with open_archive(path) as reader:
        start = reader.get("l0")
        assert start is not None and start.link_target_member is None
        with pytest.raises(ReadError, match="Link cycle detected") as info:
            reader.open("l0")
    # The member name is an attribute, rendered once by __str__, not repeated in
    # the message text.
    assert info.value.member_name is not None
    assert str(info.value).count(info.value.member_name) == 1


# The terminal memo is sound only because every lookup is node-local. These shapes
# reuse the memo from a second starting member, which the straight chains above never do.


def _tar(path: Path, entries: list[tuple[str, str, str | None]]) -> Path:
    """``entries`` are ``(name, kind, target)``; kind is "file", "dir", "sym" or "hard"."""
    with tarfile.open(path, "w") as tf:
        for name, kind, target in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
                continue
            if kind == "file":
                data = f"payload:{name}".encode()
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
                continue
            info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
            assert target is not None
            info.linkname = target
            tf.addfile(info)
    return path


def _terminal_names(reader: ArchiveReader) -> dict[str, str | None]:
    return {
        m.name: (m.link_target_member.name if m.link_target_member else None)
        for m in reader.members()
        if m.is_link
    }


def test_tail_into_cycle_leaves_every_prefix_unresolved(tmp_path: Path) -> None:
    entries: list[tuple[str, str, str | None]] = [
        ("t0", "sym", "t1"),
        ("t1", "sym", "t2"),
        ("t2", "sym", "c0"),
        ("c0", "sym", "c1"),
        ("c1", "sym", "c0"),
    ]
    with open_archive(_tar(tmp_path / "rho.tar", entries)) as reader:
        assert set(_terminal_names(reader).values()) == {None}
        with pytest.raises(ReadError, match="Link cycle detected"):
            reader.open("t0")


def test_hardlink_chain_resolves_every_hop(tmp_path: Path) -> None:
    entries: list[tuple[str, str, str | None]] = [
        ("f", "file", None),
        ("h1", "hard", "f"),
        ("h2", "hard", "h1"),
        ("h3", "hard", "h2"),
    ]
    with open_archive(_tar(tmp_path / "hard.tar", entries)) as reader:
        assert _terminal_names(reader) == {"h1": "f", "h2": "f", "h3": "f"}
        assert reader.read("h3") == b"payload:f"


def test_converging_chains_share_the_memo(tmp_path: Path) -> None:
    entries: list[tuple[str, str, str | None]] = [
        ("a", "sym", "m"),
        ("b", "sym", "m"),
        ("m", "sym", "end"),
        ("end", "file", None),
    ]
    with open_archive(_tar(tmp_path / "branch.tar", entries)) as reader:
        assert _terminal_names(reader) == {"a": "end", "b": "end", "m": "end"}
        assert reader.read("b") == b"payload:end"


@pytest.mark.parametrize(
    ("order", "finalized", "streamed"),
    [
        pytest.param("x x/ s h", {"s": "x", "h": "x/"}, None, id="file-first"),
        pytest.param("x/ x s h", {"s": "x", "h": "x"}, None, id="dir-first"),
        pytest.param(
            "x/ s h x", {"s": "x", "h": "x/"}, {"s": "x/", "h": "x/"}, id="file-last"
        ),
    ],
)
def test_link_target_tie_break_between_file_and_directory(
    tmp_path: Path,
    order: str,
    finalized: dict[str, str],
    streamed: dict[str, str] | None,
) -> None:
    """A target ``x`` names both a file ``x`` and a directory ``x/``.

    A symlink prefers the bare name whatever the order; a hard link takes the later
    of the two listed before it. A link yielded by a streaming pass sees only the
    members before it (``streamed`` defaults to ``finalized``).

    Mutant: give hard links the symlink rule (bare spelling first) and the hard link
    in the file-first case resolves to ``x`` instead of ``x/``.
    """
    kinds: dict[str, tuple[str, str | None]] = {
        "x": ("file", None),
        "x/": ("dir", None),
        "s": ("sym", "x"),
        "h": ("hard", "x"),
    }
    entries = [(name, *kinds[name]) for name in order.split()]
    path = _tar(tmp_path / "tie.tar", entries)
    with open_archive(path) as reader:
        assert _terminal_names(reader) == finalized
    with open_archive(path, streaming=True) as reader:
        yielded = {
            m.name: (m.link_target_member.name if m.link_target_member else None)
            for m, _stream in reader.stream_members()
            if m.is_link
        }
        assert yielded == (streamed or finalized)


@pytest.mark.parametrize("seed", range(20))
def test_memoized_terminals_match_a_fresh_walk_per_member(
    tmp_path: Path, seed: int
) -> None:
    """Random link graphs: the memo must agree with an independent walk per member."""
    rng = random.Random(seed)
    names = [f"n{i}" for i in range(40)]
    entries: list[tuple[str, str, str | None]] = []
    for i, name in enumerate(names):
        roll = rng.random()
        if roll < 0.2:
            entries.append((name, "file", None))
        elif roll < 0.35 and i > 0:
            entries.append((name, "hard", rng.choice(names[:i])))
        else:
            # Includes names that do not exist (dead ends) and forward references.
            entries.append((name, "sym", rng.choice([*names, "missing"])))
    with open_archive(_tar(tmp_path / f"g{seed}.tar", entries)) as reader:
        assert isinstance(reader, BaseArchiveReader)
        members = reader.members()
        # Published, so _resolve_link below reads the complete name index.
        assert reader._materialized is not None
        for member in members:
            if not (member.is_link and member.link_target):
                continue
            fresh = ArchiveMember(
                name=member.name, type=member.type, link_target=member.link_target
            )
            fresh._member_id = member._member_id
            fresh._archive_id = member._archive_id
            reader._resolve_link(fresh, {})
            assert member.link_target_member is fresh.link_target_member, member.name


def _unreachable_but_alive(obj: object) -> None:
    """Leave ``obj`` reachable only through a reference cycle, so reference counting
    never frees it and only a collection does: a dropped object caught in a cycle on
    CPython, and every dropped object on PyPy."""
    cycle: list[object] = [obj]
    cycle.append(cycle)


@pytest.fixture
def collector_paused() -> Iterator[None]:
    """Pause the cycle collector, so that only the refusal path collects.

    The two "dropped ... is collected" tests that use it fail on CPython if the retry
    is limited to interpreters without reference counting."""
    import gc

    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


@pytest.mark.usefixtures("collector_paused")
def test_a_dropped_pass_is_collected_before_a_new_one_is_refused(
    tmp_path: Path,
) -> None:
    with open_archive(_zip_with_files(tmp_path), streaming=True) as reader:
        passing = iter(reader)
        next(passing)
        _unreachable_but_alive(passing)
        del passing
        assert len(reader.members_report().members) == 2


@pytest.mark.usefixtures("collector_paused")
def test_a_dropped_member_stream_is_collected_before_a_new_open_is_refused(
    tmp_path: Path,
) -> None:
    with open_archive(_zip_with_files(tmp_path)) as reader:
        first, second = reader.members()
        stream = reader.open(first)
        _unreachable_but_alive(stream)
        del stream
        with reader.open(second) as again:
            assert again.read()


@pytest.mark.usefixtures("collector_paused")
def test_a_pass_still_held_is_refused_after_the_collection(tmp_path: Path) -> None:
    with open_archive(_zip_with_files(tmp_path), streaming=True) as reader:
        passing = iter(reader)
        next(passing)
        with pytest.raises(ArchiveyUsageError, match="already active"):
            next(iter(reader))
        passing.close()


def test_an_overlap_refusal_is_a_plain_usage_error(tmp_path: Path) -> None:
    # The docs and the error-handling spec promise ArchiveyUsageError itself for an
    # overlap; the mark that lets a collection retry it stays off the type.
    with open_archive(_zip_with_files(tmp_path)) as reader:
        first, second = reader.members()
        with reader.open(first), pytest.raises(ArchiveyUsageError) as excinfo:
            reader.open(second)
    assert type(excinfo.value) is ArchiveyUsageError


def test_a_closed_reader_is_refused_without_a_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Only an overlap can be a dropped pass or stream; a closed reader cannot, so
    # its refusal must not pay for a collection first.
    import gc

    collections: list[int] = []
    monkeypatch.setattr(gc, "collect", lambda *a: collections.append(1) or 0)
    state = _state()
    assert state.mark_reader_closed()
    for attempt in (
        lambda: state.acquire_pass("stream_members"),
        lambda: state.acquire_worker("open"),
        state.reserve_live_stream,
    ):
        with pytest.raises(ArchiveyUsageError, match="has been closed"):
            attempt()
    assert collections == []


def test_closing_a_stream_members_pass_closes_the_backend_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The backend's pass can hold a process (unrar for a solid RAR). Closing the
    # caller's pass closes it at once, even while something else still refers to it,
    # which is every dropped object until a collection on PyPy.
    with open_archive(_zip_with_files(tmp_path)) as reader:
        backend_passes = []
        real = reader._iter_with_data

        def kept(*args: object, **kwargs: object) -> Iterator[object]:
            source = real(*args, **kwargs)
            backend_passes.append(source)
            return source

        monkeypatch.setattr(reader, "_iter_with_data", kept)
        with contextlib.closing(reader.stream_members()) as passing:
            next(iter(passing))
        (source,) = backend_passes
        assert source.gi_frame is None


def _filter_raising_on(name: str) -> Callable[[ArchiveMember], ArchiveMember]:
    def refuse(member: ArchiveMember) -> ArchiveMember:
        if member.name == name:
            raise RuntimeError(f"filter refused {name}")
        return member

    return refuse


def test_an_error_out_of_extraction_closes_its_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Keeping the pass in a list stands in for PyPy, where a dropped pass stays alive
    # until a collection, and for a caller holding the traceback.
    with open_archive(_zip_with_files(tmp_path)) as reader:
        first = reader.members()[0]
        passes = []
        real = reader._stream_members

        def kept(*args: object, **kwargs: object) -> Iterator[object]:
            source = real(*args, **kwargs)  # type: ignore[arg-type]
            passes.append(source)
            return source

        monkeypatch.setattr(reader, "_stream_members", kept)
        with pytest.raises(RuntimeError, match="filter refused") as excinfo:
            reader.extract_all(tmp_path / "out", filter=_filter_raising_on(first.name))
        assert excinfo.value is not None  # the traceback is still held here
        (source,) = passes
        assert source.gi_frame is None


def _tar_with_orphaned_hardlink(tmp_path: Path) -> Path:
    path = tmp_path / "links.tar"
    with tarfile.open(path, "w") as tf:
        data = b"source data"
        info = tarfile.TarInfo("source.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link.txt")
        link.type = tarfile.LNKTYPE
        link.linkname = "source.txt"
        tf.addfile(link)
    return path


def test_an_error_out_of_the_orphan_pass_closes_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Extracting only the link leaves its source for a second pass over the archive.
    from archivey.internal.extraction import ExtractionCoordinator

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("linking failed")

    monkeypatch.setattr(ExtractionCoordinator, "_link_orphan_group", fail)
    with open_archive(_tar_with_orphaned_hardlink(tmp_path)) as reader:
        passes = []
        real = reader.stream_members

        def kept(*args: object, **kwargs: object) -> object:
            source = real(*args, **kwargs)  # type: ignore[arg-type]
            passes.append(source)
            return source

        monkeypatch.setattr(reader, "stream_members", kept)
        with pytest.raises(RuntimeError, match="linking failed") as excinfo:
            reader.extract_all(tmp_path / "out", members=["link.txt"], policy="trusted")
        assert excinfo.value is not None  # the traceback is still held here
        (orphan_pass,) = passes
        assert orphan_pass._pass.gi_frame is None


def test_a_failed_pass_close_does_not_hide_the_extraction_error() -> None:
    from archivey.internal.extraction import _closing_pass

    class FailingClose:
        def close(self) -> None:
            raise OSError("close failed")

    with (
        pytest.raises(RuntimeError, match="body failed") as excinfo,
        _closing_pass(FailingClose()),
    ):
        raise RuntimeError("body failed")
    assert any("close failed" in note for note in excinfo.value.__notes__)
    with pytest.raises(OSError, match="close failed"), _closing_pass(FailingClose()):
        pass
