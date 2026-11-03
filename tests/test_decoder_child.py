"""The decoder child pool: reuse, blame, re-run in a fresh child, recycling, deaths.

Most tests run a stand-in worker: ``decoder_worker.py`` loaded by path with extra
codecs added to its ``LOADERS``, so the real frame and serve loop answer.
"""

from __future__ import annotations

import os
import signal
import sys
import textwrap
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    ReadError,
    ResourceUnavailableError,
)
from archivey.internal.streams.codecs import decoder_child, decoder_worker
from archivey.internal.streams.codecs.decoder_child import POOL, DecoderChild
from archivey.internal.streams.codecs.isolated import ISOLATED

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in workers signal themselves"
)

# Codecs the stand-in worker adds:
# - "poison": a decoder whose ``decompress`` returns its input and marks the process
#   damaged, without crashing;
# - "zlib": the real one, except that in a damaged process its ``decompress`` crashes;
# - "liar": returns its input, except that in a damaged process its first call returns
#   it reversed and its second crashes;
# - "die": a decoder whose ``decompress`` ends the process with the signal its argument
#   names;
# - "intflags": a decoder whose ``eof`` and ``needs_input`` are the ints 1 and 0, as
#   PyPy reads a C ``bool`` member.
_STAND_IN = textwrap.dedent(
    """
    import importlib.util, os, signal, sys

    spec = importlib.util.spec_from_file_location("decoder_worker", {worker!r})
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    damaged = []

    class Poison:
        eof = False
        needs_input = True
        def decompress(self, data, max_length=-1):
            damaged.append(True)
            return data

    class Die:
        def __init__(self, signum):
            self.signum = signum
        def decompress(self, data, max_length=-1):
            os.kill(os.getpid(), self.signum)

    class Liar:
        calls = 0
        def decompress(self, data, max_length=-1):
            self.calls += 1
            if not damaged:
                return data
            if self.calls == 1:
                return data[::-1]
            os.kill(os.getpid(), signal.SIGSEGV)

    real_zlib = worker.LOADERS["zlib"]

    def load_zlib():
        build = real_zlib()
        def make(*args, **kwargs):
            decoder = build(*args, **kwargs)
            if not damaged:
                return decoder
            class Crashing:
                eof = False
                needs_input = True
                def decompress(self, data, max_length=0):
                    os.kill(os.getpid(), signal.SIGSEGV)
            return Crashing()
        return make

    class IntFlags:
        eof = 1
        needs_input = 0
        def decompress(self, data, max_length=-1):
            return b""

    worker.LOADERS["poison"] = lambda: Poison
    worker.LOADERS["die"] = lambda: Die
    worker.LOADERS["liar"] = lambda: Liar
    worker.LOADERS["intflags"] = lambda: IntFlags
    worker.LOADERS["zlib"] = load_zlib
    worker.main()
    """
)


@pytest.fixture(autouse=True)
def _empty_pool() -> Iterator[None]:
    POOL.close_idle()
    yield
    POOL.close_idle()


@pytest.fixture
def stand_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "stand_in_worker.py"
    script.write_text(_STAND_IN.format(worker=str(decoder_child.WORKER)))
    monkeypatch.setattr(decoder_child, "WORKER", script)
    return script


def _zlib_round_trip(data: bytes) -> bytes:
    decomp = ISOLATED.zlib_decompressobj()
    try:
        out = decomp.decompress(zlib.compress(data))
        assert decomp.eof
        return out
    finally:
        decomp.close()


def test_a_child_is_reused_after_a_clean_finish() -> None:
    first = DecoderChild("zlib")
    first.call("decompress", zlib.compress(b"a"))
    first.close()
    assert POOL.idle_count() == 1
    second = DecoderChild("zlib")
    try:
        assert second.served_before
        assert second.call("decompress", zlib.compress(b"b")) == b"b"
    finally:
        second.close()


def test_a_child_is_not_reused_after_an_error() -> None:
    child = DecoderChild("zlib", known={("zlib", "error"): zlib.error})
    with pytest.raises(zlib.error):
        child.call("decompress", b"not zlib data")
    child.close()
    assert POOL.idle_count() == 0


def _interrupt_on_write(
    monkeypatch: pytest.MonkeyPatch, process: decoder_child._Process, nth: int
) -> None:
    """Make the ``nth`` write (from 0) to the child write 100 bytes, then raise
    ``KeyboardInterrupt``, as a Ctrl-C part-way through a blocking pipe write does."""
    stdin = process.proc.stdin
    assert stdin is not None
    seen: list[int] = []
    real_write = stdin.write

    def write(data: bytes) -> int:
        if len(seen) == nth:
            real_write(bytes(data[:100]))
            stdin.flush()
            raise KeyboardInterrupt
        seen.append(len(data))
        return real_write(data)

    monkeypatch.setattr(stdin, "write", write)


def test_a_child_is_not_reused_after_an_interrupted_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = DecoderChild("zlib")
    process = child._lease.process
    assert process is not None
    # A ``decompress`` request is three writes: the frame header, the marshalled
    # call, then the input. The third is cut after 100 of its 65536 bytes.
    _interrupt_on_write(monkeypatch, process, 2)
    with pytest.raises(KeyboardInterrupt):
        child.call("decompress", os.urandom(1 << 16))
    monkeypatch.undo()
    # Back in the pool, the child would read the next decoder's frames as the rest
    # of the input and never reply.
    assert not child._lease.reusable
    with pytest.raises(ArchiveyUsageError, match="interrupted in the middle of a"):
        child.call("decompress", b"")
    child.close()
    assert POOL.idle_count() == 0
    assert _zlib_round_trip(b"after") == b"after"


def test_a_child_is_not_reused_after_an_interrupted_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = DecoderChild("zlib")
    process = child._lease.process
    assert process is not None
    stdout = process.proc.stdout
    assert stdout is not None

    def interrupted_read(size: int = -1) -> bytes:
        raise KeyboardInterrupt

    monkeypatch.setattr(stdout, "read", interrupted_read)
    with pytest.raises(KeyboardInterrupt):
        child.call("decompress", zlib.compress(b"reply"))
    monkeypatch.undo()
    # The reply is still in the pipe: the next read would take it for a header.
    assert not child._lease.reusable
    with pytest.raises(ArchiveyUsageError, match="interrupted in the middle of a"):
        child.call("decompress", b"")
    child.close()
    assert POOL.idle_count() == 0
    assert _zlib_round_trip(b"after") == b"after"


def test_an_interrupted_close_frame_ends_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = DecoderChild("zlib")
    child.call("decompress", zlib.compress(b"a"))
    process = child._lease.process
    assert process is not None
    _interrupt_on_write(monkeypatch, process, 0)
    # The pool's CLOSE frame is the write that is cut. No lease holds the child after
    # that, so a child left running here would never be ended.
    with pytest.raises(KeyboardInterrupt):
        child.close()
    monkeypatch.undo()
    assert process.proc.poll() is not None
    assert POOL.idle_count() == 0


def test_member_b_reads_correctly_after_member_a_damaged_the_child(
    stand_in: Path,
) -> None:
    del stand_in
    a = DecoderChild("poison")
    assert a.call("decompress", b"member A") == b"member A"
    a.close()  # a clean finish: the damaged child goes back to the pool
    assert POOL.idle_count() == 1
    # Member B's decode crashes in the damaged child; it re-runs in a fresh one.
    assert _zlib_round_trip(b"member B" * 100) == b"member B" * 100


def test_a_crash_in_a_fresh_child_is_the_verdict(stand_in: Path) -> None:
    del stand_in
    child = DecoderChild("die", (int(signal.SIGSEGV),))
    assert not child.served_before
    with pytest.raises(CorruptionError, match="crashed"):
        child.call("decompress", b"x")
    with pytest.raises(CorruptionError):
        child.call("decompress", b"x")  # every later call raises it again
    child.close()


def test_a_crash_in_a_reused_child_is_re_run_fresh(stand_in: Path) -> None:
    del stand_in
    first = DecoderChild("zlib")
    first.call("decompress", zlib.compress(b"a"))
    first.close()
    child = DecoderChild("die", (int(signal.SIGSEGV),))
    assert child.served_before
    # The re-run in a fresh child crashes too: only then is it the verdict.
    with pytest.raises(CorruptionError, match="crashed"):
        child.call("decompress", b"x")
    child.close()


def test_an_error_in_a_reused_child_comes_from_the_fresh_re_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = DecoderChild("zlib")
    first.call("decompress", zlib.compress(b"a"))
    first.close()
    spawned: list[object] = []
    real = decoder_child._Process

    def counting() -> decoder_child._Process:
        process = real()
        spawned.append(process)
        return process

    child = DecoderChild("zlib", known={("zlib", "error"): zlib.error})
    assert child.served_before
    monkeypatch.setattr(decoder_child, "_Process", counting)
    try:
        with pytest.raises(zlib.error):
            child.call("decompress", b"not zlib data")
    finally:
        child.close()
    assert len(spawned) == 1


def test_a_re_run_that_disagrees_with_delivered_output_raises(stand_in: Path) -> None:
    del stand_in
    a = DecoderChild("poison")
    a.call("decompress", b"member A")
    a.close()
    b = DecoderChild("liar")
    assert b.served_before
    try:
        assert b.call("decompress", b"abc") == b"cba"  # wrong, and already returned
        with pytest.raises(ReadError, match="does not reproduce"):
            b.call("decompress", b"def")
    finally:
        b.close()
    assert POOL.idle_count() == 0


@pytest.mark.parametrize(
    ("signum", "error"),
    # By name: Windows has no SIGKILL, and collection runs there before the skip.
    [("SIGKILL", ResourceUnavailableError), ("SIGTERM", ReadError)],
)
def test_an_end_from_outside_is_not_a_verdict(
    stand_in: Path, signum: str, error: type[Exception]
) -> None:
    del stand_in
    child = DecoderChild("die", (int(getattr(signal, signum)),))
    with pytest.raises(error) as caught:
        child.call("decompress", b"x")
    assert not isinstance(caught.value, CorruptionError)
    child.close()


def test_a_child_is_ended_after_its_decoder_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decoder_child, "MAX_DECODERS_PER_CHILD", 2)
    pids = []
    for _ in range(4):
        child = DecoderChild("zlib")
        process = child._lease.process
        assert process is not None
        pids.append(process.proc.pid)
        child.call("decompress", zlib.compress(b"a"))
        child.close()
    assert pids[0] == pids[1] != pids[2] == pids[3]


def test_a_long_decoder_moves_to_a_fresh_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decoder_child, "REPLAY_LIMIT", 1000)
    first = DecoderChild("zlib")
    first.call("decompress", zlib.compress(b"a"))
    first.close()
    data = os.urandom(5000)
    packed = zlib.compress(data)
    child = DecoderChild("zlib")
    assert child.served_before
    try:
        out = b"".join(
            child.call("decompress", packed[i : i + 700])
            for i in range(0, len(packed), 700)
        )
        assert not child.served_before  # moved, and blamed directly from now on
        assert out == data
    finally:
        child.close()


def test_threads_get_children_of_their_own() -> None:
    a = DecoderChild("zlib")
    b = DecoderChild("zlib")
    try:
        assert a._lease.process is not b._lease.process
    finally:
        a.close()
        b.close()


def _reused_zlib_child() -> DecoderChild:
    first = DecoderChild("zlib")
    first.call("decompress", zlib.compress(b"a"))
    first.close()
    child = DecoderChild("zlib")
    assert child.served_before
    return child


def test_a_request_past_the_replay_limit_goes_only_to_a_fresh_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request that would take the record past ``REPLAY_LIMIT`` moves first, so it
    is decoded once, never in the reused child and then again in the fresh one."""
    monkeypatch.setattr(decoder_child, "REPLAY_LIMIT", 1000)
    child = _reused_zlib_child()
    reused = child._lease.process
    sent: list[tuple[object, int]] = []
    send = decoder_child._Process.send

    def recording(self: decoder_child._Process, tag: int, arg: int, *parts: bytes):
        sent.append((self, tag))
        return send(self, tag, arg, *parts)

    monkeypatch.setattr(decoder_child._Process, "send", recording)
    data = os.urandom(5000)
    try:
        assert child.call("decompress", zlib.compress(data)) == data
        assert not child.served_before
        calls = [process for process, tag in sent if tag == decoder_child.CALL]
        assert calls == [child._lease.process]
        assert reused not in calls
    finally:
        child.close()


def test_no_fresh_child_part_way_is_the_open_time_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh child that cannot start when the decoder moves part-way raises what
    the same failure raises at open: ``ResourceLimitError`` naming the setting."""
    monkeypatch.setattr(decoder_child, "REPLAY_LIMIT", 1000)
    child = _reused_zlib_child()

    def refuse() -> decoder_child._Process:
        raise decoder_child.start_error("fake: no process available")

    monkeypatch.setattr(decoder_child, "_Process", refuse)
    try:
        for _ in range(2):  # and again on the next call
            with pytest.raises(ResourceUnavailableError, match="process_isolation"):
                child.call("decompress", zlib.compress(os.urandom(5000)))
    finally:
        child.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_process_leaves_its_parents_leased_child_alone() -> None:
    """A process created by ``fork`` that inherits an open decoder neither closes its
    parent's decoder by dropping it nor writes to the parent's pipe by using it."""
    data = os.urandom(20_000)
    packed = zlib.compress(data)
    decomp = ISOLATED.zlib_decompressobj()
    try:
        first = decomp.decompress(packed[:1000])
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - runs in the forked process
            status = b"?"
            try:
                try:
                    decomp.decompress(packed[1000:2000])
                    status = b"read"
                except Exception as exc:  # noqa: BLE001 - reported to the parent
                    status = type(exc).__name__.encode()
                decomp.close()
            finally:
                os.write(write_fd, status)
                os._exit(0)
        os.close(write_fd)
        os.waitpid(pid, 0)
        assert os.read(read_fd, 100) == b"ArchiveyUsageError"
        os.close(read_fd)
        assert first + decomp.decompress(packed[1000:]) == data
    finally:
        decomp.close()


def test_a_closed_decoder_refuses_a_call_past_the_replay_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The move to a fresh child comes after the usability check, so a closed decoder
    raises rather than taking a child nothing would give back."""
    monkeypatch.setattr(decoder_child, "REPLAY_LIMIT", 1000)
    child = _reused_zlib_child()
    child.call("decompress", b"")  # leaves a record behind, as a read part-way does
    child.close()
    idle = POOL.idle_count()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        child.call("decompress", zlib.compress(os.urandom(5000)))
    assert child._lease.process is None
    assert POOL.idle_count() == idle


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_process_cannot_move_its_parents_decoder_to_a_child_of_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request past the replay limit in the fork raises like any other call there,
    instead of replaying into a fresh child the fork started."""
    monkeypatch.setattr(decoder_child, "REPLAY_LIMIT", 1000)
    child = _reused_zlib_child()
    data = os.urandom(20_000)
    packed = zlib.compress(data)
    try:
        first = child.call("decompress", packed[:500])
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - runs in the forked process
            status = b"?"
            try:
                try:
                    child.call("decompress", packed[500:5000])
                    status = b"read"
                except Exception as exc:  # noqa: BLE001 - reported to the parent
                    status = type(exc).__name__.encode()
            finally:
                os.write(write_fd, status)
                os._exit(0)
        os.close(write_fd)
        os.waitpid(pid, 0)
        assert os.read(read_fd, 100) == b"ArchiveyUsageError"
        os.close(read_fd)
        assert first + child.call("decompress", packed[500:]) == data
    finally:
        child.close()


def test_a_flag_read_as_an_int_is_reported_as_a_bool() -> None:
    """Under PyPy, backports.zstd's ``eof`` (a C ``bool`` member) reads as the int 1
    once a frame ends. The state carries an int flag as a bool, 0 as ``False``."""

    class _IntFlags:
        eof = 1
        needs_input = 0

    state = decoder_worker._state("zstd", _IntFlags(), None)
    assert state["eof"] is True
    assert state["needs_input"] is False


def test_an_int_flag_reaches_the_parent_as_a_bool(stand_in: Path) -> None:
    """The same, end to end: the child sends the state and ``flag`` reads it."""
    child = DecoderChild("intflags")
    try:
        child.call("decompress", b"x")
        assert child.flag("eof") is True
        assert child.flag("needs_input") is False
    finally:
        child.close()
