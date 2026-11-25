"""close() defers what a running call still uses: the backend and the source stay
open, and nothing closes under a call, until the last call out (design: openspec
concurrency-cut §3, "Entry points" and "Member streams and the shared handle").

Each test runs the blocking call on a worker thread, gated on an event, and joins it
with a timeout: a deadlock fails the test instead of hanging the suite.
"""

from __future__ import annotations

import dataclasses
import io
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from archivey import ArchiveMember, ArchiveyConfig, open_archive
from archivey.exceptions import ArchiveyUsageError
from archivey.formats import (
    MemberData,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    register_format,
)
from archivey.internal.format_adapter import registration_scope
from tests.test_format_api import _ENTRIES, TOYA, ToyHandler, ToyReader, build_toya

CLOSED = "after the archive reader has been closed"
TIMEOUT = 10.0


@dataclasses.dataclass
class _Hooks:
    """What the test plugin does, set by each test after open."""

    events: list[str] = dataclasses.field(default_factory=list)
    # Set to make the next ``archive_info()`` signal ``entered`` and wait on ``go``.
    block_info: bool = False
    # Set to make ``open_member()`` read the source first, so ``on_source_read``
    # runs while the plugin method holds the handle lock.
    read_in_open: bool = False
    is_solid: bool = False
    # Set to make the next member-stream ``read()`` signal ``entered`` and wait on
    # ``go``.
    block_read: bool = False
    entered: threading.Event = dataclasses.field(default_factory=threading.Event)
    go: threading.Event = dataclasses.field(default_factory=threading.Event)
    # Set to make the next member-stream ``close()`` signal ``close_entered`` and
    # wait on ``close_go`` before it records itself.
    block_close: bool = False
    close_entered: threading.Event = dataclasses.field(default_factory=threading.Event)
    close_go: threading.Event = dataclasses.field(default_factory=threading.Event)
    # Set to make the next member-stream ``read()`` read the source first, so
    # ``on_source_read`` runs inside the stream's read.
    read_in_read: bool = False


_HOOKS = _Hooks()


class _GatedStream(io.RawIOBase):
    """A plugin's member stream that records its close and can block a read."""

    def __init__(self, data: bytes, name: str, source: ReaderSource) -> None:
        self._data = io.BytesIO(data)
        self._name = name
        self._source = source

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        if _HOOKS.read_in_read:
            _HOOKS.read_in_read = False
            self._source.read_at(0, 1)
        if _HOOKS.block_read:
            _HOOKS.block_read = False
            _HOOKS.entered.set()
            assert _HOOKS.go.wait(TIMEOUT)
            _HOOKS.events.append(f"read {self._name} done")
        return self._data.readinto(b)

    def close(self) -> None:
        if _HOOKS.block_close:
            _HOOKS.block_close = False
            _HOOKS.close_entered.set()
            assert _HOOKS.close_go.wait(TIMEOUT)
        if not self.closed:
            _HOOKS.events.append(f"stream close {self._name}")
        super().close()


class _GatedReader(ToyReader):
    def open_member(
        self, member: ArchiveMember, locator: tuple[int, int]
    ) -> MemberData:
        if _HOOKS.read_in_open:
            self._source.read_at(0, 1)
        offset, size = locator
        data = self._source.read_at(offset, size)
        return MemberData(_GatedStream(data, member.name, self._source))

    def archive_info(self) -> ReaderArchiveInfo:
        if _HOOKS.block_info:
            _HOOKS.block_info = False
            _HOOKS.entered.set()
            assert _HOOKS.go.wait(TIMEOUT)
        _HOOKS.events.append("archive_info")
        return ReaderArchiveInfo(format_version="1", is_solid=_HOOKS.is_solid)

    def close(self) -> None:
        _HOOKS.events.append("plugin close")


class _GatedHandler(ToyHandler):
    def open(self, source: ReaderSource, context: ReaderContext) -> _GatedReader:
        return _GatedReader(source, context)


@pytest.fixture
def gated(tmp_path: Path) -> Iterator[Path]:
    global _HOOKS
    _HOOKS = _Hooks()
    path = tmp_path / "t.toya"
    path.write_bytes(build_toya(_ENTRIES))
    with registration_scope():
        register_format(_GatedHandler)
        yield path


def _run(fn: Callable[[], object]) -> tuple[threading.Thread, list[object]]:
    out: list[object] = []

    def body() -> None:
        try:
            out.append(fn())
        except BaseException as exc:  # noqa: BLE001 - the test inspects it
            out.append(exc)

    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    return thread, out


@pytest.mark.parametrize("concurrent", [False, True])
def test_close_waits_out_a_running_info_before_teardown(
    gated: Path, concurrent: bool
) -> None:
    """A live ``info`` holds teardown back: ``close()`` returns at once, the plugin is
    not closed under ``archive_info()``, and the call raises the closed error."""
    reader = open_archive(gated, concurrent_operations=concurrent)
    assert reader.format == TOYA
    _HOOKS.block_info = True
    thread, out = _run(lambda: reader.info)
    assert _HOOKS.entered.wait(TIMEOUT)
    closer, closed = _run(reader.close)
    closer.join(TIMEOUT)
    assert not closer.is_alive(), "close() waited for the running info"
    assert closed == [None]
    assert "plugin close" not in _HOOKS.events
    _HOOKS.go.set()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    assert isinstance(out[0], ArchiveyUsageError), out
    assert CLOSED in str(out[0])
    assert _HOOKS.events[-2:] == ["archive_info", "plugin close"]


@pytest.mark.parametrize("concurrent", [False, True])
def test_info_from_a_callback_under_open_member_does_not_deadlock(
    gated: Path, concurrent: bool
) -> None:
    """``on_source_read`` runs inside ``open_member()``, which holds the plugin's
    handle lock; ``info`` there answers the snapshot and never calls the plugin."""
    seen: list[object] = []
    holder: list[object] = []

    def on_read(_progress: object) -> None:
        if _HOOKS.read_in_open and holder:
            seen.append(holder[0].info)  # type: ignore[attr-defined]

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    with open_archive(gated, config=config, concurrent_operations=concurrent) as reader:
        holder.append(reader)
        reader.members()  # the listing asks archive_info() for the comment
        live = reader.info
        calls = _HOOKS.events.count("archive_info")
        _HOOKS.read_in_open = True
        thread, out = _run(lambda: reader.read("docs/a.txt"))
        thread.join(TIMEOUT)
        assert not thread.is_alive(), "info in the callback deadlocked"
        assert out == [b"alpha\n"]
        assert seen
        assert all(info == live for info in seen)
        assert _HOOKS.events.count("archive_info") == calls


def test_cost_follows_the_published_info(gated: Path) -> None:
    """``cost`` is the published ``info``'s: it never calls the plugin, and a live
    ``info`` that learns more republishes both."""
    with open_archive(gated) as reader:
        first = reader.info
        calls = _HOOKS.events.count("archive_info")
        assert reader.cost == first.cost
        assert _HOOKS.events.count("archive_info") == calls
        _HOOKS.is_solid = True
        second = reader.info
        assert second.cost != first.cost
        assert reader.cost == second.cost


def test_close_from_a_callback_under_open_member_leaves_an_idle_sibling(
    gated: Path,
) -> None:
    """Under the flag, a plugin's streams share its handle lock. A ``close()`` from
    a callback inside ``open_member()`` (which holds that lock) must not close an idle
    sibling stream there: the sibling's close would wait for the lock this thread
    holds. The sibling is closed by the last call out, inner streams first."""
    holder: list[object] = []

    def on_read(_progress: object) -> None:
        if _HOOKS.read_in_open:
            _HOOKS.read_in_open = False
            holder[0].close()  # type: ignore[attr-defined]

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    reader = open_archive(gated, config=config, concurrent_operations=True)
    holder.append(reader)
    idle = reader.open("b.bin")
    assert idle.read(1) == b"\x00"
    _HOOKS.read_in_open = True
    thread, out = _run(lambda: reader.read("docs/a.txt"))
    thread.join(TIMEOUT)
    assert not thread.is_alive(), "close() from the callback deadlocked"
    assert isinstance(out[0], ArchiveyUsageError), out
    assert CLOSED in str(out[0])
    with pytest.raises(ValueError, match="closed file"):
        idle.read(1)
    closes = [e for e in _HOOKS.events if "close" in e]
    assert closes.count("stream close b.bin") == 1
    assert closes[-1] == "plugin close"


def test_close_beside_a_blocked_read_defers_every_close(gated: Path) -> None:
    """Stream A blocked in ``read()``, stream B idle: ``close()`` returns at once,
    B's reads raise ``ValueError``, and nothing (no inner stream, not the plugin) is
    closed until A's read returns; then all close once, inner streams first."""
    reader = open_archive(gated, concurrent_operations=True)
    a = reader.open("b.bin")
    b = reader.open("docs/a.txt")
    _HOOKS.block_read = True
    thread, out = _run(lambda: a.read(16))
    assert _HOOKS.entered.wait(TIMEOUT)
    closer, closed = _run(reader.close)
    closer.join(TIMEOUT)
    assert not closer.is_alive(), "close() waited for the blocked read"
    assert closed == [None]
    # Closed to the caller at once, though its inner close waits for A's read.
    assert b.closed
    with pytest.raises(ValueError, match="closed file"):
        b.read(1)
    b.close()
    assert b.closed
    assert not [e for e in _HOOKS.events if "close" in e]
    _HOOKS.go.set()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    after = _HOOKS.events[_HOOKS.events.index("read b.bin done") :]
    closes = [e for e in after if "close" in e]
    assert sorted(closes[:2]) == ["stream close b.bin", "stream close docs/a.txt"]
    assert closes[2:] == ["plugin close"]
    # The read was running when close() came: it stops before it returns its bytes,
    # with the closed-file error a stream raises once closed.
    assert isinstance(out[0], ValueError), out
    assert "closed file" in str(out[0])
    with pytest.raises(ValueError, match="closed file"):
        a.read(1)


@pytest.mark.parametrize("concurrent", [False, True])
def test_close_beside_a_blocked_yielded_stream_defers_the_wind_down(
    gated: Path, concurrent: bool
) -> None:
    """A ``stream_members()`` pass suspended at its yield while the yielded stream
    blocks in ``read()`` on another thread: ``close()`` returns at once and winds
    nothing down under the read; after it, the stream, then the plugin, close once."""
    reader = open_archive(gated, concurrent_operations=concurrent)
    passes = reader.stream_members()
    member, stream = next(passes)
    while stream is None:
        member, stream = next(passes)
    _HOOKS.block_read = True
    thread, out = _run(lambda: stream.read(1))
    assert _HOOKS.entered.wait(TIMEOUT)
    closer, closed = _run(reader.close)
    closer.join(TIMEOUT)
    assert not closer.is_alive(), "close() waited for the blocked read"
    assert closed == [None]
    assert not [e for e in _HOOKS.events if "close" in e]
    # Dropping the pass while the read still runs closes nothing under it either: the
    # wind-down stays with the last call out.
    dropper, dropped = _run(passes.close)
    dropper.join(TIMEOUT)
    assert not dropper.is_alive(), "closing the pass waited for the blocked read"
    assert dropped == [None]
    assert not [e for e in _HOOKS.events if "close" in e]
    _HOOKS.go.set()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    assert isinstance(out[0], ArchiveyUsageError), out
    closes = [e for e in _HOOKS.events if "close" in e]
    assert closes == [f"stream close {member.name}", "plugin close"]


@pytest.mark.parametrize("concurrent", [False, True])
def test_info_from_a_callback_with_nothing_published_does_not_deadlock(
    tmp_path: Path, concurrent: bool
) -> None:
    """A plugin whose ``archive_info()`` failed at open has no snapshot. ``info``
    from a callback under ``open_member()`` (which holds the handle lock) then raises
    that failure again instead of calling the plugin and waiting on the lock, in both
    modes: without the flag there is no lock, but the callback may still run inside
    a plugin method."""

    class _FailsAtOpen(_GatedReader):
        calls = 0

        def archive_info(self) -> ReaderArchiveInfo:
            type(self).calls += 1
            if type(self).calls == 1:
                raise OSError("archive_info failed at open")
            return super().archive_info()

    class _Handler(ToyHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> _FailsAtOpen:
            return _FailsAtOpen(source, context)

    global _HOOKS
    _HOOKS = _Hooks()
    path = tmp_path / "t.toya"
    path.write_bytes(build_toya(_ENTRIES))
    seen: list[BaseException] = []
    holder: list[object] = []

    def on_read(_progress: object) -> None:
        if _HOOKS.read_in_open and holder:
            _HOOKS.read_in_open = False
            try:
                holder[0].info  # type: ignore[attr-defined]  # noqa: B018
            except Exception as exc:  # noqa: BLE001 - the test inspects it
                seen.append(exc)

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    with registration_scope():
        register_format(_Handler)
        with open_archive(
            path, config=config, concurrent_operations=concurrent
        ) as reader:
            holder.append(reader)
            reader.members()
            calls = _FailsAtOpen.calls
            _HOOKS.read_in_open = True
            thread, out = _run(lambda: reader.read("docs/a.txt"))
            thread.join(TIMEOUT)
            assert not thread.is_alive(), "info in the callback deadlocked"
            assert out == [b"alpha\n"]
            assert len(seen) == 1
            assert "archive_info failed at open" in str(seen[0])
            assert _FailsAtOpen.calls == calls, "the callback called the plugin"


@pytest.mark.parametrize("concurrent", [False, True])
def test_a_proof_query_after_close_touches_nothing_under_the_shutdown(
    gated: Path, concurrent: bool
) -> None:
    """While the shutdown is closing a stream's inner, ``verified`` and
    ``verifiable`` on that stream answer what its member stored: they refresh no
    reader state and ask the inner nothing."""
    reader = open_archive(gated, concurrent_operations=concurrent)
    stream = reader.open("b.bin")
    stream.read(1)
    refreshes: list[str] = []
    real_refresh = stream._level_refresh  # type: ignore[attr-defined]

    def refresh() -> None:
        if _HOOKS.close_entered.is_set():
            refreshes.append(threading.current_thread().name)
        real_refresh()

    stream._level_refresh = refresh  # type: ignore[attr-defined]
    _HOOKS.block_close = True
    closer, closed = _run(reader.close)
    assert _HOOKS.close_entered.wait(TIMEOUT)
    member = stream._level_member  # type: ignore[attr-defined]
    assert stream.verified == member.verified
    assert stream.verifiable == member.verifiable
    assert refreshes == []
    _HOOKS.close_go.set()
    closer.join(TIMEOUT)
    assert not closer.is_alive()
    assert closed == [None]


@pytest.mark.parametrize("concurrent", [False, True])
def test_reader_close_beside_a_blocked_stream_close_closes_it_once(
    gated: Path, concurrent: bool
) -> None:
    """A stream's own ``close()`` blocked in the plugin's cleanup is a running
    call: ``reader.close()`` returns at once, closes nothing under it, and the plugin
    is closed after the stream's close returns, each once."""
    reader = open_archive(gated, concurrent_operations=concurrent)
    stream = reader.open("b.bin")
    _HOOKS.block_close = True
    stream_closer, stream_closed = _run(stream.close)
    assert _HOOKS.close_entered.wait(TIMEOUT)
    closer, closed = _run(reader.close)
    closer.join(TIMEOUT)
    assert not closer.is_alive(), "reader close waited for the stream close"
    assert closed == [None]
    assert not [e for e in _HOOKS.events if "close" in e]
    _HOOKS.close_go.set()
    stream_closer.join(TIMEOUT)
    assert not stream_closer.is_alive()
    assert stream_closed == [None]
    assert [e for e in _HOOKS.events if "close" in e] == [
        "stream close b.bin",
        "plugin close",
    ]


@pytest.mark.parametrize("concurrent", [False, True])
@pytest.mark.parametrize("which", ["same", "sibling"])
def test_a_stream_close_from_a_callback_inside_a_read_raises(
    gated: Path, concurrent: bool, which: str
) -> None:
    """A member stream's ``close()`` from a callback that runs inside a read (of
    that stream, or of a sibling, which may hold the shared handle lock) raises
    ``ArchiveyUsageError``; the read completes and the stream stays usable."""
    if which == "sibling" and not concurrent:
        pytest.skip("one open stream at a time without the flag")
    seen: list[BaseException] = []
    targets: list[object] = []

    def on_read(_progress: object) -> None:
        if targets:
            target = targets.pop()
            try:
                target.close()  # type: ignore[attr-defined]
            except BaseException as exc:  # noqa: BLE001 - the test inspects it
                seen.append(exc)

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    with open_archive(gated, config=config, concurrent_operations=concurrent) as reader:
        a = reader.open("b.bin")
        b = reader.open("docs/a.txt") if which == "sibling" else a
        targets.append(b)
        _HOOKS.read_in_read = True
        thread, out = _run(lambda: a.read(1))
        thread.join(TIMEOUT)
        assert not thread.is_alive(), "the close in the callback deadlocked"
        assert out == [b"\x00"]
        assert len(seen) == 1, seen
        assert isinstance(seen[0], ArchiveyUsageError), seen
        assert not b.closed
        assert b.read(1)


def test_a_stream_close_from_a_callback_inside_open_raises(gated: Path) -> None:
    """A sibling stream's ``close()`` from a callback inside ``open()``, whose
    ``open_member()`` holds the plugin's handle lock under the flag, raises
    ``ArchiveyUsageError`` instead of waiting on that lock; the open completes and
    the sibling stays usable."""
    seen: list[BaseException] = []
    targets: list[object] = []

    def on_read(_progress: object) -> None:
        if _HOOKS.read_in_open and targets:
            target = targets.pop()
            try:
                target.close()  # type: ignore[attr-defined]
            except BaseException as exc:  # noqa: BLE001 - the test inspects it
                seen.append(exc)

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    with open_archive(gated, config=config, concurrent_operations=True) as reader:
        idle = reader.open("b.bin")
        targets.append(idle)
        _HOOKS.read_in_open = True
        thread, out = _run(lambda: reader.open("docs/a.txt"))
        thread.join(TIMEOUT)
        assert not thread.is_alive(), "the close in the callback deadlocked"
        assert len(seen) == 1 and isinstance(seen[0], ArchiveyUsageError), seen
        assert not idle.closed
        assert idle.read(1) == b"\x00"
        out[0].close()  # type: ignore[attr-defined]


@pytest.mark.parametrize("concurrent", [False, True])
def test_reader_read_overtaken_after_its_open_raises_the_closed_error(
    gated: Path, concurrent: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``reader.read()`` whose reader closes between its ``open()`` and its read
    raises the reader's closed error naming ``read()``, not the stream's
    closed-file ``ValueError``."""
    reader = open_archive(gated, concurrent_operations=concurrent)
    real_open = reader.open

    def open_then_close(member: object) -> object:
        stream = real_open(member)  # type: ignore[arg-type]
        reader.close()
        return stream

    monkeypatch.setattr(reader, "open", open_then_close)
    with pytest.raises(ArchiveyUsageError, match=r"read\(\) is not available"):
        reader.read("docs/a.txt")


def test_a_stream_dropped_after_close_beside_a_running_read_closes_nothing(
    gated: Path,
) -> None:
    """``reader.close()`` keeps the streams it defers alive until its shutdown
    closes them: an idle stream the caller drops while a sibling's read still runs
    is not closed by the collector beside that read (under the flag its close would
    wait on the handle lock the read holds), and is closed once, after the read."""
    import gc

    reader = open_archive(gated, concurrent_operations=True)
    a = reader.open("b.bin")
    held = [reader.open("docs/a.txt")]
    _HOOKS.block_read = True
    thread, _out = _run(lambda: a.read(1))
    assert _HOOKS.entered.wait(TIMEOUT)
    reader.close()

    def drop() -> None:
        held.clear()
        gc.collect()

    dropper, dropped = _run(drop)
    dropper.join(TIMEOUT)
    try:
        assert not dropper.is_alive(), "the collector's close waited for the read"
        assert dropped == [None]
        assert not [e for e in _HOOKS.events if "close" in e]
    finally:
        _HOOKS.go.set()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    closes = [e for e in _HOOKS.events if "close" in e]
    assert sorted(closes[:2]) == ["stream close b.bin", "stream close docs/a.txt"]
    assert closes[2:] == ["plugin close"]


@pytest.mark.parametrize("concurrent", [False, True])
def test_reader_read_keeps_a_callbacks_own_value_error(
    gated: Path, concurrent: bool
) -> None:
    """A callback inside ``reader.read()`` that closes the reader and then raises
    its own ``ValueError``: that same exception escapes, not the reader's closed
    error that ``read()`` raises for a stream overtaken by ``close()``."""
    sentinel = ValueError("the caller's own error")
    reader: object = None

    def on_read(_progress: object) -> None:
        if _HOOKS.read_in_read is False and reader is not None:
            reader.close()  # type: ignore[attr-defined]
            raise sentinel

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    reader = open_archive(gated, config=config, concurrent_operations=concurrent)
    _HOOKS.read_in_read = True
    with pytest.raises(ValueError) as info:
        reader.read("docs/a.txt")  # type: ignore[attr-defined]
    assert info.value is sentinel


def test_a_sibling_dropped_inside_a_read_closes_after_the_read(gated: Path) -> None:
    """A callback inside a member-stream read drops the last reference to an idle
    sibling, with the reader still open. Under the flag the read holds the plugin's
    handle lock, which the sibling's inner close also takes: the collector's close
    is queued instead of waiting on that lock, and runs once the read is out."""
    import gc

    held: list[object] = []

    def on_read(_progress: object) -> None:
        if held:
            held.clear()
            gc.collect()
            _HOOKS.events.append("dropped")

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    with open_archive(gated, config=config, concurrent_operations=True) as reader:
        a = reader.open("b.bin")
        held.append(reader.open("docs/a.txt"))
        _HOOKS.read_in_read = True
        thread, out = _run(lambda: a.read(1))
        thread.join(TIMEOUT)
        assert not thread.is_alive(), "the collector's close waited on the read"
        assert out == [b"\x00"]
        assert [e for e in _HOOKS.events if e != "archive_info"] == [
            "dropped",
            "stream close docs/a.txt",
        ]
        assert a.read(1)
        a.close()
    assert [e for e in _HOOKS.events if "close" in e] == [
        "stream close docs/a.txt",
        "stream close b.bin",
        "plugin close",
    ]


def test_a_sibling_dropped_inside_a_read_then_reader_closed_closes_once(
    gated: Path,
) -> None:
    """The callback drops the sibling and then closes the reader: the queued close
    is left to the reader's shutdown, which closes the sibling once, after the read
    and before the plugin."""
    import gc

    held: list[object] = []
    reader: object = None

    def on_read(_progress: object) -> None:
        if held:
            held.clear()
            gc.collect()
            reader.close()  # type: ignore[attr-defined]

    config = ArchiveyConfig(on_source_read=on_read, source_read_step=0)
    reader = open_archive(gated, config=config, concurrent_operations=True)
    a = reader.open("b.bin")  # type: ignore[attr-defined]
    held.append(reader.open("docs/a.txt"))  # type: ignore[attr-defined]
    _HOOKS.read_in_read = True
    thread, out = _run(lambda: a.read(1))
    thread.join(TIMEOUT)
    assert not thread.is_alive(), "the collector's close waited on the read"
    assert len(out) == 1 and isinstance(out[0], ValueError), out
    closes = [e for e in _HOOKS.events if "close" in e]
    assert sorted(closes[:2]) == ["stream close b.bin", "stream close docs/a.txt"]
    assert closes[2:] == ["plugin close"]
