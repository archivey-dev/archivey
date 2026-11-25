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


_HOOKS = _Hooks()


class _GatedStream(io.RawIOBase):
    """A plugin's member stream that records its close and can block a read."""

    def __init__(self, data: bytes, name: str) -> None:
        self._data = io.BytesIO(data)
        self._name = name

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        if _HOOKS.block_read:
            _HOOKS.block_read = False
            _HOOKS.entered.set()
            assert _HOOKS.go.wait(TIMEOUT)
            _HOOKS.events.append(f"read {self._name} done")
        return self._data.readinto(b)

    def close(self) -> None:
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
        return MemberData(_GatedStream(data, member.name))

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
    thread, _out = _run(lambda: a.read(16))
    assert _HOOKS.entered.wait(TIMEOUT)
    closer, closed = _run(reader.close)
    closer.join(TIMEOUT)
    assert not closer.is_alive(), "close() waited for the blocked read"
    assert closed == [None]
    with pytest.raises(ValueError, match="closed file"):
        b.read(1)
    assert not [e for e in _HOOKS.events if "close" in e]
    _HOOKS.go.set()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    after = _HOOKS.events[_HOOKS.events.index("read b.bin done") :]
    closes = [e for e in after if "close" in e]
    assert sorted(closes[:2]) == ["stream close b.bin", "stream close docs/a.txt"]
    assert closes[2:] == ["plugin close"]
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
    thread, _out = _run(lambda: stream.read(1))
    assert _HOOKS.entered.wait(TIMEOUT)
    closer, closed = _run(reader.close)
    closer.join(TIMEOUT)
    assert not closer.is_alive(), "close() waited for the blocked read"
    assert closed == [None]
    assert not [e for e in _HOOKS.events if "close" in e]
    _HOOKS.go.set()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    closes = [e for e in _HOOKS.events if "close" in e]
    assert closes == [f"stream close {member.name}", "plugin close"]
    passes.close()
    assert [e for e in _HOOKS.events if "close" in e] == closes
