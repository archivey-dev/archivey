"""close() never waits and never refuses: it cancels the calls still running.

A running call stops at its next checkpoint with the closed error, the last call out
tears the archive down, and a teardown failure reaches that call without hiding what
it was already raising (design: openspec concurrency-cut §3).
"""

from __future__ import annotations

import io
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.exceptions import ArchiveyUsageError
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.reader_state import LifecycleState

CLOSED = "after the archive reader has been closed"


def _zip_with_bidi_name() -> bytes:
    """A ZIP whose listing emits a diagnostic (a bidi control in a name)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil\u202etxt.exe", b"x")
        zf.writestr("plain.txt", b"y")
    return buf.getvalue()


def _plain_zip(tmp_path: Path, n: int = 3) -> Path:
    path = tmp_path / "plain.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(n):
            zf.writestr(f"f{i}.txt", f"data {i}".encode())
    return path


def _reader_closing_from_its_callback(
    then: Callable[[], None] | None = None,
) -> BaseArchiveReader:
    """A reader whose first diagnostic callback closes it, then runs ``then``."""
    holder: list[BaseArchiveReader] = []
    fired: list[int] = []

    def on_diagnostic(_diag: object) -> None:
        if fired:
            return
        fired.append(1)
        holder[0].close()
        if then is not None:
            then()

    config = ArchiveyConfig(on_diagnostic=on_diagnostic)
    reader = open_archive(io.BytesIO(_zip_with_bidi_name()), config=config)
    assert isinstance(reader, BaseArchiveReader)
    holder.append(reader)
    return reader


def _failing_teardown(
    reader: BaseArchiveReader, monkeypatch: pytest.MonkeyPatch
) -> list[int]:
    calls: list[int] = []
    real = reader._close_archive

    def close_archive() -> None:
        calls.append(1)
        real()
        raise OSError("teardown failed")

    monkeypatch.setattr(reader, "_close_archive", close_archive)
    return calls


def test_teardown_error_is_the_cause_of_the_closed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader_closing_from_its_callback()
    teardowns = _failing_teardown(reader, monkeypatch)
    with pytest.raises(ArchiveyUsageError, match=CLOSED) as ei:
        reader.members()
    assert isinstance(ei.value.__cause__, OSError)
    assert str(ei.value.__cause__) == "teardown failed"
    assert teardowns == [1]
    assert reader._state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    reader.close()  # a no-op: teardown is not retried
    assert teardowns == [1]


def test_teardown_error_is_a_note_on_another_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The callback closes the reader and then raises its own error: that error
    reaches the caller unchanged, with the teardown failure as a note."""

    def fail() -> None:
        raise RuntimeError("callback failed")

    reader = _reader_closing_from_its_callback(then=fail)
    teardowns = _failing_teardown(reader, monkeypatch)
    with pytest.raises(RuntimeError, match="callback failed") as ei:
        reader.members()
    notes = getattr(ei.value, "__notes__", [])
    assert any("teardown failed" in note for note in notes)
    assert teardowns == [1]


@pytest.mark.parametrize("inside_except", [False, True])
def test_a_call_returning_normally_raises_the_teardown_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inside_except: bool
) -> None:
    """A lookup past its last checkpoint returns its result even if a close came in
    between; when that call is the last out and teardown fails, it raises that. Also
    when the call runs inside the caller's own ``except`` block: the exception that
    block handles is not this call's."""
    reader = open_archive(_plain_zip(tmp_path), concurrent_operations=True)
    assert isinstance(reader, BaseArchiveReader)
    reader.members()
    teardowns = _failing_teardown(reader, monkeypatch)
    inside = threading.Event()
    release = threading.Event()
    real = reader._published_within_limits

    def slow_lookup() -> object:
        published = real()
        if threading.current_thread() is not threading.main_thread():
            inside.set()
            assert release.wait(5)
        return published

    monkeypatch.setattr(reader, "_published_within_limits", slow_lookup)
    outcome: list[object] = []

    def lookup() -> None:
        try:
            if not inside_except:
                outcome.append(reader.get("f0.txt"))
                return
            try:
                raise KeyError("the caller's own")
            except KeyError:
                outcome.append(reader.get("f0.txt"))
        except BaseException as exc:  # noqa: BLE001 - checked below
            outcome.append(exc)

    worker = threading.Thread(target=lookup)
    worker.start()
    assert inside.wait(5)
    reader.close()  # nothing to tear down yet: the lookup is running
    assert teardowns == []
    release.set()
    worker.join(5)
    assert not worker.is_alive()
    (result,) = outcome
    assert isinstance(result, OSError)
    assert str(result) == "teardown failed"
    assert teardowns == [1]


def test_close_after_the_bind_hands_back_a_closed_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bind is open()'s publication point: a close after it closes the
    registered stream like any other, so open() returns a stream already closed."""
    reader = open_archive(_plain_zip(tmp_path))
    assert isinstance(reader, BaseArchiveReader)
    reader.members()
    state = reader._state
    real_bind = state.bind_live_stream

    def bind_then_close(token: object, stream: object) -> None:
        real_bind(token, stream)  # type: ignore[arg-type]
        reader.close()

    monkeypatch.setattr(state, "bind_live_stream", bind_then_close)
    stream = reader.open("f0.txt")
    assert stream.closed
    with pytest.raises(ValueError, match="closed"):
        stream.read()
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


def test_close_before_the_bind_discards_the_new_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = open_archive(_plain_zip(tmp_path))
    assert isinstance(reader, BaseArchiveReader)
    reader.members()
    state = reader._state
    real_bind = state.bind_live_stream
    bound: list[object] = []

    def close_then_bind(token: object, stream: object) -> None:
        bound.append(stream)
        reader.close()
        real_bind(token, stream)  # type: ignore[arg-type]

    monkeypatch.setattr(state, "bind_live_stream", close_then_bind)
    with pytest.raises(ArchiveyUsageError, match=CLOSED):
        reader.open("f0.txt")
    (stream,) = bound
    assert stream.closed  # type: ignore[attr-defined]
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


def test_a_failing_close_of_the_unbound_stream_keeps_the_closed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """open() raises the closed error, not the stream's close failure, which it
    carries as a note."""
    reader = open_archive(_plain_zip(tmp_path))
    assert isinstance(reader, BaseArchiveReader)
    reader.members()
    state = reader._state
    real_bind = state.bind_live_stream

    def close_then_bind(token: object, stream: object) -> None:
        real_close = stream._close_scoped  # type: ignore[attr-defined]

        def failing_close() -> None:
            real_close()
            raise OSError("stream cleanup failed")

        stream._close_scoped = failing_close  # type: ignore[attr-defined]
        reader.close()
        real_bind(token, stream)  # type: ignore[arg-type]

    monkeypatch.setattr(state, "bind_live_stream", close_then_bind)
    with pytest.raises(ArchiveyUsageError, match=CLOSED) as ei:
        reader.open("f0.txt")
    notes = getattr(ei.value, "__notes__", [])
    assert any("stream cleanup failed" in n for n in notes), notes
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


def test_close_from_on_progress_stops_extract_all(tmp_path: Path) -> None:
    """Closing from a progress callback is the supported way to cancel."""
    reader = open_archive(_plain_zip(tmp_path, n=5))
    assert isinstance(reader, BaseArchiveReader)
    seen: list[object] = []

    def on_progress(progress: object) -> None:
        seen.append(progress)
        reader.close()

    with pytest.raises(ArchiveyUsageError, match=CLOSED):
        reader.extract_all(tmp_path / "out", on_progress=on_progress)
    assert seen
    assert reader._state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    written = sorted(p.name for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert len(written) < 5


@pytest.mark.parametrize("concurrent", [False, True])
def test_a_progress_callback_cannot_open_a_member_during_extract_all(
    tmp_path: Path, concurrent: bool
) -> None:
    """A callback is not library-internal: extract_all's own opens are, but an
    open() from its progress callback is re-entry and raises."""
    reader = open_archive(_plain_zip(tmp_path), concurrent_operations=concurrent)
    errors: list[BaseException] = []

    def on_progress(_progress: object) -> None:
        try:
            reader.open("f1.txt").close()
        except ArchiveyUsageError as exc:
            errors.append(exc)

    with reader:
        reader.extract_all(tmp_path / "out", on_progress=on_progress)
    assert errors
    assert all("re-entered" in str(e) for e in errors)


def _zip_with_a_big_stored_member(tmp_path: Path) -> Path:
    path = tmp_path / "big.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", bytes(range(256)) * (4 * 4096 * 4))  # 16 MiB
        zf.writestr("after.txt", b"after")
    return path


def _hold_the_second_read(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[threading.Event, threading.Event, list[int]]:
    """Hold the first worker thread's second member-stream read until released."""
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl

    held = threading.Event()
    release = threading.Event()
    real = ArchiveStreamImpl._ensure_open
    calls: list[int] = []

    def ensure_open(self: ArchiveStreamImpl) -> object:
        if threading.current_thread() is not threading.main_thread():
            calls.append(1)
            if len(calls) == 2:
                held.set()
                assert release.wait(5)
        return real(self)

    monkeypatch.setattr(ArchiveStreamImpl, "_ensure_open", ensure_open)
    return held, release, calls


@pytest.mark.parametrize("call", ["extract_all", "verify_all"])
def test_close_from_another_thread_stops_the_run_within_a_chunk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    """A close() while extract_all() or verify_all() reads a member on another thread
    stops the run at that member's next read: the error names the call, the member
    being written is not placed, and no temp file is left."""
    reader = open_archive(_zip_with_a_big_stored_member(tmp_path))
    assert isinstance(reader, BaseArchiveReader)
    reader.members()
    out = tmp_path / "out"
    held, release, reads = _hold_the_second_read(monkeypatch)
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            if call == "extract_all":
                reader.extract_all(out)
            else:
                reader.verify_all()
        except BaseException as exc:  # noqa: BLE001 - checked below
            outcome.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    assert held.wait(5)
    reader.close()
    release.set()
    worker.join(10)
    assert not worker.is_alive()
    (error,) = outcome
    assert isinstance(error, ArchiveyUsageError)
    assert str(error).startswith(f"{call}()"), error
    # The held read was the last: 16 one-MiB chunks were left, none was read.
    assert len(reads) == 2, len(reads)
    assert reader._state.lifecycle is LifecycleState.TEARDOWN_COMPLETE
    if call == "extract_all":
        left = sorted(p.name for p in out.rglob("*")) if out.exists() else []
        assert left == [], left  # neither big.bin nor a temp, nor after.txt


def test_a_cancelled_extract_all_names_extract_all(tmp_path: Path) -> None:
    """Closing from on_progress mid-member: the error names extract_all(), not the
    nested pass, and the member is not placed."""
    reader = open_archive(_zip_with_a_big_stored_member(tmp_path))
    out = tmp_path / "out"

    def on_progress(_progress: object) -> None:
        reader.close()

    with pytest.raises(ArchiveyUsageError, match=r"^extract_all\(\)"):
        reader.extract_all(out, on_progress=on_progress)
    left = sorted(p.name for p in out.rglob("*")) if out.exists() else []
    assert left == [], left


@pytest.mark.parametrize("last_out", [False, True])
def test_an_interrupt_while_settling_the_listing_still_releases_the_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, last_out: bool
) -> None:
    """Teardown is claimed once and never retried, so an interrupt in its first step
    (settling the listing) must still run the walk, backend and source releases."""
    from archivey.internal import base_reader as base_reader_module

    reader = open_archive(_plain_zip(tmp_path), concurrent_operations=last_out)
    assert isinstance(reader, BaseArchiveReader)
    reader.members()
    released: list[int] = []
    real_close_archive = reader._close_archive

    def close_archive() -> None:
        released.append(1)
        real_close_archive()

    monkeypatch.setattr(reader, "_close_archive", close_archive)
    real_close_walk = reader._close_walk

    def close_walk() -> None:
        released.append(0)
        real_close_walk()

    monkeypatch.setattr(reader, "_close_walk", close_walk)
    real_settle = base_reader_module._settle_listing

    def interrupted_settle(*args: object, **kwargs: object) -> None:
        monkeypatch.setattr(base_reader_module, "_settle_listing", real_settle)
        raise KeyboardInterrupt

    monkeypatch.setattr(base_reader_module, "_settle_listing", interrupted_settle)
    if not last_out:
        with pytest.raises(KeyboardInterrupt):
            reader.close()
    else:
        # The teardown runs on a running call's way out: close() from its callback.
        inside = threading.Event()
        release = threading.Event()
        real_lookup = reader._published_within_limits
        outcome: list[BaseException | None] = []

        def slow_lookup() -> object:
            published = real_lookup()
            if threading.current_thread() is not threading.main_thread():
                inside.set()
                assert release.wait(5)
            return published

        monkeypatch.setattr(reader, "_published_within_limits", slow_lookup)

        def lookup() -> None:
            try:
                reader.get("f0.txt")
                outcome.append(None)
            except BaseException as exc:  # noqa: BLE001 - checked below
                outcome.append(exc)

        worker = threading.Thread(target=lookup)
        worker.start()
        assert inside.wait(5)
        reader.close()
        release.set()
        worker.join(5)
        assert len(outcome) == 1 and isinstance(outcome[0], KeyboardInterrupt)
    # The walk is closed too, before the backend: its ``finally`` blocks run on an
    # open archive.
    assert released == [0, 1]
    assert reader._state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


def _zip_with_dir_and_symlink(tmp_path: Path) -> Path:
    path = tmp_path / "dirlink.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(zipfile.ZipInfo("adir/"), b"")
        link = zipfile.ZipInfo("alink")
        link.external_attr = (0o120777 << 16) | 0x20
        link.create_system = 3
        zf.writestr(link, b"target.txt")
    return path


@pytest.mark.parametrize("closing_at", ["adir", "alink"])
def test_close_from_the_filter_places_no_directory_or_link(
    tmp_path: Path, closing_at: str
) -> None:
    """A directory or link is placed with no read and no swap; a close() from the
    filter must still stop the call before it reaches the destination."""
    reader = open_archive(_zip_with_dir_and_symlink(tmp_path))
    out = tmp_path / "out"

    def keep(member: object) -> object:
        if getattr(member, "name", "").rstrip("/") == closing_at:
            reader.close()
        return member

    with pytest.raises(ArchiveyUsageError, match=r"^extract_all\(\)"):
        reader.extract_all(out, filter=keep)  # type: ignore[arg-type]
    left = sorted(p.name for p in out.iterdir()) if out.exists() else []
    assert closing_at not in left, left
