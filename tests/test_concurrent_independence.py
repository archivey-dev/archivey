"""Operations on one ``concurrent_operations=True`` reader stay independent of each other.

Under the flag, calls that may overlap do not see each other's effects: what one call
emits, or a close on another thread, does not show up in a different call's result
as something that call did. ``test_concurrent_pass_refusals.py`` covers which calls
may overlap; this file covers what they see of each other.
"""

from __future__ import annotations

import io
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.internal.streams.archive_stream import ArchiveStreamImpl
from tests.test_concurrent_pass_refusals import _in_thread, _run_together

pytestmark = pytest.mark.concurrent_reader


def test_random_stream_diagnostics_are_its_own(tmp_path: Path) -> None:
    """A stream opened on one thread keeps the emits its own reads make, only."""
    path = tmp_path / "names.tar"
    with tarfile.open(path, "w") as tf:
        for name in ("a.txt", ".//b.txt"):
            info = tarfile.TarInfo(name)
            info.size = 3
            tf.addfile(info, io.BytesIO(b"abc"))
    with open_archive(path, concurrent_operations=True) as reader:
        # Opening a.txt walks only as far as a.txt; the walk to .//b.txt, which
        # emits, then happens on another thread while the stream is open.
        with reader.open("a.txt") as stream:
            _in_thread(lambda: reader.read("b.txt"))
            assert stream.read() == b"abc"
            assert stream.diagnostics.total_count == 0
        assert reader.diagnostics.total_count == 1


def test_stream_calls_leave_the_threads_scope_stack_as_they_found_it(
    tmp_path: Path,
) -> None:
    """``read``, ``seek`` and ``close`` take the stream's scope off the thread again.

    A scope left on the stack would count every later emit on the thread into a stream
    that is done with, and into its ``diagnostics``.
    """
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"alpha" * 100)
    with open_archive(path, seekable_members=True) as reader:
        stack = reader._diagnostics_collector.scope_stack()  # type: ignore[attr-defined]
        stream = reader.open("a.txt")
        assert stack == []
        stream.read(3)
        assert stack == []
        stream.seek(0)
        assert stack == []
        with pytest.raises(TypeError):
            stream.read(1.5)  # type: ignore[arg-type]
        assert stack == []
        stream.close()
        assert stack == []


def _zip_with_empty_symlink(tmp_path: Path) -> Path:
    path = tmp_path / "link.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("target.txt", b"data")
        info = zipfile.ZipInfo("lnk")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"")
    return path


def test_link_followed_on_several_threads_is_reported_once(tmp_path: Path) -> None:
    path = _zip_with_empty_symlink(tmp_path)
    config = ArchiveyConfig(read_link_targets=False)
    unavailable = DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
    with open_archive(path, config=config) as reader:
        reader.members()
        with pytest.raises(Exception) as single:
            reader.read("lnk")
        alone = reader.diagnostics.counts[unavailable]
    errors: list[type[BaseException]] = []

    def follow() -> None:
        try:
            reader.read("lnk")
        except Exception as exc:  # noqa: BLE001 - compared with the single-thread error
            errors.append(type(exc))

    with open_archive(path, config=config, concurrent_operations=True) as reader:
        reader.members()
        _run_together(*([follow] * 4))
        assert reader.diagnostics.counts[unavailable] == alone
    assert errors == [type(single.value)] * 4


def test_close_beside_members_report_if_available_cancels_the_walk(
    tmp_path: Path,
) -> None:
    """``close()`` does not wait for the walk: it returns, the peek raises the closed
    error at the walk's next checkpoint, and the archive is torn down after it."""
    from archivey.exceptions import ArchiveyUsageError
    from archivey.internal.reader_state import LifecycleState

    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"a")
    reader = open_archive(path, concurrent_operations=True)
    walking = threading.Event()
    release = threading.Event()
    original = reader._ensure_walked  # type: ignore[attr-defined]

    def slow_walk() -> None:
        walking.set()
        release.wait(5)
        original()

    reader._ensure_walked = slow_walk  # type: ignore[attr-defined]
    outcome: list[object] = []

    def peek() -> None:
        try:
            outcome.append(reader.members_report_if_available())
        except BaseException as exc:  # noqa: BLE001 - checked below
            outcome.append(exc)

    caller = threading.Thread(target=peek)
    caller.start()
    assert walking.wait(5)
    reader.close()  # returns at once
    state = reader._state  # type: ignore[attr-defined]
    assert state.lifecycle is LifecycleState.READER_CLOSED  # the peek holds teardown
    release.set()
    caller.join(5)
    assert not caller.is_alive()
    (result,) = outcome
    assert isinstance(result, ArchiveyUsageError)
    assert "closed" in str(result)
    assert state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


def test_close_during_a_read_raises_the_closed_file_error() -> None:
    """A read that a close on another thread cuts off is not reported as damage."""
    reading = threading.Event()
    release = threading.Event()

    class Inner(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def read(self, n: int = -1) -> bytes:
            reading.set()
            release.wait(5)
            # What a closed pipe or buffer raises under a read in flight.
            raise OSError("pipe closed under the read")

    def translate(exc: Exception) -> Exception | None:
        from archivey import TruncatedError

        return TruncatedError(f"looks damaged: {exc}")

    stream = ArchiveStreamImpl(Inner, translate=translate)  # type: ignore[arg-type]
    errors: list[BaseException] = []

    def read() -> None:
        try:
            stream.read(10)
        except BaseException as exc:  # noqa: BLE001 - checked below
            errors.append(exc)

    reader = threading.Thread(target=read)
    reader.start()
    reading.wait(5)
    closer = threading.Thread(target=stream.close)
    closer.start()
    closer.join(0.2)
    release.set()
    reader.join(5)
    closer.join(5)
    assert len(errors) == 1
    assert type(errors[0]) is ValueError
    assert "closed file" in str(errors[0])
