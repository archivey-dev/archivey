"""Operations on one ``concurrent_operations=True`` reader stay independent of each other.

Under the flag every call works as if it ran on a reader of its own: what one call
emits, or a close on another thread, does not show up in a different call's result
as something that call did. ``test_concurrent_pass_workers.py`` covers which calls
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
from tests.test_concurrent_pass_workers import _in_thread, _run_together

pytestmark = pytest.mark.concurrent_reader


def test_pass_stream_diagnostics_leave_out_another_threads_walk(
    tmp_path: Path,
) -> None:
    """The names another thread's ``members()`` normalizes are not the stream's."""
    path = tmp_path / "names.tar"
    with tarfile.open(path, "w") as tf:
        for name in ("a.txt", ".//b.txt", ".//c.txt"):
            info = tarfile.TarInfo(name)
            info.size = 3
            tf.addfile(info, io.BytesIO(b"abc"))
    normalized = DiagnosticCode.MEMBER_NAME_NORMALIZED
    with open_archive(path, concurrent_operations=True) as reader:
        it = reader.stream_members()
        member, stream = next(it)
        assert member.name == "a.txt"
        assert stream is not None
        _in_thread(reader.members)
        assert stream.read() == b"abc"
        assert stream.diagnostics.total_count == 0
        assert reader.diagnostics.counts[normalized] == 2
        it.close()


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


def test_close_waits_for_members_report_if_available(tmp_path: Path) -> None:
    """``close()`` waits for the walk, as it does for ``members()``."""
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
    reports: list[object] = []
    caller = threading.Thread(
        target=lambda: reports.append(reader.members_report_if_available())
    )
    caller.start()
    walking.wait(5)
    closer = threading.Thread(target=reader.close)
    closer.start()
    closer.join(0.2)
    # Still waiting for the walk.
    assert closer.is_alive()
    release.set()
    caller.join(5)
    closer.join(5)
    report = reports[0]
    assert report is not None
    assert [m.name for m in report.members] == ["a.txt"]  # type: ignore[attr-defined]
    assert report.error is None  # type: ignore[attr-defined]


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
