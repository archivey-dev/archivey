"""Declared member-stream capabilities: gate, seekability, usage errors."""

from __future__ import annotations

import gc
import io
import weakref
from pathlib import Path

import pytest

from archivey import (
    ArchiveyError,
    ArchiveyUsageError,
    open_archive,
)
from tests.conftest import CPYTHON
from tests.extract_util import open_and_extract

pytestmark = pytest.mark.concurrent_reader


def _two_file_dir(tmp_path: Path) -> Path:
    (tmp_path / "a.txt").write_bytes(b"aaa")
    (tmp_path / "b.txt").write_bytes(b"bbb")
    return tmp_path


def test_second_overlapping_open_raises_usage_error(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    with open_archive(root) as reader:
        s1 = reader.open("a.txt")
        with pytest.raises(
            ArchiveyUsageError, match="concurrent_operations=True"
        ) as ei:
            reader.open("b.txt")
        # Breadcrumb points at this test file.
        assert "test_member_streams.py" in str(ei.value)
        assert s1.read() == b"aaa"
        s1.close()
        # After close, another open is fine.
        with reader.open("b.txt") as s2:
            assert s2.read() == b"bbb"


def test_refused_open_does_not_call_open_member(tmp_path: Path) -> None:
    """The single-live-stream gate must fire before ``_open_member``, not after.

    A spawn-then-close (or spawn-then-GC) implementation still raises
    ``ArchiveyUsageError`` but has already built the second stream. Counting
    ``_open_member`` is the format-agnostic discriminator.
    """
    root = _two_file_dir(tmp_path)
    with open_archive(root) as reader:
        opens = 0
        original = reader._open_member

        def counting_open_member(member):
            nonlocal opens
            opens += 1
            return original(member)

        reader._open_member = counting_open_member  # type: ignore[method-assign]
        s1 = reader.open("a.txt")
        assert opens == 1
        with pytest.raises(ArchiveyUsageError):
            reader.open("b.txt")
        assert opens == 1
        s1.close()
        with reader.open("b.txt") as s2:
            assert s2.read() == b"bbb"
        assert opens == 2


def test_failed_open_releases_reservation_and_still_tears_down(tmp_path: Path) -> None:
    """A failing ``_open_member`` must not permanently consume the single-stream slot.

    The reservation taken before open is released on failure so the next ``open()``
    succeeds, and ``close()`` still runs archive teardown (a leaked reservation
    would pin the source lease forever).
    """
    root = _two_file_dir(tmp_path)
    reader = open_archive(root)
    teardown = False
    original_close_archive = reader._close_archive

    def tracking_close_archive() -> None:
        nonlocal teardown
        teardown = True
        original_close_archive()

    reader._close_archive = tracking_close_archive  # type: ignore[method-assign]
    original_open_member = reader._open_member

    def boom(_member: object) -> object:
        raise RuntimeError("synthetic open failure")

    reader._open_member = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="synthetic open failure"):
        reader.open("a.txt")
    reader._open_member = original_open_member  # type: ignore[method-assign]
    with reader.open("a.txt") as stream:
        assert stream.read() == b"aaa"
    reader.close()
    assert teardown is True


def test_usage_error_is_not_archivey_error(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    with open_archive(root) as reader:
        s1 = reader.open("a.txt")
        try:
            try:
                reader.open("b.txt")
            except ArchiveyError:
                pytest.fail("ArchiveyUsageError must not be an ArchiveyError")
            except ArchiveyUsageError:
                pass
        finally:
            s1.close()
    assert not issubclass(ArchiveyUsageError, ArchiveyError)


def test_concurrent_flag_allows_overlapping_opens(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    with open_archive(root, concurrent_operations=True) as reader:
        s1 = reader.open("a.txt")
        s2 = reader.open("b.txt")
        assert s1.read() == b"aaa"
        assert s2.read() == b"bbb"
        s1.close()
        s2.close()


def test_default_streams_are_not_seekable(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    with open_archive(root) as reader, reader.open("a.txt") as s:
        assert s.seekable() is False
        with pytest.raises(io.UnsupportedOperation):
            s.seek(0)
        assert s.tell() == 0
        assert s.read() == b"aaa"


def test_seekable_flag_restores_positioning(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    with open_archive(root, seekable_members=True) as reader, reader.open("a.txt") as s:
        assert s.seekable() is True
        assert s.read(1) == b"a"
        s.seek(0)
        assert s.read() == b"aaa"


def test_member_streams_kwarg_is_gone(tmp_path: Path) -> None:
    """The flag-enum parameter was removed, not deprecated — passing it must fail.

    Python rejects unknown kwargs on its own; this locks the removal so a well-meant
    "accept both spellings" patch has to delete a test rather than slip through.
    """
    root = _two_file_dir(tmp_path)
    with pytest.raises(TypeError, match="member_streams"):
        open_archive(root, member_streams="anything")  # type: ignore[call-arg]


def test_concurrent_members_kwarg_is_gone(tmp_path: Path) -> None:
    """``concurrent_members`` became ``concurrent_operations`` with no alias.

    Same lock as above: accepting the old spelling again has to delete this test.
    """
    root = _two_file_dir(tmp_path)
    with pytest.raises(TypeError, match="concurrent_members"):
        open_archive(root, concurrent_members=True)  # type: ignore[call-arg]


def test_streaming_plus_concurrent_rejected(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    with pytest.raises(ArchiveyUsageError, match="streaming=True"):
        open_archive(root, streaming=True, concurrent_operations=True)


def test_extract_needs_no_capability(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    root = _two_file_dir(tmp_path / "src")
    dest = tmp_path / "out"
    dest.mkdir()
    report = open_and_extract(root, dest)
    assert (dest / "a.txt").read_bytes() == b"aaa"
    assert report.results


def test_wrong_reader_member_is_usage_error(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "f.txt").write_bytes(b"a")
    (b / "f.txt").write_bytes(b"b")
    with open_archive(a) as ra, open_archive(b) as rb:
        member_a = ra.get("f.txt")
        assert member_a is not None
        with pytest.raises(ArchiveyUsageError, match="does not belong"):
            rb.open(member_a)


def test_post_close_reader_ops_are_usage_errors(tmp_path: Path) -> None:
    root = _two_file_dir(tmp_path)
    reader = open_archive(root)
    stream = reader.open("a.txt")
    reader.close()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.open("b.txt")
    # The reader's close took the stream with it.
    assert stream.closed
    stream.close()  # idempotent


def test_dropped_stream_is_garbage_collected(tmp_path: Path) -> None:
    """A stream the caller never closed is collectable once the reader closes it."""
    root = _two_file_dir(tmp_path)
    reader = open_archive(root)
    stream = reader.open("a.txt")
    ref = weakref.ref(stream)

    reader.close()
    del stream
    for _ in range(3):
        gc.collect()

    assert ref() is None, "an unclosed member stream is still reachable after gc"


def test_dropped_stream_is_collected_without_reader_close(tmp_path: Path) -> None:
    """An abandoned reader's unclosed stream must still become collectable.

    Nothing the reader keeps for an open stream may hold it strongly: not the record
    that ``close()`` closes forgotten streams from, and not the stream's own close
    hook. Either would keep the stream and its file descriptor alive. Closing the
    reader closes the stream and hides such a reference, so the reader here is dropped
    rather than closed.
    """
    root = _two_file_dir(tmp_path)
    reader = open_archive(root)
    stream = reader.open("a.txt")
    ref = weakref.ref(stream)

    del stream, reader
    for _ in range(3):
        gc.collect()

    assert ref() is None


@pytest.mark.parametrize(
    "cycle",
    [
        pytest.param(
            False,
            id="refcount",
            marks=pytest.mark.skipif(
                not CPYTHON,
                reason="PyPy frees an unreferenced object only at its next collection",
            ),
        ),
        pytest.param(True, id="cycle"),
    ],
)
@pytest.mark.parametrize("fmt", ["dir", "zip"])
def test_dropped_stream_releases_its_lease(
    tmp_path: Path, fmt: str, cycle: bool
) -> None:
    """A stream dropped without ``close()`` gives its slot back when it is collected.

    The interpreter closes a collected stream (``IOBase.__del__``), and that close
    releases the lease: a reader without ``concurrent_operations`` then opens the
    next member, and its own close tears the archive down. ``cycle`` drops the stream
    in a reference cycle, so only the cyclic collector reclaims it.
    """
    from archivey.internal.reader_state import LifecycleState

    if fmt == "dir":
        root = _two_file_dir(tmp_path)
    else:
        import zipfile

        root = tmp_path / "a.zip"
        with zipfile.ZipFile(root, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", b"aaa")
            zf.writestr("b.txt", b"bbb")
    reader = open_archive(root)
    stream = reader.open("a.txt")
    assert stream.read() == b"aaa"
    ref = weakref.ref(stream)
    if cycle:
        stream.self_reference = stream  # type: ignore[attr-defined]
    del stream
    if cycle:
        assert ref() is not None
        gc.collect()
    assert ref() is None

    with reader.open("b.txt") as second:
        assert second.read() == b"bbb"
    reader.close()
    assert reader._state.lifecycle is LifecycleState.TEARDOWN_COMPLETE


def test_reader_close_closes_streams_in_open_order(tmp_path: Path) -> None:
    """Close order is part of the contract, so the registry has to preserve it.

    A ``WeakSet`` would not: its iteration order is unrelated to insertion. The
    registry is a counter-keyed weak mapping instead, so dict insertion order carries
    the promise the spec makes.
    """
    root = tmp_path
    names = [f"m{i}.txt" for i in range(6)]
    for name in names:
        (root / name).write_bytes(name.encode())

    from archivey.internal.streams.archive_stream import ArchiveStream

    closed_order: list[int] = []
    real_close = ArchiveStream.close

    def recording_close(self: ArchiveStream) -> None:
        closed_order.append(id(self))
        real_close(self)

    reader = open_archive(root, concurrent_operations=True)
    try:
        streams = [reader.open(name) for name in names]
        opened_order = [id(s) for s in streams]
        ArchiveStream.close = recording_close  # type: ignore[method-assign]
        reader.close()
    finally:
        ArchiveStream.close = real_close  # type: ignore[method-assign]

    ours = [sid for sid in closed_order if sid in set(opened_order)]
    assert ours == opened_order
