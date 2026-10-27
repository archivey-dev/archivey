"""The rapidgzip child reads a member's bytes from the archive file itself.

A ZIP member in an archive on disk is a byte range of that file. On POSIX the child
gets the file's descriptor and the range (``OPEN_RANGE``) and reads with ``os.pread``,
so the compressed bytes do not cross a pipe. These tests cover the region detection
(``file_region``), the decoded result, and what the parent still checks.
"""

from __future__ import annotations

import gzip
import io
import mmap
import os
import random
import signal
import subprocess
import sys
import threading
import zipfile
from pathlib import Path

import pytest

from archivey import AcceleratorMode, ArchiveyConfig, open_archive
from archivey.exceptions import ArchiveyError, CorruptionError, TruncatedError
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.codecs import rapidgzip_child, rapidgzip_worker
from archivey.internal.streams.codecs.rapidgzip_worker import OPEN, OPEN_RANGE
from archivey.internal.streams.streamtools import SharedView, SlicingStream
from archivey.internal.streams.streamtools.slice import file_region

_DATA = random.Random(3).randbytes(300_000) + bytes(300_000)

posix_only = pytest.mark.skipif(os.name != "posix", reason="pass_fds is POSIX only")


def _file(tmp_path: Path, data: bytes = bytes(range(256)) * 4) -> Path:
    path = tmp_path / "data.bin"
    path.write_bytes(data)
    return path


def test_a_plain_file_is_its_whole_region(tmp_path: Path) -> None:
    with open(_file(tmp_path), "rb") as f:
        region = file_region(f)
        assert region is not None
        assert (region.fd, region.start, region.length) == (f.fileno(), 0, 1024)
        raw_region = file_region(f.raw)
        assert raw_region is not None
        assert raw_region.length == 1024


def test_nested_views_compose_their_offsets_and_bounds(tmp_path: Path) -> None:
    with open(_file(tmp_path), "rb") as f:
        member = SharedView(f, start=100, length=500, lock=threading.Lock())
        bounded = SlicingStream(member, start=10, length=1000, owns_inner=False)
        outer = SharedView(bounded, start=5, length=50, lock=threading.Lock())
        region = file_region(outer)
        assert region is not None
        assert (region.start, region.length) == (115, 50)
        # The bytes the region names are the bytes the view reads.
        expected = (tmp_path / "data.bin").read_bytes()[region.start :][: region.length]
        assert expected == outer.read()
        # An inner bound shorter than the outer one wins.
        tail = SlicingStream(member, start=480, length=1000, owns_inner=False)
        tail_region = file_region(tail)
        assert tail_region is not None
        assert (tail_region.start, tail_region.length) == (580, 20)


def test_the_views_archive_checks_are_kept(tmp_path: Path) -> None:
    def check() -> None:
        raise ValueError("archive closed")

    with open(_file(tmp_path), "rb") as f:
        view = SharedView(
            f, start=0, length=10, lock=threading.Lock(), check_open=check
        )
        region = file_region(view)
        assert region is not None
        assert region.checks[0] is check
        # The last check is the file's own: the child's copy of the descriptor would
        # still read after the caller closes it.
        region.checks[-1]()
    with pytest.raises(ValueError, match="closed file"):
        region.checks[-1]()


def test_streams_that_are_not_plain_files_have_no_region(tmp_path: Path) -> None:
    assert file_region(io.BytesIO(b"abc")) is None

    class Reader(io.BufferedReader):
        pass

    with open(_file(tmp_path), "rb", buffering=0) as raw:
        # A subclass may change what a read returns.
        assert file_region(Reader(raw)) is None  # type: ignore[arg-type]
    read_end, write_end = os.pipe()
    with open(read_end, "rb") as pipe, open(write_end, "wb"):
        assert file_region(pipe) is None


def test_an_archive_source_over_a_path_is_looked_through(tmp_path: Path) -> None:
    source = ArchiveSource.for_path(_file(tmp_path))
    try:
        # The handle opens lazily: nothing to answer before the first read.
        assert file_region(SharedView(source, 0, 10, lock=threading.Lock())) is None
        source.read(1)
        region = file_region(SharedView(source, 7, 10, lock=threading.Lock()))
        assert region is not None
        assert (region.start, region.length) == (7, 10)
    finally:
        source.close()


def _zip(tmp_path: Path, method: int) -> Path:
    path = tmp_path / "member.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("first.txt", b"x" * 1000, compress_type=zipfile.ZIP_STORED)
        zf.writestr("data.bin", _DATA, compress_type=method)
    return path


def _open_kinds(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the kind of every child OPEN."""
    kinds: list[int] = []
    call = rapidgzip_child.RapidgzipChildStream._call

    def spy(self, tag, arg=0, payload=b"", **kwargs):  # type: ignore[no-untyped-def]
        if tag == OPEN:
            kinds.append(arg)
        return call(self, tag, arg, payload, **kwargs)

    monkeypatch.setattr(rapidgzip_child.RapidgzipChildStream, "_call", spy)
    return kinds


_ON = ArchiveyConfig(
    use_rapidgzip=AcceleratorMode.ON, use_indexed_bzip2=AcceleratorMode.ON
)


@posix_only
@pytest.mark.parametrize("method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2])
def test_a_zip_member_is_read_from_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: int
) -> None:
    pytest.importorskip("rapidgzip")
    kinds = _open_kinds(monkeypatch)
    with open_archive(_zip(tmp_path, method), config=_ON, seekable_members=True) as r:
        member = "data.bin"
        with r.open(member) as stream:
            assert stream.read() == _DATA
            stream.seek(250_000)
            assert stream.read(1000) == _DATA[250_000:251_000]
    assert kinds == [OPEN_RANGE]


def _read_after_close(path: Path, config: ArchiveyConfig, what: str) -> Exception:
    """Close the reader's archive handle, or the caller's file under it, while the
    member stream stays open; then read on."""
    with open(path, "rb") as f:
        r = open_archive(f, config=config, seekable_members=True)
        stream = r.open("data.bin")
        try:
            assert stream.read(10) == _DATA[:10]
            if what == "archive":
                # Not ``r.close()``: that closes the member stream first, and the read
                # would fail on the stream's own closed check before reaching the child.
                r._close_archive()  # type: ignore[attr-defined]
            else:
                f.close()
            with pytest.raises(Exception) as excinfo:
                stream.read(500_000)
            return excinfo.value
        finally:
            stream.close()
            r.close()


@posix_only
@pytest.mark.parametrize("what", ["archive", "caller's file"])
def test_a_member_read_after_a_close_raises_as_the_stdlib_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, what: str
) -> None:
    pytest.importorskip("rapidgzip")
    path = _zip(tmp_path, zipfile.ZIP_DEFLATED)
    expected = _read_after_close(
        path, ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF), what
    )
    kinds = _open_kinds(monkeypatch)
    # The child could still read the file; the parent's checks stop it.
    actual = _read_after_close(path, _ON, what)
    assert kinds == [OPEN_RANGE]
    assert (type(actual), str(actual)) == (type(expected), str(expected))


@posix_only
def test_a_damaged_member_raises_as_the_stdlib_does(tmp_path: Path) -> None:
    pytest.importorskip("rapidgzip")
    path = _zip(tmp_path, zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(path) as zf:
        info = zf.getinfo("data.bin")
    data = bytearray(path.read_bytes())
    # Into the member's compressed body, past its local header.
    data[info.header_offset + 30 + len("data.bin") + 5000] ^= 0xFF
    path.write_bytes(bytes(data))
    errors = []
    for config in (ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF), _ON):
        with (
            open_archive(path, config=config, seekable_members=True) as r,
            r.open("data.bin") as stream,
            pytest.raises(ArchiveyError) as excinfo,
        ):
            stream.read()
        errors.append(type(excinfo.value))
    assert errors[0] is errors[1]


# --- reuse: one archive's members share rapidgzip children ------------------------------

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="a child is reused only where its memory peak can be reset (Linux)",
)


def _zip_members(tmp_path: Path, names: list[str], data: bytes = _DATA) -> Path:
    path = tmp_path / "members.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name in names:
            zf.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
    return path


def _count_spawns(monkeypatch: pytest.MonkeyPatch) -> list[subprocess.Popen[bytes]]:
    started: list[subprocess.Popen[bytes]] = []
    spawn = rapidgzip_child.spawn

    def spy(*args, **kwargs):  # type: ignore[no-untyped-def]
        proc = spawn(*args, **kwargs)
        started.append(proc)
        return proc

    monkeypatch.setattr(rapidgzip_child, "spawn", spy)
    return started


@posix_only
@linux_only
def test_the_members_of_one_archive_share_a_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("rapidgzip")
    started = _count_spawns(monkeypatch)
    path = _zip_members(tmp_path, ["a.bin", "b.bin", "c.bin"])
    earlier = set(rapidgzip_child._pools.values())
    pools: list[rapidgzip_child.RapidgzipChildPool] = []
    with open_archive(path, config=_ON, seekable_members=True) as r:
        for name in ("a.bin", "b.bin", "c.bin"):
            with r.open(name) as stream:
                stream.seek(250_000)
                assert stream.read(1000) == _DATA[250_000:251_000]
                stream.seek(0)
                assert stream.read() == _DATA
            pools = [
                pool for pool in rapidgzip_child._pools.values() if pool not in earlier
            ]
            assert len(pools) == 1
            assert pools[0].idle_count() == 1
        assert len(started) == 1
        assert started[0].poll() is None
    # The archive's close ends its idle children.
    assert pools[0].idle_count() == 0
    assert started[0].wait(timeout=10) is not None


def test_a_file_the_caller_opened_has_no_pool(tmp_path: Path) -> None:
    # Only an ArchiveSource says when it closes; a child cannot outlive a file whose
    # close nobody reports, so a stream over such a file gets a child of its own.
    with open(_file(tmp_path), "rb") as f:
        region = file_region(f)
        assert region is not None
        assert rapidgzip_child.child_pool(region.owner) is None
    source = ArchiveSource.for_path(_file(tmp_path))
    try:
        source.read(1)
        region = file_region(SharedView(source, 0, 10, lock=threading.Lock()))
        assert region is not None
        assert rapidgzip_child.child_pool(region.owner) is not None
    finally:
        source.close()
    assert rapidgzip_child.child_pool(source) is None


@posix_only
@linux_only
def test_a_reused_childs_earlier_stderr_is_not_read_as_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash of a reused child is judged by what it wrote while serving this
    stream: an abort message left from an earlier stream does not make the crash a
    truncation."""
    pytest.importorskip("rapidgzip")
    path = tmp_path / "data.gz"
    path.write_bytes(gzip.compress(_DATA))
    given: list[rapidgzip_child._IdleChild] = []
    give = rapidgzip_child.RapidgzipChildPool.give

    def spy(self, bzip2, fd, child):  # type: ignore[no-untyped-def]
        given.append(child)
        return give(self, bzip2, fd, child)

    monkeypatch.setattr(rapidgzip_child.RapidgzipChildPool, "give", spy)
    source = ArchiveSource.for_path(path)
    try:
        source.read(1)
        size = path.stat().st_size

        def stream() -> rapidgzip_child.RapidgzipChildStream:
            view = SharedView(source, 0, size, lock=threading.Lock())
            return rapidgzip_child.RapidgzipChildStream(
                view, label="gzip", max_memory=None
            )

        with stream() as first:
            assert first.read(10) == _DATA[:10]
        assert len(given) == 1
        given[0].stderr.write(rapidgzip_child._TRUNCATION_ABORT + b"\n")
        given[0].stderr.flush()
        with stream() as second:
            assert second._proc is given[0].proc
            assert second.read(10) == _DATA[:10]
            given[0].proc.send_signal(signal.SIGABRT)
            given[0].proc.wait(timeout=10)
            with pytest.raises(CorruptionError) as caught:
                second.read()
            assert not isinstance(caught.value, TruncatedError)
    finally:
        source.close()


@posix_only
@linux_only
def test_two_members_read_at_once_get_two_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("rapidgzip")
    started = _count_spawns(monkeypatch)
    path = _zip_members(tmp_path, ["a.bin", "b.bin", "c.bin"])
    with open_archive(
        path, config=_ON, seekable_members=True, concurrent_operations=True
    ) as r:
        with r.open("a.bin") as a, r.open("b.bin") as b:
            assert a.read(10) == b.read(10) == _DATA[:10]
            assert a.read() == b.read() == _DATA[10:]
        with r.open("c.bin") as c:
            assert c.read() == _DATA
        assert len(started) == 2
    for proc in started:
        assert proc.wait(timeout=10) is not None


@posix_only
@linux_only
def test_a_child_that_failed_on_a_member_is_not_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("rapidgzip")
    text = b"".join(b"line %d of some text\n" % i for i in range(40_000))
    path = tmp_path / "members.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", text, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("b.bin", _DATA, compress_type=zipfile.ZIP_DEFLATED)
        info = zf.getinfo("a.txt")
    data = bytearray(path.read_bytes())
    # A run of ones inside the compressed text: the decoder itself rejects it (an
    # invalid block type), and the standard library takes over from the child.
    at = info.header_offset + 30 + len("a.txt") + 2000
    data[at : at + 64] = b"\xff" * 64
    path.write_bytes(bytes(data))
    started = _count_spawns(monkeypatch)
    with open_archive(path, config=_ON, seekable_members=True) as r:
        with r.open("a.txt") as a, pytest.raises(ArchiveyError):
            a.read()
        assert started[0].wait(timeout=10) is not None
        with r.open("b.bin") as b:
            assert b.read() == _DATA
        assert len(started) == 2


def _resident(size: int) -> mmap.mmap:
    """``size`` bytes that count as resident until closed. A map, not a ``bytearray``:
    the kernel accounts for a map and its unmap at once, whatever Python's allocator
    keeps."""
    held = mmap.mmap(-1, size)
    for at in range(0, size, mmap.PAGESIZE):
        held[at] = 1
    return held


@linux_only
def test_the_memory_peak_resets_between_streams() -> None:
    # What lets a reused child measure each stream's memory from its own start.
    # Reset first: this process's peak may be past anything the test allocates.
    assert rapidgzip_worker._reset_peak()
    peak = rapidgzip_worker._peak_memory()
    assert peak is not None
    held = _resident(256 << 20)
    grown = rapidgzip_worker._peak_memory()
    assert grown is not None
    assert grown > peak + (128 << 20)
    held.close()
    assert rapidgzip_worker._reset_peak()
    after = rapidgzip_worker._peak_memory()
    assert after is not None
    assert after < grown - (128 << 20)


def test_a_reused_child_counts_every_stream_from_its_first_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # What an earlier stream left resident counts against the next stream's limit,
    # and a process that kept more than a quarter of a limit is not reused.
    # The peak is scripted: this process's real VmHWM moves with whatever else the
    # test run frees or allocates, which flaked a 64 MiB margin under a free-threaded
    # run. test_the_memory_peak_resets_between_streams covers the real reset.
    # No watcher thread: it would end the test process past the ceiling.
    monkeypatch.setattr(rapidgzip_worker._MemoryWatch, "_watch", lambda self: None)
    peak = 100 << 20
    monkeypatch.setattr(rapidgzip_worker, "_peak_memory", lambda: peak)
    watch = rapidgzip_worker._MemoryWatch()
    limit = 512 << 20
    share = limit // rapidgzip_worker._REUSE_SHARE
    watch.arm(limit)
    first = watch.ceiling
    assert first == (100 << 20) + limit
    watch.disarm()
    peak += share  # exactly a quarter kept: still reusable
    assert watch.reusable()
    peak += 1
    assert not watch.reusable()
    # The next stream's ceiling still counts from the first open, not from now.
    watch.arm(limit)
    assert watch.ceiling == first
    watch.disarm()
    peak = 100 << 20
    assert watch.reusable()


@posix_only
@linux_only
def test_a_child_is_retired_after_its_last_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("rapidgzip")
    monkeypatch.setattr(rapidgzip_child, "MAX_STREAMS_PER_CHILD", 2)
    started = _count_spawns(monkeypatch)
    path = _zip_members(tmp_path, ["a.bin", "b.bin", "c.bin"])
    with open_archive(path, config=_ON, seekable_members=True) as r:
        for name in ("a.bin", "b.bin"):
            with r.open(name) as stream:
                assert stream.read() == _DATA
        assert len(started) == 1
        # Its second stream was its last: it ends, and the third member starts another.
        assert started[0].wait(timeout=10) is not None
        with r.open("c.bin") as stream:
            assert stream.read() == _DATA
        assert len(started) == 2


@posix_only
@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_process_leaves_its_parents_child_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process created by ``fork`` that inherits an open member stream neither talks
    to the parent's rapidgzip child through the inherited pipes nor ends it at close:
    a read there raises ``ArchiveyUsageError``, and the parent reads on."""
    pytest.importorskip("rapidgzip")
    children: list[rapidgzip_child.RapidgzipChildStream] = []
    init = rapidgzip_child.RapidgzipChildStream.__init__

    def spy(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        children.append(self)
        init(self, *args, **kwargs)

    monkeypatch.setattr(rapidgzip_child.RapidgzipChildStream, "__init__", spy)
    with (
        open_archive(
            _zip(tmp_path, zipfile.ZIP_DEFLATED), config=_ON, seekable_members=True
        ) as r,
        r.open("data.bin") as stream,
    ):
        (child,) = children
        # The first read leaves no read-ahead behind, so the fork's read would be a
        # round trip on the parent's pipes; the refusal comes before the buffer anyway.
        first = stream.read(1000)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - runs in the forked process
            outcomes = []
            try:
                for name, call in (
                    ("read", lambda: stream.read(1000)),
                    ("position", child.compressed_position),
                    ("offsets", child.available_block_offsets),
                    ("close", lambda: (stream.close(), r.close())),
                ):
                    try:
                        call()
                        outcomes.append(f"{name}:ok")
                    except Exception as exc:  # noqa: BLE001 - reported to the parent
                        outcomes.append(f"{name}:{type(exc).__name__}")
            finally:
                os.write(write_fd, ",".join(outcomes).encode())
                os._exit(0)
        os.close(write_fd)
        os.waitpid(pid, 0)
        assert os.read(read_fd, 200) == (
            b"read:ArchiveyUsageError,position:ArchiveyUsageError,"
            b"offsets:ArchiveyUsageError,close:ok"
        )
        os.close(read_fd)
        assert first + stream.read() == _DATA
