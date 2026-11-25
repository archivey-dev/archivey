"""LockedStream unit tests for the TAR/ISO shared-handle wrapper."""

from __future__ import annotations

import io
import threading

import pytest

from archivey.internal.streams.streamtools import LockedStream

pytestmark = pytest.mark.concurrent_reader


class _SeekBeforeRead:
    """Fake library stream: each read seeks then reads from a shared cursor."""

    def __init__(self, shared: io.BytesIO, start: int, length: int) -> None:
        self._shared = shared
        self._start = start
        self._length = length
        self._pos = 0
        self.closed = False

    def read(self, n: int = -1) -> bytes:
        self._shared.seek(self._start + self._pos)
        if n < 0:
            n = self._length - self._pos
        n = min(n, self._length - self._pos)
        data = self._shared.read(n)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = self._length + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return True

    def close(self) -> None:
        self.closed = True


def test_locked_stream_interleaved_reads() -> None:
    shared = io.BytesIO(b"AAAABBBBCCCC")
    lock = threading.Lock()
    a = LockedStream(_SeekBeforeRead(shared, 0, 4), lock)
    b = LockedStream(_SeekBeforeRead(shared, 4, 4), lock)
    assert a.read(2) == b"AA"
    assert b.read(2) == b"BB"
    assert a.read() == b"AA"
    assert b.read() == b"BB"
    a.close()
    b.close()


def test_tar_iso_concurrent_open_uses_lock(tmp_path) -> None:
    import tarfile

    from archivey import open_archive

    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as t:
        for name, data in (("a.txt", b"aaaa"), ("b.txt", b"bbbb")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

    with open_archive(path, concurrent_operations=True, seekable_members=True) as ar:
        s1 = ar.open("a.txt")
        s2 = ar.open("b.txt")
        assert s1.read(2) == b"aa"
        assert s2.read(2) == b"bb"
        assert s1.read() == b"aa"
        assert s2.read() == b"bb"
        s1.close()
        s2.close()


class _CloseCounter(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


class _RawIOWithoutReadinto(io.RawIOBase):
    """``io.RawIOBase`` advertises ``readinto`` but the default raises ``NotImplementedError``."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._b = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        return self._b.read(n)


def test_locked_stream_readinto_falls_back_when_inner_readinto_unimplemented() -> None:
    s = LockedStream(_RawIOWithoutReadinto(b"xyz"), threading.Lock())
    buf = bytearray(2)
    assert s.readinto(buf) == 2
    assert bytes(buf) == b"xy"


def test_locked_stream_readinto_none_raises_blocking() -> None:
    class _NonBlockingReadinto(io.BytesIO):
        def readinto(self, b):  # type: ignore[no-untyped-def]
            return None

    with pytest.raises(BlockingIOError):
        LockedStream(_NonBlockingReadinto(b"x"), threading.Lock()).readinto(
            bytearray(4)
        )


def test_locked_stream_close_closes_inner_once() -> None:
    inner = _CloseCounter(b"data")
    s = LockedStream(inner, threading.Lock())
    s.close()
    assert inner.close_calls == 1
    assert s.closed
    s.close()
    assert inner.close_calls == 1


def test_a_close_under_its_own_handle_lock_waits_for_the_release() -> None:
    """A close on the thread that holds the shared-handle lock (the collector
    finalizing a dropped stream's layer inside a read through that handle) cannot
    wait for the lock: it runs when that thread lets the lock go."""
    from archivey.internal.streams.streamtools import HandleLock

    lock = HandleLock()
    stream = LockedStream(io.BytesIO(b"abc"), lock)
    with lock:
        stream.close()
        assert not stream.closed
    assert stream.closed
    assert not lock.locked()


def test_each_holder_runs_only_the_closes_it_deferred() -> None:
    """The deferred closes are the holder's: a thread that takes the lock between
    the first holder's release and its drain runs none of them, and the first
    holder's drain does not fail on a list another thread emptied."""
    from archivey.internal.streams.streamtools import HandleLock

    lock = HandleLock()
    ran: list[tuple[str, int]] = []

    def other_holder() -> None:
        with lock:
            lock.defer(lambda: ran.append(("other", threading.get_ident())))

    def first() -> None:
        ran.append(("first", threading.get_ident()))
        # Another thread takes and lets go of the lock before this holder's drain
        # reaches its second close.
        thread = threading.Thread(target=other_holder)
        thread.start()
        thread.join(5)

    with lock:
        lock.defer(first)
        lock.defer(lambda: ran.append(("second", threading.get_ident())))
    me = threading.get_ident()
    assert [name for name, _ in ran] == ["first", "other", "second"]
    assert ran[0][1] == me and ran[2][1] == me
    assert ran[1][1] != me
