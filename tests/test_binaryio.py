"""Unit tests for ``streams/streamtools/binaryio.py``: the classify/coerce helpers and BinaryIOWrapper.

These adapt arbitrary caller objects to a uniform ``BinaryIO``, so they are tested hard as
units (per CONTRIBUTING's narrow exception for stream primitives). The cross-library
"does every real stream type survive these helpers" matrix lives in ``test_stream_inputs``.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from collections.abc import Callable

import pytest

from archivey.internal.streams.streamtools import (
    BinaryIOWrapper,
    ReadableStream,
    check_read_size,
    check_seek_args,
    ensure_binaryio,
    ensure_bufferedio,
    is_filename,
    is_seekable,
    is_stream,
    read_exact,
    read_within_reach,
    readinto_via_read,
    resolve_seek,
    source_name,
)
from tests.conftest import CPYTHON
from tests.streams_util import CountingBytesIO, NonSeekableBytesIO

# Messages are compared with io.BytesIO only on CPython, whose wording archivey copies.

DATA = b"0123456789abcdefghijklmnopqrstuvwxyz"


class OnlyReadStream:
    """A bare read-only object: ``read()`` and nothing else (the canonical wrap target)."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._inner.read(size)


class ReadIntoStream(OnlyReadStream):
    """A partial file-like that *does* implement ``readinto`` (no io.IOBase base)."""

    def readinto(self, b) -> int:  # type: ignore[no-untyped-def]  # test double
        return self._inner.readinto(b)


# --- readinto_via_read -----------------------------------------------------------------


def test_readinto_via_read_fills_buffer() -> None:
    inner = io.BytesIO(DATA)
    buf = bytearray(4)
    assert readinto_via_read(inner, buf) == 4
    assert bytes(buf) == DATA[:4]
    # Source position, not just the reported count: nothing extra was consumed.
    assert inner.read() == DATA[4:]


def test_readinto_via_read_short_at_eof() -> None:
    inner = io.BytesIO(b"ab")
    buf = bytearray(10)
    assert readinto_via_read(inner, buf) == 2
    assert buf[:2] == b"ab"
    assert inner.read() == b""


def test_readinto_via_read_raises_on_overlong_read() -> None:
    class _OverRead:
        def read(self, n: int = -1) -> bytes:
            return b"abcdef"

    buf = bytearray(4)
    with pytest.raises(ValueError, match=r"read\(4\) returned 6 bytes"):
        readinto_via_read(_OverRead(), buf)


# --- read_exact ------------------------------------------------------------------------


def test_read_exact_full() -> None:
    assert read_exact(io.BytesIO(DATA), 10) == DATA[:10]


def test_read_exact_short_at_eof() -> None:
    assert read_exact(io.BytesIO(b"abc"), 10) == b"abc"


def test_read_exact_zero() -> None:
    assert read_exact(io.BytesIO(DATA), 0) == b""


def test_read_exact_negative_raises() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        read_exact(io.BytesIO(DATA), -1)


def test_read_exact_gathers_across_short_reads() -> None:
    class _Drip(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._data = data
            self._pos = 0

        def readable(self) -> bool:
            return True

        def read(self, n: int = -1, /) -> bytes:
            # Return at most 1 byte per call, to exercise the gather loop.
            if self._pos >= len(self._data):
                return b""
            chunk = self._data[self._pos : self._pos + 1]
            self._pos += 1
            return chunk

    assert read_exact(_Drip(DATA), 5) == DATA[:5]


def test_read_exact_issues_one_read_on_a_full_count_inner() -> None:
    """No gather loop when the first read satisfies the ask."""

    class _Counting(io.BytesIO):
        def __init__(self, data: bytes) -> None:
            super().__init__(data)
            self.calls = 0

        def read(self, n: int | None = -1, /) -> bytes:
            self.calls += 1
            return super().read(n)

    stream = _Counting(DATA)
    assert read_exact(stream, 10) == DATA[:10]
    assert stream.calls == 1


def test_read_exact_does_not_copy_a_satisfied_read() -> None:
    """The fast path hands back the inner's object.

    Identity, not equality: an equality assertion passes just as well against a
    copy, and copying is what this avoids — on a whole decoded 7z folder that is
    1x peak memory rather than 3x. ``is`` is the only assertion that pins it.
    """
    payload = DATA[:10]

    class _OneShot(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def read(self, n: int = -1, /) -> bytes:
            return payload

    assert read_exact(_OneShot(), 10) is payload


class _Scripted(io.RawIOBase):
    """Returns each scripted value in turn, counting calls. ``b""`` once exhausted."""

    def __init__(self, values: list) -> None:
        self._values = list(values)
        self.calls = 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        self.calls += 1
        return self._values.pop(0) if self._values else b""


def test_read_exact_stops_at_the_first_empty_read() -> None:
    """An empty return is terminal on the call that produced it, not a retry.

    A second read past EOF is wasted I/O on every source and a semantic change on
    one that can yield data after a falsy return.
    """
    stream = _Scripted([b""])
    assert read_exact(stream, 10) == b""
    assert stream.calls == 1


def test_read_exact_zero_does_not_touch_the_stream() -> None:
    """``n == 0`` is answerable without I/O, and ``read(0)`` is not always free."""
    stream = _Scripted([b"unwanted"])
    assert read_exact(stream, 0) == b""
    assert stream.calls == 0


def test_read_exact_refuses_none() -> None:
    """A non-blocking raw returns ``None`` when nothing is ready; that is not EOF.

    Scripted as None-then-data on purpose: the data was never ready when asked,
    so a gather that returned ``b""`` here would end the stream early.
    """
    stream = _Scripted([None, b"hello"])
    with pytest.raises(BlockingIOError, match="non-blocking"):
        read_exact(stream, 10)
    assert stream.calls == 1


def test_read_exact_refuses_none_after_a_short_chunk() -> None:
    """``None`` on a follow-up read raises too; the short chunk is not returned."""
    stream = _Scripted([b"ab", None, b"cd"])
    with pytest.raises(BlockingIOError, match="non-blocking"):
        read_exact(stream, 10)
    assert stream.calls == 2


def test_read_exact_refuses_an_over_read() -> None:
    """More than ``n`` bytes is a broken stream; the excess cannot be given back."""
    with pytest.raises(ValueError, match="inner returned 9 bytes for read\\(4\\)"):
        read_exact(_Scripted([b"abcdefghi"]), 4)


def test_read_exact_refuses_an_over_read_after_a_short_chunk() -> None:
    """The gathered total is checked too, not only the first read."""
    with pytest.raises(ValueError, match="inner returned 13 bytes for read\\(6\\)"):
        read_exact(_Scripted([b"abcd", b"EFGHIJKLM"]), 6)


def test_read_exact_accepts_readablestream_protocol() -> None:
    assert isinstance(OnlyReadStream(DATA), ReadableStream)


# --- read_within_reach -----------------------------------------------------------------


class _SizeRecorder(io.RawIOBase):
    """A ``BytesIO`` that records the size asked of every ``read``.

    The sizes are the observable these tests care about, not the bytes: the whole point
    of :func:`read_within_reach` is that a number out of a hostile header never reaches
    an allocation, and a helper that returned the right bytes after asking for six
    gigabytes would still be the bug.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)
        self.requested: list[int] = []

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        self.requested.append(n)
        return self._inner.read(n)


def test_read_within_reach_clamps_to_a_known_remaining() -> None:
    """The branch a sized source takes: ask for what is left, not what was requested."""
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, 6 * 1024**3, remaining=10, step=16) == DATA[:10]
    assert src.requested == [10]


def test_read_within_reach_does_not_clamp_below_the_request() -> None:
    """``remaining`` is a ceiling, never a floor: a small read stays small."""
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, 4, remaining=100, step=16) == DATA[:4]
    assert src.requested == [4]


@pytest.mark.parametrize("remaining", [0, -5])
def test_read_within_reach_clamps_an_exhausted_remaining_to_zero(
    remaining: int,
) -> None:
    """Reachable by seeking past the end first; a negative must not become a drain.

    Fails against dropping the ``max(remaining, 0)``, which turns ``remaining=-5`` into
    ``read(-5)`` — read-to-EOF, the opposite of a bound.
    """
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, 100, remaining=remaining, step=16) == b""
    assert src.requested == [0]


def test_read_within_reach_steps_an_unknown_length() -> None:
    """The branch every unmeasurable source takes; ``None`` is unknown, not unlimited.

    Fails against forwarding ``size`` when ``remaining is None``, which asks the source
    for the whole 4 294 967 296 in one call.
    """
    src = _SizeRecorder(DATA)  # 36 bytes: two whole steps and a short third
    assert read_within_reach(src, 1 << 32, remaining=None, step=16) == DATA
    # Three requests, one step each: 16, 16, and a third that returns 4, which ends
    # the loop. The assertion is on what was asked for, which is a step every time —
    # never the 4 294 967 296 the caller passed.
    assert src.requested == [16, 16, 16]


def test_read_within_reach_takes_a_short_step_as_the_end() -> None:
    """A short step ends the read, so a decoder's deferred error stays on the next one.

    Fails against looping until an empty read: the fourth read raises, and the 36
    bytes already joined are lost with it.
    """

    class _DeferredCut(_SizeRecorder):
        def read(self, n: int = -1, /) -> bytes:
            data = super().read(n)
            if not data:
                raise EOFError("cut")
            return data

    src = _DeferredCut(DATA)
    assert read_within_reach(src, 1 << 32, remaining=None, step=16) == DATA
    assert src.requested == [16, 16, 16]


def test_read_within_reach_returns_a_full_step_without_joining() -> None:
    """``size == step`` is satisfied by the first read, so it costs no join copy."""
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, 16, remaining=None, step=16) == DATA[:16]
    assert src.requested == [16]


def test_read_within_reach_enters_the_loop_one_byte_past_the_step() -> None:
    """``size == step + 1`` is the smallest request that must be stitched."""
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, 17, remaining=None, step=16) == DATA[:17]
    assert src.requested == [16, 1]


def test_read_within_reach_reads_to_eof_on_a_negative_size() -> None:
    """``read(-1)`` is the documented carve-out: it ignores ``remaining`` entirely.

    It allocates as the data arrives rather than up front, so it is not sized from the
    archive and needs no bound. Fails against a clamp written with the negative folded
    in — ``inner.read(max(min(size, remaining), 0))``, which is the natural shape if
    the ``size <= 0`` guard above is ever tidied away, and which turns every drain into
    ``read(0)``. Deleting that guard outright is *not* what this catches: with
    ``min(size, step)`` a negative survives the stepping path by accident.
    """
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, -1, remaining=8, step=16) == DATA
    assert src.requested == [-1]


def test_read_within_reach_zero_does_not_consume_a_byte() -> None:
    src = _SizeRecorder(DATA)
    assert read_within_reach(src, 0, remaining=None, step=16) == b""
    assert src.requested == [0]


# --- is_filename / is_stream / is_seekable ---------------------------------------------


def test_is_filename() -> None:
    assert is_filename("path.zip")
    assert is_filename(b"path.zip")
    assert is_filename(os.fspath("/tmp/x"))
    assert not is_filename(io.BytesIO(b"x"))
    assert not is_filename(OnlyReadStream(b"x"))


def test_source_name_decodes_bytes_stream_name(tmp_path) -> None:
    """open(bytes_path).name is bytes; callers of source_name want a str path."""
    path = tmp_path / "x.bin"
    path.write_bytes(b"")
    with open(os.fsencode(path), "rb") as f:
        assert isinstance(f.name, bytes)
        assert source_name(f) == os.fsdecode(f.name)


def test_is_stream_accepts_iobase() -> None:
    assert is_stream(io.BytesIO(b"x"))
    assert not is_stream("path.zip")


def test_is_stream_rejects_text_mode(tmp_path) -> None:
    assert not is_stream(io.StringIO("hello"))
    path = tmp_path / "note.txt"
    path.write_text("x", encoding="utf-8")
    with open(path, encoding="utf-8") as f:
        assert not is_stream(f)


def test_is_stream_rejects_write_only_handle(tmp_path) -> None:
    """A write-only file is an IOBase but not a readable BinaryIO."""
    with open(tmp_path / "out.bin", "wb") as f:
        assert not is_stream(f)
        assert not is_stream(f.raw)


def test_is_stream_accepts_closed_binary_handle(tmp_path) -> None:
    """A handle that can no longer answer still qualifies, so the caller's first read
    reports the closed file rather than a type error. That includes a closed buffered
    writer, whose ``writable()`` raises."""
    stream = io.BytesIO(b"x")
    stream.close()
    assert is_stream(stream)
    with open(tmp_path / "out.bin", "wb") as f:
        pass
    assert is_stream(f)


def test_is_stream_accepts_subclass_that_never_declares_readable() -> None:
    """``IOBase.readable()`` defaults to ``False``; a subclass that reads but does not
    override it is not a writer and keeps passing through."""

    class _MinimalBuffered(io.BufferedIOBase):
        def __init__(self, data: bytes) -> None:
            self._d = io.BytesIO(data)

        def read(self, n: int | None = -1) -> bytes:
            return self._d.read(n)

    assert is_stream(_MinimalBuffered(b"x"))


@pytest.mark.parametrize("entry", ["open_archive", "open_stream", "detect_format"])
def test_entry_points_name_a_write_only_source(entry) -> None:
    """The same words at every entry point, including ``open_stream``, which keeps its
    own message for other wrong types."""
    import archivey

    writer = io.BufferedWriter(io.BytesIO())
    with pytest.raises(TypeError, match="BufferedWriter is write-only"):
        getattr(archivey, entry)(writer)


@pytest.mark.parametrize("buffer_type", [bytearray, memoryview])
def test_open_archive_names_a_byte_buffer_source(buffer_type) -> None:
    """A byte buffer is a Sequence of int, not a volume list: the refusal names the
    buffer's type, not ``int``."""
    import archivey

    with pytest.raises(
        TypeError, match=f"unsupported source type: <class '{buffer_type.__name__}'>"
    ):
        archivey.open_archive(buffer_type(b"PK\x03\x04"))


def test_is_stream_rejects_partial_object() -> None:
    # Has read() but is missing the rest of the BinaryIO surface (and isn't io.IOBase).
    assert not is_stream(OnlyReadStream(b"x"))


def test_is_stream_accepts_full_duck_typed_object() -> None:
    # Not an io.IOBase, but exposes the whole interface is_stream() checks for.
    class _Full:
        def read(self, n=-1):  # type: ignore[no-untyped-def]
            return b""

        def seek(self, o, w=0):  # type: ignore[no-untyped-def]
            return 0

        def tell(self):  # type: ignore[no-untyped-def]
            return 0

        def close(self):  # type: ignore[no-untyped-def]
            return None

        def readable(self):  # type: ignore[no-untyped-def]
            return True

        def writable(self):  # type: ignore[no-untyped-def]
            return False

        def seekable(self):  # type: ignore[no-untyped-def]
            return True

        def readinto(self, b):  # type: ignore[no-untyped-def]
            return 0

        closed = False

    assert is_stream(_Full())


def test_is_seekable_true_false() -> None:
    assert is_seekable(io.BytesIO(b"x"))
    assert not is_seekable(NonSeekableBytesIO(b"x"))


def test_is_seekable_unwraps_buffered_reader() -> None:
    # BufferedReader.seekable() already forwards to the raw (False here).
    # Unwrap still recurses onto the raw so a detached buffer is False rather
    # than ValueError — not a lie-correction.
    buffered = io.BufferedReader(NonSeekableBytesIO(DATA))
    assert not is_seekable(buffered)


def test_is_seekable_detached_buffer_is_false() -> None:
    buffered = io.BufferedReader(io.BytesIO(DATA))
    buffered.detach()
    assert buffered.raw is None
    assert is_seekable(buffered) is False


def test_is_seekable_object_without_seekable_method() -> None:
    assert not is_seekable(OnlyReadStream(b"x"))


def test_is_seekable_tarfile_exfileobject_in_streaming_mode() -> None:
    # tarfile.ExFileObject.seekable() in r| mode delegates to tarfile._Stream, which
    # lacks seekable() — AttributeError. Member streams are forward-only there anyway.
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    data = buf.getvalue()

    with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as t:
        for info in t:
            member_stream = t.extractfile(info)
            assert member_stream is not None
            assert not is_seekable(member_stream)
            break
    # A stream can claim seekable()=True yet be a pipe whose seek() does not reposition
    # (real Windows os.pipe behavior). is_seekable must distrust the claim for a FIFO and
    # return False. Verified portably with a real pipe fd, which is a FIFO on every platform.
    r, w = os.pipe()

    class _LyingPipe:
        def seekable(self) -> bool:
            return True  # the lie a Windows pipe tells

        def fileno(self) -> int:
            return r

    try:
        assert is_seekable(_LyingPipe()) is False
    finally:
        os.close(r)
        os.close(w)


def test_is_seekable_special_cases_mmap() -> None:
    import mmap

    # mmap is seekable but exposes no seekable() method and isn't an io.IOBase.
    mm = mmap.mmap(-1, 16)
    try:
        assert is_seekable(mm) is True
    finally:
        mm.close()


def test_wrapper_over_mmap_seeks_and_returns_int_position() -> None:
    import mmap

    mm = mmap.mmap(-1, len(DATA))
    mm.write(DATA)
    mm.seek(0)
    wrapper = BinaryIOWrapper(mm)
    try:
        assert wrapper.seekable() is True
        assert wrapper.read(5) == DATA[:5]
        # mmap.seek() returns None before 3.13; the wrapper must still return an int pos.
        assert wrapper.seek(0) == 0
        # A relative seek must report the resulting *absolute* position (via tell()),
        # not the relative offset.
        assert wrapper.seek(10) == 10
        assert wrapper.seek(3, io.SEEK_CUR) == 13
        assert wrapper.seek(-1, io.SEEK_END) == len(DATA) - 1
        assert wrapper.read(1) == DATA[-1:]
    finally:
        mm.close()


class _NoneSeekNoTell:
    """seek() returns None (like mmap<3.13) and there is no tell() — the degenerate case."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._inner.read(size)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> None:
        self._inner.seek(offset, whence)  # returns None


def test_wrapper_seek_none_no_tell_absolute_ok_relative_raises() -> None:
    wrapper = BinaryIOWrapper(_NoneSeekNoTell(DATA))
    # Absolute (SEEK_SET): the offset *is* the resulting position.
    assert wrapper.seek(4) == 4
    assert wrapper.read(2) == DATA[4:6]
    # Relative/end: position is unknowable without tell(); don't guess — raise, and flag
    # it as unexpected so a real occurrence gets reported.
    with pytest.raises(io.UnsupportedOperation, match="please report"):
        wrapper.seek(2, io.SEEK_CUR)
    with pytest.raises(io.UnsupportedOperation):
        wrapper.seek(0, io.SEEK_END)


# --- BinaryIOWrapper -------------------------------------------------------------------


def test_wrapper_read_and_readinto_fallback() -> None:
    # OnlyReadStream has no readinto, so readinto() must fall back to read().
    wrapper = BinaryIOWrapper(OnlyReadStream(DATA))
    assert wrapper.read(5) == DATA[:5]
    buf = bytearray(4)
    assert wrapper.readinto(buf) == 4
    assert bytes(buf) == DATA[5:9]


def test_wrapper_readinto_uses_native_when_present() -> None:
    wrapper = BinaryIOWrapper(ReadIntoStream(DATA))
    buf = bytearray(6)
    assert wrapper.readinto(buf) == 6
    assert bytes(buf) == DATA[:6]


def test_wrapper_read_to_eof() -> None:
    wrapper = BinaryIOWrapper(OnlyReadStream(b"abc"))
    assert wrapper.read() == b"abc"
    assert wrapper.read() == b""  # genuine EOF stays b"", not an error


def test_wrapper_read_none_raises_blocking_not_eof() -> None:
    """A non-blocking read() returning None must not be reported as EOF (data loss)."""

    class _NonBlocking:
        def read(self, n: int = -1) -> bytes | None:
            return None  # "no data available right now", not EOF

    with pytest.raises(BlockingIOError):
        BinaryIOWrapper(_NonBlocking()).read(10)


def test_wrapper_readinto_none_raises_blocking() -> None:
    class _NonBlockingReadinto:
        def read(self, n: int = -1) -> bytes:
            return b""

        def readinto(self, b) -> int | None:  # type: ignore[no-untyped-def]
            return None

    with pytest.raises(BlockingIOError):
        BinaryIOWrapper(_NonBlockingReadinto()).readinto(bytearray(10))


def test_wrapper_readinto_falls_back_when_native_raises() -> None:
    class _BadReadinto(OnlyReadStream):
        def readinto(self, b):  # type: ignore[no-untyped-def]
            raise io.UnsupportedOperation("readinto")

    wrapper = BinaryIOWrapper(_BadReadinto(DATA))
    buf = bytearray(5)
    assert wrapper.readinto(buf) == 5
    assert bytes(buf) == DATA[:5]


def test_wrapper_over_readonly_file_is_not_writable() -> None:
    """A read-only file *has* a write() method (it raises); the wrapper still is not writable."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "f.bin")
        with open(path, "wb") as f:
            f.write(DATA)
        # A read-only file object: it exposes write() but the wrapper must not.
        raw = open(path, "rb", buffering=0)  # noqa: SIM115 - the handle outlives this statement; its owner closes it
        assert hasattr(raw, "write")
        wrapper = BinaryIOWrapper(raw)
        assert wrapper.writable() is False
        assert wrapper.readable() is True
        raw.close()


def test_wrapper_writable_for_object_without_writable_method() -> None:
    # OnlyReadStream has neither writable() nor write() -> not writable.
    assert BinaryIOWrapper(OnlyReadStream(DATA)).writable() is False

    class _Writer(OnlyReadStream):
        def write(self, data):  # type: ignore[no-untyped-def]
            return len(data)

        def writable(self) -> bool:
            return True

    # The wrapper is read-only even when the raw would accept writes.
    wrapper = BinaryIOWrapper(_Writer(DATA))
    assert wrapper.writable() is False
    with pytest.raises(io.UnsupportedOperation, match="write"):
        wrapper.write(b"x")


def test_wrapper_write_unsupported_on_readonly() -> None:
    wrapper = BinaryIOWrapper(OnlyReadStream(DATA))
    with pytest.raises(io.UnsupportedOperation):
        wrapper.write(b"x")


def test_wrapper_mode_is_rb_not_none() -> None:
    """typing.BinaryIO.mode returns None; pycdlib does ``'b' not in fp.mode``."""
    wrapper = BinaryIOWrapper(OnlyReadStream(DATA))
    assert wrapper.mode == "rb"
    assert "b" in wrapper.mode


def test_wrapper_name_absent_without_inner_path() -> None:
    wrapper = BinaryIOWrapper(OnlyReadStream(DATA))
    assert not hasattr(wrapper, "name")


def test_wrapper_name_forwards_from_inner_file(tmp_path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"x")
    with open(path, "rb") as inner:
        wrapper = BinaryIOWrapper(inner)
        assert wrapper.name == str(path)


def test_wrapper_seek_tell_unsupported_when_absent() -> None:
    wrapper = BinaryIOWrapper(OnlyReadStream(DATA))
    assert wrapper.seekable() is False
    with pytest.raises(io.UnsupportedOperation):
        wrapper.seek(0)
    with pytest.raises(io.UnsupportedOperation):
        wrapper.tell()


def test_wrapper_seek_tell_delegate_when_present() -> None:
    wrapper = BinaryIOWrapper(io.BytesIO(DATA))
    assert wrapper.seekable() is True
    assert wrapper.read(5) == DATA[:5]
    assert wrapper.tell() == 5
    assert wrapper.seek(0) == 0
    assert wrapper.read(3) == DATA[:3]


def test_wrapper_does_not_close_underlying() -> None:
    inner = io.BytesIO(DATA)
    wrapper = BinaryIOWrapper(inner)
    wrapper.close()
    assert wrapper.closed
    assert not inner.closed  # must not close a stream it doesn't own


# --- ensure_binaryio -------------------------------------------------------------------


def test_ensure_binaryio_passthrough() -> None:
    stream = io.BytesIO(DATA)
    assert ensure_binaryio(stream) is stream


def test_ensure_binaryio_wraps_partial_object() -> None:
    wrapped = ensure_binaryio(OnlyReadStream(DATA))
    assert isinstance(wrapped, BinaryIOWrapper)
    assert wrapped.read(3) == DATA[:3]
    assert wrapped.readable() is True
    assert wrapped.writable() is False
    assert wrapped.seekable() is False


def test_ensure_binaryio_rejects_text_mode(tmp_path) -> None:
    with pytest.raises(TypeError, match="text-mode"):
        ensure_binaryio(io.StringIO("hello"))
    path = tmp_path / "note.txt"
    path.write_text("x", encoding="utf-8")
    with open(path, encoding="utf-8") as f, pytest.raises(TypeError, match="text-mode"):
        ensure_binaryio(f)


def test_ensure_bufferedio_rejects_text_mode() -> None:
    with pytest.raises(TypeError, match="text-mode"):
        ensure_bufferedio(io.StringIO("hello"))


def test_archive_source_rejects_text_mode() -> None:
    from archivey.internal.source import ArchiveSource

    with pytest.raises(TypeError, match="text-mode"):
        ArchiveSource.for_stream(io.StringIO("hello"))  # type: ignore[arg-type]


def test_open_archive_rejects_text_mode_handle(tmp_path) -> None:
    from archivey import open_archive

    path = tmp_path / "note.txt"
    path.write_text("not an archive\n", encoding="utf-8")
    with open(path, encoding="utf-8") as handle:
        with pytest.raises(TypeError, match="text-mode"):
            open_archive(handle)
        with pytest.raises(TypeError, match="text-mode"):
            open_archive([handle])


def test_open_stream_rejects_text_mode_handle(tmp_path) -> None:
    from archivey import open_stream

    path = tmp_path / "note.txt"
    path.write_text("not a stream\n", encoding="utf-8")
    with (
        open(path, encoding="utf-8") as handle,
        pytest.raises(TypeError, match="text-mode"),
    ):
        open_stream(handle)


# --- ensure_bufferedio -----------------------------------------------------------------


def test_ensure_bufferedio_passthrough_for_buffered() -> None:
    inner = io.BytesIO(DATA)  # already a BufferedIOBase
    assert ensure_bufferedio(inner) is inner


def test_ensure_bufferedio_wraps_rawiobase() -> None:
    inner = CountingBytesIO(DATA)  # a RawIOBase
    buffered = ensure_bufferedio(inner)
    assert isinstance(buffered, io.BufferedReader)
    assert buffered.read(4) == DATA[:4]


def test_ensure_bufferedio_wraps_non_iobase_object() -> None:
    # A stream-like that is not an io.IOBase: BufferedReader would reject it directly, so
    # ensure_bufferedio must adapt it through BinaryIOWrapper first.
    buffered = ensure_bufferedio(OnlyReadStream(DATA))
    assert buffered.read() == DATA


def test_ensure_bufferedio_rawiobase_with_only_read() -> None:
    """A RawIOBase that implements only read() is legal; BufferedReader.read(n) is not.

    ``io.RawIOBase.readinto`` defaults to ``NotImplementedError``. ``BufferedReader.read(n)``
    drives that, so ``ensure_bufferedio`` must wrap through ``BinaryIOWrapper`` first
    (#326 H4). ``read()`` without a size happens to fall back to ``raw.read()`` and
    would hide the bug.
    """

    class _OnlyReadRaw(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            super().__init__()
            self._buf = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def read(self, n: int = -1, /) -> bytes:
            return self._buf.read(n)

    buffered = ensure_bufferedio(_OnlyReadRaw(DATA))
    assert buffered.read(4) == DATA[:4]
    assert buffered.read() == DATA[4:]


def test_ensure_bufferedio_does_not_position_a_pending_solid_slice() -> None:
    """Wrap-time must not skip-decode a lazy solid member (#329 C1)."""
    from archivey.internal.streams.streamtools import SolidBlockReader

    reader = SolidBlockReader(io.BytesIO(b"A" * 10 + b"B" * 10), close_block=False)
    member = reader.open_member(10, 10, lazy=True)
    assert reader._pos == 0
    assert member._pending is True
    ensure_bufferedio(member)
    assert reader._pos == 0
    assert member._pending is True


def test_ensure_bufferedio_does_not_close_raw_source() -> None:
    inner = CountingBytesIO(DATA)
    buffered = ensure_bufferedio(inner)
    assert buffered.read(4) == DATA[:4]
    buffered.close()
    assert not inner.closed  # the non-closing buffer detaches rather than closing


def test_ensure_bufferedio_close_is_idempotent() -> None:
    """detach() would make IOBase.closed raise; a second close must not (#329 C8)."""
    inner = CountingBytesIO(DATA)
    buffered = ensure_bufferedio(inner)
    buffered.close()
    buffered.close()
    assert not inner.closed


def test_ensure_bufferedio_close_after_raw_closed_does_not_raise() -> None:
    """The owner closed the raw first (an outer reader closing a member stream that a
    nested archive reads): the buffer's close must not raise from detach()'s flush."""
    inner = CountingBytesIO(DATA)
    buffered = ensure_bufferedio(inner)
    assert buffered.read(4) == DATA[:4]
    inner.close()
    buffered.close()
    assert buffered.closed is True


def test_ensure_bufferedio_closed_is_true_after_close() -> None:
    """After detach, .closed must still answer True (#329 C10)."""
    inner = CountingBytesIO(DATA)
    buffered = ensure_bufferedio(inner)
    buffered.close()
    assert buffered.closed is True
    assert not inner.closed


def test_ensure_bufferedio_close_after_direct_detach() -> None:
    """A caller that detach()s first must still be able to close (#329 round 4)."""
    inner = CountingBytesIO(DATA)
    buffered = ensure_bufferedio(inner)
    buffered.detach()
    assert buffered.raw is None
    assert buffered.closed is True
    buffered.close()
    assert buffered.closed is True
    assert not inner.closed


def test_plain_bufferedreader_closes_source_demonstrates_why_we_detach() -> None:
    """Contrast: a *plain* BufferedReader closes its raw stream on close().

    This is the failure mode ``_NonClosingBufferedReader`` exists to prevent — closing the
    buffer (explicitly, or implicitly via GC / a ``with`` block) would close a stream the
    caller owns. ``ensure_bufferedio`` must NOT behave like this.
    """
    inner = CountingBytesIO(DATA)
    plain = io.BufferedReader(inner)
    plain.close()
    assert (
        inner.closed
    )  # plain BufferedReader took the (caller-owned) source down with it

    # ensure_bufferedio over the same kind of source leaves it open — the behaviour we want.
    survivor = CountingBytesIO(DATA)
    ensure_bufferedio(survivor).close()
    assert not survivor.closed


def test_ensure_bufferedio_source_still_readable_after_buffer_closed() -> None:
    """After the non-closing buffer is closed, the caller can keep reading the source."""
    inner = CountingBytesIO(DATA)
    buffered = ensure_bufferedio(inner)
    assert buffered.read(4) == DATA[:4]
    buffered.close()
    # The source is still open and continues from where the buffer left off is not
    # guaranteed (the buffer read ahead), but it must remain usable, not closed.
    assert not inner.closed
    assert inner.read(0) == b""  # a live, non-raising operation on an open stream


# ---------------------------------------------------------------------------
# source_byte_size: cheap-only contract
# ---------------------------------------------------------------------------


class TestSourceByteSize:
    def test_path_is_stated(self, tmp_path) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        p = tmp_path / "f.bin"
        p.write_bytes(b"x" * 1234)
        assert source_byte_size(p) == 1234
        assert source_byte_size(str(p)) == 1234

    def test_size_attribute_is_trusted(self) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        class _Sized(io.BytesIO):
            @property
            def size(self) -> int:
                return 999  # deliberately different from the buffer length

        assert source_byte_size(_Sized(b"abc")) == 999

    def test_whitelisted_types_are_probed(self, tmp_path) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        buf = io.BytesIO(b"x" * 77)
        buf.seek(10)
        assert source_byte_size(buf) == 77
        assert buf.tell() == 10  # position restored

        p = tmp_path / "f.bin"
        p.write_bytes(b"y" * 55)
        with open(p, "rb") as f:  # BufferedReader over FileIO
            assert source_byte_size(f) == 55

    def test_buffered_reader_over_file_is_not_seeked(self, tmp_path) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        class CountingFileIO(io.FileIO):
            seeks = 0

            def seek(self, o: int, w: int = 0) -> int:  # type: ignore[override]
                type(self).seeks += 1
                return super().seek(o, w)

        p = tmp_path / "f.bin"
        p.write_bytes(b"y" * 55)
        raw = CountingFileIO(str(p), "rb")
        try:
            buf = io.BufferedReader(raw)
            CountingFileIO.seeks = 0
            assert source_byte_size(buf) == 55
            assert CountingFileIO.seeks == 0
            assert buf.tell() == 0
        finally:
            raw.close()

    def test_bytesio_probe_does_not_seek(self) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        class _Ops(io.BytesIO):
            def __init__(self, data: bytes) -> None:
                super().__init__(data)
                self.seeks = 0

            def seek(self, offset: int, whence: int = 0) -> int:  # type: ignore[override]
                self.seeks += 1
                return super().seek(offset, whence)

        buf = _Ops(b"x" * 77)
        buf.seek(10)
        buf.seeks = 0
        assert source_byte_size(buf) == 77
        assert buf.tell() == 10
        assert buf.seeks == 0

    def test_buffered_random_unflushed_write_uses_seek_end(self, tmp_path) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        p = tmp_path / "f.bin"
        p.write_bytes(b"0123456789")
        with open(p, "r+b") as f:
            f.seek(0, io.SEEK_END)
            f.write(b"abcd")
            assert isinstance(f, io.BufferedRandom)
            assert source_byte_size(f) == 14

    def test_seek_end_fallback_counts_through_seek_counting_stream(
        self, tmp_path
    ) -> None:
        # Peel decides cheapness; the SEEK_END I/O must still go through the
        # wrapper so source_seek_count sees it (PR #328 F14).
        from archivey.internal.measurement import SeekCounter
        from archivey.internal.streams.counting import SeekCountingStream
        from archivey.internal.streams.streamtools import source_byte_size

        p = tmp_path / "f.bin"
        p.write_bytes(b"x" * 100)
        with open(p, "r+b") as f:
            assert isinstance(f, io.BufferedRandom)
            counter = SeekCounter()
            wrapped = SeekCountingStream(f, counter)
            assert source_byte_size(wrapped) == 100
            assert counter.count == 2  # SEEK_END + restore; tell is not counted

    def test_non_seekable_bytesio_subclass_is_none(self) -> None:
        # Probe 4 used to run only after is_seekable. Metadata-first would
        # answer for a BytesIO subclass that reports seekable() False
        # (PR #328 F15). The suite's NonSeekableBytesIO is a RawIOBase
        # wrapper, not a BytesIO subclass, so it would not catch this.
        from archivey.internal.streams.streamtools import source_byte_size

        class _NonSeekableBytesIO(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *args: object, **kwargs: object) -> int:
                raise io.UnsupportedOperation("seek")

        assert source_byte_size(_NonSeekableBytesIO(b"0123456789")) is None

    def test_decompressor_streams_are_never_probed(self, tmp_path) -> None:
        # SEEK_END on a decompressor means decompressing to the end; the helper must
        # return None for such streams rather than trigger that work. GzipFile is the
        # canonical trap: it is seekable and even forwards fileno() to the *compressed*
        # file, so neither a seekable() check nor an fstat duck-check is safe.
        import gzip

        from archivey.internal.streams.streamtools import source_byte_size

        p = tmp_path / "f.gz"
        p.write_bytes(gzip.compress(b"payload " * 10_000))
        with gzip.open(p, "rb") as f:
            assert source_byte_size(f) is None
            assert f.tell() == 0  # nothing was decompressed to answer

    def test_non_seekable_stream_is_none(self) -> None:
        from archivey.internal.streams.streamtools import source_byte_size

        assert source_byte_size(NonSeekableBytesIO(b"abc")) is None


class TestResolveSeek:
    """``resolve_seek`` follows ``io.BytesIO`` and asks for the end only on ``SEEK_END``."""

    def _end(self) -> int:
        self.end_calls += 1
        return 10

    def setup_method(self) -> None:
        self.end_calls = 0

    @pytest.mark.parametrize(
        ("offset", "whence", "expected"),
        [
            (7, io.SEEK_SET, 7),
            (99, io.SEEK_SET, 99),
            (3, io.SEEK_CUR, 7),
            (-4, io.SEEK_CUR, 0),
            (-99, io.SEEK_CUR, 0),
        ],
    )
    def test_set_and_cur_never_ask_for_the_end(
        self, offset: int, whence: int, expected: int
    ) -> None:
        assert resolve_seek(offset, whence, pos=4, end=self._end) == expected
        assert self.end_calls == 0

    @pytest.mark.parametrize(
        ("offset", "expected"), [(0, 10), (-3, 7), (5, 15), (-99, 0)]
    )
    def test_end_is_asked_once(self, offset: int, expected: int) -> None:
        assert resolve_seek(offset, io.SEEK_END, pos=4, end=self._end) == expected
        assert self.end_calls == 1

    def test_negative_seek_set_raises(self) -> None:
        with pytest.raises(ValueError, match="Negative seek position -1"):
            resolve_seek(-1, io.SEEK_SET, pos=4, end=self._end)
        assert self.end_calls == 0

    def test_invalid_whence_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid whence: 3"):
            resolve_seek(0, 3, pos=4, end=self._end)
        assert self.end_calls == 0

    @pytest.mark.parametrize(
        "args", [(1.5, io.SEEK_SET), (None, io.SEEK_CUR), ("1", io.SEEK_END), (0, 1.5)]
    )
    def test_non_integer_raises_type_error_as_bytesio(
        self, args: tuple[object, object]
    ) -> None:
        # Untyped handles: the arguments are wrong on purpose.
        resolve: Callable[..., int] = resolve_seek
        reference: Callable[..., int] = io.BytesIO().seek
        with pytest.raises(TypeError) as expected:
            reference(*args)
        with pytest.raises(TypeError) as excinfo:
            resolve(*args, pos=4, end=self._end)
        if CPYTHON:  # PyPy's io.BytesIO words it differently
            assert str(excinfo.value) == str(expected.value)
        assert self.end_calls == 0

    def test_int_subclass_is_its_int_value(self) -> None:
        resolved = resolve_seek(True, io.SEEK_SET, pos=4, end=self._end)
        assert resolved == 1
        assert type(resolved) is int


class TestCheckSeekArgs:
    def test_returns_exact_ints(self) -> None:
        assert check_seek_args(True, io.SEEK_CUR) == (1, io.SEEK_CUR)
        offset, whence = check_seek_args(-5, True)
        assert (offset, whence) == (-5, io.SEEK_CUR)
        assert type(offset) is int and type(whence) is int

    def test_negative_seek_set_raises(self) -> None:
        with pytest.raises(ValueError, match="Negative seek position -1"):
            check_seek_args(-1, io.SEEK_SET)

    def test_negative_relative_offset_is_left_to_the_resolver(self) -> None:
        assert check_seek_args(-1, io.SEEK_END) == (-1, io.SEEK_END)

    def test_invalid_whence_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid whence: 3"):
            check_seek_args(0, 3)


class TestCheckReadSize:
    @pytest.mark.parametrize(("n", "expected"), [(None, -1), (-5, -5), (0, 0), (7, 7)])
    def test_integers_and_none(self, n: int | None, expected: int) -> None:
        assert check_read_size(n) == expected

    def test_bool_is_its_int_value(self) -> None:
        size = check_read_size(True)
        assert size == 1 and type(size) is int

    @pytest.mark.parametrize("bad", [sys.maxsize + 1, 2**70, -sys.maxsize - 2])
    def test_int_outside_ssize_t_raises_overflow_error_as_bytesio(
        self, bad: int
    ) -> None:
        with pytest.raises(OverflowError) as expected:
            io.BytesIO(b"abc").read(bad)
        with pytest.raises(OverflowError) as excinfo:
            check_read_size(bad)
        if CPYTHON:  # PyPy words it differently
            assert str(excinfo.value) == str(expected.value)

    @pytest.mark.parametrize("edge", [sys.maxsize, -sys.maxsize - 1])
    def test_ssize_t_bounds_pass(self, edge: int) -> None:
        assert check_read_size(edge) == edge

    @pytest.mark.parametrize("bad", [1.5, "3", b"3", 2.0])
    def test_non_integer_raises_type_error_as_bytesio(self, bad: object) -> None:
        # Untyped handles: the argument is wrong on purpose.
        check: Callable[..., int] = check_read_size
        with pytest.raises(TypeError) as expected:
            io.BytesIO(b"abc").read(bad)  # type: ignore[arg-type]
        with pytest.raises(TypeError) as excinfo:
            check(bad)
        if CPYTHON:  # PyPy words it differently
            assert str(excinfo.value) == str(expected.value)
