"""Unit tests for ``SlicingStream`` and ``fix_stream_start_position`` (``streams/streamtools/slice.py``).

These are low-level building blocks every container backend relies on, so they get focused
corner-case coverage (per CONTRIBUTING's narrow exception for stream primitives).
"""

from __future__ import annotations

import io
import subprocess
import sys
import threading
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey.exceptions import TruncatedError
from archivey.internal.measurement import SeekCounter
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.counting import SeekCountingStream
from archivey.internal.streams.streamtools import (
    SharedView,
    SlicingStream,
    fix_stream_start_position,
)
from tests.streams_util import NonSeekableBytesIO, ShortReadBytesIO

DATA = b"0123456789abcdefghijklmnopqrstuvwxyz"


class _DeliverThenRaise(io.RawIOBase):
    """Mimics DecompressorStream: short prefix, then raise on the empty read."""

    def __init__(self, prefix: bytes) -> None:
        self._prefix = prefix
        self._delivered = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        if not self._delivered:
            self._delivered = True
            return self._prefix
        raise TruncatedError("stream ended before the declared size")


class TestSlicingStream:
    def test_read_with_start_and_length(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=5, length=10)
        assert sliced.read(3) == b"567"
        assert sliced.tell() == 3
        assert sliced.read() == b"89abcde"
        assert sliced.tell() == 10
        assert sliced.read(5) == b""

    def test_read_start_only_reads_to_end(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=10)
        assert sliced.read() == DATA[10:]

    def test_read_length_only_from_current_position(self) -> None:
        underlying = io.BytesIO(DATA)
        underlying.seek(7)
        sliced = SlicingStream(underlying, length=10)
        assert sliced.read() == DATA[7:17]
        assert sliced.tell() == 10

    def test_read_spanning_then_clamped_at_length(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=0, length=20)
        assert sliced.read(8) == DATA[:8]
        assert sliced.read(100) == DATA[8:20]  # clamped to the slice end
        assert sliced.read(1) == b""

    def test_read_zero_returns_empty(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=0, length=10)
        assert sliced.read(0) == b""
        assert sliced.tell() == 0

    def test_empty_slice(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=5, length=0)
        assert sliced.read() == b""
        assert sliced.read(10) == b""

    def test_slice_larger_than_underlying(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA[:10]), start=0, length=20)
        assert sliced.read() == DATA[:10]
        assert sliced.read(5) == b""

    def test_readinto(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=5, length=10)
        buf = bytearray(4)
        n = sliced.readinto(buf)
        assert n == 4
        assert bytes(buf) == DATA[5:9]

    def test_seek_set_cur_end(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=10, length=10)
        assert sliced.seek(3) == 3
        assert sliced.read(2) == DATA[13:15]
        assert sliced.seek(-2, io.SEEK_CUR) == 3
        assert sliced.read(4) == DATA[13:17]
        assert sliced.seek(-1, io.SEEK_END) == 9
        assert sliced.read(5) == DATA[19:20]

    def test_seek_past_end_then_empty_read(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=10, length=10)
        assert sliced.seek(100) == 100
        assert sliced.read(1) == b""

    def test_seek_negative_raises(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=10, length=10)
        with pytest.raises(ValueError, match="Negative seek position"):
            sliced.seek(-5)

    def test_seek_cur_underflow_clamps_like_bytesio(self) -> None:
        # BytesIO clamps SEEK_CUR/SEEK_END underflow to the origin; only SEEK_SET raises.
        sliced = SlicingStream(io.BytesIO(DATA), start=10, length=10)
        assert sliced.seek(-100, io.SEEK_CUR) == 0
        assert sliced.tell() == 0
        assert sliced.seek(-100, io.SEEK_END) == 0

    def test_seek_end_no_length_zero_offset(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=10)
        assert sliced.seek(0, io.SEEK_END) == len(DATA) - 10
        assert sliced.read(1) == b""

    def test_seek_end_no_length_nonzero_offset(self) -> None:
        # With no declared length the slice ends at the underlying EOF; SEEK_END with a
        # non-zero offset probes that end on demand and positions relative to it.
        sliced = SlicingStream(io.BytesIO(DATA), start=5)
        slice_len = len(DATA) - 5
        assert sliced.seek(-3, io.SEEK_END) == slice_len - 3
        assert sliced.read() == DATA[-3:]
        assert (
            sliced.seek(2, io.SEEK_END) == slice_len + 2
        )  # past-end allowed, like BytesIO
        assert sliced.read(1) == b""

    def test_non_seekable_no_start(self) -> None:
        sliced = SlicingStream(NonSeekableBytesIO(DATA), length=15)
        assert sliced.read(5) == DATA[:5]
        assert sliced.read() == DATA[5:15]
        assert not sliced.seekable()

    def test_non_seekable_with_start_rejected(self) -> None:
        with pytest.raises(ValueError, match="Cannot slice a non-seekable stream"):
            SlicingStream(NonSeekableBytesIO(DATA), start=5, length=10)

    def test_seek_on_non_seekable_raises(self) -> None:
        sliced = SlicingStream(NonSeekableBytesIO(DATA), length=10)
        with pytest.raises(io.UnsupportedOperation, match="seek on non-seekable"):
            sliced.seek(5)

    def test_sized_read_is_full_count_over_a_full_count_inner(self) -> None:
        """``read(n)`` returns ``n`` when the inner is full-count — the archive-source case.

        Every slice in the backends views a full-count inner: a ``SharedSource`` handle
        (``open()``'s ``BufferedReader``, or a caller stream behind an
        ``ArchiveSource``), or a decoder. A raw stream that shorts mid-stream
        gets that full-count wrapper in front rather than a gathering loop inside the view — see
        ``test_sized_read_over_a_raw_short_inner_stops_on_short`` and ADR 0014.
        """
        sliced = SlicingStream(
            ArchiveSource.for_stream(ShortReadBytesIO(DATA)), start=5, length=10
        )
        assert sliced.read(7) == DATA[5:12]
        assert sliced.tell() == 7
        # The bound still clamps: only the remaining 3 bytes come back, then EOF.
        assert sliced.read(7) == DATA[12:15]
        assert sliced.read(7) == b""

    def test_sized_read_over_a_raw_short_inner_stops_on_short(self) -> None:
        """A sized read stops on a short non-empty inner return, by ADR 0014.

        Deliberate: over a decoder, continuing past a short would pull the deferred
        ``TruncatedError`` into the same call (see
        ``test_sized_read_preserves_deliver_then_raise``). A RawIO that shorts mid-stream
        is fixed with a full-count wrapper in front, not by gathering here.
        """
        sliced = SlicingStream(ShortReadBytesIO(DATA), start=5, length=10)
        assert sliced.read(7) == DATA[5:6]

    def test_sized_read_preserves_deliver_then_raise(self) -> None:
        """A decoder's recoverable prefix must survive the view (ADR 0014).

        ``DecompressorStream`` deferred truncation returns a short prefix on the
        completing call and raises on the *next* empty ``read``. A view that kept pulling
        after the short would collapse that into one raising call and drop the prefix —
        which is exactly what a truncated 7z member read through
        ``SlicingStream(folder_stream, length=size)`` would lose.
        """
        prefix = DATA[:4]
        sliced = SlicingStream(_DeliverThenRaise(prefix), length=20)

        assert sliced.read(20) == prefix  # prefix delivered, not swallowed
        with pytest.raises(TruncatedError):
            sliced.read(20)

    def test_bounded_drain_pulls_deferred_truncation(self) -> None:
        """Bounded ``read(-1)`` uses ``read_exact``; a deliver-then-raise prefix is lost.

        Contrast ``test_sized_read_preserves_deliver_then_raise``: sized ``read(n)``
        returns the prefix. Drain is the complete-stream shape and will not be
        called again, so it gathers. Pinned so ``read_exact``'s docstring and the
        ``SlicingStream.read`` comment are not the only record of the asymmetry.
        """
        prefix = DATA[:4]
        sliced = SlicingStream(_DeliverThenRaise(prefix), length=20)
        with pytest.raises(TruncatedError):
            sliced.read(-1)

    def test_undeclared_length_drain_stays_pass_through(self) -> None:
        """Pairs with ``test_bounded_drain_pulls_deferred_truncation``.

        Same source, same ``read(-1)``, opposite outcome; the only difference is
        whether the caller passed a length. The construction clamp must not flip
        an undeclared drain onto ``read_exact``.
        """

        class _SeekableDeliverThenRaise(io.RawIOBase):
            def __init__(self, prefix: bytes, declared: int) -> None:
                self._prefix = prefix
                self._declared = declared
                self._delivered = False

            def readable(self) -> bool:
                return True

            def seekable(self) -> bool:
                return True

            def seek(self, offset: int, whence: int = 0) -> int:  # type: ignore[override]
                return 0

            def tell(self) -> int:
                return 0

            @property
            def size(self) -> int:
                return self._declared

            def read(self, size: int = -1) -> bytes:  # type: ignore[override]
                if not self._delivered:
                    self._delivered = True
                    return self._prefix
                raise TruncatedError("stream ended before the declared size")

        prefix = DATA[:4]
        sliced = SlicingStream(_SeekableDeliverThenRaise(prefix, 20))
        assert sliced.read(-1) == prefix
        with pytest.raises(TruncatedError):
            sliced.read(-1)

        # independent_view must forward the declaration, not the clamped bound —
        # a sibling of an undeclared view must also drain pass-through.
        lock = threading.Lock()
        parent = SharedView(_SeekableDeliverThenRaise(prefix, 20), start=0, lock=lock)
        sibling = parent.independent_view()
        # Same one-shot inner as ``parent``; do not drain it a second time.
        assert parent._declared_length is None
        assert sibling._declared_length is None
        assert sibling.tell() == 0

    def test_bounded_read_all_gathers_across_short_reads(self) -> None:
        """``read()`` on a bounded slice must gather across short sized reads.

        A bounded slice must not issue an unbounded ``read(-1)`` on the inner
        stream (that would overshoot into the next member). Short positive
        ``read(n)`` results are legal and must be retried until the slice is
        drained; trailing bytes past the slice must remain unread.
        """

        class _Drip(io.RawIOBase):
            def __init__(self, data: bytes) -> None:
                self._data = data
                self.pos = 0

            def readable(self) -> bool:
                return True

            def read(self, size: int = -1) -> bytes:  # type: ignore[override]
                # Bounded SlicingStream must never ask for an unbounded drain.
                if size < 0:
                    raise AssertionError(
                        "bounded SlicingStream must not issue unbounded read(-1)"
                    )
                if self.pos >= len(self._data) or size == 0:
                    return b""
                # One byte at a time so a single read(remaining) would truncate.
                chunk = self._data[self.pos : self.pos + 1]
                self.pos += len(chunk)
                return chunk

        slice_data = DATA[5:15]
        trailing = DATA[15:25]
        inner = _Drip(slice_data + trailing)
        sliced = SlicingStream(inner, length=len(slice_data))

        assert sliced.read() == slice_data
        assert sliced.tell() == len(slice_data)
        assert sliced.read(1) == b""
        assert inner.pos == len(slice_data)
        # Trailing bytes past the slice are still available on the inner stream.
        leftover = bytearray()
        while len(leftover) < len(trailing):
            chunk = inner.read(len(trailing) - len(leftover))
            assert chunk, "inner stream ended before trailing payload"
            leftover.extend(chunk)
        assert bytes(leftover) == trailing
        assert inner.pos == len(slice_data) + len(trailing)


class TestFixStreamStartPosition:
    def test_at_zero_returns_same(self) -> None:
        stream = io.BytesIO(DATA)
        assert fix_stream_start_position(stream) is stream

    def test_midstream_slices(self) -> None:
        stream = io.BytesIO(DATA)
        stream.seek(10)
        fixed = fix_stream_start_position(stream)
        assert fixed is not stream
        assert fixed.tell() == 0
        assert fixed.read(5) == DATA[10:15]

    def test_midstream_slice_has_no_name(self, tmp_path: Path) -> None:
        # fix_stream_start_position wraps mid-positioned streams; see
        # TestSlicingStreamName.test_name_not_forwarded_from_underlying for why name
        # must stay absent (pycdlib Windows + reopen-by-name footgun).
        path = tmp_path / "data.bin"
        path.write_bytes(DATA)
        with open(path, "rb") as stream:
            stream.seek(10)
            fixed = fix_stream_start_position(stream)
            assert not hasattr(fixed, "name")

    def test_non_seekable_passthrough(self) -> None:
        stream = NonSeekableBytesIO(DATA)
        assert fix_stream_start_position(stream) is stream


class TestSlicingStreamName:
    def test_name_not_forwarded_from_underlying(self, tmp_path: Path) -> None:
        """SlicingStream must not expose ``name``, even when the underlying stream has one.

        Two independent reasons — do not "fix" this by forwarding ``underlying.name``
        without considering both:

        1. **View semantics.** A slice remaps the origin (``tell()==0`` is mid-file on the
           underlying). ``stream.name`` conventionally means "reopen this path from byte 0";
           forwarding would mislead libraries that stat or ``open()`` by name into reading
           the unsliced file (embedded-archive / ``fix_stream_start_position`` cases).

        2. **Stub vs absent.** Our wrappers inherit ``typing.BinaryIO``'s stub ``name``
           (``None`` at runtime). ``hasattr(stream, 'name')`` must stay ``False`` on
           nameless views so consumers like pycdlib's Windows raw-device check
           (``fp.name.startswith(r'\\.\')``) do not crash on ``None``. Real file objects
           and ``BytesIO`` already behave this way; the slice wrapper must match.

        Callers that need a path for errors/metadata should use ``source_name()`` on the
        *original* source before wrapping (``open_archive`` captures ``archive_name`` that
        way). Logical slice length is ``SlicingStream.size``, not ``name``.
        """
        path = tmp_path / "data.bin"
        path.write_bytes(DATA)
        with open(path, "rb") as underlying:
            assert underlying.name == str(path)
            sliced = SlicingStream(underlying, start=5, length=10)
            assert not hasattr(sliced, "name")


class TestSlicingStreamSize:
    def test_size_with_declared_length(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=5, length=7)
        assert sliced.size == 7

    def test_size_derived_from_cheap_underlying(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=5)
        assert sliced.size == len(DATA) - 5

    def test_size_none_when_underlying_unknowable(self) -> None:
        sliced = SlicingStream(NonSeekableBytesIO(DATA), length=None)
        assert sliced.size is None

    def test_over_declared_length_is_clamped_to_source(self) -> None:
        # Direct construction used to report the declared length even when the
        # source was shorter (SharedSource.view already clamped). Truncated-archive
        # members take this door; size is the ratio-guard denominator.
        short = io.BytesIO(DATA[:10])
        sliced = SlicingStream(short, start=0, length=999)
        assert sliced.size == 10
        assert sliced.read() == DATA[:10]


class TestSlicingStreamConstruction:
    def test_single_consumer_does_not_leave_handle_at_start(self) -> None:
        """Construction must not reposition the caller's handle to ``start``.

        The historical eager seek left the handle at ``start`` before any read.
        A cheap size probe (metadata: ``fstat`` / ``getbuffer``, not ``SEEK_END``)
        is allowed; the handle must end where the caller left it.
        """

        class _Ops(io.BytesIO):
            def __init__(self, data: bytes) -> None:
                super().__init__(data)
                self.ops: list[tuple[object, ...]] = []

            def tell(self) -> int:
                pos = super().tell()
                self.ops.append(("tell", pos))
                return pos

            def seek(self, offset: int, whence: int = 0) -> int:  # type: ignore[override]
                result = super().seek(offset, whence)
                self.ops.append(("seek", offset, whence))
                return result

        underlying = _Ops(DATA)
        underlying.seek(7)
        underlying.ops.clear()
        sliced = SlicingStream(underlying, start=2, length=4)
        assert underlying.tell() == 7
        assert ("seek", 2, 0) not in underlying.ops
        assert sliced.read() == DATA[2:6]


class TestSlicingStreamOwnsInner:
    class _Tracked(io.BytesIO):
        closed_flag = False

        def close(self) -> None:
            self.closed_flag = True
            super().close()

    def test_default_is_non_owning(self) -> None:
        underlying = self._Tracked(DATA)
        SlicingStream(underlying, start=0, length=5).close()
        assert underlying.closed_flag is False

    def test_owns_inner_closes_underlying(self) -> None:
        underlying = self._Tracked(DATA)
        SlicingStream(underlying, start=0, length=5, owns_inner=True).close()
        assert underlying.closed_flag is True


class TestSharedViewConstruction:
    """Locked views must not probe the shared handle unlocked at construction.

    ``io.BufferedReader.tell`` is not thread-safe. A concurrent unlocked ``tell`` while
    another thread holds the lock for seek+read corrupts the buffer — the ZIP
    ``MemberStreams.CONCURRENT`` CRC race. A cheap size probe (to clamp ``length``)
    may run, but only under the lock, and must not ``SEEK_END`` a ``BufferedReader``.
    """

    def test_clamps_over_declared_length_on_seek_counting_stream(self) -> None:
        # ZIP _raw_member_stream constructs SharedView on ZipFile.fp, which is
        # the seek-counter wrapper when measurement is on. Clamp must not depend
        # on SharedSource._size.
        wrapped = SeekCountingStream(io.BytesIO(DATA[:10]), SeekCounter())
        view = SharedView(wrapped, start=0, length=999, lock=threading.Lock())
        assert view.size == 10
        assert view.read() == DATA[:10]

    def test_init_on_buffered_file_does_not_seek(self, tmp_path: Path) -> None:
        class CountingFileIO(io.FileIO):
            seeks = 0

            def seek(self, o: int, w: int = 0) -> int:  # type: ignore[override]
                type(self).seeks += 1
                return super().seek(o, w)

        path = tmp_path / "blob.bin"
        path.write_bytes(DATA)
        raw = CountingFileIO(str(path), "rb")
        try:
            buf = io.BufferedReader(raw)
            CountingFileIO.seeks = 0
            view = SharedView(buf, start=0, length=4, lock=threading.Lock())
            assert view.size == 4
            assert CountingFileIO.seeks == 0
        finally:
            raw.close()

    def test_non_seekable_rejected_at_init(self) -> None:
        with pytest.raises(ValueError, match="seekable"):
            SharedView(NonSeekableBytesIO(b"x"), lock=threading.Lock())

    def test_non_seekable_rejected_init_does_not_trip_del(self) -> None:
        # F2 raised before ``_owns_inner`` was set; ``IOBase.__del__`` then hit
        # ``AttributeError`` inside ``close``. CPython only reports that under
        # ``-X dev`` (3.11+: otherwise destructor close() errors are swallowed),
        # so the pin runs in a child with that flag.
        script = r"""
import gc, io, sys, threading
from archivey.internal.streams.streamtools import SharedView

class NonSeekable(io.BytesIO):
    def seekable(self) -> bool:
        return False

caught: list[BaseException] = []
def hook(args: object) -> None:
    caught.append(args.exc_value)  # type: ignore[attr-defined]
sys.unraisablehook = hook
try:
    SharedView(NonSeekable(b"x"), lock=threading.Lock())
except ValueError:
    pass
else:
    raise SystemExit("expected ValueError")
gc.collect()
if caught:
    raise SystemExit(f"unraisable: {caught[0]!r}")
"""
        proc = subprocess.run(
            [sys.executable, "-X", "dev", "-c", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_slicing_stream_independent_view_raises(self) -> None:
        sliced = SlicingStream(io.BytesIO(DATA), start=0, length=5)
        with pytest.raises(io.UnsupportedOperation, match="locked SharedSource view"):
            sliced.independent_view()

    def test_independent_view_is_lock_sharing_sibling_at_offset_zero(self) -> None:
        lock = threading.Lock()
        view = SharedView(io.BytesIO(DATA), start=5, length=4, lock=lock)
        assert view.read(2) == DATA[5:7]
        sibling = view.independent_view()
        assert sibling.tell() == 0
        assert sibling.size == 4
        assert sibling.read() == DATA[5:9]
        assert view.read() == DATA[7:9]
        assert sibling._io_guard is lock

    def test_locked_with_start_does_not_call_tell_unlocked(self) -> None:
        lock = threading.Lock()

        class _NoUnlockedTell(io.BytesIO):
            def tell(self) -> int:
                if not lock.locked():
                    raise AssertionError("SharedView must not tell() unlocked at init")
                return super().tell()

            def seek(self, offset: int, whence: int = 0) -> int:  # type: ignore[override]
                if not lock.locked():
                    raise AssertionError("SharedView must not seek() unlocked at init")
                return super().seek(offset, whence)

        underlying = _NoUnlockedTell(DATA)
        sliced = SharedView(underlying, start=5, length=4, lock=lock)
        assert sliced.read() == DATA[5:9]

    def test_locked_without_start_tells_under_lock(self) -> None:
        lock = threading.Lock()
        held: list[bool] = []

        class _TellUnderLock(io.BytesIO):
            def tell(self) -> int:
                held.append(lock.locked())
                return super().tell()

        underlying = _TellUnderLock(DATA)
        underlying.seek(7)
        sliced = SharedView(underlying, length=3, lock=lock)
        assert held
        assert all(held)
        assert sliced.read() == DATA[7:10]

    def test_concurrent_locked_views_over_zipfile_fp(self, tmp_path: Path) -> None:
        """Stress concurrent locked views on stdlib ``ZipFile.fp`` (a BufferedReader)."""
        path = tmp_path / "a.zip"
        payloads = {f"f{i}.txt": f"payload-{i}".encode() * 20 for i in range(16)}
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in payloads.items():
                zf.writestr(name, data)

        # Enough trials that unlocked-init construction fails reliably on this fixture.
        for _ in range(80):
            with zipfile.ZipFile(path) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                barrier = threading.Barrier(len(infos))
                errors: list[BaseException] = []
                err_lock = threading.Lock()

                def worker(info: zipfile.ZipInfo) -> None:
                    try:
                        barrier.wait(timeout=5)  # noqa: B023 - called within this iteration
                        with zf._lock:
                            fp = zf.fp
                            assert fp is not None
                            saved = fp.tell()
                            try:
                                fp.seek(info.header_offset)
                                header = fp.read(30)
                                name_len = int.from_bytes(header[26:28], "little")
                                extra_len = int.from_bytes(header[28:30], "little")
                                fp.read(name_len)
                                start = info.header_offset + 30 + name_len + extra_len
                            finally:
                                fp.seek(saved)
                        # Construct outside the lock (as ZipReader does after
                        # ``_local_data_region``) — must not unlock-tell the shared fp.
                        raw = SharedView(
                            zf.fp,  # type: ignore[arg-type]
                            start=start,
                            length=info.compress_size,
                            lock=zf._lock,
                        )
                        compressed = raw.read()
                        data = (
                            zlib.decompress(compressed, -15)
                            if info.compress_type == zipfile.ZIP_DEFLATED
                            else compressed
                        )
                        assert data == payloads[info.filename]
                    except BaseException as exc:  # noqa: BLE001
                        with err_lock:  # noqa: B023 - called within this iteration
                            errors.append(exc)  # noqa: B023 - called within this iteration

                threads = [
                    threading.Thread(target=worker, args=(info,)) for info in infos
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=30)
                if errors:
                    raise errors[0]


class _ResumeInner(io.BytesIO):
    """Seekable source whose resume offset is injected, not derived."""

    def __init__(self, data: bytes, resume: int) -> None:
        super().__init__(data)
        self._resume = resume
        self.asked: list[int] = []

    def nearest_resume_offset(self, target: int) -> int:
        self.asked.append(target)
        return self._resume


def _slicing(inner: io.BytesIO, start: int = 10, length: int = 50) -> SlicingStream:
    return SlicingStream(inner, start=start, length=length)


def _shared(inner: io.BytesIO, start: int = 10, length: int = 50) -> SharedView:
    return SharedView(inner, start=start, length=length, lock=threading.Lock())


_MakeView = Callable[[io.BytesIO], SlicingStream]


class TestSliceResumeOffset:
    """``SlicingStream.nearest_resume_offset``, also inherited by ``SharedView``."""

    @pytest.mark.parametrize("make", [_slicing, _shared], ids=["slicing", "shared"])
    def test_translates_inner_resume_into_view_space(self, make: _MakeView) -> None:
        inner = _ResumeInner(b"x" * 100, resume=40)
        view = make(inner)
        assert view.nearest_resume_offset(25) == 30
        assert inner.asked == [35]

    @pytest.mark.parametrize("make", [_slicing, _shared], ids=["slicing", "shared"])
    def test_clamps_inner_resume_before_view_start(self, make: _MakeView) -> None:
        inner = _ResumeInner(b"x" * 100, resume=5)
        view = make(inner)
        assert view.nearest_resume_offset(20) == 0
        assert inner.asked == [30]

    @pytest.mark.parametrize("make", [_slicing, _shared], ids=["slicing", "shared"])
    def test_no_signal_when_inner_has_no_resume_method(self, make: _MakeView) -> None:
        view = make(io.BytesIO(b"x" * 100))
        assert view.nearest_resume_offset(20) is None

    @pytest.mark.parametrize("make", [_slicing, _shared], ids=["slicing", "shared"])
    def test_no_signal_when_inner_returns_none(self, make: _MakeView) -> None:
        class _Declining(io.BytesIO):
            def nearest_resume_offset(self, target: int) -> None:
                return None

        view = make(_Declining(b"x" * 100))
        assert view.nearest_resume_offset(20) is None

    def test_non_seekable_view_has_no_origin_to_translate(self) -> None:
        class _Inner(NonSeekableBytesIO):
            def nearest_resume_offset(self, target: int) -> int:
                return 7

        sliced = SlicingStream(_Inner(b"x" * 20), length=10)
        assert sliced.nearest_resume_offset(4) is None

    @pytest.mark.parametrize("make", [_slicing, _shared], ids=["slicing", "shared"])
    def test_closed_view_raises(self, make: _MakeView) -> None:
        inner = _ResumeInner(b"x" * 100, resume=40)
        view = make(inner)
        view.close()
        with pytest.raises(ValueError, match="closed file"):
            view.nearest_resume_offset(25)

    def test_poisoned_shared_view_raises(self) -> None:
        def boom() -> None:
            raise ValueError("source closed")

        inner = _ResumeInner(b"x" * 100, resume=40)
        view = SharedView(
            inner, start=10, length=50, lock=threading.Lock(), check_open=boom
        )
        with pytest.raises(ValueError, match="source closed"):
            view.nearest_resume_offset(25)

    def test_shared_view_queries_inner_under_the_lock(self) -> None:
        class _RecordingLock:
            def __init__(self) -> None:
                self.entered = 0
                self._lock = threading.Lock()

            def __enter__(self) -> threading.Lock:
                self.entered += 1
                self._lock.__enter__()
                return self._lock

            def __exit__(self, *args: object) -> None:
                self._lock.__exit__(*args)

        lock = _RecordingLock()
        inner = _ResumeInner(b"x" * 100, resume=40)
        view = SharedView(inner, start=10, length=50, lock=lock)
        constructed = lock.entered
        assert view.nearest_resume_offset(25) == 30
        assert lock.entered == constructed + 1

    def test_sequential_reads_seek_once(self) -> None:
        """A handle already at the view's offset is not seeked again.

        A seek to the current position is an lseek once the buffer is empty.
        Skipping it is what this pins: a stream already at the start is not
        seeked at all.
        """
        payload = b"abcdefghij" * 50
        counter = SeekCounter()
        wrapped = SeekCountingStream(io.BytesIO(payload), counter)
        view = SharedView(wrapped, start=0, lock=threading.Lock())
        for _ in range(20):
            assert len(view.read(10)) == 10
        assert counter.count == 0
        assert view.read() == payload[200:]

    def test_interleaved_views_still_reseek(self) -> None:
        payload = bytes(range(256))
        lock = threading.Lock()
        raw = io.BytesIO(payload)
        first = SharedView(raw, start=0, length=10, lock=lock)
        second = SharedView(raw, start=10, length=10, lock=lock)
        assert first.read(4) == payload[0:4]
        assert second.read(4) == payload[10:14]
        assert first.read(4) == payload[4:8]
        assert second.read() == payload[14:20]
