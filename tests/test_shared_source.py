"""Unit tests for ``SharedSource`` (``streams/streamtools/shared.py``).

The primitive is the concurrent-open foundation for Phase 6 native readers, so it gets
focused coverage (per CONTRIBUTING's narrow exception for stream primitives): interleaved
single-thread reads, cross-thread data-correctness under the lock, and stdlib-shaped
misuse errors.
"""

from __future__ import annotations

import io
import threading
from pathlib import Path

import pytest

from archivey.internal.streams.streamtools import (
    SharedSource,
    SharedView,
    SlicingStream,
)

DATA = b"0123456789abcdefghijklmnopqrstuvwxyz"


class TestSharedSourceInterleaved:
    def test_adjacent_views_interleaved_partial_reads(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        left = shared.view(0, 10)  # "0123456789"
        right = shared.view(10, 10)  # "abcdefghij"

        # Shuffled partial-read interleaving: neither view may see the other's bytes.
        assert left.read(3) == b"012"
        assert right.read(4) == b"abcd"
        assert left.read(2) == b"34"
        assert right.read(3) == b"efg"
        assert left.read() == b"56789"
        assert right.read() == b"hij"
        assert left.read(1) == b""
        assert right.read(1) == b""

    def test_overlapping_views_interleaved(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        a = shared.view(5, 10)  # DATA[5:15]
        b = shared.view(8, 10)  # DATA[8:18]

        assert a.read(4) == DATA[5:9]
        assert b.read(4) == DATA[8:12]
        assert a.read() == DATA[9:15]
        assert b.read() == DATA[12:18]

    @pytest.mark.parametrize(
        ("regions", "chunk"),
        [
            (((0, 8), (8, 8), (16, 8)), 3),
            (((0, 10), (20, 10)), 1),
            (((5, 5), (15, 5), (25, 5)), 2),
        ],
    )
    def test_parametrized_non_overlapping_interleave(
        self,
        regions: tuple[tuple[int, int], ...],
        chunk: int,
    ) -> None:
        # Plain parametrized stand-in for a Hypothesis property (hypothesis-property-tests
        # has not landed); random non-overlapping regions × chunked interleaving.
        shared = SharedSource(io.BytesIO(DATA))
        views = [shared.view(start, length) for start, length in regions]
        expected = [DATA[start : start + length] for start, length in regions]
        got = [bytearray() for _ in regions]

        active = list(range(len(views)))
        while active:
            for i in list(active):
                piece = views[i].read(chunk)
                if not piece:
                    active.remove(i)
                else:
                    got[i].extend(piece)

        assert [bytes(g) for g in got] == expected


class TestSharedSourceThreads:
    def test_two_threads_distinct_views_byte_exact(self) -> None:
        # Deterministic: each thread reads its whole view in one go under the lock;
        # assert byte-exact output (data-correct, not parallel).
        payload = bytes(range(256)) * 64  # 16 KiB
        shared = SharedSource(io.BytesIO(payload))
        mid = len(payload) // 2
        left_view = shared.view(0, mid)
        right_view = shared.view(mid, len(payload) - mid)

        results: list[bytes | None] = [None, None]
        errors: list[BaseException] = []

        def worker(index: int, view: object, expected: bytes) -> None:
            try:
                # Many small reads to exercise lock contention without flakiness.
                chunks = bytearray()
                while True:
                    piece = view.read(17)  # type: ignore[attr-defined]
                    if not piece:
                        break
                    chunks.extend(piece)
                results[index] = bytes(chunks)
                assert results[index] == expected
            except BaseException as exc:  # noqa: BLE001 — collect for the main thread
                errors.append(exc)

        t1 = threading.Thread(target=worker, args=(0, left_view, payload[:mid]))
        t2 = threading.Thread(target=worker, args=(1, right_view, payload[mid:]))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == []
        assert results[0] == payload[:mid]
        assert results[1] == payload[mid:]


class TestSharedSourceMisuse:
    def test_read_after_view_close_raises(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        view = shared.view(0, 10)
        view.close()
        with pytest.raises(ValueError, match="closed"):
            view.read(1)

    def test_read_after_source_close_raises(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        view = shared.view(0, 10)
        shared.close()
        with pytest.raises(ValueError, match="closed"):
            view.read(1)

    def test_seek_after_close_raises(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        view = shared.view(0, 10)
        view.close()
        with pytest.raises(ValueError, match="closed"):
            view.seek(0)

    def test_out_of_bounds_view_clamps_to_available(self) -> None:
        # Like a real stream / SlicingStream: a view past EOF is readable but short,
        # so a backend opening a member from a truncated archive still gets data.
        shared = SharedSource(io.BytesIO(DATA))
        oversized = shared.view(0, len(DATA) + 10)
        assert oversized.size == len(DATA)
        assert oversized.read() == DATA
        past_eof = shared.view(len(DATA) + 5, 1)
        assert past_eof.size == 0
        assert past_eof.read() == b""
        # Start inside, length past EOF: clamp length.
        partial = shared.view(len(DATA) - 3, 100)
        assert partial.size == 3
        assert partial.read() == DATA[-3:]

    def test_direct_slice_and_view_agree_on_over_declared_length(self) -> None:
        payload = io.BytesIO(DATA[:10])
        direct = SlicingStream(io.BytesIO(DATA[:10]), start=0, length=999)
        via_view = SharedSource(payload).view(0, 999)
        assert direct.size == via_view.size == 10
        assert isinstance(via_view, SharedView)
        assert isinstance(via_view, SlicingStream)

    def test_view_clamps_over_declared_length_through_seek_counting_wrap(self) -> None:
        # wrap_handle installs SeekCountingStream; source_byte_size on that wrapper
        # used to return None, so construction clamp was a no-op and .size stayed 999.
        from archivey.internal.measurement import SeekCounter
        from archivey.internal.streams.counting import SeekCountingStream

        shared = SharedSource(
            io.BytesIO(DATA[:10]),
            wrap_handle=lambda h: SeekCountingStream(h, SeekCounter()),
        )
        assert shared.size == 10
        view = shared.view(0, 999)
        assert view.size == 10
        assert view.read() == DATA[:10]

    def test_repeated_views_do_not_seek_buffered_file(self, tmp_path: Path) -> None:
        # Construction clamp used SEEK_END on BufferedReader, which discards its
        # buffer. SharedSource.view must not move the raw FileIO at all.
        class CountingFileIO(io.FileIO):
            seeks = 0

            def seek(self, o: int, w: int = 0) -> int:  # type: ignore[override]
                type(self).seeks += 1
                return super().seek(o, w)

        path = tmp_path / "blob.bin"
        path.write_bytes(DATA * 20)
        raw = CountingFileIO(str(path), "rb")
        try:
            buf = io.BufferedReader(raw)
            shared = SharedSource(buf)
            CountingFileIO.seeks = 0
            for i in range(32):
                view = shared.view(i, 1)
                assert view.size == 1
            assert CountingFileIO.seeks == 0
        finally:
            raw.close()

    def test_view_does_not_close_source(self) -> None:
        buf = io.BytesIO(DATA)
        shared = SharedSource(buf)
        view = shared.view(0, 5)
        view.close()
        # Source still usable; a fresh view still reads.
        assert shared.view(0, 5).read() == DATA[:5]
        assert not buf.closed

    def test_a_path_source_is_borrowed_and_closed_by_its_owner(
        self, tmp_path: Path
    ) -> None:
        """A path reaches ``SharedSource`` as an ``ArchiveSource``, which owns the handle.

        ``SharedSource`` used to open and own a path itself; the handle is now the
        source's, so closing the shared source leaves it to the reader that owns it.
        """
        from archivey.internal.source import ArchiveSource

        path = tmp_path / "blob.bin"
        path.write_bytes(DATA)
        source = ArchiveSource.for_path(path)
        shared = SharedSource(source)
        assert shared.view(10, 5).read() == DATA[10:15]
        shared.close()
        with pytest.raises(ValueError, match="closed"):
            shared.view(0, 1)
        assert not source.closed
        source.close()
        assert source.closed

    def test_relative_seek_underflow_clamps_like_bytesio(self) -> None:
        # BytesIO clamps a SEEK_CUR/SEEK_END result past the origin to 0 (only a negative
        # SEEK_SET raises); backwards-from-end probes on a short source (e.g. ZipFile's
        # EOCD probe) rely on the clamp rather than a raw ValueError.
        shared = SharedSource(io.BytesIO(DATA[:10]))
        view = shared.view(0)
        assert view.seek(-100, io.SEEK_END) == 0
        assert view.tell() == 0
        view.seek(3)
        assert view.seek(-100, io.SEEK_CUR) == 0
        assert view.tell() == 0

    def test_seek_set_negative_still_raises(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        view = shared.view(0, 10)
        with pytest.raises(ValueError, match="Negative seek position"):
            view.seek(-1)


class TestSharedSourceReadAt:
    def test_read_at_does_not_move_an_open_view(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        view = shared.view(0, 10)
        assert view.read(3) == b"012"
        assert shared.read_at(20, 4) == DATA[20:24]
        assert view.read(3) == b"345"
        assert shared.read_at(0, 2) == b"01"
        assert view.read() == b"6789"

    def test_read_at_is_short_only_at_the_end(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        assert shared.read_at(len(DATA) - 3, 10) == DATA[-3:]
        assert shared.read_at(len(DATA) + 5, 10) == b""
        assert shared.read_at(4, 0) == b""

    def test_read_at_asks_again_after_a_short_raw_read(self) -> None:
        class Trickle(io.RawIOBase):
            """Returns at most 3 bytes a call, as a raw stream may."""

            def __init__(self) -> None:
                self._inner = io.BytesIO(DATA)

            def readable(self) -> bool:
                return True

            def seekable(self) -> bool:
                return True

            def seek(self, offset: int, whence: int = 0) -> int:
                return self._inner.seek(offset, whence)

            def tell(self) -> int:
                return self._inner.tell()

            def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
                data = self._inner.read(min(3, len(buffer)))
                buffer[: len(data)] = data
                return len(data)

        shared = SharedSource(Trickle())  # type: ignore[arg-type]
        assert shared.read_at(5, 10) == DATA[5:15]

    def test_read_at_refuses_negative_and_closed(self) -> None:
        shared = SharedSource(io.BytesIO(DATA))
        with pytest.raises(ValueError, match="negative"):
            shared.read_at(-1, 2)
        with pytest.raises(ValueError, match="negative"):
            shared.read_at(0, -2)
        shared.close()
        with pytest.raises(ValueError, match="closed"):
            shared.read_at(0, 2)

    def test_read_at_from_threads_is_byte_exact(self) -> None:
        payload = bytes(range(256)) * 64
        shared = SharedSource(io.BytesIO(payload))
        errors: list[BaseException] = []

        def worker(step: int) -> None:
            try:
                for offset in range(0, len(payload) - 17, step):
                    assert shared.read_at(offset, 17) == payload[offset : offset + 17]
            except BaseException as exc:  # noqa: BLE001 — collect for the main thread
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(s,)) for s in (7, 11, 13)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
