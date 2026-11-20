"""``ArchiveyConfig.on_source_read``: progress through the archive's own file."""

from __future__ import annotations

import io
import lzma
import os
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveyConfig, SourceProgress, open_archive, open_stream
from archivey.internal.read_progress import LOCAL_REPORT_STEP


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[SourceProgress] = []
        self.threads: set[int] = set()

    def __call__(self, progress: SourceProgress) -> None:
        self.calls.append(progress)
        self.threads.add(threading.get_ident())


def _xz_file(tmp_path: Path, size: int) -> Path:
    path = tmp_path / "data.xz"
    # Random bytes do not compress, so the file is about ``size`` bytes long.
    path.write_bytes(lzma.compress(os.urandom(size), preset=0))
    return path


def test_local_stream_reports_about_once_per_mib(tmp_path: Path) -> None:
    path = _xz_file(tmp_path, 5 * LOCAL_REPORT_STEP)
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen)
    with open_stream(path, config=config) as stream:
        while stream.read(1 << 16):
            pass
    size = path.stat().st_size
    assert 5 <= len(seen.calls) <= 8
    assert all(c.requests is None and c.request_done is None for c in seen.calls)
    assert all(c.size == size and c.name == str(path) for c in seen.calls)
    totals = [c.bytes_read for c in seen.calls]
    assert totals == sorted(totals)
    assert seen.calls[-1].position == size
    assert seen.calls[-1].bytes_read >= size
    assert seen.threads == {threading.get_ident()}


def test_local_archive_reports_its_reads(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("big.bin", os.urandom(3 * LOCAL_REPORT_STEP))
    seen = _Recorder()
    with open_archive(path, config=ArchiveyConfig(on_source_read=seen)) as reader:
        reader.read("big.bin")
    assert len(seen.calls) >= 3
    assert seen.calls[-1].bytes_read >= 3 * LOCAL_REPORT_STEP


def test_a_nested_reader_does_not_report(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("x.bin", os.urandom(2 * LOCAL_REPORT_STEP))
    path = tmp_path / "outer.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("inner.zip", inner.getvalue())
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen)
    with open_archive(path, config=config) as outer, outer.open("inner.zip") as member:
        before = len(seen.calls)
        with (
            open_archive(member, parent=outer, streaming=True) as nested,
            nested.stream_members() as members,
        ):
            for _, stream in members:
                if stream is not None:
                    stream.read()
    # Only the outer file's reads report: the nested reader's own source is a member.
    assert all(c.name == str(path) for c in seen.calls[before:])


def test_the_callback_s_exception_propagates(tmp_path: Path) -> None:
    path = _xz_file(tmp_path, 2 * LOCAL_REPORT_STEP)

    class Stop(Exception):
        pass

    def stop(progress: SourceProgress) -> None:
        raise Stop

    with (
        pytest.raises(Stop),
        open_stream(path, config=ArchiveyConfig(on_source_read=stop)) as stream,
    ):
        stream.read()


def test_unset_installs_no_reporter(tmp_path: Path) -> None:
    path = _xz_file(tmp_path, 1000)
    with open_stream(path) as stream:
        stream.read()
        source: Any = stream
        # Nothing reports, and nothing was built to report.
        found = [
            obj
            for obj in vars(source).values()
            if getattr(obj, "_progress", None) is not None
        ]
        assert found == []


def test_a_non_callable_is_refused() -> None:
    with pytest.raises(TypeError, match="on_source_read"):
        ArchiveyConfig(on_source_read=1)  # type: ignore[arg-type]


def test_url_source_reports_each_request() -> None:
    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(30):
            zf.writestr(f"m{i:02d}.bin", bytes([i]) * 50_000)
    fs.pipe("/progress/a.zip", buf.getvalue())
    try:
        seen = _Recorder()
        config = ArchiveyConfig(on_source_read=seen)
        with open_archive(fsspec.open("memory://progress/a.zip"), config=config) as r:
            for m in r.members():
                r.read(m)
        calls = seen.calls
        assert calls
        starts = calls[0::2]
        ends = calls[1::2]
        assert len(starts) == len(ends)
        for n, (start, end) in enumerate(zip(starts, ends, strict=True), 1):
            assert start.request_done is False and start.request_received == 0
            assert end.request_done is True
            assert start.requests == end.requests == n
            assert (start.request_start, start.request_end) == (
                end.request_start,
                end.request_end,
            )
            assert end.request_received == end.request_end - end.request_start
        assert calls[-1].bytes_read == sum(c.request_received or 0 for c in ends)
        assert calls[-1].size == len(buf.getvalue())
    finally:
        fs.rm("/progress", recursive=True)


def test_compressed_tar_reports_to_the_end(tmp_path: Path) -> None:
    import tarfile

    path = tmp_path / "a.tar.gz"
    data = os.urandom(3 * LOCAL_REPORT_STEP)
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("x.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen)
    with (
        open_archive(path, config=config, streaming=True) as reader,
        reader.stream_members() as members,
    ):
        for _, stream in members:
            if stream is not None:
                assert stream.read() == data
    assert len(seen.calls) >= 3
    assert seen.calls[-1].position == path.stat().st_size
