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


class _StopValue(ValueError):
    pass


class _StopOS(OSError):
    pass


def _zip_deflated(tmp_path: Path, size: int) -> Path:
    path = tmp_path / "d.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", os.urandom(size))
    return path


def _bz2_file(tmp_path: Path, size: int) -> Path:
    import bz2

    path = tmp_path / "data.bz2"
    path.write_bytes(bz2.compress(os.urandom(size), 1))
    return path


def _read_zip(path: Path, config: ArchiveyConfig) -> None:
    with open_archive(path, config=config) as reader:
        reader.read("big.bin")


def _read_stream(path: Path, config: ArchiveyConfig) -> None:
    with open_stream(path, config=config) as stream:
        stream.read()


@pytest.mark.parametrize("stop_type", [_StopValue, _StopOS, KeyboardInterrupt])
@pytest.mark.parametrize("shape", ["zip", "bz2", "xz"])
def test_the_callback_s_exception_propagates_unchanged(
    tmp_path: Path, stop_type: type[BaseException], shape: str
) -> None:
    calls = 0

    def stop(progress: SourceProgress) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise stop_type("stop from callback")

    config = ArchiveyConfig(on_source_read=stop)
    size = 3 * LOCAL_REPORT_STEP
    if shape == "zip":
        path = _zip_deflated(tmp_path, size)
        with pytest.raises(stop_type) as caught:
            _read_zip(path, config)
    else:
        path = _bz2_file(tmp_path, size) if shape == "bz2" else _xz_file(tmp_path, size)
        with pytest.raises(stop_type) as caught:
            _read_stream(path, config)
    assert type(caught.value) is stop_type


@pytest.mark.parametrize("shape", ["zip", "bz2"])
def test_accelerated_members_still_report_every_mib(tmp_path: Path, shape: str) -> None:
    # A deflate or bzip2 member of a ZIP is handed to an accelerator as a file region
    # when nothing reports; while reporting it is read through the source.
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen)
    size = 6 * LOCAL_REPORT_STEP
    if shape == "zip":
        path = _zip_deflated(tmp_path, size)
        _read_zip(path, config)
    else:
        path = _bz2_file(tmp_path, size)
        _read_stream(path, config)
    assert seen.calls[-1].bytes_read >= path.stat().st_size - LOCAL_REPORT_STEP
    assert len(seen.calls) >= 5


def test_detection_reads_are_reported(tmp_path: Path) -> None:
    path = _xz_file(tmp_path, 1000)
    seen = _Recorder()
    with open_archive(path, config=ArchiveyConfig(on_source_read=seen)):
        pass
    # Detection read the start of the file (and the xz index at its end) through
    # the source: a file this small reports at its end.
    assert seen.calls
    assert seen.calls[-1].bytes_read >= 12


def test_unset_installs_no_reporter(tmp_path: Path) -> None:
    path = _xz_file(tmp_path, 1000)
    with open_archive(path) as reader:
        source: Any = reader._source  # type: ignore[attr-defined]
        assert source._progress is None
        assert source.codec_path == path
    with open_archive(path, config=ArchiveyConfig(on_source_read=print)) as reader:
        source = reader._source  # type: ignore[attr-defined]
        assert source._progress is not None
        assert source.codec_path is None


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


def test_url_volume_list_reports_offsets_in_the_set() -> None:
    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(10):
            zf.writestr(f"m{i}.bin", bytes([i]) * 100_000)
    data = buf.getvalue()
    half = len(data) // 2
    # Two raw parts of one stored ZIP: offsets in part 2 start at ``half``.
    fs.pipe("/vol/a.zip.001", data[:half])
    fs.pipe("/vol/a.zip.002", data[half:])
    try:
        seen = _Recorder()
        parts = [
            fsspec.open("memory://vol/a.zip.001"),
            fsspec.open("memory://vol/a.zip.002"),
        ]
        with open_archive(parts, config=ArchiveyConfig(on_source_read=seen)) as r:
            for m in r.members():
                r.read(m)
        assert seen.calls[0].size == len(data)
        ends = [c.request_end for c in seen.calls if c.request_end is not None]
        assert max(ends) == len(data)
        assert any(
            c.request_start is not None and c.request_start >= half for c in seen.calls
        )
    finally:
        fs.rm("/vol", recursive=True)


class _Pipe(io.RawIOBase):
    """A non-seekable stream of unknown size, as a pipe is."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        return self._inner.readinto(b)


@pytest.mark.parametrize("size", [100, 2 * LOCAL_REPORT_STEP + 1000])
def test_a_pipe_reports_its_last_bytes(size: int) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.bin", os.urandom(size))
    data = buf.getvalue()
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen)
    with (
        open_archive(_Pipe(data), config=config, streaming=True) as reader,
        reader.stream_members() as members,
    ):
        for _, stream in members:
            if stream is not None:
                stream.read()
    assert seen.calls
    assert seen.calls[-1].size is None
    # Every byte taken from the pipe reaches the callback by the end.
    assert seen.calls[-1].bytes_read == len(data)


def _gz_file(tmp_path: Path, size: int) -> Path:
    import gzip

    path = tmp_path / "data.gz"
    path.write_bytes(gzip.compress(os.urandom(size), 1))
    return path


def _tar_gz(tmp_path: Path, members: int, size: int) -> Path:
    import tarfile

    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for i in range(members):
            data = os.urandom(size)
            info = tarfile.TarInfo(f"m{i}.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _stop_on(n: int, stop_type: type[BaseException]) -> Any:
    calls = 0

    def stop(progress: SourceProgress) -> None:
        nonlocal calls
        calls += 1
        if calls == n:
            raise stop_type("stop from callback")

    return stop


@pytest.mark.parametrize("stop_type", [_StopValue, _StopOS])
@pytest.mark.parametrize("shape", ["gz", "tar.gz"])
def test_a_stop_on_the_first_call_is_not_lost(
    tmp_path: Path, stop_type: type[BaseException], shape: str
) -> None:
    # The first report on a .gz comes from a probe that catches broad types.
    config = ArchiveyConfig(on_source_read=_stop_on(1, stop_type))
    with pytest.raises(stop_type) as caught:
        if shape == "gz":
            _read_stream(_gz_file(tmp_path, 3 * LOCAL_REPORT_STEP), config)
        else:
            path = _tar_gz(tmp_path, 2, 2 * LOCAL_REPORT_STEP)
            with open_archive(path, config=config) as reader:
                reader.extract_all(tmp_path / "out")
    assert type(caught.value) is stop_type


@pytest.mark.parametrize("shape", ["zip", "tar.gz"])
def test_a_stop_ends_an_extraction_that_continues_on_errors(
    tmp_path: Path, shape: str
) -> None:
    if shape == "zip":
        path = tmp_path / "m.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(3):
                zf.writestr(f"m{i}.bin", os.urandom(2 * LOCAL_REPORT_STEP))
    else:
        path = _tar_gz(tmp_path, 3, 2 * LOCAL_REPORT_STEP)
    config = ArchiveyConfig(on_source_read=_stop_on(2, _StopOS))
    with (
        pytest.raises(_StopOS),
        open_archive(path, config=config) as reader,
    ):
        reader.extract_all(tmp_path / "out", on_error="continue")
