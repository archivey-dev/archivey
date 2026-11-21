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

from archivey import (
    ArchiveyConfig,
    SourceProgress,
    SpoolLimits,
    open_archive,
    open_stream,
)
from archivey.internal.read_progress import LOCAL_REPORT_STEP, SourceReadReporter
from tests.conftest import requires, requires_unrar_cli

_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


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


def test_a_nested_reader_reports_at_its_nest_level(tmp_path: Path) -> None:
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
    # The child shares the parent's config, so its reads come to the same callback,
    # one level down; the outer file's reads stay at level 0.
    after = seen.calls[before:]
    assert {c.nest_level for c in after} == {0, 1}
    assert all(c.name == str(path) for c in after if c.nest_level == 0)
    assert all(c.name != str(path) for c in after if c.nest_level == 1)
    assert all(c.nest_level == 0 for c in seen.calls[:before])


def test_a_nested_reader_with_its_own_callback_reports_there(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("x.bin", os.urandom(2 * LOCAL_REPORT_STEP))
    path = tmp_path / "outer.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("inner.zip", inner.getvalue())
    outer_seen, inner_seen = _Recorder(), _Recorder()
    config = ArchiveyConfig(on_source_read=outer_seen)
    inner_config = ArchiveyConfig(on_source_read=inner_seen)
    with (
        open_archive(path, config=config) as outer,
        outer.open("inner.zip") as member,
        open_archive(
            member, parent=outer, config=inner_config, streaming=True
        ) as nested,
        nested.stream_members() as members,
    ):
        for _, stream in members:
            if stream is not None:
                stream.read()
    assert inner_seen.calls
    assert all(c.nest_level == 1 for c in inner_seen.calls)
    assert all(c.nest_level == 0 for c in outer_seen.calls)


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
    # A deflate or bzip2 member of a ZIP is handed to an accelerator as a file region,
    # and while reporting the accelerator notes its reads of it.
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


@requires_unrar_cli()
def test_a_rar_from_a_pipe_reports_what_the_feeder_thread_read() -> None:
    # The forward pass: a RAR from a pipe, under a spool limit smaller than the
    # archive, goes to unrar as rolling volumes that archivey's own thread writes
    # from the pipe. Its reports reach the caller on reads of unrar's output.
    from archivey.internal.backends.rar_unrar import unrar_reads_rolling_volumes

    if not unrar_reads_rolling_volumes():
        pytest.skip("this unrar is older than the one rolling volumes were measured on")
    data = (_RAR_FIXTURES / "encryption_large__rar4.rar").read_bytes()
    seen = _Recorder()
    config = ArchiveyConfig(
        rar_decompressor="unrar",
        spool_limits=SpoolLimits(max_bytes=40_000),
        on_source_read=seen,
    )
    with (
        open_archive(
            _Pipe(data), config=config, streaming=True, password="password"
        ) as reader,
        reader.stream_members() as members,
    ):
        for _, stream in members:
            if stream is not None:
                while stream.read(1 << 12):
                    pass
    assert seen.calls
    assert seen.threads == {threading.get_ident()}
    assert seen.calls[-1].bytes_read == len(data)


def test_step_zero_reports_every_read_as_a_range(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(5):
            zf.writestr(f"m{i}.bin", os.urandom(50_000))
    size = path.stat().st_size
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen, source_read_step=0)
    with open_archive(path, config=config) as reader:
        for member in reader.members():
            reader.read(member)
    ranges = [(c.read_start, c.position) for c in seen.calls]
    assert all(s is not None and 0 <= s < e <= size for s, e in ranges)
    # One call per read, each with its own range: the ranges add up to the total.
    assert sum(e - s for s, e in ranges) == seen.calls[-1].bytes_read  # type: ignore[operator]
    # The directory at the end and every member's header and data were read.
    read = set()
    for start, end in ranges:
        read.update(range(start, end))  # type: ignore[arg-type]
    assert size - 1 in read
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            data_end = info.header_offset + 30 + len(info.filename) + info.compress_size
            assert read.issuperset(range(info.header_offset, data_end))


def test_the_default_step_reports_once_per_mib_with_the_latest_range(
    tmp_path: Path,
) -> None:
    path = _xz_file(tmp_path, 3 * LOCAL_REPORT_STEP)
    seen = _Recorder()
    _read_stream(path, ArchiveyConfig(on_source_read=seen))
    assert all(
        c.read_start is not None and c.read_start < c.position for c in seen.calls
    )
    assert len(seen.calls) <= 6


def test_a_url_source_leaves_read_start_unset() -> None:
    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.bin", b"x" * 1000)
    fs.pipe("/rs/a.zip", buf.getvalue())
    try:
        seen = _Recorder()
        config = ArchiveyConfig(on_source_read=seen, source_read_step=0)
        with open_archive(fsspec.open("memory://rs/a.zip"), config=config) as r:
            r.read("a.bin")
        assert seen.calls
        assert all(c.read_start is None for c in seen.calls)
    finally:
        fs.rm("/rs", recursive=True)


@requires("rapidgzip")
def test_an_accelerated_gzip_trailer_check_does_not_swallow_a_stop(
    tmp_path: Path,
) -> None:
    # rapidgzip's trailer and member probes read the source's tail and treat an
    # OSError as "cannot look". A stop from the callback there must still reach
    # the caller, whichever read it comes on.
    path = _gz_file(tmp_path, LOCAL_REPORT_STEP)

    def read(callback: Any) -> None:
        config = ArchiveyConfig(
            use_rapidgzip="on", on_source_read=callback, source_read_step=0
        )
        with open_stream(path, seekable=True, config=config) as stream:
            stream.read()

    recorder = _Recorder()
    read(recorder)
    calls = len(recorder.calls)
    assert calls > 0
    for n in range(1, calls + 1):
        with pytest.raises(_StopOS) as caught:
            read(_stop_on(n, _StopOS))
        assert type(caught.value) is _StopOS


def _small_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_a_stop_of_an_archivey_error_type_reaches_the_caller_as_itself(
    tmp_path: Path,
) -> None:
    from archivey import CorruptionError

    path = tmp_path / "a.zip"
    path.write_bytes(_small_zip({"sample.txt": b"hello"}))
    stop = CorruptionError("stop from callback")
    calls = 0

    def callback(progress: SourceProgress) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise stop

    config = ArchiveyConfig(on_source_read=callback, source_read_step=0)
    with (
        pytest.raises(CorruptionError) as caught,
        open_archive(path, config=config) as reader,
    ):
        for member in reader.members():
            reader.read(member)
    # Not rewritten into "Could not open ZIP archive: ...".
    assert caught.value is stop


def test_a_stop_holds_for_cached_url_reads() -> None:
    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    fs.pipe(
        "/cached/a.zip",
        _small_zip(
            {"a.txt": b"a" * 100, "b.txt": b"b" * 100, "big": os.urandom(2 << 20)}
        ),
    )
    try:
        stopping = False

        def callback(progress: SourceProgress) -> None:
            if stopping and progress.request_done is False:
                raise _StopValue("stop from callback")

        config = ArchiveyConfig(on_source_read=callback)
        with open_archive(fsspec.open("memory://cached/a.zip"), config=config) as r:
            assert r.read("a.txt") == b"a" * 100
            stopping = True
            with pytest.raises(_StopValue):
                r.read("big")
            stopping = False
            # The small member's bytes are cached; the stop holds for them too.
            with pytest.raises(_StopValue):
                r.read("a.txt")
    finally:
        fs.rm("/cached", recursive=True)


def test_a_split_set_beside_a_stub_reports(tmp_path: Path) -> None:
    data = _small_zip({"x.bin": os.urandom(300_000)})
    half = len(data) // 2
    (tmp_path / "vol.exe").write_bytes(b"\0" * 64)
    (tmp_path / "vol.zip.001").write_bytes(data[:half])
    (tmp_path / "vol.zip.002").write_bytes(data[half:])
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen, source_read_step=0)
    with open_archive(tmp_path / "vol.exe", config=config) as reader:
        assert reader.read("x.bin")
    set_calls = [c for c in seen.calls if c.size == len(data)]
    assert set_calls
    assert max(c.position for c in set_calls) == len(data)


@requires("pycdlib")
def test_a_cue_sheet_reports_its_track_reads(tmp_path: Path) -> None:
    from tests.test_iso_cue import _PAYLOAD, _plain_iso
    from tests.test_iso_raw_sectors import to_raw

    data = to_raw(_plain_iso())
    (tmp_path / "disc.bin").write_bytes(data)
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen, source_read_step=0)
    with open_archive(cue, config=config) as reader:
        assert reader.read("big.dat") == _PAYLOAD
    track = [c for c in seen.calls if c.name == "disc.bin"]
    assert track
    assert all(c.size == len(data) for c in track)
    assert sum(c.position - (c.read_start or 0) for c in track) >= len(_PAYLOAD)


def test_a_mid_stream_open_reports_file_offsets() -> None:
    prefix = 5_000
    archive = _small_zip({"sample.txt": b"hello"})
    stream = io.BytesIO(b"\0" * prefix + archive)
    stream.seek(prefix)
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen, source_read_step=0)
    with open_archive(stream, config=config) as reader:
        assert reader.read("sample.txt") == b"hello"
    assert seen.calls
    for c in seen.calls:
        assert c.read_start is not None
        assert prefix <= c.read_start <= c.position <= prefix + len(archive)
        assert c.size == prefix + len(archive)


def test_a_mixed_volume_list_reports_local_and_remote_parts() -> None:
    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    data = _small_zip({f"m{i}.bin": bytes([i]) * 100_000 for i in range(4)})
    half = len(data) // 2
    fs.pipe("/mixed/a.zip.002", data[half:])
    try:
        seen = _Recorder()
        parts = [io.BytesIO(data[:half]), fsspec.open("memory://mixed/a.zip.002")]
        config = ArchiveyConfig(on_source_read=seen, source_read_step=0)
        with open_archive(parts, config=config) as r:
            for m in r.members():
                r.read(m)
        local = [c for c in seen.calls if c.request_start is None]
        remote_ends = [c for c in seen.calls if c.request_done]
        assert local and remote_ends
        assert all(c.read_start is not None and c.position <= half for c in local)
        assert min(c.read_start or 0 for c in local) == 0
        assert all((c.request_start or 0) >= half for c in remote_ends)
        local_bytes = sum(c.position - (c.read_start or 0) for c in local)
        remote_bytes = sum(c.request_received or 0 for c in remote_ends)
        assert seen.calls[-1].bytes_read == local_bytes + remote_bytes
    finally:
        fs.rm("/mixed", recursive=True)


def test_a_caller_thread_named_like_archivey_s_still_reports(tmp_path: Path) -> None:
    path = _gz_file(tmp_path, 3 * LOCAL_REPORT_STEP)
    seen = _Recorder()
    config = ArchiveyConfig(on_source_read=seen)
    errors: list[BaseException] = []

    def work() -> None:
        try:
            _read_stream(path, config)
        except Exception as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    thread = threading.Thread(target=work, name="archivey-user-worker")
    thread.start()
    thread.join()
    assert not errors
    assert len(seen.calls) >= 3
    assert seen.threads == {thread.ident}


def test_a_compressed_url_reports_its_url_as_the_name() -> None:
    import gzip

    fsspec = pytest.importorskip("fsspec")
    fs = fsspec.filesystem("memory")
    fs.pipe("/named/example.zip.gz", gzip.compress(_small_zip({"a.txt": b"a"})))
    try:
        seen = _Recorder()
        opened = fsspec.open("memory://named/example.zip.gz", compression="gzip")
        with open_archive(opened, config=ArchiveyConfig(on_source_read=seen)) as r:
            assert r.read("a.txt") == b"a"
        assert seen.calls
        assert all(c.name and "example.zip.gz" in c.name for c in seen.calls)
    finally:
        fs.rm("/named", recursive=True)


def test_bytes_a_failed_request_reported_stay_counted() -> None:
    """A request that reported bytes inside its answer and then failed (it never
    ends) took those bytes: the next request's report still counts them, so the
    totals never go down. Fails if ``request_started`` drops the in-flight count."""
    seen: list[int] = []
    reporter = SourceReadReporter(lambda p: seen.append(p.bytes_read), "x", 1 << 30)
    reporter.request_started(0, 3 << 20)
    reporter.request_received(0, 3 << 20, 1 << 20)
    reporter.request_received(0, 3 << 20, 2 << 20)
    # The answer broke here: no request_ended. The reader retries.
    reporter.request_started(2 << 20, 3 << 20)
    reporter.request_ended(2 << 20, 3 << 20, 1 << 20)
    assert seen == [0, 1 << 20, 2 << 20, 2 << 20, 3 << 20]


def test_bytes_of_a_finished_request_count_once() -> None:
    """Bytes reported inside an answer count once its request ends: the in-flight
    count is cleared, not added again by the next request."""
    seen: list[int] = []
    reporter = SourceReadReporter(lambda p: seen.append(p.bytes_read), "x", 1 << 30)
    reporter.request_started(0, 2 << 20)
    reporter.request_received(0, 2 << 20, 1 << 20)
    reporter.request_ended(0, 2 << 20, 2 << 20)
    reporter.request_started(2 << 20, 3 << 20)
    assert seen == [0, 1 << 20, 2 << 20, 2 << 20]
