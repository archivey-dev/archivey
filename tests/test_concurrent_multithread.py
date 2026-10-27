"""Multi-thread stress for promoted MemberStreams.CONCURRENT.

These tests also run under the Linux ``3.13t`` ``free-threaded-concurrency`` CI job
(marker ``concurrent_reader``). Optional backends (ISO/pycdlib) skip cleanly and are
not claimed covered by the core-only free-threaded job.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import ArchiveyUsageError
from archivey.types import MemberStreams

pytestmark = pytest.mark.concurrent_reader


def _dir_with_files(tmp_path: Path, n: int = 8) -> Path:
    root = tmp_path / "dir"
    root.mkdir()
    for i in range(n):
        (root / f"f{i}.txt").write_bytes(f"payload-{i}".encode() * 20)
    return root


def _make_zip(path: Path, n: int = 8) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(n):
            zf.writestr(f"f{i}.txt", f"payload-{i}".encode() * 20)
    return path


def _make_tar(path: Path, *, compressed: bool = False, n: int = 8) -> Path:
    mode = "w:gz" if compressed else "w"
    with tarfile.open(path, mode) as tf:
        for i in range(n):
            data = f"payload-{i}".encode() * 20
            info = tarfile.TarInfo(name=f"f{i}.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _expected(n: int = 8) -> dict[str, bytes]:
    return {f"f{i}.txt": f"payload-{i}".encode() * 20 for i in range(n)}


def _fan_out_read(path: Path, *, seekable: bool = False) -> dict[str, bytes]:
    with open_archive(
        path, concurrent_operations=True, seekable_members=seekable
    ) as reader:
        members = [m for m in reader.members() if m.is_file]
        barrier = threading.Barrier(len(members))
        got: dict[str, bytes] = {}
        lock = threading.Lock()
        errors: list[BaseException] = []

        def worker(name: str) -> None:
            try:
                barrier.wait(timeout=5)
                with reader.open(name) as stream:
                    data = stream.read()
                with lock:
                    got[name] = data
            except BaseException as exc:  # noqa: BLE001 - collect and re-raise below
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(m.name,)) for m in members]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()
        if errors:
            raise errors[0]
        return got


@pytest.mark.concurrent_reader
def test_multithread_directory_open_read(tmp_path: Path) -> None:
    root = _dir_with_files(tmp_path)
    assert _fan_out_read(root) == _expected()


@pytest.mark.concurrent_reader
def test_multithread_zip_open_close_refcnt_stress(tmp_path: Path) -> None:
    """Stress concurrent ZIP member open/close under free-threading.

    Stdlib ``zipfile`` updates ``_fileRefCnt`` without a lock on open/close; under
    CPython ``3.13t`` that races and asserts in ``_fpclose``. Repeat fan-out enough
    times to make the failure reliable before the ZIP handle lock fix.

    Also catches the native-codec path's concurrent CRC race: locked ``SlicingStream``
    views over ``ZipFile.fp`` must not call unlocked ``BufferedReader.tell`` at
    construction (see ``TestSlicingStreamLockedConstruction``).
    """
    path = _make_zip(tmp_path / "a.zip", n=16)
    expected = _expected(16)
    # Enough trials that an unlocked free-threaded run / unlocked-init tell race
    # fails consistently; a correct lock + construction keeps every trial green.
    for _ in range(80):
        assert _fan_out_read(path) == expected


@pytest.mark.concurrent_reader
def test_multithread_plain_tar_open_read(tmp_path: Path) -> None:
    path = _make_tar(tmp_path / "a.tar")
    assert _fan_out_read(path) == _expected()


@pytest.mark.concurrent_reader
def test_multithread_gzip_tar_open_read(tmp_path: Path) -> None:
    path = _make_tar(tmp_path / "a.tar.gz", compressed=True)
    assert _fan_out_read(path) == _expected()


@pytest.mark.concurrent_reader
def test_multithread_single_file_gz(tmp_path: Path) -> None:
    # Single-file archives have one member; stress overlapping open after materialization
    # is not applicable — instead fan reads across two concurrent opens of the same
    # archive path (two readers), and one CONCURRENT reader with SEEKABLE chunk reads.
    raw = b"hello-single-file-payload" * 50
    path = tmp_path / "x.gz"
    path.write_bytes(gzip.compress(raw))
    with open_archive(
        path, concurrent_operations=True, seekable_members=True
    ) as reader:
        reader.members()
        member = next(m for m in reader.members() if m.is_file)

        def read_all() -> bytes:
            with reader.open(member) as stream:
                return stream.read()

        with ThreadPoolExecutor(max_workers=2) as pool:
            # Two overlapping opens of the same member are allowed under CONCURRENT;
            # each must see the full payload.
            futs = [pool.submit(read_all), pool.submit(read_all)]
            results = [f.result(timeout=30) for f in as_completed(futs)]
        assert results == [raw, raw]


def test_multithread_iso_open_read(tmp_path: Path) -> None:
    pytest.importorskip("pycdlib")
    # Build a tiny ISO via pycdlib.
    import pycdlib

    iso_path = tmp_path / "a.iso"
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=1)
    for i in range(4):
        name = f"F{i}.TXT;1"
        data = f"payload-{i}".encode() * 20
        iso.add_fp(io.BytesIO(data), len(data), f"/{name}")
    iso.write(str(iso_path))
    iso.close()

    expected = {f"F{i}.TXT": f"payload-{i}".encode() * 20 for i in range(4)}
    # ISO member names may normalize; compare by payload set via open-by-member.
    with open_archive(iso_path, concurrent_operations=True) as reader:
        files = [m for m in reader.members() if m.is_file]
        assert len(files) >= 4
        barrier = threading.Barrier(len(files))
        got: dict[str, bytes] = {}
        lock = threading.Lock()

        def worker(member) -> None:
            barrier.wait(timeout=5)
            with reader.open(member) as stream:
                data = stream.read()
            with lock:
                got[member.name] = data

        threads = [threading.Thread(target=worker, args=(m,)) for m in files]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()
        assert set(got.values()) == set(expected.values())


@pytest.mark.concurrent_reader
def test_concurrent_close_shuts_streams_down_once(tmp_path: Path) -> None:
    """Two overlapping close() calls must not both walk the live-stream registry.

    mark_reader_closed() returns False both for "I transitioned but leases remain" and
    for "a peer already closed", so it cannot identify the owner of stream shutdown.
    ArchiveStream.close tests its closed flag outside its lock, so without a once-guard
    both callers can reach the same stream's inner close -- and a backend that is not
    re-entrant on close would be entered twice.
    """
    path = _make_zip(tmp_path / "a.zip", n=1)
    reader = open_archive(path, concurrent_operations=True)
    stream = reader.open("f0.txt")

    shutdowns: list[int] = []
    real_shutdown = reader._close_public_streams  # type: ignore[attr-defined]

    def counting_shutdown() -> None:
        shutdowns.append(threading.get_ident())
        real_shutdown()

    reader._close_public_streams = counting_shutdown  # type: ignore[attr-defined]

    # Pin the interleaving: both callers are inside mark_reader_closed() at once and
    # leave it together, so both then race for claim_stream_shutdown(). Without the
    # barriers the first thread usually finishes close() before the second starts.
    entered = threading.Barrier(2)
    released = threading.Barrier(2)
    real_mark = reader._state.mark_reader_closed

    def synced_mark() -> bool:
        entered.wait(timeout=10)
        result = real_mark()
        released.wait(timeout=10)
        return result

    reader._state.mark_reader_closed = synced_mark  # type: ignore[assignment]

    errors: list[BaseException] = []

    def closer() -> None:
        try:
            reader.close()
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=closer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()

    assert not errors
    assert len(shutdowns) == 1, f"stream shutdown ran {len(shutdowns)} times"
    assert stream.closed


@pytest.mark.concurrent_reader
def test_close_closes_every_live_stream(tmp_path: Path) -> None:
    """reader.close() closes all live streams, not just one; new opens fail."""
    path = _make_zip(tmp_path / "a.zip", n=4)
    reader = open_archive(path, concurrent_operations=True)
    members = [m for m in reader.members() if m.is_file]
    streams = [reader.open(m.name) for m in members[:2]]
    reader.close()
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.open(members[2].name)
    assert all(s.closed for s in streams)
    for s in streams:
        s.close()  # idempotent


@pytest.mark.concurrent_reader
@pytest.mark.parametrize("compressed", [False, True])
def test_multithread_reads_beside_stream_members(
    tmp_path: Path, compressed: bool
) -> None:
    """Threads read members while the caller's thread drives a stream_members() pass.

    The pass's streams and the threads' random opens interleave on the shared handle,
    so on a tar.gz both move the one decoder back and forth under the handle lock.
    """
    name = "a.tar.gz" if compressed else "a.tar"
    path = _make_tar(tmp_path / name, compressed=compressed, n=4)
    expected = _expected(4)
    with open_archive(path, concurrent_operations=True) as reader:
        barrier = threading.Barrier(5)
        errors: list[BaseException] = []
        got: list[dict[str, bytes]] = []

        def read_all() -> None:
            try:
                barrier.wait(timeout=5)
                got.append({name: reader.read(name) for name in expected})
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=read_all) for _ in range(4)]
        for t in threads:
            t.start()
        passed: dict[str, bytes] = {}
        for member, stream in reader.stream_members():
            if member.name == "f0.txt":
                barrier.wait(timeout=5)
            assert stream is not None
            passed[member.name] = stream.read()
        for t in threads:
            t.join(timeout=30)
        assert not errors
        assert passed == expected
        assert got == [expected] * 4


# --- Coordinated first-touch materialization + draining close ----------------------------


@pytest.mark.concurrent_reader
def test_concurrent_first_touch_open_materializes_once(tmp_path: Path) -> None:
    """N threads first-touch open() share one materialization and read correct bytes."""
    path = _make_zip(tmp_path / "a.zip", n=8)
    expected = _expected(8)
    names = list(expected)
    reader = open_archive(path, concurrent_operations=True)
    scan_calls = {"n": 0}
    original_iter = reader._iter_members

    def counting_iter():
        scan_calls["n"] += 1
        return original_iter()

    reader._iter_members = counting_iter  # type: ignore[method-assign]
    barrier = threading.Barrier(len(names))
    got: dict[str, bytes] = {}
    lock = threading.Lock()
    errors: list[BaseException] = []

    def worker(name: str) -> None:
        try:
            barrier.wait(timeout=5)
            with reader.open(name) as stream:
                data = stream.read()
            with lock:
                got[name] = data
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()
    reader.close()
    if errors:
        raise errors[0]
    assert got == expected
    assert scan_calls["n"] == 1


@pytest.mark.concurrent_reader
def test_concurrent_first_touch_materialization_failure_wakes_waiters(
    tmp_path: Path,
) -> None:
    """Failed first-touch leaves no partial snapshot; waiters see the error / clean retry."""
    path = _make_zip(tmp_path / "a.zip", n=4)
    reader = open_archive(path, concurrent_operations=True)
    original_iter = reader._iter_members
    fail_once = {"armed": True}
    barrier = threading.Barrier(4)
    results: list[BaseException | list] = []
    lock = threading.Lock()

    def flaky_iter():
        if fail_once["armed"]:
            fail_once["armed"] = False
            raise OSError("simulated corrupt header")
        return original_iter()

    reader._iter_members = flaky_iter  # type: ignore[method-assign]

    def worker() -> None:
        try:
            barrier.wait(timeout=5)
            members = reader.members()
            with lock:
                results.append(members)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                results.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()

    # Cache must never have been published as a partial list during the failure.
    # After the flaky first attempt, a waiter (or the same electing path on retry)
    # may succeed — collect successes and failures.
    successes = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]
    assert failures, "at least the electing thread should observe the translated error"
    assert all(not isinstance(f, ArchiveyUsageError) for f in failures)
    # No partial publication: either empty successes (all saw the error before retry
    # completed) or full member lists only.
    for members in successes:
        assert len(members) == 4
        assert {m.name for m in members if m.is_file} == set(_expected(4))
    assert reader._materialized is None or len(reader._materialized.report) == 4
    reader.close()


@pytest.mark.concurrent_reader
def test_close_drains_in_flight_workers_then_closes(tmp_path: Path) -> None:
    """close() waits for in-flight open() workers, then closes the streams they returned."""
    path = _make_zip(tmp_path / "a.zip", n=4)
    reader = open_archive(path, concurrent_operations=True)
    reader.members()  # publish so open() work is post-materialization
    entered = threading.Event()
    release = threading.Event()
    original_open_member = reader._open_member

    def blocking_open_member(member):
        entered.set()
        assert release.wait(timeout=5)
        return original_open_member(member)

    reader._open_member = blocking_open_member  # type: ignore[method-assign]
    errors: list[BaseException] = []
    stream_box: dict[str, object] = {}

    def worker() -> None:
        try:
            stream_box["s"] = reader.open("f0.txt")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=worker)
    t.start()
    assert entered.wait(timeout=5)
    close_done = threading.Event()

    def closer() -> None:
        reader.close()
        close_done.set()

    ct = threading.Thread(target=closer)
    ct.start()
    # close must block while the worker is still inside open().
    assert not close_done.wait(timeout=0.2)
    release.set()
    t.join(timeout=10)
    ct.join(timeout=10)
    assert close_done.is_set()
    assert not errors
    stream = stream_box["s"]
    assert stream is not None
    # The worker's open() completed before close() was allowed to proceed, so the
    # stream existed -- and close() then closed it along with the reader.
    assert stream.closed  # type: ignore[union-attr]
    stream.close()  # type: ignore[union-attr]  # idempotent
    with pytest.raises(ArchiveyUsageError, match="closed"):
        reader.open("f1.txt")


@pytest.mark.concurrent_reader
def test_concurrent_double_close_is_idempotent(tmp_path: Path) -> None:
    path = _make_zip(tmp_path / "a.zip", n=2)
    reader = open_archive(path, concurrent_operations=True)
    reader.members()
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def closer() -> None:
        try:
            barrier.wait(timeout=5)
            reader.close()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=closer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()
    assert not errors
    # Second close after both finish remains a no-op.
    reader.close()


@pytest.mark.concurrent_reader
def test_concurrent_double_close_exception_group_on_dual_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simultaneous inner-close + teardown failure surfaces once as ExceptionGroup."""
    path = _make_zip(tmp_path / "a.zip", n=1)
    reader = open_archive(path, concurrent_operations=True)
    stream = reader.open("f0.txt")

    def boom_close_archive() -> None:
        raise OSError("teardown failed")

    monkeypatch.setattr(reader, "_close_archive", boom_close_archive)

    def boom_inner_close() -> None:
        raise OSError("stream close failed")

    # Both halves fail during one reader.close(): closing the reader closes the member
    # stream (whose inner close fails), and dropping that last lease runs teardown
    # (which also fails). The caller must see one ExceptionGroup, not whichever
    # exception happened to be raised last.
    inner = stream._ensure_open()
    monkeypatch.setattr(inner, "close", boom_inner_close)
    with pytest.raises(ExceptionGroup) as exc_info:
        reader.close()
    assert "member-stream close and archive teardown both failed" in str(exc_info.value)


# --- Internal-open exemption is thread-scoped (deep N3) ---------------------------------


def test_internal_open_exemption_is_thread_scoped() -> None:
    """extract_all's internal-open window admits the owning thread's opens as children
    of its root pass; a FOREIGN thread's open must still be rejected (pre-fix it was
    silently admitted, and unlocked shared handles then served wrong bytes)."""
    from archivey.internal.reader_state import ReaderState

    state = ReaderState(member_streams=MemberStreams(0), open_site=None)
    root = state.acquire_pass("extract_all")
    state.begin_internal_opens()
    try:
        # Owning thread: admitted as a child of the root.
        token = state.acquire_worker("open")
        assert token.parent is root
        state.release_worker(token)

        # Foreign thread: rejected like during any active root pass.
        outcome: list[object] = []

        def foreign() -> None:
            try:
                outcome.append(state.acquire_worker("open"))
            except ArchiveyUsageError as exc:
                outcome.append(exc)

        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert len(outcome) == 1 and isinstance(outcome[0], ArchiveyUsageError)
    finally:
        state.end_internal_opens()
        state.release_pass(root)


@pytest.mark.concurrent_reader
def test_foreign_thread_open_rejected_during_extract_all(tmp_path: Path) -> None:
    """End-to-end N3: while extract_all runs on thread A (no CONCURRENT declared), a
    second thread's reader.open() must raise instead of being silently admitted under
    extract_all's internal-open exemption."""
    archive = _make_tar(tmp_path / "a.tar")
    dest = tmp_path / "out"
    with open_archive(archive) as reader:
        in_extract = threading.Event()
        proceed = threading.Event()
        outcome: list[str] = []

        def on_progress(progress: object) -> None:
            if not in_extract.is_set():
                in_extract.set()
                # Hold the extraction mid-pass until the foreign open has resolved.
                assert proceed.wait(timeout=30)

        def foreign_open() -> None:
            try:
                assert in_extract.wait(timeout=30)
                try:
                    with reader.open("f0.txt") as stream:
                        stream.read()
                    outcome.append("admitted")
                except ArchiveyUsageError:
                    outcome.append("rejected")
            finally:
                proceed.set()

        thread = threading.Thread(target=foreign_open)
        thread.start()
        reader.extract_all(dest, on_progress=on_progress)
        thread.join(timeout=30)
        assert not thread.is_alive()
        assert outcome == ["rejected"]


# --- members_report_if_available under threads (debt-ledger T4) -------------------------


@pytest.mark.concurrent_reader
def test_members_report_if_available_during_concurrent_materialization(
    tmp_path: Path,
) -> None:
    """Foreign-thread peeks that straddle a live materialization are all-or-nothing.

    ``members_report_if_available()`` reads the published snapshot without joining the
    materialization election, so it is the one accessor that can observe the cache slot
    mid-scan. It must return ``None`` or a *complete* report — never the scan's partial
    working list — and it must never itself start a scan.

    The scan is held open until every probe has recorded an observation, so the
    mid-materialization window is deterministic rather than a timing race.
    """
    path = _make_tar(tmp_path / "a.tar", n=8)  # no upfront index: None until published
    reader = open_archive(path, concurrent_operations=True)
    original_iter = reader._iter_members
    scan_calls = {"n": 0}
    scan_started = threading.Event()
    scan_released = threading.Event()
    probes_recorded = threading.Barrier(5)  # 4 probes + the scanning thread

    def held_iter():
        scan_calls["n"] += 1
        for i, member in enumerate(original_iter()):
            if i == 4:
                # Hold with half the members already registered, so a partial
                # publication would have something visible to leak.
                scan_started.set()
                probes_recorded.wait(timeout=30)
            yield member

    reader._iter_members = held_iter  # type: ignore[method-assign]

    observations: list[object] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def probe() -> None:
        try:
            assert scan_started.wait(timeout=30)
            during = reader.members_report_if_available()
            with lock:
                observations.append(during)
            probes_recorded.wait(timeout=30)
            # And again once materialization has finished, to catch a torn publication.
            assert scan_released.wait(timeout=30)
            after = reader.members_report_if_available()
            with lock:
                observations.append(after)
        except BaseException as exc:  # noqa: BLE001 - collect and re-raise below
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=probe) for _ in range(4)]
    for t in threads:
        t.start()
    members = reader.members()
    scan_released.set()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive()
    reader.close()

    if errors:
        raise errors[0]
    assert len(members) == 8
    # Every peek is None or the whole list; a partial snapshot would fail here.
    for report in observations:
        if report is not None:
            assert report.error is None
            assert len(report) == 8
    # 4 mid-scan peeks (nothing published yet) + 4 post-materialization peeks, so the
    # window was really exercised in both directions; and peeking never drove a scan.
    assert observations.count(None) == 4
    assert len(observations) == 8
    assert scan_calls["n"] == 1


@pytest.mark.concurrent_reader
def test_members_report_if_available_concurrent_on_upfront_index(
    tmp_path: Path,
) -> None:
    """The ``_MEMBER_LIST_UPFRONT`` branch builds a fresh report per call: concurrent
    callers must each get a complete, equal list (it reads backend index state that a
    materializing thread is touching at the same time)."""
    path = _make_zip(tmp_path / "a.zip", n=16)
    with open_archive(path, concurrent_operations=True) as reader:
        barrier = threading.Barrier(9)  # 8 probes + the materializing thread
        results: list[list[str]] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def probe() -> None:
            try:
                barrier.wait(timeout=10)
                report = reader.members_report_if_available()
                assert report is not None  # ZIP has an upfront central directory
                with lock:
                    results.append([m.name for m in report])
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=probe) for _ in range(8)]
        for t in threads:
            t.start()
        barrier.wait(timeout=10)
        expected = [m.name for m in reader.members()]
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()

        if errors:
            raise errors[0]
        assert len(results) == 8
        assert all(names == expected for names in results)


@pytest.mark.concurrent_reader
def test_members_report_shares_the_worker_slot_with_open(tmp_path: Path) -> None:
    """Under CONCURRENT, members_report() admits alongside another thread's open().

    It takes the same worker slot as members(), so an open() in
    flight on another thread does not block it; an exclusive pass would raise
    ArchiveyUsageError.
    """
    path = _make_zip(tmp_path / "a.zip", n=4)
    with open_archive(path, concurrent_operations=True) as reader:
        expected = [m.name for m in reader.members()]
        entered = threading.Event()
        release = threading.Event()
        original_open_member = reader._open_member

        def blocking_open_member(member):
            entered.set()
            assert release.wait(timeout=5)
            return original_open_member(member)

        reader._open_member = blocking_open_member  # type: ignore[method-assign]
        stream_box: dict[str, object] = {}
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                stream_box["s"] = reader.open("f0.txt")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        t = threading.Thread(target=worker)
        t.start()
        try:
            assert entered.wait(timeout=5)
            assert [m.name for m in reader.members_report()] == expected
            assert [m.name for m in reader.members()] == expected
        finally:
            release.set()
            t.join(timeout=10)
        assert not errors
        stream_box["s"].close()  # type: ignore[union-attr]
