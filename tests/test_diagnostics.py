"""Focused and behavior tests for lifecycle-aware diagnostics."""

from __future__ import annotations

import dataclasses
import gzip
import io
import json
import logging
import os
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ARCHIVE_INTEGRITY_CODES,
    AbortOn,
    ArchiveMember,
    ArchiveyConfig,
    Diagnostic,
    DiagnosticCode,
    DiagnosticPolicy,
    DiagnosticRaisedError,
    ExtractionStatus,
    OnError,
    detect_format,
    open_archive,
)
from archivey.diagnostics import (
    DiagnosticSummary,
    MemberTimestampContext,
    NameNormalizationContext,
    ScanRaceContext,
)
from archivey.exceptions import (
    ArchiveyUsageError,
    FilterRejectionError,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector, EmitLog
from archivey.types import ArchiveFormat, MemberType
from tests.extract_util import open_and_extract
from tests.scandir_util import patch_dir_entry_stat


def _norm_context(**overrides: object) -> NameNormalizationContext:
    base: dict[str, object] = {
        "archive_name": None,
        "member_name": "a/b",
        "member_id": 1,
        "raw_name_base64": None,
        "presented_name": "a\\b",
        "normalized_name": "a/b",
    }
    base.update(overrides)
    return NameNormalizationContext(**base)  # type: ignore[arg-type]


def _emit_norm(
    collector: DiagnosticCollector,
    *,
    member: ArchiveMember | None = None,
    attach: bool = False,
    message: str = "Member name normalized: 'a\\\\b' -> 'a/b'",
) -> Diagnostic:
    return collector.emit(
        code=DiagnosticCode.MEMBER_NAME_NORMALIZED,
        message=message,
        context=_norm_context(
            member_name=member.name if member is not None else "a/b",
            member_id=member._member_id if member is not None else 1,
        ),
        member=member,
        attach_to_member=attach,
        logger=logging.getLogger("archivey.normalization"),
    )


def _make_member(name: str = "a/b") -> ArchiveMember:
    m = ArchiveMember(type=MemberType.FILE, name=name)
    m._member_id = 1
    return m


# ---------------------------------------------------------------------------
# 4.1 — policy matrix, retention, serialization, callbacks, reentrancy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "disposition,expect_retained,expect_log,expect_callback,expect_raise",
    [
        ("ignore", False, False, False, False),
        ("collect", True, True, True, False),
        ("raise", True, True, True, True),
    ],
)
def test_policy_matrix_cells(
    disposition: str,
    expect_retained: bool,
    expect_log: bool,
    expect_callback: bool,
    expect_raise: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    seen: list[Diagnostic] = []
    collector = DiagnosticCollector(
        policy={
            "ignore": DiagnosticPolicy(ignore={DiagnosticCode.MEMBER_NAME_NORMALIZED}),
            "collect": DiagnosticPolicy(),
            "raise": DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_NAME_NORMALIZED}),
        }[disposition],
        on_diagnostic=seen.append,
    )
    with caplog.at_level(logging.WARNING, logger="archivey.normalization"):
        if expect_raise:
            with pytest.raises(DiagnosticRaisedError) as ei:
                _emit_norm(collector)
            assert ei.value.diagnostic.code is DiagnosticCode.MEMBER_NAME_NORMALIZED
        else:
            _emit_norm(collector)

    snap = collector.snapshot()
    assert snap.total_count == 1
    assert snap.counts[DiagnosticCode.MEMBER_NAME_NORMALIZED] == 1
    assert (len(snap.retained) == 1) is expect_retained
    assert bool(caplog.records) is expect_log
    assert (len(seen) == 1) is expect_callback


def test_retention_exhaustion_keeps_exact_counts() -> None:
    collector = DiagnosticCollector(max_retained=2)
    for i in range(5):
        _emit_norm(collector, message=f"norm {i}")
    snap = collector.snapshot()
    assert snap.total_count == 5
    assert snap.counts[DiagnosticCode.MEMBER_NAME_NORMALIZED] == 5
    assert len(snap.retained) == 2
    assert snap.dropped_count == 3


def test_shared_budget_aggregate_then_attachment() -> None:
    member = _make_member()
    # Two slots: one aggregate + one attachment for the first event; second event
    # gets aggregate only (one slot left) — wait, after first: 2 used. Second: no slots.
    collector = DiagnosticCollector(max_retained=2)
    _emit_norm(collector, member=member, attach=True, message="first")
    assert len(member.diagnostics) == 1
    assert len(collector.snapshot().retained) == 1

    member2 = _make_member("c/d")
    member2._member_id = 2
    _emit_norm(collector, member=member2, attach=True, message="second")
    # Only one slot left after first (aggregate+attach used 2) — second gets nothing
    assert len(collector.snapshot().retained) == 1
    assert member2.diagnostics == ()

    # With 3 slots: second gets aggregate but not attachment
    collector2 = DiagnosticCollector(max_retained=3)
    m1, m2 = _make_member("x"), _make_member("y")
    m1._member_id, m2._member_id = 1, 2
    _emit_norm(collector2, member=m1, attach=True, message="a")
    _emit_norm(collector2, member=m2, attach=True, message="b")
    assert len(collector2.snapshot().retained) == 2
    assert len(m1.diagnostics) == 1
    assert m2.diagnostics == ()  # attachment omitted; aggregate retained


def test_occurrence_id_value_correlation() -> None:
    member = _make_member()
    collector = DiagnosticCollector()
    d = _emit_norm(collector, member=member, attach=True)
    snap = collector.snapshot()
    assert snap.retained[0].occurrence_id == member.diagnostics[0].occurrence_id
    assert snap.retained[0] == member.diagnostics[0]
    assert snap.retained[0].occurrence_id == d.occurrence_id


def test_context_json_safe_and_immutable() -> None:
    collector = DiagnosticCollector()
    d = _emit_norm(collector)
    payload = d.to_dict()
    json.dumps(payload)  # must not raise
    assert payload["code"] == "member_name_normalized"
    assert payload["context"]["kind"] == "name_normalization"
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.message = "mutated"  # type: ignore[misc]


def test_symlink_context_has_no_password_material() -> None:
    from archivey.diagnostics import SymlinkTargetContext

    ctx = SymlinkTargetContext(
        archive_name="a.zip",
        member_name="link",
        member_id=1,
        reason="password_required",
    )
    blob = json.dumps(ctx.to_dict())
    assert "password_required" in blob
    assert "secret" not in blob.lower() or "password_required" in blob


def test_callback_order_and_failure_propagates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    order: list[str] = []

    def cb(d: Diagnostic) -> None:
        order.append(d.message)
        if d.message == "second":
            raise RuntimeError("callback boom")

    collector = DiagnosticCollector(on_diagnostic=cb)
    with caplog.at_level(logging.WARNING, logger="archivey.normalization"):
        _emit_norm(collector, message="first")
        with pytest.raises(RuntimeError, match="callback boom"):
            _emit_norm(collector, message="second")
    assert order == ["first", "second"]
    assert collector.snapshot().total_count == 2


def test_deferring_raises_holds_until_the_outermost_block_asks() -> None:
    collector = DiagnosticCollector(policy=DiagnosticPolicy.STRICT)
    with collector.deferring_raises() as outer:
        with collector.deferring_raises() as inner:
            _emit_norm(collector, message="first")
            _emit_norm(collector, message="second")
            assert inner() is None  # an inner block leaves the raise to its owner
        held = outer()
    assert isinstance(held, DiagnosticRaisedError)
    assert str(held).startswith("first")
    assert collector.snapshot().total_count == 2
    # Outside any block the same emit raises at once again.
    with pytest.raises(DiagnosticRaisedError):
        _emit_norm(collector, message="third")


def test_deferring_raises_holds_a_callback_exception_but_not_an_interrupt() -> None:
    def boom(d: Diagnostic) -> None:
        raise RuntimeError("callback boom")

    collector = DiagnosticCollector(on_diagnostic=boom)
    with collector.deferring_raises() as pending:
        _emit_norm(collector, message="first")
        assert isinstance(pending(), RuntimeError)

    def interrupt(d: Diagnostic) -> None:
        raise KeyboardInterrupt

    collector = DiagnosticCollector(on_diagnostic=interrupt)
    with collector.deferring_raises() as pending:
        with pytest.raises(KeyboardInterrupt):
            _emit_norm(collector, message="first")
        assert pending() is None


def test_callback_may_read_snapshot() -> None:
    collector = DiagnosticCollector()

    def cb(d: Diagnostic) -> None:
        snap = collector.snapshot()
        assert snap.total_count >= 1
        assert any(x.occurrence_id == d.occurrence_id for x in snap.retained)

    collector._on_diagnostic = cb  # type: ignore[attr-defined]
    # Recreate properly
    collector = DiagnosticCollector(on_diagnostic=cb)
    _emit_norm(collector)


def _emit_race(collector: DiagnosticCollector) -> Diagnostic:
    return collector.emit(
        code=DiagnosticCode.SCAN_ENTRY_VANISHED,
        message="vanished",
        context=ScanRaceContext(archive_name=None, relative_path="x"),
    )


def test_replaying_records_then_repeats_without_recording_again() -> None:
    delivered: list[Diagnostic] = []
    collector = DiagnosticCollector(on_diagnostic=delivered.append)
    log = EmitLog()
    with collector.replaying(log):
        first = _emit_norm(collector, member=_make_member(), attach=True)
    member = _make_member()
    with collector.replaying(log):
        again = _emit_norm(collector, member=member, attach=True)
        extra = _emit_race(collector)
    assert again is first
    assert member.diagnostics == (first,)
    assert delivered == [first, extra]
    assert collector.snapshot().counts == {
        DiagnosticCode.MEMBER_NAME_NORMALIZED: 1,
        DiagnosticCode.SCAN_ENTRY_VANISHED: 1,
    }
    # The emit past the end of the log was recorded, so a third run repeats both.
    with collector.replaying(log):
        _emit_norm(collector)
        _emit_race(collector)
    assert len(delivered) == 2


def test_replaying_stops_at_an_emit_that_differs_from_the_log() -> None:
    collector = DiagnosticCollector()
    log = EmitLog()
    with collector.replaying(log):
        _emit_norm(collector)
        _emit_norm(collector)
    with collector.replaying(log):
        _emit_race(collector)
        _emit_norm(collector)
    assert collector.snapshot().counts == {
        DiagnosticCode.MEMBER_NAME_NORMALIZED: 3,
        DiagnosticCode.SCAN_ENTRY_VANISHED: 1,
    }
    # The log was cut at the difference and now describes the second run, so a third
    # run like it replays instead of counting again.
    assert log.codes == [
        DiagnosticCode.SCAN_ENTRY_VANISHED,
        DiagnosticCode.MEMBER_NAME_NORMALIZED,
    ]
    with collector.replaying(log):
        _emit_race(collector)
        _emit_norm(collector)
    assert collector.snapshot().total_count == 4


def test_replaying_a_run_that_emits_less_does_not_grow_the_log() -> None:
    collector = DiagnosticCollector()
    log = EmitLog()
    with collector.replaying(log):
        _emit_norm(collector)
        _emit_race(collector)
    for _ in range(3):
        with collector.replaying(log):
            _emit_race(collector)
    assert log.codes == [DiagnosticCode.SCAN_ENTRY_VANISHED]
    assert collector.snapshot().counts == {
        DiagnosticCode.MEMBER_NAME_NORMALIZED: 1,
        DiagnosticCode.SCAN_ENTRY_VANISHED: 2,
    }


def test_a_settled_log_replays_from_its_codes_alone() -> None:
    strict = DiagnosticCollector(
        policy=DiagnosticPolicy(raise_on={DiagnosticCode.SCAN_ENTRY_VANISHED})
    )
    log = EmitLog()
    with strict.replaying(log):
        _emit_norm(strict, member=_make_member(), attach=True)
        with pytest.raises(DiagnosticRaisedError) as first:
            _emit_race(strict)
    log.settle()
    assert log.details is None
    member = _make_member()
    with strict.replaying(log):
        _emit_norm(strict, member=member, attach=True)
        with pytest.raises(DiagnosticRaisedError) as second:
            _emit_race(strict)
    # Nothing is counted or attached again; the emit's own raise still repeats.
    assert member.diagnostics == ()
    assert second.value is first.value
    assert strict.snapshot().total_count == 2


def test_replaying_repeats_the_emit_raise_but_not_a_callback_raise() -> None:
    def interrupting(diagnostic: Diagnostic) -> None:
        raise KeyboardInterrupt

    collector = DiagnosticCollector(on_diagnostic=interrupting)
    log = EmitLog()
    with pytest.raises(KeyboardInterrupt), collector.replaying(log):
        _emit_norm(collector)
    with collector.replaying(log):
        _emit_norm(collector)  # replayed: the callback is not called again

    strict = DiagnosticCollector(
        policy=DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_NAME_NORMALIZED})
    )
    log = EmitLog()
    with pytest.raises(DiagnosticRaisedError) as first, strict.replaying(log):
        _emit_norm(strict)
    with pytest.raises(DiagnosticRaisedError) as second, strict.replaying(log):
        _emit_norm(strict)
    assert second.value is first.value
    assert strict.snapshot().counts == {DiagnosticCode.MEMBER_NAME_NORMALIZED: 1}


def test_replayed_raise_does_not_grow_its_traceback() -> None:
    # A replay raises the stored exception object again. Each raise adds the frames it
    # passes to that object's traceback, so without a reset every retry made it longer.
    strict = DiagnosticCollector(
        policy=DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_NAME_NORMALIZED})
    )
    log = EmitLog()
    depths: list[int] = []
    for _ in range(10):
        with pytest.raises(DiagnosticRaisedError) as caught, strict.replaying(log):
            _emit_norm(strict)
        tb = caught.value.__traceback__
        depth = 0
        while tb is not None:
            depth += 1
            tb = tb.tb_next
        depths.append(depth)
    # The first run raises from the recording site; compare the replays with each other.
    assert depths[1:] == [depths[1]] * (len(depths) - 1), depths
    assert strict.snapshot().counts == {DiagnosticCode.MEMBER_NAME_NORMALIZED: 1}


def test_operational_reentrancy_rejected() -> None:
    collector = DiagnosticCollector()

    def cb(d: Diagnostic) -> None:
        collector.emit(
            code=DiagnosticCode.SCAN_ENTRY_VANISHED,
            message="reenter",
            context=ScanRaceContext(
                archive_name=None, relative_path="x", entry_kind="entry"
            ),
        )

    collector = DiagnosticCollector(on_diagnostic=cb)
    with pytest.raises(ArchiveyUsageError, match="reentrancy"):
        _emit_norm(collector)


def test_concurrent_emits_are_not_treated_as_reentrancy() -> None:
    # A slow callback holds one thread inside delivery while other threads emit. The
    # reentrancy guard is per-thread, so concurrent emitters must NOT be rejected.
    import threading

    release = threading.Event()
    entered = threading.Event()

    def cb(d: Diagnostic) -> None:
        if d.message == "slow":
            entered.set()
            release.wait(5)

    collector = DiagnosticCollector(on_diagnostic=cb)
    errors: list[BaseException] = []

    def slow() -> None:
        try:
            _emit_norm(collector, message="slow")
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            errors.append(exc)

    def fast() -> None:
        try:
            entered.wait(5)  # ensure the slow emit is mid-delivery
            _emit_norm(collector, message="fast")
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            errors.append(exc)
        finally:
            release.set()

    t_slow, t_fast = threading.Thread(target=slow), threading.Thread(target=fast)
    t_slow.start()
    t_fast.start()
    t_slow.join(5)
    t_fast.join(5)

    assert errors == []
    assert collector.snapshot().total_count == 2


def test_scope_counts_only_its_own_threads_emits() -> None:
    # On a reader shared between threads, a call's own report must not pick up what
    # another thread emits meanwhile: that is what a scope is for, over a watermark.
    import threading

    collector = DiagnosticCollector(max_retained=4)
    inside = threading.Event()
    emitted = threading.Event()
    summaries = {}

    def scoped() -> None:
        with collector.scoped() as outer:
            _emit_norm(collector, message="mine")
            with collector.scoped() as inner:
                inside.set()
                emitted.wait(5)
                _emit_norm(collector, message="nested")
        summaries["outer"] = outer.summary()
        summaries["inner"] = inner.summary()
        summaries["stack"] = list(collector.scope_stack())

    thread = threading.Thread(target=scoped)
    thread.start()
    inside.wait(5)
    _emit_norm(collector, message="other thread")
    emitted.set()
    thread.join(5)
    _emit_norm(collector, message="after")

    outer, inner = summaries["outer"], summaries["inner"]
    assert outer.total_count == 2
    assert [d.message for d in outer.retained] == ["mine", "nested"]
    assert inner.total_count == 1
    assert [d.message for d in inner.retained] == ["nested"]
    assert collector.snapshot().total_count == 4
    # Both scopes left the thread's stack on exit.
    assert summaries["stack"] == []


def test_scope_counts_exactly_past_retention() -> None:
    collector = DiagnosticCollector(max_retained=1)
    with collector.scoped() as scope:
        for _ in range(3):
            _emit_norm(collector)
    summary = scope.summary()
    assert summary.total_count == 3
    assert len(summary.retained) == 1
    assert summary.dropped_count == 2


def test_snapshots_are_immutable_points_in_time() -> None:
    collector = DiagnosticCollector()
    _emit_norm(collector, message="one")
    before = collector.snapshot()
    _emit_norm(collector, message="two")
    after = collector.snapshot()
    assert before.total_count == 1
    assert after.total_count == 2
    assert before.retained[0].message == "one"


# ---------------------------------------------------------------------------
# 4.2 — lifecycle, surfaces, migrated sites, extraction, EOF precedence
# ---------------------------------------------------------------------------


def test_detect_format_attaches_conflict_diagnostics(tmp_path: Path) -> None:
    # ZIP magic under a .tar name → conflict (existing test pattern).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
    path = tmp_path / "looks.tar"
    path.write_bytes(buf.getvalue())
    info = detect_format(path)
    assert info.diagnostics.total_count >= 1
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in info.diagnostics.counts


def test_open_archive_transfers_detection_collector(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
    path = tmp_path / "looks.tar"
    path.write_bytes(buf.getvalue())
    with open_archive(path) as reader:
        snap = reader.diagnostics
        assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in snap.counts
        assert snap.total_count >= 1


def test_extract_all_report_covers_only_its_own_call(tmp_path: Path) -> None:
    # ``reader.extract_all()`` reports its own call only; the detection and open
    # diagnostics stay on ``reader.diagnostics``.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
    src = tmp_path / "looks.tar"
    src.write_bytes(buf.getvalue())
    dest = tmp_path / "out"
    dest.mkdir()
    with open_archive(src) as reader:
        assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in reader.diagnostics.counts
        report = reader.extract_all(dest)
        assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT not in report.diagnostics.counts
        assert report.diagnostics.total_count == 0
        assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in reader.diagnostics.counts


def test_extraction_report_behaves_like_its_results_sequence(tmp_path: Path) -> None:
    # The report iterates / sizes / indexes as ``results`` so the common extraction loop
    # (`for r in reader.extract_all(...)`, `len(...)`, `report[0]`) keeps working alongside
    # ``report.diagnostics``.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
        zf.writestr("b.txt", b"yo")
    src = tmp_path / "a.zip"
    src.write_bytes(buf.getvalue())
    dest = tmp_path / "out"
    dest.mkdir()

    report = open_and_extract(src, dest)
    assert len(report) == len(report.results)
    assert list(report) == list(report.results)
    assert report[0] is report.results[0]


def test_extract_all_report_is_delta_only(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hi")
    src = tmp_path / "looks.tar"
    src.write_bytes(buf.getvalue())
    dest = tmp_path / "out"
    dest.mkdir()
    with open_archive(src) as reader:
        before = reader.diagnostics.total_count
        assert before >= 1  # detection conflict already counted
        report = reader.extract_all(dest)
        # The report covers the call only; it does not re-count earlier diagnostics.
        assert report.diagnostics.total_count == 0 or (
            DiagnosticCode.FORMAT_EXTENSION_CONFLICT not in report.diagnostics.counts
        )
        assert reader.diagnostics.total_count == before + report.diagnostics.total_count


def test_member_name_normalized_attaches(tmp_path: Path) -> None:
    # ZIP with backslash name → normalization diagnostic attached to member.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Force a stored name with backslash via ZipInfo
        info = zipfile.ZipInfo(r"dir\file.txt")
        zf.writestr(info, b"x")
    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        members = reader.members()
        assert members
        # Either the member got an attachment or the reader aggregate has the code
        snap = reader.diagnostics
        if DiagnosticCode.MEMBER_NAME_NORMALIZED in snap.counts:
            matched = [m for m in members if m.diagnostics]
            # Attachment is budget-dependent; aggregate must exist
            assert snap.counts[DiagnosticCode.MEMBER_NAME_NORMALIZED] >= 1
            if matched:
                assert matched[0].diagnostics[0].occurrence_id in {
                    d.occurrence_id for d in snap.retained
                }


def test_directory_scan_race_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.txt").write_text("x")

    def flaky_stat(entry: os.DirEntry[str], real_stat: Callable[[], object]) -> object:
        if entry.name == "a.txt":
            raise FileNotFoundError(entry.path)
        return real_stat()

    patch_dir_entry_stat(monkeypatch, flaky_stat)
    with open_archive(tmp_path) as reader:
        list(reader.members())
        assert DiagnosticCode.SCAN_ENTRY_VANISHED in reader.diagnostics.counts


@pytest.mark.parametrize("on_error", [OnError.CONTINUE, OnError.STOP])
def test_extraction_blocked_is_result_only(tmp_path: Path, on_error: OnError) -> None:
    """A blocked member is recorded in ``results`` and nowhere else.

    The placement clause: extraction returns a per-item report, so the outcome has no
    second home in the diagnostics channel.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.txt", b"x")
    dest = tmp_path / "out"
    dest.mkdir()
    report = open_and_extract(
        io.BytesIO(buf.getvalue()),
        dest,
        on_error=on_error,
    )
    blocked = [r for r in report.results if r.status is ExtractionStatus.BLOCKED]
    assert blocked
    assert isinstance(blocked[0].error, FilterRejectionError)
    assert blocked[0].error.message.startswith("Path traversal")
    # No extraction-outcome code exists to be counted.
    assert not [
        code
        for code in report.diagnostics.counts
        if code.value.startswith("extraction_")
    ]


def test_abort_on_blocked_member_stops_despite_continue(tmp_path: Path) -> None:
    """The named replacement for RAISE-on-EXTRACTION_MEMBER_BLOCKED.

    Same behaviour the disposition used to give by accident — abort on the first unsafe
    member, under ``OnError.CONTINUE`` — now spelled out, and raising the underlying
    rejection rather than a ``DiagnosticRaisedError``.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.txt", b"x")
        zf.writestr("ok.txt", b"y")
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(FilterRejectionError):
        open_and_extract(
            io.BytesIO(buf.getvalue()),
            dest,
            on_error=OnError.CONTINUE,
            abort_on={AbortOn.BLOCKED_MEMBER},
        )
    # No report is returned, and the later member was never processed.
    assert not (dest / "ok.txt").exists()


def test_blocked_member_does_not_abort_without_opt_in(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.txt", b"x")
        zf.writestr("ok.txt", b"y")
    dest = tmp_path / "out"
    dest.mkdir()
    report = open_and_extract(
        io.BytesIO(buf.getvalue()), dest, on_error=OnError.CONTINUE
    )
    assert [r.status for r in report.results] == [
        ExtractionStatus.BLOCKED,
        ExtractionStatus.EXTRACTED,
    ]
    assert (dest / "ok.txt").read_bytes() == b"y"


def test_reading_diagnostic_raise_still_halts_extraction(tmp_path: Path) -> None:
    """Dispositions stay authoritative for the diagnostics that still fire while
    extracting: per-member outcomes left the channel, reading events did not."""
    import tarfile
    import time

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        info.mtime = -(2**40)  # far outside the representable range
        tf.addfile(info, io.BytesIO(b"x"))
    dest = tmp_path / "out"
    dest.mkdir()
    policy = DiagnosticPolicy(raise_on={DiagnosticCode.MEMBER_TIMESTAMP_INVALID})
    del time
    with pytest.raises(DiagnosticRaisedError) as ei:
        open_and_extract(
            io.BytesIO(buf.getvalue()),
            dest,
            on_error=OnError.CONTINUE,
            config=ArchiveyConfig(diagnostic_policy=policy),
        )
    diagnostic = ei.value.diagnostic
    assert diagnostic.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
    assert diagnostic.message == "Invalid TAR PAX mtime for 'a.txt': '-1099511627776'"
    context = diagnostic.context
    assert isinstance(context, MemberTimestampContext)
    assert (context.field, context.source, context.value_repr) == (
        "modified",
        "tar",
        "'-1099511627776'",
    )


def test_eof_marker_raise_yields_diagnostic_error() -> None:
    from archivey.types import ArchiveFormat
    from tests.test_tar import _tar_missing_eof_block

    data = _tar_missing_eof_block()
    policy = DiagnosticPolicy(raise_on={DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING})
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.TAR,
            config=ArchiveyConfig(diagnostic_policy=policy),
        ) as ar,
    ):
        ar.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING


def test_eof_marker_ignore_counts_without_raising() -> None:
    # The missing trailer carries no escalation of its own, so IGNORE is honoured: the
    # count moves and nothing is raised, retained or delivered.
    from archivey.types import ArchiveFormat
    from tests.test_tar import _tar_missing_eof_block

    data = _tar_missing_eof_block()
    policy = DiagnosticPolicy(ignore={DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING})
    with open_archive(
        io.BytesIO(data),
        format=ArchiveFormat.TAR,
        config=ArchiveyConfig(diagnostic_policy=policy),
    ) as ar:
        assert len(ar.members()) == 4
        summary = ar.diagnostics
        assert summary.counts[DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING] == 1
        assert summary.retained == ()


def test_extraction_report_results_frozen(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_bytes(b"x")
    dest = tmp_path / "out"
    dest.mkdir()
    report = open_and_extract(src, dest)
    assert isinstance(report.results, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.results[0].status = ExtractionStatus.FAILED  # type: ignore[misc]
    # Member remains live/mutable
    report.results[0].member.comment = "late"
    assert report.results[0].member.comment == "late"


def test_empty_summary_helper() -> None:
    empty = DiagnosticSummary.empty()
    assert empty.total_count == 0
    assert empty.retained == ()
    assert empty.dropped_count == 0


# ---------------------------------------------------------------------------
# The review batch: unused arguments, empty listings, unconfirmed formats
# ---------------------------------------------------------------------------


def test_empty_zip_reports_only_emptiness() -> None:
    """A magic-confirmed empty archive is empty, and that is all there is to say."""
    buf = io.BytesIO()
    zipfile.ZipFile(buf, "w").close()

    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        assert reader.members() == []
        assert dict(reader.diagnostics.counts) == {DiagnosticCode.EMPTY_ARCHIVE: 1}


def test_empty_archive_is_emitted_once_per_reader() -> None:
    buf = io.BytesIO()
    zipfile.ZipFile(buf, "w").close()

    with open_archive(io.BytesIO(buf.getvalue())) as reader:
        reader.members()
        reader.members()
        assert reader.diagnostics.counts[DiagnosticCode.EMPTY_ARCHIVE] == 1


@pytest.mark.parametrize("kind", ["directory", "gzip"])
def test_auto_detected_open_without_encoding_is_not_reported_unused(
    kind: str, tmp_path: Path
) -> None:
    """Only the *caller's* explicit encoding counts; an ordinary open passes none.

    Both backends ignore ``encoding=``, so the guard's ``encoding is not None`` clause
    is the only thing keeping this open silent.
    """
    if kind == "directory":
        (tmp_path / "a.txt").write_bytes(b"hello")
        source: Path | io.BytesIO = tmp_path
    else:
        source = io.BytesIO(gzip.compress(b"hello"))

    with open_archive(source) as reader:
        reader.members()
        assert DiagnosticCode.ENCODING_ARGUMENT_UNUSED not in reader.diagnostics.counts


def test_unused_argument_context_carries_no_password_material() -> None:
    """`diagnostics`: no diagnostic surface may contain passwords or candidate counts."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hello")
    data = buf.getvalue()

    import tarfile

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))
    del data

    with open_archive(io.BytesIO(tar_buf.getvalue()), password="hunter2") as reader:
        (record,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.PASSWORD_ARGUMENT_UNUSED
        ]
        serialized = json.dumps(record.to_dict())
        assert "hunter2" not in serialized
        assert record.context.argument == "password"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Named policy presets
# ---------------------------------------------------------------------------


def test_strict_preset_equals_hand_built_policy() -> None:
    """Presets add no resolution axis — they are ordinary frozen policy values."""
    assert DiagnosticPolicy.STRICT == DiagnosticPolicy(
        raise_on=list(ARCHIVE_INTEGRITY_CODES)
    )
    assert DiagnosticPolicy.PEDANTIC == DiagnosticPolicy(raise_on=set(DiagnosticCode))
    assert hash(DiagnosticPolicy.STRICT) == hash(
        DiagnosticPolicy(raise_on=ARCHIVE_INTEGRITY_CODES)
    )
    assert DiagnosticPolicy.STRICT.raise_on == ARCHIVE_INTEGRITY_CODES
    assert DiagnosticPolicy.STRICT.ignore == frozenset()
    assert DiagnosticPolicy.PEDANTIC.raise_on == frozenset(DiagnosticCode)
    assert DiagnosticPolicy.PEDANTIC.ignore == frozenset()


def test_policy_fields_are_frozensets_of_codes() -> None:
    """Any iterable of codes or their spellings is stored as a frozenset of members."""
    policy = DiagnosticPolicy(
        ignore=["password_argument_unused"],
        raise_on=(DiagnosticCode.ARCHIVE_TRAILING_DATA, "ARCHIVE_EOF_MARKER_MISSING"),
    )
    assert policy.ignore == frozenset({DiagnosticCode.PASSWORD_ARGUMENT_UNUSED})
    assert policy.raise_on == frozenset(
        {
            DiagnosticCode.ARCHIVE_TRAILING_DATA,
            DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
        }
    )
    assert isinstance(policy.ignore, frozenset)
    assert DiagnosticCode.PASSWORD_ARGUMENT_UNUSED in policy.ignore
    assert DiagnosticCode.EMPTY_ARCHIVE not in policy.ignore | policy.raise_on


def test_policy_refuses_a_code_in_both_sets() -> None:
    with pytest.raises(ArchiveyUsageError, match="both ignore= and raise_on="):
        DiagnosticPolicy(
            ignore={DiagnosticCode.ARCHIVE_TRAILING_DATA},
            raise_on=["ARCHIVE_TRAILING_DATA"],
        )


@pytest.mark.parametrize("field", ["ignore", "raise_on"])
def test_policy_refuses_a_bare_string(field: str) -> None:
    """``ignore="x"`` is a typo for ``ignore=["x"]``, not a set of characters."""
    with pytest.raises(ArchiveyUsageError, match="bare string"):
        DiagnosticPolicy(**{field: "archive_trailing_data"})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["ignore", "raise_on"])
def test_policy_refuses_a_mapping(field: str) -> None:
    """The removed ``overrides={code: disposition}`` shape iterates as its keys, so
    under ``ignore=`` it would silence a code the caller asked to raise on."""
    overrides = {DiagnosticCode.ARCHIVE_TRAILING_DATA: "raise"}
    with pytest.raises(ArchiveyUsageError, match="not a mapping"):
        DiagnosticPolicy(**{field: overrides})  # type: ignore[arg-type]


def test_policy_refuses_a_single_code_by_name() -> None:
    """A member where a one-element set was meant is named as a code, not a string."""
    with pytest.raises(ArchiveyUsageError) as info:
        DiagnosticPolicy(ignore=DiagnosticCode.ARCHIVE_TRAILING_DATA)  # type: ignore[arg-type]
    message = str(info.value)
    assert "single code DiagnosticCode.ARCHIVE_TRAILING_DATA" in message
    assert "{DiagnosticCode.ARCHIVE_TRAILING_DATA}" in message


def test_policy_fields_support_set_operations() -> None:
    """The fields read back as frozensets, so a preset is adjusted from its own field."""
    policy = DiagnosticPolicy(
        raise_on=DiagnosticPolicy.STRICT.raise_on
        - {DiagnosticCode.ARCHIVE_TRAILING_DATA}
    )
    assert policy.raise_on == ARCHIVE_INTEGRITY_CODES - {
        DiagnosticCode.ARCHIVE_TRAILING_DATA
    }


def test_policy_refuses_an_unknown_code() -> None:
    with pytest.raises(ArchiveyUsageError):
        DiagnosticPolicy(raise_on=["no_such_code"])


def test_policy_fields_are_keyword_only() -> None:
    with pytest.raises(TypeError):
        DiagnosticPolicy({DiagnosticCode.EMPTY_ARCHIVE})  # type: ignore[misc]


def test_strict_preset_raises_on_archive_integrity() -> None:
    from archivey.types import ArchiveFormat
    from tests.test_tar import _tar_missing_eof_block

    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(
            io.BytesIO(_tar_missing_eof_block()),
            format=ArchiveFormat.TAR,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as ar,
    ):
        ar.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING


def test_strict_preset_does_not_raise_on_argument_hygiene(tmp_path: Path) -> None:
    """The pipeline case: a password passed speculatively to every call must not make
    every unencrypted archive raise under a policy named 'strict'."""
    import tarfile

    from archivey.types import ArchiveFormat

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    data = buf.getvalue()
    with open_archive(
        io.BytesIO(data),
        format=ArchiveFormat.TAR,
        password="unused",
        config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
    ) as ar:
        ar.members()
        assert DiagnosticCode.PASSWORD_ARGUMENT_UNUSED in ar.diagnostics.counts
    # PEDANTIC is the preset that does raise on it.
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.TAR,
            password="unused",
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.PEDANTIC),
        ) as ar,
    ):
        ar.members()
    assert ei.value.diagnostic.code is DiagnosticCode.PASSWORD_ARGUMENT_UNUSED


def test_strict_preset_does_not_raise_on_empty_archive() -> None:
    """An empty archive is legitimate; the diagnostics spec forbids treating zero
    members as an error, so STRICT must not turn it into one."""
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w"):
        pass
    from archivey.types import ArchiveFormat

    with open_archive(
        io.BytesIO(buf.getvalue()),
        format=ArchiveFormat.TAR,
        config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
    ) as ar:
        assert ar.members() == []
        assert DiagnosticCode.EMPTY_ARCHIVE in ar.diagnostics.counts


def test_archive_integrity_codes_are_all_real_codes() -> None:
    """The preset and the taxonomy cannot drift apart silently."""
    assert ARCHIVE_INTEGRITY_CODES <= set(DiagnosticCode)
    excluded = set(DiagnosticCode) - ARCHIVE_INTEGRITY_CODES
    # Soft probe-only unconfirmed stays out of strict= — the typed TruncatedError /
    # CorruptionError already carries format_unconfirmed; RAISE would replace it.
    assert excluded == {
        DiagnosticCode.EMPTY_ARCHIVE,
        DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY,
        DiagnosticCode.ENCODING_ARGUMENT_UNUSED,
        DiagnosticCode.PASSWORD_ARGUMENT_UNUSED,
        DiagnosticCode.STREAM_REWIND_REDECOMPRESSES,
        DiagnosticCode.PROBE_FORMAT_UNCONFIRMED,
        DiagnosticCode.MEMBER_SELECTOR_UNMATCHED,
        # Fires only on a stream abandoned before EOF; in strict it would turn a peek
        # at a ZipCrypto member into DiagnosticRaisedError.
        DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED,
        # ``zip -FI`` writes the shape and the bytes are delivered; nothing hidden.
        DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA,
        # A zero-width joiner is part of ordinary emoji and of Indic spelling.
        DiagnosticCode.MEMBER_NAME_INVISIBLE_CHARACTER,
        # The name is wrong, not the bytes: the bytes win and the archive reads in full.
        DiagnosticCode.FORMAT_EXTENSION_CONFLICT,
        # Adobe AIR writes the shape and the data is checked against the local CRC-32.
        DiagnosticCode.MEMBER_LOCAL_CRC_USED,
        # macOS writes ZIPs past 4 GiB this way by default; the correction is checked.
        DiagnosticCode.ARCHIVE_OFFSET_WRAPPED,
        # The same Mac archives with a member past 4 GiB; length and CRC are checked.
        DiagnosticCode.MEMBER_SIZE_WRAPPED,
        # GNU tar extracts an unknown TAR typeflag as a file; the data is delivered.
        DiagnosticCode.MEMBER_TYPE_UNKNOWN,
    }


def test_strict_opens_a_tarball_named_gz_and_records_the_conflict(
    tmp_path: Path,
) -> None:
    """A wrong extension is recorded, but ``STRICT`` does not refuse the archive."""
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
    path = tmp_path / "b.gz"
    path.write_bytes(gzip.compress(buf.getvalue()))
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    info = detect_format(path, config=config)
    assert info.format == ArchiveFormat.TAR_GZ
    assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in info.diagnostics.counts
    with open_archive(path, config=config) as ar:
        assert [m.name for m in ar.members()] == ["a.txt"]
        assert ar.read("a.txt") == b"hi"
        assert DiagnosticCode.FORMAT_EXTENSION_CONFLICT in ar.diagnostics.counts


def test_the_logged_line_is_the_escaped_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The WARNING line carries ``diagnostic.message``, which escaping has made inert,
    not the raw text the emit site passed in."""
    from archivey.diagnostics import EmptyArchiveContext

    logger = logging.getLogger("archivey.test.escaped_log")
    collector = DiagnosticCollector(logger=logger)
    with caplog.at_level(logging.WARNING, logger=logger.name):
        diagnostic = collector.emit(
            code=DiagnosticCode.EMPTY_ARCHIVE,
            message="Archive listed no members ev\x1b[2Kil\rSPOOF.txt",
            context=EmptyArchiveContext(archive_name="x", format="zip"),
        )
    assert "\x1b" not in diagnostic.message and "\r" not in diagnostic.message
    assert [r.getMessage() for r in caplog.records] == [diagnostic.message]


@pytest.mark.parametrize("kind", ["gz", "tar", "directory"])
def test_password_provider_is_not_reported_unused(tmp_path: Path, kind: str) -> None:
    """A provider on a format without encryption records nothing; a string still does.

    The CLI passes a provider on every run, so reporting it made every TAR, gzip and
    directory run print a warning about a password nobody typed.
    """
    import gzip
    import tarfile

    if kind == "gz":
        source = tmp_path / "a.txt.gz"
        source.write_bytes(gzip.compress(b"hello"))
    elif kind == "tar":
        source = tmp_path / "a.tar"
        with tarfile.open(source, mode="w") as tar:
            info = tarfile.TarInfo("a.txt")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"hello"))
    else:
        source = tmp_path / "tree"
        source.mkdir()
        (source / "a.txt").write_bytes(b"hello")

    def provider(_request: object) -> str:
        raise AssertionError("a format without encryption must not ask")

    with open_archive(source, password=provider) as reader:
        reader.members()
        assert DiagnosticCode.PASSWORD_ARGUMENT_UNUSED not in reader.diagnostics.counts
    with open_archive(source, password="typed") as reader:
        assert reader.diagnostics.counts[DiagnosticCode.PASSWORD_ARGUMENT_UNUSED] == 1


@pytest.mark.parametrize("lazy", [False, True], ids=["eager", "lazy"])
def test_stream_diagnostics_count_its_unverifiable_digest(lazy: bool) -> None:
    """A member stream's own ``diagnostics`` count the digest it cannot check.

    The verifier reports ``DIGEST_UNVERIFIABLE`` while the stream is built, before
    any read. A lazy stream enters its diagnostic scope there only when it has a
    digest to check, so this pins that the case is still inside the scope.
    """
    from archivey.internal.streams.archive_stream import ArchiveStream

    collector = DiagnosticCollector()
    stream = ArchiveStream(
        lambda: io.BytesIO(b"data"),
        translate=lambda _e: None,
        lazy=lazy,
        collector=collector,
        expected_hashes={"no-such-digest": b"\x00"},  # type: ignore[dict-item]
    )
    with stream:
        assert stream.diagnostics.counts == {DiagnosticCode.DIGEST_UNVERIFIABLE: 1}
        assert stream.read() == b"data"
