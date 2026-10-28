"""Contract tests for the BaseArchiveReader extension points and access-mode enforcement.

Exercised directly with minimal in-test readers (no real format backend), covering the
access-mode gate (``streaming=True`` is forward-only) plus
``members_report_if_available``.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import archivey
from archivey.cost import (
    AccessCost,
    CostReceipt,
    ListingCost,
    StreamCapability,
)
from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import ArchiveyUsageError, DiagnosticRaisedError
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.archive_stream import MemberStreamParts
from archivey.types import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveMember,
    MemberType,
)
from tests.corruption_util import (
    is_corruption_not_truncation,
    raises_corruption_not_truncation,
)


def _info(
    format: ArchiveFormat, listing: ListingCost, stream: StreamCapability
) -> ArchiveInfo:
    return ArchiveInfo(
        format=format,
        format_version=None,
        is_solid=False,
        member_count=None,
        comment=None,
        is_encrypted=False,
        is_multivolume=False,
        cost=CostReceipt(
            listing_cost=listing,
            access_cost=AccessCost.DIRECT,
            stream_capability=stream,
        ),
    )


class _IndexedReader(BaseArchiveReader):
    """Random-access reader with a true upfront index (like ZIP / a directory)."""

    _MEMBER_LIST_UPFRONT = True

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=1)

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        return self._member_parts(io.BytesIO(b"x"), member.name, size=member.size)

    def _get_archive_info(self) -> ArchiveInfo:
        return _info(ArchiveFormat.ZIP, ListingCost.INDEXED, StreamCapability.SEEKABLE)

    def _close_archive(self) -> None:
        pass


class _ForwardOnlyReader(BaseArchiveReader):
    """A reader with no upfront index (like a streaming TAR)."""

    _MEMBER_LIST_UPFRONT = False

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=1)

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        return self._member_parts(io.BytesIO(b"x"), member.name, size=member.size)

    def _get_archive_info(self) -> ArchiveInfo:
        return _info(
            ArchiveFormat.TAR,
            ListingCost.REQUIRES_SCANNING,
            StreamCapability.FORWARD_ONLY,
        )

    def _close_archive(self) -> None:
        pass


# --- Access-mode gate: streaming=True is forward-only, even on a capable backend ----


def test_streaming_disables_random_access_on_capable_backend() -> None:
    reader = _IndexedReader(ArchiveFormat.ZIP, True, "x.zip")  # streaming=True
    for call in (
        lambda: reader.members(),
        lambda: reader.get("a.txt"),
        lambda: reader.open("a.txt"),
        lambda: reader.read("a.txt"),
    ):
        with pytest.raises(archivey.ArchiveyUsageError):
            call()
    # A single forward pass is still allowed.
    assert [m.name for m in reader] == ["a.txt"]


def test_no_len_so_list_works_on_streaming_reader() -> None:
    # The reader defines no __len__ (it is not a collection), so len() raises Python's
    # own TypeError — and list(reader), which probes __len__ via the length-hint
    # protocol (suppressing TypeError), performs the plain forward pass.
    reader = _IndexedReader(ArchiveFormat.ZIP, True, "x.zip")  # streaming=True
    with pytest.raises(TypeError):
        len(reader)
    assert [m.name for m in list(reader)] == ["a.txt"]


def test_contains_is_identity_and_mode_free() -> None:
    # Identity membership works even on a streaming reader (no scan involved), and a
    # string operand raises TypeError instead of falling back to iteration.
    reader = _IndexedReader(ArchiveFormat.ZIP, True, "x.zip")  # streaming=True
    (member,) = list(reader)
    assert member in reader
    other = _IndexedReader(ArchiveFormat.ZIP, False, "y.zip")
    assert other.members()[0] not in reader
    with pytest.raises(TypeError):
        "a.txt" in reader  # noqa: B015 - the expression itself must raise


class _OpenCountingReader(_IndexedReader):
    """Counts ``_open_member`` calls to observe stream laziness."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.opens = 0

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=1)
        yield ArchiveMember(type=MemberType.FILE, name="b.txt", size=1)

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        self.opens += 1
        return self._member_parts(io.BytesIO(b"x"), member.name, size=member.size)


def test_stream_members_opens_lazily() -> None:
    # The yielded streams open the member's data on first read, not at yield time: a
    # consumer that skips a member (or a selector that filters it) pays nothing for it.
    reader = _OpenCountingReader(ArchiveFormat.ZIP, False, "x.zip")
    for _member, stream in reader.stream_members():
        assert stream is not None
    assert reader.opens == 0  # iterated, never read -> never opened

    reader = _OpenCountingReader(ArchiveFormat.ZIP, False, "x.zip")
    read = {m.name: s.read() for m, s in reader.stream_members(["b.txt"]) if s}
    assert read == {"b.txt": b"x"}
    assert reader.opens == 1  # only the selected member was opened


def test_open_rejects_member_from_another_reader() -> None:
    # The same identity rule as `member in reader`: a member object yielded by a
    # different reader must not open here — without the check it would resolve against
    # the wrong offsets/paths and could silently return the wrong data.
    reader = _IndexedReader(ArchiveFormat.ZIP, False, "x.zip")
    other = _IndexedReader(ArchiveFormat.ZIP, False, "y.zip")
    foreign = other.members()[0]
    with pytest.raises(ArchiveyUsageError, match="does not belong to this reader"):
        reader.open(foreign)
    # The same name opens fine when looked up on the right reader.
    assert reader.read("a.txt") == b"x"


# --- members_report_if_available: never scans; safe on any reader -------------------


def test_members_report_if_available_returns_report_for_indexed_backend() -> None:
    # Even on a streaming reader: it is a no-scan peek, not random access.
    reader = _IndexedReader(ArchiveFormat.ZIP, True, "x.zip")  # streaming=True
    report = reader.members_report_if_available()
    assert report is not None
    assert report.error is None
    assert [m.name for m in report] == ["a.txt"]


def test_members_report_if_available_is_none_without_index() -> None:
    reader = _ForwardOnlyReader(ArchiveFormat.TAR, True, "x.tar")  # streaming=True
    assert reader.members_report_if_available() is None


def test_members_report_if_available_returns_cache_once_materialized() -> None:
    # No upfront index, but a non-streaming iteration materializes the cache, after
    # which the list is available without a fresh scan.
    reader = _ForwardOnlyReader(ArchiveFormat.TAR, False, "x.tar")  # streaming=False
    assert reader.members_report_if_available() is None
    _ = list(reader)
    report = reader.members_report_if_available()
    assert report is not None
    assert report.error is None


def test_streaming_iteration_registers_member_ids() -> None:
    # A streaming pass must still stamp identity onto the members it yields (the
    # progressive path bypasses _materialize_members).
    reader = _IndexedReader(ArchiveFormat.ZIP, True, "x.zip")  # streaming=True
    (member,) = list(reader)
    assert member.member_id == 0
    assert member in reader


def test_streaming_second_iter_raises() -> None:
    reader = _IndexedReader(ArchiveFormat.ZIP, True, "x.zip")
    list(reader)
    with pytest.raises(archivey.ArchiveyUsageError):
        list(reader)


def test_members_report_if_available_after_streaming_pass() -> None:
    reader = _ForwardOnlyReader(ArchiveFormat.TAR, True, "x.tar")
    list(reader)
    report = reader.members_report_if_available()
    assert report is not None
    assert report.error is None
    assert [m.name for m in report] == ["a.txt"]


def test_members_report_equals_members_in_random_mode() -> None:
    reader = _IndexedReader(ArchiveFormat.ZIP, False, "x.zip")
    assert list(reader.members_report().members) == reader.members()
    assert [m.name for m in reader] == ["a.txt"]


def test_streaming_members_refusal_names_the_two_listing_routes() -> None:
    """members() refuses on a streaming reader and points at what works there."""
    reader = _ForwardOnlyReader(ArchiveFormat.TAR, True, "x.tar")
    with pytest.raises(ArchiveyUsageError) as info:
        reader.members()
    message = str(info.value)
    assert "members_report()" in message
    assert "stream_members()" in message
    # Both routes still list the archive; members_report() uses up the pass.
    assert [m.name for m in reader.members_report()] == ["a.txt"]


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda r: r.get("a.txt"), id="get"),
        pytest.param(lambda r: r.open("a.txt"), id="open"),
        pytest.param(lambda r: r.read("a.txt"), id="read"),
    ],
)
def test_streaming_data_refusal_names_the_data_route(
    call: Callable[[Any], object],
) -> None:
    """get()/open()/read() want member data, so the refusal names the route that
    gives it (stream_members()) and none of the listing-only routes."""
    reader = _ForwardOnlyReader(ArchiveFormat.TAR, True, "x.tar")
    with pytest.raises(ArchiveyUsageError) as info:
        call(reader)
    message = str(info.value)
    assert "stream_members() and read each member's stream" in message
    assert "members_report" not in message
    assert "ignore the streams" not in message


def test_members_report_usage_errors_name_members_report() -> None:
    closed = _IndexedReader(ArchiveFormat.ZIP, False, "x.zip")
    closed.close()
    with pytest.raises(
        ArchiveyUsageError, match=r"^members_report\(\) is not available"
    ):
        closed.members_report()

    streaming = _ForwardOnlyReader(ArchiveFormat.TAR, True, "x.tar")
    pass_ = streaming.stream_members()
    next(pass_)
    with pytest.raises(ArchiveyUsageError, match="Cannot start 'members_report'"):
        streaming.members_report()
    pass_.close()


# --- BaseException during materialization must not wedge the reader (review C1/Q1) --


class _FlakyReader(_IndexedReader):
    """An indexed reader whose first materialization attempt is interrupted.

    Simulates a KeyboardInterrupt/MemoryError raised mid-scan: the first
    ``_iter_members`` raises BaseException, later ones succeed.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._raised = False

    def _iter_members(self) -> Iterator[ArchiveMember]:
        if not self._raised:
            self._raised = True
            raise KeyboardInterrupt("interrupted mid-scan")
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=1)


def test_baseexception_during_materialization_does_not_wedge_reader() -> None:
    reader = _FlakyReader(ArchiveFormat.ZIP, False, "x.zip")
    # The interrupt propagates unchanged (BaseException, not reclassified).
    with pytest.raises(KeyboardInterrupt):
        reader.members()
    # The reader must remain usable: the failed election was rolled back to
    # UNMATERIALIZED, so a retry re-elects and succeeds instead of raising a
    # misleading "materialization already in progress".
    assert [m.name for m in reader.members()] == ["a.txt"]


# --- A failed streaming pass must not publish a partial member list (deep N1) --------


class _FailingScanReader(BaseArchiveReader):
    """Streaming reader whose scan raises after yielding its first member."""

    _MEMBER_LIST_UPFRONT = False

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=1)
        raise archivey.CorruptionError("scan failed mid-pass")

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        return self._member_parts(io.BytesIO(b"x"), member.name, size=member.size)

    def _get_archive_info(self) -> ArchiveInfo:
        return _info(
            ArchiveFormat.TAR,
            ListingCost.REQUIRES_SCANNING,
            StreamCapability.FORWARD_ONLY,
        )

    def _close_archive(self) -> None:
        pass


class _FailingRandomAccessReader(_IndexedReader):
    """Random-access reader whose listing ends with terminal archive damage."""

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.FILE, name="a.txt", size=1)
        raise archivey.CorruptionError("scan failed after prefix")


def test_random_access_terminal_damage_report_and_yield_then_raise() -> None:
    reader = _FailingRandomAccessReader(ArchiveFormat.ZIP, False, "x.zip")

    report = reader.members_report()
    assert [m.name for m in report] == ["a.txt"]
    assert is_corruption_not_truncation(report.error)
    assert reader.members_report() is report

    with raises_corruption_not_truncation():
        reader.members()

    it = iter(reader)
    member = next(it)
    assert member.name == "a.txt"
    assert reader.read(member) == b"x"
    with raises_corruption_not_truncation():
        next(it)

    assert reader.get("a.txt") is member
    with raises_corruption_not_truncation():
        reader.get("missing.txt")


def test_failed_streaming_pass_publishes_incomplete_report() -> None:
    # Terminal archive damage publishes the recovered prefix as an incomplete report,
    # never as a complete member list.
    reader = _FailingScanReader(ArchiveFormat.TAR, True, "x.tar")
    it = iter(reader)
    assert next(it).name == "a.txt"
    with raises_corruption_not_truncation():
        next(it)
    # The listing methods label the partial scan as incomplete, never complete.
    finished = reader.members_report()
    assert is_corruption_not_truncation(finished.error)
    assert [m.name for m in finished] == ["a.txt"]
    report = reader.members_report_if_available()
    assert report is not None
    assert is_corruption_not_truncation(report.error)
    assert [m.name for m in report] == ["a.txt"]


def test_failed_streaming_pass_replays_incomplete_report() -> None:
    reader = _FailingScanReader(ArchiveFormat.TAR, True, "x.tar")
    with raises_corruption_not_truncation():
        list(reader)
    for _ in range(2):
        report = reader.members_report()
        assert [m.name for m in report] == ["a.txt"]
        assert is_corruption_not_truncation(report.error)


# --- Incomplete listing must survive a secondary link-finalize fault (double-fault) ---


class _LinkFinalizeDoubleFaultRA(_IndexedReader):
    """Listing recovers a symlink, then fails; link-target read also fails.

    Models ZIP/7z/RAR where ``_ensure_link_target`` reads member data after a
    partial listing. A real ZIP cannot hit mid-listing damage after the central
    directory parse, so this synthetic reader is the regression fixture.
    """

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.SYMLINK, name="link", size=8)
        raise archivey.CorruptionError("listing damaged after prefix")

    def _ensure_link_target(self, member: ArchiveMember) -> None:
        raise archivey.TruncatedError("symlink target data truncated")


class _LinkFinalizeDoubleFaultStream(_ForwardOnlyReader):
    """Streaming twin of ``_LinkFinalizeDoubleFaultRA``."""

    def _iter_members(self) -> Iterator[ArchiveMember]:
        yield ArchiveMember(type=MemberType.SYMLINK, name="link", size=8)
        raise archivey.CorruptionError("listing damaged after prefix")

    def _ensure_link_target(self, member: ArchiveMember) -> None:
        raise archivey.TruncatedError("symlink target data truncated")


def test_ra_incomplete_listing_survives_link_finalize_double_fault() -> None:
    reader = _LinkFinalizeDoubleFaultRA(ArchiveFormat.ZIP, False, "x.zip")

    report = reader.members_report()
    assert [m.name for m in report] == ["link"]
    assert is_corruption_not_truncation(report.error)
    assert "listing damaged" in str(report.error)
    # Secondary TruncatedError must not replace the listing error or clear the report.
    assert reader.members_report() is report
    with raises_corruption_not_truncation(match="listing damaged"):
        reader.members()


def test_streaming_incomplete_listing_survives_link_finalize_double_fault() -> None:
    reader = _LinkFinalizeDoubleFaultStream(ArchiveFormat.TAR, True, "x.tar")

    it = iter(reader)
    assert next(it).name == "link"
    with raises_corruption_not_truncation(match="listing damaged"):
        next(it)

    report = reader.members_report_if_available()
    assert report is not None
    assert [m.name for m in report] == ["link"]
    assert is_corruption_not_truncation(report.error)
    assert "listing damaged" in str(report.error)


# --- One handle per member: ``_open_member`` returns the member's parts ---------------


class _UnverifiableDigestReader(_IndexedReader):
    """A reader whose member lists a digest no hasher exists for."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.opened: list[io.BytesIO] = []

    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        data = io.BytesIO(b"x")
        self.opened.append(data)
        return self._member_parts(
            data,
            member.name,
            size=member.size,
            expected_hashes={"no-such-digest": b"\0"},  # type: ignore[dict-item]
        )


def _digest_reader(*, raising: bool) -> _UnverifiableDigestReader:
    policy = DiagnosticPolicy(
        raise_on={DiagnosticCode.DIGEST_UNVERIFIABLE} if raising else ()
    )
    return _UnverifiableDigestReader(
        ArchiveFormat.ZIP,
        False,
        "x.zip",
        collector=DiagnosticCollector(policy=policy),
    )


def test_a_lazy_handle_reports_its_members_unverifiable_digest() -> None:
    """The handle that serves the member builds its verifier on first read, inside
    its own scope, so the digest it cannot check is reported on that handle."""
    reader = _digest_reader(raising=False)
    for _member, stream in reader.stream_members():
        assert stream is not None
        assert stream.diagnostics.counts == {}
        assert stream.read() == b"x"
        assert stream.diagnostics.counts == {DiagnosticCode.DIGEST_UNVERIFIABLE: 1}


def test_an_open_handle_reports_its_members_unverifiable_digest() -> None:
    reader = _digest_reader(raising=False)
    with reader.open("a.txt") as f:
        assert f.diagnostics.counts == {DiagnosticCode.DIGEST_UNVERIFIABLE: 1}
        assert f.read() == b"x"


def test_a_lazy_handle_that_refuses_its_member_closes_the_data() -> None:
    """A verifier refused under a RAISE policy fails the open, and the member's data,
    which no handle took, is closed rather than left to the garbage collector."""
    reader = _digest_reader(raising=True)
    for _member, stream in reader.stream_members():
        assert stream is not None
        with pytest.raises(DiagnosticRaisedError):
            stream.read()
        assert [data.closed for data in reader.opened] == [True]
        # The same open, so the same error, and no second open of the member.
        with pytest.raises(DiagnosticRaisedError):
            stream.read()
        assert len(reader.opened) == 1


def test_an_open_that_refuses_its_member_closes_the_data() -> None:
    reader = _digest_reader(raising=True)
    with pytest.raises(DiagnosticRaisedError):
        reader.open("a.txt")
    assert [data.closed for data in reader.opened] == [True]
