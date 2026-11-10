"""The helpers archivey.formats gives a reader for the fields many formats share:
Unix mode bits, Unix times and DOS times."""

from __future__ import annotations

import stat
from datetime import UTC, datetime
from typing import Any

import pytest

from archivey import ArchiveMember, ArchiveyConfig, DiagnosticCode, MemberType
from archivey.diagnostics import MemberTimestampContext
from archivey.formats import ReaderContext, unix_member_type


def _unused(*args: Any) -> Any:
    raise AssertionError("not used by these helpers")


def _context() -> tuple[ReaderContext, list[tuple[Any, ...]]]:
    reports: list[tuple[Any, ...]] = []
    context = ReaderContext(
        encoding=None,
        archive_name="t",
        config=ArchiveyConfig(),
        decompress=_unused,
        report=lambda *args: reports.append(args),
        link_target_unavailable=_unused,
        hold=_unused,
        charge_metadata=_unused,
    )
    return context, reports


def _member() -> ArchiveMember:
    return ArchiveMember(type=MemberType.FILE, name="a")


@pytest.mark.parametrize(
    ("mode", "has_data", "expected"),
    [
        (stat.S_IFREG | 0o644, True, (MemberType.FILE, None)),
        (stat.S_IFDIR | 0o755, False, (MemberType.DIRECTORY, None)),
        (stat.S_IFLNK | 0o777, True, (MemberType.SYMLINK, None)),
        (stat.S_IFCHR, False, (MemberType.OTHER, "char_device")),
        (stat.S_IFBLK, False, (MemberType.OTHER, "block_device")),
        (stat.S_IFIFO, False, (MemberType.OTHER, "fifo")),
        (stat.S_IFSOCK, False, (MemberType.OTHER, "socket")),
        (stat.S_IFIFO, True, (MemberType.FILE, "fifo")),
        (0o644, False, (MemberType.OTHER, "unknown")),
        (0o644, True, (MemberType.FILE, "unknown")),
    ],
)
def test_unix_member_type(
    mode: int, has_data: bool, expected: tuple[MemberType, str | None]
) -> None:
    assert unix_member_type(mode, has_data=has_data) == expected


def test_a_unix_time_sets_the_field_in_utc() -> None:
    context, reports = _context()
    member = _member()
    context.set_unix_time(
        member, "accessed", 1_700_000_000, nanoseconds=123_456_789, source="cpio"
    )
    assert member.accessed == datetime(2023, 11, 14, 22, 13, 20, 123456, tzinfo=UTC)
    assert reports == []


def test_a_unix_time_before_the_epoch() -> None:
    context, _ = _context()
    member = _member()
    context.set_unix_time(member, "modified", -86_400, source="ar")
    assert member.modified == datetime(1969, 12, 31, tzinfo=UTC)


@pytest.mark.parametrize(
    ("seconds", "nanoseconds", "value_repr"),
    [
        (999_999_999_999, 0, "999999999999"),
        (-(10**12), 0, "-1000000000000"),
        (0, 1_000_000_000, "0 s + 1000000000 ns"),
        (0, -1, "0 s + -1 ns"),
    ],
)
def test_a_unix_time_outside_a_datetime_is_reported_and_left_unset(
    seconds: int, nanoseconds: int, value_repr: str
) -> None:
    context, reports = _context()
    member = _member()
    context.set_unix_time(
        member, "modified", seconds, nanoseconds=nanoseconds, source="ar"
    )
    assert member.modified is None
    ((code, message, details, reported),) = reports
    assert code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
    assert "modified is left unset" in message
    assert reported is member
    assert details == MemberTimestampContext(
        member_name="a", field="modified", source="ar", value_repr=value_repr
    )


def test_a_dos_time_sets_a_local_time() -> None:
    context, reports = _context()
    member = _member()
    # 2024-05-06 07:08:10: years since 1980, then seconds / 2.
    stamp = (44 << 25 | 5 << 21 | 6 << 16) | (7 << 11 | 8 << 5 | 5)
    context.set_dos_time(member, "modified", stamp, source="dos")
    assert member.modified == datetime(2024, 5, 6, 7, 8, 10)
    assert reports == []


def test_a_zero_dos_time_is_no_time() -> None:
    context, reports = _context()
    member = _member()
    context.set_dos_time(member, "created", 0, source="dos")
    assert member.created is None
    assert reports == []


def test_an_impossible_dos_time_is_reported_and_left_unset() -> None:
    context, reports = _context()
    member = _member()
    context.set_dos_time(member, "modified", 15 << 21 | 1 << 16, source="dos")
    assert member.modified is None
    ((code, _, details, _),) = reports
    assert code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
    assert details.value_repr == "0x01e10000"
