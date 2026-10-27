"""``stream_members()`` returns a ``MemberPass``: an iterator that can be closed."""

from __future__ import annotations

import io
import threading
import zipfile
from collections.abc import Generator, Iterator

import pytest

from archivey import ArchiveyUsageError, MemberPass, open_archive


def _zip() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"first")
        zf.writestr("b.txt", b"second")
    buf.seek(0)
    return buf


def test_a_pass_is_an_iterator_of_member_stream_pairs() -> None:
    with open_archive(_zip()) as reader:
        members = reader.stream_members()
        assert isinstance(members, MemberPass)
        assert isinstance(members, Iterator)
        assert iter(members) is members
        got = {m.name: s.read() for m, s in members if s is not None}
    assert got == {"a.txt": b"first", "b.txt": b"second"}


def test_a_paused_pass_blocks_the_reader_until_closed() -> None:
    with open_archive(_zip()) as reader:
        members = reader.stream_members()
        _member, stream = next(members)
        with pytest.raises(ArchiveyUsageError, match="stream_members"):
            reader.read("b.txt")
        members.close()
        assert stream is not None and stream.closed
        assert reader.read("b.txt") == b"second"
        with pytest.raises(StopIteration):
            next(members)
        members.close()  # closing again does nothing


def test_with_block_ends_the_pass_when_the_body_raises() -> None:
    with open_archive(_zip()) as reader:
        with (
            pytest.raises(RuntimeError, match="boom"),
            reader.stream_members() as members,
        ):
            for _member, _stream in members:
                raise RuntimeError("boom")
        assert reader.read("b.txt") == b"second"


def test_closing_a_finished_pass_does_nothing() -> None:
    with open_archive(_zip()) as reader:
        with reader.stream_members() as members:
            assert len(list(members)) == 2
        members.close()
        assert reader.read("a.txt") == b"first"


def test_a_pass_closes_on_a_streaming_reader_too() -> None:
    with open_archive(_zip(), streaming=True) as reader:
        with reader.stream_members() as members:
            member, stream = next(members)
            assert member.name == "a.txt"
        assert stream is not None and stream.closed
        # Closing does not give the streaming reader a second pass; members_report()
        # finishes the interrupted walk.
        assert [m.name for m in reader.members_report().members] == ["a.txt", "b.txt"]
        assert reader.members_report_if_available() is not None
        with pytest.raises(ArchiveyUsageError):
            next(reader.stream_members())


def test_iterating_a_streaming_reader_returns_a_closable_pass() -> None:
    with open_archive(_zip(), streaming=True) as reader:
        members = iter(reader)
        assert isinstance(members, MemberPass)
        assert next(members).name == "a.txt"
        with pytest.raises(ArchiveyUsageError, match="__iter__"):
            reader.members_report()
        members.close()
        assert len(reader.members_report().members) == 2


def test_closing_a_pass_another_thread_is_advancing_raises_usage_error() -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocking(_member: object) -> bool:
        entered.set()
        release.wait(10)
        return True

    with open_archive(_zip(), concurrent_operations=True) as reader:
        members = reader.stream_members(blocking)
        got: list[str] = []
        worker = threading.Thread(target=lambda: got.append(next(members)[0].name))
        worker.start()
        try:
            assert entered.wait(10)
            with pytest.raises(ArchiveyUsageError, match="while it is executing"):
                members.close()
        finally:
            release.set()
            worker.join(10)
        assert got == ["a.txt"]
        members.close()
        assert reader.read("b.txt") == b"second"


def test_a_value_error_from_the_pass_itself_is_not_translated() -> None:
    def failing() -> Generator[int, None, None]:
        try:
            yield 1
        finally:
            raise ValueError("from the pass")

    members = MemberPass(failing())
    next(members)
    with pytest.raises(ValueError, match="from the pass") as info:
        members.close()
    assert not isinstance(info.value, ArchiveyUsageError)


def test_a_selector_closing_its_own_pass_raises_usage_error() -> None:
    errors: list[BaseException] = []

    def closing(_member: object) -> bool:
        try:
            members.close()
        except ArchiveyUsageError as exc:
            errors.append(exc)
        return True

    with open_archive(_zip()) as reader:
        members = reader.stream_members(closing)
        assert [m.name for m, _ in members] == ["a.txt", "b.txt"]
    assert len(errors) == 2
    assert "selector is closing its own pass" in str(errors[0])
