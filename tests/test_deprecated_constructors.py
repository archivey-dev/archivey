"""Building ``ArchiveStream`` or ``MemberPass`` directly still works until 0.4.0, with a
``DeprecationWarning`` that names where to get one instead (DR-12a).

Both public classes are bases now: the call builds archivey's own subclass, the one
the readers hand out."""

from __future__ import annotations

import gzip
import io
import warnings
import zipfile

import pytest

from archivey import ArchiveStream, MemberPass, open_archive, open_stream
from archivey.internal.member_pass import MemberPassImpl
from archivey.internal.streams.archive_stream import ArchiveStreamImpl


def test_archive_stream_constructor_warns_and_still_reads() -> None:
    with pytest.warns(DeprecationWarning, match=r"ArchiveReader\.open\(\)"):
        stream = ArchiveStream(
            lambda: io.BytesIO(b"payload"), translate=lambda _e: None
        )
    assert type(stream) is ArchiveStreamImpl
    with stream:
        assert stream.read() == b"payload"


def test_member_pass_constructor_warns_and_still_iterates() -> None:
    def items():
        yield 1
        yield 2

    with pytest.warns(DeprecationWarning, match=r"stream_members\(\)"):
        members = MemberPass(items())
    assert type(members) is MemberPassImpl
    assert list(members) == [1, 2]


def test_readers_build_streams_and_passes_without_warning(tmp_path) -> None:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"payload")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        with open_archive(path) as reader:
            assert reader.read("a.txt") == b"payload"
            with reader.open("a.txt") as opened:
                assert isinstance(opened, ArchiveStream)
            with reader.stream_members() as members:
                assert isinstance(members, MemberPass)
                for _member, stream in members:
                    assert stream is not None and stream.read() == b"payload"
            assert [m.name for m in reader] == ["a.txt"]
        gz = tmp_path / "a.gz"
        gz.write_bytes(gzip.compress(b"payload"))
        with open_stream(gz) as stream:
            assert stream.read() == b"payload"


def test_an_archive_stream_subclass_from_0_2_warns_and_still_reads() -> None:
    """In 0.2 ``ArchiveStream`` was concrete, so a subclass could add to it alone.
    Built with no warning, its arguments were dropped and ``read()`` raised
    ``NotImplementedError``."""

    class Tagged(ArchiveStream):
        tag = "mine"

    with pytest.warns(DeprecationWarning, match=r"subclassing ArchiveStream.*0\.4\.0"):
        stream = Tagged(lambda: io.BytesIO(b"payload"), translate=lambda _e: None)
    assert isinstance(stream, Tagged)
    assert isinstance(stream, ArchiveStreamImpl)
    assert stream.tag == "mine"
    with stream:
        assert stream.read() == b"payload"


def test_a_member_pass_subclass_from_0_2_warns_and_still_iterates() -> None:
    """Such a subclass raised ``TypeError`` at once: its abstract methods were unset."""

    class Counted(MemberPass[int]):
        def __next__(self) -> int:
            return 10 * super().__next__()

    def items():
        yield 1
        yield 2

    with pytest.warns(DeprecationWarning, match=r"subclassing MemberPass.*Counted"):
        members = Counted(items())
    assert isinstance(members, Counted)
    assert list(members) == [10, 20]
    members.close()


def test_a_complete_subclass_builds_as_written_without_warning() -> None:
    class Done(MemberPass[int]):
        def __next__(self) -> int:
            raise StopIteration

        def close(self) -> None:
            pass

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        members = Done()
    assert type(members) is Done
    assert list(members) == []
