"""``ArchiveStream`` and ``MemberPass`` are bases that archivey's readers build, not
classes a caller builds. 0.3 built archivey's own subclass for a direct call or for a
subclass with an abstract method left, with a ``DeprecationWarning``; 0.4 refuses both
with ``TypeError`` (DR-12a)."""

from __future__ import annotations

import gzip
import io
import warnings
import zipfile

import pytest

from archivey import ArchiveStream, MemberPass, open_archive, open_stream


def test_archive_stream_cannot_be_built_directly() -> None:
    with pytest.raises(TypeError, match=r"ArchiveReader\.open\(\)"):
        ArchiveStream(lambda: io.BytesIO(b"payload"), translate=lambda _e: None)


def test_member_pass_cannot_be_built_directly() -> None:
    with pytest.raises(TypeError, match=r"stream_members\(\)"):
        MemberPass(iter((1, 2)))  # type: ignore[abstract]


def test_an_archive_stream_subclass_from_0_2_is_refused() -> None:
    """In 0.2 ``ArchiveStream`` was concrete, so a subclass could add to it alone."""

    class Tagged(ArchiveStream):
        tag = "mine"

    with pytest.raises(TypeError, match=r"Tagged with abstract methods .*read"):
        Tagged(lambda: io.BytesIO(b"payload"), translate=lambda _e: None)


def test_a_member_pass_subclass_from_0_2_is_refused() -> None:
    class Counted(MemberPass[int]):
        def __next__(self) -> int:
            return 10 * super().__next__()

    with pytest.raises(TypeError, match="close"):
        Counted(iter((1, 2)))  # type: ignore[abstract]


def test_a_complete_subclass_builds_as_written() -> None:
    class Done(MemberPass[int]):
        def __next__(self) -> int:
            raise StopIteration

        def close(self) -> None:
            pass

    members = Done()
    assert type(members) is Done
    assert list(members) == []


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
